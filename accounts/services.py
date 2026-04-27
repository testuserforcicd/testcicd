import datetime
import os
import uuid
import io
import base64

import psutil
from django.conf import settings
from django.contrib.auth import get_user_model
from django.db import connection
from django.db.models import Count, Q
from django.core.mail import send_mail
from django.contrib.sessions.models import Session
from django.utils import timezone
from django_otp import login as otp_login
from django_otp.plugins.otp_totp.models import TOTPDevice
import qrcode

from accounts.models import ProtectedSite, RequestLog, AdminMessage, AccessToken, WAFRule
from accounts.tasks import export_logs_to_csv

User = get_user_model()


def get_waf_status_by_domain(domain: str) -> dict:
    site = ProtectedSite.objects.get(domain=domain)
    return {
        "domain": domain,
        "is_protected": site.is_protected,
        "target_ip": site.target_ip,
    }


def get_user_traffic_stats(user) -> dict:
    user_sites = ProtectedSite.objects.filter(user=user)
    return RequestLog.objects.filter(site__in=user_sites).aggregate(
        total_requests=Count("id"),
        blocked_requests=Count("id", filter=Q(was_blocked=True)),
        sqli_attacks=Count("id", filter=Q(rule_triggered__name__icontains="SQL")),
        xss_attacks=Count("id", filter=Q(rule_triggered__name__icontains="XSS")),
    )


def list_available_exports(user) -> list[dict]:
    exports_dir = os.path.join(settings.MEDIA_ROOT, "exports")
    files = []
    if os.path.exists(exports_dir):
        for name in sorted(os.listdir(exports_dir), reverse=True):
            if user.is_superuser or name.startswith(f"logs_{user.id}_"):
                if name.endswith(".csv"):
                    files.append(
                        {
                            "name": name,
                            "url": f"{settings.MEDIA_URL}exports/{name}",
                        }
                    )
    return files


def trigger_log_export(user):
    export_logs_to_csv.delay(user.id, is_admin=user.is_superuser)


def get_monitoring_metrics() -> dict:
    cpu = psutil.cpu_percent(interval=1)
    ram = psutil.virtual_memory()
    disk = psutil.disk_usage("/")
    one_min_ago = timezone.now() - datetime.timedelta(minutes=1)
    rps = RequestLog.objects.filter(timestamp__gte=one_min_ago).count()
    try:
        connection.ensure_connection()
        db_ok = True
    except Exception:
        db_ok = False

    return {
        "cpu_percent": cpu,
        "ram_total_gb": round(ram.total / 1024**3, 2),
        "ram_used_gb": round(ram.used / 1024**3, 2),
        "ram_percent": ram.percent,
        "disk_total_gb": round(disk.total / 1024**3, 2),
        "disk_used_gb": round(disk.used / 1024**3, 2),
        "disk_percent": disk.percent,
        "requests_per_minute": rps,
        "db_ok": db_ok,
    }


def register_user(username: str, email: str, password: str):
    user = User.objects.create_user(
        username=username,
        email=email,
        password=password,
        role="user",
    )
    user.is_active = False
    user.email_verification_token = str(uuid.uuid4())
    user.save()
    verify_url = f"http://127.0.0.1:8000/verify/{user.email_verification_token}/"
    send_mail(
        "Подтверждение регистрации WAF",
        f"Перейдите по ссылке для подтверждения: {verify_url}",
        settings.EMAIL_HOST_USER,
        [user.email],
        fail_silently=False,
    )
    return user


def verify_email_token(token: str):
    user = User.objects.get(email_verification_token=token)
    user.is_active = True
    user.is_email_verified = True
    user.email_verification_token = None
    user.save()
    return user


def add_site_for_user(user, form):
    new_site = form.save(commit=False)
    new_site.user = user
    new_site.save()
    return new_site


def send_message_to_admin(user, message: str):
    msg_text = message.strip()
    if msg_text:
        AdminMessage.objects.create(user=user, message=msg_text)
        return True
    return False


def build_2fa_qr(user):
    device, _ = TOTPDevice.objects.get_or_create(user=user, name="default")
    otp_url = device.config_url
    img = qrcode.make(otp_url)
    buffer = io.BytesIO()
    img.save(buffer, format="PNG")
    qr_code_base64 = base64.b64encode(buffer.getvalue()).decode()
    return device, qr_code_base64


def verify_2fa_setup_token(user, token: str):
    device = TOTPDevice.objects.filter(user=user, name="default").first()
    if device and device.verify_token(token):
        device.confirmed = True
        device.save()
        return device
    return None


def verify_login_otp_token(user, token: str):
    device = TOTPDevice.objects.filter(user=user, confirmed=True).first()
    if device and device.verify_token(token):
        return device
    return None


def mark_admin_message_read(msg):
    msg.is_read = True
    msg.save()


def toggle_token_active(token):
    token.is_active = not token.is_active
    token.save()
    return token


def block_ip_for_token(token, ip: str):
    ip = ip.strip()
    if not ip:
        return "empty"
    existing = token.get_blocked_ips_list()
    if ip in existing:
        return "exists"
    existing.append(ip)
    token.blocked_ips = ",".join(existing)
    token.save()
    return "ok"


def unblock_ip_for_token(token, ip: str):
    ip = ip.strip()
    existing = token.get_blocked_ips_list()
    if ip not in existing:
        return False
    existing.remove(ip)
    token.blocked_ips = ",".join(existing)
    token.save()
    return True


def change_user_password(user, new_password: str):
    if new_password:
        user.set_password(new_password)
        user.save()
        return True
    return False


def deactivate_session_by_key(session_key: str):
    Session.objects.filter(session_key=session_key).delete()


def create_waf_rule_from_form(form):
    return WAFRule.objects.create(
        name=form.cleaned_data["name"],
        pattern=form.cleaned_data["pattern"],
        description=form.cleaned_data.get("description", ""),
        severity=form.cleaned_data["severity"],
        action=form.cleaned_data["action"],
        is_active=form.cleaned_data.get("is_active", True),
    )


def update_waf_rule_from_form(rule, form):
    rule.name = form.cleaned_data["name"]
    rule.pattern = form.cleaned_data["pattern"]
    rule.description = form.cleaned_data.get("description", "")
    rule.severity = form.cleaned_data["severity"]
    rule.action = form.cleaned_data["action"]
    rule.is_active = form.cleaned_data.get("is_active", True)
    rule.save()
    return rule
