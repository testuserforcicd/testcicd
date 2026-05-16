from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import get_user_model, update_session_auth_hash, logout
from django.contrib.auth.decorators import login_required, user_passes_test
from django.contrib.auth.forms import PasswordChangeForm
from django.contrib.sessions.models import Session
from django.core.mail import send_mail
from django.conf import settings
from django.utils import timezone
from django.contrib import messages
from django_otp.plugins.otp_totp.models import TOTPDevice
from django_otp import user_has_device, login as otp_login
import qrcode, io, base64, uuid, psutil, datetime
from django.http import HttpResponse
from django.db.models import Q, Count
from .services import (
    add_site_for_user,
    block_ip_for_token,
    build_2fa_qr,
    change_user_password,
    create_waf_rule_from_form,
    deactivate_session_by_key,
    get_monitoring_metrics,
    get_user_traffic_stats,
    list_available_exports,
    mark_admin_message_read,
    register_user,
    send_message_to_admin,
    toggle_token_active,
    trigger_log_export,
    unblock_ip_for_token,
    update_waf_rule_from_form,
    verify_2fa_setup_token,
    verify_email_token,
    verify_login_otp_token,
)
import os
import csv

from .forms import (
    RegistrationForm, AvatarForm, ChangeRoleForm,
    ProtectedSiteForm, AccessTokenForm, WAFRuleForm
)
from .models import AccessToken, ProtectedSite, WAFRule, RequestLog, AdminMessage
User = get_user_model()

def is_superuser(user):
    return user.is_superuser


#  регистрация / верификация 
def register_view(request):
    if request.method == 'POST':
        form = RegistrationForm(request.POST)
        if form.is_valid():
            register_user(
                username=form.cleaned_data['username'],
                email=form.cleaned_data['email'],
                password=form.cleaned_data['password'],
            )
            return render(request, 'accounts/verify_sent.html', {'email': form.cleaned_data['email']})
    else:
        form = RegistrationForm()
    return render(request, 'accounts/register.html', {'form': form})


def verify_email(request, token):
    try:
        verify_email_token(token)
        return render(request, 'accounts/verify_success.html')
    except User.DoesNotExist:
        return render(request, 'accounts/verify_success.html', {'error': 'Неверный токен'})


#  дашборд пользователя 
@login_required
def dashboard_view(request):
    if request.user.is_superuser:
        return redirect('admin_panel')
    if user_has_device(request.user) and not request.user.is_verified():
        return redirect('verify_otp_login')
        
    user_sites = ProtectedSite.objects.filter(user=request.user)
    
    stats = get_user_traffic_stats(request.user)
    # ------------------------------------------------

    if request.method == 'POST':
        form = ProtectedSiteForm(request.POST)
        if form.is_valid():
            add_site_for_user(request.user, form)
            messages.success(request, 'Ваш сервер успешно добавлен под защиту WAF!')
            return redirect('dashboard')
    else:
        form = ProtectedSiteForm()

    ready_exports = get_available_exports(request.user.id)

    return render(request, 'accounts/dashboard.html', {
        'user': request.user,
        'sites': user_sites,
        'form': form,
        'stats': stats, 
        'exports': ready_exports
    })

#  выход из системы 

def logout_view(request):
    """Страница подтверждения выхода. GET — показываем форму, POST — выходим."""
    if request.method == 'POST':
        logout(request)
        return redirect('login')
    return render(request, 'accounts/logout.html')



@login_required
def contact_admin(request):
    """Отправка сообщения администратору"""
    if request.method == 'POST':
        if send_message_to_admin(request.user, request.POST.get('message', '')):
            messages.success(request, 'Сообщение отправлено администратору.')
    return redirect('dashboard')



#  2FA 

@login_required
def setup_2fa(request):
    device, qr_code_base64 = build_2fa_qr(request.user)
    return render(request, 'accounts/setup_2fa.html', {'qr_code': qr_code_base64, 'device': device})


@login_required
def verify_2fa_setup(request):
    if request.method == 'POST':
        token = request.POST.get('otp_token')
        device = verify_2fa_setup_token(request.user, token)
        if device:
            otp_login(request, device)
            return redirect('dashboard')
        return render(request, 'accounts/verify_otp.html', {'error': 'Неверный код'})
    return redirect('setup_2fa')


@login_required
def verify_otp_login(request):
    if request.method == 'POST':
        token = request.POST.get('otp_token')
        device = verify_login_otp_token(request.user, token)
        if device:
            otp_login(request, device)
            return redirect('dashboard')
        return render(request, 'accounts/verify_otp.html', {'error': 'Неверный код'})
    return render(request, 'accounts/verify_otp.html')


@login_required
@user_passes_test(is_superuser)
def admin_mark_message_read(request, msg_id):
    msg = get_object_or_404(AdminMessage, id=msg_id)
    mark_admin_message_read(msg)
    return redirect('admin_panel')


# панель администратора (суперпользователь)

@login_required
@user_passes_test(is_superuser)
def admin_panel(request):
    all_messages = AdminMessage.objects.select_related('user').order_by('-created_at')[:50]
    unread_count = AdminMessage.objects.filter(is_read=False).count()
    return render(request, 'accounts/admin/panel.html', {
        'admin_messages': all_messages,
        'unread_count': unread_count,
    })


# 1. Управление токенами
@login_required
@user_passes_test(is_superuser)
def admin_tokens(request):
    tokens = AccessToken.objects.select_related('user').all().order_by('-created_at')
    return render(request, 'accounts/admin/tokens.html', {'tokens': tokens})


@login_required
@user_passes_test(is_superuser)
def admin_token_toggle(request, token_id):
    t = get_object_or_404(AccessToken, id=token_id)
    toggle_token_active(t)
    return redirect('admin_tokens')


@login_required
@user_passes_test(is_superuser)
def admin_token_delete(request, token_id):
    get_object_or_404(AccessToken, id=token_id).delete()
    return redirect('admin_tokens')


@login_required
@user_passes_test(is_superuser)
def admin_token_block_ip(request, token_id):
    """Добавить IP в список заблокированных для токена."""
    if request.method == 'POST':
        t = get_object_or_404(AccessToken, id=token_id)
        ip = request.POST.get('ip', '')
        result = block_ip_for_token(t, ip)
        if result == 'ok':
            messages.success(request, f'IP {ip.strip()} заблокирован для токена')
        elif result == 'exists':
            messages.warning(request, f'IP {ip.strip()} уже в списке')
        return redirect('admin_tokens')
    return redirect('admin_tokens')


@login_required
@user_passes_test(is_superuser)
def admin_token_unblock_ip(request, token_id):
    """Удалить IP из списка заблокированных для токена."""
    if request.method == 'POST':
        t = get_object_or_404(AccessToken, id=token_id)
        ip = request.POST.get('ip', '').strip()
        if unblock_ip_for_token(t, ip):
            messages.success(request, f'IP {ip} разблокирован')
    return redirect('admin_tokens')


# 2. Управление пользователями (роли, блокировка, сайты, трафик)
@login_required
@user_passes_test(is_superuser)
def admin_users(request):
    users = User.objects.all().order_by('username')
    return render(request, 'accounts/admin/users.html', {'users': users})


@login_required
@user_passes_test(is_superuser)
def admin_user_detail(request, user_id):
    target = get_object_or_404(User, id=user_id)
    sites = target.sites.all()
    tokens = target.access_tokens.all()
    if request.method == 'POST':
        action = request.POST.get('action')
        if action == 'set_role':
            role = request.POST.get('role')
            if role in ('user', 'admin'):
                target.role = role
                target.save()
                messages.success(request, f'Роль изменена на {role}')
        elif action == 'set_tariff':
            tariff = request.POST.get('tariff_plan')
            if tariff in ('free', 'basic', 'pro'):
                target.tariff_plan = tariff
                target.save()
                messages.success(request, f'Тарифный план изменён на {target.get_tariff_plan_display()}')
        elif action == 'toggle_block':
            # Запрещаем блокировать самого себя
            if target.pk == request.user.pk:
                messages.error(request, 'Нельзя заблокировать собственный аккаунт')
            else:
                target.is_blocked = not target.is_blocked
                target.is_active = not target.is_blocked
                target.save()
                messages.success(request, 'Статус блокировки изменён')
        elif action == 'change_password':
            new_pw = request.POST.get('new_password')
            if change_user_password(target, new_pw):
                messages.success(request, 'Пароль изменён')
        elif action == 'site_protection':
            site_id = request.POST.get('site_id')
            site = get_object_or_404(ProtectedSite, id=site_id, user=target)
            site.is_protected = not site.is_protected
            site.save()
            messages.success(request, 'Статус защиты сайта изменён')
        elif action == 'site_traffic':
            site_id = request.POST.get('site_id')
            limit = request.POST.get('traffic_limit_mb', 0)
            site = get_object_or_404(ProtectedSite, id=site_id, user=target)
            try:
                site.traffic_limit_mb = int(limit)
                site.save()
                messages.success(request, 'Лимит трафика обновлён')
            except ValueError:
                messages.error(request, 'Некорректное значение лимита')
        return redirect('admin_user_detail', user_id=user_id)
    return render(request, 'accounts/admin/user_detail.html', {
        'target': target, 'sites': sites, 'tokens': tokens
    })


# 3. Смена пароля (для самого суперпользователя)
@login_required
@user_passes_test(is_superuser)
def admin_change_password(request):
    if request.method == 'POST':
        form = PasswordChangeForm(request.user, request.POST)
        if form.is_valid():
            user = form.save()
            update_session_auth_hash(request, user)
            messages.success(request, 'Пароль успешно изменён')
            return redirect('admin_panel')
    else:
        form = PasswordChangeForm(request.user)
    return render(request, 'accounts/admin/change_password.html', {'form': form})


# 4. Деактивация активных сессий
@login_required
@user_passes_test(is_superuser)
def admin_sessions(request):
    now = timezone.now()
    active_sessions = Session.objects.filter(expire_date__gte=now)
    session_data = []
    for s in active_sessions:
        data = s.get_decoded()
        uid = data.get('_auth_user_id')
        try:
            u = User.objects.get(pk=uid)
        except User.DoesNotExist:
            u = None
        session_data.append({'session': s, 'user': u, 'data': data})

    if request.method == 'POST':
        session_key = request.POST.get('session_key')
        if session_key:
            # Не позволяем администратору завершить собственную сессию через эту форму
            if session_key == request.session.session_key:
                messages.error(request, 'Нельзя завершить собственную текущую сессию через эту панель. Используйте кнопку «Выйти».')
            else:
                deactivate_session_by_key(session_key)
                messages.success(request, 'Сессия деактивирована. Пользователь будет перенаправлен на страницу входа.')
        return redirect('admin_sessions')

    return render(request, 'accounts/admin/sessions.html', {
        'sessions': session_data,
        'current_session_key': request.session.session_key,
    })


# 5. Смена аватара (суперпользователь меняет свой аватар)
@login_required
@user_passes_test(is_superuser)
def admin_avatar(request):
    if request.method == 'POST':
        form = AvatarForm(request.POST, request.FILES, instance=request.user)
        if form.is_valid():
            form.save()
            messages.success(request, 'Аватар обновлён')
            return redirect('admin_panel')
    else:
        form = AvatarForm(instance=request.user)
    return render(request, 'accounts/admin/avatar.html', {'form': form})


#  Реестр правил WAF 

@login_required
@user_passes_test(is_superuser)
def admin_rules(request):
    rules = WAFRule.objects.all().order_by('-created_at')
    if request.method == 'POST':
        form = WAFRuleForm(request.POST)
        if form.is_valid():
            create_waf_rule_from_form(form)
            messages.success(request, 'Правило добавлено')
            return redirect('admin_rules')
    else:
        form = WAFRuleForm()
    return render(request, 'accounts/admin/rules.html', {'rules': rules, 'form': form})


@login_required
@user_passes_test(is_superuser)
def admin_rule_edit(request, rule_id):
    rule = get_object_or_404(WAFRule, id=rule_id)
    if request.method == 'POST':
        form = WAFRuleForm(request.POST)
        if form.is_valid():
            update_waf_rule_from_form(rule, form)
            messages.success(request, 'Правило обновлено')
            return redirect('admin_rules')
    else:
        form = WAFRuleForm(initial={
            'name': rule.name, 'pattern': rule.pattern, 'description': rule.description,
            'severity': rule.severity, 'action': rule.action, 'is_active': rule.is_active,
        })
    return render(request, 'accounts/admin/rule_edit.html', {'form': form, 'rule': rule})


@login_required
@user_passes_test(is_superuser)
def admin_rule_delete(request, rule_id):
    get_object_or_404(WAFRule, id=rule_id).delete()
    messages.success(request, 'Правило удалено')
    return redirect('admin_rules')


@login_required
@user_passes_test(is_superuser)
def admin_rule_toggle(request, rule_id):
    rule = get_object_or_404(WAFRule, id=rule_id)
    rule.is_active = not rule.is_active
    rule.save()
    return redirect('admin_rules')


#  Мониторинг 

@login_required
@user_passes_test(is_superuser)
def admin_monitoring(request):
    metrics = get_monitoring_metrics()

    context = {
        'cpu': metrics['cpu_percent'],
        'ram_total': metrics['ram_total_gb'],
        'ram_used': metrics['ram_used_gb'],
        'ram_percent': metrics['ram_percent'],
        'disk_total': metrics['disk_total_gb'],
        'disk_used': metrics['disk_used_gb'],
        'disk_percent': metrics['disk_percent'],
        'rps': metrics['requests_per_minute'],
        'db_ok': metrics['db_ok'],
    }
    return render(request, 'accounts/admin/monitoring.html', context)


#  Логи 

def get_available_exports(user_id):
    user = get_object_or_404(User, id=user_id)
    return list_available_exports(user)

@login_required
def delete_export(request, filename):
    if not filename.endswith('.csv') or '/' in filename or '\\' in filename:
        messages.error(request, "Недопустимое имя файла.")
        return redirect('dashboard')

    is_admin = request.user.is_superuser
    user_id = request.user.id

    if not is_admin and not filename.startswith(f"logs_{user_id}_"):
        messages.error(request, "У вас нет прав на удаление этого файла.")
        return redirect('dashboard')

    file_path = os.path.join(settings.MEDIA_ROOT, 'exports', filename)
    if os.path.exists(file_path):
        os.remove(file_path)
        messages.success(request, f"Файл {filename} успешно удален.")
    else:
        messages.error(request, "Файл не найден.")

    referer = request.META.get('HTTP_REFERER', '')
    if 'panel' in referer:
        return redirect('admin_logs')
    return redirect('dashboard')



@login_required
def user_download_logs(request):
    trigger_log_export(request.user)
    messages.success(request, "Генерация логов запущена.")
    return redirect('dashboard')

@login_required
@user_passes_test(lambda u: u.is_superuser)
def admin_download_logs(request):
    trigger_log_export(request.user)
    messages.success(request, "Генерация логов запущена.")
    return redirect('admin_logs')



@login_required
@user_passes_test(lambda u: u.is_superuser)
def admin_logs(request):
    logs = RequestLog.objects.select_related('site', 'rule_triggered').order_by('-timestamp')[:500]
    
    stats = RequestLog.objects.aggregate(
        total_requests=Count('id'),
        blocked_requests=Count('id', filter=Q(was_blocked=True))
    )

    ready_exports = get_available_exports(request.user.id)
    

    return render(request, 'accounts/admin/logs.html', {
        'logs': logs, 
        'stats': stats,
        'exports': ready_exports
    })

@login_required
def start_log_export(request):
    trigger_log_export(request.user)
    messages.info(request, "Генерация логов запущена в фоновом режиме.")
    return redirect('dashboard')