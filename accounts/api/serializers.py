from rest_framework import serializers
from accounts.models import (
    ProtectedSite, WAFRule, RequestLog, AccessToken,
    BannedIP, AttackAttempt, TrafficStats, AdminMessage, User
)


# ─── Problem Details (только для документации схемы) ───────────────────────

class ProblemDetailSerializer(serializers.Serializer):
    requestId = serializers.CharField(help_text="уникальный идентификатор запроса")
    title = serializers.CharField(help_text="Краткое описание ошибки")
    detail = serializers.CharField(help_text="описание и способ устранения")
    timestamp = serializers.CharField(help_text="Метка времени UTC")


# ─── Sites ─────────────────────────────────────────────────────────────────

class ProtectedSiteSerializer(serializers.ModelSerializer):
    class Meta:
        model = ProtectedSite
        fields = ["id", "domain", "target_ip", "is_protected", "traffic_limit_mb", "created_at"]
        read_only_fields = ["id", "created_at"]


class ProtectedSiteCreateSerializer(serializers.ModelSerializer):
    class Meta:
        model = ProtectedSite
        fields = ["domain", "target_ip", "is_protected", "traffic_limit_mb"]


# ─── WAF Rules ─────────────────────────────────────────────────────────────

class WAFRuleSerializer(serializers.ModelSerializer):
    class Meta:
        model = WAFRule
        fields = [
            "id", "name", "pattern", "description",
            "severity", "action", "is_active", "created_at", "updated_at",
        ]
        read_only_fields = ["id", "created_at", "updated_at"]


class WAFRuleCreateSerializer(serializers.ModelSerializer):
    class Meta:
        model = WAFRule
        fields = ["name", "pattern", "description", "severity", "action", "is_active"]


# ─── Request Logs ──────────────────────────────────────────────────────────

class RequestLogSerializer(serializers.ModelSerializer):
    site_domain = serializers.CharField(source="site.domain", read_only=True, allow_null=True)
    rule_name = serializers.CharField(source="rule_triggered.name", read_only=True, allow_null=True)

    class Meta:
        model = RequestLog
        fields = [
            "id", "site_domain", "ip_address", "method", "path",
            "status_code", "was_blocked", "rule_name", "timestamp", "user_agent",
        ]
        read_only_fields = fields


# ─── Access Tokens ─────────────────────────────────────────────────────────

class AccessTokenSerializer(serializers.ModelSerializer):
    blocked_ips_list = serializers.SerializerMethodField()

    class Meta:
        model = AccessToken
        fields = ["id", "name", "token", "is_active", "created_at", "blocked_ips_list"]
        read_only_fields = ["id", "token", "created_at"]

    def get_blocked_ips_list(self, obj):
        return obj.get_blocked_ips_list()


class AccessTokenCreateSerializer(serializers.ModelSerializer):
    class Meta:
        model = AccessToken
        fields = ["name"]


# ─── Banned IPs ────────────────────────────────────────────────────────────

class BannedIPSerializer(serializers.ModelSerializer):
    site_domain = serializers.CharField(source="site.domain", read_only=True)

    class Meta:
        model = BannedIP
        fields = [
            "id", "site_domain", "ip_address", "reason",
            "banned_at", "expires_at", "is_active", "attack_count", "time_window_minutes",
        ]
        read_only_fields = fields


# ─── Traffic Stats ─────────────────────────────────────────────────────────

class TrafficStatsSerializer(serializers.ModelSerializer):
    total_mb = serializers.FloatField(read_only=True)

    class Meta:
        model = TrafficStats
        fields = ["id", "date", "bytes_in", "bytes_out", "total_mb"]
        read_only_fields = fields


# ─── Users (admin) ─────────────────────────────────────────────────────────

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = [
            "id", "username", "email", "role", "tariff_plan",
            "is_active", "is_blocked", "is_email_verified", "date_joined",
        ]
        read_only_fields = ["id", "date_joined", "is_email_verified"]


class UserUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ["role", "tariff_plan", "is_blocked"]


# ─── WAF Status (для nginx/engine) ─────────────────────────────────────────

class WAFStatusResponseSerializer(serializers.Serializer):
    domain = serializers.CharField()
    is_protected = serializers.BooleanField()
    target_ip = serializers.CharField(allow_null=True)


class WAFStatusQuerySerializer(serializers.Serializer):
    domain = serializers.CharField(required=True, help_text="Домен для проверки статуса WAF")


# ─── Admin messages ────────────────────────────────────────────────────────

class AdminMessageSerializer(serializers.ModelSerializer):
    username = serializers.CharField(source="user.username", read_only=True)

    class Meta:
        model = AdminMessage
        fields = ["id", "username", "message", "created_at", "is_read"]
        read_only_fields = fields


# ─── Monitoring ────────────────────────────────────────────────────────────

class MonitoringSerializer(serializers.Serializer):
    cpu_percent = serializers.FloatField()
    ram_total_gb = serializers.FloatField()
    ram_used_gb = serializers.FloatField()
    ram_percent = serializers.FloatField()
    disk_total_gb = serializers.FloatField()
    disk_used_gb = serializers.FloatField()
    disk_percent = serializers.FloatField()
    requests_per_minute = serializers.IntegerField()
    db_ok = serializers.BooleanField()


# ─── Log export ────────────────────────────────────────────────────────────

class LogExportSerializer(serializers.Serializer):
    name = serializers.CharField()
    url = serializers.CharField()


# ─── Auth & Profile ─────────────────────────────────────────────────────────

class RegisterSerializer(serializers.Serializer):
    username = serializers.CharField(max_length=100)
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)
    password2 = serializers.CharField(write_only=True)

    def validate(self, attrs):
        if attrs["password"] != attrs["password2"]:
            raise serializers.ValidationError("Пароли не совпадают.")
        return attrs


class LoginSerializer(serializers.Serializer):
    username = serializers.CharField()
    password = serializers.CharField(write_only=True)
    otp_token = serializers.CharField(required=False, allow_blank=True)


class TokenObtainSerializer(serializers.Serializer):
    username = serializers.CharField()
    password = serializers.CharField(write_only=True)
    otp_token = serializers.CharField(required=False, allow_blank=True)
    token_name = serializers.CharField(required=False, allow_blank=True, max_length=100)


class VerifyOtpSerializer(serializers.Serializer):
    otp_token = serializers.CharField()


class AdminMessageCreateSerializer(serializers.Serializer):
    message = serializers.CharField()


class PasswordChangeSerializer(serializers.Serializer):
    old_password = serializers.CharField(write_only=True, required=False)
    new_password = serializers.CharField(write_only=True)


class AvatarUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ["avatar"]
