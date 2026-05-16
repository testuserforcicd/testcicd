from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from .models import User, AccessToken, ProtectedSite, WAFRule, RequestLog


@admin.register(User)
class CustomUserAdmin(UserAdmin):
    model = User
    list_display = ['username', 'email', 'role', 'is_email_verified', 'is_blocked', 'is_active', 'is_staff']
    list_filter = ['role', 'is_blocked', 'is_active', 'is_staff']
    fieldsets = UserAdmin.fieldsets + (
        ('WAF', {'fields': ('role', 'is_email_verified', 'email_verification_token', 'avatar', 'is_blocked')}),
    )


@admin.register(AccessToken)
class AccessTokenAdmin(admin.ModelAdmin):
    list_display = ['name', 'user', 'token', 'is_active', 'created_at']
    list_filter = ['is_active']


@admin.register(ProtectedSite)
class ProtectedSiteAdmin(admin.ModelAdmin):
    list_display = ['domain', 'user', 'is_protected', 'traffic_limit_mb', 'created_at']
    list_filter = ['is_protected']


@admin.register(WAFRule)
class WAFRuleAdmin(admin.ModelAdmin):
    list_display = ['name', 'severity', 'action', 'is_active', 'updated_at']
    list_filter = ['severity', 'action', 'is_active']


@admin.register(RequestLog)
class RequestLogAdmin(admin.ModelAdmin):
    list_display = ['ip_address', 'method', 'path', 'status_code', 'was_blocked', 'timestamp']
    list_filter = ['was_blocked', 'method']
    readonly_fields = ['timestamp']
