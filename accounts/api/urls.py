"""
URL-маршруты API v1.
Все маршруты монтируются с префиксом /api/v1/ в главном urls.py.
"""
from django.urls import path
from accounts.api.views import (
    # Auth
    RegisterView,
    VerifyEmailView,
    LoginView,
    TokenObtainView,
    LogoutView,
    Setup2FAView,
    Verify2FASetupView,
    # WAF Engine
    WAFStatusView,
    # Sites
    SiteListCreateView,
    SiteDetailView,
    # Rules
    RuleListCreateView,
    RuleDetailView,
    RuleToggleView,
    # Logs
    LogListView,
    LogExportView,
    LogExportListView,
    LogExportDeleteView,
    # Tokens
    TokenListCreateView,
    TokenDetailView,
    TokenBlockIPView,
    TokenUnblockIPView,
    # Users
    UserListView,
    UserDetailView,
    # Monitoring
    MonitoringView,
    # Security
    BannedIPListView,
    # Admin
    AdminMessageListView,
    AdminMessageReadView,
    SessionListView,
    SessionDeleteView,
    # Stats
    StatsView,
    AdminPasswordChangeView,
    AdminAvatarView,
    AdminMessageCreateView,
    UserPasswordChangeView,
    UserAvatarView,
)

urlpatterns = [
    # ── Auth ────────────────────────────────────────────────────────────────
    path("auth/register/", RegisterView.as_view(), name="api_auth_register"),
    path("auth/verify-email/<str:token>/", VerifyEmailView.as_view(), name="api_auth_verify_email"),
    path("auth/login/", LoginView.as_view(), name="api_auth_login"),
    path("auth/token/", TokenObtainView.as_view(), name="api_auth_token"),
    path("auth/logout/", LogoutView.as_view(), name="api_auth_logout"),
    path("auth/2fa/setup/", Setup2FAView.as_view(), name="api_auth_2fa_setup"),
    path("auth/2fa/verify/", Verify2FASetupView.as_view(), name="api_auth_2fa_verify"),

    # ── WAF Engine ──────────────────────────────────────────────────────────
    path("waf-status/", WAFStatusView.as_view(), name="api_waf_status"),

    # ── Sites ───────────────────────────────────────────────────────────────
    path("sites/", SiteListCreateView.as_view(), name="api_sites"),
    path("sites/<int:site_id>/", SiteDetailView.as_view(), name="api_site_detail"),

    # ── WAF Rules ────────────────────────────────────────────────────────────
    path("rules/", RuleListCreateView.as_view(), name="api_rules"),
    path("rules/<int:rule_id>/", RuleDetailView.as_view(), name="api_rule_detail"),
    path("rules/<int:rule_id>/toggle/", RuleToggleView.as_view(), name="api_rule_toggle"),

    # ── Logs ─────────────────────────────────────────────────────────────────
    path("logs/", LogListView.as_view(), name="api_logs"),
    path("logs/export/", LogExportView.as_view(), name="api_log_export"),
    path("logs/exports/", LogExportListView.as_view(), name="api_log_export_list"),
    path("logs/exports/<str:filename>/", LogExportDeleteView.as_view(), name="api_log_export_delete"),

    # ── Access Tokens ─────────────────────────────────────────────────────────
    path("tokens/", TokenListCreateView.as_view(), name="api_tokens"),
    path("tokens/<int:token_id>/", TokenDetailView.as_view(), name="api_token_detail"),
    path("tokens/<int:token_id>/block-ip/", TokenBlockIPView.as_view(), name="api_token_block_ip"),
    path("tokens/<int:token_id>/unblock-ip/", TokenUnblockIPView.as_view(), name="api_token_unblock_ip"),

    # ── Users ─────────────────────────────────────────────────────────────────
    path("users/", UserListView.as_view(), name="api_users"),
    path("users/<int:user_id>/", UserDetailView.as_view(), name="api_user_detail"),
    path("users/me/password/change/", UserPasswordChangeView.as_view(), name="api_user_password_change"),
    path("users/me/avatar/", UserAvatarView.as_view(), name="api_user_avatar"),

    # ── Monitoring ────────────────────────────────────────────────────────────
    path("monitoring/", MonitoringView.as_view(), name="api_monitoring"),

    # ── Security ──────────────────────────────────────────────────────────────
    path("banned-ips/", BannedIPListView.as_view(), name="api_banned_ips"),

    # ── Admin ─────────────────────────────────────────────────────────────────
    path("admin/messages/send/", AdminMessageCreateView.as_view(), name="api_admin_message_send"),
    path("admin/messages/", AdminMessageListView.as_view(), name="api_admin_messages"),
    path("admin/messages/<int:msg_id>/read/", AdminMessageReadView.as_view(), name="api_admin_msg_read"),
    path("admin/sessions/", SessionListView.as_view(), name="api_sessions"),
    path("admin/sessions/<str:session_key>/", SessionDeleteView.as_view(), name="api_session_delete"),
    path("admin/password/change/", AdminPasswordChangeView.as_view(), name="api_admin_password_change"),
    path("admin/avatar/", AdminAvatarView.as_view(), name="api_admin_avatar"),

    # ── Stats ─────────────────────────────────────────────────────────────────
    path("stats/", StatsView.as_view(), name="api_stats"),
]
