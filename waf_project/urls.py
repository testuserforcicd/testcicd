from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static
from drf_spectacular.views import SpectacularAPIView, SpectacularSwaggerView, SpectacularRedocView
from accounts.views import (
    register_view, verify_email, dashboard_view,
    setup_2fa, verify_2fa_setup, verify_otp_login,
    logout_view,
    # admin panel
    admin_panel, admin_tokens, admin_token_toggle, admin_token_delete,
    contact_admin, admin_mark_message_read,
    admin_token_block_ip, admin_token_unblock_ip,
    admin_users, admin_user_detail, admin_change_password,
    admin_sessions, admin_avatar,
    # rules
    admin_rules, admin_rule_edit, admin_rule_delete, admin_rule_toggle,
    # monitoring & logs
    admin_monitoring, admin_logs,
    user_download_logs, admin_download_logs, delete_export,
)

urlpatterns = [
    path('admin/', admin.site.urls),
    path('register/', register_view, name='register'),
    path('verify/<str:token>/', verify_email, name='verify_email'),
    path('login/', __import__('django.contrib.auth.views', fromlist=['LoginView']).LoginView.as_view(
        template_name='accounts/login.html'
    ), name='login'),
    path('logout/', logout_view, name='logout'),
    path('dashboard/', dashboard_view, name='dashboard'),
    path('dashboard/contact/', contact_admin, name='contact_admin'),
    path('dashboard/logs/download/', user_download_logs, name='user_download_logs'),
    path('accounts/', include('allauth.urls')),
    path('2fa/setup/', setup_2fa, name='setup_2fa'),
    path('2fa/verify/', verify_2fa_setup, name='verify_2fa_setup'),
    path('verify-2fa/', verify_otp_login, name='verify_otp_login'),

    # Admin panel
    path('panel/', admin_panel, name='admin_panel'),
    path('panel/tokens/', admin_tokens, name='admin_tokens'),
    path('panel/tokens/<int:token_id>/toggle/', admin_token_toggle, name='admin_token_toggle'),
    path('panel/tokens/<int:token_id>/delete/', admin_token_delete, name='admin_token_delete'),
    path('panel/tokens/<int:token_id>/block-ip/', admin_token_block_ip, name='admin_token_block_ip'),
    path('panel/tokens/<int:token_id>/unblock-ip/', admin_token_unblock_ip, name='admin_token_unblock_ip'),
    path('panel/users/', admin_users, name='admin_users'),
    path('panel/users/<int:user_id>/', admin_user_detail, name='admin_user_detail'),
    path('panel/password/', admin_change_password, name='admin_change_password'),
    path('panel/sessions/', admin_sessions, name='admin_sessions'),
    path('panel/avatar/', admin_avatar, name='admin_avatar'),
    path('panel/rules/', admin_rules, name='admin_rules'),
    path('panel/rules/<int:rule_id>/edit/', admin_rule_edit, name='admin_rule_edit'),
    path('panel/rules/<int:rule_id>/delete/', admin_rule_delete, name='admin_rule_delete'),
    path('panel/rules/<int:rule_id>/toggle/', admin_rule_toggle, name='admin_rule_toggle'),
    path('panel/monitoring/', admin_monitoring, name='admin_monitoring'),
    path('panel/logs/', admin_logs, name='admin_logs'),
    path('panel/logs/download/', admin_download_logs, name='admin_download_logs'),
    path('panel/logs/export/<str:filename>/delete/', delete_export, name='delete_export'),
    path('panel/messages/<int:msg_id>/read/', admin_mark_message_read, name='admin_mark_message_read'),

    #  REST API v1
    path('api/v1/', include('accounts.api.urls')),

    #  OpenAPI Schema & Swagger UI
    path('api/schema/', SpectacularAPIView.as_view(), name='schema'),
    path('api/docs/', SpectacularSwaggerView.as_view(url_name='schema'), name='swagger-ui'),
    path('api/redoc/', SpectacularRedocView.as_view(url_name='schema'), name='redoc'),
] + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
