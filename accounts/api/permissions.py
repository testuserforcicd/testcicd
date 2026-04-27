from rest_framework.permissions import BasePermission
from accounts.models import AccessToken


class IsTokenAuthenticated(BasePermission):
    """
    Разрешение на основе токена доступа.
    Ожидает заголовок: Authorization: Bearer <token>
    """
    message = "Недействительный или отсутствующий токен доступа."

    def has_permission(self, request, view):
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return False
        token_value = auth_header.split(" ", 1)[1].strip()
        try:
            token = AccessToken.objects.get(token=token_value, is_active=True)
        except AccessToken.DoesNotExist:
            return False
        # Проверяем блокировку IP
        client_ip = get_client_ip(request)
        if client_ip in token.get_blocked_ips_list():
            return False
        request.token = token
        return True


class IsAdminTokenAuthenticated(IsTokenAuthenticated):
    """
    Разрешение: токен + пользователь является суперпользователем.
    """
    message = "Требуются права администратора."

    def has_permission(self, request, view):
        if not super().has_permission(request, view):
            return False
        return request.token.user.is_superuser


class IsTokenOrSessionAuthenticated(IsTokenAuthenticated):
    """
    Разрешение: либо Bearer-токен, либо обычная Django-сессия.
    Удобно для серверных HTML-страниц, которые вызывают API через fetch.
    """

    def has_permission(self, request, view):
        if super().has_permission(request, view):
            return True
        return bool(getattr(request, "user", None) and request.user.is_authenticated)


def get_client_ip(request) -> str:
    x_forwarded = request.META.get("HTTP_X_FORWARDED_FOR")
    if x_forwarded:
        return x_forwarded.split(",")[0].strip()
    return request.META.get("REMOTE_ADDR", "")
