"""
WAF REST API views.
Все ошибки возвращаются в формате Problem Details (RFC 7807/9457).
"""
import datetime
import os
import uuid

import psutil
import qrcode
from django.conf import settings
from django.contrib.auth import authenticate, login, logout
from django.contrib.sessions.models import Session
from django.db import connection
from django.db.models import Count, Q
from django.core.mail import send_mail
from django.utils import timezone
from django_otp import user_has_device, login as otp_login
from django_otp.plugins.otp_totp.models import TOTPDevice
from drf_spectacular.utils import (
    OpenApiExample,
    OpenApiParameter,
    OpenApiResponse,
    extend_schema,
    extend_schema_view,
    inline_serializer,
)
from rest_framework import serializers as drf_serializers
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.parsers import FormParser, JSONParser, MultiPartParser
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.views import APIView

from accounts.api.permissions import IsAdminTokenAuthenticated, IsTokenAuthenticated
from accounts.api.serializers import (
    AccessTokenCreateSerializer,
    AccessTokenSerializer,
    AdminMessageSerializer,
    BannedIPSerializer,
    LogExportSerializer,
    MonitoringSerializer,
    PasswordChangeSerializer,
    ProblemDetailSerializer,
    ProtectedSiteCreateSerializer,
    ProtectedSiteSerializer,
    RegisterSerializer,
    RequestLogSerializer,
    LoginSerializer,
    TokenObtainSerializer,
    TrafficStatsSerializer,
    UserSerializer,
    UserUpdateSerializer,
    VerifyOtpSerializer,
    WAFRuleCreateSerializer,
    WAFRuleSerializer,
    WAFStatusQuerySerializer,
    WAFStatusResponseSerializer,
    AdminMessageCreateSerializer,
    AvatarUpdateSerializer,
)
from accounts.api.utils import problem_response
from accounts.models import (
    AccessToken,
    AdminMessage,
    AttackAttempt,
    BannedIP,
    ProtectedSite,
    RequestLog,
    TrafficStats,
    User,
    WAFRule,
)
from accounts.services import (
    get_monitoring_metrics,
    get_user_traffic_stats,
    get_waf_status_by_domain,
    list_available_exports,
    trigger_log_export,
)
import io
import base64

#  примеры ошибок

_ERR_401 = OpenApiResponse(
    response=ProblemDetailSerializer,
    description="Не авторизован — токен отсутствует или недействителен.",
    examples=[
        OpenApiExample(
            "401 Unauthorized",
            value={
                "requestId": "018f1a2b-3c4d-7e5f-8a9b-0c1d2e3f4a5b",
                "title": "Unauthorized",
                "detail": "Аутентификация не выполнена. Передайте токен в заголовке Authorization: Bearer <token>.",
                "timestamp": "2025-04-27T12:00:00Z",
            },
        )
    ],
)

_ERR_403 = OpenApiResponse(
    response=ProblemDetailSerializer,
    description="Запрещено — недостаточно прав.",
    examples=[
        OpenApiExample(
            "403 Forbidden",
            value={
                "requestId": "018f1a2b-3c4d-7e5f-8a9b-0c1d2e3f4a5c",
                "title": "Forbidden",
                "detail": "У вас нет прав для выполнения данного действия.",
                "timestamp": "2025-04-27T12:00:00Z",
            },
        )
    ],
)

_ERR_404 = OpenApiResponse(
    response=ProblemDetailSerializer,
    description="Ресурс не найден.",
    examples=[
        OpenApiExample(
            "404 Not Found",
            value={
                "requestId": "018f1a2b-3c4d-7e5f-8a9b-0c1d2e3f4a5d",
                "title": "Not Found",
                "detail": "Запрошенный ресурс не найден. Проверьте правильность URL.",
                "timestamp": "2025-04-27T12:00:00Z",
            },
        )
    ],
)

_ERR_400 = OpenApiResponse(
    response=ProblemDetailSerializer,
    description="Некорректный запрос.",
    examples=[
        OpenApiExample(
            "400 Bad Request",
            value={
                "requestId": "018f1a2b-3c4d-7e5f-8a9b-0c1d2e3f4a5e",
                "title": "Bad Request",
                "detail": "Запрос содержит некорректные данные. Проверьте тело запроса.",
                "timestamp": "2025-04-27T12:00:00Z",
            },
        )
    ],
)

_ERR_500 = OpenApiResponse(
    response=ProblemDetailSerializer,
    description="Внутренняя ошибка сервера.",
)

_ERR_405 = OpenApiResponse(
    response=ProblemDetailSerializer,
    description="HTTP-метод не поддерживается.",
)

_ERR_429 = OpenApiResponse(
    response=ProblemDetailSerializer,
    description="Слишком много запросов.",
)

_AUTH_HEADER_PARAM = OpenApiParameter(
    "Authorization",
    str,
    OpenApiParameter.HEADER,
    required=True,
    description="Bearer <access_token>",
)


# 0. Auth / Profile


@extend_schema(tags=["Auth"], request=RegisterSerializer, auth=[])
class RegisterView(APIView):
    authentication_classes = []
    permission_classes = []

    def post(self, request: Request) -> Response:
        ser = RegisterSerializer(data=request.data)
        if not ser.is_valid():
            return problem_response(400, detail=f"Ошибки валидации: {ser.errors}")
        try:
            user = User.objects.create_user(
                username=ser.validated_data["username"],
                email=ser.validated_data["email"],
                password=ser.validated_data["password"],
                role="user",
            )
            user.is_active = False
            user.email_verification_token = str(uuid.uuid4())
            user.save()
            verify_url = f"http://127.0.0.1:8000/api/v1/auth/verify-email/{user.email_verification_token}/"
            send_mail(
                "Подтверждение регистрации WAF",
                f"Перейдите по ссылке для подтверждения: {verify_url}",
                settings.EMAIL_HOST_USER,
                [user.email],
                fail_silently=False,
            )
            return Response({"detail": "Письмо для подтверждения отправлено.", "email": user.email}, status=201)
        except Exception:
            return problem_response(500)


@extend_schema(tags=["Auth"], auth=[])
class VerifyEmailView(APIView):
    authentication_classes = []
    permission_classes = []

    def get(self, request: Request, token: str) -> Response:
        try:
            user = User.objects.get(email_verification_token=token)
        except User.DoesNotExist:
            return problem_response(404, detail="Неверный токен подтверждения.")
        user.is_active = True
        user.is_email_verified = True
        user.email_verification_token = None
        user.save()
        return Response({"detail": "Email успешно подтверждён."})


@extend_schema(tags=["Auth"], request=LoginSerializer, auth=[])
class LoginView(APIView):
    authentication_classes = []
    permission_classes = []

    def post(self, request: Request) -> Response:
        ser = LoginSerializer(data=request.data)
        if not ser.is_valid():
            return problem_response(400, detail=f"Ошибки валидации: {ser.errors}")

        username = ser.validated_data["username"]
        password = ser.validated_data["password"]
        otp_token = ser.validated_data.get("otp_token", "")
        user = authenticate(request=request, username=username, password=password)
        if not user:
            return problem_response(401, detail="Неверный логин или пароль.")
        if user.is_blocked:
            return problem_response(403, detail="Пользователь заблокирован.")
        if not user.is_active:
            return problem_response(403, detail="Аккаунт не активирован. Подтвердите email.")

        device = TOTPDevice.objects.filter(user=user, confirmed=True).first()
        if device:
            if not otp_token:
                return Response({"detail": "Требуется 2FA-код.", "requires_2fa": True}, status=409)
            if not device.verify_token(otp_token):
                return problem_response(400, detail="Неверный 2FA-код.")

        login(request, user)
        if device:
            otp_login(request, device)
        return Response({"detail": "Вход выполнен успешно."})


@extend_schema(
    tags=["Auth"],
    summary="Получить Bearer-токен для API",
    description=(
        "Возвращает токен доступа для последующих запросов API.\n\n"
        "Использование:\n"
        "1) Вызовите этот endpoint с username/password (и otp_token, если включён 2FA).\n"
        "2) Скопируйте поле token из ответа.\n"
        "3) В Swagger нажмите Authorize и вставьте: Bearer <token>."
    ),
    request=TokenObtainSerializer,
    responses={200: AccessTokenSerializer, 400: _ERR_400, 401: _ERR_401, 403: _ERR_403},
    auth=[],
)
class TokenObtainView(APIView):
    authentication_classes = []
    permission_classes = []

    def post(self, request: Request) -> Response:
        ser = TokenObtainSerializer(data=request.data)
        if not ser.is_valid():
            return problem_response(400, detail=f"Ошибки валидации: {ser.errors}")

        username = ser.validated_data["username"]
        password = ser.validated_data["password"]
        otp_token = ser.validated_data.get("otp_token", "")
        token_name = ser.validated_data.get("token_name", "").strip() or "swagger-token"

        user = authenticate(request=request, username=username, password=password)
        if not user:
            return problem_response(401, detail="Неверный логин или пароль.")
        if user.is_blocked:
            return problem_response(403, detail="Пользователь заблокирован.")
        if not user.is_active:
            return problem_response(403, detail="Аккаунт не активирован. Подтвердите email.")

        device = TOTPDevice.objects.filter(user=user, confirmed=True).first()
        if device:
            if not otp_token:
                return Response({"detail": "Требуется 2FA-код.", "requires_2fa": True}, status=409)
            if not device.verify_token(otp_token):
                return problem_response(400, detail="Неверный 2FA-код.")

        token = AccessToken.objects.filter(user=user, name=token_name, is_active=True).order_by("-created_at").first()
        if not token:
            token = AccessToken.objects.create(user=user, name=token_name)
        return Response(AccessTokenSerializer(token).data)


@extend_schema(tags=["Auth"])
class LogoutView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request: Request) -> Response:
        logout(request)
        return Response({"detail": "Выход выполнен."})


@extend_schema(tags=["Auth"])
class Setup2FAView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request: Request) -> Response:
        device, _ = TOTPDevice.objects.get_or_create(user=request.user, name="default")
        otp_url = device.config_url
        img = qrcode.make(otp_url)
        buffer = io.BytesIO()
        img.save(buffer, format="PNG")
        qr_code_base64 = base64.b64encode(buffer.getvalue()).decode()
        return Response({"otp_url": otp_url, "qr_code_base64": qr_code_base64})


@extend_schema(tags=["Auth"], request=VerifyOtpSerializer)
class Verify2FASetupView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request: Request) -> Response:
        ser = VerifyOtpSerializer(data=request.data)
        if not ser.is_valid():
            return problem_response(400, detail=f"Ошибки валидации: {ser.errors}")
        device = TOTPDevice.objects.filter(user=request.user, name="default").first()
        if not device or not device.verify_token(ser.validated_data["otp_token"]):
            return problem_response(400, detail="Неверный код.")
        device.confirmed = True
        device.save()
        otp_login(request, device)
        return Response({"detail": "2FA успешно подключён."})


# 1. WAF Status  (для nginx/engine — без токена)


@extend_schema(
    tags=["WAF Engine"],
    summary="Получить статус защиты домена",
    description=(
        "Возвращает, защищён ли домен WAF и на какой IP проксировать трафик.\n\n"
        
    ),
    parameters=[
        OpenApiParameter("domain", str, OpenApiParameter.QUERY, required=True,
                         description="Домен для проверки, например: example.com"),
    ],
    responses={
        200: WAFStatusResponseSerializer,
        400: _ERR_400,
        405: _ERR_405,
        500: _ERR_500,
    },
    auth=[],
)
class WAFStatusView(APIView):
    authentication_classes = []
    permission_classes = []
    parser_classes = [JSONParser]

    def get(self, request: Request) -> Response:
        domain = request.query_params.get("domain", "").strip()
        if not domain:
            return problem_response(400, detail="Параметр 'domain' обязателен.")
        try:
            return Response(WAFStatusResponseSerializer(get_waf_status_by_domain(domain)).data, status=200)
        except ProtectedSite.DoesNotExist:
            return Response({"domain": domain, "is_protected": False, "target_ip": None})
        except Exception:
            return problem_response(500)

    def post(self, request: Request) -> Response:
        domain = request.data.get("domain", "").strip()
        if not domain:
            return problem_response(400, detail="Поле 'domain' обязательно.")
        try:
            return Response(WAFStatusResponseSerializer(get_waf_status_by_domain(domain)).data, status=200)
        except ProtectedSite.DoesNotExist:
            return Response({"domain": domain, "is_protected": False, "target_ip": None})
        except Exception:
            return problem_response(500)



# 2. Protected Sites


@extend_schema_view(
    get=extend_schema(
        tags=["Sites"],
        summary="Список защищённых сайтов",
        description="Возвращает все сайты текущего пользователя (по токену). Администратор видит все сайты.",
        parameters=[
            OpenApiParameter("domain", str, OpenApiParameter.QUERY, required=False,
                             description="Фильтр по домену (частичное совпадение), например: example.com"),
            OpenApiParameter("is_protected", bool, OpenApiParameter.QUERY, required=False,
                             description="Фильтр по статусу защиты: true / false"),
        ],
        responses={
            200: ProtectedSiteSerializer(many=True),
            401: _ERR_401,
            500: _ERR_500,
        },
    ),
    post=extend_schema(
        tags=["Sites"],
        summary="Добавить сайт под защиту",
        description=(
            "Регистрирует новый домен в WAF для текущего пользователя.\n\n"
            "После успешного создания в ответе вернётся **id** сайта — используйте его "
            "для фильтрации логов (`site_id`) и прямого доступа к ресурсу (`/api/v1/sites/{site_id}/`)."
        ),
        request=ProtectedSiteCreateSerializer,
        examples=[
            OpenApiExample(
                "Пример запроса",
                value={
                    "domain": "example.com",
                    "target_ip": "192.168.1.10",
                    "is_protected": True,
                    "traffic_limit_mb": 1024,
                },
                request_only=True,
            ),
            OpenApiExample(
                "Пример ответа",
                value={
                    "id": 42,
                    "domain": "example.com",
                    "target_ip": "192.168.1.10",
                    "is_protected": True,
                    "traffic_limit_mb": 1024,
                    "created_at": "2025-04-27T12:00:00Z",
                },
                response_only=True,
            ),
        ],
        responses={
            201: ProtectedSiteSerializer,
            400: _ERR_400,
            401: _ERR_401,
            500: _ERR_500,
        },
    ),
)
@extend_schema(parameters=[_AUTH_HEADER_PARAM])
class SiteListCreateView(APIView):
    permission_classes = [IsTokenAuthenticated]

    def get(self, request: Request) -> Response:
        user = request.token.user
        sites = (
            ProtectedSite.objects.all()
            if user.is_superuser
            else ProtectedSite.objects.filter(user=user)
        )
        domain = request.query_params.get("domain", "").strip()
        if domain:
            sites = sites.filter(domain__icontains=domain)
        is_protected = request.query_params.get("is_protected")
        if is_protected is not None:
            sites = sites.filter(is_protected=(is_protected.lower() == "true"))
        return Response(ProtectedSiteSerializer(sites, many=True).data)

    def post(self, request: Request) -> Response:
        ser = ProtectedSiteCreateSerializer(data=request.data)
        if not ser.is_valid():
            return problem_response(
                400,
                detail=f"Ошибки валидации: {ser.errors}",
            )
        try:
            site = ser.save(user=request.token.user)
            return Response(ProtectedSiteSerializer(site).data, status=201)
        except Exception:
            return problem_response(500)


@extend_schema_view(
    get=extend_schema(
        tags=["Sites"],
        summary="Детали сайта",
        responses={200: ProtectedSiteSerializer, 401: _ERR_401, 403: _ERR_403, 404: _ERR_404},
    ),
    patch=extend_schema(
        tags=["Sites"],
        summary="Обновить параметры сайта",
        request=ProtectedSiteCreateSerializer,
        responses={200: ProtectedSiteSerializer, 400: _ERR_400, 401: _ERR_401, 403: _ERR_403, 404: _ERR_404},
    ),
    delete=extend_schema(
        tags=["Sites"],
        summary="Удалить сайт из защиты",
        responses={
            200: inline_serializer("DeletedMsg", {"detail": drf_serializers.CharField()}),
            401: _ERR_401, 403: _ERR_403, 404: _ERR_404,
        },
    ),
)
@extend_schema(parameters=[_AUTH_HEADER_PARAM])
class SiteDetailView(APIView):
    permission_classes = [IsTokenAuthenticated]

    def _get_site(self, request: Request, site_id: int):
        try:
            site = ProtectedSite.objects.get(pk=site_id)
        except ProtectedSite.DoesNotExist:
            return None, problem_response(404)
        if site.user != request.token.user and not request.token.user.is_superuser:
            return None, problem_response(403)
        return site, None

    def get(self, request: Request, site_id: int) -> Response:
        site, err = self._get_site(request, site_id)
        if err:
            return err
        return Response(ProtectedSiteSerializer(site).data)

    def patch(self, request: Request, site_id: int) -> Response:
        site, err = self._get_site(request, site_id)
        if err:
            return err
        ser = ProtectedSiteCreateSerializer(site, data=request.data, partial=True)
        if not ser.is_valid():
            return problem_response(400, detail=f"Ошибки валидации: {ser.errors}")
        site = ser.save()
        return Response(ProtectedSiteSerializer(site).data)

    def delete(self, request: Request, site_id: int) -> Response:
        site, err = self._get_site(request, site_id)
        if err:
            return err
        site.delete()
        return Response({"detail": "Сайт удалён из защиты WAF."})



# 3. WAF Rules  (только администратор)


@extend_schema_view(
    get=extend_schema(
        tags=["Rules"],
        summary="Список правил WAF",
        responses={200: WAFRuleSerializer(many=True), 401: _ERR_401, 403: _ERR_403},
    ),
    post=extend_schema(
        tags=["Rules"],
        summary="Создать правило WAF",
        request=WAFRuleCreateSerializer,
        responses={201: WAFRuleSerializer, 400: _ERR_400, 401: _ERR_401, 403: _ERR_403},
    ),
)
@extend_schema(parameters=[_AUTH_HEADER_PARAM])
class RuleListCreateView(APIView):
    permission_classes = [IsAdminTokenAuthenticated]

    def get(self, request: Request) -> Response:
        rules = WAFRule.objects.all().order_by("-created_at")
        return Response(WAFRuleSerializer(rules, many=True).data)

    def post(self, request: Request) -> Response:
        ser = WAFRuleCreateSerializer(data=request.data)
        if not ser.is_valid():
            return problem_response(400, detail=f"Ошибки валидации: {ser.errors}")
        rule = ser.save()
        return Response(WAFRuleSerializer(rule).data, status=201)


@extend_schema_view(
    get=extend_schema(
        tags=["Rules"],
        summary="Получить правило WAF",
        responses={200: WAFRuleSerializer, 401: _ERR_401, 403: _ERR_403, 404: _ERR_404},
    ),
    patch=extend_schema(
        tags=["Rules"],
        summary="Обновить правило WAF",
        request=WAFRuleCreateSerializer,
        responses={200: WAFRuleSerializer, 400: _ERR_400, 401: _ERR_401, 403: _ERR_403, 404: _ERR_404},
    ),
    delete=extend_schema(
        tags=["Rules"],
        summary="Удалить правило WAF",
        responses={
            200: inline_serializer("RuleDeleted", {"detail": drf_serializers.CharField()}),
            401: _ERR_401, 403: _ERR_403, 404: _ERR_404,
        },
    ),
)
@extend_schema(parameters=[_AUTH_HEADER_PARAM])
class RuleDetailView(APIView):
    permission_classes = [IsAdminTokenAuthenticated]

    def _get_rule(self, rule_id: int):
        try:
            return WAFRule.objects.get(pk=rule_id), None
        except WAFRule.DoesNotExist:
            return None, problem_response(404, detail="Правило WAF не найдено.")

    def get(self, request: Request, rule_id: int) -> Response:
        rule, err = self._get_rule(rule_id)
        if err:
            return err
        return Response(WAFRuleSerializer(rule).data)

    def patch(self, request: Request, rule_id: int) -> Response:
        rule, err = self._get_rule(rule_id)
        if err:
            return err
        ser = WAFRuleCreateSerializer(rule, data=request.data, partial=True)
        if not ser.is_valid():
            return problem_response(400, detail=f"Ошибки валидации: {ser.errors}")
        return Response(WAFRuleSerializer(ser.save()).data)

    def delete(self, request: Request, rule_id: int) -> Response:
        rule, err = self._get_rule(rule_id)
        if err:
            return err
        rule.delete()
        return Response({"detail": "Правило удалено."})


@extend_schema(
    tags=["Rules"],
    summary="Переключить активность правила",
    responses={
        200: inline_serializer("RuleToggled", {
            "id": drf_serializers.IntegerField(),
            "is_active": drf_serializers.BooleanField(),
        }),
        401: _ERR_401, 403: _ERR_403, 404: _ERR_404,
    },
)
@extend_schema(parameters=[_AUTH_HEADER_PARAM])
class RuleToggleView(APIView):
    permission_classes = [IsAdminTokenAuthenticated]

    def post(self, request: Request, rule_id: int) -> Response:
        try:
            rule = WAFRule.objects.get(pk=rule_id)
        except WAFRule.DoesNotExist:
            return problem_response(404, detail="Правило WAF не найдено.")
        rule.is_active = not rule.is_active
        rule.save()
        return Response({"id": rule.id, "is_active": rule.is_active})



# 4. Request Logs


@extend_schema(
    tags=["Logs"],
    summary="Получить логи запросов",
    description=(
        "Администратор получает все логи. "
        "Обычный пользователь — только по своим сайтам. "
        "Результат ограничен 500 записями (последние по времени).\n\n"
        "**Как получить `site_id`:** выполните `GET /api/v1/sites/` — в ответе каждый сайт содержит поле `id`."
    ),
    parameters=[
        OpenApiParameter("blocked_only", bool, OpenApiParameter.QUERY,
                         description="Если true — только заблокированные запросы."),
        OpenApiParameter(
            "site_id", int, OpenApiParameter.QUERY,
            description=(
                "Фильтр по числовому ID сайта. "
                "ID можно получить через GET /api/v1/sites/."
            ),
        ),
        OpenApiParameter(
            "site_domain", str, OpenApiParameter.QUERY,
            description=(
                "Альтернатива site_id: фильтр по домену сайта (точное совпадение), "
                "например: example.com. Если указаны оба параметра, приоритет у site_id."
            ),
        ),
    ],
    responses={
        200: RequestLogSerializer(many=True),
        401: _ERR_401,
        500: _ERR_500,
    },
)
@extend_schema(parameters=[_AUTH_HEADER_PARAM])
class LogListView(APIView):
    permission_classes = [IsTokenAuthenticated]

    def get(self, request: Request) -> Response:
        user = request.token.user
        qs = RequestLog.objects.select_related("site", "rule_triggered").order_by("-timestamp")

        if not user.is_superuser:
            user_sites = ProtectedSite.objects.filter(user=user)
            qs = qs.filter(site__in=user_sites)

        if request.query_params.get("blocked_only") == "true":
            qs = qs.filter(was_blocked=True)

        site_id = request.query_params.get("site_id")
        if site_id:
            try:
                qs = qs.filter(site_id=int(site_id))
            except ValueError:
                return problem_response(400, detail="site_id должен быть целым числом.")
        else:
            site_domain = request.query_params.get("site_domain", "").strip()
            if site_domain:
                qs = qs.filter(site__domain=site_domain)

        return Response(RequestLogSerializer(qs[:500], many=True).data)


@extend_schema(
    tags=["Logs"],
    summary="Запустить экспорт логов в CSV",
    description="Готовый файл в /media/exports/.",
    responses={
        202: inline_serializer("ExportStarted", {"detail": drf_serializers.CharField()}),
        401: _ERR_401,
        500: _ERR_500,
    },
)
@extend_schema(parameters=[_AUTH_HEADER_PARAM])
class LogExportView(APIView):
    permission_classes = [IsTokenAuthenticated]

    def post(self, request: Request) -> Response:
        user = request.token.user
        try:
            trigger_log_export(user)
            return Response(
                {"detail": "Генерация CSV запущена. Файл  в /media/exports/."},
                status=202,
            )
        except Exception:
            return problem_response(500, detail="Не удалось поставить задачу в очередь Celery.")


@extend_schema(
    tags=["Logs"],
    summary="Список готовых CSV-экспортов",
    responses={200: LogExportSerializer(many=True), 401: _ERR_401},
)
@extend_schema(parameters=[_AUTH_HEADER_PARAM])
class LogExportListView(APIView):
    permission_classes = [IsTokenAuthenticated]

    def get(self, request: Request) -> Response:
        user = request.token.user
        return Response(LogExportSerializer(list_available_exports(user), many=True).data)


@extend_schema(
    tags=["Logs"],
    summary="Удалить CSV-экспорт",
    responses={
        200: inline_serializer("ExportDeleted", {"detail": drf_serializers.CharField()}),
        400: _ERR_400, 401: _ERR_401, 403: _ERR_403, 404: _ERR_404,
    },
)
@extend_schema(parameters=[_AUTH_HEADER_PARAM])
class LogExportDeleteView(APIView):
    permission_classes = [IsTokenAuthenticated]

    def delete(self, request: Request, filename: str) -> Response:
        if not filename.endswith(".csv") or "/" in filename or "\\" in filename:
            return problem_response(400, detail="Недопустимое имя файла.")
        user = request.token.user
        if not user.is_superuser and not filename.startswith(f"logs_{user.id}_"):
            return problem_response(403, detail="У вас нет прав на удаление этого файла.")
        file_path = os.path.join(settings.MEDIA_ROOT, "exports", filename)
        if not os.path.exists(file_path):
            return problem_response(404, detail="Файл экспорта не найден.")
        os.remove(file_path)
        return Response({"detail": f"Файл {filename} удалён."})



# 5. Access Tokens


@extend_schema_view(
    get=extend_schema(
        tags=["Tokens"],
        summary="Список токенов",
        description=" Администратор видит все токены.",
        responses={200: AccessTokenSerializer(many=True), 401: _ERR_401},
    ),
    post=extend_schema(
        tags=["Tokens"],
        summary="Создать токен доступа",
        request=AccessTokenCreateSerializer,
        responses={201: AccessTokenSerializer, 400: _ERR_400, 401: _ERR_401},
    ),
)
@extend_schema(parameters=[_AUTH_HEADER_PARAM])
class TokenListCreateView(APIView):
    permission_classes = [IsTokenAuthenticated]

    def get(self, request: Request) -> Response:
        user = request.token.user
        qs = (
            AccessToken.objects.all()
            if user.is_superuser
            else AccessToken.objects.filter(user=user)
        )
        return Response(AccessTokenSerializer(qs.order_by("-created_at"), many=True).data)

    def post(self, request: Request) -> Response:
        ser = AccessTokenCreateSerializer(data=request.data)
        if not ser.is_valid():
            return problem_response(400, detail=f"Ошибки валидации: {ser.errors}")
        token = ser.save(user=request.token.user)
        return Response(AccessTokenSerializer(token).data, status=201)


@extend_schema_view(
    patch=extend_schema(
        tags=["Tokens"],
        summary="Переключить активность токена (toggle)",
        description=" Администратор может управлять любыми токенами.",
        responses={
            200: inline_serializer("TokenToggled", {
                "id": drf_serializers.IntegerField(),
                "is_active": drf_serializers.BooleanField(),
            }),
            401: _ERR_401, 403: _ERR_403, 404: _ERR_404,
        },
    ),
    delete=extend_schema(
        tags=["Tokens"],
        summary="Удалить токен",
        description="Пользователь может удалять свои токены. Администратор — любые.",
        responses={
            200: inline_serializer("TokenDeleted", {"detail": drf_serializers.CharField()}),
            401: _ERR_401, 403: _ERR_403, 404: _ERR_404,
        },
    ),
)
@extend_schema(parameters=[_AUTH_HEADER_PARAM])
class TokenDetailView(APIView):
    permission_classes = [IsTokenAuthenticated]

    def _get_token(self, request: Request, token_id: int):
        try:
            token = AccessToken.objects.get(pk=token_id)
        except AccessToken.DoesNotExist:
            return None, problem_response(404, detail="Токен не найден.")
        # Обычный пользователь может работать только со своими токенами
        if not request.token.user.is_superuser and token.user != request.token.user:
            return None, problem_response(403, detail="У вас нет прав для управления этим токеном.")
        return token, None

    def patch(self, request: Request, token_id: int) -> Response:
        token, err = self._get_token(request, token_id)
        if err:
            return err
        token.is_active = not token.is_active
        token.save()
        return Response({"id": token.id, "is_active": token.is_active})

    def delete(self, request: Request, token_id: int) -> Response:
        token, err = self._get_token(request, token_id)
        if err:
            return err
        token.delete()
        return Response({"detail": "Токен удалён."})


@extend_schema(
    tags=["Tokens"],
    summary="Заблокировать IP для токена",
    request=inline_serializer("BlockIPBody", {"ip": drf_serializers.IPAddressField()}),
    responses={
        200: inline_serializer("BlockIPResult", {"detail": drf_serializers.CharField()}),
        400: _ERR_400, 401: _ERR_401, 403: _ERR_403, 404: _ERR_404,
    },
)
@extend_schema(parameters=[_AUTH_HEADER_PARAM])
class TokenBlockIPView(APIView):
    permission_classes = [IsAdminTokenAuthenticated]

    def post(self, request: Request, token_id: int) -> Response:
        try:
            token = AccessToken.objects.get(pk=token_id)
        except AccessToken.DoesNotExist:
            return problem_response(404, detail="Токен не найден.")
        ip = request.data.get("ip", "").strip()
        if not ip:
            return problem_response(400, detail="Поле 'ip' обязательно.")
        existing = token.get_blocked_ips_list()
        if ip in existing:
            return problem_response(400, detail=f"IP {ip} уже заблокирован для этого токена.")
        existing.append(ip)
        token.blocked_ips = ",".join(existing)
        token.save()
        return Response({"detail": f"IP {ip} заблокирован."})


@extend_schema(
    tags=["Tokens"],
    summary="Разблокировать IP для токена",
    request=inline_serializer("UnblockIPBody", {"ip": drf_serializers.IPAddressField()}),
    responses={
        200: inline_serializer("UnblockIPResult", {"detail": drf_serializers.CharField()}),
        400: _ERR_400, 401: _ERR_401, 403: _ERR_403, 404: _ERR_404,
    },
)
@extend_schema(parameters=[_AUTH_HEADER_PARAM])
class TokenUnblockIPView(APIView):
    permission_classes = [IsAdminTokenAuthenticated]

    def post(self, request: Request, token_id: int) -> Response:
        try:
            token = AccessToken.objects.get(pk=token_id)
        except AccessToken.DoesNotExist:
            return problem_response(404, detail="Токен не найден.")
        ip = request.data.get("ip", "").strip()
        if not ip:
            return problem_response(400, detail="Поле 'ip' обязательно.")
        existing = token.get_blocked_ips_list()
        if ip not in existing:
            return problem_response(400, detail=f"IP {ip} не найден в списке заблокированных.")
        existing.remove(ip)
        token.blocked_ips = ",".join(existing)
        token.save()
        return Response({"detail": f"IP {ip} разблокирован."})



# 6. Users  (только администратор)


@extend_schema(
    tags=["Users"],
    summary="Список пользователей",
    responses={200: UserSerializer(many=True), 401: _ERR_401, 403: _ERR_403},
)
@extend_schema(parameters=[_AUTH_HEADER_PARAM])
class UserListView(APIView):
    permission_classes = [IsAdminTokenAuthenticated]

    def get(self, request: Request) -> Response:
        users = User.objects.all().order_by("username")
        return Response(UserSerializer(users, many=True).data)


@extend_schema_view(
    get=extend_schema(
        tags=["Users"],
        summary="Детали пользователя",
        responses={200: UserSerializer, 401: _ERR_401, 403: _ERR_403, 404: _ERR_404},
    ),
    patch=extend_schema(
        tags=["Users"],
        summary="Изменить роль / тариф / блокировку",
        request=UserUpdateSerializer,
        responses={200: UserSerializer, 400: _ERR_400, 401: _ERR_401, 403: _ERR_403, 404: _ERR_404},
    ),
)
@extend_schema(parameters=[_AUTH_HEADER_PARAM])
class UserDetailView(APIView):
    permission_classes = [IsAdminTokenAuthenticated]

    def _get_user(self, user_id: int):
        try:
            return User.objects.get(pk=user_id), None
        except User.DoesNotExist:
            return None, problem_response(404, detail="Пользователь не найден.")

    def get(self, request: Request, user_id: int) -> Response:
        user, err = self._get_user(user_id)
        if err:
            return err
        return Response(UserSerializer(user).data)

    def patch(self, request: Request, user_id: int) -> Response:
        user, err = self._get_user(user_id)
        if err:
            return err
        if user.pk == request.token.user.pk and request.data.get("is_blocked"):
            return problem_response(403, detail="Нельзя заблокировать собственный аккаунт.")
        ser = UserUpdateSerializer(user, data=request.data, partial=True)
        if not ser.is_valid():
            return problem_response(400, detail=f"Ошибки валидации: {ser.errors}")
        user = ser.save()
        if "is_blocked" in request.data:
            user.is_active = not user.is_blocked
            user.save()
        return Response(UserSerializer(user).data)



# 7. Monitoring  (только администратор)


@extend_schema(
    tags=["Monitoring"],
    summary="Метрики системы",
    description="CPU, RAM, Disk, RPS за последнюю минуту, статус БД.",
    responses={
        200: MonitoringSerializer,
        401: _ERR_401,
        403: _ERR_403,
        500: _ERR_500,
    },
)
@extend_schema(parameters=[_AUTH_HEADER_PARAM])
class MonitoringView(APIView):
    permission_classes = [IsAdminTokenAuthenticated]

    def get(self, request: Request) -> Response:
        try:
            data = get_monitoring_metrics()
            return Response(MonitoringSerializer(data).data)
        except Exception:
            return problem_response(500)



# 8. Banned IPs


@extend_schema(
    tags=["Security"],
    summary="Список забаненных IP",
    description=(
        "Возвращает список заблокированных IP-адресов.\n\n"
        "**Как получить `site_id`:** выполните `GET /api/v1/sites/` — в ответе каждый сайт содержит поле `id`."
    ),
    parameters=[
        OpenApiParameter(
            "site_id", int, OpenApiParameter.QUERY,
            description="Фильтр по числовому ID сайта (получить через GET /api/v1/sites/).",
        ),
        OpenApiParameter("active_only", bool, OpenApiParameter.QUERY,
                         description="Если true — только активные баны."),
    ],
    responses={
        200: BannedIPSerializer(many=True),
        401: _ERR_401,
        403: _ERR_403,
    },
)
@extend_schema(parameters=[_AUTH_HEADER_PARAM])
class BannedIPListView(APIView):
    permission_classes = [IsAdminTokenAuthenticated]

    def get(self, request: Request) -> Response:
        qs = BannedIP.objects.select_related("site").order_by("-banned_at")
        site_id = request.query_params.get("site_id")
        if site_id:
            try:
                qs = qs.filter(site_id=int(site_id))
            except ValueError:
                return problem_response(400, detail="site_id должен быть целым числом.")
        if request.query_params.get("active_only") == "true":
            qs = qs.filter(is_active=True)
        return Response(BannedIPSerializer(qs, many=True).data)



# 9. Admin Messages


@extend_schema(
    tags=["Admin"],
    summary="Сообщения пользователей администратору",
    responses={200: AdminMessageSerializer(many=True), 401: _ERR_401, 403: _ERR_403},
)
@extend_schema(parameters=[_AUTH_HEADER_PARAM])
class AdminMessageListView(APIView):
    permission_classes = [IsAdminTokenAuthenticated]

    def get(self, request: Request) -> Response:
        msgs = AdminMessage.objects.select_related("user").order_by("-created_at")[:50]
        return Response(AdminMessageSerializer(msgs, many=True).data)


@extend_schema(
    tags=["Admin"],
    summary="Отметить сообщение как прочитанное",
    responses={
        200: inline_serializer("MsgRead", {"detail": drf_serializers.CharField()}),
        401: _ERR_401, 403: _ERR_403, 404: _ERR_404,
    },
)
@extend_schema(parameters=[_AUTH_HEADER_PARAM])
class AdminMessageReadView(APIView):
    permission_classes = [IsAdminTokenAuthenticated]

    def post(self, request: Request, msg_id: int) -> Response:
        try:
            msg = AdminMessage.objects.get(pk=msg_id)
        except AdminMessage.DoesNotExist:
            return problem_response(404, detail="Сообщение не найдено.")
        msg.is_read = True
        msg.save()
        return Response({"detail": "Сообщение отмечено как прочитанное."})


@extend_schema(
    tags=["Admin"],
    summary="Отправить сообщение администратору",
    request=AdminMessageCreateSerializer,
)
@extend_schema(parameters=[_AUTH_HEADER_PARAM])
class AdminMessageCreateView(APIView):
    permission_classes = [IsTokenAuthenticated]

    def post(self, request: Request) -> Response:
        ser = AdminMessageCreateSerializer(data=request.data)
        if not ser.is_valid():
            return problem_response(400, detail=f"Ошибки валидации: {ser.errors}")
        text = ser.validated_data["message"].strip()
        if not text:
            return problem_response(400, detail="Сообщение не может быть пустым.")
        AdminMessage.objects.create(user=request.token.user, message=text)
        return Response({"detail": "Сообщение отправлено администратору."}, status=201)



# 10. Sessions  (только администратор)


@extend_schema(
    tags=["Admin"],
    summary="Список активных сессий",
    responses={
        200: inline_serializer("SessionList", {
            "session_key": drf_serializers.CharField(),
            "user_id": drf_serializers.IntegerField(allow_null=True),
            "username": drf_serializers.CharField(allow_null=True),
            "expires": drf_serializers.DateTimeField(),
        }, many=True),
        401: _ERR_401,
        403: _ERR_403,
    },
)
@extend_schema(parameters=[_AUTH_HEADER_PARAM])
class SessionListView(APIView):
    permission_classes = [IsAdminTokenAuthenticated]

    def get(self, request: Request) -> Response:
        now = timezone.now()
        sessions = Session.objects.filter(expire_date__gte=now)
        result = []
        for s in sessions:
            data = s.get_decoded()
            uid = data.get("_auth_user_id")
            try:
                u = User.objects.get(pk=uid)
                uname = u.username
            except (User.DoesNotExist, TypeError):
                u = None
                uname = None
            result.append({
                "session_key": s.session_key,
                "user_id": int(uid) if uid else None,
                "username": uname,
                "expires": s.expire_date,
            })
        return Response(result)


@extend_schema(
    tags=["Admin"],
    summary="Завершить сессию",
    responses={
        200: inline_serializer("SessionDeleted", {"detail": drf_serializers.CharField()}),
        400: _ERR_400, 401: _ERR_401, 403: _ERR_403, 404: _ERR_404,
    },
)
@extend_schema(parameters=[_AUTH_HEADER_PARAM])
class SessionDeleteView(APIView):
    permission_classes = [IsAdminTokenAuthenticated]

    def delete(self, request: Request, session_key: str) -> Response:
        try:
            session = Session.objects.get(session_key=session_key)
        except Session.DoesNotExist:
            return problem_response(404, detail="Сессия не найдена.")
        session.delete()
        return Response({"detail": "Сессия завершена."})



# 11. Statistics 


@extend_schema(
    tags=["Stats"],
    summary="Сводная статистика по трафику и атакам",
    responses={
        200: inline_serializer("UserStats", {
            "total_requests": drf_serializers.IntegerField(),
            "blocked_requests": drf_serializers.IntegerField(),
            "sqli_attacks": drf_serializers.IntegerField(),
            "xss_attacks": drf_serializers.IntegerField(),
        }),
        401: _ERR_401,
    },
)
@extend_schema(parameters=[_AUTH_HEADER_PARAM])
class StatsView(APIView):
    permission_classes = [IsTokenAuthenticated]

    def get(self, request: Request) -> Response:
        return Response(get_user_traffic_stats(request.token.user))


@extend_schema(
    tags=["Admin"],
    summary="Сменить пароль администратора",
    request=PasswordChangeSerializer,
)
@extend_schema(parameters=[_AUTH_HEADER_PARAM])
class AdminPasswordChangeView(APIView):
    permission_classes = [IsAdminTokenAuthenticated]

    def post(self, request: Request) -> Response:
        ser = PasswordChangeSerializer(data=request.data)
        if not ser.is_valid():
            return problem_response(400, detail=f"Ошибки валидации: {ser.errors}")
        user = request.token.user
        old_password = ser.validated_data.get("old_password")
        if old_password and not user.check_password(old_password):
            return problem_response(400, detail="Старый пароль введён неверно.")
        user.set_password(ser.validated_data["new_password"])
        user.save()
        return Response({"detail": "Пароль успешно изменён."})


@extend_schema(
    tags=["Users"],
    summary="Сменить пароль текущего пользователя",
    request=PasswordChangeSerializer,
)
@extend_schema(parameters=[_AUTH_HEADER_PARAM])
class UserPasswordChangeView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request: Request) -> Response:
        ser = PasswordChangeSerializer(data=request.data)
        if not ser.is_valid():
            return problem_response(400, detail=f"Ошибки валидации: {ser.errors}")
        user = request.user
        old_password = ser.validated_data.get("old_password")
        if not old_password:
            return problem_response(400, detail="Поле old_password обязательно.")
        if not user.check_password(old_password):
            return problem_response(400, detail="Старый пароль введён неверно.")
        user.set_password(ser.validated_data["new_password"])
        user.save()
        return Response({"detail": "Пароль успешно изменён."})


@extend_schema(
    tags=["Admin"],
    summary="Обновить аватар администратора",
    request=AvatarUpdateSerializer,
)
@extend_schema(parameters=[_AUTH_HEADER_PARAM])
class AdminAvatarView(APIView):
    permission_classes = [IsAdminTokenAuthenticated]
    parser_classes = [MultiPartParser, FormParser]

    def patch(self, request: Request) -> Response:
        user = request.token.user
        ser = AvatarUpdateSerializer(user, data=request.data, partial=True)
        if not ser.is_valid():
            return problem_response(400, detail=f"Ошибки валидации: {ser.errors}")
        ser.save()
        return Response({"detail": "Аватар обновлён.", "avatar": user.avatar.url if user.avatar else None})


@extend_schema(
    tags=["Users"],
    summary="Обновить аватар текущего пользователя",
    request=AvatarUpdateSerializer,
)
@extend_schema(parameters=[_AUTH_HEADER_PARAM])
class UserAvatarView(APIView):
    permission_classes = [IsAuthenticated]
    parser_classes = [MultiPartParser, FormParser]

    def patch(self, request: Request) -> Response:
        user = request.user
        ser = AvatarUpdateSerializer(user, data=request.data, partial=True)
        if not ser.is_valid():
            return problem_response(400, detail=f"Ошибки валидации: {ser.errors}")
        ser.save()
        return Response({"detail": "Аватар обновлён.", "avatar": user.avatar.url if user.avatar else None})
