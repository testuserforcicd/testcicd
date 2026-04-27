"""
Утилиты для API:
  - generate_uuid7()       — UUIDv7 (time-based, RFC 9562)
  - problem_response(...)  — Problem Details (RFC 7807/9457)
"""
import time
import os
import datetime
from rest_framework.response import Response


# ─────────────────────────────────────────
# UUIDv7  (RFC 9562)
# Формат: 48 бит Unix-мс | 4 бит ver=7 | 12 бит rand_a | 2 бит var | 62 бит rand_b
# ─────────────────────────────────────────

def generate_uuid7() -> str:
    ms = int(time.time() * 1000)          # Unix timestamp в миллисекундах
    rand_a = int.from_bytes(os.urandom(2), "big") & 0x0FFF  # 12 бит
    rand_b = int.from_bytes(os.urandom(8), "big") & 0x3FFFFFFFFFFFFFFF  # 62 бит

    uuid_int = (
        (ms & 0xFFFFFFFFFFFF) << 80       # bits 127-80: 48-bit timestamp
        | 0x7 << 76                        # bits 79-76:  version = 7
        | rand_a << 64                     # bits 75-64:  rand_a
        | 0b10 << 62                       # bits 63-62:  variant = 10
        | rand_b                           # bits 61-0:   rand_b
    )

    hex_str = f"{uuid_int:032x}"
    return f"{hex_str[0:8]}-{hex_str[8:12]}-{hex_str[12:16]}-{hex_str[16:20]}-{hex_str[20:32]}"


# ─────────────────────────────────────────
# Problem Details  (RFC 7807 / 9457)
# ─────────────────────────────────────────

# Стандартные заголовки и детали для каждого HTTP-кода
PROBLEM_CATALOG: dict[int, tuple[str, str]] = {
    # 4xx
    400: (
        "Bad Request",
        "Запрос содержит некорректные данные. Проверьте тело запроса и повторите попытку.",
    ),
    401: (
        "Unauthorized",
        "Аутентификация не выполнена. Передайте токен в заголовке Authorization: Bearer <token>.",
    ),
    403: (
        "Forbidden",
        "У вас нет прав для выполнения данного действия. Обратитесь к администратору.",
    ),
    404: (
        "Not Found",
        "Запрошенный ресурс не найден. Проверьте правильность URL.",
    ),
    405: (
        "Method Not Allowed",
        "HTTP-метод не поддерживается для данного ресурса. Смотрите заголовок Allow.",
    ),
    413: (
        "Payload Too Large",
        "Тело запроса превышает допустимый размер. Уменьшите объём передаваемых данных.",
    ),
    414: (
        "URI Too Long",
        "URI запроса слишком длинный. Сократите путь или строку параметров.",
    ),
    415: (
        "Unsupported Media Type",
        "Тип контента не поддерживается. Используйте Content-Type: application/json.",
    ),
    418: (
        "I'm a teapot",
        "Сервер — чайник и не умеет варить кофе (RFC 2324). Запрос отклонён намеренно.",
    ),
    429: (
        "Too Many Requests",
        "Превышен лимит запросов. Подождите и повторите позже. Смотрите заголовок Retry-After.",
    ),
    # 5xx
    500: (
        "Internal Server Error",
        "Внутренняя ошибка сервера. Обратитесь в службу поддержки с указанием requestId.",
    ),
    501: (
        "Not Implemented",
        "Запрошенная функциональность ещё не реализована.",
    ),
    502: (
        "Bad Gateway",
        "Шлюз получил некорректный ответ от вышестоящего сервера.",
    ),
    503: (
        "Service Unavailable",
        "Сервис временно недоступен. Попробуйте позже.",
    ),
    504: (
        "Gateway Timeout",
        "Вышестоящий сервер не ответил вовремя. Попробуйте позже.",
    ),
}


def problem_response(
    status: int,
    *,
    detail: str | None = None,
    title: str | None = None,
    extra: dict | None = None,
) -> Response:
    """
    Возвращает DRF Response в формате Problem Details (RFC 7807/9457).

    Параметры:
        status  — HTTP-код ответа
        detail  — переопределяет стандартное описание ошибки
        title   — переопределяет стандартный заголовок
        extra   — дополнительные поля (добавляются в тело ответа)
    """
    default_title, default_detail = PROBLEM_CATALOG.get(
        status, ("Error", "Произошла ошибка.")
    )

    body: dict = {
        "requestId": generate_uuid7(),
        "title": title or default_title,
        "detail": detail or default_detail,
        "timestamp": datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    if extra:
        body.update(extra)

    return Response(body, status=status, content_type="application/problem+json")
