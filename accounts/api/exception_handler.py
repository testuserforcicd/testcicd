"""
Глобальный обработчик исключений DRF.
Преобразует стандартные ошибки DRF в формат Problem Details (RFC 7807/9457).
"""
from rest_framework.views import exception_handler
from accounts.api.utils import problem_response


# Сопоставление кодов статуса DRF -> наши коды
_STATUS_DETAIL_MAP = {
    400: None,  # используем дефолт из каталога
    401: None,
    403: None,
    404: None,
    405: None,
    415: None,
    429: None,
    500: None,
}


def custom_exception_handler(exc, context):
    """
    Вызывается DRF при необработанном исключении.
    Возвращает Problem Details вместо стандартного JSON.
    """
    response = exception_handler(exc, context)

    if response is not None:
        status_code = response.status_code
        # Извлекаем detail из стандартного ответа DRF
        drf_detail = None
        if isinstance(response.data, dict):
            drf_detail = response.data.get("detail")
        elif isinstance(response.data, list) and response.data:
            drf_detail = str(response.data[0])

        detail_str = str(drf_detail) if drf_detail else None
        return problem_response(status_code, detail=detail_str)

    # Необработанное исключение Python → 500
    return problem_response(500)
