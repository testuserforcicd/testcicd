from .request_types import ParsedRequest, InspectionResult
from .signatures import sqli, xss, traversal
from .heuristics import anomalies
from .db_rules import get_active_rules_from_db


def analyze_request(request: ParsedRequest) -> InspectionResult:
    """
    Главная точка входа для сервера
    """
    
    # сигнатурные проверки (статически зашитые)
    is_sqli, details = sqli.check(request)
    if is_sqli:
        return InspectionResult(is_safe=False, action='block', reason='SQL_INJECTION', details=details)
        
    is_xss, details = xss.check(request)
    if is_xss:
        return InspectionResult(is_safe=False, action='block', reason='XSS', details=details)
        
    is_traversal, details = traversal.check(request)
    if is_traversal:
        return InspectionResult(is_safe=False, action='block', reason='PATH_TRAVERSAL', details=details)

    # эвристические проверки
    is_anomaly, details = anomalies.check(request)
    if is_anomaly:
        return InspectionResult(is_safe=False, action='block', reason='ANOMALY', details=details)

    db_rules = get_active_rules_from_db()
    if db_rules:
        # Собираем все строки для проверки
        strings_to_check = []
        
        # Query параметры
        for key, value in request.query_params.items():
            if isinstance(value, str):
                strings_to_check.append(('query', key, value))
        
        # Заголовки
        for name, value in request.headers.items():
            if isinstance(value, str):
                strings_to_check.append(('header', name, value))
        
        # Тело запроса
        if isinstance(request.body, str):
            strings_to_check.append(('body', None, request.body))
        elif isinstance(request.body, dict):
            for key, value in request.body.items():
                if isinstance(value, str):
                    strings_to_check.append(('body', key, value))
        
        # Применяем правила
        for rule in db_rules:
            for source, key, value in strings_to_check:
                if rule['pattern'].search(value):
                    return InspectionResult(
                        is_safe=False, 
                        action=rule['action'],  # 'block', 'allow', или 'log'
                        reason=f"DB_RULE_{rule['name']}",
                        details=f"Matched in {source}" + (f" '{key}'" if key else "")
                    )

    return InspectionResult(is_safe=True, action='allow')
