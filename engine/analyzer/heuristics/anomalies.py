from typing import Tuple, Optional
from ..request_types import ParsedRequest

MAX_PARAM_LENGTH = 250         # Максимальная длина одного параметра в URL
MAX_HEADER_LENGTH = 1024       # Максимальная длина заголовка
SPECIAL_CHAR_RATIO = 0.35      # Если больше 35% текста — спецсимволы, это подозрительно
MIN_LEN_FOR_RATIO = 20         # Проверять плотность символов только для длинных строк

SUSPICIOUS_CHARS = set("'\"<>()[]{};=*-+/%|&\\")

def _check_density(text: str, location: str) -> Tuple[bool, Optional[str]]:
    if len(text) < MIN_LEN_FOR_RATIO:
        return False, None
        
    special_count = sum(1 for char in text if char in SUSPICIOUS_CHARS)
    ratio = special_count / len(text)
    
    if ratio > SPECIAL_CHAR_RATIO:
        return True, f"High density of special chars ({(ratio*100):.1f}%) in {location}"
        
    return False, None

def check(request: ParsedRequest) -> Tuple[bool, Optional[str]]:
    
    for key, value in request.query_params.items():
        if len(value) > MAX_PARAM_LENGTH:
            return True, f"Anomalous length ({len(value)} chars) in query parameter '{key}'"
            
        is_anomaly, details = _check_density(value, f"query parameter '{key}'")
        if is_anomaly: return True, details

    for header_name, header_value in request.headers.items():
        if len(header_value) > MAX_HEADER_LENGTH:
             return True, f"Anomalous length in header '{header_name}'"
             
        is_anomaly, details = _check_density(header_value, f"header '{header_name}'")
        if is_anomaly: return True, details

    return False, None