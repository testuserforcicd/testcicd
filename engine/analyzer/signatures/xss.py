import re
import urllib.parse
from typing import Tuple, Optional
from ..request_types import ParsedRequest

XSS_PATTERNS = {
    "SCRIPT_TAG": re.compile(r"(?i)<\s*script[^>]*>"), 
    
    "EVENT_HANDLERS": re.compile(r"(?i)\bon[a-z]+\s*=\s*(?:['\"]?[^>]+['\"]?|[^>\s]+)"), 
    
    "JAVASCRIPT_URI": re.compile(r"(?i)(javascript|vbscript)\s*:"), 
    
    "DANGEROUS_TAGS": re.compile(r"(?i)<\s*(iframe|object|embed|applet|svg|math)\b"), 
    
    "DATA_URI_XSS": re.compile(r"(?i)data\s*:[^,]*text/html[^,]*base64\s*,"),
}

def check(request: ParsedRequest) -> Tuple[bool, Optional[str]]:
    
    def _inspect_string(target_string: str, location: str) -> Tuple[bool, Optional[str]]:
        if not target_string:
            return False, None
            
        decoded_string = urllib.parse.unquote(target_string)
        
        for attack_type, pattern in XSS_PATTERNS.items():
            if pattern.search(decoded_string):
                return True, f"Found {attack_type} in {location}"
                
        return False, None

    for key, value in request.query_params.items():
        is_attack, details = _inspect_string(value, f"query parameter '{key}'")
        if is_attack:
            return True, details

    RFC_HEADERS_FORMATS = {
        'accept': re.compile(r'^[a-zA-Z0-9\*/\-\.;=,\s\+]+$'),
        'accept-encoding': re.compile(r'^[a-zA-Z0-9\-\.;=,\s\+]+$'),
        'accept-language': re.compile(r'^[a-zA-Z0-9\-\.;=,\s]+$'),
        'content-length': re.compile(r'^\d+$'),
        'host': re.compile(r'^[a-zA-Z0-9\-\.:\[\]]+$'),
        'connection': re.compile(r'^[a-zA-Z\-\s,]+$'),
        'cache-control': re.compile(r'^[a-zA-Z0-9\-\s,=]+$'),
        'upgrade-insecure-requests': re.compile(r'^\d$')
    }

    for header_name, header_value in request.headers.items():
        header_name_lower = header_name.lower()
        
        if header_name_lower.startswith('sec-ch-') or header_name_lower.startswith('sec-fetch-'):
            continue

        if header_name_lower in RFC_HEADERS_FORMATS:
            if not RFC_HEADERS_FORMATS[header_name_lower].match(header_value):
                return True, f"RFC format violation in strict header '{header_name}'"
            
            continue 

        is_attack, details = _inspect_string(header_value, f"header '{header_name}'")
        if is_attack:
            return True, details

    if isinstance(request.body, str):
        is_attack, details = _inspect_string(request.body, "request body")
        if is_attack:
            return True, details
    elif isinstance(request.body, dict):
        for key, value in request.body.items():
            if isinstance(value, str):
                 is_attack, details = _inspect_string(value, f"body key '{key}'")
                 if is_attack:
                     return True, details

    return False, None