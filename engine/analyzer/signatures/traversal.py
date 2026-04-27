import re
import urllib.parse
from typing import Tuple, Optional
from ..request_types import ParsedRequest

TRAVERSAL_PATTERNS = [
    re.compile(r"(?i)(\.\./|\.\.\\|%2e%2e%2f|%2e%2e%5c)"),
    re.compile(r"(?i)(/etc/passwd|/etc/shadow|c:\\windows\\system32)"), 
    re.compile(r"(?i)(file://|php://filter)") 
]

def check(request: ParsedRequest) -> Tuple[bool, Optional[str]]:
    def _inspect_string(target_string: str, location: str) -> Tuple[bool, Optional[str]]:
        if not target_string:
             return False, None
        decoded_string = urllib.parse.unquote(target_string)
        for pattern in TRAVERSAL_PATTERNS:
             if pattern.search(decoded_string):
                 return True, f"Found PATH_TRAVERSAL in {location}"
        return False, None

    if _inspect_string(request.path, "request path")[0]:
        return True, "Found PATH_TRAVERSAL in request path"

    for key, value in request.query_params.items():
        is_attack, details = _inspect_string(value, f"query parameter '{key}'")
        if is_attack: return True, details

    return False, None