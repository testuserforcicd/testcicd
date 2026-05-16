from dataclasses import dataclass
from typing import Optional, Dict

@dataclass
class ParsedRequest:
    """То, что сервер передает в анализатор"""
    method: str                # 'GET', 'POST' ...
    path: str                  # '/api/v1/login' 
    headers: Dict[str, str]    # {'User-Agent': '...', 'Content-Type': '...'}
    query_params: Dict[str, str] # {'id': '1'}
    body: Optional[str] = None # Распарсенное тело или сырая строка
    ip_address: str = ""       # IP клиента для эвристики

@dataclass
class InspectionResult:
    """То, что анализатор возвращает серверу"""
    is_safe: bool
    action: str                # 'allow', 'block', 'log'
    reason: Optional[str] = None # 'SQL_INJECTION', 'XSS', 'ANOMALY'
    details: Optional[str] = None 