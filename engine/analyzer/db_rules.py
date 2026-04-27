# analyzer/db_rules.py
import re
import psycopg2
import os
from typing import List, Dict, Optional

_rules_cache = None
_rules_cache_time = 0

def get_active_rules_from_db():
    """Загружает активные правила из таблицы accounts_wafrule"""
    global _rules_cache, _rules_cache_time
    
    import time
    # Обновляем кэш каждые 60 секунд
    if _rules_cache is not None and (time.time() - _rules_cache_time) < 60:
        return _rules_cache
    
    try:
        conn = psycopg2.connect(
            dbname=os.environ.get('DB_NAME', 'waf_db'),
            user=os.environ.get('DB_USER', 'waf_user'),
            password=os.environ.get('DB_PASSWORD', 'secretpassword'),
            host=os.environ.get('DB_HOST', 'db'),
            port=os.environ.get('DB_PORT', '5432')
        )
        cur = conn.cursor()
        cur.execute("""
            SELECT id, name, pattern, severity, action 
            FROM accounts_wafrule 
            WHERE is_active = True
        """)
        rules = cur.fetchall()
        cur.close()
        conn.close()
        
        compiled_rules = []
        print(f"[WAF DEBUG] Загружено {len(compiled_rules)} правил из БД")
        for rule_id, name, pattern, severity, action in rules:
            try:
                compiled_rules.append({
                    'id': rule_id,
                    'name': name,
                    'pattern': re.compile(pattern, re.IGNORECASE),
                    'severity': severity,
                    'action': action
                })
            except re.error as e:
                print(f"[WAF] Ошибка компиляции regex для правила '{name}': {e}")
        
        _rules_cache = compiled_rules
        _rules_cache_time = time.time()
        print(f"[WAF] Загружено {len(compiled_rules)} правил из БД")
        return compiled_rules
        
    except Exception as e:
        print(f"[WAF] Ошибка загрузки правил из БД: {e}")
        return []
