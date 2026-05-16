import json
import requests
import sys
import os
import psycopg2
import threading
from collections import defaultdict
from datetime import date
import time
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from urllib.parse import unquote, urlparse, parse_qs

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from analyzer.inspector import analyze_request
from analyzer.request_types import ParsedRequest

traffic_cache = defaultdict(lambda: {'bytes_in': 0, 'bytes_out': 0, 'requests': 0})
cache_lock = threading.Lock()
last_flush_time = time.time()

def get_db_connection():
    return psycopg2.connect(
        dbname=os.environ.get('DB_NAME', 'waf_db'),
        user=os.environ.get('DB_USER', 'waf_user'),
        password=os.environ.get('DB_PASSWORD', 'secretpassword'),
        host=os.environ.get('DB_HOST', 'db'),
        port=os.environ.get('DB_PORT', '5432')
    )
    
def get_site_info_from_db(domain):
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("""
            SELECT target_ip, is_protected, traffic_limit_mb 
            FROM accounts_protectedsite 
            WHERE domain = %s
        """, (domain,))
        result = cur.fetchone()
        cur.close()
        conn.close()
        if result:
            return result[0], result[1], result[2]
        return None, False, 0
    except Exception as e:
        print(f"Database error: {e}")
        return None, False, 0

def update_traffic_stats_db(domain, bytes_in, bytes_out):
    print(f"[TRAFFIC] Updating stats for {domain}: in={bytes_in}, out={bytes_out}")
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT id FROM accounts_protectedsite WHERE domain = %s", (domain,))
        site_row = cur.fetchone()
        if not site_row:
            print(f"[TRAFFIC] Site not found for domain: {domain}")
            return
        site_id = site_row[0]
        today = date.today()
        cur.execute("""
            INSERT INTO accounts_trafficstats (site_id, date, bytes_in, bytes_out)
            VALUES (%s, %s, %s, %s)
            ON CONFLICT (site_id, date) 
            DO UPDATE SET 
                bytes_in = accounts_trafficstats.bytes_in + EXCLUDED.bytes_in,
                bytes_out = accounts_trafficstats.bytes_out + EXCLUDED.bytes_out
        """, (site_id, today, bytes_in, bytes_out))
        conn.commit()
        print(f"[TRAFFIC] Successfully updated stats for {domain}")
        cur.close()
        conn.close()
    except Exception as e:
        print(f"Traffic stats error: {e}")

def check_traffic_limit(domain, limit_mb):
    if limit_mb <= 0:
        return True
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("""
            SELECT COALESCE(SUM(t.bytes_in + t.bytes_out), 0) / (1024.0 * 1024) as used_mb
            FROM accounts_protectedsite s
            LEFT JOIN accounts_trafficstats t 
                ON t.site_id = s.id 
                AND t.date >= date_trunc('month', CURRENT_DATE)
            WHERE s.domain = %s
            GROUP BY s.id
        """, (domain,))
        result = cur.fetchone()
        cur.close()
        conn.close()
        used_mb = result[0] if result else 0
        return used_mb < limit_mb
    except Exception as e:
        print(f"Check limit error: {e}")
        return True
        
def log_request(ip_address, method, path, status_code, was_blocked, user_agent, domain=None, rule_name=None):
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        site_id = None
        if domain:
            cur.execute("SELECT id FROM accounts_protectedsite WHERE domain = %s", (domain,))
            site_row = cur.fetchone()
            site_id = site_row[0] if site_row else None
        rule_id = None
        if rule_name:
            clean_rule_name = rule_name
            if rule_name.startswith('DB_RULE_'):
                clean_rule_name = rule_name[8:]
            cur.execute("SELECT id FROM accounts_wafrule WHERE name = %s", (clean_rule_name,))
            rule_row = cur.fetchone()
            rule_id = rule_row[0] if rule_row else None
        cur.execute("""
            INSERT INTO accounts_requestlog 
            (ip_address, method, path, status_code, was_blocked, user_agent, site_id, rule_triggered_id, timestamp)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, NOW())
        """, (ip_address, method, path, status_code, was_blocked, user_agent, site_id, rule_id))
        conn.commit()
        cur.close()
        conn.close()
    except Exception as e:
        print(f"Log error: {e}")

def flush_traffic_cache():
    global last_flush_time, traffic_cache
    while True:
        time.sleep(60)
        with cache_lock:
            for domain, stats in list(traffic_cache.items()):
                if stats['bytes_in'] > 0 or stats['bytes_out'] > 0:
                    update_traffic_stats_db(domain, stats['bytes_in'], stats['bytes_out'])
                    stats['bytes_in'] = 0
                    stats['bytes_out'] = 0
                    stats['requests'] = 0

flush_thread = threading.Thread(target=flush_traffic_cache, daemon=True)
flush_thread.start()

def get_client_ip(self):
    """Получает реальный IP клиента, учитывая прокси"""
    # Проверяем X-Forwarded-For (может содержать несколько IP)
    x_forwarded_for = self.headers.get('X-Forwarded-For')
    if x_forwarded_for:
        # Берем первый IP в списке (реальный клиент)
        client_ip = x_forwarded_for.split(',')[0].strip()
        print(f"[IP] X-Forwarded-For: {x_forwarded_for} -> {client_ip}")
        return client_ip
    
    # Проверяем X-Real-IP
    x_real_ip = self.headers.get('X-Real-IP')
    if x_real_ip:
        print(f"[IP] X-Real-IP: {x_real_ip}")
        return x_real_ip
    
    # Fallback на IP соединения (будет IP nginx)
    print(f"[IP] Direct connection IP: {self.client_address[0]}")
    return self.client_address[0]

class WAFProxy(BaseHTTPRequestHandler):
    
    def do_GET(self):
        self._handle_any_request('GET')
    def do_POST(self):
        self._handle_any_request('POST')
    def do_PUT(self):
        self._handle_any_request('PUT')
    def do_DELETE(self):
        self._handle_any_request('DELETE')
    def do_PATCH(self):
        self._handle_any_request('PATCH')
    def do_OPTIONS(self):
        self._handle_any_request('OPTIONS')
    def do_HEAD(self):
        self._handle_any_request('HEAD')
        
    def _handle_any_request(self, method):
        host_header = self.headers.get('Host', '')
        domain = host_header.split(':')[0] 
        client_ip = self.get_client_ip()
        user_agent = self.headers.get('User-Agent', '')
        
        if not domain:
            self.send_error(400, "Missing Host header")
            return
        if is_ip_banned(domain, client_ip):
            self.send_response(403)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({
                "error": "Your IP has been temporarily banned",
                "reason": "Too many suspicious requests",
                "unblock_after": "1 hour"
            }).encode())
            return   
        target_ip, is_protected, traffic_limit_mb = get_site_info_from_db(domain)
        
        if not target_ip:
            self.send_error(404, f"Domain '{domain}' is not registered")
            return
            
        # Check traffic limit
        if not check_traffic_limit(domain, traffic_limit_mb):
            print(f"LIMIT EXCEEDED [{domain}]")
            content_length = int(self.headers.get('Content-Length', 0))
            raw_body = self.rfile.read(content_length) if content_length > 0 else None
        
            # Проксируем сразу, минуя WAF
            self._proxy_to_backend(method, raw_body, f"http://{target_ip}")
            log_request(client_ip, method, self.path, status_code, False, user_agent, domain, rule_name="TRAFFIC_LIMIT_EXCEEDED")
        
            print(f"[STATS] {domain}: +{bytes_in} in, +{bytes_out} out (BYPASSED due to limit)")
            return
        
        target_url = f"http://{target_ip}"

        # Read body for analysis
        content_length = int(self.headers.get('Content-Length', 0))
        raw_body = self.rfile.read(content_length) if content_length > 0 else None
        bytes_in = content_length
        
        # Parse body for analyzer
        body_parsed = None
        if raw_body:
            try:
                body_parsed = json.loads(raw_body.decode('utf-8'))
            except:
                body_parsed = raw_body.decode('utf-8') if raw_body else None
        
        # Parse request for analyzer
        parsed_url = urlparse(self.path)
        request_to_analyze = ParsedRequest(
            method=method,
            path=parsed_url.path,
            query_params={k: v[0] for k, v in parse_qs(parsed_url.query).items()},
            headers=dict(self.headers),
            body=body_parsed
        )

        # Analyze request for attacks
        result = analyze_request(request_to_analyze)
        
        # Check if should block
        was_blocked = False
        triggered_rule = None
        
        if not result.is_safe:
            print(f"ATTACK DETECTED [{domain}]: {result.reason} ({result.details}) from {client_ip}")
            was_blocked = True
            triggered_rule = result.reason
            log_attack_attempt(domain, client_ip, result.reason)
            check_and_ban_if_needed(domain, client_ip)
            if is_protected:

                print(f"BLOCKED [{domain}]: {method} {self.path} - {result.reason}")
                
                # Log blocked request
                log_request(client_ip, method, self.path, 403, was_blocked, user_agent, domain, triggered_rule)
                
                # Update traffic stats (only incoming bytes, no outgoing)
                with cache_lock:
                    stats = traffic_cache[domain]
                    stats['bytes_in'] += bytes_in
                    stats['requests'] += 1
                
                print(f"[STATS] {domain}: +{bytes_in} in, +0 out (BLOCKED)")
                
                # Send 403 response
                self.send_response(403)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({
                    "error": "Request blocked by WAF",
                    "reason": result.reason,
                    "details": result.details
                }).encode())
                return
            else:
                # Protection disabled - just log, don't block (monitoring mode)
                print(f"MONITOR ONLY [{domain}]: Would block but protection disabled")
        
        # Proxy the request (safe OR attack with protection disabled)
        status_code, response_content = self._proxy_to_backend(method, raw_body, target_url)
        
        # Update traffic statistics
        bytes_out = len(response_content) if response_content else 0
        with cache_lock:
            stats = traffic_cache[domain]
            stats['bytes_in'] += bytes_in
            stats['bytes_out'] += bytes_out
            stats['requests'] += 1
        
        # Log the request
        log_request(client_ip, method, self.path, status_code, was_blocked, user_agent, domain, triggered_rule)
        
        print(f"[STATS] {domain}: +{bytes_in} in, +{bytes_out} out")


    def get_client_ip(self):
        x_forwarded_for = self.headers.get('X-Forwarded-For')
        if x_forwarded_for:
            client_ip = x_forwarded_for.split(',')[0].strip()
            print(f"[IP] X-Forwarded-For: {x_forwarded_for} -> {client_ip}")
            return client_ip
        
        x_real_ip = self.headers.get('X-Real-IP')
        if x_real_ip:
            print(f"[IP] X-Real-IP: {x_real_ip}")
            return x_real_ip
        
        print(f"[IP] Direct connection IP: {self.client_address[0]}")
        return self.client_address[0]

    def _proxy_to_backend(self, method, raw_body, target_url):
        if '/socket.io/' in self.path:
            self.send_response(200)
            self.end_headers()
            return 200, b''
        
        headers = {k: v for k, v in self.headers.items() if k.lower() not in ['content-length', 'host']}
        try:
            response = requests.request(
                method=method,
                url=target_url + self.path,
                headers=headers,
                data=raw_body,
                timeout=10,
                allow_redirects=False
            )
            self.send_response(response.status_code)
            excluded_headers = ['content-length', 'transfer-encoding', 'connection', 'date', 'server']
            for k, v in response.headers.items():
                if k.lower() not in excluded_headers:
                    self.send_header(k, v)
            self.send_header('Content-Length', str(len(response.content)))
            self.end_headers()
            self.wfile.write(response.content)
            return response.status_code, response.content
        except Exception as e:
            print(f"Proxy Error: {e}")
            self.send_error(502, f"Proxy error: {str(e)}")
            return 502, b''

def log_attack_attempt(domain, ip_address, rule_name):
    """Логирует попытку атаки в таблицу AttackAttempt"""
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        # Получаем site_id
        cur.execute("SELECT id FROM accounts_protectedsite WHERE domain = %s", (domain,))
        site_row = cur.fetchone()
        if not site_row:
            return
        site_id = site_row[0]
        
        # Получаем rule_id (если есть)
        rule_id = None
        if rule_name:
            cur.execute("SELECT id FROM accounts_wafrule WHERE name = %s", (rule_name,))
            rule_row = cur.fetchone()
            rule_id = rule_row[0] if rule_row else None
        
        # Вставляем запись об атаке
        cur.execute("""
            INSERT INTO accounts_attackattempt (site_id, ip_address, rule_triggered_id, timestamp)
            VALUES (%s, %s, %s, NOW())
        """, (site_id, ip_address, rule_id))
        conn.commit()
        
        cur.close()
        conn.close()
    except Exception as e:
        print(f"Error logging attack attempt: {e}")

def check_and_ban_if_needed(domain, ip_address):
    """Проверяет, нужно ли забанить IP, и банит если надо"""
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        # Получаем site_id
        cur.execute("SELECT id FROM accounts_protectedsite WHERE domain = %s", (domain,))
        site_row = cur.fetchone()
        if not site_row:
            print(f"[BAN] Site not found for domain: {domain}")
            return
        site_id = site_row[0]
        
        # Считаем атаки за последние 10 минут
        cur.execute("""
            SELECT COUNT(*) FROM accounts_attackattempt
            WHERE site_id = %s AND ip_address = %s
            AND timestamp > NOW() - INTERVAL '10 minutes'
        """, (site_id, ip_address))
        attack_count = cur.fetchone()[0]
        
        print(f"[BAN] IP {ip_address} has {attack_count} attacks in last 10 minutes")
        
        # Если 3 или более атаки - баним
        if attack_count >= 3:
            print(f"[BAN] Threshold reached, attempting to ban...")
            
            # Проверяем, не забанен ли уже
            cur.execute("""
                SELECT id FROM accounts_bannedip
                WHERE site_id = %s AND ip_address = %s AND is_active = True
                AND expires_at > NOW()
            """, (site_id, ip_address))
            already_banned = cur.fetchone()
            
            if not already_banned:
                # Баним на 1 час - теперь с banned_at
                cur.execute("""
                    INSERT INTO accounts_bannedip 
                    (site_id, ip_address, reason, banned_at, expires_at, attack_count, time_window_minutes, is_active)
                    VALUES (%s, %s, %s, NOW(), NOW() + INTERVAL '1 hour', %s, %s, True)
                """, (site_id, ip_address, f"Auto-banned after {attack_count} attacks in 10 minutes", attack_count, 10))
                conn.commit()
                print(f"[BAN] ✅ AUTO-BANNED {ip_address} for {domain} - {attack_count} attacks in 10 minutes")
            else:
                print(f"[BAN] IP {ip_address} is already banned")
        
        cur.close()
        conn.close()
    except Exception as e:
        print(f"[BAN] Error: {e}")
        import traceback
        traceback.print_exc()

def is_ip_banned(domain, ip_address):
    """Проверяет, забанен ли IP для данного домена"""
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("""
            SELECT expires_at FROM accounts_bannedip b
            JOIN accounts_protectedsite s ON s.id = b.site_id
            WHERE s.domain = %s AND b.ip_address = %s 
            AND b.is_active = True AND b.expires_at > NOW()
        """, (domain, ip_address))
        result = cur.fetchone()
        cur.close()
        conn.close()
        
        if result:
            expires_at = result[0]
            print(f"BLOCKED: IP {ip_address} is banned until {expires_at}")
            return True
        return False
    except Exception as e:
        print(f"Error checking ban: {e}")
        return False
if __name__ == '__main__':
    server = ThreadingHTTPServer(('0.0.0.0', 8080), WAFProxy)
    print("WAF with traffic stats, monitoring and blocking modes running on port 8080")
    server.serve_forever()
