import random
from accounts.models import User, ProtectedSite, RequestLog, WAFRule



testuser, _ = User.objects.get_or_create(username='testuser', defaults={'email': 'testuser@mail.com'})
user1, _ = User.objects.get_or_create(username='user1', defaults={'email': 'user1@mail.com'})

if _:
    testuser.set_password('password123'); testuser.save()
    user1.set_password('password123'); user1.save()

site_example_org, _ = ProtectedSite.objects.get_or_create(
    domain='example.org', 
    user=testuser, 
    defaults={'target_ip': '127.0.0.1'}
)

site_test1, _ = ProtectedSite.objects.get_or_create(
    domain='testuser1.com', 
    user=user1, 
    defaults={'target_ip': '127.0.0.1'}
)

site_admin_org, _ = ProtectedSite.objects.get_or_create(
    domain='admin.org', 
    user=user1, 
    defaults={'target_ip': '127.0.0.1'}
)

sites = [site_example_org, site_test1, site_admin_org]

rule_sqli, _ = WAFRule.objects.get_or_create(name='SQL Injection test', defaults={'pattern': 'UNION SELECT', 'action': 'block'})
rule_xss, _ = WAFRule.objects.get_or_create(name='XSS Cross-site test', defaults={'pattern': '<script>', 'action': 'block'})
rules = [rule_sqli, rule_xss]

TOTAL_LOGS = 5000000 
BATCH_SIZE = 5000
logs_batch = []

paths = ['/login', '/api/data', '/index.html', '/images/logo.png', '/socket.io/']
methods = ['GET', 'POST', 'PUT', 'DELETE']


for i in range(TOTAL_LOGS):
    site = random.choice(sites)
    method = random.choice(methods)
    is_attack = random.random() < 0.15 
    
    if is_attack:
        rule = random.choice(rules)
        path = random.choice(paths) + ("?id=1' OR '1'='1" if rule == rule_sqli else "?search=<script>alert(1)</script>")
        status = 403
    else:
        rule = None
        path = random.choice(paths)
        status = random.choice([200, 200, 200, 301, 404])

    log = RequestLog(
        site=site,
        ip_address=f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}",
        method=method,
        path=path,
        status_code=status,
        was_blocked=is_attack,
        rule_triggered=rule,
        user_agent="Mozilla/5.0 (LoadTester)"
    )
    logs_batch.append(log)
    
    if len(logs_batch) >= BATCH_SIZE:
        RequestLog.objects.bulk_create(logs_batch)
        logs_batch = []
        print(f"Сгенерировано {i + 1} из {TOTAL_LOGS}...")

if logs_batch:
    RequestLog.objects.bulk_create(logs_batch)

