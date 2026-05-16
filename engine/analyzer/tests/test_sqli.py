# test_sqli.py
from ..request_types import ParsedRequest
from ..signatures import sqli

def run_tests():
    # 1. Безопасный запрос (должен пройти)
    safe_request = ParsedRequest(
        method="GET",
        path="/api/users",
        headers={"User-Agent": "Mozilla/5.0"},
        query_params={"id": "12", "name": "Ivan"},
        body=None
    )

    # 2. Очевидная атака в URL (должна быть заблокирована)
    attack_url_request = ParsedRequest(
        method="GET",
        path="/api/users",
        headers={"User-Agent": "Mozilla/5.0"},
        query_params={"id": "12' OR '1'='1"}, # Классическая тавтология
        body=None
    )

    # 3. Атака, спрятанная в URL-кодировке (должна быть раскодирована и заблокирована)
    encoded_attack_request = ParsedRequest(
        method="GET",
        path="/api/users",
        headers={"User-Agent": "Mozilla/5.0"},
        # %55%4E%49%4F%4E%20%53%45%4C%45%43%54 = UNION SELECT
        query_params={"search": "%55%4E%49%4F%4E%20%53%45%4C%45%43%54"}, 
        body=None
    )

    tests = [
        ("Safe GET Request", safe_request, False),
        ("SQLi in Query Params", attack_url_request, True),
        ("URL Encoded SQLi", encoded_attack_request, True),
    ]

    print("--- Запуск тестов SQLi ---")
    for name, req, expected_to_block in tests:
        is_attack, details = sqli.check(req)
        
        if is_attack == expected_to_block:
            print(f"[OK] {name}")
            if is_attack:
                print(f"     Поймано правилом: {details}")
        else:
            print(f"[FAIL] {name} - Ожидалась блокировка: {expected_to_block}, Получено: {is_attack}")

if __name__ == "__main__":
    run_tests()