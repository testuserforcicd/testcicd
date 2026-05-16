import os
import time
from ..request_types import ParsedRequest 
from ..signatures import sqli

def run_fuzzer(filepath="Generic-SQLi.txt"):
    if not os.path.exists(filepath):
        print(f"[-] Ошибка: Файл '{filepath}' не найден в текущей директории.")
        return

    total_payloads = 0
    blocked_payloads = 0
    bypassed_payloads = []

    print(f"[*] Запуск тестирования по словарю: {filepath}...")
    start_time = time.time()

    with open(filepath, 'r', encoding='utf-8', errors='ignore') as file:
        for line in file:
            payload = line.strip()
            
            if not payload:
                continue

            total_payloads += 1

            mock_request = ParsedRequest(
                method="GET",
                path="/search",
                headers={"User-Agent": "Mozilla/5.0"},
                query_params={"q": payload}, 
                body=None
            )

            is_attack, details = sqli.check(mock_request)

            if is_attack:
                blocked_payloads += 1
            else:
                bypassed_payloads.append(payload)

    execution_time = time.time() - start_time

    print("\n" + "="*30)
    print(" РЕЗУЛЬТАТЫ СКАНИРОВАНИЯ")
    print("="*30)
    print(f"Всего пейлоадов: {total_payloads}")
    print(f"Заблокировано:   {blocked_payloads}")
    print(f"Пропущено:       {len(bypassed_payloads)}")
    
    if total_payloads > 0:
        detection_rate = (blocked_payloads / total_payloads) * 100
        print(f"Эффективность:   {detection_rate:.2f}%")
        print(f"Время проверки:  {execution_time:.3f} сек.")

    if bypassed_payloads:
        bypassed_file = "bypassed_sqli.txt"
        with open(bypassed_file, "w", encoding="utf-8") as f:
            for p in bypassed_payloads:
                f.write(p + "\n")
        print(f"\n[!] Пропущенные пейлоады сохранены в файл: {bypassed_file}")
        print("    Изучи их, чтобы добавить новые правила (RegEx) в sqli.py")

if __name__ == "__main__":
    run_fuzzer("analyzer/tests/Generic-SQLi.txt")