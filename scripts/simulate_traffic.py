import time
import requests
import random

API_URL = "http://localhost:8000/api/logs"

# Cazuri sintetice de test: trafic benign amestecat cu evenimente care declanșează regulile
TEST_SCENARIOS = [
    # Trafic legitim / normal
    {
        "source_ip": "192.168.1.50",
        "service": "nginx",
        "method": "GET",
        "endpoint": "/index.html",
        "status_code": 200,
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        "raw_log": "192.168.1.50 - - [08/Oct/2026:11:00:01 +0000] \"GET /index.html HTTP/1.1\" 200 4520"
    },
    {
        "source_ip": "192.168.1.52",
        "service": "nginx",
        "method": "GET",
        "endpoint": "/assets/style.css",
        "status_code": 200,
        "user_agent": "Mozilla/5.0 (X11; Linux x86_64)",
        "raw_log": "192.168.1.52 - - [08/Oct/2026:11:00:02 +0000] \"GET /assets/style.css HTTP/1.1\" 200 1204"
    },
    # Test regulă: Căi sensibile / Directory Traversal
    {
        "source_ip": "198.51.100.23",
        "service": "nginx",
        "method": "GET",
        "endpoint": "/wp-login.php",
        "status_code": 404,
        "user_agent": "Mozilla/5.0 (compatible; SecurityScanner/1.0)",
        "raw_log": "198.51.100.23 - - [08/Oct/2026:11:00:05 +0000] \"GET /wp-login.php HTTP/1.1\" 404 162"
    },
    # Test regulă: SQL Injection Pattern
    {
        "source_ip": "203.0.113.88",
        "service": "nginx",
        "method": "POST",
        "endpoint": "/api/search?q=test%20union%20select%201,2,3",
        "status_code": 400,
        "user_agent": "Python-urllib/3.12",
        "raw_log": "203.0.113.88 - - [08/Oct/2026:11:00:10 +0000] \"POST /api/search?q=test union select 1,2,3 HTTP/1.1\" 400 320"
    },
    # Test regulă: Acces fișiere configurare (.git)
    {
        "source_ip": "198.51.100.45",
        "service": "nginx",
        "method": "GET",
        "endpoint": "/.git/config",
        "status_code": 404,
        "user_agent": "curl/8.6.0",
        "raw_log": "198.51.100.45 - - [08/Oct/2026:11:00:15 +0000] \"GET /.git/config HTTP/1.1\" 404 162"
    }
]

def run_simulation(rounds=1, delay_between=2):
    print(f"[*] Incep simularea traficului catre {API_URL}...")
    for round_num in range(1, rounds + 1):
        print(f"\n--- Runda {round_num}/{rounds} ---")
        for event in TEST_SCENARIOS:
            try:
                res = requests.post(API_URL, json=event, timeout=3)
                if res.status_code == 200 or res.status_code == 201:
                    print(f"[+] Trimis: {event['method']} {event['endpoint']} ({event['source_ip']}) -> Status {res.status_code}")
                else:
                    print(f"[-] Eroare ingestie: Status {res.status_code}")
            except requests.RequestException as e:
                print(f"[!] Eroare de conexiune la backend: {e}")
            
            # Pauză între evenimente pentru a observa streaming-ul în dashboard
            time.sleep(delay_between)

    print("\n[+] Simulare finalizata cu succes!")

if __name__ == "__main__":
    # Rulează 2 iterații cu 2 secunde pauză între cereri
    run_simulation(rounds=2, delay_between=2)
