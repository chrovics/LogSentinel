import os
import re
import sys
import time
import requests

API_URL = os.getenv("SENTINEL_API_URL", "http://localhost:8000/api/logs")
LOG_FILE_PATH = os.getenv("SENTINEL_LOG_FILE", "/var/log/nginx/access.log")

# Regex standard pentru formatul Nginx combined log
NGINX_LOG_REGEX = re.compile(
    r'^(?P<ip>[\d\.\:a-fA-F]+)\s+-\s+\S+\s+\[(?P<time>[^\]]+)\]\s+"(?P<method>[A-Z]+)\s+(?P<endpoint>\S+)\s+[^\"]*"\s+(?P<status>\d{3})\s+\d+\s+"[^\"]*"\s+"(?P<user_agent>[^\"]*)"'
)

def parse_nginx_line(raw_line: str):
    match = NGINX_LOG_REGEX.match(raw_line.strip())
    if not match:
        return None
    
    data = match.groupdict()
    return {
        "source_ip": data["ip"],
        "service": "nginx",
        "method": data["method"],
        "endpoint": data["endpoint"],
        "status_code": int(data["status"]),
        "user_agent": data["user_agent"],
        "raw_log": raw_line.strip()
    }

def stream_logs(file_path: str):
    """Echivalentul funcțional al comenzii `tail -F` în Python."""
    if not os.path.exists(file_path):
        print(f"[-] Fisierul {file_path} nu exista inca. Astept creare...")
        while not os.path.exists(file_path):
            time.sleep(1)

    print(f"[+] Monitorizez logurile in timp real din: {file_path}")
    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        # Mergem direct la finalul fișierului pentru a citi doar liniile noi
        f.seek(0, os.SEEK_END)
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.1)
                continue
            yield line

def send_to_sentinel(payload: dict):
    try:
        res = requests.post(API_URL, json=payload, timeout=2)
        if res.status_code == 201:
            print(f"[+] [INGESTED] {payload['source_ip']} -> {payload['method']} {payload['endpoint']} ({payload['status_code']})")
        else:
            print(f"[-] [API REJECT] Status: {res.status_code}")
    except requests.exceptions.RequestException as e:
        print(f"[!] [NETWORK ERROR] Nu ma pot conecta la backend: {e}")

def main():
    print(f"[*] Pornesc LogSentinel Agent catre {API_URL}...")
    for line in stream_logs(LOG_FILE_PATH):
        parsed = parse_nginx_line(line)
        if parsed:
            send_to_sentinel(parsed)

if __name__ == "__main__":
    main()
