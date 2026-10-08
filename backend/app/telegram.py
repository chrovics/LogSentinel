import os
import requests

TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID")

def send_telegram_alert(rule_name: str, severity: str, source_ip: str, details: str, country: str = "N/A", abuse_score: int = 0):
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        print("[!] Telegram Bot Token sau Chat ID lipseste. Alerta nu a fost trimisa pe chat.")
        return

    icon = "🚨" if severity == "CRITICAL" else "⚠️"
    
    message = (
        f"{icon} <b>LogSentinel Incident Alert</b> {icon}\n\n"
        f"<b>Severitate:</b> <code>{severity}</code>\n"
        f"<b>Regulă:</b> {rule_name}\n"
        f"<b>IP Atacator:</b> <code>{source_ip}</code> ({country})\n"
        f"<b>Scor AbuseIPDB:</b> {abuse_score}%\n\n"
        f"<b>Detalii Eveniment:</b>\n"
        f"<code>{details}</code>"
    )

    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    payload = {
        "chat_id": TELEGRAM_CHAT_ID,
        "text": message,
        "parse_mode": "HTML"
    }

    try:
        res = requests.post(url, json=payload, timeout=4)
        if res.status_code == 200:
            print(f"[+] Alerta Telegram trimisa cu succes pentru IP {source_ip}")
        else:
            print(f"[-] Eroare la trimiterea alertei Telegram ({res.status_code}): {res.text}")
    except requests.exceptions.RequestException as e:
        print(f"[!] Eroare retea Telegram: {e}")
