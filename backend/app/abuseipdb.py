import os
import requests
from typing import Optional, Dict

ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
API_URL = "https://api.abuseipdb.com/api/v2/check"

def check_ip_reputation(ip_address: str) -> Optional[Dict]:
    """
    Interoghează AbuseIPDB v2 Check API.
    Dacă nu există o cheie setată, returnează date simulate pentru test local.
    """
    # Fallback util pentru dezvoltare locală dacă nu ai setat încă o cheie reală
    if not ABUSEIPDB_API_KEY or ABUSEIPDB_API_KEY == "your_api_key_here":
        print(f"[!] Cheia AbuseIPDB lipseste. Simulez verificare pentru {ip_address}")
        return {
            "ipAddress": ip_address,
            "abuseConfidenceScore": 85,
            "countryCode": "RO",
            "usageType": "Data Center/Web Hosting/Transit"
        }

    headers = {
        "Accept": "application/json",
        "Key": ABUSEIPDB_API_KEY
    }
    params = {
        "ipAddress": ip_address,
        "maxAgeInDays": 90
    }

    try:
        response = requests.get(API_URL, headers=headers, params=params, timeout=5)
        if response.status_code == 200:
            return response.json().get("data", {})
        else:
            print(f"[-] AbuseIPDB a returnat codul {response.status_code}: {response.text}")
            return None
    except requests.exceptions.RequestException as e:
        print(f"[!] Eroare conexiune AbuseIPDB: {e}")
        return None
