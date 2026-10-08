import re
from sqlalchemy.orm import Session
from . import models
from .abuseipdb import check_ip_reputation
from .telegram import send_telegram_alert

SUSPICIOUS_PATHS = [
    ".env", "wp-login.php", "wp-admin", "config.php",
    "phpmyadmin", ".git", "/etc/passwd", "shell.php", "id_rsa"
]

SQLI_PATTERNS = [
    r"union\s+select",
    r"or\s+1=1",
    r"sleep\(\d+\)",
    r"--"
]

def flag_ip_with_intel(ip_address: str, reason: str, db: Session):
    existing = db.query(models.FlaggedIP).filter(models.FlaggedIP.ip_address == ip_address).first()
    if existing:
        return existing.country, existing.abuse_score

    intel = check_ip_reputation(ip_address)
    score = intel.get("abuseConfidenceScore", 0) if intel else 0
    country = intel.get("countryCode") if intel else "UNKNOWN"

    flagged = models.FlaggedIP(
        ip_address=ip_address,
        abuse_score=score,
        country=country,
        reason=reason
    )
    db.add(flagged)
    db.commit()
    return country, score

def analyze_web_log(log_entry: models.LogEntry, db: Session):
    endpoint = (log_entry.endpoint or "").lower()

    # 1. Directory Traversal / Căi sensibile
    for suspicious in SUSPICIOUS_PATHS:
        if suspicious in endpoint or "../" in endpoint:
            details_msg = f"Tentativa accesare cale interzisa: {log_entry.endpoint}"
            alert = models.Alert(
                source_ip=log_entry.source_ip,
                rule_name="Suspicious Path / Directory Traversal",
                severity="HIGH",
                details=details_msg
            )
            db.add(alert)
            db.commit()
            
            country, score = flag_ip_with_intel(log_entry.source_ip, "Suspicious Path Scan", db)
            send_telegram_alert(
                rule_name="Suspicious Path / Directory Traversal",
                severity="HIGH",
                source_ip=log_entry.source_ip,
                details=details_msg,
                country=country,
                abuse_score=score
            )
            return

    # 2. SQL Injection
    for pattern in SQLI_PATTERNS:
        if re.search(pattern, endpoint):
            details_msg = f"Pattern SQLi detectat in URL: {log_entry.endpoint}"
            alert = models.Alert(
                source_ip=log_entry.source_ip,
                rule_name="SQL Injection Pattern Detected",
                severity="CRITICAL",
                details=details_msg
            )
            db.add(alert)
            db.commit()
            
            country, score = flag_ip_with_intel(log_entry.source_ip, "SQLi Payload Injected", db)
            send_telegram_alert(
                rule_name="SQL Injection Pattern Detected",
                severity="CRITICAL",
                source_ip=log_entry.source_ip,
                details=details_msg,
                country=country,
                abuse_score=score
            )
            return
