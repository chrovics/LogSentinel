from sqlalchemy import Column, Integer, String, DateTime, Text, Boolean, Index
from sqlalchemy.sql import func
from .database import Base

class LogEntry(Base):
    __tablename__ = "log_entries"

    id = Column(Integer, primary_key=True, index=True)
    source_ip = Column(String(45), index=True, nullable=False)
    service = Column(String(50), nullable=False)       # ex: "nginx", "ssh"
    method = Column(String(10), nullable=True)          # ex: "GET", "POST"
    endpoint = Column(String(2048), nullable=True)      # Calea cerută / URL
    status_code = Column(Integer, nullable=True)
    user_agent = Column(Text, nullable=True)
    raw_log = Column(Text, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), index=True)


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    source_ip = Column(String(45), index=True, nullable=False)
    rule_name = Column(String(100), nullable=False)     # ex: "Directory Traversal", "SQL Injection"
    severity = Column(String(20), default="MEDIUM", index=True, nullable=False)  # LOW, MEDIUM, HIGH, CRITICAL
    details = Column(Text, nullable=False)
    is_acknowledged = Column(Boolean, default=False, nullable=False, index=True)
    acknowledged_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), index=True)


class FlaggedIP(Base):
    __tablename__ = "flagged_ips"

    id = Column(Integer, primary_key=True, index=True)
    ip_address = Column(String(45), unique=True, index=True, nullable=False)
    abuse_score = Column(Integer, default=0, nullable=False)  # Scor 0-100 de la AbuseIPDB
    country = Column(String(10), nullable=True)
    total_reports = Column(Integer, default=0)                # Raportări globale AbuseIPDB
    reason = Column(String(255), nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), index=True)

    __table_args__ = (
        Index("idx_flagged_score", "abuse_score"),
    )
