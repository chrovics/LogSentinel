from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from fastapi import Request
import os

templates = Jinja2Templates(directory="templates")

from fastapi import FastAPI, Depends, BackgroundTasks
from sqlalchemy.orm import Session
from pydantic import BaseModel, Field
from typing import Optional, List
from . import models
from .database import engine, get_db
from .rules_engine import analyze_web_log

# Inițializează tabelele automat
models.Base.metadata.create_all(bind=engine)

app = FastAPI(title="LogSentinel API", version="1.0.0")

class LogIngestSchema(BaseModel):
    source_ip: str = Field(..., example="192.168.1.50")
    service: str = Field(..., example="nginx")
    method: Optional[str] = Field(None, example="GET")
    endpoint: Optional[str] = Field(None, example="/.env")
    status_code: Optional[int] = Field(None, example=404)
    user_agent: Optional[str] = Field(None, example="sqlmap/1.5")
    raw_log: str = Field(..., example='192.168.1.50 - - [08/Oct/2026:10:00:00] "GET /.env HTTP/1.1" 404 ...')

@app.get("/api/health")
def health():
    return {"status": "healthy", "service": "LogSentinel Backend"}

@app.post("/api/logs", status_code=201)
def ingest_log(payload: LogIngestSchema, bg_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    # 1. Salvăm logul în baza de date
    db_entry = models.LogEntry(**payload.model_dump())
    db.add(db_entry)
    db.commit()
    db.refresh(db_entry)

    # 2. Declanșăm motorul de analiză asincron în fundal
    bg_tasks.add_task(analyze_web_log, db_entry, db)

    return {"status": "ingested", "log_id": db_entry.id}

@app.get("/api/alerts")
def list_alerts(limit: int = 50, db: Session = Depends(get_db)):
    return db.query(models.Alert).order_by(models.Alert.created_at.desc()).limit(limit).all()

@app.get("/api/flagged-ips")
def list_flagged_ips(db: Session = Depends(get_db)):
    return db.query(models.FlaggedIP).order_by(models.FlaggedIP.created_at.desc()).all()


@app.get("/", response_class=HTMLResponse)
def get_dashboard(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

@app.get("/api/stats")
def get_stats(db: Session = Depends(get_db)):
    total_logs = db.query(models.LogEntry).count()
    total_alerts = db.query(models.Alert).count()
    critical_alerts = db.query(models.Alert).filter(models.Alert.severity == "CRITICAL").count()
    flagged_ips = db.query(models.FlaggedIP).count()
    
    return {
        "total_logs": total_logs,
        "total_alerts": total_alerts,
        "critical_alerts": critical_alerts,
        "flagged_ips": flagged_ips
    }
