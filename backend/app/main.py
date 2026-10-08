import os
from datetime import datetime, timezone
from typing import Optional

from fastapi import FastAPI, Depends, HTTPException, BackgroundTasks, Request, Response
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from sqlalchemy.orm import Session
from sqlalchemy import desc

from . import models, database, auth
from .rules_engine import analyze_web_log

models.Base.metadata.create_all(bind=database.engine)

app = FastAPI(title="LogSentinel SIEM-lite", version="1.0.0")
templates = Jinja2Templates(directory="templates")

class LogCreate(BaseModel):
    source_ip: str
    service: str
    method: Optional[str] = None
    endpoint: Optional[str] = None
    status_code: Optional[int] = None
    user_agent: Optional[str] = None
    raw_log: str

class LoginRequest(BaseModel):
    username: str
    password: str

@app.get("/", response_class=HTMLResponse)
def get_dashboard(request: Request):
    try:
        auth.verify_token(request)
    except HTTPException:
        return RedirectResponse(url="/login")
    return templates.TemplateResponse("index.html", {"request": request})

@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})

@app.post("/api/auth/login")
def login(data: LoginRequest, response: Response):
    valid_user = os.getenv("ADMIN_USERNAME", "admin")
    valid_pass = os.getenv("ADMIN_PASSWORD", "admin123")
    if data.username != valid_user or data.password != valid_pass:
        raise HTTPException(status_code=401, detail="User sau parola incorecte")
    token = auth.create_access_token({"sub": data.username})
    response.set_cookie(key="access_token", value=token, httponly=True, max_age=auth.ACCESS_TOKEN_EXPIRE_MINUTES * 60, samesite="lax")
    return {"status": "success"}

@app.post("/api/auth/logout")
def logout(response: Response):
    response.delete_cookie("access_token")
    return {"status": "success"}

@app.post("/api/logs", status_code=201)
def ingest_log(log_data: LogCreate, background_tasks: BackgroundTasks, db: Session = Depends(database.get_db)):
    db_entry = models.LogEntry(source_ip=log_data.source_ip, service=log_data.service, method=log_data.method, endpoint=log_data.endpoint, status_code=log_data.status_code, user_agent=log_data.user_agent, raw_log=log_data.raw_log)
    db.add(db_entry)
    db.commit()
    db.refresh(db_entry)
    background_tasks.add_task(analyze_web_log, db_entry, db)
    return {"status": "ingested", "log_id": db_entry.id}

@app.get("/api/stats")
def get_stats(db: Session = Depends(database.get_db), current_user: str = Depends(auth.verify_token)):
    return {
        "total_logs": db.query(models.LogEntry).count(),
        "total_alerts": db.query(models.Alert).count(),
        "critical_alerts": db.query(models.Alert).filter(models.Alert.severity == "CRITICAL").count(),
        "high_alerts": db.query(models.Alert).filter(models.Alert.severity == "HIGH").count(),
        "flagged_ips_count": db.query(models.FlaggedIP).count()
    }

@app.get("/api/alerts")
def get_alerts(limit: int = 50, db: Session = Depends(database.get_db), current_user: str = Depends(auth.verify_token)):
    return db.query(models.Alert).order_by(desc(models.Alert.created_at)).limit(limit).all()

@app.get("/api/flagged-ips")
def get_flagged_ips(db: Session = Depends(database.get_db), current_user: str = Depends(auth.verify_token)):
    return db.query(models.FlaggedIP).order_by(desc(models.FlaggedIP.created_at)).limit(20).all()

@app.patch("/api/alerts/{alert_id}/acknowledge")
def acknowledge_alert(alert_id: int, db: Session = Depends(database.get_db), current_user: str = Depends(auth.verify_token)):
    alert = db.query(models.Alert).filter(models.Alert.id == alert_id).first()
    if not alert: raise HTTPException(status_code=404, detail="Alerta nu a fost gasita")
    alert.is_acknowledged = not alert.is_acknowledged
    alert.acknowledged_at = datetime.now(timezone.utc) if alert.is_acknowledged else None
    db.commit()
    db.refresh(alert)
    return {"status": "success", "alert_id": alert.id, "is_acknowledged": alert.is_acknowledged, "acknowledged_at": alert.acknowledged_at}

@app.delete("/api/alerts/{alert_id}")
def delete_single_alert(alert_id: int, db: Session = Depends(database.get_db), current_user: str = Depends(auth.verify_token)):
    alert = db.query(models.Alert).filter(models.Alert.id == alert_id).first()
    if not alert: raise HTTPException(status_code=404, detail="Alerta nu a fost gasita")
    db.delete(alert)
    db.commit()
    return {"status": "success"}

@app.delete("/api/alerts")
def clear_all_alerts(db: Session = Depends(database.get_db), current_user: str = Depends(auth.verify_token)):
    deleted = db.query(models.Alert).delete()
    db.commit()
    return {"status": "success", "deleted_count": deleted}

@app.get("/api/health")
def health_check():
    return {"status": "healthy"}
