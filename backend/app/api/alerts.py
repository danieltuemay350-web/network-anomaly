"""REST API routes for alerts."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.database.database import get_db
from app.services.alert_service import AlertService

router = APIRouter(prefix="/api/alerts", tags=["alerts"])


class AlertUpdate(BaseModel):
    status: str


@router.get("")
def list_alerts(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    alert_type: str | None = None,
    severity: str | None = None,
    status: str | None = None,
    db: Session = Depends(get_db),
):
    svc = AlertService(db)
    alerts = svc.get_alerts(skip=skip, limit=limit, alert_type=alert_type, severity=severity, status=status)
    return {"alerts": [a.to_dict() for a in alerts], "count": len(alerts)}


@router.get("/{alert_id}")
def get_alert(alert_id: int, db: Session = Depends(get_db)):
    svc = AlertService(db)
    alert = svc.get_alert(alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert.to_dict()


@router.patch("/{alert_id}")
def update_alert(alert_id: int, body: AlertUpdate, db: Session = Depends(get_db)):
    svc = AlertService(db)
    try:
        alert = svc.update_alert_status(alert_id, body.status)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert.to_dict()
