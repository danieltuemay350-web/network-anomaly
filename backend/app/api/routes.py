"""API routes: health, stats, devices, traffic."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.database.database import get_db
from app.services.alert_service import AlertService

router = APIRouter(prefix="/api", tags=["system"])


@router.get("/health")
def health_check():
    return {"status": "ok", "service": "network-anomaly-detector"}


@router.get("/stats")
def get_stats(db: Session = Depends(get_db)):
    svc = AlertService(db)
    return svc.get_stats()


@router.get("/devices")
def get_devices(db: Session = Depends(get_db)):
    svc = AlertService(db)
    return {"devices": svc.get_unique_devices()}


@router.get("/traffic")
def get_traffic(
    limit: int = Query(60, ge=1, le=500),
    db: Session = Depends(get_db),
):
    svc = AlertService(db)
    return {"traffic": svc.get_traffic_stats(limit=limit)}


@router.get("/analytics")
def get_analytics(
    limit: int = Query(60, ge=1, le=500),
    db: Session = Depends(get_db),
):
    return AlertService(db).get_analytics(limit=limit)
