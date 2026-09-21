"""Incident investigation endpoints."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.database.database import get_db
from app.services.incident_service import IncidentService

router = APIRouter(prefix="/api/incidents", tags=["incidents"])


@router.get("")
def list_incidents(skip: int = Query(0, ge=0), limit: int = Query(100, ge=1, le=500), status: str | None = None, db: Session = Depends(get_db)):
    service = IncidentService(db)
    incidents = service.get_incidents(skip, limit, status)
    return {"incidents": [incident.to_dict() for incident in incidents], "count": len(incidents), "overview": service.overview()}


@router.get("/{incident_id}")
def get_incident(incident_id: int, db: Session = Depends(get_db)):
    incident = IncidentService(db).get_incident(incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    return IncidentService(db).detail(incident)


def _set_status(incident_id: int, status: str, db: Session):
    try:
        incident = IncidentService(db).update_status(incident_id, status)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    return IncidentService(db).detail(incident)


@router.post("/{incident_id}/acknowledge")
def acknowledge_incident(incident_id: int, db: Session = Depends(get_db)):
    return _set_status(incident_id, "ACKNOWLEDGED", db)


@router.post("/{incident_id}/resolve")
def resolve_incident(incident_id: int, db: Session = Depends(get_db)):
    return _set_status(incident_id, "RESOLVED", db)
