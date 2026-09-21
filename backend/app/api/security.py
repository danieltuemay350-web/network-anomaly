"""Analyst controls, activity, investigation, and health endpoints."""
from __future__ import annotations
import json
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy import func, or_
from sqlalchemy.orm import Session
from app.database.database import engine, get_db
from app.capture.sniffer import PacketSniffer
from app.models.alert import Alert, AlertSuppression, Incident, TrustedDevice
from app.services.security_controls import SecurityControls

router = APIRouter(prefix="/api", tags=["security"])
class RuleBody(BaseModel): enabled: bool = True; settings: dict = Field(default_factory=dict)
class TrustedBody(BaseModel): ip_address: str; description: str = ""; mac_address: str | None = None; hostname: str | None = None; policy: dict = Field(default_factory=lambda: {"suppressed_types": []})
class SuppressionBody(BaseModel): alert_type: str | None = None; source_ip: str | None = None; destination_ip: str | None = None; reason: str; enabled: bool = True; expires_at: datetime | None = None
class CaptureConfigBody(BaseModel): mode: str; interface_name: str | None = None
def rule_dict(r): return {"rule_type":r.rule_type,"enabled":bool(r.enabled),"settings":json.loads(r.settings),"updated_at":r.updated_at.isoformat()}
def trusted_dict(d): return {"id":d.id,"ip_address":d.ip_address,"description":d.description,"mac_address":d.mac_address,"hostname":d.hostname,"policy":json.loads(d.policy or '{"suppressed_types": []}'),"created_at":d.created_at.isoformat(),"updated_at":d.updated_at.isoformat()}
def suppression_dict(s): return {"id":s.id,"alert_type":s.alert_type,"source_ip":s.source_ip,"destination_ip":s.destination_ip,"reason":s.reason,"enabled":bool(s.enabled),"expires_at":s.expires_at.isoformat() if s.expires_at else None}
def capture_dict(c): return {"mode":c.mode.lower(),"selected_interface":c.interface_name,"updated_at":c.updated_at.isoformat() if c.updated_at else None}

@router.get("/network/interfaces")
def network_interfaces(db: Session = Depends(get_db)):
    return {"interfaces": PacketSniffer.available_interfaces(), **capture_dict(SecurityControls(db).capture_configuration())}

@router.get("/network/config")
def network_config(db: Session = Depends(get_db)):
    return capture_dict(SecurityControls(db).capture_configuration())

@router.put("/network/config")
def put_network_config(body: CaptureConfigBody, request: Request, db: Session = Depends(get_db)):
    mode = body.mode.upper()
    if mode not in {"AUTO", "MANUAL"}: raise HTTPException(400, "mode must be AUTO or MANUAL")
    interface_name = None
    if mode == "MANUAL":
        if not body.interface_name: raise HTTPException(400, "Select an interface for manual mode")
        item = PacketSniffer.resolve_manual_interface(body.interface_name)
        if item is None or not item.suitable:
            raise HTTPException(400, "The selected interface is no longer available. Switch to Automatic or select another interface.")
        interface_name = item.capture_name
    try:
        config = SecurityControls(db).save_capture_configuration(mode, interface_name)
        restart = getattr(request.app.state, "replace_capture", None)
        if restart: restart(interface_name if mode == "MANUAL" else "")
        return capture_dict(config)
    except Exception:
        raise HTTPException(400, "Could not start capture on the selected interface. Check capture permissions and select another interface.")

@router.get("/rules")
def rules(db: Session = Depends(get_db)): return {"rules":[rule_dict(r) for r in SecurityControls(db).rules()]}
@router.put("/rules/{rule_type}")
def put_rule(rule_type: str, body: RuleBody, request: Request, db: Session = Depends(get_db)):
    try:
        rule = SecurityControls(db).update_rule(rule_type, body.enabled, body.settings)
        engine = getattr(request.app.state, "detection_engine", None)
        if engine is not None:
            engine.apply_rule(rule.rule_type, bool(rule.enabled), json.loads(rule.settings))
        return rule_dict(rule)
    except ValueError as exc: raise HTTPException(400, str(exc))
@router.get("/trusted-devices")
def trusted_devices(db: Session = Depends(get_db)): return {"devices":[trusted_dict(d) for d in SecurityControls(db).trusted()]}
@router.post("/trusted-devices")
def add_trusted(body: TrustedBody, db: Session = Depends(get_db)):
    try: return trusted_dict(SecurityControls(db).save_trusted(body.ip_address, body.description, body.mac_address, body.hostname, body.policy))
    except ValueError as exc: raise HTTPException(400, str(exc))
@router.delete("/trusted-devices/{device_id}")
def delete_trusted(device_id: int, db: Session = Depends(get_db)):
    item=db.get(TrustedDevice,device_id)
    if not item: raise HTTPException(404,"Trusted device not found")
    db.delete(item); db.commit(); return {"deleted":True}
@router.get("/suppressions")
def suppressions(db: Session = Depends(get_db)): return {"suppressions":[suppression_dict(s) for s in SecurityControls(db).suppressions()]}
@router.post("/suppressions")
def add_suppression(body: SuppressionBody, db: Session = Depends(get_db)):
    try: return suppression_dict(SecurityControls(db).save_suppression(body.model_dump()))
    except ValueError as exc: raise HTTPException(400, str(exc))
@router.get("/activity")
def activity(limit: int = Query(100,ge=1,le=500), db: Session = Depends(get_db)):
    return {"events":[{"id":e.id,"timestamp":e.timestamp.isoformat(),"category":e.category,"severity":e.severity,"message":e.message,"source_ip":e.source_ip,"incident_id":e.incident_id} for e in SecurityControls(db).activity(limit)]}
@router.get("/investigation/ip/{ip}")
def investigate_ip(ip: str, db: Session = Depends(get_db)):
    alerts=db.query(Alert).filter(or_(Alert.source_ip==ip,Alert.destination_ip==ip)).order_by(Alert.timestamp.desc()).limit(200).all()
    incidents=db.query(Incident).filter(or_(Incident.source_ip==ip,Incident.destination_ip==ip)).order_by(Incident.last_seen.desc()).all()
    if not alerts and not incidents: raise HTTPException(404,"No stored activity for IP")
    return {"ip":ip,"alerts":[a.to_dict() for a in alerts],"incidents":[i.to_dict() for i in incidents],"first_seen":min((a.timestamp for a in alerts),default=None),"last_seen":max((a.last_seen for a in alerts),default=None),"protocols":dict(db.query(Alert.protocol,func.sum(Alert.occurrences)).filter(or_(Alert.source_ip==ip,Alert.destination_ip==ip)).group_by(Alert.protocol).all())}
@router.get("/health")
def health(): return {"api":"HEALTHY","database":"HEALTHY" if engine else "UNKNOWN"}
