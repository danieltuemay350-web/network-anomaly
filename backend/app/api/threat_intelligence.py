from __future__ import annotations
from datetime import datetime
import csv, json
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from app.database.database import get_db
from app.models.alert import AIThreatInvestigation, ThreatIndicator, ThreatMatch
from app.ai.service import InvestigationService
from app.services.threat_intelligence import ThreatIntelligenceService

router=APIRouter(prefix="/api/threat-intelligence",tags=["threat-intelligence"])
class InvestigationBody(BaseModel): indicator_type:str; indicator_value:str; reason:str|None=None; incident_id:int|None=None; language:str="en"
def investigation_out(item):
    try: error=json.loads(item.error) if item.error else None
    except (TypeError,json.JSONDecodeError): error={"error_type":"legacy","message":item.error}
    return {"id":item.id,"indicator_type":item.indicator_type,"indicator_value":item.indicator_value,"reason":item.reason,"language":getattr(item,"language","en"),"status":item.status,"assessment":item.assessment,"confidence":item.confidence,"summary":item.summary,"evidence":json.loads(item.evidence or "[]"),"sources":json.loads(item.sources or "[]"),"limitations":json.loads(item.limitations or "[]"),"model":item.model,"error":error,"incident_id":item.incident_id,"created_at":item.created_at.isoformat(),"completed_at":item.completed_at.isoformat() if item.completed_at else None}
class IndicatorBody(BaseModel):
    indicator_type:str; value:str; source:str="manual"; description:str|None=None; tags:str|None=None; confidence:float=.5; severity:str="MEDIUM"; expires_at:datetime|None=None; enabled:bool=True
def out(i): return {"id":i.id,"indicator_type":i.indicator_type,"value":i.value,"source":i.source,"description":i.description,"tags":i.tags,"confidence":i.confidence,"severity":i.severity,"enabled":bool(i.enabled),"expires_at":i.expires_at.isoformat() if i.expires_at else None}
@router.get("/indicators")
def indicators(search:str|None=None, indicator_type:str|None=None, severity:str|None=None, status:str|None=None, limit:int=Query(200,ge=1,le=500), db:Session=Depends(get_db)):
    query=db.query(ThreatIndicator)
    if search: query=query.filter(ThreatIndicator.value.contains(search.casefold()))
    if indicator_type: query=query.filter(ThreatIndicator.indicator_type==indicator_type.upper())
    if severity: query=query.filter(ThreatIndicator.severity==severity.upper())
    if status=="DISABLED": query=query.filter(ThreatIndicator.enabled==0)
    if status=="ACTIVE": query=query.filter(ThreatIndicator.enabled==1, (ThreatIndicator.expires_at.is_(None)) | (ThreatIndicator.expires_at>datetime.now().astimezone()))
    return {"indicators":[out(i) for i in query.order_by(ThreatIndicator.updated_at.desc()).limit(limit)]}
@router.post("/indicators")
def create(body:IndicatorBody,db:Session=Depends(get_db)):
    try:return out(ThreatIntelligenceService(db).add(body.model_dump()))
    except ValueError as exc:raise HTTPException(400,str(exc))
@router.get("/indicators/{indicator_id}")
def get_indicator(indicator_id:int,db:Session=Depends(get_db)):
    item=ThreatIntelligenceService(db).get(indicator_id)
    if not item: raise HTTPException(404,"Indicator not found")
    return out(item)
@router.put("/indicators/{indicator_id}")
def update_indicator(indicator_id:int,body:IndicatorBody,db:Session=Depends(get_db)):
    try: item=ThreatIntelligenceService(db).update(indicator_id,body.model_dump())
    except ValueError as exc: raise HTTPException(400,str(exc))
    if not item: raise HTTPException(404,"Indicator not found")
    return out(item)
@router.delete("/indicators/{indicator_id}")
def delete_indicator(indicator_id:int,db:Session=Depends(get_db)):
    item=ThreatIntelligenceService(db).disable(indicator_id)
    if not item: raise HTTPException(404,"Indicator not found")
    return {"id":item.id,"enabled":False,"message":"Indicator disabled; historical matches preserved."}
class ImportBody(BaseModel): format:str; content:str
@router.post("/import")
def import_indicators(body:ImportBody,db:Session=Depends(get_db)):
    try:
        if body.format.lower()=="json":
            # Older dashboard versions always label pasted content as JSON.
            # Accept a CSV header as a safe compatibility fallback.
            try: records=json.loads(body.content); records=records.get("indicators",records) if isinstance(records,dict) else records
            except json.JSONDecodeError:
                if "," not in body.content.splitlines()[0]: raise
                records=list(csv.DictReader(body.content.splitlines()))
        elif body.format.lower()=="csv": records=list(csv.DictReader(body.content.splitlines()))
        else: raise ValueError("format must be json or csv")
        if not isinstance(records,list): raise ValueError("import must contain a list of records")
        return ThreatIntelligenceService(db).import_records(records)
    except (ValueError,json.JSONDecodeError) as exc: raise HTTPException(400,str(exc))
@router.get("/matches")
def matches(indicator_id:int|None=None, source_ip:str|None=None, db:Session=Depends(get_db)):
    query=db.query(ThreatMatch)
    if indicator_id: query=query.filter(ThreatMatch.indicator_id==indicator_id)
    if source_ip: query=query.filter(ThreatMatch.source_ip==source_ip)
    return {"matches":[{"id":m.id,"indicator_id":m.indicator_id,"indicator_value":m.indicator_value,"matched_field":m.matched_field,"timestamp":m.timestamp.isoformat(),"source_ip":m.source_ip,"destination_ip":m.destination_ip,"alert_id":m.alert_id,"incident_id":m.incident_id,"evidence":m.evidence} for m in query.order_by(ThreatMatch.timestamp.desc()).limit(200)]}
@router.get("/stats")
def stats(db:Session=Depends(get_db)):
    now=datetime.now().astimezone()
    return {"total_indicators":db.query(ThreatIndicator).count(),"active_indicators":len(ThreatIntelligenceService(db).active()),"disabled_indicators":db.query(ThreatIndicator).filter(ThreatIndicator.enabled==0).count(),"expired_indicators":db.query(ThreatIndicator).filter(ThreatIndicator.expires_at.isnot(None),ThreatIndicator.expires_at<=now).count(),"recent_matches":db.query(ThreatMatch).count()}

@router.post("/investigations")
def investigate(body: InvestigationBody, db: Session = Depends(get_db)):
    try: return investigation_out(InvestigationService(db).create(body.model_dump()))
    except ValueError as exc: raise HTTPException(400,str(exc))

@router.get("/investigations")
def investigations(db: Session = Depends(get_db)):
    return {"investigations":[investigation_out(row) for row in db.query(AIThreatInvestigation).order_by(AIThreatInvestigation.created_at.desc()).limit(200)]}

@router.get("/investigations/{investigation_id}")
def investigation(investigation_id:int,db:Session=Depends(get_db)):
    row=db.get(AIThreatInvestigation,investigation_id)
    if not row: raise HTTPException(404,"Investigation not found")
    return investigation_out(row)
