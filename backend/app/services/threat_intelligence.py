"""Offline, normalized threat-intelligence indicators and metadata matcher."""
from __future__ import annotations
import ipaddress, json
from datetime import datetime, timezone
from urllib.parse import urlsplit
from sqlalchemy.orm import Session
from app.models.alert import ThreatIndicator, ThreatMatch

def normalize(value: str, indicator_type: str) -> str:
    value = value.strip()
    if indicator_type in {"IPV4", "IPV6"}: return str(ipaddress.ip_address(value))
    if indicator_type == "DOMAIN": return value.rstrip(".").casefold()
    if indicator_type == "URL":
        parsed=urlsplit(value if "://" in value else f"http://{value}")
        if not parsed.netloc: raise ValueError("Invalid URL")
        return f"{parsed.scheme.casefold()}://{parsed.netloc.casefold()}{parsed.path.rstrip('/')}"
    raise ValueError("Unsupported indicator type")

class ThreatIntelligenceService:
    def __init__(self, db: Session): self.db=db
    def add(self, data: dict):
        kind=data["indicator_type"].upper(); value=normalize(data["value"],kind)
        if not 0 <= float(data.get("confidence",.5)) <= 1: raise ValueError("confidence must be 0..1")
        item=self.db.query(ThreatIndicator).filter_by(indicator_type=kind,value=value,source=data.get("source","manual")).first()
        now=datetime.now(timezone.utc)
        if item is None: item=ThreatIndicator(indicator_type=kind,value=value,source=data.get("source","manual"),first_seen=now)
        for key in ("description","tags","confidence","severity","expires_at","enabled"): 
            if key in data: setattr(item,key,data[key])
        item.last_seen=item.updated_at=now; self.db.add(item); self.db.commit(); self.db.refresh(item); return item
    def get(self, indicator_id: int): return self.db.get(ThreatIndicator, indicator_id)
    def update(self, indicator_id: int, data: dict):
        item=self.get(indicator_id)
        if item is None: return None
        data={**{"indicator_type":item.indicator_type,"value":item.value,"source":item.source},**data}
        # Changing normalized identity creates/updates the canonical record;
        # callers normally change metadata only.
        if data["indicator_type"].upper()!=item.indicator_type or normalize(data["value"],data["indicator_type"].upper())!=item.value:
            return self.add(data)
        for key in ("source","description","tags","confidence","severity","expires_at","enabled"):
            if key in data: setattr(item,key,data[key])
        item.updated_at=datetime.now(timezone.utc); self.db.commit(); self.db.refresh(item); return item
    def disable(self, indicator_id: int):
        item=self.get(indicator_id)
        if item is None:return None
        item.enabled=0; item.updated_at=datetime.now(timezone.utc); self.db.commit(); return item
    def import_records(self, records: list[dict]):
        summary={"total_records":len(records),"new_indicators":0,"updated_indicators":0,"duplicates":0,"invalid_records":[]}
        for index,data in enumerate(records,1):
            try:
                kind=data.get("indicator_type","").upper(); value=normalize(str(data.get("value","")),kind)
                existed=self.db.query(ThreatIndicator).filter_by(indicator_type=kind,value=value,source=data.get("source","manual")).first()
                self.add({**data,"indicator_type":kind,"value":value})
                if existed: summary["updated_indicators"]+=1; summary["duplicates"]+=1
                else: summary["new_indicators"]+=1
            except (ValueError,TypeError) as exc: summary["invalid_records"].append({"record":index,"error":str(exc)})
        return summary
    def active(self):
        now=datetime.now(timezone.utc)
        return self.db.query(ThreatIndicator).filter(ThreatIndicator.enabled==1).filter((ThreatIndicator.expires_at.is_(None)) | (ThreatIndicator.expires_at>now)).all()
    def match(self, metadata: dict):
        values=[("source_ip",metadata.get("source_ip")),("destination_ip",metadata.get("destination_ip")),("dns_query",metadata.get("dns_query"))]
        active={(item.indicator_type,item.value):item for item in self.active()}
        found=[]
        for field,value in values:
            if not value: continue
            for kind in (["IPV4","IPV6"] if field.endswith("ip") else ["DOMAIN"]):
                try: indicator=active.get((kind,normalize(value,kind)))
                except ValueError: indicator=None
                if indicator: found.append((indicator,field))
        return found
    def record(self, indicator, field, metadata, alert_id=None, incident_id=None):
        evidence={"indicator_type":indicator.indicator_type,"source":indicator.source,"confidence":indicator.confidence,"severity":indicator.severity,"tags":indicator.tags}
        match=ThreatMatch(indicator_id=indicator.id,indicator_value=indicator.value,matched_field=field,source_ip=metadata.get("source_ip"),destination_ip=metadata.get("destination_ip"),alert_id=alert_id,incident_id=incident_id,evidence=json.dumps(evidence))
        self.db.add(match); self.db.commit(); return match
