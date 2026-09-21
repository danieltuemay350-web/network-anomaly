"""Offline TI normalization, matching, CRUD/import, and risk pipeline tests."""
from datetime import datetime, timedelta, timezone
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from app.models.alert import Base, ThreatMatch
from app.services.alert_service import AlertService
from app.services.incident_service import IncidentService
from app.services.threat_intelligence import ThreatIntelligenceService, normalize

def db():
    engine=create_engine("sqlite:///:memory:"); Base.metadata.create_all(engine)
    return sessionmaker(bind=engine)()

def test_normalization():
    assert normalize("192.168.56.6", "IPV4") == "192.168.56.6"
    assert normalize("2001:0DB8::1", "IPV6") == "2001:db8::1"
    assert normalize("Example.COM.", "DOMAIN") == "example.com"
    assert normalize("HTTPS://Example.COM/path/", "URL") == "https://example.com/path"

def test_active_disabled_expired_and_multiple_matches():
    session=db(); ti=ThreatIntelligenceService(session)
    one=ti.add({"indicator_type":"IPV4","value":"192.168.56.6","source":"lab","confidence":.9,"severity":"HIGH"})
    ti.add({"indicator_type":"DOMAIN","value":"evil.lab.","source":"lab"})
    ti.add({"indicator_type":"IPV4","value":"192.168.56.7","source":"lab","enabled":False})
    ti.add({"indicator_type":"IPV4","value":"192.168.56.8","source":"lab","expires_at":datetime.now(timezone.utc)-timedelta(seconds=1)})
    found=ti.match({"source_ip":"192.168.56.6","destination_ip":"192.168.56.7","dns_query":"EVIL.LAB."})
    assert {(item.id,field) for item,field in found} == {(one.id,"source_ip"),(2,"dns_query")}

def test_ti_match_to_alert_incident_and_explainable_contributor():
    session=db(); ti=ThreatIntelligenceService(session)
    indicator=ti.add({"indicator_type":"IPV4","value":"192.168.56.6","source":"local-test","confidence":.85,"severity":"HIGH","tags":"lab"})
    metadata={"source_ip":"192.168.56.6","destination_ip":"192.168.56.5","protocol":"TCP"}
    match=ti.record(indicator,"source_ip",metadata)
    alert=AlertService(session).create_alert("THREAT_INTELLIGENCE","HIGH","Threat-intelligence match: source_ip matched IPV4 indicator from local-test.",source_ip="192.168.56.6",destination_ip="192.168.56.5",protocol="TCP",metadata={"match_id":match.id,"confidence":.85,"source":"local-test"})
    incident=alert.incidents[0]; detail=IncidentService(session).detail(incident)
    contributor=next(item for item in detail["risk_contributors"] if item["category"]=="THREAT_INTELLIGENCE")
    assert contributor["score"] == 30 and "THREAT_INTELLIGENCE" in contributor["explanation"]
    assert session.query(ThreatMatch).count()==1

def test_import_reports_invalid_and_duplicate():
    session=db(); ti=ThreatIntelligenceService(session)
    summary=ti.import_records([{"indicator_type":"DOMAIN","value":"Example.com","source":"lab"},{"indicator_type":"DOMAIN","value":"example.com","source":"lab"},{"indicator_type":"IPV4","value":"bad"}])
    assert summary["new_indicators"]==1 and summary["duplicates"]==1 and len(summary["invalid_records"])==1
