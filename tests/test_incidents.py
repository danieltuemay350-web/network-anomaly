"""Deterministic tests for deduplication, correlation, scoring, and APIs."""
import os
import tempfile

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.database.database import get_db
from app.main import app
from app.models.alert import Base
from app.services.alert_service import AlertService
from app.services.incident_service import IncidentService, severity_for_score


@pytest.fixture
def db():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    engine = create_engine(f"sqlite:///{path}", connect_args={"check_same_thread": False})
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    yield session
    session.close(); engine.dispose(); os.unlink(path)


def test_related_detections_form_one_incident_with_explainable_score(db):
    service = AlertService(db)
    service.create_alert("PORT_SCAN", "HIGH", "PORT_SCAN", source_ip="192.168.56.6", destination_ip="192.168.56.5", protocol="TCP")
    service.create_alert("CONNECTION_ANOMALY", "MEDIUM", "CONNECTION_ANOMALY", source_ip="192.168.56.6", destination_ip="192.168.56.5", protocol="TCP")
    # Traffic spikes are global detector events; with one active related
    # incident, the correlation rule may safely attach the spike to it.
    service.create_alert("TRAFFIC_ANOMALY", "MEDIUM", "TRAFFIC_ANOMALY")
    incidents = IncidentService(db).get_incidents()
    assert len(incidents) == 1
    assert incidents[0].risk_score == 75
    assert incidents[0].severity == "HIGH"
    assert {alert.alert_type for alert in incidents[0].alerts} == {"PORT_SCAN", "CONNECTION_ANOMALY", "TRAFFIC_ANOMALY"}
    detail = IncidentService(db).detail(incidents[0])
    assert sum(item["score"] for item in detail["risk_contributors"]) == 75
    assert {item["category"] for item in detail["risk_contributors"]} == {"PORT_SCAN", "CONNECTION_ANOMALY", "TRAFFIC_ANOMALY"}


def test_unrelated_sources_create_separate_incidents(db):
    service = AlertService(db)
    service.create_alert("PORT_SCAN", "HIGH", "one", source_ip="192.168.56.6", destination_ip="192.168.56.5", protocol="TCP")
    service.create_alert("PORT_SCAN", "HIGH", "two", source_ip="192.168.56.7", destination_ip="192.168.56.5", protocol="TCP")
    assert len(IncidentService(db).get_incidents()) == 2


def test_identical_alerts_are_deduplicated(db):
    service = AlertService(db)
    first = service.create_alert("DNS_ANOMALY", "MEDIUM", "dns", source_ip="192.168.56.6", destination_ip="192.168.56.5", protocol="DNS")
    second = service.create_alert("DNS_ANOMALY", "MEDIUM", "dns", source_ip="192.168.56.6", destination_ip="192.168.56.5", protocol="DNS")
    assert first.id == second.id
    assert second.occurrences == 2


def test_risk_score_boundaries_are_transparent():
    assert severity_for_score(0) == "LOW"
    assert severity_for_score(30) == "MEDIUM"
    assert severity_for_score(60) == "HIGH"
    assert severity_for_score(80) == "CRITICAL"


def test_incident_api_detail_and_status_changes(db):
    alert = AlertService(db).create_alert("PORT_SCAN", "HIGH", "scan", source_ip="192.168.56.6", destination_ip="192.168.56.5", protocol="TCP")
    incident = alert.incidents[0]
    def override():
        yield db
    app.dependency_overrides[get_db] = override
    client = TestClient(app)
    assert client.get("/api/incidents").status_code == 200
    detail = client.get(f"/api/incidents/{incident.id}").json()
    assert detail["alerts"][0]["id"] == alert.id
    assert client.post(f"/api/incidents/{incident.id}/acknowledge").json()["status"] == "ACKNOWLEDGED"
    assert client.post(f"/api/incidents/{incident.id}/resolve").json()["status"] == "RESOLVED"
    app.dependency_overrides.clear()
