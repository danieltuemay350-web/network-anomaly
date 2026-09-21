"""Tests for database operations and alert service."""

import os
import tempfile
import time

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.models.alert import Alert, Base, TrafficStat
from app.services.alert_service import AlertService


@pytest.fixture
def db_session():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    engine = create_engine(f"sqlite:///{path}", connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    yield session
    session.close()
    engine.dispose()
    os.unlink(path)


class TestAlertService:
    def test_create_alert(self, db_session):
        svc = AlertService(db_session)
        alert = svc.create_alert(
            alert_type="PORT_SCAN",
            severity="HIGH",
            description="Test scan detected",
            source_ip="10.0.0.1",
            destination_ip="10.0.0.2",
        )
        assert alert.id is not None
        assert alert.alert_type == "PORT_SCAN"
        assert alert.severity == "HIGH"
        assert alert.source_ip == "10.0.0.1"
        assert alert.status == "NEW"

    def test_get_alert(self, db_session):
        svc = AlertService(db_session)
        alert = svc.create_alert("CONNECTION_ANOMALY", "MEDIUM", "Burst detected")
        fetched = svc.get_alert(alert.id)
        assert fetched is not None
        assert fetched.alert_type == "CONNECTION_ANOMALY"

    def test_get_alert_not_found(self, db_session):
        svc = AlertService(db_session)
        assert svc.get_alert(9999) is None

    def test_get_alerts_list(self, db_session):
        svc = AlertService(db_session)
        for i in range(5):
            svc.create_alert("PORT_SCAN", "HIGH", f"Scan {i}")
        alerts = svc.get_alerts(limit=3)
        assert len(alerts) == 3

    def test_update_alert_status(self, db_session):
        svc = AlertService(db_session)
        alert = svc.create_alert("PORT_SCAN", "HIGH", "Scan")
        updated = svc.update_alert_status(alert.id, "ACKNOWLEDGED")
        assert updated.status == "ACKNOWLEDGED"

    def test_update_alert_invalid_status(self, db_session):
        svc = AlertService(db_session)
        alert = svc.create_alert("PORT_SCAN", "HIGH", "Scan")
        with pytest.raises(ValueError):
            svc.update_alert_status(alert.id, "INVALID")

    def test_get_stats(self, db_session):
        svc = AlertService(db_session)
        svc.create_alert("PORT_SCAN", "HIGH", "Scan 1")
        svc.create_alert("PORT_SCAN", "HIGH", "Scan 2")
        svc.create_alert("DNS_ANOMALY", "MEDIUM", "DNS 1")
        stats = svc.get_stats()
        assert stats["total_alerts"] == 3
        assert stats["high_severity"] == 2
        assert stats["medium_severity"] == 1
        assert "PORT_SCAN" in stats["alerts_by_type"]

    def test_filter_by_type(self, db_session):
        svc = AlertService(db_session)
        svc.create_alert("PORT_SCAN", "HIGH", "Scan")
        svc.create_alert("DNS_ANOMALY", "MEDIUM", "DNS")
        alerts = svc.get_alerts(alert_type="PORT_SCAN")
        assert len(alerts) == 1

    def test_filter_by_severity(self, db_session):
        svc = AlertService(db_session)
        svc.create_alert("PORT_SCAN", "HIGH", "Scan")
        svc.create_alert("DNS_ANOMALY", "LOW", "DNS")
        alerts = svc.get_alerts(severity="LOW")
        assert len(alerts) == 1

    def test_traffic_stat(self, db_session):
        svc = AlertService(db_session)
        stat = svc.record_traffic_stat(100.0, 50000.0, 5, 3)
        assert stat.id is not None
        assert stat.packets_per_second == 100.0

    def test_get_traffic_stats(self, db_session):
        svc = AlertService(db_session)
        for _ in range(3):
            svc.record_traffic_stat(10.0, 1000.0)
        stats = svc.get_traffic_stats(limit=10)
        assert len(stats) == 3

    def test_get_unique_devices(self, db_session):
        svc = AlertService(db_session)
        svc.create_alert("PORT_SCAN", "HIGH", "Scan", source_ip="10.0.0.1")
        svc.create_alert("PORT_SCAN", "HIGH", "Scan", source_ip="10.0.0.1")
        svc.create_alert("DNS_ANOMALY", "MEDIUM", "DNS", source_ip="10.0.0.2")
        devices = svc.get_unique_devices()
        assert len(devices) == 2
        assert devices[0]["ip"] == "10.0.0.1"
        assert devices[0]["alert_count"] == 2

    def test_alert_to_dict(self, db_session):
        svc = AlertService(db_session)
        alert = svc.create_alert(
            "PORT_SCAN", "HIGH", "Scan",
            source_ip="10.0.0.1",
            metadata={"key": "value"},
        )
        d = alert.to_dict()
        assert d["alert_type"] == "PORT_SCAN"
        assert d["metadata"] is not None
