"""Tests for REST API endpoints."""

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
from app.capture.sniffer import InterfaceInfo, PacketSniffer

# Override DB for tests
_test_engine = None
_TestSession = None


@pytest.fixture(autouse=True)
def setup_test_db():
    global _test_engine, _TestSession
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    _test_engine = create_engine(f"sqlite:///{path}", connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=_test_engine)
    _TestSession = sessionmaker(bind=_test_engine)

    def _override():
        db = _TestSession()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = _override
    yield
    app.dependency_overrides.clear()
    _test_engine.dispose()
    os.unlink(path)


@pytest.fixture
def client():
    return TestClient(app)


class TestHealthEndpoint:
    def test_health(self, client):
        resp = client.get("/api/health")
        assert resp.status_code == 200
        assert resp.json()["status"] == "ok"


class TestAlertsEndpoint:
    def test_list_empty(self, client):
        resp = client.get("/api/alerts")
        assert resp.status_code == 200
        assert resp.json()["count"] == 0

    def test_create_and_list(self, client):
        db = _TestSession()
        svc = AlertService(db)
        svc.create_alert("PORT_SCAN", "HIGH", "Test scan", source_ip="10.0.0.1")
        db.close()

        resp = client.get("/api/alerts")
        assert resp.status_code == 200
        assert resp.json()["count"] == 1

    def test_get_alert_by_id(self, client):
        db = _TestSession()
        svc = AlertService(db)
        alert = svc.create_alert("DNS_ANOMALY", "MEDIUM", "Test DNS")
        alert_id = alert.id
        db.close()

        resp = client.get(f"/api/alerts/{alert_id}")
        assert resp.status_code == 200
        assert resp.json()["alert_type"] == "DNS_ANOMALY"

    def test_get_alert_not_found(self, client):
        resp = client.get("/api/alerts/9999")
        assert resp.status_code == 404

    def test_update_alert_status(self, client):
        db = _TestSession()
        svc = AlertService(db)
        alert = svc.create_alert("PORT_SCAN", "HIGH", "Scan")
        alert_id = alert.id
        db.close()

        resp = client.patch(f"/api/alerts/{alert_id}", json={"status": "ACKNOWLEDGED"})
        assert resp.status_code == 200
        assert resp.json()["status"] == "ACKNOWLEDGED"

    def test_update_invalid_status(self, client):
        db = _TestSession()
        svc = AlertService(db)
        alert = svc.create_alert("PORT_SCAN", "HIGH", "Scan")
        alert_id = alert.id
        db.close()

        resp = client.patch(f"/api/alerts/{alert_id}", json={"status": "INVALID"})
        assert resp.status_code == 400


class TestStatsEndpoint:
    def test_stats(self, client):
        resp = client.get("/api/stats")
        assert resp.status_code == 200
        data = resp.json()
        assert "total_alerts" in data
        assert "alerts_by_type" in data


class TestDevicesEndpoint:
    def test_devices_empty(self, client):
        resp = client.get("/api/devices")
        assert resp.status_code == 200
        assert resp.json()["devices"] == []


class TestTrafficEndpoint:
    def test_traffic_empty(self, client):
        resp = client.get("/api/traffic")
        assert resp.status_code == 200
        assert resp.json()["traffic"] == []


class TestNetworkConfiguration:
    def test_interfaces_and_invalid_manual_interface(self, client, monkeypatch):
        info = InterfaceInfo("Dynamic adapter", "dynamic0", "192.0.2.10", aliases=("dynamic0",))
        monkeypatch.setattr(PacketSniffer, "_interface_infos", classmethod(lambda cls: [info]))
        assert client.get("/api/network/interfaces").json()["interfaces"][0]["name"] == "Dynamic adapter"
        response = client.put("/api/network/config", json={"mode": "MANUAL", "interface_name": "gone0"})
        assert response.status_code == 400

    def test_auto_configuration_keeps_no_manual_interface(self, client):
        response = client.put("/api/network/config", json={"mode": "AUTO"})
        assert response.status_code == 200
        assert response.json()["mode"] == "auto"
        assert response.json()["selected_interface"] is None


class TestTrustedDevicePolicy:
    def test_trusted_policy_preserves_alert_but_skips_incident(self, client):
        created = client.post("/api/trusted-devices", json={"ip_address":"192.0.2.44","description":"lab","policy":{"suppressed_types":["PORT_SCAN"]}})
        assert created.status_code == 200
        db = _TestSession()
        alert = AlertService(db).create_alert("PORT_SCAN", "HIGH", "lab scan", source_ip="192.0.2.44")
        assert alert.incidents == []
        assert 'trusted_device_policy' in alert.extra_data
        db.close()
