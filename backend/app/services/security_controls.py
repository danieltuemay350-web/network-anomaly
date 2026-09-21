"""Persisted analyst controls kept outside the packet-capture path."""
from __future__ import annotations

import ipaddress
import json
from datetime import datetime, timezone

from sqlalchemy import or_
from sqlalchemy.orm import Session

from app.models.alert import ActivityEvent, AlertSuppression, CaptureConfiguration, DetectionRule, TrustedDevice

RULE_TYPES = {"PORT_SCAN", "CONNECTION_BURST", "TRAFFIC_SPIKE", "DNS_ANOMALY", "UNTRUSTED_OUTBOUND"}


class SecurityControls:
    def __init__(self, db: Session): self.db = db

    def rules(self): return self.db.query(DetectionRule).order_by(DetectionRule.rule_type).all()

    def update_rule(self, rule_type: str, enabled: bool, settings: dict):
        if rule_type not in RULE_TYPES or not isinstance(settings, dict): raise ValueError("Unknown rule or invalid settings")
        for key, value in settings.items():
            if key in {"threshold", "window", "cooldown", "multiplier", "min_samples"} and (not isinstance(value, (int, float)) or isinstance(value, bool) or value < 0):
                raise ValueError(f"Invalid {key}")
        rule = self.db.query(DetectionRule).filter_by(rule_type=rule_type).first() or DetectionRule(rule_type=rule_type)
        rule.enabled, rule.settings, rule.updated_at = int(enabled), json.dumps(settings), datetime.now(timezone.utc)
        self.db.add(rule); self.db.commit(); return rule

    def capture_configuration(self):
        return self.db.get(CaptureConfiguration, 1) or CaptureConfiguration(id=1, mode="AUTO")

    def save_capture_configuration(self, mode: str, interface_name: str | None):
        item = self.db.get(CaptureConfiguration, 1) or CaptureConfiguration(id=1)
        item.mode, item.interface_name, item.updated_at = mode, interface_name, datetime.now(timezone.utc)
        self.db.add(item); self.db.commit(); self.db.refresh(item); return item

    def trusted(self): return self.db.query(TrustedDevice).order_by(TrustedDevice.ip_address).all()

    def save_trusted(self, ip: str, description: str = "", mac: str | None = None, hostname: str | None = None, policy: dict | None = None):
        try: ipaddress.ip_address(ip)
        except ValueError: raise ValueError("Invalid IP address")
        device = self.db.query(TrustedDevice).filter_by(ip_address=ip).first() or TrustedDevice(ip_address=ip)
        device.description, device.mac_address, device.hostname, device.updated_at = description, mac, hostname, datetime.now(timezone.utc)
        if policy is not None:
            types = policy.get("suppressed_types", [])
            if not isinstance(types, list) or any(not isinstance(item, str) for item in types): raise ValueError("Invalid trusted-device policy")
            device.policy = json.dumps({"suppressed_types": types})
        self.db.add(device); self.db.commit(); return device

    def trusted_policy(self, ip: str | None) -> dict | None:
        if not ip: return None
        item = self.db.query(TrustedDevice).filter_by(ip_address=ip).first()
        return json.loads(item.policy) if item else None

    def suppressions(self): return self.db.query(AlertSuppression).order_by(AlertSuppression.created_at.desc()).all()

    def save_suppression(self, data: dict):
        if not data.get("reason") or not any(data.get(k) for k in ("alert_type", "source_ip", "destination_ip")): raise ValueError("Reason and at least one match criterion are required")
        item = AlertSuppression(**data); self.db.add(item); self.db.commit(); return item

    def matching_suppression(self, alert_type, source, destination):
        now = datetime.now(timezone.utc)
        return self.db.query(AlertSuppression).filter(AlertSuppression.enabled == 1, or_(AlertSuppression.expires_at.is_(None), AlertSuppression.expires_at > now)).filter(
            or_(AlertSuppression.alert_type.is_(None), AlertSuppression.alert_type == alert_type),
            or_(AlertSuppression.source_ip.is_(None), AlertSuppression.source_ip == source),
            or_(AlertSuppression.destination_ip.is_(None), AlertSuppression.destination_ip == destination),
        ).first()

    def activity(self, limit=100): return self.db.query(ActivityEvent).order_by(ActivityEvent.timestamp.desc()).limit(limit).all()
    def add_activity(self, category, severity, message, source_ip=None, incident_id=None):
        item = ActivityEvent(category=category, severity=severity, message=message, source_ip=source_ip, incident_id=incident_id)
        self.db.add(item); self.db.commit(); return item
