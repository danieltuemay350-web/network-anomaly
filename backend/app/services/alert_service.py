"""Business logic for storing and querying alerts."""

from __future__ import annotations

import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from sqlalchemy import func
from sqlalchemy.orm import Session

from app.config import ALERT_DEDUP_WINDOW_SECONDS
from app.models.alert import Alert, AlertStatus, Incident, TrafficStat
from app.services.incident_service import IncidentService, severity_for_score
from app.services.security_controls import SecurityControls

logger = logging.getLogger(__name__)


class AlertService:
    def __init__(self, db: Session):
        self.db = db

    def create_alert(
        self,
        alert_type: str,
        severity: str,
        description: str,
        source_ip: str | None = None,
        destination_ip: str | None = None,
        source_port: int | None = None,
        destination_port: int | None = None,
        protocol: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> Alert:
        controls = SecurityControls(self.db)
        suppression = controls.matching_suppression(alert_type, source_ip, destination_ip)
        trusted_policy = controls.trusted_policy(source_ip)
        metadata = dict(metadata or {})
        trusted_suppressed = bool(trusted_policy and alert_type in trusted_policy.get("suppressed_types", []))
        if trusted_suppressed:
            metadata["suppressed"] = True
            metadata["trusted_device_policy"] = True
            metadata["suppression_reason"] = f"Source {source_ip} is trusted for {alert_type}."
        if suppression:
            metadata["suppressed"] = True
            metadata["suppression_id"] = suppression.id
            metadata["suppression_reason"] = suppression.reason
        now = datetime.now(timezone.utc)
        cutoff = now - timedelta(seconds=ALERT_DEDUP_WINDOW_SECONDS)
        # Deduplicate only an identical detection context during a short,
        # configured window. Distinct targets/types stay separate alerts.
        existing = (
            self.db.query(Alert)
            .filter(
                Alert.alert_type == alert_type,
                Alert.source_ip == source_ip,
                Alert.destination_ip == destination_ip,
                Alert.protocol == protocol,
                Alert.description == description,
                Alert.last_seen >= cutoff,
            )
            .order_by(Alert.last_seen.desc())
            .first()
        )
        if existing is not None:
            existing.occurrences += 1
            existing.last_seen = now
            self.db.commit()
            self.db.refresh(existing)
            IncidentService(self.db).correlate_alert(existing)
            logger.info("Alert deduplicated: %s (occurrences=%d)", alert_type, existing.occurrences)
            return existing
        alert = Alert(
            alert_type=alert_type,
            severity=severity,
            source_ip=source_ip,
            destination_ip=destination_ip,
            source_port=source_port,
            destination_port=destination_port,
            protocol=protocol,
            description=description,
            status=AlertStatus.NEW.value,
            extra_data=json.dumps(metadata) if metadata else None,
            timestamp=now,
            last_seen=now,
        )
        self.db.add(alert)
        self.db.commit()
        self.db.refresh(alert)
        if not suppression and not trusted_suppressed:
            incident = IncidentService(self.db).correlate_alert(alert)
            SecurityControls(self.db).add_activity("ALERT", severity, f"{alert_type} detected", source_ip, incident.id)
        else:
            reason = suppression.reason if suppression else metadata["suppression_reason"]
            SecurityControls(self.db).add_activity("ALERT", "INFO", f"{alert_type} stored but suppressed: {reason}", source_ip)
        logger.warning("Alert created: %s [%s] %s", alert_type, severity, description[:120])
        return alert

    def get_alert(self, alert_id: int) -> Alert | None:
        return self.db.query(Alert).filter(Alert.id == alert_id).first()

    def get_alerts(
        self,
        skip: int = 0,
        limit: int = 100,
        alert_type: str | None = None,
        severity: str | None = None,
        status: str | None = None,
    ) -> list[Alert]:
        q = self.db.query(Alert)
        if alert_type:
            q = q.filter(Alert.alert_type == alert_type)
        if severity:
            q = q.filter(Alert.severity == severity)
        if status:
            q = q.filter(Alert.status == status)
        return q.order_by(Alert.timestamp.desc()).offset(skip).limit(limit).all()

    def update_alert_status(self, alert_id: int, new_status: str) -> Alert | None:
        alert = self.get_alert(alert_id)
        if alert is None:
            return None
        if new_status not in [s.value for s in AlertStatus]:
            raise ValueError(f"Invalid status: {new_status}")
        alert.status = new_status
        self.db.commit()
        self.db.refresh(alert)
        return alert

    def get_stats(self) -> dict[str, Any]:
        total = self.db.query(func.count(Alert.id)).scalar() or 0
        high = self.db.query(func.count(Alert.id)).filter(Alert.severity == "HIGH").scalar() or 0
        medium = self.db.query(func.count(Alert.id)).filter(Alert.severity == "MEDIUM").scalar() or 0
        low = self.db.query(func.count(Alert.id)).filter(Alert.severity == "LOW").scalar() or 0
        critical = self.db.query(func.count(Alert.id)).filter(Alert.severity == "CRITICAL").scalar() or 0

        type_counts = dict(
            self.db.query(Alert.alert_type, func.count(Alert.id))
            .group_by(Alert.alert_type)
            .all()
        )

        unique_sources = self.db.query(func.count(func.distinct(Alert.source_ip))).scalar() or 0

        return {
            "total_alerts": total,
            "high_severity": high,
            "medium_severity": medium,
            "low_severity": low,
            "critical_severity": critical,
            "unique_source_ips": unique_sources,
            "alerts_by_type": type_counts,
        }

    def get_unique_devices(self) -> list[dict[str, Any]]:
        results = (
            self.db.query(
                Alert.source_ip,
                func.sum(Alert.occurrences).label("alert_count"),
                func.min(Alert.timestamp).label("first_seen"),
                func.max(Alert.timestamp).label("last_seen"),
                func.sum(Alert.occurrences).label("connections"),
            )
            .filter(Alert.source_ip.isnot(None))
            .group_by(Alert.source_ip)
            .order_by(func.sum(Alert.occurrences).desc())
            .all()
        )
        incident_risk = dict(
            self.db.query(Incident.source_ip, func.max(Incident.risk_score))
            .filter(Incident.source_ip.isnot(None))
            .group_by(Incident.source_ip)
            .all()
        )
        return [
            {
                "ip": r.source_ip,
                "alert_count": r.alert_count,
                "first_seen": r.first_seen.isoformat() if r.first_seen else None,
                "last_seen": r.last_seen.isoformat() if r.last_seen else None,
                "connections": int(r.connections or 0),
                "risk_score": int(incident_risk.get(r.source_ip, 0) or 0),
                "risk_level": severity_for_score(int(incident_risk.get(r.source_ip, 0) or 0)),
            }
            for r in results
        ]

    def get_analytics(self, limit: int = 60) -> dict[str, Any]:
        """Small, indexed aggregates for the polling dashboard."""
        top_sources = self.db.query(Alert.source_ip, func.sum(Alert.occurrences)).filter(Alert.source_ip.isnot(None)).group_by(Alert.source_ip).order_by(func.sum(Alert.occurrences).desc()).limit(10).all()
        top_destinations = self.db.query(Alert.destination_ip, func.sum(Alert.occurrences)).filter(Alert.destination_ip.isnot(None)).group_by(Alert.destination_ip).order_by(func.sum(Alert.occurrences).desc()).limit(10).all()
        protocol_distribution = self.db.query(Alert.protocol, func.sum(Alert.occurrences)).filter(Alert.protocol.isnot(None)).group_by(Alert.protocol).all()
        incident_counts = self.db.query(Incident.severity, func.count(Incident.id)).group_by(Incident.severity).all()
        return {
            "traffic": self.get_traffic_stats(limit),
            "protocol_distribution": [{"protocol": key, "count": int(value)} for key, value in protocol_distribution],
            "top_sources": [{"ip": key, "count": int(value)} for key, value in top_sources],
            "top_destinations": [{"ip": key, "count": int(value)} for key, value in top_destinations],
            "incidents_by_severity": dict(incident_counts),
        }

    def get_traffic_stats(self, limit: int = 60) -> list[dict[str, Any]]:
        rows = (
            self.db.query(TrafficStat)
            .order_by(TrafficStat.timestamp.desc())
            .limit(limit)
            .all()
        )
        return [r.to_dict() for r in reversed(rows)]

    def record_traffic_stat(
        self,
        packets_per_second: float,
        bytes_per_second: float,
        unique_sources: int = 0,
        unique_destinations: int = 0,
    ) -> TrafficStat:
        stat = TrafficStat(
            packets_per_second=packets_per_second,
            bytes_per_second=bytes_per_second,
            unique_sources=unique_sources,
            unique_destinations=unique_destinations,
        )
        self.db.add(stat)
        self.db.commit()
        self.db.refresh(stat)
        return stat
