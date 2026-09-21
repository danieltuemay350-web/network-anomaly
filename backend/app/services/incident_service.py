"""Alert correlation, transparent risk scoring, and incident investigation."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import func, or_
from sqlalchemy.orm import Session

from app.config import (
    CORRELATION_WINDOW_SECONDS, RISK_CRITICAL_MIN, RISK_HIGH_MIN,
    RISK_MEDIUM_MIN, RISK_SCORE_CONNECTION_BURST, RISK_SCORE_DNS_ANOMALY,
    RISK_SCORE_PORT_SCAN, RISK_SCORE_SUSPICIOUS_OUTBOUND, RISK_SCORE_TRAFFIC_SPIKE,
    RISK_SCORE_THREAT_INTELLIGENCE,
)
from app.models.alert import Alert, AlertStatus, Incident, IncidentEvent, RiskContributor

RISK_WEIGHTS = {
    "PORT_SCAN": RISK_SCORE_PORT_SCAN,
    "CONNECTION_ANOMALY": RISK_SCORE_CONNECTION_BURST,
    "TRAFFIC_ANOMALY": RISK_SCORE_TRAFFIC_SPIKE,
    "DNS_ANOMALY": RISK_SCORE_DNS_ANOMALY,
    "SUSPICIOUS_OUTBOUND": RISK_SCORE_SUSPICIOUS_OUTBOUND,
    "THREAT_INTELLIGENCE": RISK_SCORE_THREAT_INTELLIGENCE,
}


def _now() -> datetime:
    return datetime.now(timezone.utc)


def severity_for_score(score: int) -> str:
    if score >= RISK_CRITICAL_MIN:
        return "CRITICAL"
    if score >= RISK_HIGH_MIN:
        return "HIGH"
    if score >= RISK_MEDIUM_MIN:
        return "MEDIUM"
    return "LOW"


class IncidentService:
    def __init__(self, db: Session):
        self.db = db

    @staticmethod
    def _description(alert_types: set[str]) -> str:
        labels = ", ".join(sorted(alert_types))
        return f"Correlated network-security detections: {labels}."

    def _matching_incident(self, alert: Alert) -> Incident | None:
        cutoff = _now() - timedelta(seconds=CORRELATION_WINDOW_SECONDS)
        query = self.db.query(Incident).filter(
            Incident.status != AlertStatus.RESOLVED.value,
            Incident.last_seen >= cutoff,
        )
        if alert.source_ip:
            query = query.filter(Incident.source_ip == alert.source_ip)
            if alert.destination_ip:
                query = query.filter(or_(Incident.destination_ip == alert.destination_ip, Incident.destination_ip.is_(None)))
            return query.order_by(Incident.last_seen.desc()).first()

        # A global traffic spike has no endpoint. Only attach it when there is
        # exactly one recent active incident, avoiding blind correlation.
        if alert.alert_type == "TRAFFIC_ANOMALY":
            candidates = query.order_by(Incident.last_seen.desc()).limit(2).all()
            return candidates[0] if len(candidates) == 1 else None
        return None

    def _recalculate(self, incident: Incident) -> None:
        alert_types = {alert.alert_type for alert in incident.alerts}
        old_score, old_severity = incident.risk_score, incident.severity
        self.db.query(RiskContributor).filter(RiskContributor.incident_id == incident.id, RiskContributor.source == "DETECTION_RULE").delete()
        for alert_type in alert_types:
            score = RISK_WEIGHTS.get(alert_type, 0)
            self.db.add(RiskContributor(incident_id=incident.id, source="DETECTION_RULE", category=alert_type, score=score, confidence=1.0, severity=incident.severity, explanation=f"{alert_type} detection contributed {score} points.", evidence_reference=f"alert_type:{alert_type}"))
        contributors = self.db.query(RiskContributor).filter(RiskContributor.incident_id == incident.id).all()
        incident.risk_score = min(100, sum(item.score for item in contributors))
        incident.severity = severity_for_score(incident.risk_score)
        incident.description = self._description(alert_types)
        incident.updated_at = _now()
        if incident.risk_score != old_score or incident.severity != old_severity:
            self.db.add(IncidentEvent(
                incident=incident,
                event_type="RISK_UPDATED",
                description=f"Risk score changed from {old_score} to {incident.risk_score}; severity is {incident.severity}.",
            ))

    def correlate_alert(self, alert: Alert) -> Incident:
        incident = self._matching_incident(alert)
        if incident is None:
            incident = Incident(
                title=f"Network security activity: {alert.alert_type}",
                description=f"Initial detection: {alert.alert_type}.",
                severity="LOW", risk_score=0, status=AlertStatus.NEW.value,
                source_ip=alert.source_ip, destination_ip=alert.destination_ip,
                first_seen=alert.timestamp, last_seen=alert.last_seen or alert.timestamp,
            )
            self.db.add(incident)
            self.db.flush()
            self.db.add(IncidentEvent(incident=incident, event_type="INCIDENT_CREATED", description="Incident created from a stored detection."))
        if alert not in incident.alerts:
            incident.alerts.append(alert)
            self.db.add(IncidentEvent(
                incident=incident, event_type="DETECTION_CORRELATED",
                description=f"{alert.alert_type} detection correlated (alert #{alert.id}, occurrences: {alert.occurrences}).",
            ))
        # The alert is the newest stored event in this correlation operation.
        # Assign rather than compare Python datetimes because SQLite may return
        # legacy rows without timezone information.
        incident.last_seen = alert.last_seen or alert.timestamp
        self._recalculate(incident)
        self.db.commit()
        self.db.refresh(incident)
        return incident

    def get_incidents(self, skip: int = 0, limit: int = 100, status: str | None = None) -> list[Incident]:
        query = self.db.query(Incident)
        if status:
            query = query.filter(Incident.status == status)
        return query.order_by(Incident.last_seen.desc()).offset(skip).limit(limit).all()

    def get_incident(self, incident_id: int) -> Incident | None:
        return self.db.query(Incident).filter(Incident.id == incident_id).first()

    def update_status(self, incident_id: int, status: str) -> Incident | None:
        if status not in {item.value for item in AlertStatus}:
            raise ValueError(f"Invalid incident status: {status}")
        incident = self.get_incident(incident_id)
        if incident is None:
            return None
        if incident.status != status:
            previous = incident.status
            incident.status, incident.updated_at = status, _now()
            self.db.add(IncidentEvent(incident=incident, event_type="STATUS_CHANGED", description=f"Incident status changed from {previous} to {status}."))
            self.db.commit()
            self.db.refresh(incident)
        return incident

    def detail(self, incident: Incident) -> dict:
        result = incident.to_dict()
        result["alerts"] = [alert.to_dict() for alert in sorted(incident.alerts, key=lambda item: item.timestamp)]
        result["timeline"] = [event.to_dict() for event in sorted(incident.events, key=lambda item: item.timestamp)]
        result["contributing_detections"] = sorted({alert.alert_type for alert in incident.alerts})
        result["risk_contributors"] = [item.to_dict() for item in self.db.query(RiskContributor).filter(RiskContributor.incident_id == incident.id).order_by(RiskContributor.timestamp).all()]
        return result

    def overview(self) -> dict:
        rows = self.db.query(Incident.severity, func.count(Incident.id)).filter(Incident.status != AlertStatus.RESOLVED.value).group_by(Incident.severity).all()
        counts = dict(rows)
        return {"open_incidents": sum(counts.values()), **{level.lower(): counts.get(level, 0) for level in ("CRITICAL", "HIGH", "MEDIUM", "LOW")}}
