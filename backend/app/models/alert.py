"""SQLAlchemy models for the alert database."""

from __future__ import annotations

import enum
from datetime import datetime, timezone

from sqlalchemy import (
    Column,
    DateTime,
    Enum,
    Float,
    Integer,
    String,
    Text,
    ForeignKey,
    Table,
)
from sqlalchemy.orm import DeclarativeBase, relationship


class AlertStatus(str, enum.Enum):
    NEW = "NEW"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    RESOLVED = "RESOLVED"


class SeverityLevel(str, enum.Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class Base(DeclarativeBase):
    pass


incident_alerts = Table(
    "incident_alerts",
    Base.metadata,
    Column("incident_id", ForeignKey("incidents.id"), primary_key=True),
    Column("alert_id", ForeignKey("alerts.id"), primary_key=True),
)


class Alert(Base):
    __tablename__ = "alerts"

    id: int = Column(Integer, primary_key=True, autoincrement=True)
    timestamp: datetime = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    alert_type: str = Column(String(64), nullable=False, index=True)
    severity: str = Column(String(16), nullable=False, index=True)
    source_ip: str = Column(String(45), nullable=True)
    destination_ip: str = Column(String(45), nullable=True)
    source_port: int = Column(Integer, nullable=True)
    destination_port: int = Column(Integer, nullable=True)
    protocol: str = Column(String(16), nullable=True)
    description: str = Column(Text, nullable=False)
    status: str = Column(String(16), nullable=False, default=AlertStatus.NEW.value)
    extra_data: str = Column("metadata", Text, nullable=True)
    occurrences: int = Column(Integer, nullable=False, default=1)
    last_seen: datetime = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False, index=True)
    incidents = relationship("Incident", secondary=incident_alerts, back_populates="alerts")

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "alert_type": self.alert_type,
            "severity": self.severity,
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "source_port": self.source_port,
            "destination_port": self.destination_port,
            "protocol": self.protocol,
            "description": self.description,
            "status": self.status,
            "metadata": self.extra_data,
            "occurrences": self.occurrences,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
        }


class Incident(Base):
    __tablename__ = "incidents"

    id: int = Column(Integer, primary_key=True, autoincrement=True)
    title: str = Column(String(160), nullable=False)
    description: str = Column(Text, nullable=False)
    severity: str = Column(String(16), nullable=False, index=True)
    risk_score: int = Column(Integer, nullable=False, default=0, index=True)
    status: str = Column(String(16), nullable=False, default=AlertStatus.NEW.value, index=True)
    source_ip: str = Column(String(45), nullable=True, index=True)
    destination_ip: str = Column(String(45), nullable=True, index=True)
    first_seen: datetime = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc), index=True)
    last_seen: datetime = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc), index=True)
    created_at: datetime = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    alerts = relationship("Alert", secondary=incident_alerts, back_populates="incidents")
    events = relationship("IncidentEvent", back_populates="incident", cascade="all, delete-orphan")

    def to_dict(self) -> dict:
        return {
            "id": self.id, "title": self.title, "description": self.description,
            "severity": self.severity, "risk_score": self.risk_score, "status": self.status,
            "source_ip": self.source_ip, "destination_ip": self.destination_ip,
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "alert_count": len(self.alerts),
        }


class IncidentEvent(Base):
    __tablename__ = "incident_events"

    id: int = Column(Integer, primary_key=True, autoincrement=True)
    incident_id: int = Column(Integer, ForeignKey("incidents.id"), nullable=False, index=True)
    timestamp: datetime = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc), index=True)
    event_type: str = Column(String(48), nullable=False)
    description: str = Column(Text, nullable=False)
    incident = relationship("Incident", back_populates="events")

    def to_dict(self) -> dict:
        return {"id": self.id, "timestamp": self.timestamp.isoformat(), "event_type": self.event_type, "description": self.description}


class RiskContributor(Base):
    """Stored, explainable evidence contributing to an incident risk score."""
    __tablename__ = "risk_contributors"
    id: int = Column(Integer, primary_key=True, autoincrement=True)
    incident_id: int = Column(Integer, ForeignKey("incidents.id"), nullable=False, index=True)
    source: str = Column(String(64), nullable=False)
    category: str = Column(String(64), nullable=False)
    score: int = Column(Integer, nullable=False)
    confidence: float = Column(Float, nullable=False, default=1.0)
    severity: str = Column(String(16), nullable=False)
    explanation: str = Column(Text, nullable=False)
    evidence_reference: str = Column(String(128), nullable=True)
    timestamp: datetime = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    incident = relationship("Incident")

    def to_dict(self) -> dict:
        return {"id": self.id, "source": self.source, "category": self.category, "score": self.score, "confidence": self.confidence, "severity": self.severity, "explanation": self.explanation, "evidence_reference": self.evidence_reference, "timestamp": self.timestamp.isoformat()}


class ThreatIndicator(Base):
    __tablename__ = "threat_indicators"
    id: int = Column(Integer, primary_key=True)
    indicator_type: str = Column(String(16), nullable=False, index=True)
    value: str = Column(String(2048), nullable=False, index=True)
    source: str = Column(String(128), nullable=False, default="manual")
    description: str = Column(Text, nullable=True)
    tags: str = Column(Text, nullable=True)
    confidence: float = Column(Float, nullable=False, default=0.5)
    severity: str = Column(String(16), nullable=False, default="MEDIUM")
    first_seen: datetime = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    last_seen: datetime = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    expires_at: datetime = Column(DateTime, nullable=True, index=True)
    enabled: bool = Column(Integer, nullable=False, default=1)
    created_at: datetime = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))


class ThreatMatch(Base):
    __tablename__ = "threat_matches"
    id: int = Column(Integer, primary_key=True)
    indicator_id: int = Column(Integer, ForeignKey("threat_indicators.id"), nullable=False, index=True)
    indicator_value: str = Column(String(2048), nullable=False)
    matched_field: str = Column(String(32), nullable=False)
    source_ip: str = Column(String(45), nullable=True, index=True)
    destination_ip: str = Column(String(45), nullable=True, index=True)
    timestamp: datetime = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc), index=True)
    alert_id: int = Column(Integer, nullable=True, index=True)
    incident_id: int = Column(Integer, nullable=True, index=True)
    evidence: str = Column(Text, nullable=False)


class AIThreatInvestigation(Base):
    __tablename__ = "ai_threat_investigations"
    id: int = Column(Integer, primary_key=True)
    indicator_type: str = Column(String(16), nullable=False, index=True)
    indicator_value: str = Column(String(2048), nullable=False, index=True)
    reason: str = Column(Text, nullable=True)
    language: str = Column(String(8), nullable=False, default="en")
    status: str = Column(String(16), nullable=False, default="QUEUED", index=True)
    assessment: str = Column(String(32), nullable=True)
    confidence: float = Column(Float, nullable=True)
    summary: str = Column(Text, nullable=True)
    evidence: str = Column(Text, nullable=True)
    sources: str = Column(Text, nullable=True)
    limitations: str = Column(Text, nullable=True)
    model: str = Column(String(128), nullable=True)
    error: str = Column(Text, nullable=True)
    incident_id: int = Column(Integer, nullable=True, index=True)
    created_at: datetime = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    completed_at: datetime = Column(DateTime, nullable=True)


class DetectionRule(Base):
    __tablename__ = "detection_rules"
    id: int = Column(Integer, primary_key=True)
    rule_type: str = Column(String(64), nullable=False, unique=True, index=True)
    enabled: bool = Column(Integer, nullable=False, default=1)
    settings: str = Column(Text, nullable=False, default="{}")
    updated_at: datetime = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))


class CaptureConfiguration(Base):
    """One persisted analyst choice; auto remains the safe default."""
    __tablename__ = "capture_configuration"
    id: int = Column(Integer, primary_key=True, default=1)
    mode: str = Column(String(16), nullable=False, default="AUTO")
    interface_name: str = Column(String(512), nullable=True)
    updated_at: datetime = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))


class TrustedDevice(Base):
    __tablename__ = "trusted_devices"
    id: int = Column(Integer, primary_key=True)
    ip_address: str = Column(String(45), nullable=False, unique=True, index=True)
    mac_address: str = Column(String(32), nullable=True)
    hostname: str = Column(String(255), nullable=True)
    description: str = Column(Text, nullable=True)
    policy: str = Column(Text, nullable=False, default='{"suppressed_types": []}')
    created_at: datetime = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))


class AlertSuppression(Base):
    __tablename__ = "alert_suppressions"
    id: int = Column(Integer, primary_key=True)
    alert_type: str = Column(String(64), nullable=True, index=True)
    source_ip: str = Column(String(45), nullable=True, index=True)
    destination_ip: str = Column(String(45), nullable=True, index=True)
    reason: str = Column(Text, nullable=False)
    enabled: bool = Column(Integer, nullable=False, default=1)
    expires_at: datetime = Column(DateTime, nullable=True, index=True)
    created_at: datetime = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))


class ActivityEvent(Base):
    __tablename__ = "activity_events"
    id: int = Column(Integer, primary_key=True)
    timestamp: datetime = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc), index=True)
    category: str = Column(String(24), nullable=False, index=True)
    severity: str = Column(String(16), nullable=False)
    message: str = Column(Text, nullable=False)
    source_ip: str = Column(String(45), nullable=True, index=True)
    incident_id: int = Column(Integer, nullable=True, index=True)


class TrafficStat(Base):
    __tablename__ = "traffic_stats"

    id: int = Column(Integer, primary_key=True, autoincrement=True)
    timestamp: datetime = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    packets_per_second: float = Column(Float, nullable=False)
    bytes_per_second: float = Column(Float, nullable=False)
    unique_sources: int = Column(Integer, nullable=False, default=0)
    unique_destinations: int = Column(Integer, nullable=False, default=0)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "packets_per_second": self.packets_per_second,
            "bytes_per_second": self.bytes_per_second,
            "unique_sources": self.unique_sources,
            "unique_destinations": self.unique_destinations,
        }
