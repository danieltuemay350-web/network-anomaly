"""Central detection engine.

Receives packet metadata from the capture layer and evaluates every
active detection rule.  Alerts are forwarded to the alert service for
persistence.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Callable

from app.capture.sniffer import PacketMetadata
from app.detection.connection_anomaly import ConnectionBurstDetector
from app.detection.dns_anomaly import DNSAnomalyDetector
from app.detection.port_scan import PortScanDetector
from app.detection.suspicious_outbound import SuspiciousOutboundDetector
from app.detection.traffic_anomaly import TrafficSpikeDetector

logger = logging.getLogger(__name__)


@dataclass
class DetectionEngine:
    """Orchestrates all detection rules.

    The engine holds one instance of each detector and evaluates incoming
    packets against all of them.  Alerts are forwarded via *alert_callback*.
    """

    alert_callback: Callable[[dict], None]
    traffic_stat_callback: Callable[[dict], None] | None = None
    threat_matcher: Callable[[dict], list[dict]] | None = None

    port_scan: PortScanDetector = field(default_factory=PortScanDetector)
    connection_burst: ConnectionBurstDetector = field(default_factory=ConnectionBurstDetector)
    traffic_spike: TrafficSpikeDetector = field(default_factory=TrafficSpikeDetector)
    dns_anomaly: DNSAnomalyDetector = field(default_factory=DNSAnomalyDetector)
    suspicious_outbound: SuspiciousOutboundDetector = field(default_factory=SuspiciousOutboundDetector)

    _evaluators: list = field(init=False, repr=False)

    _packet_count: int = 0
    _alert_count: int = 0
    _rule_overrides: dict[str, dict] = field(default_factory=dict, repr=False)

    def __post_init__(self) -> None:
        self._evaluators = [
            self.port_scan,
            self.connection_burst,
            self.traffic_spike,
            self.dns_anomaly,
            self.suspicious_outbound,
        ]

    def process_packet(self, meta: PacketMetadata) -> None:
        """Evaluate a single packet against all detection rules."""
        self._packet_count += 1
        packet = meta.to_dict()

        for evaluator in self._evaluators:
            try:
                rule_type = {
                    "PortScanDetector": "PORT_SCAN", "ConnectionBurstDetector": "CONNECTION_BURST",
                    "TrafficSpikeDetector": "TRAFFIC_SPIKE", "DNSAnomalyDetector": "DNS_ANOMALY",
                    "SuspiciousOutboundDetector": "UNTRUSTED_OUTBOUND",
                }[type(evaluator).__name__]
                override = self._rule_overrides.get(rule_type, {})
                if override and not override.get("enabled", True):
                    continue
                result = evaluator.evaluate(packet)
                if result is not None:
                    if override.get("severity"):
                        result["severity"] = override["severity"]
                    result.setdefault("timestamp", time.strftime(
                        "%Y-%m-%dT%H:%M:%SZ", time.gmtime(meta.timestamp)
                    ))
                    self._alert_count += 1
                    self.alert_callback(result)
            except Exception:
                logger.exception("Error in detector %s", type(evaluator).__name__)

        if self.threat_matcher:
            try:
                for match in self.threat_matcher(packet):
                    self.alert_callback(match)
            except Exception:
                logger.exception("Threat-intelligence matcher failed")

        # Traffic stats (sampled every 10 packets to reduce DB writes)
        if self.traffic_stat_callback and self._packet_count % 10 == 0:
            stats = self.traffic_spike.get_current_stats()
            stats["timestamp"] = meta.timestamp
            try:
                self.traffic_stat_callback(stats)
            except Exception:
                logger.exception("Error recording traffic stats")

    def apply_rule(self, rule_type: str, enabled: bool, settings: dict) -> None:
        """Apply persisted settings to existing detector objects immediately."""
        mapping = {
            "PORT_SCAN": self.port_scan, "CONNECTION_BURST": self.connection_burst,
            "TRAFFIC_SPIKE": self.traffic_spike, "DNS_ANOMALY": self.dns_anomaly,
            "UNTRUSTED_OUTBOUND": self.suspicious_outbound,
        }
        detector = mapping.get(rule_type)
        if detector is None:
            raise ValueError(f"Unknown rule type: {rule_type}")
        allowed = {"threshold", "window", "cooldown", "multiplier", "min_samples", "long_domain_length", "severity"}
        for name, value in settings.items():
            if name in allowed and name != "severity" and hasattr(detector, name):
                setattr(detector, name, value)
        self._rule_overrides[rule_type] = {"enabled": enabled, **settings}

    @property
    def packet_count(self) -> int:
        return self._packet_count

    @property
    def alert_count(self) -> int:
        return self._alert_count
