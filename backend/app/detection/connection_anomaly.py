"""Connection burst detection rule.

Detects when a source host generates an abnormally high number of
connection attempts within a short time window.
"""

from __future__ import annotations

import logging
import time
from collections import defaultdict
from dataclasses import dataclass, field

from app.config import CONNECTION_COOLDOWN, CONNECTION_THRESHOLD, CONNECTION_WINDOW

logger = logging.getLogger(__name__)


@dataclass
class ConnectionBurstDetector:
    """Detects connection bursts from a single source IP.

    Parameters (configurable via env vars):
        threshold – max connections before alerting  (default 100)
        window    – time window in seconds           (default 10)
        cooldown  – suppress duplicate alerts         (default 60 s)
    """

    threshold: int = CONNECTION_THRESHOLD
    window: int = CONNECTION_WINDOW
    cooldown: int = CONNECTION_COOLDOWN

    _connections: dict[str, list[float]] = field(
        default_factory=lambda: defaultdict(list), repr=False
    )
    _cooldowns: dict[str, float] = field(default_factory=dict, repr=False)

    def _cleanup(self, now: float) -> None:
        cutoff = now - self.window
        for src in list(self._connections):
            self._connections[src] = [t for t in self._connections[src] if t >= cutoff]
            if not self._connections[src]:
                del self._connections[src]

        cd_cutoff = now - self.cooldown
        for key in list(self._cooldowns):
            if self._cooldowns[key] < cd_cutoff:
                del self._cooldowns[key]

    def evaluate(self, packet: dict) -> dict | None:
        """Return an alert dict if a connection burst is detected, else None."""
        src = packet.get("source_ip", "")
        proto = packet.get("protocol", "")
        now = packet.get("timestamp", time.time())

        if proto not in ("TCP", "UDP"):
            return None

        self._cleanup(now)
        self._connections[src].append(now)

        count = len(self._connections[src])
        if count < self.threshold:
            return None

        last_alert = self._cooldowns.get(src, 0)
        if now - last_alert < self.cooldown:
            return None

        self._cooldowns[src] = now
        self._connections[src] = []

        alert = {
            "alert_type": "CONNECTION_ANOMALY",
            "severity": "MEDIUM",
            "source_ip": src,
            "destination_ip": packet.get("destination_ip"),
            "source_port": packet.get("source_port"),
            "destination_port": packet.get("destination_port"),
            "protocol": proto,
            "description": (
                f"Connection burst detected: {src} made {count} "
                f"connection attempts within {self.window}s"
            ),
            "metadata": {
                "connection_count": count,
                "window_seconds": self.window,
                "threshold": self.threshold,
            },
        }
        logger.warning("CONNECTION_ANOMALY: %s (%d connections)", src, count)
        return alert
