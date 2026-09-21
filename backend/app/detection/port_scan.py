"""Port scan detection rule.

Detects when a single source IP contacts an unusually large number of
distinct destination ports on a single target host within a sliding
time window.  A cooldown prevents duplicate alerts for an ongoing scan.
"""

from __future__ import annotations

import logging
import time
from collections import defaultdict
from dataclasses import dataclass, field

from app.config import (
    PORT_SCAN_COOLDOWN,
    PORT_SCAN_THRESHOLD,
    PORT_SCAN_WINDOW,
)

logger = logging.getLogger(__name__)


@dataclass
class PortScanDetector:
    """Sliding-window port-scan detector.

    Parameters (all configurable via env vars):
        threshold – unique ports before alerting  (default 20)
        window    – time window in seconds        (default 5)
        cooldown  – suppress duplicate alerts      (default 60 s)
    """

    threshold: int = PORT_SCAN_THRESHOLD
    window: int = PORT_SCAN_WINDOW
    cooldown: int = PORT_SCAN_COOLDOWN

    # tracking: src_ip -> dst_ip -> [(port, timestamp)]
    _port_access: dict[str, dict[str, list[tuple[int, float]]]] = field(
        default_factory=lambda: defaultdict(lambda: defaultdict(list)),
        repr=False,
    )
    # cooldown: (src_ip, dst_ip) -> last_alert_time
    _cooldowns: dict[tuple[str, str], float] = field(default_factory=dict, repr=False)

    def _cleanup(self, now: float) -> None:
        cutoff = now - self.window
        for src in list(self._port_access):
            for dst in list(self._port_access[src]):
                self._port_access[src][dst] = [
                    (p, t) for p, t in self._port_access[src][dst] if t >= cutoff
                ]
                if not self._port_access[src][dst]:
                    del self._port_access[src][dst]
            if not self._port_access[src]:
                del self._port_access[src]

        cd_cutoff = now - self.cooldown
        for key in list(self._cooldowns):
            if self._cooldowns[key] < cd_cutoff:
                del self._cooldowns[key]

    def evaluate(self, packet: dict) -> dict | None:
        """Return an alert dict if a port scan is detected, else None."""
        src = packet.get("source_ip", "")
        dst = packet.get("destination_ip", "")
        dport = packet.get("destination_port")
        proto = packet.get("protocol", "")
        now = packet.get("timestamp", time.time())

        if dport is None or proto not in ("TCP", "UDP"):
            return None

        self._cleanup(now)
        self._port_access[src][dst].append((dport, now))

        unique_ports = {p for p, _ in self._port_access[src][dst]}

        if len(unique_ports) < self.threshold:
            return None

        cd_key = (src, dst)
        last_alert = self._cooldowns.get(cd_key, 0)
        if now - last_alert < self.cooldown:
            return None

        self._cooldowns[cd_key] = now
        # Reset tracking after alerting
        self._port_access[src].pop(dst, None)

        alert = {
            "alert_type": "PORT_SCAN",
            "severity": "HIGH",
            "source_ip": src,
            "destination_ip": dst,
            "source_port": packet.get("source_port"),
            "destination_port": dport,
            "protocol": proto,
            "description": (
                f"Port scan detected: {src} contacted {len(unique_ports)} "
                f"unique ports on {dst} within {self.window}s window"
            ),
            "metadata": {
                "unique_ports": len(unique_ports),
                "window_seconds": self.window,
                "threshold": self.threshold,
            },
        }
        logger.warning("PORT_SCAN: %s -> %s (%d ports)", src, dst, len(unique_ports))
        return alert
