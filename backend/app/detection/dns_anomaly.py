"""DNS anomaly detection rule.

Monitors DNS traffic for patterns that *may* indicate suspicious behaviour:

1. A single host issuing an unusually high number of DNS queries in a
   short window (possible DNS tunneling / DGA scanning).
2. Unusually long domain names (often used in DNS tunnelling).

These are heuristics, **not** definitive malware indicators.
"""

from __future__ import annotations

import logging
import time
from collections import defaultdict
from dataclasses import dataclass, field

from app.config import DNS_COOLDOWN, DNS_LONG_DOMAIN_LENGTH, DNS_THRESHOLD, DNS_WINDOW

logger = logging.getLogger(__name__)


@dataclass
class DNSAnomalyDetector:
    """DNS anomaly detector.

    Parameters (configurable via env vars):
        threshold          – queries per source before alerting (default 50)
        window             – sliding window in seconds         (default 10)
        long_domain_length – domain length trigger             (default 50)
        cooldown           – suppress duplicate alerts          (default 60 s)
    """

    threshold: int = DNS_THRESHOLD
    window: int = DNS_WINDOW
    long_domain_length: int = DNS_LONG_DOMAIN_LENGTH
    cooldown: int = DNS_COOLDOWN

    _queries: dict[str, list[float]] = field(
        default_factory=lambda: defaultdict(list), repr=False
    )
    _cooldowns: dict[str, float] = field(default_factory=dict, repr=False)

    def _cleanup(self, now: float) -> None:
        cutoff = now - self.window
        for src in list(self._queries):
            self._queries[src] = [t for t in self._queries[src] if t >= cutoff]
            if not self._queries[src]:
                del self._queries[src]

        cd_cutoff = now - self.cooldown
        for key in list(self._cooldowns):
            if self._cooldowns[key] < cd_cutoff:
                del self._cooldowns[key]

    def evaluate(self, packet: dict) -> dict | None:
        """Evaluate a packet for DNS anomalies.

        Returns an alert dict on detection, None otherwise.
        May return different alert types depending on the anomaly.
        """
        proto = packet.get("protocol", "")
        now = packet.get("timestamp", time.time())
        src = packet.get("source_ip", "")

        # Rule 1 – long domain name
        dns_query = packet.get("dns_query")
        if dns_query and len(dns_query) > self.long_domain_length:
            alert = {
                "alert_type": "DNS_ANOMALY",
                "severity": "MEDIUM",
                "source_ip": src,
                "destination_ip": packet.get("destination_ip"),
                "source_port": packet.get("source_port"),
                "destination_port": packet.get("destination_port"),
                "protocol": proto,
                "description": (
                    f"Unusually long DNS domain ({len(dns_query)} chars): "
                    f"{dns_query[:80]}..."
                ),
                "metadata": {
                    "domain_length": len(dns_query),
                    "domain": dns_query[:120],
                    "rule": "long_domain",
                },
            }
            logger.warning("DNS_ANOMALY (long domain): %s (%d chars)", src, len(dns_query))
            return alert

        # Rule 2 – DNS query burst
        if proto != "DNS":
            return None

        self._cleanup(now)
        self._queries[src].append(now)

        count = len(self._queries[src])
        if count < self.threshold:
            return None

        last_alert = self._cooldowns.get(src, 0)
        if now - last_alert < self.cooldown:
            return None

        self._cooldowns[src] = now
        self._queries[src] = []

        alert = {
            "alert_type": "DNS_ANOMALY",
            "severity": "MEDIUM",
            "source_ip": src,
            "destination_ip": packet.get("destination_ip"),
            "source_port": packet.get("source_port"),
            "destination_port": packet.get("destination_port"),
            "protocol": proto,
            "description": (
                f"Possible DNS anomaly: {src} made {count} DNS queries "
                f"within {self.window}s (threshold: {self.threshold})"
            ),
            "metadata": {
                "query_count": count,
                "window_seconds": self.window,
                "threshold": self.threshold,
                "rule": "query_burst",
            },
        }
        logger.warning("DNS_ANOMALY (burst): %s (%d queries)", src, count)
        return alert
