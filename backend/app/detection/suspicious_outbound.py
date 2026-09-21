"""Suspicious outbound connection detector.

Checks destination IPs against configurable lists of trusted and
suspicious networks.  This is a simple allow/block-list mechanism, **not**
a full threat-intelligence feed.
"""

from __future__ import annotations

import ipaddress
import logging
import time
from dataclasses import dataclass, field

from app.config import SUSPICIOUS_DESTINATIONS, TRUSTED_NETWORKS

logger = logging.getLogger(__name__)


@dataclass
class SuspiciousOutboundDetector:
    """Flags connections to untrusted or explicitly suspicious destinations.

    Parameters (configurable via env vars):
        trusted_networks       – CIDRs considered safe (default RFC1918)
        suspicious_destinations – IPs that always trigger an alert
    """

    trusted_networks: list[str] = field(default_factory=lambda: list(TRUSTED_NETWORKS))
    suspicious_destinations: list[str] = field(default_factory=lambda: list(SUSPICIOUS_DESTINATIONS))

    _trusted_nets: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = field(
        default_factory=list, repr=False, init=False
    )
    _suspicious_set: set[str] = field(default_factory=set, repr=False, init=False)
    _last_alerts: dict[str, float] = field(default_factory=dict, repr=False)
    _cooldown: int = 60

    def __post_init__(self) -> None:
        for cidr in self.trusted_networks:
            try:
                self._trusted_nets.append(ipaddress.ip_network(cidr, strict=False))
            except ValueError:
                logger.warning("Invalid trusted CIDR: %s", cidr)
        for ip_str in self.suspicious_destinations:
            try:
                ipaddress.ip_address(ip_str)
                self._suspicious_set.add(ip_str)
            except ValueError:
                logger.warning("Invalid suspicious IP: %s", ip_str)

    def _is_ip_in_trusted(self, ip_str: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip_str)
        except ValueError:
            return False
        return any(addr in net for net in self._trusted_nets)

    def evaluate(self, packet: dict) -> dict | None:
        """Return an alert if the outbound connection is suspicious."""
        dst = packet.get("destination_ip", "")
        src = packet.get("source_ip", "")
        now = packet.get("timestamp", time.time())

        # Explicit suspicious destination
        if dst in self._suspicious_set:
            cd_key = f"suspicious:{src}:{dst}"
            last = self._last_alerts.get(cd_key, 0)
            if now - last < self._cooldown:
                return None
            self._last_alerts[cd_key] = now

            return {
                "alert_type": "SUSPICIOUS_OUTBOUND",
                "severity": "HIGH",
                "source_ip": src,
                "destination_ip": dst,
                "source_port": packet.get("source_port"),
                "destination_port": packet.get("destination_port"),
                "protocol": packet.get("protocol"),
                "description": (
                    f"Connection to known suspicious destination: {src} -> {dst}"
                ),
                "metadata": {"reason": "blocked_destination"},
            }

        # Destination outside trusted networks
        if not self._is_ip_in_trusted(dst):
            cd_key = f"untrusted:{src}:{dst}"
            last = self._last_alerts.get(cd_key, 0)
            if now - last < self._cooldown * 5:  # longer cooldown for low-severity
                return None
            self._last_alerts[cd_key] = now

            return {
                "alert_type": "SUSPICIOUS_OUTBOUND",
                "severity": "LOW",
                "source_ip": src,
                "destination_ip": dst,
                "source_port": packet.get("source_port"),
                "destination_port": packet.get("destination_port"),
                "protocol": packet.get("protocol"),
                "description": (
                    f"Possible unusual outbound connection: {src} -> {dst} "
                    f"(destination outside configured trusted networks)"
                ),
                "metadata": {"reason": "untrusted_destination"},
            }

        return None
