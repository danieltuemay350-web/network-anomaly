"""Traffic spike detection rule.

Uses a simple baseline comparison: compute the average traffic rate
over a historical window and alert when the *current* rate exceeds a
configurable multiple of that baseline.
"""

from __future__ import annotations

import logging
import time
from collections import deque
from dataclasses import dataclass, field

from app.config import TRAFFIC_BASELINE_WINDOW, TRAFFIC_COOLDOWN, TRAFFIC_MIN_SAMPLES, TRAFFIC_SPIKE_MULTIPLIER

logger = logging.getLogger(__name__)


@dataclass
class TrafficSpikeDetector:
    """Baseline-comparison traffic spike detector.

    Maintains a rolling window of per-second packet counts and byte
    totals.  When enough samples exist and the latest second's values
    exceed *multiplier* × baseline, an alert fires.

    Parameters (configurable via env vars):
        baseline_window – seconds of history to average  (default 60)
        multiplier      – spike threshold factor         (default 3.0)
        min_samples     – samples before baseline valid  (default 5)
        cooldown        – suppress duplicate alerts       (default 30 s)
    """

    baseline_window: int = TRAFFIC_BASELINE_WINDOW
    multiplier: float = TRAFFIC_SPIKE_MULTIPLIER
    min_samples: int = TRAFFIC_MIN_SAMPLES
    cooldown: int = TRAFFIC_COOLDOWN

    # Per-second buckets: deque of (epoch_second, pkt_count, byte_count)
    _buckets: deque[tuple[int, int, int]] = field(default_factory=lambda: deque(), repr=False)
    _current_second: int = 0
    _current_pkts: int = 0
    _current_bytes: int = 0
    _last_alert: float = 0.0

    # Unique src/dst tracking for the current second
    _src_ips: set[str] = field(default_factory=set, repr=False)
    _dst_ips: set[str] = field(default_factory=set, repr=False)

    def _record_bucket(self, epoch_sec: int) -> None:
        self._buckets.append((epoch_sec, self._current_pkts, self._current_bytes))
        cutoff = epoch_sec - self.baseline_window
        while self._buckets and self._buckets[0][0] < cutoff:
            self._buckets.popleft()

    def evaluate(self, packet: dict) -> dict | None:
        """Evaluate a packet for traffic spike anomalies.

        Returns an alert dict on spike, None otherwise.
        Also returns traffic stats for the caller to persist.
        """
        now: float = packet.get("timestamp", time.time())
        pkt_size: int = packet.get("packet_size", 0)
        epoch_sec = int(now)

        if self._current_second == 0:
            self._current_second = epoch_sec

        if epoch_sec != self._current_second:
            self._record_bucket(self._current_second)
            self._current_second = epoch_sec
            self._current_pkts = 0
            self._current_bytes = 0
            self._src_ips = set()
            self._dst_ips = set()

        self._current_pkts += 1
        self._current_bytes += pkt_size
        self._src_ips.add(packet.get("source_ip", ""))
        self._dst_ips.add(packet.get("destination_ip", ""))

        # Need at least min_samples buckets to compute a baseline
        if len(self._buckets) < self.min_samples:
            return None

        avg_pkts = sum(b[1] for b in self._buckets) / len(self._buckets)
        avg_bytes = sum(b[2] for b in self._buckets) / len(self._buckets)

        spike_pkts = self._current_pkts > avg_pkts * self.multiplier if avg_pkts > 0 else False
        spike_bytes = self._current_bytes > avg_bytes * self.multiplier if avg_bytes > 0 else False

        if not (spike_pkts or spike_bytes):
            return None

        now_f = time.time()
        if now_f - self._last_alert < self.cooldown:
            return None
        self._last_alert = now_f

        alert = {
            "alert_type": "TRAFFIC_ANOMALY",
            "severity": "MEDIUM",
            "source_ip": None,
            "destination_ip": None,
            "source_port": None,
            "destination_port": None,
            "protocol": None,
            "description": (
                f"Traffic spike: current rate "
                f"({self._current_pkts} pkts/s, {self._current_bytes} B/s) "
                f"exceeds {self.multiplier}× baseline "
                f"({avg_pkts:.0f} pkts/s, {avg_bytes:.0f} B/s)"
            ),
            "metadata": {
                "current_pps": self._current_pkts,
                "current_bps": self._current_bytes,
                "baseline_pps": round(avg_pkts, 2),
                "baseline_bps": round(avg_bytes, 2),
                "multiplier": self.multiplier,
            },
        }
        logger.warning(
            "TRAFFIC_ANOMALY: %d pps (baseline %.0f) | %d Bps (baseline %.0f)",
            self._current_pkts,
            avg_pkts,
            self._current_bytes,
            avg_bytes,
        )
        return alert

    def get_current_stats(self) -> dict:
        """Return stats about the current traffic state."""
        avg_pkts = 0.0
        avg_bytes = 0.0
        if self._buckets:
            avg_pkts = sum(b[1] for b in self._buckets) / len(self._buckets)
            avg_bytes = sum(b[2] for b in self._buckets) / len(self._buckets)
        return {
            "current_pps": self._current_pkts,
            "current_bps": self._current_bytes,
            "baseline_pps": round(avg_pkts, 2),
            "baseline_bps": round(avg_bytes, 2),
            "unique_sources": len(self._src_ips),
            "unique_destinations": len(self._dst_ips),
        }
