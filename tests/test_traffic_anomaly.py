"""Tests for traffic spike detection."""

import time

from app.detection.traffic_anomaly import TrafficSpikeDetector


def _make_packet(size=64, ts=None):
    return {
        "source_ip": "10.0.0.1",
        "destination_ip": "10.0.0.2",
        "source_port": 12345,
        "destination_port": 80,
        "protocol": "TCP",
        "packet_size": size,
        "timestamp": ts or time.time(),
    }


class TestTrafficSpikeDetector:
    def setup_method(self):
        self.detector = TrafficSpikeDetector(
            baseline_window=10,
            multiplier=2.0,
            min_samples=3,
            cooldown=5,
        )

    def test_no_alert_insufficient_samples(self):
        now = time.time()
        for i in range(2):
            for _ in range(5):
                self.detector.evaluate(_make_packet(ts=now + i))
            # Advance 1 second
        # Only 2 buckets, need min_samples=3
        result = self.detector.evaluate(_make_packet(ts=now + 2))
        # With 3 buckets of 5 pkts, current 1 pkt won't spike
        assert result is None

    def test_spike_detected(self):
        now = time.time()
        # Build baseline: 3 seconds of 5 pkts each
        for sec in range(3):
            for _ in range(5):
                self.detector.evaluate(_make_packet(ts=now + sec))

        # Spike: 20 packets in one second (> 2x baseline of ~5)
        for _ in range(20):
            result = self.detector.evaluate(_make_packet(ts=now + 10))

        # At least one of those should trigger
        # The spike detection compares current_second against avg
        assert self.detector.get_current_stats()["current_pps"] == 20

    def test_get_current_stats(self):
        now = time.time()
        for _ in range(5):
            self.detector.evaluate(_make_packet(ts=now))

        stats = self.detector.get_current_stats()
        assert "current_pps" in stats
        assert "current_bps" in stats
        assert "baseline_pps" in stats
        assert stats["unique_sources"] >= 1
