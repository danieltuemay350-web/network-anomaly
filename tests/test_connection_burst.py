"""Tests for connection burst detection."""

import time

from app.detection.connection_anomaly import ConnectionBurstDetector


def _make_packet(src, proto="TCP", ts=None):
    return {
        "source_ip": src,
        "destination_ip": "10.0.0.2",
        "source_port": 12345,
        "destination_port": 80,
        "protocol": proto,
        "packet_size": 64,
        "timestamp": ts or time.time(),
    }


class TestConnectionBurstDetector:
    def setup_method(self):
        self.detector = ConnectionBurstDetector(threshold=10, window=5, cooldown=5)

    def test_no_alert_below_threshold(self):
        now = time.time()
        for i in range(9):
            result = self.detector.evaluate(_make_packet("10.0.0.1", ts=now))
            assert result is None

    def test_alert_on_threshold(self):
        now = time.time()
        result = None
        for i in range(10):
            result = self.detector.evaluate(_make_packet("10.0.0.1", ts=now))
        assert result is not None
        assert result["alert_type"] == "CONNECTION_ANOMALY"
        assert result["severity"] == "MEDIUM"
        assert result["source_ip"] == "10.0.0.1"

    def test_cooldown_suppresses_duplicate(self):
        now = time.time()
        for i in range(10):
            self.detector.evaluate(_make_packet("10.0.0.1", ts=now))
        # Second burst within cooldown
        for i in range(10):
            result = self.detector.evaluate(_make_packet("10.0.0.1", ts=now + 0.1))
            assert result is None

    def test_icmp_not_tracked(self):
        now = time.time()
        for i in range(15):
            result = self.detector.evaluate(_make_packet("10.0.0.1", proto="ICMP", ts=now))
            assert result is None

    def test_separate_sources_independent(self):
        now = time.time()
        for i in range(10):
            self.detector.evaluate(_make_packet("10.0.0.1", ts=now))

        result = None
        for i in range(10):
            result = self.detector.evaluate(_make_packet("10.0.0.5", ts=now))
        assert result is not None
        assert result["source_ip"] == "10.0.0.5"
