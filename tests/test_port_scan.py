"""Tests for the port scan detection rule."""

import time

from app.detection.port_scan import PortScanDetector


def _make_packet(src, dst, dport, ts=None, proto="TCP"):
    return {
        "source_ip": src,
        "destination_ip": dst,
        "source_port": 12345,
        "destination_port": dport,
        "protocol": proto,
        "packet_size": 64,
        "timestamp": ts or time.time(),
    }


class TestPortScanDetector:
    def setup_method(self):
        self.detector = PortScanDetector(threshold=5, window=10, cooldown=5)

    def test_no_alert_below_threshold(self):
        now = time.time()
        for port in range(1, 4):
            result = self.detector.evaluate(_make_packet("10.0.0.1", "10.0.0.2", port, ts=now))
            assert result is None

    def test_alert_on_threshold(self):
        now = time.time()
        result = None
        for port in range(1, 6):
            result = self.detector.evaluate(_make_packet("10.0.0.1", "10.0.0.2", port, ts=now))
        assert result is not None
        assert result["alert_type"] == "PORT_SCAN"
        assert result["severity"] == "HIGH"
        assert result["source_ip"] == "10.0.0.1"
        assert result["destination_ip"] == "10.0.0.2"

    def test_cooldown_suppresses_duplicate(self):
        now = time.time()
        for port in range(1, 6):
            self.detector.evaluate(_make_packet("10.0.0.1", "10.0.0.2", port, ts=now))

        # Second scan within cooldown should not alert
        for port in range(100, 106):
            result = self.detector.evaluate(_make_packet("10.0.0.1", "10.0.0.2", port, ts=now + 0.1))
            assert result is None

    def test_different_targets_independent(self):
        now = time.time()
        for port in range(1, 6):
            self.detector.evaluate(_make_packet("10.0.0.1", "10.0.0.2", port, ts=now))

        # Different target should still be tracked independently
        result = None
        for port in range(1, 6):
            result = self.detector.evaluate(_make_packet("10.0.0.1", "10.0.0.3", port, ts=now))
        assert result is not None
        assert result["destination_ip"] == "10.0.0.3"

    def test_udp_scan_detected(self):
        now = time.time()
        result = None
        for port in range(1, 6):
            result = self.detector.evaluate(_make_packet("10.0.0.1", "10.0.0.2", port, ts=now, proto="UDP"))
            if result is not None:
                break
        assert result is not None
        assert result["alert_type"] == "PORT_SCAN"

    def test_no_port_returns_none(self):
        pkt = {
            "source_ip": "10.0.0.1",
            "destination_ip": "10.0.0.2",
            "source_port": 12345,
            "destination_port": None,
            "protocol": "ICMP",
            "packet_size": 64,
            "timestamp": time.time(),
        }
        assert self.detector.evaluate(pkt) is None
