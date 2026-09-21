"""Tests for the suspicious outbound connection detector."""

import time

from app.detection.suspicious_outbound import SuspiciousOutboundDetector


def _make_packet(src, dst, ts=None, proto="TCP"):
    return {
        "source_ip": src,
        "destination_ip": dst,
        "source_port": 12345,
        "destination_port": 80,
        "protocol": proto,
        "packet_size": 64,
        "timestamp": ts or time.time(),
    }


class TestSuspiciousOutboundDetector:
    def setup_method(self):
        self.detector = SuspiciousOutboundDetector(
            trusted_networks=["10.0.0.0/8", "192.168.0.0/16"],
            suspicious_destinations=["203.0.113.66"],
        )

    def test_trusted_destination_no_alert(self):
        alert = self.detector.evaluate(_make_packet("10.0.0.1", "192.168.1.50"))
        assert alert is None

    def test_untrusted_destination_low_alert(self):
        alert = self.detector.evaluate(_make_packet("10.0.0.1", "8.8.8.8"))
        assert alert is not None
        assert alert["alert_type"] == "SUSPICIOUS_OUTBOUND"
        assert alert["severity"] == "LOW"

    def test_explicit_suspicious_destination_high_alert(self):
        alert = self.detector.evaluate(_make_packet("10.0.0.1", "203.0.113.66"))
        assert alert is not None
        assert alert["severity"] == "HIGH"
        assert alert["metadata"]["reason"] == "blocked_destination"

    def test_cooldown_suppresses_repeat_untrusted(self):
        now = time.time()
        first = self.detector.evaluate(_make_packet("10.0.0.1", "8.8.8.8", ts=now))
        assert first is not None
        second = self.detector.evaluate(_make_packet("10.0.0.1", "8.8.8.8", ts=now + 0.1))
        assert second is None

    def test_invalid_cidr_ignored(self):
        detector = SuspiciousOutboundDetector(
            trusted_networks=["not-a-cidr"],
            suspicious_destinations=["not-an-ip"],
        )
        # Invalid config should not crash; address falls through as untrusted
        alert = detector.evaluate(_make_packet("192.168.1.1", "192.168.1.2"))
        assert alert is not None
        assert alert["severity"] == "LOW"

    def test_loopback_untracked(self):
        alert = self.detector.evaluate(_make_packet("127.0.0.1", "127.0.0.1"))
        assert alert is not None