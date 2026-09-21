"""Tests for DNS anomaly detection."""

import time

from app.detection.dns_anomaly import DNSAnomalyDetector


def _make_dns_packet(src, ts=None, query=None):
    pkt = {
        "source_ip": src,
        "destination_ip": "8.8.8.8",
        "source_port": 12345,
        "destination_port": 53,
        "protocol": "DNS",
        "packet_size": 64,
        "timestamp": ts or time.time(),
    }
    if query is not None:
        pkt["dns_query"] = query
    return pkt


class TestDNSAnomalyDetector:
    def setup_method(self):
        self.detector = DNSAnomalyDetector(
            threshold=5,
            window=10,
            long_domain_length=30,
            cooldown=5,
        )

    def test_no_alert_below_threshold(self):
        now = time.time()
        for i in range(4):
            result = self.detector.evaluate(_make_dns_packet("10.0.0.1", ts=now))
            assert result is None

    def test_burst_alert(self):
        now = time.time()
        result = None
        for i in range(5):
            result = self.detector.evaluate(_make_dns_packet("10.0.0.1", ts=now))
        assert result is not None
        assert result["alert_type"] == "DNS_ANOMALY"
        assert result["source_ip"] == "10.0.0.1"

    def test_long_domain_alert(self):
        long_domain = "a" * 50 + ".example.com"
        pkt = _make_dns_packet("10.0.0.1", query=long_domain)
        result = self.detector.evaluate(pkt)
        assert result is not None
        assert result["alert_type"] == "DNS_ANOMALY"
        assert result["severity"] == "MEDIUM"
        assert "long_domain" in result["metadata"]["rule"]

    def test_short_domain_no_alert(self):
        pkt = _make_dns_packet("10.0.0.1", query="example.com")
        result = self.detector.evaluate(pkt)
        # Should be None: short domain, and query count below threshold
        assert result is None

    def test_cooldown_suppresses(self):
        now = time.time()
        for i in range(5):
            self.detector.evaluate(_make_dns_packet("10.0.0.1", ts=now))
        # Second burst in cooldown
        for i in range(5):
            result = self.detector.evaluate(_make_dns_packet("10.0.0.1", ts=now + 0.1))
            assert result is None

    def test_non_dns_protocol_ignored(self):
        now = time.time()
        pkt = {
            "source_ip": "10.0.0.1",
            "destination_ip": "8.8.8.8",
            "source_port": 12345,
            "destination_port": 53,
            "protocol": "TCP",
            "packet_size": 64,
            "timestamp": now,
        }
        result = self.detector.evaluate(pkt)
        assert result is None
