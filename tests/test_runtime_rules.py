"""Live detection-rule and explainable-risk regression tests."""
from app.capture.sniffer import PacketMetadata
from app.detection.engine import DetectionEngine


def packet(port: int) -> PacketMetadata:
    return PacketMetadata(1.0 + port / 1000, "192.168.56.6", "192.168.56.5", 40000, port, "TCP", 60)


def test_live_port_scan_threshold_and_enabled_flag():
    alerts = []
    engine = DetectionEngine(alert_callback=alerts.append)
    engine.apply_rule("PORT_SCAN", True, {"threshold": 2, "window": 10, "cooldown": 0, "severity": "CRITICAL"})
    engine.process_packet(packet(80)); engine.process_packet(packet(81))
    assert alerts[0]["alert_type"] == "PORT_SCAN"
    assert alerts[0]["severity"] == "CRITICAL"
    alerts.clear()
    engine.apply_rule("PORT_SCAN", False, {"threshold": 1})
    engine.process_packet(packet(82))
    assert alerts == []
