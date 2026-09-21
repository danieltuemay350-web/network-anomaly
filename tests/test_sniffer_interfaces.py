"""Unit tests for interface selection and capture lifecycle (no NIC required)."""

import time

from app.capture.sniffer import InterfaceInfo, PacketSniffer


WINDOWS_ETHERNET = InterfaceInfo(
    name="Intel(R) PRO/1000 MT Desktop Adapter",
    capture_name="Ethernet",
    ipv4="192.168.56.5",
    aliases=("Ethernet", "\\Device\\NPF_{F4DA}", "Intel(R) PRO/1000 MT Desktop Adapter"),
)
LINUX_ETHERNET = InterfaceInfo("enp0s3", "enp0s3", "10.0.2.15", aliases=("enp0s3",))
LOOPBACK = InterfaceInfo("lo", "lo", "127.0.0.1", aliases=("lo",), ignored_reason="loopback")
VIRTUAL = InterfaceInfo("Docker", "docker0", "172.17.0.1", aliases=("docker0",), ignored_reason="virtual or tunnel adapter")


def _infos(items):
    return classmethod(lambda cls: items)


def test_explicit_windows_friendly_name_resolves_to_capture_name(monkeypatch):
    monkeypatch.setattr(PacketSniffer, "_interface_infos", _infos([WINDOWS_ETHERNET]))
    sniffer = PacketSniffer(lambda _: None, "Ethernet")
    assert sniffer.interface == "Ethernet"
    assert sniffer.configuration_warning is None


def test_windows_npcap_alias_resolves_to_friendly_capture_name(monkeypatch):
    monkeypatch.setattr(PacketSniffer, "_interface_infos", _infos([WINDOWS_ETHERNET]))
    sniffer = PacketSniffer(lambda _: None, "\\Device\\NPF_{F4DA}")
    assert sniffer.interface == "Ethernet"


def test_invalid_explicit_interface_falls_back_with_visible_warning(monkeypatch):
    monkeypatch.setattr(PacketSniffer, "_interface_infos", _infos([WINDOWS_ETHERNET]))
    monkeypatch.setattr("app.capture.sniffer.conf.route.route", lambda _: ("Ethernet", None, None))
    sniffer = PacketSniffer(lambda _: None, "eth0")
    assert sniffer.interface == "Ethernet"
    assert "Configured interface 'eth0'" in sniffer.configuration_warning
    assert sniffer.auto_selected


def test_auto_selection_excludes_loopback_and_virtual_interfaces(monkeypatch):
    monkeypatch.setattr(PacketSniffer, "_interface_infos", _infos([LOOPBACK, VIRTUAL, LINUX_ETHERNET]))
    sniffer = PacketSniffer(lambda _: None, "")
    assert sniffer.interface == "enp0s3"


def test_interface_discovery_is_dynamic_and_exposes_safe_metadata(monkeypatch):
    monkeypatch.setattr(PacketSniffer, "_interface_infos", _infos([WINDOWS_ETHERNET, LOOPBACK]))
    rows = PacketSniffer.available_interfaces()
    assert rows[0]["name"] == WINDOWS_ETHERNET.name
    assert rows[0]["ipv4"] == "192.168.56.5"
    assert rows[0]["available"] is True
    assert rows[1]["available"] is False


def test_manual_selection_only_accepts_discovered_aliases(monkeypatch):
    monkeypatch.setattr(PacketSniffer, "_interface_infos", _infos([LINUX_ETHERNET]))
    assert PacketSniffer.resolve_manual_interface("enp0s3").capture_name == "enp0s3"
    assert PacketSniffer.resolve_manual_interface("not-a-nic") is None


def test_no_available_interface_is_reported(monkeypatch):
    monkeypatch.setattr(PacketSniffer, "_interface_infos", _infos([LOOPBACK, VIRTUAL]))
    sniffer = PacketSniffer(lambda _: None, "")
    assert sniffer.interface == ""
    sniffer.start()
    time.sleep(0.02)
    assert not sniffer.is_running
    assert sniffer.state == "failed"
    assert "no suitable capture interface" in sniffer.last_error.lower()


def test_callback_error_does_not_break_packet_processing(monkeypatch):
    monkeypatch.setattr(PacketSniffer, "_interface_infos", _infos([LINUX_ETHERNET]))
    sniffer = PacketSniffer(lambda _: (_ for _ in ()).throw(RuntimeError("callback boom")), "enp0s3")

    class Packet:
        pass

    metadata = object()
    monkeypatch.setattr(sniffer, "_extract_metadata", lambda _: metadata)
    sniffer._process_packet(Packet())
    assert sniffer.packet_count == 1


def test_ipv6_packet_uses_next_header_when_proto_is_absent(monkeypatch):
    monkeypatch.setattr(PacketSniffer, "_interface_infos", _infos([LINUX_ETHERNET]))
    sniffer = PacketSniffer(lambda _: None, "enp0s3")

    class IPv6Layer:
        src = "fe80::1"
        dst = "ff02::1"
        nh = 58

    class Packet:
        def getlayer(self, layer):
            return None if layer.__name__ == "IP" else IPv6Layer()

        def haslayer(self, _):
            return False

        def __len__(self):
            return 64

    assert sniffer._extract_metadata(Packet()).protocol == "proto-58"


def test_capture_failure_is_visible_and_thread_exits(monkeypatch):
    monkeypatch.setattr(PacketSniffer, "_interface_infos", _infos([LINUX_ETHERNET]))
    monkeypatch.setattr("app.capture.sniffer.sniff", lambda **_: (_ for _ in ()).throw(OSError("socket closed")))
    sniffer = PacketSniffer(lambda _: None, "enp0s3")
    sniffer.start()
    sniffer._thread.join(timeout=3)
    assert sniffer.state == "failed"
    assert "socket closed" in sniffer.last_error


def test_clean_shutdown_after_successful_capture_cycle(monkeypatch):
    monkeypatch.setattr(PacketSniffer, "_interface_infos", _infos([LINUX_ETHERNET]))
    monkeypatch.setattr("app.capture.sniffer.sniff", lambda **_: time.sleep(0.01))
    sniffer = PacketSniffer(lambda _: None, "enp0s3")
    sniffer.start()
    time.sleep(0.03)
    sniffer.stop()
    assert not sniffer.is_running
    assert sniffer.state == "stopped"
