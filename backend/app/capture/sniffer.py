"""Cross-platform packet capture and capture-interface diagnostics."""
from __future__ import annotations

import ipaddress
import logging
import platform
import time
from collections import deque
from dataclasses import dataclass
from threading import Thread
from typing import Callable, Iterable

from scapy.all import DNS, ICMP, IP, IPv6, TCP, UDP, conf, sniff  # type: ignore[import-untyped]
from app.config import NETWORK_INTERFACE

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class InterfaceInfo:
    name: str
    capture_name: str
    ipv4: str | None = None
    ipv6: str | None = None
    mac: str | None = None
    aliases: tuple[str, ...] = ()
    ignored_reason: str | None = None

    @property
    def suitable(self) -> bool:
        return self.ignored_reason is None and bool(self.ipv4)


@dataclass
class PacketMetadata:
    timestamp: float
    source_ip: str
    destination_ip: str
    source_port: int | None
    destination_port: int | None
    protocol: str
    packet_size: int
    tcp_flags: str | None = None
    dns_query: str | None = None

    def to_dict(self) -> dict:
        return self.__dict__.copy()


class PacketSniffer:
    """Capture packet metadata with observable state and bounded failures."""

    def __init__(self, callback: Callable[[PacketMetadata], None], interface: str | None = None):
        self.callback = callback
        self.requested_interface = (interface if interface is not None else NETWORK_INTERFACE).strip()
        self.interface, self.configuration_warning = self._resolve_interface(self.requested_interface)
        self.auto_selected = bool(self.configuration_warning)
        self._running = False
        self._thread: Thread | None = None
        self._packet_count = 0
        self._recent_packets: deque[PacketMetadata] = deque(maxlen=1000)
        self.last_error: str | None = None
        self.state = "stopped"

    @staticmethod
    def _is_loopback(name: str) -> bool:
        value = name.lower()
        return value == "lo" or "loopback" in value or "software loopback" in value

    @classmethod
    def _ignored_reason(cls, name: str) -> str | None:
        value = name.lower()
        if cls._is_loopback(name):
            return "loopback"
        if any(token in value for token in ("wan miniport", "teredo", "isatap", "6to4")):
            return "tunnel or WAN miniport"
        if any(token in value for token in ("docker", "veth", "virbr", "vmnet", "tap", "tun")) or value.startswith("br-"):
            return "virtual or tunnel adapter"
        return None

    @classmethod
    def _interface_infos(cls) -> list[InterfaceInfo]:
        """Read Scapy's interface table instead of raw Npcap device paths."""
        try:
            interfaces: Iterable[object] = conf.ifaces.values()
        except Exception as exc:
            logger.warning("Unable to read Scapy interface table: %s", exc)
            return []
        infos = []
        for iface in interfaces:
            name = str(getattr(iface, "name", "") or "")
            if not name:
                continue
            network_name = str(getattr(iface, "network_name", "") or "")
            description = str(getattr(iface, "description", "") or "")
            aliases = tuple(dict.fromkeys(v for v in (name, network_name, description) if v))
            display_name = description if description and description != name else name
            infos.append(InterfaceInfo(
                display_name, name,
                str(getattr(iface, "ip", "") or "") or None,
                str(getattr(iface, "ip6", "") or "") or None,
                str(getattr(iface, "mac", "") or "") or None,
                aliases, cls._ignored_reason(" ".join(aliases)),
            ))
        return infos

    @classmethod
    def _available_interfaces(cls) -> list[str]:
        return [info.capture_name for info in cls._interface_infos()]

    @classmethod
    def available_interfaces(cls) -> list[dict]:
        return [{"name": item.name, "capture_name": item.capture_name, "ipv4": item.ipv4,
                 "ipv6": item.ipv6, "mac": item.mac, "available": item.suitable,
                 "reason": item.ignored_reason} for item in cls._interface_infos()]

    @classmethod
    def resolve_manual_interface(cls, requested: str) -> InterfaceInfo | None:
        return cls._match_interface(requested, cls._interface_infos())

    @staticmethod
    def _is_private_ipv4(address: str | None) -> bool:
        try:
            return bool(address and ipaddress.ip_address(address).is_private)
        except ValueError:
            return False

    @classmethod
    def _match_interface(cls, candidate: str, infos: list[InterfaceInfo]) -> InterfaceInfo | None:
        candidate = candidate.casefold()
        return next((info for info in infos if any(alias.casefold() == candidate for alias in info.aliases)), None)

    @classmethod
    def _auto_select_interface(cls, infos: list[InterfaceInfo] | None = None) -> InterfaceInfo | None:
        infos = infos if infos is not None else cls._interface_infos()
        candidates = [info for info in infos if info.suitable]
        if not candidates:
            return None
        try:
            route_name = str(conf.route.route("0.0.0.0")[0] or "")
        except Exception as exc:
            logger.debug("Default-route lookup failed: %s", exc)
            route_name = ""
        route_match = cls._match_interface(route_name, candidates) if route_name else None
        return max(candidates, key=lambda info: (
            30 if info is route_match else 0,
            10 if cls._is_private_ipv4(info.ipv4) else 0,
            -len(info.name),
        ))

    @classmethod
    def _resolve_interface(cls, requested: str) -> tuple[str, str | None]:
        infos = cls._interface_infos()
        if requested:
            match = cls._match_interface(requested, infos)
            if match and match.suitable:
                return match.capture_name, None
            available = ", ".join(f"{i.name} ({i.ipv4 or 'no IPv4'})" for i in infos if i.suitable)
            selected = cls._auto_select_interface(infos)
            if selected:
                message = (f"Configured interface '{requested}' is unavailable or unsuitable. "
                           f"Available capture interfaces: {available or 'none'}. "
                           f"Automatically selected: {selected.name} ({selected.ipv4}).")
                logger.warning(message)
                return selected.capture_name, message
            message = f"Configured interface '{requested}' is unavailable. No suitable capture interface was found."
            logger.error(message)
            return "", message
        selected = cls._auto_select_interface(infos)
        if selected:
            message = f"NETWORK_INTERFACE is unset; automatically selected {selected.name} ({selected.ipv4})."
            logger.info(message)
            return selected.capture_name, message
        message = "NETWORK_INTERFACE is unset and no suitable capture interface was found."
        logger.error(message)
        return "", message

    def _extract_metadata(self, pkt) -> PacketMetadata | None:
        ip_layer = pkt.getlayer(IP) or pkt.getlayer(IPv6)
        if ip_layer is None:
            return None
        source_port = destination_port = None
        # IPv4 calls this field ``proto``; IPv6 calls the equivalent field
        # ``nh`` (next header).  Capturing IPv6 multicast/ND traffic on
        # Windows is normal, so never assume an IPv4 layer here.
        protocol_number = getattr(ip_layer, "proto", None)
        if protocol_number is None:
            protocol_number = getattr(ip_layer, "nh", "unknown")
        protocol, tcp_flags, dns_query = f"proto-{protocol_number}", None, None
        if pkt.haslayer(TCP):
            layer = pkt[TCP]
            source_port, destination_port, protocol, tcp_flags = layer.sport, layer.dport, "TCP", str(layer.flags)
        elif pkt.haslayer(UDP):
            layer = pkt[UDP]
            source_port, destination_port, protocol = layer.sport, layer.dport, "UDP"
            if pkt.haslayer(DNS) and pkt[DNS].qr == 0 and pkt[DNS].qd:
                dns_query = pkt[DNS].qd.qname.decode("utf-8", errors="replace").rstrip(".")
                protocol = "DNS"
        elif pkt.haslayer(ICMP):
            protocol = "ICMP"
        return PacketMetadata(time.time(), ip_layer.src, ip_layer.dst, source_port, destination_port, protocol, len(pkt), tcp_flags, dns_query)

    def _process_packet(self, pkt) -> None:
        try:
            metadata = self._extract_metadata(pkt)
            if metadata is not None:
                self._packet_count += 1
                self._recent_packets.append(metadata)
                self.callback(metadata)
        except Exception:
            logger.exception("Packet processing failed; packet skipped")

    def _sniff_loop(self) -> None:
        if not self.interface:
            self.last_error, self.state, self._running = self.configuration_warning or "No capture interface is available.", "failed", False
            return
        self.state = "running"
        failures = 0
        logger.info("Packet capture started on '%s'", self.interface)
        while self._running:
            try:
                # Timeout ensures stopping works even when no packets arrive.
                started = time.monotonic()
                sniff(iface=self.interface, prn=self._process_packet, store=False, timeout=1)
                # Some libpcap failures are logged by Scapy then returned as an
                # immediate, otherwise-successful sniff().  Treat repeated
                # immediate returns as a capture failure instead of reporting a
                # healthy but dead capture thread forever.
                if time.monotonic() - started < 0.05 and self._running:
                    failures += 1
                    self.last_error = f"Capture socket on '{self.interface}' closed unexpectedly."
                    logger.error("%s", self.last_error)
                    if failures >= 2:
                        break
                    time.sleep(1)
                else:
                    failures = 0
            except PermissionError:
                self.last_error = "Permission denied: packet capture requires Administrator/root privileges."
                break
            except Exception as exc:
                failures += 1
                self.last_error = f"Unable to capture on '{self.interface}': {type(exc).__name__}: {exc}"
                logger.exception("%s", self.last_error)
                if failures >= 2:
                    break
                time.sleep(1)
        if self._running and self.last_error:
            self.state = "failed"
        elif self.state != "failed":
            self.state = "stopped"
        self._running = False
        logger.info("Packet capture stopped; state=%s", self.state)

    def start(self) -> None:
        if self.is_running:
            return
        self.last_error = None if self.interface else self.configuration_warning
        self._running, self.state = True, "starting"
        self._thread = Thread(target=self._sniff_loop, daemon=True, name="packet-sniffer")
        self._thread.start()

    def stop(self) -> None:
        self._running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=3)
        if self.state != "failed":
            self.state = "stopped"

    @property
    def is_running(self) -> bool:
        return self._running and self._thread is not None and self._thread.is_alive() and self.state in {"starting", "running"}

    @property
    def packet_count(self) -> int:
        return self._packet_count


def _print_interfaces() -> None:
    print("Available interfaces:")
    for info in PacketSniffer._interface_infos():
        print(f"\n[{'CAPTURE OK' if info.suitable else 'IGNORED'}]\nName: {info.name}\nCapture name: {info.capture_name}")
        print(f"IPv4: {info.ipv4 or '-'}\nIPv6: {info.ipv6 or '-'}\nMAC: {info.mac or '-'}")
        npcap = next((alias for alias in info.aliases if alias.startswith("\\\\Device\\\\NPF_")), None)
        if npcap:
            print(f"Npcap: {npcap}")
        if info.ignored_reason:
            print(f"Reason: {info.ignored_reason}")


def _self_test(interface: str | None, duration: float) -> int:
    sniffer = PacketSniffer(lambda _: None, interface)
    print(f"OS: {platform.platform()}\nScapy: {conf.version}\nSelected interface: {sniffer.interface or 'none'}")
    if sniffer.configuration_warning:
        print(f"Configuration: {sniffer.configuration_warning}")
    sniffer.start(); time.sleep(duration); sniffer.stop()
    print(f"Packets captured: {sniffer.packet_count}\nState: {sniffer.state}\nError: {sniffer.last_error or 'none'}")
    return 0 if sniffer.state != "failed" else 1


def main() -> None:
    import argparse
    parser = argparse.ArgumentParser(description="Network packet capture diagnostics")
    parser.add_argument("--interface", "-i", default=None)
    parser.add_argument("--list-interfaces", action="store_true")
    parser.add_argument("--test", action="store_true")
    parser.add_argument("--duration", type=float, default=3.0)
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    if args.list_interfaces:
        _print_interfaces(); return
    if args.test:
        raise SystemExit(_self_test(args.interface, max(args.duration, 0.1)))
    sniffer = PacketSniffer(lambda meta: print(meta.to_dict()), args.interface)
    sniffer.start()
    try:
        while sniffer.is_running:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        sniffer.stop()


if __name__ == "__main__":
    main()
