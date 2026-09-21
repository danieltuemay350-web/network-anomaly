#!/usr/bin/env python3
"""Live end-to-end "alive test" for the network anomaly detection system.

Crafts synthetic packets on the loopback interface, then asserts the
expected alerts are visible through the REST API.

Requirements:
  1. The backend capturing on the loopback interface `lo`:
       Linux/macOS: sudo -E env NETWORK_INTERFACE=lo <venv-python> -m uvicorn app.main:app --app-dir backend --port 8000
       Windows:     run the command as Administrator; set NETWORK_INTERFACE to
                    your NIC name (or leave it unset and let the backend auto-select).
                    Note: loopback testing on Windows needs the "Npcap Loopback
                    Adapter" (enable "Support loopback traffic" in the Npcap setup).
  2. This script, with the same venv python (root/admin only if your platform
     needs it to send raw packets):
       <venv-python> scripts/alive_test.py --api http://127.0.0.1:8000

Exit code 0 if all scenarios were detected, 1 otherwise.
"""
import argparse
import json
import random
import sys
import time

import httpx
from scapy.all import IP, TCP, UDP, DNS, DNSQR, send

SCENARIOS = ["PORT_SCAN", "CONNECTION_ANOMALY", "DNS_ANOMALY", "TRAFFIC_ANOMALY"]


def send_pkt(src: str, sport: int, dport: int, payload=None) -> None:
    send(
        IP(src=src, dst="127.0.0.1")
        / (UDP(sport=sport, dport=dport) / payload if payload is not None else TCP(sport=sport, dport=dport, flags="S")),
        verbose=0,
    )


def scenario_port_scan() -> None:
    src, base = "192.168.1.10", random.randint(40000, 50000)
    for off in range(30):
        send_pkt(src, base + off, 1000 + off)


def scenario_connection_burst() -> None:
    src, port = "192.168.1.20", random.randint(1000, 4000)
    for i in range(105):
        send_pkt(src, random.randint(50000, 60000), port)


def scenario_dns() -> None:
    src = "192.168.1.30"
    long_qname = "a" * 60 + ".example.com"
    send_pkt(src, random.randint(50000, 60000), 53, payload=DNS(rd=1, qd=DNSQR(qname=long_qname)))
    time.sleep(0.1)
    for _ in range(50):
        send_pkt(src, random.randint(50000, 60000), 53, payload=DNS(rd=1, qd=DNSQR(qname="example.com")))


def scenario_traffic() -> None:
    src, port = "192.168.1.40", random.randint(1000, 4000)
    for _ in range(5):
        send_pkt(src, random.randint(50000, 60000), port)
        time.sleep(1.1)
    for _ in range(40):
        send_pkt(src, random.randint(50000, 60000), port)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--api", default="http://127.0.0.1:8000")
    args = parser.parse_args()

    api = httpx.Client(base_url=args.api, timeout=10.0)
    results = {}

    try:
        health = api.get("/api/health").json()
        print(f"[API] health  -> PASS ({health.get('status')})")
        status = api.get("/api/capture/status").json()
        print(f"[API] capture -> running={status.get('running')} interface={status.get('interface')} packet_count={status.get('packet_count')}")
        if not status.get("running"):
            print(f"[API] capture -> WARN not capturing (interface={status.get('interface')} missing or not usable)")
    except httpx.HTTPError as exc:
        print(f"[API] health  -> FAIL ({exc})")
        return 1

    steps = [
        ("send port scan burst (30 TCP SYN to distinct ports)", scenario_port_scan),
        ("send connection burst (105 TCP SYN)", scenario_connection_burst),
        ("send DNS queries (1 long domain + 50 normal)", scenario_dns),
        ("send traffic baseline + spike (5x1pps then 40pps)", scenario_traffic),
    ]
    for label, fn in steps:
        try:
            fn()
            print(f"[send] {label} -> OK")
        except Exception as exc:
            print(f"[send] {label} -> SKIP ({exc})")

    print("[wait] 2s for the detection pipeline...")
    time.sleep(2)

    status = api.get("/api/capture/status").json()
    print(f"[API] capture -> after traffic packet_count={status.get('packet_count')}")
    if not status.get("running"):
        print("HINT: capture is not running. Check which backend answered this request:")
        print("      1. an old `wlan0`/`eth0` server may still own port 8000 -> `ps aux | grep uvicorn`")
        print("      2. interface=eth0 means the NEW server was NOT started with NETWORK_INTERFACE=lo;")
        print("         restart it as shown in the script docstring")
    elif status.get("packet_count", 0) == 0:
        print("HINT: interface=lo is capturing but the builtin capture packet_count is 0. Check the [send] lines above:")
        print("      if they were SKIP, this shell lacks root; if OK, the API request may not be hitting the")
        print("      server that owns this interface.")

    try:
        payload = api.get("/api/alerts", params={"limit": 200}).json()
        alerts = payload.get("alerts", [])
        stats = api.get("/api/stats").json()
    except httpx.HTTPError as exc:
        print(f"[API] alerts -> FAIL ({exc})")
        return 1

    counts = {}
    for a in alerts:
        counts[a["alert_type"]] = counts.get(a["alert_type"], 0) + 1
    print(f"[API] total alerts in window: {len(alerts)}")
    print(f"[API] stats.alerts_by_type : {json.dumps(stats.get('alerts_by_type', {}))}")

    ok = True
    for scenario in SCENARIOS:
        n = counts.get(scenario, 0)
        passed = n >= 1
        ok = ok and passed
        results[scenario] = n
        print(f"[assert] {scenario:<20} count={n:>3} -> {'PASS' if passed else 'FAIL'}")

    print("-" * 50)
    if ok:
        print("ALIVE TEST: PASS - the full pipeline (capture -> detect -> store -> API) is working.")
        return 0
    print("ALIVE TEST: FAIL - some alerts were not detected. Review the skips/warnings above.")
    return 1


if __name__ == "__main__":
    sys.exit(main())