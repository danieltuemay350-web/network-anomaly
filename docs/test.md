# Windows + Kali Controlled-Lab Test Runbook

Use this runbook only on the isolated VirtualBox host-only network described
below. Do not point the commands at public, corporate, or third-party systems.

## Current Features

- Live packet-metadata capture with Scapy; packet payloads are not stored.
- Cross-platform interface selection for Linux and Windows/Npcap, including
  Windows friendly adapter names and their Npcap device mappings.
- Capture diagnostics with `--list-interfaces` and a safe timed `--test` mode.
- Visible capture state, selected interface, packet count, configuration
  warnings, and capture errors through `/api/capture/status` and the dashboard.
- Clean capture start/stop behavior, bounded socket-failure handling, and
  protection against malformed packets or callback errors ending capture.
- IPv4 and IPv6 metadata extraction; IPv6 next-header traffic is handled
  without assuming an IPv4 `proto` field.
- Rule-based detections for port scans, connection bursts, traffic spikes,
  DNS query anomalies, and suspicious/untrusted outbound destinations.
- SQLite alert and traffic-stat persistence, REST endpoints, and a polling
  React dashboard for alerts, devices, statistics, traffic, and capture status.

## Lab scope

- Windows detector/target: `192.168.56.5`
- Kali test VM: `192.168.56.6`
- Network: the isolated `192.168.56.0/24` host-only network
- Windows account: open PowerShell **as Administrator** for packet capture

The expected capture adapter is `Ethernet` with IPv4 address `192.168.56.5`.

## One-time Python setup

Run this once if `backend\venv\Scripts\python.exe` does not exist. Afterwards,
use that interpreter for every backend command in this guide.

```powershell
cd Z:\network-anomaly-detector\backend
py -m venv venv
.\venv\Scripts\python.exe -m pip install -r requirements.txt
```

## 1. Prepare the detector

From the project root, confirm `.env` contains this setting. An empty value is
intentional: it enables Scapy/Npcap auto-detection instead of assuming `eth0`.

```env
NETWORK_INTERFACE=
```

In an Administrator PowerShell on Windows:

```powershell
cd Z:\network-anomaly-detector\backend
.\venv\Scripts\python.exe -m app.capture.sniffer --list-interfaces
.\venv\Scripts\python.exe -m app.capture.sniffer --test --duration 5
```

Pass criteria:

- The interface list includes `Ethernet` and `192.168.56.5`.
- The self-test says `Selected interface: Ethernet`.
- The self-test ends with `State: stopped` and `Error: none`.
- A zero packet count is acceptable when there is no traffic during the five
  second window; generate a ping while the self-test runs to prove capture.

If the selected interface is not `Ethernet`, stop here. Run
`--list-interfaces`, then set `NETWORK_INTERFACE` to the exact **Capture name**
shown for the `192.168.56.5` adapter, save `.env`, and repeat the self-test.

## 2. Start the API and confirm capture status

Keep the following window open:

```powershell
cd Z:\network-anomaly-detector\backend
.\venv\Scripts\python.exe -m uvicorn app.main:app --host 0.0.0.0 --port 8000
```

In a second Windows PowerShell window:

```powershell
Invoke-RestMethod http://127.0.0.1:8000/api/health | ConvertTo-Json
Invoke-RestMethod http://127.0.0.1:8000/api/capture/status | ConvertTo-Json
```

Pass criteria:

- `/api/health` returns `"status": "ok"`.
- `/api/capture/status` returns `"running": true` and `"interface": "Ethernet"`.
- `last_error` is null/empty. An informational `configuration_warning` stating
  that `Ethernet` was automatically selected is expected and safe.

To run the dashboard, use a third terminal:

```powershell
cd Z:\network-anomaly-detector\frontend
npm install
npm run dev
```

Open the local Vite URL (normally `http://localhost:5173`). The header should
show **Capture Active**, `Ethernet`, and a packet count.

## 3. Prove packets reach the complete pipeline

From Kali, while the Windows API is running:

```bash
ping -c 4 192.168.56.5
```

Then, on Windows, run:

```powershell
Invoke-RestMethod http://127.0.0.1:8000/api/capture/status | ConvertTo-Json
```

Pass criterion: `packet_count` has increased. This proves Npcap → Scapy →
`PacketSniffer` is working. ICMP packets are intentionally not counted by the
TCP/UDP port-scan and connection-burst rules.

## 4. Verify port-scan detection

From Kali, scan only the Windows lab VM:

```bash
nmap -sT -n -T4 -p 1-25 192.168.56.5
```

Wait two seconds, then query Windows:

```powershell
Invoke-RestMethod 'http://127.0.0.1:8000/api/alerts?limit=20' | ConvertTo-Json -Depth 8
```

Pass criterion: an alert with `alert_type` `PORT_SCAN`, severity `HIGH`, source
`192.168.56.6`, and destination `192.168.56.5`. The default threshold is 20
distinct TCP/UDP destination ports in five seconds.

## 5. Verify connection-burst detection

The default threshold is 100 TCP/UDP packets within ten seconds. From Kali:

```bash
nmap -sT -n -T5 -p 1-120 192.168.56.5
```

Then on Windows:

```powershell
Invoke-RestMethod 'http://127.0.0.1:8000/api/alerts?limit=50' |
  ConvertTo-Json -Depth 8
```

Pass criterion: a `CONNECTION_ANOMALY` alert with severity `MEDIUM`. This scan
will normally also generate a `PORT_SCAN` alert; that is expected because both
rules observe the same controlled traffic.

## 6. Verify traffic-spike detection

Traffic-spike detection needs five one-second baseline samples before it can
alert. First create low-rate baseline traffic from Kali:

```bash
ping -i 1 -c 8 192.168.56.5
```

Immediately afterwards, create a bounded burst against the same lab host:

```bash
nmap -sT -n -T5 -p 1-120 192.168.56.5
```

Query alerts as above. Pass criterion: a `TRAFFIC_ANOMALY` alert with severity
`MEDIUM`. If it does not fire, the baseline was not sufficiently low or not yet
established; wait 10 seconds and repeat the baseline then burst once.

## 7. Verify the suspicious-destination rule

This deterministic test avoids external destinations. In `.env`, temporarily
set the Kali lab VM as explicitly suspicious:

```env
SUSPICIOUS_DESTINATIONS=192.168.56.6
```

Restart the backend, then from Windows run:

```powershell
ping 192.168.56.6
Invoke-RestMethod 'http://127.0.0.1:8000/api/alerts?limit=20' | ConvertTo-Json -Depth 8
```

Pass criterion: a `SUSPICIOUS_OUTBOUND` alert with severity `HIGH` and
destination `192.168.56.6`. Remove the setting and restart after the test.

## 8. Verify DNS processing (optional)

DNS alerts require the detector to see the DNS query. The most reliable lab
method is to operate a controlled DNS responder on Kali, set Windows to query
`192.168.56.6`, then issue more than 50 queries within ten seconds. Do not use
public resolvers for this test.

After the controlled resolver is available, run from Windows:

```powershell
1..55 | ForEach-Object { nslookup "test$_.lab" 192.168.56.6 | Out-Null }
Invoke-RestMethod 'http://127.0.0.1:8000/api/alerts?limit=50' | ConvertTo-Json -Depth 8
```

Pass criterion: a `DNS_ANOMALY` alert with `metadata.rule` of `query_burst`.
If no controlled DNS server is configured, skip this test rather than sending
queries outside the isolated lab.

## 9. Verify persistence and dashboard updates

```powershell
Invoke-RestMethod http://127.0.0.1:8000/api/stats | ConvertTo-Json -Depth 8
Invoke-RestMethod http://127.0.0.1:8000/api/devices | ConvertTo-Json -Depth 8
Invoke-RestMethod http://127.0.0.1:8000/api/traffic | ConvertTo-Json -Depth 8
```

Pass criteria:

- Previously generated alerts remain in `/api/alerts` after an API restart.
- `/api/stats` reports alert totals.
- The dashboard shows the same alerts after its next three-second refresh.
- The packet count continues increasing when new lab traffic arrives.

## 10. Test summary to record

Record each result as pass/fail with the command output:

- Interface diagnostic selected `Ethernet` / `192.168.56.5`.
- Capture status reported `running: true`.
- Ping increased `packet_count`.
- 25-port scan created `PORT_SCAN`.
- 120-port scan created `CONNECTION_ANOMALY`.
- Baseline plus bounded burst created `TRAFFIC_ANOMALY`.
- Optional local DNS burst created `DNS_ANOMALY`.
- Explicit Kali destination created `SUSPICIOUS_OUTBOUND`.
- Alerts persisted and appeared in the dashboard.

## Troubleshooting

- `ModuleNotFoundError: app`: run from `backend`, or add `--app-dir backend`.
- `running: false` with a permission error: run PowerShell as Administrator.
- Wrong adapter selected: use `--list-interfaces` and set the exact capture name
  in `NETWORK_INTERFACE`, then restart the backend.
- `Packet processing failed` mentioning `proto`: ensure the backend was
  restarted after the IPv6 metadata patch.
- Packet count does not change: verify both VMs are on the same host-only
  network and repeat the sniffer self-test while sending a ping.
