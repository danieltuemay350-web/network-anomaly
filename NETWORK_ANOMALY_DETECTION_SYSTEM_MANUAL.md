# Network Anomaly Detection System Manual

This is an operator and technical reference for the current implementation. It describes what the system actually does today, including its limits. It is intended for use with an isolated Kali Linux ↔ Windows VirtualBox lab.

## Part I — What this system is

This project is a lightweight network sensor and dashboard. It watches packet **metadata** seen by the network adapter on the machine running the backend. Metadata is the useful addressing information on an envelope—source IP, destination IP, ports, protocol, packet size, TCP flags, and DNS query name. The program does **not** save packet payload/content.

An anomaly is traffic that matches one of the local heuristics: many ports contacted quickly, many TCP/UDP packets from one source quickly, a traffic spike, unusual DNS activity, or a connection to an untrusted/explicitly suspicious destination. A match creates an **alert**. Nearby alerts with the same source (and compatible destination) can be grouped into an **incident**. The incident has a risk score made from transparent **risk contributors**.

Threat Intelligence (TI) is a local, offline list of Indicators of Compromise (IOCs): IP addresses, domains, IPv6 addresses, and URLs. The live matcher currently compares packet source IP, destination IP, and DNS query metadata to active IP/domain indicators. A match is evidence and creates a `THREAT_INTELLIGENCE` alert.

This is not an enterprise IDS, SIEM, EDR, malware sandbox, packet recorder, or replacement for analyst judgment. It cannot see traffic that does not reach its selected interface, decrypt encrypted traffic, prove compromise, use external TI feeds, or infer every malicious action. “No alert” does not mean “safe”; a TI match does not prove a compromise.

## Part II — Architecture and verification

```text
Network traffic → Scapy packet capture → PacketMetadata → DetectionEngine
→ detection rules / TI matcher → AlertService → SQLite alerts database
→ IncidentService correlation + risk contributors → FastAPI JSON → React dashboard
```

```text
TI indicator → SQLite threat_indicators → active TI matcher → threat_matches evidence
→ THREAT_INTELLIGENCE alert → existing correlation → incident → risk contributor → dashboard
```

| Stage | Code | Input → output | Failure / verification |
| --- | --- | --- | --- |
| Capture | `backend/app/capture/sniffer.py`, `PacketSniffer` | Scapy packet → `PacketMetadata` | Capture may fail without privileges or with a wrong adapter. Check `GET /api/capture/status`. |
| Metadata | `PacketSniffer._extract_metadata` | IPv4/IPv6 packet → IPs, ports, protocol, size, DNS query | Non-IP packets are skipped; per-packet errors are logged and skipped. |
| Detection | `backend/app/detection/engine.py`, `DetectionEngine.process_packet` | metadata → zero or more alert dictionaries | Individual detector errors are logged; other detectors continue. |
| Alert persistence | `backend/app/services/alert_service.py`, `create_alert` | alert dictionary → `alerts` row | DB errors are logged by `main._alert_callback`. Check `GET /api/alerts`. |
| Correlation/risk | `backend/app/services/incident_service.py` | stored alert → incident, timeline, contributors | Suppressed alerts are stored but do not enter correlation. Check `GET /api/incidents/{id}`. |
| TI | `backend/app/services/threat_intelligence.py` | indicator + metadata → `ThreatMatch` and TI alert | Matcher failure is logged and does not stop normal detection. Check `/api/threat-intelligence/matches`. |
| UI | `frontend/src/App.jsx` | JSON responses → React state/components | Browser console logs polling errors. The UI polls every 3 seconds. |

## Part III — Backend structure

```text
backend/
├── app/
│   ├── api/                  alerts.py, incidents.py, routes.py, security.py, threat_intelligence.py
│   ├── capture/sniffer.py    cross-platform Scapy capture and diagnostics
│   ├── database/database.py  SQLite engine, sessions, additive initialization
│   ├── detection/            engine.py and five detector modules
│   ├── models/alert.py       all SQLAlchemy tables and status enums
│   ├── services/             alert, incident, controls, and TI business logic
│   ├── config.py             environment-backed defaults
│   └── main.py               FastAPI lifespan, capture, engine, routers
├── data/alerts.db            SQLite database (created/used at runtime)
├── requirements.txt
└── README.md
```

`app/main.py` initializes tables, constructs `DetectionEngine`, reapplies saved rule overrides, starts `PacketSniffer`, and stops it at shutdown. It exposes capture status and includes every API router.

`app/models/alert.py` defines `Alert`, `Incident`, `IncidentEvent`, `RiskContributor`, `ThreatIndicator`, `ThreatMatch`, `DetectionRule`, `TrustedDevice`, `AlertSuppression`, `ActivityEvent`, and `TrafficStat`. Think of models as blueprints for the SQLite tables.

`app/database/database.py` uses SQLite and `Base.metadata.create_all()`. It has no migration framework; it performs two additive upgrades for older `alerts` tables before creating tables.

`app/services/alert_service.py` short-term deduplicates identical alert type/source/destination/protocol/description contexts. The default deduplication period is 60 seconds. It increases `occurrences` instead of making uncontrolled duplicate alert rows.

`app/services/incident_service.py` attaches an alert to a recent unresolved incident of the same source IP and compatible destination in the 60-second correlation window. A global traffic alert has no IP, so it attaches only if exactly one recent unresolved incident exists.

## Part IV — Packet capture pipeline

The backend uses Scapy. `PacketSniffer` reads Scapy’s own interface table, not a hard-coded Linux adapter name. With an empty `NETWORK_INTERFACE`, it chooses a usable adapter with IPv4, preferring the default route and private IPv4 addresses while ignoring loopback, tunnel/WAN miniport, and common virtual adapters.

The capture state is `starting`, `running`, `stopped`, or `failed`. Repeated immediate socket closures set a capture error. A working dashboard/API without a working capture interface produces no new traffic-derived alerts.

### Windows sensor requirements

Install Npcap and run the backend in an elevated PowerShell (“Run as Administrator”). Npcap exposes capture devices such as `\\Device\\NPF_{...}`; the application accepts its Scapy display name/alias, such as `Ethernet`, and resolves it to the capture name. Do not set `NETWORK_INTERFACE=eth0` on Windows.

From **Windows PowerShell (Administrator)**, while in `backend`:

```powershell
.\venv\Scripts\python.exe -m app.capture.sniffer --list-interfaces
.\venv\Scripts\python.exe -m app.capture.sniffer --test --duration 5
Get-NetAdapter
Get-NetIPAddress -AddressFamily IPv4
```

The self-test prints selected interface, captured packet count, state, and error. Generate harmless traffic during its five seconds (for example, ping from Kali). If the result is `failed`, read the printed error and select/fix the adapter before testing detection.

### Kali/Linux sensor requirements

The normal Linux commands are:

```bash
ip addr
ip link
sudo -E .venv/bin/python -m app.capture.sniffer --list-interfaces
sudo -E .venv/bin/python -m app.capture.sniffer --test --duration 5
sudo tcpdump -ni <INTERFACE> host <WINDOWS_IP>
```

The last command is an independent visibility check, not part of the application. Root/capabilities are normally needed for packet capture. The detector runs on whichever machine runs the backend; in this lab that is Windows.

## Part V — Backend ↔ frontend communication

The React development server runs on port 5173 and proxies paths beginning `/api` to FastAPI on port 8000. `frontend/src/services/api.js` is the single UI API layer. `App.jsx` polls it every 3 seconds, puts responses in React state, and passes state to components.

### Implemented API reference

All routes below are under `http://127.0.0.1:8000`. There is currently no authentication or authorization.

| Method and URL | Purpose / request | Response and UI consumer |
| --- | --- | --- |
| `GET /api/health` | Simple service check | `{status, service}`; API client only. |
| `GET /api/stats` | Alert counts | totals, severities, types; `StatsOverview`, `DetectionSummary`. |
| `GET /api/devices` | Alert-source aggregates | `{devices: [...]}`; `DevicesTable`. |
| `GET /api/traffic?limit=60` | Recent sampled traffic stats, limit 1–500 | `{traffic: [...]}`; `TrafficChart`. |
| `GET /api/analytics?limit=60` | Traffic, top IPs, protocol and incident aggregates | API available; no current dashboard consumer. |
| `GET /api/capture/status` | Capture state/interface/errors/count | header. |
| `GET /api/alerts?skip=&limit=&alert_type=&severity=&status=` | List alerts | `{alerts, count}`; `AlertTable`. |
| `GET /api/alerts/{id}` | One alert | alert JSON; API available. |
| `PATCH /api/alerts/{id}` | body `{"status":"NEW|ACKNOWLEDGED|RESOLVED"}` | updated alert; alert detail modal. |
| `GET /api/incidents?skip=&limit=&status=` | Incident list and overview | `{incidents,count,overview}`; incident cards/table. |
| `GET /api/incidents/{id}` | Detail, alerts, timeline, contributors | incident JSON; incident modal. |
| `POST /api/incidents/{id}/acknowledge` | Mark incident acknowledged | detailed incident; modal. |
| `POST /api/incidents/{id}/resolve` | Mark incident resolved | detailed incident; modal. |
| `GET /api/rules` | Saved detector overrides | `{rules}`; Rules & Controls. |
| `PUT /api/rules/{rule_type}` | body `{"enabled":true,"settings":{...}}` | saved rule; applies to live engine immediately. |
| `GET/POST /api/trusted-devices` | POST body has `ip_address`, optional description/mac/hostname | device list/object; control page. |
| `DELETE /api/trusted-devices/{id}` | Remove stored record | `{deleted:true}`; control page. |
| `GET/POST /api/suppressions` | POST requires `reason` and one/more criteria: alert type/source/destination | list/object; control page. |
| `GET /api/activity?limit=100` | Stored alert-creation activity | `{events}`; Live Activity. |
| `GET /api/investigation/ip/{ip}` | Stored alerts/incidents for IP | history/protocols or 404; API only (no UI view). |
| `GET /api/threat-intelligence/indicators?search=&indicator_type=&severity=&status=&limit=` | List TI indicators | `{indicators}`; TI table. |
| `POST /api/threat-intelligence/indicators` | Indicator body below | created indicator; TI form. |
| `GET/PUT /api/threat-intelligence/indicators/{id}` | PUT uses full indicator body | indicator JSON; API supports update, UI does not expose edit. |
| `DELETE /api/threat-intelligence/indicators/{id}` | Soft-disable, retaining matches | disable confirmation; TI table. |
| `POST /api/threat-intelligence/import` | `{"format":"json|csv","content":"..."}` | import summary; TI import panel. |
| `GET /api/threat-intelligence/matches?indicator_id=&source_ip=` | TI evidence rows | `{matches}`; Recent TI Matches. |
| `GET /api/threat-intelligence/stats` | TI totals | counts; TI cards. |

## Part VI — Start the system

Replace `Z:\network-anomaly-detector` below with your actual project folder if it differs. Run the backend from its `backend` folder because `app` is there.

### Windows (sensor machine)

Open **PowerShell as Administrator**:

```powershell
cd 'Z:\network-anomaly-detector\backend'
py -m venv venv
.\venv\Scripts\python.exe -m pip install -r requirements.txt
.\venv\Scripts\python.exe -m uvicorn app.main:app --host 0.0.0.0 --port 8000
```

Only create the virtual environment once. Do not append `-m uvicorn` to the activation command. If you choose activation, use `.\venv\Scripts\Activate.ps1` on one line, then `python -m uvicorn ...` on the next.

In a second PowerShell window:

```powershell
cd 'Z:\network-anomaly-detector\frontend'
npm install
npm run dev
```

Open `http://localhost:5173`. When code changes, stop/restart Vite if needed and hard-refresh the browser with Ctrl+F5. Stop either server with Ctrl+C.

### Kali/Linux

Kali is normally the traffic generator, not the sensor. To run the entire application there instead:

```bash
cd /path/to/network-anomaly-detector/backend
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
sudo -E .venv/bin/python -m uvicorn app.main:app --host 0.0.0.0 --port 8000
```

In another terminal: `cd /path/to/network-anomaly-detector/frontend && npm install && npm run dev`.

## Part VII — Health checklist

Run these on Windows after backend startup:

```powershell
Invoke-RestMethod http://127.0.0.1:8000/api/health
Invoke-RestMethod http://127.0.0.1:8000/api/capture/status | ConvertTo-Json
Invoke-RestMethod http://127.0.0.1:8000/api/stats | ConvertTo-Json
Invoke-RestMethod http://127.0.0.1:8000/api/alerts | ConvertTo-Json -Depth 5
Test-NetConnection 127.0.0.1 -Port 8000
Test-NetConnection 127.0.0.1 -Port 5173
```

- [ ] `/api/health` says `ok`.
- [ ] Capture status says `running: true` and shows the intended interface.
- [ ] Packet count rises while you generate lab traffic.
- [ ] `/api/alerts` returns JSON, even if its list is empty.
- [ ] The dashboard is reachable on port 5173 and header shows Capture Active.
- [ ] Rules are enabled (`GET /api/rules`; no row means built-in defaults are active).

`/api/health` only confirms API process availability. `/api/capture/status` is the sensor check. The security-controls `/api/health` route has the same URL definition but is shadowed by the earlier simple route, so use capture status for practical health.

## Part VIII — isolated Kali → Windows lab

Use only VMs and IPs you own. A host-only VirtualBox network keeps test traffic away from production and the public Internet. Past sensor logs showed Windows `192.168.56.5`; do not assume it—discover both addresses:

```powershell
# Windows
Get-NetIPAddress -AddressFamily IPv4 | Format-Table IPAddress,InterfaceAlias
```

```bash
# Kali
ip -4 addr
ping -c 3 <WINDOWS_IP>
```

If Kali is `192.168.56.6` and Windows is `192.168.56.5`, Kali generates lab traffic and Windows runs backend/frontend. Confirm `ping` before the detector tests. Ping proves basic ICMP reachability and capture visibility, but the current port/connection detectors only count TCP or UDP, so ping alone should not create those alerts.

## Part IX — prove the pipeline, not just a command

For every test: generate traffic → independently verify it exists → verify capture packet count increases → query alerts API → inspect alert details → open/select incident → inspect timeline and risk contributors. An attack/test command completing is not evidence that the detector worked.

## Parts X–XV — safe detector tests

### 1. Connectivity

On Kali: `ping -c 3 <WINDOWS_IP>`. It creates ICMP packets. Expect packet count to rise; do not expect a port-scan or connection-burst alert. It proves the lab path, not anomaly detection.

### 2. Port scan

The `PortScanDetector` counts distinct TCP or UDP destination ports for one source-to-one-destination pair. Default: at least **20 unique ports in 5 seconds**, then a **60-second** cooldown. It produces `PORT_SCAN`, severity `HIGH`.

On Kali, against **only your Windows VM**:

```bash
nmap -sT -T4 -p 1-1000 <WINDOWS_IP>
```

Verify packets first: on Windows packet count rises; from Kali, `sudo tcpdump -ni <KALI_INTERFACE> host <WINDOWS_IP> and tcp` shows traffic. Then query:

```powershell
Invoke-RestMethod 'http://127.0.0.1:8000/api/alerts?alert_type=PORT_SCAN' | ConvertTo-Json -Depth 5
```

Open Dashboard → alert row → detail. Open the incident row and check `PORT_SCAN +30`. A scan can take longer than five seconds depending on VM performance, firewall behavior, Nmap timing, and capture drops. Reduce the active `PORT_SCAN` threshold only in your isolated lab via Rules & Controls, then restore it.

### 3. Connection burst

`ConnectionBurstDetector` counts every captured TCP/UDP packet from a source, not completed TCP sessions. Default: **100 packets in 10 seconds**, 60-second cooldown; result `CONNECTION_ANOMALY`, `MEDIUM`. Make a harmless temporary HTTP service on Windows:

```powershell
cd $env:TEMP
py -m http.server 8080
```

On Kali, use a loop against that service only:

```bash
for i in $(seq 1 120); do curl -s -o /dev/null --max-time 2 http://<WINDOWS_IP>:8080/ & done; wait
```

Then query `GET /api/alerts?alert_type=CONNECTION_ANOMALY`. Stop the temporary server with Ctrl+C. If 100 is not reached, use the Rules & Controls JSON for `CONNECTION_BURST`, for example `{"threshold":20,"window":10,"cooldown":60}`, save, test, then restore the normal value.

### 4. Traffic spike

`TrafficSpikeDetector` builds a rolling baseline of per-second packet/byte buckets: default 60-second history, at least 5 completed samples, and current rate greater than 3.0× average. It emits `TRAFFIC_ANOMALY`, `MEDIUM`, with no source/destination. Let normal lab traffic run for more than five seconds first, then generate a short burst to the harmless HTTP service:

```bash
for i in $(seq 1 300); do curl -s -o /dev/null --max-time 2 http://<WINDOWS_IP>:8080/ & done; wait
```

This heuristic is timing-dependent. Inspect `/api/traffic` and alert metadata for `current_pps`, `baseline_pps`, and multiplier. The detector's `baseline_window` cannot currently be changed through the rule API; `multiplier`, `min_samples`, and `cooldown` can. A global traffic alert only correlates if exactly one active incident exists.

### 5. DNS anomaly

DNS is the system that turns a name such as `example.org` into an IP. The sniffer records UDP DNS **queries** (not responses) as protocol `DNS`. The detector alerts if a query name is longer than 50 characters or if one source makes 50 DNS queries in 10 seconds; severity is `MEDIUM` and cooldown is 60 seconds.

On Kali, in the isolated lab, query harmless names through your configured resolver:

```bash
for i in $(seq 1 55); do dig +tries=1 +time=1 example.org >/dev/null; done
```

The Windows sensor must be able to see Kali’s DNS packets. A switched host-only network might only expose traffic to the Windows adapter if the Windows VM is the DNS path or the capture setup sees that traffic. Check capture count/tcpdump before expecting an alert. Query the API with `alert_type=DNS_ANOMALY`.

### 6. Suspicious/untrusted outbound destination

`SuspiciousOutboundDetector` checks destination IPs only. Its default trusted networks are RFC1918 ranges (`10/8`, `172.16/12`, `192.168/16`), so the host-only lab IPs are trusted and do not trigger it. `SUSPICIOUS_DESTINATIONS` in `.env` is an optional comma-separated explicit IP list; an explicit destination triggers `SUSPICIOUS_OUTBOUND` at `HIGH`, while destinations outside trusted networks trigger it at `LOW`. Do not use public targets merely to test this.

For a safe controlled test, add the IP of a second private lab-only VM to `SUSPICIOUS_DESTINATIONS`, restart backend (environment values load at process start), run a harmless HTTP server on that VM, and curl it from the sensor-visible host. This detector’s lists cannot be changed through the current UI.

## Parts XVI–XIX — Threat Intelligence

**Indicator** means something a security system wants to watch because it may be associated with harmful activity. Supported stored kinds are `IPV4`, `IPV6`, `DOMAIN`, and `URL`. IPs are canonicalized with Python IP parsing; domains are lower-cased and trailing dots removed; URLs are lower-cased in scheme/host with trailing path slash removed.

An indicator is active only when `enabled` and not expired. Confidence is a number from 0 to 1. Source describes where it came from; tags/description are optional context. Duplicate identity is type + normalized value + source: adding the same identity updates its metadata rather than inserting another row.

Important current scope: the live matcher examines `source_ip`, `destination_ip`, and `dns_query`. Thus IPv4, IPv6, and domain indicators can match live metadata. URL indicators are accepted/stored/imported but cannot match because packet metadata does not include a URL. Historical `ThreatMatch` rows survive disabling an indicator. Match evidence stores indicator/source/confidence/severity/tags and packet endpoints, but its `alert_id` and `incident_id` are not filled by the current runtime implementation.

### Add an indicator in the UI

1. Open **Threat Intelligence**.
2. In **Add Indicator**, choose type and enter Value. The value is required.
3. Set source (default `local-test`), confidence 0–1, severity, optional expiry and description.
4. Click **Create indicator**. The table should show it as ACTIVE.
5. Use **Disable** to stop future matching; it preserves old evidence.

The UI can create, list, search (client-side by value/source), import, and disable. It does not currently offer an edit form, even though `PUT /api/threat-intelligence/indicators/{id}` exists.

API creation example:

```powershell
$body = @{ indicator_type='IPV4'; value='<KALI_IP>'; source='local-lab'; description='Safe Kali lab indicator'; tags='lab'; confidence=0.9; severity='HIGH'; enabled=$true } | ConvertTo-Json
Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8000/api/threat-intelligence/indicators -ContentType 'application/json' -Body $body
```

### Safe end-to-end TI test

Create an `IPV4` indicator for the **Kali lab IP**, for example `192.168.56.6`, then send Kali traffic to the monitored Windows IP:

```bash
ping -c 3 <WINDOWS_IP>
```

Ping is enough for TI because the matcher checks all packet IP metadata. Then, on Windows:

```powershell
Invoke-RestMethod http://127.0.0.1:8000/api/threat-intelligence/matches | ConvertTo-Json -Depth 6
Invoke-RestMethod 'http://127.0.0.1:8000/api/alerts?alert_type=THREAT_INTELLIGENCE' | ConvertTo-Json -Depth 6
Invoke-RestMethod http://127.0.0.1:8000/api/incidents | ConvertTo-Json -Depth 6
```

In the dashboard, see Recent TI Matches, then the TI alert. Click its related incident in the incident table and look for `THREAT_INTELLIGENCE +30` in Risk contributors. Repeated matching packets create evidence rows, but the alert service deduplicates an identical TI alert context inside 60 seconds and increases its occurrence count.

### TI import

In the TI page select a `.json`/`.csv` file or paste content, choose format (file choice sets it automatically), then click Import. JSON can be a list or an object with an `indicators` list. CSV uses headers. Required fields are `indicator_type` and `value`; source defaults to `manual`. Invalid records are returned in `invalid_records`, not silently discarded.

`lab-indicators.csv`:

```csv
indicator_type,value,source,description,tags,confidence,severity
IPV4,192.168.56.6,local-lab,Safe lab test,lab,0.9,HIGH
DOMAIN,example.org,local-lab,Harmless DNS lab test,lab,0.5,LOW
```

`lab-indicators.json`:

```json
[{"indicator_type":"IPV4","value":"192.168.56.6","source":"local-lab","confidence":0.9,"severity":"HIGH","tags":"lab"}]
```

The response has `total_records`, `new_indicators`, `updated_indicators`, `duplicates`, and `invalid_records`. In this implementation an existing record is counted as both updated and duplicate.

## Parts XX–XXII — Alerts, incidents, and risk

An alert includes timestamp, type, configured severity, source/destination IP and ports when available, protocol, explanation, status, metadata, occurrence count, and last-seen time. `NEW` means not yet handled, `ACKNOWLEDGED` means an analyst has seen it, and `RESOLVED` means closed. Status changes do not prove a security conclusion.

An incident is a container for related alerts, not the raw packet. Example: a Kali scan can cause `PORT_SCAN`; a TI match from the same Kali IP during the correlation window can join the same incident. The detailed incident displays alerts, timeline, and contributors.

Risk is the sum of one contributor per alert type, capped at 100. Defaults are:

| Detection contributor | Points |
| --- | ---: |
| `PORT_SCAN` | 30 |
| `CONNECTION_ANOMALY` | 25 |
| `TRAFFIC_ANOMALY` | 20 |
| `DNS_ANOMALY` | 15 |
| `SUSPICIOUS_OUTBOUND` | 10 |
| `THREAT_INTELLIGENCE` | 30 |

Risk levels are Low below 30, Medium 30–59, High 60–79, Critical 80+. The contributor record explains why points were added. A TI indicator's confidence/severity is stored in alert metadata/evidence; it does not change the fixed TI point value in the current scorer.

## Parts XXIII–XXV — Rules and controls

Open **Rules & Controls**. Save JSON settings such as:

```json
{"threshold":20,"window":5,"cooldown":60}
```

Allowed runtime setting names are `threshold`, `window`, `cooldown`, `multiplier`, `min_samples`, `long_domain_length`, and `severity`. The server validates non-negative numeric threshold/window/cooldown/multiplier/min_samples. Saving applies values to already-running detector objects immediately and saves them for the next restart. Environment settings apply when the backend starts. For `UNTRUSTED_OUTBOUND`, only `enabled` has useful current runtime effect; it has no matching generic numeric attributes. `severity` override applies to an alert result.

The UI calls the rule `UNTRUSTED_OUTBOUND`, while that detector produces alerts named `SUSPICIOUS_OUTBOUND`. This distinction matters for API filters/suppressions.

Trusted Devices can be saved/removed, but they are **not used by alert creation or detector evaluation in the current code**. Adding a trusted device does not whitelist it yet. Treat the page as inventory only, not as an active safety/control mechanism.

Suppressions do work: matching future alerts are still stored with suppression metadata and an activity event, but are not correlated into incidents. A suppression needs a reason and at least one criterion. It cannot be deleted/disabled through the current API/UI; set a carefully chosen expiration when testing. The UI’s selector contains rule names, so use the API to suppress `SUSPICIOUS_OUTBOUND` or `THREAT_INTELLIGENCE` specifically.

## Parts XXVI–XXIX — Investigation and troubleshooting

Beginner workflow: read alert type/description → record source/destination → inspect metadata and occurrences → click/open the incident → compare contributing detections → read timeline → inspect risk contributors → check TI Matches for IP/domain context → decide expected vs suspicious → acknowledge while investigating → resolve only after documented review.

`GET /api/investigation/ip/{ip}` returns stored alerts, incidents, first/last seen, and protocol occurrence sums for an IP. There is no domain investigation endpoint or dedicated UI page. A missing TI match means only that this local indicator list did not match; it does not mean safe.

Live Activity records alert creation (`ALERT` category) and is polled every 3 seconds. It does not currently record every status change or all control actions.

| Symptom | Check |
| --- | --- |
| Dashboard does not open | `npm run dev`, then `Test-NetConnection 127.0.0.1 -Port 5173`. |
| API unavailable | backend terminal and `Invoke-RestMethod http://127.0.0.1:8000/api/health`. |
| Dashboard/API work but no new alerts | `/api/capture/status`, adapter, Administrator privilege, packet count. |
| Packets do not rise | correct host-only adapter, Kali→Windows connectivity, Npcap/permissions. |
| Traffic exists but no alert | detector enabled, correct protocol, threshold/window/cooldown, not suppression. |
| API has alert but UI does not | browser dev console, Vite process, Ctrl+F5, proxy to port 8000. |
| TI indicator does not match | active/not expired, normalized type/value, IP/domain only, traffic visible. |

Decision tree:

```text
No alert?
├─ API running? no → start backend
├─ capture status running and packet count rising? no → adapter/Npcap/Admin/network
├─ expected detector enabled? no → enable/save rule
├─ required threshold/window reached? no → safe sufficient lab traffic
├─ cooldown/suppression active? yes → wait/remove expiry or use distinct safe test
└─ alert in API but absent in UI? → restart Vite, hard refresh, inspect browser console
```

## Part XXX — full end-to-end lab exercise

1. On Windows, start backend as Administrator and frontend; verify capture status.
2. Discover `<WINDOWS_IP>` and `<KALI_IP>`.
3. Add `<KALI_IP>` as a `local-lab` IPv4 TI indicator in the TI page.
4. On Kali: `ping -c 3 <WINDOWS_IP>`. Expect packet count, TI match/evidence, TI alert, incident, and TI risk contributor.
5. On Kali: `nmap -sT -T4 -p 1-1000 <WINDOWS_IP>`. Expect a `PORT_SCAN` alert if at least 20 ports are observed in five seconds. When it joins the active TI incident, expect `PORT_SCAN +30` and `THREAT_INTELLIGENCE +30`, normally a High risk score of 60.
6. Prove each stage with `/api/capture/status`, `/api/threat-intelligence/matches`, filtered alerts, `/api/incidents`, then dashboard detail dialogs.

If stage 4 fails, fix capture/TI activation before stage 5. If stage 5 fails, lower only the lab rule threshold, repeat, and restore it. This is the practical proof: captured lab packets produced persistent evidence, alert(s), a correlated incident, and explained risk in the UI.

## Parts XXXI–XXXIII — common mistakes and glossary

Common mistakes: targeting the wrong IP; using NAT rather than the host-only adapter; running capture without Administrator/root; expecting ping to trigger TCP/UDP detectors; not reaching a threshold; forgetting cooldown; disabling a rule; assuming a stored trusted device whitelists traffic; expecting URL indicators to match live traffic; treating TI as proof; confusing an alert with an incident; and blaming the frontend before checking the API/capture state.

| Term | Meaning |
| --- | --- |
| Packet | A small unit of network communication. |
| Metadata / payload | Addressing/technical envelope details / the contents; this project stores metadata, not payload. |
| TCP / UDP | Common transport protocols; TCP is connection-oriented, UDP is lightweight. |
| IP / port | Network address / numbered service endpoint such as TCP/443. |
| DNS | Name-to-IP lookup system. |
| Interface / sensor | Adapter used to observe traffic / the machine/software doing so. |
| Threshold, window, cooldown | Amount required / time period measured / wait before similar alert repeats. |
| Alert / incident | A detection record / related alerts grouped for investigation. |
| Correlation | Grouping related alerts by time/endpoints. |
| IOC/indicator/TI | Observable to watch / a value in the TI list / contextual indicator intelligence. |
| Confidence | Source’s stated reliability, 0 to 1. |
| False positive / false negative | Harmless event flagged / harmful event missed. |
| Baseline | Recent normal-ish traffic average used for comparison. |
| Risk score/contributor | Summed incident priority / the evidence category and points explaining it. |
| Whitelist / suppression | Allow/ignore concept / this implementation stores matching alerts but excludes them from incidents. |
| API / REST / JSON | Program HTTP interface / HTTP resource style / common structured data format. |
| Frontend / backend | Browser React application / FastAPI, detection, and database service. |

## Parts XXXIV–XXXVI — command cheat sheets

### API (PowerShell)

```powershell
Invoke-RestMethod http://127.0.0.1:8000/api/capture/status | ConvertTo-Json
Invoke-RestMethod http://127.0.0.1:8000/api/alerts | ConvertTo-Json -Depth 6
Invoke-RestMethod http://127.0.0.1:8000/api/incidents | ConvertTo-Json -Depth 6
Invoke-RestMethod http://127.0.0.1:8000/api/rules | ConvertTo-Json
Invoke-RestMethod http://127.0.0.1:8000/api/threat-intelligence/indicators | ConvertTo-Json -Depth 6
Invoke-RestMethod http://127.0.0.1:8000/api/threat-intelligence/matches | ConvertTo-Json -Depth 6
```

### Kali (isolated lab only)

| Test | Command | Expected result |
| --- | --- | --- |
| Connectivity | `ping -c 3 <WINDOWS_IP>` | reachability/capture count; TI can match source IP. |
| Port scan | `nmap -sT -T4 -p 1-1000 <WINDOWS_IP>` | `PORT_SCAN` if threshold reached. |
| DNS | `for i in $(seq 1 55); do dig example.org >/dev/null; done` | DNS alert only if Windows can see queries. |
| HTTP burst | curl loop in Part XII | connection/traffic behavior. |
| Visibility | `sudo tcpdump -ni <IFACE> host <WINDOWS_IP>` | packets independently visible. |

### Windows

```powershell
Get-NetIPAddress -AddressFamily IPv4
Get-NetAdapter
Test-Connection <KALI_IP> -Count 3
Get-NetTCPConnection -State Listen
Get-NetFirewallProfile | Format-Table Name,Enabled
Get-Process python,node -ErrorAction SilentlyContinue
```

## Parts XXXVII–XL — developer and deployment view

For a port scan, the exact path is: Kali Nmap → Windows adapter → `PacketSniffer._process_packet` → `_extract_metadata` → `main._on_packet` → `DetectionEngine.process_packet` → `PortScanDetector.evaluate` → `main._alert_callback` → `AlertService.create_alert` → `IncidentService.correlate_alert`/`_recalculate` → SQLite → `api/alerts.py` or `api/incidents.py` → `frontend/src/services/api.js` → `App.jsx` state → `AlertTable`/`IncidentDetail`.

Frontend files: `src/main.jsx` mounts React; `src/App.jsx` owns polling, view state, and modal selection; `src/services/api.js` issues JSON fetches; component files render dashboard cards/tables, controls, and TI. There is no client-side router; three navigation buttons select conditional views. Fetch errors are logged to the browser console; there is no visible global error banner.

Backend request pattern: FastAPI router → Pydantic request model where defined → service → SQLAlchemy session/SQLite → dictionary/JSON response. Packet detection is different: background Scapy thread → engine callbacks → database service.

Development Vite proxies `/api`; production needs a built frontend, managed backend process, protected access, persistent database backup, correct packet-capture permissions, and intentional network placement. Hosting a dashboard server does not make it see every network packet. Switched networks usually require traffic visibility such as a SPAN/mirror port, TAP, gateway placement, or a dedicated sensor.

## Parts XLI–XLIII — before-test and final reference

- [ ] Kali and Windows are on the isolated host-only network.
- [ ] Both lab IPs are confirmed; Kali can ping Windows.
- [ ] Backend runs as Administrator/root and frontend runs.
- [ ] Capture status is running on the correct adapter and packet count rises.
- [ ] Target is your own lab VM; rules are enabled; no unwanted suppression exists.
- [ ] Dashboard is open; you know which alert/incident/TI API checks to use.

Quick sequence: **start backend → start frontend → check capture status → verify packets → run a safe lab test → check alerts → inspect incident → read risk contributors → investigate → acknowledge/resolve appropriately.**

If you see `TCP/443`, it means TCP traffic to port 443; it does not itself identify an application or prove danger. `HIGH` is the configured severity of that detection. A TI match means local indicator metadata matched, and multiple contributors explain why the incident score is higher.

## Implementation reference

```text
Backend:          backend/
Frontend:         frontend/
Database:         backend/data/alerts.db (default resolved database location)
Main backend:     backend/app/main.py
Main frontend:    frontend/src/main.jsx
Packet capture:   backend/app/capture/sniffer.py
Detection engine: backend/app/detection/engine.py
Threat Intelligence: backend/app/services/threat_intelligence.py and backend/app/api/threat_intelligence.py
Tests:            tests/
Configuration:    .env and backend/app/config.py
```
