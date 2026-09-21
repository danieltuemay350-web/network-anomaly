# Network Anomaly Detection System

A lightweight, rule-based network monitoring and anomaly detection system built for learning, lab environments, and controlled demonstrations.

## Project Overview

This MVP captures live network traffic, extracts metadata and statistics, evaluates transparent rule-based detection logic, stores alerts, and visualizes them in a real-time web dashboard. It detects port scanning, connection bursts, traffic spikes, suspicious outbound connections, and basic DNS anomalies—using only explainable, configurable rules (no machine learning).

## Problem Statement

Organizations need visibility into network traffic to detect suspicious behaviour early. Commercial SIEM and IDS solutions are complex and expensive. This project demonstrates the core concepts—packet capture, feature extraction, rule-based detection, alerting, and visualization—in a transparent, understandable, and runnable MVP.

## Architecture

```
Network Traffic → Scapy Sniffer → Feature Extraction → Detection Engine
                                                            ↓
                                                    Alert / Normal
                                                        ↓
                                                  SQLite Database
                                                        ↓
                                                    FastAPI REST
                                                        ↓
                                                  React Dashboard
```

## Technology Stack

| Layer       | Technology                        |
|-------------|-----------------------------------|
| Capture     | Python, Scapy                     |
| Backend     | Python, FastAPI, SQLAlchemy, Pydantic |
| Database    | SQLite                            |
| Frontend    | React, Vite, Tailwind CSS, Lucide, Recharts |
| DevOps      | Docker, Docker Compose            |
| Testing     | pytest, httpx                     |

## Quick Start

### Prerequisites

- Python 3.11+
- Node.js 18+
- npm
- Linux or Windows with Npcap installed for packet capture

### 1. Clone and configure

```bash
cd network-anomaly-detector
cp .env.example .env
# Edit .env as needed
```

### 2. Backend

```bash
cd backend
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Run the API + capture (requires root for live capture)
sudo -E $(which python) -m uvicorn app.main:app --host 0.0.0.0 --port 8000
```

### 3. Frontend

```bash
cd frontend
npm install
npm run dev
```

Open http://localhost:5173

### 4. Docker (dashboard only)

```bash
docker compose up --build
```

> **Note:** Packet capture requires host-level privileges. Docker is suitable for running the API and dashboard, but live capture should run directly on the host.

## Running Packet Capture

The sniffer can also run standalone for testing capture only:

```bash
cd backend
source venv/bin/activate
python -m app.capture.sniffer --list-interfaces
python -m app.capture.sniffer --test --duration 5
```

- Leave `NETWORK_INTERFACE` blank to auto-detect a suitable IPv4 adapter. The
  diagnostic lists Scapy's real capture names and Npcap mappings on Windows.
- An invalid explicit interface is never hidden: the API/dashboard logs the
  configured value, available choices, and any auto-selected replacement.
- Linux capture generally needs root; Windows capture generally needs a terminal
  started as Administrator with Npcap installed.

## Configuration

All settings are controlled via environment variables. The backend automatically loads a `.env` file from the project root if present. See `.env.example` for the full list.

Key settings:

| Variable | Default | Description |
|---|---|---|
| `NETWORK_INTERFACE` | empty / auto-detect | Interface for packet capture |
| `PORT_SCAN_THRESHOLD` | 20 | Unique ports to trigger scan alert |
| `PORT_SCAN_WINDOW` | 5 | Time window for port scan (seconds) |
| `CONNECTION_THRESHOLD` | 100 | Connections to trigger burst alert |
| `TRAFFIC_SPIKE_MULTIPLIER` | 3.0 | Factor above baseline to trigger spike alert |
| `DNS_THRESHOLD` | 50 | DNS queries to trigger burst alert |
| `DATABASE_PATH` | ./data/alerts.db | SQLite database path |
| `API_PORT` | 8000 | API server port |

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/health` | Health check |
| GET | `/api/alerts` | List alerts (supports `?severity=HIGH&alert_type=PORT_SCAN`) |
| GET | `/api/alerts/{id}` | Get alert details |
| PATCH | `/api/alerts/{id}` | Update alert status |
| GET | `/api/stats` | Aggregate alert statistics |
| GET | `/api/devices` | Unique source IPs with alert counts |
| GET | `/api/traffic` | Traffic rate history |
| GET | `/api/capture/status` | Capture status and packet count |

## Detection Rules

See `docs/detection-rules.md` for detailed explanations of each rule.

## Testing

```bash
cd backend
python -m pytest ../tests/ -v
```

## Lab Testing

See `docs/testing.md` for a controlled lab testing guide with attack simulation scenarios.

## Known Limitations

- No encrypted traffic decryption
- No ML-based detection (rule-based only in v1)
- No authentication on API endpoints
- Single-node architecture (not distributed)
- SQLite has write contention under heavy load
- No persistent alert correlation across time
- IPv4 focus (IPv6 not tracked)
- Low-and-slow attacks below thresholds evade detection

> **Running under `sudo`:** packet capture needs root, but that makes the SQLite DB
> (`data/alerts.db`) root-owned; later non-root runs then fail with
> `attempt to write a readonly database`. If that happens, fix ownership once:
> `sudo chown -R $USER:$USER backend/data` — or set `DATABASE_PATH` to a personal path.

## Future Improvements

- **Authentication & authorization** on the API (API keys / OAuth2) with role-based access
- **TLS termination** for the API and dashboard
- **ML-based detection layer** using the stored alert history as labeled training data
- **Alert correlation** across time and hosts (e.g. scan-then-exploit chains)
- **Distributed collectors** that forward metrics to a central analysis node
- **Encrypted-traffic metadata analysis** (TLS SNI, certificate transparency logs)
- **More DNS heuristics** (random-looking subdomains, NXDOMAIN storms, entropy scoring)
- **Threat-intelligence feed integration** to replace the static suspicious-destination list
- **Email / webhook / Slack notification** on critical alerts
- **Historical reporting** and export (CSV/PDF)
- **Alert deduplication and aggregation** improvements
- **Proper IPv6 support**

## License

Educational / learning project. No warranty.
