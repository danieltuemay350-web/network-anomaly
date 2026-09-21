# Backend

Python/FastAPI backend for the Network Anomaly Detection System.

## Components

| Directory | Purpose |
|-----------|---------|
| `app/config.py` | Environment-variable configuration |
| `app/capture/` | Scapy packet capture |
| `app/detection/` | Rule-based detection engine and rules |
| `app/services/` | Alert persistence and business logic |
| `app/api/` | REST API endpoints |
| `app/models/` | SQLAlchemy models |
| `app/database/` | SQLite database setup |

## Setup

```bash
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Run (with packet capture – requires root)

```bash
sudo -E $(which python) -m uvicorn app.main:app --host 0.0.0.0 --port 8000
```

## Run (API only, no capture)

```bash
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000
```

## Standalone capture test

```bash
sudo python -m app.capture.sniffer --interface eth0
```

## Tests

```bash
cd backend
python -m pytest ../tests/ -v
```