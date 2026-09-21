# Architecture

## Overview

The system follows a pipeline architecture:

```
┌──────────────────┐     ┌──────────────────┐     ┌──────────────────┐
│ Packet Capture   │────▶│ Feature Extract   │────▶│ Detection Engine │
│ (Scapy)          │     │ (per-detector)    │     │ (rule evaluators)│
└──────────────────┘     └──────────────────┘     └────────┬─────────┘
                                                           │
                                                   ┌───────┴───────┐
                                                   ▼               ▼
                                               Normal          Alert
                                                           ┌──────┴──────┐
                                                           │ Alert Store │
                                                           │ (SQLite)    │
                                                           └──────┬──────┘
                                                           ┌──────┴──────┐
                                                           │  REST API   │
                                                           │  (FastAPI)  │
                                                           └──────┬──────┘
                                                           ┌──────┴──────┐
                                                           │  Dashboard  │
                                                           │  (React)    │
                                                           └─────────────┘
```

## Components

### Packet Capture (`capture/sniffer.py`)

- Uses Scapy's `sniff()` in a background thread
- Extracts metadata: source/destination IP, ports, protocol, size, TCP flags, DNS queries
- Forwards `PacketMetadata` objects to the detection engine
- Does **not** store packet payloads

### Detection Engine (`detection/engine.py`)

- Central orchestrator holding all detector instances
- Receives `PacketMetadata` from the sniffer
- Passes each packet to every detector
- Forwards alerts to the persistence layer
- Periodically records traffic statistics

### Detection Rules (`detection/*.py`)

Each detector is an independent, configurable class:

1. **PortScanDetector** – sliding-window unique-port counter
2. **ConnectionBurstDetector** – sliding-window connection counter
3. **TrafficSpikeDetector** – baseline comparison with rolling average
4. **DNSAnomalyDetector** – query frequency + domain length analysis
5. **SuspiciousOutboundDetector** – allow/block-list matching

### Alert Service (`services/alert_service.py`)

- CRUD operations on the alert database
- Statistics aggregation
- Device tracking
- Traffic stat recording

### REST API (`api/*.py`)

- FastAPI application with CORS enabled
- Endpoints for alerts, stats, devices, traffic, health
- Pydantic validation on request bodies

### Frontend (`frontend/`)

- React single-page application
- Polls the API every 3 seconds
- Displays: stats overview, alert table, traffic chart, detection summary, device list
- Alert detail modal with status management

## Data Flow

1. Scapy captures a raw packet on the configured interface
2. `PacketSniffer._extract_metadata()` converts it to `PacketMetadata`
3. The metadata is passed to `DetectionEngine.process_packet()`
4. The engine evaluates the packet against all 5 detectors
5. Any detector returning an alert dict triggers `AlertService.create_alert()`
6. The alert is stored in SQLite
7. The React frontend polls `/api/alerts` and renders the new alert

## Threading Model

- **Main thread**: FastAPI / uvicorn serves the REST API
- **Sniffer thread**: Scapy's `sniff()` runs in a daemon thread
- **Database access**: Uses separate sessions per operation (thread-safe with `check_same_thread=False`)
