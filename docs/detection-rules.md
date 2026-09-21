# Detection Rules

All rules are configurable via environment variables. No rules use machine learning—every decision is transparent and explainable.

---

## 1. Port Scan Detection

**File:** `backend/app/detection/port_scan.py`

**Method:** Sliding-window unique-port counting.

When a single source IP contacts more than `PORT_SCAN_THRESHOLD` unique destination ports on a target within `PORT_SCAN_WINDOW` seconds, an alert fires.

**Configuration:**

| Variable | Default | Description |
|---|---|---|
| `PORT_SCAN_THRESHOLD` | 20 | Unique ports required to trigger |
| `PORT_SCAN_WINDOW` | 5 | Time window in seconds |
| `PORT_SCAN_COOLDOWN` | 60 | Minimum seconds between alerts for same src→dst pair |

**Alert severity:** HIGH

**Example alert:**
```json
{
  "alert_type": "PORT_SCAN",
  "severity": "HIGH",
  "source_ip": "192.168.1.100",
  "destination_ip": "192.168.1.50",
  "description": "Port scan detected: 192.168.1.100 contacted 25 unique ports on 192.168.1.50 within 5s window"
}
```

---

## 2. Connection Burst Detection

**File:** `backend/app/detection/connection_anomaly.py`

**Method:** Sliding-window connection counting per source IP.

When a host makes more than `CONNECTION_THRESHOLD` connection attempts within `CONNECTION_WINDOW` seconds, an alert fires.

**Configuration:**

| Variable | Default | Description |
|---|---|---|
| `CONNECTION_THRESHOLD` | 100 | Connections required to trigger |
| `CONNECTION_WINDOW` | 10 | Time window in seconds |
| `CONNECTION_COOLDOWN` | 60 | Minimum seconds between alerts for same source |

**Alert severity:** MEDIUM

---

## 3. Traffic Spike Detection

**File:** `backend/app/detection/traffic_anomaly.py`

**Method:** Baseline comparison with rolling average.

The detector maintains a rolling window of per-second packet counts and byte totals. When enough samples exist (≥ `TRAFFIC_MIN_SAMPLES`), it computes the average and compares the current second's values against it. If the current rate exceeds `TRAFFIC_SPIKE_MULTIPLIER × baseline`, an alert fires.

**Configuration:**

| Variable | Default | Description |
|---|---|---|
| `TRAFFIC_BASELINE_WINDOW` | 60 | Seconds of history to average |
| `TRAFFIC_SPIKE_MULTIPLIER` | 3.0 | Factor above average to trigger |
| `TRAFFIC_MIN_SAMPLES` | 5 | Minimum samples before baseline is valid |
| `TRAFFIC_COOLDOWN` | 30 | Minimum seconds between alerts |

**Alert severity:** MEDIUM

**Why this approach:** Simple, understandable, and deterministic. A moving average baseline catches sustained increases without requiring training data.

---

## 4. DNS Anomaly Detection

**File:** `backend/app/detection/dns_anomaly.py`

**Method:** Two independent rules:

### Rule A: DNS Query Burst
Counts DNS queries per source IP within a window. If the count exceeds `DNS_THRESHOLD`, an alert fires.

### Rule B: Long Domain Name
If any DNS query contains a domain name longer than `DNS_LONG_DOMAIN_LENGTH` characters, an alert fires immediately (no window needed).

Long domains are often associated with DNS tunnelling or DGA (Domain Generation Algorithm) malware.

**Configuration:**

| Variable | Default | Description |
|---|---|---|
| `DNS_THRESHOLD` | 50 | Queries to trigger burst alert |
| `DNS_WINDOW` | 10 | Time window in seconds |
| `DNS_LONG_DOMAIN_LENGTH` | 50 | Characters to trigger long-domain alert |
| `DNS_COOLDOWN` | 60 | Minimum seconds between alerts |

**Alert severity:** MEDIUM

**Important caveat:** These rules detect *anomalous patterns*, not definitively malicious behaviour. High DNS volume could be a legitimate CDN client.

---

## 5. Suspicious Outbound Connections

**File:** `backend/app/detection/suspicious_outbound.py`

**Method:** Allow/block-list matching.

The detector checks each packet's destination IP against:
1. **Trusted networks** (default: RFC 1918 private ranges)
2. **Suspicious destinations** (explicitly configured IPs)

Connections to explicitly suspicious destinations generate a HIGH severity alert. Connections to destinations outside trusted networks generate a LOW severity alert.

**Configuration:**

| Variable | Default | Description |
|---|---|---|
| `TRUSTED_NETWORKS` | 10.0.0.0/8,172.16.0.0/12,192.168.0.0/16 | Trusted CIDRs |
| `SUSPICIOUS_DESTINATIONS` | (empty) | IPs to always flag |

**Severity:** HIGH (blocked destination) or LOW (untrusted destination)

**Caveat:** This is not a threat intelligence system. It demonstrates the architecture for integrating such data.
