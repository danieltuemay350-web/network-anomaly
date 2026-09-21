# Lab Testing Guide

## Required Environment

All testing must be performed in an **isolated lab environment**. Never test against networks you do not own or control.

### Recommended Setup

```
┌─────────────────┐     ┌──────────────────────────────┐
│  Attacker VM    │     │  Target + Detector            │
│  (Kali Linux)   │     │  (Ubuntu / Debian)            │
│                 │     │                               │
│  nmap, hping3,  │────▶│  Network Anomaly Detector     │
│  dig, curl      │     │  (running on same host)       │
│                 │     │                               │
└─────────────────┘     └──────────────────────────────┘
        │                              │
        └──── Isolated VirtualBox/VMware Network ──────┘
              (Host-only or NAT network)
```

### Virtual Network Configuration

1. Create a host-only or internal network in your hypervisor
2. Assign IPs in the `192.168.56.0/24` range
3. Ensure no traffic leaks to production networks

## Running the Detector

```bash
cd backend
source venv/bin/activate
sudo -E $(which python) -m uvicorn app.main:app --host 0.0.0.0 --port 8000
```

## Test Scenarios

### Test 1: Normal Traffic (No Alert Expected)

From the attacker VM:
```bash
ping 192.168.56.100
curl http://192.168.56.100:80
```

**Expected result:** No security alerts generated.

---

### Test 2: Port Scan (PORT_SCAN Alert Expected)

From the attacker VM:
```bash
sudo nmap -sT -p 1-50 192.168.56.100
```

**Expected result:** `PORT_SCAN` alert with severity HIGH, showing source IP of attacker and 50 ports scanned.

Verify:
```bash
curl http://localhost:8000/api/alerts | python3 -m json.tool
```

---

### Test 3: Connection Burst (CONNECTION_ANOMALY Alert Expected)

From the attacker VM:
```bash
for i in $(seq 1 150); do
  curl --connect-timeout 0.1 http://192.168.56.100:80 2>/dev/null &
done
wait
```

**Expected result:** `CONNECTION_ANOMALY` alert with severity MEDIUM.

---

### Test 4: Traffic Spike (TRAFFIC_ANOMALY Alert Expected)

From the attacker VM, generate sustained high-bandwidth traffic:
```bash
dd if=/dev/urandom | pv -L 10m | nc 192.168.56.100 9999 &
# Run for ~15 seconds, then kill
```

Or use hping3:
```bash
sudo hping3 --flood --rand-source -S 192.168.56.100
```

**Expected result:** `TRAFFIC_ANOMALY` alert after baseline is established (~5+ seconds of data).

---

### Test 5: DNS Anomaly (DNS_ANOMALY Alert Expected)

From the attacker VM, generate DNS query burst:
```bash
for i in $(seq 1 60); do
  dig @192.168.56.100 test${i}.example.com 2>/dev/null
done
```

**Expected result:** `DNS_ANOMALY` alert with query burst detection.

For long domain test:
```bash
# Create a very long subdomain
LONG=$(python3 -c "print('a' * 60 + '.example.com')")
dig @8.8.8.8 "$LONG"
```

**Expected result:** `DNS_ANOMALY` alert for long domain name.

---

### Test 6: Database Persistence

```bash
curl http://localhost:8000/api/stats | python3 -m json.tool
curl http://localhost:8000/api/alerts?severity=HIGH | python3 -m json.tool
curl http://localhost:8000/api/devices | python3 -m json.tool
```

---

### Test 7: Alert Status Management

```bash
# Acknowledge an alert
curl -X PATCH http://localhost:8000/api/alerts/1 \
  -H "Content-Type: application/json" \
  -d '{"status": "ACKNOWLEDGED"}'

# Resolve it
curl -X PATCH http://localhost:8000/api/alerts/1 \
  -H "Content-Type: application/json" \
  -d '{"status": "RESOLVED"}'
```

---

## Test Results Template

| # | Test | Expected | Actual | Result |
|---|------|----------|--------|--------|
| 1 | Normal traffic | No alerts | | |
| 2 | Port scan (nmap) | PORT_SCAN alert | | |
| 3 | Connection burst | CONNECTION_ANOMALY alert | | |
| 4 | Traffic spike | TRAFFIC_ANOMALY alert | | |
| 5 | DNS burst | DNS_ANOMALY alert | | |
| 6 | Database persistence | Alerts stored & queryable | | |
| 7 | Alert status update | Status changes reflected | | |
| 8 | Dashboard display | Alerts visible in UI | | |
