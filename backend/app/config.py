"""Application configuration loaded from environment variables."""

from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent.parent

load_dotenv(BASE_DIR.parent / ".env")


def _int(key: str, default: int) -> int:
    return int(os.getenv(key, str(default)))


def _float(key: str, default: float) -> float:
    return float(os.getenv(key, str(default)))


def _str(key: str, default: str) -> str:
    return os.getenv(key, default)


# Network
# Empty means auto-detect.  Do not use a Linux-only default such as ``eth0``:
# on Windows Scapy/Npcap exposes the adapter through its own interface table.
NETWORK_INTERFACE: str = _str("NETWORK_INTERFACE", "").strip()

# Port‑scan detection
PORT_SCAN_THRESHOLD: int = _int("PORT_SCAN_THRESHOLD", 20)
PORT_SCAN_WINDOW: int = _int("PORT_SCAN_WINDOW", 5)
PORT_SCAN_COOLDOWN: int = _int("PORT_SCAN_COOLDOWN", 60)

# Connection burst detection
CONNECTION_THRESHOLD: int = _int("CONNECTION_THRESHOLD", 100)
CONNECTION_WINDOW: int = _int("CONNECTION_WINDOW", 10)
CONNECTION_COOLDOWN: int = _int("CONNECTION_COOLDOWN", 60)

# Traffic spike detection
TRAFFIC_BASELINE_WINDOW: int = _int("TRAFFIC_BASELINE_WINDOW", 60)
TRAFFIC_SPIKE_MULTIPLIER: float = _float("TRAFFIC_SPIKE_MULTIPLIER", 3.0)
TRAFFIC_MIN_SAMPLES: int = _int("TRAFFIC_MIN_SAMPLES", 5)
TRAFFIC_COOLDOWN: int = _int("TRAFFIC_COOLDOWN", 30)

# DNS anomaly detection
DNS_THRESHOLD: int = _int("DNS_THRESHOLD", 50)
DNS_WINDOW: int = _int("DNS_WINDOW", 10)
DNS_LONG_DOMAIN_LENGTH: int = _int("DNS_LONG_DOMAIN_LENGTH", 50)
DNS_COOLDOWN: int = _int("DNS_COOLDOWN", 60)

# Database (normalized to an absolute path anchored at the backend dir)
DATABASE_PATH: str = _str("DATABASE_PATH", str(BASE_DIR / "data" / "alerts.db"))
if not Path(DATABASE_PATH).is_absolute():
    DATABASE_PATH = str(BASE_DIR / Path(DATABASE_PATH))

# API
API_HOST: str = _str("API_HOST", "0.0.0.0")
API_PORT: int = _int("API_PORT", 8000)

# Trusted networks (comma‑separated CIDRs)
TRUSTED_NETWORKS: list[str] = [
    n.strip()
    for n in _str("TRUSTED_NETWORKS", "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16").split(",")
    if n.strip()
]

# Suspicious destinations (comma‑separated IPs)
SUSPICIOUS_DESTINATIONS: list[str] = [
    d.strip()
    for d in _str("SUSPICIOUS_DESTINATIONS", "").split(",")
    if d.strip()
]

# Feature‑extraction cleanup
MAX_TRACKING_AGE: int = _int("MAX_TRACKING_AGE", 120)

# Correlation, incident risk, and alert deduplication. Scores are summed once
# per contributing detection type and capped at 100.
CORRELATION_WINDOW_SECONDS: int = _int("CORRELATION_WINDOW_SECONDS", 60)
ALERT_DEDUP_WINDOW_SECONDS: int = _int("ALERT_DEDUP_WINDOW_SECONDS", 60)
RISK_SCORE_PORT_SCAN: int = _int("RISK_SCORE_PORT_SCAN", 30)
RISK_SCORE_CONNECTION_BURST: int = _int("RISK_SCORE_CONNECTION_BURST", 25)
RISK_SCORE_TRAFFIC_SPIKE: int = _int("RISK_SCORE_TRAFFIC_SPIKE", 20)
RISK_SCORE_DNS_ANOMALY: int = _int("RISK_SCORE_DNS_ANOMALY", 15)
RISK_SCORE_SUSPICIOUS_OUTBOUND: int = _int("RISK_SCORE_SUSPICIOUS_OUTBOUND", 10)
RISK_SCORE_THREAT_INTELLIGENCE: int = _int("RISK_SCORE_THREAT_INTELLIGENCE", 30)
RISK_MEDIUM_MIN: int = _int("RISK_MEDIUM_MIN", 30)
RISK_HIGH_MIN: int = _int("RISK_HIGH_MIN", 60)
RISK_CRITICAL_MIN: int = _int("RISK_CRITICAL_MIN", 80)

# Optional AI investigation. The key is backend-only and AI is off by default.
GEMINI_API_KEY: str = _str("GEMINI_API_KEY", "")
GEMINI_API_KEYS: list[str] = [key.strip() for key in _str("GEMINI_API_KEYS", "").split(",") if key.strip()]
GEMINI_MODEL: str = _str("GEMINI_MODEL", "gemini-3.5-flash")
AI_TI_ENABLED: bool = _str("AI_TI_ENABLED", "false").lower() == "true"
AI_TI_AUTO_INVESTIGATION: bool = _str("AI_TI_AUTO_INVESTIGATION", "false").lower() == "true"
AI_TI_MAX_REQUESTS_PER_MINUTE: int = _int("AI_TI_MAX_REQUESTS_PER_MINUTE", 5)
AI_TI_TIMEOUT_SECONDS: int = _int("AI_TI_TIMEOUT_SECONDS", 20)
AI_TI_RETRY_ATTEMPTS: int = _int("AI_TI_RETRY_ATTEMPTS", 3)
AI_TI_RETRY_BASE_DELAY: float = _float("AI_TI_RETRY_BASE_DELAY", 2.0)
AI_TI_PROVIDER_COOLDOWN_SECONDS: int = _int("AI_TI_PROVIDER_COOLDOWN_SECONDS", 60)
