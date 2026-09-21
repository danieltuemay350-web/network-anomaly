# Presentation content audit

## Files inspected

- `README.md`
- `docs/testing.md`
- `docs/detection-rules.md`
- `backend/app/detection/*`
- `backend/app/services/threat_intelligence.py`
- `backend/app/ai/*`
- `frontend/package.json`
- `docker-compose.yml`

## Verified implemented features

- Scapy packet capture and metadata extraction
- Rule-based port scan, connection burst, traffic anomaly, DNS anomaly, and suspicious outbound detection
- FastAPI, SQLAlchemy, SQLite, React, Vite, Tailwind CSS, Recharts, Lucide, and Docker Compose
- Threat indicators: IPv4, IPv6, domain, URL; normalization; enable/disable; expiry; import; match evidence
- Alerts, correlation, incidents, explainable risk contributors, and dashboard
- Optional Gemini AI investigation with English and Amharic explanations; AI does not change detection/risk

## Evidence and screenshots

- `tmp/pdfs/manual-01.png` is used as an operator-manual excerpt, not as a live dashboard screenshot.
- Lab/testing claims come from `docs/testing.md` and are described as controlled scenarios, not measured production outcomes.

## Proposed or future content

- Target customers, Ethiopia-first potential, business model, revenue services, pricing rationale, and roadmap are proposed concepts.
- Production hardening, more TI integrations, and managed services are future work.

## Claims intentionally excluded

- No detection accuracy, market size, customer count, revenue, or performance claims.
- No claim of real-time web grounding, enterprise IDS equivalence, or market leadership.

## External sources

- None used. Ecosystem references are described generically without a ranking or external factual claims.

## Deliverable

- `Network_Anomaly_Detector_Presentation.pptx`
