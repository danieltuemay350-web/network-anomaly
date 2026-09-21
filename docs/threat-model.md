# Threat Model

## Assets

The system monitors and protects:

- **Network traffic metadata** – packet headers, flow statistics
- **Hosts on the monitored network** – by detecting suspicious patterns directed at or originating from them
- **Network availability** – by detecting potential DDoS or abuse patterns early

## Threats Detected

| Threat | Detection Method | Confidence |
|--------|-----------------|------------|
| Port scanning | Unique-port counting per source→dest | High |
| Connection flooding/bursts | Connection rate per source IP | High |
| Traffic flooding/spikes | Baseline comparison | Medium |
| DNS tunnelling / DGA | Query frequency + domain length | Low–Medium |
| Connections to suspicious destinations | Allow/block-list | Depends on list quality |

## Attack Surface

### The detector itself

- **API endpoints** – currently unauthenticated; anyone on the network can query alerts
- **Packet capture** – requires root; a vulnerability in Scapy could be exploitable
- **SQLite database** – stored on disk; readable by any process with filesystem access
- **Configuration** – environment variables; an attacker with env access could disable detection

### Limitations of the attack surface analysis

This MVP does not implement:
- TLS for API communication
- Authentication/authorization
- Input sanitization beyond Pydantic validation
- Rate limiting on API endpoints
- Audit logging of API access

## What This System Cannot Detect

Be explicit about these limitations:

1. **Encrypted payload inspection** – Cannot decrypt or inspect TLS traffic contents
2. **Application-layer attacks** – SQL injection, XSS, etc. are not visible at the network level
3. **Low-and-slow attacks** – Attackers who stay below thresholds will not trigger alerts
4. **Encrypted C2 channels** – Cannot distinguish encrypted malware C2 from legitimate HTTPS
5. **Insider threats from trusted IPs** – Connections from within trusted networks are not flagged
6. **Zero-day exploits** – Rule-based detection cannot identify novel attack patterns
7. **Spoofed IPs** – IP-based tracking can be defeated by IP spoofing
8. **Distributed attacks** – Each source is tracked independently; distributed scans from many IPs each below threshold will not trigger alerts
9. **IPv6** – The current implementation focuses on IPv4

## Recommendations for Production Use

This MVP is designed for learning and lab environments. For production:

- Add API authentication (OAuth2, API keys)
- Use TLS for all API communication
- Run on a dedicated monitoring interface
- Add log rotation and retention policies
- Consider a proper IDS (Suricata, Zeek) for production detection
- Implement proper threat intelligence feeds
- Add distributed collection if monitoring multiple network segments
