# Investigation Scope
- investigation_start: 2026-03-06T18:00:05Z
- investigation_end: 2026-03-06T21:00:05Z
- completion_status: Complete
- degraded_mode: false

# Executive Triage Summary
- Top services/ports of interest include VNC (with authentication issues), SSH, MS Terminal Server, Redis (showing unusual HTTP-like requests), and ICS/OT protocols like Kamstrup and Guardian AST.
- Confirmed known exploitation for CVE-2006-2369 related to VNC server authentication.
- Adbhoney malware samples and various web path traversals observed in Tanner are notable unmapped exploit-like items.
- High volume of attacks from Dynu Systems Incorporated (US) and DigitalOcean, LLC ASNs suggest potential botnet activity or compromised infrastructure, with specific Adbhoney malware samples pointing to potential Android-based botnet activity.

# Candidate Discovery Summary
- Total attack events: 30460
- Top attacking countries: United States (18044), Bolivia (1810), Ukraine (1171)
- Top attacker IPs: 207.174.0.19 (12925), 200.105.151.2 (1810), 79.124.40.98 (1002)
- Top CVEs: CVE-2006-2369 (7929), CVE-2025-55182 (91)
- Top alert categories: Misc activity (41703), Attempted Administrator Privilege Gain (7958)
- Missing inputs/errors: `has_url_path` field shows 0, suggesting a potential gap in general web path logging.

# Emerging n-day Exploitation
- **CVE-2006-2369: VNC Server Not Requiring Authentication**
    - cve/signature mapping: CVE-2006-2369, ET EXPLOIT VNC Server Not Requiring Authentication (case 2), ET INFO VNC Authentication Failure.
    - evidence summary: 7929 alerts for CVE-2006-2369. Additional 7927 alerts for VNC authentication failures.
    - affected service/port: VNC (typically port 5900/TCP).
    - confidence: High.
    - operational notes: Widespread scanning and attempted exploitation of VNC servers without authentication.

# Novel or Zero-Day Exploit Candidates (UNMAPPED ONLY, ranked)
- None identified with strong evidence to be labeled "potential zero-day candidate".

# Botnet/Campaign Infrastructure Mapping
- **item_id**: 1 (Based on high volume and shared infrastructure)
    - campaign_shape: Spray (numerous attacks from diverse IPs targeting common services). Potentially fan-out from specific compromised infrastructure.
    - suspected_compromised_src_ips: 207.174.0.19 (12925 counts), 200.105.151.2 (1810 counts), 79.124.40.98 (1002 counts).
    - ASNs / geo hints: AS398019 (Dynu Systems Incorporated, US), AS26210 (AXS Bolivia S. A., Bolivia), AS14061 (DigitalOcean, LLC).
    - suspected_staging indicators: Adbhoney malware samples (e.g., dl/689b47e85e5f2dde8c935d6b05b6a2db1d7d1686ee158b84e34e86f787844b21.raw).
    - suspected_c2 indicators: None explicitly identified as C2; Adbhoney malware download sources could be C2 or staging.
    - confidence: Medium.
    - operational notes: Monitor IPs associated with Dynu Systems and DigitalOcean for sustained VNC/SSH activity. Investigate Adbhoney malware sample download origins.

# Odd-Service / Minutia Attacks
- **service_fingerprint**: Kamstrup protocol / Guardian AST (Conpot honeypot)
    - why it’s unusual/interesting: These are ICS/OT specific protocols, indicating targeting of industrial control systems.
    - evidence summary: 52 events for Kamstrup protocol, 11 for Guardian AST.
    - confidence: High.
    - recommended monitoring pivots: Monitor ICS/OT network segments for activity related to these protocols, especially from external sources.
- **service_fingerprint**: Redis honeypot activity (port 6379/TCP)
    - why it’s unusual/interesting: Redis is often targeted for data exfiltration or as a pivot point. The presence of `GET / HTTP/1.0` is unusual for Redis, suggesting HTTP-based scanning against Redis ports.
    - evidence summary: 34 Redis actions, including `Closed`, `NewConnect`, `info`, `INFO`, `NONEXISTENT`, `PING`, `QUIT`, `GET / HTTP/1.0`.
    - confidence: Medium.
    - recommended monitoring pivots: Monitor Redis instances for unusual commands, connections from external IPs, and non-Redis protocols.

# Known-Exploit / Commodity Exclusions
- **Credential noise**: High volume of `root`, `user`, `admin` usernames and `123456`, `12345678`, `password` as passwords.
- **Scanning**: "ET SCAN MS Terminal Server Traffic on Non-standard Port" and Suricata truncated packet alerts indicate scanning.
- **Common bot patterns**: Numerous source IPs with "known attacker" and "mass scanner" reputations. High volume of `Linux 2.2.x-3.x` and `Windows NT kernel` OS fingerprints from P0f.

# Infrastructure & Behavioral Classification
- **Exploitation vs scanning**: Significant VNC exploitation attempts and credential stuffing, alongside widespread scanning for various services.
- **Campaign shape**: Predominantly wide-area scanning and opportunistic exploitation (spray) with some evidence of targeted ICS/OT and Android-based activities.
- **Infra reuse indicators**: Dynu Systems Incorporated and DigitalOcean, LLC ASNs show consistent malicious activity.
- **Odd-service fingerprints**: VNC (unauthenticated), Kamstrup protocol, Guardian AST, Redis (with unusual HTTP-like requests).

# Evidence Appendix
- **CVE-2006-2369: VNC Server Not Requiring Authentication**
    - source IPs with counts: 207.174.0.19 (among others).
    - ASNs with counts: Dynu Systems Incorporated (AS398019), DigitalOcean, LLC (AS14061), AXS Bolivia S. A. (AS26210).
    - target ports/services: VNC (5900/TCP).
    - payload/artifact excerpts: "GPL INFO VNC server response", "ET EXPLOIT VNC Server Not Requiring Authentication (case 2)", "ET INFO VNC Authentication Failure".
    - staging indicators: missing.
    - temporal checks results: unavailable.
- **Botnet/Campaign Infrastructure Mapping - Item 1**
    - source IPs with counts: 207.174.0.19 (12925), 200.105.151.2 (1810), 79.124.40.98 (1002).
    - ASNs with counts: Dynu Systems Incorporated (12925), DigitalOcean, LLC (3885), AXS Bolivia S. A. (1810).
    - target ports/services: Various.
    - paths/endpoints: `/data/local/tmp/nohup /data/local/tmp/trinity`, `dl/689b47e85e5f2dde8c935d6b05b6a2db1d7d1686ee158b84e34e86f787844b21.raw`.
    - payload/artifact excerpts: Adbhoney input commands and malware sample filenames.
    - staging indicators: Adbhoney malware sample download URLs.
    - temporal checks results: unavailable.

# Indicators of Interest
- **IPs**: 207.174.0.19, 200.105.151.2, 79.124.40.98, 136.114.97.84, 165.22.112.196
- **CVEs**: CVE-2006-2369, CVE-2025-55182
- **Malware Hashes/Filenames**: `689b47e85e5f2dde8c935d6b05b6a2db1d7d1686ee158b84e34e86f787844b21.raw`
- **Paths/URLs**: `/../../../../../etc/passwd`, `/.env`, `/SDK/webLanguage`, `/V2/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php`
- **Honeypot Artifacts**: `b'\x01I20100\n'` (Conpot input), `trinity` (Adbhoney payload).

# Backend Tool Issues
- The `has_url_path` field in `field_presence_check` returned 0, indicating that a general `url.path` field might not be consistently populated across all relevant logs. This potentially weakens comprehensive URL/path analysis outside of dedicated honeypots like Tanner.