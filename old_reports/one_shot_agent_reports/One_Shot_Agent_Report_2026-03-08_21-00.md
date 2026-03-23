# Investigation Scope
- investigation_start: 2026-03-08T21:00:10Z
- investigation_end: 2026-03-09T00:00:10Z
- completion_status: Complete
- degraded_mode: false

# Executive Triage Summary
- Top services/ports of interest: VNC (ports 5901-5907), SSH (port 22), SMB (port 445), HTTP (port 80/443), Redis (port 6379), MS Terminal Server.
- Top confirmed known exploitation: Extensive VNC-related activity, including "VNC server response" (19224 counts), "MS Terminal Server Traffic on Non-standard Port" (818 counts), and "VNC Server Not Requiring Authentication (case 2)" (510 counts, mapped to CVE-2006-2369).
- Top unmapped exploit-like items: No clearly novel unmapped exploit candidates. Activity appears largely commodity-driven.
- Botnet/campaign mapping highlights: Significant activity from DigitalOcean, LLC (ASN 14061) and Google LLC (ASN 396982), suggesting cloud-based scanning or botnet infrastructure. Broad targeting across various ports and services indicates widespread scanning/brute-force.
- Major uncertainties if degraded: None.

# Candidate Discovery Summary
- Total attack events: 19272
- Top attacking countries: United States (5525), India (1177), Indonesia (1037), Australia (992), Netherlands (979)
- Top attacking source IPs: 45.95.214.24 (945), 136.114.97.84 (925), 177.126.130.163 (848)
- Top ASNs: DigitalOcean, LLC (ASN 14061, 5353), Google LLC (ASN 396982, 1308), Emre Anil Arslan (ASN 216099, 945)
- Top Suricata signatures: GPL INFO VNC server response (19224), ET SCAN MS Terminal Server Traffic on Non-standard Port (818)
- Top CVEs: CVE-2006-2369 (510), CVE-2025-55182 (84)
- Top alert categories: Misc activity (20285), Generic Protocol Command Decode (1353)
- Top usernames: root (195), admin (85)
- Top passwords: 123456 (96), 3245gs5662d34 (68)
- Top OS distribution (P0f): Windows NT kernel (48299), Linux 2.2.x-3.x (41733)
- Tanner honeypot paths: / (32), /.env (3), path traversal attempts (2)
- Adbhoney input: "echo "$(getprop ro.product.name 2>/dev/null) $(whoami 2>/dev/null)"" (2), "echo hello" (1)
- Conpot/Adbhoney malware samples: Missing/none found.
- `url.path` field missing from field presence check.

# Emerging n-day Exploitation
- **CVE-2006-2369: VNC Server Not Requiring Authentication**
    - cve/signature mapping: CVE-2006-2369, ET EXPLOIT VNC Server Not Requiring Authentication (case 2) (Signature ID: 2002923)
    - evidence summary: 510 counts related to this CVE. Primarily targeting various VNC ports.
    - affected service/port: VNC (ports 5901-5907, and others as seen in country-to-port for US, Australia)
    - confidence: High
    - operational notes: Continued monitoring for VNC exploitation, especially from IPs associated with mass scanning.

# Novel or Zero-Day Exploit Candidates
- No novel or potential zero-day exploit candidates were identified in this window.

# Botnet/Campaign Infrastructure Mapping
- **Mass Scanning and Credential Brute-Forcing Campaign**
    - item_id: N/A (broad campaign)
    - campaign_shape: Spray (wide distribution of source IPs, targeting many services)
    - suspected_compromised_src_ips:
        - 45.95.214.24 (945 counts)
        - 136.114.97.84 (925 counts)
        - 177.126.130.163 (848 counts)
        - 103.177.233.162 (535 counts)
    - ASNs / geo hints:
        - DigitalOcean, LLC (ASN 14061) - 5353 counts (primarily US)
        - Google LLC (ASN 396982) - 1308 counts
        - Emre Anil Arslan (ASN 216099) - 945 counts
    - suspected_staging indicators: No clear staging indicators.
    - suspected_c2 indicators: No explicit C2 indicators. Activity points to reconnaissance and initial access attempts.
    - confidence: High (for scanning/brute-forcing)
    - operational notes: Continue to monitor IPs from DigitalOcean and Google ASNs for persistent or evolving attack patterns. Focus on common credential attempts and VNC exploitation.

# Odd-Service / Minutia Attacks
- **Redis Honeypot Interactions**
    - service_fingerprint: Redis (port 6379)
    - why it’s unusual/interesting: Redis is often targeted for data exfiltration or to gain code execution. Observed actions include "Closed", "NewConnect", "info", and "help", indicating reconnaissance and basic interaction.
    - evidence summary: 27 total Redis events, with 9 "Closed", 9 "NewConnect", 5 "info", 2 "help".
    - confidence: Medium
    - recommended monitoring pivots: Monitor for more advanced Redis commands, attempts to write files, or suspicious module loading.

- **Adbhoney Reconnaissance Activity**
    - service_fingerprint: ADB (port 5555, inferred from Adbhoney)
    - why it’s unusual/interesting: Attacks against ADB are less common but can indicate attempts to compromise Android-based devices or IoT. Observed commands suggest attacker is trying to identify device information.
    - evidence summary: 34 total Adbhoney events. Input commands: `echo "$(getprop ro.product.name 2>/dev/null) $(whoami 2>/dev/null)"` (2), `echo hello` (1).
    - confidence: Medium
    - recommended monitoring pivots: Watch for further ADB commands, especially those attempting file transfers or command execution.

# Known-Exploit / Commodity Exclusions
- **Credential Noise**:
    - Brute-force attempts against common usernames (root, admin, ubuntu) and passwords (123456, password, 123) across various services. (Evidence: `get_input_usernames` and `get_input_passwords` results).
- **Common Scanners**:
    - Widespread scanning for VNC (ports 5900-5907), SSH (port 22), and SMB (port 445) from various source IPs and ASNs. (Evidence: `get_alert_signature` for VNC/SSH, `get_country_to_port` showing common ports, `get_src_ip_reputation` indicating "mass scanner").
- **Known Commodity Bot Patterns**:
    - Activity from "known attacker" IPs (11260 counts) and "bot, crawler" IPs (7 counts), indicating automated, widespread attack attempts. (Evidence: `get_src_ip_reputation`).

# Infrastructure & Behavioral Classification
- **Exploitation vs Scanning**: Predominantly scanning and brute-forcing activity, with some instances of known N-day VNC exploitation.
- **Campaign Shape**: Primarily "spray" pattern, with attackers originating from diverse IPs and ASNs, targeting a wide range of services and ports.
- **Infra Reuse Indicators**: High counts from specific ASNs like DigitalOcean and Google suggest the use of cloud infrastructure for launching attacks.
- **Odd-Service Fingerprints**: Redis honeypot interactions and Adbhoney reconnaissance indicate targeting of less common services beyond traditional web/SSH.

# Evidence Appendix
- **Emerging n-day Exploitation: CVE-2006-2369**
    - source IPs with counts: Associated with IPs from top attackers (e.g., 45.95.214.24, 136.114.97.84)
    - ASNs with counts: DigitalOcean, LLC (ASN 14061), Google LLC (ASN 396982), Emre Anil Arslan (ASN 216099)
    - target ports/services: VNC (5901, 5902, 5903, 5904, 5905, 5906, 5907)
    - paths/endpoints: N/A for VNC protocol
    - payload/artifact excerpts: "VNC server response", "VNC Server Not Requiring Authentication (case 2)", "VNC Authentication Failure"
    - staging indicators: Missing
    - temporal checks results: Observed within the report timeframe.

- **Botnet/Campaign Infrastructure Mapping: Mass Scanning and Credential Brute-Forcing Campaign**
    - source IPs with counts:
        - 45.95.214.24 (945)
        - 136.114.97.84 (925)
        - 177.126.130.163 (848)
        - 103.177.233.162 (535)
        - 178.128.247.189 (525)
    - ASNs with counts:
        - DigitalOcean, LLC (ASN 14061, 5353)
        - Google LLC (ASN 396982, 1308)
        - Emre Anil Arslan (ASN 216099, 945)
    - target ports/services: 22 (SSH), 80/443 (HTTP/S), 445 (SMB), 5901-5907 (VNC), 1337, 17000, 6036, 1133, 8088 (various)
    - paths/endpoints: / (32), /.env (3), path traversal attempts (e.g., /%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2Fetc%2Fpasswd)
    - payload/artifact excerpts: "root", "admin", "123456", "password", "echo "$(getprop ro.product.name 2>/dev/null) $(whoami 2>/dev/null)""
    - staging indicators: Missing
    - temporal checks results: Observed throughout the report timeframe.

# Indicators of Interest
- **IPs**: 45.95.214.24, 136.114.97.84, 177.126.130.163, 103.177.233.162, 178.128.247.189
- **CVEs**: CVE-2006-2369, CVE-2025-55182
- **Common Passwords**: 123456, password, 123
- **Common Usernames**: root, admin
- **VNC Signatures**: GPL INFO VNC server response, ET EXPLOIT VNC Server Not Requiring Authentication (case 2)
- **Tanner Paths**: /.env, path traversal strings like /%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2Fetc%2Fpasswd

# Backend Tool Issues
- No backend tool failures were encountered. However, `url.path` field was not present in the field presence check, suggesting that this specific field might not be indexed or used across all relevant honeypots. This did not materially affect the conclusions as other path-related fields (`tanner.path.keyword`) were available.