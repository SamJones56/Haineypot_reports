# Investigation Report

## 1) Investigation Scope
- investigation_start: 2026-03-07T03:00:04Z
- investigation_end: 2026-03-07T06:00:04Z
- completion_status: Complete
- degraded_mode: false

## 2) Executive Triage Summary
- Top services/ports of interest: VNC (ports 5901-5905), HTTP (port 80), SSH (port 22), Modbus/ICS protocols (Conpot: guardian_ast, kamstrup_management_protocol, IEC104).
- Top confirmed known exploitation: CVE-2025-55182 CVE-2025-55182, CVE-2024-38816 CVE-2024-38816, CVE-2024-23334 CVE-2024-23334, CVE-2024-14007 CVE-2024-14007.
- Top unmapped exploit-like items: Attempts to access various `.env` files (Tanner honeypot), and generic "Misc activity" and "Generic Protocol Command Decode" alerts warrant further investigation for novel attack patterns.
- Botnet/campaign mapping highlights: High volume of "known attacker" and "mass scanner" IPs across multiple ASNs, particularly DigitalOcean, Google LLC, and Bucklog SARL. Geographically, United States, France, Indonesia, India, and Ukraine are prominent sources.
- Major uncertainties: Adbhoney honeypot did not capture significant input commands or malware samples, potentially indicating a lack of Android-specific attacks or limited honeypot engagement.

## 3) Candidate Discovery Summary
- Total attack events: 17442
- Top countries: United States (5318), France (1461), Indonesia (1073)
- Top attacking IPs: 185.177.72.23 (958), 136.114.97.84 (752), 45.95.214.24 (466)
- Top ASNs: DigitalOcean, LLC (2884), Google LLC (1428), Bucklog SARL (1112)
- Top alert signatures: GPL INFO VNC server response (16869), SURICATA IPv4 truncated packet (871), SURICATA AF-PACKET truncated packet (871)
- Top CVEs: CVE-2025-55182 CVE-2025-55182 (68), CVE-2024-38816 CVE-2024-38816 (12), CVE-2024-23334 CVE-2024-23334 (6)
- Top alert categories: Misc activity (17426), Generic Protocol Command Decode (3404), Misc Attack (1211)
- Top usernames: root (240), 345gs5662d34 (68), user (30)
- Top passwords: 345gs5662d34 (68), 3245gs5662d34 (67), password (40)
- Top OS (P0f): Linux 2.2.x-3.x (27337), Linux 3.11 and newer (2902), Windows NT kernel 5.x (634)
- Redis actions: NewConnect (18), Closed (17), GET / HTTP/1.1 (4)
- Adbhoney inputs/malware: Missing
- Conpot inputs: b'\x01I20100' (2), GET /favicon.ico HTTP/1.1... (1)
- Conpot protocols: guardian_ast (28), kamstrup_management_protocol (11), kamstrup_protocol (3)
- Tanner URIs: / (32), /.aws/credentials (4), /.env.dev.local (4)
- IP reputations: known attacker (10804), mass scanner (465)
- Missing inputs/errors: Adbhoney inputs and malware samples were not observed in significant counts. `has_url_path` field in `field_presence_check` shows 0 documents.

## 4) Emerging n-day Exploitation
- **CVE-2025-55182**:
    - cve/signature mapping: CVE-2025-55182 CVE-2025-55182 (alert.signature.keyword)
    - evidence summary: 68 occurrences.
    - affected service/port: Various, requires further investigation for specific port mapping.
    - confidence: High
    - operational notes: Monitor for specific exploit attempts related to this CVE.
- **CVE-2024-38816**:
    - cve/signature mapping: CVE-2024-38816 CVE-2024-38816 (alert.signature.keyword)
    - evidence summary: 12 occurrences.
    - affected service/port: Various, requires further investigation for specific port mapping.
    - confidence: Medium
    - operational notes: Investigate the context of these alerts to determine the targeted service.
- **CVE-2024-23334**:
    - cve/signature mapping: CVE-2024-23334 CVE-2024-23334 (alert.signature.keyword)
    - evidence summary: 6 occurrences.
    - affected service/port: Various, requires further investigation for specific port mapping.
    - confidence: Medium
    - operational notes: Assess potential impact and targeted systems.
- **CVE-2024-14007**:
    - cve/signature mapping: CVE-2024-14007 CVE-2024-14007 (alert.signature.keyword)
    - evidence summary: 5 occurrences.
    - affected service/port: Various, requires further investigation for specific port mapping.
    - confidence: Medium
    - operational notes: Further analysis needed to identify specific vulnerability exploitation.

## 5) Novel or Zero-Day Exploit Candidates
- No strong candidates for novel or zero-day exploits were identified at this time, but the unmapped activities below warrant continued monitoring.

## 6) Botnet/Campaign Infrastructure Mapping
- **VNC/SSH/HTTP Scanning Campaign**:
    - item_id: N/A (broad campaign)
    - campaign_shape: Spray (wide distribution across IPs and countries)
    - suspected_compromised_src_ips:
        - 185.177.72.23 (958 counts)
        - 136.114.97.84 (752 counts)
        - 45.95.214.24 (466 counts)
    - ASNs / geo hints: DigitalOcean, LLC (US), Google LLC (US), Bucklog SARL (France), Microsoft Corporation (US), FOP Dmytro Nedilskyi (Ukraine), UCLOUD INFORMATION TECHNOLOGY HK LIMITED (Hong Kong), Emre Anil Arslan (Turkey), IP Volume inc (Canada), PT Cloud Hosting Indonesia (Indonesia), ISPIXP IN CAMBODIA WITH THE BEST VERVICE IN THERE. (Cambodia). Top countries: United States, France, Indonesia, India, Ukraine.
    - suspected_staging indicators: N/A, appears to be direct scanning.
    - suspected_c2 indicators: N/A
    - confidence: High
    - operational notes: Block top attacking IPs and ranges from DigitalOcean and other cloud providers. Monitor for VNC, SSH, and HTTP brute-force or exploit attempts.

## 7) Odd-Service / Minutia Attacks
- **Conpot ICS Protocol Attacks**:
    - service_fingerprint: Conpot honeypot, ports associated with industrial control systems (ICS). Protocols: guardian_ast, kamstrup_management_protocol, IEC104.
    - why it’s unusual/interesting: Targeting of ICS/OT protocols suggests specialized attackers or automated scans aimed at industrial environments.
    - evidence summary: 28 guardian_ast, 11 kamstrup_management_protocol, 3 kamstrup_protocol, 1 IEC104 events. Inputs: b'\x01I20100', GET /favicon.ico HTTP/1.1...
    - confidence: Medium
    - recommended monitoring pivots: Further investigate source IPs targeting Conpot, analyze full payload of ICS protocol interactions for specific commands or exploits.
- **Redis Honeypot Activity**:
    - service_fingerprint: Redis (port 6379 by default). Actions: NewConnect, Closed, GET / HTTP/1.1, info, INFO, NONEXISTENT, PING, QUIT, SSH-2.0-Go.
    - why it’s unusual/interesting: Attempts to interact with Redis using common commands and an unexpected HTTP GET request, and even SSH-related string. This suggests reconnaissance or attempts to exploit misconfigured Redis instances.
    - evidence summary: 18 NewConnect, 17 Closed, 4 GET / HTTP/1.1, 3 info, 2 INFO, 2 NONEXISTENT, 2 PING, 2 QUIT, 2 SSH-2.0-Go events.
    - confidence: Medium
    - recommended monitoring pivots: Monitor for known Redis vulnerabilities, unusual commands, or data exfiltration attempts.

## 8) Known-Exploit / Commodity Exclusions
- **Credential Noise**:
    - Brute-force attempts against services using common usernames ("root", "user", "admin") and weak passwords ("123456", "password"). (Counts: "root" 240, "password" 40, "123456" 35).
- **Scanning Activity**:
    - High volume of "Misc activity" and "Generic Protocol Command Decode" alerts, indicating broad reconnaissance and port scanning across various IPs. (Total attacks: 17442).
    - IPs with "mass scanner" reputation. (Counts: 465).
- **Known Bot Patterns**:
    - IPs categorized as "known attacker" and "bot, crawler". (Counts: 10804 "known attacker", 4 "bot, crawler").
    - Recurrent VNC activity ("GPL INFO VNC server response" 16869 counts) and SSH session attempts on expected ports ("ET INFO SSH session in progress on Expected Port" 292 counts).

## 9) Infrastructure & Behavioral Classification
- **VNC/SSH/HTTP Scanning Campaign**: Exploitation vs scanning: Primarily scanning and brute-forcing, with some CVE-mapped exploitation attempts. Campaign shape: Spray. Infra reuse indicators: Multiple IPs from various ASNs, especially cloud providers. Odd-service fingerprints: VNC (5901-5905), SSH (22), HTTP (80).
- **ICS Protocol Attacks (Conpot)**: Exploitation vs scanning: Scanning and reconnaissance of ICS protocols. Campaign shape: Unknown (limited data). Infra reuse indicators: N/A. Odd-service fingerprints: Guardian_ast, kamstrup_management_protocol, IEC104.
- **Redis Honeypot Activity**: Exploitation vs scanning: Reconnaissance and potential exploitation attempts. Campaign shape: Unknown. Infra reuse indicators: N/A. Odd-service fingerprints: Redis (6379).
- **Tanner URI Attempts**: Exploitation vs scanning: Reconnaissance for sensitive configuration files. Campaign shape: Unknown. Infra reuse indicators: N/A. Odd-service fingerprints: Web server paths (/.env, /.aws/credentials).

## 10) Evidence Appendix
- **CVE-2025-55182**:
    - source IPs with counts: N/A (specific IPs not aggregated for this CVE).
    - ASNs with counts: N/A.
    - target ports/services: N/A.
    - paths/endpoints: N/A.
    - payload/artifact excerpts: N/A (raw Suricata events not retrieved).
    - staging indicators: N/A.
    - temporal checks results: N/A.
- **VNC/SSH/HTTP Scanning Campaign**:
    - source IPs with counts: 185.177.72.23 (958), 136.114.97.84 (752), 45.95.214.24 (466), 134.209.37.134 (438), 175.100.52.28 (337).
    - ASNs with counts: DigitalOcean, LLC (2884), Google LLC (1428), Bucklog SARL (1112), Microsoft Corporation (858).
    - target ports/services:
        - United States: 5902 (439), 5903 (274), 5904 (266), 5901 (259), 5905 (234).
        - France: 80 (1112), 22 (30), 37777 (25).
        - India: 22 (76), 5 (5), 23 (1).
        - Indonesia: 22 (101), 3306 (8), 5985 (1).
        - Ukraine: 25 (27), 4 (4), 22 (4), 3350 (3), 3395 (3), 4444 (2).
    - paths/endpoints: N/A (specific HTTP paths not aggregated for this campaign, but Tanner shows attempts for /.env files).
    - payload/artifact excerpts: "GPL INFO VNC server response", "ET INFO SSH session in progress on Expected Port".
    - staging indicators: N/A.
    - temporal checks results: N/A.
- **Conpot ICS Protocol Attacks**:
    - source IPs with counts: N/A (specific IPs not aggregated for Conpot).
    - ASNs with counts: N/A.
    - target ports/services: ICS-related ports.
    - paths/endpoints: N/A.
    - payload/artifact excerpts: "b'\x01I20100'", "GET /favicon.ico HTTP/1.1", "guardian_ast", "kamstrup_management_protocol", "IEC104".
    - staging indicators: N/A.
    - temporal checks results: N/A.
- **Redis Honeypot Activity**:
    - source IPs with counts: N/A.
    - ASNs with counts: N/A.
    - target ports/services: Redis (default 6379).
    - paths/endpoints: N/A.
    - payload/artifact excerpts: "NewConnect", "GET / HTTP/1.1", "info", "SSH-2.0-Go".
    - staging indicators: N/A.
    - temporal checks results: N/A.

## 11) Indicators of Interest
- **IPs**: 185.177.72.23, 136.114.97.84, 45.95.214.24, 134.209.37.134, 175.100.52.28
- **CVEs**: CVE-2025-55182, CVE-2024-38816, CVE-2024-23334, CVE-2024-14007
- **Alert Signatures**: GPL INFO VNC server response, ET SCAN MS Terminal Server Traffic on Non-standard Port, ET INFO SSH session in progress on Expected Port
- **Paths/Endpoints**: /, /.aws/credentials, /.env.dev.local, /.env.docker, /.env.example, /.env.local, /.env.prod, /.env.sample, /.env.save.1, /.env.save.2 (from Tanner)
- **Honeypot Inputs**: "root", "345gs5662d34", "password", "@qwer2025", "123456"
- **Conpot Protocol Inputs**: b'\x01I20100', guardian_ast, kamstrup_management_protocol, IEC104
- **Redis Actions**: GET / HTTP/1.1, info, SSH-2.0-Go

## 12) Backend Tool Issues
- None. All requested tool calls completed successfully.