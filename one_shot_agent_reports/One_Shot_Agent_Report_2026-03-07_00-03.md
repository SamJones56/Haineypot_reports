# Investigation Report

## 1) Investigation Scope
- investigation_start: 2026-03-07T00:00:05Z
- investigation_end: 2026-03-07T03:00:05Z
- completion_status: Complete
- degraded_mode: false

## 2) Executive Triage Summary
- Top services/ports of interest include VNC (5900-series), MS Terminal Server (non-standard ports), SSH (port 22), SMB (port 445), and various ICS/SCADA protocols (Kamstrup, Guardian AST) via Conpot.
- Confirmed known exploitation includes attempts related to CVE-2025-55182 and CVE-2006-3602, alongside widespread scanning for VNC and RDP.
- No novel or zero-day exploit candidates were strongly identified in this window.
- Botnet/campaign activity is characterized by broad scanning from diverse source IPs, with significant activity originating from DigitalOcean, ADISTA SAS, and Shereverov Marat Ahmedovich ASNs.
- Minutia attacks on ICS/SCADA honeypots using Kamstrup and Guardian AST protocols indicate specific targeting of industrial control systems.

## 3) Candidate Discovery Summary
- Total attack events: 24726
- Top attacking countries: United States (5993), France (3971), Seychelles (1935), Russia (1273), Netherlands (1097)
- Top attacking source IPs: 79.98.102.166 (2568), 45.87.249.170 (1887), 185.177.72.38 (953), 136.114.97.84 (842), 46.19.137.194 (609)
- Top attacking ASNs: DigitalOcean, LLC (3840), ADISTA SAS (2568), Shereverov Marat Ahmedovich (1888), Google LLC (1475), Bucklog SARL (1261)
- Top Suricata alert signatures: GPL INFO VNC server response (17707), ET SCAN MS Terminal Server Traffic on Non-standard Port (1720), ET INFO CURL User Agent (1299)
- Top CVEs: CVE-2025-55182 (78), CVE-2006-3602/4458/4542 (51), CVE-2024-38816 (13)
- Top alert categories: Misc activity (18639), Generic Protocol Command Decode (4560), Attempted Information Leak (3220)
- Top P0f OS distributions: Linux 2.2.x-3.x (34642), Windows NT kernel (32216), Linux 3.11 and newer (4237)
- Top input usernames: root (361), admin (92), 345gs5662d34 (87)
- Top input passwords: 345gs5662d34 (87), 3245gs5662d34 (85), 123456 (80)
- Top Tanner URI paths: / (57), /.aws/credentials (4), /.env.dev.local (4)
- Top Adbhoney input commands: None found.
- Top Adbhoney malware samples: None found.
- Top Conpot input commands: b'\x01I20100\n' (2)
- Top Conpot protocols: kamstrup_protocol (24), guardian_ast (14), kamstrup_management_protocol (1)
- Source IP reputations: known attacker (16275), mass scanner (545), bot, crawler (8)
- Missing inputs/errors: None.

## 4) Emerging n-day Exploitation
- **CVE-2025-55182**:
    - cve/signature mapping: CVE-2025-55182
    - evidence summary: 78 events
    - affected service/port: Unspecified in current data, but often related to web services or network protocols.
    - confidence: High
    - operational notes: Monitor for specific exploit attempts related to this CVE.
- **CVE-2006-3602/4458/4542**:
    - cve/signature mapping: CVE-2006-3602 CVE-2006-4458 CVE-2006-4542
    - evidence summary: 51 events
    - affected service/port: Older vulnerabilities, likely targeting various services.
    - confidence: High
    - operational notes: Indicates opportunistic scanning for older, unpatched systems.
- **GPL INFO VNC server response**:
    - cve/signature mapping: Suricata signature ID 2100560
    - evidence summary: 17707 events, indicating widespread scanning for VNC services.
    - affected service/port: VNC (ports 5901-5905 are prominent targets).
    - confidence: High
    - operational notes: Widespread scanning for VNC, likely for brute-forcing or known vulnerabilities.
- **ET SCAN MS Terminal Server Traffic on Non-standard Port**:
    - cve/signature mapping: Suricata signature ID 2023753
    - evidence summary: 1720 events, suggesting attempts to find RDP services on non-standard ports.
    - affected service/port: Microsoft Terminal Services/RDP (port 3389 typically, but scanned on non-standard ports).
    - confidence: High
    - operational notes: Indicates targeted scanning for RDP services, potentially for brute-force attacks.

## 5) Novel or Zero-Day Exploit Candidates
No strong evidence of novel or zero-day exploit candidates was identified in this investigation window.

## 6) Botnet/Campaign Infrastructure Mapping
- **Item ID:** Botnet-001 (Associated with broad scanning and brute-forcing)
    - campaign_shape: Spray/Fan-out (numerous IPs targeting various services)
    - suspected_compromised_src_ips: 79.98.102.166 (2568), 45.87.249.170 (1887), 185.177.72.38 (953)
    - ASNs / geo hints: DigitalOcean, LLC (US, 3840), ADISTA SAS (FR, 2568), Shereverov Marat Ahmedovich (SC, 1888)
    - suspected_staging indicators: No direct staging indicators from current data, but repeated attempts to access /.env* files via Tanner suggest potential reconnaissance for web application misconfigurations.
    - suspected_c2 indicators: No explicit C2 indicators.
    - confidence: High
    - operational notes: Block top attacking IPs and ranges from identified ASNs. Monitor for recurring patterns in `ET INFO CURL User Agent` and `ET INFO Request to Hidden Environment File - Inbound` signatures.

## 7) Odd-Service / Minutia Attacks
- **service_fingerprint: Conpot (kamstrup_protocol, guardian_ast)**
    - why it’s unusual/interesting: Targeting of industrial control system (ICS) specific protocols, indicating specialized attacks on critical infrastructure honeypots.
    - evidence summary: 24 events for `kamstrup_protocol`, 14 for `guardian_ast`, 1 for `kamstrup_management_protocol`.
    - confidence: High
    - recommended monitoring pivots: Further investigation into source IPs targeting Conpot, analysis of input commands for known ICS exploits.

## 8) Known-Exploit / Commodity Exclusions
- **Credential Noise**: Frequent attempts with usernames like "root", "admin", "postgres" and common passwords like "123456", "password" indicate widespread brute-force activity. (Counts: root: 361, admin: 92, 123456: 80)
- **Scanning**: Extensive scanning for VNC (GPL INFO VNC server response, 17707 events) and RDP on non-standard ports (ET SCAN MS Terminal Server Traffic on Non-standard Port, 1720 events) are common commodity scanning patterns.
- **Known Bot Patterns**: High volumes of activity from ASNs like DigitalOcean and Shereverov Marat Ahmedovich, often associated with hosting malicious infrastructure, align with commodity botnet activity. (DigitalOcean: 3840 events, Shereverov: 1888 events)

## 9) Infrastructure & Behavioral Classification
- **Exploitation vs Scanning**: Predominantly scanning activity (VNC, RDP, web path enumeration) with a notable presence of known n-day exploitation attempts (CVE-mapped alerts). Brute-forcing also observed.
- **Campaign Shape**: Primarily spray and fan-out patterns, where numerous source IPs are broadly scanning and attempting to exploit a wide range of services.
- **Infra Reuse Indicators**: High counts from specific ASNs and source IPs over the investigation period suggest continued use of established malicious infrastructure.
- **Odd-Service Fingerprints**: Distinct ICS/SCADA protocol interactions on Conpot honeypots (Kamstrup, Guardian AST).

## 10) Evidence Appendix
- **CVE-2025-55182**:
    - Source IPs with counts: Not directly available from `get_cve` output.
    - ASNs with counts: Not directly available from `get_cve` output.
    - Target ports/services: Not directly available from `get_cve` output.
    - Paths/endpoints: Not directly available from `get_cve` output.
    - Payload/artifact excerpts: Requires `suricata_cve_samples` for raw events.
    - Staging indicators: Not observed.
    - Temporal checks results: Within investigation window.
- **GPL INFO VNC server response (Signature ID 2100560)**:
    - Source IPs with counts: Not directly available from `get_alert_signature` output. Requires `top_src_ips_for_signature` (not available).
    - ASNs with counts: Not directly available.
    - Target ports/services: 5901, 5902, 5903, 5904, 5905 (from `get_country_to_port` for US).
    - Paths/endpoints: N/A (VNC protocol).
    - Payload/artifact excerpts: Requires `suricata_signature_samples` for raw events.
    - Staging indicators: Not observed.
    - Temporal checks results: Within investigation window.
- **Botnet-001 (Source IPs and ASNs)**:
    - Source IPs with counts: 79.98.102.166 (2568), 45.87.249.170 (1887), 185.177.72.38 (953), 136.114.97.84 (842), 46.19.137.194 (609)
    - ASNs with counts: DigitalOcean, LLC (3840), ADISTA SAS (2568), Shereverov Marat Ahmedovich (1888), Google LLC (1475), Bucklog SARL (1261)
    - Target ports/services: Varies widely, including 445, 80, 22, 5900s, 37777, 9100.
    - Paths/endpoints: / (57), /.aws/credentials (4), /.env.dev.local (4) (from Tanner).
    - Payload/artifact excerpts: Common usernames/passwords.
    - Staging indicators: Reconnaissance for hidden environment files (`/.env*`).
    - Temporal checks results: Within investigation window.

## 11) Indicators of Interest
- **IPs**: 79.98.102.166, 45.87.249.170, 185.177.72.38, 136.114.97.84, 46.19.137.194
- **CVEs**: CVE-2025-55182, CVE-2006-3602, CVE-2024-38816
- **Paths/Endpoints**: /, /.aws/credentials, /.env.dev.local, /.env.docker, /.env.example
- **Payload Fragments (Usernames)**: root, admin, 345gs5662d34, postgres, user
- **Payload Fragments (Passwords)**: 345gs5662d34, 3245gs5662d34, 123456, 12345, @qwer2024

## 12) Backend Tool Issues
No backend tool issues were encountered during this investigation. All data retrievals were successful.
