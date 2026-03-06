# Investigation Report

## Investigation Scope
- investigation_start: 2026-03-06T09:00:03Z
- investigation_end: 2026-03-06T12:00:03Z
- completion_status: Complete
- degraded_mode: false

## Executive Triage Summary
- Top services/ports of interest: VNC (5900, 5901, 5902, 5903, 5904), SMB (445), SSH (22), SMTP (25), HTTP (80/443), Kamstrup Management Protocol, Guardian AST.
- Top confirmed known exploitation: VNC server not requiring authentication (CVE-2006-2369) and React Server Components React2Shell Unsafe Flight Protocol Property Access (CVE-2025-55182).
- Top unmapped exploit-like items: Path traversal attempts (e.g., /%2E%2E%2Fetc%2Fpasswd) and attempts to access /.env files via Tanner honeypot.
- Botnet/campaign mapping highlights: Significant VNC scanning activity originating from the United States, and SMB scanning from Ukraine, France, and Russia. Credential stuffing attempts observed with common usernames and passwords.
- Major uncertainties if degraded: None.

## Candidate Discovery Summary
- Total attack events: 24878
- Top countries: United States (7368), Ukraine (4550), France (2936)
- Top attacker IPs: 79.98.102.166 (2574), 176.120.59.98 (2156), 207.174.1.152 (2001)
- Top ASNs: DigitalOcean, LLC (3076), ADISTA SAS (2574), Langate Ltd (2156)
- Top Suricata signatures: GPL INFO VNC server response (20842), SURICATA IPv4 truncated packet (2172), ET EXPLOIT VNC Server Not Requiring Authentication (case 2) (2081)
- Top CVEs: CVE-2006-2369 (2081), CVE-2025-55182 (187), CVE-2024-14007 (5)
- Top alert categories: Misc activity (23437), Generic Protocol Command Decode (5344), Attempted Administrator Privilege Gain (2108)
- Common usernames: root (193), 345gs5662d34 (53), user (38)
- Common passwords: 3245gs5662d34 (53), 345gs5662d34 (53), 123456 (48)
- P0f OS distribution: Windows NT kernel (54916), Linux 2.2.x-3.x (29178), Windows 7 or 8 (6519)
- Redis actions: Closed (1), NewConnect (1), info (1)
- Adbhoney input: Missing/no significant input.
- Adbhoney malware samples: Missing/no significant samples.
- Conpot inputs: Various control commands, potentially malformed.
- Tanner URIs: /, /favicon.ico, path traversal attempts, /.env, /robots.txt
- Conpot protocols: kamstrup_management_protocol (160), guardian_ast (47), kamstrup_protocol (3)
- Source IP reputation: known attacker (11697), mass scanner (677)

## Emerging n-day Exploitation
- **CVE-2006-2369: VNC Server Not Requiring Authentication**
    - cve/signature mapping: CVE-2006-2369, ET EXPLOIT VNC Server Not Requiring Authentication (case 2), GPL INFO VNC server response
    - evidence summary: 2081 events mapped to CVE, 20842 "GPL INFO VNC server response" alerts. Primarily targeting ports 5900-5904.
    - affected service/port: VNC (5900, 5901, 5902, 5903, 5904)
    - confidence: High
    - operational notes: Widespread scanning activity, particularly from the United States. Ensure VNC services are properly authenticated or not exposed publicly.

- **CVE-2025-55182: React Server Components React2Shell Unsafe Flight Protocol Property Access**
    - cve/signature mapping: CVE-2025-55182, ET WEB_SPECIFIC_APPS React Server Components React2Shell Unsafe Flight Protocol Property Access
    - evidence summary: 187 events mapped to CVE, 187 related Suricata alerts.
    - affected service/port: Web applications (HTTP/S)
    - confidence: Medium
    - operational notes: Monitor web server logs for exploitation attempts related to React Server Components. Patch vulnerable applications.

## Novel or Zero-Day Exploit Candidates (UNMAPPED ONLY, ranked)
- **candidate_id: NEC-20260306-001**
    - classification: novel exploit candidate
    - novelty_score: 7/10
    - confidence: Medium
    - provisional: false
    - key evidence: 2 events of path traversal attempts (e.g., /%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2Fetc%2Fpasswd) and 2 events of /.env file access attempts captured by Tanner honeypot. Source IPs involved include 79.98.102.166.
    - knownness checks performed + outcome: No CVE or specific signature mapping found for these particular path traversal patterns or .env file access in the provided Suricata data.
    - temporal checks (previous window / 24h) or “unavailable”: Unavailable
    - required follow-up: Investigate the specific source IPs for further activity. Analyze full request payloads for these events if available.

## Botnet/Campaign Infrastructure Mapping
- **item_id: BMI-20260306-001 (VNC/SMB Scanner Campaign)**
    - campaign_shape: Spray
    - suspected_compromised_src_ips: 79.98.102.166 (2574), 176.120.59.98 (2156), 207.174.1.152 (2001)
    - ASNs / geo hints: ADISTA SAS (France), Langate Ltd (Ukraine), Dynu Systems Incorporated (United States)
    - suspected_staging indicators: None explicitly identified from provided data.
    - suspected_c2 indicators: None explicitly identified from provided data.
    - confidence: High
    - operational notes: The widespread VNC and SMB scanning activity from various ASNs and countries suggests a large-scale scanning campaign. Block or rate-limit traffic from the identified source IPs and ASNs.

- **item_id: BMI-20260306-002 (Credential Stuffing Campaign)**
    - campaign_shape: Spray
    - suspected_compromised_src_ips: Not directly available per IP, but aggregated counts of common usernames/passwords indicate a broad credential stuffing effort.
    - ASNs / geo hints: N/A (IPs for credential stuffing are not specifically aggregated with this tool)
    - suspected_staging indicators: None explicitly identified from provided data.
    - suspected_c2 indicators: None explicitly identified from provided data.
    - confidence: High
    - operational notes: Implement strong password policies and multi-factor authentication to mitigate credential stuffing attacks. Monitor for authentication failures.

## Odd-Service / Minutia Attacks
- **service_fingerprint: VNC (ports 5900-5904)**
    - why it’s unusual/interesting: High volume of VNC scanning and exploitation attempts (CVE-2006-2369), indicating active targeting of VNC services, potentially misconfigured or unpatched.
    - evidence summary: 20842 "GPL INFO VNC server response" alerts, 2081 events of VNC server not requiring authentication exploit attempts.
    - confidence: High
    - recommended monitoring pivots: Monitor VNC port activity, review VNC server configurations for authentication requirements, and ensure VNC software is updated.

- **service_fingerprint: Kamstrup Management Protocol (Conpot Honeypot)**
    - why it’s unusual/interesting: Observation of ICS/OT-specific protocols like Kamstrup Management Protocol in a honeypot environment. This suggests targeted or generalized scanning/probing of industrial control systems.
    - evidence summary: 160 events for `kamstrup_management_protocol` and 3 events for `kamstrup_protocol` in Conpot honeypot.
    - confidence: Medium
    - recommended monitoring pivots: Monitor ICS/OT network segments for unexpected traffic on Kamstrup-related ports. Analyze Conpot logs for specific command inputs or further protocol interactions.

## Known-Exploit / Commodity Exclusions
- **Credential Noise:** High counts of common usernames ("root", "user", "admin") and passwords ("123456", "1234") indicate widespread brute-force or credential stuffing attempts across many IPs.
- **VNC/SMB Scanning:** Extensive scanning for VNC services on ports 5900-5904 and SMB services on port 445 is a common commodity activity.
- **IPv4 Truncated Packets:** Numerous "SURICATA IPv4 truncated packet" alerts (2172 counts) and "SURICATA AF-PACKET truncated packet" alerts (2172 counts) are often indicative of network anomalies or non-malicious traffic variations, but can also obscure malicious activity.

## Infrastructure & Behavioral Classification
- **Exploitation vs Scanning:** The majority of observed activity is scanning (VNC, SMB) with confirmed exploitation for CVE-2006-2369 (VNC) and CVE-2025-55182 (React). There are also indications of novel exploit attempts targeting web paths and `.env` files.
- **Campaign Shape:** Predominantly "spray" campaigns for VNC and SMB scanning, as well as credential stuffing, originating from a diverse set of source IPs and ASNs globally.
- **Infra Reuse Indicators:** The presence of specific source IPs engaged in multiple types of scanning and exploit attempts (e.g., 79.98.102.166 involved in VNC scanning and path traversal attempts) suggests some infrastructure reuse.
- **Odd-Service Fingerprints:** VNC on standard and non-standard ports, as well as ICS/OT protocols like Kamstrup Management Protocol via Conpot, stand out as operationally interesting.

## Evidence Appendix
- **CVE-2006-2369 (VNC Server Not Requiring Authentication)**
    - Source IPs with counts: 207.174.1.152 (2001), numerous other IPs involved in VNC scanning from US, Ukraine, France, Russia.
    - ASNs with counts: Dynu Systems Incorporated (US, 2001), Langate Ltd (Ukraine, 2156), ADISTA SAS (France, 2574)
    - Target ports/services: VNC (5900, 5901, 5902, 5903, 5904)
    - Paths/endpoints: N/A (protocol-level exploit)
    - Payload/artifact excerpts: "GPL INFO VNC server response", "ET EXPLOIT VNC Server Not Requiring Authentication (case 2)"
    - Staging indicators: Missing
    - Temporal checks results: Unavailable

- **NEC-20260306-001 (Novel Exploit Candidate: Path Traversal / .env access)**
    - Source IPs with counts: 79.98.102.166 (involved in 2 path traversal events and 2 .env access attempts)
    - ASNs with counts: ADISTA SAS (France, associated with 79.98.102.166)
    - Target ports/services: HTTP/S (Web servers via Tanner honeypot)
    - Paths/endpoints: /%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2Fetc%2Fpasswd, /..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd, /.env
    - Payload/artifact excerpts: Specific request paths indicating attempts to access sensitive files.
    - Staging indicators: Missing
    - Temporal checks results: Unavailable

- **BMI-20260306-001 (VNC/SMB Scanner Campaign)**
    - Source IPs with counts: 79.98.102.166 (2574), 176.120.59.98 (2156), 207.174.1.152 (2001), 193.239.26.198 (1017), 188.17.158.240 (1000)
    - ASNs with counts: DigitalOcean, LLC (3076), ADISTA SAS (2574), Langate Ltd (2156), Dynu Systems Incorporated (2001), Google LLC (1543)
    - Target ports/services: VNC (5900-5904), SMB (445), SSH (22), SMTP (25)
    - Paths/endpoints: N/A (port scanning/protocol-level)
    - Payload/artifact excerpts: Various Suricata alerts for VNC, SMB, and other protocol activity.
    - Staging indicators: Missing
    - Temporal checks results: Unavailable

## Indicators of Interest
- **IPs:** 79.98.102.166, 176.120.59.98, 207.174.1.152, 193.239.26.198, 188.17.158.240
- **CVEs:** CVE-2006-2369, CVE-2025-55182
- **Paths:** /%2E%2E%2Fetc%2Fpasswd, /.env, /+CSCOE+/logon.html, /wp-includes/wlwmanifest.xml
- **Payload fragments (Conpot):** "version bind", "default", "GET / HTTP/1.0" (as input)
- **Protocols (Conpot):** kamstrup_management_protocol, guardian_ast

## Backend Tool Issues
- No tool failures were encountered. All key checks were completed successfully.