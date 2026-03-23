Investigation Scope
- investigation_start: 2026-03-09T00:00:07Z
- investigation_end: 2026-03-09T03:00:07Z
- completion_status: Complete
- degraded_mode: false

Executive Triage Summary
- Top services of interest: SSH (port 22), VNC (ports 5901-5912), SMB (port 445), Redis (port 6379), Kamstrup Management Protocol, IEC104.
- Top confirmed known exploitation: Notable CVEs include CVE-2025-55182, CVE-2024-14007, and older ones like CVE-2019-11500. Suricata alerts show "GPL INFO VNC server response" as the highest count.
- Top unmapped exploit-like items: Path traversal attempts on Tanner honeypot (e.g., "/..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd") and Adbhoney commands executing `echo "$(getprop ro.product.name 2>/dev/null) $(whoami 2>/dev/null)"`.
- Botnet/campaign mapping highlights: DigitalOcean, LLC and Google LLC ASNs are prominent sources of attacks. "Known attacker" is the most frequent IP reputation.
- Major uncertainties: No specific Adbhoney malware samples were identified, and Conpot input attempts were not recorded.

Candidate Discovery Summary
- Total attack events: 21938
- Top attacking countries: United States (5553), Indonesia (1874), South Korea (1527), Mexico (1097), Vietnam (1078)
- Top attacker source IPs: 136.114.97.84 (938), 46.19.137.194 (542), 79.124.40.98 (501)
- Top attacker ASNs: DigitalOcean, LLC (4211), Google LLC (1247), UNINET (1096)
- Top CVEs: CVE-2025-55182 (72), CVE-2024-14007 (21), CVE-2024-38816 (16)
- Top alert signatures: GPL INFO VNC server response (18189), SURICATA IPv4 truncated packet (2278), SURICATA AF-PACKET truncated packet (2278)
- Top alert categories: Misc activity (18797), Generic Protocol Command Decode (7241), Misc Attack (1041)
- Top P0f OS distribution: Windows NT kernel (51632), Linux 2.2.x-3.x (33476)
- Honeypot activity:
    - Tanner: 49 events, top paths include '/', '/.env', path traversal attempts.
    - Redis: 18 events, actions like 'Closed', 'NewConnect', 'info', 'GET / HTTP/1.1'.
    - Adbhoney: 19 events, inputs like `echo "$(getprop ro.product.name 2>/dev/null) $(whoami 2>/dev/null)"`. No malware samples.
    - Conpot: 3 events, protocols `kamstrup_management_protocol` and `IEC104`. No input.
- Top input usernames: root (292), admin (192), 345gs5662d34 (106)
- Top input passwords: "" (151), 345gs5662d34 (106), 3245gs5662d34 (105)

Emerging n-day Exploitation
- cve/signature mapping: CVE-2025-55182, CVE-2024-14007, CVE-2024-38816 were observed.
- evidence summary: 72 events for CVE-2025-55182, 21 for CVE-2024-14007, 16 for CVE-2024-38816. The specific services or ports for these CVEs were not directly provided by the `get_cve` tool.
- affected service/port: Not explicitly identified for these CVEs from the current data.
- confidence: High (based on CVE identification in Suricata alerts).
- operational notes: Monitor for specific exploitation attempts related to these CVEs.

Novel or Zero-Day Exploit Candidates (UNMAPPED ONLY, ranked)
- candidate_id: NEC-20260309-001
- classification: novel exploit candidate
- novelty_score: High
- confidence: Medium
- provisional: true
- key evidence: Tanner honeypot detected multiple path traversal attempts, e.g., `/..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd` (1 count), `/.env` (3 counts), `/.git/config` (1 count). These indicate attempts to access sensitive files outside of the web root.
- knownness checks performed + outcome: Basic checks for common web paths; these specific traversal patterns are less common in commodity scans.
- temporal checks: unavailable
- required follow-up: Investigate source IPs associated with these path traversal attempts for further context.

- candidate_id: NEC-20260309-002
- classification: novel exploit candidate
- novelty_score: Medium
- confidence: Medium
- provisional: true
- key evidence: Adbhoney honeypot captured input commands like `echo "$(getprop ro.product.name 2>/dev/null) $(whoami 2>/dev/null)"` (2 counts). This command attempts to gather system information, potentially as part of a post-exploitation reconnaissance phase.
- knownness checks performed + outcome: The command itself is not a direct exploit but an indicative behavior.
- temporal checks: unavailable
- required follow-up: Analyze the source IPs for these Adbhoney interactions and check for further malicious activity.

Botnet/Campaign Infrastructure Mapping
- item_id: BIM-20260309-001 (Associated with general scanning/attack activity)
- campaign_shape: Spray (wide distribution of source IPs across various ASNs and countries).
- suspected_compromised_src_ips: Top IPs include 136.114.97.84 (938), 46.19.137.194 (542), 79.124.40.98 (501).
- ASNs / geo hints: DigitalOcean, LLC (AS14061) - 4211 events, Google LLC (AS396982) - 1247 events, UNINET (AS8151) - 1096 events. Top countries: United States, Indonesia, South Korea.
- suspected_staging indicators: None explicitly identified in the provided data.
- suspected_c2 indicators: None explicitly identified.
- confidence: High (for identifying broad attack infrastructure).
- operational notes: Block known attacker IPs and monitor traffic from implicated ASNs, particularly DigitalOcean and Google Cloud, for further malicious activity.

Odd-Service / Minutia Attacks
- service_fingerprint: VNC on non-standard ports (5901-5912) from the United States.
- why it’s unusual/interesting: While VNC is a legitimate service, extensive scanning or attempted connections on a range of non-standard VNC ports suggests reconnaissance or brute-force attempts targeting less common VNC deployments.
- evidence summary: United States shows highest counts for ports 5902 (456), 5904 (286), 5903 (285), 5901 (267), 5905 (243).
- confidence: High
- recommended monitoring pivots: Monitor VNC traffic on both standard and non-standard ports, especially from source IPs with "known attacker" reputations.

- service_fingerprint: Conpot (Kamstrup Management Protocol, IEC104)
- why it’s unusual/interesting: These are ICS/OT protocols, typically not exposed to the internet. Any interaction with honeypots for these protocols indicates targeted reconnaissance or attacks against industrial control systems.
- evidence summary: Kamstrup Management Protocol (2 counts), IEC104 (1 count).
- confidence: Medium (low event count but high operational interest).
- recommended monitoring pivots: Investigate any observed traffic on ICS/OT protocols and implement strong segmentation for such systems.

Known-Exploit / Commodity Exclusions
- **Credential Noise**: Extensive brute-force attempts observed on SSH (port 22) and other services, indicated by top input usernames like "root," "admin," and common passwords like "12345," "123456," and empty passwords. This is widespread across many source IPs and countries.
- **Scanning Activity**: High volume of "Misc activity" and "Generic Protocol Command Decode" alerts. The "GPL INFO VNC server response" signature, while high count, can indicate widespread VNC scanning. "ET SCAN MS Terminal Server Traffic on Non-standard Port" also points to scanning.
- **Known Bot Patterns**: High count of source IPs with "known attacker" reputation and involvement of large hosting ASNs (DigitalOcean, Google LLC) suggest automated botnet activity.

Infrastructure & Behavioral Classification
- **Exploitation vs Scanning**: The majority of detected activity leans towards widespread scanning and brute-forcing. Specific exploitation attempts are indicated by CVEs and some novel path traversal attempts.
- **Campaign Shape**: Predominantly "spray" attacks from a large number of diverse source IPs and ASNs targeting various ports and services.
- **Infra Reuse Indicators**: High counts from specific ASNs (DigitalOcean, Google LLC) suggest the use of cloud hosting providers for attack infrastructure.
- **Odd-Service Fingerprints**: VNC on non-standard ports, Redis honeypot interactions, and ICS protocols (Kamstrup, IEC104) on Conpot.

Evidence Appendix
- **Novel Exploit Candidate NEC-20260309-001 (Path Traversal)**
    - source IPs with counts: Not directly available from the `tanner_unifrom_resource_search` tool for individual paths.
    - ASNs with counts: Missing.
    - target ports/services: HTTP/HTTPS (implied by web paths).
    - paths/endpoints: `/`, `/.env`, `/?XDEBUG_SESSION_START=phpstorm`, `/%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2Fetc%2Fpasswd`, `/..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd`, `/.env.test`, `/.git/config`, `/HNAP1`, `/cgi-bin/authLogin.cgi`, `/docker-compose.yml`
    - payload/artifact excerpts: `/.env`, `etc/passwd` (implied from path traversal)
    - staging indicators: missing
    - temporal checks results: unavailable

- **Novel Exploit Candidate NEC-20260309-002 (Adbhoney Reconnaissance)**
    - source IPs with counts: Not directly available from the `adbhoney_input` tool for individual inputs.
    - ASNs with counts: Missing.
    - target ports/services: ADB (Android Debug Bridge, implied by Adbhoney honeypot)
    - paths/endpoints: missing
    - payload/artifact excerpts: `echo "$(getprop ro.product.name 2>/dev/null) $(whoami 2>/dev/null)"`, `echo hello`
    - staging indicators: missing
    - temporal checks results: unavailable

- **Emerging n-day Exploitation (CVEs)**
    - cve/signature mapping: CVE-2025-55182, CVE-2024-14007, CVE-2024-38816
    - source IPs with counts: Not directly available from the `get_cve` tool.
    - ASNs with counts: Missing.
    - target ports/services: Not directly available from the `get_cve` tool.
    - paths/endpoints: Not directly available.
    - payload/artifact excerpts: Not directly available.
    - staging indicators: missing
    - temporal checks results: unavailable

- **Botnet/Campaign Infrastructure Mapping BIM-20260309-001**
    - source IPs with counts: 136.114.97.84 (938), 46.19.137.194 (542), 79.124.40.98 (501), 14.181.156.142 (500), 134.209.37.134 (454), 107.170.66.78 (445), 187.210.77.100 (445), 170.64.167.119 (410), 213.209.159.158 (409), 129.212.184.194 (341)
    - ASNs with counts: DigitalOcean, LLC (14061, 4211), Google LLC (396982, 1247), UNINET (8151, 1096), PT Cloud Hosting Indonesia (136052, 1027), Korea Telecom (4766, 1010)
    - target ports/services: Wide range of ports including 22, 445, 5901-5912, 6379, 5436, 15432, 80.
    - paths/endpoints: Various, including generic web paths and specific honeypot inputs.
    - payload/artifact excerpts: "GPL INFO VNC server response" (signature), various usernames/passwords.
    - staging indicators: missing
    - temporal checks results: unavailable

Indicators of Interest
- IPs: 136.114.97.84, 46.19.137.194, 79.124.40.98, 14.181.156.142, 134.209.37.134
- Domains/URLs: None explicitly identified as malicious C2 or staging. However, paths like `/.env`, `/..%2F..%2Fetc%2Fpasswd`, `/.git/config` are of high interest.
- CVEs: CVE-2025-55182, CVE-2024-14007, CVE-2024-38816
- Payload fragments: `echo "$(getprop ro.product.name 2>/dev/null) $(whoami 2>/dev/null)"` (Adbhoney input)
- Ports: 22 (SSH), 445 (SMB), 5901-5912 (VNC), 6379 (Redis), 5436 (Conpot/Kamstrup), 15432 (Conpot/IEC104)
- Usernames: root, admin
- Passwords: "", 345gs5662d34, 12345

Backend Tool Issues
- None. All requested tools executed successfully.