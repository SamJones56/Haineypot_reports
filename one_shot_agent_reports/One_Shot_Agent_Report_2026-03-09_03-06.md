# Investigation Scope
- investigation_start: 2026-03-09T03:00:03Z
- investigation_end: 2026-03-09T06:00:03Z
- completion_status: Complete
- degraded_mode: false

# Executive Triage Summary
- Top services/ports of interest: VNC (ports 5900-5915), SMB (port 445), SSH (port 22), MS Terminal Server (non-standard ports), Redis (port 6379), HTTP (port 80, 8888), Modbus/IEC104 (Conpot).
- Top confirmed known exploitation: GPL INFO VNC server response (17436 events), ET SCAN MS Terminal Server Traffic on Non-standard Port (810 events), CVEs including CVE-2025-55182 (60 events), and a cluster of older CVEs (CVE-2006-3602, CVE-2006-4458, CVE-2006-4542 with 57 events).
- Top unmapped exploit-like items: None explicitly identified as novel/zero-day candidates.
- Botnet/Campaign mapping highlights: Widespread scanning for VNC and SMB services from cloud providers like DigitalOcean and The Constant Company. Significant attack volume from Indonesia and the United States.
- Major uncertainties if degraded: None.

# Candidate Discovery Summary
- Total attack events: 24395
- Top countries: United States (8930), Indonesia (3151), Netherlands (965)
- Top source IPs: 182.8.193.5 (2267), 144.202.106.26 (1477), 107.170.66.78 (1030)
- Top ASNs: DigitalOcean, LLC (14061, 4916), PT. Telekomunikasi Selular (23693, 2267), The Constant Company, LLC (20473, 1934)
- Top CVEs: CVE-2025-55182 (60), CVE-2006-3602 CVE-2006-4458 CVE-2006-4542 (57), CVE-2024-38816 (13)
- Top alert signatures: GPL INFO VNC server response (17436), ET SCAN MS Terminal Server Traffic on Non-standard Port (810)
- Top alert categories: Misc activity (18017), Generic Protocol Command Decode (4083), Misc Attack (1115)
- Common usernames: root (180), admin (145), 345gs5662d34 (97)
- Common passwords: 345gs5662d34 (97), 3245gs5662d34 (96), 123456 (85)
- P0f OS distribution: Windows NT kernel (47056), Linux 2.2.x-3.x (32412)
- Redis actions: Closed (4), NewConnect (4), info (4)
- Adbhoney input: `echo "$(getprop ro.product.name 2>/dev/null) $(whoami 2>/dev/null)"` (2)
- Adbhoney malware samples: None
- Conpot input: None
- Tanner URIs: / (14), /.env (2), /actuator/gateway/routes (2)
- Conpot protocols: IEC104 (7), guardian_ast (2), kamstrup_protocol (1)
- Source IP reputations: known attacker (11758), mass scanner (703)
- Missing inputs/errors: None

# Emerging n-day Exploitation
- **CVE-2025-55182**
    - cve/signature mapping: CVE-2025-55182
    - evidence summary: 60 events
    - affected service/port: Not explicitly identified.
    - confidence: High
    - operational notes: Monitor for specific exploitation attempts related to this CVE.

- **CVE-2006-3602 CVE-2006-4458 CVE-2006-4542**
    - cve/signature mapping: CVE-2006-3602, CVE-2006-4458, CVE-2006-4542
    - evidence summary: 57 events
    - affected service/port: Not explicitly identified.
    - confidence: High
    - operational notes: These are older CVEs, likely commodity scanning or opportunistic exploitation.

# Novel or Zero-Day Exploit Candidates (UNMAPPED ONLY, ranked)
No strong candidates identified as novel or potential zero-day from the aggregated data. All identified CVEs appear to be known.

# Botnet/Campaign Infrastructure Mapping
- **VNC/MS Terminal Server Scanning Campaign**
    - item_id: N/A
    - campaign_shape: Spray
    - suspected_compromised_src_ips: 182.8.193.5 (2267), 144.202.106.26 (1477), 107.170.66.78 (1030)
    - ASNs / geo hints: DigitalOcean, LLC (US), PT. Telekomunikasi Selular (Indonesia), The Constant Company, LLC (US). Top countries include United States, Indonesia, Netherlands, Hong Kong, Australia.
    - suspected_staging indicators: Not explicitly identified.
    - suspected_c2 indicators: Not explicitly identified.
    - confidence: High
    - operational notes: Widespread scanning for VNC (ports 5900-5915) and RDP (MS Terminal Server) from various cloud providers and ISPs. Focus on blocking top attacking IPs and monitoring for successful connections to these services.

- **SMB Attack Campaign**
    - item_id: N/A
    - campaign_shape: Spray
    - suspected_compromised_src_ips: Top IPs from Indonesia (2360 events to port 445) and India (399 events to port 445).
    - ASNs / geo hints: PT. Telekomunikasi Selular (Indonesia), ASNs associated with India.
    - suspected_staging indicators: Not explicitly identified.
    - suspected_c2 indicators: Not explicitly identified.
    - confidence: Medium
    - operational notes: Significant SMB activity, especially from Indonesia and India. Investigate specific SMB attacks for potential exploits or credential stuffing.

# Odd-Service / Minutia Attacks
- **Conpot ICS Protocol Activity**
    - service_fingerprint: Conpot honeypot, protocols IEC104, guardian_ast, kamstrup_protocol.
    - why it’s unusual/interesting: Targeting of Industrial Control Systems (ICS) protocols indicates potential reconnaissance or attacks against critical infrastructure.
    - evidence summary: 10 events related to Conpot, with specific protocols identified.
    - confidence: Medium
    - recommended monitoring pivots: Monitor for further ICS protocol activity and associated source IPs.

- **Redis Honeypot Activity**
    - service_fingerprint: Redis (port 6379)
    - why it’s unusual/interesting: Redis instances are often targeted for data exfiltration or use as C2 infrastructure.
    - evidence summary: 12 events including "Closed", "NewConnect", and "info" actions.
    - confidence: Medium
    - recommended monitoring pivots: Monitor Redis logs for unusual commands, connections from new IPs, or large data transfers.

- **Adbhoney Input Activity**
    - service_fingerprint: Adbhoney (Android Debug Bridge honeypot)
    - why it’s unusual/interesting: Attempts to interact with ADB ports can indicate targeting of Android devices or IoT. The command `echo "$(getprop ro.product.name 2>/dev/null) $(whoami 2>/dev/null)"` suggests reconnaissance or fingerprinting.
    - evidence summary: 8 events, including the command mentioned.
    - confidence: Medium
    - recommended monitoring pivots: Monitor ADB port exposure and activity for similar reconnaissance commands or attempts to upload malware.

# Known-Exploit / Commodity Exclusions
- **Credential Noise:** High volume of common usernames ("root", "admin", "test", "user") and passwords ("123456", "password", "123") seen across many IPs.
- **Scanning Activity:** Widespread VNC and MS Terminal Server scanning, indicated by "GPL INFO VNC server response" and "ET SCAN MS Terminal Server Traffic on Non-standard Port" signatures. General "Misc activity" and "Generic Protocol Command Decode" alert categories also suggest broad scanning.
- **Known Bot Patterns:** IPs from DigitalOcean, The Constant Company, LLC, and PT. Telekomunikasi Selular frequently appear in the top attacker lists, consistent with cloud-based botnet or scanning infrastructure. "known attacker" and "mass scanner" reputations are prevalent.

# Infrastructure & Behavioral Classification
- Exploitation vs Scanning: Predominantly scanning activity, with some indications of attempted exploitation for known CVEs. Credential stuffing attempts are also significant.
- Campaign shape: Largely "spray" campaigns, targeting common services across a wide range of IPs.
- Infra reuse indicators: Extensive use of cloud infrastructure (DigitalOcean, The Constant Company, LLC) for attack origination. Repeat offenders among top source IPs.
- Odd-service fingerprints: ICS protocols (IEC104, guardian_ast, kamstrup_protocol) via Conpot, Redis database interactions, and Android Debug Bridge (Adbhoney) reconnaissance attempts.

# Evidence Appendix
- **Emerging n-day Exploitation: CVE-2025-55182**
    - source IPs with counts: Not explicitly aggregated.
    - ASNs with counts: Not explicitly aggregated.
    - target ports/services: Not explicitly identified.
    - paths/endpoints: Not explicitly identified.
    - payload/artifact excerpts: Not available.
    - staging indicators: Not available.
    - temporal checks results: Unavailable.

- **Emerging n-day Exploitation: CVE-2006-3602 CVE-2006-4458 CVE-2006-4542**
    - source IPs with counts: Not explicitly aggregated.
    - ASNs with counts: Not explicitly aggregated.
    - target ports/services: Not explicitly identified.
    - paths/endpoints: Not explicitly identified.
    - payload/artifact excerpts: Not available.
    - staging indicators: Not available.
    - temporal checks results: Unavailable.

- **Botnet/Campaign Infrastructure Mapping: VNC/MS Terminal Server Scanning Campaign**
    - source IPs with counts: 182.8.193.5 (2267), 144.202.106.26 (1477), 107.170.66.78 (1030)
    - ASNs with counts: DigitalOcean, LLC (4916), PT. Telekomunikasi Selular (2267), The Constant Company, LLC (1934)
    - target ports/services: VNC (5900-5915), MS Terminal Server (non-standard ports)
    - paths/endpoints: Not explicitly identified, general scanning.
    - payload/artifact excerpts: Not available, but alerts indicate VNC server responses and RDP traffic.
    - staging indicators: Not available.
    - temporal checks results: Unavailable.

- **Botnet/Campaign Infrastructure Mapping: SMB Attack Campaign**
    - source IPs with counts: Top IPs from Indonesia, India.
    - ASNs with counts: PT. Telekomunikasi Selular (Indonesia), ASNs associated with India.
    - target ports/services: SMB (port 445)
    - paths/endpoints: Not explicitly identified, general SMB attacks.
    - payload/artifact excerpts: Not available.
    - staging indicators: Not available.
    - temporal checks results: Unavailable.

# Indicators of Interest
- **IPs:** 182.8.193.5, 144.202.106.26, 107.170.66.78, 103.146.204.12
- **CVEs:** CVE-2025-55182, CVE-2006-3602, CVE-2006-4458, CVE-2006-4542, CVE-2024-38816
- **Paths/Endpoints (Tanner):** /, /.env, /actuator/gateway/routes
- **Adbhoney Input:** `echo "$(getprop ro.product.name 2>/dev/null) $(whoami 2>/dev/null)"`
- **Conpot Protocols:** IEC104, guardian_ast, kamstrup_protocol

# Backend Tool Issues
None.
