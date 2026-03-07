Investigation Scope
- investigation_start: 2026-03-06T21:00:08Z
- investigation_end: 2026-03-07T00:00:08Z
- completion_status: Complete
- degraded_mode: false

Executive Triage Summary
- Top services/ports of interest: VNC (5901-5905), SMB (445), HTTP (80), SSH (22), Kamstrup protocol, Guardian AST.
- Top confirmed known exploitation: "GPL INFO VNC server response" (17805 events), "ET INFO CURL User Agent" (778 events), "ET SCAN MS Terminal Server Traffic on Non-standard Port" (586 events).
- Top unmapped exploit-like items: Potential CVE-2025-55182 activity, several requests for common sensitive files like `.env` and `*.auto.tfvars`.
- Botnet/campaign mapping highlights: High volume of attacks from DigitalOcean and ADISTA SAS. Significant VNC scanning activity originating from the United States. SMB scanning from France and Mexico.
- Major uncertainties: None.

Candidate Discovery Summary
- Total attack events: 20855
- Top countries: United States (5208), France (3739), Seychelles (1681), Mexico (1678), United Kingdom (1069)
- Top attacker source IPs: 79.98.102.166 (2573), 45.87.249.170 (1630), 189.231.160.65 (1513)
- Top attacker ASNs: DigitalOcean, LLC (3987), ADISTA SAS (2573), Google LLC (1710)
- Top alert categories: Misc activity (18604), Generic Protocol Command Decode (3238), Attempted Information Leak (1552)
- Top Suricata signatures: GPL INFO VNC server response (17805), SURICATA IPv4 truncated packet (973)
- Top CVEs: CVE-2025-55182 (101), CVE-2024-14007 (8)
- Top honeypot usernames: root (390), 345gs5662d34 (65)
- Top honeypot passwords: 123456 (92), 3245gs5662d34 (65)
- Top P0f OS distribution: Windows NT kernel (52158), Linux 2.2.x-3.x (43624)
- Redis actions: Closed (8), NewConnect (8), info (5)
- Conpot protocols: kamstrup_protocol (24), guardian_ast (5)
- Tanner requested paths: / (27), /.env (4)

Emerging n-day Exploitation
- cve/signature mapping: CVE-2025-55182 (101 events)
- evidence summary: 101 events mapped to CVE-2025-55182, seen across various source IPs. Specific exploit details are not available from the tool output, but the count indicates active scanning or exploitation attempts.
- affected service/port: Not explicitly detailed, but usually web services.
- confidence: Medium (based on explicit CVE mapping and event count).
- operational notes: Monitor for specific payloads or further indicators related to CVE-2025-55182.

Novel or Zero-Day Exploit Candidates (UNMAPPED ONLY, ranked)
- No strong candidates for novel or zero-day exploits identified. Most exploit-like behavior is mapped to existing CVEs or known scanning patterns.

Botnet/Campaign Infrastructure Mapping
- item_id: DigitalOcean_AS14061_Campaign
- campaign_shape: Spray (high count from multiple IPs within the ASN)
- suspected_compromised_src_ips: Top examples include IPs from ASN 14061 (DigitalOcean, LLC) with 3987 events.
- ASNs / geo hints: AS14061 (DigitalOcean, LLC), primarily US-based.
- suspected_staging indicators: Not directly observed in the provided tools.
- suspected_c2 indicators: Not directly observed in the provided tools.
- confidence: High (based on consistent ASN and high event volume).
- operational notes: Block/monitor traffic from AS14061 for VNC/SMB scanning.

- item_id: ADISTA_AS16347_Campaign
- campaign_shape: Spray
- suspected_compromised_src_ips: Top example 79.98.102.166 from AS16347 (ADISTA SAS) with 2573 events.
- ASNs / geo hints: AS16347 (ADISTA SAS), primarily France-based.
- suspected_staging indicators: Not directly observed.
- suspected_c2 indicators: Not directly observed.
- confidence: High (consistent ASN and high event volume).
- operational notes: Block/monitor traffic from AS16347 for SMB scanning.

Odd-Service / Minutia Attacks
- service_fingerprint: VNC (ports 5901, 5902, 5903, 5904, 5905)
- why it’s unusual/interesting: High volume of VNC server response alerts and MS Terminal Server traffic on non-standard ports indicates active scanning for remote access services, possibly for vulnerable systems.
- evidence summary: "GPL INFO VNC server response" (17805 events), "ET SCAN MS Terminal Server Traffic on Non-standard Port" (586 events). Top target ports from the US include 5902, 5901, 5903, 5904, 5905.
- confidence: High.
- recommended monitoring pivots: Monitor VNC and RDP ports for unusual traffic patterns, especially from external IPs.

- service_fingerprint: Kamstrup Protocol (Conpot)
- why it’s unusual/interesting: Interaction with ICS/SCADA honeypot using specific industrial protocols. This indicates targeted reconnaissance or attacks against industrial control systems.
- evidence summary: 24 events for 'kamstrup_protocol' and 5 for 'guardian_ast' captured by Conpot honeypot.
- confidence: Medium.
- recommended monitoring pivots: Monitor ICS/SCADA systems for similar protocol interactions.

Known-Exploit / Commodity Exclusions
- **VNC/RDP Scanning:** "GPL INFO VNC server response" (17805 events) and "ET SCAN MS Terminal Server Traffic on Non-standard Port" (586 events) are common scanning activities.
- **SMB Scanning:** High volume of traffic to port 445 from France and Mexico (2573 and 1513 events respectively) indicating typical SMB scanning for vulnerabilities.
- **Credential Stuffing:** Common usernames like 'root' and passwords like '123456' indicate automated brute-force or credential stuffing attacks.
- **Generic Reconnaissance:** "ET INFO CURL User Agent" (778 events) and basic path requests like "/" and "/favicon.ico" are common reconnaissance or bot activity.
- **Miscellaneous Activity:** "Misc activity" (18604 events) and "Generic Protocol Command Decode" (3238 events) represent broad, often commodity, network noise.

Infrastructure & Behavioral Classification
- **Exploitation vs Scanning:** Predominantly scanning activity (VNC, SMB, credential stuffing) with some confirmed n-day exploitation attempts (CVE-2025-55182).
- **Campaign Shape:** Mostly "spray" patterns observed with wide distribution across source IPs and ASNs for scanning activities.
- **Infra Reuse Indicators:** DigitalOcean and ADISTA ASNs are frequently observed, suggesting the use of cloud infrastructure for attacks.
- **Odd-Service Fingerprints:** VNC on non-standard ports, and ICS/SCADA protocols (Kamstrup, Guardian AST) are notable odd-service fingerprints.

Evidence Appendix
- **Emerging n-day Exploitation (CVE-2025-55182):**
    - Source IPs with counts: Not directly available from the `get_cve` tool, but spread across various IPs based on overall attack counts.
    - ASNs with counts: Not directly available for this specific CVE, but likely from the top attacking ASNs.
    - Target ports/services: Not explicitly detailed.
    - Paths/endpoints: Not explicitly detailed.
    - Payload/artifact excerpts: Missing.
    - Staging indicators: Missing.
    - Temporal checks results: Unavailable.

- **Botnet/Campaign Infrastructure Mapping (DigitalOcean_AS14061_Campaign):**
    - Source IPs with counts: IPs within AS14061, total 3987 events.
    - ASNs with counts: AS14061 (DigitalOcean, LLC) - 3987 events.
    - Target ports/services: Varied, but contribute to VNC scanning.
    - Paths/endpoints: Not directly available for the entire ASN.
    - Payload/artifact excerpts: Missing.
    - Staging indicators: Missing.
    - Temporal checks results: Unavailable.

- **Botnet/Campaign Infrastructure Mapping (ADISTA_AS16347_Campaign):**
    - Source IPs with counts: 79.98.102.166 (2573 events), part of AS16347.
    - ASNs with counts: AS16347 (ADISTA SAS) - 2573 events.
    - Target ports/services: Primarily 445 (SMB) from 79.98.102.166.
    - Paths/endpoints: Not directly available for the entire ASN.
    - Payload/artifact excerpts: Missing.
    - Staging indicators: Missing.
    - Temporal checks results: Unavailable.

Indicators of Interest
- **IPs:**
    - 79.98.102.166 (SMB scanning, France)
    - 45.87.249.170
    - 189.231.160.65
    - 136.114.97.84
    - 165.22.112.196
- **ASNs:**
    - AS14061 (DigitalOcean, LLC)
    - AS16347 (ADISTA SAS)
- **CVEs:**
    - CVE-2025-55182
- **Paths/Payload Fragments:**
    - `/.env` (Tanner honeypot)
    - `/*.auto.tfvars` (Tanner honeypot)
    - Conpot protocol data: `b'0018080404030807080508060401050106010503060302010203002b0009080304030303020301003300260024001d0020ad39c5759def71f32600e3cf670a6399b976ba9a91f94b14846658583c'`
    - Conpot protocol data: `b'\x01I20100'`

Backend Tool Issues
- No tool failures observed.
