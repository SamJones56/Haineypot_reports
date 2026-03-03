# Honeypot Threat Hunt Report

## 1) Investigation Scope
- investigation_start: 2026-02-28T14:58:58Z
- investigation_end: 2026-02-28T15:58:58Z
- completion_status: Complete
- degraded_mode: false

## 2) Executive Triage Summary
- High volume of commodity scanning activity observed, primarily targeting VNC, SOCKS, SSH, and RDP services.
- Top services of interest include VNC (ports 5925, 5926), SOCKS (port 1080), and HTTP web paths (e.g., `/.env` reconnaissance). Redis (port 6379) also showed connection activity.
- Confirmed known exploitation attempts related to CVE-2020-2551, CVE-2024-14007, CVE-2019-11500, and CVE-2021-3449, though counts were low.
- No novel exploit candidates or potential zero-day activity were identified or validated in this window.
- Significant scanning infrastructure originating from DigitalOcean, Unmanaged Ltd, Beijing 3389 Network Technology, and Akamai Connected Cloud ASNs, particularly from the United States and China.
- Common credential stuffing attempts using "admin", "root" with passwords "123456", "123".

## 3) Candidate Discovery Summary
- Total attacks observed: 3791.
- No high-signal novel exploit candidates were discovered or added to the validation queue.
- No deep investigation leads were triggered.
- OSINT validation was inconclusive due to the absence of candidates.

## 4) Emerging n-day Exploitation
- **CVE-2020-2551**: 2 instances observed. Likely exploitation attempts against Oracle WebLogic Server.
- **CVE-2024-14007**: 2 instances observed. Mapping suggests potential vulnerabilities in specific software versions.
- **CVE-2019-11500**: 1 instance observed. Related to Pulse Connect Secure.
- **CVE-2021-3449**: 1 instance observed. Related to OpenSSL vulnerability.
- **GPL INFO VNC server response**: 1654 instances. Evidence of active VNC port scanning. Affected service/port: VNC (various ports, including 5925, 5926). Confidence: High. Operational notes: Widespread VNC scanning, potentially enumeration for vulnerable servers.
- **GPL INFO SOCKS Proxy attempt**: 355 instances. Evidence of SOCKS proxy enumeration or brute force. Affected service/port: SOCKS (port 1080). Confidence: High. Operational notes: Commodity scanning for open SOCKS proxies.
- **SURICATA SSH invalid banner**: 351 instances. Indicates SSH connection attempts with malformed or unexpected banners, often associated with scanning tools. Affected service/port: SSH (port 22). Confidence: High. Operational notes: Commodity SSH scanning.
- **ET INFO SSH session in progress on Unusual Port**: 137 instances. SSH activity on non-standard ports. Affected service/port: SSH (various non-standard ports). Confidence: High. Operational notes: SSH enumeration/brute force on atypical ports.
- **ET SCAN MS Terminal Server Traffic on Non-standard Port**: 115 instances. RDP scanning activity on non-standard ports. Affected service/port: RDP (various non-standard ports). Confidence: High. Operational notes: Commodity RDP scanning.

## 5) Novel Exploit Candidates (UNMAPPED ONLY, ranked)
No novel exploit candidates were identified or validated in this investigation window.

## 6) Botnet/Campaign Infrastructure Mapping
- **Item_id: Infra-001 - Broad Scanning Campaign**
    - campaign_shape: Spray/Widespread Scanning
    - suspected_compromised_src_ips:
        - 103.189.141.153 (354 counts)
        - 129.212.188.196 (252 counts)
        - 129.212.179.18 (249 counts)
        - 129.212.184.194 (110 counts)
        - 170.64.152.136 (105 counts)
    - ASNs / geo hints:
        - DigitalOcean, LLC (ASN 14061) - 1052 total counts (US)
        - Unmanaged Ltd (ASN 47890) - 571 total counts (US)
        - Beijing 3389 Network Technology Co., Ltd. (ASN 136146) - 354 total counts (China)
        - Akamai Connected Cloud (ASN 63949) - 283 total counts (US)
    - suspected_staging indicators: None directly observed; cloud provider ASNs (DigitalOcean, Akamai) are frequently used for staging/C2.
    - suspected_c2 indicators: None directly observed.
    - confidence: High (for widespread scanning, moderate for specific campaign attribution).
    - operational notes: Block identified scanning IPs and monitor for follow-on activity from these ASNs.

## 7) Odd-Service / Minutia Attacks
- **service_fingerprint: Redis (Port 6379)**
    - why it’s unusual/interesting: Redis is a common target for unauthenticated access or known vulnerabilities. Activity included 'NewConnect', 'Closed', and 'info' commands, suggesting enumeration.
    - evidence summary: 9 total hits, including 3 'NewConnect', 3 'Closed', and 2 'info' actions. One specific connection from 'MGLNDD_167.71.255.16_6379'.
    - confidence: Moderate (basic enumeration observed).
    - recommended monitoring pivots: Monitor for authentication bypass attempts, specific Redis commands related to data exfiltration or RCE (e.g., `SLAVEOF`, `CONFIG SET`).

- **service_fingerprint: HTTP Web Application Reconnaissance (Ports 80/443)**
    - why it’s unusual/interesting: Requests for `/.env` and `/.env.test` indicate targeted reconnaissance for exposed environment configuration files, which can lead to sensitive information disclosure.
    - evidence summary: 11 total hits on Tanner honeypot, including 6 requests for `/`, 2 for `/.env`, 1 for `/.env.test`, 1 for `/favicon.ico`, and 1 for `/robots.txt`.
    - confidence: High.
    - recommended monitoring pivots: Scan web assets for exposed .env files, block IPs attempting to access such paths.

## 8) Known-Exploit / Commodity Exclusions
- **Credential Noise/Brute Force**:
    - Top usernames: `admin` (69), `root` (23), `ubuntu` (15).
    - Top passwords: `123456` (9), `123` (8), `1234` (7).
    - Evidence: Found across numerous login attempts, typical of commodity credential stuffing campaigns.
- **Common Scanning Activity**:
    - **VNC Scanning**: Signature "GPL INFO VNC server response" (1654 counts), targeting ports like 5925, 5926.
    - **SOCKS Scanning**: Signature "GPL INFO SOCKS Proxy attempt" (355 counts), primarily on port 1080.
    - **SSH Scanning**: Signatures "SURICATA SSH invalid banner" (351 counts), "ET INFO SSH session in progress on Unusual Port" (137 counts), "ET INFO SSH session in progress on Expected Port" (56 counts).
    - **RDP Scanning**: "ET SCAN MS Terminal Server Traffic on Non-standard Port" (115 counts).
    - **General Scans**: Alerts like "Potentially Bad Traffic" (7 counts), "Detection of a Network Scan" (6 counts).
    - **Malformed Traffic**: Signatures like "SURICATA IPv4 truncated packet" (244 counts), "SURICATA AF-PACKET truncated packet" (244 counts), "SURICATA STREAM reassembly sequence GAP" (104 counts) indicative of scanning tools or network anomalies.
- **Common Attack Categories**: "Misc activity" (1893 counts), "Generic Protocol Command Decode" (1051 counts), "Attempted Information Leak" (530 counts) are broad categories encompassing typical commodity scanning and reconnaissance.

## 9) Infrastructure & Behavioral Classification
- **Exploitation vs. Scanning**: Predominantly scanning and reconnaissance activities (VNC, SOCKS, SSH, RDP, web path enumeration). A few low-count CVE-mapped exploitation attempts were observed but not validated further in this workflow.
- **Campaign Shape**: Wide-spread "spray" scanning originating from multiple cloud providers and geographic regions, indicating commodity botnet or large-scale attack infrastructure.
- **Infra Reuse Indicators**: Top source IPs and ASNs show consistent, high-volume activity typical of persistent scanning infrastructure. DigitalOcean and Akamai ASNs are frequently associated with such activity.
- **Odd-Service Fingerprints**: Redis port 6379 enumeration, ADBHoney connection attempts, and web application reconnaissance for sensitive files (e.g., `/.env`) suggest attackers are also probing less common or specific web service configurations.

## 10) Evidence Appendix
### Emerging n-day Exploitation
- **CVE-2020-2551**
    - Source IPs with counts: Not directly available from current context (only total CVE counts).
    - ASNs with counts: Not directly available.
    - Target ports/services: Oracle WebLogic (default ports often 7001, 7002, 7003, etc.).
    - Payload/artifact excerpts: Not directly available.
    - Temporal checks results: Observed within the current 60-minute window.
- **CVE-2024-14007**
    - Source IPs with counts: Not directly available.
    - ASNs with counts: Not directly available.
    - Target ports/services: Specific to mapped vulnerability (not in provided data).
    - Payload/artifact excerpts: Not directly available.
    - Temporal checks results: Observed within the current 60-minute window.
- **GPL INFO VNC server response**
    - Source IPs with counts: Not directly available, but associated with IPs from US (252 on 5926, 249 on 5925) and other countries.
    - ASNs with counts: Associated with broad scanning ASNs.
    - Target ports/services: VNC (5925, 5926 and others).
    - Payload/artifact excerpts: VNC server response banners.
    - Temporal checks results: Observed within the current 60-minute window.
### Botnet/Campaign Infrastructure Mapping (Top 5 IPs)
- **103.189.141.153** (354 counts)
    - ASNs: Beijing 3389 Network Technology Co., Ltd. (ASN 136146)
    - Target ports/services: Implied SOCKS (1080, China) and other common ports.
    - Paths/endpoints: Not directly available for this IP.
    - Staging indicators: None.
    - Temporal checks results: Observed within the current 60-minute window.
- **129.212.188.196** (252 counts)
    - ASNs: Unmanaged Ltd (ASN 47890)
    - Target ports/services: VNC (5926) for United States
    - Paths/endpoints: Not directly available.
    - Staging indicators: None.
    - Temporal checks results: Observed within the current 60-minute window.
- **129.212.179.18** (249 counts)
    - ASNs: Unmanaged Ltd (ASN 47890)
    - Target ports/services: VNC (5925) for United States
    - Paths/endpoints: Not directly available.
    - Staging indicators: None.
    - Temporal checks results: Observed within the current 60-minute window.
- **129.212.184.194** (110 counts)
    - ASNs: DigitalOcean, LLC (ASN 14061)
    - Target ports/services: Not directly specified for this IP, but part of DigitalOcean activity.
    - Paths/endpoints: Not directly available.
    - Staging indicators: None.
    - Temporal checks results: Observed within the current 60-minute window.
- **170.64.152.136** (105 counts)
    - ASNs: Akamai Connected Cloud (ASN 63949)
    - Target ports/services: Not directly specified for this IP, but part of Akamai activity.
    - Paths/endpoints: Not directly available.
    - Staging indicators: None.
    - Temporal checks results: Observed within the current 60-minute window.

## 11) Indicators of Interest
- **Source IPs**:
    - 103.189.141.153
    - 129.212.188.196
    - 129.212.179.18
    - 129.212.184.194
    - 170.64.152.136
- **Targeted Ports/Services**:
    - VNC (5925, 5926)
    - SOCKS (1080)
    - SSH (22, non-standard ports)
    - RDP (non-standard ports)
    - Redis (6379)
- **Web Paths**:
    - `/.env`
    - `/.env.test`
- **CVEs**:
    - CVE-2020-2551
    - CVE-2024-14007
    - CVE-2019-11500
    - CVE-2021-3449
- **Alert Signatures**:
    - GPL INFO VNC server response (signature_id: 2100560)
    - GPL INFO SOCKS Proxy attempt (signature_id: 2100615)
    - SURICATA SSH invalid banner (signature_id: 2228000)
    - ET INFO SSH session in progress on Unusual Port (signature_id: 2001984)
    - ET SCAN MS Terminal Server Traffic on Non-standard Port (signature_id: 2023753)

## 12) Backend Tool Issues
- No explicit tool failures were reported in the workflow state.
- The `CandidateDiscoveryAgent` did not identify any candidates for validation, which resulted in `CandidateValidationLoopAgent` and `OSINTAgent` having no items to process. This is not a tool failure, but an absence of high-signal unmapped activity.

## 13) Agent Action Summary (Audit Trail)

- **agent_name**: ParallelInvestigationAgent
    - **purpose**: Orchestrates parallel execution of baseline, known signal, credential noise, and honeypot-specific investigations.
    - **inputs_used**: `investigation_start`, `investigation_end`.
    - **actions_taken**: Launched sub-agents (BaselineAgent, KnownSignalAgent, CredentialNoiseAgent, HoneypotSpecificAgent) to gather initial telemetry.
    - **key_results**: Collected baseline attack statistics, known security alerts, credential noise data, and honeypot interaction logs.
    - **errors_or_gaps**: None.

- **agent_name**: BaselineAgent
    - **purpose**: Gathers fundamental statistics and attacker infrastructure details.
    - **inputs_used**: `gte_time_stamp`, `lte_time_stamp`.
    - **actions_taken**: Called `get_current_time`, `get_total_attacks`, `get_top_countries`, `get_attacker_src_ip`, `get_country_to_port`, `get_attacker_asn`.
    - **key_results**: Total 3791 attacks, top countries (US, China, Romania), top attacker IPs (e.g., 103.189.141.153), country-to-port mapping (e.g., US -> 5926, 5925), top ASNs (e.g., DigitalOcean).
    - **errors_or_gaps**: None.

- **agent_name**: KnownSignalAgent
    - **purpose**: Identifies activity matching known signatures and CVEs.
    - **inputs_used**: `gte_time_stamp`, `lte_time_stamp`.
    - **actions_taken**: Called `get_current_time`, `get_alert_signature`, `get_cve`, `get_alert_category`.
    - **key_results**: Identified 10 top alert signatures (e.g., "GPL INFO VNC server response" with 1654 counts), detected CVEs (e.g., CVE-2020-2551), and classified alert categories (e.g., "Misc activity" with 1893 counts).
    - **errors_or_gaps**: None.

- **agent_name**: CredentialNoiseAgent
    - **purpose**: Detects common credential stuffing and brute force attempts.
    - **inputs_used**: `gte_time_stamp`, `lte_time_stamp`.
    - **actions_taken**: Called `get_current_time`, `get_input_usernames`, `get_input_passwords`, `get_p0f_os_distribution`.
    - **key_results**: Top usernames (`admin`, `root`), top passwords (`123456`, `123`), and OS distribution of attackers (e.g., Windows NT kernel).
    - **errors_or_gaps**: None.

- **agent_name**: HoneypotSpecificAgent
    - **purpose**: Gathers specific telemetry from various honeypots.
    - **inputs_used**: `gte_time_stamp`, `lte_time_stamp`.
    - **actions_taken**: Called `get_current_time`, `redis_duration_and_bytes`, `adbhoney_input`, `adbhoney_malware_samples`, `conpot_input`, `tanner_unifrom_resource_search`, `conpot_protocol`.
    - **key_results**: Redis: 9 hits (connect/close/info). ADBHoney: 8 hits, no specific inputs/malware. Conpot: 0 hits. Tanner: 11 hits (web path reconnaissance for `/.env`, `/.env.test`).
    - **errors_or_gaps**: None.

- **agent_name**: CandidateDiscoveryAgent
    - **purpose**: Identifies novel exploit candidates by filtering known activity and detecting unmapped anomalies.
    - **inputs_used**: Baseline, Known Signals, Credential Noise, Honeypot Specific results.
    - **actions_taken**: Analyzed collected data for unmapped exploit-like behavior.
    - **key_results**: No novel candidates were identified for validation.
    - **errors_or_gaps**: No candidates found; therefore, the subsequent validation loop was empty.

- **agent_name**: CandidateValidationLoopAgent
    - **purpose**: Validates discovered candidates through various checks (knownness, temporal, infrastructure).
    - **inputs_used**: Candidates queue (from CandidateDiscoveryAgent).
    - **actions_taken**: (Managed by CandidateLoopControllerAgent) Attempted to load candidates.
    - **key_results**: 0 iterations run, 0 candidates validated. Loop exited due to an empty candidate queue.
    - **errors_or_gaps**: No candidates were provided for validation.

- **agent_name**: DeepInvestigationLoopController
    - **purpose**: Manages detailed investigations into high-priority candidates, including malware analysis and C2 tracking.
    - **inputs_used**: Promoted candidates (from CandidateValidationLoopAgent).
    - **actions_taken**: No candidates were promoted for deep investigation.
    - **key_results**: 0 iterations run, no key leads pursued. Loop stalled/exited due to absence of candidates for deep investigation.
    - **errors_or_gaps**: No candidates were provided for deep investigation.

- **agent_name**: OSINTAgent
    - **purpose**: Performs OSINT lookups to enrich candidate information and confirm knownness/novelty.
    - **inputs_used**: Validated candidates.
    - **actions_taken**: Attempted to process candidates for OSINT.
    - **key_results**: OSINT validation was inconclusive as no candidates were provided.
    - **errors_or_gaps**: No candidates were provided for OSINT investigation.

- **agent_name**: ReportAgent
    - **purpose**: Compiles the final report from all collected workflow state outputs.
    - **inputs_used**: `investigation_start`, `investigation_end`, `baseline_result`, `known_signals_result`, `credential_noise_result`, `honeypot_specific_result`, `candidate_discovery_result` (implicit empty), `validated_candidates` (empty), `osint_validation_result` (inconclusive), `investigation_log` (context messages).
    - **actions_taken**: Compiled report content as per specified format, summarizing findings from all preceding agents.
    - **key_results**: Generated comprehensive report detailing commodity activity, known exploitation, infrastructure mapping, and absence of novel candidates.
    - **errors_or_gaps**: None.

- **agent_name**: SaveReportAgent
    - **purpose**: Saves the generated report to persistent storage.
    - **inputs_used**: Final markdown report content.
    - **actions_taken**: Will call `investigation_write_file` (downstream tool call).
    - **key_results**: (Status not yet available in current context)
    - **errors_or_gaps**: (Not applicable at this stage).