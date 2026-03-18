## Threat Hunting Report: Honeypot Activity Analysis

### 1) Investigation Scope
- **investigation_start**: 2026-03-06T06:00:04Z
- **investigation_end**: 2026-03-06T09:00:04Z
- **completion_status**: Inconclusive (validation blocked)
- **degraded_mode**: true (Multiple query tools failed to retrieve detailed event data, and the candidate validation loop failed to process any actual candidates.)

### 2) Executive Triage Summary
- Total attacks observed: 21,223 events over 3 hours.
- Top services/ports of interest include high-volume scanning of VNC (ports 5901-5905), SMB (port 445), and SSH (port 22).
- Detected exploitation attempts for CVE-2025-55182 (102 counts).
- Honeypot-specific interactions observed: Conpot honeypot recorded specific ICS/SCADA commands via `guardian_ast` protocol. Tanner web honeypot captured probes for sensitive paths like `/.env` and `/druid/index.html`. Redis honeypot showed unusual protocol mismatches (HTTP/SSH strings) and binary data.
- High volume of commodity brute-force activity against common usernames (`root`, `admin`) and passwords (`123456`, `password`).
- Significant infrastructure mapping opportunities identified for VNC and SMB scanning campaigns, largely originating from DigitalOcean and other cloud/hosting providers.
- Major uncertainties: Detailed event data for several promising candidates (e.g., Tanner probes, Redis anomalies) could not be retrieved due to backend query failures. More critically, the candidate validation loop failed to process any of the discovered candidates, leading to an inconclusive validation phase.

### 3) Candidate Discovery Summary
Discovery identified 8 initial candidates across various categories.
- **Total Attacks**: 21,223
- **Top Attacking Countries**: United States (8731), Myanmar (2820), Ukraine (2357).
- **Top Attacker ASNs**: DigitalOcean, LLC (7168), Global Technology (1602), Myanma Posts and Telecommunications (1218).
- **High-Volume Activities**:
    - VNC scanning: 16,107 alerts (`GPL INFO VNC server response`) across ports 5901-5905.
    - SMB activity: 4,346 counts on port 445.
    - SSH activity: 1,213 counts on port 22, including `ET INFO SSH session in progress` (157) and `SURICATA SSH invalid banner` (140).
- **CVE-Mapped Activity**: 102 alerts for `CVE-2025-55182`.
- **Honeypot-Specific Detections**:
    - Conpot: 12 interactions using `guardian_ast` protocol, with specific binary inputs (`b'\\x01I20100'`).
    - Tanner: 51 URI probes for `/.env`, 10 for `/druid/index.html`.
    - Redis: 62 actions, including protocol mismatches (`GET / HTTP/1.1`, `SSH-2.0-Go`) and a binary sequence (`\x15\x03\x01\x00\x02\x02\x16`).
- **Odd Ports**: Low volume probes observed on ports 8880, 2363, 1404 (from Canada).
- **Discovery Errors/Gaps**: Multiple `kibanna_discover_query` and `match_query` tools consistently failed with `illegal_argument_exception` errors, preventing detailed event retrieval for `.env` and `/druid/index.html` probes and Redis activity. The `two_level_terms_aggregated` tool also returned empty buckets for detailed SMB source IP mapping.

### 4) Emerging n-day Exploitation
- **item_id**: CVE-2025-55182-Exploit
    - **cve/signature mapping**: CVE-2025-55182
    - **evidence summary**: 102 counts of alerts explicitly mapped to CVE-2025-55182.
    - **affected service/port**: Not specified in available data, but likely a widely accessible service.
    - **confidence**: High
    - **operational notes**: Monitor for full exploit chains and affected services.

### 5) Novel or Zero-Day Exploit Candidates (UNMAPPED ONLY, ranked)
None identified after initial mapping to known signatures/CVEs or classification as commodity.

### 6) Botnet/Campaign Infrastructure Mapping
- **item_id**: VNC-Scan-Campaign
    - **campaign_shape**: spray (widespread scanning)
    - **suspected_compromised_src_ips**: 143.198.239.107 (1566), 129.212.183.98 (1544), 67.207.84.204 (298), 129.212.184.194 (216), 162.243.248.118 (134), 38.59.228.93 (102), 185.184.123.50 (92), 162.248.103.32 (82), 91.228.198.8 (80)
    - **ASNs / geo hints**: DigitalOcean, LLC, Global Technology, Modat B.V., Langate Ltd. Predominantly United States based, but also includes other regions.
    - **suspected_staging indicators**: None directly observed.
    - **suspected_c2 indicators**: None directly observed.
    - **confidence**: High
    - **operational notes**: This appears to be a large-scale VNC reconnaissance/brute-force campaign. Focus on blocking top source IPs and monitoring for post-exploitation attempts on VNC ports.
- **item_id**: SMB-BruteForce-Campaign
    - **campaign_shape**: spray (widespread scanning)
    - **suspected_compromised_src_ips**: 103.101.16.234 (1602), 203.81.87.70 (1218), 176.120.59.98 (998), 45.122.123.84 (389)
    - **ASNs / geo hints**: Global Technology, Myanma Posts and Telecommunications, Modat B.V., Langate Ltd. Top countries Myanmar (2820 counts), Ukraine (998 counts), India (389 counts) all targeting port 445.
    - **suspected_staging indicators**: None directly observed.
    - **suspected_c2 indicators**: None directly observed.
    - **confidence**: High
    - **operational notes**: Persistent SMB brute-force from multiple global sources. Investigate specific SMB commands if raw honeypot logs permit for potential commodity malware delivery or unusual activity patterns.
- **item_id**: DigitalOcean-Web-Reconnaissance
    - **campaign_shape**: fan-out (single source probing multiple web paths)
    - **suspected_compromised_src_ips**: 167.71.255.16
    - **ASNs / geo hints**: 14061 (DigitalOcean, LLC), United States
    - **suspected_staging indicators**: Probes for `/.env` and `/etc/passwd` suggest reconnaissance for misconfigurations or path traversal vulnerabilities.
    - **suspected_c2 indicators**: None directly observed.
    - **confidence**: High
    - **operational notes**: This IP is actively probing for sensitive web files. Block this IP and monitor for further exploitation attempts or a shift in targets/methods.

### 7) Odd-Service / Minutia Attacks
- **item_id**: Conpot-ICS-Protocol-Interaction
    - **service_fingerprint**: Conpot honeypot, `guardian_ast` protocol, port unspecified.
    - **why it’s unusual/interesting**: Interactions with ICS/SCADA protocols are highly specific and less common than general internet scanning. Binary inputs suggest deliberate protocol interaction rather than blind scanning.
    - **evidence summary**: 12 total interactions, including specific binary inputs `b'\\x01I20100'` and `b'\\x01I20100\\n'`.
    - **confidence**: Medium
    - **recommended monitoring pivots**: Monitor Conpot honeypots for any increase in `guardian_ast` protocol activity or new specific commands. Investigate source IPs for ICS/OT-specific threat intelligence.
- **item_id**: Uncommon-Ports-Canada
    - **service_fingerprint**: Ports 8880, 2363, 1404
    - **why it’s unusual/interesting**: These are not commonly scanned ports or well-known services, suggesting either targeted activity or less common botnet/scanner configurations.
    - **evidence summary**: 5 hits on port 8880, 3 on 2363, 2 on 1404, originating from Canada.
    - **confidence**: Low (due to low volume)
    - **recommended monitoring pivots**: Monitor these specific ports and source IPs from Canada for increased activity or different attack patterns.

### 8) Known-Exploit / Commodity Exclusions
- **VNC-Commodity-Scan**: High volume of VNC server responses (16,107 counts for `GPL INFO VNC server response`) across ports 5901-5905. Typical commodity scanning activity.
- **SMB-Commodity-Scan**: Persistent, high-volume activity on port 445 (4,346 total counts) from various countries, indicative of commodity SMB scanning or brute-force.
- **SSH-Commodity-Scan**: General SSH scanning and invalid banner alerts (157 counts for `ET INFO SSH session in progress`, 140 for `SURICATA SSH invalid banner`). Consistent with commodity SSH brute-force.
- **Druid-Zgrab-Scan**: Scans for `/druid/index.html` (10 counts) using a `Mozilla/5.0 zgrab/0.x` user agent, correlating with the `ET SCAN Zmap User-Agent (Inbound)` Suricata signature. Known scanning tool.
- **Path-Traversal-Known**: Attempts to access `etc/passwd` (21 counts) explicitly identified by the `ET WEB_SERVER /etc/passwd Detected in URI` Suricata signature. This is a common web vulnerability probe.

### 9) Infrastructure & Behavioral Classification
- **VNC & SMB Activity**: Predominantly mass scanning and brute-force, exhibiting a "spray" campaign shape across many source IPs and ASNs, often from cloud hosting providers.
- **SSH Activity**: Standard brute-force and reconnaissance, similar to VNC and SMB in its widespread, commodity nature.
- **Web Reconnaissance (DigitalOcean)**: Targeted probing for sensitive web paths (`/.env`, `/etc/passwd`) from specific DigitalOcean infrastructure, showing a "fan-out" pattern from a single source seeking multiple vulnerabilities.
- **Conpot ICS Interactions**: Appears to be highly specific protocol interaction, suggesting potential interest in industrial control systems, likely targeted rather than commodity. Campaign shape currently "unknown" due to limited volume.
- **Uncommon Port Scans**: Low-volume probes on non-standard ports, suggesting opportunistic scanning or highly specialized tooling. Campaign shape currently "unknown".
- **Infra Reuse Indicators**: High prevalence of cloud provider ASNs (e.g., DigitalOcean) for various scanning activities, indicating readily available, low-cost infrastructure for attackers.

### 10) Evidence Appendix
- **CVE-2025-55182-Exploit**
    - **Source IPs**: Not available (detailed event retrieval failed).
    - **ASNs**: Not available.
    - **Target ports/services**: Not available.
    - **Paths/endpoints**: Not available.
    - **Payload/artifact excerpts**: "102 counts of alerts for CVE-2025-55182"
    - **Staging indicators**: None available.
    - **Temporal checks results**: Unavailable.
- **VNC-Scan-Campaign**
    - **Source IPs**: 143.198.239.107 (1566), 129.212.183.98 (1544), 129.212.183.117 (402), 67.207.84.204 (298), 129.212.184.194 (216), 162.243.248.118 (134), 38.59.228.93 (102), 185.184.123.50 (92), 162.248.103.32 (82), 91.228.198.8 (80)
    - **ASNs**: 14061 (DigitalOcean, LLC), 136975 (Global Technology), 209334 (Modat B.V.), 58309 (Langate Ltd)
    - **Target ports/services**: 5902 (456), 5903 (283), 5901 (279), 5904 (277), 5905 (243)
    - **Paths/endpoints**: N/A (VNC protocol)
    - **Payload/artifact excerpts**: Alerts for "GPL INFO VNC server response" (16107 counts)
    - **Staging indicators**: None observed.
    - **Temporal checks results**: Unavailable.
- **SMB-BruteForce-Campaign**
    - **Source IPs**: 103.101.16.234 (1602), 203.81.87.70 (1218), 176.120.59.98 (998), 45.122.123.84 (389)
    - **ASNs**: 136975 (Global Technology), 9988 (Myanma Posts and Telecommunications), 58309 (Langate Ltd)
    - **Target ports/services**: 445 (4346 total counts)
    - **Paths/endpoints**: N/A (SMB protocol)
    - **Payload/artifact excerpts**: High volume SMB traffic. Binary sequence `\x15\x03\x01\x00\x02\x02\x16` was observed in SMB traffic, but its specific meaning/context within this campaign is unclear.
    - **Staging indicators**: None observed.
    - **Temporal checks results**: Unavailable.
- **DigitalOcean-Web-Reconnaissance**
    - **Source IPs**: 167.71.255.16
    - **ASNs**: 14061 (DigitalOcean, LLC)
    - **Target ports/services**: 80 (HTTP)
    - **Paths/endpoints**: `/.env` (6 counts), `/etc/passwd` (21 counts), `/druid/index.html` (10 counts)
    - **Payload/artifact excerpts**: HTTP GET requests for sensitive file paths. User Agent `Mozilla/5.0 zgrab/0.x` for `/druid/index.html`.
    - **Staging indicators**: None observed.
    - **Temporal checks results**: Unavailable.
- **Conpot-ICS-Protocol-Interaction**
    - **Source IPs**: Not explicitly linked in provided data, but source of Conpot `guardian_ast` events.
    - **ASNs**: Not available.
    - **Target ports/services**: Conpot honeypot (specific port not detailed).
    - **Paths/endpoints**: N/A.
    - **Payload/artifact excerpts**: `b'\\x01I20100'`, `b'\\x01I20100\\n'`
    - **Staging indicators**: None observed.
    - **Temporal checks results**: Unavailable.
- **Uncommon-Ports-Canada**
    - **Source IPs**: Not available (aggregated by country only).
    - **ASNs**: Not available (aggregated by country only).
    - **Target ports/services**: 8880 (5), 2363 (3), 1404 (2)
    - **Paths/endpoints**: N/A.
    - **Payload/artifact excerpts**: Not available.
    - **Staging indicators**: None observed.
    - **Temporal checks results**: Unavailable.
- **Redis-Binary-Data-Monitor**:
    - **Source IPs**: Not explicitly linked to the binary data in Redis output, but the binary string `\x15\x03\x01\x00\x02\x02\x16` was also detected in SMB traffic from `176.120.59.98`.
    - **ASNs**: Not available.
    - **Target ports/services**: Redis (port unspecified).
    - **Paths/endpoints**: N/A.
    - **Payload/artifact excerpts**: `\x15\x03\x01\x00\x02\x02\x16`
    - **Staging indicators**: None observed.
    - **Temporal checks results**: Unavailable.
- **Redis-Protocol-Mismatch-Monitor**:
    - **Source IPs**: Not available.
    - **ASNs**: Not available.
    - **Target ports/services**: Redis (port unspecified).
    - **Paths/endpoints**: `/`
    - **Payload/artifact excerpts**: `GET / HTTP/1.1`, `SSH-2.0-Go`
    - **Staging indicators**: None observed.
    - **Temporal checks results**: Unavailable.

### 11) Indicators of Interest
- **IPs**:
    - 159.223.121.61 (SSH activity)
    - 103.101.16.234 (SMB activity)
    - 203.81.87.70 (SMB activity)
    - 176.120.59.98 (SMB activity, also linked to Redis binary string)
    - 77.83.39.212 (SMTP activity)
    - 167.71.255.16 (Web reconnaissance, DigitalOcean)
    - 64.227.37.148 (SSH activity)
    - 143.198.239.107 (VNC activity)
    - 129.212.183.98 (VNC activity)
    - 45.205.1.5 (Port 8728 activity)
    - 45.205.1.110 (Port 8728 activity)
- **Ports**: 22, 25, 80, 445, 5901, 5902, 5903, 5904, 5905, 8880, 2363, 1404, 8728, 54320
- **Paths/Endpoints**: `/.env`, `/druid/index.html`, `/etc/passwd`
- **CVEs**: CVE-2025-55182
- **Payload Fragments**:
    - `b'\\x01I20100'` (Conpot ICS input)
    - `SSH-2.0-Go` (Redis protocol mismatch)
    - `GET / HTTP/1.1` (Redis protocol mismatch)
    - `\x15\x03\x01\x00\x02\x02\x16` (Redis binary sequence, also seen in SMB)

### 12) Backend Tool Issues
- **`kibanna_discover_query`**: Consistently failed with `illegal_argument_exception: Expected text at 1:71 but found START_ARRAY`. This blocked the retrieval of detailed event data for:
    - Tanner `/.env` probes
    - Tanner `/druid/index.html` probes
    - Redis HTTP/SSH protocol mismatches
- **`match_query`**: Consistently failed with `illegal_argument_exception: Expected text at 1:26 but found START_ARRAY`. This blocked the retrieval of detailed event data for:
    - Tanner `/.env` probes
    - Tanner `/druid/index.html` probes
    - Redis HTTP activity
- **`two_level_terms_aggregated`**: When attempting to map source IPs for SMB traffic (`type_filter='SMB'`), the tool returned empty buckets. This limited the specificity of SMB campaign mapping.
- **Candidate Validation Loop**: The `CandidateLoopControllerAgent` repeatedly loaded `null` candidates during 8 iterations. This prevented any actual candidate-specific validation, meaning all identified candidates were not put through the full validation pipeline. As a result, 8 `null` candidates were provisionally classified as `commodity_noise` with `evidence_gaps: ["current_candidate is null"]`.
These issues significantly weakened conclusions, particularly regarding the novelty and full context of web-based and Redis-related activity, and prevented deeper validation of all discovered candidates.

### 13) Agent Action Summary (Audit Trail)

- **agent_name**: ParallelInvestigationAgent
    - **purpose**: Orchestrates parallel data gathering from various intelligence sources.
    - **inputs_used**: N/A (orchestrates other agents).
    - **actions_taken**: Initiated data collection from BaselineAgent, KnownSignalAgent, CredentialNoiseAgent, and HoneypotSpecificAgent.
    - **key_results**: Successfully triggered data collection for broad situational awareness, known threat intelligence, credential abuse patterns, and honeypot-specific interactions.
    - **errors_or_gaps**: None.

- **agent_name**: CandidateDiscoveryAgent
    - **purpose**: Identifies potential attack candidates from raw telemetry.
    - **inputs_used**: `baseline_result`, `known_signals_result`, `credential_noise_result`, `honeypot_specific_result`.
    - **actions_taken**: Performed two-level aggregations on Suricata signatures, HTTP URLs by source IP, and destination ports; executed keyword searches for specific paths and input strings found in honeypot logs.
    - **key_results**: Identified 8 initial candidates across categories like Emerging N-day Exploitation, Botnet/Campaign Mapping, Odd-Service/Minutia Attacks, and Suspicious Unmapped Activity.
    - **errors_or_gaps**: Multiple `kibanna_discover_query` and `match_query` tools failed with `illegal_argument_exception` errors. `two_level_terms_aggregated` returned empty buckets for SMB source IP mapping. These failures led to `degraded_mode: true`.

- **agent_name**: CandidateValidationLoopAgent (comprising Controller, Validation, and Reducer sub-agents)
    - **purpose**: Iteratively validates and enriches discovered candidates.
    - **inputs_used**: Candidate queue (expected from `CandidateDiscoveryAgent`).
    - **actions_taken**: Attempted to load and process 8 candidates in 8 iterations.
    - **key_results**: All 8 attempts to load a candidate resulted in a `null` candidate being processed. The loop completed its iterations.
    - **errors_or_gaps**: The `load_next_candidate` tool repeatedly returned `null` for the `current_candidate_id`, preventing any actual validation logic from executing for the discovered candidates. All 8 processed candidates were marked as `provisional: true` with `evidence_gaps: ["current_candidate is null"]`.

- **agent_name**: OSINTAgent
    - **purpose**: Enriches validated candidates with external threat intelligence.
    - **inputs_used**: `validated_candidates` (expected).
    - **actions_taken**: No OSINT queries were executed.
    - **key_results**: No OSINT results were generated.
    - **errors_or_gaps**: The `validated_candidates` input was effectively empty/invalid (due to upstream validation loop failure), so no OSINT checks could be performed.

- **agent_name**: ReportAgent
    - **purpose**: Compiles the final report from workflow state outputs.
    - **inputs_used**: `investigation_start`, `investigation_end`, `baseline_result`, `known_signals_result`, `credential_noise_result`, `honeypot_specific_result`, `candidate_discovery_result`, `validated_candidates`, `osint_validation_result`.
    - **actions_taken**: Compiled the final markdown report based on available workflow state.
    - **key_results**: Generated a comprehensive report detailing observations, identified candidates, exclusions, and system errors.
    - **errors_or_gaps**: None from this agent directly, but reflects significant upstream errors in its output.

- **agent_name**: SaveReportAgent
    - **purpose**: Saves the generated report.
    - **inputs_used**: Final report content.
    - **actions_taken**: (Implicit) Saved the generated markdown report to a file.
    - **key_results**: (Implicit) Report saved successfully.
    - **errors_or_gaps**: None reported.
