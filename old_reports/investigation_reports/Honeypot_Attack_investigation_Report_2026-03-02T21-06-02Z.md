# Threat Investigation Report

## 1) Investigation Scope
- **investigation_start**: 2026-03-02T20:00:11Z
- **investigation_end**: 2026-03-02T21:00:11Z
- **completion_status**: Partial
- **degraded_mode**: true, due to tool errors blocking raw event detail inspection and some specific queries, limiting the ability to fully characterize some activities.

## 2) Executive Triage Summary
- Top services/ports of interest include VNC (ports 5926, 5925, 5902, 5900, 5905), SSH (port 22), Conpot ICS protocols (guardian_ast, kamstrup_protocol), and Tanner honeypot observing web path requests (/.env, /.aws/credentials).
- Widespread VNC scanning activity, identified by the "GPL INFO VNC server response" signature, is the top confirmed known exploitation.
- No fully validated novel exploit items were confirmed, primarily due to tool errors preventing deep inspection of raw event data.
- A significant VNC scanning campaign originating largely from DigitalOcean and DpkgSoft ASNs was mapped.
- Major uncertainties remain regarding the full nature and payload of the Conpot ICS interactions and Tanner sensitive file requests due to blocked raw event data access.

## 3) Candidate Discovery Summary
- **Total Attacks Observed**: 4905
- **Top Attacking Countries**: United States (1780), India (724), Germany (682)
- **Top Attacking Source IPs**: 160.119.76.250 (361), 165.232.71.157 (300), 129.212.188.196 (263)
- **Top Attacker ASNs**: DigitalOcean, LLC (ASN 14061, 3056 attacks), Alsycon B.V. (ASN 49870, 361 attacks)
- **Top Alert Signatures**: GPL INFO VNC server response (2260), SURICATA IPv4 truncated packet (230), ET INFO SSH session in progress on Expected Port (79).
- **Honeypot Observations**:
    - Conpot: Interactions with 'guardian_ast' (27 events) and 'kamstrup_protocol' (6 events) protocols, and a specific input `b'I20100'` (1 event).
    - Tanner: Requests for sensitive paths `/.env` (2 events) and `/.aws/credentials` (1 event).
- **Credential Noise**: High volume of brute-force attempts targeting common usernames ('root', 'admin') and passwords ('123456', 'password').
- **Missing Inputs/Errors**: Multiple `kibanna_discover_query` and `match_query` tools failed for key indicators (paths, conpot input, ASN), preventing detailed inspection of specific events and materially affecting the ability to fully validate potential novel exploit candidates and classify unmapped activity.

## 4) Emerging n-day Exploitation
None identified in this investigation window.

## 5) Novel or Zero-Day Exploit Candidates (UNMAPPED ONLY, ranked)
None identified in this investigation window due to tool limitations in extracting sufficient raw evidence for unmapped activity.

## 6) Botnet/Campaign Infrastructure Mapping
- **item_id**: VNC-SCAN-20260302
    - **campaign_shape**: spray
    - **suspected_compromised_src_ips**: 129.212.183.117 (132), 129.212.184.194 (74), 150.241.115.50 (50), 162.243.248.118 (48), 149.202.37.76 (20), 178.32.233.136 (20), 37.19.210.12 (20), 104.234.30.10 (18), 144.76.135.165 (18), 157.250.199.154 (18) (and 1842 more unique IPs)
    - **ASNs / geo hints**: DigitalOcean, LLC (ASN 14061, United States), DpkgSoft International Limited (ASN 215590, United States).
    - **suspected_staging indicators**: None identified.
    - **suspected_c2 indicators**: None identified.
    - **confidence**: High
    - **operational notes**: This represents widespread VNC scanning activity, consistent with commodity network reconnaissance. Monitor for changes in target ports or observed VNC-related payloads.

## 7) Odd-Service / Minutia Attacks
- **candidate_id**: CONPOT-ICS-PROBE-20260302
    - **service_fingerprint**: Conpot honeypot, guardian_ast and kamstrup_protocol, specific input `b'I20100'`.
    - **why it’s unusual/interesting**: Interactions with ICS/OT-specific protocols (guardian_ast, kamstrup_protocol) and a unique byte string input (`b'I20100'`) suggest targeted or unusual reconnaissance/attack against industrial control systems, which is a high-value operational target.
    - **evidence summary**: Conpot protocol activity: 'guardian_ast' (27 events), 'kamstrup_protocol' (6 events). Conpot input: `b'I20100'` (1 event). Source IPs include 205.210.31.109 (19), 198.235.24.49 (4), 89.169.110.125 (4) for guardian_ast; 85.11.183.25 (6) for kamstrup_protocol.
    - **confidence**: Medium
    - **recommended monitoring pivots**: Further investigation into `b'I20100'` if tools become available, or if similar patterns recur. OSINT on the specific byte string may reveal known exploits or tools. Monitor ICS protocols more broadly for similar activity.
    - **provisional**: true

## 8) Known-Exploit / Commodity Exclusions
- **VNC Scanning/Brute Force**: High volume activity (2260 events) mapped to 'GPL INFO VNC server response' signature, originating from numerous IPs across ASNs like DigitalOcean (14061) and DpkgSoft (215590), targeting VNC ports (5900, 5902, 5905, 5925, 5926). This is typical commodity reconnaissance.
- **SSH Brute Force**: Detected through 'ET INFO SSH session in progress on Expected Port' signature (79 events), accompanied by high volume brute-force attempts using common usernames ('root', 'admin') and passwords ('123456', 'password').
- **Generic Scanning/Malformed Traffic**: Indicated by 'SURICATA IPv4 truncated packet' (230 events) and 'SURICATA AF-PACKET truncated packet' (230 events), representing general network probing or traffic anomalies.
- **Credential Noise**: Extensive attempts to log in with common credentials, including 'root' (151), 'admin' (77), 'user' (29) and '123456' (27), 'password' (23).

## 9) Infrastructure & Behavioral Classification
- **VNC Scanning Campaign**: Characterized by widespread scanning (spray-style) targeting various VNC ports. Significant infrastructure reuse observed across multiple source IPs primarily from DigitalOcean and DpkgSoft ASNs.
- **ICS Protocol Probing (Conpot)**: Represents reconnaissance or probing activity against industrial control systems, with an unknown campaign shape at this time. Limited source infrastructure details were fully resolved due to tool limitations.
- **Sensitive Web File Probing (Tanner)**: Detected as reconnaissance, targeting common sensitive configuration files. Campaign shape is currently unknown, and source infrastructure is limited.
- **SSH Brute Force**: Classified as scanning activity, likely spray-style due to the volume and common credential usage.

## 10) Evidence Appendix

### VNC-SCAN-20260302 (Botnet/Campaign Infrastructure Mapping)
- **Source IPs with counts**: 129.212.183.117 (132), 129.212.184.194 (74), 150.241.115.50 (50), 162.243.248.118 (48), 149.202.37.76 (20), 178.32.233.136 (20), 37.19.210.12 (20), 104.234.30.10 (18), 144.76.135.165 (18), 157.250.199.154 (18).
- **ASNs with counts**: DigitalOcean, LLC (ASN 14061, total 3056 attacks), DpkgSoft International Limited (ASN 215590).
- **Target ports/services**: VNC (5900, 5902, 5905, 5925, 5926).
- **Paths/endpoints**: N/A (protocol-level interaction, not HTTP paths directly).
- **Payload/artifact excerpts**: Suricata alert signature: "GPL INFO VNC server response".
- **Staging indicators**: None identified.
- **Temporal checks results**: Consistent activity observed throughout the 60-minute window for analyzed IPs (e.g., 129.212.183.117: 2026-03-02T20:00:19Z - 2026-03-02T20:59:46Z; 129.212.184.194: 2026-03-02T20:00:24Z - 2026-03-02T20:59:46Z).

### CONPOT-ICS-PROBE-20260302 (Odd-Service / Minutia Attack)
- **Source IPs with counts**: 205.210.31.109 (19 - guardian_ast), 198.235.24.49 (4 - guardian_ast), 89.169.110.125 (4 - guardian_ast); 85.11.183.25 (6 - kamstrup_protocol).
- **ASNs with counts**: Not explicitly available from current data for these specific IPs.
- **Target ports/services**: Conpot honeypot, guardian_ast protocol, kamstrup_protocol.
- **Paths/endpoints**: N/A.
- **Payload/artifact excerpts**: Conpot input: `b'I20100'`.
- **Staging indicators**: None identified.
- **Temporal checks results**: Unavailable.

### SUSPICIOUS-UNMAPPED-20260302 (Suspicious Unmapped Activity to Monitor)
- **Source IPs with counts**: Not explicitly available for these specific path requests.
- **ASNs with counts**: Not explicitly available.
- **Target ports/services**: Web service (Tanner honeypot).
- **Paths/endpoints**: `/.env`, `/.aws/credentials`.
- **Payload/artifact excerpts**: N/A.
- **Staging indicators**: None identified.
- **Temporal checks results**: Unavailable.

## 11) Indicators of Interest
- **Source IPs (High-Signal)**:
    - VNC Scanners: 129.212.183.117, 129.212.184.194, 150.241.115.50, 162.243.248.118
    - Conpot Interactors: 205.210.31.109, 85.11.183.25
- **ASNs**: 14061 (DigitalOcean, LLC), 215590 (DpkgSoft International Limited)
- **Target Ports**: 5900, 5902, 5905, 5925, 5926 (VNC), 22 (SSH)
- **Paths/Endpoints**: `/.env`, `/.aws/credentials`
- **Payload Fragments**: `b'I20100'` (Conpot specific input)
- **Alert Signatures**: GPL INFO VNC server response, ET INFO SSH session in progress on Expected Port

## 12) Backend Tool Issues
- **`kibanna_discover_query` failures**: Failed for `path.keyword="/.env"`, `path.keyword="/.aws/credentials"`, and `conpot.input.keyword="b'\x01I20100'"`.
    - **Affected Validations**: This prevented the full retrieval of raw event details for Tanner and Conpot activities, severely limiting the ability to assess novelty, understand specific attack vectors, and determine potential exploit payloads.
- **`match_query` failures**: Failed for `path.keyword="/.env"`, `path.keyword="/.aws/credentials"`, `conpot.input.keyword="b'\x01I20100'"`, and `geoip.asn="215590"`.
    - **Affected Validations**: Similar to `kibanna_discover_query`, these failures blocked detailed event inspection for Tanner and Conpot. The failure for `geoip.asn` prevented specific ASN-filtered queries in Deep Investigation, limiting a complete understanding of the campaign's infrastructure from ASN perspective.
- **`two_level_terms_aggregated` (Conpot protocol)**: This query returned empty buckets when filtered for type 'Conpot'.
    - **Affected Validations**: This suggests a potential field mismatch or a lack of specific hits under the applied filter, making it difficult to directly link Conpot protocols to specific source IPs or other contextual data through this aggregation.

These issues led to conclusions for "Odd-Service / Minutia Attacks" and "Suspicious Unmapped Activity to Monitor" being marked as Provisional and reduced overall confidence in fully characterizing the potential novelty of these items.

## 13) Agent Action Summary (Audit Trail)

### ParallelInvestigationAgent
- **Purpose**: Orchestrate concurrent data collection and initial analysis across various honeypot and detection systems.
- **Inputs Used**: `investigation_start`, `investigation_end`.
- **Actions Taken**: Called `BaselineAgent`, `KnownSignalAgent`, `CredentialNoiseAgent`, and `HoneypotSpecificAgent`.
- **Key Results**: Consolidated initial telemetry on total attacks, top countries/IPs/ASNs, known alert signatures, credential brute-force attempts, and honeypot-specific interactions.
- **Errors or Gaps**: None.

### BaselineAgent
- **Purpose**: Establish foundational metrics of observed attack activity within the investigation window.
- **Inputs Used**: Time window `2026-03-02T20:00:11Z` to `2026-03-02T21:00:11Z`.
- **Actions Taken**: Executed `get_total_attacks`, `get_top_countries`, `get_attacker_src_ip`, `get_country_to_port`, and `get_attacker_asn`.
- **Key Results**: Identified 4905 total attacks, top attacker country United States (1780), top attacker IP 160.119.76.250 (361), and significant activity from DigitalOcean, LLC (ASN 14061) with 3056 events.
- **Errors or Gaps**: None.

### KnownSignalAgent
- **Purpose**: Identify and categorize known threat activities using alert signatures and CVE mappings.
- **Inputs Used**: Time window `2026-03-02T20:00:11Z` to `2026-03-02T21:00:11Z`.
- **Actions Taken**: Executed `get_alert_signature`, `get_cve`, `get_alert_category`, and `suricata_lenient_phrase_search` for "VNC server response".
- **Key Results**: Detected 2260 instances of 'GPL INFO VNC server response' alerts, identified minor CVE associations, and categorized a large portion of activity as 'Misc activity' (2440 events).
- **Errors or Gaps**: None.

### CredentialNoiseAgent
- **Purpose**: Characterize and quantify common credential-based attacks and noise.
- **Inputs Used**: Time window `2026-03-02T20:00:11Z` to `2026-03-02T21:00:11Z`.
- **Actions Taken**: Executed `get_input_usernames`, `get_input_passwords`, and `get_p0f_os_distribution`.
- **Key Results**: Documented prevalent brute-force attempts using usernames like 'root' (151) and 'admin' (77), and passwords such as '123456' (27) and 'password' (23). Identified target OS distribution, predominantly Windows NT kernel (14925) and Linux (7087).
- **Errors or Gaps**: None.

### HoneypotSpecificAgent
- **Purpose**: Analyze activity unique to specific honeypot deployments to uncover unusual or targeted attacks.
- **Inputs Used**: Time window `2026-03-02T20:00:11Z` to `2026-03-02T21:00:11Z`.
- **Actions Taken**: Executed `redis_duration_and_bytes`, `adbhoney_input`, `adbhoney_malware_samples`, `conpot_input`, `tanner_unifrom_resource_search`, and `conpot_protocol`.
- **Key Results**: Observed Conpot honeypot interactions involving 'guardian_ast' (27 events) and 'kamstrup_protocol' (6 events), including a unique input `b'I20100'`. Tanner honeypot detected requests for sensitive web paths (`/.env`, `/.aws/credentials`). Minimal activity on Redis and ADBHoney.
- **Errors or Gaps**: None.

### CandidateDiscoveryAgent
- **Purpose**: Identify and initially triage potential high-signal attack candidates from various data sources.
- **Inputs Used**: `baseline_result`, `known_signals_result`, `credential_noise_result`, `honeypot_specific_result`.
- **Actions Taken**: Performed `kibanna_discover_query`, `two_level_terms_aggregated`, and `match_query` for paths, Conpot inputs, and alert signatures.
- **Key Results**: Identified a VNC scanning campaign as a known commodity. Surfaced Conpot ICS probing and Tanner sensitive file requests as potential "odd-service" or "suspicious unmapped" activity. Noted significant tool errors affecting deeper analysis.
- **Errors or Gaps**: Encountered `illegal_argument_exception` errors for `kibanna_discover_query` and `match_query` when attempting to retrieve raw event details for paths (`/.env`, `/.aws/credentials`) and Conpot input (`b'I20100'`), severely hindering detailed candidate validation.

### CandidateValidationLoopAgent (Summarized via Controller & Reducer)
- **Purpose**: Validate and enrich discovered candidates through targeted queries and checks.
- **Inputs Used**: Three candidates generated by `CandidateDiscoveryAgent`.
- **Iterations Run**: 1 iteration.
- **# Candidates Validated**: 1 candidate (`VNC-SCAN-20260302`).
- **Early Exit Reason**: None.
- **Actions Taken**: Loaded `VNC-SCAN-20260302`, performed knownness checks and collected infrastructure details from aggregated data.
- **Key Results**: Classified `VNC-SCAN-20260302` as a `known_exploit_campaign` with high confidence, providing detailed infrastructure indicators.
- **Errors or Gaps**: None explicitly from the validation logic itself, but downstream deep investigation faced tool errors which impacted related candidates.

### DeepInvestigationLoopController
- **Purpose**: Conduct in-depth, iterative investigation on high-priority leads identified in earlier stages.
- **Inputs Used**: Leads such as `src_ip:129.212.183.117`, `src_ip:129.212.184.194`, `src_ip:150.241.115.50`, `asn:215590`, `src_ip:162.243.248.118`.
- **Iterations Run**: 5 iterations.
- **Key Leads Pursued**: Investigated top attacking IPs involved in the VNC scanning campaign and attempted to broadly investigate an associated ASN.
- **Stall/Exit Reason**: Exited due to a `stall_count` of 2, indicating repeated failures or diminishing returns in pursuing leads.
- **Errors or Gaps**: `match_query` tool failed when trying to investigate `asn:215590`, limiting the ability to comprehensively map the ASN's involvement. This weakened the confidence in fully understanding the broader campaign infrastructure originating from that ASN.

### OSINTAgent
- **Purpose**: Augment internal telemetry with external threat intelligence to assess knownness, recency, and impact.
- **Inputs Used**: `VNC-SCAN-20260302` candidate details.
- **Actions Taken**: Performed a `search` query with "GPL INFO VNC server response VNC ports 5926 5925 5902".
- **Key Results**: Public documentation confirmed VNC port conventions and frequent scanning/brute-force targeting of these ports, reducing the novelty score of the VNC scanning activity and reinforcing its classification as commodity.
- **Errors or Gaps**: None.

### ReportAgent
- **Purpose**: Compile the final investigation report from all preceding workflow state outputs.
- **Inputs Used**: All generated workflow state outputs (`investigation_start`, `investigation_end`, `baseline_result`, `known_signals_result`, `credential_noise_result`, `honeypot_specific_result`, `candidate_discovery_result`, `validated_candidates`, `osint_validation_result`, `deep_investigation_logs/state`).
- **Actions Taken**: Compiled the comprehensive markdown report as instructed by the workflow.
- **Key Results**: The complete final investigation report.
- **Errors or Gaps**: None.

### SaveReportAgent
- **Purpose**: Persist the final investigation report to a file.
- **Inputs Used**: The compiled report content.
- **Actions Taken**: Called `investigation_write_file`.
- **Key Results**: The report was successfully saved.
- **Errors or Gaps**: None.
