# Final Honeypot Threat Report

## 1) Investigation Scope
- **investigation_start**: 2026-03-09T06:00:11Z
- **investigation_end**: 2026-03-09T09:00:11Z
- **completion_status**: Partial
- **degraded_mode**: true (Degraded evidence due to inability to fully retrieve raw events and source IPs for some honeypot-specific activities, and a discrepancy in total attack counts.)

## 2) Executive Triage Summary
- Total observed attacks: 21049 (Note: Discrepancy with raw event counts, see Backend Tool Issues).
- Top Services/Ports of Interest: VNC (5900-5904, various high ports), SMB (445), Redis (6379), ADBHoney (5555), Tanner (HTTP), Conpot (ICS protocols: guardian_ast, IEC104), and uncommon scanning on ports 18789, 9000, 3116, 8865, 9200, 4021.
- Confirmed Known Exploitation: CVE-2006-2369 exploitation attempts on VNC from an internal IP (10.17.0.5) to external targets.
- Unmapped Exploit-like Items: None identified as novel exploits.
- Botnet/Campaign Mapping Highlights:
    - ADBHoney detected "ufo.miner" Android cryptominer activity, associated with the known Fbot botnet.
    - Widespread VNC and SMB scanning campaigns were observed from various external source IPs.
- Major Uncertainties: Inability to retrieve specific raw event details and source IPs for ADBHoney "ufo.miner" activity, Redis "MGLNDD" interactions, and Conpot ICS protocol interactions. This limits the ability to fully understand the scope and origin of these activities.

## 3) Candidate Discovery Summary
A total of 8 candidates were identified and processed. Top areas of interest included VNC scanning, SMB scanning, ADBHoney "ufo.miner" activity, Redis interactions with "MGLNDD" strings, Conpot ICS protocol observations, and scanning for sensitive web paths.
- **Missing Inputs/Errors**:
    - The `total_attacks` metric (21049) from the baseline agent is significantly lower than the total event counts from `timeline_counts` (hundreds of thousands), suggesting a difference in how "attacks" are counted vs. all events.
    - Unable to retrieve specific raw events or source IPs for ADBHoney "ufo.miner" activity using standard `kibanna_discover_query`, `two_level_terms_aggregated`, or `discover_by_keyword` despite initial honeypot-specific tool reporting presence of data. This indicates a potential field mapping or query interpretation issue.

## 4) Emerging n-day Exploitation
- **item_id**: CVE-2006-2369-internal
    - **cve/signature mapping**: CVE-2006-2369, Suricata signature 'ET EXPLOIT VNC Server Not Requiring Authentication (case 2)'
    - **evidence summary**: 508 events related to CVE-2006-2369. Source IP 10.17.0.5 is initiating a high volume of rfb (VNC-related) events from source port 5900, targeting various public destination IPs on varied high-numbered ports. This activity spans the entire reporting window.
    - **affected service/port**: VNC (TCP/5900, various high ports)
    - **confidence**: Medium
    - **operational notes**: Investigate internal source IP 10.17.0.5 to determine if it is a compromised internal host, a misconfigured internal sensor, or participating in the VNC scanning campaign. This is a known, established vulnerability.

## 5) Novel or Zero-Day Exploit Candidates (UNMAPPED ONLY, ranked)
No novel or potential zero-day exploit candidates were identified in this investigation.

## 6) Botnet/Campaign Infrastructure Mapping
- **item_id**: adbhoney_ufo_miner_botnet
    - **campaign_shape**: spray/fan-in (targeting multiple devices with same malware)
    - **suspected_compromised_src_ips**: Not directly retrievable via standard queries, blocked validation.
    - **ASNs / geo hints**: Not directly retrievable via standard queries, blocked validation.
    - **suspected_staging indicators**: dl/0d3c687ffc30e185b836b99bd07fa2b0d460a090626f6bbbd40a95b98ea70257.raw (malware sample)
    - **suspected_c2 indicators**: OSINT suggests Fbot botnet uses EmerDNS for C2, specific indicators not extracted from current data.
    - **confidence**: Moderate-High
    - **operational notes**: Activity consistent with a known Android cryptominer ("ufo.miner" / ADB.Miner) and potentially related to the Fbot botnet. Requires further investigation to identify source IPs and analyze the malware hash.
- **item_id**: vnc_scanning_campaign
    - **campaign_shape**: spray
    - **suspected_compromised_src_ips**: 79.124.40.98 (501 hits on 5900), 134.209.37.134 (449 hits across 5901-5904), 129.212.184.194 (339 hits on 5902).
    - **ASNs / geo hints**: DigitalOcean, LLC, Tamatiya EOOD (Bulgaria for 79.124.40.98)
    - **suspected_staging indicators**: None
    - **suspected_c2 indicators**: None
    - **confidence**: High
    - **operational notes**: Widespread VNC reconnaissance or brute-force scanning. Monitor these source IPs for further malicious activity.
- **item_id**: smb_scanning_campaign
    - **campaign_shape**: spray
    - **suspected_compromised_src_ips**: 200.105.151.2 (1803 hits), 106.51.31.166 (1409 hits), 182.8.193.5 (856 hits), 14.96.246.174 (618 hits), 49.206.28.13 (392 hits).
    - **ASNs / geo hints**: AXS Bolivia S. A., Atria Convergence Technologies Pvt. Ltd. Broadband Internet Service Provider INDIA, PT. Telekomunikasi Selular.
    - **suspected_staging indicators**: None
    - **suspected_c2 indicators**: None
    - **confidence**: High
    - **operational notes**: High volume SMB port (445) scanning, typical commodity enumeration or brute-force. Monitor these source IPs.

## 7) Odd-Service / Minutia Attacks
- **item_id**: redis_mglndd_interaction
    - **service_fingerprint**: Redis (TCP/6379)
    - **why it’s unusual/interesting**: Presence of "MGLNDD" strings (`MGLNDD_134.199.242.175_6379`, `MGLNDD_167.71.255.16_6379`) in Redis actions. OSINT indicates MGLNDD is associated with internet scanning activity, possibly from RIPE Atlas probes.
    - **evidence summary**: Redis actions included `MGLNDD_134.199.242.175_6379` (1 count), `MGLNDD_167.71.255.16_6379` (1 count), and `info` command (4 counts).
    - **confidence**: Medium
    - **recommended monitoring pivots**: Investigate honeypot logs for source IPs for these interactions. Perform OSINT on 134.199.242.175 and 167.71.255.16.
- **item_id**: conpot_ics_protocols
    - **service_fingerprint**: Conpot (guardian_ast, IEC104 protocols)
    - **why it’s unusual/interesting**: Interaction with niche Industrial Control System (ICS) protocols (guardian_ast, IEC104) on a honeypot.
    - **evidence summary**: Conpot honeypot observed interactions using `guardian_ast` protocol (5 counts) and `IEC104` protocol (1 count).
    - **confidence**: Medium
    - **recommended monitoring pivots**: Investigate honeypot configuration/data indexing to retrieve raw event details and source IPs for these interactions. Manual review of Conpot logs if direct querying fails.
- **item_id**: uncommon_port_scanning
    - **service_fingerprint**: Various TCP ports (e.g., 3392, 9999, 18789, 9000, 5900-5905)
    - **why it’s unusual/interesting**: Scanning activity targeting a variety of high/uncommon ports beyond the standard range, including ports often associated with remote access or less common services.
    - **evidence summary**: Scanning activity on ports 18789 (424 counts), 9000 (356 counts). Source IPs include 136.114.97.84 and 45.32.136.109. Suricata alerts for 'ET SCAN MS Terminal Server Traffic on Non-standard Port' (747 counts) and 'ET SCAN NMAP -sS window 1024' (109 counts) are present.
    - **confidence**: Medium
    - **recommended monitoring pivots**: Monitor for further activity on these non-standard ports and from the identified source IPs to detect potential targeted attacks.

## 8) Known-Exploit / Commodity Exclusions
- **commodity_ssh_smb_noise**: High volume, generic SSH (port 22) and SMB (port 445) brute-force/scanning without specific exploit payloads or novel patterns beyond commodity noise. Common usernames (root, admin) and weak passwords (123456) detected.

## 9) Infrastructure & Behavioral Classification
- **CVE-2006-2369-internal**: Exploitation / Scanning (VNC) | Campaign Shape: Fan-out | Infra Reuse: Internal IP (10.17.0.5) to multiple external targets.
- **adbhoney_ufo_miner_botnet**: Exploitation / Malware Installation (ADBHoney) | Campaign Shape: Spray/Fan-in | Infra Reuse: Specific malware sample.
- **vnc_scanning_campaign**: Scanning (VNC) | Campaign Shape: Spray | Infra Reuse: Multiple compromised IPs/ASNs (DigitalOcean, Tamatiya EOOD).
- **smb_scanning_campaign**: Scanning (SMB) | Campaign Shape: Spray | Infra Reuse: Multiple compromised IPs/ASNs (AXS Bolivia, Atria Convergence, PT. Telekomunikasi).
- **redis_mglndd_interaction**: Scanning (Redis) | Campaign Shape: Unknown | Infra Reuse: Potential RIPE Atlas probes (external IPs 134.199.242.175, 167.71.255.16).
- **conpot_ics_protocols**: Scanning / Reconnaissance (ICS protocols) | Campaign Shape: Unknown | Infra Reuse: Unknown (source IPs not retrievable).
- **uncommon_port_scanning**: Scanning (Various TCP) | Campaign Shape: Unknown | Infra Reuse: Specific source IPs (136.114.97.84, 45.32.136.109).
- **tanner_web_path_scanning**: Scanning / Reconnaissance (HTTP/HTTPS) | Campaign Shape: Spray | Infra Reuse: Multiple external IPs/ASNs (Hostglobal.plus, Google LLC).

## 10) Evidence Appendix
- **CVE-2006-2369-internal**
    - **source IPs with counts**: 10.17.0.5 (508 events related to CVE-2006-2369, thousands of RFB events)
    - **ASNs with counts**: Not explicitly provided for this specific internal IP, but generally an internal network.
    - **target ports/services**: VNC (TCP/5900) to various high-numbered destination ports (e.g., 28759, 2105, 5058, 37749, etc.)
    - **paths/endpoints**: N/A (VNC protocol activity)
    - **payload/artifact excerpts**: Suricata alert signature: 'ET EXPLOIT VNC Server Not Requiring Authentication (case 2)'. Events are of `event_type: rfb`.
    - **staging indicators**: None
    - **temporal checks results**: First seen: 2026-03-09T06:00:12.509Z, Last seen: 2026-03-09T09:00:11.921Z (activity throughout the window).
- **adbhoney_ufo_miner_botnet**
    - **source IPs with counts**: Not directly retrievable via standard queries.
    - **ASNs with counts**: Not directly retrievable via standard queries.
    - **target ports/services**: ADBHoney (TCP/5555)
    - **paths/endpoints**: `/data/local/tmp/ufo.apk`
    - **payload/artifact excerpts**: Commands: `pm path com.ufo.miner`, `am start -n com.ufo.miner/com.example.test.MainActivity`, `pm install /data/local/tmp/ufo.apk`, `ps | grep trinity`, `rm -f /data/local/tmp/ufo.apk`, `rm -rf /data/local/tmp/*`.
    - **staging indicators**: `dl/0d3c687ffc30e185b836b99bd07fa2b0d460a090626f6bbbd40a95b98ea70257.raw` (malware sample download path)
    - **temporal checks results**: unavailable (due to querying issues)
- **vnc_scanning_campaign**
    - **source IPs with counts**: 79.124.40.98 (501), 134.209.37.134 (449), 129.212.184.194 (339).
    - **ASNs with counts**: DigitalOcean, LLC, Tamatiya EOOD (AS50360).
    - **target ports/services**: VNC (5900, 5901, 5902, 5903, 5904).
    - **paths/endpoints**: N/A
    - **payload/artifact excerpts**: Suricata alert signature: 'GPL INFO VNC server response'.
    - **staging indicators**: None
    - **temporal checks results**: Activity is persistent across the time window.
- **smb_scanning_campaign**
    - **source IPs with counts**: 200.105.151.2 (1803), 106.51.31.166 (1409), 182.8.193.5 (856), 14.96.246.174 (618), 49.206.28.13 (392).
    - **ASNs with counts**: AXS Bolivia S. A., Atria Convergence Technologies Pvt. Ltd. Broadband Internet Service Provider INDIA, PT. Telekomunikasi Selular.
    - **target ports/services**: SMB (TCP/445).
    - **paths/endpoints**: N/A
    - **payload/artifact excerpts**: Suricata alert signatures: 'GPL NETBIOS SMB-DS IPC$ share access', 'GPL NETBIOS SMB-DS IPC$ unicode share access'.
    - **staging indicators**: None
    - **temporal checks results**: Persistent activity throughout the window.
- **redis_mglndd_interaction**
    - **source IPs with counts**: Not directly retrievable via standard queries.
    - **ASNs with counts**: Not directly retrievable via standard queries.
    - **target ports/services**: Redis (TCP/6379).
    - **paths/endpoints**: N/A
    - **payload/artifact excerpts**: Redis actions: 'MGLNDD_134.199.242.175_6379', 'MGLNDD_167.71.255.16_6379', 'info'.
    - **staging indicators**: Suspected IP addresses within MGLNDD string: 134.199.242.175, 167.71.255.16.
    - **temporal checks results**: unavailable (due to querying issues)
- **tanner_web_path_scanning**
    - **source IPs with counts**: 78.153.140.40 (UK), 34.158.79.105 (NL), 34.66.133.48 (US).
    - **ASNs with counts**: Hostglobal.plus Ltd, Google LLC, DigitalOcean, LLC.
    - **target ports/services**: HTTP/HTTPS (ports 80, 443, 8080, 8443).
    - **paths/endpoints**: `/.env`, `/.git/config`.
    - **payload/artifact excerpts**: HTTP GET requests for the mentioned paths with various User-Agents.
    - **staging indicators**: None
    - **temporal checks results**: Persistent activity throughout the window.

## 11) Indicators of Interest
- **Source IPs**:
    - 10.17.0.5 (internal, CVE-2006-2369 activity)
    - 200.105.151.2 (SMB scanning)
    - 106.51.31.166 (SMB scanning)
    - 136.114.97.84 (uncommon port scanning)
    - 182.8.193.5 (SMB scanning)
    - 45.32.136.109 (uncommon port scanning)
    - 79.124.40.98 (VNC scanning)
    - 134.209.37.134 (VNC scanning)
    - 129.212.184.194 (VNC scanning)
    - 78.153.140.40 (web path scanning)
    - 34.158.79.105 (web path scanning)
    - 34.66.133.48 (web path scanning)
    - 134.199.242.175 (suspected MGLNDD Redis scanning target/origin)
    - 167.71.255.16 (suspected MGLNDD Redis scanning target/origin)
- **Malware Hashes**: `0d3c687ffc30e185b836b99bd07fa2b0d460a090626f6bbbd40a95b98ea70257.raw` (ufo.miner sample)
- **URLs/Paths**:
    - `/.env`
    - `/.git/config`
- **CVEs**: CVE-2006-2369
- **Suricata Signatures**:
    - `ET EXPLOIT VNC Server Not Requiring Authentication (case 2)`
    - `GPL INFO VNC server response`
    - `GPL NETBIOS SMB-DS IPC$ share access`
    - `GPL NETBIOS SMB-DS IPC$ unicode share access`
    - `ET SCAN MS Terminal Server Traffic on Non-standard Port`
    - `ET SCAN NMAP -sS window 1024`

## 12) Backend Tool Issues
- **`CandidateDiscoveryAgent`**:
    - `total_attacks_metric_discrepancy`: The `total_attacks` (21049) from the baseline agent is significantly lower than the total event counts from `timeline_counts` (hundreds of thousands), suggesting a difference in how "attacks" are counted vs. all events. This weakens the overall attack volume assessment.
    - `adbhoney_details`: Unable to retrieve specific raw events or source IPs for ADBHoney "ufo.miner" activity using standard `kibanna_discover_query`, `two_level_terms_aggregated`, or `discover_by_keyword` despite initial honeypot-specific tool reporting presence of data. This indicates a potential field mapping or query interpretation issue, weakening the infrastructure mapping and source attribution for this botnet activity.
    - `blocked_validation_steps`: `adbhoney.input.keyword` field queries, `adbhoney.malware_sample.keyword` field queries.
- **`CandidateValidationAgent` for `redis_mglndd_interaction`**:
    - `evidence_gaps`: Unable to directly correlate specific source IPs to the observed "MGLNDD" Redis actions using available ElasticSearch tools.
    - `blocked_validation_steps`: Direct source IP correlation for 'MGLNDD' Redis actions. This weakens the confidence in understanding the full scope and origin of this activity.
- **`CandidateValidationAgent` for `conpot_ics_protocols`**:
    - `evidence_gaps`: Unable to retrieve raw event details or source IPs for the Conpot protocol interactions.
    - `blocked_validation_steps`: Direct source IP identification for Conpot protocol interactions, Detailed raw event inspection for Conpot protocol interactions. This significantly weakens the ability to classify, attribute, and assess the true novelty and threat of these ICS protocol interactions.

## 13) Agent Action Summary (Audit Trail)

- **agent_name**: ParallelInvestigationAgent (and its sub-agents: BaselineAgent, KnownSignalAgent, CredentialNoiseAgent, HoneypotSpecificAgent)
    - **purpose**: Gather initial baseline telemetry, known threat intelligence signals, credential abuse indicators, and honeypot-specific observations within the investigation timeframe.
    - **inputs_used**: None (initial data collection)
    - **actions_taken**: Queried for total attacks, top countries/ASNs/IPs, country-to-port mapping, alert signatures, CVEs, alert categories, common usernames/passwords, OS distribution from p0f, Redis actions, ADBHoney inputs/malware samples, Conpot inputs/protocols, and Tanner web paths.
    - **key_results**: Identified high-volume VNC and SMB activity, VNC-related CVE-2006-2369, "ufo.miner" malware via ADBHoney, "MGLNDD" in Redis, ICS protocols on Conpot, and web path scanning.
    - **errors_or_gaps**: `total_attacks_metric_discrepancy` noted.

- **agent_name**: CandidateDiscoveryAgent
    - **purpose**: Identify potential high-signal items for deeper investigation by correlating and highlighting unusual activity from the initial telemetry.
    - **inputs_used**: `baseline_result`, `known_signals_result`, `credential_noise_result`, `honeypot_specific_result`.
    - **actions_taken**: Performed two-level aggregations on ADBHoney inputs, queried for CVE-related IPs and ports, aggregated source IPs by destination port, and generated a timeline of event counts. Set initial classification and required follow-ups.
    - **key_results**: Identified 8 candidates for validation across Emerging n-day Exploitation, Botnet/Campaign Mapping, Odd-Service/Minutia, and Suspicious Unmapped Activity.
    - **errors_or_gaps**: `adbhoney_details` (inability to retrieve specific raw events/source IPs for "ufo.miner" activity). Blocked validation steps for `adbhoney.input.keyword` and `adbhoney.malware_sample.keyword` field queries.

- **agent_name**: CandidateValidationLoopAgent
    - **purpose**: Orchestrate the validation of identified candidates through iterative queries and OSINT checks.
    - **inputs_used**: Candidates generated by `CandidateDiscoveryAgent`.
    - **actions_taken**: Iterated through 8 candidates, loading each for validation by the `CandidateValidationAgent`.
    - **key_results**: 8 candidates queued, 8 candidates validated (or attempted validation for). Loop completed.
    - **errors_or_gaps**: None reported at the controller level, but individual validation steps had issues as reported by `CandidateValidationAgent` and `CandidateLoopReducerAgent`.

- **agent_name**: CandidateValidationAgent (within the loop, for each candidate)
    - **purpose**: Validate individual threat candidates using specific queries and OSINT searches.
    - **inputs_used**: Current candidate details from `CandidateLoopControllerAgent`.
    - **actions_taken**: Executed various tools like `suricata_cve_samples`, `events_for_src_ip`, `first_last_seen_src_ip`, `search` (for OSINT), `kibanna_discover_query`, `two_level_terms_aggregated`, `custom_basic_search`, `web_path_samples`, `suricata_lenient_phrase_search`.
    - **key_results**: Successfully validated several campaign mappings and scanning activities. Identified specific evidence and confirmed knownness for most.
    - **errors_or_gaps**: Failed to retrieve raw event details or source IPs for `adbhoney_ufo_miner_botnet` (`adbhoney_details` gap), `redis_mglndd_interaction` (blocked direct source IP correlation), and `conpot_ics_protocols` (blocked source IP identification and detailed raw event inspection).

- **agent_name**: OSINTAgent
    - **purpose**: Perform Open Source Intelligence (OSINT) lookups for validated candidates to determine knownness, recency, and adjust confidence.
    - **inputs_used**: All validated candidates from `CandidateValidationAgent` via `CandidateLoopReducerAgent`.
    - **actions_taken**: Performed OSINT searches for specific CVEs, malware terms ("ufo.miner botnet", malware hash), and specific activity strings ("MGLNDD Redis", web paths).
    - **key_results**: Confirmed knownness for CVE-2006-2369, "ufo.miner" (associated with Fbot botnet), MGLNDD scanning, VNC/SMB scanning patterns, and web path reconnaissance. `conpot_ics_protocols` OSINT was inconclusive due to lack of retrievable details.
    - **errors_or_gaps**: OSINT for `conpot_ics_protocols` was inconclusive due to prior blocked validation steps. Malware hash `0d3c687ffc30e185b836b99bd07fa2b0d460a090626f6bbbd40a95b98ea70257` did not yield direct public results.

- **agent_name**: ReportAgent (self)
    - **purpose**: Compile the final report from all workflow state outputs.
    - **inputs_used**: `investigation_start`, `investigation_end`, `baseline_result`, `known_signals_result`, `credential_noise_result`, `honeypot_specific_result`, `candidate_discovery_result`, `validated_candidates`, `osint_validation_result`.
    - **actions_taken**: Consolidated all collected data, applied mandatory logic for completion status, triage summary, and categorical routing, and formatted the final markdown report.
    - **key_results**: This markdown report.
    - **errors_or_gaps**: None (report generation successful, but relies on potentially degraded upstream data).

- **agent_name**: SaveReportAgent
    - **purpose**: Save the generated report to a specified location.
    - **inputs_used**: The content of the final report.
    - **actions_taken**: Called `default_write_file`.
    - **key_results**: (Implicit: report content passed to tool, success expected unless tool-level error occurred).
    - **errors_or_gaps**: None reported.
