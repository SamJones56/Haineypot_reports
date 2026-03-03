# Investigation Report

## 1) Investigation Scope
- **investigation_start**: 2026-03-02T18:44:28Z
- **investigation_end**: 2026-03-02T19:44:28Z
- **completion_status**: Partial
- **degraded_mode**: true (Due to persistent backend tool errors preventing detailed evidence correlation and raw event inspection.)

## 2) Executive Triage Summary
- **Top Services/Ports of Interest**: VNC (ports 5926, 5925, 5902, 5906, 5907, 5912), RDP (non-standard ports), SSH (port 22), SMTP (port 25), and an unusual Nintendo 3DS interaction on Minecraft's default port (25565). Web application path scanning (/.env) was also observed.
- **Top Confirmed Known Exploitation**: Widespread VNC and RDP scanning activity, matching known Suricata/Emerging Threats signatures. Commodity web vulnerability scanning for `.env` files. Low-count alerts for several known CVEs (CVE-2025-55182, CVE-2024-14007, CVE-2021-3449, CVE-2019-11500) suggest scanning rather than active, widespread exploitation.
- **Top Unmapped Exploit-Like Items**: None were confidently classified as novel exploits.
- **Botnet/Campaign Mapping Highlights**: Significant VNC/RDP scanning originated from DigitalOcean and JSC Selectel ASNs, indicative of commodity botnet activity. Adbhoney detected multiple malware sample downloads, consistent with ADB malware distribution patterns, potentially cryptojacking.
- **Major Uncertainties**: The inability to perform granular queries due to backend tool errors prevented direct correlation of source IPs to specific payloads, malware file hashes, or detailed exploit steps, thereby limiting the depth of analysis for certain candidates.

## 3) Candidate Discovery Summary
- **Total Attacks Observed**: 3184
- **Top Attacking Countries**: United States (1696), Russia (508), Australia (199).
- **Top Attacker ASNs**: DigitalOcean, LLC (ASN 14061, 1200 counts), JSC Selectel (ASN 49505, 505 counts).
- **Key Services/Ports**: VNC (5926, 5925, 5902, 5906, 5907, 5912), SSH (22), SMTP (25), uncommon ports (3001, 3005, 3019, 3020, 8728, 1024, 2083), Minecraft (25565).
- **Honeypot-Specific Findings**: Adbhoney recorded 6 malware sample downloads from distinct hashes. Tanner honeypot detected access to the `/.env` path. Redis honeypot observed basic connection/info commands.
- **Material Gaps/Errors**: Multiple `kibanna_discover_query`, `match_query`, and `complete_custom_search` tool calls failed with `illegal_argument_exception` or `parsing_exception` errors. These failures significantly hampered the ability to retrieve raw event data and perform complex aggregations for deeper analysis and correlation.

## 4) Emerging n-day Exploitation
- **CVE-2025-55182 (React2Shell)**
    - **CVE/signature mapping**: CVE-2025-55182 (React2Shell), critical RCE (CVSS 10.0) affecting React Server Components. Public exploits observed since December 2025.
    - **Evidence summary**: 1 count of alert.
    - **Affected service/port**: React Server Components / Web services (not specified by port in alert).
    - **Confidence**: Moderate (due to low count, but high severity and recency).
    - **Operational notes**: Likely scanning activity for a recently disclosed, actively exploited vulnerability. Monitor for escalated activity or higher volume.
- **CVE-2024-14007 (NVMS-9000)**
    - **CVE/signature mapping**: CVE-2024-14007, critical authentication bypass (CVSS 8.7) affecting NVMS-9000 control protocol in DVR/NVR/IPC products.
    - **Evidence summary**: 2 counts of alert.
    - **Affected service/port**: NVMS-9000 control port (not specified by port in alert).
    - **Confidence**: Moderate (due to low count, but high severity).
    - **Operational notes**: Scanning for a critical authentication bypass. Monitor for increased volume or successful exploitation attempts.
- **CVE-2021-3449 (OpenSSL DoS)**
    - **CVE/signature mapping**: CVE-2021-3449, denial of service (DoS) in OpenSSL TLS servers.
    - **Evidence summary**: 3 counts of alert.
    - **Affected service/port**: TLSv1.2-enabled services (not specified by port in alert).
    - **Confidence**: Moderate.
    - **Operational notes**: Indicative of probing for known OpenSSL DoS vulnerabilities.
- **CVE-2019-11500 (Dovecot RCE)**
    - **CVE/signature mapping**: CVE-2019-11500, critical RCE (CVSS 9.8) in Dovecot IMAP/POP3 server.
    - **Evidence summary**: 2 counts of alert.
    - **Affected service/port**: IMAP/POP3 services (not specified by port in alert).
    - **Confidence**: Moderate.
    - **Operational notes**: Indicative of probing for known Dovecot RCE vulnerabilities.

## 5) Novel or Zero-Day Exploit Candidates
No candidates were identified as novel or potential zero-day exploits in this investigation window.

## 6) Botnet/Campaign Infrastructure Mapping
- **item_id**: VNC_RDP_Scanning_Campaign
    - **campaign_shape**: spray
    - **suspected_compromised_src_ips**: 129.212.188.196 (263), 129.212.179.18 (261), 5.182.4.39 (162), 188.246.224.186 (158), 188.246.224.87 (130)
    - **ASNs / geo hints**: ASN 14061 (DigitalOcean, LLC), ASN 49505 (JSC Selectel). Top countries: United States, Russia.
    - **suspected_staging indicators**: N/A
    - **suspected_c2 indicators**: N/A
    - **confidence**: High
    - **operational notes**: Widespread, commodity scanning for VNC and RDP services. Monitor for payload changes or escalated activity from identified IPs/ASNs.
- **item_id**: Adbhoney_Malware_Distribution
    - **campaign_shape**: unknown (multiple distinct payloads)
    - **suspected_compromised_src_ips**: 165.245.183.230
    - **ASNs / geo hints**: N/A
    - **suspected_staging indicators**: Malware file URLs: `dl/4251293b2d3765833f16988c2dbec30362df1c84dfe33c58dcc0815596d31353.raw`, `dl/9a56e2c761e10156cac6589bc9e929b1b8b5b00dd6c79ca0d33c2399b88e3a43.raw`, `dl/9bc28777e722c46898754ef256d052e9cd684f6ad812d69878c68ba6cc0c72fe.raw`. Possible malware distribution/staging host.
    - **suspected_c2 indicators**: N/A
    - **confidence**: Medium (due to tool errors preventing full correlation of IP to specific malware hashes)
    - **operational notes**: Investigate tool issues to correlate source IPs to specific malware file hashes and look for associated commands/inputs.

## 7) Odd-Service / Minutia Attacks
- **item_id**: Nintendo3DS_Minecraft_Probe
    - **service_fingerprint**: dest_port: 25565 (Minecraft Java Edition default port), OS: Nintendo 3DS
    - **why it’s unusual/interesting**: Official "Minecraft: New Nintendo 3DS Edition" lacks online multiplayer and does not utilize port 25565. The observed telemetry (Nintendo 3DS OS connecting to port 25565, plus one source IP on a Spamhaus DROP list) is highly incongruent with legitimate Nintendo 3DS Minecraft activity, strongly suggesting unusual or malicious intent. This behavior is not publicly documented as a known exploit or common scanning pattern for legitimate Nintendo 3DS devices.
    - **evidence summary**: Two distinct source IPs (176.65.149.219, 51.15.34.47) detected by P0f as 'Nintendo 3DS' OS, both attempting to connect to destination port 25565. Deep investigation showed activity from 176.65.149.219 also triggered a Suricata alert for "ET DROP Spamhaus DROP Listed Traffic Inbound group 33."
    - **confidence**: High
    - **recommended monitoring pivots**: Investigate raw packets for this traffic (if tools allow) to confirm protocol and payload. Explore OSINT for Nintendo 3DS exploits targeting non-standard services or vulnerabilities related to game consoles.

## 8) Known-Exploit / Commodity Exclusions
- **VNC/RDP Scanning**: Widespread scanning activity indicated by "GPL INFO VNC server response" (2020 counts) and "ET SCAN MS Terminal Server Traffic on Non-standard Port" (611 counts). These are commodity network reconnaissance activities seen across many IPs, particularly from DigitalOcean and JSC Selectel ASNs.
- **Credential Noise**: Brute-force/credential stuffing attempts targeting common usernames ('admin', 'user', 'sol') and numerical passwords, indicative of automated login attempts.
- **Web Vulnerability Scanning**: A single source IP (78.153.140.149) accessing the `/.env` path on the Tanner honeypot, a common indicator of automated web vulnerability scanning for sensitive configuration files.

## 9) Infrastructure & Behavioral Classification
- **VNC/RDP Scanning**: Scanning, Spray campaign, Infra reuse indicators (DigitalOcean, Selectel ASNs).
- **Adbhoney Malware Distribution**: Exploitation (malware delivery), Unknown campaign shape, Suspected staging infrastructure.
- **Nintendo3DS Minecraft Probe**: Scanning/reconnaissance, Spray campaign, Odd-service fingerprint (Nintendo 3DS OS on Minecraft port).
- **Emerging n-day CVE alerts**: Scanning/reconnaissance for known n-day vulnerabilities.
- **Credential Noise**: Brute-force/scanning.
- **Web Path Scanning (`/.env`)**: Scanning.

## 10) Evidence Appendix
- **VNC_RDP_Scanning_Campaign**
    - **Source IPs with counts**: 129.212.188.196 (263), 129.212.179.18 (261), 5.182.4.39 (162), 188.246.224.186 (158), 188.246.224.87 (130)
    - **ASNs with counts**: ASN 14061 (DigitalOcean, LLC) - 1200, ASN 49505 (JSC Selectel) - 505
    - **Target ports/services**: 5926, 5925, 5902 (VNC), non-standard RDP ports.
    - **Payload/artifact excerpts**: "GPL INFO VNC server response", "ET SCAN MS Terminal Server Traffic on Non-standard Port"
    - **Temporal checks**: Unavailable (activity observed throughout the investigation window)
- **Adbhoney_Malware_Distribution**
    - **Source IPs with counts**: 165.245.183.230 (observed interacting during malware downloads)
    - **Target ports/services**: Adbhoney (implied port 5555)
    - **Payload/artifact excerpts**: Malware file hashes: `dl/4251293b2d3765833f16988c2dbec30362df1c84dfe33c58dcc0815596d31353.raw`, `dl/9a56e2c761e10156cac6589bc9e929b1b8b5b00dd6c79ca0d33c2399b88e3a43.raw`, `dl/9bc28777e722c46898754ef256d052e9cd684f6ad812d69878c68ba6cc0c72fe.raw`
    - **Staging indicators**: Malware file URLs.
    - **Temporal checks**: Unavailable (activity observed throughout the investigation window)
- **Nintendo3DS_Minecraft_Probe**
    - **Source IPs with counts**: 176.65.149.219, 51.15.34.47
    - **ASNs with counts**: ASN 51396 (Pfcloud UG), ASN 12876 (Scaleway S.a.s.)
    - **Target ports/services**: 25565 (Minecraft Java Edition default port)
    - **Payload/artifact excerpts**: P0f OS: 'Nintendo 3DS'. Suricata alert: 'ET DROP Spamhaus DROP Listed Traffic Inbound group 33' (for 176.65.149.219).
    - **Temporal checks**:
        - `176.65.149.219`: First seen: `2026-03-02T19:19:12.000Z`, Last seen: `2026-03-02T19:29:48.125Z`
        - `51.15.34.47`: First seen: `2026-03-02T18:45:53.893Z`, Last seen: `2026-03-02T18:57:41.500Z`

## 11) Indicators of Interest
- **Source IPs**:
    - `129.212.188.196` (VNC/RDP scanning)
    - `129.212.179.18` (VNC/RDP scanning)
    - `5.182.4.39` (VNC/RDP scanning)
    - `188.246.224.186` (VNC/RDP scanning)
    - `188.246.224.87` (VNC/RDP scanning)
    - `165.245.183.230` (Adbhoney malware distribution)
    - `176.65.149.219` (Nintendo 3DS probe, Spamhaus listed)
    - `51.15.34.47` (Nintendo 3DS probe)
    - `78.153.140.149` (Web path scanning)
- **Malware Hashes (Adbhoney staging)**:
    - `dl/4251293b2d3765833f16988c2dbec30362df1c84dfe33c58dcc0815596d31353.raw`
    - `dl/9a56e2c761e10156cac6589bc9e929b1b8b5b00dd6c79ca0d33c2399b88e3a43.raw`
    - `dl/9bc28777e722c46898754ef256d052e9cd684f6ad812d69878c68ba6cc0c72fe.raw`
- **Target Ports**: 25565 (Minecraft), 5902, 5925, 5926 (VNC), 22 (SSH), 25 (SMTP).
- **Paths/Endpoints**: `/.env`

## 12) Backend Tool Issues
- **Tool**: `kibanna_discover_query`
    - **Reason**: `illegal_argument_exception` (Expected text at 1:71 but found START_ARRAY)
    - **Context**: Occurred during attempts to retrieve raw Adbhoney events by malware file hash and by `type.keyword: Adbhoney`.
    - **Weakened conclusions**: Weakened ability to directly correlate Adbhoney malware files with specific source IPs and detailed event context.
- **Tool**: `match_query`
    - **Reason**: `illegal_argument_exception` (Expected text at 1:26 but found START_ARRAY)
    - **Context**: Occurred during an attempt to retrieve raw events for `src_ip.keyword: 165.245.183.230`.
    - **Weakened conclusions**: Prevented detailed inspection of events associated with the Adbhoney malware distribution IP.
- **Tool**: `complete_custom_search`
    - **Reason**: `parsing_exception` (Expected [START_OBJECT] but found [VALUE_STRING])
    - **Context**: Occurred during attempts to use custom queries to link source IPs to Adbhoney malware files and to get top IPs for VNC signatures.
    - **Weakened conclusions**: Significantly impacted the ability to perform complex aggregations for deeper infrastructure mapping and exploitation analysis.
- **Agent**: `CandidateLoopReducerAgent`
    - **Reason**: Received a validation step with `candidate_id=None` despite `has_candidate=True`.
    - **Context**: During candidate validation loop processing.
    - **Weakened conclusions**: Indicates a workflow failure in passing candidate context, potentially blocking further validation steps or misrepresenting validation outcomes.

## 13) Agent Action Summary (Audit Trail)

- **agent_name**: ParallelInvestigationAgent (and its sub-agents: BaselineAgent, KnownSignalAgent, CredentialNoiseAgent, HoneypotSpecificAgent)
    - **purpose**: Gather initial baseline, known signal, credential noise, and honeypot-specific telemetry.
    - **inputs_used**: Initial time window for the investigation.
    - **actions_taken**: Executed various `get_*` and honeypot-specific tools to collect data on total attacks, top countries, source IPs, ASNs, port activity, alert signatures, CVEs, credential attempts, and honeypot interactions (Redis, Adbhoney, Tanner, Conpot).
    - **key_results**: Identified 3184 total attacks, top attacking countries and ASNs (DigitalOcean, Selectel), prevalent VNC/RDP scanning, low-count CVEs, common credential stuffing, Adbhoney malware downloads, Tanner web path access (/.env), and detection of Nintendo 3DS OS activity.
    - **errors_or_gaps**: No direct tool errors reported by these sub-agents.

- **agent_name**: CandidateDiscoveryAgent
    - **purpose**: Aggregate initial findings, identify potential attack candidates, and perform initial grouping/classification.
    - **inputs_used**: `baseline_result`, `known_signals_result`, `credential_noise_result`, `honeypot_specific_result`.
    - **actions_taken**: Synthesized `triage_summary`. Identified and initially classified candidates into `known_exploit_exclusions`, `botnet_campaign_mapping`, `odd_service_minutia_attacks`, and `suspicious_unmapped_monitor`. Attempted detailed data retrieval and aggregation queries using `kibanna_discover_query`, `discover_by_keyword`, `two_level_terms_aggregated`, `match_query`, `p0f_os_search`, and `complete_custom_search`.
    - **key_results**: Identified VNC/RDP scanning as commodity activity, Adbhoney malware distribution, an unusual Nintendo 3DS probe targeting Minecraft, and several known CVEs for monitoring.
    - **errors_or_gaps**: `degraded_mode: true` due to persistent `illegal_argument_exception` and `parsing_exception` errors across several detailed query tools (`kibanna_discover_query`, `match_query`, `complete_custom_search`), blocking granular evidence correlation.

- **agent_name**: CandidateValidationLoopAgent
    - **purpose**: Validate identified candidates based on defined criteria.
    - **inputs_used**: Candidate queue data (implicitly from `CandidateLoopControllerAgent`).
    - **actions_taken**: Attempted to load and process a candidate for validation.
    - **key_results**: Failed to process a valid candidate, reporting "No current candidate to validate."
    - **errors_or_gaps**: `candidate_id` was `None` despite `has_candidate` being `True` in the queue, indicating a failure in the candidate loading mechanism. Validation was blocked for the first attempted candidate.

- **agent_name**: CandidateLoopReducerAgent
    - **purpose**: Consolidate results from candidate validation steps.
    - **inputs_used**: Output from CandidateValidationAgent.
    - **actions_taken**: Appended one provisional error result to the validated candidates list.
    - **key_results**: Recorded 1 validated candidate, which was an error entry due to missing candidate context.
    - **errors_or_gaps**: Received a validation step with an invalid candidate context (`candidate_id=None`), leading to a provisional error.

- **agent_name**: DeepInvestigationLoopController
    - **purpose**: Orchestrate deep investigation steps for high-signal leads.
    - **inputs_used**: Leads from CandidateDiscoveryAgent, deep investigation state.
    - **actions_taken**: Initiated one iteration of deep investigation.
    - **key_results**: Successfully controlled the `DeepInvestigationAgent` to pursue one lead.
    - **errors_or_gaps**: Exited loop after one iteration with `loop_exit_requested`, indicating no further leads were generated or pursued within this loop.

- **agent_name**: DeepInvestigationAgent
    - **purpose**: Perform in-depth investigation of specific high-signal leads.
    - **inputs_used**: Lead: `odd_service_minutia_attacks:Nintendo3DS_Minecraft_Probe`, time window.
    - **actions_taken**: Performed targeted queries including `first_last_seen_src_ip`, `events_for_src_ip`, `suricata_signature_samples`, `discover_by_keyword`, and `two_level_terms_aggregated` for IPs associated with the Nintendo 3DS probe.
    - **key_results**: Confirmed Nintendo 3DS OS for two IPs targeting port 25565, identified one IP on a Spamhaus DROP list, and gathered temporal data.
    - **errors_or_gaps**: No explicit tool errors during its queries, but noted a limitation in extracting raw protocol or payload details.

- **agent_name**: OSINTAgent
    - **purpose**: Conduct external intelligence gathering to contextualize findings and assess knownness/novelty.
    - **inputs_used**: Candidate IDs and associated search terms derived from CandidateDiscoveryAgent output.
    - **actions_taken**: Executed multiple `search` queries for VNC/RDP scanning patterns, Adbhoney malware, Nintendo 3DS Minecraft activity, and specific CVEs (CVE-2025-55182, CVE-2024-14007, CVE-2021-3449, CVE-2019-11500).
    - **key_results**: Confirmed VNC/RDP scanning is commodity. Corroborated Adbhoney malware distribution. Established that observed Nintendo 3DS Minecraft activity is highly unusual for legitimate devices. Provided detailed public context for all low-count CVEs, confirming their knownness and impact.
    - **errors_or_gaps**: No tool errors reported by this agent.

- **agent_name**: ReportAgent (Self)
    - **purpose**: Compile the final report from workflow state outputs.
    - **inputs_used**: All available workflow state outputs (`investigation_start`, `investigation_end`, `baseline_result`, `known_signals_result`, `credential_noise_result`, `honeypot_specific_result`, `candidate_discovery_result`, `validated_candidates`, `osint_validation_result`, deep investigation logs/state).
    - **actions_taken**: Compiled the comprehensive markdown report as specified.
    - **key_results**: The completed final report.
    - **errors_or_gaps**: None for this agent's actions, but reported on the errors/gaps of other agents.

- **agent_name**: SaveReportAgent
    - **purpose**: Save the final report content to a file.
    - **inputs_used**: The compiled report text.
    - **actions_taken**: Executed `investigation_write_file`.
    - **key_results**: File successfully written.
    - **errors_or_gaps**: None.
