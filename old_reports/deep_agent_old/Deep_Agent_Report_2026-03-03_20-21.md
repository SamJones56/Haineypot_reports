# Investigation Report: 2026-03-03T20:00:05Z to 2026-03-03T21:00:05Z

## 1) Investigation Scope
- investigation_start: 2026-03-03T20:00:05Z
- investigation_end: 2026-03-03T21:00:05Z
- completion_status: Partial
- degraded_mode: true
- degraded_mode_reason: Tool failures (`kibanna_discover_query` and `match_query`) prevented full raw payload analysis for key findings, impacting the completeness of infrastructure mapping and exploit detail. The deep investigation loop also exited prematurely, leaving some leads uninvestigated.

## 2) Executive Triage Summary
- High volume of VNC (ports 5925, 5926, etc.) and SMB (port 445) related activity observed.
- Confirmed N-day exploitation of DoublePulsar Backdoor (associated with EternalBlue/CVE-2017-0144) from Paraguay.
- Confirmed N-day exploitation of RealVNC Authentication Bypass (CVE-2006-2369) from multiple IPs in the US and Australia.
- Significant web application reconnaissance targeting sensitive configuration files (`.env`, `.aws-secrets`) and known vulnerable paths from various sources.
- Noteworthy interaction with Kamstrup ICS protocols on a Conpot honeypot, indicating niche industrial control system probing.
- Substantial credential brute-force noise and commodity scanning activity.
- Major uncertainties remain regarding the full payload details and potential C2 for the DoublePulsar activity due to tool errors during deep investigation.

## 3) Candidate Discovery Summary
- Total attacks: 4326
- Top services of interest: VNC (ports 5926, 5925, 5902), SMB (port 445), HTTP (port 80), ICS (Kamstrup protocols).
- Top known signals: GPL INFO VNC server response (2634), ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication (457), ET SCAN MS Terminal Server Traffic on Non-standard Port (271), ET INFO Request to Hidden Environment File - Inbound (90), ET EXPLOIT VNC Server Not Requiring Authentication (case 2) (24), CVE-2006-2369 (24).
- Credential noise summary: Frequent brute-force attempts with common usernames (admin, root, user) and passwords (123456, admin, empty) observed.
- Honeypot specific summary: Tanner honeypot observed requests for sensitive web application paths like `/.env` and `/.aws-secrets`. Conpot honeypot recorded interactions with Kamstrup management and standard protocols.
- Material effects: Discovery was successful, but subsequent validation was affected by tool errors.

## 4) Emerging n-day Exploitation

- **DoublePulsar Backdoor (CVE-2017-0144 / MS17-010)**
    - cve/signature mapping: ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication (signature_id: 2024766). Associated with CVE-2017-0144 (EternalBlue) based on OSINT.
    - Evidence summary: 457 occurrences of the DoublePulsar signature from source IP 186.16.211.126. Raw Dionaea and Suricata events confirm SMB activity.
    - Affected service/port: SMB/445
    - Confidence: High
    - Operational notes: This represents critical N-day exploitation. Unpatched SMBv1 systems are targets. Immediate patching of MS17-010 is essential.

- **RealVNC Authentication Bypass (CVE-2006-2369)**
    - cve/signature mapping: ET EXPLOIT VNC Server Not Requiring Authentication (case 2) (signature_id: 2100650). Directly mapped to CVE-2006-2369.
    - Evidence summary: 24 occurrences of the exploit signature. Multiple source IPs (e.g., 129.212.188.196, 129.212.179.18) from the US and Australia were observed targeting various VNC ports. OSINT confirms public exploits (e.g., Metasploit) for this vulnerability.
    - Affected service/port: VNC (e.g., ports 5926, 5925, 5902)
    - Confidence: High
    - Operational notes: Indicates active scanning and exploitation for known VNC vulnerabilities. Ensure VNC services are patched and require strong authentication to prevent unauthorized access.

## 5) Novel or Zero-Day Exploit Candidates (UNMAPPED ONLY, ranked)

- No novel exploit candidates were identified in this investigation window.

## 6) Botnet/Campaign Infrastructure Mapping

- **BCM-DOUBLEPULSAR-001 (DoublePulsar/EternalBlue Campaign)**
    - item_id: BCM-DOUBLEPULSAR-001
    - campaign_shape: Spray
    - suspected_compromised_src_ips: 186.16.211.126 (1029 total events)
    - ASNs / geo hints: ASN 23201, organization: Telecel S.A., country: Paraguay
    - suspected_staging indicators: None identified due to blocked raw payload analysis.
    - suspected_c2 indicators: None identified due to blocked raw payload analysis.
    - confidence: Moderate (High confidence in exploit identification, but supporting infrastructure details are provisional due to tool error.)
    - operational notes: Monitor IP 186.16.211.126 for continued activity. Manual inspection of raw logs for 186.16.211.126 is required to extract payload details and identify potential staging/C2.

- **BCM-VNC-EXPLOIT-001 (VNC Exploitation Campaign)**
    - item_id: BCM-VNC-EXPLOIT-001
    - campaign_shape: Spray
    - suspected_compromised_src_ips: 129.212.188.196 (264 events), 129.212.179.18 (262 events), 129.212.184.194 (113 events), 165.245.138.210 (106 events), 170.64.152.136 (106 events)
    - ASNs / geo hints: ASN 14061 (DigitalOcean, LLC, United States), ASN 396982 (Google LLC, United States)
    - suspected_staging indicators: None identified.
    - suspected_c2 indicators: None identified.
    - confidence: High
    - operational notes: Block identified source IPs. Implement network segmentation and egress filtering to limit VNC exposure. Ensure VNC services are updated and secured.

- **BCM-HTTP-ENV-SCAN-001 (Web Application Reconnaissance/Exploitation)**
    - item_id: BCM-HTTP-ENV-SCAN-001
    - campaign_shape: Spray
    - suspected_compromised_src_ips: 136.114.97.84 (326 events), 152.42.221.249 (304 events), 2.57.122.208 (111 events)
    - ASNs / geo hints: ASN 14061 (DigitalOcean, LLC), ASN 396982 (Google LLC). IP 2.57.122.208 is blacklisted.
    - suspected_staging indicators: Requests for known sensitive web application paths like `/.env`, `/.aws-secrets`, `/_asterisk/graph.php`, `/digium_phones/ajax.php`. OSINT confirms these paths are frequently targeted for information disclosure or exploitation.
    - suspected_c2 indicators: None directly identified; activity aligns with initial reconnaissance probes.
    - confidence: High
    - operational notes: Implement robust Web Application Firewall (WAF) rules to block requests for sensitive paths. Review web server configurations to prevent exposure of `.env` or similar files. Block listed IPs.

## 7) Odd-Service / Minutia Attacks

- **OSM-CONPOT-KAMSTRUP-001 (Kamstrup ICS Protocol Interaction)**
    - service_fingerprint: Protocols: `kamstrup_management_protocol`, `kamstrup_protocol`; App Hint: Conpot ICS honeypot.
    - why it’s unusual/interesting: Interactions with proprietary Industrial Control System (ICS) smart meter protocols (Kamstrup) are highly niche and often indicate targeted reconnaissance or attack against critical infrastructure.
    - evidence summary: 3 interactions with `kamstrup_management_protocol` and 1 with `kamstrup_protocol` observed on a Conpot honeypot. All events originated from IP 152.42.221.249.
    - confidence: Moderate
    - recommended monitoring pivots: Conduct a deep inspection of raw Conpot logs for 152.42.221.249 to identify specific commands or data exchanged. Broaden monitoring for other source IPs interacting with Kamstrup or other ICS/OT protocols.

## 8) Known-Exploit / Commodity Exclusions

- **VNC Scanning:** High volume VNC scanning activity, indicated by 'GPL INFO VNC server response' (2634 counts) and 'ET SCAN Potential VNC Scan 5900-5920' (1 count). Seen across multiple IPs in the United States and Australia.
- **SSH Scanning:** Commodity SSH scanning ('ET INFO SSH session in progress on Expected Port') with 44 occurrences, primarily from 2.57.122.208 (Romania) targeting port 22.
- **Credential Brute-forcing:** Widespread attempts to gain unauthorized access using common usernames (e.g., 'admin', 'root', 'user') and weak passwords (e.g., '123456', 'admin', empty string) across various services.

## 9) Infrastructure & Behavioral Classification

- **Exploitation vs. Scanning:**
    - DoublePulsar activity (SMB/445) and VNC exploitation (CVE-2006-2369) are confirmed exploitation attempts.
    - HTTP sensitive path requests are indicative of reconnaissance activity, likely preceding exploitation attempts.
    - Kamstrup ICS protocol interaction is considered probing/reconnaissance of a specialized service.
    - Other VNC/SSH scanning and credential brute-forcing are commodity scanning activities.
- **Campaign Shape:** The observed activity predominantly exhibits "spray" characteristics, where a limited number of source IPs target a wide range of potential services or vulnerabilities across different hosts.
- **Infra Reuse Indicators:**
    - ASN 14061 (DigitalOcean, LLC) and ASN 396982 (Google LLC) are frequently observed as hosting providers for attack infrastructure, participating in VNC exploitation and HTTP reconnaissance.
    - ASN 23201 (Telecel S.A., Paraguay) is a significant source for DoublePulsar exploitation.
    - One IP (2.57.122.208) involved in HTTP reconnaissance and SSH scanning is blacklisted, suggesting use of compromised or low-reputation infrastructure.
- **Odd-Service Fingerprints:** Direct interaction with Kamstrup management and standard protocols (ICS) via a Conpot honeypot highlights niche targeting.

## 10) Evidence Appendix

- **BCM-DOUBLEPULSAR-001 (DoublePulsar/EternalBlue Campaign)**
    - Source IPs: 186.16.211.126 (1029 total events; 457 DoublePulsar alerts)
    - ASNs: 23201 (Telecel S.A., Paraguay)
    - Target ports/services: 445/SMB
    - Paths/endpoints: N/A (SMB protocol)
    - Payload/artifact excerpts: Suricata 'ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication' signature. In-depth raw payload analysis was blocked due to tool error.
    - Staging indicators: None identified.
    - Temporal checks: Observed throughout the investigation window (first seen 2026-03-03T20:00:05.014Z, last seen 2026-03-03T21:00:05.982Z).
- **BCM-VNC-EXPLOIT-001 (VNC Exploitation Campaign)**
    - Source IPs: 129.212.188.196 (264 events), 129.212.179.18 (262 events), 129.212.184.194 (113 events), 165.245.138.210 (106 events), 170.64.152.136 (106 events)
    - ASNs: 14061 (DigitalOcean, LLC, United States), 396982 (Google LLC, United States)
    - Target ports/services: 5926, 5925, 5902, 5903, 5905, 5906, 5907, 5911, 5912, 5913 / VNC
    - Paths/endpoints: N/A (VNC protocol)
    - Payload/artifact excerpts: Suricata 'ET EXPLOIT VNC Server Not Requiring Authentication (case 2)' signature, CVE-2006-2369. Detailed payload content not retrieved due to tool error during deep investigation.
    - Staging indicators: None identified.
    - Temporal checks: Activity from 129.212.179.18: first seen 2026-03-03T20:00:06.057Z, last seen 2026-03-03T20:59:53.000Z. Other IPs observed consistently throughout the window.
- **BCM-HTTP-ENV-SCAN-001 (Web Application Reconnaissance/Exploitation)**
    - Source IPs: 136.114.97.84 (326 events), 152.42.221.249 (304 events), 2.57.122.208 (111 events)
    - ASNs: 14061 (DigitalOcean, LLC), 396982 (Google LLC)
    - Target ports/services: 80/HTTP
    - Paths/endpoints: `/.env`, `/.aws-secrets`, `////remote/login?lang=en`, `/_asterisk/graph.php`, `/assets`, `/assets/graph.php`, `/digium_phones/ajax.php`, `/recordings/graph.php`, `/recordings/index.php`.
    - Payload/artifact excerpts: HTTP GET requests targeting the listed paths. 'ET INFO Request to Hidden Environment File - Inbound' signature.
    - Staging indicators: None directly identified (reconnaissance probes).
    - Temporal checks: Activity observed consistently throughout the investigation window.
- **OSM-CONPOT-KAMSTRUP-001 (Kamstrup ICS Protocol Interaction)**
    - Source IPs: 152.42.221.249 (4 events)
    - ASNs: 14061 (DigitalOcean, LLC)
    - Target ports/services: N/A (Conpot ICS honeypot, protocol-based)
    - Paths/endpoints: N/A (protocol interaction)
    - Payload/artifact excerpts: Conpot interactions with `kamstrup_management_protocol` and `kamstrup_protocol`. Raw interaction details are not available in current outputs.
    - Staging indicators: None identified.
    - Temporal checks: Activity observed within the investigation window.

## 11) Indicators of Interest

- **Source IPs:**
    - 186.16.211.126 (DoublePulsar activity)
    - 129.212.188.196 (VNC exploitation)
    - 129.212.179.18 (VNC exploitation)
    - 136.114.97.84 (HTTP reconnaissance)
    - 152.42.221.249 (HTTP reconnaissance, Kamstrup ICS probing)
    - 2.57.122.208 (Blacklisted, HTTP reconnaissance, SSH scanning)
- **Target Ports/Protocols:**
    - 445/SMB (DoublePulsar)
    - 5900-5926/VNC (VNC Exploitation)
    - 80/HTTP (Web Reconnaissance)
    - Kamstrup management protocol (ICS probing)
    - Kamstrup protocol (ICS probing)
- **Paths/Endpoints:**
    - `/.env`
    - `/.aws-secrets`
    - `/_asterisk/graph.php`
    - `/digium_phones/ajax.php`
- **Suricata Signatures:**
    - 2024766: ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication
    - 2100650: ET EXPLOIT VNC Server Not Requiring Authentication (case 2)
    - 2031502: ET INFO Request to Hidden Environment File - Inbound
- **CVEs:**
    - CVE-2017-0144 (Associated with DoublePulsar)
    - CVE-2006-2369 (VNC authentication bypass)
    - CVE-2021-45461 (Associated with `/digium_phones/ajax.php` endpoint)

## 12) Backend Tool Issues

- **`kibanna_discover_query` failure:** During the validation of candidate BCM-DOUBLEPULSAR-001, the `kibanna_discover_query` tool failed with an `illegal_argument_exception: Expected text at 1:70 but found START_ARRAY`. This error prevented the retrieval of raw event payloads for detailed analysis, hindering the confirmation of staging/C2 indicators and full exploit details for the DoublePulsar activity.
- **`match_query` failure:** During the deep investigation of CVE-2006-2369 (part of BCM-VNC-EXPLOIT-001), the `match_query` tool failed with an `illegal_argument_exception: Expected text at 1:25 but found START_ARRAY`. This prevented comprehensive retrieval of raw events associated with the VNC exploit signature, limiting deeper analysis of the VNC exploitation campaign.
- **Deep Investigation Loop Early Exit:** The Deep Investigation loop (`DeepInvestigationLoopController`) exited prematurely (`stall_count: 1`, `loop_exit_requested`) after processing only two leads. This means several identified source IPs (e.g., 129.212.184.194, 165.245.138.210, 170.64.152.136 for VNC exploitation, and IPs for HTTP reconnaissance) were not fully investigated, leading to a partial understanding of their specific activities and potential broader campaign scope.

## 13) Agent Action Summary (Audit Trail)

- **BaselineAgent**
    - Purpose: Establish basic activity metrics for the investigation window.
    - Inputs used: investigation_start, investigation_end
    - Actions taken: `get_report_time`, `get_total_attacks`, `get_top_countries`, `get_attacker_src_ip`, `get_country_to_port`, `get_attacker_asn`.
    - Key results: Identified 4326 total attacks; top countries US (1768), Paraguay (1029); top source IP 186.16.211.126 (1029); top ASN DigitalOcean (1520).
    - Errors or gaps: None.
- **KnownSignalAgent**
    - Purpose: Identify and categorize known attack signatures, CVEs, and alert categories.
    - Inputs used: investigation_start, investigation_end
    - Actions taken: `get_alert_signature`, `get_cve`, `get_alert_category`, `suricata_lenient_phrase_search` (for "VNC").
    - Key results: Detected high volumes of 'GPL INFO VNC server response' (2634), 'DoublePulsar Backdoor installation communication' (457), 'MS Terminal Server Traffic' (271). Identified CVE-2006-2369 (24 counts).
    - Errors or gaps: None.
- **CredentialNoiseAgent**
    - Purpose: Identify common credential brute-force attempts and OS distributions.
    - Inputs used: investigation_start, investigation_end
    - Actions taken: `get_input_usernames`, `get_input_passwords`, `get_p0f_os_distribution`.
    - Key results: Identified common usernames ('admin', 'root') and passwords ('123456', 'admin') in brute-force attempts. Noted Windows NT kernel (12935) and Linux (7536) as top observed OS distributions.
    - Errors or gaps: None.
- **HoneypotSpecificAgent**
    - Purpose: Gather data from specific honeypot types for unique attack patterns.
    - Inputs used: investigation_start, investigation_end
    - Actions taken: `redis_duration_and_bytes`, `adbhoney_input`, `adbhoney_malware_samples`, `conpot_input`, `tanner_unifrom_resource_search`, `conpot_protocol`.
    - Key results: Tanner honeypot detected requests for `/.env` (2 counts) and `/.aws-secrets` (1 count). Conpot honeypot observed 3 interactions with `kamstrup_management_protocol` and 1 with `kamstrup_protocol`.
    - Errors or gaps: None.
- **CandidateDiscoveryAgent**
    - Purpose: Consolidate initial findings, identify high-signal candidates, and categorize known/novel threats.
    - Inputs used: baseline_result, known_signals_result, credential_noise_result, honeypot_specific_result
    - Actions taken: Merged results from upstream agents, performed initial threat scoring and categorization.
    - Key results: Identified 4 candidates for further validation: 3 botnet/campaign mappings (DoublePulsar, VNC exploit, HTTP ENV scan) and 1 odd-service minutia attack (Conpot Kamstrup). Categorized various activities into known exploit exclusions.
    - Errors or gaps: None.
- **CandidateValidationLoopAgent**
    - Purpose: Validate individual candidates through targeted queries and contextual enrichment.
    - Inputs used: BCM-DOUBLEPULSAR-001 candidate definition.
    - Actions taken: Ran 1 iteration. Validated BCM-DOUBLEPULSAR-001 by querying `events_for_src_ip` for 186.16.211.126, `suricata_cve_samples` for CVE-2017-0144, and attempting `kibanna_discover_query`.
    - Key results: Confirmed SMB activity and DoublePulsar signature from 186.16.211.126. Candidate BCM-DOUBLEPULSAR-001 marked as Provisional.
    - Errors or gaps: `kibanna_discover_query` failed, blocking full payload extraction and analysis.
- **DeepInvestigationLoopController**
    - Purpose: Conduct in-depth analysis on high-priority leads generated from candidate validation.
    - Inputs used: Initial leads related to BCM-VNC-EXPLOIT-001 (CVE-2006-2369, src_ip:129.212.188.196, src_ip:129.212.179.18).
    - Actions taken: Ran 2 iterations. Consumed 'cve:CVE-2006-2369' (using `suricata_cve_samples`, `events_for_src_ip`, `top_src_ips_for_cve`, `top_dest_ports_for_cve`, `search` for CVE details, attempted `match_query`) and 'src_ip:129.212.179.18' (using `events_for_src_ip`, `first_last_seen_src_ip`).
    - Key results: Confirmed VNC exploitation, correlated with CVE-2006-2369, and identified additional participating IPs. Added 4 new leads for other VNC source IPs to the queue.
    - Errors or gaps: `match_query` tool failed. The loop exited early due to an internal `loop_exit_requested` (stall_count: 1), leaving 4 leads uninvestigated.
- **OSINTAgent**
    - Purpose: Provide external threat intelligence and context for identified candidates.
    - Inputs used: Candidate IDs and associated search terms derived from other agents' results.
    - Actions taken: Performed 11 `search` tool calls covering DoublePulsar/EternalBlue, CVE-2006-2369, web sensitive paths (.env, .aws-secrets, etc.), reputation checks for several IPs, and Kamstrup protocol details.
    - Key results: Confirmed knownness and details for DoublePulsar (N-day malware family), CVE-2006-2369 (N-day CVE), and common web reconnaissance/exploitation patterns. Provided context on Kamstrup proprietary protocols and general smart meter vulnerabilities. Identified IP 2.57.122.208 as blacklisted.
    - Errors or gaps: Search for 152.42.221.249 as an ICS honeypot yielded no public confirmation.
- **ReportAgent**
    - Purpose: Compile final investigation report from all available workflow state outputs.
    - Inputs used: All preceding agent outputs (baseline_result, known_signals_result, credential_noise_result, honeypot_specific_result, candidate_discovery_result, validated_candidates, deep_investigation logs/state, osint_validation_result).
    - Actions taken: Synthesized and structured all collected information into the final report markdown.
    - Key results: Generated the comprehensive final report content.
    - Errors or gaps: None (report generation itself).
- **SaveReportAgent**
    - Purpose: Save the generated report to persistent storage.
    - Inputs used: The report content generated by ReportAgent.
    - Actions taken: Configured for downstream file write via `deep_agent_write_file`.
    - Key results: Report content prepared for saving.
    - Errors or gaps: Not applicable to this agent's current task (generating content).