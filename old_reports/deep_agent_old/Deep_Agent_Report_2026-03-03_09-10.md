# Honeypot Threat Report

## 1) Investigation Scope
- **investigation_start**: 2026-03-03T09:00:46Z
- **investigation_end**: 2026-03-03T10:00:46Z
- **completion_status**: Partial
- **degraded_mode**: true
  - **Reason**: Multiple backend query tool failures, particularly `kibanna_discover_query` and `two_level_terms_aggregated`, prevented comprehensive event correlation and detailed temporal analysis. This led to incomplete validation of some candidates and early termination of deep investigation, resulting in degraded evidence for certain findings.

## 2) Executive Triage Summary
- Observed 5234 total attacks, predominantly VNC and SSH scanning/brute-forcing.
- A notable Android cryptomining campaign ("UFO Miner") was detected via ADBHoney, involving malware installation and command execution from a Chinese IP (115.233.222.114). OSINT confirms this as an established Android cryptominer.
- The Conpot honeypot recorded interactions with the 'guardian_ast' industrial control system (ICS) protocol from an Iranian IP, suggesting specialized ICS reconnaissance. OSINT identified this as an emulation of a Veeder-Root TLS-350 ATG.
- Web application reconnaissance for sensitive `/.env` files was observed on a Tanner honeypot, identified as a common scanning technique.
- Significant credential stuffing attempts were logged across various services using common usernames and weak passwords.
- Multiple query tool failures impacted the ability to fully correlate specific events, particularly for temporal analysis and deep inspection of some artifacts like "Coinhive" and "Test" app hints.

## 3) Candidate Discovery Summary
A total of 5234 attacks were observed within the timeframe. Key activities include widespread VNC and SSH scanning/brute-forcing, Android malware deployment (ufo.miner) via ADBHoney, and reconnaissance targeting `.env` files on Tanner honeypots. Notably, the Conpot honeypot recorded interactions with the 'guardian_ast' industrial control system protocol from an Iranian IP, indicating potential specialized probing. High volume of commodity credential noise detected.

- **Total Attacks**: 5234
- **Top Services of Interest**:
    - VNC (ports 5926, 5925, 5902)
    - SSH (port 22)
    - ADB (Android Debug Bridge - inferred from ADBHoney activity)
    - Conpot (guardian_ast protocol, dest_port 10001)
    - HTTP/HTTPS (Tanner, for /.env path)
- **Top Known Signals**:
    - GPL INFO VNC server response (2524 counts)
    - SURICATA IPv4 truncated packet (412 counts)
    - SURICATA AF-PACKET truncated packet (412 counts)
- **Credential Noise Summary**: Significant credential stuffing attempts using common usernames ('root', 'wallet', 'admin') and weak/blank passwords ('', '123456', 'password').
- **Honeypot-Specific Summary**:
    - ADBHoney detected 'ufo.miner' installation and cleanup commands, along with several malware sample downloads, all linked to a single IP.
    - Conpot observed 5 interactions using the 'guardian_ast' protocol from an Iranian IP, including input `b'\\x01I20100'`.
    - Tanner recorded a request for the `/.env` path from a DigitalOcean IP, indicating web reconnaissance.
- **Missing Inputs/Errors**: Several `kibanna_discover_query` and `two_level_terms_aggregated` calls failed, impacting event correlation and detailed temporal analysis, particularly for Conpot and general keyword searches.

## 4) Emerging n-day Exploitation
(No specific emerging n-day exploitation identified and mapped to CVEs or novel signatures beyond known commodity activity during this window.)

## 5) Novel or Zero-Day Exploit Candidates (UNMAPPED ONLY, ranked)
(No novel or zero-day exploit candidates were identified after knownness checks and OSINT validation.)

## 6) Botnet/Campaign Infrastructure Mapping
- **item_id**: ADBHoney_UFO_Miner_Campaign
    - **campaign_shape**: fan-out
    - **suspected_compromised_src_ips**: 115.233.222.114 (Count: 35 Adbhoney events)
    - **ASNs / geo hints**: ASN 4134, Chinanet, China
    - **suspected_staging indicators**: Implied by malware download URLs (e.g., dl/51ad31d5be1e1099fee1d03c711c9f698124899cfc321da5c0c56f8c93855e57.raw) and coordinated commands.
    - **suspected_c2 indicators**: Coinhive (implied by OSINT, direct honeypot telemetry confirmation was blocked by tool failure).
    - **confidence**: High
    - **operational notes**: This is an active Android cryptomining campaign. Analyze downloaded malware samples for family identification and confirm C2 infrastructure. Monitor IP 115.233.222.114 for continued activity and broader campaign indicators.

## 7) Odd-Service / Minutia Attacks
- **item_id**: Conpot_Guardian_AST_Probe
    - **service_fingerprint**: guardian_ast protocol (TCP port 10001)
    - **why it’s unusual/interesting**: Emulates a Veeder-Root TLS-350 Automated Tank Gauge (ATG), an Industrial Control System (ICS) device. Attacks targeting ICS protocols are specialized and often precursors to targeted operations. The protocol is known to operate over unauthenticated Telnet.
    - **evidence summary**: 5 interactions observed on Conpot, including input `b'\\x01I20100'`. Source IP: 77.90.185.16 (Iran, ASN 213790, Limited Network LTD).
    - **confidence**: Medium (Provisional: true, as the specific impact of the command `b'\\x01I20100'` is not fully validated)
    - **recommended monitoring pivots**: Further investigation into the 'guardian_ast' protocol and the specific input `b'\\x01I20100'` for known vulnerabilities or exploit techniques. Monitor 77.90.185.16 for additional ICS-related scanning or attack patterns.

## 8) Suspicious Unmapped Activity to Monitor
- **item_id**: Tanner_Dot_Env_Recon
    - **service_fingerprint**: HTTP/HTTPS (Tanner honeypot), path `/.env`
    - **why it’s unusual/interesting**: Reconnaissance for `/.env` files is a common technique to discover sensitive environment variables (database credentials, API keys) in web applications. While common, its presence indicates targeted web app probing.
    - **evidence summary**: 1 request for `/.env` path. Source IP: 78.153.140.93 (DigitalOcean, LLC).
    - **confidence**: Low (Provisional: true, due to single event and common nature, but worth monitoring)
    - **recommended monitoring pivots**: Monitor 78.153.140.93 for further web application attacks or reconnaissance. Correlate with other web application honeypot data for broader campaign context.

## 9) Known-Exploit / Commodity Exclusions
- **VNC Scanning Campaign**: High volume of VNC scanning activity, evidenced by 2524 alerts for the `GPL INFO VNC server response` signature. Top destination ports include 5926, 5925, and 5902. Source IPs largely originate from DigitalOcean and Hetzner. This is commodity reconnaissance.
- **SSH Brute-Force**: Persistent brute-force attempts targeting SSH (port 22). This activity is common from various countries (e.g., Germany, United Kingdom) and utilizes frequently seen usernames such as 'root', 'wallet', and 'admin', alongside weak/blank passwords like '', '123456', and 'password'.
- **General Credential Noise**: Widespread attempts to compromise various services using common credentials, distinct from targeted SSH activity. This is evidenced by a broad distribution of top usernames (`root`, `wallet`, `admin`, `git`, `hadoop`) and weak passwords (`'', '123456', 'password', '12345', 'qwerty'`).

## 10) Infrastructure & Behavioral Classification
- **Exploitation vs. Scanning**:
    - ADBHoney activity related to "UFO Miner" is classified as **Exploitation/Malware Delivery** due to command execution and malware downloads.
    - Conpot 'guardian_ast' interaction is classified as **Reconnaissance** (specialized ICS probing).
    - Tanner '/.env' requests are classified as **Reconnaissance** (web application vulnerability scanning).
    - VNC and SSH activities are categorized as widespread **Scanning/Brute-forcing**.
- **Campaign Shape**:
    - The ADBHoney "UFO Miner" campaign exhibits a **fan-out** pattern, indicating an automated deployment of malware from a likely compromised or attacker-controlled source.
    - Other activities generally appear as broad **spray** scanning.
- **Infra Reuse Indicators**:
    - The attacker IP 115.233.222.114 (Chinanet, China) is consistently involved in ADBHoney activity, suggesting dedicated infrastructure for the UFO Miner campaign.
    - DigitalOcean (ASN 14061) is a significant source of overall attack traffic, including the `/ .env` reconnaissance and general scanning, indicating its use by multiple threat actors or broad scanning services.
- **Odd-Service Fingerprints**:
    - The `guardian_ast` protocol on TCP port 10001 is a distinct indicator of ICS-focused reconnaissance.

## 11) Evidence Appendix

### ADBHoney_UFO_Miner_Campaign
- **Source IPs with counts**: 115.233.222.114 (Total 35 Adbhoney events in 1h window)
- **ASNs with counts**: ASN 4134, Chinanet (China)
- **Target ports/services**: ADB (port 5555)
- **Paths/endpoints**: `/data/adbhoney/log/adbhoney.json`
- **Payload/artifact excerpts**:
    - Inputs: `pm path com.ufo.miner` (2), `am start -n com.ufo.miner/com.example.test.MainActivity` (1), `pm install /data/local/tmp/ufo.apk` (1), `ps | grep trinity` (1), `rm -f /data/local/tmp/ufo.apk` (1), `rm -rf /data/local/tmp/*` (1)
    - Malware hashes (filenames): `dl/51ad31d5be1e1099fee1d03c711c9f698124899cfc321da5c0c56f8c93855e57.raw` (4), `dl/9a56e2c761e10156cac6589bc9e929b1b8b5b00dd6c79ca0d33c2399b88e3a43.raw` (4), `dl/9bc28777e722c46898754ef256d052e9cd684f6ad812d69878c68ba6cc0c72fe.raw` (4), `dl/0d3c687ffc30e185b836b99bd07fa2b0d460a090626f6bbbd40a95b98ea70257.raw` (1), `dl/76ae6d577ba96b1c3a1de8b21c32a9faf6040f7e78d98269e0469d896c29dc64.raw` (1)
- **Staging indicators**: Implied by malware download URLs.
- **Temporal checks results**:
    - Current 1h window (ADBHoney events): 35 events.
    - Previous 30m window (ADBHoney events): 9 events.
    - IP 115.233.222.114 activity: First seen 2026-03-03T09:40:25Z, Last seen 2026-03-03T09:55:35Z.

### Conpot_Guardian_AST_Probe
- **Source IPs with counts**: 77.90.185.16 (5 events)
- **ASNs with counts**: ASN 213790, Limited Network LTD (Iran)
- **Target ports/services**: guardian_ast protocol (TCP port 10001)
- **Paths/endpoints**: `/data/conpot/log/conpot_guardian_ast.json`
- **Payload/artifact excerpts**: Input `b'\\x01I20100'`
- **Staging indicators**: N/A
- **Temporal checks results**: Unavailable (due to tool limitations for Conpot-specific temporal analysis)

### Tanner_Dot_Env_Recon
- **Source IPs with counts**: 78.153.140.93 (1 event)
- **ASNs with counts**: ASN 14061, DigitalOcean, LLC
- **Target ports/services**: HTTP/HTTPS (Tanner honeypot), path `/.env`
- **Paths/endpoints**: `/.env`
- **Payload/artifact excerpts**: HTTP GET request for `/.env`
- **Staging indicators**: N/A
- **Temporal checks results**: Unavailable (limited context due to single event and tool limitations)

## 12) Indicators of Interest
- **Source IPs**:
    - 115.233.222.114 (Chinanet, China) - ADBHoney UFO Miner campaign
    - 77.90.185.16 (Limited Network LTD, Iran) - Conpot Guardian_AST probing
    - 78.153.140.93 (DigitalOcean, LLC) - Tanner /.env reconnaissance
- **Malware Hashes (partial filenames)**:
    - `dl/51ad31d5be1e1099fee1d03c711c9f698124899cfc321da5c0c56f8c93855e57.raw`
    - `dl/9a56e2c761e10156cac6589bc9e929b1b8b5b00dd6c79ca0d33c2399b88e3a43.raw`
    - `dl/9bc28777e722c46898754ef256d052e9cd684f6ad812d69878c68ba6cc0c72fe.raw`
- **Paths/Endpoints**:
    - `/.env` (web application reconnaissance)
- **Payload/Command Fragments**:
    - `pm path com.ufo.miner` (ADBHoney)
    - `b'\\x01I20100'` (Conpot Guardian_AST)
- **Suspected C2/Infrastructure**:
    - Coinhive (suspected for UFO Miner, based on OSINT)

## 13) Backend Tool Issues
- **`kibanna_discover_query`**:
    - **Failures**: Multiple instances of `status_code: 400`, `error: 'illegal_argument_exception'`, `reason: 'Expected text at ... but found START_ARRAY'`.
    - **Affected Validations**:
        - Direct raw event inspection for `ufo.miner` related inputs and source IPs.
        - Comprehensive search for `Coinhive` payload activity.
        - Comprehensive search for `Test` app hint.
        - General searching by `type.keyword` (e.g., for Conpot events).
    - **Impact**: Weakened ability to inspect raw events, correlate specific indicators, and perform deeper analysis of certain leads.
- **`two_level_terms_aggregated`**:
    - **Failures**:
        - Returned no buckets for `malware_file.keyword` primary field and `src_ip.keyword` secondary field (type filter `Adbhoney`).
        - Returned no buckets for `conpot.protocol.keyword` and `path.keyword` (type filter `Conpot`).
        - Ineffective when attempting to filter by `geoip.country_name.keyword` and then aggregate `src_ip.keyword` or `dest_port` for specific countries (e.g., Iran), as `outer_size=1` limited output to only the top country (United States).
    - **Affected Validations**:
        - Direct correlation of malware sample hashes with specific source IPs.
        - Aggregation of Conpot path data by source IP.
        - Targeted aggregation of activities from specific countries (e.g., Iran).
    - **Impact**: Hindered detailed infrastructure mapping and behavioral analysis for specific items.
- **`discover_by_keyword`**:
    - **Failures**: Returned 0 hits for keyword 'ufo.miner', despite `adbhoney_input` showing related commands.
    - **Affected Validations**: Initial keyword-based discovery for 'ufo.miner' activity.
    - **Impact**: Required alternative methods to confirm 'ufo.miner' presence.
- **`timeline_counts`**:
    - **Failures**: Did not accurately pick up 'Conpot' type events for temporal analysis.
    - **Affected Validations**: Comprehensive temporal analysis for Conpot activities.
    - **Impact**: Limited temporal context for the `Conpot_Guardian_AST_Probe` finding.

## 14) Agent Action Summary (Audit Trail)

### ParallelInvestigationAgent
- **purpose**: Orchestrates parallel data collection across baseline, known signals, credential noise, and honeypot-specific sources.
- **inputs_used**: `investigation_start`, `investigation_end`
- **actions_taken**:
    - `BaselineAgent`: Called `get_total_attacks`, `get_top_countries`, `get_attacker_src_ip`, `get_country_to_port`, `get_attacker_asn`.
    - `KnownSignalAgent`: Called `get_alert_signature`, `get_cve`, `get_alert_category`, `suricata_lenient_phrase_search` (for VNC).
    - `CredentialNoiseAgent`: Called `get_input_usernames`, `get_input_passwords`, `get_p0f_os_distribution`.
    - `HoneypotSpecificAgent`: Called `redis_duration_and_bytes`, `adbhoney_input`, `adbhoney_malware_samples`, `conpot_input`, `tanner_unifrom_resource_search`, `conpot_protocol`.
- **key_results**: Gathered initial telemetry on attack volume, top countries/IPs/ASNs, known signatures, CVEs, credential noise, and specific honeypot interactions (ADBHoney, Conpot, Tanner, Redis).
- **errors_or_gaps**: None reported by this agent directly, but its outputs feed into subsequent agents that identified gaps.

### CandidateDiscoveryAgent
- **purpose**: Consolidates initial findings, identifies potential high-signal candidates, and performs initial checks for knownness and infrastructure mapping.
- **inputs_used**: `baseline_result`, `known_signals_result`, `credential_noise_result`, `honeypot_specific_result`
- **actions_taken**:
    - Merged results into a comprehensive context.
    - Identified initial candidate seeds based on honeypot activity and unusual patterns.
    - Performed `two_level_terms_aggregated` queries to link ADBHoney inputs/malware and Conpot protocols to source IPs.
    - Executed `kibanna_discover_query` to gather more details on specific IPs and honeypot types.
    - Performed `get_attacker_asn` for candidate IPs.
    - Ran `timeline_counts` for ADBHoney and Conpot for temporal analysis.
- **key_results**:
    - Identified "ADBHoney UFO Miner Campaign" (botnet mapping), "Conpot Guardian_AST Probe" (odd service), "Tanner Dot Env Recon" (suspicious unmapped).
    - Established initial infrastructure details for these candidates (src_IPs, ASNs, related inputs/malware).
    - Identified commodity VNC scanning and SSH brute-forcing for exclusion.
- **errors_or_gaps**:
    - `tool_errors_detected: true`, `degraded_mode: true`.
    - Multiple `kibanna_discover_query` calls failed due to `illegal_argument_exception: Expected text at ... but found START_ARRAY`.
    - `two_level_terms_aggregated` queries failed to link malware files to IPs and for Conpot paths.
    - `discover_by_keyword` for 'ufo.miner' yielded no results.
    - `timeline_counts` for Conpot activity was ineffective.
    - Blocked validations: comprehensive temporal analysis for Conpot/Tanner, direct malware-IP correlation.

### CandidateValidationLoopAgent
- **purpose**: Iteratively validates each candidate identified by the `CandidateDiscoveryAgent`.
- **inputs_used**: Candidate seed list (from `CandidateDiscoveryAgent` output)
- **actions_taken**:
    - **Iterations run**: 1 (validated `ADBHoney_UFO_Miner_Campaign`)
    - Called `kibanna_discover_query` to search for 'ufo.miner' and source IP (failed).
    - Called `suricata_lenient_phrase_search` for 'ufo.miner' and 'adb exploit' signatures.
    - Performed CVE check (implicit).
    - Used `append_validated_candidate` to store validated candidate.
- **key_results**:
    - Validated `ADBHoney_UFO_Miner_Campaign` as a botnet/campaign mapping with high confidence and Provisional: false.
    - Confirmed no known Suricata signatures or CVEs directly mapped to 'ufo.miner' activity.
- **errors_or_gaps**:
    - `kibanna_discover_query` failed for `ufo.miner` and specific src_ip with `illegal_argument_exception`.
    - Blocked validation: direct raw event inspection.

### DeepInvestigationLoopController
- **purpose**: Conducts in-depth investigation on high-signal leads generated during candidate discovery/validation.
- **inputs_used**: `ADBHoney_UFO_Miner_Campaign` lead (from `CandidateValidationLoopAgent`), `osint_validation_result` (implicitly used for context and new leads, though the agent itself doesn't explicitly *receive* osint_validation_result, it *uses* a search tool which mimics OSINT).
- **actions_taken**:
    - **Iterations run**: 5
    - Pursued `src_ip:115.233.222.114`: Used `events_for_src_ip` and `first_last_seen_src_ip` to confirm activity and extract raw details.
    - Pursued `artifact:ufo.miner`: Used `search` tool for malware analysis.
    - Pursued `payload:Coinhive`: Used `kibanna_discover_query` (failed).
    - Pursued `country:Iran`: Used `two_level_terms_aggregated` (ineffective).
    - Pursued `app_hint:Test`: Used `kibanna_discover_query` (failed).
- **key_results**:
    - Corroborated `ADBHoney_UFO_Miner_Campaign` details, confirmed IP 115.233.222.114 (Chinanet, China) and ADB port 5555.
    - OSINT confirmed "UFO Miner" as an Android cryptomining app using Coinhive, appearing as "Test" app.
    - Identified several new leads (countries, Coinhive, app_hint:Test).
- **errors_or_gaps**:
    - `stall_count`: 3, `exit_loop` requested.
    - Repeated `kibanna_discover_query` failures with `illegal_argument_exception` when searching for `Coinhive` and `Test`.
    - `two_level_terms_aggregated` was ineffective for targeted country-based analysis (Iran).
    - Blocked validations: Direct observation of Coinhive activity, targeted country analysis, specific app_hint correlation.

### OSINTAgent
- **purpose**: Validates candidates against public intelligence to determine knownness, recency, and novelty impact.
- **inputs_used**: `candidate_id`s, classification inputs for ADBHoney, Conpot, Tanner.
- **actions_taken**:
    - Performed `search` queries for "ufo.miner malware analysis", "guardian_ast protocol Conpot honeypot b'\\x01I20100'", and ".env file reconnaissance web application security".
- **key_results**:
    - Mapped "UFO Miner" to an established Android cryptominer family, reducing its novelty.
    - Mapped "guardian_ast" protocol to Conpot's Veeder-Root TLS-350 ATG emulation, reducing its novelty.
    - Mapped `/.env` reconnaissance to a known scanning technique, reducing its novelty.
    - Provided detailed notes for each mapping.
- **errors_or_gaps**: None reported.

### ReportAgent (self)
- **purpose**: Compiles the final report from aggregated workflow state outputs.
- **inputs_used**: `investigation_start`, `investigation_end`, `baseline_result`, `known_signals_result`, `credential_noise_result`, `honeypot_specific_result`, `candidate_discovery_result`, `validated_candidates` (from `CandidateLoopReducerAgent`), `deep investigation outputs` (from `DeepInvestigationAgent`), `osint_validation_result`.
- **actions_taken**: Compiled the report into the specified markdown format.
- **key_results**: Generated a comprehensive threat report.
- **errors_or_gaps**: None (compilation only, does not generate new data or encounter tool errors).

### SaveReportAgent
- **purpose**: Saves the completed report.
- **inputs_used**: Report content (from `ReportAgent`).
- **actions_taken**: (Implied: wrote the report to a file).
- **key_results**: Report file successfully saved.
- **errors_or_gaps**: None.
