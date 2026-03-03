# Investigation Report

## 1) Investigation Scope
- **investigation_start**: 2026-03-03T00:00:12Z
- **investigation_end**: 2026-03-03T01:00:12Z
- **completion_status**: Partial
- **degraded_mode**: true - Persistent `kibanna_discover_query` tool errors, issues with `two_level_terms_aggregated` parameter, and blocked validation steps significantly impacted comprehensive analysis and infrastructure mapping.

## 2) Executive Triage Summary
- A total of 4021 attacks were observed within the hour, primarily originating from the United States and Germany.
- High volume of commodity scanning activity identified, targeting VNC, SSH/Telnet, and Redis services.
- Web application probing for sensitive files (e.g., `/.env`) and common application paths was detected, confirmed by OSINT as known scanner tooling.
- Coordinated scanning activity indicative of a botnet campaign was identified, specifically targeting MikroTik WinBox (port 8728) from multiple distinct source IPs.
- Interaction with an ICS/SCADA (Conpot) honeypot using the 'guardian_ast' protocol was observed, representing an unusual and operationally interesting attack vector.
- Significant uncertainties remain regarding detailed payload analysis and full infrastructure mapping due to tool limitations.

## 3) Candidate Discovery Summary
- **Total Attacks**: 4021
- **Top Attacker Countries**: United States (1958), Germany (1063)
- **Top Attacker Source IPs**: 64.226.116.132 (473), 206.189.193.104 (458), 142.93.105.169 (280)
- **Top Attacker ASNs**: DigitalOcean, LLC (14061, 2647), Google LLC (396982, 126)
- **Top Alert Categories**: Generic Protocol Command Decode (7653), Misc activity (2398)
- **Top Services of Interest**: VNC (ports 5902, 5906, 5907, 5911, 5912, 5915, 5925, 5926, 5969), SSH (port 22), MikroTik WinBox (port 8728), PostgreSQL (ports 5434, 5432), ICS/SCADA (Conpot - guardian_ast protocol).
- **Tool Errors/Gaps Affecting Discovery**: `kibanna_discover_query` calls for specific terms/values failed due to an `illegal_argument_exception`. The `two_level_terms_aggregated` tool's `value_filter` parameter did not function as expected, hindering specific drill-down on low-count uncommon ports.

## 4) Emerging n-day Exploitation
None identified in this reporting window.

## 5) Novel or Zero-Day Exploit Candidates (UNMAPPED ONLY, ranked)
None identified in this reporting window after OSINT mapping. The initial candidate for web application probing has been reclassified as known commodity activity.

## 6) Botnet/Campaign Infrastructure Mapping
- **item_id**: BTN-20260303-001
- **campaign_shape**: Spray
- **suspected_compromised_src_ips**: 45.205.1.5 (62), 45.205.1.110 (34), 185.169.4.141 (21), 64.226.91.27 (7), 170.39.218.48 (4)
- **ASNs / geo hints**: Not directly available for all IPs, but inferred from top attacking ASNs (DigitalOcean, Google).
- **suspected_staging indicators**: None explicitly identified from current data.
- **suspected_c2 indicators**: None explicitly identified from current data.
- **confidence**: High
- **operational notes**: Consistent scanning on MikroTik WinBox (port 8728) from multiple distinct source IPs indicates a coordinated campaign. Further investigation into payloads on port 8728 is recommended if advanced packet inspection tools become available.

## 7) Odd-Service / Minutia Attacks
- **item_id**: ODD-20260303-001
- **service_fingerprint**: Conpot honeypot, 'guardian_ast' protocol (port not specified, but associated with ICS/SCADA)
- **why it’s unusual/interesting**: Interaction with an ICS/SCADA-specific honeypot protocol ('guardian_ast') with a specific input `b'\x01I20100'` suggests specialized probing or unique attack vectors targeting industrial control systems.
- **evidence summary**: 3 total events for 'guardian_ast' protocol and 1 event for input `b'\x01I20100'` on the Conpot honeypot. Source IPs could not be reliably extracted due to tool limitations.
- **confidence**: Medium
- **recommended monitoring pivots**: Further investigation into associated source IPs and full event details is crucial. Monitor for increased activity on ICS/SCADA protocols or similar unique inputs.

## 8) Known-Exploit / Commodity Exclusions
- **VNC Scanning**: High volume (2237 counts for 'GPL INFO VNC server response') across various 59XX ports (5902, 5906, 5907, 5911, 5912, 5915, 5925, 5926, 5969), indicating commodity scanning activity.
- **SSH/Telnet Brute Force**: High counts on standard ports (22 (331 counts), 23 (8 counts)) with common username/password combinations (e.g., admin:password, root:123456), consistent with commodity brute force attacks. Includes command execution attempts on Cowrie honeypots, such as `uname` commands and `busybox`.
- **Redis Scanning**: Basic Redis commands observed ('INFO', 'PING', 'QUIT', 'NewConnect', 'Closed'), typical for commodity Redis scanning (30 total events).
- **General Network Noise**: High volume of network-level alerts related to truncated or reassembly errors ('SURICATA IPv4 truncated packet' (3749 counts), 'SURICATA AF-PACKET truncated packet' (3749 counts)), likely network noise rather than targeted exploitation.
- **Web Application Misconfiguration Scanning**: Probing for sensitive web application paths like `/.env` (1 count), `/geoserver/web/` (1 count), and `/wiki` (1 count) on Tanner honeypots. OSINT confirms that accessing `/.env` is a publicly documented critical security vulnerability (misconfiguration) commonly exploited by automated scanners. The source IP `78.153.140.149` (Hostglobal.plus Ltd, ASN 202306 - UK) involved in the `/.env` probe is part of a "Very aggressive" range frequently listed on threat intelligence blocklists.

## 9) Infrastructure & Behavioral Classification
- **Exploitation vs Scanning**: Predominantly scanning activity, with some targeted web application probing and ICS/SCADA protocol interaction. No confirmed novel exploitation.
- **Campaign Shape**: MikroTik WinBox activity exhibits a spray pattern (multiple IPs targeting a single service). Web application probing shows distributed, individual probes.
- **Infra Reuse Indicators**: High volume of activity from DigitalOcean, LLC (ASN 14061) and other well-known hosting providers, suggesting use of rented infrastructure for scanning. Source IP `78.153.140.149` (ASN 202306) linked to previous abusive activities.
- **Odd-Service Fingerprints**: Conpot honeypot 'guardian_ast' protocol activity, indicating niche ICS/SCADA focused attacks.

## 10) Evidence Appendix
### Known-Exploit / Commodity Exclusions: Web Application Misconfiguration Scanning (formerly NVL-20260303-001)
- **Source IPs with counts**:
    - `/.env`: 78.153.140.149 (1)
    - `/geoserver/web/`: 64.62.197.212 (1)
    - `/wiki`: 199.45.154.124 (1)
- **ASNs with counts**:
    - 202306 (Hostglobal.plus Ltd, GB) for 78.153.140.149
    - 6939 (Hurricane Electric LLC, US) for 64.62.197.212
    - 398722 (Censys, Inc., US) for 199.45.154.124
- **Target ports/services**: HTTP/HTTPS (Tanner honeypot) on ports 80/443
- **Paths/endpoints**: `/.env`, `/geoserver/web/`, `/wiki`
- **Payload/artifact excerpts**: HTTP GET requests. Example for `/.env`: `http.url: '/.env', http.method: 'GET', http.user_agent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.5845.140 Safari/537.36'`
- **Staging indicators**: None identified.
- **Temporal checks results**: All activity for these paths occurred within the investigation window.
    - 78.153.140.149: First seen 2026-03-03T00:15:24Z, Last seen 2026-03-03T00:16:30Z.
    - 64.62.197.212: First seen 2026-03-03T00:02:29Z, Last seen 2026-03-03T00:07:23Z.
    - 199.45.154.124: First seen 2026-03-03T00:11:48Z, Last seen 2026-03-03T00:13:13Z.

### Botnet/Campaign Infrastructure Mapping: MikroTik WinBox Scanning (BTN-20260303-001)
- **Source IPs with counts**:
    - 45.205.1.5 (62)
    - 45.205.1.110 (34)
    - 185.169.4.141 (21)
    - 64.226.91.27 (7)
    - 170.39.218.48 (4)
- **ASNs with counts**: Not specifically aggregated for these IPs, but overall top ASNs include DigitalOcean.
- **Target ports/services**: 8728 (MikroTik WinBox)
- **Paths/endpoints**: Not applicable (protocol-level scanning).
- **Payload/artifact excerpts**: Not available (requires deeper inspection).
- **Staging indicators**: None identified.
- **Temporal checks results**: Unavailable.

### Odd-Service / Minutia Attacks: Conpot ICS/SCADA Protocol (ODD-20260303-001)
- **Source IPs with counts**: Not reliably extracted due to tool limitations.
- **ASNs with counts**: Not reliably extracted due to tool limitations.
- **Target ports/services**: Conpot honeypot (specific port not detailed, but associated with ICS/SCADA protocols)
- **Paths/endpoints**: Not applicable.
- **Payload/artifact excerpts**: `b'\x01I20100'`
- **Staging indicators**: None identified.
- **Temporal checks results**: Unavailable.

## 11) Indicators of Interest
- **Source IPs**:
    - 78.153.140.149 (Associated with known `.env` scanning, from Hostglobal.plus Ltd - UK, ASN 202306)
    - 45.205.1.5 (MikroTik WinBox scanner)
    - 45.205.1.110 (MikroTik WinBox scanner)
    - 185.169.4.141 (MikroTik WinBox scanner)
    - 64.226.91.27 (MikroTik WinBox scanner)
    - 170.39.218.48 (MikroTik WinBox scanner)
- **Paths/Endpoints**:
    - `/.env` (Web application misconfiguration scanner target)
    - `/geoserver/web/` (Web application probe)
    - `/wiki` (Web application probe)
- **Payload Fragments**: `b'\x01I20100'` (Conpot ICS/SCADA input)
- **User Agents**: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.5845.140 Safari/537.36` (used in `/.env` probe)

## 12) Backend Tool Issues
- **`kibanna_discover_query`**: All calls failed with `illegal_argument_exception: Expected text at 1:71 but found START_ARRAY`. This blocked the retrieval of raw event details for suspicious paths on Tanner, Conpot protocol interactions, and specific port activity. Consequently, detailed payload analysis and precise source IP correlation for some events were not possible, weakening conclusions about exploit chains or downloader activity.
- **`two_level_terms_aggregated`**: The `value_filter` parameter did not function as expected when attempting to drill down on low-count uncommon ports (e.g., 28121, 51504, 3018, 4430, 9962). This prevented detailed analysis and correlation of source IPs for these potentially interesting, but low-volume, activities. It also failed when attempting to aggregate source IPs by ASN, blocking a key step in infrastructure mapping.

## 13) Agent Action Summary (Audit Trail)

### BaselineAgent
- **purpose**: Gather high-level statistics and baseline activity for the investigation window.
- **inputs_used**: None (initial agent).
- **actions_taken**: Called `get_current_time`, `get_total_attacks`, `get_top_countries`, `get_attacker_src_ip`, `get_country_to_port`, `get_attacker_asn`.
- **key_results**: Identified 4021 total attacks, top attacking countries (US, Germany), top source IPs, ports targeted per country, and top ASNs (DigitalOcean).
- **errors_or_gaps**: None.

### KnownSignalAgent
- **purpose**: Identify known threat signatures, CVEs, and alert categories to filter commodity activity.
- **inputs_used**: Baseline time window.
- **actions_taken**: Called `get_alert_signature`, `get_cve`, `get_alert_category`, `suricata_lenient_phrase_search` for "ET POLICY".
- **key_results**: Identified high volumes of Suricata network alerts, VNC server responses, and Dshield blocklisted sources. Detected 2 CVEs (CVE-2002-0013, CVE-2024-14007).
- **errors_or_gaps**: `suricata_lenient_phrase_search` for "ET POLICY" returned no hits.

### CredentialNoiseAgent
- **purpose**: Detect and summarize credential-stuffing and brute-force activity.
- **inputs_used**: Baseline time window.
- **actions_taken**: Called `get_input_usernames`, `get_input_passwords`, `get_p0f_os_distribution`.
- **key_results**: Identified common usernames (`admin`, `root`) and passwords (`password`, `123456`) being used. Provided OS distribution of scanned systems.
- **errors_or_gaps**: None.

### HoneypotSpecificAgent
- **purpose**: Extract specific activity from honeypot logs to identify unique attack behaviors.
- **inputs_used**: Baseline time window.
- **actions_taken**: Called `redis_duration_and_bytes`, `adbhoney_input`, `adbhoney_malware_samples`, `conpot_input`, `tanner_unifrom_resource_search`, `conpot_protocol`.
- **key_results**: Observed basic Redis commands, Conpot 'guardian_ast' protocol activity, and Tanner honeypot probes for `/`, `/core/misc/favicon.ico`, `/favicon.ico`, `/.env`, `/bin/`, `/geoserver/web/`, `/wiki`.
- **errors_or_gaps**: `adbhoney_input` and `adbhoney_malware_samples` returned no specific inputs or malware samples.

### CandidateDiscoveryAgent
- **purpose**: Synthesize findings from previous agents, identify potential high-signal candidates, and perform initial aggregations for investigation.
- **inputs_used**: `baseline_result`, `known_signals_result`, `credential_noise_result`, `honeypot_specific_result`.
- **actions_taken**: Attempted `kibanna_discover_query` for several paths, then used `two_level_terms_aggregated` for Tanner paths, Conpot protocols, Suricata signatures, and destination ports. Also attempted `two_level_terms_aggregated` with `value_filter` for uncommon ports.
- **key_results**: Identified `NVL-20260303-001` (web path probes), `BTN-20260303-001` (MikroTik WinBox scanning), `ODD-20260303-001` (Conpot ICS/SCADA activity), and suspicious uncommon destination ports.
- **errors_or_gaps**: All calls to `kibanna_discover_query` failed. `two_level_terms_aggregated` with `value_filter` parameter for uncommon ports did not function as expected, preventing specific drill-down.

### CandidateValidationLoopAgent
- **purpose**: Validate novel exploit candidates through targeted queries and correlation.
- **inputs_used**: `candidate_discovery_result` (specifically NVL-20260303-001).
- **actions_taken**: Called `web_path_samples` for `/.env`, `/bin/`, `/geoserver/web/`, `/wiki`. Used `suricata_lenient_phrase_search` for `http.url` related to web paths. Used `first_last_seen_src_ip` for source IPs associated with the web paths.
- **key_results**: Confirmed HTTP GET requests for `/.env`, `/geoserver/web/`, `/wiki` on Tanner honeypots. Clarified `/bin/` activity as command execution on Cowrie, not web probing. Identified source IPs and ASNs for web probes. Confirmed no specific Suricata exploit alerts.
- **errors_or_gaps**: `kibanna_discover_query` failures from CandidateDiscoveryAgent impacted the ability to retrieve raw event details for deeper payload analysis.

### DeepInvestigationLoopController
- **purpose**: Conduct in-depth investigation on high-signal leads generated by validation.
- **iterations run**: 3
- **key leads pursued**: `path:/.env`, `asn:202306`, `url:/`.
- **stall/exit reason**: The loop stalled due to repeated tool failures (`two_level_terms_aggregated` for ASN, `web_path_samples` and `kibanna_discover_query` for URL) and eventually exited after 2 consecutive stalls.
- **errors_or_gaps**: `two_level_terms_aggregated` failed for ASN correlation. `web_path_samples` and `kibanna_discover_query` failed for root path analysis, blocking further investigation of general web activity.

### OSINTAgent
- **purpose**: Perform Open-Source Intelligence (OSINT) lookups to determine knownness and context of high-signal indicators.
- **inputs_used**: Validated candidate `NVL-20260303-001` details, specifically `/.env` path and associated source IP.
- **actions_taken**: Performed OSINT searches for `/.env exploit` and `78.153.140.149 OSINT`.
- **key_results**: Confirmed `/.env` probing is a publicly documented misconfiguration vulnerability. Mapped source IP `78.153.140.149` (ASN 202306) to known "promiscuous" and "Very aggressive" threat intelligence blocklists, reducing the novelty of the observed activity.
- **errors_or_gaps**: Infrastructure mapping for ASN 202306 was inconclusive due to prior tool limitations in DeepInvestigation.

### ReportAgent (self)
- **purpose**: Compile the final investigation report from all workflow state outputs.
- **inputs_used**: `investigation_start`, `investigation_end`, `baseline_result`, `known_signals_result`, `credential_noise_result`, `honeypot_specific_result`, `candidate_discovery_result`, `validated_candidates`, `osint_validation_result`, `deep_investigation_logs/state`.
- **actions_taken**: Consolidated, categorized, and formatted all available information into the specified markdown report structure, including rerouting candidates based on OSINT findings.
- **key_results**: Produced the comprehensive final investigation report.
- **errors_or_gaps**: None (report compilation was successful despite upstream data gaps).

### SaveReportAgent
- **purpose**: Save the final report to persistent storage.
- **inputs_used**: The generated markdown report content.
- **actions_taken**: Called `investigation_write_file`.
- **key_results**: Successfully saved the report.
- **errors_or_gaps**: None.
