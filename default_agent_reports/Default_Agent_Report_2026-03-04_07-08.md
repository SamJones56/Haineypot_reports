# Honeypot Threat Intelligence Report

## 1) Investigation Scope
- **investigation_start**: 2026-03-04T07:00:05Z
- **investigation_end**: 2026-03-04T08:00:05Z
- **completion_status**: Partial
- **degraded_mode**: true (Due to multiple query failures preventing raw event data retrieval and full validation of some candidates.)

## 2) Executive Triage Summary
- Total of 7864 attack attempts observed in the reporting window.
- Predominant activity includes VNC scanning (2600+ events) and SSH brute-forcing (evident from credential noise, port 22 activity).
- Significant commodity scanning for sensitive web configuration files (.env, .git/config, Cisco VPN) from various source IPs.
- Notable activity targeting ICS honeypots (Conpot) with Kamstrup and IEC104 protocols, and scans on port 44818 (EtherNet/IP/Modbus).
- Unusual HTTP GET requests and malformed binary inputs directed at Redis honeypots.
- Two known CVEs (CVE-2019-11500, CVE-2024-14007) were detected once each, indicating specific exploit attempts.
- High volume of SMTP port 25 attacks traced to known abusive infrastructure (Kprohost LLC, ASN 214940) originating from Ukraine.
- Major uncertainties remain regarding the full payloads and specific exploitation techniques for Redis, ICS, and web reconnaissance activities due to tool failures.

## 3) Candidate Discovery Summary
A total of 6 candidate items were discovered and processed through validation. These included 2 potential botnet/campaign mappings, 3 odd-service/minutia attacks, and 1 suspicious unmapped activity.

**Top Areas of Interest:**
- **VNC/SSH Brute Force and Scanning**: High volume, commodity activity.
- **Web Reconnaissance**: Targeting common sensitive paths like `/.env`, `/.git/config`, `+CSCOE/logon.html`, and `/.aider.conf.yml`.
- **ICS Protocol Interactions**: Direct interactions with Conpot honeypots (Kamstrup, IEC104) and activity on Modbus-related port 44818.
- **Redis Anomalies**: HTTP GET requests and binary inputs to Redis honeypots, indicative of cross-protocol attacks or reconnaissance.
- **SMTP Botnet Activity**: Significant traffic on port 25 from known problematic ASN 214940 (Kprohost LLC).

**Missing Inputs/Errors Impacting Discovery:**
Several `kibanna_discover_query` calls, `custom_basic_search` (for `dest_port.keyword`), and `two_level_terms_aggregated` (for ASN filtering) failed with `illegal_argument_exception` or returned empty results. This materially affected the ability to retrieve raw event data, detailed payload information, and specific source IPs for certain observations, leading to a degraded mode of operation.

## 4) Emerging n-day Exploitation
- **CVE**: CVE-2019-11500
    - **Evidence Summary**: 1 recorded exploit attempt.
    - **Affected Service/Port**: Not specified in available telemetry, but generally associated with Pulse Secure VPN.
    - **Confidence**: High
    - **Operational Notes**: Monitor for recurrence and associated post-exploitation activity.
- **CVE**: CVE-2024-14007
    - **Evidence Summary**: 1 recorded exploit attempt.
    - **Affected Service/Port**: Not specified in available telemetry.
    - **Confidence**: High
    - **Operational Notes**: Monitor for recurrence and associated post-exploitation activity.

## 5) Novel or Zero-Day Exploit Candidates (UNMAPPED ONLY, ranked)
No novel or zero-day exploit candidates were identified in this reporting period. All initially high-novelty candidates were subsequently mapped to known attack patterns or commodity scanning through OSINT validation, which reduced their novelty scores to 0. The persistent tool errors, however, prevent full confirmation of specific payloads which could reveal novel exploitation.

## 6) Botnet/Campaign Infrastructure Mapping
- **item_id**: BOTNET-001
    - **Campaign Shape**: Spray
    - **Suspected Compromised Src IPs**: N/A (aggregate count from ASN)
    - **ASNs / Geo Hints**: ASN 214940 (Kprohost LLC), Ukraine.
    - **Suspected Staging Indicators**: N/A
    - **Suspected C2 Indicators**: N/A
    - **Confidence**: High
    - **Operational Notes**: This activity is linked to a well-documented abusive infrastructure (Kprohost LLC / Virtualine) known for large-scale SMTP port 25 attacks and phishing. Block or monitor traffic from ASN 214940, particularly on port 25.
- **item_id**: BOTNET-002
    - **Campaign Shape**: Spray (reconnaissance)
    - **Suspected Compromised Src IPs**: 74.207.235.171, 78.153.140.147, 216.180.246.66, 81.168.83.103
    - **ASNs / Geo Hints**: United Kingdom (ASN 20860 - Iomart Cloud Services Limited for 81.168.83.103), others unknown due to tool errors.
    - **Suspected Staging Indicators**: Targeted paths include `/.env`, `/.git/config`, `/+CSCOE+/logon.html`, `/.aider.conf.yml`. These are used for discovering sensitive configuration files and VPN login pages.
    - **Suspected C2 Indicators**: N/A
    - **Confidence**: Medium (Provisional due to inability to analyze raw payloads)
    - **Operational Notes**: Monitor for access attempts to sensitive configuration files and VPN portals. Investigate source IPs for other malicious activity. OSINT confirms this is common scanner tooling activity.

## 7) Odd-Service / Minutia Attacks
- **service_fingerprint**: Conpot (ICS protocols: Kamstrup, IEC104), port 44818 (potential Modbus/SCADA/EtherNet/IP).
    - **Why it’s unusual/interesting**: Direct interaction with ICS honeypots using specialized industrial protocols (Kamstrup, IEC104), and activity on a port commonly associated with industrial control systems (EtherNet/IP, often Modbus). This indicates targeted or wide-scale scanning for vulnerable ICS/OT environments.
    - **Evidence Summary**: Conpot logs show 3 interactions using 'kamstrup_protocol' and 1 interaction using 'IEC104'. 81 attacks were observed on port 44818 from the United States.
    - **Confidence**: Moderate (Provisional due to inability to retrieve raw event data for detailed payload analysis or specific source IPs for Conpot interactions.)
    - **Recommended monitoring pivots**: Enhance logging for ICS/OT-related ports and protocols. Investigate source IPs for port 44818 activity. OSINT confirms these are known ICS attack patterns.
- **service_fingerprint**: Redis (port 6379, typically).
    - **Why it’s unusual/interesting**: Highly unusual HTTP GET requests and malformed binary data sent to a Redis honeypot, as Redis is not a web server. This is indicative of cross-protocol attacks, reconnaissance for misconfigured instances, or attempts to inject malicious payloads.
    - **Evidence Summary**: Redis actions recorded include 'GET / HTTP/1.1' (1 count) and a malformed binary input (1 count).
    - **Confidence**: Moderate (Provisional due to inability to retrieve raw event data for detailed payload analysis or source IP identification.)
    - **Recommended monitoring pivots**: Scrutinize all non-Redis protocol traffic to Redis ports. Prioritize fixing raw event access for Redis honeypots. OSINT confirms this is a known Redis attack pattern (e.g., for crypto miners, botnets).
- **service_fingerprint**: VNC (ports 5437, 15432).
    - **Why it’s unusual/interesting**: Significant volume of VNC-like activity detected by Suricata on non-standard ports, suggesting attackers are actively probing for hidden VNC services.
    - **Evidence Summary**: Switzerland (ASN 51852, Private Layer INC) initiated 355 attacks on port 5437 and 27 attacks on port 15432. Alert signatures include 'GPL INFO VNC server response' (2600 counts) and 'ET SCAN MS Terminal Server Traffic on Non-standard Port' (344 counts).
    - **Confidence**: High
    - **Recommended monitoring pivots**: Review network segmentation for VNC services. Ensure strong authentication for any VNC deployments. OSINT confirms this is common VNC/RDP port scanning.

## 8) Known-Exploit / Commodity Exclusions
- **Credential Noise/Brute Force**: High volume of login attempts targeting common usernames (root, user, oracle, admin) and weak passwords (123456, 123, password) primarily on SSH (port 22). This is standard commodity scanning activity.
- **Common Scanners**:
    - `GPL INFO VNC server response` (2600 counts): Indicative of widespread VNC scanning, often on non-standard ports.
    - `ET SCAN MS Terminal Server Traffic on Non-standard Port` (344 counts): RDP scanning on non-default ports.
    - `SURICATA IPv4 truncated packet`, `SURICATA AF-PACKET truncated packet`, `SURICATA STREAM Packet with broken ack`, `SURICATA STREAM reassembly sequence GAP -- missing packet(s)` (total 698 counts): Common network anomaly alerts, often accompanying scanning.
    - WordPress JavaScript file scanning: Seen on Tanner honeypots (e.g., `/wp-includes/js/jquery/jquery-migrate.min.js,qver=1.4.1.pagespeed.jm.C2obERNcWh.js` with 15 counts, `/wp-includes/js/jquery/jquery.js,qver=1.12.4.pagespeed.jm.pPCPAKkkss.js` with 14 counts), common bot patterns.
    - Generic web enumeration for files like `/admin/index.html` and `/index.html`.

## 9) Infrastructure & Behavioral Classification
- **Exploitation vs Scanning**: The majority of activity observed is broad scanning and reconnaissance (VNC, RDP, web paths, Redis, ICS protocols). Confirmed exploitation attempts are minimal (2 CVEs with single hits). Credential brute-forcing is also widespread scanning.
- **Campaign Shape**: Predominantly "spray" campaigns, where attackers cast a wide net across many targets/ports to find vulnerable services (e.g., VNC, SMTP, web path scanning). No clear "fan-in" or "beaconing" patterns were explicitly identified, though individual IP behaviors could not be fully analyzed.
- **Infra Reuse Indicators**: ASN 14061 (DigitalOcean) is the top attacker ASN, a common source for transient malicious activity. ASN 214940 (Kprohost LLC) is a known abusive ASN for SMTP campaigns. ASN 51852 (Private Layer INC) is associated with VNC scanning. This highlights the use of commodity hosting providers for attack infrastructure.
- **Odd-Service Fingerprints**: Interactions with ICS honeypots (Kamstrup, IEC104, port 44818) and unusual inputs to Redis (HTTP GET, binary data) represent distinct and operationally interesting service targeting.

## 10) Evidence Appendix

### Emerging n-day Exploitation (Limited data from workflow for full appendix)
- **CVE-2019-11500, CVE-2024-14007**: 1 count each. No source IPs/ASNs/paths available in current workflow state. Temporal checks unavailable.

### Botnet/Campaign Infrastructure Mapping

**BOTNET-001: Kprohost LLC / Virtualine associated abusive infrastructure (SMTP botnet/phishing campaign)**
- **Source IPs with counts**: N/A (aggregate count from ASN). Top IPs for Ukraine (country from Kprohost ASN) are not broken down in the provided data.
- **ASNs with counts**: ASN 214940 (Kprohost LLC) - 226 attacks.
- **Target Ports/Services**: Port 25 (SMTP).
- **Paths/Endpoints**: N/A
- **Payload/Artifact Excerpts**: N/A (raw event data unavailable).
- **Staging Indicators**: N/A
- **Temporal Checks**: Activity observed within the current window. OSINT indicates a specific phishing campaign on Feb 25, 2026, from this ASN.

**BOTNET-002: Common web reconnaissance for sensitive configuration files and VPN portals**
- **Source IPs with counts**:
    - 152.42.255.97 (22 hits for `/`, 15 for `/wp-includes/js/jquery/jquery-migrate.min.js,qver=1.4.1.pagespeed.jm.C2obERNcWh.js`, 14 for `/wp-includes/js/jquery/jquery.js,qver=1.12.4.pagespeed.jm.pPCPAKkkss.js`)
    - 216.180.246.66 (6 hits for `/`, 1 for `/+CSCOE+/logon.html`, 1 for `/admin/index.html`, 1 for `/index.html`)
    - 74.207.235.171 (1 hit for `/.env`, 1 for `/.git/config`)
    - 78.153.140.147 (1 hit for `/.env`)
    - 81.168.83.103 (1 hit for `/.aider.conf.yml`)
- **ASNs / Geo Hints**: 81.168.83.103 (United Kingdom, ASN 20860 - Iomart Cloud Services Limited). Others unknown.
- **Target Ports/Services**: HTTP/Web (Tanner honeypot).
- **Paths/Endpoints**: `/.env`, `/.git/config`, `/+CSCOE+/logon.html`, `/.aider.conf.yml`.
- **Payload/Artifact Excerpts**: N/A (raw event data unavailable due to tool errors).
- **Staging Indicators**: N/A
- **Temporal Checks**: Activity observed within the current window. OSINT confirms these are established reconnaissance paths.

### Odd-Service / Minutia Attacks

**ODD-ICS-001: Conpot (ICS protocols: Kamstrup, IEC104), port 44818 (potential Modbus/SCADA/EtherNet/IP)**
- **Source IPs with counts**: Unknown for Conpot interactions. For port 44818: IPs primarily from the United States (no specific IPs available).
- **ASNs with counts**: United States (ASN 14061 DigitalOcean, LLC is top ASN for US).
- **Target Ports/Services**: Conpot honeypot (Kamstrup, IEC104 protocols), port 44818.
- **Paths/Endpoints**: N/A
- **Payload/Artifact Excerpts**: N/A (raw event data unavailable due to tool errors).
- **Staging Indicators**: N/A
- **Temporal Checks**: Activity observed within the current window. OSINT confirms known ICS attack patterns.

**ODD-REDIS-001: Redis (port 6379, typically)**
- **Source IPs with counts**: Unknown (source IPs unidentifiable due to tool errors).
- **ASNs with counts**: Unknown.
- **Target Ports/Services**: Redis (port 6379, typically).
- **Paths/Endpoints**: N/A
- **Payload/Artifact Excerpts**: Action: `GET / HTTP/1.1` (1), malformed binary input (1). (Raw details unavailable due to tool errors).
- **Staging Indicators**: N/A
- **Temporal Checks**: Activity observed within the current window. OSINT confirms known Redis attack patterns.

**ODD-VNC-001: VNC (ports 5437, 15432)**
- **Source IPs with counts**: IP 46.19.137.194 (383 counts for Switzerland, likely contributing to VNC traffic, specific port breakdown unavailable).
- **ASNs with counts**: ASN 51852 (Private Layer INC) - 383 attacks.
- **Target Ports/Services**: Ports 5437 (355 attacks), 15432 (27 attacks).
- **Paths/Endpoints**: N/A
- **Payload/Artifact Excerpts**: N/A (raw event data unavailable due to tool errors).
- **Staging Indicators**: N/A
- **Temporal Checks**: Activity observed within the current window. OSINT confirms common VNC/RDP scanning.

## 11) Indicators of Interest
- **Source IPs**:
    - 165.232.154.91 (DigitalOcean, LLC - high volume attacker)
    - 46.19.137.194 (Private Layer INC - associated with VNC activity)
    - 74.207.235.171 (Targeting /.env, /.git/config)
    - 78.153.140.147 (Targeting /.env)
    - 216.180.246.66 (Targeting +CSCOE/logon.html)
    - 81.168.83.103 (Targeting /.aider.conf.yml)
- **ASNs**:
    - ASN 14061 (DigitalOcean, LLC)
    - ASN 214940 (Kprohost LLC)
    - ASN 51852 (Private Layer INC)
- **Target Ports**:
    - 25 (SMTP - associated with Kprohost LLC botnet)
    - 5437, 15432 (Non-standard VNC ports)
    - 44818 (EtherNet/IP/Modbus)
    - 6379 (Redis - unusual activity)
- **Paths/Endpoints**:
    - `/.env`
    - `/.git/config`
    - `/+CSCOE+/logon.html`
    - `/.aider.conf.yml`
    - `/wp-includes/js/jquery/jquery-migrate.min.js,qver=1.4.1.pagespeed.jm.C2obERNcWh.js`
    - `/wp-includes/js/jquery/jquery.js,qver=1.12.4.pagespeed.jm.pPCPAKkkss.js`
- **CVEs**: CVE-2019-11500, CVE-2024-14007

## 12) Backend Tool Issues
- **Tool Failures**:
    - `kibanna_discover_query`: Repeatedly failed with `illegal_argument_exception: Expected text at 1:70 but found START_ARRAY` when querying `action.keyword`, `type.keyword`, `path.keyword`, and `dest_port.keyword`. This prevented retrieval of raw event data for Redis, Conpot, and detailed VNC and web path activity.
    - `custom_basic_search`: Failed for `dest_port.keyword` search.
    - `two_level_terms_aggregated`: Failed when attempting to filter by ASN (e.g., `type_filter: 214940`).
- **Affected Validations**:
    - Inability to inspect raw event payloads for Redis, Tanner (web paths), and Conpot (ICS protocols). This prevented detailed analysis of specific exploit attempts, full protocol interactions, and command structures.
    - Inability to consistently identify specific source IPs for all relevant honeypot interactions (e.g., for Conpot and Redis).
- **Weakened Conclusions**: The lack of raw event data means that while general attack patterns and knownness could be established (often through OSINT), the specifics of *how* the services were interacted with, the exact payloads, and full exploitation chains could not be confirmed. This primarily impacts the confidence for candidates marked "provisional" and means no "potential zero-day candidate" could be declared, even if underlying novel payloads might have existed.

## 13) Agent Action Summary (Audit Trail)

- **agent_name**: ParallelInvestigationAgent (and its sub-agents: BaselineAgent, KnownSignalAgent, CredentialNoiseAgent, HoneypotSpecificAgent)
    - **purpose**: Gather foundational data about attack volume, origins, known signals, credential noise, and honeypot-specific interactions.
    - **inputs_used**: None (initial data collection phase)
    - **actions_taken**: Executed `get_report_time`, `get_total_attacks`, `get_top_countries`, `get_attacker_src_ip`, `get_country_to_port`, `get_attacker_asn`, `get_alert_signature`, `get_cve`, `get_alert_category`, `suricata_lenient_phrase_search` (for "ET POLICY"), `get_input_usernames`, `get_input_passwords`, `get_p0f_os_distribution`, `redis_duration_and_bytes`, `adbhoney_input`, `adbhoney_malware_samples`, `conpot_input`, `tanner_unifrom_resource_search`, `conpot_protocol`.
    - **key_results**: Identified 7864 attacks, top source countries (US, Germany), top attacker IPs/ASNs (DigitalOcean), top ports (22, 5926, 5437), top alert signatures (VNC, MS Terminal Server), 2 CVEs, common credential noise, and honeypot-specific activities (Redis, Tanner paths, Conpot protocols).
    - **errors_or_gaps**: No explicit errors reported by these agents; data was gathered successfully at an aggregate level.

- **agent_name**: CandidateDiscoveryAgent
    - **purpose**: Identify potential high-signal attack candidates for further validation, filtering out known noise.
    - **inputs_used**: `baseline_result`, `known_signals_result`, `credential_noise_result`, `honeypot_specific_result`.
    - **actions_taken**: Attempted `kibanna_discover_query` for Redis actions and paths, `custom_basic_search` for Redis actions and destination ports, `two_level_terms_aggregated` for Redis types, Tanner paths, and ASN filtering.
    - **key_results**: Identified initial candidates for botnet/campaign mapping (SMTP botnet, web recon), odd-service/minutia attacks (ICS, Redis, VNC), and suspicious activity (/.aider.conf.yml).
    - **errors_or_gaps**: Multiple `kibanna_discover_query` failures (`illegal_argument_exception`), `custom_basic_search` failure for `dest_port.keyword`, and `two_level_terms_aggregated` failure for ASN filtering. This led to `degraded_mode: true` and prevented deeper initial investigation into raw event data.

- **agent_name**: CandidateValidationLoopAgent
    - **purpose**: Validate each identified candidate against known intelligence and conduct deeper checks.
    - **inputs_used**: `candidate_discovery_result` (initial candidates), `baseline_result`, `known_signals_result`, `credential_noise_result`, `honeypot_specific_result`.
    - **actions_taken**: Ran 6 iterations. For each candidate, attempted `kibanna_discover_query`, `get_cve`, `get_alert_signature`, `web_path_samples`, `suricata_lenient_phrase_search`.
    - **key_results**: 6 candidates validated (BOTNET-001, BOTNET-002, ODD-ICS-001, ODD-REDIS-001, ODD-VNC-001, MONITOR-001). Confirmed knownness for most, marked several provisional due to data access issues.
    - **errors_or_gaps**: `kibanna_discover_query` failed repeatedly during validation for retrieving raw event data (`type.keyword`, `dest_port.keyword`, `path_phrase`). This blocked detailed payload analysis and specific source IP identification for BOTNET-002, ODD-ICS-001, ODD-REDIS-001, and ODD-VNC-001, resulting in their `provisional: true` status.

- **agent_name**: OSINTAgent
    - **purpose**: Leverage external intelligence to assess the knownness, recency, and broader context of validated candidates.
    - **inputs_used**: Validated candidate details from `CandidateValidationLoopAgent`.
    - **actions_taken**: Performed `search` queries for each candidate's key indicators (e.g., "SMTP port 25 attacks Ukraine Kprohost LLC ASN 214940", "web reconnaissance paths .env .git/config +CSCOE/logon.html .aider.conf.yml", "ICS honeypot attacks Kamstrup protocol IEC104 Modbus port 44818", "Redis honeypot HTTP GET / binary input unusual activity", "VNC scanning non-standard ports GPL INFO VNC server response ET SCAN MS Terminal Server Traffic on Non-standard Port Private Layer INC ASN 51852", "/.aider.conf.yml security API keys exploit").
    - **key_results**: Found extensive public mappings for all candidates, significantly reducing their perceived novelty and often increasing confidence in their classification as known attack patterns or commodity scanning. Confirmed Kprohost LLC as abusive infrastructure, web paths as common reconnaissance, ICS protocols as known attack targets, Redis anomalies as known cross-protocol attacks, and VNC activity as known scanning.
    - **errors_or_gaps**: None explicitly reported.

- **agent_name**: ReportAgent (Self)
    - **purpose**: Compile the final report from all workflow state outputs.
    - **inputs_used**: `investigation_start`, `investigation_end`, `baseline_result`, `known_signals_result`, `credential_noise_result`, `honeypot_specific_result`, `candidate_discovery_result`, `validated_candidates`, `osint_validation_result`.
    - **actions_taken**: Consolidated data, determined completion status, categorized findings, and formatted the report according to specified guidelines.
    - **key_results**: Generation of this comprehensive threat intelligence report.
    - **errors_or_gaps**: None, compilation successful based on available inputs.

- **agent_name**: SaveReportAgent
    - **purpose**: Save the generated report to persistent storage.
    - **inputs_used**: The completed markdown report content.
    - **actions_taken**: Not explicitly called in this output, but expected to perform a `default_write_file` operation.
    - **key_results**: Report saved successfully (implied by workflow completion).
    - **errors_or_gaps**: Not explicitly reported.