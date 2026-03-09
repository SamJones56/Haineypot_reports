# Honeypot Threat Intelligence Report

## 1) Investigation Scope
-   **investigation_start**: 2026-03-08T21:00:10Z
-   **investigation_end**: 2026-03-09T00:00:10Z
-   **completion_status**: Partial
-   **degraded_mode**: true (Some queries for raw event data failed, and deeper validation for certain alerts was blocked, leading to gaps in full validation of some identified CVEs.)

## 2) Executive Triage Summary
-   **Total Attacks Observed**: 19,272 events within the 3-hour window.
-   **Dominant Commodity Activity**: Mass-scale VNC scanning and exploitation (`CVE-2006-2369`) and high-volume SMB scanning (port 445) constitute the majority of high-count alerts.
-   **Emerging n-day Exploitation Confirmed**: Active exploitation attempts for `CVE-2024-23334` (aiohttp Directory Traversal) observed from two blacklisted IPs (`193.34.212.9`, `89.42.231.182`). These IPs are running a coordinated, distributed web scanning campaign.
-   **Critical Unvalidated Alerts**: Alerts were triggered for `CVE-2025-55182` (React Server Components RCE) and `CVE-2024-38816` (Spring Framework Path Traversal). While raw events for these specific alerts could not be retrieved, OSINT confirms `CVE-2025-55182` is a critical, actively exploited RCE vulnerability on CISA's KEV catalog.
-   **Odd-Service Activity**: Repeated, unidentified protocol activity on port 1337 from a malicious IP (`204.76.203.18`), a port known for custom protocols and malware association.
-   **Honeypot-Specific Reconnaissance**: Redis honeypot detected a "MGLNDD_" pattern, identified as a known scanner fingerprint (Stretchoid/Magellan) targeting Redis instances.
-   **Major Uncertainties**: Inability to fully retrieve raw event data for `CVE-2024-38816` and `CVE-2025-55182` alerts, and inability to trace the origin of specific Redis `MGLNDD_` commands directly to a source IP from event logs.

## 3) Candidate Discovery Summary
-   **Total Attacks**: 19,272
-   **Top Countries by Attack Count**: United States (5525), India (1177), Indonesia (1037), Australia (992), Netherlands (979).
-   **Top Attacker ASNs**: DigitalOcean, LLC (5353), Google LLC (1308), Emre Anil Arslan (945).
-   **Top Alert Signatures**:
    -   `GPL INFO VNC server response` (19224)
    -   `ET SCAN MS Terminal Server Traffic on Non-standard Port` (818)
    -   `ET EXPLOIT VNC Server Not Requiring Authentication (case 2)` (510)
-   **CVEs with Alert Detections**:
    -   `CVE-2006-2369` (510 events, VNC exploitation)
    -   `CVE-2025-55182` (84 events, React Server Components RCE - *validation blocked*)
    -   `CVE-2024-38816` (15 events, Spring Framework Path Traversal - *validation blocked*)
    -   `CVE-2024-23334` (9 events, aiohttp Directory Traversal - *validated*)
-   **Honeypot Activity**:
    -   Redis: 27 actions, including `MGLNDD_` scanner fingerprints.
    -   ADBHoney: 34 inputs, including `echo` commands. No malware samples.
    -   Tanner: 45 URIs, including path traversal attempts (`/.env`, `/etc/passwd`).
    -   Conpot: No activity.
-   **Discovery Gaps**: Initial attempts to aggregate CVEs with source IPs failed. Direct retrieval of raw events for `CVE-2024-38816` and `CVE-2025-55182` alerts was unsuccessful, limiting full validation. Inability to correlate specific Redis commands (`MGLNDD_`) with source IPs directly.

## 4) Emerging n-day Exploitation
-   **CVE-2024-23334: aiohttp Directory Traversal in Static Routing**
    -   **cve/signature mapping**: `CVE-2024-23334` (ET EXPLOIT aiohttp Directory Traversal in Static Routing)
    -   **evidence summary**: 9 Suricata alerts across various web ports. HTTP GET requests for `/static/link/%2e%2e/%2e%2e/etc/passwd` and similar path traversal payloads. Source IPs `193.34.212.9` and `89.42.231.182` observed executing these attempts.
    -   **affected service/port**: Web applications potentially running aiohttp, observed targeting ports 1080, 9443, 7443, 8888, 8443, 8181, 8081, 7080, 8080.
    -   **confidence**: High
    -   **operational notes**: Active, widespread scanning campaign from known malicious IPs. Block identified source IPs immediately. Implement WAF rules to detect and prevent path traversal attempts. Monitor web logs for similar payloads on a variety of web service ports.

## 5) Novel or Zero-Day Exploit Candidates (UNMAPPED ONLY, ranked)
No exploit candidates were classified as novel or potential zero-days in this investigation window.

## 6) Botnet/Campaign Infrastructure Mapping
-   **Item ID**: BCM-001
    -   **Campaign Name**: VNC Scanning and Exploitation Campaign
    -   **campaign_shape**: spray
    -   **suspected_compromised_src_ips**: `129.212.184.194`, `134.209.37.134` (top examples from port 5902 activity). Broad distribution across many IPs.
    -   **ASNs / geo hints**: DigitalOcean, LLC (AS14061), Google LLC (AS396982), United States (top geo).
    -   **suspected_staging indicators**: None identified.
    -   **suspected_c2 indicators**: None identified.
    -   **confidence**: High
    -   **operational notes**: This is a high-volume, commodity botnet activity targeting an old VNC vulnerability. Continue to block source IPs and monitor for any deviation from expected VNC scanning patterns.
-   **Item ID**: BCM-002
    -   **Campaign Name**: SMB Scanning Campaign
    -   **campaign_shape**: spray
    -   **suspected_compromised_src_ips**: `45.95.214.24`, `103.177.233.162` (top source IPs targeting port 445).
    -   **ASNs / geo hints**: Emre Anil Arslan (AS216099), Ishans Network (AS45117), from Türkiye, India.
    -   **suspected_staging indicators**: None identified.
    -   **suspected_c2 indicators**: None identified.
    -   **confidence**: High
    -   **operational notes**: Standard commodity SMB scanning. IPs are associated with hosting providers. Monitor these and other high-volume IPs for changes in activity or targets.
-   **Item ID**: (Derived from deep investigation)
    -   **Campaign Name**: CVE-2024-23334 aiohttp Directory Traversal Campaign
    -   **campaign_shape**: spray
    -   **suspected_compromised_src_ips**: `193.34.212.9` (Poland), `89.42.231.182` (Netherlands). Both are blacklisted and engaged in this specific attack.
    -   **ASNs / geo hints**: MEVSPACE sp. z o.o. (AS201814, Poland), Amarutu Technology Ltd (AS206264, Netherlands).
    -   **suspected_staging indicators**: Hostnames `134.199.242.175`, `167.71.255.16` observed in HTTP requests within the honeypot network context.
    -   **suspected_c2 indicators**: None identified.
    -   **confidence**: High
    -   **operational notes**: These are dedicated web scanners. Block the identified source IPs and implement enhanced WAF/IPS rules for path traversal attacks, especially on non-standard web ports.

## 7) Odd-Service / Minutia Attacks
-   **Item ID**: OSM-001
    -   **service_fingerprint**: Port 1337 (TCP), P0f app: ??? (unknown protocol)
    -   **why it’s unusual/interesting**: Port 1337 is often associated with custom protocols and various malware (e.g., Backdoor.Win32.Small.n, cryptominers). The unidentified application by P0f increases suspicion.
    -   **evidence summary**: 35 events, all from `204.76.203.18`. Captured by Honeytrap and P0f.
    -   **confidence**: Low (Provisional=True, but OSINT confirms malicious association of port).
    -   **recommended monitoring pivots**: Monitor port 1337 for any new activity or changes in protocol. Investigate the source IP `204.76.203.18` (Pfcloud UG, Netherlands) for other malicious activities and consider blocking. Further analysis of packet captures for port 1337 traffic is recommended if available.

## 8) Known-Exploit / Commodity Exclusions
-   **VNC Scanning and Exploitation (CVE-2006-2369)**: Mass-scale scanning and exploitation of VNC servers not requiring authentication. This accounts for over 20,000 events (`GPL INFO VNC server response`, `ET EXPLOIT VNC Server Not Requiring Authentication (case 2)`) and is commodity botnet activity.
-   **SMB Scanning (Port 445)**: High-volume scanning activity on port 445 (1480 events) originating from various IPs, indicative of common SMB reconnaissance.
-   **SSH Credential Brute-Force (Port 22)**: Standard brute-force attempts targeting common usernames (`root`, `admin`, `ubuntu`, `user`) and passwords (`123456`, `password`, `123`, `1234`) on SSH (524 events on port 22).
-   **MS Terminal Server Scanning**: Alerts for "ET SCAN MS Terminal Server Traffic on Non-standard Port" (818 events).
-   **Redis Scanner Fingerprint**: Detection of `MGLNDD_` pattern, identified via OSINT as a known scanner fingerprint (Stretchoid/Magellan) targeting Redis instances on port 6379. This is a commodity scanning technique.

## 9) Infrastructure & Behavioral Classification
-   **VNC Campaign (BCM-001)**: Exploitation (CVE-2006-2369), spray campaign, leveraging cloud provider infrastructure (DigitalOcean, Google LLC). Targets VNC services on 5900+ ports.
-   **SMB Scanning (BCM-002)**: Scanning, spray campaign, originating from various hosting providers. Targets SMB on port 445.
-   **CVE-2024-23334 Campaign**: Active Exploitation/Scanning, spray campaign, conducted by dedicated web scanners from blacklisted IPs (MEVSPACE, Amarutu Technology Ltd). Targets web services on a broad range of common and alternative ports (8080-9443, 1080) with specific directory traversal payloads (`/etc/passwd`).
-   **Port 1337 Activity (OSM-001)**: Scanning/Reconnaissance, fan-out behavior from a single, known malicious IP. Targets an unusual port with an unidentified protocol, indicating potential custom or malware-related communication.
-   **Redis Scanner (SUM-001)**: Reconnaissance/Scanning, likely a spray campaign using a known scanner fingerprint (MGLNDD_) against Redis (port 6379).

## 10) Evidence Appendix
### CVE-2024-23334 (aiohttp Directory Traversal)
-   **Source IPs with counts**:
    -   `193.34.212.9` (Poland, AS201814 MEVSPACE sp. z o.o.) - 762 events
    -   `89.42.231.182` (Netherlands, AS206264 Amarutu Technology Ltd) - 197 events
-   **Target ports/services**: 1080, 9443, 7443, 8888, 8443, 8181, 8081, 7080, 8080 (HTTP/HTTPS)
-   **Paths/endpoints**:
    -   `/static/link/%2e%2e/%2e%2e/etc/passwd`
    -   `/%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2Fetc%2Fpasswd`
    -   `/..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd`
-   **Payload/artifact excerpts**: HTTP GET requests. User-Agent: `Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:146.0) Gecko/20100101 Firefox/146.0`
-   **Staging indicators**: Hostnames `134.199.242.175`, `167.71.255.16` observed in HTTP requests within the honeypot network context.
-   **Temporal checks**: Active throughout the investigation window:
    -   `193.34.212.9`: First seen `2026-03-08T21:06:08Z`, Last seen `2026-03-08T23:57:20Z`
    -   `89.42.231.182`: First seen `2026-03-08T21:03:08Z`, Last seen `2026-03-08T23:17:38Z`

### BCM-001: VNC Scanning and Exploitation Campaign
-   **Source IPs with counts**:
    -   `129.212.184.194` (United States) - 340 events overall, specific to port 5902 activity
    -   `134.209.37.134` (United States) - 452 events overall, specific to port 5902 activity
    -   Many other distributed IPs from baseline.
-   **ASNs with counts**: DigitalOcean, LLC (AS14061) - 5353 events, Google LLC (AS396982) - 1308 events (overall baseline)
-   **Target ports/services**: 5901, 5902, 5903, 5904, 5905, 5906, 5907, 5914, 5915 (VNC)
-   **Payload/artifact excerpts**: Suricata signatures "GPL INFO VNC server response", "ET EXPLOIT VNC Server Not Requiring Authentication (case 2)".
-   **Staging indicators**: None identified.
-   **Temporal checks**: Observed continuously throughout the window.

### BCM-002: SMB Scanning Campaign
-   **Source IPs with counts**:
    -   `45.95.214.24` (Türkiye) - 945 events, primarily targeting port 445.
    -   `103.177.233.162` (India) - 535 events, primarily targeting port 445.
-   **ASNs with counts**: Emre Anil Arslan (AS216099) - 945 events, Ishans Network (AS45117) - 535 events.
-   **Target ports/services**: 445 (SMB)
-   **Payload/artifact excerpts**: Inferred from port activity and "ET SCAN MS Terminal Server Traffic" signature category.
-   **Staging indicators**: None identified.
-   **Temporal checks**: Observed continuously throughout the window.

### OSM-001: Unknown service on port 1337
-   **Source IPs with counts**:
    -   `204.76.203.18` (Netherlands) - 35 events
-   **ASNs with counts**: Pfcloud UG (AS51396)
-   **Target ports/services**: 1337 (TCP)
-   **Payload/artifact excerpts**: "P0f app: ???", indicating an unknown application/protocol.
-   **Staging indicators**: None identified.
-   **Temporal checks**: Observed continuously throughout the window.

## 11) Indicators of Interest
-   **Source IPs**:
    -   `193.34.212.9` (Associated with `CVE-2024-23334` exploitation and blacklisted)
    -   `89.42.231.182` (Associated with `CVE-2024-23334` exploitation and blacklisted)
    -   `204.76.203.18` (Associated with port 1337 activity and blacklisted)
-   **Attack Paths/Endpoints**:
    -   `/static/link/%2e%2e/%2e%2e/etc/passwd`
    -   `/%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2Fetc%2Fpasswd`
    -   `/..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd`
-   **CVEs**:
    -   `CVE-2024-23334` (aiohttp Directory Traversal)
    -   `CVE-2025-55182` (React Server Components RCE - critical, alerts observed, further validation needed)
    -   `CVE-2024-38816` (Spring Framework Path Traversal - alerts observed, further validation needed)
-   **User-Agent**: `Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:146.0) Gecko/20100101 Firefox/146.0` (used in `CVE-2024-23334` campaign)
-   **Scanner Fingerprints**: `MGLNDD_` (observed on Redis port 6379)

## 12) Backend Tool Issues
-   **CandidateDiscoveryAgent**:
    -   **Failed Queries**:
        -   `two_level_terms_aggregated` on `alert.cve.keyword`: Failed to retrieve CVEs mapped to source IPs.
        -   `two_level_terms_aggregated` with `type_filter`: Failed to correctly filter for VNC traffic or other specific ports in early attempts.
        -   `two_level_terms_aggregated` on `http.url.keyword` for campaign IPs: Failed to aggregate source IPs using a specific URL payload.
        -   `kibanna_discover_query` for `MGLNDD_` Redis command: Failed due to a field mismatch in the query.
    -   **Affected Validations**:
        -   Could not retrieve raw events for alerts related to `CVE-2024-38816` or `CVE-2025-55182` via keyword search, weakening the ability to fully validate exploitation attempts.
        -   Could not directly determine the origin of the `MGLNDD_` Redis commands from event logs.
        -   Initial attempts to comprehensively map all IPs for the `CVE-2024-23334` campaign were blocked, though partially overcome by using `web_path_samples`.
-   **DeepInvestigationAgent**:
    -   **Failed Queries**:
        -   `two_level_terms_aggregated` (primary_field=src_ip.keyword, secondary_field=dest_port) for `193.34.212.9`: Failed to correctly map destination ports.
        -   `two_level_terms_aggregated` (primary_field=http.url.keyword, secondary_field=src_ip.keyword) for `/static/link/%2e%2e/%2e%2e/etc/passwd`: Failed to aggregate all source IPs using the specific payload.
    -   **Affected Validations**:
        -   Comprehensive mapping of attacker target ports was initially blocked.
        -   Full enumeration of all campaign source IPs for `CVE-2024-23334` was initially blocked, requiring a manual review of `web_path_samples` output.

## 13) Agent Action Summary (Audit Trail)
-   **agent_name**: BaselineAgent
    -   **purpose**: Establish baseline threat activity and gather high-level statistics.
    -   **inputs_used**: `investigation_start`, `investigation_end`
    -   **actions_taken**: Called `get_total_attacks`, `get_top_countries`, `get_attacker_src_ip`, `get_country_to_port`, `get_attacker_asn`.
    -   **key_results**: Identified 19,272 attacks, top attacking countries (US, India), top source IPs, and top ASNs (DigitalOcean, Google LLC). Highlighted high activity on VNC ports (5900+), SMB (445), and SSH (22).
    -   **errors_or_gaps**: None.
-   **agent_name**: KnownSignalAgent
    -   **purpose**: Identify known alert signatures, CVEs, and alert categories for initial threat mapping.
    -   **inputs_used**: `investigation_start`, `investigation_end`
    -   **actions_taken**: Called `get_alert_signature`, `get_cve`, `get_alert_category`, `suricata_lenient_phrase_search` for "ET" signatures.
    -   **key_results**: Identified predominant VNC-related signatures (GPL INFO VNC, ET EXPLOIT VNC), alerts for CVEs including `CVE-2006-2369`, `CVE-2025-55182`, `CVE-2024-38816`, and `CVE-2024-23334`. Categorized most activity as "Misc activity".
    -   **errors_or_gaps**: None.
-   **agent_name**: CredentialNoiseAgent
    -   **purpose**: Characterize credential brute-force and related reconnaissance activities.
    -   **inputs_used**: `investigation_start`, `investigation_end`
    -   **actions_taken**: Called `get_input_usernames`, `get_input_passwords`, `get_p0f_os_distribution`.
    -   **key_results**: Identified common usernames (`root`, `admin`) and passwords (`123456`, `password`) used in brute-force attempts. Showed a diverse distribution of detected operating systems.
    -   **errors_or_gaps**: None.
-   **agent_name**: HoneypotSpecificAgent
    -   **purpose**: Identify activity specific to different honeypot types.
    -   **inputs_used**: `investigation_start`, `investigation_end`
    -   **actions_taken**: Called `redis_duration_and_bytes`, `adbhoney_input`, `adbhoney_malware_samples`, `conpot_input`, `tanner_unifrom_resource_search`, `conpot_protocol`.
    -   **key_results**: Observed Redis connections and an "MGLNDD_" command. Detected `echo` commands in ADBHoney. Found path traversal attempts (`/.env`, `/etc/passwd`) in Tanner. No Conpot activity or ADB malware samples.
    -   **errors_or_gaps**: None.
-   **agent_name**: CandidateDiscoveryAgent
    -   **purpose**: Consolidate raw data, identify and classify high-signal candidates, and exclude commodity noise.
    -   **inputs_used**: `baseline_result`, `known_signals_result`, `credential_noise_result`, `honeypot_specific_result`.
    -   **actions_taken**: Attempted `two_level_terms_aggregated` (4 calls, 3 failed due to parameter misuse/no results), `search` (1 call) for CVE info, `kibanna_discover_query` (3 calls) for specific ports and Redis commands, `discover_by_keyword` (1 call) for CVEs, `set_model_response` (1 call) to compile triage data.
    -   **key_results**: Identified VNC/SMB campaigns, active exploitation of `CVE-2024-23334`, odd port 1337 activity, and a Redis scanner fingerprint. Categorized known brute force and scanning activity as exclusions. Acknowledged detection of `CVE-2024-38816` and `CVE-2025-55182` alerts but noted validation blockers.
    -   **errors_or_gaps**: Multiple query failures (`two_level_terms_aggregated` and `kibanna_discover_query` for Redis command), leading to blocked validation steps for retrieving raw events for certain CVEs and tracing Redis commands.
-   **agent_name**: CandidateValidationLoopAgent
    -   **iterations run**: 1
    -   **# candidates validated**: 1 (`CVE-2024-23334`)
    -   **early exit reason**: The loop successfully processed the first available candidate for validation and then the deep investigation agent took over.
-   **agent_name**: DeepInvestigationLoopController
    -   **iterations run**: 5
    -   **key leads pursued**: `CVE-2024-23334` as the initial lead. Pivoted to `src_ip:193.34.212.9`, then `src_ip:89.42.231.182`, and attempted to map the campaign via `path:/static/link/%2e%2e/%2e%2e/etc/passwd`.
    -   **stall/exit reason**: `exit_loop` called after 2 stalls (due to tool errors and no new leads generated for existing ones), indicating no further productive investigation paths could be identified within the current lead queue and capabilities.
-   **agent_name**: OSINTAgent
    -   **purpose**: Provide external context and validate knownness of identified threats.
    -   **inputs_used**: Leads from CandidateDiscovery and DeepInvestigation.
    -   **actions_taken**: Performed 6 `search` queries for CVEs (`CVE-2024-38816`, `CVE-2025-55182`, `CVE-2006-2369`, `CVE-2024-23334`), specific port usage (1337), Redis command patterns (`MGLNDD_`), and threat intelligence on specific IPs (`193.34.212.9`, `89.42.231.182`).
    -   **key_results**: Confirmed `CVE-2024-23334` is a recent, actively exploited vulnerability. Validated `193.34.212.9` and `89.42.231.182` as blacklisted malicious IPs involved in botnet/scanning activity. Clarified port 1337's association with malware and custom protocols. Identified "MGLNDD_" as a known scanner fingerprint. Corrected initial assessment of `CVE-2025-55182`, confirming it as a critical, actively exploited RCE on CISA's KEV catalog.
    -   **errors_or_gaps**: None.
-   **agent_name**: ReportAgent
    -   **purpose**: Compile final report from workflow state outputs.
    -   **inputs_used**: All workflow state outputs.
    -   **actions_taken**: Report compilation based on mandatory logic and strict output format.
    -   **key_results**: N/A (this markdown report is the result).
    -   **errors_or_gaps**: None.
-   **agent_name**: SaveReportAgent
    -   **purpose**: Save the compiled report to persistent storage.
    -   **inputs_used**: Report content from ReportAgent.
    -   **actions_taken**: Tool call `deep_agent_write_file` (status pending in current context).
    -   **key_results**: N/A (report saving is the final step, status will be determined by tool call).
    -   **errors_or_gaps**: None (operation pending).