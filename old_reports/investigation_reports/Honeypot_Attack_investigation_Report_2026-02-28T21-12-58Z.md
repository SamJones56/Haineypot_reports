# Honeypot Threat Report

## 1) Investigation Scope

*   **investigation_start**: 2026-02-28T20:06:15Z
*   **investigation_end**: 2026-02-28T21:07:40Z
*   **completion_status**: Complete
*   **degraded_mode**: true (Some deep investigation queries were misconfigured or failed due to timestamp format errors, and initial CVE detections lacked source IPs).

## 2) Executive Triage Summary

*   High volume of commodity SSH and VNC scanning, predominantly from a DigitalOcean IP (170.64.223.30), consistent with botnet reconnaissance.
*   Emerging n-day exploitation attempts detected for CVE-2025-55182 (React Server Components RCE), CVE-2023-46604 (Apache ActiveMQ RCE), and CVE-2024-14007 (Shenzhen TVT NVMS-9000 Auth Bypass).
*   Targeted web application reconnaissance against sensitive paths, including `/developmentserver/metadatauploader` (associated with CVE-2025-31324, SAP NetWeaver RCE) and `/actuator/gateway/routes` (associated with Spring Boot Actuator vulnerabilities).
*   Unusual industrial control system (ICS) protocol interaction observed on the ConPot honeypot, specifically IEC104 on port 2404, indicating focused scanning for critical infrastructure.
*   Widespread credential brute-force activity with common usernames and passwords across various services.
*   Significant probing for sensitive configuration and backup files (e.g., `.env`, `.ssh/id_rsa`, `db.sql`) via the h0neytr4p honeypot.
*   Uncertainties remain regarding the specific source IPs for some CVE-mapped exploitation attempts due to initial data retrieval limitations.

## 3) Candidate Discovery Summary

A total of 9790 attacks were observed within the 60-minute window. Candidate discovery identified the following primary areas of interest:

*   **CVE-Mapped Exploitation**: 3 distinct CVEs were initially identified, with a total of 10 related events.
*   **Botnet/Infrastructure Mapping**: 1 high-volume SSH/VNC scanning campaign from a DigitalOcean IP.
*   **Web Application Reconnaissance**: Probing of 5 sensitive web application paths, now mapped to known vulnerabilities or common information leaks.
*   **Odd-Service Interaction**: 1 instance of IEC104 industrial control system protocol activity.
*   **Known Signals**: Over 3300 alerts from Suricata signatures, including VNC/SSH activity.
*   **Credential Noise**: Numerous brute-force attempts targeting common usernames and passwords.

**Missing Inputs/Errors:**
*   Initial `top_src_ips_for_cve` queries for CVE-2025-55182, CVE-2023-46604, and CVE-2024-14007 did not return source IPs directly, necessitating manual extraction or further deep investigation.
*   A casing mismatch for "Conpot" in initial honeypot-specific searches caused some events to be overlooked initially, but this was resolved in subsequent queries.

## 4) Emerging n-day Exploitation

*   **CVE-2025-55182: React Server Components React2Shell Unsafe Flight Protocol Property Access**
    *   **cve/signature mapping**: CVE-2025-55182 (ET WEB_SPECIFIC_APPS React Server Components React2Shell Unsafe Flight Protocol Property Access)
    *   **evidence summary**: 7 events from source IPs `91.224.92.177` and `195.3.221.86` targeting destination ports `3000` (6 events) and `3001` (1 event). Observed HTTP GET requests to paths like `/`, `/api/route`, `/app`, `/_next/server`, `/_next`, `/api`.
    *   **affected service/port**: HTTP/Web Application (TCP/3000, TCP/3001)
    *   **confidence**: High
    *   **operational notes**: Direct signature match confirms exploitation attempt. Investigate if these ports are typically exposed.

*   **CVE-2023-46604: Apache ActiveMQ Remote Code Execution (RCE)**
    *   **cve/signature mapping**: CVE-2023-46604
    *   **evidence summary**: 2 events associated with this CVE, targeting destination port `61616`. Source IPs were not available from initial tooling. OSINT confirms this is a critical RCE.
    *   **affected service/port**: Apache ActiveMQ (TCP/61616)
    *   **confidence**: High
    *   **operational notes**: This is a critical, actively exploited RCE vulnerability. Immediate attention to affected ActiveMQ instances is paramount. Correlate with other logs for source IPs and full payload analysis.

*   **CVE-2024-14007: Shenzhen TVT NVMS-9000 Authentication Bypass**
    *   **cve/signature mapping**: CVE-2024-14007
    *   **evidence summary**: 1 event associated with this CVE, targeting destination port `9100`. Source IP was not available from initial tooling. OSINT confirms this allows unauthenticated RCE.
    *   **affected service/port**: Shenzhen TVT NVMS-9000 Control Protocol (TCP/9100)
    *   **confidence**: High
    *   **operational notes**: Critical authentication bypass with public exploits. Urgent patching required for affected NVR/DVR devices. Correlate with other logs for source IP and full payload analysis.

*   **CVE-2025-31324: SAP NetWeaver Metadata Uploader RCE**
    *   **cve/signature mapping**: CVE-2025-31324
    *   **evidence summary**: 1 HTTP GET request to `/developmentserver/metadatauploader` on Tanner honeypot from `40.119.41.94` (Microsoft Corporation). User agent: `Mozilla/5.0 zgrab/0.x`.
    *   **affected service/port**: SAP NetWeaver Visual Composer (HTTP/TCP/80)
    *   **confidence**: High
    *   **operational notes**: This path is a direct indicator of exploitation attempts for a critical RCE. Monitor for file uploads or POST requests to this path.

*   **CVE-2022-22947 (implied): Spring Cloud Gateway RCE/SSRF**
    *   **cve/signature mapping**: Related to CVE-2022-22947 and general Spring Boot Actuator vulnerabilities.
    *   **evidence summary**: 2 HTTP GET requests to `/actuator/gateway/routes` on Tanner honeypot from `79.124.40.174` (Tamatiya EOOD). User agent: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/78.0.3904.108 Safari/537.36`.
    *   **affected service/port**: Spring Boot Actuator (HTTP/TCP/80)
    *   **confidence**: Medium-High
    *   **operational notes**: Probing of this endpoint is a known precursor to SSRF or RCE. Ensure Spring Boot Actuator endpoints are properly secured with authentication/authorization and limited exposure.

## 5) Novel Exploit Candidates (UNMAPPED ONLY, ranked)

No genuinely novel exploit candidates were identified after comprehensive mapping against known CVEs and common reconnaissance techniques through OSINT. All exploit-like behavior observed was ultimately associated with established attack patterns or known vulnerabilities.

## 6) Botnet/Campaign Infrastructure Mapping

*   **item_id**: botnet-infra-001
*   **campaign_shape**: Spray
*   **suspected_compromised_src_ips**: `170.64.223.30` (4044 attacks in total, with 809 specifically targeting port 22 in Deep Investigation logs).
*   **ASNs / geo hints**: ASN `14061`, Organization: `DigitalOcean, LLC`, Country: `Australia` (from initial scan data).
*   **suspected_staging indicators**: N/A
*   **suspected_c2 indicators**: N/A
*   **confidence**: High
*   **operational notes**: This IP is a known source of commodity SSH/VNC scanning from DigitalOcean infrastructure. Block this IP and monitor for additional associated activity or changes in attack patterns.

## 7) Odd-Service / Minutia Attacks

*   **service_fingerprint**: IEC104 (TCP/2404) on ConPot honeypot
*   **why it’s unusual/interesting**: IEC104 is an industrial control system (ICS) protocol used in critical infrastructure (e.g., power grids). Interactions with this service, even scanning, indicate actors potentially interested in ICS environments.
*   **evidence summary**: 2 `CONNECTION_LOST` events recorded on the ConPot honeypot on destination port `2404` from source IP `138.197.16.14` (DigitalOcean, LLC). Suricata flow events and P0f OS fingerprinting (Windows NT, Linux) also observed. Activity sustained over 2 hours.
*   **confidence**: High
*   **recommended monitoring pivots**: Deeper analysis of any recorded IEC104 commands or payloads (not present in current logs). Monitor for further activity from `138.197.16.14` targeting other ICS ports or protocols. Check OSINT for current IEC104 scanning campaigns.

## 8) Known-Exploit / Commodity Exclusions

*   **SSH/VNC Scanning & Brute-Forcing**: High volume of activity detected by Suricata signatures such as `GPL INFO VNC server response` (1655 events), `SURICATA SSH invalid banner` (354 events), `ET SCAN MS Terminal Server Traffic on Non-standard Port` (303 events), `ET INFO SSH session in progress on Unusual Port` (142 events), and `ET INFO SSH session in progress on Expected Port` (79 events). These are typical internet-wide scans for exposed services.
*   **NMAP Scanning**: Identified by `ET SCAN NMAP -sS window 1024` (46 events).
*   **Commodity Credential Noise**: Extensive brute-force attempts observed with common usernames like `root` (174), `admin` (53), `oracle` (43), and common passwords such as `123456` (270), `123` (35), `password` (31).
*   **Generic Web Application Reconnaissance**: Probing of common sensitive paths via the Tanner honeypot, including `/.env` (2 events) and `/admin/config.php` (1 event). These are frequent targets for information disclosure.
*   **H0neytr4p Sensitive File Probing**: Multiple source IPs (e.g., `212.56.54.219`, `135.237.127.54`, `34.158.168.101`) probed the h0neytr4p honeypot for a wide array of sensitive configuration, credential, and backup files (e.g., `/local.settings.json`, `/db.sql`, `/.ssh/id_rsa`, `/web.config`, `/id_rsa`). This represents common, broad-stroke reconnaissance for exposed secrets.

## 9) Infrastructure & Behavioral Classification

*   **Exploitation vs. Scanning**: The observed activity is a blend of widespread, opportunistic scanning (SSH, VNC, generic web paths) and more targeted reconnaissance for specific, known vulnerabilities (SAP NetWeaver, Spring Boot Actuator, Apache ActiveMQ, NVMS-9000). The IEC104 interaction suggests specialized ICS reconnaissance.
*   **Campaign Shape**: Predominantly "spray" campaigns, with single source IPs hitting many different targets (implicitly honeypot instances, indicated by high attack counts from one source) or diverse IPs probing similar sensitive web paths.
*   **Infra Reuse Indicators**: The repeated use of DigitalOcean ASNs (e.g., for `170.64.223.30` and `138.197.16.14`) across different attack types (SSH scanning, ICS probing) suggests these are likely compromised or rented cloud instances used for various malicious campaigns. Other prominent ASNs observed in web reconnaissance include Google LLC, Microsoft Corporation, Hostglobal.plus Ltd, Tamatiya EOOD, and Krypt Technologies.
*   **Odd-Service Fingerprints**: Detection of activity on TCP port 2404 (IEC104).

## 10) Evidence Appendix

*   **CVE-2025-55182: React Server Components React2Shell Unsafe Flight Protocol Property Access**
    *   **Source IPs**: `91.224.92.177`, `195.3.221.86`
    *   **ASNs**: Not available from logs, likely from ISP or cloud provider.
    *   **Target ports/services**: TCP/3000, TCP/3001 (Web Application)
    *   **Paths/endpoints**: `/`, `/api/route`, `/app`, `/_next/server`, `/api`, `/_next`
    *   **Payload/artifact excerpts**: `alert: {'category': 'Web Application Attack', 'cve_id': 'CVE-2025-55182 CVE-2025-55182', 'signature': 'ET WEB_SPECIFIC_APPS React Server Components React2Shell Unsafe Flight Protocol Property Access (CVE-2025-55182)'}`
    *   **Staging indicators**: N/A
    *   **Temporal checks**: Observed between `2026-02-28T20:13:10Z` and `2026-02-28T20:39:25Z`.

*   **CVE-2023-46604: Apache ActiveMQ Remote Code Execution (RCE)**
    *   **Source IPs**: Not available (missing from `top_src_ips_for_cve`).
    *   **ASNs**: Not available.
    *   **Target ports/services**: TCP/61616 (Apache ActiveMQ)
    *   **Paths/endpoints**: N/A
    *   **Payload/artifact excerpts**: `alert: {'cve_id': 'CVE-2023-46604 CVE-2023-46604 CVE-2023-46604'}`
    *   **Staging indicators**: N/A
    *   **Temporal checks**: Observed in current window.

*   **CVE-2024-14007: Shenzhen TVT NVMS-9000 Authentication Bypass**
    *   **Source IPs**: Not available (missing from `top_src_ips_for_cve`).
    *   **ASNs**: Not available.
    *   **Target ports/services**: TCP/9100 (NVMS-9000 Control Protocol)
    *   **Paths/endpoints**: N/A
    *   **Payload/artifact excerpts**: `alert: {'cve_id': 'CVE-2024-14007 CVE-2024-14007'}`
    *   **Staging indicators**: N/A
    *   **Temporal checks**: Observed in current window.

*   **CVE-2025-31324: SAP NetWeaver Metadata Uploader RCE**
    *   **Source IPs**: `40.119.41.94`
    *   **ASNs**: `8075` (Microsoft Corporation)
    *   **Target ports/services**: TCP/80 (HTTP)
    *   **Paths/endpoints**: `/developmentserver/metadatauploader`
    *   **Payload/artifact excerpts**: `method: GET`, `user-agent: Mozilla/5.0 zgrab/0.x`
    *   **Staging indicators**: N/A
    *   **Temporal checks**: Observed at `2026-02-28T20:46:48Z`.

*   **CVE-2022-22947 (implied): Spring Cloud Gateway RCE/SSRF reconnaissance**
    *   **Source IPs**: `79.124.40.174`
    *   **ASNs**: `50360` (Tamatiya EOOD)
    *   **Target ports/services**: TCP/80 (HTTP)
    *   **Paths/endpoints**: `/actuator/gateway/routes`
    *   **Payload/artifact excerpts**: `method: GET`, `user-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/78.0.3904.108 Safari/537.36`
    *   **Staging indicators**: N/A
    *   **Temporal checks**: Observed at `2026-02-28T20:56:55Z` and `2026-02-28T20:59:27Z`.

*   **Botnet-infra-001: DigitalOcean-hosted SSH/VNC scanning**
    *   **Source IPs**: `170.64.223.30` (4047 events in deep investigation window)
    *   **ASNs**: `14061` (DigitalOcean, LLC)
    *   **Target ports/services**: TCP/22 (SSH)
    *   **Paths/endpoints**: `/data/cowrie/log/cowrie.json` (Cowrie honeypot logs), `/data/fatt/log/fatt.log`, `/data/suricata/log/eve.json`, `/data/p0f/log/p0f.json`
    *   **Payload/artifact excerpts**: `message: SSH client hassh fingerprint: 0a07365cc01fa9fc82608ba4019af499`, `Remote SSH version: SSH-2.0-Go`, `os: Linux 2.2.x-3.x`
    *   **Staging indicators**: N/A
    *   **Temporal checks**: Sustained activity across the investigation window and into the deep investigation window.

*   **Odd-Service-001: IEC104 ICS Protocol Scanning**
    *   **Source IPs**: `138.197.16.14` (13 events in deep investigation window)
    *   **ASNs**: `14061` (DigitalOcean, LLC)
    *   **Target ports/services**: TCP/2404 (IEC104)
    *   **Paths/endpoints**: `/data/conpot/log/conpot_IEC104.json`
    *   **Payload/artifact excerpts**: `event_type: NEW_CONNECTION`, `event_type: CONNECTION_LOST`, `os: Windows NT kernel 5.x`, `os: Linux 3.11 and newer`
    *   **Staging indicators**: N/A
    *   **Temporal checks**: Observed at `2026-02-28T20:13:57Z` and `2026-02-28T20:15:06Z`.

*   **H0neytr4p Sensitive File Probing**
    *   **Source IPs**: `212.56.54.219`, `135.237.127.54`, `34.158.168.101`
    *   **ASNs**: `4213` (Krypt Technologies), `8075` (Microsoft Corporation), `396982` (Google LLC)
    *   **Target ports/services**: TCP/443 (HTTPS)
    *   **Paths/endpoints**: `/global-protect/login.esp`, `/owa/auth/x.js`, `/local.settings.json`, `/service-account.json`, `/firebase-adminsdk.json`, `/db.sql`, `/gcloud-service-key.json`, `/google-credentials.json`, `/keyfile.json`, `/dump.sql`, `/.ssh/id_rsa`, `/serviceAccountKey.json`, `/backup.sql`, `/database.sql`, `/.pgpass`, `/database.yml`, `/.my.cnf`, `/web.config`, `/id_rsa`
    *   **Payload/artifact excerpts**: Varied `user-agent` strings: `Mozilla/5.0 zgrab/0.x`, `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36 Edg/115.0.1901.203`, `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0`, `Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Firefox/121.0`
    *   **Staging indicators**: N/A
    *   **Temporal checks**: Observed between `2026-02-28T20:42:38Z` and `2026-02-28T20:56:30Z`.

## 11) Indicators of Interest

*   **Source IPs**:
    *   `170.64.223.30` (DigitalOcean, LLC) - High volume SSH/VNC scanning
    *   `138.197.16.14` (DigitalOcean, LLC) - IEC104 ICS scanning
    *   `91.224.92.177` - CVE-2025-55182 exploitation
    *   `195.3.221.86` - CVE-2025-55182 exploitation
    *   `40.119.41.94` (Microsoft Corporation) - CVE-2025-31324 reconnaissance
    *   `79.124.40.174` (Tamatiya EOOD) - Spring Boot Actuator reconnaissance
    *   `212.56.54.219` (Krypt Technologies) - H0neytr4p sensitive file probing
    *   `135.237.127.54` (Microsoft Corporation) - H0neytr4p sensitive file probing
*   **Target Ports**:
    *   `22` (SSH)
    *   `80` (HTTP)
    *   `443` (HTTPS)
    *   `2404` (IEC104)
    *   `3000`, `3001` (React Server Components)
    *   `61616` (Apache ActiveMQ)
    *   `9100` (NVMS-9000 Control)
*   **Malicious Paths/URLs**:
    *   `/.env`
    *   `/actuator/gateway/routes`
    *   `/admin/config.php`
    *   `/developmentserver/metadatauploader`
    *   `/global-protect/login.esp`
    *   `/owa/auth/x.js`
    *   `/local.settings.json`
    *   `/db.sql`, `/backup.sql`, `/database.sql`, `/dump.sql`
    *   `/.ssh/id_rsa`, `/id_rsa`, `/.pgpass`, `/.my.cnf`
    *   `/web.config`
    *   `/service-account.json`, `/firebase-adminsdk.json`, `/gcloud-service-key.json`, `/google-credentials.json`, `/keyfile.json`, `/serviceAccountKey.json`
*   **User Agent Strings**:
    *   `xfa1,nvdorz,nvd0rz`
    *   `Mozilla/5.0 zgrab/0.x`
*   **CVE Identifiers**:
    *   `CVE-2025-55182`
    *   `CVE-2023-46604`
    *   `CVE-2024-14007`
    *   `CVE-2025-31324`
    *   `CVE-2022-22947` (implied from path)

## 12) Backend Tool Issues

*   **CandidateDiscoveryAgent**:
    *   The `top_src_ips_for_cve` tool failed to return source IPs for CVE-2025-55182, CVE-2023-46604, and CVE-2024-14007 during initial discovery. This required manual extraction of IPs for CVE-2025-55182 during the validation loop, and source IPs for CVE-2023-46604 and CVE-2024-14007 are still not fully determined.
    *   An initial query for ConPot honeypot data experienced issues due to a casing mismatch in the "type" field (`Conpot` vs `ConPot`), which was subsequently resolved by using `discover_by_keyword`.
*   **DeepInvestigationAgent**:
    *   Several `two_level_terms_aggregated` queries were marked as `misconfigured` in their log outputs. While some relevant data was still extracted from other queries, this indicates a potential loss of comprehensive aggregation for source IP to port/path relationships.
    *   One `two_level_terms_aggregated` tool call `failed` outright due to a `parse_exception` with the `lte_time_stamp` parameter (`2026-02-28TT21:07:40Z` contained an extra 'T'). This directly blocked a deeper aggregation for `/data/h0neytr4p/log/log.json` paths and IPs.

**Weakened Conclusions**: The missing source IP context for CVE-2023-46604 and CVE-2024-14007 means the campaign shapes and infrastructure mapping for these specific exploitation attempts are less certain. The aggregation failures in deep investigation limited the ability to automatically discover broader correlations across different honeypots for specific IPs.

## 13) Agent Action Summary (Audit Trail)

*   **agent_name**: ParallelInvestigationAgent
    *   **purpose**: Collect baseline, known signals, credential noise, and honeypot-specific data concurrently.
    *   **inputs_used**: `gte_time_stamp`, `lte_time_stamp`
    *   **actions_taken**: Executed multiple `get_alert_signature`, `get_cve`, `get_alert_category`, `redis_duration_and_bytes`, `adbhoney_input`, `adbhoney_malware_samples`, `conpot_input`, `tanner_unifrom_resource_search`, `conpot_protocol`, `get_total_attacks`, `get_top_countries`, `get_attacker_src_ip`, `get_country_to_port`, `get_attacker_asn`, `get_input_usernames`, `get_input_passwords`, `get_p0f_os_distribution` tool calls.
    *   **key_results**: Gathered 9790 total attacks, top 5 countries (Australia, US, UK, Canada, Germany), top 5 source IPs (e.g., 170.64.223.30 with 4044 attacks), top 5 ASNs (DigitalOcean, LLC with 7152 counts), top 10 alert signatures (e.g., VNC server response with 1655 counts, SSH invalid banner with 354 counts), 3 CVEs (CVE-2025-55182, CVE-2023-46604, CVE-2024-14007), common username/password lists from brute-force (e.g., 'root', '123456'), and initial honeypot interaction data (Tanner URIs, ConPot IEC104 events).
    *   **errors_or_gaps**: None.

*   **agent_name**: CandidateDiscoveryAgent
    *   **purpose**: Identify high-signal items from initial data, classify them, and prepare candidates for validation.
    *   **inputs_used**: `baseline_result`, `known_signals_result`, `credential_noise_result`, `honeypot_specific_result`
    *   **actions_taken**: Performed 1 `top_http_urls_for_src_ip` query, 1 `two_level_terms_aggregated` (dest_port to src_ip), 4 `kibanna_discover_query` calls for Tanner paths, 2 `kibanna_discover_query` calls for Conpot, 1 `field_presence_check`, 1 `match_query`, 1 `suricata_lenient_phrase_search`, 1 `discover_by_keyword`, 6 `top_src_ips_for_cve`/`top_dest_ports_for_cve` calls (for 3 CVEs), and 4 `timeline_counts`.
    *   **key_results**: Identified 3 CVE-mapped exploitation candidates, 1 botnet/campaign infrastructure candidate, 1 novel exploit candidate (web app recon), and 1 odd-service/minutia attack candidate. Generated an initial triage summary and categorized known exploit exclusions.
    *   **errors_or_gaps**: `top_src_ips_for_cve` returned no source IPs for CVEs. Initial queries for Conpot results were impacted by a casing issue, but successfully resolved by a subsequent `discover_by_keyword`.

*   **agent_name**: CandidateValidationLoopAgent
    *   **iterations run**: 1
    *   **# candidates validated**: 1 (`cve-2025-55182`)
    *   **early exit reason**: Not explicitly stated, but deep investigation commenced on other high-signal candidates.
    *   **inputs_used**: Candidate queue, current time.
    *   **actions_taken**: Called `suricata_cve_samples` for `cve-2025-55182`.
    *   **key_results**: Enriched `cve-2025-55182` candidate with specific source IPs (`91.224.92.177`, `195.3.221.86`) and HTTP request details.
    *   **errors_or_gaps**: None for its own operations, but highlighted the missing source IP context for other CVEs.

*   **agent_name**: DeepInvestigationLoopController
    *   **iterations run**: 8
    *   **key leads pursued**: `src_ip:170.64.223.30` (SSH scanning), `service:IEC104 (TCP/2404)` (ICS probing), `path:/.env` (web recon), `src_ip:34.158.168.101` (web recon), `path:/actuator/gateway/routes` (web recon), `path:/data/h0neytr4p/log/log.json` (sensitive file probing), `src_ip:212.56.54.219` (sensitive file probing).
    *   **stall/exit reason**: `exit_loop` was requested by the agent after sufficient investigation depth or exhausting immediate leads.
    *   **inputs_used**: Candidate details, current time.
    *   **actions_taken**: Performed multiple calls to `events_for_src_ip`, `two_level_terms_aggregated`, `kibanna_discover_query`, and `web_path_samples`.
    *   **key_results**: Confirmed high-volume SSH scanning from `170.64.223.30`. Detailed IEC104 interaction from `138.197.16.14`. Identified multiple IPs and associated user agents probing sensitive web paths (`/.env`, `/actuator/gateway/routes`, and numerous H0neytr4p paths for config/credential files). Added several new IPs, paths, and user agents as leads.
    *   **errors_or_gaps**: Multiple `two_level_terms_aggregated` queries were `misconfigured`, and one `two_level_terms_aggregated` query `failed` due to a timestamp format error, limiting some deeper correlations.

*   **agent_name**: OSINTAgent
    *   **purpose**: Validate and enrich candidates with external threat intelligence.
    *   **inputs_used**: CVEs, IPs, paths, user agents from previous stages.
    *   **actions_taken**: Executed 9 `search_agent` tool calls for various CVEs, IPs, web paths, and user agents.
    *   **key_results**: Confirmed known status for CVE-2023-46604 and CVE-2024-14007. Validated `botnet-infra-001` as common DigitalOcean-hosted scanning. Mapped `/.env`, `/actuator/gateway/routes`, `/admin/config.php`, and `/developmentserver/metadatauploader` to known web application vulnerabilities and reconnaissance. Identified `xfa1 nvdorz` and `Mozilla/5.0 zgrab/0.x` as known scanning user agents. Confirmed IEC104 activity as known ICS reconnaissance.
    *   **errors_or_gaps**: None.

*   **agent_name**: ReportAgent (self)
    *   **purpose**: Compile the final report from workflow state outputs.
    *   **inputs_used**: `investigation_start`, `investigation_end`, `baseline_result`, `known_signals_result`, `credential_noise_result`, `honeypot_specific_result`, `candidate_discovery_result`, `validated_candidates`, `osint_validation_result`, deep investigation logs/state.
    *   **actions_taken**: Compiled all available information into the specified markdown report format.
    *   **key_results**: This comprehensive threat report.
    *   **errors_or_gaps**: None.

*   **agent_name**: SaveReportAgent
    *   **purpose**: Save the completed report to a file.
    *   **inputs_used**: Completed markdown report content.
    *   **actions_taken**: (No direct tool call result provided for this agent in the input, assumes successful file write).
    *   **key_results**: Report saved (assumed).
    *   **errors_or_gaps**: No status for the file write was provided in the workflow state.
