# Honeypot Threat Hunting Report

### 1) Investigation Scope
- **investigation_start:** 2026-03-02T03:00:20Z
- **investigation_end:** 2026-03-02T04:00:20Z
- **completion_status:** Partial (degraded evidence)
- **degraded_mode:** true. Key investigation pivots were blocked by persistent failures in the `kibanna_discover_query` and `two_level_terms_aggregated` tools, preventing full infrastructure mapping and source identification for some threats.

### 2) Executive Triage Summary
- **Top Services/Ports of Interest:** High-volume scanning activity was observed against VNC services (multiple ports) and SSH (22). Targeted, exploit-like activity was focused on HTTP (80), with low-volume interactions on Android Debug Bridge (ADB) ports.
- **Top Confirmed Known Exploitation:** A multi-exploit campaign was identified from source IP `37.120.213.13`. This actor attempted to exploit vulnerabilities in PHPUnit (CVE-2017-9841), PHP CGI (CVE-2024-4577), ThinkPHP, and PEAR, and also scanned for exposed Docker APIs.
- **Top Unmapped Exploit-like Items:** No high-confidence novel candidates remain. The primary candidate was successfully mapped to a known threat actor.
- **Botnet/Campaign Mapping Highlights:** The campaign from `37.120.213.13` was conclusively identified through OSINT as the **RedTail cryptomining botnet**. The unique user agent `libredtail-http` served as a high-fidelity indicator linking all observed TTPs.
- **Major Uncertainties:** The source IPs responsible for downloading three distinct malware samples via the Adbhoney honeypot could not be determined due to tool failures. The full scale of the RedTail campaign (i.e., whether other IPs were involved) could not be assessed due to data aggregation tool issues.

### 3) Candidate Discovery Summary
- The discovery phase identified two primary areas of interest:
    1.  Targeted HTTP exploit attempts against PHPUnit and a PHP Local/Remote File Inclusion (LFI/RFI) endpoint. These were quickly correlated to a single source IP: `37.120.213.13`.
    2.  The download of three malware samples on the Adbhoney (Android) honeypot.
- The investigation into the Adbhoney activity was blocked due to repeated failures of the `kibanna_discover_query` tool, preventing source IP identification. The HTTP exploit attempts were forwarded for validation as a single high-confidence candidate.

### 4) Emerging n-day Exploitation
- **Item ID:** RedTail-Botnet-Campaign-1
- **cve/signature mapping:**
    - CVE-2017-9841 (PHPUnit RCE)
    - CVE-2024-4577 (PHP CGI RCE via Argument Injection)
    - ThinkPHP RCE (related to CVE-2018-20062 / CVE-2019-9082)
    - PEARCMD RCE via LFI (related to CVE-2022-47945)
- **evidence summary:** A single source IP (`37.120.213.13`) was observed conducting a series of exploit attempts against multiple web application frameworks. All requests from this actor shared the unique user agent `libredtail-http`. OSINT validation confirmed this signature belongs to the RedTail botnet.
- **affected service/port:** HTTP (80)
- **confidence:** High
- **operational notes:** This actor is leveraging a toolkit that includes both older, widely exploited vulnerabilities and a very recent, critical vulnerability (CVE-2024-4577). The user agent `libredtail-http` is a strong indicator for this campaign.

### 6) Botnet/Campaign Infrastructure Mapping
- **item_id:** Candidate-1 / RedTail Botnet
- **campaign_shape:** Fan-out (all observed activity originated from a single source IP in this window).
- **suspected_compromised_src_ips:** `37.120.213.13`
- **ASNs / geo hints:** AS9009 (M247 Europe SRL), Zurich, Switzerland.
- **suspected_staging indicators:** None observed in telemetry.
- **suspected_c2 indicators:** No C2 communication was directly observed in the honeypot logs. However, OSINT reports link the `libredtail-http` user agent to known RedTail C2 infrastructure, such as `178.16.55.224`. This connection is based on external reporting, not direct evidence from this investigation period.
- **confidence:** High
- **operational notes:** The source IP `37.120.213.13` should be blocked. Network monitoring for the user agent `libredtail-http` can provide early warning of related activity.

### 7) Odd-Service / Minutia Attacks
- **service_fingerprint:** Android Debug Bridge (ADB), likely port 5555.
- **why it’s unusual/interesting:** Indicates automated attempts to compromise exposed ADB instances on IoT devices, mobile testing environments, or containers to propagate malware.
- **evidence summary:** Three distinct malware samples were downloaded to the Adbhoney honeypot. The source IP(s) of these download attempts could not be identified due to tool failures.
- **confidence:** High (that the event occurred), Inconclusive (on scope and source).
- **recommended monitoring pivots:** Prioritize fixing the `kibanna_discover_query` tool to allow for source attribution of Adbhoney events. Monitor network traffic for the downloaded malware hashes.

### 8) Known-Exploit / Commodity Exclusions
- **VNC Scanning:** High volume of events (2,031) with the signature "GPL INFO VNC server response" seen across many IPs, indicating widespread, untargeted scanning for open VNC servers.
- **SSH Credential Stuffing:** Standard brute-force attacks against SSH (port 22) using common username (`root`, `admin`, `test`) and password (`123456`, `password`) lists.
- **RDP Scanning:** Activity matching "ET SCAN MS Terminal Server Traffic on Non-standard Port" indicates scanning for Remote Desktop Protocol services.
- **General Scanning Noise:** A baseline of miscellaneous scanning across various ports and protocols from a large, distributed set of source IPs, primarily originating from cloud hosting providers like DigitalOcean.

### 9) Infrastructure & Behavioral Classification
- **RedTail Botnet (`37.120.213.13`):**
    - **Behavior:** Active Exploitation (multi-vulnerability).
    - **Campaign Shape:** Fan-out from a single observed source.
    - **Infra Reuse:** Not observed in this window, but the toolkit is known to be reused globally.
    - **Odd-Service Fingerprints:** Targeted multiple common but often-vulnerable web application components (PHPUnit, ThinkPHP) and infrastructure (Docker API).
- **Commodity Noise:**
    - **Behavior:** Scanning and Credential Stuffing.
    - **Campaign Shape:** Spray (large number of sources, broad targets).
    - **Infra Reuse:** High IP churn, typical of commodity scanners.
    - **Odd-Service Fingerprints:** Focused on well-known services like VNC and SSH.

### 10) Evidence Appendix
**Item: RedTail Botnet Campaign (Candidate-1)**
- **source IPs:** `37.120.213.13` (173+ related events observed).
- **ASNs:** AS9009 (M247 Europe SRL).
- **target ports/services:** 80 (HTTP).
- **paths/endpoints:**
    - `/V2/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php` (and other variants)
    - `/?%ADd+allow_url_include%3d1+%ADd+auto_prepend_file%3dphp://input`
    - `/public/index.php?s=/index/\think\app/invokefunction&...`
    - `/index.php?lang=../../../../../../../../usr/local/lib/php/pearcmd&+config-create...`
    - `/containers/json`
- **payload/artifact excerpts:**
    - **User Agent:** `libredtail-http`
- **staging indicators:** None observed.
- **temporal checks:** Activity was consistent within the 1-hour investigation window.

### 11) Indicators of Interest
- **IP:** `37.120.213.13`
- **User-Agent:** `libredtail-http`
- **Paths:**
    - `/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php`
    - `/?s=/index/\think\app/invokefunction`
    - `/index.php?lang=../../../../../../../../usr/local/lib/php/pearcmd`
    - `/containers/json`
- **Malware Hashes (from Adbhoney filenames):**
    - `4251293b2d3765833f16988c2dbec30362df1c84dfe33c58dcc0815596d31353`
    - `9a56e2c761e10156cac6589bc9e929b1b8b5b00dd6c79ca0d33c2399b88e3a43`
    - `9bc28777e722c46898754ef256d052e9cd684f6ad812d69878c68ba6cc0c72fe`

### 12) Backend Tool Issues
- **`kibanna_discover_query`:** This tool failed repeatedly with an `illegal_argument_exception`. This critical failure blocked the investigation into Adbhoney malware downloads, preventing the identification of source IPs. It also blocked payload inspection during candidate validation.
- **`two_level_terms_aggregated`:** This tool failed to return expected results when pivoting on certain keywords (e.g., the `libredtail-http` user agent and the `/containers/json` path), even though events containing these keywords were confirmed to exist. This prevented an assessment of the RedTail campaign's full scale.

### 13) Agent Action Summary (Audit Trail)
- **agent_name:** ParallelInvestigationAgent
- **purpose:** Perform initial parallel data collection across different data sources.
- **inputs_used:** `investigation_start`, `investigation_end`.
- **actions_taken:** Executed baseline, known signal, credential noise, and honeypot-specific queries.
- **key_results:**
    - Established baseline of 8904 attacks.
    - Identified high-volume VNC scanning (2031 events).
    - Confirmed standard credential stuffing patterns.
    - Uncovered initial leads: PHPUnit exploit paths and Adbhoney malware downloads.
- **errors_or_gaps:** None.

- **agent_name:** CandidateDiscoveryAgent
- **purpose:** Synthesize triage data to discover novel or high-value leads.
- **inputs_used:** `baseline_result`, `known_signals_result`, `credential_noise_result`, `honeypot_specific_result`.
- **actions_taken:** Merged triage data; identified PHPUnit/LFI and Adbhoney seeds; used `two_level_terms_aggregated` to link PHPUnit/LFI attempts to `37.120.213.13`; attempted to pivot on Adbhoney data.
- **key_results:**
    - Created a high-confidence candidate for the PHPUnit/LFI activity from a single source IP.
    - Identified that the Adbhoney investigation path was blocked.
- **errors_or_gaps:** The investigation into Adbhoney malware was blocked by three consecutive failures of the `kibanna_discover_query` tool.

- **agent_name:** CandidateValidationLoopAgent
- **purpose:** Validate and enrich discovered candidates.
- **inputs_used:** Candidate queue from `CandidateDiscoveryAgent`.
- **actions_taken:** Processed 1 candidate; ran OSINT searches on exploit path and source IP.
- **key_results:**
    - Confirmed the PHPUnit exploit path is for CVE-2017-9841.
    - Found public abuse reports for the source IP `37.120.213.13`.
    - Classified the candidate as a `known_exploit_campaign`.
- **errors_or_gaps:** `kibanna_discover_query` failures blocked inspection of raw event payloads.

- **agent_name:** DeepInvestigationLoopController
- **purpose:** Perform deep-dive analysis on high-value validated candidates.
- **inputs_used:** Validated candidate `37.120.213.13`.
- **actions_taken:** Ran 5 iterations pursuing leads starting with the source IP. Pivoted to investigate ThinkPHP, PEARCMD, and Docker API scanning TTPs. Identified the unique `libredtail-http` user agent.
- **key_results:**
    - Expanded the known TTPs of the actor beyond the initial PHPUnit exploit.
    - Uncovered the `libredtail-http` user agent as a unifying indicator for all of the actor's activity.
    - Linked behavior to multiple additional CVEs.
- **errors_or_gaps:** The loop was exited after stalling twice due to `two_level_terms_aggregated` failing to return data for the user agent and other pivots, which blocked attempts to scale the campaign beyond the single source IP.

- **agent_name:** OSINTAgent
- **purpose:** Validate internal findings against public threat intelligence.
- **inputs_used:** `validated_candidates`, `deep_investigation_log`.
- **actions_taken:** Performed OSINT searches for the PHPUnit path, the PHP LFI/RFI technique, and the `libredtail-http` user agent.
- **key_results:**
    - Confirmed the PHPUnit path is for CVE-2017-9841.
    - Confirmed the LFI/RFI technique is used to exploit the recent, critical CVE-2024-4577.
    - Conclusively linked the `libredtail-http` user agent to the **RedTail cryptomining botnet**.
- **errors_or_gaps:** None.

- **agent_name:** ReportAgent
- **purpose:** Builds finale report from workflow state (no new searching).
- **inputs_used:** All available workflow state outputs.
- **actions_taken:** Compiled and formatted the final report based on the evidence gathered by previous agents.
- **key_results:** This markdown report.
- **errors_or_gaps:** Input state was degraded due to upstream tool failures, noted in the report.

- **agent_name:** SaveReportAgent
- **purpose:** Persists the final report to storage.
- **inputs_used:** Final markdown report content.
- **actions_taken:** Call `investigation_write_file`.
- **key_results:** Report successfully queued for saving.
- **errors_or_gaps:** None.
