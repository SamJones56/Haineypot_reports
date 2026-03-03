# Honeypot Threat Hunting Report

### 1) Investigation Scope
- **investigation_start:** 2026-03-01T12:20:12Z
- **investigation_end:** 2026-03-01T13:20:12Z
- **completion_status:** Partial (degraded evidence)
- **degraded_mode:** true. Investigation was severely hampered by persistent failures in core data retrieval tools (`kibanna_discover_query`, `two_level_terms_aggregated`), which blocked validation and analysis of multiple high-signal candidates.

### 2) Executive Triage Summary
- **Top Services/Ports of Interest:** High-volume, targeted activity was observed on port 443 (HTTPS) from a single source. Widespread scanning occurred on port 5900 (VNC).
- **Odd/Minutia Services:** An unusual `guardian_ast` protocol, associated with ICS/SCADA systems, was detected in the Conpot honeypot, but further investigation was blocked.
- **Top Confirmed Known Exploitation:** An attempt to exploit the PHPUnit RCE vulnerability (CVE-2017-9841) was confirmed via a URI path match. This is considered commodity activity.
- **Top Unmapped Exploit-Like Items:** A targeted campaign from source IP `160.119.76.250` sent hundreds of requests to specific `ajax.php` endpoints, all containing the same unique MD5 query parameter. This activity remains unmapped to a known threat.
- **Botnet/Campaign Mapping Highlights:** Two distinct campaigns were identified:
    - A targeted HTTPS campaign from `160.119.76.250` (Seychelles, ASN 49870).
    - A distributed, multi-source `spray` campaign scanning for open VNC servers on port 5900.
- **Major Uncertainties:** Due to tool failures, the ultimate goal of the HTTPS campaign, the scope of the PHPUnit exploit attempt, and the nature of the `guardian_ast` activity could not be determined.

### 3) Candidate Discovery Summary
The discovery phase identified four primary candidates for investigation, though enrichment was hindered by query failures:
- **Known Exploit Path:** `/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php` (implying CVE-2017-9841).
- **Unusual Service:** `guardian_ast` protocol on the Conpot honeypot (37 events).
- **Botnet/Campaign IP:** `160.119.76.250` targeting port 443 (564 events).
- **Known Vulnerability:** `CVE-2024-14007` (4 events).

### 4) Novel Exploit Candidates (UNMAPPED ONLY, ranked)
*No candidates were fully validated and promoted to this category due to tool failures blocking analysis. The activity from `160.119.76.250` detailed in the Botnet section is the strongest lead for future investigation.*

### 5) Botnet/Campaign Infrastructure Mapping

**Item 1: Targeted HTTPS Campaign**
- **item_id:** `campaign-160.119.76.250`
- **campaign_shape:** `targeted_activity` (single source, high-volume)
- **suspected_compromised_src_ips:** `160.119.76.250` (564+ events)
- **ASNs / geo hints:** ASN 49870 (Alsycon B.V.), Seychelles
- **suspected_staging indicators:**
    - URI Path: `/admin/modules/_cache/ajax.php`
    - URI Path: `/rest_phoness/ajax.php`
    - URI Path: `/vtigercrmxx/ajax.php`
    - Shared Artifact: `?md5=df7f545f04bfb7836ecca1923ec2bb7b` in all requests.
- **suspected_c2 indicators:** None identified.
- **confidence:** Moderate (for coordinated activity), Low (for impact/goal, due to blocked analysis).
- **operational notes:** This appears to be a specific, automated campaign. The shared MD5 artifact is a high-confidence indicator. Monitor for other sources using these URIs.

**Item 2: Distributed VNC Scanning Campaign**
- **item_id:** `vnc-scan-5900`
- **campaign_shape:** `spray`
- **suspected_compromised_src_ips:** `144.229.29.3`, `144.229.29.120`, `162.248.102.10`, `213.21.253.75`, `45.127.4.62` (and others).
- **ASNs / geo hints:** Unavailable due to tool failure.
- **suspected_staging indicators:** None identified.
- **confidence:** High (commodity scanning activity).
- **operational notes:** Standard internet background noise scanning for open VNC services. Block and monitor.

### 6) Odd-Service / Minutia Attacks

**Item 1: Conpot ICS Protocol Activity**
- **service_fingerprint:** `guardian_ast` protocol (Conpot Honeypot)
- **why it’s unusual/interesting:** The `guardian_ast` protocol is associated with SCADA/ICS systems for monitoring industrial equipment (e.g., gas turbines), making its appearance in general internet traffic highly anomalous.
- **evidence summary:** 37 events were recorded by the Conpot honeypot. Investigation into source IPs and actions was blocked by tool failures.
- **confidence:** Low (Monitor Only)
- **recommended monitoring pivots:** Prioritize fixing the `two_level_terms_aggregated` tool to enable investigation of source IPs interacting with the Conpot service.

### 7) Known-Exploit / Commodity Exclusions
- **PHPUnit RCE Attempt (CVE-2017-9841):** A single request to `/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php` was logged. OSINT confirmed this is a widely known, established vulnerability from 2017.
- **VNC Scanning (Port 5900):** Widespread scanning activity confirmed by 1,843 `GPL INFO VNC server response` alerts from numerous IPs.
- **Credential Noise:** Standard brute-force attempts observed using common usernames (`root`, `admin`) and passwords (`123456`, `password`).
- **MS Terminal Server Scanning:** 195 `ET SCAN MS Terminal Server Traffic on Non-standard Port` alerts indicate broad scanning for RDP.
- **Low-Volume CVE Alerts:** A small number of alerts (4) for `CVE-2024-14007` were seen but could not be investigated further.

### 8) Infrastructure & Behavioral Classification
- **exploitation vs scanning:**
    - The `160.119.76.250` activity is classified as **targeted exploitation** due to the specific, repeated URIs with a unique artifact.
    - The Port 5900 VNC activity is classified as **scanning**.
    - The PHPUnit URI request is classified as **exploit scanning**.
- **campaign shape:**
    - The HTTPS campaign is a single-source, high-volume targeted activity.
    - The VNC campaign is a distributed `spray`.
- **infra reuse indicators:** The query string `?md5=df7f545f04bfb7836ecca1923ec2bb7b` is a strong indicator of campaign-specific tooling.
- **odd-service fingerprints:** The `guardian_ast` protocol on the Conpot honeypot is a significant anomaly.

### 9) Evidence Appendix

**Item: Targeted HTTPS Campaign (`campaign-160.119.76.250`)**
- **source IPs:** `160.119.76.250` (564+ events)
- **ASNs:** 49870 (Alsycon B.V.)
- **target ports/services:** 443 (HTTPS)
- **paths/endpoints:** `/admin/modules/_cache/ajax.php`, `/rest_phoness/ajax.php`, `/vtigercrmxx/ajax.php`
- **payload/artifact excerpts:** `?md5=df7f545f04bfb7836ecca1923ec2bb7b`
- **temporal checks:** Active within a 23-minute window from `2026-03-01T12:26:14Z` to `2026-03-01T12:49:03Z`.

**Item: PHPUnit RCE Attempt (`uri_path:/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php`)**
- **source IPs:** Unknown due to tool failure.
- **ASNs:** Unknown.
- **target ports/services:** HTTP (Tanner Honeypot)
- **paths/endpoints:** `/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php`
- **payload/artifact excerpts:** Implied CVE-2017-9841
- **temporal checks:** unavailable

### 10) Indicators of Interest
- **IP:** `160.119.76.250`
- **URI:** `/admin/modules/_cache/ajax.php?md5=df7f545f04bfb7836ecca1923ec2bb7b`
- **URI:** `/rest_phoness/ajax.php?md5=df7f545f04bfb7836ecca1923ec2bb7b`
- **URI:** `/vtigercrmxx/ajax.php?md5=df7f545f04bfb7836ecca1923ec2bb7b`
- **Artifact:** `df7f545f04bfb7836ecca1923ec2bb7b`
- **URI:** `/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php`

### 11) Backend Tool Issues
- **`kibanna_discover_query`**: Failed repeatedly with an `illegal_argument_exception`. This critical failure blocked investigation of the PHPUnit exploit source, the scope of the HTTPS campaign, and other leads.
- **`two_level_terms_aggregated`**: Returned empty results when querying Conpot and Suricata alert data. This blocked the investigation into the `guardian_ast` protocol and prevented a full mapping of the VNC scanning campaign.
- **`top_http_urls_for_src_ip`**: Failed to return URLs for the primary campaign IP, forcing a less efficient raw log analysis.
- **`top_src_ips_for_cve`**: Failed to retrieve source IPs for CVE alerts, blocking that investigation path.
- **Weakened Conclusions:** The root cause and full scope of every major finding are uncertain due to these pervasive tool failures. Classifications are provisional and based on incomplete data.

### 12) Agent Action Summary (Audit Trail)

- **agent_name:** ParallelInvestigationAgent
- **purpose:** Gathers broad, initial telemetry across different domains.
- **inputs_used:** `investigation_start`, `investigation_end`.
- **actions_taken:** Executed `BaselineAgent`, `KnownSignalAgent`, `CredentialNoiseAgent`, and `HoneypotSpecificAgent` sub-agents to collect initial data.
- **key_results:**
    - Identified 6,072 total attacks.
    - Flagged top source IP `160.119.76.250`.
    - Identified top alert `GPL INFO VNC server response`.
    - Found odd-service indicators: PHPUnit path and `guardian_ast` protocol.
- **errors_or_gaps:** None.

- **agent_name:** CandidateDiscoveryAgent
- **purpose:** Sifts through parallel agent outputs to create focused investigation seeds.
- **inputs_used:** `baseline_result`, `known_signals_result`, `credential_noise_result`, `honeypot_specific_result`.
- **actions_taken:** Created four candidate seeds (PHPUnit path, `guardian_ast`, `160.119.76.250`, CVE-2024-14007) and attempted initial data queries.
- **key_results:** Successfully prioritized high-signal events for deeper analysis.
- **errors_or_gaps:** Multiple query tools failed (`kibanna_discover_query`, `two_level_terms_aggregated`, etc.), preventing initial enrichment of candidates.

- **agent_name:** CandidateValidationLoopAgent
- **purpose:** Iteratively validates candidates from the discovery queue.
- **inputs_used:** Candidate queue.
- **actions_taken:** Ran for 1 iteration on the PHPUnit candidate. Used `search` and `suricata_lenient_phrase_search`.
- **key_results:** Validated the PHPUnit path as a provisional, known exploit attempt for CVE-2017-9841.
- **errors_or_gaps:** `kibanna_discover_query` failed, blocking source IP identification. The loop did not proceed to other candidates, likely due to the persistent errors.

- **agent_name:** DeepInvestigationLoopController
- **purpose:** Performs deep-dive analysis on high-confidence leads.
- **inputs_used:** `validated_candidates`, internal lead queue.
- **actions_taken:** Ran for 3 iterations, pursuing leads on `160.119.76.250`, its associated MD5 artifact, and the `GPL INFO VNC server response` signature before exiting.
- **key_results:**
    - Characterized the `160.119.76.250` activity as a targeted campaign with specific URI/artifact indicators.
    - Identified multiple source IPs involved in a distributed VNC scanning campaign.
- **errors_or_gaps:** The investigation stalled repeatedly due to `kibanna_discover_query` and `two_level_terms_aggregated` failures, forcing an early exit from the loop.

- **agent_name:** OSINTAgent
- **purpose:** Enriches validated findings with public threat intelligence.
- **inputs_used:** `validated_candidates`.
- **actions_taken:** Performed OSINT lookup on the single validated PHPUnit path candidate.
- **key_results:** Confirmed the path maps to CVE-2017-9841 and is an established, non-novel threat.
- **errors_or_gaps:** Analysis was limited as only one of four initial candidates could be validated due to upstream tool failures.

- **agent_name:** ReportAgent
- **purpose:** Builds finale report from workflow state (no new searching).
- **inputs_used:** All available workflow state outputs.
- **actions_taken:** Compiled this final report.
- **key_results:** Report generated.
- **errors_or_gaps:** None (compilation only).

- **agent_name:** SaveReportAgent
- **purpose:** Writes the final report to a file.
- **inputs_used:** Final report content.
- **actions_taken:** Will call `investigation_write_file`.
- **key_results:** Pending tool execution.
- **errors_or_gaps:** None.