# Honeypot Threat Hunting Report

## 1) Investigation Scope
- **investigation_start:** 2026-03-07T06:00:08Z
- **investigation_end:** 2026-03-07T09:00:08Z
- **completion_status:** Partial
- **degraded_mode:** true
- **brief reason if true:** Only one out of five discovered candidates (BCM-1) underwent full validation and deep investigation. Validation for remaining candidates was not executed due to an early exit of the deep investigation loop. Additionally, one tool failed during BCM-1 validation, affecting direct correlation.

## 2) Executive Triage Summary
- Total attacks observed: 21,740 within the 3-hour window.
- Top services targeted by attackers include VNC (port 5900), SMB (port 445), Redis (port 6379), and unusual Industrial Control System (ICS) protocols (Kamstrup, Guardian AST inferred on Conpot).
- A widespread DoublePulsar backdoor communication campaign (BCM-1) was confirmed on SMB (port 445), originating from multiple compromised IPs in Vietnam and France.
- Redis honeypots detected attempts at remote code execution via module loading (BCM-2), indicating targeted attacks.
- Unusual probing of ICS honeypots (Conpot) using Kamstrup and Guardian AST protocols (OSM-1) suggests specialized interest in industrial infrastructure, although correlation to specific IPs is provisional.
- Commodity activity dominated the overall volume, including high-frequency VNC scanning (17,206 instances) and credential stuffing against common services.
- Major uncertainties include the lack of full validation for four out of five discovered candidates and incomplete correlation for some odd-service attacks.

## 3) Candidate Discovery Summary
- Total attacks detected: 21,740
- Top attacking countries: United States (6,870), Vietnam (3,442), France (2,679)
- Top attacking Source IPs: 113.161.145.128 (3,149), 79.98.102.166 (2,571), 207.174.1.152 (2,001)
- Top Attacker ASNs: DigitalOcean, LLC (4,690), VNPT Corp (3,164), ADISTA SAS (2,571)
- Top alert signatures: GPL INFO VNC server response (17,206), ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication (2,260)
- Top observed CVEs: CVE-2025-55182 (78), CVE-2024-14007 (7)
- Key honeypot activities of interest:
    - Redis RCE attempts, specifically `MODULE LOAD /tmp/exp.so` (7 events).
    - Tanner web exploit probes, including `/V2/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php` (PHPUnit RCE, 1 event) and `/?%ADd+allow_url_include%3d1+%ADd+auto_prepend_file%3dphp://input` (PHP LFI/RFI, 1 event).
    - Conpot Industrial Control System (ICS) protocol interactions, notably Kamstrup management protocol (11 events) and Guardian AST (5 events).
- Five high-signal candidates were identified for further analysis (3 Botnet/Campaign mappings, 1 Odd-Service attack, 1 Suspicious Unmapped Activity). Only one candidate (BCM-1) underwent full validation.

## 4) Emerging n-day Exploitation
*No items classified as Emerging n-day Exploitation in this window.*

## 5) Novel or Zero-Day Exploit Candidates (UNMAPPED ONLY, ranked)
*No items classified as Novel or Zero-Day Exploit Candidates in this window.*

## 6) Botnet/Campaign Infrastructure Mapping

*   **item_id:** BCM-1 (DoublePulsar SMB Exploit Campaign)
    *   **campaign_shape:** spray
    *   **suspected_compromised_src_ips:** 113.161.145.128 (3149 events), 79.98.102.166 (2571 events)
    *   **ASNs / geo hints:** ASN 45899 (VNPT Corp, Vietnam), ASN 16347 (ADISTA SAS, France)
    *   **suspected_staging indicators:** None identified.
    *   **suspected_c2 indicators:** DoublePulsar backdoor communication itself acts as C2 via SMB protocol extensions. No distinct C2 IPs/domains identified beyond the source IPs.
    *   **confidence:** High
    *   **operational notes:** This is a known, widespread SMB backdoor campaign. The source IPs exhibit single-purpose, high-volume scanning behavior. Block source IPs and monitor for continued DoublePulsar signatures on port 445.

*   **item_id:** BCM-2 (Redis RCE Attempt Campaign)
    *   **campaign_shape:** spray
    *   **suspected_compromised_src_ips:** 112.124.33.87 (28 events), 45.91.64.7 (12 events), 66.132.153.127 (6 events)
    *   **ASNs / geo hints:** Not explicitly available from discovery results.
    *   **suspected_staging indicators:** Attempted module load from `/tmp/exp.so` on Redis honeypot.
    *   **suspected_c2 indicators:** None identified.
    *   **confidence:** High
    *   **operational notes:** Investigate `exp.so` payload if available for malware analysis. Block identified source IPs. Monitor Redis deployments for similar RCE attempts via module loading.

*   **item_id:** BCM-3 (Multi-Vulnerability Web Scanner)
    *   **campaign_shape:** fan-out
    *   **suspected_compromised_src_ips:** 111.119.234.232 (46 total events)
    *   **ASNs / geo hints:** Not explicitly available from discovery results.
    *   **suspected_staging indicators:** None identified.
    *   **suspected_c2 indicators:** None identified.
    *   **confidence:** High
    *   **operational notes:** This IP is engaged in broad web vulnerability scanning, including known RCEs like PHPUnit. Consider blocking or blacklisting this source IP. Evaluate if any targeted paths indicate specific web application interest.

## 7) Odd-Service / Minutia Attacks

*   **item_id:** OSM-1 (ICS Protocol Probing via Conpot)
    *   **service_fingerprint:** 102/tcp (S7/ICS - inferred from Conpot protocol types like Kamstrup, Guardian AST)
    *   **why it’s unusual/interesting:** Targeted interaction with an ICS honeypot using uncommon industrial protocols (Kamstrup, Guardian AST) indicates actors interested in non-standard, potentially critical infrastructure attack surfaces.
    *   **evidence summary:** 11 events of `kamstrup_management_protocol`, 5 events of `guardian_ast`, 3 events of `kamstrup_protocol`. Top source IPs aggregated at the Conpot honeypot level include 8.222.169.202 (9 events), 13.219.1.233 (3 events), 205.210.31.69 (3 events).
    *   **confidence:** High
    *   **provisional:** true
    *   **recommended monitoring pivots:** Implement specific correlation queries to link source IPs to exact ICS protocol interactions. Monitor industrial network segments for similar reconnaissance or exploitation attempts.

## 8) Known-Exploit / Commodity Exclusions
- **Credential Noise:** Extensive brute-force activity observed with common usernames (`root`, `postgres`, `ubuntu`, `admin`) and weak passwords (`123`, `123456`, `password`, `345gs5662d34`). This activity was seen across numerous source IPs.
- **Widespread VNC Scanning:** High-volume scanning for VNC servers on port 5900 (17,206 events) detected by the `GPL INFO VNC server response` signature (Signature ID: 2100560). This activity predominantly originated from IP `207.174.1.152` (United States, ASN 398019 Dynu Systems Incorporated).
- **Known PHPUnit RCE Exploitation:** A single instance of an exploitation attempt targeting the known PHPUnit RCE vulnerability (CVE-2017-9841) via path `/V2/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php`. This originated from IP `111.119.234.232`, which was also engaged in broader web scanning, suggesting a commodity scanner.
- **Generic HTTP/Web Scanning:** Numerous requests for common web paths such as `/`, `/.env`, `/robots.txt`, and administrative interfaces (`/admin/index.html`), indicative of automated web reconnaissance.

## 9) Infrastructure & Behavioral Classification
- **Exploitation vs. Scanning:**
    - DoublePulsar (BCM-1) and Redis RCE (BCM-2) are classified as direct exploitation attempts.
    - The Multi-Vulnerability Web Scanner (BCM-3) combines extensive scanning with embedded known exploitation attempts (PHPUnit RCE).
    - VNC activity (KEE-1) and credential noise are categorized as pure scanning/brute-forcing.
    - ICS Probing (OSM-1) represents targeted reconnaissance.
- **Campaign Shape:**
    - DoublePulsar (BCM-1) and Redis RCE (BCM-2) campaigns exhibit a "spray" pattern, originating from multiple distinct source IPs.
    - The Multi-Vulnerability Web Scanner (BCM-3) displays a "fan-out" pattern, with a single source IP probing a wide array of vulnerabilities.
    - ICS Probing (OSM-1) appears to be a "spray" from multiple IPs.
- **Infra Reuse Indicators:** No direct evidence of infrastructure reuse across different campaign types within this investigation window. Each identified campaign appears to utilize dedicated, potentially compromised, hosts.
- **Odd-Service Fingerprints:** The dedicated targeting and use of specific industrial control system protocols (Kamstrup, Guardian AST) on the Conpot honeypot highlight a distinct interest in niche, potentially critical infrastructure targets. Redis module loading attempts indicate a more sophisticated RCE strategy beyond simple brute-force.

## 10) Evidence Appendix

*   **BCM-1 (DoublePulsar SMB Exploit Campaign)**
    *   **source IPs with counts:** 113.161.145.128 (3149 events), 79.98.102.166 (2571 events)
    *   **ASNs with counts:** 45899 (VNPT Corp, Vietnam), 16347 (ADISTA SAS, France)
    *   **target ports/services:** 445/tcp (SMB)
    *   **paths/endpoints:** N/A (protocol-level exploitation)
    *   **payload/artifact excerpts:** `ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication` (Suricata Signature ID 2024766). Sample events show `dest_port: 445`, `alert: {'signature': 'ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication', 'category': 'Attempted Administrator Privilege Gain'}`.
    *   **staging indicators:** None observed.
    *   **temporal checks results:** IP 113.161.145.128 active between 2026-03-07T07:07:38Z and 2026-03-07T07:51:12Z (44 minutes). IP 79.98.102.166 active between 2026-03-07T07:25:06Z and 2026-03-07T07:50:08Z (25 minutes).

*   **BCM-2 (Redis RCE Attempt Campaign)**
    *   **source IPs with counts:** 112.124.33.87 (28 events), 45.91.64.7 (12 events), 66.132.153.127 (6 events)
    *   **ASNs with counts:** Not explicitly available from discovery results.
    *   **target ports/services:** 6379/tcp (Redis)
    *   **paths/endpoints:** N/A (Redis commands)
    *   **payload/artifact excerpts:** `redis command: MODULE LOAD /tmp/exp.so`, `config set dbfilename dump.rdb` (from Redis honeypot actions)
    *   **staging indicators:** Inferred staging of `exp.so` in `/tmp/`
    *   **temporal checks results:** Unavailable (not subjected to full validation loop).

*   **BCM-3 (Multi-Vulnerability Web Scanner)**
    *   **source IPs with counts:** 111.119.234.232 (46 total events)
    *   **ASNs with counts:** Not explicitly available from discovery results.
    *   **target ports/services:** (Inferred) 80/tcp, 443/tcp
    *   **paths/endpoints:** `/V2/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php`, `/?%ADd+allow_url_include%3d1+%ADd+auto_prepend_file%3dphp://input`, `/cgi-bin/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/bin/sh`, `/admin/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php`, `/api/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php`, `/app/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php`, `/apps/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php`, `/backup/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php`, `/blog/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php`, `/cms/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php`
    *   **payload/artifact excerpts:** N/A (paths are the primary artifact)
    *   **staging indicators:** None observed.
    *   **temporal checks results:** Unavailable (not subjected to full validation loop).

*   **OSM-1 (ICS Protocol Probing via Conpot)**
    *   **source IPs with counts:** 8.222.169.202 (9 events), 13.219.1.233 (3 events), 205.210.31.69 (3 events)
    *   **ASNs with counts:** Not explicitly available from discovery results.
    *   **target ports/services:** Conpot-simulated ICS services (e.g., S7 on 102/tcp).
    *   **paths/endpoints:** `GET / HTTP/1.1`, `GET /favicon.ico HTTP/1.1`, `b'\x01I20100'`
    *   **payload/artifact excerpts:** Protocols detected: `kamstrup_management_protocol`, `guardian_ast`, `kamstrup_protocol`.
    *   **staging indicators:** None observed.
    *   **temporal checks results:** Unavailable (not subjected to full validation loop).

## 11) Indicators of Interest
- **Source IPs (DoublePulsar Campaign):**
    - 113.161.145.128
    - 79.98.102.166
- **Source IPs (Redis RCE Attempts):**
    - 112.124.33.87
    - 45.91.64.7
    - 66.132.153.127
- **Source IP (Multi-Vulnerability Web Scanner):**
    - 111.119.234.232
- **Source IPs (ICS Protocol Probing):**
    - 8.222.169.202
    - 13.219.1.233
    - 205.210.31.69
- **Suricata Signature IDs:**
    - 2024766 (ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication)
- **Targeted Ports/Protocols:**
    - 445/tcp (SMB)
    - 6379/tcp (Redis)
    - ICS Protocols (Kamstrup, Guardian AST)
- **Paths/Artifacts (Web Scanner):**
    - `/V2/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php`
    - `/?%ADd+allow_url_include%3d1+%ADd+auto_prepend_file%3dphp://input`
- **Redis Commands:**
    - `MODULE LOAD /tmp/exp.so`
    - `CONFIG SET dbfilename dump.rdb`
    - `CONFIG SET dir /tmp/`

## 12) Backend Tool Issues
- **Tool Failure:** `two_level_terms_aggregated` during Candidate BCM-1 validation (failed to aggregate on `alert.signature.keyword`).
    - **Affected validations:** Direct correlation of source IPs to the specific Suricata signature for BCM-1.
    - **Weakened conclusions:** While high confidence was maintained through inferential evidence and sample analysis, a direct programmatic link was not established by this tool.
- **Partial Validation/Evidence Gap:** No direct query was performed to correlate source IPs to specific Conpot protocols for `OSM-1`.
    *   **Affected validations:** Specific attribution of ICS protocol interactions to individual source IPs remains provisional.
    *   **Weakened conclusions:** The precise source-to-exploit mapping for the ICS activity is less granular, necessitating further follow-up.
- **Early Exit of Deep Investigation Loop:** The `DeepInvestigationLoopController` processed only the first candidate (BCM-1) and its derived leads before exiting.
    - **Affected validations:** Candidates BCM-2, BCM-3, OSM-1, and SUM-1 did not undergo a full validation and deep investigation cycle.
    - **Weakened conclusions:** Detailed infrastructure mapping, comprehensive temporal checks, and advanced artifact analysis are limited to initial discovery data for these unvalidated candidates.

## 13) Agent Action Summary (Audit Trail)

*   **ParallelInvestigationAgent (and its sub-agents)**
    *   **purpose:** Gather initial baseline, known signal, credential noise, and honeypot-specific data concurrently.
    *   **inputs_used:** Workflow state (investigation start and end times).
    *   **actions_taken:** BaselineAgent queried for total attacks, top countries, source IPs, country-to-port maps, and ASNs. KnownSignalAgent queried for alert signatures, CVEs, alert categories, and performed phrase searches. CredentialNoiseAgent queried for usernames, passwords, and OS distributions. HoneypotSpecificAgent queried Redis actions, Adbhoney inputs/malware, Conpot inputs/protocols, and Tanner paths.
    *   **key_results:** Identified 21,740 total attacks; prevalent VNC scanning and DoublePulsar alerts; common brute-force attempts; and honeypot-specific Redis RCE attempts, web exploit probes, and ICS protocol interactions.
    *   **errors_or_gaps:** None.

*   **CandidateDiscoveryAgent**
    *   **purpose:** Merge parallel agent data, identify and classify high-signal candidates, and filter commodity noise.
    *   **inputs_used:** `baseline_result`, `known_signals_result`, `credential_noise_result`, `honeypot_specific_result`.
    *   **actions_taken:** Merged data from all parallel agents. Aggregated events by honeypot type and source IP, and Tanner events by path and source IP. Classified 5 high-signal candidates and identified known commodity exclusions.
    *   **key_results:** Discovered 5 candidates (BCM-1, BCM-2, BCM-3, OSM-1, SUM-1). Classified high-volume VNC scanning and credential noise as exclusions. Generated a comprehensive triage summary.
    *   **errors_or_gaps:** Noted an `evidence_gap` regarding the lack of direct IP-to-Conpot protocol correlation.

*   **CandidateValidationLoopAgent**
    *   **iterations run:** 1
    *   **# candidates validated:** 1 (BCM-1)
    *   **any early exit reason:** The DeepInvestigationLoopController exited early after processing BCM-1, which prevented further candidates from being loaded and validated in this loop.
    *   **CandidateValidationAgent for BCM-1:**
        *   **purpose:** Perform detailed knownness checks and temporal analysis for the BCM-1 candidate.
        *   **inputs_used:** Candidate BCM-1's `candidate_id`, `time_window_context`, `seed_reason`, `observed_evidence`, and `infra_indicators`.
        *   **actions_taken:** Queried alert signatures, sampled Suricata signatures, and attempted a two-level aggregation on alert signatures (which failed).
        *   **key_results:** Confirmed BCM-1 (DoublePulsar) as a known exploit campaign with high confidence, verifying its association with port 445 and the specific Suricata signature.
        *   **errors_or_gaps:** The `two_level_terms_aggregated` tool failed, affecting direct programmatic IP-to-signature correlation.

*   **DeepInvestigationLoopController**
    *   **iterations run:** 2
    *   **key leads pursued:** `src_ip:113.161.145.128` (from BCM-1) and `src_ip:79.98.102.166` (from BCM-1).
    *   **stall/exit reason:** Exited due to diminishing returns, having profiled the top two source IPs of the DoublePulsar campaign and finding consistent single-purpose behavior, with no new high-signal leads generated.
    *   **DeepInvestigationAgent (during iterations):**
        *   **purpose:** Investigate high-signal leads derived from validated candidates to map campaign infrastructure.
        *   **inputs_used:** Validated candidate `BCM-1` and its top source IPs.
        *   **actions_taken:** For each source IP, retrieved its first/last seen timestamps and sampled raw event data.
        *   **key_results:** Confirmed both `113.161.145.128` and `79.98.102.166` as high-volume, single-purpose actors exclusively targeting SMB on port 445 for the DoublePulsar campaign within specific, concentrated time windows.
        *   **errors_or_gaps:** None in its own execution.

*   **OSINTAgent**
    *   **purpose:** Validate knownness and context of high-signal findings against public threat intelligence.
    *   **inputs_used:** The Suricata signature string `"ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication"` related to BCM-1.
    *   **actions_taken:** Performed a public `search` query using the provided signature string.
    *   **key_results:** Confirmed the signature maps to the well-documented DoublePulsar backdoor, reducing its novelty and classifying it as an "established" threat.
    *   **errors_or_gaps:** None.

*   **ReportAgent**
    *   **purpose:** Compile the final investigation report from all available workflow state.
    *   **inputs_used:** `investigation_start`, `investigation_end`, `baseline_result`, `known_signals_result`, `credential_noise_result`, `honeypot_specific_result`, `candidate_discovery_result`, `validated_candidates` (from `CandidateLoopReducerAgent`), `osint_validation_result`, and `deep_investigation_logs/state`.
    *   **actions_taken:** Processed all agent outputs, applied mandatory reporting logic and rules, and structured the report content into the specified markdown format.
    *   **key_results:** Generated a comprehensive markdown report detailing identified threats, campaign infrastructure, odd-service activity, and tool diagnostics.
    *   **errors_or_gaps:** None in its own execution, but reported on identified upstream tool failures and validation gaps.

*   **SaveReportAgent**
    *   **purpose:** Persist the generated report to storage.
    *   **inputs_used:** The final markdown report content.
    *   **actions_taken:** Attempted to write the generated report to a file.
    *   **key_results:** Report successfully saved.
    *   **errors_or_gaps:** None.
