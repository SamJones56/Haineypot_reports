# Threat Hunting Final Report: TH-20260302-0900

## 1) Investigation Scope
- **investigation_start:** 2026-03-02T08:00:13Z
- **investigation_end:** 2026-03-02T09:00:13Z
- **completion_status:** Partial (degraded evidence)
- **degraded_mode:** true. The investigation was significantly impacted by backend tool failures, which prevented payload analysis and attribution for several CVE-based alerts.

## 2) Executive Triage Summary
- **Top Services of Interest:** High-volume scanning activity was observed against VNC/RDP (ports 5900-5926), SSH (port 22), and HTTP (port 80) services.
- **Top Confirmed Known Exploitation:** A single actor was identified attempting to exploit two distinct, known web vulnerabilities: the recent PHP CGI argument injection (CVE-2024-4577) and the older PHPUnit RCE (CVE-2017-9841).
- **Unmapped Exploit-Like Items:** No novel or unmapped exploit candidates were identified in this window; all high-value signals were mapped to known threats.
- **Botnet/Campaign Mapping Highlights:** A key infrastructure indicator, **130.61.28.82** (Oracle Public Cloud), was observed using a "fan-out" strategy, probing for multiple vulnerabilities from a single source.
- **Major Uncertainties:** Failures in data retrieval tools prevented the inspection of execution payloads, meaning we could not confirm successful compromise or identify potential C2/staging infrastructure. Additionally, we were unable to attribute several low-volume CVE alerts to their source IPs.

## 3) Candidate Discovery Summary
Candidate discovery focused on activity from the web honeypot (Tanner), which revealed a single actor (`130.61.28.82`) engaged in multi-vulnerability probing. Initial hypotheses of novelty were superseded by OSINT validation, which mapped the activity to known n-day exploits. Discovery was materially affected by the failure of tools (`kibanna_discover_query`, `top_src_ips_for_cve`) intended to retrieve payload details and correlate other alerts.

## 4) Emerging n-day Exploitation
### PHP CGI Argument Injection Exploit Attempt
- **cve/signature mapping:** CVE-2024-4577
- **evidence summary:**
  - 1 event recorded from source IP `130.61.28.82`.
  - Artifact: The request path `/?%ADd+allow_url_include%3d1+%ADd+auto_prepend_file%3dphp://input` is a direct match for the publicly documented exploit vector for this vulnerability.
- **affected service/port:** HTTP (80)
- **confidence:** High
- **operational notes:** This confirms active, in-the-wild exploitation of a recently disclosed vulnerability. The source IP is hosted on Oracle Public Cloud, a common origin for scanning and exploitation activity.

## 5) Novel or Zero-Day Exploit Candidates (UNMAPPED ONLY, ranked)
No candidates met the criteria for novel or potential zero-day exploitation in this investigation window. The primary candidate was re-classified as Emerging n-day Exploitation following OSINT validation.

## 6) Botnet/Campaign Infrastructure Mapping
### Multi-Vulnerability Web Probing Actor
- **item_id:** BCM-01
- **campaign_shape:** fan-out (one source IP targeting multiple, distinct vulnerabilities)
- **suspected_compromised_src_ips:** `130.61.28.82`
- **ASNs / geo hints:** Oracle Public Cloud USA
- **suspected_staging indicators:** None identified. Payload inspection was blocked by tool failures.
- **suspected_c2 indicators:** None identified. Payload inspection was blocked by tool failures.
- **confidence:** High (for infrastructure identification), Provisional (for impact, due to blocked validation)
- **operational notes:** This actor is leveraging known n-day vulnerabilities (CVE-2024-4577, CVE-2017-9841). The IP should be considered a high-signal indicator of interest for blocking and further monitoring.

## 7) Odd-Service / Minutia Attacks (optional)
No unusual or odd-service attacks were identified during this investigation window.

## 8) Known-Exploit / Commodity Exclusions
- **PHPUnit RCE (CVE-2017-9841):** Probes for `/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php` from `130.61.28.82`. Classified as a known exploit attempt.
- **VNC/RDP Scanning:** High-volume generic scanning, evidenced by 1,943 `GPL INFO VNC server response` alerts and 234 `ET SCAN MS Terminal Server Traffic on Non-standard Port` alerts.
- **Credential Noise:** Standard brute-force attempts on SSH (port 22) using common usernames (`root`, `admin`) and passwords (`123456`, `password`).
- **Generic Web Reconnaissance:** Probes for common paths like `/aaa9` and `/.env` from multiple IPs, consistent with commodity web scanners.

## 9) Infrastructure & Behavioral Classification
- **Exploitation vs Scanning:** The activity from `130.61.28.82` is classified as **active exploitation**. The remainder of the high-volume activity is **scanning and brute-force**.
- **Campaign Shape:** `130.61.28.82` exhibits a **fan-out** shape. All other activity appears to be broad, uncoordinated **spray**.
- **Infra Reuse Indicators:** The actor IP originates from a major cloud provider (Oracle Public Cloud), suggesting potential use of ephemeral infrastructure.

## 10) Evidence Appendix
### Item: BCM-01 (Multi-Vulnerability Actor)
- **source IPs:** `130.61.28.82` (4 total exploit-like requests)
- **ASNs:** Oracle Public Cloud USA
- **target ports/services:** HTTP (80)
- **paths/endpoints:**
  - `/?%ADd+allow_url_include%3d1+%ADd+auto_prepend_file%3dphp://input` (CVE-2024-4577)
  - `/V2/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php` (CVE-2017-9841)
  - `/admin/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php` (CVE-2017-9841)
  - `/api/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php` (CVE-2017-9841)
- **payload/artifact excerpts:** Payload inspection failed due to tool errors.
- **staging indicators:** Unavailable.
- **temporal checks results:** Unavailable.

## 11) Indicators of Interest
- **IP:** `130.61.28.82` (Actor actively exploiting CVE-2024-4577 and CVE-2017-9841)
- **Path (Exact Match):** `/?%ADd+allow_url_include%3d1+%ADd+auto_prepend_file%3dphp://input` (Indicator for CVE-2024-4577)
- **Path (Contains):** `/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php` (Indicator for CVE-2017-9841)

## 12) Backend Tool Issues
- **kibanna_discover_query:** This tool failed repeatedly with an `illegal_argument_exception`. This critical failure blocked the inspection of raw HTTP POST request bodies from actor `130.61.28.82`, preventing any analysis of potential execution payloads, staging URLs, or C2 indicators.
- **top_src_ips_for_cve:** This tool returned empty results for both `CVE-2024-4577` and `CVE-2023-46604`, despite initial telemetry showing alerts for these vulnerabilities. This blocked the attribution of these attacks to specific source IPs, weakening the overall threat assessment.

## 13) Agent Action Summary (Audit Trail)
- **ParallelInvestigationAgent:**
  - **Purpose:** Gathers initial, broad telemetry at the start of the workflow.
  - **Inputs Used:** `investigation_start`, `investigation_end`.
  - **Actions Taken:** Executed four sub-agents (`Baseline`, `KnownSignal`, `CredentialNoise`, `HoneypotSpecific`) to query different data sources.
  - **Key Results:** Returned baseline statistics (10,851 attacks), top known alerts (VNC scanning), common credential pairs, and initial web honeypot paths.
  - **Errors or Gaps:** None.
- **CandidateDiscoveryAgent:**
  - **Purpose:** Identifies high-value leads from the initial telemetry.
  - **Inputs Used:** `baseline_result`, `known_signals_result`, `credential_noise_result`, `honeypot_specific_result`.
  - **Actions Taken:** Correlated web paths to source IPs, identifying `130.61.28.82`. Attempted payload and CVE actor queries, which failed. Used OSINT to classify scanner noise.
  - **Key Results:** Produced one high-value infrastructure candidate (`BCM-01`) and excluded commodity scanning activity.
  - **Errors or Gaps:** Critically impacted by failures in `kibanna_discover_query` and `top_src_ips_for_cve`, leading to declared evidence gaps.
- **CandidateValidationLoopAgent:**
  - **Purpose:** Iteratively validates and enriches candidates.
  - **Actions Taken:** Did not run; the loop was exited by the controller. Iterations: 0.
  - **Key Results:** N/A.
- **DeepInvestigationLoopController:**
  - **Purpose:** Manages the deep-dive investigation loop.
  - **Inputs Used:** State from `CandidateDiscoveryAgent`.
  - **Actions Taken:** Immediately requested to exit the loop.
  - **Key Results:** No deep investigation was performed.
  - **Errors or Gaps:** None.
- **OSINTAgent:**
  - **Purpose:** Enriches candidates with external intelligence.
  - **Inputs Used:** `candidate_discovery_result`.
  - **Actions Taken:** Searched for IP `130.61.28.82` and exploit artifact `auto_prepend_file=php://input`.
  - **Key Results:** Successfully mapped the activity of `130.61.28.82` to known exploit attempts for CVE-2024-4577 and CVE-2017-9841. This was the key finding that re-classified the primary candidate.
  - **Errors or Gaps:** None.
- **ReportAgent (self):**
  - **Purpose:** Compiles the final report from all workflow state outputs.
  - **Inputs Used:** All available state from preceding agents.
  - **Actions Taken:** Assembled this report.
  - **Key Results:** Report generated.
  - **Errors or Gaps:** Working in degraded mode due to upstream tool failures.
- **SaveReportAgent:**
  - **Purpose:** Persists the final report.
  - **Actions Taken:** Will be called to save the generated report.
  - **Key Results:** Pending execution.
