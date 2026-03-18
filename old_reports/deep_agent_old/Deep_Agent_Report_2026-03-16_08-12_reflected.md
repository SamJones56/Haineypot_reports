# Threat Investigation Report: Honeypot Activity Analysis

## 1) Investigation Scope
- **investigation_start:** 2026-03-16T08:00:10Z
- **investigation_end:** 2026-03-16T12:00:10Z
- **completion_status:** Partial (degraded evidence)
- **degraded_mode:** true
  - **Reason:** A backend query to retrieve source IP information for the Conpot (ICS honeypot) failed. This prevented the complete mapping of observed Industrial Control System (ICS) scanning activity.

## 2) Executive Triage Summary
- **Top Services/Ports of Interest:**
  - Port 445 (SMB) and VNC-related ports (5901-5905) received a high volume of commodity scanning and brute-force traffic.
  - Port 80 (HTTP) was targeted by a coordinated web vulnerability scanning campaign.
  - Uncommon ICS protocols (`guardian_ast`, `kamstrup_protocol`) were observed, indicating scanning for industrial/utility systems.
- **Top Confirmed Known Exploitation:**
  - A multi-IP campaign was identified scanning for CVE-2017-9841, a known remote code execution (RCE) vulnerability in PHPUnit.
- **Top Unmapped Exploit-like Items:**
  - No novel or unmapped exploit candidates were validated in this window.
- **Botnet/Campaign Mapping Highlights:**
  - A small, focused "spray" campaign was mapped, consisting of two source IPs (`94.103.169.88`, `147.45.60.22`) using identical tooling to scan for a wide range of web vulnerabilities, including CVE-2017-9841 (PHPUnit), CVE-2021-42013 (Apache), ThinkPHP, and PEAR exploits.
- **Major Uncertainties:**
  - The source IPs and geographic origin of the ICS scanning activity on our Conpot honeypot remain unknown due to a data pipeline failure.

## 3) Candidate Discovery Summary
- **Total Attacks Analyzed:** 27,464
- **Key Areas of Interest Identified:**
  - Coordinated scanning for PHPUnit RCE (CVE-2017-9841) from multiple source IPs.
  - Scanning for common Spring Boot actuator endpoints.
  - Reconnaissance of ICS protocols (Guardian AST for Automatic Tank Gauges, Kamstrup for smart metering).
- **Discovery Gaps:** The investigation was materially affected by a failed `kibanna_discover_query` against `Conpot` data, preventing source correlation for the ICS activity.

## 6) Botnet/Campaign Infrastructure Mapping

### Item ID: BOT-01 (Expanded Web Vulnerability Scanning Campaign)
- **Related Candidate ID(s):** BOT-01
- **Campaign Shape:** spray (multiple source IPs using identical scanning patterns).
- **Suspected Compromised Source IPs:**
  - `94.103.169.88` (AS215439 - Play2go International Limited, DE)
  - `147.45.60.22` (AS215540 - Global Connectivity Solutions Llp, RU)
- **ASNs / Geo Hints:** AS215439 (Germany), AS215540 (Russia).
- **Suspected Staging Indicators:** No staging indicators were identified; activity appears to be direct scanning.
- **Suspected C2 Indicators:** None identified.
- **Confidence:** High
- **Operational Notes:** The activity is consistent with a broad, automated scanning campaign seeking multiple low-hanging web vulnerabilities. The two identified IPs should be blocked.

## 7) Odd-Service / Minutia Attacks

### Item ID: ODD-01 (Provisional ICS Scanning)
- **Service Fingerprint:** `guardian_ast` / `kamstrup_protocol` (Conpot ICS Honeypot)
- **Why it’s unusual/interesting:** This activity represents scanning for specialized Industrial Control Systems (ICS) and smart grid infrastructure (Automatic Tank Gauges and smart meters), which is less common than typical web or service brute-forcing.
- **Evidence Summary:**
  - **Protocols Observed:** `guardian_ast` (24 events), `kamstrup_protocol` (16 events).
  - **Key Artifacts:** Specific request `b'\\x01I20100'` observed, which is a known command for Guardian AST systems.
- **Confidence:** Medium (Provisional)
- **Recommended Monitoring Pivots:** The primary follow-up is to resolve the backend data pipeline issue for Conpot logs to enable source IP and infrastructure correlation in future windows.

## 8) Known-Exploit / Commodity Exclusions
- **Credential Noise:** High volume of brute-force attempts using common usernames (`root`, `admin`, `user`) and passwords (`123456`, `password`).
- **Commodity Scanning:**
  - Widespread scanning on port 445 (SMB) from various sources, primarily from India and the UK.
  - Significant scanning activity targeting VNC ports (5901-5905), identified by the `GPL INFO VNC server response` signature (13,317 events).
- **Known Bot Patterns / Scanners:**
  - Activity matching CVE-2017-9841 (PHPUnit RCE) and CVE-2021-42013 (Apache Path Traversal).
  - Scanning for exposed Spring Boot actuator endpoints (`/actuator/gateway/routes`).

## 9) Infrastructure & Behavioral Classification
- **Exploitation vs. Scanning:**
  - The BOT-01 campaign involved active exploitation attempts against known web vulnerabilities (PHPUnit, Apache, etc.).
  - The ODD-01 activity was classified as reconnaissance/scanning for ICS systems.
- **Campaign Shape:**
  - The BOT-01 campaign exhibited a "spray" shape, with multiple source IPs using identical tools and targeting the same set of vulnerabilities.
- **Infra Reuse Indicators:** The two IPs in the BOT-01 campaign used the exact same set of URL paths, strongly indicating infrastructure and tool reuse.
- **Odd-Service Fingerprints:** `guardian_ast` and `kamstrup_protocol` were detected, indicating interest in ICS/SCADA systems.

## 10) Evidence Appendix

### BOT-01: Expanded Web Vulnerability Scanning Campaign
- **Source IPs:**
  - `94.103.169.88`
  - `147.45.60.22`
- **ASNs:**
  - `215439` (Play2go International Limited)
  - `215540` (Global Connectivity Solutions Llp)
- **Target Ports/Services:** 80 (HTTP)
- **Payload/Artifact Excerpts:**
  - `/V2/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php` (CVE-2017-9841)
  - `/?%ADd+allow_url_include%3d1+%ADd+auto_prepend_file%3dphp://input` (PHP RCE attempt)
  - `/cgi-bin/%%32%65%%32%65/` (CVE-2021-42013 - Apache Path Traversal)
  - `/index.php?s=/index/\\think\\app/invokefunction` (ThinkPHP RCE attempt)
  - `pearcmd&+config-create` (PEAR command injection attempt)
- **Staging Indicators:** None observed.
- **Temporal Checks:**
  - `94.103.169.88` active from 2026-03-16T11:50:21Z to 2026-03-16T11:51:34Z.
  - `147.45.60.22` active from 2026-03-16T10:20:51Z to 2026-03-16T10:22:01Z.

### ODD-01: Provisional ICS Scanning
- **Source IPs:** Unavailable
- **ASNs:** Unavailable
- **Target Ports/Services:** Conpot Honeypot (protocols: guardian_ast, kamstrup_protocol)
- **Payload/Artifact Excerpts:** `b'\\x01I20100'`
- **Staging Indicators:** None observed.
- **Temporal Checks:** Unavailable

## 11) Indicators of Interest
- **Source IPs (High Confidence Scanner):**
  - `94.103.169.88`
  - `147.45.60.22`
- **URL Paths (Exploitation Artifacts):**
  - `/V2/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php`
  - `/cgi-bin/%%32%65%%32%65/`
  - `/index.php?s=/index/\\think\\app/invokefunction`

## 12) Backend Tool Issues
- **Tool:** `kibanna_discover_query`
- **Failure:** The query failed to retrieve logs for `type: Conpot`.
- **Affected Validations:** This failure directly blocked the identification of source IPs, ASNs, and geographic locations for the ICS scanning activity (Candidate ODD-01). As a result, the assessment of this activity remains provisional and its infrastructure could not be mapped.

## 13) Agent Action Summary (Audit Trail)

### ParallelInvestigationAgent
- **Purpose:** To run initial data collection agents in parallel.
- **Inputs Used:** `investigation_start`, `investigation_end`.
- **Actions Taken:** Executed `BaselineAgent`, `KnownSignalAgent`, `CredentialNoiseAgent`, and `HoneypotSpecificAgent`.
- **Key Results:** Gathered baseline statistics, known CVE/signature matches, common credential stuffing pairs, and honeypot-specific interactions.
- **Errors_or_Gaps:** None.

### CandidateDiscoveryAgent
- **Purpose:** To synthesize parallel results and discover initial threat candidates.
- **Inputs Used:** `baseline_result`, `known_signals_result`, `credential_noise_result`, `honeypot_specific_result`.
- **Actions Taken:**
  - Analyzed Tanner logs for suspicious web paths.
  - Used `kibanna_discover_query` to investigate paths like `/V2/vendor/phpunit...`, `/actuator/gateway/routes`, etc.
  - Attempted to query Conpot logs.
  - Used `search` to get context on `guardian_ast`.
- **Key Results:**
  - Identified a multi-IP PHPUnit scanning pattern (BOT-01).
  - Identified ICS scanning on Conpot (ODD-01).
  - Classified other activity (Spring Boot scanning) as known exclusions.
- **Errors_or_Gaps:** The `kibanna_discover_query` for Conpot logs failed, leading to a degraded analysis state.

### CandidateValidationLoopAgent
- **Purpose:** To validate and enrich threat candidates from the discovery queue.
- **Iterations Run:** 1
- **Candidates Validated:** 1 (BOT-01)
- **Actions Taken:**
  - For BOT-01, used `search` to map the PHPUnit path to CVE-2017-9841.
  - Used `suricata_lenient_phrase_search` to check for existing signatures (none found).
  - Used `two_level_terms_aggregated` to confirm the source IPs associated with the exploit paths.
- **Key Results:** Confirmed BOT-01 is a known exploit campaign for CVE-2017-9841, involving two source IPs.
- **Errors_or_Gaps:** Did not process ODD-01 as the deep dive on BOT-01 was prioritized.

### DeepInvestigationLoopController
- **Purpose:** To perform deep-dive pivots on high-value validated candidates.
- **Iterations Run:** 3
- **Key Leads Pursued:** `src_ip:94.103.169.88`, `src_ip:147.45.60.22`, `path:/cgi-bin/%%32%65%%32%65/`.
- **Actions Taken:**
  - Used `first_last_seen_src_ip` and `top_http_urls_for_src_ip` to map the activity of the two source IPs.
  - Used `search` and `web_path_samples` to investigate the CGI path artifact.
- **Key Results:**
  - Confirmed both IPs were part of the same automated scanning campaign.
  - Expanded the list of targeted vulnerabilities to include Apache (CVE-2021-42013), ThinkPHP, and PEAR.
- **Stall/Exit Reason:** The investigation stalled after two consecutive pivots failed to uncover new infrastructure or leads, and the `exit_loop` command was issued.

### OSINTAgent
- **Purpose:** To enrich validated candidates with public threat intelligence.
- **Inputs Used:** `validated_candidates` (BOT-01), `candidate_discovery_result` (ODD-01).
- **Actions Taken:** Ran `search` for "PHPUnit ... CVE" and "kamstrup_protocol vulnerability".
- **Key Results:**
  - Confirmed the PHPUnit activity maps to the well-known, actively exploited CVE-2017-9841.
  - Confirmed that Guardian AST and Kamstrup are known ICS/smart grid protocols and that scanning for them is established, non-novel behavior.
- **Errors_or_Gaps:** None.

### ReportAgent
- **Purpose:** To compile the final report from all available workflow state outputs.
- **Inputs Used:** `investigation_start`, `investigation_end`, `baseline_result`, `known_signals_result`, `credential_noise_result`, `honeypot_specific_result`, `candidate_discovery_result`, `validated_candidates`, `deep_investigation_log`, `osint_validation_result`.
- **Actions Taken:** Assembled this report.
- **Key Results:** Generated the final markdown report.
- **Errors_or_Gaps:** Noted the degraded mode status originating from the `CandidateDiscoveryAgent`.

### SaveReportAgent
- **Purpose:** To save the compiled markdown report to a file.
- **Inputs Used:** Compiled report content from ReportAgent.
- **Actions Taken:** Called `deep_agent_write_file`.
- **Key Results:** Successfully saved the report to `/home/user/Haineypot/reports/deep_agent_reports/Deep_Agent_Report_2026-03-16_08-12.md`.
- **Errors_or_Gaps:** None.
