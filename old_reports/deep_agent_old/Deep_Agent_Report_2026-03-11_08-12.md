# Honeypot Threat Hunting Report

## 1) Investigation Scope
- **investigation_start:** 2026-03-11T08:00:05Z
- **investigation_end:** 2026-03-11T12:00:05Z
- **completion_status:** Partial (degraded evidence)
- **degraded_mode:** true. The investigation was completed, but several backend tool queries failed during analysis. This prevented the correlation of source IPs to specific activities (CVE-2025-55182, ICS protocol scanning) and the validation of all initial candidates.

## 2) Executive Triage Summary
- **Top Services/Ports of Interest:** The most significant activity involved mass scanning on VNC (port 5900). Other notable targets included HTTP (80/443), SSH (22), and the Docker Engine API (2375).
- **Odd/Minutia Service Highlights:** Scanning was detected against Industrial Control System (ICS) protocols, specifically `guardian_ast` (TCP/10001, for Automatic Tank Gauges), `kamstrup_management_protocol`, and `IEC104`.
- **Top Confirmed Known Exploitation:** A massive scanning campaign from IP `185.231.33.22` targeted the VNC authentication bypass vulnerability CVE-2006-2369. A separate, multi-exploit campaign scanned for CVE-2017-9841 (PHPUnit RCE) and other web vulnerabilities.
- **Unmapped Exploit-like Items:** No high-confidence novel exploit candidates remain after deep investigation and OSINT re-classified the initial candidates as known threats.
- **Botnet/Campaign Mapping Highlights:**
    - A high-volume VNC scanning campaign originating from ASN 211720 (Seychelles).
    - A distributed, multi-exploit web scanning campaign using the user-agent `libredtail-http` from IPs in Singapore and South Korea. This campaign showed a division of labor, with one IP focused on general web exploits and another on the Docker API.
- **Major Uncertainties:** The source IPs behind the ICS protocol scanning could not be identified due to a tool query failure, making the finding provisional.

## 3) Candidate Discovery Summary
Initial analysis of baseline, known signal, and honeypot data surfaced several areas of interest. Over 36,000 attacks were observed, dominated by a VNC scanning campaign (CVE-2006-2369). The Tanner honeypot detected PHPUnit RCE attempts, which became a key pivot for deep investigation. The Conpot honeypot recorded scans for ICS protocols. Additionally, a targeted credential stuffing campaign using Solana-related usernames was identified. Discovery was materially affected by tool failures that prevented the correlation of source IPs for a reported CVE (`CVE-2025-55182`) and the Conpot ICS activity.

## 4) Emerging n-day Exploitation
### Multi-Exploit Web and Container Scanning Campaign
- **cve/signature mapping:** CVE-2017-9841 (PHPUnit RCE), ET WEB_SERVER ThinkPHP RCE Exploitation Attempt, potential CVE-2024-4577 (PHP CGI RCE), Docker Engine API enumeration.
- **evidence summary:** The campaign was identified by a unique user-agent (`libredtail-http`) across two source IPs: `207.166.168.14` and `114.111.54.188`. The former scanned for a wide range of PHP vulnerabilities, while the latter focused exclusively on the Docker API. Artifacts include requests to paths like `/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php`, `/index.php?s=/index/\\think\\app/invokefunction`, and `/containers/json`.
- **affected service/port:** HTTP (80), Docker (2375).
- **confidence:** High.
- **operational notes:** This is an automated, distributed scanning campaign using shared tooling to find multiple known vulnerabilities. The division of labor between the source IPs suggests a degree of sophistication.

## 5) Novel or Zero-Day Exploit Candidates (UNMAPPED ONLY, ranked)
No candidates fully met the criteria for Novel or Zero-Day exploits after the deep investigation and OSINT validation phases. The primary candidate, `NOV-01`, was successfully mapped to the known vulnerabilities detailed in the "Emerging n-day Exploitation" section.

## 6) Botnet/Campaign Infrastructure Mapping
### VNC Scanning Campaign (BOT-01)
- **item_id:** BOT-01
- **campaign_shape:** spray
- **suspected_compromised_src_ips:** `185.231.33.22` was the source of 7,960 events.
- **ASNs / geo hints:** ASN 211720 (Datashield, Inc.) in Seychelles.
- **suspected_staging indicators:** None identified.
- **suspected_c2 indicators:** None identified.
- **confidence:** High.
- **operational notes:** This is a high-volume, commodity scanning campaign for the well-known VNC vulnerability CVE-2006-2369.

### Solana-themed Credential Stuffing (BOT-02, Provisional)
- **item_id:** BOT-02
- **campaign_shape:** spray
- **suspected_compromised_src_ips:** Unknown. The workflow was unable to correlate the observed usernames to source IPs.
- **ASNs / geo hints:** Unavailable.
- **suspected_staging indicators:** None identified.
- **suspected_c2 indicators:** None identified.
- **confidence:** Low.
- **operational notes:** This campaign targets Solana-related usernames (`solana`, `solv`, `validator`). However, OSINT validation confirmed that Solana validators use cryptographic keypairs, not passwords, for core functions, making this attack vector implausible against a properly configured target. The activity is likely noise.

### Multi-Exploit Web Scanning Campaign (derived from NOV-01)
- **item_id:** NOV-01-DEEP
- **campaign_shape:** Distributed Scanning
- **suspected_compromised_src_ips:** `207.166.168.14`, `114.111.54.188`.
- **ASNs / geo hints:** ASN 150436 (Byteplus Pte. Ltd., Singapore), ASN 54994 (Meteverse Limited., South Korea).
- **suspected_staging indicators:** None identified.
- **suspected_c2 indicators:** None identified.
- **confidence:** High.
- **operational notes:** The campaign uses a shared user-agent (`libredtail-http`) as an indicator of common infrastructure/tooling. Blocking this user-agent and the associated IPs is recommended.

## 7) Odd-Service / Minutia Attacks
### ICS Protocol Scanning (ODD-01, Provisional)
- **service_fingerprint:** Conpot Honeypot / TCP/10001 / Protocols: `guardian_ast`, `kamstrup_management_protocol`, `IEC104`.
- **why it’s unusual/interesting:** This activity represents scanning for non-standard enterprise IT protocols, specifically targeting Industrial Control Systems (ICS) for operational technology environments. The `guardian_ast` protocol is used for Automatic Tank Gauge systems in the energy sector.
- **evidence summary:** The Conpot honeypot recorded 58 events for `guardian_ast`, 3 for `kamstrup`, and 1 for `IEC104`. OSINT confirmed this is a known, albeit niche, area of automated scanning.
- **confidence:** Medium.
- **recommended monitoring pivots:** Monitor and block external IPs attempting to connect to common ICS ports (e.g., 102, 502, 10001). This finding is provisional because a tool failure prevented identification of the source IPs.

## 8) Known-Exploit / Commodity Exclusions
- **SSH Brute-Force:** Standard, high-volume brute-force attempts using common credentials like `root`, `admin`, and `ubuntu` were observed from numerous IPs and classified as noise.
- **Web Directory Scanning:** Probes for common sensitive files like `/.env` were observed from multiple IPs and are considered low-sophistication, opportunistic scanning.

## 9) Infrastructure & Behavioral Classification
- **Exploitation vs Scanning:** The VNC (BOT-01) and Multi-Exploit (NOV-01-DEEP) campaigns were classified as active exploitation scanning. The ICS (ODD-01) and Solana (BOT-02) activities were classified as reconnaissance scanning and credential stuffing, respectively.
- **Campaign Shape:** The VNC and Solana campaigns exhibited a `spray` (one-to-many) shape. The multi-exploit campaign was `distributed`, using multiple sources.
- **Infra Reuse Indicators:** The multi-exploit campaign demonstrated infrastructure reuse through the shared `libredtail-http` user-agent across two distinct IPs and ASNs.
- **Odd-Service Fingerprints:** ICS protocol scanning (`guardian_ast`, `kamstrup`, `IEC104`) on non-standard ports was the primary odd-service activity.

## 10) Evidence Appendix
### Emerging n-day: Multi-Exploit Campaign (NOV-01-DEEP)
- **source IPs:** `207.166.168.14`, `114.111.54.188`
- **ASNs:** 150436 (Byteplus Pte. Ltd.), 54994 (Meteverse Limited.)
- **target ports/services:** 80 (HTTP), 2375 (Docker)
- **paths/endpoints:** `/?%ADd+allow_url_include%3d1+%ADd+auto_prepend_file%3dphp://input`, `/V2/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php`, `/index.php?s=/index/\\think\\app/invokefunction&...`, `/containers/json`
- **payload/artifact excerpts:** `http.http_user_agent`: "libredtail-http"
- **temporal checks results:** Unavailable

### Botnet Mapping: VNC Scanning Campaign (BOT-01)
- **source IPs:** `185.231.33.22` (7,960 events)
- **ASNs:** 211720 (Datashield, Inc.)
- **target ports/services:** 5900 (VNC)
- **payload/artifact excerpts:** Suricata Signatures: "ET EXPLOIT VNC Server Not Requiring Authentication (case 2)", "ET INFO VNC Authentication Failure"
- **temporal checks results:** Unavailable

## 11) Indicators of Interest
- **IPs:**
    - `185.231.33.22` (VNC Scanning)
    - `207.166.168.14` (Web/PHP Exploit Scanning)
    - `114.111.54.188` (Docker API Scanning)
- **User-Agent:**
    - `libredtail-http`
- **URIs / Paths:**
    - `/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php`
    - `/?%ADd+allow_url_include%3d1+%ADd+auto_prepend_file%3dphp://input`
    - `/index.php?s=/index/\\think\\app/invokefunction`
    - `/containers/json`
- **CVEs:**
    - `CVE-2006-2369`
    - `CVE-2017-9841`

## 12) Backend Tool Issues
- **`top_src_ips_for_cve`:** This tool failed to return results for `CVE-2025-55182`, despite the `KnownSignalAgent` reporting 159 events for this CVE. This blocked any further validation or investigation of that activity.
- **`two_level_terms_aggregated`:** The query against Conpot data failed, likely due to a field name misconfiguration. This prevented the identification of source IPs for the ICS protocol scanning, weakening the `ODD-01` candidate and making it provisional.
- **`kibanna_discover_query`:** An initial query attempt failed during the deep investigation due to an incorrect field name (`http.user_agent.keyword`). The agent successfully remediated this by using the correct field (`http.http_user_agent.keyword`) and continued the investigation.

## 13) Agent Action Summary (Audit Trail)

- **agent_name:** ParallelInvestigationAgent
- **purpose:** Executes initial data gathering across multiple domains (baseline, known signals, credentials, honeypots).
- **inputs_used:** `investigation_start`, `investigation_end`.
- **actions_taken:** Called sub-agents to query various data sources in parallel.
- **key_results:** Produced four reports summarizing baseline statistics, known CVEs/signatures (highlighting a major VNC campaign), credential stuffing attempts (including Solana-themed usernames), and specific honeypot interactions (PHPUnit paths, ICS protocols).
- **errors_or_gaps:** None.

- **agent_name:** CandidateDiscoveryAgent
- **purpose:** Generates initial threat candidates from the parallel investigation outputs.
- **inputs_used:** `baseline_result`, `known_signals_result`, `credential_noise_result`, `honeypot_specific_result`.
- **actions_taken:** Analyzed parallel data, attempted to correlate CVEs and honeypot data with source IPs using tools like `top_src_ips_for_cve` and `two_level_terms_aggregated`.
- **key_results:** Identified and proposed 5 candidates: `BOT-01` (VNC), `BOT-02` (Solana), `NOV-01` (PHPUnit), `ODD-01` (ICS), and `MIN-01` (Unusual Ports).
- **errors_or_gaps:** The agent's actions were directly impacted by the failure of `top_src_ips_for_cve` and `two_level_terms_aggregated`, which it flagged as evidence gaps.

- **agent_name:** CandidateValidationLoopAgent
- **purpose:** Performs initial validation of candidates generated by the discovery agent.
- **inputs_used:** `candidate_discovery_result`.
- **actions_taken:** The loop ran for one iteration, validating candidate `BOT-01`. It used `search` to confirm the CVE details and `events_for_src_ip` to verify the traffic from the source IP.
- **key_results:** Successfully validated `BOT-01` as a known exploit campaign.
- **errors_or_gaps:** The loop did not process all 5 candidates, passing the remaining queue to the deep investigation stage.

- **agent_name:** DeepInvestigationLoopController
- **purpose:** Conducts in-depth, iterative investigation starting from high-priority unvalidated candidates.
- **inputs_used:** `candidate_discovery_result` (specifically `NOV-01`).
- **actions_taken:** Executed a 3-iteration investigation. It started with the source IP from `NOV-01`, pivoted to a unique user-agent (`libredtail-http`), and then investigated a newly discovered IP. Used tools `events_for_src_ip`, `top_http_urls_for_src_ip`, and `kibanna_discover_query`.
- **key_results:** Successfully mapped a multi-exploit scanning campaign, identified a second IP (`114.111.54.188`), and uncovered the campaign's TTPs, including a division of labor between scanning nodes.
- **errors_or_gaps:** Remediated one tool query failure by correcting a field name. The agent exited the loop after determining the campaign had been sufficiently mapped.

- **agent_name:** OSINTAgent
- **purpose:** Validates and adds public context to investigation findings.
- **inputs_used:** `candidate_discovery_result`.
- **actions_taken:** Performed web searches for artifacts related to candidates `NOV-01`, `BOT-02`, and `ODD-01`.
- **key_results:**
    - Confirmed `NOV-01` activity maps to known, critical CVEs (CVE-2017-9841).
    - Reduced confidence in `BOT-02` by finding that its premise (password-stuffing Solana validators) is technically implausible.
    - Confirmed `ODD-01` (ICS scanning) is commodity activity.
- **errors_or_gaps:** None.

- **agent_name:** ReportAgent
- **purpose:** Compiles the final report from all workflow state outputs.
- **inputs_used:** `investigation_start`, `investigation_end`, `baseline_result`, `known_signals_result`, `credential_noise_result`, `honeypot_specific_result`, `candidate_discovery_result`, `validated_candidates`, `investigation_log` (from deep investigation), `osint_validation_result`.
- **actions_taken:** Consolidated all available data, applied mandatory reporting logic, and structured the final markdown report.
- **key_results:** Produced this report.
- **errors_or_gaps:** Noted degraded mode and evidence gaps from upstream tool failures.

- **agent_name:** SaveReportAgent
- **purpose:** Persists the final report to storage.
- **inputs_used:** Final report content from ReportAgent.
- **actions_taken:** Will call `deep_agent_write_file`.
- **key_results:** File write status.
- **errors_or_gaps:** None anticipated.
