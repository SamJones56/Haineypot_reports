# Threat Hunting Final Report

## 1) Investigation Scope
- **investigation_start:** 2026-03-18T06:00:05Z
- **investigation_end:** 2026-03-18T09:00:05Z
- **completion_status:** Partial (degraded evidence)
- **degraded_mode:** true. The investigation was significantly hampered by multiple backend tool failures during the candidate discovery phase. These failures prevented the correlation of source IPs with specific signatures and CVEs, limiting the ability to map infrastructure.

## 2) Executive Triage Summary
- **Top Services/Ports of Interest:** VNC (5900), Redis (6379), ADB (5555), and various web (80/443) and ICS-related ports (Conpot) were key areas of activity.
- **Top Confirmed Known Exploitation:** The investigation confirmed active exploitation attempts for PHP vulnerabilities **CVE-2017-9841** (PHPUnit) and **CVE-2024-4577** (PHP CGI Argument Injection).
- **Unmapped Exploit-like Items:** No unmapped novel exploit candidates were identified. All suspicious activity was successfully mapped to known techniques or CVEs by OSINT.
- **Botnet/Campaign Mapping Highlights:** A massive, widespread scanning campaign targeting VNC services was identified, accounting for over 27,000 events. However, due to data correlation failures, mapping the specific source IPs of this campaign was not possible.
- **Major Uncertainties:** The primary uncertainty lies in the attribution of observed attacks. While the "what" was identified (e.g., VNC scanning, PHP exploits), the "who" (source IPs, coordinated actors) could not be determined due to tool failures.

## 3) Candidate Discovery Summary
Candidate discovery was partially successful but operated in a degraded mode. Initial telemetry identified high-volume VNC scanning, known exploit signatures for DoublePulsar, RDP scanning, and notable activity on specialized honeypots (Redis, ADB, Tanner, Conpot). However, multiple query tools (`top_src_ips_for_cve`, `two_level_terms_aggregated`, `custom_basic_search`) failed, preventing the agent from enriching these findings or discovering novel correlations. As a result, no new candidates were generated for deep validation; instead, activity was binned into broad categories for OSINT verification.

## 4) Emerging n-day Exploitation
The following items, initially flagged for monitoring, were confirmed by OSINT to be active exploitation attempts of known n-day vulnerabilities.

- **CVE/Signature Mapping:** CVE-2017-9841 (PHPUnit RCE) & CVE-2024-4577 (PHP CGI Argument Injection RCE)
- **Evidence Summary:**
    - Multiple HTTP requests were captured by the Tanner honeypot targeting paths and using parameters specific to these vulnerabilities.
    - Key artifacts include requests for `/V2/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php` and query strings containing `?%ADd+allow_url_include%3d1+%ADd+auto_prepend_file%3dphp://input`.
    - Total related events: 2
- **Affected Service/Port:** HTTP (Tanner Honeypot)
- **Confidence:** High
- **Operational Notes:** These are attempts to exploit publicly known and critical PHP vulnerabilities. The presence of CVE-2024-4577 is particularly notable due to its recent disclosure.

## 5) Novel or Zero-Day Exploit Candidates (UNMAPPED ONLY, ranked)
No novel or potential zero-day exploit candidates were identified during this investigation window. All suspicious activity was successfully mapped to known exploits, tools, or behaviors.

## 6) Botnet/Campaign Infrastructure Mapping

- **item_id:** BOT-01
- **campaign_shape:** spray (widespread, uncoordinated scanning)
- **suspected_compromised_src_ips:** Multiple, but could not be listed due to query failures during discovery.
- **ASNs / geo hints:** Not correlated due to query failures. Baseline data shows high activity from ASNs like DigitalOcean and Google LLC.
- **suspected_staging indicators:** None identified.
- **suspected_c2 indicators:** None identified.
- **confidence:** Medium
- **operational notes:** This represents a massive, commodity VNC scanning campaign. The activity is very high volume (27,605 events) but appears to be reconnaissance. The `provisional` flag is set because the inability to inspect the source IPs prevents a deeper assessment of coordination or intent.

## 7) Odd-Service / Minutia Attacks

- **item_id:** ODD-01
- **service_fingerprint:** Redis (6379)
- **why it’s unusual/interesting:** Attackers attempted to use Redis commands to write an SSH authorized_keys file, a known technique to gain persistent access to the underlying server.
- **evidence summary:**
    - Events: 9
    - Key Artifacts: `CONFIG SET dir /home/redis/.ssh/`, `CONFIG SET dir /root/.ssh/`, `CONFIG SET dir /var/lib/redis/.ssh/`
- **confidence:** High (Confirmed as a well-known exploit pattern)
- **recommended monitoring pivots:** Monitor for exposed Redis instances and alert on `CONFIG SET` commands manipulating file paths.

- **item_id:** ODD-02
- **service_fingerprint:** ADBHoney (Android Debug Bridge, 5555)
- **why it’s unusual/interesting:** The activity shows a classic malware dropper pattern for Android devices, where a payload is made executable and run from a temporary directory.
- **evidence summary:**
    - Events: 1
    - Key Artifacts: `chmod 755 /data/local/tmp/.p 2>/dev/null; (/data/local/tmp/.p >/dev/null 2>&1 &)`
- **confidence:** High (Confirmed as a standard ADB malware technique)
- **recommended monitoring pivots:** Monitor for shell commands executed via ADB, particularly those involving `chmod` and execution from `/data/local/tmp`.

## 8) Known-Exploit / Commodity Exclusions
- **Known Bot Patterns:**
    - **DoublePulsar Backdoor Communication:** 1,595 events associated with the signature `ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication`. This is commodity activity related to a well-known SMB implant.
- **Scanning Activity:**
    - **VNC Scanning:** 27,605 events with signature `GPL INFO VNC server response`, indicating widespread reconnaissance for open VNC servers.
    - **RDP Scanning:** 584 events for `ET SCAN MS Terminal Server Traffic on Non-standard Port`, indicating scans for exposed RDP services.
    - **ICS Protocol Scanning:** Low-volume activity targeting the `IEC104` protocol was observed on the Conpot honeypot, consistent with public scanning for industrial control systems.
- **Credential Noise:**
    - Standard brute-force attempts were observed targeting common usernames (`root`, `admin`, `postgres`) and simple passwords (`123456`, `password`).
- **Honeypot Interaction Noise:**
    - Activity on the Conpot honeypot related to `guardian_ast` was confirmed by OSINT to be an interaction with a built-in simulator, not a real-world protocol.

## 9) Infrastructure & Behavioral Classification
- **Exploitation vs Scanning:** The investigation identified both widespread scanning (VNC, RDP, IEC104) and targeted exploitation attempts (PHP CVEs, Redis, ADB).
- **Campaign Shape:** The dominant campaign was a massive `spray` of VNC scanning. Other activities were more opportunistic.
- **Infra Reuse Indicators:** Could not be determined due to tool failures preventing IP-level analysis.
- **Odd-Service Fingerprints:** Clear attack patterns were identified for misconfigured Redis and exposed ADB services.

## 10) Evidence Appendix

- **Item: Emerging n-day Exploitation (CVE-2017-9841 & CVE-2024-4577)**
    - **Source IPs:** Unavailable due to query failures.
    - **Target Ports/Services:** HTTP (Tanner Honeypot)
    - **Paths/Endpoints:** `/V2/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php`, `/`
    - **Payload/Artifact Excerpts:** `/?%ADd+allow_url_include%3d1+%ADd+auto_prepend_file%3dphp://input`

- **Item: Botnet Mapping (BOT-01 - VNC Scanning)**
    - **Source IPs:** Unavailable due to query failures.
    - **ASNs:** Unavailable due to query failures.
    - **Target Ports/Services:** VNC (5900)
    - **Payload/Artifact Excerpts:** Suricata Signature: `GPL INFO VNC server response`

- **Item: Odd-Service Attack (ODD-01 - Redis RCE)**
    - **Source IPs:** Unavailable due to query failures.
    - **Target Ports/Services:** Redis (6379)
    - **Payload/Artifact Excerpts:** `CONFIG SET dir /root/.ssh/`

- **Item: Odd-Service Attack (ODD-02 - ADBHoney Dropper)**
    - **Source IPs:** Unavailable due to query failures.
    - **Target Ports/Services:** ADB (5555)
    - **Payload/Artifact Excerpts:** `chmod 755 /data/local/tmp/.p 2>/dev/null; (/data/local/tmp/.p >/dev/null 2>&1 &)`

## 11) Indicators of Interest
- **Paths / URLs:**
    - `/V2/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php` (CVE-2017-9841)
- **Payload Fragments:**
    - `?%ADd+allow_url_include%3d1+%ADd+auto_prepend_file%3dphp://input` (CVE-2024-4577)
    - `CONFIG SET dir /root/.ssh/` (Redis RCE Attempt)
    - `chmod 755 /data/local/tmp` (ADB Malware Staging)

## 12) Reflection Findings
- **Reflection Candidates Discovered:** Based on the evidence gaps in the initial report, five candidates for further investigation were identified:
    - **BOT-01:** Attribution of the high-volume VNC scanning campaign.
    - **MON-01:** Attribution of the PHP exploitation attempts (CVE-2017-9841 & CVE-2024-4577).
    - **ODD-01:** Identification of the source of Redis RCE attempts.
    - **ODD-02:** Identification of the source of ADBHoney malware dropper activity.
    - **SYS-01:** Root cause analysis of the backend tool failures that degraded the investigation.
- **Actions Taken:** The five candidates were successfully queued for a re-investigation loop. However, the loop controller did not execute any of the candidates in this workflow run.
- **Findings:** No new findings were generated as the reflection process was not completed.
- **Enhancements:** This reflection phase did not enhance any of the existing findings, but it has staged the necessary follow-up actions to address the significant gaps identified in this report.

## 13) Backend Tool Issues
The following tools failed during the Candidate Discovery phase, severely impacting the investigation:
- **`top_src_ips_for_cve`**: Failed to retrieve source IPs for observed CVEs.
- **`suricata_lenient_phrase_search`**: Failed to find IPs associated with the high-volume VNC signature.
- **`two_level_terms_aggregated`**: Failed multiple times, preventing aggregation of IPs against signatures or ports.
- **`custom_basic_search`**: Failed to retrieve top destination ports.

These failures made it impossible to correlate attackers with specific behaviors, thus weakening all infrastructure mapping conclusions and preventing a full assessment of campaign coordination.

## 14) Agent Action Summary (Audit Trail)

- **agent_name:** ParallelInvestigationAgent
- **purpose:** Gathers broad, parallel telemetry at the start of the investigation.
- **inputs_used:** `investigation_start`, `investigation_end`.
- **actions_taken:** Executed sub-agents to query baseline stats, known signatures, credential abuse, and honeypot-specific logs.
- **key_results:**
    - Identified 15,173 total attacks.
    - Found high-volume VNC scanning signatures (27k+ events).
    - Detected Redis, ADB, Tanner, and Conpot honeypot interactions.
    - Logged common credential stuffing pairs.
- **errors_or_gaps:** None.

- **agent_name:** CandidateDiscoveryAgent
- **purpose:** Sifts through initial telemetry to find and rank potential threat candidates.
- **inputs_used:** `baseline_result`, `known_signals_result`, `credential_noise_result`, `honeypot_specific_result`.
- **actions_taken:** Attempted to correlate CVEs and signatures with source IPs. Pivoted multiple times after query failures. Finally, used a reliable `kibanna_discover_query` to sample events from a top IP, confirming it was just a scanner.
- **key_results:**
    - Concluded that query tools were unreliable.
    - Declared `degraded_mode` and did not generate novel candidates.
    - Directly classified activity into buckets: known exploits (DoublePulsar), botnet/campaign (VNC scanning), odd-service (Redis, ADB), and suspicious-to-monitor (Tanner, Conpot).
- **errors_or_gaps:** Multiple tool failures (`top_src_ips_for_cve`, `suricata_lenient_phrase_search`, `two_level_terms_aggregated`, `custom_basic_search`) blocked key validation steps.

- **agent_name:** CandidateValidationLoopAgent
- **purpose:** Manages the deep validation of a single candidate.
- **inputs_used:** `candidate_discovery_result`.
- **actions_taken:** Initialized an empty candidate queue and exited immediately.
- **key_results:** Iterations run: 0. Candidates validated: 0.
- **errors_or_gaps:** No error; the loop was exited correctly as there were no novel candidates to validate.

- **agent_name:** DeepInvestigationLoopController
- **purpose:** Controls the deep-dive investigation loop for validated candidates.
- **inputs_used:** None.
- **actions_taken:** Did not run.
- **key_results:** Iterations run: 0.
- **errors_or_gaps:** Not applicable.

- **agent_name:** OSINTAgent
- **purpose:** Enriches candidates with open-source intelligence.
- **inputs_used:** `candidate_discovery_result` (all classified items).
- **actions_taken:** Performed targeted web searches for signatures, commands, and paths associated with every item identified by the discovery agent.
- **key_results:**
    - Confirmed all "known" and "odd-service" items were well-documented attack patterns.
    - Mapped the VNC signature to generic scanning tools.
    - **Critically re-classified the `MON-01` (Tanner) activity as known n-day exploitation for CVE-2017-9841 and CVE-2024-4577.**
    - Clarified that `MON-02` (Conpot) activity was interaction with a honeypot simulator and known ICS scanning.
- **errors_or_gaps:** None.

- **agent_name:** ReportAgent
- **purpose:** Compiles the final report from all workflow state.
- **inputs_used:** All preceding agent outputs.
- **actions_taken:** Synthesized all findings, incorporated the degraded mode status, and restructured the report based on OSINT's re-classification of the Tanner activity.
- **key_results:** Generated this final report.
- **errors_or_gaps:** None.
