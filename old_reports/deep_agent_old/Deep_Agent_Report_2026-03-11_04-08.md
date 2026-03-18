# Threat Hunt Report: 2026-03-11T04:00:06Z to 2026-03-11T08:00:06Z

## 1) Investigation Scope
- **investigation_start:** 2026-03-11T04:00:06Z
- **investigation_end:** 2026-03-11T08:00:06Z
- **completion_status:** Complete
- **degraded_mode:** false
  - Initial candidate discovery experienced minor tool failures, but the core novel candidate was successfully validated and investigated by the validation and deep-dive loops.

## 2) Executive Triage Summary
- **Top Services/Ports of Interest:** VNC (5900), ADB (5555), Web (Gradio/7860, Streamlit/8501), and Minecraft (25565).
- **Top Confirmed Known Exploitation:**
    - **VNC (CVE-2006-2369):** A massive scanning campaign targeting VNC servers that do not require authentication.
    - **Android/ADB:** Confirmed activity from the "Trinity" botnet, which installs the "ufo.apk" crypto-miner.
    - **Gradio (CVE-2026-28416):** Reconnaissance for a newly disclosed SSRF vulnerability in the Gradio web framework.
    - **PHPUnit (CVE-2017-9841):** Low-volume attempts to exploit a known RCE vulnerability.
- **Novel Exploit Candidates:** The primary novel candidate (unusual web traffic) was successfully identified as reconnaissance for an emerging n-day vulnerability (CVE-2026-28416). No unmapped novel candidates remain.
- **Botnet/Campaign Mapping Highlights:**
    - A single IP (`132.208.105.135`) was observed delivering the Trinity Android malware payload.
    - A massive, single-source VNC scanning campaign (`185.231.33.22`) was identified.
    - A multi-framework web application scanner (`45.76.190.64`) was observed probing for Gradio and Streamlit applications.
- **Odd-Service Highlight:** Traffic fingerprinted as a "Nintendo 3DS" was observed scanning for Minecraft servers on a port not used by that console's version of the game, indicating an unusual scanner profile.

## 3) Candidate Discovery Summary
- **Total Attacks Analyzed:** 52,271
- **Top Areas of Interest Identified:**
    - High-volume VNC scanning linked to CVE-2006-2369.
    - A multi-step malware installation chain on the Adbhoney honeypot.
    - Web requests to paths associated with PHPUnit RCE (CVE-2017-9841).
    - Significant traffic to non-standard web ports (7860, 8501, 6334) from a concentrated source.
    - Unusual OS fingerprint ("Nintendo 3DS") scanning for Minecraft servers.
- **Gaps:** An initial query to aggregate Conpot (ICS) data failed, preventing a deeper look into that activity during the discovery phase. This did not impact the investigation of the other, higher-signal candidates.

## 4) Emerging n-day Exploitation
- **cve/signature mapping:** CVE-2026-28416 (Gradio SSRF Vulnerability)
- **evidence summary:** Observed HTTP GET requests to the `/config` endpoint on port 7860, which is the default for the Gradio UI framework. The user-agent was 'node'. This activity is consistent with reconnaissance for the specified CVE. 348 related events were observed.
- **affected service/port:** Gradio / TCP 7860
- **confidence:** High
- **operational notes:** This appears to be the reconnaissance phase. No active exploitation (e.g., calls to the `/proxy=` endpoint) was observed in the timeframe. Source IPs should be monitored for follow-up exploitation attempts.

## 5) Novel or Zero-Day Exploit Candidates (UNMAPPED ONLY, ranked)
*No unmapped novel exploit candidates were validated in this window. The primary candidate was reclassified as an Emerging n-day.*

## 6) Botnet/Campaign Infrastructure Mapping

### Item: Trinity Android Botnet
- **item_id:** [BOT-01]
- **campaign_shape:** fan-out
- **suspected_compromised_src_ips:** `132.208.105.135` (2 events)
- **ASNs / geo hints:** Not available from data.
- **suspected_staging indicators:** Malware files (`trinity`, `ufo.apk`) and execution commands (`/data/local/tmp/nohup /data/local/tmp/trinity`, `am start -n com.ufo.miner/com.example.test.MainActivity`) observed in Adbhoney logs. OSINT confirms this is a known cryptomining botnet that spreads via open ADB ports.
- **suspected_c2 indicators:** Not directly observed, but the purpose is cryptomining.
- **confidence:** High
- **operational notes:** This is a known commodity botnet. Block source IP. Scan for any publicly exposed ADB ports.

### Item: VNC Scanning Campaign
- **item_id:** [BOT-02]
- **campaign_shape:** spray
- **suspected_compromised_src_ips:** `185.231.33.22` (27,465 events)
- **ASNs / geo hints:** AS211720 (Datashield, Inc.) / Seychelles
- **suspected_staging indicators:** None. Direct scanning activity.
- **suspected_c2 indicators:** None.
- **confidence:** High
- **operational notes:** High-volume scanning for VNC servers vulnerable to CVE-2006-2369. This is commodity background noise. Recommend adding the source IP to network blocklists.

### Item: Web Application Framework Scanner
- **item_id:** (Related to [NOV-01])
- **campaign_shape:** fan-out
- **suspected_compromised_src_ips:** `45.76.190.64`
- **ASNs / geo hints:** AS20473 (The Constant Company, LLC) / Singapore
- **suspected_staging indicators:** The probe URLs themselves are the indicators: `/config` (Gradio), `/_stcore/health` (Streamlit), `/collections` (Unknown).
- **suspected_c2 indicators:** None.
- **confidence:** High
- **operational notes:** This source is performing broad reconnaissance for multiple web application frameworks. Monitor this IP for exploit attempts against discovered services.

## 7) Odd-Service / Minutia Attacks
- **service_fingerprint:** OS: "Nintendo 3DS", Port/App: TCP/25565 (Minecraft)
- **why it’s unusual/interesting:** A source with a p0f OS fingerprint of a "Nintendo 3DS" gaming console was observed scanning for Minecraft servers. OSINT confirms that the 3DS version of Minecraft does not use port 25565, making this combination of scanner fingerprint and target highly anomalous. It suggests an attacker using non-standard tools or spoofed fingerprints to evade simple detection.
- **evidence summary:** 26 events from source IPs including `176.65.149.219`, `176.65.134.6`, and `176.65.148.185`.
- **confidence:** High
- **recommended monitoring pivots:** Track the identified source IPs for other unusual scanning profiles or TTPs.

## 8) Known-Exploit / Commodity Exclusions
- **VNC Scanning (CVE-2006-2369):** Massive activity (27,976 signature matches) from a single IP (`185.231.33.22`) targeting port 5900, consistent with scanning for VNC servers with no authentication.
- **PHPUnit RCE (CVE-2017-9841):** Low-volume attempts (3 hits) from `81.163.28.149` to exploit a known RCE in PHPUnit via the `eval-stdin.php` script.
- **Credential Noise:** Standard brute-force attempts on SSH/Telnet with common usernames (`root`, `admin`) and passwords (`123456`, `password`).
- **Reputation/Scanner Alerts:** Generic alerts for NMAP scanning (`ET SCAN NMAP -sS window 1024`) and connections from IPs on threat intelligence blocklists (`ET CINS Active Threat Intelligence`).

## 9) Infrastructure & Behavioral Classification
- **Trinity Botnet ([BOT-01]):** Classified as **Exploitation**. Exhibits a **fan-out** shape from a single source, using **known malware** infrastructure.
- **VNC Scanner ([BOT-02]):** Classified as **Scanning**. Exhibits a **spray** shape from a single, high-volume source.
- **Web Scanner ([NOV-01]):** Classified as **Scanning**. Exhibits a **fan-out** shape, probing for multiple services from a single source.
- **Nintendo 3DS Scanner ([ODD-01]):** Classified as **Scanning**. Shape is undetermined, but notable for its **odd-service fingerprint**.

## 10) Evidence Appendix

### Emerging n-day: Gradio Recon (CVE-2026-28416)
- **source IPs:** `45.76.190.64`
- **ASNs:** AS20473 (The Constant Company, LLC)
- **target ports/services:** 7860 (Gradio)
- **paths/endpoints:** `/config`
- **payload/artifact excerpts:** `GET /config HTTP/1.1`, User-Agent: `node`

### Botnet Mapping: Trinity ([BOT-01])
- **source IPs:** `132.208.105.135`
- **ASNs:** N/A
- **target ports/services:** 5555 (ADB)
- **paths/endpoints:** N/A
- **payload/artifact excerpts:** Commands: `pm install /data/local/tmp/ufo.apk`, `am start -n com.ufo.miner/com.example.test.MainActivity`. Files: `trinity`, `ufo.apk`.

### Botnet Mapping: VNC Scanner ([BOT-02])
- **source IPs:** `185.231.33.22` (27,465 events)
- **ASNs:** 211720 (Datashield, Inc.)
- **target ports/services:** 5900 (VNC)
- **paths/endpoints:** N/A

## 11) Indicators of Interest
- **IPs:**
  - `132.208.105.135` (Trinity Android Botnet)
  - `185.231.33.22` (High-volume VNC Scanner)
  - `45.76.190.64` (Gradio/Streamlit Web Scanner)
- **Paths:**
  - `/config` (Gradio Recon)
  - `/_stcore/health` (Streamlit Recon)
  - `/V2/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php` (PHPUnit RCE)
- **Filenames / Payloads:**
  - `trinity`
  - `ufo.apk`
- **Associated CVEs:**
  - `CVE-2026-28416` (Gradio SSRF)
  - `CVE-2006-2369` (VNC No Auth)
  - `CVE-2017-9841` (PHPUnit RCE)

## 12) Backend Tool Issues
- **CandidateDiscoveryAgent:**
  - `two_level_terms_aggregated`: The tool failed to execute a query for `conpot.protocol.keyword`, preventing an initial assessment of ICS-related activity.
  - `complete_custom_search`: The tool failed to construct a query to investigate web traffic on non-standard ports, weakening the initial discovery phase for candidate `[NOV-01]`. This was later remediated by the `CandidateValidationLoopAgent`.

## 13) Agent Action Summary (Audit Trail)

- **agent_name:** ParallelInvestigationAgent
- **purpose:** Gathers broad, initial data sets across different honeypots and signal types.
- **inputs_used:** investigation time window.
- **actions_taken:** Executed multiple `get_*` and `search` tools to query baseline traffic, known signals, credential stuffing, and honeypot-specific logs.
- **key_results:** Identified high-volume VNC scanning (CVE-2006-2369), Adbhoney malware commands, unusual web ports (7860, 8501), and the "Nintendo 3DS" p0f fingerprint.
- **errors_or_gaps:** None.

- **agent_name:** CandidateDiscoveryAgent
- **purpose:** Synthesizes initial data to identify and score potential leads for investigation.
- **inputs_used:** Outputs from all parallel investigation sub-agents.
- **actions_taken:** Used `two_level_terms_aggregated` to pivot on interesting fields, `p0f_os_search` to isolate the Nintendo fingerprint, and `search` to map the PHPUnit activity to a CVE.
- **key_results:** Generated four primary candidates: `[BOT-01]` (Adbhoney), `[BOT-02]` (VNC), `[NOV-01]` (Web Ports), `[ODD-01]` (Nintendo).
- **errors_or_gaps:** Two tool queries failed, hindering analysis of ICS data and the initial deep-dive into the `[NOV-01]` web traffic.

- **agent_name:** CandidateValidationLoopAgent
- **purpose:** Performs targeted validation of a single high-priority candidate.
- **inputs_used:** Candidate `[NOV-01]`.
- **actions_taken:** Ran 1 iteration. Used `kibanna_discover_query` to inspect traffic on ports 7860 and 8501. Used `search` on "Gradio vulnerability /config endpoint".
- **key_results:** Validated that traffic on port 7860 was reconnaissance for Gradio SSRF vulnerability CVE-2026-28416. Re-classified candidate from "Novel" to "Emerging n-day".
- **errors_or_gaps:** None.

- **agent_name:** DeepInvestigationLoopController
- **purpose:** Conducts further pivots based on validated, high-confidence leads.
- **inputs_used:** Validated candidate `[NOV-01]` and its associated CVE lead.
- **actions_taken:** Ran 2 iterations. Searched for exploitation patterns (`/proxy=`). Pivoted on the source IP (`45.76.190.64`) to inspect all its URL requests.
- **key_results:** Confirmed no exploitation occurred. Discovered the same IP was also scanning for Streamlit (`/_stcore/health`), revealing a multi-framework scanner campaign.
- **errors_or_gaps:** None. Loop exited after exhausting immediate leads.

- **agent_name:** OSINTAgent
- **purpose:** Enriches internal findings with publicly available threat intelligence.
- **inputs_used:** `candidate_discovery_result`.
- **actions_taken:** Executed `search` queries for the "Trinity" malware, the Nintendo 3DS scan anomaly, and the high-volume VNC scanner IP.
- **key_results:** Confirmed `[BOT-01]` is the known "Trinity" botnet. Confirmed the `[ODD-01]` behavior is anomalous and not widely documented. Confirmed `[BOT-02]` activity is commodity scanning.
- **errors_or_gaps:** None.

- **agent_name:** ReportAgent
- **purpose:** Compiles the final report from all workflow state outputs.
- **inputs_used:** `baseline_result`, `known_signals_result`, `candidate_discovery_result`, `validated_candidates`, `deep_investigation_log`, `osint_validation_result`.
- **actions_taken:** Assembled this markdown document.
- **key_results:** Report generated.
- **errors_or_gaps:** None.

- **agent_name:** SaveReportAgent
- **purpose:** Writes the final report file.
- **inputs_used:** Finalized markdown report content.
- **actions_taken:** `deep_agent_write_file` will be called with the report content.
- **key_results:** Pending execution.
- **errors_or_gaps:** None.
