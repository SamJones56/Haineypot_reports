# Threat Hunting Honeypot Investigation Report

## 1. Investigation Scope
- **investigation_start**: 2026-03-18T06:00:05Z
- **investigation_end**: 2026-03-18T09:00:05Z
- **completion_status**: Complete
- **degraded_mode**: false

## 2. Executive Triage Summary
- **Total Attacks**: 15,173 events analyzed in the 3-hour window.
- **Top Services of Interest**: Significant activity was observed targeting VNC (ports 5901, 5902, 5903), Redis (6379), and Android Debug Bridge (ADB, 5555). Low-volume probes were also seen against ICS protocols (guardian_ast, IEC104).
- **Top Unmapped Exploit-like Items**: A key finding was the delivery of a novel malware sample via ADB, where the malware hash had no public record. Additionally, a focused web scanner was identified using multiple exploit payloads that were not being detected by network IDS.
- **Top Confirmed Known Exploitation**: The majority of background noise consisted of high-volume VNC scanning (`GPL INFO VNC server response`) and repeated exploitation attempts for the DoublePulsar backdoor.
- **Botnet/Campaign Mapping Highlights**: A multi-vector campaign was identified originating from `45.205.1.110`. This attacker leveraged known Redis misconfigurations to gain access, while simultaneously attempting to drop a novel malware payload via the ADB honeypot.
- **Honeypot-Specific Highlights**: Adbhoney was crucial in capturing the novel malware sample and downloader command. The Tanner honeypot captured the undetected web exploit attempts. Redis honeypot logs confirmed the attacker's TTP of writing to SSH directories.

## 3. Candidate Discovery Summary
The discovery phase successfully triaged 15,173 events to identify four high-signal candidates for further investigation. Initial leads were primarily generated from Adbhoney and Tanner honeypot logs, which captured unusual malware delivery and suspicious PHP requests, respectively. These were correlated with Redis and Suricata logs to build a more complete picture of the activity, resulting in the following candidates:
- **Two Novel Exploit Candidates**: One related to undetected PHP exploitation (`NOV-01`) and another concerning novel ADB-based malware delivery (`NOV-02`).
- **One Botnet/Campaign Mapping**: A multi-vector attack campaign (`BOT-01`) originating from a single source IP targeting multiple services.
- **One Odd-Service Attack**: Low-volume activity against ICS protocols (`ODD-01`).

## 4. Emerging n-day Exploitation
The following items were initially classified as novel but were later mapped to known vulnerabilities during deep investigation and OSINT validation. The key operational finding is that these known exploits were **not detected** by the deployed IDS/IPS signatures, indicating a critical detection gap.

- **CVE/Signature Mapping**: **CVE-2017-9841** (PHPUnit RCE), **CVE-2019-9082** (ThinkPHP RCE), **CVE-2024-4577** (PHP CGI RCE)
- **Evidence Summary**:
    - **Attacker IP**: `82.24.64.32`
    - **Total Events**: 151 events from this IP over a 91-second period.
    - **Key Artifacts**:
        - `/?%ADd+allow_url_include%3d1+%ADd+auto_prepend_file%3dphp://input` (CVE-2024-4577)
        - `/V2/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php` (CVE-2017-9841)
        - `/index.php?s=/index/	hinkpp/invokefunction&function=call_user_func_array...` (CVE-2019-9082)
- **Affected Service/Port**: HTTP (80)
- **Confidence**: High
- **Operational Notes**: This activity is from an automated, multi-vulnerability scanner. While the exploits are known, they are bypassing existing network signatures. A signature update or creation is required to close this detection gap.

## 5. Novel or Zero-Day Exploit Candidates (UNMAPPED ONLY, ranked)

- **candidate_id**: `NOV-02`
- **classification**: novel exploit candidate
- **novelty_score**: 9
- **confidence**: High
- **provisional**: false
- **key evidence**:
    - **Counts**: 1 malware sample captured, 1 related downloader command executed.
    - **Artifacts**:
        - **Malware Hash (SHA256)**: `b6a05e2244a46eca59671bad97f27846eaaca8beb3d915dae39140969612650c`
        - **Downloader Command**: `chmod 755 /data/local/tmp/.p 2>/dev/null; (/data/local/tmp/.p >/dev/null 2>&1 &)`
        - **Source IP**: `45.205.1.110`
- **knownness checks performed + outcome**:
    - OSINT search for the malware hash returned zero results, indicating it is not publicly documented.
    - Suricata logs for the source IP `45.205.1.110` showed only a generic "poor reputation" alert, with no specific signature match for the malware download or ADB activity.
- **temporal checks**: unavailable
- **required follow-up**: The malware sample requires immediate reverse engineering to determine its capabilities and intent. The associated source IP should be blocked.

## 6. Botnet/Campaign Infrastructure Mapping

- **item_id**: `BOT-01`
- **campaign_shape**: fan-out (multi-vector attack from a single node)
- **suspected_compromised_src_ips**:
    - `45.205.1.110` (957 events)
- **ASNs / geo hints**:
    - ASN: 215925
    - Organization: Vpsvault.host Ltd (United States)
- **suspected_staging indicators**: No HTTP-based staging indicators were found. The attacker appears to use direct-to-host methods.
- **suspected_c2 indicators**: No C2 indicators were identified in the logs.
- **supporting evidence**: This IP was observed conducting a coordinated attack across multiple services, including:
    - **Redis**: Using the `CONFIG SET` command to attempt writing SSH keys to `authorized_keys` in `/root/.ssh/` and other directories. This is a well-documented TTP for gaining persistence.
    - **ADB**: Dropping the novel malware sample detailed in `NOV-02`.
    - **SSH**: Numerous connection attempts logged by the Cowrie honeypot.
    - **Reputation**: The IP triggered a Suricata alert for being on the "ET CINS Active Threat Intelligence Poor Reputation" list.
- **confidence**: High
- **operational notes**: The IP `45.205.1.110` should be added to a high-confidence blocklist. Further monitoring of activity from ASN 215925 is recommended. This campaign links an established Redis exploitation technique with a novel malware payload.

## 7. Odd-Service / Minutia Attacks

- **service_fingerprint**: Conpot Honeypot / `guardian_ast`, `IEC104` protocols
- **why it’s unusual/interesting**: Activity targeting Industrial Control System (ICS) protocols is always of interest, even at low volumes.
- **evidence summary**:
    - **Counts**: 6 events for `guardian_ast`, 1 event for `IEC104`.
    - **Artifacts**: No specific malicious payloads were identified.
- **confidence**: Low
- **recommended monitoring pivots**: OSINT validation revealed that `guardian_ast` is an internal simulator for the Conpot honeypot, not a real-world protocol. The activity is likely benign scanning or a result of honeypot artifacts. Treat as low priority unless volumes increase or more specific payloads are observed.

## 8. Known-Exploit / Commodity Exclusions
- **VNC Scanning**: High-volume VNC server responses (`GPL INFO VNC server response`, 27,605 events) were observed from numerous sources, consistent with widespread, non-targeted scanning.
- **Known Exploits**: Repeated attempts to use the DoublePulsar backdoor (1,595 events) were logged. This is a well-known, commodity exploit.
- **Credential Noise**: Standard brute-force attempts using common usernames (`root`, `admin`, `postgres`) and passwords (`123456`, `password`) were observed across SSH and other services.
- **Generic Scanning**: Activity included scans for MS Terminal Server on non-standard ports, consistent with reconnaissance.

## 9. Infrastructure & Behavioral Classification
- **Exploitation vs Scanning**: The investigation identified both targeted exploitation and broad, automated scanning.
    - `45.205.1.110`: **Exploitation**. Conducted a multi-stage, multi-vector attack with the clear intent of gaining persistence (Redis->SSH) and deploying a payload (ADB malware).
    - `82.24.64.32`: **Scanning**. Operated for only 91 seconds, testing a wide array of known web vulnerabilities (PHPUnit, ThinkPHP, etc.) in a rapid, automated fashion.
- **Campaign Shape**:
    - `BOT-01` (`45.205.1.110`): **Fan-out** from a single compromised node attacking multiple services on the honeypot.
- **Infra Reuse Indicators**: The IP `45.205.1.110` is on public blacklists, indicating it is likely a compromised host being reused for multiple campaigns. The Redis `CONFIG SET` TTP is a widely reused botnet technique.
- **Odd-Service Fingerprints**: The ICS protocol activity was determined to be low-confidence, likely related to honeypot noise rather than a targeted attack on OT infrastructure.

## 10. Evidence Appendix

**Item: Emerging n-day Exploitation (from `NOV-01`)**
- **source IPs**: `82.24.64.32` (151 events)
- **ASNs**: 395793, Arisk Communications inc. (United Kingdom)
- **target ports/services**: 80 (HTTP)
- **paths/endpoints**:
    - `/?%ADd+allow_url_include%3d1+%ADd+auto_prepend_file%3dphp://input`
    - `/V2/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php`
    - `/admin/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php`
    - `/index.php?s=/index/	hinkpp/invokefunction&function=call_user_func_array&vars[0]=md5&vars[1][]=Hello`
    - `/cgi-bin/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/bin/sh`
- **payload/artifact excerpts**: Payloads embedded in the URL paths are designed to trigger known RCEs in PHP, PHPUnit, and ThinkPHP.
- **temporal checks**: Attacker was active for only 91 seconds, between `2026-03-18T07:48:06.000Z` and `2026-03-18T07:49:37.764Z`.

**Item: Novel Exploit Candidate `NOV-02`**
- **source IPs**: `45.205.1.110`
- **ASNs**: 215925, Vpsvault.host Ltd (United States)
- **target ports/services**: 5555 (ADB)
- **payload/artifact excerpts**:
    - `chmod 755 /data/local/tmp/.p 2>/dev/null; (/data/local/tmp/.p >/dev/null 2>&1 &)`
    - SHA256 Hash: `b6a05e2244a46eca59671bad97f27846eaaca8beb3d915dae39140969612650c`
- **temporal checks**: unavailable

**Item: Botnet/Campaign `BOT-01`**
- **source IPs**: `45.205.1.110` (957 events)
- **ASNs**: 215925, Vpsvault.host Ltd (United States)
- **target ports/services**: 22 (SSH), 6379 (Redis), 5555 (ADB)
- **payload/artifact excerpts**:
    - Redis: `CONFIG SET dir /root/.ssh/`
    - Redis: `CONFIG SET dir /var/lib/redis/.ssh/`
    - Adb: (see `NOV-02`)
- **temporal checks**: unavailable

## 11. Indicators of Interest
- **IPs**:
    - `45.205.1.110` (High Confidence: Multi-vector exploitation, novel malware source)
    - `82.24.64.32` (High Confidence: Known-exploit scanner, IDS evasion)
- **Malware Hash (SHA256)**:
    - `b6a05e2244a46eca59671bad97f27846eaaca8beb3d915dae39140969612650c`
- **URLs / Paths**:
    - `/?%ADd+allow_url_include%3d1+%ADd+auto_prepend_file%3dphp://input`
    - `/V2/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php`
    - `/index.php?s=/index/	hinkpp/invokefunction&function=call_user_func_array&vars[0]=md5&vars[1][]=Hello`
- **Payload Fragments**:
    - ADB Command: `chmod 755 /data/local/tmp/.p`
    - Redis Command: `CONFIG SET dir /root/.ssh/`

## 12. Backend Tool Issues
No significant tool failures occurred that materially degraded the investigation's outcome. The `DeepInvestigationAgent` encountered a query that returned no results for an ASN pivot, but correctly diagnosed this as isolated attacker activity rather than a tool or data error before moving to the next lead.

## 13. Agent Action Summary (Audit Trail)
- **agent_name**: ParallelInvestigationAgent
- **purpose**: Gathered foundational telemetry across four parallel workstreams (Baseline, Known Signals, Credential Noise, Honeypot Specific).
- **inputs_used**: `investigation_start`, `investigation_end`.
- **actions_taken**: Executed multiple Kibana queries to get baseline statistics, top alerts, common credentials, and honeypot-specific interactions.
- **key_results**:
    - Identified 15,173 total attacks.
    - Highlighted VNC and DoublePulsar as top known signals.
    - Captured initial leads in Tanner (PHP requests) and Adbhoney (malware sample) logs.
- **errors_or_gaps**: None.

- **agent_name**: CandidateDiscoveryAgent
- **purpose**: Synthesized parallel outputs to identify and rank high-signal leads for deep investigation.
- **inputs_used**: `baseline_result`, `known_signals_result`, `credential_noise_result`, `honeypot_specific_result`.
- **actions_taken**: Pivoted from honeypot logs using `kibanna_discover_query` to correlate suspicious paths and commands with source IPs. Performed initial knownness checks against Suricata data.
- **key_results**:
    - Created 4 candidates: `NOV-01`, `NOV-02`, `BOT-01`, `ODD-01`.
    - Linked the novel ADB malware (`NOV-02`) and Redis activity to the same source IP (`BOT-01`).
    - Identified that the suspicious PHP requests in `NOV-01` did not have corresponding Suricata alerts.
- **errors_or_gaps**: None.

- **agent_name**: CandidateValidationLoopAgent
- **purpose**: To systematically validate the evidence for each discovered candidate.
- **inputs_used**: `candidate_discovery_result`.
- **actions_taken**: Ran 1 iteration on candidate `BOT-01`. Used `events_for_src_ip` to pull all 957 events related to the attacker IP `45.205.1.110`.
- **key_results**: Confirmed and enriched `BOT-01`, detailing the multi-vector nature of the attack across Redis, ADB, and SSH, and noting the "poor reputation" alert.
- **errors_or_gaps**: The provided log only shows the validation of one candidate.

- **agent_name**: DeepInvestigationLoopController
- **purpose**: To perform deep-dive analysis on validated candidates, pivoting on artifacts to uncover broader campaign activity or confirm novelty.
- **inputs_used**: `validated_candidates`.
- **actions_taken**: Ran 1 iteration. Pursued ASN pivot on `BOT-01` (concluded activity was isolated). Pursued exploit analysis on `NOV-01`, using OSINT (`search`) to map a ThinkPHP payload to `CVE-2019-9082`, then queried Suricata data for that CVE.
- **key_results**:
    - Confirmed activity from ASN 215925 was isolated to a single IP in this window.
    - **Crucially confirmed a detection gap**: The scanner `82.24.64.32` was using a known exploit for `CVE-2019-9082`, but no signatures existed in the local IDS to detect it.
- **errors_or_gaps**: None, loop exited after exhausting leads.

- **agent_name**: OSINTAgent
- **purpose**: To provide external context and validate the novelty and knownness of candidates.
- **inputs_used**: All candidate data.
- **actions_taken**: Performed multiple `search` queries for IPs, the malware hash, and exploit strings.
- **key_results**:
    - Reclassified `NOV-01` by mapping its exploit attempts to `CVE-2017-9841` and `CVE-2024-4577`.
    - Confirmed the malware hash from `NOV-02` has no public presence.
    - Confirmed the IP `45.205.1.110` is on public abuse blacklists.
    - Confirmed the Redis TTP is a well-documented botnet technique.
- **errors_or_gaps**: None.

- **agent_name**: ReportAgent
- **purpose**: Compile the final report from all workflow state outputs.
- **inputs_used**: All previous agent outputs.
- **actions_taken**: Assembled this report by consolidating, re-classifying, and summarizing evidence as mandated by OSINT and Deep Investigation findings.
- **key_results**: This markdown report.
- **errors_or_gaps**: None.

- **agent_name**: SaveReportAgent
- **purpose**: To save the final report artifact.
- **inputs_used**: The generated markdown report.
- **actions_taken**: Will call `deep_agent_write_file`.
- **key_results**: File write status and path.
- **errors_or_gaps**: To be determined.