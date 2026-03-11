# Threat Hunting Report: 2026-03-11T08:00:04Z to 2026-03-11T12:00:04Z

## 1) Investigation Scope
- **investigation_start**: 2026-03-11T08:00:04Z
- **investigation_end**: 2026-03-11T12:00:04Z
- **completion_status**: Complete
- **degraded_mode**: true - A backend tool failure prevented correlation of Industrial Control System (ICS) honeypot events to source IPs.

## 2) Executive Triage Summary
- **Top Services/Ports of Interest**: VNC (5900), HTTP (80), SSH (22), and various web-related ports (8180, 8183, 8191).
- **Odd/Minutia Services**: Probes detected for Industrial Control System (ICS) protocols, including `guardian_ast`, `kamstrup_management_protocol`, and `IEC104`. Attribution was blocked by a tool error.
- **Top Confirmed Known Exploitation**: A massive scanning campaign targeting VNC (port 5900) was identified, mapped to CVE-2006-2369.
- **Top Unmapped Exploit-like Items**: An advanced scanner was found testing for multiple, un-alerted web vulnerabilities including PHPUnit (CVE-2017-9841), ThinkPHP RCE (CVE-2018-20062), and LFI via `pearcmd`. OSINT analysis later identified this as the "RedTail Cryptominer" scanner.
- **Botnet/Campaign Mapping Highlights**: Four distinct campaigns were identified: a high-volume VNC scanner (BOT-01), the RedTail multi-exploit scanner (NOV-01), an Android fingerprinting tool (BOT-02), and a `.env` credential scanner (BOT-03).
- **Major Uncertainties**: The actors behind the ICS protocol scanning remain unknown due to a data pipeline failure.

## 3) Candidate Discovery Summary
- **Novel Candidates Identified**: 1 (NOV-01, later reclassified as N-day)
- **Botnet/Campaign Candidates Identified**: 3
- **Odd Service Candidates Identified**: 1
- **Summary**: The discovery phase successfully surfaced a multi-exploit web scanner (NOV-01) that was not being detected by existing signatures. It also isolated several smaller, distinct campaigns targeting VNC, Android, and web application credentials.
- **Material Gaps**: The failure of the `two_level_terms_aggregated` tool for `Conpot` data prevented the promotion of ICS-related activity into a full candidate with source attribution.

## 4) Emerging n-day Exploitation
- **cve/signature mapping**: CVE-2017-9841 (PHPUnit RCE), CVE-2018-20062 / CVE-2019-9082 (ThinkPHP RCE), LFI via `pearcmd`.
- **evidence summary**:
    - **Attacker IP**: `207.166.168.14` (174 events)
    - **User-Agent**: `libredtail-http`
    - **Key Artifacts**: Probes for `/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php`, `/index.php?s=/index/\think\app/invokefunction`, and LFI attempts using `pearcmd`.
- **affected service/port**: HTTP (80)
- **confidence**: High
- **operational notes**: This activity was initially flagged as a novel candidate (NOV-01). Deep investigation and OSINT confirmed it is the publicly documented "RedTail Cryptominer" scanner, which bundles multiple known exploits. While the exploits are known, our telemetry confirms they were not being detected by current signatures.

## 5) Novel or Zero-Day Exploit Candidates (UNMAPPED ONLY, ranked)
*No candidates remain in this category. The initial candidate, NOV-01, was re-classified as "Emerging n-day Exploitation" after validation and OSINT enrichment identified it as a known scanning tool (RedTail) using established exploits that were not generating alerts.*

## 6) Botnet/Campaign Infrastructure Mapping

- **item_id**: RedTail Scanner (from NOV-01)
- **campaign_shape**: fan-out
- **suspected_compromised_src_ips**: `207.166.168.14`
- **ASNs / geo hints**: AS150436 (Byteplus Pte. Ltd.), Singapore
- **suspected_staging indicators**: N/A - Scanner only.
- **suspected_c2 indicators**: The user-agent `libredtail-http` is known to be used for C2 communication by the RedTail malware, but no such traffic was directly observed.
- **confidence**: High
- **operational notes**: This is a multi-exploit scanner known to precede cryptomining activity. Blocking the IP and user-agent is recommended.

- **item_id**: BOT-01 (VNC Scanner)
- **campaign_shape**: spray
- **suspected_compromised_src_ips**: `185.231.33.22` (7,962 events)
- **ASNs / geo hints**: AS211720 (Datashield, Inc.)
- **suspected_staging indicators**: N/A
- **suspected_c2 indicators**: N/A
- **confidence**: High
- **operational notes**: Commodity but high-volume scanning for CVE-2006-2369. Worth monitoring the source IP for other activity.

- **item_id**: BOT-03 (.env Scanner)
- **campaign_shape**: fan-in
- **suspected_compromised_src_ips**: `78.153.140.93`
- **ASNs / geo hints**: (Unavailable)
- **suspected_staging indicators**: N/A
- **suspected_c2 indicators**: N/A
- **confidence**: Medium
- **operational notes**: Focused reconnaissance for exposed credential files.

- **item_id**: BOT-02 (Android Fingerprinting)
- **campaign_shape**: unknown
- **suspected_compromised_src_ips**: `45.135.194.48`
- **ASNs / geo hints**: (Unavailable)
- **suspected_staging indicators**: N/A
- **suspected_c2 indicators**: N/A
- **confidence**: Medium
- **operational notes**: Use of Android-specific `getprop` commands suggests targeted reconnaissance against mobile or embedded devices.

## 7) Odd-Service / Minutia Attacks
- **service_fingerprint**: `guardian_ast`, `kamstrup_management_protocol`, `IEC104` (ICS Protocols)
- **why it’s unusual/interesting**: These are specialized ICS protocols, indicating targeted reconnaissance against industrial systems, a deviation from typical commodity scanning.
- **evidence summary**: `guardian_ast` (58 events), `kamstrup_management_protocol` (3 events), `IEC104` (1 event).
- **confidence**: Medium (Provisional)
- **recommended monitoring pivots**: This investigation was unable to attribute the activity to a source IP due to a tool failure. The top priority is to fix the Conpot data pipeline to enable source IP correlation for future events.

## 8) Known-Exploit / Commodity Exclusions
- **VNC Exploitation (CVE-2006-2369)**: High-volume activity (7,962 events from one IP) matching signatures "ET EXPLOIT VNC Server Not Requiring Authentication". This is commodity scanning.
- **Credential Noise**: Standard brute-force attempts on SSH and other services using common usernames (`root`, `admin`, `ubuntu`) and passwords (`123456`, `password`).

## 9) Infrastructure & Behavioral Classification
- **RedTail Scanner (NOV-01)**: **Exploitation Scanning**. Uses a **fan-out** shape, testing many web exploit types from a single IP. Reuses known **scanner tooling** (`libredtail-http` user agent).
- **VNC Scanner (BOT-01)**: **Exploitation Scanning**. A **spray** campaign targeting one vulnerability from a single IP.
- **Android Fingerprinter (BOT-02)**: **Reconnaissance**. Targets **odd-service** fingerprints (Android `adbd`).
- **.env Scanner (BOT-03)**: **Reconnaissance**. A **fan-in** campaign focused on finding specific web application credential files.
- **ICS Probes (ODD-01)**: **Reconnaissance**. Targets **odd-service** fingerprints (ICS protocols).

## 10) Evidence Appendix

- **Item**: Emerging n-day: RedTail Scanner (NOV-01)
    - **source IPs**: `207.166.168.14` (174 events)
    - **ASNs**: 150436 (Byteplus Pte. Ltd.)
    - **target ports/services**: 80 (HTTP)
    - **payload/artifact excerpts**:
        - `GET /V2/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php`
        - `GET /index.php?s=/index/\think\app/invokefunction&function=call_user_func_array&vars[0]=md5&vars[1][]=Hello`
        - `GET /index.php?lang=../../../../../../../../usr/local/lib/php/pearcmd&+config-create+/&/<?echo(md5("hi"));?>+/tmp/index1.php`
        - `GET /containers/json`
    - **temporal checks**: First seen: `2026-03-11T10:38:45.000Z`, Last seen: `2026-03-11T10:40:06.631Z`

- **Item**: Botnet: VNC Scanner (BOT-01)
    - **source IPs**: `185.231.33.22` (7,962 events)
    - **ASNs**: 211720 (Datashield, Inc.)
    - **target ports/services**: 5900 (VNC)
    - **payload/artifact excerpts**: Associated with signatures "ET INFO VNC Authentication Failure" and "ET EXPLOIT VNC Server Not Requiring Authentication (case 2)". Mapped to CVE-2006-2369.
    - **temporal checks**: Unavailable.

## 11) Indicators of Interest
- **IPs**:
    - `207.166.168.14` (RedTail Multi-Exploit Scanner)
    - `185.231.33.22` (High-volume VNC Scanner)
- **User-Agents**:
    - `libredtail-http` (Associated with RedTail Cryptominer)
- **Paths / Payloads**:
    - `/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php` (PHPUnit CVE-2017-9841)
    - `\think\app/invokefunction` (ThinkPHP CVE-2018-20062)
    - `pearcmd&+config-create` (LFI to RCE technique)

## 12) Backend Tool Issues
- **Tool**: `two_level_terms_aggregated`
- **Affected Agent**: CandidateDiscoveryAgent
- **Failure**: The tool failed to execute when primary_field was `conpot.protocol.keyword`.
- **Impact**: This failure blocked the attribution of source IPs to ICS-related activity detected by the Conpot honeypot. As a result, the "Odd-Service / Minutia Attacks" findings are incomplete and marked as provisional, and no botnet/campaign analysis could be performed on this activity.

## 13) Agent Action Summary (Audit Trail)

- **agent_name**: ParallelInvestigationAgent
- **purpose**: Gathers broad, parallelized data sets for initial triage.
- **inputs_used**: `investigation_start`, `investigation_end`.
- **actions_taken**: Executed baseline queries for total attacks, top countries, IPs, ASNs, ports, known CVEs, alert signatures, and credential harvesting.
- **key_results**: Established a baseline of 36,961 attacks, dominated by activity from the US and Seychelles. Identified VNC-related signatures and CVE-2006-2369 as the most frequent known signals.
- **errors_or_gaps**: None.

- **agent_name**: CandidateDiscoveryAgent
- **purpose**: Synthesizes parallel inputs to identify novel or high-signal activity.
- **inputs_used**: `baseline_result`, `known_signals_result`, `credential_noise_result`, `honeypot_specific_result`.
- **actions_taken**: Aggregated data using `two_level_terms_aggregated` across different honeypot and event types. Enriched a potential finding with `search`.
- **key_results**: Identified one candidate for novel exploitation (NOV-01, PHPUnit), three botnet patterns (VNC, Android, .env), and one cluster of odd ICS activity.
- **errors_or_gaps**: A query to correlate Conpot (ICS honeypot) events with source IPs failed, preventing full analysis of that activity. `degraded_mode` was set to true.

- **agent_name**: CandidateValidationLoopAgent
- **purpose**: Manages the sequential validation of discovered candidates.
- **inputs_used**: `candidate_discovery_result`.
- **actions_taken**: Ran for 1 iteration, processing 1 candidate (NOV-01).
- **key_results**: Successfully queued and orchestrated the validation of the single high-priority candidate.
- **errors_or_gaps**: None.

- **agent_name**: DeepInvestigationLoopController
- **purpose**: Conducts deep, iterative analysis on high-confidence validated leads.
- **inputs_used**: The lead `src_ip:207.166.168.14` from the validated NOV-01 candidate.
- **actions_taken**: Ran for 1 iteration. Used `first_last_seen_src_ip` and `top_http_urls_for_src_ip` to pivot on the IP. Used `search` to identify a ThinkPHP exploit.
- **key_results**: Confirmed the IP was a multi-exploit scanner active for <2 minutes. Identified additional exploit attempts for ThinkPHP RCE (CVE-2018-20062) and LFI.
- **errors_or_gaps**: None; loop was exited intentionally after initial deep dive.

- **agent_name**: OSINTAgent
- **purpose**: Enriches validated findings with public, open-source intelligence.
- **inputs_used**: `validated_candidates`, `deep_investigation_log`.
- **actions_taken**: Executed `search` queries for "CVE-2017-9841", "libredtail-http", "pearcmd config-create", and "thinkphp invokefunction".
- **key_results**: Correctly identified the activity from NOV-01 as the "RedTail Cryptominer" scanner. This re-classified the finding from "novel" to "emerging n-day" as the TTPs are publicly known, though un-alerted in our environment.
- **errors_or_gaps**: None.

- **agent_name**: ReportAgent
- **purpose**: Compiles the final report from all available workflow state.
- **inputs_used**: All preceding agent outputs.
- **actions_taken**: Assembled this markdown report.
- **key_results**: Generated the final investigation report.
- **errors_or_gaps**: Noted the degraded state due to the Conpot data correlation failure.

- **agent_name**: SaveReportAgent
- **purpose**: Persists the final report file.
- **inputs_used**: Markdown report content.
- **actions_taken**: Called `deep_agent_write_file`.
- **key_results**: Report successfully saved.
- **errors_or_gaps**: None.
