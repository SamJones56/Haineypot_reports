# Honeypot Threat Hunting Report

## 1) Investigation Scope
- **investigation_start**: 2026-03-11T16:00:05Z
- **investigation_end**: 2026-03-11T20:00:05Z
- **completion_status**: Partial (degraded evidence)
- **degraded_mode**: true. The investigation was partially degraded due to a backend tool failure that prevented the direct analysis of Industrial Control System (ICS) honeypot data (Conpot), limiting insight into reported ICS protocol activity.

## 2) Executive Triage Summary
- **Top Services/Ports of Interest**: The most significant activity targeted VNC (5900, 5902-5904), SMB (445), and HTTP (80).
- **Odd-Service Highlights**: Unusual scanning activity was observed targeting game-related ports, notably Minecraft (25565), from sources fingerprinted as "Nintendo 3DS" game consoles. Additionally, unverified activity involving ICS protocols (guardian_ast, IEC104) was reported by honeypot sensors.
- **Top Confirmed Known Exploitation**: Activity included exploitation attempts for **CVE-2024-4577** (a recent PHP argument injection vulnerability) and **CVE-2017-9841** (PHPUnit RCE).
- **Novel Exploit Candidates**: One initial candidate (`NOV-01`) was identified but was subsequently reclassified as a known n-day exploit (CVE-2024-4577) following OSINT validation. No novel exploit candidates remain.
- **Botnet/Campaign Mapping**: A multi-vulnerability scanner (`163.7.3.156`) was identified and linked with high confidence to the **"RedTail" cryptomining malware campaign**. A separate high-volume, single-purpose SMB scanner (`41.35.120.170`) was also isolated.
- **Major Uncertainties**: The nature and intent of reported ICS protocol interactions could not be validated due to a backend query failure, leaving a gap in our understanding of potential threats to OT services.

## 3) Candidate Discovery Summary
- The discovery phase analyzed 20,697 attack events, identifying several distinct clusters of activity for further investigation.
- Key findings included high-volume commodity scanning (VNC, SMB), targeted web exploit attempts (PHP LFI/RCE, PHPUnit RCE), and highly anomalous game server probing.
- The discovery process was materially affected by a failure to query Conpot honeypot data, which prevented the validation of observed ICS protocol events.

## 4) Emerging n-day Exploitation

#### Item 1: PHP Argument Injection Exploit
- **cve/signature mapping**: CVE-2024-4577
- **evidence summary**: 1 observed event. The artifact `/?%ADd+allow_url_include%3d1+%ADd+auto_prepend_file%3dphp://input` is a direct match for known exploitation techniques for this CVE.
- **affected service/port**: HTTP (80/TCP)
- **confidence**: High
- **operational notes**: This is a recently disclosed vulnerability affecting PHP on Windows. The observed activity confirms it is being actively exploited in the wild by automated scanners.

#### Item 2: PHPUnit Remote Code Execution
- **cve/signature mapping**: CVE-2017-9841
- **evidence summary**: Multiple observed events targeting various common paths for the vulnerable file, e.g., `/V2/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php`.
- **affected service/port**: HTTP (80/TCP)
- **confidence**: High
- **operational notes**: This is a well-known, older vulnerability. Its inclusion in scanning activity indicates it remains a viable target for initial access.

## 5) Novel or Zero-Day Exploit Candidates (UNMAPPED ONLY, ranked)
- No novel exploit candidates were confirmed in this window.
- The initial candidate **NOV-01** was reclassified as an emerging n-day exploit for **CVE-2024-4577** based on OSINT evidence.

## 6) Botnet/Campaign Infrastructure Mapping

#### Item 1: "RedTail" Cryptomining Campaign Scanner
- **item_id**: BOT-01
- **campaign_shape**: fan-out (a single source IP testing for many vulnerabilities)
- **suspected_compromised_src_ips**: `163.7.3.156` (1)
- **ASNs / geo hints**: ASN 150436 (Byteplus Pte. Ltd.), Indonesia
- **suspected_staging indicators**: The `libredtail-http` User-Agent was a key indicator linking this activity to the RedTail campaign. No C2 or staging URLs were observed in the telemetry.
- **confidence**: High
- **operational notes**: This actor is part of a known malware campaign. The IP was observed scanning for CVE-2024-4577, CVE-2017-9841, ThinkPHP RCE, and other web vulnerabilities. All activity from this source should be considered malicious.

#### Item 2: High-Volume SMB Scanner
- **item_id**: BOT-02
- **campaign_shape**: spray (a single source IP scanning a single port at high volume)
- **suspected_compromised_src_ips**: `41.35.120.170` (3,147 events)
- **ASNs / geo hints**: ASN 8452 (TE Data), Egypt
- **suspected_staging indicators**: None observed. This appears to be simple, indiscriminate scanning.
- **confidence**: High
- **operational notes**: This is commodity scanning activity, likely searching for systems vulnerable to worm propagation (e.g., WannaCry, NotPetya) or initial access.

## 7) Odd-Service / Minutia Attacks

#### Item 1: Game Server Probing from Consumer Devices
- **service_fingerprint**: Minecraft (25565/TCP) and various other high-numbered ports.
- **why it’s unusual/interesting**: The source IP's operating system was consistently fingerprinted by p0f as "Nintendo 3DS". Deep investigation revealed multiple IPs from the same Slovenian residential ISP exhibiting this behavior, suggesting compromised consumer devices (such as IoT, routers, or actual game consoles) are being used for scanning.
- **evidence summary**: 15 total events with the "Nintendo 3DS" fingerprint from IPs including `176.65.134.6` and `176.65.148.185`. The activity was limited to port scanning with no exploit payloads.
- **confidence**: High
- **recommended monitoring pivots**: Monitor the `176.65.0.0/16` network block for further scanning activity.

## 8) Known-Exploit / Commodity Exclusions
- **VNC Scanning**: Excluded due to extremely high volume (16,691 events) from a wide spray of diverse source IPs. Activity matches the well-known informational signature `GPL INFO VNC server response`.
- **SMB Scanning**: Excluded as it represents common, high-volume scanning for a well-understood protocol often used in worm and botnet propagation.
- **Credential Noise**: Excluded due to low-sophistication brute-force attempts using default or common credential pairs (e.g., root/123, admin/password).

## 9) Infrastructure & Behavioral Classification
- **Exploitation vs Scanning**: The majority of events were classified as scanning. However, targeted, evidence-backed exploitation for specific CVEs was conducted by the "RedTail" campaign actor (`163.7.3.156`).
- **Campaign Shape**: The RedTail scanner exhibited a "fan-out" pattern (one-to-many vulnerabilities). The VNC and SMB activity showed a "spray" pattern.
- **Infra Reuse Indicators**: The IP `163.7.3.156` was reused to scan for at least four distinct web application vulnerabilities, indicating a multi-purpose attack tool.
- **Odd-Service Fingerprints**: The "Nintendo 3DS" OS fingerprint associated with game server port scanning is a notable anomaly.

## 10) Evidence Appendix

#### Emerging n-day: CVE-2024-4577
- **source IPs**: `163.7.3.156` (count: 1)
- **ASNs**: 150436 (Byteplus Pte. Ltd.)
- **target ports/services**: 80/TCP (HTTP)
- **paths/endpoints**: `/?%ADd+allow_url_include%3d1+%ADd+auto_prepend_file%3dphp://input`
- **payload/artifact excerpts**: The URL path itself is the primary artifact.

#### Botnet Mapping: BOT-01 ("RedTail" Campaign)
- **source IPs**: `163.7.3.156`
- **ASNs**: 150436 (Byteplus Pte. Ltd.)
- **target ports/services**: 80/TCP (HTTP)
- **paths/endpoints**: `/V2/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php`, `/index.php?s=/index/\think\app/invokefunction&...`, `/containers/json`, and others.
- **payload/artifact excerpts**: User-Agent: `libredtail-http`
- **temporal checks results**: All observed activity occurred within a two-minute window.

#### Botnet Mapping: BOT-02 (SMB Scanner)
- **source IPs**: `41.35.120.170` (count: 3,147)
- **ASNs**: 8452 (TE Data)
- **target ports/services**: 445/TCP (SMB)
- **paths/endpoints**: N/A
- **payload/artifact excerpts**: N/A (port scanning only)

## 11) Indicators of Interest
- **IPs**:
    - `163.7.3.156` ("RedTail" multi-vulnerability scanner)
    - `41.35.120.170` (High-volume SMB scanner)
    - `176.65.134.6` (Game server scanner / "Nintendo 3DS")
    - `176.65.148.185` (Game server scanner / "Nintendo 3DS")
- **URLs/Paths**:
    - `/?%ADd+allow_url_include%3d1+%ADd+auto_prepend_file%3dphp://input` (CVE-2024-4577)
    - `/V2/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php` (CVE-2017-9841)
- **Other Artifacts**:
    - User-Agent: `libredtail-http`

## 12) Backend Tool Issues
- **`two_level_terms_aggregated` (tool)**: This tool failed during the `CandidateDiscoveryAgent` phase when querying `Conpot` data.
    - **Affected Validation**: This failure blocked the ability to analyze and validate reported activity on ICS protocols (guardian_ast, IEC104). Conclusions regarding odd-service attacks are therefore weakened, as this entire category of threat could not be investigated.
- **`two_level_terms_aggregated` (tool)**: This tool failed again during the `DeepInvestigationAgent` phase when attempting to pivot on the `http.user_agent.keyword` field.
    - **Affected Validation**: This prevented a direct pivot to find other source IPs associated with the "RedTail" campaign via its unique User-Agent, forcing the agent to use a less direct indicator (exploit path).

## 13) Agent Action Summary (Audit Trail)

- **agent_name**: ParallelInvestigationAgent
- **purpose**: Gathers broad, parallel telemetry streams at the start of the workflow.
- **inputs_used**: `investigation_start`, `investigation_end`.
- **actions_taken**: Executed four sub-agents: BaselineAgent, KnownSignalAgent, CredentialNoiseAgent, and HoneypotSpecificAgent to query general statistics, known signatures, credential stuffing indicators, and honeypot-specific data.
- **key_results**: Provided the initial dataset indicating high VNC activity, SMB scanning, PHP exploit attempts, and unusual OS/protocol observations (Nintendo 3DS, ICS protocols).
- **errors_or_gaps**: None.

- **agent_name**: CandidateDiscoveryAgent
- **purpose**: Synthesizes parallel data streams to identify and rank potential threats.
- **inputs_used**: `baseline_result`, `known_signals_result`, `credential_noise_result`, `honeypot_specific_result`.
- **actions_taken**: Aggregated telemetry, correlated Tanner HTTP paths with source IPs, looked up a known exploit path (PHPUnit), and identified unusual OS fingerprints (Nintendo 3DS). Formulated initial candidates for validation.
- **key_results**: Identified and categorized candidates: `NOV-01` (PHP LFI/RCE), `BOT-01` (Web Scanner), `BOT-02` (SMB Scanner), and `ODD-01` (Nintendo 3DS).
- **errors_or_gaps**: A query to aggregate Conpot (ICS) data failed, preventing analysis of that activity.

- **agent_name**: CandidateValidationLoopAgent
- **purpose**: Performs initial, shallow validation of discovered candidates.
- **inputs_used**: `candidate_discovery_result`.
- **actions_taken**: Ran 1 iteration. Validated the `VNC Scanning` candidate by sampling Suricata events.
- **key_results**: Confirmed that "VNC Scanning" was high-volume, commodity noise matching an informational signature and classified it for exclusion.
- **errors_or_gaps**: The full validation loop for all candidates was not completed or its results were not present in the final state.

- **agent_name**: DeepInvestigationLoopController
- **purpose**: Conducts deep, iterative investigation on high-priority validated candidates.
- **inputs_used**: `validated_candidates` (implicitly, via queue).
- **actions_taken**: Ran 2 iterations.
    - **Lead 1 (BOT-01)**: Pivoted on source IP `163.7.3.156`, identified its multi-vulnerability scanning behavior, and linked it to the "RedTail" campaign via OSINT on its user-agent. Further pivots stalled.
    - **Lead 2 (ODD-01)**: Pivoted on source IP `176.65.134.6`, confirmed its behavior was limited to port scanning, and used OSINT to link its ASN and network block to a residential ISP, contextualizing the "Nintendo 3DS" anomaly.
- **key_results**: Successfully attributed `BOT-01` to a named malware campaign. Successfully explained the `ODD-01` anomaly as likely compromised consumer devices. Exited loop after exhausting leads.
- **errors_or_gaps**: A query to pivot on the `libredtail-http` user-agent failed.

- **agent_name**: OSINTAgent
- **purpose**: Enriches findings with external intelligence.
- **inputs_used**: `validated_candidates` (specifically `NOV-01`).
- **actions_taken**: Performed a web search on the key artifact from candidate `NOV-01`.
- **key_results**: Correctly reclassified the "novel" candidate as an exploitation attempt for the recently disclosed `CVE-2024-4577`, significantly reducing its novelty but increasing its assessed risk.
- **errors_or_gaps**: None.

- **agent_name**: ReportAgent
- **purpose**: Compiles the final report from all workflow state outputs.
- **inputs_used**: All available state keys.
- **actions_taken**: Assembled this markdown report.
- **key_results**: This report.
- **errors_or_gaps**: None.

- **agent_name**: SaveReportAgent
- **purpose**: Saves the final report to disk.
- **inputs_used**: `report_content`.
- **actions_taken**: Awaiting call to `deep_agent_write_file`.
- **key_results**: Pending.
- **errors_or_gaps**: None.
