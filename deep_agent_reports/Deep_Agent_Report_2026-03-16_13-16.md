# Honeypot Threat Hunting Report: Final

## 1. Investigation Scope
- **investigation_start**: 2026-03-16T13:00:10Z
- **investigation_end**: 2026-03-16T16:00:10Z
- **completion_status**: Partial (degraded evidence)
- **degraded_mode**: true
  - **Reason**: The deep investigation into unusual Industrial Control System (ICS) activity was blocked by consecutive query failures, leading to an early exit from the analysis loop. Full correlation of source IPs to ICS protocols could not be completed.

## 2. Executive Triage Summary
- **Top Services/Ports of Interest**:
  - **VNC (5901-5905)**: Subjected to high-volume commodity scanning.
  - **ICS/SCADA (Conpot)**: Exhibited unusual and concerning interactions with specialized industrial protocols (`kamstrup_protocol`, `IEC104`).
  - **Android Debug Bridge (Adbhoney)**: Targeted by low-volume reconnaissance scanning, indicating interest in non-standard IoT/mobile services.
  - **Multiple Web Ports (80, 2000, 3011, 7000+)**: Targeted by two distinct, automated web vulnerability scanning campaigns.
- **Top Confirmed Known Exploitation**:
  - **CVE-2025-55182 (React2Shell)**: A high-volume, wide fan-out scanning campaign from a single IP (`193.32.162.28`) targeting this recently disclosed critical RCE.
  - **CVE-2017-9841 & CVE-2024-4577**: A multi-purpose scanner (`62.171.133.187`) used a "kitchen sink" approach, targeting old (PHPUnit) and recent (PHP RFI) vulnerabilities.
- **Novel Exploit Candidates**:
  - No novel or zero-day candidates were validated in this window. All exploit-like activity was successfully mapped to known vulnerabilities.
- **Botnet/Campaign Mapping Highlights**:
  - Two distinct automated campaigns were identified, each from a single source IP, displaying different scanning strategies (fan-out vs. multi-exploit spray).
- **Major Uncertainties**:
  - A full mapping of the actors targeting the Conpot ICS honeypot was not possible due to backend query failures. The scope and intent of this activity remain a key intelligence gap.

## 3. Candidate Discovery Summary
The discovery phase successfully identified four candidates for investigation based on high-signal alerts, unusual URIs, and odd-service protocol usage. The initial assessment was partially degraded due to query failures that prevented the retrieval of source IPs for `CVE-2025-55182` and the correlation of IPs with Conpot ICS protocol activity.

- **Emerging n-day Exploitation Candidates**: 1 (CVE-2025-55182)
- **Botnet/Campaign Mapping Candidates**: 1 (PHPUnit/PHP RFI Scanner)
- **Odd-Service/Minutia Attack Candidates**: 2 (Adbhoney Recon, Conpot ICS Probing)

## 4. Emerging n-day Exploitation

### NDE-01: CVE-2025-55182 (React2Shell) Scanning Campaign
- **cve/signature mapping**: CVE-2025-55182 / `ET WEB_SPECIFIC_APPS React Server Components React2Shell Unsafe Flight Protocol Property Access (CVE-2025-55182)`
- **evidence summary**:
  - 82 events directly matched the CVE signature.
  - All activity originated from a single source IP, `193.32.162.28`, which was responsible for 1,409 total events in the window.
  - The attacker used a fixed set of 6 URLs (e.g., `/_next`, `/api/route`, `/app`) consistent with exploiting this vulnerability.
- **affected service/port**: A wide range of common web ports including 2000, 3006, 3007, 3011, 7000, 7777, 8181, 9090, and 10000.
- **confidence**: High
- **operational notes**: OSINT confirms CVE-2025-55182 is a critical, publicly disclosed RCE from December 2025. The observed behavior is consistent with widespread, automated scanning for this known vulnerability. The campaign shape is a classic fan-out scan from a single source.

## 5. Novel or Zero-Day Exploit Candidates (UNMAPPED ONLY, ranked)
*No candidates met the criteria for this category in the current investigation window. All identified exploit-like behavior was mapped to known vulnerabilities.*

## 6. Botnet/Campaign Infrastructure Mapping

### Item: BOT-01 - Multi-Exploit Web Scanner
- **related candidate_id(s)**: BOT-01
- **campaign_shape**: spray
- **suspected_compromised_src_ips**: `62.171.133.187` (151 events)
- **ASNs / geo hints**: ASN 51167 (Contabo GmbH)
- **suspected_staging indicators**:
  - `/V2/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php` (CVE-2017-9841)
  - `/?%ADd+allow_url_include%3d1+%ADd+auto_prepend_file%3dphp://input` (CVE-2024-4577)
  - `/index.php?s=/index/\think\app/invokefunction...` (ThinkPHP RCE)
  - `/cgi-bin/.%2e/.%2e/.../bin/sh` (CGI Command Injection)
- **suspected_c2 indicators**: None identified.
- **confidence**: High
- **operational notes**: This actor is a "kitchen sink" scanner, testing for at least five distinct, high-profile web vulnerabilities in a rapid burst of activity. OSINT confirms the source IP has a known-bad abuse reputation.

### Item: NDE-01-Campaign - CVE-2025-55182 Scanner
- **related candidate_id(s)**: NDE-01
- **campaign_shape**: fan-out
- **suspected_compromised_src_ips**: `193.32.162.28` (1,409 events)
- **ASNs / geo hints**: ASN 47890 (Unmanaged Ltd)
- **suspected_staging indicators**: Paths consistent with React2Shell exploit: `/`, `/_next`, `/api`, `/app`, etc.
- **suspected_c2 indicators**: None identified.
- **confidence**: High
- **operational notes**: This is a single-purpose, automated scanner exclusively focused on finding and exploiting CVE-2025-55182 across a wide range of web service ports.

## 7. Odd-Service / Minutia Attacks

### Item: ODD-02 - ICS/SCADA Protocol Probing
- **service_fingerprint**: Conpot (ICS/SCADA Honeypot)
- **why it’s unusual/interesting**: The targeted protocols, `kamstrup_protocol` (utility meters) and `IEC104` (power grid control), are highly specialized and not part of typical internet background noise. Probing these services suggests targeted reconnaissance against critical infrastructure.
- **evidence summary**:
  - `kamstrup_protocol`: 39 events
  - `IEC104`: 14 events
  - **Provisional**: A full investigation was blocked by query failures. Only one sample event was retrieved, linking source IP `85.217.149.46` (AS 209334, Modat B.V.) to a connection loss event.
- **confidence**: Medium
- **recommended monitoring pivots**: Requires immediate follow-up to resolve the data access issues preventing full analysis. Understanding the actors and their TTPs against these protocols is a high priority.

### Item: ODD-01 - Android Debug Bridge (ADB) Reconnaissance
- **service_fingerprint**: Adbhoney (port 5555/TCP)
- **why it’s unusual/interesting**: Represents scanning and enumeration of a non-standard mobile/IoT service interface.
- **evidence summary**: A single event from `45.135.194.48` executed the command: `echo "$(getprop ro.product.name 2>/dev/null) $(whoami 2>/dev/null)"`.
- **confidence**: Low
- **recommended monitoring pivots**: OSINT confirms this is a common, low-sophistication fingerprinting command. Monitor the source IP for any follow-on exploit attempts against IoT infrastructure.

## 8. Known-Exploit / Commodity Exclusions
- **VNC Scanning**: 14,938 events for `GPL INFO VNC server response` were observed across many IPs. This is commodity scanning activity.
- **RDP Scanning**: 551 events for `ET SCAN MS Terminal Server Traffic on Non-standard Port` were observed. This is common RDP scanning noise.
- **Credential Noise**: Standard brute-force usernames (`root`, `admin`, `user`) and passwords (`123456`, `password`) were observed. A likely bot-generated credential pair (`345gs5662d34`/`3245gs5662d34`) was attempted 72 times.
- **Known Web Exploits**: The PHPUnit (CVE-2017-9841) and PHP RFI (CVE-2024-4577) attempts were excluded from novel candidacy and tracked as part of the BOT-01 campaign.

## 9. Infrastructure & Behavioral Classification
- **Exploitation vs. Scanning**: The activity from `193.32.162.28` (NDE-01) and `62.171.133.187` (BOT-01) was confirmed exploitation activity targeting known CVEs. The ICS and ADB activity was classified as reconnaissance scanning.
- **Campaign Shape**: `NDE-01` was a **fan-out** campaign (one actor, one exploit, many targets/ports). `BOT-01` was a **spray** campaign (one actor, many exploits, one target port).
- **Infra Reuse Indicators**: No infrastructure reuse was observed between the distinct campaigns within the analysis window.
- **Odd-Service Fingerprints**: **ICS/SCADA** (`kamstrup_protocol`, `IEC104`) and **Android/IoT** (Adbhoney recon command).

## 10. Evidence Appendix

### NDE-01 / CVE-2025-55182 Campaign
- **Source IPs**: `193.32.162.28` (1,409)
- **ASNs**: 47890 (Unmanaged Ltd)
- **Target Ports**: 2000, 3006, 3007, 3011, 7000, 7777, 8181
- **Paths/Endpoints**: `/`, `/_next`, `/_next/server`, `/api`, `/api/route`, `/app`
- **Payload/Artifact Excerpts**: `alert.signature: "ET WEB_SPECIFIC_APPS React Server Components React2Shell Unsafe Flight Protocol Property Access (CVE-2025-55182)"`

### BOT-01 / Multi-Exploit Scanner
- **Source IPs**: `62.171.133.187` (151)
- **ASNs**: 51167 (Contabo GmbH)
- **Target Ports**: 80
- **Paths/Endpoints**:
  - `/V2/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php`
  - `/?%ADd+allow_url_include%3d1+%ADd+auto_prepend_file%3dphp://input`
  - `/index.php?s=/index/\think\app/invokefunction&function=call_user_func_array&vars[0]=md5&vars[1][]=Hello`

## 11. Indicators of Interest
- **IPs**:
  - `193.32.162.28` (High-volume CVE-2025-55182 scanner)
  - `62.171.133.187` (Multi-exploit web scanner)
  - `85.217.149.46` (Provisional: Linked to ICS protocol scanning)
- **URLs/Paths**:
  - `/V2/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php`
  - `/?%ADd+allow_url_include%3d1+%ADd+auto_prepend_file%3dphp://input`
- **CVEs**:
  - `CVE-2025-55182`
  - `CVE-2017-9841`
  - `CVE-2024-4577`

## 12. Backend Tool Issues
- **`top_src_ips_for_cve`**: Failed during Candidate Discovery, initially weakening the assessment of the CVE-2025-55182 campaign.
- **`two_level_terms_aggregated`, `kibanna_discover_query`, `discover_by_keyword`**: Multiple query tools failed to access Conpot honeypot data during both discovery and deep investigation. This blocked the validation of candidate ODD-02 and prevented a full mapping of ICS-related threats. Conclusions for this candidate are provisional and require engineering follow-up to fix data access.

## 13. Agent Action Summary (Audit Trail)
- **ParallelInvestigationAgent**:
  - **purpose**: Gathered baseline statistics, known threat signatures, credential noise, and honeypot-specific data for the time window.
  - **inputs_used**: `investigation_start`, `investigation_end`.
  - **actions_taken**: Executed parallel queries via four sub-agents.
  - **key_results**: Produced structured data on attack volume, top countries/ASNs, top CVEs/signatures, common credentials, and notable honeypot URIs/protocols.
  - **errors_or_gaps**: None.
- **CandidateDiscoveryAgent**:
  - **purpose**: Identified high-signal leads from the initial data haul.
  - **inputs_used**: All outputs from ParallelInvestigationAgent.
  - **actions_taken**: Analyzed inputs to create four distinct candidates (NDE-01, BOT-01, ODD-01, ODD-02).
  - **key_results**: Generated a ranked list of threats for validation.
  - **errors_or_gaps**: The `top_src_ips_for_cve` and `two_level_terms_aggregated` (for Conpot) queries failed, resulting in an incomplete initial picture.
- **CandidateValidationLoopAgent**:
  - **purpose**: Conducted initial validation of the first high-priority candidate.
  - **inputs_used**: `candidate_discovery_result`.
  - **actions_taken**: Ran 1 iteration validating `NDE-01`. Used `suricata_cve_samples` and `events_for_src_ip` to correlate CVE events to a single source IP.
  - **key_results**: Confirmed `NDE-01` as a high-confidence, single-actor campaign, enriching it with source IP and event count.
  - **errors_or_gaps**: Loop did not proceed to other candidates in the provided context.
- **DeepInvestigationLoopController**:
  - **purpose**: Performed in-depth, iterative analysis of validated leads.
  - **inputs_used**: Leads derived from `NDE-01`, `BOT-01`, and `ODD-02`.
  - **actions_taken**: Ran 4 iterations. Fully investigated the two scanner IPs (`193.32.162.28`, `62.171.133.187`) by analyzing their activity windows, targeted ports, and requested URLs. Attempted to investigate Conpot activity.
  - **key_results**: Mapped the TTPs of the React2Shell and PHP scanners. Discovered the correct query syntax (`type: "ConPot"`) for Conpot events before being forced to exit.
  - **errors_or_gaps**: The loop was forced to exit after reaching a `stall_count` of 2 due to consecutive query failures while investigating Conpot data. The investigation of `ODD-02` was left incomplete.
- **OSINTAgent**:
  - **purpose**: Enriched findings with open-source intelligence.
  - **inputs_used**: All four candidates from the discovery phase.
  - **actions_taken**: Performed `search` queries on CVEs, exploit URIs, reconnaissance commands, and ICS protocols.
  - **key_results**: Confirmed all exploit activity maps to known, publicly documented vulnerabilities (CVE-2025-55182, CVE-2017-9841, CVE-2024-4577). Confirmed odd-service activity maps to established recon patterns. Reduced novelty of all candidates but increased operational concern for the ICS activity.
  - **errors_or_gaps**: None.
- **ReportAgent**:
  - **purpose**: Compiled the final report from all available workflow state.
  - **inputs_used**: All preceding agent outputs.
  - **actions_taken**: Synthesized data, determined completion status, applied mandatory logic, and structured the final markdown output.
  - **key_results**: This report.
  - **errors_or_gaps**: Operated in degraded mode due to incomplete state from the DeepInvestigationLoopController.
- **SaveReportAgent**:
  - **purpose**: Persist the final report.
  - **inputs_used**: Final markdown report content.
  - **actions_taken**: Calling `deep_agent_write_file`.
  - **key_results**: File write status to be determined.
  - **errors_or_gaps**: None.
