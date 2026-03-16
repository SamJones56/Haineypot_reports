# Threat Investigation Report

## 1. Investigation Scope
- **investigation_start**: 2026-03-10T06:00:06Z
- **investigation_end**: 2026-03-10T09:00:06Z
- **completion_status**: Partial (degraded evidence)
- **degraded_mode**: true; Key correlation queries failed during candidate discovery, preventing source IP identification for some notable activity.

## 2. Executive Triage Summary
- **Top Services/Ports of Interest**: Web (80/tcp), SMB (445/tcp), VNC (5901-5913/tcp), Minecraft (25565/tcp), and Industrial Control System (ICS) protocols (kamstrup_protocol).
- **Top Confirmed Known Exploitation**: A multi-exploit web campaign was identified from a single IP, primarily targeting PHP vulnerabilities (including CVE-2024-4577 and CVE-2017-9841).
- **Top Unmapped Exploit-like Items**: No high-confidence novel exploit candidates were validated.
- **Botnet/Campaign Mapping Highlights**: A single source IP (**85.208.51.38**) was observed conducting a spray of attacks targeting various web vulnerabilities, including PHPUnit RCE, PHP-CGI flaws (CVE-2024-4577), Apache Path Traversal (CVE-2021-42013), and probes for ThinkPHP, PEAR, and Docker APIs.
- **Odd-Service Highlights**: Unusual activity includes traffic from sources fingerprinted as "Nintendo 3DS" targeting a Minecraft server port, and significant but unattributed probing using the `kamstrup_protocol` associated with ICS/smart meters.
- **Major Uncertainties**: Source IPs for the `kamstrup_protocol` activity could not be identified due to tool failures, blocking further analysis of this potentially significant ICS-related event.

## 3. Candidate Discovery Summary
- The discovery process identified three main areas of interest from the initial telemetry:
  1.  Widespread web exploitation attempts against PHPUnit and other web frameworks, which was classified as a botnet/campaign activity (**BCM-001**).
  2.  Anomalous client OS fingerprints ("Nintendo 3DS") targeting a game server port (**OSM-001**).
  3.  A significant volume of ICS-related protocol (`kamstrup_protocol`) activity in the Conpot honeypot (**OSM-002**).
- Discovery was materially affected by query failures that prevented the correlation of source IPs with the Conpot/ICS activity.

## 4. Emerging n-day Exploitation
*No items classified as Emerging n-day Exploitation in this window.*

## 5. Novel or Zero-Day Exploit Candidates
*No items classified as Novel Exploit Candidates in this window.*

## 6. Botnet/Campaign Infrastructure Mapping
- **item_id**: BCM-001
- **campaign_shape**: fan-out (A single source IP using a wide array of exploit payloads against a single target).
- **suspected_compromised_src_ips**: 
  - **85.208.51.38** (High Confidence)
  - 209.141.37.52 (Low Confidence)
  - 78.153.140.147 (Low Confidence)
- **ASNs / geo hints**: ASN 51167 (Contabo GmbH, France) associated with the primary source IP.
- **suspected_staging indicators**: Not Applicable.
- **suspected_c2 indicators**: None identified. All traffic was unidirectional towards the honeypot.
- **confidence**: High
- **operational notes**: This campaign actor is using a versatile scanner to check for numerous high-profile web vulnerabilities in a very short time window (<2 minutes). The primary IOC, **85.208.51.38**, should be blocked. The activity is linked to known, widespread exploitation of PHP vulnerabilities.

## 7. Odd-Service / Minutia Attacks
- **Item 1: Anomalous Game Server Probing**
  - **service_fingerprint**: p0f OS fingerprint: 'Nintendo 3DS' | Target Port: 25565/tcp (Minecraft) and others.
  - **why it’s unusual/interesting**: The client OS fingerprint is highly anomalous for automated scanning. OSINT analysis indicates that such p0f fingerprints can be deliberately spoofed to mislead defenders.
  - **evidence summary**: 22 events from 3 source IPs (`51.15.34.47`, `176.65.148.185`, `176.65.134.6`) targeting multiple ports, including the Minecraft server port.
  - **confidence**: Medium
  - **recommended monitoring pivots**: Monitor the source IPs for other anomalous behavior. Track activity on game-related ports for signs of misuse.

- **Item 2: Industrial Control System (ICS) Probing**
  - **service_fingerprint**: Conpot Honeypot | Protocol: `kamstrup_protocol`
  - **why it’s unusual/interesting**: This traffic targets an ICS protocol used for utility meters, indicating reconnaissance against operational technology (OT) assets.
  - **evidence summary**: 246 events logged for `kamstrup_protocol`.
  - **confidence**: Low (Provisional)
  - **recommended monitoring pivots**: This finding is provisional because backend query failures prevented the identification of source IPs. The immediate follow-up is to repair the query logic to enable source attribution for this activity in future windows.

## 8. Known-Exploit / Commodity Exclusions
- **VNC Scanning**: Widespread activity (22,042 events) matching the Suricata signature "GPL INFO VNC server response" (ID: 2100560) was observed across numerous source IPs. This is background noise.
- **SMB Scanning**: High-volume traffic on port 445/tcp from countries including India, Kuwait, and Bolivia, typical of commodity worm and scanner activity.
- **Credential Noise**: Standard brute-force attempts using common usernames (`root`, `admin`, `user`) and passwords (`123456`, `password`, `1234`).

## 9. Infrastructure & Behavioral Classification
- **Exploitation vs Scanning**: The investigation identified both widespread, low-sophistication scanning (VNC, SMB) and targeted, known exploitation (BCM-001 web campaign).
- **Campaign Shape**: The primary campaign (BCM-001) exhibited a `fan-out` or spray behavior, with one IP delivering a diverse payload of exploits.
- **Infra Reuse Indicators**: The actor behind BCM-001 reused a single IP (`85.208.51.38`) for its multi-exploit campaign. The "Nintendo 3DS" activity involved a small cluster of IPs.
- **Odd-Service Fingerprints**: Key oddities include the `kamstrup_protocol` (ICS) and the spoofed `Nintendo 3DS` p0f fingerprint.

## 10. Evidence Appendix
- **BCM-001 (Web Exploit Campaign)**
  - **Source IPs**: `85.208.51.38` (173 events)
  - **ASNs**: 51167 (Contabo GmbH)
  - **Target Ports/Services**: 80/tcp (HTTP)
  - **Payload/Artifact Excerpts (Paths)**:
    - `/?%ADd+allow_url_include%3d1+%ADd+auto_prepend_file%3dphp://input` (PHP-CGI CVE-2024-4577)
    - `/V2/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php` (PHPUnit RCE CVE-2017-9841)
    - `/cgi-bin/%%32%65.../bin/sh` (Apache Path Traversal/RCE CVE-2021-42013)
    - `/index.php?s=/index/\think\app/invokefunction...` (ThinkPHP RCE)
    - `/index.php?lang=../../.../pearcmd&+config-create...` (PEAR RCE)
    - `/containers/json` (Docker API)
  - **Temporal Checks**: All activity from the primary IP occurred in a brief window between 2026-03-10T08:20:54.000Z and 2026-03-10T08:22:06.642Z.

- **OSM-001 (Anomalous Game Server Probing)**
  - **Source IPs**: `51.15.34.47`, `176.65.148.185`, `176.65.134.6`
  - **ASNs**: Not available.
  - **Target Ports/Services**: 25565/tcp, 27565/tcp, 41571/tcp, 20100/tcp, and others.
  - **Payload/Artifact Excerpts**: p0f OS Fingerprint: `Nintendo 3DS`
  - **Temporal Checks**: Unavailable.

- **OSM-002 (ICS Probing)**
  - **Source IPs**: Unavailable due to query failure.
  - **ASNs**: Unavailable.
  - **Target Ports/Services**: Unavailable.
  - **Payload/Artifact Excerpts**: Conpot Protocol: `kamstrup_protocol`
  - **Temporal Checks**: Unavailable.

## 11. Indicators of Interest
- **IPs (High Confidence - Block)**:
  - `85.208.51.38`
- **IPs (Medium Confidence - Monitor)**:
  - `51.15.34.47`
  - `176.65.148.185`
  - `176.65.134.6`
- **CVEs Observed**:
  - `CVE-2024-4577` (PHP-CGI Argument Injection)
  - `CVE-2017-9841` (PHPUnit RCE)
  - `CVE-2021-42013` (Apache Path Traversal)
- **Malicious URL Paths / Fragments**:
  - `/?%ADd+allow_url_include%3d1+%ADd+auto_prepend_file%3dphp://input`
  - `vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php`
  - `cgi-bin/%%32%65`
  - `index.php?s=/index/\think\app/invokefunction`
  - `pearcmd&+config-create`

## 12. Backend Tool Issues
- **`CandidateDiscoveryAgent`**:
  - `two_level_terms_aggregated`: The tool failed to execute when attempting to correlate `conpot.protocol.keyword` with `src_ip.keyword`.
  - `top_src_ips_for_cve`: The tool returned no results for `CVE-2025-55182`, preventing attribution.
- **Affected Validations**: These failures directly blocked the validation of candidate `OSM-002` by preventing the identification of source IPs for the `kamstrup_protocol` activity. This significantly weakens the conclusion, marking it as provisional.

## 13. Agent Action Summary (Audit Trail)
- **agent_name**: ParallelInvestigationAgent
- **purpose**: Perform initial broad-spectrum data gathering.
- **inputs_used**: `investigation_start`, `investigation_end`.
- **actions_taken**: Sub-agents queried for baseline statistics, known signatures/CVEs, credential stuffing indicators, and honeypot-specific logs.
- **key_results**: Identified high-volume VNC/SMB scanning, common credential abuse, PHPUnit exploit attempts, anomalous "Nintendo 3DS" p0f fingerprints, and ICS protocol activity.
- **errors_or_gaps**: None.

- **agent_name**: CandidateDiscoveryAgent
- **purpose**: Synthesize initial findings into actionable investigation candidates.
- **inputs_used**: All outputs from the `ParallelInvestigationAgent`.
- **actions_taken**: Aggregated data, searched for correlations, and performed initial OSINT lookups.
- **key_results**: Generated three candidates: BCM-001 (Web Campaign), OSM-001 (Nintendo 3DS), OSM-002 (ICS Protocol).
- **errors_or_gaps**: Several `two_level_terms_aggregated` queries failed, preventing IP correlation for Conpot activity. `top_src_ips_for_cve` also failed. Marked run as `degraded_mode`.

- **agent_name**: CandidateValidationLoopAgent
- **purpose**: Perform detailed validation of a single candidate.
- **inputs_used**: Candidate `BCM-001`.
- **actions_taken**: Ran `web_path_samples` and `two_level_terms_aggregated` to correlate Tanner and Suricata data for the web exploit paths.
- **key_results**: Validated that `BCM-001` represents a known exploit campaign, identified the primary source IP (`85.208.51.38`), and linked the activity to multiple Suricata signatures and CVEs.
- **errors_or_gaps**: The loop only processed one candidate before handing off to the deep investigation.

- **agent_name**: DeepInvestigationLoopController
- **purpose**: Conduct an in-depth, iterative investigation starting from a high-value validated candidate.
- **inputs_used**: Validated candidate `BCM-001`, specifically lead `src_ip:85.208.51.38`.
- **actions_taken**: Iterations run: 3. Pursued leads for the source IP and associated malicious URL paths. Used `first_last_seen_src_ip`, `top_http_urls_for_src_ip`, `web_path_samples`, and OSINT search.
- **key_results**: Uncovered the full scope of the web campaign from `85.208.51.38`, identifying exploit attempts for ThinkPHP, Shellshock, PEAR, and Docker in addition to the initial PHPUnit vector. Confirmed all paths led back to the same source IP.
- **errors_or_gaps**: The investigation loop exited after stalling for 2 iterations (no new leads were generated), correctly halting the deep dive.

- **agent_name**: OSINTAgent
- **purpose**: Provide external context on vulnerabilities, actors, and indicators.
- **inputs_used**: Leads from other agents (e.g., "CVE-2024-4577", "Nintendo 3DS p0f", "kamstrup").
- **actions_taken**: Performed web searches for key terms.
- **key_results**: Provided detailed context on CVE-2024-4577, confirmed the possibility of p0f fingerprint spoofing, and gathered information on Kamstrup meter communication protocols.
- **errors_or_gaps**: None.

- **agent_name**: ReportAgent
- **purpose**: Compile the final report from all available workflow state.
- **inputs_used**: All preceding agent outputs and investigation logs.
- **actions_taken**: Aggregated and structured all findings into this final report document.
- **key_results**: This report.
- **errors_or_gaps**: Noted where missing data (due to tool failures) weakened conclusions (e.g., OSM-002).

- **agent_name**: SaveReportAgent
- **purpose**: Persist the final report.
- **actions_taken**: Awaiting tool call to write the report content to a file.
- **key_results**: Pending.
- **errors_or_gaps**: Pending.
