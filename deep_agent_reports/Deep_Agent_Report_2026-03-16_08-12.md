# Threat Hunting Honeypot Investigation Report

## 1) Investigation Scope
- **investigation_start**: 2026-03-16T08:00:10Z
- **investigation_end**: 2026-03-16T12:00:10Z
- **completion_status**: Partial (degraded evidence)
- **degraded_mode**: true. The deep investigation into unusual Industrial Control System (ICS) activity was blocked due to repeated tool query failures, leaving a significant gap in the analysis.

## 2) Executive Triage Summary
- **Top Services of Interest**: High-volume scanning was observed on port 445 (SMB) and VNC ports (5902-5904). A significant emerging campaign targeted a wide range of non-standard web development ports (3004, 3010, 3333, 5001, 8081, etc.).
- **Odd/Minutia Services**: Probes against Industrial Control System (ICS) protocols (`guardian_ast`, `kamstrup_protocol`) were reported by honeypots. However, a full investigation was blocked by tool failures.
- **Top Confirmed Known Exploitation**: Widespread, active exploitation of **CVE-2025-55182 (React2Shell)**, a critical and recently disclosed RCE in React Server Components.
- **Botnet/Campaign Mapping Highlights**: The React2Shell campaign is comprised of at least two distinct actor types: a high-volume, specialized scanner (`193.32.162.28` from Romania) and a lower-volume, general-purpose scanner (`79.124.40.174` from Bulgaria).
- **Major Uncertainties**: The nature, origin, and scale of the reported ICS activity remain completely unknown due to backend tool failures preventing analysis.

## 3) Candidate Discovery Summary
The discovery process identified several key areas for investigation based on initial telemetry:
- **Known Exploits**: PHPUnit RCE (CVE-2017-9841).
- **Emerging Threats**: Recently disclosed CVEs, most notably CVE-2025-55182.
- **Credential Stuffing**: Use of an unusual but documented credential pair (`345gs5662d34` / `3245gs5662d34`) linked to botnets.
- **Odd-Service Activity**: Probes against Conpot ICS honeypots.
- **Investigation into the ICS activity was materially affected by tool failures**, which prevented any validation or analysis of the initial lead.

## 4) Emerging n-day Exploitation
### CVE-2025-55182 (React2Shell) Exploitation Campaign
- **cve/signature mapping**: `CVE-2025-55182`, `ET WEB_SPECIFIC_APPS React Server Components React2Shell Unsafe Flight Protocol Property Access (CVE-2025-55182)`
- **evidence summary**: 120 events directly referencing the CVE were observed. Analysis of attacker behavior revealed thousands of related events. Key artifacts include targeted requests to Next.js paths like `/_next/server` and `/api/route`.
- **affected service/port**: A wide range of non-standard TCP web ports, including 3004, 3010, 3333, 5001, 8081, 8088, 8888, 9000, and 9443.
- **confidence**: High
- **operational notes**: This is a critical, recently disclosed (Dec 2025) unauthenticated RCE being actively and widely exploited. All internet-facing assets using React Server Components (especially Next.js) must be patched immediately.

## 5) Novel or Zero-Day Exploit Candidates
No novel exploit candidates were validated during this investigation window. The most promising lead (ICS activity) could not be investigated.

## 6) Botnet/Campaign Infrastructure Mapping
### CVE-2025-55182 (React2Shell) Campaign
- **item_id**: CVE-2025-55182
- **campaign_shape**: Coordinated spray from multiple distinct actors with different behavioral profiles.
- **suspected_compromised_src_ips**:
    - **Specialist Scanner**: `193.32.162.28` (1701 events) - High-volume, focused exclusively on this CVE, uses rotating user agents.
    - **Generalist Scanner**: `79.124.40.174` (248 events) - Lower-volume, scanned for multiple vulnerabilities including this CVE.
- **ASNs / geo hints**: AS 47890 (Unmanaged Ltd, Romania), AS 50360 (Tamatiya EOOD, Bulgaria).
- **suspected_staging indicators**: None observed. Activity appears to be direct-to-target scanning.
- **suspected_c2 indicators**: None observed.
- **confidence**: High
- **operational notes**: Block source IPs. Monitor for inbound traffic on unusual web ports targeting Next.js application paths, as this is a strong indicator of this campaign.

### Commodity PHPUnit Scanning
- **related candidate_id(s)**: 1
- **campaign_shape**: spray
- **suspected_compromised_src_ips**: `94.103.169.88`, `147.45.60.22`.
- **ASNs / geo hints**: AS 215439 (Play2go International Limited, Germany), AS 215540 (Global Connectivity Solutions Llp, Russia).
- **confidence**: High
- **operational notes**: This is low-level opportunistic scanning for an old vulnerability (CVE-2017-9841). It serves as a good baseline for general internet noise.

## 7) Odd-Service / Minutia Attacks
### Industrial Control System (ICS) Probes (Provisional)
- **service_fingerprint**: `guardian_ast` and `kamstrup_protocol` (from initial honeypot report).
- **why it’s unusual/interesting**: Probing of specialized ICS protocols is operationally significant as it may indicate reconnaissance against Operational Technology (OT) environments, which is far less common than typical web or SSH scans.
- **evidence summary**: The HoneypotSpecific agent reported 24 `guardian_ast` and 16 `kamstrup_protocol` events. **However, all subsequent attempts to query, validate, or investigate this activity failed due to tool errors.** No source IPs, target ports, or event details could be retrieved.
- **confidence**: Low (unvalidated)
- **recommended monitoring pivots**: The immediate priority is to **resolve the backend tool/data pipeline issue** preventing queries against Conpot honeypot data. This is a critical visibility gap.

## 8) Known-Exploit / Commodity Exclusions
- **Credential Noise & Brute Force**: High volume of generic usernames (`root`, `admin`) and passwords. Notably, the use of `345gs5662d34` and `3245gs5662d34` was observed, which OSINT confirms is linked to established botnet activity (e.g., Mirai variants) for SSH/Telnet brute-forcing.
- **Commodity Web Scanning**: Opportunistic scanning for old vulnerabilities like PHPUnit RCE (CVE-2017-9841) and general PHP RFI attempts.
- **High-Volume Port Scanning**:
    - **VNC**: Over 13,000 alerts for `GPL INFO VNC server response`, indicating widespread scanning of VNC services.
    - **SMB**: Thousands of connections to port 445 from India and the UK.
    - **RDP**: Hundreds of alerts for `ET SCAN MS Terminal Server Traffic on Non-standard Port`.

## 9) Infrastructure & Behavioral Classification
- **CVE-2025-55182 Campaign**: Characterized as active **exploitation**. The campaign uses a **coordinated spray** shape, leveraging at least two distinct actor types: a high-volume, specialized scanner and a low-volume, generalist scanner.
- **CVE-2017-9841 Activity**: Characterized as opportunistic **scanning**. The campaign shape is a simple **spray**, with actors reusing infrastructure to scan for multiple common web vulnerabilities.
- **ICS Probing**: The behavior is unclassifiable due to blocked investigation. The service fingerprint of `guardian_ast` and `kamstrup_protocol` makes it highly anomalous.

## 10) Evidence Appendix
### Emerging n-day: CVE-2025-55182
- **source IPs**: `193.32.162.28` (1701 events), `79.124.40.174` (248 events)
- **ASNs**: 47890 (Romania), 50360 (Bulgaria)
- **target ports/services**: 3004/tcp, 3010/tcp, 3333/tcp, 5001/tcp, 8081/tcp, 8088/tcp, 9000/tcp, 9443/tcp
- **paths/endpoints**: `/_next/server`, `/api/route`, `/app`, `/`
- **payload/artifact excerpts**: Suricata Signature: `ET WEB_SPECIFIC_APPS React Server Components React2Shell Unsafe Flight Protocol Property Access (CVE-2025-55182)`
- **temporal checks**: Both source IPs were active for nearly the entire 4-hour investigation window.

## 11) Indicators of Interest
- **CVE**: `CVE-2025-55182`
- **Source IPs (React2Shell Campaign)**:
    - `193.32.162.28` (High-volume specialist)
    - `79.124.40.174` (Generalist scanner)
- **Source IPs (Commodity PHPUnit Scanning)**:
    - `94.103.169.88`
    - `147.45.60.22`
- **Paths (React2Shell Indicators)**:
    - `/_next/server`
    - `/api/route`
- **Credentials (Known Botnet)**:
    - `345gs5662d34`
    - `3245gs5662d34`

## 12) Backend Tool Issues
- **Tool Failures**: The `DeepInvestigationAgent` encountered critical failures when using the `two_level_terms_aggregated` and `kibanna_discover_query` tools to investigate Conpot honeypot data.
- **Affected Validations**: These failures completely **blocked the investigation into the unusual ICS activity**. The source, scale, and intent of the `guardian_ast` and `kamstrup_protocol` probes could not be determined.
- **Weakened Conclusions**: The "Odd-Service / Minutia Attacks" section is provisional and has Low confidence. The overall completeness of this report is degraded, as a potentially high-signal event could not be analyzed.

## 13) Agent Action Summary (Audit Trail)
- **ParallelInvestigationAgent**:
    - **purpose**: Gather broad, concurrent telemetry streams.
    - **inputs_used**: `investigation_start`, `investigation_end`.
    - **actions_taken**: Executed sub-agents for baseline, known signal, credential, and honeypot-specific data collection.
    - **key_results**: Successfully provided initial data identifying VNC/SMB scanning, the emerging CVE-2025-55182, and anomalous ICS protocol events.
    - **errors_or_gaps**: None.
- **CandidateDiscoveryAgent**:
    - **purpose**: Synthesize initial telemetry into actionable investigation leads.
    - **inputs_used**: All outputs from the ParallelInvestigationAgent.
    - **actions_taken**: Formulated a 6-point investigation plan.
    - **key_results**: Prioritized PHPUnit, emerging CVEs, ICS activity, and unusual credentials for investigation.
    - **errors_or_gaps**: None.
- **CandidateValidationLoopAgent**:
    - **purpose**: Perform initial validation of a lead.
    - **inputs_used**: Candidate queue.
    - **actions_taken**: Ran for 1 iteration, validating the PHPUnit exploit candidate using OSINT and telemetry queries.
    - **key_results**: Confirmed PHPUnit activity was related to known vulnerability CVE-2017-9841 and was commodity scanning.
    - **errors_or_gaps**: Loop did not continue to validate other candidates.
- **DeepInvestigationLoopController**:
    - **purpose**: Conduct in-depth, iterative investigation of leads.
    - **inputs_used**: Initial leads, validated candidates.
    - **actions_taken**: Ran for 5 iterations. Successfully investigated CVE-2025-55182 by pivoting through the CVE, source IPs, and related signatures. Attempted to investigate ICS activity.
    - **key_results**: Fully characterized the CVE-2025-55182 campaign and its actors.
    - **errors_or_gaps**: Stalled and exited after 2 consecutive query failures related to Conpot data, leaving the ICS investigation incomplete.
- **OSINTAgent**:
    - **purpose**: Enrich findings with public threat intelligence.
    - **inputs_used**: Validated findings from previous stages.
    - **actions_taken**: Used search tool to research CVE-2017-9841, CVE-2025-55182, and the `345gs5662d34` credentials.
    - **key_results**: Confirmed all investigated items were publicly known, reducing their novelty and mapping them to established threats.
    - **errors_or_gaps**: None.
- **ReportAgent**:
    - **purpose**: Compile the final report from all workflow state.
    - **inputs_used**: All available state outputs from the pipeline.
    - **actions_taken**: Assembled this markdown report.
    - **key_results**: The report you are reading.
    - **errors_or_gaps**: Report completeness is degraded due to the failed ICS investigation.
- **SaveReportAgent**:
    - **purpose**: Persist the final report.
    - **inputs_used**: Content from ReportAgent.
    - **actions_taken**: Will call `deep_agent_write_file`.
    - **key_results**: Pending.
    - **errors_or_gaps**: None.
