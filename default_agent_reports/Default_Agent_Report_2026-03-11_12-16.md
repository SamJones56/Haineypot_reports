# Honeypot Threat Hunting Report

## 1. Investigation Scope
- **investigation_start**: 2026-03-11T12:00:05Z
- **investigation_end**: 2026-03-11T16:00:05Z
- **completion_status**: Partial (degraded evidence)
- **degraded_mode**: true
  - **Reason**: The investigation was hampered by multiple query failures. Key source IP attribution failed during initial discovery, requiring manual validation. More critically, a data visibility gap prevented the validation of all Industrial Control System (ICS) related activity, making conclusions in that area provisional.

## 2. Executive Triage Summary
- **Top Services/Ports of Interest**:
    - **Web Services (HTTP)**: Heavily targeted by multiple campaigns, including exploitation of CVE-2025-55182 (React2Shell) and broad scanning for vulnerabilities like Apache Path Traversal (CVE-2021-41773) and PHPUnit RCE (CVE-2017-9841).
    - **Industrial Control Systems (ICS)**: Significant reconnaissance activity detected against sensitive, non-IT protocols such as IEC104 and Kamstrup. This is a high-priority area of concern despite data gaps.
    - **VNC (multiple ports)**: A high volume of scanning and exploit alerts were observed but were ultimately classified as commodity noise or internal network activity.
- **Top Confirmed Known Exploitation**:
    - **CVE-2025-55182 (React2Shell)**: 176 exploit attempts were observed from two external source IPs (`195.3.221.86`, `193.32.162.28`) against a likely React/Next.js application.
    - **Multi-Exploit Web Campaign**: A coordinated campaign from IPs `178.251.232.252` and `112.51.27.81` was identified, scanning for numerous common web application vulnerabilities.
- **Major Uncertainties**:
    - **ICS Reconnaissance Source**: The origin (source IPs) of the targeted probes against ICS protocols could not be determined due to a persistent data pipeline failure during the validation phase. The actors behind this activity remain unknown.

## 3. Candidate Discovery Summary
- The pipeline analyzed 18,826 total attacks, identifying four initial candidates for investigation.
- Key areas of interest flagged were high-volume VNC noise, evidence of a recent n-day web exploit (React2Shell), a coordinated multi-vulnerability web scanning campaign, and unusual probing against ICS protocols.
- The discovery phase was materially affected by failed queries to attribute source IPs to CVE-2025-55182 alerts and to correlate IPs with ICS protocol activity, marking those candidates as provisional from the start.

## 4. Emerging n-day Exploitation
### [NDE-01] Exploitation of CVE-2025-55182 (React2Shell)
- **cve/signature mapping**: CVE-2025-55182 / `ET WEB_SPECIFIC_APPS React Server Components React2Shell Unsafe Flight Protocol Property Access (CVE-2025-55182)`
- **evidence summary**: 176 total events observed from source IPs `195.3.221.86` and `193.32.162.28`. The activity involved systematic scanning of multiple common application ports.
- **affected service/port**: HTTP on ports 3200, 5055, 6004, 8180.
- **confidence**: High
- **operational notes**: This activity is part of a known, widespread campaign exploiting a recently disclosed critical RCE vulnerability. OSINT confirmed recent port scanning activity from `193.32.162.28`.

## 6. Botnet/Campaign Infrastructure Mapping
### [BOT-01] Multi-Vulnerability Web Scanning Campaign
- **item_id**: [BOT-01]
- **campaign_shape**: Fan-out & Spray
- **suspected_compromised_src_ips**: `178.251.232.252`, `112.51.27.81`
- **ASNs / geo hints**:
    - `178.251.232.252`: AS214673 (mijn.host B.V., The Netherlands)
    - `112.51.27.81`: AS9808 (China Mobile, China). OSINT confirms this IP has a public history of abuse.
- **suspected_staging indicators**: None identified.
- **suspected_c2 indicators**: None identified.
- **confidence**: High
- **operational notes**: This is a commodity scanning campaign targeting multiple well-known web RCE vulnerabilities, including Apache Path Traversal (CVE-2021-41773) and PHPUnit RCE (CVE-2017-9841). The use of multiple IPs and targeting of diverse, known vulnerabilities is characteristic of automated botnet activity.

## 7. Odd-Service / Minutia Attacks
### [ODD-01] Industrial Control System (ICS) Protocol Reconnaissance
- **service_fingerprint**: IEC104, kamstrup_protocol, guardian_ast
- **why it’s unusual/interesting**: Probing of specialized ICS/SCADA protocols is a strong indicator of reconnaissance for attacks against critical infrastructure. This activity is of high operational interest.
- **evidence summary**: Initial discovery agents reported 41 events, including 18 for IEC104 and 12 for Kamstrup. **However, all validation queries for this activity failed, returning zero results.** This indicates a critical data visibility gap. The source IPs and specific targets remain unknown.
- **confidence**: Low (Provisional, pending data pipeline fix)
- **recommended monitoring pivots**: A critical-priority investigation into the Conpot data pipeline is required. The IEC104 and Kamstrup protocols should be placed on a high-priority watch list for all future monitoring windows.

## 8. Known-Exploit / Commodity Exclusions
- **Commodity VNC Scanning**: A high volume of alerts (19,875 for `GPL INFO VNC server response`) and 517 specific exploit alerts for CVE-2006-2369 were observed. All 517 CVE-related alerts originated from the internal IP `10.17.0.5`, indicating this is internal scanning or sensor noise, not an external threat.
- **Credential Noise**: Standard brute-force attempts were seen across multiple services, using common usernames (`root`, `admin`, `ubuntu`) and passwords (`123456`, `password`, `admin`). This is considered background noise.
- **Generic Web Scanning**: Tanner honeypots recorded generic scanning for common sensitive files like `/` (40 hits) and `/.env` (4 hits) from a wide spray of IPs.

## 9. Infrastructure & Behavioral Classification
- **Exploitation vs Scanning**:
    - **[NDE-01]**: Targeted exploitation.
    - **[BOT-01]**: Automated scanning with intent to exploit.
    - **[ODD-01]**: Reconnaissance / Scanning.
- **Campaign Shape**:
    - **[NDE-01]**: Fan-in (two sources to one target).
    - **[BOT-01]**: Fan-out & Spray (one primary scanner, one coordinated participant).
    - **[ODD-01]**: Unknown (due to data gap).
- **Odd-Service Fingerprints**:
    - Probing of ICS protocols (IEC104, Kamstrup) on the Conpot honeypot is the primary unusual finding.

## 10. Evidence Appendix
### [NDE-01] Emerging n-day: CVE-2025-55182
- **source IPs**: `195.3.221.86`, `193.32.162.28`
- **ASNs**: AS47890 (Unmanaged Ltd) for 193.32.162.28.
- **target ports/services**: 3200, 5055, 6004, 8180 (HTTP)
- **paths/endpoints**: `/api/route`, `/app`, `/_next/server`, `/api`, `/_next`, `/`
- **payload/artifact excerpts**: N/A (Signature-based detection: `ET WEB_SPECIFIC_APPS React Server Components React2Shell Unsafe Flight Protocol Property Access (CVE-2025-55182)`)

### [BOT-01] Botnet/Campaign: Multi-Vulnerability Web Scanner
- **source IPs**: `178.251.232.252`, `112.51.27.81`
- **ASNs**: 214673 (Netherlands), 9808 (China)
- **target ports/services**: 80 (HTTP)
- **paths/endpoints**:
    - `/cgi-bin/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/bin/sh`
    - `/V2/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php`
    - `/?%ADd+allow_url_include%3d1+%ADd+auto_prepend_file%3dphp://input`
    - `/index.php?s=/index/\think\app/invokefunction...`

## 11. Indicators of Interest
- **IPs (Exploitation)**:
    - `195.3.221.86` (CVE-2025-55182)
    - `193.32.162.28` (CVE-2025-55182)
- **IPs (Scanning Campaign)**:
    - `178.251.232.252`
    - `112.51.27.81`
- **CVEs**:
    - `CVE-2025-55182`
- **Protocols (for monitoring)**:
    - `IEC104`
    - `kamstrup_protocol`
- **Paths / Payloads**:
    - `cgi-bin/.%2e/.%2e`
    - `vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php`

## 12. Backend Tool Issues
- **`top_src_ips_for_cve`**: This tool failed during the Candidate Discovery phase for `CVE-2025-55182`, preventing initial IP attribution for 176 alerts. This was manually resolved during validation.
- **`two_level_terms_aggregated`**: This tool failed to aggregate on the `alert.cve_id.keyword` field, weakening automated correlation checks for CVE-based candidates.
- **`two_level_terms_aggregated` & `kibanna_discover_query`**: Both tools failed to return *any* results for `Conpot` data during the Candidate Validation phase. This contradicted the 41 hits reported by the HoneypotSpecificAgent in the discovery phase, indicating a severe data pipeline or indexing issue.
- **Impact**: These failures significantly weakened the investigation. The ICS activity (`[ODD-01]`) could not be validated or attributed, and its conclusions are provisional and low-confidence.

## 13. Agent Action Summary (Audit Trail)
- **ParallelInvestigationAgent**:
    - **purpose**: Gather initial telemetry across baseline, known signals, credential noise, and honeypot sensors.
    - **inputs_used**: `investigation_start`, `investigation_end`.
    - **actions_taken**: Executed sub-agents to query for total attacks, top CVEs, common credentials, and honeypot-specific interactions (e.g., Conpot protocols, Tanner paths).
    - **key_results**: Identified 18,826 attacks; 176 alerts for CVE-2025-55182; 517 alerts for CVE-2006-2369; web exploit paths; 41 Conpot ICS events.
    - **errors_or_gaps**: None reported at this stage.
- **CandidateDiscoveryAgent**:
    - **purpose**: Synthesize parallel results into actionable investigation candidates.
    - **inputs_used**: `baseline_result`, `known_signals_result`, `credential_noise_result`, `honeypot_specific_result`.
    - **actions_taken**: Aggregated data, attempted IP-to-CVE and IP-to-Path correlation.
    - **key_results**: Produced four candidates: `[NDE-01]` (React2Shell), `[NDE-02]` (VNC), `[BOT-01]` (Web Campaign), `[ODD-01]` (ICS Probing).
    - **errors_or_gaps**: `top_src_ips_for_cve` query failed for CVE-2025-55182. IP correlation failed for Conpot data. The discovery output was marked as degraded.
- **CandidateValidationLoopAgent**:
    - **purpose**: Iterate through and deeply validate each candidate.
    - **inputs_used**: Candidate list from `CandidateDiscoveryAgent`.
    - **actions_taken**: Ran 4 iterations. Used tools like `suricata_cve_samples` and `web_path_samples` to find specific event samples. Attempted to retrieve raw Conpot events with `kibanna_discover_query`.
    - **key_results**: Confirmed `[NDE-01]` as emerging n-day; re-classified `[NDE-02]` to commodity noise (internal IP); confirmed `[BOT-01]` as a web scanning campaign; failed to validate `[ODD-01]`, re-classifying it for monitoring.
    - **errors_or_gaps**: Queries to retrieve any Conpot events for `[ODD-01]` failed completely, blocking all validation steps for that candidate.
- **DeepInvestigationLoopController**:
    - **purpose**: Not applicable.
    - **actions_taken**: This agent was not run in this workflow.
- **OSINTAgent**:
    - **purpose**: Enrich validated candidates with public threat intelligence.
    - **inputs_used**: `validated_candidates` from the validation loop.
    - **actions_taken**: Performed `search` queries on source IPs and protocols for candidates `[NDE-01]`, `[BOT-01]`, and `[ODD-01]`.
    - **key_results**: Found public abuse history for `112.51.27.81`, recent scanning reports for `193.32.162.28`, and documentation on tools used to scan for the IEC104 protocol. All findings reduced the novelty of the observed activities.
    - **errors_or_gaps**: None.
- **ReportAgent (self)**:
    - **purpose**: Compile the final report from all workflow state outputs.
    - **inputs_used**: All preceding agent outputs.
    - **actions_taken**: Assembled this markdown document.
    - **key_results**: The report you are reading.
    - **errors_or_gaps**: None.
- **SaveReportAgent**:
    - **purpose**: Save the final report content.
    - **inputs_used**: Final report markdown from ReportAgent.
    - **actions_taken**: Will call `default_write_file` tool.
    - **key_results**: Pending.
    - **errors_or_gaps**: None.
