# Threat Hunting Investigation Report

## 1) Investigation Scope
- **investigation_start**: 2026-03-10T20:00:12Z
- **investigation_end**: 2026-03-11T00:00:12Z
- **completion_status**: Partial (degraded evidence)
- **degraded_mode**: true - Key validation queries failed for one candidate (ODD-01), preventing full analysis of ICS protocol activity.

## 2) Executive Triage Summary
- **Top Services/Ports of Interest**: VNC (5900), SMB (445), and simulated ICS protocols (guardian_ast, kamstrup_protocol) on Conpot honeypots.
- **Top Confirmed Known Exploitation**: High-volume scanning for VNC servers vulnerable to CVE-2006-2369 ("VNC Server Not Requiring Authentication").
- **Top Unmapped Exploit-like Items**: No novel exploit candidates were validated. Initial candidates were reclassified as known scanning or benign honeypot interactions.
- **Botnet/Campaign Mapping Highlights**: A large-scale VNC scanning campaign was identified, originating from a single source IP (`185.231.33.22`). A separate, smaller SMB scanning campaign was also observed.
- **Major Uncertainties**: The specific nature of interactions with simulated ICS protocols on the Conpot honeypot could not be fully validated due to backend tool failures. Source IPs and payloads for this activity remain unknown.

## 3) Candidate Discovery Summary
- The discovery phase identified two main areas of interest for validation:
  - **ODD-01**: Low-volume interactions with specialized Industrial Control System (ICS) protocols (`guardian_ast`, `kamstrup_protocol`) simulated by the Conpot honeypot.
  - **MIN-01**: Common web enumeration scanning for sensitive configuration files (`/.git/config`, `/.env`).
- Additionally, two distinct botnet-like campaigns were flagged based on their shape and known signatures:
  - **BOT-01**: A high-volume, fan-in VNC scanning campaign.
  - **BOT-02**: A smaller, spray-and-pray SMB scanning campaign.

## 4) Emerging n-day Exploitation
- No activity matching signatures of emerging n-day exploits was identified during this investigation window.

## 5) Novel or Zero-Day Exploit Candidates
- No candidates were validated as novel or potential zero-day exploits. All initial candidates were either reclassified as known commodity activity or could not be sufficiently validated due to evidence gaps.

## 6) Botnet/Campaign Infrastructure Mapping

- **item_id**: BOT-01
  - **related_candidate_id(s)**: VNC-CVE-2006-2369
  - **campaign_shape**: fan-in
  - **suspected_compromised_src_ips**: `185.231.33.22` (9,027 events)
  - **ASNs / geo hints**: ASN 211720 (Datashield, Inc.), Seychelles
  - **suspected_staging indicators**: None identified.
  - **suspected_c2 indicators**: None identified.
  - **confidence**: high
  - **operational_notes**: This is a high-volume, single-source campaign exploiting a very old VNC vulnerability. It represents opportunistic, automated scanning rather than a targeted attack.

- **item_id**: BOT-02
  - **related_candidate_id(s)**: N/A
  - **campaign_shape**: spray
  - **suspected_compromised_src_ips**: `178.153.127.226`, `31.30.172.40`
  - **ASNs / geo hints**: ASN 8781 (Ooredoo Q.S.C.), ASN 16019 (Vodafone Czech Republic a.s.)
  - **suspected_staging indicators**: None identified.
  - **suspected_c2 indicators**: None identified.
  - **confidence**: medium
  - **operational_notes**: Standard, low-volume SMB probing from disparate sources. Likely background noise from previously compromised hosts.

## 7) Odd-Service / Minutia Attacks

- **service_fingerprint**: Conpot ICS Honeypot (Ports 1025, 50100) / `guardian_ast`, `kamstrup_protocol`
  - **why it’s unusual/interesting**: This activity targets emulated ICS protocols, which is less common than standard web or SSH attacks. While confirmed by OSINT to be a feature of the honeypot, any interaction with these services is notable.
  - **evidence_summary**: 6 events were recorded, including one with the input string `b'\x01I20100'`. However, source IPs and full payloads could not be retrieved.
  - **confidence**: low (Provisional)
  - **recommended_monitoring_pivots**: The primary recommendation is to fix the backend query failures to enable proper analysis of Conpot events in future windows.

## 8) Known-Exploit / Commodity Exclusions
- **VNC Exploitation (CVE-2006-2369)**: Over 9,000 events from a single IP (`185.231.33.22`) targeting port 5900, matching signatures for "VNC Server Not Requiring Authentication". This is classified as a known, high-volume scanning campaign.
- **Web Configuration File Scanning**: A few dozen events from multiple IPs scanning for common sensitive files like `/.git/config` and `/.env`. OSINT confirms the source IPs are known scanners. This is commodity background noise.
- **SMB Scanning**: Over 2,500 events targeting port 445 from multiple sources, consistent with widespread, opportunistic SMB probing.
- **Credential Noise**: Standard brute-force attempts observed against SSH and other services using common default usernames like `root`, `admin`, and `user`.

## 9) Infrastructure & Behavioral Classification
- **VNC Campaign (BOT-01)**: Classified as **Exploitation** (known vulnerability) with a **fan-in** campaign shape. No infrastructure reuse was identified.
- **SMB Campaign (BOT-02)**: Classified as **Scanning** with a **spray** campaign shape.
- **Web Enumeration (MIN-01)**: Classified as **Scanning** with a **spray** campaign shape. OSINT confirmed infrastructure reuse for malicious activities.
- **ICS Interaction (ODD-01)**: Classified as **Monitor-only** (benign honeypot interaction). Campaign shape is **unknown** due to evidence gaps.

## 10) Evidence Appendix

**Item**: BOT-01 (VNC Campaign)
- **source IPs**: `185.231.33.22` (9027)
- **ASNs**: 211720 (9028)
- **target ports/services**: 5900 (VNC)
- **paths/endpoints**: N/A
- **payload/artifact excerpts**: Signature: `ET EXPLOIT VNC Server Not Requiring Authentication (case 2)`, CVE: `CVE-2006-2369`
- **staging indicators**: None
- **temporal checks results**: Activity concentrated in this window.

**Item**: MIN-01 (Web Enumeration)
- **source IPs**: `209.141.37.52` (2), `172.94.9.253` (1), `34.55.80.185` (1), `78.153.140.147` (1)
- **ASNs**: 53667, 213790, 396982, 202306
- **target ports/services**: 80 (HTTP)
- **paths/endpoints**: `/.git/config`, `/.env`
- **payload/artifact excerpts**: HTTP GET requests for the specified paths.
- **staging indicators**: None
- **temporal checks results**: Sporadic activity observed.

**Item**: ODD-01 (ICS Interaction)
- **source IPs**: unavailable
- **ASNs**: unavailable
- **target ports/services**: 1025, 50100 (Kamstrup, Guardian AST)
- **paths/endpoints**: N/A
- **payload/artifact excerpts**: `protocol: guardian_ast`, `protocol: kamstrup_protocol`, `input: b'\x01I20100'`
- **staging indicators**: None
- **temporal checks results**: unavailable

## 11) Indicators of Interest
- **IPs**: 
  - `185.231.33.22` (High-volume VNC scanning)
  - `209.141.37.52` (Web scanning, confirmed malicious by OSINT)
  - `172.94.9.253` (Web scanning, confirmed malicious by OSINT)
  - `78.153.140.147` (Web scanning, confirmed malicious by OSINT)
- **Paths**: `/.git/config`, `/.env` (Common web enumeration targets)
- **CVEs**: `CVE-2006-2369` (Commodity VNC exploit)

## 12) Backend Tool Issues
- **two_level_terms_aggregated**: This tool failed to return any results for Conpot-related aggregations when validating candidate ODD-01. This prevented the identification of source IPs and other pivot points.
- **kibanna_discover_query**: This tool failed to retrieve raw event logs for Conpot, even when using a known input string from the initial triage. This blocked direct payload inspection.
- **Impact**: These failures significantly weakened the conclusions for candidate ODD-01, forcing it to be marked as `Provisional` and preventing a full understanding of the ICS-related activity.

## 13) Agent Action Summary (Audit Trail)

- **agent_name**: ParallelInvestigationAgent
  - **purpose**: Gathers broad initial telemetry across different categories.
  - **inputs_used**: `investigation_start`, `investigation_end`.
  - **actions_taken**: Executed parallel queries for baseline stats, known signals, credential noise, and honeypot-specific data.
  - **key_results**: Provided the foundational data for the entire investigation, highlighting VNC, SMB, and ICS activity.
  - **errors_or_gaps**: None.

- **agent_name**: CandidateDiscoveryAgent
  - **purpose**: Synthesizes initial telemetry to identify and rank potential threats.
  - **inputs_used**: All outputs from ParallelInvestigationAgent.
  - **actions_taken**: Merged telemetry. Used `search` to enrich context on ICS protocols. Identified and structured 2 candidates (`ODD-01`, `MIN-01`) and 2 botnet campaigns.
  - **key_results**: Successfully triaged 37k events into a small set of actionable leads and known-commodity buckets.
  - **errors_or_gaps**: None.

- **agent_name**: CandidateValidationLoopAgent
  - **purpose**: Iteratively validates or dismisses candidates identified by the discovery agent.
  - **inputs_used**: Candidate queue from CandidateDiscoveryAgent.
  - **actions_taken**: Ran 2 validation iterations. Used `two_level_terms_aggregated` and `kibanna_discover_query` to investigate candidates.
  - **key_results**: Re-classified `MIN-01` as commodity scanning. Confirmed evidence gaps for `ODD-01`.
  - **errors_or_gaps**: Tool failures (`two_level_terms_aggregated`, `kibanna_discover_query`) for candidate `ODD-01` blocked validation.

- **agent_name**: DeepInvestigationLoopController
  - **purpose**: Manages the validation and deep investigation loops.
  - **inputs_used**: Candidate queue.
  - **actions_taken**: Initialized the queue with 2 candidates. Executed 2 iterations of the validation loop. Called `exit_loop` after the queue was empty.
  - **key_results**: Loop completed, but no deep investigation was triggered as no novel candidates were confirmed.
  - **errors_or_gaps**: None.

- **agent_name**: OSINTAgent
  - **purpose**: Enriches validated candidates and infrastructure with public threat intelligence.
  - **inputs_used**: Outputs from CandidateDiscoveryAgent and CandidateValidationLoopAgent.
  - **actions_taken**: Used `search` to investigate ICS protocols and source IPs from web scanning activity.
  - **key_results**: Confirmed that the ICS protocol activity was related to benign honeypot emulation. Verified that IPs scanning for web configuration files are known malicious actors.
  - **errors_or_gaps**: No public vulnerabilities were found for the specific ICS interactions, which aligns with the benign classification.

- **agent_name**: ReportAgent
  - **purpose**: Compiles the final report from all available workflow state outputs.
  - **inputs_used**: All preceding agent outputs.
  - **actions_taken**: Assembled this markdown report.
  - **key_results**: Generated final report.
  - **errors_or_gaps**: Noted `degraded_mode` due to upstream validation failures.

- **agent_name**: SaveReportAgent
  - **purpose**: Saves the final report artifact.
  - **inputs_used**: Report content from ReportAgent.
  - **actions_taken**: Awaits tool call with final content.
  - **key_results**: Pending.
  - **errors_or_gaps**: None.
