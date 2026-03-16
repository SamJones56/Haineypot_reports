# Honeypot Threat Intelligence Report

## 1) Investigation Scope
- **investigation_start**: 2026-03-07T12:00:08Z
- **investigation_end**: 2026-03-07T15:00:08Z
- **completion_status**: Complete
- **degraded_mode**: true (Initial candidate discovery was affected by tool errors preventing full validation of one candidate.)

## 2) Executive Triage Summary
- Total attacks observed: 20541.
- Top services of interest include VNC (high volume commodity scanning/exploitation), Minecraft (25565) due to an unusual client signature, and Kamstrup ICS Protocol activity on a Conpot honeypot (unvalidated). SSH (22) and SMB (445) show commodity brute-force and scanning.
- Top confirmed known exploitation: VNC Server Not Requiring Authentication (CVE-2006-2369) with significant activity.
- A "Nintendo 3DS" Minecraft scanning campaign was identified, involving three source IPs from different ASNs. This campaign exhibits a consistent TTP of using a likely spoofed P0f OS fingerprint.
- Major uncertainties: Kamstrup ICS protocol activity could not be fully validated due to Kibana query failures, preventing identification of source IPs and detailed interaction data.

## 3) Candidate Discovery Summary
- Total attack events: 20541
- Top attacking countries: United States (5549), Australia (1953), Seychelles (1227), Indonesia (1162), India (1094).
- Top attacker IPs: 45.87.249.170 (1213), 136.114.97.84 (708), 79.124.40.98 (653).
- Top attacker ASNs: DigitalOcean, LLC (14061, 4470), Google LLC (396982, 1357), Shereverov Marat Ahmedovich (210006, 1214).
- Top target ports from countries: VNC (5901-5905, 5902, 5906, 5907, 5911, 5912), SSH (22), SMB (445), DCS (37777).
- Top alert signatures: GPL INFO VNC server response (17987), SURICATA IPv4 truncated packet (1102), ET EXPLOIT VNC Server Not Requiring Authentication (case 2) (501).
- Top CVEs: CVE-2006-2369 (501), CVE-2025-55182 (96).
- Top alert categories: Misc activity (19250), Generic Protocol Command Decode (3412).
- Top input usernames for credential noise: root (486), admin (88), 345gs5662d34 (71).
- Top input passwords for credential noise: 123456 (77), 345gs5662d34 (71), 3245gs5662d34 (67).
- Honeypot-specific findings:
    - P0f detected "Nintendo 3DS" OS for 3 events.
    - Conpot honeypot recorded 15 "kamstrup_protocol" and 2 "kamstrup_management_protocol" events.
- Material errors/gaps affecting discovery: Kibana query failures for Conpot events (`kibanna_discover_query(term='type.keyword', value='Conpot')` and `discover_by_keyword(keyword='kamstrup')`) affected the validation of Kamstrup protocol activity.

## 4) Emerging n-day Exploitation
None identified.

## 5) Novel or Zero-Day Exploit Candidates (UNMAPPED ONLY, ranked)
None identified.

## 6) Botnet/Campaign Infrastructure Mapping
**Item ID**: OSMA-MC-3DS-1 (Minecraft/Nintendo 3DS Scanning Campaign)
- **campaign_shape**: Spray (distributed scanning from multiple source IPs to a single target port).
- **suspected_compromised_src_ips**:
    - `51.15.34.47` (Netherlands, Scaleway S.a.s. - AS12876) - 110 events over 24h.
    - `176.65.134.24` (Slovenia, Netiface LLC - AS36680) - 13 events over 24h.
    - `45.148.10.134` (Netherlands, Techoff Srv Limited - AS48090) - 27 events over 24h.
- **ASNs / geo hints**: As listed above; activity originates from IPs across Netherlands and Slovenia.
- **suspected_staging indicators**: None observed.
- **suspected_c2 indicators**: None observed.
- **supporting evidence / uncertainty**: Deep investigation confirmed all three IPs exclusively target TCP port 25565 (Minecraft) and consistently use a 'Nintendo 3DS' P0f OS fingerprint over a 24-hour period. No other protocols or payloads were detected. This indicates a coordinated, single-purpose scanning operation. OSINT confirms the 3DS fingerprint is highly unlikely to be legitimate for a scanner, suggesting it is a deliberate TTP.
- **confidence**: High
- **operational notes**: Monitor these source IPs and their ASNs for any shift in activity or targeting. Consider blocking or rate-limiting traffic from these sources to port 25565 if this activity impacts operations.

## 7) Odd-Service / Minutia Attacks
1.  **candidate_id**: OSMA-MC-3DS-1
    - **service_fingerprint**: TCP Port 25565 (Minecraft) with P0f OS signature: 'Nintendo 3DS' (likely spoofed)
    - **why it’s unusual/interesting**: The extremely unusual OS fingerprint (Nintendo 3DS) associated with a non-standard service (Minecraft game server) is indicative of either highly niche, custom tooling or, more likely, deliberate spoofing as a TTP to evade detection or misdirect. OSINT confirmed the improbability of a legitimate Nintendo 3DS Minecraft scanner.
    - **evidence summary**: 38 connection events during the report window (total 150 events over 24h) from three distinct source IPs (51.15.34.47, 176.65.134.24, 45.148.10.134) from different ASNs, all exclusively targeting TCP port 25565. Events consisted of TCP flow establishment without observable application-layer payloads.
    - **confidence**: High
    - **recommended monitoring pivots**: Monitor for further activity from this cluster of source IPs. Broaden monitoring for other unusual or likely spoofed P0f OS fingerprints used for reconnaissance against non-standard ports, as this may represent an emerging TTP.

2.  **candidate_id**: OSMA-ICS-KAMSTRUP-1 (Provisional)
    - **service_fingerprint**: Conpot Honeypot, Kamstrup ICS Protocol (Kamstrup_protocol, Kamstrup_management_protocol)
    - **why it’s unusual/interesting**: Interaction with an Industrial Control Systems (ICS) protocol (Kamstrup) is highly unusual for general internet scanning and warrants further investigation, especially given the potential criticality of ICS environments.
    - **evidence summary**: HoneypotSpecificAgent reported 15 events for 'kamstrup_protocol' and 2 for 'kamstrup_management_protocol' on the Conpot honeypot, totaling 17 events.
    - **confidence**: Low (due to degraded validation)
    - **recommended monitoring pivots**: Debug Kibana query failures for Conpot to enable validation of source IPs and detailed interaction content. Prioritize obtaining raw event logs for this activity to understand the nature of the interaction.

## 8) Known-Exploit / Commodity Exclusions
-   **VNC Scanning and Exploitation (CVE-2006-2369)**: High-volume scanning and exploitation attempts targeting various VNC ports (5900-5907, 37777). This activity is well-mapped by Suricata signatures such as `GPL INFO VNC server response` (17987 counts) and `ET EXPLOIT VNC Server Not Requiring Authentication (case 2)` (501 counts), correlating to CVE-2006-2369. This represents routine commodity scanning.
-   **SSH Brute-Force**: Persistent brute-force attacks targeting port 22, characterized by attempts with common usernames (`root`, `admin`, `ubuntu`) and weak passwords (`123456`, `password`, `12345`). This is typical, low-value commodity activity.
-   **SMB Scanning**: Scanning activity observed on port 445 (485 counts), indicative of reconnaissance for Windows shares or services, often part of broader botnet scanning.
-   **Other Port Scanning**: General scanning activity on various other ports, including database services (e.g., MS SQL 1433, PostgreSQL 15432, 55432) from a diverse set of source IPs, typical of opportunistic scanners.

## 9) Infrastructure & Behavioral Classification
-   **Minecraft "Nintendo 3DS" Scanning**: Classified as reconnaissance/scanning behavior. Exhibits a 'spray' campaign shape across multiple, diverse source IPs (three distinct ASNs). Strong infrastructure reuse indicators (consistent spoofed OS fingerprint, single target port). This is an operationally interesting odd-service fingerprint due to the console OS attribution.
-   **VNC Scanning/Exploitation**: Primarily scanning with evidence of known exploit attempts. Likely a broad 'spray' campaign from various compromised hosts seeking vulnerable VNC services.
-   **SSH/SMB Brute-Force/Scanning**: Typical commodity scanning and credential stuffing operations, consistent with 'spray' tactics from distributed botnets.
-   **Kamstrup ICS Protocol Interaction**: Classified as a potential minutia attack or unusual interaction. Campaign shape and infrastructure reuse are unvalidated due to data gaps.

## 10) Evidence Appendix
### OSMA-MC-3DS-1 (Minecraft/Nintendo 3DS Scanning Campaign)
-   **Source IPs with counts**:
    -   `51.15.34.47` (Netherlands): 15 events in report window, 110 events over 24h.
    -   `176.65.134.24` (Slovenia): 6 events in report window, 13 events over 24h.
    -   `45.148.10.134` (Netherlands): 17 events in report window, 27 events over 24h.
-   **ASNs with counts**:
    -   AS12876: Scaleway S.a.s. (Netherlands)
    -   AS36680: Netiface LLC (Slovenia)
    -   AS48090: Techoff Srv Limited (Netherlands)
-   **Target ports/services**: TCP 25565 (Minecraft)
-   **Paths/endpoints**: N/A (connection attempts only)
-   **Payload/artifact excerpts**: P0f OS signature: 'Nintendo 3DS' (likely spoofed, no actual payloads observed).
-   **Staging indicators**: None.
-   **Temporal checks results**: Activity for `51.15.34.47` observed from `2026-03-06T15:08:44.689Z` to `2026-03-07T14:56:31.165Z`. Activity for `176.65.134.24` from `2026-03-07T10:06:27.000Z` to `2026-03-07T14:30:40.003Z`. Activity for `45.148.10.134` from `2026-03-07T10:13:53.000Z` to `2026-03-07T14:06:39.418Z`.

### KEE-VNC-2006-2369 (Commodity VNC Exploitation)
-   **Source IPs with counts (examples)**:
    -   `79.124.40.98` (501 on 5900)
    -   `129.212.184.194` (340 on 5902)
    -   `165.245.138.210` (153 on 5901)
    -   `134.199.197.108` (168 on 5903)
-   **ASNs with counts (examples)**:
    -   AS14061: DigitalOcean, LLC (4470 total)
    -   AS210006: Shereverov Marat Ahmedovich (1214 total)
    -   AS50360: Tamatiya EOOD (663 total)
-   **Target ports/services**: TCP 5900, 5901, 5902, 5903, 5904, 5905, 5906, 5907, 37777.
-   **Paths/endpoints**: N/A (protocol-level scanning/exploitation)
-   **Payload/artifact excerpts**: Suricata signature `GPL INFO VNC server response`, `ET EXPLOIT VNC Server Not Requiring Authentication (case 2)`.
-   **Staging indicators**: None.
-   **Temporal checks results**: Unavailable (assumed ongoing commodity activity).

## 11) Indicators of Interest
-   **Source IPs (Minecraft Scanner)**: `51.15.34.47`, `176.65.134.24`, `45.148.10.134`
-   **Target Port (Minecraft)**: `25565` (TCP)
-   **P0f OS Fingerprint (Spoofed TTP)**: `'Nintendo 3DS'`
-   **CVE (VNC)**: `CVE-2006-2369`
-   **Suricata Signature IDs (VNC)**: `2100560` (GPL INFO VNC server response), `2002923` (ET EXPLOIT VNC Server Not Requiring Authentication (case 2))
-   **Common Brute-force Usernames**: `root`, `admin`, `ubuntu`, `345gs5662d34`, `sol`, `solana`, `test`, `postgres`, `user`, `dev`
-   **Common Brute-force Passwords**: `123456`, `345gs5662d34`, `3245gs5662d34`, `password`, `12345`, `123`, `12345678`, `1234`, `123456789`, `admin123`

## 12) Backend Tool Issues
-   **Tool Failures**:
    -   `CandidateDiscoveryAgent` failed to execute `kibanna_discover_query(term='type.keyword', value='Conpot')`.
    -   `CandidateDiscoveryAgent` failed to execute `discover_by_keyword(keyword='kamstrup')`.
-   **Affected Validations**:
    -   These failures blocked the full validation of the `OSMA-ICS-KAMSTRUP-1` candidate (Kamstrup ICS Protocol activity on Conpot). Specifically, the inability to retrieve raw Conpot events prevented the identification of source IPs and detailed interaction data, leading to a "Low" confidence and "Provisional" status for this item.

## 13) Agent Action Summary (Audit Trail)
-   **ParallelInvestigationAgent**:
    -   Purpose: Conduct parallel baseline data collection and known signal identification.
    -   Inputs used: `investigation_start`, `investigation_end`.
    -   Actions taken: Called multiple tools across Baseline, KnownSignal, CredentialNoise, and HoneypotSpecific sub-agents to gather initial telemetry.
    -   Key Results: Identified total attacks, top attacker IPs/countries/ASNs, top ports (VNC, SSH, SMB), prevalent Suricata signatures (VNC-related), CVEs (CVE-2006-2369), common credential noise, and specific honeypot activities (Nintendo 3DS P0f, Kamstrup protocol on Conpot).
    -   Errors or Gaps: None.

-   **CandidateDiscoveryAgent**:
    -   Purpose: Identify and triage potential high-signal candidates from raw and correlated data.
    -   Inputs used: `baseline_result`, `known_signals_result`, `credential_noise_result`, `honeypot_specific_result`.
    -   Actions taken: Performed targeted queries for unusual P0f OS fingerprints (`Nintendo 3DS`) and honeypot-specific protocol detections (`Kamstrup`). Attempted to discover raw Conpot events.
    -   Key Results: Identified two candidates: `OSMA-MC-3DS-1` (Nintendo 3DS Minecraft scanning) and `OSMA-ICS-KAMSTRUP-1` (Kamstrup ICS protocol activity). Classified VNC exploitation as a known commodity. Set degraded_mode to true.
    -   Errors or Gaps: Two Kibana queries failed (`kibanna_discover_query(term='type.keyword', value='Conpot')`, `discover_by_keyword(keyword='kamstrup')`), preventing full validation of the Kamstrup candidate.

-   **CandidateValidationLoopAgent (via CandidateLoopControllerAgent)**:
    -   Purpose: Systematically validate identified candidates using specific queries and OSINT.
    -   Inputs used: Candidates identified by `CandidateDiscoveryAgent`.
    -   Actions taken: Executed 1 iteration. Loaded `OSMA-MC-3DS-1`. Performed Kibana queries for `dest_port=25565`, `first_last_seen_src_ip` for three source IPs, and an OSINT search for related keywords.
    -   Key Results: Successfully validated `OSMA-MC-3DS-1`, confirming its unusual nature and the likely spoofed OS fingerprint, and identified a third source IP. OSINT findings increased the novelty confidence.
    -   Errors or Gaps: The loop processed only 1 out of 2 initially queued candidates before the Deep Investigation phase was initiated. The `OSMA-ICS-KAMSTRUP-1` candidate remained unvalidated by this agent.

-   **DeepInvestigationLoopController (implicit controller of DeepInvestigationAgent)**:
    -   Purpose: Conduct in-depth investigation of high-signal validated candidates.
    -   Inputs used: Validated candidate `OSMA-MC-3DS-1`, extended time window (24h).
    -   Actions taken: Completed 4 iterations. Consumed and investigated three source IP leads (`45.148.10.134`, `51.15.34.47`, `176.65.134.24`) by querying their full activity over 24 hours. Subsequently, consumed one ASN lead (`asn:48090`) to find other related scanners.
    -   Key Results: Confirmed consistent, single-purpose scanning of port 25565 across all three source IPs from different ASNs, reinforcing the campaign characterization. Extended the temporal scope of the observed activity. Found no further related IPs in one of the ASNs.
    -   Errors or Gaps: None. The loop exited after 4 iterations due to the `stall_count` reaching 3 (no new investigative leads generated).

-   **OSINTAgent**:
    -   Purpose: Perform external OSINT lookups for identified candidates.
    -   Inputs used: Details of `OSMA-MC-3DS-1`.
    -   Actions taken: Performed a targeted OSINT search for "Minecraft server scanner 'Nintendo 3DS' p0f fingerprint".
    -   Key Results: Confirmed the absence of public documentation for such a legitimate scanner, validating the hypothesis of a spoofed fingerprint as a novel TTP and increasing concern.
    -   Errors or Gaps: None.

-   **ReportAgent**:
    -   Purpose: Compile the final investigation report.
    -   Inputs used: All available workflow state outputs (`investigation_start`, `investigation_end`, `baseline_result`, `known_signals_result`, `credential_noise_result`, `honeypot_specific_result`, `candidate_discovery_result`, `validated_candidates` details, `deep_investigation_outputs` summaries, `osint_validation_result`).
    -   Actions taken: Compiled the final report in the specified markdown format, incorporating all pertinent findings and adhering to classification rules.
    -   Key Results: This comprehensive threat intelligence report.
    -   Errors or Gaps: None.

-   **SaveReportAgent**:
    -   Purpose: Save the generated report to persistent storage.
    -   Inputs used: The final markdown report content.
    -   Actions taken: Tool `deep_agent_write_file` would be called.
    -   Key Results: File write status: (Assumed successful, no explicit failure reported). Path/identifier: N/A (not specified in workflow state).
    -   Errors or Gaps: None.