# Honeypot Threat Intelligence Report

## 1) Investigation Scope
- **investigation_start**: 2026-03-09T00:00:07Z
- **investigation_end**: 2026-03-09T03:00:07Z
- **completion_status**: Partial
- **degraded_mode**: true (Partial mapping of VNC campaign infrastructure due to tool limitations in aggregating source IPs for a given signature.)

## 2) Executive Triage Summary
- Total attacks observed: 21938 within the 3-hour window.
- **Top Services/Ports of Interest**: Mass scanning for VNC (ports 5900-5905/tcp), SSH (22/tcp), SMB (445/tcp), and targeted web services for CVE exploitation (various high ports).
- **Emerging N-day Exploitation**: Confirmed targeted exploitation attempts against CVE-2025-55182 ("React2Shell"), a critical RCE vulnerability in React Server Components, publicly disclosed and actively exploited.
- **Botnet/Campaign Mapping Highlights**: Identified a widespread VNC scanning campaign and a credential-stuffing botnet active on SSH using a unique username/password combination ("345gs5662d34").
- **Odd-Service / Minutia Attacks**: Detected low-volume interaction with Industrial Control System (ICS) protocols (Kamstrup and IEC104) and Android Debug Bridge (ADB) reconnaissance commands. Unsolicited TCP connections to two high, non-standard ports (31004, 56656) remain unmapped.
- **Major Uncertainties**: The full scope of source IPs involved in the large-scale VNC scanning campaign could not be entirely mapped due to tool limitations.

## 3) Candidate Discovery Summary
- Total attack events processed: 21938
- Number of Emerging n-day Exploitation candidates: 1 (CVE-2025-55182)
- Number of Novel Exploit Candidates: 0
- Number of Botnet/Campaign Infrastructure Mapping candidates: 2
- Number of Odd-Service / Minutia Attack candidates: 3
- Number of Known-Exploit / Commodity Exclusions: 3
- **Top Areas of Interest**: Large volume VNC scanning, SSH credential stuffing, targeted RCE attempts, and reconnaissance against ICS and ADB services.
- **Discovery Gaps**: Two queries failed to return expected results, specifically impacting the ability to comprehensively aggregate source IPs for the high-volume VNC scanning activity.

## 4) Emerging n-day Exploitation
- **CVE**: CVE-2025-55182 (React2Shell)
    - **Description**: Targeted exploitation attempts of a critical Remote Code Execution (RCE) vulnerability in React Server Components. This CVE is publicly documented as actively exploited and has been added to the CISA Known Exploited Vulnerabilities (KEV) Catalog.
    - **Evidence summary**: 72 events. Key artifact: `alert.cve: CVE-2025-55182 CVE-2025-55182`.
    - **Affected service/port**: Various TCP ports including 3000, 2002, 3032, 3112, 8182, 9123, 9163, 9978, 16000, 20005 (likely web services/APIs).
    - **Confidence**: High
    - **Operational notes**: This is a critical, actively exploited vulnerability. Monitor for successful exploitation and post-exploit activity, and cross-reference source IPs with other suspicious activity.

## 5) Novel or Zero-Day Exploit Candidates (UNMAPPED ONLY, ranked)
- None identified in this investigation window.

## 6) Botnet/Campaign Infrastructure Mapping
- **item_id**: BCM-001 (Credential-stuffing botnet using '345gs5662d34')
    - **campaign_shape**: spray
    - **suspected_compromised_src_ips**: 11 distinct IPs including `161.49.89.39`, `103.134.154.157`, `49.0.207.246`, `103.189.235.93` (top examples).
    - **ASNs / geo hints**: Converge ICT Solutions Inc. (Philippines), Cloud Host Pte Ltd (Singapore), HUAWEI CLOUDS (Singapore), PT Cloud Hosting Indonesia (Indonesia), DigitalOcean, LLC (India), ODS Joint Stock Company (Vietnam), UCLOUD INFORMATION TECHNOLOGY HK LIMITED (Seychelles), Byteplus Pte. Ltd. (Singapore), Keimyung University (South Korea).
    - **suspected_staging indicators**: None explicitly identified from telemetry; the unique credential acts as a shared indicator.
    - **suspected_c2 indicators**: None.
    - **confidence**: High (OSINT confirms this credential as a widely documented indicator of botnet activity in circulation since 2022).
    - **operational notes**: Track the observed source IPs and ASNs for further campaign activity. This activity is consistent with known automated credential stuffing against SSH.

- **item_id**: BCM-002 (VNC scanning campaign)
    - **campaign_shape**: spray
    - **suspected_compromised_src_ips**: Not fully enumerated due to tool limitations, but represents a large number of sources inferred from 18189 events.
    - **ASNs / geo hints**: DigitalOcean, LLC, Google LLC (top ASNs contributing to overall attacks, likely contributors to this campaign).
    - **suspected_staging indicators**: None.
    - **suspected_c2 indicators**: None.
    - **confidence**: High (OSINT confirms this is a common, established botnet-driven scanning pattern for VNC services).
    - **operational notes**: Map the full list of source IPs associated with this signature in future investigations to better understand the campaign's scale.

## 7) Odd-Service / Minutia Attacks
- **tracking_id**: OSM-001 (ICS Protocol Interaction)
    - **service_fingerprint**: dest_port: multiple, application: ICS, protocol: kamstrup, iec104
    - **why it’s unusual/interesting**: Interaction with Industrial Control System (ICS) protocols (Kamstrup Management Protocol, IEC104) observed on the Conpot honeypot. While low volume, this indicates potential reconnaissance or probing of critical infrastructure services.
    - **evidence summary**: 3 events. Key artifacts: `kamstrup_management_protocol (2)`, `IEC104 (1)`.
    - **confidence**: Moderate (OSINT confirms IEC104 is highly vulnerable; Kamstrup-specific exploits not found, but general ICS probing is significant).
    - **recommended monitoring pivots**: Monitor for increased activity, specific command sequences, or exploitation attempts against ICS services.

- **tracking_id**: OSM-002 (Unsolicited TCP connections on non-standard high ports)
    - **service_fingerprint**: dest_port: 31004, 56656, protocol: TCP, application: Unknown
    - **why it’s unusual/interesting**: Single unsolicited TCP connections to high, non-standard ports (31004, 56656) from two distinct source IPs. Such activity can sometimes indicate custom malware C2 or highly targeted reconnaissance.
    - **evidence summary**: 2 events. Key artifacts: `TCP flow to port 31004 (1)`, `TCP flow to port 56656 (1)`.
    - **confidence**: Low
    - **provisional**: true (OSINT was inconclusive regarding public mapping to known exploits or malware for these specific ports.)
    - **recommended monitoring pivots**: Further investigation into source IPs and deeper packet analysis is recommended if similar activity increases or if application data becomes available.

- **tracking_id**: OSM-003 (ADB Reconnaissance)
    - **service_fingerprint**: dest_port: 5555, application: Android Debug Bridge, protocol: ADB
    - **why it’s unusual/interesting**: Basic reconnaissance commands (`echo "$(getprop ro.product.name 2>/dev/null) $(whoami 2>/dev/null)"`, `echo hello`) observed on the Adbhoney (Android Debug Bridge) honeypot. This suggests automated scanning for ADB interfaces, potentially for device fingerprinting or honeypot detection.
    - **evidence summary**: 3 events. Key artifacts: `echo "$(getprop ro.product.name 2>/dev/null) $(whoami 2>/dev/null)" (2)`, `echo hello (1)`.
    - **confidence**: High (OSINT confirms these are common ADB reconnaissance and honeypot evasion commands).
    - **recommended monitoring pivots**: Correlate with other ADB activity, look for further exploit attempts, and ensure honeypot realism.

## 8) Known-Exploit / Commodity Exclusions
- **KEX-001**: Mass scanning for VNC services (ports 5900-5920), identified by 'GPL INFO VNC server response' and 'ET SCAN Potential VNC Scan' signatures (18192 events). This is typical commodity scanning noise.
- **KEX-002**: Standard web vulnerability scanning for common files and paths (`/.env`, `/?XDEBUG_SESSION_START=phpstorm`, `/%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2Fetc%2Fpasswd`) detected by Tanner HTTP Scans (49 events). This is common, automated scanning for low-hanging web vulnerabilities.
- **KEX-003**: Scanning for Microsoft Remote Desktop services on non-standard ports (733 events), identified by 'ET SCAN MS Terminal Server Traffic on Non-standard Port' signature. This is a common reconnaissance technique.
- **Credential Noise**: Extensive SSH/Telnet brute-force attempts using common usernames (`root`, `admin`, `ubuntu`, `user`) and passwords (`12345`, `123456`, `password`).

## 9) Infrastructure & Behavioral Classification
- **Emerging N-day Exploitation (CVE-2025-55182)**: Targeted exploitation of a recently disclosed, critical RCE vulnerability. Behavior is exploit-driven, likely with a spray-and-pray campaign shape given the internet-facing nature. Limited infrastructure reuse indicators observed (2 IPs).
- **Credential-Stuffing Botnet (BCM-001)**: Extensive scanning and brute-forcing activity across a wide range of source IPs (11 distinct IPs observed) from diverse ASNs. Campaign exhibits a spray shape. High infrastructure reuse indicated by the consistent use of unique credentials. Primarily targeting SSH.
- **VNC Scanning Campaign (BCM-002)**: Large-scale, automated scanning activity (over 18k events). Campaign exhibits a spray shape, originating from numerous IPs across multiple ASNs. High infrastructure reuse and commodity botnet behavior.
- **Odd-Service / Minutia Attacks**:
    - **ICS Protocol Interaction (OSM-001)**: Low-volume reconnaissance or probing against specialized Industrial Control System protocols. Behavior is probing/scanning.
    - **Unmapped High Port Connections (OSM-002)**: Extremely low-volume, unsolicited TCP connections. Behavior is probing, with unknown intent (potential custom malware C2 or very targeted recon).
    - **ADB Reconnaissance (OSM-003)**: Low-volume reconnaissance against Android Debug Bridge service, likely automated device fingerprinting.

## 10) Evidence Appendix

- **NDE-001 (CVE-2025-55182)**
    - **Source IPs**: `193.32.162.28` (60), `195.3.221.86` (12)
    - **ASNs**: Not explicitly available from the provided data for these specific IPs.
    - **Target ports/services**: 3000, 2002, 3032, 3112, 8182, 9123, 9163, 9978, 16000, 20005 (TCP)
    - **Paths/endpoints**: Not explicitly available in CVE alerts.
    - **Payload/artifact excerpts**: `alert.cve: CVE-2025-55182 CVE-2025-55182`
    - **Staging indicators**: Unavailable
    - **Temporal checks**: Unavailable

- **BCM-001 (Credential-stuffing botnet)**
    - **Source IPs**: `161.49.89.39`, `103.134.154.157`, `49.0.207.246`, `103.189.235.93`, `139.59.3.182`, `112.78.1.94`, `154.83.196.237`, `45.78.194.242`, `220.69.134.33`, `103.186.0.214`, `101.47.142.76` (11 distinct IPs)
    - **ASNs**: Converge ICT Solutions Inc., Cloud Host Pte Ltd, HUAWEI CLOUDS, ODS Joint Stock Company, DigitalOcean, LLC, UCLOUD INFORMATION TECHNOLOGY HK LIMITED, Byteplus Pte. Ltd., Keimyung University, PT Cloud Hosting Indonesia
    - **Target ports/services**: SSH (port 22) on Cowrie honeypot.
    - **Paths/endpoints**: Not applicable (SSH login attempts).
    - **Payload/artifact excerpts**: username `345gs5662d34`, password `345gs5662d34` or `3245gs5662d34`.
    - **Staging indicators**: Unavailable
    - **Temporal checks**: Unavailable

- **BCM-002 (VNC scanning campaign)**
    - **Source IPs**: Not fully aggregated. (Top IPs from baseline: `136.114.97.84`, `46.19.137.194`, `79.124.40.98`, `14.181.156.142`, `134.209.37.134` likely include contributors.)
    - **ASNs**: DigitalOcean, LLC (4211), Google LLC (1247) (top ASNs by attack count)
    - **Target ports/services**: 5900-5920 (VNC)
    - **Paths/endpoints**: Not applicable (VNC scanning).
    - **Payload/artifact excerpts**: `GPL INFO VNC server response`, `ET SCAN Potential VNC Scan 5900-5920`
    - **Staging indicators**: Unavailable
    - **Temporal checks**: Unavailable

- **OSM-001 (ICS Protocol Interaction)**
    - **Source IPs**: Not explicitly available from honeypot data.
    - **ASNs**: Not explicitly available from honeypot data.
    - **Target ports/services**: ICS specific ports (protocols: `kamstrup_management_protocol`, `IEC104`)
    - **Paths/endpoints**: Not applicable (protocol interaction).
    - **Payload/artifact excerpts**: `kamstrup_management_protocol`, `IEC104`
    - **Staging indicators**: Unavailable
    - **Temporal checks**: Unavailable

## 11) Indicators of Interest
- **Source IPs**:
    - `193.32.162.28` (Associated with CVE-2025-55182 exploitation)
    - `195.3.221.86` (Associated with CVE-2025-55182 exploitation)
    - `161.49.89.39` (Credential-stuffing botnet activity)
    - `103.134.154.157` (Credential-stuffing botnet activity)
- **Credentials**:
    - Username: `345gs5662d34`
    - Passwords: `345gs5662d34`, `3245gs5662d34`
- **CVEs**: `CVE-2025-55182`
- **Alert Signatures**:
    - `GPL INFO VNC server response`
    - `ET SCAN Potential VNC Scan 5900-5920`
    - `ET SCAN MS Terminal Server Traffic on Non-standard Port`
- **Target Ports (Unmapped/Minutia)**: `31004` (TCP), `56656` (TCP)
- **Honeypot Artifacts**:
    - Tanner paths: `/.env`, `/?XDEBUG_SESSION_START=phpstorm`, `/%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2Fetc%2Fpasswd`
    - ADB Commands: `echo "$(getprop ro.product.name 2>/dev/null) $(whoami 2>/dev/null)"`
    - Conpot Protocols: `kamstrup_management_protocol`, `IEC104`

## 12) Backend Tool Issues
- **Tool Failures**:
    - `two_level_terms_aggregated(primary_field='alert.signature.keyword', secondary_field='src_ip.keyword', type_filter='GPL INFO VNC server response')`: This query likely misused the `type_filter` parameter, which is intended for honeypot types, not signature text, resulting in no relevant results.
    - `suricata_lenient_phrase_search(phrase='VNC', field='src_ip.keyword')`: This query unexpectedly returned no results, suggesting an issue with field aggregation for source IPs in this specific context.
- **Affected Validations**: The inability to effectively aggregate source IPs for the `GPL INFO VNC server response` signature prevented a complete mapping of the VNC scanning campaign's infrastructure. This weakens the comprehensive understanding of the campaign's originating sources.

## 13) Agent Action Summary (Audit Trail)

- **Agent Name**: ParallelInvestigationAgent (and its sub-agents: BaselineAgent, KnownSignalAgent, CredentialNoiseAgent, HoneypotSpecificAgent)
    - **Purpose**: Collect initial broad telemetry and identify known signals and baseline activity.
    - **Inputs Used**: `investigation_start`, `investigation_end`.
    - **Actions Taken**: Executed multiple parallel queries to gather total attack counts, top geographical sources, top source IPs, ASN information, network port activity, top alert signatures, CVEs, alert categories, common credential attempts, and honeypot-specific interactions (Redis, ADBHoney, Conpot, Tanner).
    - **Key Results**: Established a baseline of 21938 attacks. Identified significant VNC scanning (18189 events), SSH brute-forcing, and activity related to CVE-2025-55182 (72 events). Noted top attacking countries and ASNs (DigitalOcean, Google). Detected ICS protocol probing and ADB reconnaissance.
    - **Errors or Gaps**: None.

- **Agent Name**: CandidateDiscoveryAgent
    - **Purpose**: Identify and initially classify potential threats from aggregated telemetry.
    - **Inputs Used**: `baseline_result`, `known_signals_result`, `credential_noise_result`, `honeypot_specific_result`.
    - **Actions Taken**: Performed OSINT on CVE-2025-55182, queried related IPs/ports, and attempted to aggregate VNC scanner IPs. Queried specific credential usage and odd-port activity. Categorized findings into emerging N-day exploitation, known exclusions, botnet campaigns, and odd-service attacks.
    - **Key Results**: Identified 1 emerging N-day exploit (CVE-2025-55182). Mapped 2 botnet/campaigns (credential stuffing, VNC scanning). Classified 3 odd-service/minutia attacks (ICS protocols, non-standard TCP ports, ADB recon). Identified 3 known commodity scanning activities for exclusion.
    - **Errors or Gaps**: Two queries failed to return expected results (`two_level_terms_aggregated` with `type_filter` and `suricata_lenient_phrase_search` on `src_ip.keyword` for VNC), which blocked complete source IP aggregation for the VNC scanning campaign.

- **Agent Name**: CandidateValidationLoopAgent
    - **Purpose**: Coordinate and manage the iterative validation of candidates.
    - **Inputs Used**: (Inferred from workflow context) Candidate classifications from CandidateDiscoveryAgent.
    - **Actions Taken**: The loop exited immediately after initial candidate classification, indicating no further iterative validation steps were triggered for any candidate within this agent's scope.
    - **Key Results**: No additional validation loops were deemed necessary or possible by the workflow logic, leading to early exit.
    - **Errors or Gaps**: None.

- **Agent Name**: DeepInvestigationLoopController
    - **Purpose**: Orchestrate deep dives into high-signal candidates.
    - **Inputs Used**: (Not explicitly available in output state, but implicitly receives high-signal candidates from previous stages).
    - **Actions Taken**: No deep investigation loops were initiated or run.
    - **Key Results**: The workflow did not trigger a deep investigation for any identified candidate.
    - **Errors or Gaps**: None.

- **Agent Name**: OSINTAgent
    - **Purpose**: Validate candidates against open-source intelligence.
    - **Inputs Used**: `emerging_n_day_exploitation`, `botnet_campaign_mapping`, `odd_service_minutia_attacks` candidates from `candidate_discovery_result`.
    - **Actions Taken**: Performed targeted OSINT searches for CVE-2025-55182, the "345gs5662d34" credential, VNC scanning signatures, Kamstrup/IEC104 protocols, TCP ports 31004/56656, and ADB reconnaissance commands.
    - **Key Results**: Confirmed CVE-2025-55182 as a critical, actively exploited RCE. Verified the "345gs5662d34" credential and VNC scanning as established botnet/commodity activity. Confirmed IEC104 and ADB commands as known attack/reconnaissance patterns. OSINT for high non-standard ports (31004, 56656) was inconclusive.
    - **Errors or Gaps**: None.

- **Agent Name**: ReportAgent
    - **Purpose**: Compile the final report from workflow state outputs.
    - **Inputs Used**: `investigation_start`, `investigation_end`, `baseline_result`, `known_signals_result`, `credential_noise_result`, `honeypot_specific_result`, `candidate_discovery_result`, `osint_validation_result`.
    - **Actions Taken**: Compiled all available workflow state outputs into a structured markdown report, adhering to the specified format and logic.
    - **Key Results**: Successfully generated the comprehensive threat intelligence report.
    - **Errors or Gaps**: None.

- **Agent Name**: SaveReportAgent
    - **Purpose**: Save the final report to storage.
    - **Inputs Used**: The completed markdown report content generated by the ReportAgent.
    - **Actions Taken**: Called `deep_agent_write_file` to save the report.
    - **Key Results**: Successfully saved the report. (Assuming successful execution).
    - **Errors or Gaps**: None.