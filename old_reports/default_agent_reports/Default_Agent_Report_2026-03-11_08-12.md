# Honeypot Threat Hunting Report

## 1. Investigation Scope
- **investigation_start**: 2026-03-11T08:00:04Z
- **investigation_end**: 2026-03-11T12:00:04Z
- **completion_status**: Partial (degraded evidence)
- **degraded_mode**: true
  - **Reason**: Evidence gathering for Industrial Control System (ICS) activity failed, preventing source IP identification and campaign analysis for that specific candidate.

## 2. Executive Triage Summary
- **Top Services/Ports of Interest**: VNC (5900), HTTP (80, 6036, 8000, 9000), various Industrial Control System protocols (IEC104, Kamstrup KMP, guardian_ast), and Android Debug Bridge (ADB).
- **Top Confirmed Known Exploitation**:
  - **CVE-2025-55182 (React2Shell)**: Critical RCE exploitation observed against port 9000.
  - **CVE-2024-4577 (PHP RCE)**: Exploitation of a recently disclosed PHP argument injection vulnerability on Windows.
  - **CVE-2006-2369 (VNC Auth Bypass)**: High-volume, botnet-like exploitation against VNC port 5900.
- **Unmapped Exploit-like Items**: No high-confidence novel exploit candidates remain after OSINT validation. The initial candidate was successfully mapped to CVE-2024-4577.
- **Botnet/Campaign Mapping Highlights**: A large-scale, single-source campaign was identified targeting CVE-2006-2369 (VNC) from IP `185.231.33.22` (AS211720).
- **Major Uncertainties**: The source and coordination of observed attacks against emulated ICS protocols could not be determined due to tool failures during evidence gathering.

## 3. Candidate Discovery Summary
- **Total Attacks Analyzed**: 36,961 events within the time window.
- **Initial Candidates Generated**: 6 candidates were generated for validation, spanning emerging n-day exploits, botnet activity, a potential novel exploit, odd-service attacks, and suspicious monitoring activity.
- **Top Areas of Interest**:
    - High-volume VNC exploitation (CVE-2006-2369).
    - Web exploitation targeting recently disclosed CVEs (CVE-2025-55182, CVE-2024-4577).
    - Reconnaissance against Android Debug Bridge (ADB).
    - Probes against Industrial Control System (ICS) honeypot services.
- **Evidence Gaps**: Discovery was materially affected by query failures (`two_level_terms_aggregated`, `kibanna_discover_query`) against Conpot data, which prevented the correlation of source IPs to the observed ICS protocol interactions.

## 4. Emerging n-day Exploitation
### NDE-01: CVE-2025-55182 (React2Shell)
- **cve/signature mapping**: `CVE-2025-55182` / `ET WEB_SPECIFIC_APPS React Server Components React2Shell Unsafe Flight Protocol Property Access`
- **evidence summary**: 159 events targeting `/app` via POST requests.
- **affected service/port**: HTTP / 9000
- **confidence**: High
- **operational notes**: Activity matches public reports of a critical, unauthenticated RCE. Monitor all web servers running React or Next.js for similar POST requests.

### NDE-02: CVE-2024-14007 (Shenzhen TVT NVR)
- **cve/signature mapping**: `CVE-2024-14007` / `ET WEB_SPECIFIC_APPS Shenzhen TVT NVMS-9000 Information Disclosure Attempt`
- **evidence summary**: 16 events from a single source IP.
- **affected service/port**: HTTP / 6036
- **confidence**: High
- **operational notes**: Known authentication bypass vulnerability. Indicates targeted scanning for vulnerable NVR/DVR systems.

### NOV-01 (Re-classified): CVE-2024-4577 (PHP RCE)
- **cve/signature mapping**: `CVE-2024-4577`
- **evidence summary**: 1 event with path `/?%ADd+allow_url_include%3d1+%ADd+auto_prepend_file%3dphp://input`.
- **affected service/port**: HTTP / 80
- **confidence**: High
- **operational notes**: This activity, initially flagged as a novel candidate, was identified by OSINT as exploitation of a recent, critical PHP RCE affecting CGI implementations on Windows. The payload uses a "soft hyphen" (`%AD`) argument injection technique.

## 5. Novel or Zero-Day Exploit Candidates (UNMAPPED ONLY, ranked)
- No candidates were validated as novel in this window.
- The single candidate (`NOV-01`) initially classified as potentially novel was successfully mapped to **CVE-2024-4577** during the OSINT validation phase and has been moved to the "Emerging n-day Exploitation" section.

## 6. Botnet/Campaign Infrastructure Mapping
### BOT-01: VNC Auth Bypass Campaign (CVE-2006-2369)
- **related_candidate_id(s)**: BOT-01
- **campaign_shape**: fan-in (single source, many attempts)
- **suspected_compromised_src_ips**: `185.231.33.22` (7,962 hits)
- **ASNs / geo hints**: AS211720 / Datashield, Inc. (Seychelles)
- **suspected_staging indicators**: N/A
- **suspected_c2 indicators**: N/A
- **confidence**: High
- **operational notes**: This is a high-volume, automated campaign leveraging a very old but effective VNC authentication bypass vulnerability. The activity originates from a single IP, suggesting a dedicated scanner or a compromised server. Recommend blocking IP `185.231.33.22`.

## 7. Odd-Service / Minutia Attacks
### ODD-01: Probing of ICS Protocols
- **service_fingerprint**: Conpot Honeypot (protocols: `guardian_ast`, `kamstrup_management_protocol`, `IEC104`)
- **why it’s unusual/interesting**: Interaction with uncommon ICS protocols suggests targeted reconnaissance against operational technology (OT) assets. While IEC104 and Kamstrup are known, 'guardian_ast' is not a standard ICS protocol, suggesting custom tooling or a honeypot fingerprinting attempt.
- **evidence summary**: 58 events for `guardian_ast`, 3 for `kamstrup_management_protocol`, 1 for `IEC104`.
- **confidence**: Low
- **recommended monitoring pivots**: **Provisional Finding.** Source IPs could not be identified due to tool errors. Requires fixing the underlying query to Conpot data to enable source analysis and assess if this activity is coordinated or isolated background noise.

## 8. Known-Exploit / Commodity Exclusions
- **VNC Auth Bypass (CVE-2006-2369)**: Over 7,900 events from a single IP (`185.231.33.22`) exploiting a well-known VNC vulnerability from 2006. Classified as botnet activity.
- **SSH Credential Stuffing**: Standard brute-force attempts targeting common usernames like `root`, `admin`, `user`, and service-specific names like `solana`, `n8n`, and `validator`.
- **PHP RCE Scanning (CVE-2017-9841)**: Low-volume probes for a known PHPUnit RCE vulnerability via paths like `/V2/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php`.
- **Common Web Scanning**: Probes for sensitive files like `/.env`.
- **ADB Reconnaissance**: Known pattern of Android malware reconnaissance observed from IP `45.135.194.48`, using `getprop` and `whoami` to profile devices with exposed ADB ports.

## 9. Infrastructure & Behavioral Classification
- **Exploitation vs Scanning**: The investigation identified both widespread, opportunistic scanning (VNC, SSH, PHPUnit) and targeted exploitation of recently disclosed vulnerabilities (CVE-2025-55182, CVE-2024-4577).
- **Campaign Shape**: A clear `fan-in` shape was observed for the VNC campaign (`BOT-01`), with one IP generating thousands of attacks. Other exploitation appeared more distributed or as single events.
- **Infra Reuse Indicators**: The IP `185.231.33.22` is dedicated to the VNC campaign. The IP `45.135.194.48` is associated with ADB recon and has numerous public abuse reports.
- **Odd-Service Fingerprints**: Activity targeting ICS protocols (`IEC104`, `kamstrup_management_protocol`) and Android Debug Bridge indicates a diverse interest in non-standard enterprise services.

## 10. Evidence Appendix
### Emerging N-Day: CVE-2025-55182 (NDE-01)
- **Source IPs**: `195.3.221.86` (159)
- **ASNs**: AS201814 / MEVSPACE sp. z o.o. (Poland)
- **Target Ports/Services**: 9000/TCP (HTTP)
- **Paths/Endpoints**: `/app` (HTTP POST)
- **Payload/Artifact Excerpts**: Signature: `ET WEB_SPECIFIC_APPS React Server Components React2Shell Unsafe Flight Protocol Property Access (CVE-2025-55182)`

### Botnet Mapping: VNC Campaign (BOT-01)
- **Source IPs**: `185.231.33.22` (7962), `66.132.153.143` (1)
- **ASNs**: AS211720 / Datashield, Inc. (7962)
- **Target Ports/Services**: 5900/TCP (VNC)
- **Payload/Artifact Excerpts**: Signature: `ET EXPLOIT VNC Server Not Requiring Authentication (case 2)`, CVE: `CVE-2006-2369`

### Emerging N-Day: CVE-2024-4577 (NOV-01)
- **Source IPs**: `207.166.168.14` (1)
- **ASNs**: AS150436 / Byteplus Pte. Ltd. (Singapore)
- **Target Ports/Services**: 80/TCP (HTTP)
- **Paths/Endpoints**: `/?%ADd+allow_url_include%3d1+%ADd+auto_prepend_file%3dphp://input`

## 11. Indicators of Interest
- **IPs**:
  - `185.231.33.22` (High-volume VNC scanning, block recommended)
  - `195.3.221.86` (Exploiting CVE-2025-55182)
  - `207.166.168.14` (Exploiting CVE-2024-4577)
  - `176.65.139.12` (Exploiting CVE-2024-14007)
  - `45.135.194.48` (ADB reconnaissance)
- **Paths/Payloads**:
  - `/?%ADd+allow_url_include%3d1+%ADd+auto_prepend_file%3dphp://input` (CVE-2024-4577)
  - `/V2/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php` (CVE-2017-9841)
- **CVEs**:
  - `CVE-2025-55182` (React2Shell)
  - `CVE-2024-4577` (PHP RCE)
  - `CVE-2024-14007` (Shenzhen TVT NVR)
  - `CVE-2006-2369` (VNC Auth Bypass)

## 12. Backend Tool Issues
- **Tool Failures**: `two_level_terms_aggregated`, `kibanna_discover_query`
- **Affected Validations**: The tools failed to execute correctly when querying `Conpot` data. This specifically blocked the ability to retrieve source IPs associated with the ICS protocol activity (`ODD-01`).
- **Weakened Conclusions**: The significance and coordination of the "Odd-Service / Minutia Attacks" finding is provisional and marked with low confidence. It is impossible to determine if the activity represents a coordinated campaign or unrelated background noise without source IP data.

## 13. Agent Action Summary (Audit Trail)
### ParallelInvestigationAgent
- **Purpose**: To run parallel sub-agents for baseline data collection.
- **Inputs Used**: `investigation_start`, `investigation_end`.
- **Actions Taken**: Executed `BaselineAgent`, `KnownSignalAgent`, `CredentialNoiseAgent`, and `HoneypotSpecificAgent` concurrently.
- **Key Results**: Aggregated baseline statistics, known CVE/signature data, credential stuffing noise, and honeypot-specific interactions.
- **Errors_or_Gaps**: None reported at this stage.

### CandidateDiscoveryAgent
- **Purpose**: To synthesize data from the parallel investigation and discover potential threat candidates.
- **Inputs Used**: `baseline_result`, `known_signals_result`, `honeypot_specific_result`, `credential_noise_result`.
- **Actions Taken**:
    - Queried for IPs related to top CVEs (`top_src_ips_for_cve`).
    - Aggregated data by path and protocol (`two_level_terms_aggregated`).
    - Searched for specific exploit artifacts (`kibanna_discover_query`, `suricata_lenient_phrase_search`).
- **Key Results**: Generated 6 distinct threat candidates, including emerging n-days, a botnet, a novel candidate, and odd-service activity.
- **Errors_or_Gaps**: The agent explicitly reported that queries to identify source IPs for Conpot (ICS) activity failed. This gap was passed downstream.

### CandidateValidationLoopAgent
- **Purpose**: To iterate through discovered candidates for initial triage.
- **Inputs Used**: `candidate_discovery_result`.
- **Actions Taken**:
    - Initialized queue with 6 candidates (`innit_candidate_que`).
    - Iterated 6 times, loading each candidate for review (`load_next_candidate`).
- **Key Results**: All 6 candidates were processed through the loop without modification, confirming the initial set for further analysis by the OSINT agent. The loop exited normally after processing all items.
- **Errors_or_Gaps**: None.

### OSINTAgent
- **Purpose**: To enrich and validate candidates with open-source intelligence.
- **Inputs Used**: All 6 candidates from the validation loop.
- **Actions Taken**: Performed targeted web searches (`search`) for each candidate's CVEs, IPs, protocol names, and unique artifact strings.
- **Key Results**:
    - Successfully mapped candidate `NOV-01` to `CVE-2024-4577`.
    - Confirmed `NDE-01` (React2Shell) as a recently disclosed, critical vulnerability.
    - Confirmed `BOT-01` and `MIN-01` as well-known, established commodity attack patterns.
    - Provided context for ICS protocols in `ODD-01`.
- **Errors_or_Gaps**: No public documentation found for the "guardian_ast" protocol.

### ReportAgent (self)
- **Purpose**: To compile the final report from all workflow state outputs.
- **Inputs Used**: `investigation_start`, `investigation_end`, `baseline_result`, `known_signals_result`, `credential_noise_result`, `honeypot_specific_result`, `candidate_discovery_result`, `osint_validation_result`, `CandidateLoopControllerAgent` logs.
- **Actions Taken**:
    - Synthesized inputs and re-classified candidate `NOV-01` based on OSINT findings.
    - Structured all findings into the mandatory 13-section report format.
    - Noted the `Partial` completion status due to evidence gaps from the `CandidateDiscoveryAgent`.
- **Key Results**: Generated this markdown report.
- **Errors_or_Gaps**: None; worked in degraded mode as required.

### SaveReportAgent
- **Purpose**: To save the final report artifact.
- **Inputs Used**: The markdown content from the `ReportAgent`.
- **Actions_Taken**: `default_write_file` will be called with the report content.
- **Key_Results**: The report file will be saved.
- **Errors_or_Gaps**: To be determined upon execution.
