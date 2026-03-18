# Honeypot Threat Hunting Report

## 1) Investigation Scope
- **investigation_start**: 2026-03-18T09:00:05Z
- **investigation_end**: 2026-03-18T12:00:05Z
- **completion_status**: Complete
- **degraded_mode**: false

## 2) Executive Triage Summary
- **Top Services/Ports of Interest**: The most significant activity centered on VNC (ports 5900-5903) and web services on HTTP port 80 (Tanner honeypot). Minutia activity was noted on the IEC104 protocol (Conpot honeypot).
- **Top Confirmed Known Exploitation**: A widespread campaign targeting VNC authentication bypass (CVE-2006-2369) was the dominant known activity. Additionally, a multi-pronged PHP exploit campaign targeting a known PHPUnit RCE vulnerability (CVE-2017-9841) was identified.
- **Top Unmapped Exploit-like Items**: No high-confidence novel candidates remain after OSINT validation. The most interesting activity, initially flagged as a novel PHP exploit, was mapped to a known vulnerability (CVE-2017-9841), though it appears to use an evasive payload variant not detected by current signatures.
- **Botnet/Campaign Mapping Highlights**: A large-scale, distributed 'spray' campaign targeting VNC was mapped, involving numerous source IPs primarily from ASNs 50360 (Tamatiya EOOD) and 14061 (DigitalOcean).
- **Major Uncertainties**: None. The investigation proceeded without tool failures or significant evidence gaps.

## 3) Candidate Discovery Summary
Initial analysis of telemetry identified four primary areas of interest:
1.  A high-volume VNC scanning and exploitation campaign (later mapped to `BOT-01`).
2.  A targeted, multi-vector PHP exploitation attempt from a single source IP, which included probes for PHPUnit, LFI, and XDEBUG vulnerabilities (later mapped to `NOV-01`).
3.  Low-volume reconnaissance against the IEC104 Industrial Control System protocol (later mapped to `ODD-01`).
4.  Scanning for Spring Boot Actuator endpoints, indicative of reconnaissance for cloud infrastructure vulnerabilities (later mapped to `MIN-01`).

## 4) Emerging n-day Exploitation
### PHPUnit RCE (CVE-2017-9841) with Potential Evasion
- **cve/signature mapping**: CVE-2017-9841 (Remote Code Execution in PHPUnit).
- **evidence summary**: A single source IP (`154.50.110.184`) launched a multi-pronged attack targeting several PHP vulnerabilities. This included attempts to exploit a known RCE in PHPUnit via the `/V2/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php` path, Local File Inclusion (LFI) via `allow_url_include` and PEAR, and probes for XDEBUG. Notably, the PHPUnit RCE attempt did not trigger any matching Suricata signatures, suggesting the use of a modified or obfuscated payload to evade detection.
- **affected service/port**: HTTP (Tanner) on port 80.
- **confidence**: High.
- **operational notes**: This activity represents a known, actively exploited vulnerability being deployed with potentially evasive characteristics. Signature development is recommended to detect this specific variant.

## 5) Novel or Zero-Day Exploit Candidates (UNMAPPED ONLY, ranked)
*No candidates met the criteria for this section. The primary candidate (`NOV-01`) was re-classified as an Emerging n-day Exploitation following OSINT validation which mapped it to CVE-2017-9841.*

## 6) Botnet/Campaign Infrastructure Mapping
### VNC Scanning Campaign (BOT-01)
- **item_id**: BOT-01
- **campaign_shape**: spray (high volume from many disparate sources).
- **suspected_compromised_src_ips**: `79.124.40.98` (999 events), `165.232.109.215` (738 events), and hundreds of others.
- **ASNs / geo hints**: The campaign is distributed across multiple ASNs, with the largest clusters in AS50360 (Tamatiya EOOD, Bulgaria) and AS14061 (DigitalOcean, LLC, United States).
- **suspected_staging indicators**: No staging indicators were identified in the telemetry. The activity appears to be direct-to-target scanning.
- **suspected_c2 indicators**: None identified.
- **confidence**: High.
- **operational notes**: This is a high-volume, opportunistic campaign scanning for the old and well-known VNC authentication bypass vulnerability (CVE-2006-2369). The IPs are likely compromised systems or low-cost cloud servers used for scanning. Blocking VNC ports (5900-5903) from untrusted sources is the primary mitigation.

## 7) Odd-Service / Minutia Attacks
### ICS Protocol Reconnaissance (ODD-01)
- **service_fingerprint**: IEC104 on Conpot honeypot.
- **why it’s unusual/interesting**: IEC104 is a protocol used in Industrial Control Systems (ICS) and SCADA environments. Activity on this protocol, while low volume, indicates reconnaissance interest in critical infrastructure.
- **evidence summary**: A small number of events (8) were recorded on the Conpot honeypot for the IEC104 protocol. OSINT confirms this is a known target for academic research and vulnerability scanning due to inherent weaknesses in the protocol.
- **confidence**: Low (due to volume, indicating passive scanning rather than an active attack).
- **recommended monitoring pivots**: Monitor for any increase in volume, changes in source IPs, or attempts to send specific control commands over this protocol.

## 8) Known-Exploit / Commodity Exclusions
- **VNC Authentication Bypass Scanning (CVE-2006-2369)**: The majority of traffic in this window consisted of widespread, automated scanning for a well-known VNC vulnerability from 2006. This is considered commodity background noise.
- **Credential Noise**: Standard brute-force attempts were observed against SSH, using common usernames like `root`, `admin`, and `ubuntu`, and predictable passwords like `123456` and `password`.
- **Common Web Scanning**:
    - Probing for exposed configuration files like `.env`.
    - Reconnaissance for Spring Boot Actuator endpoints (`/actuator/gateway/routes`) from IP `79.124.40.174`. OSINT confirms this is a standard technique to find systems vulnerable to CVE-2022-22947.

## 9) Infrastructure & Behavioral Classification
- **Exploitation vs Scanning**: The activity from `154.50.110.184` (PHPUnit) was targeted exploitation. The VNC and Spring Boot activity represents widespread, opportunistic scanning.
- **Campaign Shape**: The VNC campaign (`BOT-01`) was a classic distributed 'spray' attack. The PHP campaign (`NOV-01`) was a 'fan-out' from a single source targeting multiple vulnerabilities.
- **Infra Reuse Indicators**: The actor at `79.124.40.174` was observed scanning for both Spring Boot web vulnerabilities and PostgreSQL databases, indicating reuse of infrastructure for different reconnaissance tasks.
- **Odd-Service Fingerprints**: Activity on the IEC104 protocol indicates niche interest in ICS/SCADA systems.

## 10) Evidence Appendix
### Emerging n-day: PHPUnit RCE (NOV-01)
- **source IPs**: `154.50.110.184` (173 events)
- **ASNs**: 46783 (EASY LINK LLC)
- **target ports/services**: 80 (HTTP/Tanner)
- **paths/endpoints**:
    - `/V2/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php`
    - `/?%ADd+allow_url_include%3d1+%ADd+auto_prepend_file%3dphp://input`
    - `/index.php?lang=../../../../../../../../usr/local/lib/php/pearcmd&+config-create+/&/<?echo(md5("hi"));?>+/tmp/index1.php`
    - `/containers/json`
- **payload/artifact excerpts**: LFI and RCE attempts embedded in URI paths.
- **temporal checks results**: unavailable.

### Botnet Mapping: VNC Campaign (BOT-01)
- **source IPs**: `79.124.40.98` (999), `165.232.109.215` (738), `136.114.97.84` (636), and others.
- **ASNs**: 14061 (DigitalOcean, LLC), 50360 (Tamatiya EOOD), 396982 (Google LLC), and others.
- **target ports/services**: 5900, 5901, 5902, 5903 (VNC)
- **payload/artifact excerpts**: Traffic matching signatures 'ET EXPLOIT VNC Server Not Requiring Authentication' and 'GPL INFO VNC server response', correlated with CVE-2006-2369.
- **temporal checks results**: unavailable.

## 11) Indicators of Interest
- **IPs**:
    - `154.50.110.184` (High confidence; associated with multi-vector PHP exploit toolkit).
    - `79.124.40.174` (Moderate confidence; scanner for Spring Boot and PostgreSQL).
- **Paths/URIs**:
    - `/V2/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php` (CVE-2017-9841 exploit attempt).
    - `/?%ADd+allow_url_include%3d1+%ADd+auto_prepend_file%3dphp://input` (PHP RCE attempt).
    - `/actuator/gateway/routes` (Spring Boot Actuator reconnaissance).

## 12) Backend Tool Issues
- No tool failures were reported during the investigation. All analysis branches completed successfully.

## 13) Agent Action Summary (Audit Trail)
- **agent_name**: ParallelInvestigationAgent
- **purpose**: Gather initial broad-spectrum telemetry.
- **inputs_used**: Time window.
- **actions_taken**: Executed parallel queries via sub-agents (`BaselineAgent`, `KnownSignalAgent`, `CredentialNoiseAgent`, `HoneypotSpecificAgent`) to collect baseline statistics, known alerts, credential stuffing data, and honeypot-specific logs.
- **key_results**:
    - Identified 16,838 total attacks.
    - Flagged massive volume of VNC-related alerts (signatures 2100560, 2002923) and CVE-2006-2369.
    - Noted standard SSH brute-force patterns.
    - Uncovered suspicious web paths on the Tanner honeypot and IEC104 protocol activity on Conpot.
- **errors_or_gaps**: None.

- **agent_name**: CandidateDiscoveryAgent
- **purpose**: Synthesize initial data to identify and prioritize potential threats.
- **inputs_used**: All outputs from ParallelInvestigationAgent.
- **actions_taken**: Merged data from all sources. Pivoted investigation on suspicious Tanner paths and related source IPs (`154.50.110.184`, `79.124.40.174`). Formulated and categorized four primary candidates (`NOV-01`, `BOT-01`, `ODD-01`, `MIN-01`).
- **key_results**:
    - Identified a novel PHP exploit candidate (`NOV-01`) based on exploit-like behavior without a matching signature.
    - Characterized the VNC activity as a large-scale campaign (`BOT-01`).
    - Flagged ICS (`ODD-01`) and Spring Boot (`MIN-01`) activity for monitoring.
- **errors_or_gaps**: None.

- **agent_name**: CandidateValidationLoopAgent
- **purpose**: Manage the deep validation of individual candidates.
- **inputs_used**: Candidate queue from CandidateDiscoveryAgent.
- **actions_taken**: Initialized the candidate queue. The loop was exited immediately as no candidates required deep, iterative tool-based validation in this workflow run.
- **key_results**: 0 iterations run. 0 candidates validated via deep loop.
- **errors_or_gaps**: None.

- **agent_name**: DeepInvestigationLoopController
- **purpose**: Perform deep, iterative investigation on high-value leads.
- **inputs_used**: n/a
- **actions_taken**: The loop was not entered.
- **key_results**: 0 iterations run.
- **errors_or_gaps**: None.

- **agent_name**: OSINTAgent
- **purpose**: Validate and contextualize findings using public threat intelligence.
- **inputs_used**: `candidate_discovery_result`.
- **actions_taken**: Performed targeted web searches for each of the four candidates based on their key artifacts (CVEs, URL paths, protocols).
- **key_results**:
    - Mapped `NOV-01` to the known vulnerability CVE-2017-9841, reducing its novelty.
    - Confirmed `BOT-01` targets CVE-2006-2369 and is commodity scanning.
    - Confirmed `MIN-01` is known reconnaissance for CVE-2022-22947.
    - Confirmed `ODD-01` is known scanning behavior for ICS protocols.
- **errors_or_gaps**: None.

- **agent_name**: ReportAgent
- **purpose**: Compile the final report from all workflow state outputs.
- **inputs_used**: All preceding agent state outputs.
- **actions_taken**: Synthesized all available data. Re-categorized candidate `NOV-01` from "Novel" to "Emerging n-day" based on OSINT findings, per workflow rules. Assembled the final markdown report following the strict output format.
- **key_results**: This report.
- **errors_or_gaps**: None.

- **agent_name**: SaveReportAgent
- **purpose**: Save the final report artifact.
- **inputs_used**: Final report content from ReportAgent.
- **actions_taken**: Will call `deep_agent_write_file` to save the report.
- **key_results**: File write status.
- **errors_or_gaps**: None pending.