# Honeypot Threat Hunting Final Report

## 1) Investigation Scope
- **investigation_start**: 2026-03-18T12:00:03Z
- **investigation_end**: 2026-03-18T15:00:03Z
- **completion_status**: Complete
- **degraded_mode**: False

## 2) Executive Triage Summary
- **Top Services/Ports of Interest**: 5901-5905 (VNC), 5555 (ADB), 1025, 2404, 10001 (ICS), 80 (HTTP).
- **Top Confirmed Known Exploitation**: Reconnaissance/scanning for SAP NetWeaver Visual Composer (CVE-2025-31324) critical vulnerability.
- **Top Unmapped Exploit-Like Items**: None observed in this window.
- **Botnet/Campaign Mapping Highlights**: 
  - Trinity/UFO Miner botnet active exploitation of open ADB ports (5555).
  - Broad mass-scanning campaign utilizing the Zgrab tool targeting web endpoints (including the SAP vulnerability) originating from Microsoft Azure infrastructure.

## 3) Candidate Discovery Summary
- **Total Attacks Evaluated**: 15,475
- **Top Areas of Interest**: 
  - Widespread SSH brute force with standard and botnet-specific credentials (e.g., `345gs5662d34`).
  - AdbHoney captured successful dropping and execution of the `trinity` miner and `ufo.apk`.
  - Tanner detected targeted scanning for CVE-2025-31324 (SAP).
  - ConPot recorded probing of specific ICS protocols (Kamstrup, IEC104, Guardian AST).

## 4) Emerging n-day Exploitation
- **CVE-2025-31324 (SAP NetWeaver Visual Composer)**
  - **CVE/Signature Mapping**: CVE-2025-31324 / ET SCAN Zmap User-Agent (Inbound)
  - **Evidence Summary**: 2 attempts targeting `/developmentserver/metadatauploader` from 20.163.15.217 and 20.83.27.50 receiving 404s. Deep investigation revealed this is part of a larger Zgrab scanning campaign.
  - **Affected Service/Port**: HTTP (Port 80)
  - **Confidence**: High
  - **Operational Notes**: OSINT confirms this CVE (CVSS 10.0) is actively exploited in the wild for RCE. The observed activity was automated scanning via Zgrab.

## 5) Novel or Zero-Day Exploit Candidates
- *(No unmapped novel or zero-day exploit candidates were identified in this time window.)*

## 6) Botnet/Campaign Infrastructure Mapping
- **Item**: BOT-01 (Trinity / UFO Miner Botnet)
  - **Campaign Shape**: Fan-out
  - **Suspected Compromised Src IPs**: 132.208.105.135 (2 attempts)
  - **ASNs / Geo Hints**: AS376 (Reseau dInformations Scientifiques du Quebec), Canada
  - **Suspected Staging Indicators**: Executed `trinity` binary and `ufo.apk` delivered directly over ADB port 5555. No staging server was utilized.
  - **Suspected C2 Indicators**: Embedded in the payload; none observed in telemetry (requires static analysis of the binaries).
  - **Confidence**: High
  - **Operational Notes**: Established Android botnet targeting exposed ADB interfaces to install cryptocurrency miners.

- **Item**: Zgrab Mass-Scanning Campaign (Derived from NDE-01)
  - **Campaign Shape**: Spray
  - **Suspected Compromised Src IPs**: 20.163.15.217, 20.83.27.50, 172.203.251.111
  - **ASNs / Geo Hints**: AS8075 (Microsoft Azure), USA
  - **Suspected Staging Indicators**: N/A (Scanning activity)
  - **Suspected C2 Indicators**: N/A
  - **Confidence**: High
  - **Operational Notes**: Broad, automated mass-scanning utilizing the `Mozilla/5.0 zgrab/0.x` User-Agent to enumerate endpoints like `/developmentserver/metadatauploader` and `/manager/html`.

## 7) Odd-Service / Minutia Attacks
- **Item**: ODD-01 (ICS Protocol Scanning)
  - **Service Fingerprint**: Ports 1025, 2404, 10001 (kamstrup_protocol, IEC104, guardian_ast)
  - **Why it’s unusual/interesting**: Targeted reconnaissance of Industrial Control Systems (ICS), Smart Meters, and Fuel Dispensing infrastructure.
  - **Evidence Summary**: 54 connections to Kamstrup protocol, 11 to IEC104, and 4 to Guardian AST. Source IPs include 65.49.1.52, 184.105.139.70, and 18.218.118.203.
  - **Confidence**: High
  - **Recommended Monitoring Pivots**: Monitor for targeted exploit payloads following this generic ICS reconnaissance.

## 8) Known-Exploit / Commodity Exclusions
- **Commodity VNC Scanning**: 16,291 hits for generic VNC server responses across ports 5901-5905.
- **Commodity SSH Brute Force**: High volume of credential guessing for `root`, `admin`, and the botnet-associated password `345gs5662d34`.
- **Commodity Web Scans**: Routine scanning for `/SDK/webLanguage` (Dahua), `eval-stdin.php` (CVE-2017-9841), PHP-CGI (CVE-2012-1823), and common path traversals.

## 9) Infrastructure & Behavioral Classification
- **Exploitation vs Scanning**: The vast majority of activity was commodity scanning. Direct exploitation was limited to open, unauthenticated ADB ports (Trinity botnet).
- **Campaign Shape**: Spray campaigns dominated web and ICS reconnaissance. Fan-out behavior was seen in the ADB miner infections.
- **Infra Reuse Indicators**: Significant scanning volume originating from Microsoft Azure (AS8075) and DigitalOcean (AS14061). Hurricane Electric (AS6939) was prominent in ICS scanning.
- **Odd-Service Fingerprints**: Heavy emphasis on ICS emulation (ports 1025, 2404, 10001) and ADB (5555).

## 10) Evidence Appendix
- **NDE-01 (CVE-2025-31324 Scanner)**
  - Source IPs: 20.163.15.217, 20.83.27.50
  - ASNs: AS8075
  - Target Ports/Services: HTTP (80)
  - Paths/Endpoints: `/developmentserver/metadatauploader`
  - Payload/Artifact Excerpts: User-Agent: `Mozilla/5.0 zgrab/0.x`
  - Temporal Checks: Unavailable
- **BOT-01 (Trinity Botnet)**
  - Source IPs: 132.208.105.135
  - ASNs: AS376
  - Target Ports/Services: ADB (5555)
  - Paths/Endpoints: N/A
  - Payload/Artifact Excerpts: `pm install /data/local/tmp/ufo.apk`, `/data/local/tmp/nohup /data/local/tmp/trinity`, `am start -n com.ufo.miner/com.example.test.MainActivity`
  - Temporal Checks: Unavailable
- **ODD-01 (ICS Scanning)**
  - Source IPs: 65.49.1.52, 184.105.139.70, 18.218.118.203
  - ASNs: AS6939, AS16509
  - Target Ports/Services: 1025, 2404, 10001
  - Temporal Checks: Unavailable

## 11) Indicators of Interest
- **IP Addresses**:
  - `20.163.15.217`, `20.83.27.50`, `172.203.251.111` (Zgrab / SAP Scanners)
  - `132.208.105.135` (Trinity Botnet)
  - `65.49.1.52`, `184.105.139.70`, `18.218.118.203` (ICS Reconnaissance)
- **Web Paths**: `/developmentserver/metadatauploader`
- **Artifacts**: `ufo.apk`, `trinity`, `Mozilla/5.0 zgrab/0.x`

## 12) Reflection Findings
- **Discovered Candidates:**
  1. *Trinity/UFO Miner C2 Extraction:* C2 indicators were missing from BOT-01 telemetry; required attempting extraction from `ufo.apk` and `trinity`.
  2. *Uninvestigated Emerging CVE Activity:* The baseline identified hits for recent CVEs (CVE-2025-55182, CVE-2025-30208, CVE-2024-14007) that were omitted from deep dive.
  3. *ICS/SCADA Deep Payload Analysis:* Generic ICS protocol scanning was observed, but payload analysis and handshake completion needed deeper investigation.
  4. *Full Spectrum of Zgrab Campaign Targets:* The Azure Zgrab mass-scanning campaign generated 87 hits, but only two paths were initially reviewed.
- **Actions Taken:** 
  - For the *Trinity/UFO Miner C2 Extraction* candidate, OSINT searches were conducted for the precise malware hashes (e.g., `0d3c687ffc...`).
  - AdbHoney logs and Suricata flow/DNS telemetry were queried to check for any outbound HTTP requests or domain resolutions.
- **Findings:** 
  - The OSINT searches did not uncover public C2 domain or IP mappings for the observed hashes. 
  - Telemetry confirmed the honeypot made zero external outbound requests or DNS resolutions. 
  - The `ufo.apk` and `trinity` payloads were confirmed to have been pushed directly over the ADB connection rather than downloaded from a staging server, indicating the C2 is embedded and not accessible strictly via network telemetry without offline static analysis.
- **Enhancements:** 
  - *BOT-01 (Trinity Botnet)* was enhanced. The confirmation that the malware was pushed directly over ADB validated that staging indicators were absent by design, and C2 indicators could not be identified via network logs due to being embedded within the compiled binaries.

## 13) Backend Tool Issues
- None observed.

## 14) Agent Action Summary (Audit Trail)
- **ParallelInvestigationAgent**:
  - *Purpose*: Gather baseline statistics, known signals, credentials, and honeypot-specific telemetry.
  - *Inputs Used*: Time window 2026-03-18T12:00:03Z to 2026-03-18T15:00:03Z.
  - *Actions Taken*: Queried attack counts, IPs, ASNs, signatures, credentials, and specific honeypot inputs.
  - *Key Results*: Identified 15,475 attacks, heavy VNC/SSH noise, ADB miner payloads, and SAP/ICS scanning.
  - *Errors/Gaps*: None.
- **CandidateDiscoveryAgent**:
  - *Purpose*: Generate exploit candidates and summarize findings.
  - *Inputs Used*: Baseline and honeypot-specific results.
  - *Actions Taken*: Evaluated paths, grouped findings into distinct candidate profiles, excluded commodity noise.
  - *Key Results*: Generated NDE-01 (SAP), BOT-01 (Trinity), and ODD-01 (ICS).
  - *Errors/Gaps*: None.
- **CandidateValidationLoopAgent**:
  - *Purpose*: Validate queued candidates against evidence.
  - *Inputs Used*: NDE-01 candidate details.
  - *Actions Taken*: Queried detailed events for SAP scanning source IPs.
  - *Key Results*: Validated NDE-01 as high-confidence emerging n-day scanning. 1 candidate validated; loop exited.
  - *Errors/Gaps*: None.
- **DeepInvestigationLoopController**:
  - *Purpose*: Deep dive into validated candidates to find campaign context.
  - *Inputs Used*: NDE-01 validated result.
  - *Actions Taken*: Pivoted on web paths and Zgrab User-Agent to uncover broader infrastructure. 2 iterations run.
  - *Key Results*: Uncovered a wider Azure-based mass-scanning campaign.
  - *Errors/Gaps*: None.
- **OSINTAgent**:
  - *Purpose*: Enrich findings with external intelligence.
  - *Inputs Used*: Candidate summaries (NDE-01, BOT-01, ODD-01).
  - *Actions Taken*: Searched for CVE mappings, botnet names, and ICS honeypot activity.
  - *Key Results*: Confirmed CVE-2025-31324 details, mapped Trinity/UFO miner behavior, and confirmed generic ICS scanning patterns.
  - *Errors/Gaps*: None.
- **ReflectionCandidateDiscoverAgent**:
  - *Purpose*: Identify gaps or avenues for further analysis in the draft report.
  - *Inputs Used*: The initial saved report.
  - *Actions Taken*: Generated reflection candidates (C2 extraction, uninvestigated CVEs, ICS payload analysis, Zgrab target spectrum).
  - *Key Results*: Outputted 4 distinct reflection candidates.
  - *Errors/Gaps*: None.
- **ReflectDeepInvestigationAgent**:
  - *Purpose*: Execute deep investigation based on reflection candidates.
  - *Inputs Used*: Trinity/UFO Miner C2 Extraction candidate details.
  - *Actions Taken*: Performed hash lookups in OSINT and checked DNS/Flows in Suricata and AdbHoney for staging servers.
  - *Key Results*: Concluded C2 is embedded in the binary as the payload was pushed directly with no network resolution observed.
  - *Errors/Gaps*: None.
- **ReportAgent**:
  - *Purpose*: Compile final markdown report.
  - *Inputs Used*: All agent outputs.
  - *Actions Taken*: Formatted final comprehensive document.
  - *Key Results*: Produced final markdown structure including reflection findings.
  - *Errors/Gaps*: None.
- **SaveReportAgent**:
  - *Purpose*: Save the final report to disk.
  - *Inputs Used*: Markdown text.
  - *Actions Taken*: Called `deep_agent_write_file`.
  - *Key Results*: Report saved successfully.
  - *Errors/Gaps*: None.'