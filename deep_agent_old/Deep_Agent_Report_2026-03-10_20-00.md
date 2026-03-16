# Threat Hunting Report: 2026-03-10T20:00:12Z to 2026-03-11T00:00:12Z

## 1) Investigation Scope
- **investigation_start**: 2026-03-10T20:00:12Z
- **investigation_end**: 2026-03-11T00:00:12Z
- **completion_status**: Complete
- **degraded_mode**: false
  - The investigation completed successfully. A minor tool query issue was encountered during candidate validation but was successfully circumvented by the agent, allowing the investigation to proceed without loss of evidence.

## 2) Executive Triage Summary
- **Top Services of Interest**:
  - Web Application (HTTP on ports 4001, 9999, and others): Targeted by a multi-exploit campaign.
  - VNC (port 5900): Subjected to high-volume, commodity exploitation.
  - ICS Protocols (guardian_ast, kamstrup_protocol): Unusual reconnaissance activity detected on the Conpot honeypot.
  - SSH (ports 22, 31146): Targeted by broad scanning and brute-force activity.
- **Top Confirmed Known Exploitation**:
  - **CVE-2025-55182 (React2Shell)**: Active exploitation of a critical RCE vulnerability in React Server Components from a dedicated attacker.
  - **CVE-2006-2369 (VNC Auth Bypass)**: Widespread, automated scanning from a commodity botnet.
- **Top Unmapped Exploit-like Items**:
  - No novel or unmapped exploit candidates were identified. All initial candidates were successfully mapped to known TTPs or vulnerabilities.
- **Botnet/Campaign Mapping Highlights**:
  - A multi-exploit web campaign was identified from source IP **193.32.162.28** (ASN 47890), simultaneously targeting **CVE-2025-55182 (React2Shell)** and **Javascript Prototype Pollution** vulnerabilities.
  - The source ASN **47890 (Unmanaged Ltd, Romania)** was identified as a malicious infrastructure provider, hosting multiple, distinct threat actors conducting web exploitation and SSH scanning.
- **Major Uncertainties**:
  - None. The investigation successfully contextualized all major findings.

## 3) Candidate Discovery Summary
The discovery phase triaged 37,766 total attacks, identifying several clusters of interest. Key areas included high-volume VNC activity (CVE-2006-2369), alerts for a recent web vulnerability (CVE-2025-55182), and unusual ICS protocol interactions on the Conpot honeypot. These were processed into three primary candidates for validation, while widespread commodity scanning (e.g., SMB on port 445, web scanning for `.env` files) was flagged for exclusion.

## 4) Emerging n-day Exploitation

### Item: Multi-Exploit Web Campaign (React2Shell & Prototype Pollution)
- **cve/signature mapping**:
  - CVE-2025-55182
  - `ET WEB_SPECIFIC_APPS React Server Components React2Shell Unsafe Flight Protocol Property Access (CVE-2025-55182)`
  - `ET HUNTING Javascript Prototype Pollution Attempt via __proto__ in HTTP Body`
- **evidence summary**:
  - **Count**: 146 events matching CVE-2025-55182, with an additional 72 alerts for Prototype Pollution from the same source.
  - **Key Artifacts**: All malicious activity originated from source IP **193.32.162.28**. Attacker targeted common React/Next.js endpoints like `/api/route`, `/_next/server`, and `/app` across numerous ports (4001, 9999, 5001, 3210, etc.).
- **affected service/port**: HTTP on various high ports (e.g., 4001, 9999).
- **confidence**: High
- **operational notes**: This represents active exploitation of a critical (CVSS 10.0) RCE vulnerability. The attacker is using a multi-pronged approach, scanning for at least two distinct web application vulnerabilities simultaneously. Immediate action is recommended.

## 5) Novel or Zero-Day Exploit Candidates (UNMAPPED ONLY)
None identified.

## 6) Botnet/Campaign Infrastructure Mapping

### Item: Malicious Infrastructure Provider (ASN 47890)
- **item_id**: ASN-47890
- **campaign_shape**: The ASN hosts multiple, distinct campaigns with different shapes.
  - **Web Exploit Campaign**: fan-out (one attacker scanning multiple ports/services on a target).
  - **SSH Scanning Campaign**: spray (multiple IPs scanning for a common service).
- **suspected_compromised_src_ips**:
  - **193.32.162.28**: Web exploitation (React2Shell, Prototype Pollution).
  - **2.57.122.96**: SSH scanning on port 22.
  - **80.94.92.68** (and related `80.94.92.0/24` IPs): SSH scanning on non-standard port 31146.
- **ASNs / geo hints**: AS47890 (Unmanaged Ltd, Romania).
- **suspected_staging indicators**: The ASN itself appears to be a staging ground for malicious actors.
- **confidence**: High
- **operational notes**: This ASN should be considered hostile. Traffic originating from ASN 47890 warrants heightened scrutiny or proactive blocking. The investigation clearly separated at least three distinct activity groups operating from this network.

### Item: VNC Auth-Bypass Botnet
- **item_id**: BOT-01
- **campaign_shape**: fan-in (single compromised host scanning widely).
- **suspected_compromised_src_ips**: **185.231.33.22** (9,027 events).
- **ASNs / geo hints**: AS211720 (Datashield, Inc.), Seychelles.
- **suspected_staging indicators**: N/A
- **suspected_c2 indicators**: N/A
- **confidence**: High
- **operational notes**: This is a commodity botnet engaged in internet-wide scanning for the very old CVE-2006-2369 vulnerability in VNC. The activity is high-volume but low-sophistication.

## 7) Odd-Service / Minutia Attacks

### Item: ICS Reconnaissance Activity
- **service_fingerprint**: Conpot Honeypot, protocols `guardian_ast` and `kamstrup_protocol`.
- **why it’s unusual/interesting**: These are specific Industrial Control System (ICS) protocols. `guardian_ast` mimics a Veeder-Root Automated Tank Gauge used at gas stations, and `kamstrup_protocol` mimics smart energy/water meters. Interaction with these indicates specific targeting of industrial or utility systems.
- **evidence summary**: Low volume (6 total events), but high signal. 5 events for `guardian_ast`, 1 for `kamstrup_protocol`.
- **confidence**: Moderate (High signal, but low event count).
- **recommended monitoring pivots**: Monitor for any further interactions with the Conpot honeypot or other ICS-related services. Correlate source IPs of this activity against other suspicious behavior.

## 8) Known-Exploit / Commodity Exclusions
- **VNC Authentication Bypass (CVE-2006-2369)**: 9,030 events from IP `185.231.33.22` targeting port 5900, identified by signature `ET EXPLOIT VNC Server Not Requiring Authentication (case 2)`. This is textbook commodity botnet activity.
- **SSH Scanning & Brute-Force**:
  - IPs `2.57.122.96` and the `80.94.92.0/24` cluster (from ASN 47890) conducted widespread scanning on ports 22 and 31146.
  - Generic credential stuffing attempts observed across multiple honeypots with common usernames (`root`, `admin`) and passwords (`123`, `password`).
- **Commodity Web Scanning**: Widespread, low-sophistication probes for sensitive configuration files (`/.git/config`, `/.env`) and admin panels (`/manager/html`) from numerous unrelated IPs.
- **SMB Scanning**: Activity on port 445 from sources in Qatar and Czechia, matching signatures for `ET SCAN MS Terminal Server Traffic on Non-standard Port`. This is typical internet background noise.

## 9) Infrastructure & Behavioral Classification
- **Exploitation vs Scanning**:
  - **Exploitation**: The activity from `193.32.162.28` (React2Shell) and `185.231.33.22` (VNC Auth Bypass) was confirmed exploitation.
  - **Scanning/Recon**: The ICS protocol interactions, SSH activity from ASN 47890, and general web/SMB probes constitute scanning and reconnaissance.
- **Campaign Shape**:
  - **Fan-Out**: The web exploit campaign from `193.32.162.28`.
  - **Fan-In**: The VNC botnet activity from `185.231.33.22`.
  - **Spray**: General web, SMB, and some SSH scanning activities.
- **Odd-Service Fingerprints**: `guardian_ast` and `kamstrup_protocol` on the Conpot honeypot.

## 10) Evidence Appendix

### Emerging n-day Item: Multi-Exploit Web Campaign (React2Shell)
- **source IPs**: `193.32.162.28` (1900 events)
- **ASNs**: `47890` (Unmanaged Ltd, Romania)
- **target ports/services**: HTTP on ports 4001, 9999, 5001, 3210, 9001, 18080, and others.
- **paths/endpoints**: `/api/route`, `/_next/server`, `/app`, `/_next`, `/api`, `/`
- **payload/artifact excerpts**:
  - `ET WEB_SPECIFIC_APPS React Server Components React2Shell Unsafe Flight Protocol Property Access (CVE-2025-55182)`
  - `ET HUNTING Javascript Prototype Pollution Attempt via __proto__ in HTTP Body`
- **temporal checks**: Activity observed from 2026-03-10T20:12:31Z to 2026-03-11T00:00:11Z.

### Botnet Mapping Item: VNC Auth-Bypass Botnet
- **source IPs**: `185.231.33.22` (9027 events)
- **ASNs**: `211720` (Datashield, Inc.), Seychelles
- **target ports/services**: VNC on port 5900
- **payload/artifact excerpts**: `ET EXPLOIT VNC Server Not Requiring Authentication (case 2)` (CVE-2006-2369)
- **temporal checks**: Concentrated within the investigation window.

## 11) Indicators of Interest
- **IPs**:
  - `193.32.162.28` (High Priority - Active Web Exploitation)
  - `185.231.33.22` (Commodity VNC Bot)
  - `2.57.122.96` (SSH Scanner)
  - `80.94.92.68` (SSH Scanner)
- **ASN**:
  - `47890` (Unmanaged Ltd - Confirmed Malicious Infrastructure)
- **CVEs**:
  - `CVE-2025-55182` (React2Shell)
  - `CVE-2006-2369` (VNC Auth Bypass)
- **URLs/Paths**:
  - `/api/route`
  - `/_next/server`
  - `/app`

## 12) Backend Tool Issues
- **Tool**: `two_level_terms_aggregated`
- **Agent**: CandidateValidationAgent
- **Issue**: During the validation of candidate `NDE-01` (React2Shell), an initial call to `two_level_terms_aggregated` failed to correctly isolate the low-volume attack signature and instead returned results for a high-volume, unrelated VNC signature.
- **Impact**: This issue weakened the initial attempt at automated correlation. However, the `CandidateValidationAgent` successfully recovered by using more specific `suricata_cve_samples` and `suricata_signature_samples` queries, which allowed validation to complete without loss of fidelity. The final conclusions are not weakened.

## 13) Agent Action Summary (Audit Trail)

- **agent_name**: ParallelInvestigationAgent
- **purpose**: Runs initial, broad data collection agents in parallel.
- **inputs_used**: `investigation_start`, `investigation_end`.
- **actions_taken**: Executed `BaselineAgent`, `KnownSignalAgent`, `CredentialNoiseAgent`, and `HoneypotSpecificAgent`.
- **key_results**:
  - Produced initial telemetry summaries covering attack volume, sources, signatures, CVEs, and honeypot-specific interactions.
  - Highlighted VNC, SMB, and unusual ICS protocols as areas of interest.
  - Identified CVE-2006-2369 and CVE-2025-55182 as key known signals.
- **errors_or_gaps**: None.

- **agent_name**: CandidateDiscoveryAgent
- **purpose**: Synthesizes parallel outputs to identify and rank threat candidates.
- **inputs_used**: `baseline_result`, `known_signals_result`, `credential_noise_result`, `honeypot_specific_result`.
- **actions_taken**: Queried for CVE-source IP correlation, aggregated web paths.
- **key_results**:
  - Generated 3 primary candidates: `NDE-01` (CVE-2025-55182), `BOT-01` (VNC activity), and `ODD-01` (ICS protocols).
  - Correctly triaged commodity web/SMB scanning for exclusion.
- **errors_or_gaps**: None.

- **agent_name**: CandidateValidationLoopAgent
- **purpose**: Iterates through candidates to validate and contextualize them.
- **inputs_used**: `candidate_discovery_result`.
- **actions_taken**: Ran 1 iteration on candidate `NDE-01`. Used `suricata_cve_samples`, `suricata_signature_samples`, and `search` (OSINT).
- **key_results**:
  - Validated `NDE-01`, re-classifying it from a potential zero-day to `emerging_n_day_exploitation`.
  - Confirmed the activity was exploitation of the `React2Shell` vulnerability (CVE-2025-55182) from a single source IP.
- **errors_or_gaps**: Encountered a minor issue with `two_level_terms_aggregated` but successfully worked around it.

- **agent_name**: DeepInvestigationLoopController
- **purpose**: Performs deep-dive, pivot-based investigation on high-value leads.
- **inputs_used**: Validated candidate `NDE-01` lead (`src_ip:193.32.162.28`).
- **actions_taken**: Ran 5 iterations. Pivoted from source IP to ASN, and from ASN to other IPs and signatures. Used `events_for_src_ip`, `first_last_seen_src_ip`, `top_http_urls_for_src_ip`, `complete_custom_search`, and `suricata_signature_samples`.
- **key_results**:
  - Confirmed the attacker (`193.32.162.28`) was also using Prototype Pollution techniques.
  - Discovered that the source ASN (`47890`) hosted other actors engaged in different forms of SSH scanning.
  - Successfully separated and defined three distinct campaigns/activity groups.
- **errors_or_gaps**: None. Exited loop via `exit_loop` command once context was established.

- **agent_name**: OSINTAgent
- **purpose**: Enriches findings with public intelligence.
- **inputs_used**: Initial candidates `NDE-01`, `BOT-01`, `ODD-01`.
- **actions_taken**: Used `search` to look up CVEs, signatures, protocols, and IP abuse history.
- **key_results**:
  - Confirmed `CVE-2025-55182` is React2Shell.
  - Confirmed `CVE-2006-2369` is an old, well-known VNC vulnerability.
  - Confirmed `guardian_ast` and `kamstrup_protocol` are legitimate ICS protocols emulated by Conpot.
- **errors_or_gaps**: None.

- **agent_name**: ReportAgent
- **purpose**: Compiles the final report from all workflow state outputs.
- **inputs_used**: All preceding agent outputs.
- **actions_taken**: Assembled this report.
- **key_results**: This markdown document.
- **errors_or_gaps**: None.

- **agent_name**: SaveReportAgent
- **purpose**: Persists the final report artifact.
- **inputs_used**: The markdown content from ReportAgent.
- **actions_taken**: Will call `deep_agent_write_file`.
- **key_results**: Pending execution.
- **errors_or_gaps**: None.
