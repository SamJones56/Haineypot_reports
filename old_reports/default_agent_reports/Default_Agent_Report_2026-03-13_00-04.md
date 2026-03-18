# Investigation Report: Threat Analysis for 2026-03-13

## 1) Investigation Scope
- **investigation_start:** 2026-03-13T00:00:11Z
- **investigation_end:** 2026-03-13T04:00:11Z
- **completion_status:** Partial (degraded evidence)
- **degraded_mode:** true. The investigation was unable to retrieve raw event data from the Conpot ICS honeypot. This prevented the identification of source IPs and infrastructure for the observed Kamstrup protocol activity, weakening the conclusion for that specific finding.

## 2) Executive Triage Summary
- **Top Services of Interest:** The majority of activity targeted VNC (port 5900), followed by SMB (port 445) and Android Debug Bridge (ADB) on port 5555.
- **Top Confirmed Known Exploitation:** The environment was dominated by three distinct, known campaigns:
    1.  Widespread VNC scanning exploiting an authentication bypass vulnerability (CVE-2006-2369).
    2.  Targeted activity from the ADB.Miner/Trinity cryptomining botnet against Android devices.
    3.  DoublePulsar backdoor installation attempts, likely related to EternalBlue exploits against SMB.
- **Unmapped Exploit-like Items:** No novel or unmapped exploit candidates were identified in this window. All significant exploit-like behavior was successfully mapped to known threats.
- **Botnet/Campaign Mapping Highlights:** A large-scale VNC scanning campaign (`spray`) was identified originating primarily from ASNs in Seychelles and Bulgaria. A separate, more focused Android cryptomining campaign (`fan-out`) was observed from a single IP in South Korea.
- **Odd-Service / Minutia Attacks:** Low-volume scanning for the Kamstrup smart meter protocol (an ICS-related protocol) was detected. This is unusual and suggests targeted reconnaissance of industrial or utility systems.
- **Major Uncertainties:** The source infrastructure (IPs, ASNs, geo) for the Kamstrup ICS scanning remains unknown due to persistent data retrieval failures from the Conpot honeypot.

## 3) Candidate Discovery Summary
Initial analysis of baseline, known signal, and honeypot-specific data led to the discovery of several areas of interest. High-volume VNC alerts, DoublePulsar backdoor signatures, and specific commands in the ADBHoney and Conpot logs formed the basis for candidate generation. Discovery was partially hindered by query failures when attempting to find source IPs for DoublePulsar and Conpot events, requiring deeper validation to resolve or confirm the evidence gap.

## 4) Botnet/Campaign Infrastructure Mapping

### VNC Scanning Campaign (Commodity)
- **item_id:** BOT-01
- **campaign_shape:** spray
- **suspected_compromised_src_ips:** 185.231.33.22 (15,444 events), 79.124.40.98 (2,000 events)
- **ASNs / geo hints:** ASN 211720 (Datashield, Inc., Seychelles), ASN 50360 (Tamatiya EOOD, Bulgaria)
- **suspected_staging indicators:** None identified.
- **suspected_c2 indicators:** None identified.
- **confidence:** High
- **operational notes:** This is a high-volume, commodity scanning campaign for vulnerable VNC servers (CVE-2006-2369). IPs and ASNs should be monitored for continued activity.

### ADB.Miner/Trinity Cryptomining Botnet (Commodity)
- **item_id:** BOT-02
- **campaign_shape:** fan-out
- **suspected_compromised_src_ips:** 121.181.94.166
- **ASNs / geo hints:** ASN 4766 (Korea Telecom, South Korea)
- **suspected_staging indicators:** Payloads named `trinity` and `ufo.miner` were executed, and malware samples were downloaded to the `/data/local/tmp/` directory.
- **suspected_c2 indicators:** None directly observed, but the malware is known to communicate with mining pools.
- **confidence:** High
- **operational notes:** This activity matches the TTPs of the well-documented ADB.Miner/Trinity botnet. The primary follow-up is to analyze the captured malware samples to extract C2 and cryptocurrency wallet information.

### DoublePulsar Backdoor Campaign (Commodity)
- **item_id:** MIN-01
- **campaign_shape:** fan-out
- **suspected_compromised_src_ips:** 113.160.202.170
- **ASNs / geo hints:** (Unavailable)
- **suspected_staging indicators:** None identified; this is the installation phase.
- **suspected_c2 indicators:** None identified.
- **confidence:** High
- **operational notes:** This is a known backdoor installation attempt targeting the SMB service (port 445), likely using the EternalBlue exploit.

## 5) Odd-Service / Minutia Attacks

### Kamstrup Protocol Scanning (ICS)
- **service_fingerprint:** port: 1025, protocol: tcp, app_hint: Kamstrup (ICS/Smart Meter)
- **why it’s unusual/interesting:** Kamstrup is a niche protocol used in smart utility meters. Scanning for this protocol is not typical internet background noise and suggests targeted reconnaissance against Industrial Control Systems (ICS) or smart grid infrastructure.
- **evidence summary:** 45 total events detected by the Conpot honeypot, including `kamstrup_protocol` (42 events) and `kamstrup_management_protocol` (3 events).
- **confidence:** Medium
- **recommended monitoring pivots:** Prioritize fixing the data retrieval pipeline for the Conpot honeypot to enable source identification for this activity in subsequent investigation windows.

## 6) Known-Exploit / Commodity Exclusions
- **Credential Noise:** Standard brute-force login attempts were observed across multiple services, using common usernames like `root`, `admin`, `user` and passwords such as `qwerty`, `123456`, and `345gs5662d34`.
- **Known Bot Patterns & Scanners:**
    - The high-volume VNC activity (21,000+ events) is linked to CVE-2006-2369, a well-known VNC authentication bypass.
    - The ADB activity (44 events) is mapped to the established ADB.Miner/Trinity cryptomining botnet.
    - The DoublePulsar alerts (1,444 events) are associated with the infamous backdoor often delivered via the EternalBlue SMB exploit.
    - Web scanners were observed making generic requests for files like `/`, `/.env`, and `/robots.txt` via the Tanner honeypot.
    - Redis scanners were observed sending commands like `info` and `ping`.

## 7) Infrastructure & Behavioral Classification
- **exploitation vs scanning:** The VNC, ADB, and DoublePulsar activities were clear exploitation attempts. The Kamstrup activity was classified as targeted reconnaissance/scanning. General web and Redis activity was untargeted scanning.
- **campaign shape:** The VNC campaign (`BOT-01`) was a large-scale `spray` from multiple sources. The ADB (`BOT-02`) and DoublePulsar (`MIN-01`) campaigns were `fan-out` from single sources within this timeframe. The Kamstrup campaign shape is `unknown` due to missing source data.
- **infra reuse indicators:** No infrastructure reuse was observed between the distinct campaigns (VNC, ADB, DoublePulsar).
- **odd-service fingerprints:** `kamstrup_protocol` on TCP/1025 targeting ICS infrastructure.

## 8) Evidence Appendix

### BOT-01: VNC Scanning Campaign
- **source IPs:** `185.231.33.22` (15,444 hits), `79.124.40.98` (2,000 hits)
- **ASNs:** `211720` (Datashield, Inc.), `50360` (Tamatiya EOOD)
- **target ports/services:** 5900/tcp (VNC)
- **payload/artifact excerpts:** `GPL INFO VNC server response`, `ET EXPLOIT VNC Server Not Requiring Authentication (case 2)`
- **staging indicators:** None
- **temporal checks results:** Consistent high-volume activity throughout the window.

### BOT-02: ADB.Miner/Trinity Campaign
- **source IPs:** `121.181.94.166`
- **ASNs:** `4766` (Korea Telecom)
- **target ports/services:** 5555/tcp (ADB)
- **payload/artifact excerpts:** `rm -rf /data/local/tmp/*`, `/data/local/tmp/nohup /data/local/tmp/trinity`, `am start -n com.ufo.miner/com.example.test.MainActivity`
- **staging indicators:** `dl/0d3c687ffc30e185b836b99bd07fa2b0d460a090626f6bbbd40a95b98ea70257.raw`
- **temporal checks results:** Activity occurred in a focused burst.

### MIN-01: DoublePulsar Backdoor Activity
- **source IPs:** `113.160.202.170`
- **ASNs:** (Unavailable)
- **target ports/services:** 445/tcp (SMB)
- **payload/artifact excerpts:** `ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication`
- **staging indicators:** None
- **temporal checks results:** Activity occurred in a focused burst.

## 9) Indicators of Interest
- **IPs:**
    - `185.231.33.22` (VNC Scanning)
    - `79.124.40.98` (VNC Scanning)
    - `121.181.94.166` (ADB.Miner/Trinity)
    - `113.160.202.170` (DoublePulsar)
- **Payloads/Commands:**
    - `trinity` (ADB malware)
    - `ufo.miner` (ADB malware)
    - `kamstrup_protocol` (ICS scanning)
- **Signatures / CVEs:**
    - `CVE-2006-2369` (VNC Auth Bypass)
    - `ET EXPLOIT VNC Server Not Requiring Authentication (case 2)`
    - `ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication`
- **Malware Hashes:**
    - `0d3c687ffc30e185b836b99bd07fa2b0d460a090626f6bbbd40a95b98ea70257` (Associated with ADB.Miner/Trinity)

## 10) Backend Tool Issues
- **kibanna_discover_query:** This tool consistently failed to retrieve any raw event data for the `Conpot` honeypot. This failure was the primary reason for the `Partial` completion status, as it completely blocked the validation of source infrastructure for the `ODD-01` (Kamstrup) candidate, forcing it to be marked as `Provisional`.
- **suricata_lenient_phrase_search:** The initial query by the `CandidateDiscoveryAgent` to find source IPs for `DoublePulsar` failed, creating a temporary evidence gap. This was later mitigated during validation using a different tool (`suricata_signature_samples`).
- **two_level_terms_aggregated:** This tool failed during two separate validation steps due to queries on non-aggregatable fields or empty data sets (Dionaea). Pivots to other tools were required, indicating a limitation in its flexibility.

## 11) Agent Action Summary (Audit Trail)
- **agent_name:** ParallelInvestigationAgent
- **purpose:** Gather high-level, aggregated telemetry for the time window.
- **inputs_used:** `investigation_start`, `investigation_end`.
- **actions_taken:** Executed four sub-agents (Baseline, KnownSignal, CredentialNoise, HoneypotSpecific) to query top IPs, ASNs, signatures, CVEs, credentials, and honeypot artifacts.
- **key_results:** Identified high-volume VNC scanning from Seychelles, DoublePulsar alerts, ADB.Miner commands, and Kamstrup protocol events.
- **errors_or_gaps:** None.

- **agent_name:** CandidateDiscoveryAgent
- **purpose:** Sift through initial telemetry to identify potential threats for further investigation.
- **inputs_used:** All outputs from the `ParallelInvestigationAgent`.
- **actions_taken:** Pivoted from key artifacts (e.g., "DoublePulsar", "trinity") to identify related infrastructure. Attempted to query source IPs for all suspicious activity.
- **key_results:** Generated five candidates: `NDE-01` (VNC Exploit), `BOT-01` (VNC Campaign), `BOT-02` (ADB Campaign), `ODD-01` (Kamstrup Scan), `MIN-01` (DoublePulsar Activity).
- **errors_or_gaps:** Failed to retrieve source IPs for DoublePulsar and Conpot events due to tool errors (`suricata_lenient_phrase_search`, `kibanna_discover_query`), leading to degraded initial findings.

- **agent_name:** CandidateValidationLoopAgent
- **purpose:** Iteratively validate each discovered candidate for knownness, infrastructure, and novelty.
- **inputs_used:** Candidate list from `CandidateDiscoveryAgent`.
- **actions_taken:** Ran 5 iterations, one for each candidate. Used a variety of tools to query for event samples (`suricata_signature_samples`), aggregate data (`top_src_ips_for_cve`), and perform external lookups (`search`).
- **key_results:** Validated all 5 candidates. Mapped VNC, ADB, and DoublePulsar activity to known commodity threats. Confirmed Kamstrup as unusual but was blocked on infrastructure analysis. Successfully found the DoublePulsar source IP, resolving an earlier evidence gap.
- **errors_or_gaps:** The loop was unable to get raw Conpot logs, confirming the evidence gap for candidate `ODD-01`. Several `two_level_terms_aggregated` queries failed, requiring pivots.

- **agent_name:** OSINTAgent
- **purpose:** Enrich validated candidates with public threat intelligence.
- **inputs_used:** `validated_candidates`.
- **actions_taken:** Performed `search` queries using keywords, IPs, and signatures from each validated candidate.
- **key_results:** Confirmed that VNC, ADB.Miner, and DoublePulsar are all well-established, publicly documented threats, reducing their novelty. Confirmed Kamstrup is a niche ICS protocol, increasing the level of concern for that activity.
- **errors_or_gaps:** None.

- **agent_name:** ReportAgent
- **purpose:** Compile the final report from all workflow state outputs.
- **inputs_used:** All available workflow state keys.
- **actions_taken:** Assembled this markdown report according to the specified format.
- **key_results:** This report.
- **errors_or_gaps:** None.

- **agent_name:** SaveReportAgent
- **purpose:** Persist the final report.
- **inputs_used:** Final report content from `ReportAgent`.
- **actions_taken:** Called the `default_write_file` tool.
- **key_results:** File write status.
- **errors_or_gaps:** None.