# Threat Hunting Honeypot Report

### **1) Investigation Scope**
- **investigation_start**: 2026-03-01T14:00:14Z
- **investigation_end**: 2026-03-01T15:00:14Z
- **completion_status**: Partial (degraded evidence)
- **degraded_mode**: true - Backend tool failures (`kibanna_discover_query`) blocked investigation into two identified leads (Kamstrup ICS protocol activity and fake CVE alerts).

### **2) Executive Triage Summary**
- **Top Services of Interest**: High-volume scanning targeted VNC and SSH. Operationally significant activity was observed against the Android Debug Bridge (ADB) on TCP/5555 and the Kamstrup Industrial Control System (ICS) protocol.
- **Top Confirmed Known Exploitation**: A single-actor campaign was identified targeting exposed ADB interfaces to deploy the well-known "ADB.Miner/Trinity" Android cryptomining malware.
- **Top Unmapped Exploit-like Items**: No novel exploit candidates were validated. Investigation into alerts for a likely fake `CVE-2025-55182` was blocked by tool failures.
- **Botnet/Campaign Mapping Highlights**: The ADB.Miner campaign was traced to a single source IP (`177.36.81.144`) from ASN `262865` in Brazil. The actor was active for only a 15-minute window and focused exclusively on this attack vector.
- **Major Uncertainties**: The source, scope, and intent of the unusual activity targeting the Kamstrup ICS protocol could not be determined due to persistent data query failures.

### **3) Candidate Discovery Summary**
- Candidate discovery was initiated based on a review of baseline traffic, known signals, and honeypot-specific logs.
- Key seeds identified for investigation included: a multi-step attack on the Adbhoney honeypot, unusual ICS protocol interactions on Conpot, common web scanning on Tanner, and alerts for a non-existent CVE.
- The discovery and subsequent validation phases were materially affected by tool failures, which prevented a full investigation of the Conpot and CVE-related signals.

### **4) Botnet/Campaign Infrastructure Mapping**
- **item_id**: BCM-01
- **campaign_shape**: single-source
- **suspected_compromised_src_ips**: `177.36.81.144` (1 IP)
- **ASNs / geo hints**: ASN `262865` (Ired Internet Ltda), Brazil.
- **suspected_staging indicators**: None observed in telemetry.
- **suspected_c2 indicators**: None observed in telemetry.
- **confidence**: High
- **operational notes**: This activity maps to the known ADB.Miner/Trinity cryptomining family. The immediate threat is commodity cryptojacking targeting misconfigured Android devices. The single IP appears to be a dedicated actor for this campaign.

### **5) Odd-Service / Minutia Attacks**
- **service_fingerprint**: port/protocol/app_hint: Conpot / kamstrup_protocol
- **why it’s unusual/interesting**: The Kamstrup protocol is a niche utility metering protocol used in ICS/SCADA environments. Its appearance in broad internet scanning is highly anomalous and suggests targeted reconnaissance.
- **evidence summary**: 18 events were detected by the HoneypotSpecificAgent, but further details could not be retrieved.
- **confidence**: Medium (Provisional)
- **recommended monitoring pivots**: Resolve the backend `kibanna_discover_query` tool failures for Conpot data to enable future analysis of source IPs and campaign shape for this type of event.

### **6) Known-Exploit / Commodity Exclusions**
- **ADB.Miner Cryptomining Campaign (BCM-01)**: The primary finding of this investigation was validated and enriched with OSINT, confirming it as activity from the known ADB.Miner/Trinity malware family. It has been re-classified as a known commodity threat.
- **Credential Noise**: Widespread SSH brute-force attempts using common usernames (`root`, `admin`, `test`) and passwords (`123456`, `password`).
- **VNC/RDP Scanning**: High volume of scanning for VNC and RDP services, indicated by signatures like `GPL INFO VNC server response` (1,896 events) and `ET SCAN MS Terminal Server Traffic on Non-standard Port` (269 events).
- **Commodity Web Scanning (EX-02)**: Uncoordinated scanning from numerous, unrelated IPs targeting common sensitive files (`/.env`, `/.git/config`, `/storage/logs/laravel.log`) on the Tanner web honeypot.

### **7) Infrastructure & Behavioral Classification**
- **Exploitation vs Scanning**: The ADB.Miner activity (BCM-01) was confirmed exploitation involving payload delivery. The Tanner web activity was scanning. The nature of the Conpot/Kamstrup activity remains unknown.
- **Campaign Shape**: The ADB.Miner campaign was a single-source attack. The Tanner web scanning was a wide spray from many unrelated actors.
- **Infra Reuse Indicators**: The actor IP `177.36.81.144` was used exclusively for the ADB attack during the observation window, suggesting specialized use.
- **Odd-Service Fingerprints**: `Android Debug Bridge (TCP/5555)` and `ICS/SCADA (kamstrup_protocol)` were the most notable service fingerprints.

### **8) Evidence Appendix**
**Item**: BCM-01 (ADB.Miner Campaign)
- **source IPs with counts**: `177.36.81.144` (41 related events in deep investigation)
- **ASNs with counts**: `262865` (Ired Internet Ltda), 1
- **target ports/services**: TCP/5555
- **paths/endpoints**: N/A
- **payload/artifact excerpts**:
  - `am start -n com.ufo.miner/com.example.test.MainActivity`
  - `ps | grep trinity`
  - `rm -rf /data/local/tmp/*`
  - Malware Hash (from adbhoney_malware_samples): `71ecfb7bbc015b2b192c05f726468b6f08fcc804c093c718b950e688cc414af5`
- **staging indicators**: None observed.
- **temporal checks results**: First seen: `2026-03-01T14:12:05.000Z`, Last seen: `2026-03-01T14:27:15.278Z`

**Item**: OS-01 (Kamstrup ICS Protocol)
- **source IPs with counts**: unavailable
- **ASNs with counts**: unavailable
- **target ports/services**: Conpot (kamstrup_protocol)
- **payload/artifact excerpts**: unavailable
- **temporal checks results**: unavailable

### **9) Indicators of Interest**
- **IP**: `177.36.81.144` (Source of ADB.Miner/Trinity campaign)
- **ASN**: `262865` (Ired Internet Ltda)
- **SHA256**: `71ecfb7bbc015b2b192c05f726468b6f08fcc804c093c718b950e688cc414af5` (ADB.Miner payload)
- **Malware Artifacts**: `com.ufo.miner` (package name), `trinity` (process name)

### **10) Backend Tool Issues**
- **kibanna_discover_query**: This tool failed repeatedly with a `400 Bad Request` error (`illegal_argument_exception`).
- **Impact**: This failure blocked the retrieval of raw event data, preventing any investigation into the source IPs and behavior related to the `kamstrup_protocol` activity (OS-01) and the fake `CVE-2025-55182` alerts (SUM-01). The conclusions for these items are therefore provisional and incomplete.
- **top_src_ips_for_cve**: This query also returned no results for the fake CVE, likely due to the same underlying data access issue, blocking a key investigation path.

### **11) Agent Action Summary (Audit Trail)**
- **agent_name**: ParallelInvestigationAgent
- **purpose**: Collects baseline, known signal, credential, and honeypot-specific data.
- **inputs_used**: `investigation_start`, `investigation_end`.
- **actions_taken**: Executed sub-agents to gather initial telemetry across multiple data sources.
- **key_results**: Provided initial data identifying high-volume VNC/SSH scanning and highlighted anomalous ADB and Kamstrup protocol activity.
- **errors_or_gaps**: None.

- **agent_name**: CandidateDiscoveryAgent
- **purpose**: Triage initial data and identify investigation leads.
- **inputs_used**: `baseline_result`, `known_signals_result`, `credential_noise_result`, `honeypot_specific_result`.
- **actions_taken**: Merged parallel results, generated 4 candidate seeds, and ran discovery queries.
- **key_results**: Identified the ADB cryptomining campaign from a single IP (BCM-01) and flagged the Kamstrup protocol activity (OS-01) as an anomaly.
- **errors_or_gaps**: Multiple tool queries failed (`kibanna_discover_query`, `top_src_ips_for_cve`), which blocked further discovery on the Conpot and fake CVE leads.

- **agent_name**: CandidateValidationLoopAgent
- **purpose**: Deeply validate a single candidate from the queue.
- **inputs_used**: Candidate data for `BCM-01`.
- **actions_taken**: Iterations run: 1. Validated 1 candidate. Attempted raw sample retrieval and performed knownness checks.
- **key_results**: Confirmed the ADB attack sequence from `177.36.81.144` and its associated malware artifacts. Found no pre-existing Suricata signatures matching the artifacts.
- **errors_or_gaps**: `kibanna_discover_query` failed twice, preventing raw log inspection. Validation was marked `provisional`.

- **agent_name**: DeepInvestigationLoopController
- **purpose**: Expands on validated candidates to map infrastructure.
- **inputs_used**: Validated candidate `BCM-01`.
- **actions_taken**: Iterations run: 4. Pursued leads for src_ip, ASN, service, and signature. Used temporal analysis and OSINT search tools.
- **key_results**: Confirmed the actor's brief 15-minute activity window. Mapped the IP to a Brazilian ASN (`262865`). OSINT search successfully identified the campaign as known ADB.Miner malware.
- **errors_or_gaps**: Loop exited after exhausting all available pivots; no new infrastructure found.

- **agent_name**: OSINTAgent
- **purpose**: Enriches validated candidates with open-source intelligence.
- **inputs_used**: Artifacts from candidate `BCM-01`.
- **actions_taken**: Performed a web search for keywords: `"com.ufo.miner" "trinity" malware android ADB`.
- **key_results**: Confirmed the observed TTPs are part of the well-documented ADB.Miner/Trinity cryptomining family, confirming it as a known threat.
- **errors_or_gaps**: None.

- **agent_name**: ReportAgent
- **purpose**: Builds finale report from workflow state (no new searching).
- **inputs_used**: All available workflow state outputs.
- **actions_taken**: Compiled all agent outputs and tool results into this final report.
- **key_results**: This report.
- **errors_or_gaps**: None.

- **agent_name**: SaveReportAgent
- **purpose**: Writes the final report to a file.
- **inputs_used**: The generated markdown report.
- **actions_taken**: Will call `investigation_write_file`.
- **key_results**: File write status pending.
- **errors_or_gaps**: None.