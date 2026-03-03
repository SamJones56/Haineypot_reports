# Threat Hunting Honeypot Report

### 1) Investigation Scope
- **investigation_start**: `2026-03-01T18:00:15Z`
- **investigation_end**: `2026-03-01T19:00:15Z`
- **completion_status**: Partial (degraded evidence)
- **degraded_mode**: true - Multiple backend tool failures (`kibanna_discover_query`, `suricata_lenient_phrase_search`) prevented the full investigation of two high-priority leads: an unusual ICS protocol (`guardian_ast`) and a high-volume VNC scanning campaign.

### 2) Executive Triage Summary
- **Top Services/Ports of Interest**: High volume of scanning was observed against common services like SSH (22) and VNC (5925, 5926).
- **Odd/Minutia Service Highlights**: The most notable finding was a connection to a Minecraft service port (25565) from a source fingerprinted by P0f as a "Nintendo 3DS". Subsequent investigation reclassified this as a known, automated scanner.
- **Uninvestigated Odd-Service Activity**: Activity involving the `guardian_ast` Industrial Control System (ICS) protocol was detected on the Conpot honeypot but could not be investigated due to persistent tool failures.
- **Top Confirmed Known Exploitation**: Activity was dominated by commodity scanning and brute-force attempts. This includes widespread VNC scanning, SSH credential stuffing, and probes for common web misconfigurations (`/.env`, `/_profiler/phpinfo`).
- **Unmapped Campaigns**: A high-volume VNC scanning campaign was identified but could not be mapped due to tool failures, leaving its infrastructure and coordination patterns unknown.
- **Major Uncertainties**: The nature and source of the `guardian_ast` ICS protocol activity remain unknown. The scale and infrastructure of the VNC scanning campaign are also unconfirmed.

### 3) Candidate Discovery Summary
- **Initial Seeds Identified**: 
    - An unusual client OS ("Nintendo 3DS") connecting to the Minecraft port (25565).
    - An unusual ICS protocol (`guardian_ast`) on the Conpot honeypot.
    - High-volume VNC scanning activity.
    - Isolated web probes for sensitive files (`/_profiler/phpinfo`, `/.env`).
- **Discovery Process Notes**: The discovery process was materially affected by the failure of the `kibanna_discover_query` tool, which blocked initial attempts to gather context on the `guardian_ast` protocol activity.

### 4) Odd-Service / Minutia Attacks
**Item 1: Minecraft Scanner with Misleading OS Fingerprint**
- **service_fingerprint**: `port:25565/tcp`, `app_hint:Minecraft`, `client_os_fingerprint:Nintendo 3DS`
- **why it’s unusual/interesting**: An initial P0f signature identified the client as a "Nintendo 3DS", which is highly anomalous for server scanning activity. Deep investigation and OSINT revealed the fingerprint was likely spoofed or a misidentification by a known scanning tool.
- **evidence summary**: A single source IP, `51.15.34.47` (AS12876 - Scaleway), made 7 connections to port 25565. OSINT confirmed this IP is a known "Minecraft server scanner" with extensive public abuse reports.
- **confidence**: High (reclassified from "oddity" to "known scanner").
- **recommended monitoring pivots**: Monitor for other unusual P0f fingerprints from known scanning infrastructure (e.g., cloud provider ASNs) as a potential TTP for evading simple filters.

**Item 2: Uninvestigated ICS Protocol Activity**
- **service_fingerprint**: `protocol:guardian_ast`, `honeypot:Conpot`
- **why it’s unusual/interesting**: `guardian_ast` is a niche ICS protocol. Any interaction with it on a honeypot is noteworthy and warrants investigation for potential reconnaissance or exploit development targeting OT environments.
- **evidence summary**: Initial triage detected 4 events associated with this protocol. However, all subsequent attempts to retrieve detailed logs or source IP information failed due to backend tool errors.
- **confidence**: Low (detection is confirmed, but context is missing).
- **recommended monitoring pivots**: Fix the underlying data query tools to enable investigation of this protocol. Monitor for any further `guardian_ast` activity.

### 5) Known-Exploit / Commodity Exclusions
- **Credential Noise**: High-volume brute-force attacks against SSH (22) using common usernames (`root`, `admin`) and passwords (`123456`, `password`). Seen across many source IPs, primarily from ASN 14061 (DigitalOcean).
- **Commodity Scanning**:
    - **VNC Scanning**: Widespread scanning activity detected by signature "GPL INFO VNC server response" (1,999 events).
    - **Web Probes**: Isolated, uncoordinated requests for sensitive paths like `/.env` and `/_profiler/phpinfo` from single-source IPs.
    - **Minecraft Server Scanning**: The activity initially flagged as "Nintendo 3DS" was confirmed via OSINT to be a known, automated scanner targeting port 25565.

### 6) Infrastructure & Behavioral Classification
- **exploitation vs scanning**: The vast majority of activity (99%+) was classified as scanning or credential stuffing. No successful exploitation was observed.
- **campaign shape**:
    - The Minecraft scanner was a single IP targeting a specific service.
    - The VNC scanning appeared to be a broad "spray" campaign, but infrastructure mapping failed.
    - The `guardian_ast` activity shape is unknown.
- **infra reuse indicators**: ASN 14061 (DigitalOcean) was the source of a significant volume (11,775 events) of generic scanning activity. The Minecraft scanner originated from ASN 12876 (Scaleway), a known source of scanning tooling.
- **odd-service fingerprints**:
    - `p0f:Nintendo 3DS -> port:25565/tcp` (Explained)
    - `conpot:guardian_ast` (Unexplained)

### 7) Evidence Appendix
**Item: Minecraft Scanner (formerly "Nintendo 3DS")**
- **source IPs with counts**: `51.15.34.47` (7 events)
- **ASNs with counts**: ASN 12876 (Scaleway S.a.s.)
- **target ports/services**: 25565/TCP (Minecraft)
- **paths/endpoints**: N/A
- **payload/artifact excerpts**: P0f OS fingerprint: "Nintendo 3DS"
- **staging indicators**: None observed.
- **temporal checks results**: First seen at `2026-03-01T18:15:01.000Z`, last seen at `2026-03-01T18:25:09.150Z`.

### 8) Indicators of Interest
- **IPs**: `51.15.34.47` (Known Minecraft scanner with misleading P0f signature)
- **Services**: `guardian_ast` (ICS protocol for monitoring)

### 9) Backend Tool Issues
- **`kibanna_discover_query`**: This tool failed repeatedly across multiple agents (`CandidateDiscoveryAgent`, `CandidateValidationAgent`, `DeepInvestigationAgent`) with an `illegal_argument_exception`. This failure directly blocked all attempts to investigate the `guardian_ast` ICS protocol activity on the Conpot honeypot.
- **`suricata_lenient_phrase_search`**: This tool failed to aggregate source IPs for the VNC scanning campaign, returning empty results. This blocked the investigation into botnet/campaign infrastructure mapping for that activity.
- **`two_level_terms_aggregated`**: This tool returned zero results when querying Conpot data, further contributing to the blocked investigation of the `guardian_ast` protocol.
- **Weakened Conclusions**: The inability to investigate the `guardian_ast` protocol and map the VNC scanning campaign are significant gaps in this report. The true risk or novelty of these events could not be assessed.

### 10) Agent Action Summary (Audit Trail)
- **agent_name**: ParallelInvestigationAgent
- **purpose**: Runs initial triage queries in parallel to gather baseline, known signal, credential, and honeypot-specific data.
- **inputs_used**: `investigation_start`, `investigation_end`.
- **actions_taken**: Executed 15+ initial data queries across its four sub-agents.
- **key_results**: Provided the foundational data for the investigation, identifying high-volume scanning, common credential stuffing, the "Nintendo 3DS" p0f record, and `guardian_ast` protocol activity.
- **errors_or_gaps**: None.

- **agent_name**: CandidateDiscoveryAgent
- **purpose**: Merges parallel results to identify and prioritize interesting leads (candidates).
- **inputs_used**: `baseline_result`, `known_signals_result`, `credential_noise_result`, `honeypot_specific_result`.
- **actions_taken**: Merged inputs, identified 4 initial seeds, and ran 5 queries to get initial context.
- **key_results**: Successfully identified the "Nintendo 3DS"/Minecraft, `guardian_ast`, and VNC scanning leads as top priorities.
- **errors_or_gaps**: Experienced multiple failures with `kibanna_discover_query`, which prevented initial analysis of the `guardian_ast` lead.

- **agent_name**: CandidateValidationLoopAgent
- **purpose**: Iterates through candidates, performs structured validation checks, and produces a validated candidate object.
- **inputs_used**: `candidate_discovery_result`.
- **actions_taken**: Ran 1 iteration on the "Nintendo 3DS" candidate.
- **key_results**: Formally validated one candidate (`candidate_id: 1`) with a classification of `odd_service_minutia`, while noting the failure to retrieve raw logs.
- **errors_or_gaps**: The `kibanna_discover_query` tool failed during validation, preventing the retrieval of raw event logs for the candidate. The loop did not proceed to other candidates.

- **agent_name**: DeepInvestigationLoopController
- **purpose**: Conducts deep-dive, unstructured investigation on high-value validated candidates or leads.
- **inputs_used**: `validated_candidates`, `candidate_discovery_result`.
- **actions_taken**: Ran 3 iterations. Pursued leads for the Nintendo 3DS IP, the `guardian_ast` protocol, and the VNC signature.
- **key_results**: Successfully re-classified the "Nintendo 3DS" activity as a known Minecraft scanner using OSINT. Confirmed the other two leads were blocked by tool failures.
- **errors_or_gaps**: Stalled twice due to persistent tool failures (`kibanna_discover_query`, `suricata_lenient_phrase_search`). Exited the loop after two consecutive stalls, leaving two high-priority leads uninvestigated.

- **agent_name**: OSINTAgent
- **purpose**: Enriches findings with public intelligence.
- **inputs_used**: `validated_candidates`.
- **actions_taken**: Performed 2 search queries related to the source IP `51.15.34.47` and the "Nintendo 3DS" p0f fingerprint.
- **key_results**: Found extensive public reporting confirming `51.15.34.47` is a known Minecraft scanner. This finding significantly reduced the novelty of the event and explained the observed behavior.
- **errors_or_gaps**: None.

- **agent_name**: ReportAgent
- **purpose**: Builds finale report from workflow state (no new searching).
- **inputs_used**: All preceding agent outputs.
- **actions_taken**: Compiled all available evidence, noted degraded mode due to tool failures, and synthesized the final report.
- **key_results**: This report.
- **errors_or_gaps**: None.

- **agent_name**: SaveReportAgent
- **purpose**: Writes the final report to storage.
- **inputs_used**: `report_content`.
- **actions_taken**: Awaiting report content for file write.
- **key_results**: Pending.
- **errors_or_gaps**: None.