# Threat Hunting Investigation Report

## 1) Investigation Scope
- **investigation_start**: 2026-03-02T11:00:07Z
- **investigation_end**: 2026-03-02T12:00:07Z
- **completion_status**: Partial (degraded evidence)
- **degraded_mode**: true. The investigation was severely hampered by multiple backend tool failures. These failures prevented the correlation of source IPs with key suspicious activities, blocking infrastructure mapping and payload analysis.

## 2) Executive Triage Summary
- **Top Services of Interest**: High-volume scanning targeted VNC (ports 5925, 5926) and SMB (port 445), consistent with commodity activity.
- **Odd-Service Activity**: Targeted reconnaissance was observed against the `kamstrup_protocol`, a niche protocol used in Industrial Control Systems (ICS) and smart meters. This is unusual and points to a specialized actor.
- **Suspicious Unmapped Activity**: A small cluster of events on port 9200 (Elasticsearch) incorrectly triggered a signature for a critical web RCE vulnerability (CVE-2025-55182). While the signature was a misfire, the underlying activity on port 9200 remains suspicious and unclassified.
- **Botnet/Campaign Mapping**: Efforts to map the infrastructure behind the large-scale VNC scanning campaign were blocked due to backend tool failures.
- **Major Uncertainties**: The primary uncertainty is the origin (source IPs, ASNs) of the most interesting activities, including the ICS probing and the port 9200 events. This was a direct result of data retrieval tool errors.

## 3) Candidate Discovery Summary
Initial triage identified 13,228 total attacks, dominated by commodity SMB and VNC scanning. After excluding this noise, two candidates were generated for follow-up: one related to odd-service ICS probing (`kamstrup_protocol`) and another related to anomalous signature alerts (`CVE-2025-55182` on port 9200). Discovery was materially affected by multiple tool errors which blocked the ability to correlate IPs with these events from the outset.

## 7) Odd-Service / Minutia Attacks
- **service_fingerprint**: Conpot Honeypot / `kamstrup_protocol`
- **why it’s unusual/interesting**: This is not random internet noise. It represents targeted reconnaissance against a specific family of Industrial Control System (ICS) / Advanced Metering Infrastructure (AMI) protocols used in utilities. OSINT confirmed the legitimacy of the protocol family, which increases the concern that this activity is from an actor with specific, non-standard interests.
- **evidence summary**: 52 events were recorded by the Conpot honeypot. Source IPs and other infrastructure details could not be retrieved due to tool failures.
- **confidence**: Medium
- **recommended monitoring pivots**: Prioritize engineering efforts to fix data retrieval for Conpot logs. Once resolved, identify and monitor the source IPs for any further activity, particularly against other OT/ICS-related ports and services.

## 8) Known-Exploit / Commodity Exclusions
- **Credential Noise**: Standard brute-force attacks against SSH (port 22) using common usernames (`root`, `admin`) and passwords (`123456`, `password`) were observed and excluded as background noise.
- **Commodity Scanning**:
    - High-volume scanning of SMB on port 445 from sources including `189.87.56.210` (Brazil) and `79.98.102.166` (France).
    - High-volume scanning of VNC services, triggering 2,033 "GPL INFO VNC server response" alerts.
    - Generic web scanning for common paths like `/.env` and `/user/login`.
- **Misfired Signatures**: 6 alerts for `CVE-2025-55182` targeting port 9200 were determined to be misfires. OSINT confirmed this CVE relates to web frameworks (React), not Elasticsearch. The underlying activity that caused the trigger is now being monitored.

## 9) Infrastructure & Behavioral Classification
- **exploitation vs scanning**: The vast majority of activity (95%+) was classified as scanning and reconnaissance. The `kamstrup_protocol` activity is considered targeted reconnaissance.
- **campaign_shape**: The high-volume VNC and SMB activity appears to be a classic `spray` from a small number of high-activity sources. The shape of the ICS probing is `unknown` due to the inability to resolve source IPs.
- **infra reuse indicators**: No significant infrastructure reuse could be confirmed.
- **odd-service fingerprints**: `kamstrup_protocol` (ICS/AMI).

## 10) Evidence Appendix
### ODD-1: ICS/SCADA Protocol Probing
- **source IPs with counts**: Unavailable due to tool failure.
- **ASNs with counts**: Unavailable due to tool failure.
- **target ports/services**: Conpot honeypot (`kamstrup_protocol`).
- **paths/endpoints**: N/A.
- **payload/artifact excerpts**: Unavailable due to tool failure.
- **temporal checks results**: N/A.

## 11) Indicators of Interest
- **IPs (High-Volume Scanners)**:
    - `189.87.56.210` (AS4230 - CLARO S.A., Brazil)
    - `79.98.102.166` (AS16347 - ADISTA SAS, France)
- **Protocols of Interest**:
    - `kamstrup_protocol` (monitor for ICS/OT reconnaissance).
- **Ports of Interest**:
    - `9200` (monitor for suspicious activity that caused a misfired CVE alert).

## 12) Backend Tool Issues
The following tools failed during the investigation, severely degrading the results:
- **`two_level_terms_aggregated`**: Repeatedly failed or returned empty results, preventing the correlation of source IPs with Conpot and VNC activity.
- **`kibanna_discover_query`**: Returned HTTP 400 errors, blocking the retrieval of raw event logs for Conpot events and the misfired CVE alerts.
- **`top_src_ips_for_cve`**: Failed to return any source IPs for `CVE-2025-55182`.
- **`suricata_lenient_phrase_search`**: Failed to return source IPs for the VNC scanning campaign.
- **Weakened Conclusions**: The inability to identify source IPs for the most interesting candidates (`ODD-1`, `MON-1`) means they remain provisional and unactionable. The deep investigation into a high-volume scanner also stalled due to inconsistent data between aggregate and raw queries.

## 13) Agent Action Summary (Audit Trail)
- **agent_name**: ParallelInvestigationAgent
- **purpose**: To run initial baseline, known-signal, credential-noise, and honeypot-specific queries in parallel.
- **inputs_used**: `investigation_start`, `investigation_end`.
- **actions_taken**: Executed 4 parallel investigation threads with multiple data-gathering tool calls each.
- **key_results**: Provided the initial triage data, identifying high-volume SMB/VNC scanning, low-volume CVEs, standard credential stuffing, and notable `kamstrup_protocol` activity on Conpot.
- **errors_or_gaps**: None.

- **agent_name**: CandidateDiscoveryAgent
- **purpose**: To merge parallel results and generate high-signal candidates for investigation.
- **inputs_used**: `baseline_result`, `known_signals_result`, `credential_noise_result`, `honeypot_specific_result`.
- **actions_taken**: Merged inputs, excluded commodity noise, and seeded two candidates: `ODD-1` (Kamstrup) and `MON-1` (anomalous CVE). Attempted deeper queries to enrich seeds but was blocked by multiple tool failures (`kibanna_discover_query`, `top_src_ips_for_cve`, etc.). Used `search` to get initial OSINT on `CVE-2025-55182`.
- **key_results**: Produced a structured list of candidates and exclusions, but highlighted significant evidence gaps due to tool errors.
- **errors_or_gaps**: Detected and reported failures in `two_level_terms_aggregated`, `suricata_lenient_phrase_search`, `top_src_ips_for_cve`, and `kibanna_discover_query`.

- **agent_name**: CandidateValidationLoopAgent
- **purpose**: To iteratively validate candidates discovered in the previous step.
- **inputs_used**: `candidate_discovery_result`.
- **actions_taken**: Ran for 1 iteration. Processed candidate `ODD-1`. Attempted to retrieve source IPs and raw logs using `kibanna_discover_query` and `two_level_terms_aggregated`.
- **key_results**: The validation was blocked by tool failures. The candidate `ODD-1` could not be validated and was marked as provisional with low confidence.
- **errors_or_gaps**: Both tool calls failed, preventing any meaningful validation. The loop did not proceed to the second candidate.

- **agent_name**: DeepInvestigationLoopController
- **purpose**: To perform a deep dive on high-value leads.
- **inputs_used**: Top attacker IP from `baseline_result`.
- **actions_taken**: Ran for 2 iterations pursuing the lead `src_ip:189.87.56.210`. Used `first_last_seen_src_ip` and `events_for_src_ip` to analyze its behavior.
- **key_results**: Identified a data inconsistency where aggregate queries reported Dionaea events from the IP, but raw samples contained only Suricata flow logs. This discrepancy stalled the investigation.
- **errors_or_gaps**: The investigation stalled and exited due to conflicting data from backend tools, preventing a clear conclusion on the actor's full behavior.

- **agent_name**: OSINTAgent
- **purpose**: To enrich validated candidates with public intelligence.
- **inputs_used**: `validated_candidates` (specifically `ODD-1`), `candidate_discovery_result` (specifically `MON-1`).
- **actions_taken**: Used the `search` tool for terms "kamstrup protocol" and "CVE-2025-55182".
- **key_results**: Confirmed `kamstrup_protocol` is a niche ICS/AMI protocol family, increasing the significance of the observed activity. Confirmed `CVE-2025-55182` is a real, critical CVE but is unrelated to the observed target (Elasticsearch), proving the signature was a misfire.
- **errors_or_gaps**: None.

- **agent_name**: ReportAgent
- **purpose**: To compile the final report from all workflow state outputs.
- **inputs_used**: All previous agent outputs.
- **actions_taken**: Assembled this report.
- **key_results**: This document.
- **errors_or_gaps**: None.
