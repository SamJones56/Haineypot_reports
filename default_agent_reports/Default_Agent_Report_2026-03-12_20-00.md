# Honeypot Threat Hunting Report

## 1) Investigation Scope
- **investigation_start**: 2026-03-12T20:00:13Z
- **investigation_end**: 2026-03-13T00:00:13Z
- **completion_status**: Partial (degraded evidence)
- **degraded_mode**: true
  - **Reason**: The investigation was hindered by the inability to retrieve raw event logs for the Conpot (ICS) honeypot. This blocked the validation of unusual activity involving the `kamstrup_protocol`, preventing source IP identification and intent analysis.

## 2) Executive Triage Summary
- **Top Services/Ports of Interest**: 
  - **Port 5900 (VNC)**: Overwhelmingly the highest volume of traffic, consisting of commodity scanning noise.
  - **Port 445 (SMB)**: Targeted by a significant, single-source exploit campaign for the DoublePulsar backdoor.
  - **Port 80 (HTTP)**: Utilized in a coordinated, multi-source campaign scanning for sensitive web configuration files.
  - **Port 102 (S7/ICS - Assumed)**: Associated with anomalous and unverified activity involving the `kamstrup_protocol`, an ICS/SCADA protocol.
- **Top Confirmed Known Exploitation**: A high-volume DoublePulsar backdoor installation campaign was identified, originating from the IP `118.99.79.48` in Indonesia.
- **Unmapped Exploit-like Items**: No novel or unmapped exploit candidates were validated in this window.
- **Botnet/Campaign Mapping Highlights**: 
  - A single-source "fan-out" campaign (`118.99.79.48`) was responsible for all observed DoublePulsar activity.
  - A multi-source "spray" campaign, involving numerous IPs, was observed systematically scanning for `.env` and `.aws/credentials` files.
- **Major Uncertainties**: The source, nature, and intent of the 21 observed `kamstrup_protocol` events are unknown due to backend data retrieval failures. This finding is provisional and requires follow-up.

## 3) Candidate Discovery Summary
The discovery process merged data from baseline, known signature, and honeypot-specific agents to identify three primary areas of interest. The dominant traffic patterns, including VNC scanning and common credential brute-forcing, were flagged for exclusion. The investigation was materially affected by failed queries for Conpot honeypot data, which prevented a full assessment of a potential threat targeting ICS protocols.

- **Total Attacks Analyzed**: 35,714
- **Candidates Generated**: 3
  - **BOT-01**: Coordinated web scanning for sensitive configuration files.
  - **BOT-02**: High-volume, single-source DoublePulsar exploit activity.
  - **ODD-01**: Anomalous ICS/SCADA protocol (`kamstrup_protocol`) interaction.

## 6) Botnet/Campaign Infrastructure Mapping

### Web Configuration File Scanning Campaign
- **item_id**: BOT-01
- **campaign_shape**: spray
- **suspected_compromised_src_ips**: `185.177.72.23`, `185.177.72.38`, `209.38.224.165`, `45.148.10.119`, `78.153.140.39`, `34.158.79.105`, `170.64.194.42`
- **ASNs / geo hints**: ASNs `211590` (France), `14061` (DigitalOcean, Germany/Australia), `48090` (The Netherlands), `202306` (United Kingdom), `396982` (Google, The Netherlands). The infrastructure is geographically diverse, typical of a botnet.
- **suspected_staging indicators**: None observed. The activity appears to be direct reconnaissance scanning.
- **suspected_c2 indicators**: None observed.
- **confidence**: High
- **operational notes**: This is a common but high-signal reconnaissance pattern. The identified source IPs should be added to blocklists and monitored for other malicious activity.

### DoublePulsar Exploit Campaign
- **item_id**: BOT-02
- **campaign_shape**: fan-out
- **suspected_compromised_src_ips**: `118.99.79.48`
- **ASNs / geo hints**: ASN `17451` (BIZNET NETWORKS, Indonesia)
- **suspected_staging indicators**: None observed.
- **suspected_c2 indicators**: None observed. The signature is for the backdoor installation, not post-compromise C2 traffic.
- **confidence**: High
- **operational notes**: This activity represents active exploitation of a known, potent vulnerability. The source IP `118.99.79.48` should be immediately blocked.

## 7) Odd-Service / Minutia Attacks

### Anomalous ICS/SCADA Protocol Activity
- **provisional**: True
- **service_fingerprint**: `kamstrup_protocol` on Conpot (ICS Honeypot), likely on port 102.
- **why it’s unusual/interesting**: Kamstrup is a proprietary protocol used for utility and energy metering systems. Unsolicited interaction on a honeypot suggests targeted reconnaissance or scanning for industrial control systems, which is a rare and potentially high-impact event.
- **evidence summary**: 21 events referencing `kamstrup_protocol` were reported in initial aggregations. However, raw logs could not be retrieved for validation.
- **confidence**: Low
- **recommended monitoring pivots**: The primary action is to investigate the data pipeline failure for Conpot logs. If logs can be recovered, a follow-up investigation should be initiated to identify the source IP(s) and analyze the payload data.

## 8) Known-Exploit / Commodity Exclusions
- **VNC Scanning**: The vast majority of traffic (21,931 events) was related to the `GPL INFO VNC server response` signature on port 5900. This is background noise from automated scanners, with `185.231.33.22` (Seychelles) being the top source.
- **Credential Noise**: Standard brute-force login attempts were observed across various services, using common usernames (`root`, `admin`, `test`) and passwords (`password`, `123456`). This activity is considered commodity background noise.
- **Web Scanning (General)**: The Tanner honeypot observed 1,702 total events, the majority of which were generic scans for common web paths (`/`) from a wide array of sources, distinct from the targeted `.env` campaign.

## 9) Infrastructure & Behavioral Classification
- **exploitation vs scanning**: The workflow identified both active exploitation (BOT-02, DoublePulsar) and reconnaissance scanning (BOT-01, `.env` files). The intent of the ODD-01 (Kamstrup) activity is unknown.
- **campaign shape**: A "fan-out" shape was observed for the single-source DoublePulsar campaign, and a "spray" shape was observed for the multi-source `.env` scanning campaign.
- **infra reuse indicators**: The `.env` scanning campaign showed clear signs of infrastructure reuse, with multiple IPs from different ASNs conducting identical scans.
- **odd-service fingerprints**: The detection of `kamstrup_protocol` is a significant odd-service finding, though its validation is incomplete.

## 10) Evidence Appendix

### BOT-01: Web Configuration File Scanning
- **source IPs with counts**: `78.153.140.39` (4+), `185.177.72.38` (2+), `185.177.72.23` (2+), `209.38.224.165` (1+), `45.148.10.119` (1+), `34.158.79.105` (1+), `170.64.194.42` (1+)
- **ASNs with counts**: `202306` (4+), `211590` (3+), `14061` (2+), `396982` (1+), `48090` (1+)
- **target ports/services**: 80 (HTTP)
- **paths/endpoints**: `/.env` (10 hits), `/.aws/credentials` (4 hits), `/.env.development` (4 hits), `/.env.local` (4 hits), `/.env.production` (4 hits)
- **payload/artifact excerpts**: N/A (GET requests for paths)
- **staging indicators**: None
- **temporal checks results**: unavailable

### BOT-02: DoublePulsar Exploit Campaign
- **source IPs with counts**: `118.99.79.48` (3,107+ hits on port 445)
- **ASNs with counts**: `17451` (BIZNET NETWORKS) (3,107+)
- **target ports/services**: 445 (SMB)
- **paths/endpoints**: N/A
- **payload/artifact excerpts**: Suricata alert signature: `ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication` (1,287 alerts)
- **staging indicators**: None
- **temporal checks results**: unavailable

### ODD-01: Anomalous ICS/SCADA Protocol Activity
- **source IPs with counts**: unavailable
- **ASNs with counts**: unavailable
- **target ports/services**: Conpot Honeypot (assumed port 102)
- **paths/endpoints**: N/A
- **payload/artifact excerpts**: Protocol name `kamstrup_protocol` (21 hits). Raw payloads were unavailable.
- **staging indicators**: None
- **temporal checks results**: unavailable

## 11) Indicators of Interest
- **IPs (High Confidence)**:
  - `118.99.79.48` (DoublePulsar exploit source)
  - `185.177.72.23` (`.env` scanning)
  - `185.177.72.38` (`.env` scanning)
  - `209.38.224.165` (`.env` scanning)
  - `45.148.10.119` (`.env` scanning)
  - `78.153.140.39` (`.env` scanning)
- **Paths (High Confidence)**:
  - `/.env`
  - `/.aws/credentials`
  - `/.env.production`
- **Payload Fragments / Signatures (High Confidence)**:
  - `ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication`

## 12) Backend Tool Issues
- **`kibanna_discover_query`**: This tool failed to retrieve raw event logs for the `Conpot` honeypot (`type.keyword: 'Conpot'`), returning 0 results despite initial aggregate data showing 21 hits.
  - **Affected Validation**: This failure directly blocked the validation of candidate **ODD-01**, preventing the identification of the source IP, the timeline of the interaction, and the nature of the payloads for the `kamstrup_protocol` activity. This is the primary reason the investigation is classified as "Partial".
- **`suricata_lenient_phrase_search`**: This tool failed to find alerts using the phrase "DoublePulsar", which was inconsistent with aggregate data from the KnownSignalAgent.
  - **Affected Validation**: This weakened the direct discovery path for candidate **BOT-02**. The analyst had to pivot and use IP-based evidence (`118.99.79.48`) to confirm the activity, which was successful but less direct.

## 13) Agent Action Summary (Audit Trail)

- **agent_name**: ParallelInvestigationAgent
- **purpose**: To gather broad, concurrent baseline data from different perspectives (network, signature, honeypot).
- **inputs_used**: `investigation_start`, `investigation_end`.
- **actions_taken**: Executed parallel queries for total attacks, top countries, top IPs, alert signatures, CVEs, common credentials, and honeypot-specific interactions (`Tanner`, `Conpot`, etc.).
- **key_results**: 
  - Identified high-volume VNC scanning (port 5900).
  - Flagged 1,287 "DoublePulsar" alerts.
  - Detected a web scanning campaign for `.env` files via Tanner.
  - Detected 21 anomalous `kamstrup_protocol` events via Conpot.
- **errors_or_gaps**: None.

- **agent_name**: CandidateDiscoveryAgent
- **purpose**: To synthesize parallel data, exclude commodity noise, and generate high-signal candidates for validation.
- **inputs_used**: `baseline_result`, `known_signals_result`, `credential_noise_result`, `honeypot_specific_result`.
- **actions_taken**: Merged inputs, identified three primary seeds, and ran targeted queries (`kibanna_discover_query`, `two_level_terms_aggregated`) to enrich and classify them.
- **key_results**: 
  - Produced three structured candidates: BOT-01 (Web Scanning), BOT-02 (DoublePulsar), ODD-01 (Kamstrup).
  - Determined campaign shapes ('spray' for BOT-01, 'fan-out' for BOT-02).
- **errors_or_gaps**: Tool calls for `suricata_lenient_phrase_search` and `kibanna_discover_query` (for Conpot) failed, triggering `degraded_mode`.

- **agent_name**: CandidateValidationLoopAgent
- **purpose**: To iteratively investigate and validate each discovered candidate.
- **iterations run**: 3 of 3.
- **inputs_used**: `candidate_discovery_result`.
- **actions_taken**: For each candidate, ran specific validation queries (`suricata_signature_samples`, `events_for_src_ip`, `kibanna_discover_query`) and OSINT checks (`search`).
- **key_results**: 
  - Validated BOT-01, confirming multiple source IPs and target paths.
  - Validated BOT-02, confirming the link between IP `118.99.79.48` and the DoublePulsar signature.
  - Marked ODD-01 as `provisional` because the necessary raw logs could not be retrieved.
- **errors_or_gaps**: The `kibanna_discover_query` tool failed to retrieve Conpot events, blocking validation for ODD-01.

- **agent_name**: DeepInvestigationLoopController
- **purpose**: To perform deep, multi-turn investigations on high-value or novel leads.
- **iterations run**: 0. The loop was not activated in this workflow.
- **inputs_used**: N/A.
- **actions_taken**: N/A.
- **key_results**: N/A.
- **errors_or_gaps**: N/A.

- **agent_name**: OSINTAgent
- **purpose**: To enrich and validate findings against public threat intelligence.
- **inputs_used**: `validated_candidates`.
- **actions_taken**: Ran `search` queries for `.env` scanning, the DoublePulsar exploit, and the Kamstrup protocol.
- **key_results**: 
  - Confirmed BOT-01 and BOT-02 relate to established, non-novel techniques and malware.
  - Confirmed ODD-01 involves a niche ICS protocol, increasing concern but finding no public exploits.
- **errors_or_gaps**: None.

- **agent_name**: ReportAgent
- **purpose**: To compile the final report from all workflow state outputs.
- **inputs_used**: All previous agent outputs.
- **actions_taken**: Assembled this markdown report.
- **key_results**: Report generated successfully.
- **errors_or_gaps**: None.