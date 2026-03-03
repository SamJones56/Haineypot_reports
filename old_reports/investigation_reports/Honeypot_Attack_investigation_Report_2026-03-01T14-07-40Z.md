# Honeypot Threat Hunting Final Report

## 1) Investigation Scope
- **investigation_start**: 2026-03-01T13:00:10Z
- **investigation_end**: 2026-03-01T14:00:10Z
- **completion_status**: Partial (degraded evidence)
- **degraded_mode**: true. Data query tools (`kibanna_discover_query`, `suricata_lenient_phrase_search`, `two_level_terms_aggregated`) failed during the discovery and validation phases, blocking initial source IP identification for key candidates and preventing ASN correlation. Some gaps were overcome with alternative queries, but the source of the odd-service attack remains unknown.

## 2) Executive Triage Summary
- **Top Services/Ports of Interest**: Significant activity was observed against VNC services (ports 5900, 5902, 5903, 5925, 5926), SMB (port 445), and SSH (port 22).
- **Odd/Minutia Service Highlight**: Probing activity was detected against a niche Industrial Control Systems (ICS) service, the `kamstrup_protocol`, on a Conpot honeypot.
- **Top Confirmed Known Exploitation**: Probes matching known exploit patterns for Boa web servers (`/boaform/admin/formLogin`) were observed, classified as commodity scanning.
- **Top Unmapped Exploit-like Items**: No novel exploit candidates were validated in this window.
- **Botnet/Campaign Mapping Highlights**: A large-scale, coordinated VNC scanning campaign (`VNC-SCAN-20260301-1`) was identified and mapped. The campaign originates from a pool of source IPs within a single cloud provider ASN (14061, DigitalOcean, LLC).
- **Major Uncertainties**: The source IP(s) and infrastructure behind the `kamstrup_protocol` probing could not be identified due to persistent data query failures.

## 3) Candidate Discovery Summary
The discovery process identified four main areas of interest: high-volume VNC scanning, unusual ICS protocol activity (Kamstrup), a specific web exploit probe (`/boaform/`), and generic web reconnaissance (`/.env`, `/.git/HEAD`). Initial attempts to enrich these findings with source IP data were hampered by multiple query tool failures. After re-querying and using OSINT, the web probes were excluded as commodity noise, while the VNC scanning campaign and the Kamstrup ICS activity were promoted for further validation.

## 4) Emerging n-day Exploitation
| cve/signature mapping | evidence summary | affected service/port | confidence | operational notes |
| --- | --- | --- | --- | --- |
| CVE-2024-14007 | 2 events observed in Suricata alerts. | unavailable | Low | Very low signal with no corroborating evidence. Monitor for any increase in activity. |

## 5) Novel Exploit Candidates (UNMAPPED ONLY, ranked)
*No candidates met the criteria for Novel Exploit in this investigation window.*

## 6) Botnet/Campaign Infrastructure Mapping
| item_id | campaign_shape | suspected_compromised_src_ips | ASNs / geo hints | suspected_staging indicators | suspected_c2 indicators | confidence | operational notes |
| --- | --- | --- | --- | --- | --- | --- | --- |
| VNC-SCAN-20260301-1 | spray | `129.212.179.18`, `129.212.188.196`, `129.212.184.194`, `134.199.197.108` (4 of many) | ASN: 14061, DigitalOcean, LLC | None observed | None observed | High | This is a coordinated VNC scanning campaign originating from a single cloud provider ASN. Each IP scans one or more VNC-related ports persistently. Recommend blocking identified IPs and monitoring ASN 14061 for similar activity. |

## 7) Odd-Service / Minutia Attacks
| service_fingerprint | why it’s unusual/interesting | evidence summary | confidence | recommended monitoring pivots |
| --- | --- | --- | --- | --- |
| honeypot: Conpot; protocol: kamstrup_protocol | Targets a proprietary and niche Industrial Control Systems (ICS) protocol used in smart meters. OSINT confirms no public CVEs or widespread exploit campaigns, making any probe noteworthy. | 20 total events across `kamstrup_protocol` (18) and `kamstrup_management_protocol` (2). | Medium (Provisional) | The immediate priority is to resolve data access issues to identify the source IP(s) and ASN(s) involved. Continue monitoring Conpot for any follow-on activity. |

## 8) Known-Exploit / Commodity Exclusions
- **Credential Noise**: Standard brute-force attempts against SSH (port 22) using common usernames (`root`, `admin`, `ubuntu`) and passwords (`123456`, `password`, `qwerty`).
- **Commodity SMB Scanning**: High-volume scanning (2,515 events) on port 445 from a single source IP `41.124.97.100`.
- **Known Web Exploit Probes**: 
    - Request for `/boaform/admin/formLogin?username=ec8&psd=ec8` from `103.93.93.182`, matching known exploit patterns for Boa web server vulnerabilities.
    - Uncoordinated opportunistic scanning for `/.env` (from `78.153.140.149`) and `////.git/HEAD` (from `192.253.248.12`).
- **Common Scanner Signatures**: Alerts for "ET SCAN MS Terminal Server Traffic on Non-standard Port" and "ET DROP Dshield Block Listed Source group 1" were observed and excluded as background noise.

## 9) Infrastructure & Behavioral Classification
- **VNC-SCAN-20260301-1**:
    - **Type**: Coordinated Scanning.
    - **Shape**: A spray campaign from a pool of source IPs.
    - **Infrastructure**: All identified high-volume source IPs originate from the same cloud provider ASN (14061, DigitalOcean, LLC), indicating centralized control or resource provisioning.
- **CONPOT-KAMSTRUP-20260301-1**:
    - **Type**: Reconnaissance / Scanning.
    - **Shape**: Unknown due to lack of source IP data.
    - **Infrastructure**: Unknown.
    - **Fingerprint**: Unusual targeting of a proprietary ICS protocol (`kamstrup_protocol`).

## 10) Evidence Appendix
### VNC-SCAN-20260301-1
- **source IPs with counts**: `129.212.179.18` (257+ events), `129.212.188.196` (256+ events), `129.212.184.194` (112+ events), `134.199.197.108` (56+ events).
- **ASNs with counts**: ASN 14061 (DigitalOcean, LLC) - All 4 high-volume IPs.
- **target ports/services**: 5900, 5902, 5903, 5925, 5926 (VNC).
- **payload/artifact excerpts**: Suricata signature: "GPL INFO VNC server response".
- **staging indicators**: None observed.
- **temporal checks results**: All four listed IPs were active for the majority or entirety of the 60-minute investigation window.

### CONPOT-KAMSTRUP-20260301-1 (Provisional)
- **source IPs with counts**: unavailable
- **ASNs with counts**: unavailable
- **target ports/services**: Conpot Honeypot (`kamstrup_protocol`, `kamstrup_management_protocol`).
- **payload/artifact excerpts**: None available.
- **temporal checks results**: unavailable

## 11) Indicators of Interest
| Type | Indicator | Context |
| --- | --- | --- |
| IP | `129.212.179.18` | VNC Scanning Campaign Source |
| IP | `129.212.188.196` | VNC Scanning Campaign Source |
| IP | `129.212.184.194` | VNC Scanning Campaign Source |
| IP | `134.199.197.108` | VNC Scanning Campaign Source |
| ASN | `14061` | VNC Scanning Campaign Origin (DigitalOcean, LLC) |
| Port | `5900`, `5902`, `5903`, `5925`, `5926` | VNC Scanning Campaign Targets |
| IP | `41.124.97.100` | Commodity SMB Scanner |
| IP | `103.93.93.182` | Commodity Web Probe (Boa) Source |
| Path | `/boaform/admin/formLogin?username=ec8&psd=ec8` | Commodity Web Exploit Probe |
| Protocol | `kamstrup_protocol` | Unusual ICS/SCADA Target |

## 12) Backend Tool Issues
- **`kibanna_discover_query`**: Failed with `status 400: illegal_argument_exception`. This blocked direct event lookups for web and ICS activity.
- **`suricata_lenient_phrase_search`**: Failed to return source IPs for a high-volume signature query, blocking an initial line of investigation.
- **`two_level_terms_aggregated`**: Intermittently returned empty results for aggregations where data was known to exist. This blocked initial IP identification for Conpot and VNC activity, and later blocked ASN correlation during the validation stage.
- **Affected Conclusions**: The source infrastructure for the `CONPOT-KAMSTRUP-20260301-1` odd-service attack remains completely unknown, weakening our ability to assess its threat level.

## 13) Agent Action Summary (Audit Trail)
- **agent_name**: ParallelInvestigationAgent
- **purpose**: Gather initial telemetry across different domains.
- **inputs_used**: `investigation_start`, `investigation_end`.
- **actions_taken**: Executed four sub-agents to collect baseline stats, known signals, credential noise, and honeypot-specific data.
- **key_results**: Identified high volumes of VNC and SMB traffic; top signature "GPL INFO VNC server response"; standard credential stuffing; and niche `kamstrup_protocol` activity on Conpot.
- **errors_or_gaps**: None.

- **agent_name**: CandidateDiscoveryAgent
- **purpose**: Synthesize initial telemetry, exclude noise, and identify high-signal candidates.
- **inputs_used**: `baseline_result`, `known_signals_result`, `credential_noise_result`, `honeypot_specific_result`.
- **actions_taken**: Excluded commodity SMB/SSH noise. Attempted to enrich VNC, Conpot, and web probe seeds using `suricata_lenient_phrase_search`, `two_level_terms_aggregated`, and `kibanna_discover_query`. Used `search` for OSINT on web exploit and ICS protocol.
- **key_results**: Promoted the VNC scanning campaign and the Conpot/Kamstrup activity as provisional candidates after excluding web probes as commodity.
- **errors_or_gaps**: Multiple data query tools failed, preventing source IP identification for VNC and Conpot candidates and forcing degraded mode.

- **agent_name**: CandidateValidationLoopAgent
- **purpose**: Iteratively validate candidates from the discovery phase.
- **iterations run**: 1
- **# candidates validated**: 1 (`VNC-SCAN-20260301-1`)
- **actions_taken**: Successfully pivoted using `two_level_terms_aggregated` on destination ports to find source IPs for the VNC campaign, bypassing earlier query failures.
- **key_results**: Confirmed the VNC activity is a multi-source "spray" campaign and identified key source IPs.
- **errors_or_gaps**: The tool failed to retrieve ASN information. Validation of the second candidate (`CONPOT-KAMSTRUP-20260301-1`) was not completed, likely due to persistent data access issues.

- **agent_name**: DeepInvestigationLoopController
- **purpose**: Perform deep-dive analysis on high-confidence, validated findings.
- **iterations run**: 4
- **key leads pursued**: `src_ip:129.212.179.18` and three other IPs (`129.212.188.196`, `129.212.184.194`, `134.199.197.108`) from the VNC campaign.
- **stall/exit reason**: Exited loop after confirming all four source IPs originated from the same ASN (14061) and showed similar TTPs, indicating diminishing returns on further pivots.

- **agent_name**: OSINTAgent
- **purpose**: Enrich findings with external context.
- **inputs_used**: `validated_candidates` (`VNC-SCAN-20260301-1`), `candidate_discovery_result` (`CONPOT-KAMSTRUP-20260301-1`).
- **actions_taken**: Used the `search` tool to research the VNC signature, a source IP, and the Kamstrup protocol.
- **key_results**: Confirmed VNC activity is typical of scanners. Confirmed Kamstrup is a proprietary ICS protocol with no public CVEs. Found no direct negative reputation for the checked IP but noted abuse from the same ASN.
- **errors_or_gaps**: None.

- **agent_name**: ReportAgent
- **purpose**: Builds finale report from workflow state (no new searching).
- **inputs_used**: All available state outputs (`baseline_result`, `known_signals_result`, `candidate_discovery_result`, `validated_candidates`, `investigation_log`, `osint_validation_result`, etc.).
- **actions_taken**: Compiled all state data into the final markdown report.
- **key_results**: This report.
- **errors_or_gaps**: Relied on provisional data for the Conpot candidate due to incomplete validation.

- **agent_name**: SaveReportAgent
- **purpose**: Persist the final report.
- **inputs_used**: Completed report markdown from this agent.
- **actions_taken**: Will call `investigation_write_file`.
- **key_results**: To be determined.
- **errors_or_gaps**: To be determined.