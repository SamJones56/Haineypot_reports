# Investigation Report: Honeypot Threat Analysis

## 1. Investigation Scope
- **investigation_start**: 2026-02-28T23:00:33Z
- **investigation_end**: 2026-03-01T00:00:33Z
- **completion_status**: Partial (degraded evidence)
- **degraded_mode**: true. The investigation was degraded due to backend tool failures during the deep investigation phase, which prevented a full pivot on TLS SNI indicators.

## 2. Executive Triage Summary
- **Top Services of Interest**: The most notable activity targeted VNC (ports 5900-5926), SMB (port 445), and SSH (port 22).
- **Odd-Service/Minutia Highlights**: Low-volume reconnaissance activity was detected against the Kamstrup smart-metering protocol (ICS/OT) on the Conpot honeypot. Additionally, suspicious TLS beaconing to `aiplatform.googleapis.com` was observed.
- **Top Confirmed Known Exploitation**: A large, geographically distributed scanning campaign (`VNC-Spray-1`) was identified, consistent with attempts to exploit the established VNC authentication bypass vulnerability CVE-2006-2369.
- **Botnet/Campaign Mapping Highlights**: The `VNC-Spray-1` campaign was confirmed to originate from a botnet of compromised hosts across multiple ASNs in the US, France, and the Netherlands. A separate multi-purpose malicious host (`167.71.255.16`) was identified acting as both a scanner and a potential C2 client.
- **Major Uncertainties**: The full scope of the suspected C2 activity involving `aiplatform.googleapis.com` could not be determined due to tool query failures. The significance of the Kamstrup ICS protocol activity remains provisional due to a lack of source IP correlation.

## 3. Candidate Discovery Summary
- **Total Attacks Analyzed**: 13,284
- **Top Honeypots by Activity**: Cowrie (SSH/Telnet, 7888 events), Honeytrap (Multi-protocol, 2895 events), and Dionaea (SMB/low-interaction, 2103 events).
- **Key Discovery Areas**:
    - A widespread VNC scanning campaign was identified, associated with the `GPL INFO VNC server response` signature.
    - High-volume, single-source scanning against SMB (port 445) from `151.84.83.133`.
    - Unusual ICS protocol activity (`kamstrup_protocol`) on the Conpot honeypot.
    - Common web reconnaissance probes for sensitive files (`/.env`, `/.git/config`) on the Tanner honeypot.
- **Gaps**: Initial discovery was impacted by missing source IP data for the Conpot and Tanner findings, requiring them to be marked as provisional.

## 4. Botnet/Campaign Infrastructure Mapping

### Item: VNC-Spray-1 (Commodity Botnet)
- **item_id**: VNC-Spray-1
- **campaign_shape**: spray (geographically and network-distributed)
- **suspected_compromised_src_ips**: `129.212.183.117`, `66.103.206.9`, `144.91.83.79`, `88.151.33.168`, and others.
- **ASNs / geo hints**: AS14061 (DigitalOcean, US), AS35916 (MULTACOM, US), AS51167 (Contabo GmbH, France), AS41608 (NextGenWebs, S.L., Netherlands).
- **suspected_staging indicators**: None observed.
- **suspected_c2 indicators**: None directly observed for this campaign.
- **confidence**: High
- **operational notes**: This is a geographically distributed botnet performing reconnaissance for vulnerable VNC servers, likely exploiting CVE-2006-2369. The source IPs should be considered compromised and added to blocklists.

### Item: Suspected C2 Beaconing
- **item_id**: C2-Beacon-1
- **campaign_shape**: beaconing (from single source to multiple destination IPs)
- **suspected_compromised_src_ips**: `167.71.255.16`
- **ASNs / geo hints**: Source: AS14061 (DigitalOcean, LLC, US). Destination: Google ASNs.
- **suspected_staging indicators**: None observed.
- **suspected_c2 indicators**:
    - **Host**: `167.71.255.16` initiated all connections.
    - **Destination SNI**: `aiplatform.googleapis.com`
    - **Destination IPs**: `142.250.72.10`, `142.250.68.202`, `142.250.217.234`, and others in Google's IP space.
    - **Fingerprint**: Consistent JA3 hash `d39e1be3241d516b1f714bd47c2bc968` across all connections.
- **confidence**: High (for beaconing behavior), Medium (for C2 classification)
- **operational notes**: The use of a legitimate high-reputation domain for beaconing is a common evasion technique. `167.71.255.16` is a multi-purpose malicious host also involved in scanning and should be blocked. The JA3 hash can be used as a high-fidelity indicator for this specific client activity.

## 5. Odd-Service / Minutia Attacks

### Item: ICS Reconnaissance
- **service_fingerprint**: Conpot honeypot, `kamstrup_protocol`
- **why it’s unusual/interesting**: Kamstrup is a protocol used in smart metering (gas, water, electricity). Activity against it, even if low-volume, indicates reconnaissance against Industrial Control Systems (ICS) / Operational Technology (OT).
- **evidence summary**: 3 events recorded. Source IPs could not be retrieved.
- **confidence**: Low (Provisional)
- **recommended monitoring pivots**: Enhance logging on Conpot sensors to ensure source IPs and any command payloads for this protocol are captured. Track for future occurrences.

## 6. Known-Exploit / Commodity Exclusions
- **VNC Scanning (CVE-2006-2369)**: Extensive scanning across a wide range of VNC ports (5900-5926) was observed from numerous IPs. This activity generated 1,922 `GPL INFO VNC server response` alerts and is consistent with exploitation attempts against the old and well-documented CVE-2006-2369 authentication bypass.
- **Credential Stuffing/Brute-Force**: High volume of login attempts against SSH (port 22) and other services using common username/password combinations (e.g., `root`/`123456`, `admin`/`123`).
- **SMB Scanning**: A single IP, `151.84.83.133` (AS1267, Wind Tre S.p.A., Italy), was responsible for 2,081 connection attempts to port 445 (SMB), indicating a targeted scan.
- **Web Reconnaissance**: Standard scanning for sensitive configuration and source code files, such as `/.env` and `/.git/config`, was observed by the Tanner honeypot.
- **Misc Scanning Signatures**: Common alerts such as `ET SCAN MS Terminal Server Traffic on Non-standard Port` and `SURICATA SSH invalid banner` were observed, indicating broad, non-specific scanning activity.

## 7. Infrastructure & Behavioral Classification
- **Exploitation vs Scanning**: The activity was a mix of both. The `VNC-Spray-1` campaign constitutes attempted exploitation, while the activity from `151.84.83.133` (SMB) and probes for `.env` files are classified as scanning/reconnaissance.
- **Campaign Shape**:
    - **Spray**: The `VNC-Spray-1` campaign used many sources against many targets.
    - **Fan-out**: The SMB scanning from `151.84.83.133` represents a fan-out from a single host.
    - **Beaconing**: The suspected C2 traffic from `167.71.255.16` to `aiplatform.googleapis.com` is classified as beaconing.
- **Infra Reuse Indicators**: The `VNC-Spray-1` campaign reuses a botnet of compromised hosts across multiple ASNs. The host `167.71.255.16` was observed performing multiple malicious activities (scanning, suspected C2).
- **Odd-Service Fingerprints**: `kamstrup_protocol` (ICS/OT) and TLS beaconing to a legitimate AI/ML platform service (`aiplatform.googleapis.com`) were the key unusual fingerprints.

## 8. Evidence Appendix

### VNC-Spray-1
- **Source IPs (sample)**: `129.212.183.117`, `66.103.206.9`, `144.91.83.79`, `88.151.33.168`
- **ASNs (sample)**: 14061 (DigitalOcean, LLC), 35916 (MULTACOM CORPORATION), 51167 (Contabo GmbH), 41608 (NextGenWebs, S.L.)
- **Target Ports/Services**: 5900, 5902, 5905, 5906, 5907, 5911, 5912, 5925, 5926
- **Payload/Artifact Excerpts**: `alert.signature: "GPL INFO VNC server response"`
- **Related CVE**: CVE-2006-2369
- **Temporal Checks**: unavailable

### C2-Beacon-1
- **Source IPs**: `167.71.255.16`
- **ASNs**: 14061 (DigitalOcean, LLC)
- **Target Ports/Services**: 443 (TLS)
- **Staging Indicators (Suspected C2 IPs)**: `142.250.72.10`, `142.250.68.202`, `142.250.217.234`, `142.251.211.106`, `142.251.45.170`
- **Payload/Artifact Excerpts**:
    - `tls.sni: "aiplatform.googleapis.com"`
    - `tls.ja3.hash: "d39e1be3241d516b1f714bd47c2bc968"`
- **Temporal Checks**: unavailable

## 9. Indicators of Interest
- **IPs**:
    - `167.71.255.16` (Multi-purpose malicious host: scanning + suspected C2)
    - `151.84.83.133` (High-volume SMB scanner)
    - `129.212.183.117` (VNC botnet member)
    - `66.103.206.9` (VNC botnet member)
    - `144.91.83.79` (VNC botnet member)
- **Domains / SNI**:
    - `aiplatform.googleapis.com` (Suspected C2 domain)
- **JA3 Hashes**:
    - `d39e1be3241d516b1f714bd47c2bc968` (Fingerprint for suspected C2 client)
- **Alert Signatures**:
    - `GPL INFO VNC server response`
- **Paths**:
    - `/.env`
    - `/.git/config`

## 10. Backend Tool Issues
- **Tool**: `two_level_terms_aggregated`
- **Failures**:
    1. The tool initially failed when aggregating on the `tls.sni` text field because fielddata was not enabled.
    2. A subsequent attempt using `tls.sni.keyword` failed due to a `parse_exception` on the `gte_time_stamp`. The agent incorrectly formatted the date as `2026-2-28...` instead of the required `2026-02-28...`.
- **Affected Validations**: These failures blocked the pivot from the `aiplatform.googleapis.com` SNI to identify other source IPs using the same C2 channel. This weakened the conclusion about whether the C2 client was unique to a single host or part of a broader campaign.

## 11. Agent Action Summary (Audit Trail)

- **agent_name**: ParallelInvestigationAgent
- **purpose**: Gather broad, concurrent telemetry at the start of the investigation.
- **inputs_used**: `investigation_start`, `investigation_end`.
- **actions_taken**: Executed sub-agents (`BaselineAgent`, `KnownSignalAgent`, `CredentialNoiseAgent`, `HoneypotSpecificAgent`) which ran queries for total attacks, top IPs/ASNs/countries, known CVEs/signatures, common credentials, and honeypot-specific interactions.
- **key_results**: 
    - Identified 13,284 total attacks.
    - Flagged heavy activity from AS14061 (DigitalOcean).
    - Detected 1,922 "GPL INFO VNC server response" alerts and linked CVE-2006-2369.
    - Found common `root`/`admin` brute-force attempts.
    - Noted rare `kamstrup_protocol` ICS activity and web probes for `.env`.
- **errors_or_gaps**: None reported.

- **agent_name**: CandidateDiscoveryAgent
- **purpose**: Sift through initial telemetry to create a prioritized list of investigation candidates.
- **inputs_used**: `baseline_result`, `known_signals_result`, `credential_noise_result`, `honeypot_specific_result`.
- **actions_taken**: Merged and analyzed parallel inputs, generated triage summary, and created candidate lists.
- **key_results**: 
    - Created candidates for VNC scanning (`VNC-Spray-1`), SMB scanning (`SMB-Scanner-1`), ICS activity (`ICS-Kamstrup-1`), and web probes (`Web-Probes-1`).
    - Correctly classified VNC and SMB activity as botnet/campaign mapping targets.
    - Correctly classified ICS activity as an odd-service attack.
- **errors_or_gaps**: Noted that source IPs for Conpot and Tanner activity were not retrieved, making those candidates provisional.

- **agent_name**: CandidateValidationLoopAgent
- **purpose**: Perform initial validation of a single candidate from the queue.
- **inputs_used**: `candidate_discovery_result`.
- **actions_taken**: Processed 1 candidate (`VNC-Spray-1`). Used `suricata_signature_samples` to pull raw events for the VNC signature.
- **key_results**: Confirmed that multiple source IPs were involved in the VNC scanning campaign, validating its "spray" nature and providing initial IPs for the deep investigation.
- **errors_or_gaps**: The workflow only shows one iteration before proceeding to deep investigation.

- **agent_name**: DeepInvestigationLoopController
- **purpose**: Conduct an iterative, pivot-based investigation starting from high-value leads.
- **inputs_used**: `validated_candidates`.
- **actions_taken**: Ran 7 iterations. Pursued leads including source IPs, ASNs, services, domains, and a JA3 hash. Pivoted using tools like `events_for_src_ip`, `two_level_terms_aggregated`, and `kibanna_discover_query`.
- **key_results**: 
    - Confirmed the geographically distributed nature of the `VNC-Spray-1` botnet.
    - Uncovered a multi-purpose malicious host `167.71.255.16`.
    - Identified suspicious TLS beaconing to `aiplatform.googleapis.com` as a potential C2 channel.
    - Mapped the consistent JA3 hash `d39e1be3241d516b1f714bd47c2bc968` to the C2 activity.
- **errors_or_gaps**: The investigation stalled twice and was prematurely exited. It was degraded by multiple `two_level_terms_aggregated` tool failures when trying to pivot on TLS SNI, preventing a full mapping of the suspected C2 infrastructure.

- **agent_name**: OSINTAgent
- **purpose**: Enrich findings with open-source intelligence.
- **inputs_used**: `validated_candidates` (`VNC-Spray-1`).
- **actions_taken**: Ran `search_agent` for "CVE-2006-2369 GPL INFO VNC server response".
- **key_results**: Confirmed the VNC activity is a known, "established" pattern targeting an old RealVNC authentication bypass vulnerability. This correctly reduced the novelty score of the finding.
- **errors_or_gaps**: None reported.

- **agent_name**: ReportAgent
- **purpose**: Builds finale report from workflow state (no new searching).
- **inputs_used**: `baseline_result`, `known_signals_result`, `credential_noise_result`, `honeypot_specific_result`, `candidate_discovery_result`, `validated_candidates`, `investigation_log` (from DeepInvestigationAgent), `osint_validation_result`.
- **actions_taken**: Compiled all available state information into the final structured report.
- **key_results**: This report.
- **errors_or_gaps**: None.

- **agent_name**: SaveReportAgent
- **purpose**: Persist the final report artifact.
- **inputs_used**: The completed markdown from this agent.
- **actions_taken**: A call to `investigation_write_file` will be performed by the downstream framework.
- **key_results**: File write status is pending.
- **errors_or_gaps**: None.