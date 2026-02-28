# Honeypot Threat Report: Last 60 Minutes

## 1) Investigation Scope
- **investigation_start**: 2026-02-28T15:14:16Z
- **investigation_end**: 2026-02-28T16:14:17Z
- **completion_status**: Partial
- **degraded_mode**: true (Degraded due to tool errors during candidate discovery and incomplete deep investigation due to early exit/stall conditions, specifically regarding full temporal comparisons and contextual data for a Nintendo 3DS OS fingerprint.)

## 2) Executive Triage Summary
- A total of 3768 attacks were observed within the last 60 minutes.
- Confirmed emerging n-day exploitation attempts targeting NVMS-9000 (CVE-2024-14007) on ports 6036, 6037, and 17001, with specific payload details extracted.
- Significant botnet/campaign activity includes high-volume VNC scanning from DigitalOcean (ASN 14061) and SOCKS proxy attempts from Chinese infrastructure (ASN 136146) on port 1080.
- Common web server information disclosure attempts via requests for `/.env` and `/.env.test` files were observed on HTTP/Tanner honeypots.
- Widespread scanning and known malicious traffic from Dshield blocklisted sources (signature 2402000) targeted various common ports.
- A single, unusual p0f OS fingerprint identified as "Nintendo 3DS" was detected, but full context (source IP, specific service) could not be reliably retrieved.
- Commodity brute force and credential stuffing (SSH, generic login attempts) represent a large portion of the overall noise.

## 3) Candidate Discovery Summary
A total of 3768 attacks were processed for candidate discovery.
Top services and ports of interest identified:
- VNC (ports 5925, 5926, 5902)
- SOCKS Proxy (port 1080)
- HTTP/Tanner (port 80, for .env files)
- NVMS-9000 (ports 6036, 6037, 17001)
- SSH (port 22)
- MSSQL (port 1433)
- MySQL (port 3306)
- Redis (various actions)
- Unusual OS fingerprint: Nintendo 3DS

Material errors affecting discovery:
- Aggregation queries for linking `alert.signature.keyword` to `src_ip.keyword` experienced errors, limiting direct insight into which IPs triggered which specific known alerts.
- A Kibana discover query for the `Nintendo 3DS` OS fingerprint returned no hits, hindering full context for this unusual event.

## 4) Emerging n-day Exploitation
- **CVE/signature mapping**: CVE-2024-14007 (ET WEB_SPECIFIC_APPS Shenzhen TVT NVMS-9000 Information Disclosure Attempt)
- **Evidence summary**: 3 alerts for CVE-2024-14007. Targeted ports: 6036, 6037, 17001. Source IPs: '89.42.231.179' (2 counts, payload extracted for `queryBasicCfg`), '46.151.178.13' (1 count). The CVE is a high-severity authentication bypass in NVMS-9000, allowing sensitive information disclosure.
- **Affected service/port**: NVMS-9000 control protocol on ports 6036, 6037, 17001.
- **Confidence**: High
- **Operational notes**: Exploitation confirmed with payload. Review assets with NVMS-9000. Public exploits exist.

## 5) Novel Exploit Candidates (UNMAPPED ONLY, ranked)
No truly novel exploit candidates were identified after OSINT and knownness checks. Items initially flagged as "novel exploit candidates" were reclassified as known exploitation or commodity scanning.

## 6) Botnet/Campaign Infrastructure Mapping
- **item_id**: BMC-2026-02-28-001
- **campaign_shape**: spray
- **suspected_compromised_src_ips**: 103.189.141.153 (192 counts on port 1080)
- **ASNs / geo hints**: ASN 136146 (Beijing 3389 Network Technology Co., Ltd.), China
- **suspected_staging indicators**: N/A
- **suspected_c2 indicators**: N/A (likely part of a larger SOCKS proxy network)
- **confidence**: High
- **operational notes**: Observed 228 "GPL INFO SOCKS Proxy attempt" signatures. Consistent with established SOCKS proxy botnet activity originating from China, often used for anonymizing malicious traffic. Monitor destination port 1080 for unusual client connections.

- **item_id**: BMC-2026-02-28-002
- **campaign_shape**: spray/fan-out
- **suspected_compromised_src_ips**: 129.212.188.196 (253 counts), 129.212.179.18 (251 counts), 129.212.184.194 (110 counts)
- **ASNs / geo hints**: ASN 14061 (DigitalOcean, LLC), United States
- **suspected_staging indicators**: N/A
- **suspected_c2 indicators**: N/A (consistent with broad scanning operations from cloud infrastructure)
- **confidence**: High
- **operational notes**: High volume VNC scanning from DigitalOcean IPs on ports 5925, 5926, 5902. This is a common pattern of botnet activity leveraging cloud infrastructure for reconnaissance and brute-force attempts.

- **item_id**: BMC-2026-02-28-003
- **campaign_shape**: spray
- **suspected_compromised_src_ips**: 193.163.125.183, 147.185.132.162, 167.94.145.33, 45.148.10.121, 195.184.76.214, 195.184.76.212, 206.168.34.61, 147.185.132.251, 45.148.10.147, 147.185.132.120 (and others, total 66 counts)
- **ASNs / geo hints**: Various (e.g., Google LLC, Censys Inc, Techoff Srv Limited, Driftnet Ltd, ONYPHE SAS)
- **suspected_staging indicators**: N/A
- **suspected_c2 indicators**: N/A
- **confidence**: High
- **operational notes**: Traffic from IPs listed on the Dshield blocklist, tagged as "known attacker" or "mass scanner," targeting diverse ports including SSH (22), MSSQL (1433), MySQL (3306), and others. This indicates generic scanning and brute-force activity.

## 7) Odd-Service / Minutia Attacks
- **service_fingerprint**: Unknown service, p0f OS detection.
- **why it’s unusual/interesting**: Detection of 'Nintendo 3DS' as an operating system fingerprint is highly unusual for typical internet-facing services and may indicate a misidentification, a niche IoT device interaction, or highly specific targeting.
- **evidence summary**: One p0f.os detection of 'Nintendo 3DS'. Lack of associated raw events prevented further contextualization (e.g., source IP, dest port, protocol).
- **confidence**: Low
- **recommended monitoring pivots**: Monitor p0f logs for this specific OS fingerprint, attempt to correlate with source IPs or destination ports if they appear in other logs. Broaden time window for searches.

## 8) Known-Exploit / Commodity Exclusions
- **Credential Noise**: Extensive attempts using common usernames (`admin`, `root`, `ubuntu`, `user`) and weak passwords (`123456`, `1234qwer`, `Qwerty1`, empty string). Detected by `get_input_usernames` and `get_input_passwords`.
- **Commodity VNC Scanning**: High volume of "GPL INFO VNC server response" (1680 counts) indicates widespread scanning for open VNC services, primarily from DigitalOcean infrastructure.
- **Commodity SSH Scanning**: Numerous "SURICATA SSH invalid banner" (356 counts) and "ET INFO SSH session in progress" (137/69 counts) alerts point to automated SSH brute-force or reconnaissance.
- **SOCKS Proxy Attempts**: "GPL INFO SOCKS Proxy attempt" (228 counts) on port 1080 from China, indicative of common botnet activity.
- **Web Server Information Disclosure Attempts**: Requests for `/.env` (1 count) and `/.env.test` (1 count) are well-known automated scanner tactics to find exposed environment configuration files. Identified as a known scanner tactic by OSINT.

## 9) Infrastructure & Behavioral Classification
- **CVE-2024-14007 Exploitation**: Targeted exploitation of a known vulnerability (NVMS-9000 Auth Bypass) via XML payload queries. IPs from Netherlands.
- **SOCKS Proxy Botnet (Chinese origin)**: Spray-style reconnaissance/proxy activity from compromised IPs (ASN 136146 - Beijing 3389) on port 1080, typical of botnet traffic anonymization.
- **VNC Scanning (DigitalOcean origin)**: Large-scale spray/fan-out scanning campaign from DigitalOcean (ASN 14061) targeting VNC ports, characteristic of botnet recruitment/reconnaissance.
- **Dshield Block Listed Sources**: Generic scanning and attack attempts from various IPs/ASNs identified as known bad actors or mass scanners. Behavioral pattern is opportunistic and spray-like.
- **.env File Disclosure Attempts**: Opportunistic scanning for web server misconfigurations from various IPs/ASNs.
- **Nintendo 3DS OS Fingerprint**: Minutia observation; unclassified behavior due to limited context, but highly unusual OS for honeypot interaction.

## 10) Evidence Appendix

**Emerging n-day Exploitation: CVE-2024-14007**
- **Source IPs with counts**: 89.42.231.179 (2), 46.151.178.13 (1)
- **ASNs with counts**: ASN 206264 (Amarutu Technology Ltd) - 114 events, ASN 211443 (Sino Worldwide Trading Limited) - 103 events.
- **Target ports/services**: 6036 (NVMS-9000), 6037 (NVMS-9000), 17001 (NVMS-9000)
- **Paths/endpoints**: N/A (protocol-level exploitation)
- **Payload/artifact excerpts**:
    - For 89.42.231.179 on port 6037: `<?xml version="1.0" encoding="UTF-8"?>\n<request version="1.0" systemType="NVMS-9000" clientType="WEB" url="queryBasicCfg"/>\n` (decoded from payload)
- **Staging indicators**: N/A
- **Temporal checks results**: Observed within the last 60 minutes.

**Botnet/Campaign Infrastructure Mapping: BMC-2026-02-28-001 (SOCKS Proxy)**
- **Source IPs with counts**: 103.189.141.153 (192)
- **ASNs with counts**: ASN 136146 (Beijing 3389 Network Technology Co., Ltd.) (228 total events)
- **Target ports/services**: 1080 (SOCKS Proxy)
- **Paths/endpoints**: N/A
- **Payload/artifact excerpts**: "GPL INFO SOCKS Proxy attempt" (Suricata signature 2100615)
- **Staging indicators**: N/A
- **Temporal checks results**: Observed within the last 60 minutes.

**Botnet/Campaign Infrastructure Mapping: BMC-2026-02-28-002 (VNC Scanning)**
- **Source IPs with counts**: 129.212.188.196 (253), 129.212.179.18 (251), 129.212.184.194 (110)
- **ASNs with counts**: ASN 14061 (DigitalOcean, LLC) (1064 total events)
- **Target ports/services**: 5926 (VNC), 5925 (VNC), 5902 (VNC)
- **Paths/endpoints**: N/A
- **Payload/artifact excerpts**: "GPL INFO VNC server response" (Suricata signature 2100560)
- **Staging indicators**: N/A
- **Temporal checks results**: Observed within the last 60 minutes.

## 11) Indicators of Interest
- **Source IPs**:
    - 89.42.231.179 (involved in CVE-2024-14007 exploitation, Netherlands)
    - 46.151.178.13 (involved in CVE-2024-14007 exploitation, Netherlands)
    - 103.189.141.153 (SOCKS proxy attempts, China)
- **ASNs**:
    - ASN 206264 (Amarutu Technology Ltd)
    - ASN 211443 (Sino Worldwide Trading Limited)
    - ASN 136146 (Beijing 3389 Network Technology Co., Ltd.)
    - ASN 14061 (DigitalOcean, LLC)
- **Target Ports**:
    - 6036, 6037, 17001 (NVMS-9000 exploitation)
    - 1080 (SOCKS proxy)
    - 5925, 5926, 5902 (VNC scanning)
- **Paths/Endpoints**:
    - `/.env`
    - `/.env.test`
- **Payload Fragments**:
    - `<?xml version="1.0" encoding="UTF-8"?>\n<request version="1.0" systemType="NVMS-9000" clientType="WEB" url="queryBasicCfg"/>\n` (NVMS-9000 exploitation)

## 12) Backend Tool Issues
- `two_level_terms_aggregated` (primary_field="alert.signature.keyword", secondary_field="src_ip.keyword") failed, blocking direct, granular correlation between specific Suricata signatures and individual source IPs for high-volume activity. This weakened knownness checks and campaign shape analysis by preventing easy pivot to granular IP-to-signature linking.
- `two_level_terms_aggregated` (primary_field="src_ip.keyword", secondary_field="alert.signature.keyword") partially failed, with secondary buckets not returning data, impacting detailed analysis of all signatures associated with top attacking IPs.
- `kibanna_discover_query` (term="p0f.os.keyword", value="Nintendo 3DS") failed to retrieve raw events, making it impossible to ascertain the full context (src_ip, dest_port, protocol) for the unusual OS fingerprint. This weakened the confidence and operational utility of the "Odd-Service / Minutia Attack" finding.
- Full temporal comparison of the current window vs. previous 30-minute/24-hour window was blocked due to tool limitations for some specific metrics/pivots. This reduced the ability to assess recency and trend for all identified behaviors.

## 13) Agent Action Summary (Audit Trail)

- **agent_name**: ParallelInvestigationAgent
    - **purpose**: Gathers baseline, known signal, credential noise, and honeypot-specific data concurrently.
    - **inputs_used**: investigation_start, investigation_end (implicitly via `get_current_time` calls in sub-agents)
    - **actions_taken**: Executed sub-agents (`BaselineAgent`, `KnownSignalAgent`, `CredentialNoiseAgent`, `HoneypotSpecificAgent`) to query various data sources.
    - **key_results**: Collected 3768 total attacks, identified top countries/IPs/ASNs, detected major Suricata signatures (e.g., VNC server response, SSH invalid banner), listed common credential stuffing attempts, and found specific web requests (e.g., `/.env`) on Tanner honeypot.
    - **errors_or_gaps**: None explicitly reported by the agent or its sub-agents.

- **agent_name**: CandidateDiscoveryAgent
    - **purpose**: Identifies initial exploitation and infrastructure candidates from raw telemetry and baseline/known data.
    - **inputs_used**: baseline_result, known_signals_result, credential_noise_result, honeypot_specific_result
    - **actions_taken**: Performed various Kibana discover queries and two-level aggregations to find unusual paths (`/.env`, `/.env.test`), CVE matches (CVE-2024-14007), and significant clustering of IPs/ASNs around specific attack types (VNC, SOCKS proxy, Dshield).
    Searched for CVE details.
    - **key_results**: Identified CVE-2024-14007 exploitation attempts (3 counts), SOCKS proxy activity from China (228 counts), high-volume VNC scanning from DigitalOcean (1680 counts), `.env` file requests (2 counts), Dshield block-listed source activity (66 counts), and a Nintendo 3DS OS fingerprint (1 count).
    - **errors_or_gaps**: `tool_errors_detected: true`. `two_level_terms_aggregated` failed for some signature-to-IP pivots, and `kibanna_discover_query` for 'Nintendo 3DS' failed to return events. Blocked some temporal comparisons.

- **agent_name**: CandidateValidationLoopAgent (including Controller, Validation Agent, Reducer)
    - **purpose**: Orchestrates and executes validation steps for discovered candidates.
    - **inputs_used**: Candidates generated by CandidateDiscoveryAgent.
    - **actions_taken**: 
        - Controller: Initialized candidate queue with 6 candidates, loaded 1st candidate.
        - Validation Agent: Called `suricata_cve_samples` for CVE-2024-14007.
        - Reducer: Appended validated candidate details.
    - **key_results**: Successfully validated `ENE-2024-14007` (CVE-2024-14007 exploitation) with associated Suricata alerts, IPs, and ports. 1 candidate validated.
    - **errors_or_gaps**: Only one candidate was processed in the provided log, indicating early exit or implicit completion of the validation phase before deeper investigation. Remaining 5 candidates were not explicitly shown as validated here.

- **agent_name**: DeepInvestigationLoopController (via DeepInvestigationAgent)
    - **purpose**: Conducts detailed, iterative investigations on high-signal leads.
    - **inputs_used**: Context from CandidateValidationAgent (specifically CVE-2024-14007 related IPs).
    - **actions_taken**: Initialized deep state. Queried events and performed custom searches for source IPs (`89.42.231.179`, `46.151.178.13`) and ASNs (`206264`, `211443`) involved in CVE-2024-14007. Extracted payload info for `89.42.231.179`. Appended investigation state after each lead. Exited loop.
    - **key_results**: Confirmed XML payload for `queryBasicCfg` on port 6037 from `89.42.231.179`. Detailed source IPs and target ports for ASNs involved in CVE-2024-14007 exploitation. Identified general web reconnaissance on port 7000 from `46.151.178.13`.
    - **errors_or_gaps**: `stall_count: 2`, indicating the agent stalled due to no new leads or reaching lead limits. `loop_exit_requested` was triggered, leading to early termination of deep investigation.

- **agent_name**: OSINTAgent
    - **purpose**: Gathers open-source intelligence to contextualize and validate findings.
    - **inputs_used**: Candidate details from discovery and validation.
    - **actions_taken**: Performed `search_agent` queries for CVE-2024-14007, SOCKS proxy botnets, VNC scanning from DigitalOcean, `.env` file leakage, and Dshield blocklists.
    - **key_results**: Confirmed public knowledge and impact for CVE-2024-14007. Mapped SOCKS proxy and VNC scanning to known botnet/commodity activity. Reclassified `.env` file requests as known scanner tooling. Confirmed Dshield blocklist signature. OSINT for "Nintendo 3DS" was inconclusive.
    - **errors_or_gaps**: OSINT for "Nintendo 3DS" was inconclusive due to lack of specific searchable artifacts.

- **agent_name**: ReportAgent (Self-summary)
    - **purpose**: Compiles the final report from aggregated workflow state.
    - **inputs_used**: All preceding workflow state outputs (investigation_start, investigation_end, baseline_result, known_signals_result, credential_noise_result, honeypot_specific_result, candidate_discovery_result, validated_candidates, osint_validation_result, deep_investigation_logs).
    - **actions_taken**: Read and consolidated all available state data into the specified markdown report format. Applied mandatory logic for classification and completion status.
    - **key_results**: Successfully generated the final markdown report.
    - **errors_or_gaps**: None (report compilation only).

- **agent_name**: SaveReportAgent
    - **purpose**: Saves the generated report to persistent storage.
    - **inputs_used**: Completed report content.
    - **actions_taken**: Not explicitly called in the provided context, but assumed to be triggered downstream.
    - **key_results**: File write status N/A (as not explicitly shown in logs).
    - **errors_or_gaps**: N/A (not applicable to this audit trail within current context).