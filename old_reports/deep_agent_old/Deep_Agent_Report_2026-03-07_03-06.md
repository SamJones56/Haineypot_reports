# Honeypot Threat Report

## 1) Investigation Scope
- **investigation_start**: 2026-03-07T03:00:04Z
- **investigation_end**: 2026-03-07T06:00:04Z
- **completion_status**: Partial (degraded evidence)
- **degraded_mode**: true - Initial honeypot type queries were misconfigured, and specific payload data could not be fully extracted for some events, impacting complete validation.

## 2) Executive Triage Summary
- Total attacks observed: 17442 across various honeypots.
- Dominant activity includes high-volume VNC scanning and commodity credential brute-forcing.
- A significant emerging n-day exploitation campaign targeting `CVE-2025-55182` (React2Shell Unsafe Flight Protocol Property Access) was identified with 68 instances.
- A novel exploit candidate for Redis (port 6379) showing SSH and HTTP protocol confusion was detected, indicating potential probing for misconfigured services or SSH key injection attempts. OSINT confirms this as a known exploitation technique.
- Critical infrastructure probing on ICS/SCADA protocols (Guardian AST, Kamstrup, IEC104) was observed via the Conpot honeypot.
- Extensive web application reconnaissance for sensitive files (`.aws/credentials`, `.env*`) was carried out by a specific aggressive IP (185.177.72.23) on the Tanner honeypot.
- Unusual traffic on port 37777, commonly associated with DVR/CCTV devices, warrants further monitoring.
- Major uncertainties remain regarding the full payloads for Redis protocol confusion and port 37777 traffic, requiring deeper analysis.

## 3) Candidate Discovery Summary
A total of 17442 attacks were observed within the reporting window. Key areas of interest include widespread VNC scanning, commodity RDP scanning on non-standard ports, and aggressive credential brute-forcing. Beyond commodity activity, the discovery process identified:
- An emerging n-day exploitation for CVE-2025-55182 (React2Shell) with 68 alerts.
- A novel exploit candidate involving SSH and HTTP traffic on the Redis default port (6379).
- Several botnet/campaign-like activities targeting VNC, generic credentials, web application sensitive files, and ICS/SCADA protocols.
- An odd-service attack targeting port 37777 (likely DVR/CCTV).
Missing inputs/errors materially affected discovery: Initial queries for 'Redis' honeypot types were incorrect, requiring adjustments to target 'Redishoneypot'. Direct tool-based correlation of source IPs to specific CVEs failed, necessitating custom queries. Specific payload information for port 37777 traffic could not be fully extracted.

## 4) Emerging n-day Exploitation
**Item ID: cve-2025-55182**
- **CVE/Signature Mapping**: `CVE-2025-55182` / `ET WEB_SPECIFIC_APPS React Server Components React2Shell Unsafe Flight Protocol Property Access (CVE-2025-55182)`
- **Evidence Summary**: 68 alerts detected. Top source IPs include 193.32.162.28 (53 counts), 87.121.84.24 (12 counts), 79.124.40.174 (2 counts), and 91.224.92.177 (1 count).
- **Affected Service/Port**: Web applications (implied HTTP/S).
- **Confidence**: High
- **Operational Notes**: Confirmed exploitation attempts of a recent CVE. Monitor target systems for any signs of successful compromise or post-exploitation activity.

## 5) Novel or Zero-Day Exploit Candidates (UNMAPPED ONLY, ranked)
**Candidate ID: redis-protocol-confusion**
- **Classification**: Novel exploit candidate
- **Novelty Score**: 6 (OSINT indicates this is a known technique for exploitation, reducing its absolute novelty but it remains a novel detection for the honeypot).
- **Confidence**: High
- **Provisional**: True
- **Key Evidence**: Redishoneypot (port 6379) recorded 'SSH-2.0-Go' (2 events) and 'GET / HTTP/1.1' (4 events) actions. Raw event data shows SSH key exchange attempts and SSL/TLS-like handshakes, indicating a protocol confusion or an attempt to exploit unexpected services on the Redis port. This activity originated from source IPs 3.129.187.38 and 16.58.56.214, both associated with Amazon.com, Inc. (ASN 16509).
- **Knownness Checks Performed + Outcome**: Searched internal CVE/signature mapping: none found for this specific anomaly. OSINT validation found public reporting of SSH traffic on Redis port 6379 indicating malicious activity, such as SSH key injection or exploitation of misconfigured instances.
- **Temporal Checks**: Unavailable (observed only in this window).
- **Required Follow-up**: Deep dive into raw payloads for 'SSH-2.0-Go' and 'GET / HTTP/1.1' on Redis to identify specific commands/exploitation attempts. Investigate the precise purpose of sending these protocols to a Redis service.

## 6) Botnet/Campaign Infrastructure Mapping
**Item ID: vnc-scanning-campaign**
- **Campaign Shape**: Spray
- **Suspected Compromised Src IPs**: 143.198.239.107 (1498 counts), 129.212.183.98 (1478 counts), 67.207.84.204 (554 counts)
- **ASNs / Geo Hints**: DigitalOcean, LLC (ASN 14061), United States
- **Suspected Staging Indicators**: None identified.
- **Suspected C2 Indicators**: None identified.
- **Confidence**: High
- **Operational Notes**: Commodity-level, high-volume scanning of VNC services. Focus on identifying specific VNC vulnerabilities being targeted if any deviation from standard enumeration is observed.

**Item ID: credential-brute-force-campaign**
- **Campaign Shape**: Spray
- **Suspected Compromised Src IPs**: 185.177.72.23 (958 counts), 136.114.97.84 (752 counts), 45.95.214.24 (466 counts)
- **ASNs / Geo Hints**: DigitalOcean, LLC (ASN 14061), Google LLC (ASN 396982), Bucklog SARL (ASN 211590)
- **Suspected Staging Indicators**: None identified.
- **Suspected C2 Indicators**: None identified.
- **Confidence**: High
- **Operational Notes**: Persistent, coordinated brute-force attempts using common and specific username/password combinations (e.g., '345gs5662d34'). Identify targeted services beyond simple enumeration.

**Item ID: tanner-recon-campaign**
- **Campaign Shape**: Fan-out
- **Suspected Compromised Src IPs**: 185.177.72.23
- **ASNs / Geo Hints**: Bucklog SARL (ASN 211590)
- **Suspected Staging Indicators**: Probing for sensitive web application configuration and credential files, including `/.aws/credentials`, various `/.env*` files, and `/.terraform/terraform.tfstate`.
- **Suspected C2 Indicators**: None identified.
- **Confidence**: High
- **Operational Notes**: A single, highly active source IP performing targeted reconnaissance for critical configuration data. Investigate the full scope of paths hit by 185.177.72.23 for further exploitation indicators.

**Item ID: conpot-ics-probing-campaign**
- **Campaign Shape**: Spray
- **Suspected Compromised Src IPs**: 205.210.31.228 (19 counts), 147.185.132.64 (3 counts), 43.98.248.83 (9 counts), 3.130.168.2 (1 count)
- **ASNs / Geo Hints**: Google LLC (ASN 396982), United States
- **Suspected Staging Indicators**: None identified.
- **Suspected C2 Indicators**: None identified.
- **Confidence**: High
- **Operational Notes**: Focused probing of Industrial Control Systems (ICS)/SCADA protocols (Guardian AST, Kamstrup, IEC104). Prioritize capturing specific command sequences or payloads to understand attacker intent against critical infrastructure.

**Item ID: cve-2025-55182-campaign**
- **Campaign Shape**: Spray
- **Suspected Compromised Src IPs**: 193.32.162.28 (53 counts), 87.121.84.24 (12 counts), 79.124.40.174 (2 counts), 91.224.92.177 (1 count)
- **ASNs / Geo Hints**: Not explicitly correlated in state.
- **Suspected Staging Indicators**: None identified.
- **Suspected C2 Indicators**: None identified.
- **Confidence**: High
- **Operational Notes**: Coordinated attempts to exploit `CVE-2025-55182`. Monitor for post-exploitation or C2 beaconing from successfully exploited targets.

## 7) Odd-Service / Minutia Attacks
**Item ID: port-37777-traffic**
- **Service Fingerprint**: Port 37777 (TCP)
- **Why it’s unusual/interesting**: Port 37777 is a non-standard port often associated with proprietary protocols for DVR/CCTV systems, making it a target for IoT/embedded device exploitation.
- **Evidence Summary**: 25 events (Suricata flow, Honeytrap, P0f) originating from 37.60.224.127 (Contabo GmbH, France). No specific payload information was available.
- **Confidence**: Medium
- **Recommended Monitoring Pivots**: Implement deeper packet capture for this port to identify the specific protocol and commands being attempted if activity persists.

## 8) Known-Exploit / Commodity Exclusions
- **VNC Scanning**: 16869 events identified as "GPL INFO VNC server response" across standard VNC ports (5902, 5903, 5904), indicative of widespread, opportunistic scanning.
- **RDP Scanning (Non-standard Ports)**: 788 events flagged as "ET SCAN MS Terminal Server Traffic on Non-standard Port", showing common scanning for RDP services on atypical ports.
- **Credential Brute-Force**: High volume of login attempts using common usernames ('root', 'user', 'admin') and easily guessable or leaked passwords ('password', '123456', '@qwer2025'), including a notable pattern '345gs5662d34'. This activity is consistent with commodity brute-force campaigns.
- **Web Application Reconnaissance**: Extensive probing for sensitive web application configuration files (e.g., `/.aws/credentials`, `/.env*`, `/.terraform/terraform.tfstate`) is a common reconnaissance tactic.

## 9) Infrastructure & Behavioral Classification
- **VNC Scanning Campaign**: Commodity-level, broad "spray" scanning behavior originating from diverse IPs, often hosted on cloud/VPS providers like DigitalOcean.
- **RDP Scanning (Non-standard)**: Commodity "spray" scanning, attempting to find misconfigured or hidden RDP services.
- **Credential Brute-Force Campaign**: Opportunistic "spray" exploitation attempts against various services, utilizing a mix of cloud infrastructure (DigitalOcean, Google LLC).
- **React2Shell CVE Exploitation**: Emerging n-day "spray" exploitation targeting web applications, with multiple source IPs attempting the vulnerability.
- **Redis Protocol Confusion**: Specific "minutia" attack, indicating either a misconfigured scanner or a targeted attempt at protocol confusion/exploitation (e.g., SSH key injection) on a Redis service. Currently, the campaign shape is "unknown" due to limited source IPs from Amazon AWS.
- **Tanner Sensitive File Reconnaissance**: Highly focused "fan-out" reconnaissance behavior from a single, aggressive IP (185.177.72.23), indicative of a targeted information gathering phase against web applications.
- **Conpot ICS/SCADA Probing**: Targeted "spray" reconnaissance and interaction with uncommon Industrial Control System protocols, likely seeking vulnerabilities or misconfigurations in critical infrastructure. IPs associated with Google LLC.
- **Port 37777 Traffic**: "Minutia" reconnaissance, likely targeting IoT/DVR devices, originating from a single IP.

## 10) Evidence Appendix

### Novel Exploit Candidates
**Candidate ID: redis-protocol-confusion**
- **Source IPs with counts**: 3.129.187.38 (multiple events), 16.58.56.214 (multiple events)
- **ASNs with counts**: Amazon.com, Inc. (ASN 16509)
- **Target Ports/Services**: Redis (Port 6379)
- **Paths/Endpoints**: `GET / HTTP/1.1`
- **Payload/Artifact Excerpts**:
    - `SSH-2.0-Go`
    - `\x16\x03\x01\x00{\x01\x00\x00w\x03\x03�:\xed\x1dl\x1d�Q\xc80\x1f�+\xdb\x8e \x87\xc0\xb7\xbe~\x02=\xdb\x8eM\x1f\xd7\xdf\xa3/{��\x00\x00\x1a�/�+\x11�\x07�\x13� �\x14�` (SSL/TLS-like handshake)
    - `\x15\x03\x01\x00\x02\x02\x16` (SSL/TLS-like alert)
    - `GET / HTTP/1.1`
- **Staging Indicators**: None identified.
- **Temporal Checks**: Unavailable (observed only in current window).

### Emerging n-day Exploitation
**Item ID: cve-2025-55182**
- **Source IPs with counts**: 193.32.162.28 (53), 87.121.84.24 (12), 79.124.40.174 (2), 91.224.92.177 (1)
- **ASNs with counts**: Not available in state.
- **Target Ports/Services**: Web applications (implied HTTP/S).
- **Paths/Endpoints**: Implied by "React Server Components React2Shell Unsafe Flight Protocol Property Access".
- **Payload/Artifact Excerpts**: Signature: `ET WEB_SPECIFIC_APPS React Server Components React2Shell Unsafe Flight Protocol Property Access (CVE-2025-55182)`
- **Staging Indicators**: None identified.
- **Temporal Checks**: Unavailable (observed only in current window).

### Top Botnet/Campaign Mapping Items
**Item ID: vnc-scanning-campaign**
- **Source IPs with counts**: 143.198.239.107 (1498), 129.212.183.98 (1478), 67.207.84.204 (554), 129.212.183.117 (384), 172.94.9.39 (250)
- **ASNs with counts**: DigitalOcean, LLC (ASN 14061)
- **Target Ports/Services**: VNC (5902, 5903, 5904)
- **Paths/Endpoints**: Not applicable (protocol scanning).
- **Payload/Artifact Excerpts**: Signature: `GPL INFO VNC server response`
- **Staging Indicators**: None identified.
- **Temporal Checks**: Unavailable (observed only in current window).

**Item ID: tanner-recon-campaign**
- **Source IPs with counts**: 185.177.72.23 (multiple counts across many paths)
- **ASNs with counts**: Bucklog SARL (ASN 211590)
- **Target Ports/Services**: Web application (Tanner honeypot, likely HTTP/S)
- **Paths/Endpoints**: `/.aws/credentials`, `/.env.dev.local`, `/.env.docker`, `/.env.example`, `/.env.local`, `/.env.prod`, `/.env.sample`, `/.env.save.1`, `/.env.save.2`, `/.env.sendgrid`, `/.env.server`, `/.env.stage`, `/.env.testing`, `/.env.tmp`, `/.terraform/terraform.tfstate`, `/actuator/info`, `/admin/.env`, `/api/.env`, `/api/config`
- **Payload/Artifact Excerpts**: HTTP GET requests for sensitive configuration files.
- **Staging Indicators**: None identified.
- **Temporal Checks**: Unavailable (observed only in current window).

**Item ID: conpot-ics-probing-campaign**
- **Source IPs with counts**: 205.210.31.228 (19), 147.185.132.64 (3), 43.98.248.83 (9), 3.130.168.2 (1)
- **ASNs with counts**: Google LLC (ASN 396982)
- **Target Ports/Services**: Conpot honeypot (ports implied by protocols, e.g., 10001 for Guardian AST)
- **Paths/Endpoints**: Not explicitly path-based, but includes specific protocol interactions.
- **Payload/Artifact Excerpts**: `b'\x01I20100'`, `b'\x01I20100\n'`
- **Staging Indicators**: None identified.
- **Temporal Checks**: Unavailable (observed only in current window).

## 11) Indicators of Interest
- **Source IPs**:
    - 185.177.72.23 (Tanner recon, brute-force activity)
    - 3.129.187.38 (Redis protocol confusion)
    - 16.58.56.214 (Redis protocol confusion)
    - 193.32.162.28 (CVE-2025-55182 exploitation)
    - 37.60.224.127 (Port 37777 traffic)
    - 205.210.31.228 (Conpot ICS probing)
- **Target Ports**: 6379 (unusual SSH/HTTP traffic), 37777 (unknown protocol)
- **Paths/Endpoints (Web Recon)**: `/.aws/credentials`, `/.env.dev.local`, `/.env.docker`, `/.env.example`, `/.env.local`, `/.env.prod`, `/.env.sample`, `/.terraform/terraform.tfstate`, `/admin/.env`, `/api/.env`, `/api/config`
- **Payload Fragments**: `SSH-2.0-Go`, `GET / HTTP/1.1` (when observed on port 6379), `b'\x01I20100'` (Conpot Guardian AST command)
- **CVEs**: `CVE-2025-55182`
- **Suricata Signatures**: `ET WEB_SPECIFIC_APPS React Server Components React2Shell Unsafe Flight Protocol Property Access (CVE-2025-55182)`

## 12) Backend Tool Issues
- `kibanna_discover_query` (term='honeypot.type.keyword', value='Redis'): Failed due to incorrect honeypot type mapping (should be 'Redishoneypot'). This initially blocked discovery of Redis-specific events, though later queries using the correct type succeeded.
- `kibanna_discover_query` (term='input.keyword', value='GET / HTTP/1.1'): Failed due to incorrect field mapping for Redis-specific inputs, hindering direct payload retrieval for certain events.
- `match_query` (key='type.keyword', value='Redis'): Failed due to incorrect honeypot type mapping, similar to the first issue.
- `two_level_terms_aggregated` (primary_field='conpot.protocol.keyword'): Returned empty buckets, which may indicate a misconfiguration or lack of data for that specific aggregation in the time window, weakening the detailed breakdown of Conpot protocol interactions.
- `top_src_ips_for_cve`: This tool failed to return source IPs for `CVE-2025-55182`, necessitating a custom query to gather this critical information for infrastructure mapping.
- `two_level_terms_aggregated` (for `alert.signature.keyword` with `value_filter`): This tool did not properly filter by the specific CVE signature, requiring a custom search to accurately correlate source IPs to the CVE.

These issues primarily affected the initial discovery and detailed evidence extraction for Redis and Conpot honeypots, as well as the direct correlation of source IPs for the `CVE-2025-55182` campaign. While workarounds were found for some, they reflect degraded evidence gathering capabilities in specific areas.

## 13) Agent Action Summary (Audit Trail)

**agent_name**: ParallelInvestigationAgent
- **purpose**: Orchestrate parallel data collection for baseline, known signals, credential noise, and honeypot-specific activity.
- **inputs_used**: None (initial agent).
- **actions_taken**: Launched `BaselineAgent`, `KnownSignalAgent`, `CredentialNoiseAgent`, `HoneypotSpecificAgent` concurrently.
- **key_results**: Successfully collected initial telemetry across all categories, including total attacks, top attacker IPs/countries/ASNs, major Suricata signatures, detected CVEs, top credential attempts, and honeypot-specific event counts/actions for Redis, ADB, Conpot, and Tanner.
- **errors_or_gaps**: None reported directly.

**agent_name**: CandidateDiscoveryAgent
- **purpose**: Merge initial investigation results and identify high-signal exploitation candidates and campaign patterns.
- **inputs_used**: `baseline_result`, `known_signals_result`, `credential_noise_result`, `honeypot_specific_result`.
- **actions_taken**: Merged initial data; executed `kibanna_discover_query` (6 times), `discover_by_keyword` (2 times), `match_query` (1 time), `custom_basic_search` (1 time), `two_level_terms_aggregated` (4 times), `top_src_ips_for_cve` (2 times), `suricata_lenient_phrase_search` (1 time), and `complete_custom_search` (1 time). Queries targeted specific honeypot types, keywords, ports, and CVEs to find correlations and detailed event data.
- **key_results**: Identified 1 novel exploit candidate (Redis protocol confusion), 1 emerging n-day exploit (CVE-2025-55182), 6 botnet/campaign mappings, 1 odd-service attack, and several known commodity exclusions. Generated a detailed triage summary.
- **errors_or_gaps**: Experienced 7 tool failures due to incorrect honeypot type (`Redis` instead of `Redishoneypot`), incorrect field (`input.keyword`), or aggregation issues (e.g., `top_src_ips_for_cve` for `CVE-2025-55182`). These led to evidence gaps that required manual workarounds via custom queries.

**agent_name**: CandidateValidationLoopAgent
- **purpose**: Manage the queue of discovered candidates and pass them for individual validation.
- **inputs_used**: `candidate_discovery_result` (specifically `novel_exploit_candidates` and `odd_service_minutia_attacks`).
- **actions_taken**: Initialized candidate queue with 2 candidates. Loaded 1 candidate (`redis-protocol-confusion`) for processing.
- **key_results**: `redis-protocol-confusion` candidate was prepared and passed for validation by `CandidateValidationAgent`.
- **errors_or_gaps**: None reported by the loop controller itself.

**agent_name**: CandidateValidationAgent (Implicitly run by loop)
- **purpose**: Validate a single candidate by performing specific checks and enriching its details.
- **inputs_used**: `redis-protocol-confusion` candidate details from `CandidateDiscoveryAgent`.
- **actions_taken**: Performed implicit knownness checks, re-evaluated evidence based on updated queries, and refined classification details.
- **key_results**: Confirmed the `redis-protocol-confusion` as a novel exploit candidate, updated observed evidence, added infrastructure indicators, and listed required follow-up.
- **errors_or_gaps**: Inherited `failed_queries` from `CandidateDiscoveryAgent` related to initial Redis searches.

**agent_name**: CandidateLoopReducerAgent (Implicitly run by loop)
- **purpose**: Aggregate validated candidate results into the main workflow state.
- **inputs_used**: Validated candidate `redis-protocol-confusion` result.
- **actions_taken**: Appended the validated `redis-protocol-confusion` candidate to the `validated_candidates` list.
- **key_results**: `validated_candidates` list now contains `redis-protocol-confusion`.
- **errors_or_gaps**: None.

**agent_name**: DeepInvestigationLoopController
- **purpose**: Initiate and manage deep investigation for specific high-signal leads.
- **inputs_used**: `validated_candidates` (specifically `redis-protocol-confusion`).
- **actions_taken**: Loaded the lead for `redis-protocol-confusion` (`service:6379, payload:SSH-2.0-Go, payload:GET / HTTP/1.1`). Executed `kibanna_discover_query` twice to retrieve specific events for `SSH-2.0-Go` and `GET / HTTP/1.1` actions on the Redishoneypot. Appended investigation state and requested loop exit.
- **key_results**: Confirmed the observed SSH and HTTP traffic on Redis port 6379, identified associated source IPs (3.129.187.38, 16.58.56.214), and outlined the nature of the protocol confusion. The lead was successfully consumed.
- **errors_or_gaps**: None.

**agent_name**: OSINTAgent
- **purpose**: Perform open-source intelligence lookups to contextualize and assess the knownness of novel findings.
- **inputs_used**: `redis-protocol-confusion` candidate details.
- **actions_taken**: Executed `search` tool with the query "SSH traffic on Redis port 6379".
- **key_results**: Identified public reporting indicating that SSH traffic on Redis port 6379 is a known malicious technique (e.g., SSH key injection). This reduced the novelty impact of the `redis-protocol-confusion` candidate, confirming it as an `established technique`.
- **errors_or_gaps**: None.

**agent_name**: ReportAgent (self)
- **purpose**: Compile the final report from workflow state outputs.
- **inputs_used**: `investigation_start`, `investigation_end`, `baseline_result`, `known_signals_result`, `credential_noise_result`, `honeypot_specific_result`, `candidate_discovery_result`, `validated_candidates`, `osint_validation_result`, `deep_investigation_logs/state`, `pipeline/query failure diagnostics`.
- **actions_taken**: Consolidated and formatted all available workflow state outputs into the structured markdown report.
- **key_results**: The complete final markdown report provided as output.
- **errors_or_gaps**: None; successfully compiled the report.

**agent_name**: SaveReportAgent
- **purpose**: Save the final report to storage.
- **inputs_used**: The completed markdown report content.
- **actions_taken**: (This agent will implicitly call `deep_agent_write_file` tool.)
- **key_results**: (Expected: File write status and path/identifier.)
- **errors_or_gaps**: Not yet executed.