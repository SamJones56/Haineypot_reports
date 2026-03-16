# Threat Hunting Honeypot Report: 2026-03-16

## 1) Investigation Scope
- **investigation_start**: 2026-03-16T06:17:08Z
- **investigation_end**: 2026-03-16T10:17:08Z
- **completion_status**: Partial (degraded evidence)
- **degraded_mode**: true. Tool failures during the deep investigation phase blocked the complete mapping of attacker infrastructure related to the primary identified campaign (CVE-2025-55182).

## 2) Executive Triage Summary
- **Top Services/Ports of Interest**: High-volume scanning was observed against VNC (5900-5905), SMB (445), and various web/development ports (80, 3000-3012, 8081, etc.).
- **Odd/Minutia Service Highlights**: Low-volume but unusual interactions were recorded with Industrial Control System (ICS) honeypots, specifically involving the `guardian_ast` and `kamstrup_protocol` on Conpot.
- **Top Confirmed Known Exploitation**: A targeted campaign exploiting CVE-2025-55182 (React2Shell), a critical RCE in React Server Components, was the most significant finding. Activity was traced to at least two source IPs from different networks.
- **Unmapped Exploit-like Items**: No novel or zero-day candidates were validated in this window.
- **Botnet/Campaign Mapping Highlights**:
    - The CVE-2025-55182 campaign was mapped to two distinct source ASNs, indicating coordination.
    - Widespread, opportunistic web vulnerability scanning was identified, targeting common weaknesses like `.env` file exposure, originating from a known malicious network (`185.177.72.0/24`).
- **Major Uncertainties**: The full extent of the CVE-2025-55182 campaign's infrastructure could not be mapped due to a tool failure during a critical pivot query, leaving potential additional attacker IPs undiscovered.

## 3) Candidate Discovery Summary
The discovery phase identified two primary areas of interest from over 26,000 events:
- **Emerging N-day Activity**: 102 events were linked to CVE-2025-55182.
- **Botnet/Scanner Activity**: A cluster of IPs (including `185.177.72.49`) were observed systematically scanning for common web application vulnerabilities across `/form/` and `/api/` paths.

Initial discovery was hampered by data retrieval issues, as queries to link source IPs to the CVE and Conpot activity failed, requiring the validation loop to perform enrichment.

## 4) Emerging n-day Exploitation
### NDE-01: Exploitation of React2Shell (CVE-2025-55182)
- **cve/signature mapping**: CVE-2025-55182 (`ET WEB_SPECIFIC_APPS React Server Components React2Shell Unsafe Flight Protocol Property Access`).
- **evidence summary**: 102 alert events were recorded from 2 source IPs across 9 destination ports. Key targeted URLs include `/_next/server`, `/api/route`, and `/app`.
- **affected service/port**: Primarily targets non-standard HTTP/development ports, including 3000-3012, 3333, and 8081.
- **confidence**: High.
- **operational notes**: This is active exploitation of a recently disclosed, critical RCE vulnerability. The attackers appear to be scanning for vulnerable Next.js or other React-based applications running on common development ports.

## 6) Botnet/Campaign Infrastructure Mapping
### CAM-01: React2Shell Exploitation Campaign (related to NDE-01)
- **item_id**: CAM-01 (corresponds to NDE-01)
- **campaign_shape**: Spray. The activity involves multiple attackers from different networks targeting a specific vulnerability across a range of potential victim ports.
- **suspected_compromised_src_ips**: 
    - `193.32.162.28` (Targeted, specific exploit URLs)
    - `176.65.139.44` (Broader reconnaissance followed by exploit attempts)
- **ASNs / geo hints**: 
    - AS47890 (Unmanaged Ltd, Romania)
    - AS51396 (Pfcloud UG, Germany)
- **suspected_staging indicators**: No staging hosts were identified, but the following URLs are direct indicators of exploit attempts: `/_next/server`, `/api/route`, `/api`, `/app`.
- **suspected_c2 indicators**: None identified.
- **confidence**: High.
- **operational notes**: The use of at least two distinct ASNs suggests a coordinated campaign. The difference in TTPs (one IP highly targeted, the other noisy) may indicate different roles or tools within the same campaign.

## 7) Odd-Service / Minutia Attacks
### ODD-01: Industrial Control System (ICS) Protocol Probing
- **service_fingerprint**: Conpot honeypot, ports associated with ICS.
- **why it’s unusual/interesting**: The interaction involved specific, non-standard ICS protocols (`guardian_ast`, `kamstrup_protocol`, `IEC104`). This is distinct from generic TCP/IP scanning and indicates potential specialized reconnaissance targeting operational technology (OT).
- **evidence summary**: 76 total events recorded on the Conpot honeypot, with `guardian_ast` being the most frequent protocol (55 events). Source IPs could not be reliably correlated due to data gaps.
- **confidence**: Medium.
- **recommended monitoring pivots**: Track source IPs interacting with ICS honeypots. Correlate with any subsequent exploit activity against other services.

## 8) Known-Exploit / Commodity Exclusions
- **Common Web Vulnerability Scanning**: Activity identified as `BOT-01` was confirmed by OSINT to be generic scanning for well-known vulnerabilities (`/.env` exposure, unrestricted file uploads via `/form/admin/upload`). This activity originated from IPs like `185.177.72.49`, part of a network (`185.177.72.0/24`) with a public reputation for spam and scanning.
- **Credential Noise**: Standard brute-force attempts were observed across various services. Top usernames included `root`, `admin`, `sa`, `user`. Top passwords included `123456`, `password`, `admin`.
- **VNC Scanning**: The most frequent signature by a large margin was `GPL INFO VNC server response` (14,630 events), indicating widespread, automated scanning for open VNC servers on ports 5900-5905.
- **SMB Scanning**: High volume of traffic on port 445, consistent with scanning for open SMB shares and related vulnerabilities like DoublePulsar.

## 9) Infrastructure & Behavioral Classification
- **exploitation vs scanning**:
    - **CVE-2025-55182 Campaign**: Confirmed exploitation.
    - **Web Form/API Probing**: Confirmed scanning.
    - **VNC/SMB/SSH**: Confirmed scanning.
- **campaign shape**:
    - The React2Shell campaign exhibits a **spray** shape, with multiple, unrelated sources targeting the same vulnerability.
- **infra reuse indicators**:
    - The React2Shell campaign utilizes at least two distinct ASNs (`AS47890`, `AS51396`), indicating no significant infrastructure reuse between these two actors.
    - The web vulnerability scanning originates from a known malicious block (`185.177.72.0/24`), suggesting infrastructure reuse among commodity scanners.
- **odd-service fingerprints**:
    - `guardian_ast`, `kamstrup_protocol` (ICS/OT)
    - Miniprint honeypot interaction

## 10) Evidence Appendix
### Emerging n-day: NDE-01 (CVE-2025-55182)
- **source IPs**: `193.32.162.28`, `176.65.139.44`
- **ASNs**: `47890` (Unmanaged Ltd), `51396` (Pfcloud UG)
- **target ports/services**: 3001, 3002, 3003, 3004, 3010, 3011, 3012, 3333, 8081 (TCP)
- **paths/endpoints**: `/`, `/_next`, `/_next/server`, `/api`, `/api/route`, `/app`
- **payload/artifact excerpts**:
    - Suricata Signature: `ET WEB_SPECIFIC_APPS React Server Components React2Shell Unsafe Flight Protocol Property Access (CVE-2025-55182)`
    - Suricata Signature: `ET HUNTING Javascript Prototype Pollution Attempt via __proto__ in HTTP Body`
- **temporal checks results**: First seen: 2026-03-16T06:25:57Z, Last seen: 2026-03-16T10:01:15Z.

### Botnet Mapping: BOT-01 (Web Scanning)
- **source IPs**: `185.177.72.22`, `185.177.72.23`, `185.177.72.30`, `185.177.72.49`
- **ASNs**: OSINT links this /24 block to "FBW NETWORKS SAS" (France).
- **target ports/services**: 80 (TCP)
- **paths/endpoints**: `/form/account/avatar`, `/form/admin/files`, `/form/admin/import`, `/form/admin/upload`, `/form/api/asset`, `/form/api/assets`, `/.env`, `/rest/settings`

## 11) Indicators of Interest
- **CVE-2025-55182 Attacker IPs**:
    - `193.32.162.28`
    - `176.65.139.44`
- **CVE-2025-55182 Attacker ASNs**:
    - `AS47890`
    - `AS51396`
- **CVE-2025-55182 Exploit Paths**:
    - `/_next/server`
    - `/api/route`
- **Commodity Web Scanner IPs**:
    - `185.177.72.49`
    - `185.177.72.22`
    - `185.177.72.23`
    - `185.177.72.30`

## 12) Backend Tool Issues
- **CandidateDiscoveryAgent**: The `top_src_ips_for_cve` tool failed to return results for CVE-2025-55182, requiring the validation loop to perform basic IP enrichment. The `two_level_terms_aggregated` query for Conpot also returned no data. This delayed initial analysis.
- **DeepInvestigationAgent**: The `two_level_terms_aggregated` tool failed during a critical pivot in iteration 4. The query for all source IPs targeting the `/_next/server` URL returned no data, despite other queries confirming the existence of this traffic. This failure blocked the discovery of potentially more attacker IPs and weakened the conclusion on the full scope of the campaign.
- **DeepInvestigationAgent**: In iteration 5, a broad `two_level_terms_aggregated` query to pivot on a destination port failed to isolate the signal from background noise, effectively acting as a failed query.

## 13) Agent Action Summary (Audit Trail)
- **agent_name**: ParallelInvestigationAgent
- **purpose**: Gathers baseline telemetry and known signals in parallel.
- **inputs_used**: `investigation_start`, `investigation_end`.
- **actions_taken**: Executed sub-agents to query for total attacks, top geos/IPs/ASNs, known CVEs/signatures, credential stuffing indicators, and honeypot-specific interactions.
- **key_results**: Provided foundational data identifying high VNC/SMB traffic, CVE-2025-55182, common credential stuffing, and odd ICS protocol activity.
- **errors_or_gaps**: None.

- **agent_name**: CandidateDiscoveryAgent
- **purpose**: Synthesizes parallel results to identify and propose initial threat candidates.
- **inputs_used**: `baseline_result`, `known_signals_result`, `credential_noise_result`, `honeypot_specific_result`.
- **actions_taken**: Pivoted on the top CVE and suspicious web paths. Attempted to enrich candidates with source IP data.
- **key_results**: Identified and proposed two candidates: `NDE-01` (CVE-2025-55182) and `BOT-01` (Web Scanning).
- **errors_or_gaps**: `top_src_ips_for_cve` and a Conpot-related query failed to return data, creating an initial evidence gap.

- **agent_name**: CandidateValidationLoopAgent
- **purpose**: Iteratively validates and enriches candidates from the discovery queue.
- **inputs_used**: `candidate_discovery_result`.
- **actions_taken**: Ran 1 iteration. Loaded candidate `NDE-01`. Used OSINT search (`search` tool) and detailed event queries (`suricata_cve_samples`, `events_for_src_ip`) to validate the CVE link, identify source IPs/URLs, and confirm active exploitation.
- **key_results**: Successfully validated `NDE-01`, enriching it with actionable intelligence (2 source IPs, specific URLs), upgrading its confidence to 'High', and removing its 'Provisional' status.
- **errors_or_gaps**: The loop did not proceed to validate candidate `BOT-01`; it was instead assessed later by the OSINTAgent.

- **agent_name**: DeepInvestigationLoopController
- **purpose**: Performs deep-dive, iterative investigation starting from validated high-confidence candidates.
- **inputs_used**: `validated_candidates`.
- **actions_taken**: Ran for 5 iterations, starting with the two source IPs from `NDE-01`. Pursued leads including source IPs, ASNs, and URLs using tools like `first_last_seen_src_ip`, `top_http_urls_for_src_ip`, and `kibanna_discover_query`.
- **key_results**: Confirmed the CVE-2025-55182 campaign involves at least two actors with different TTPs and network origins. Mapped some additional scanning activity from one of the attacker ASNs.
- **errors_or_gaps**: The loop exited after 2 consecutive stalls caused by a tool failure (query for `/_next/server` returned no data) and an overly broad query that failed to isolate signal. This prevented a complete mapping of the campaign.

- **agent_name**: OSINTAgent
- **purpose**: Enriches final candidates with open-source intelligence to assess novelty and knownness.
- **inputs_used**: Final candidate list from previous stages.
- **actions_taken**: Performed `search` queries for artifacts related to `BOT-01` (web paths, source IP) and `NDE-01` (CVE identifier).
- **key_results**: Confirmed `BOT-01` is commodity web scanning from a known malicious network. Confirmed `NDE-01` is active exploitation of a known, recent, critical CVE. This adjusted the novelty assessment for both items.
- **errors_or_gaps**: None.

- **agent_name**: ReportAgent
- **purpose**: Builds final report from workflow state (no new searching).
- **inputs_used**: All available state outputs from previous agents.
- **actions_taken**: Compiled this report by synthesizing all inputs, applying mandatory logic for routing and classification, and noting degraded mode due to tool failures.
- **key_results**: This markdown report.
- **errors_or_gaps**: None.

- **agent_name**: SaveReportAgent
- **purpose**: Saves the generated report.
- **inputs_used**: Final markdown report content.
- **actions_taken**: Will call `deep_agent_write_file`.
- **key_results**: File write status.
- **errors_or_gaps**: To be determined upon execution.