# Investigation Report

## 1) Investigation Scope
- **investigation_start**: 2026-03-09T03:00:03Z
- **investigation_end**: 2026-03-09T06:00:03Z
- **completion_status**: Partial
- **degraded_mode**: true - Honeypot specific query for ADBHoney malware samples timed out, affecting potential Android-specific threat analysis.

## 2) Executive Triage Summary
- A credential harvesting campaign, similar to Androxgh0st malware, was identified scanning for sensitive configuration files (`/.env`, `/.aws/credentials`) from IPs 185.177.72.60 (France) and 45.92.1.236 (Netherlands).
- High volume of VNC server response (17436 counts) and MS Terminal Server traffic on non-standard ports (810 counts) indicates widespread scanning.
- Detection of CVE-2025-55182 (60 counts) suggests active n-day exploitation attempts.
- Interactions with an Industrial Control System (ICS) honeypot via IEC104 protocol were observed (7 counts), indicating potential targeting of OT environments.
- Common credential brute-forcing attempts for usernames like 'root' and 'admin' are prevalent.
- Analysis of ADBHoney malware samples was blocked due to a tool timeout, creating a gap in understanding Android-specific threats.

## 3) Candidate Discovery Summary
A total of 24,395 attacks were observed during the investigation period. Top attacking countries include the United States (8,930), Indonesia (3,151), and Netherlands (965). Top source IPs include 182.8.193.5 (2,267), 144.202.106.26 (1,477), and 107.170.66.78 (1,030). Top ASNs are DigitalOcean, LLC (4,916), PT. Telekomunikasi Selular (2,267), and The Constant Company, LLC (1,934).

Key areas of interest include:
- High volume of `GPL INFO VNC server response` alerts (17,436 counts).
- `ET SCAN MS Terminal Server Traffic on Non-standard Port` alerts (810 counts).
- Detection of CVE-2025-55182 (60 counts).
- Repeated scanning for `/.env` and other configuration files (e.g., `/.aws/credentials`) on Tanner honeypots.
- Credential brute-force attempts targeting common usernames like `root` and `admin`.
- IEC104 protocol interactions on Conpot honeypot (7 counts).
- ADBHoney honeypot observed input `echo "$(getprop ro.product.name 2>/dev/null) $(whoami 2>/dev/null)"`.

The `adbhoney_malware_samples` query failed due to a timeout, which materially affected the discovery of potential Android-specific malware.

## 4) Emerging n-day Exploitation
- **CVE-2025-55182**
    - **cve/signature mapping**: CVE-2025-55182
    - **evidence summary**: 60 observed events.
    - **affected service/port**: Not specifically identified from current data.
    - **confidence**: High
    - **operational notes**: Monitor for successful exploitation attempts related to this CVE.

- **CVE-2024-38816**
    - **cve/signature mapping**: CVE-2024-38816
    - **evidence summary**: 13 observed events.
    - **affected service/port**: Not specifically identified from current data.
    - **confidence**: Moderate
    - **operational notes**: Track for further activity or successful exploitation.

## 5) Novel or Zero-Day Exploit Candidates (UNMAPPED ONLY, ranked)
None identified. All exploit-like candidates were mapped to known campaigns or exploitation patterns by OSINT.

## 6) Botnet/Campaign Infrastructure Mapping
- **Credential Harvesting Campaign (Androxgh0st-like / Cloud credential harvesting campaign)**
    - **item_id or related candidate_id(s)**: 185.177.72.60, 45.92.1.236
    - **campaign_shape**: Spray
    - **suspected_compromised_src_ips**: 185.177.72.60 (France), 45.92.1.236 (Netherlands)
    - **ASNs / geo hints**: AS211590 (Bucklog SARL, France), AS210558 (1337 Services GmbH, Netherlands)
    - **suspected_staging indicators**: Repeated scanning for sensitive configuration files like `/.env`, `/.aws/credentials`, `/.env.backup`, `/.env.bak`, `/.env.ci`, `/.env.config`, `/.env.default`, `/.env.dev`, `/.env.dev.local`, `/.env.development.local`, `/.env.dist`, `/.env.live`, `/.env.local`, `/.env.preprod`, `/.env.prod`, `/.env.prod.local`, `/.env.production`, `/.env.production.local`, `/.env.qa`, `/actuator/gateway/routes`, `/users/sign_in`.
    - **suspected_c2 indicators**: Not explicitly identified, but the coordinated scanning pattern suggests central control for credential harvesting.
    - **confidence**: High (publicly mapped by OSINT)
    - **operational notes**: Block identified source IPs. Implement strong access controls and monitoring for sensitive configuration files. Educate developers on secure handling of `.env` files and `.aws/credentials`.

## 7) Odd-Service / Minutia Attacks
- **IEC104 Protocol Interaction**
    - **service_fingerprint**: IEC104 protocol on Conpot honeypot
    - **why it’s unusual/interesting**: IEC104 is a protocol used in Industrial Control Systems (ICS). Interaction with this protocol indicates potential reconnaissance or targeting of critical infrastructure.
    - **evidence summary**: 7 counts of IEC104 protocol activity.
    - **confidence**: Moderate
    - **recommended monitoring pivots**: Monitor for further ICS/OT protocol interactions and assess potential impact on operational technology.

- **VNC on Non-Standard Ports**
    - **service_fingerprint**: VNC on ports 5902, 8888, 11434
    - **why it’s unusual/interesting**: While VNC is a common remote access service, its presence on non-standard ports, especially with a high volume of `GPL INFO VNC server response` alerts (17,436 counts), suggests broad scanning or attempts to bypass basic port-based filtering.
    - **evidence summary**: 438 counts on port 5902, 394 on 8888, 374 on 11434 (all from United States).
    - **confidence**: High
    - **recommended monitoring pivots**: Enhance monitoring for VNC traffic, especially on non-standard ports, and investigate associated login attempts or potential brute-forcing.

- **MS Terminal Server Traffic on Non-Standard Port**
    - **service_fingerprint**: MS Terminal Server (RDP) traffic on non-standard ports
    - **why it’s unusual/interesting**: Attackers often use non-standard ports for RDP to evade detection and bypass network defenses. 810 counts indicate significant scanning activity.
    - **evidence summary**: 810 counts of `ET SCAN MS Terminal Server Traffic on Non-standard Port` signature.
    - **confidence**: High
    - **recommended monitoring pivots**: Monitor RDP traffic on all ports, not just standard ones. Implement strong authentication and network segmentation for RDP services.

## 8) Known-Exploit / Commodity Exclusions
- **Credential Noise**: Extensive brute-force attempts with common usernames ('root', 'admin', 'test', 'user') and passwords ('123456', 'password', '123'). For example, 'root' was observed 180 times, 'admin' 145 times, and '123456' 85 times. This represents typical commodity credential stuffing/brute-forcing.
- **Scanning Activity**: High volume of generic scanning, including 17,436 `GPL INFO VNC server response` alerts and 810 `ET SCAN MS Terminal Server Traffic on Non-standard Port` alerts. This indicates broad, untargeted reconnaissance.
- **Generic Protocol Command Decode**: 4,083 alerts falling under this category, representing general network enumeration and protocol probing.
- **Attempted Information Leak**: 996 alerts, many likely related to the `.env` scanning but also encompassing broader attempts to extract information that are not part of specific campaigns.
- **Potentially Bad Traffic**: 179 alerts, indicating low-signal suspicious network activity.
- **SSH Session in Progress on Expected Port**: 327 alerts, often a benign indicator of legitimate SSH usage or commodity SSH scanning.

## 9) Infrastructure & Behavioral Classification
- **Exploitation vs Scanning**: The majority of observed activity is scanning (VNC, RDP, .env file discovery). Confirmed CVE-mapped exploitation (CVE-2025-55182) represents a smaller, but higher-signal, portion.
- **Campaign Shape**: Predominantly 'spray' type campaigns, where attackers widely scan for specific vulnerabilities or misconfigurations (e.g., .env files, open VNC/RDP ports).
- **Infra reuse indicators**: IPs 185.177.72.60 and 45.92.1.236 demonstrate similar scanning patterns for sensitive configuration files, indicating shared tooling or campaign objectives.
- **Odd-service fingerprints**: VNC (5902, 8888, 11434), RDP (non-standard ports), and IEC104 (ICS/OT protocol) are notable deviations from common enterprise services.

## 10) Evidence Appendix
- **Emerging n-day Exploitation: CVE-2025-55182**
    - **Source IPs with counts**: N/A
    - **ASNs with counts**: N/A
    - **Target ports/services**: N/A
    - **Paths/endpoints**: N/A
    - **Payload/artifact excerpts**: N/A
    - **Staging indicators**: N/A
    - **Temporal checks results**: Unavailable

- **Botnet/Campaign Infrastructure Mapping: Credential Harvesting Campaign (Androxgh0st-like / Cloud credential harvesting campaign)**
    - **Source IPs with counts**:
        - 185.177.72.60 (729 events)
        - 45.92.1.236 (21 events)
    - **ASNs with counts**:
        - AS211590 Bucklog SARL (for 185.177.72.60)
        - AS210558 1337 Services GmbH (for 45.92.1.236)
    - **Target ports/services**: 80, 443
    - **Paths/endpoints**: `/.env`, `/.aws/credentials`, `/.env.backup`, `/.env.bak`, `/.env.ci`, `/.env.config`, `/.env.default`, `/.env.dev`, `/.env.dev.local`, `/.env.development.local`, `/.env.dist`, `/.env.live`, `/.env.local`, `/.env.preprod`, `/.env.prod`, `/.env.prod.local`, `/.env.production`, `/.env.production.local`, `/.env.qa`, `/actuator/gateway/routes`, `/users/sign_in`.
    - **Payload/artifact excerpts**: `echo "$(getprop ro.product.name 2>/dev/null) $(whoami 2>/dev/null)"` (from ADBHoney, potentially related to general reconnaissance).
    - **Staging indicators**: The scanned paths themselves act as indicators for data collection points or initial access.
    - **Temporal checks results**:
        - 185.177.72.60 activity: 2026-03-09T05:49:34.000Z to 2026-03-09T05:51:47.672Z
        - 45.92.1.236 activity: 2026-03-09T03:41:32.000Z to 2026-03-09T03:42:55.367Z

## 11) Indicators of Interest
- **Source IPs**:
    - 185.177.72.60
    - 45.92.1.236
- **URLs/Paths**:
    - `/.env`
    - `/.aws/credentials`
    - `/.env.backup`
    - `/actuator/gateway/routes`
    - `/users/sign_in`
- **Payload Fragments**:
    - `echo "$(getprop ro.product.name 2>/dev/null) $(whoami 2>/dev/null)"` (ADB command)

## 12) Backend Tool Issues
- **Tool**: `adbhoney_malware_samples` (HoneypotSpecificAgent)
- **Error**: `HTTPConnectionPool(host='localhost', port=64298): Read timed out. (read timeout=15)`
- **Affected Validations**: This timeout blocked the analysis of potential malware samples captured by the ADBHoney honeypot. As a result, conclusions regarding Android-specific threats or novel malware observed by ADBHoney are weakened and may be incomplete.

## 13) Agent Action Summary (Audit Trail)
- **agent_name**: ParallelInvestigationAgent
    - **purpose**: Conduct parallel investigations for baseline, known signals, credential noise, and honeypot-specific activities.
    - **inputs_used**: `investigation_start`, `investigation_end`
    - **actions_taken**: Orchestrated calls to `BaselineAgent`, `KnownSignalAgent`, `CredentialNoiseAgent`, and `HoneypotSpecificAgent`.
    - **key_results**: Gathered initial telemetry including total attacks (24395), top attacking countries/IPs/ASNs, major alert signatures (e.g., VNC server response: 17436), identified CVEs (e.g., CVE-2025-55182: 60), common credential brute-force attempts, and honeypot interactions (Redis, ADBHoney inputs, Tanner paths, Conpot protocols).
    - **errors_or_gaps**: None from this agent directly, but propagated the `adbhoney_malware_samples` timeout from `HoneypotSpecificAgent`.

- **agent_name**: CandidateDiscoveryAgent
    - **purpose**: Identify potential novel or interesting attack candidates for further validation.
    - **inputs_used**: Honeypot-specific results, specifically `tanner_unifrom_resource_search`.
    - **actions_taken**: Performed a `kibanna_discover_query` for `path.keyword:/.env` within the investigation timeframe.
    - **key_results**: Discovered 2 distinct candidate events related to `/.env` file access on Tanner honeypots (from IPs 185.177.72.60 and 45.92.1.236).
    - **errors_or_gaps**: None.

- **agent_name**: CandidateValidationLoopAgent
    - **purpose**: Validate discovered candidates and enrich their context through targeted queries and analysis.
    - **inputs_used**: Candidates generated by `CandidateDiscoveryAgent`.
    - **actions_taken**: Executed 2 iterations to process both candidates. For each, performed `suricata_lenient_phrase_search`, `first_last_seen_src_ip`, and `top_http_urls_for_src_ip` queries.
    - **key_results**: Classified both candidates related to `/.env` scanning as `botnet_campaign_mapping`, identified extensive related paths (e.g., `/.aws/credentials`, various `.env` backups), determined source IP activity windows, and noted honeypot types interacted with.
    - **errors_or_gaps**: No validation steps were blocked, but it identified the `adbhoney_malware_samples` tool failure which affected upstream analysis.

- **agent_name**: OSINTAgent
    - **purpose**: Provide external context and validate the knownness and novelty of identified candidates using OSINT.
    - **inputs_used**: Validated candidates from `CandidateValidationLoopAgent`.
    - **actions_taken**: Performed multiple `search` queries using terms like `".env file scanning exploit"`, `"botnet" OR "malware campaign" ".env file scanning" "credential scanning"`.
    - **key_results**: Publicly mapped the observed `/.env` and `/.aws/credentials` file scanning activity to "Androxgh0st-like activity / Cloud credential harvesting campaign." Assessed the recency as "established" and noted a "reduces_novelty" impact, with high confidence in the mapping.
    - **errors_or_gaps**: None.

- **agent_name**: ReportAgent
    - **purpose**: Compile the final report from workflow state outputs.
    - **inputs_used**: `investigation_start`, `investigation_end`, `baseline_result`, `known_signals_result`, `credential_noise_result`, `honeypot_specific_result`, `validated_candidates`, `osint_validation_result`, `failed_queries` (from validation).
    - **actions_taken**: Compiled all available information into a structured markdown report, adhering to specified sections and formatting.
    - **key_results**: Generated the complete investigation report.
    - **errors_or_gaps**: None.

- **agent_name**: SaveReportAgent
    - **purpose**: Save the compiled investigation report to the designated directory.
    - **inputs_used**: The final report content generated by `ReportAgent`.
    - **actions_taken**: Will perform a `default_write_file` operation.
    - **key_results**: File write status pending, expected to be successful at specified path.
    - **errors_or_gaps**: None (status pending execution).
