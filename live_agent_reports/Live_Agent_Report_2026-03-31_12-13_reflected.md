# Investigation Report: Threat Analysis (2026-03-31 12:28 to 13:28 UTC)

### 1) Investigation Scope
- **investigation_start**: 2026-03-31T12:28:57Z
- **investigation_end**: 2026-03-31T13:28:57Z
- **completion_status**: Partial (degraded evidence)
- **degraded_mode**: true. The analysis pipeline concluded after the initial parallel investigation phase. Candidate discovery, validation, and deep investigation were not performed, limiting the report to baseline and known-signal analysis.

### 2) Executive Triage Summary
- **Top Services/Ports of Interest**: VNC (5901, 5902, 5903) was the most targeted service, primarily from US-based IPs. ICS/SCADA activity was observed against the `kamstrup_protocol`. SSH (22) also saw significant brute-force activity.
- **Top Confirmed Known Exploitation**: Activity matching `CVE-2025-55182` was observed a small number of times. The dominant known activity was widespread VNC scanning, identified by the "GPL INFO VNC server response" signature.
- **Unmapped Exploit-like Items**: No unmapped candidates were generated or validated due to the shortened workflow.
- **Botnet/Campaign Mapping Highlights**: A clear VNC scanning campaign was identified, originating largely from AS14061 (DigitalOcean, LLC) in the United States and targeting VNC services.
- **Odd-Service/Minutia Highlights**: Activity targeting the `kamstrup_protocol`, an industrial control system (ICS) protocol for smart metering, was recorded by the Conpot honeypot. A single probe for a specific web endpoint (`/goform/formJsonAjaxReq`), often associated with router exploits, was also detected.
- **Major Uncertainties**: The lack of candidate validation means any potentially novel or sophisticated attacks within the observed 896 events remain uninvestigated.

### 3) Candidate Discovery Summary
- The Candidate Discovery agent was not run. No threat candidates were generated from the initial telemetry. Analysis is therefore limited to baseline statistics and high-level signature matches.

### 4) Emerging n-day Exploitation
**Item: CVE-2025-55182**
- **cve/signature mapping**: CVE-2025-55182
- **evidence summary**: 6 events recorded matching signatures for this CVE.
- **affected service/port**: Web Application (HTTP/HTTPS)
- **confidence**: Medium (Based on signature match; payload not deeply analyzed).
- **operational notes**: Monitor for an increase in this activity. The volume is currently very low.

### 5) Novel or Zero-Day Exploit Candidates (UNMAPPED ONLY, ranked)
- No novel candidates were generated or analyzed in this investigation window as the validation and discovery stages of the workflow were not executed.

### 6) Botnet/Campaign Infrastructure Mapping
**Item: VNC Scanning Campaign (VNC-SCAN-01)**
- **related_candidate_id(s)**: N/A
- **campaign_shape**: Spray (many sources targeting multiple honeypot destinations).
- **suspected_compromised_src_ips**: The majority of VNC scanning activity originated from IPs in the United States. `160.174.129.232` (Morocco) and multiple US IPs were high-volume sources, but the VNC-specific traffic was dominated by US sources.
- **ASNs / geo hints**: AS14061 (DigitalOcean, LLC) was the top source ASN with 203 events. Geo-location is primarily United States.
- **suspected_staging indicators**: None identified. Activity appears to be direct scanning.
- **suspected_c2 indicators**: None identified.
- **confidence**: High (that this is a coordinated scanning campaign).
- **operational notes**: This is commodity scanning activity. IPs from DigitalOcean participating in this campaign can be blocked.

### 7) Odd-Service / Minutia Attacks
**Item: ICS Protocol Probing**
- **service_fingerprint**: kamstrup_protocol (Conpot Honeypot)
- **why it’s unusual/interesting**: This is a protocol used for smart water/heat/electricity meters. Its presence indicates reconnaissance targeting Industrial Control Systems (ICS) or utility infrastructure.
- **evidence summary**: 24 events recorded by the Conpot honeypot for this protocol.
- **confidence**: High
- **recommended monitoring pivots**: Track source IPs interacting with the Conpot sensor. Any further interaction beyond basic probes should be escalated.

**Item: Router Endpoint Probe**
- **service_fingerprint**: HTTP, Path: `/goform/formJsonAjaxReq`
- **why it’s unusual/interesting**: This specific path is frequently associated with vulnerability scanners and exploitation attempts against various SOHO router firmware (e.g., GoAhead).
- **evidence summary**: 1 event recorded by the Tanner honeypot.
- **confidence**: Medium
- **recommended monitoring pivots**: Monitor for any follow-up activity from the source IP that sent this probe.

### 8) Known-Exploit / Commodity Exclusions
- **Credential Noise**: Standard brute-force attempts observed, primarily against SSH. Top usernames included `root` (25 attempts), `admin` (4 attempts), and `user` (3 attempts).
- **VNC Scanning**: The most frequent signature was "GPL INFO VNC server response" with 2,528 hits, indicating widespread, automated scanning for open VNC servers. This corresponds to the high volume of traffic to ports 5901-5903.
- **General Scanning/Probing**: Signatures such as "ET DROP Dshield Block Listed Source group 1" (39 hits) confirm that some source IPs are known bad actors listed on public blocklists.
- **SSH Probing**: The "ET INFO SSH session in progress on Expected Port" signature (22 hits) aligns with the observed credential brute-force attempts.

### 9) Infrastructure & Behavioral Classification
- **exploitation vs scanning**: The overwhelming majority of activity (850+ of 896 events) is classified as **scanning and reconnaissance**. This includes VNC port scans, SSH brute-forcing, and ICS protocol probes. A small amount of activity (6 events) is classified as **known exploitation** (CVE-2025-55182).
- **campaign shape**: The dominant shape is a distributed **spray** of scanning from multiple sources (ASNs like DigitalOcean, UCLOUD) and countries (US, Brazil, Hong Kong).
- **infra reuse indicators**: The high concentration of attacks from AS14061 (DigitalOcean, LLC) indicates a common hosting provider used by attackers for scanning infrastructure.
- **odd-service fingerprints**: ICS (`kamstrup_protocol`) and embedded web server (`/goform/formJsonAjaxReq`) probes were identified.

### 10) Evidence Appendix
**Emerging n-day: CVE-2025-55182**
- **source IPs with counts**: Not available in summary data.
- **target ports/services**: HTTP/HTTPS
- **payload/artifact excerpts**: Not available in summary data.

**Botnet Mapping: VNC-SCAN-01**
- **source IPs with counts**: Top overall attacker IPs were `160.174.122.232` (88), `128.1.131.163` (78), `189.50.142.82` (78).
- **ASNs with counts**: AS14061 (DigitalOcean, LLC): 203, AS6713 (Itissalat Al-MAGHRIB): 88, AS135377 (UCLOUD INFORMATION TECHNOLOGY HK LIMITED): 86.
- **target ports/services**: 5901, 5902, 5903.
- **paths/endpoints**: N/A.
- **temporal checks results**: N/A.

### 11) Indicators of Interest
- **CVE**: `CVE-2025-55182`
- **Path**: `/goform/formJsonAjaxReq`
- **Protocol**: `kamstrup_protocol`
- **Top Attacker IP**: `160.174.129.232` (88 events)
- **Top Attacker ASN**: `14061` (DigitalOcean, LLC)

### 12) Backend Tool Issues
- No tool failures were reported by the agents that ran.
- However, the overall workflow was incomplete. The `CandidateDiscoveryAgent`, `CandidateValidationLoopAgent`, and `DeepInvestigationLoopController` agents did not run. This represents a major gap in the analysis, preventing the identification and validation of any potentially novel threats. All findings are therefore based on high-level, aggregate data.

### 13) Agent Action Summary (Audit Trail)
- **agent_name**: ParallelInvestigationAgent
- **purpose**: Run initial data gathering agents concurrently.
- **inputs_used**: `investigation_start`, `investigation_end`.
- **actions_taken**: Initiated BaselineAgent, KnownSignalAgent, CredentialNoiseAgent, and HoneypotSpecificAgent.
- **key_results**: Successfully collected initial telemetry across all four areas.
- **errors_or_gaps**: None.

- **agent_name**: BaselineAgent
- **purpose**: Gather general statistics on attack traffic.
- **inputs_used**: `investigation_start`, `investigation_end`.
- **actions_taken**: Queried for total attacks, top countries, source IPs, ASNs, and country-to-port mappings.
- **key_results**: Identified 896 total attacks, with the US as the top source country and DigitalOcean as the top source ASN. VNC ports were heavily targeted from US sources.
- **errors_or_gaps**: None.

- **agent_name**: KnownSignalAgent
- **purpose**: Identify activity matching known signatures and CVEs.
- **inputs_used**: `investigation_start`, `investigation_end`.
- **actions_taken**: Queried for top alert signatures, CVEs, and alert categories.
- **key_results**: Identified VNC scanning as the top signature, and detected 6 events matching CVE-2025-55182.
- **errors_or_gaps**: None.

- **agent_name**: CredentialNoiseAgent
- **purpose**: Analyze brute-force and credential stuffing activity.
- **inputs_used**: `investigation_start`, `investigation_end`.
- **actions_taken**: Queried for top usernames, passwords, and attacker operating systems.
- **key_results**: Found `root` as the top username. Identified Windows and Linux as the dominant attacker OS fingerprints.
- **errors_or_gaps**: None.

- **agent_name**: HoneypotSpecificAgent
- **purpose**: Query for data from specialized, high-interaction honeypots.
- **inputs_used**: `investigation_start`, `investigation_end`.
- **actions_taken**: Queried Redis, ADB, Conpot, and Tanner honeypot logs.
- **key_results**: Found no ADB activity. Identified 24 events targeting the `kamstrup_protocol` (Conpot) and 1 event for the `/goform/formJsonAjaxReq` path (Tanner).
- **errors_or_gaps**: None.

- **agent_name**: CandidateDiscoveryAgent
- **purpose**: Sift through telemetry to find novel or interesting attack patterns.
- **inputs_used**: N/A
- **actions_taken**: Not executed.
- **key_results**: N/A
- **errors_or_gaps**: This agent was not run, preventing the discovery of unmapped threats.

- **agent_name**: CandidateValidationLoopAgent
- **purpose**: Validate and enrich candidates found by the discovery agent.
- **inputs_used**: N/A
- **actions_taken**: Not executed.
- **key_results**: N/A
- **errors_or_gaps**: This agent was not run, preventing validation of any potential threats.

- **agent_name**: DeepInvestigationLoopController
- **purpose**: Perform deep, adaptive investigation on high-priority leads.
- **inputs_used**: N/A
- **actions_taken**: Not executed.
- **key_results**: N/A
- **errors_or_gaps**: This agent was not run.

- **agent_name**: OSINTAgent
- **purpose**: Enrich findings with open-source intelligence.
- **inputs_used**: N/A
- **actions_taken**: Not executed.
- **key_results**: N/A
- **errors_or_gaps**: This agent was not run.

- **agent_name**: ReportAgent
- **purpose**: Compile the final report from workflow state.
- **inputs_used**: `baseline_result`, `known_signals_result`, `credential_noise_result`, `honeypot_specific_result`. Missing `candidate_discovery_result`, `validated_candidates`.
- **actions_taken**: Assembled this report. Noted the degraded mode due to the incomplete workflow.
- **key_results**: Generated this markdown report.
- **errors_or_gaps**: None in this agent; gaps are from missing inputs.

# Deep Investigation Summary: CVE-2025-55182 and Related Campaigns

### Executive Summary
The investigation successfully expanded from a low-volume alert for **CVE-2025-55182** into a detailed analysis of a wider scanning ecosystem. The initial CVE event was contextualized as part of opportunistic internet background noise. More importantly, the investigation fully profiled a persistent, multi-purpose vulnerability scanner (`193.142.146.230`), connected its external campaign to internal telemetry, and identified a key signature gap for a known router exploit.

### Key Findings:
1.  **CVE-2025-55182 Attacker Profile (IP: 193.32.162.28 - Romania, AS47890 Unmanaged Ltd)**
    *   Initially identified as the sole source for 6 events related to CVE-2025-55182.
    *   Beyond the CVE, this IP also leveraged a **Javascript Prototype Pollution** technique (signature: `ET HUNTING Javascript Prototype Pollution Attempt via __proto__ in HTTP Body`), indicating a more versatile exploit approach.
    *   Targeted React/Next.js application paths (e.g., `/api/route`, `/_next/server`, `/app`, `/api`, `/_next`, `/`) on destination port 9999.
    *   Observed to target at least two distinct external IP addresses (`134.199.242.175` and `167.71.255.16`), suggesting it is part of a broader campaign rather than an isolated probe.

2.  **Target Host Analysis (IPs: 134.199.242.175 and 167.71.255.16 - both DigitalOcean, AS14061)**
    *   Both external target IPs were identified as generic cloud servers that attract a high volume and diverse range of scanning and reconnaissance from numerous unrelated actors.
    *   Activity included broad scanning (e.g., Zmap user agents), suspicious user agents (`visionheight.com/scan`), and specific service probes.
    *   The observation that target `134.199.242.175` is hosted on DigitalOcean (AS14061) is significant, as DigitalOcean was also the top source ASN in the baseline report for overall attack traffic, indicating shared infrastructure or common targets.

3.  **Persistent Multi-Purpose Scanner Profile (IP: 193.142.146.230 - Germany, AS213438 ColocaTel Inc.)**
    *   This actor emerged as a key finding, demonstrating a swift, automated, and fan-out scanning campaign lasting approximately three minutes.
    *   **Tactics, Techniques, and Procedures (TTPs)**:
        *   **Docker Engine API Probing**: Scanned for exposed Docker daemons on port 2376 using a `Go-http-client` user agent and the `/version` path (and variations like `/v1.16/version`).
        *   **SOHO Router Exploit Scanning**: Actively hunted for vulnerable SOHO routers on port 80 using the specific path `/goform/formJsonAjaxReq`.
    *   **Correlation**: This actor was observed hitting both external target IPs and, crucially, one of the internal Tanner honeypots with the `/goform/formJsonAjaxReq` probe. This definitively linked external scanning to internal telemetry.

4.  **Vulnerability and Signature Gap for CVE-2025-43989**
    *   OSINT research definitively linked the `/goform/formJsonAjaxReq` path to **CVE-2025-43989**, an unauthenticated command injection vulnerability in Shenzhen Tuoshi, Dionlink, and KuWFi SOHO routers.
    *   Despite this strong association, queries for `CVE-2025-43989` within our Suricata security logs returned no results.
    *   **Conclusion**: There is a **critical gap in our current intrusion detection signatures**, as activity explicitly targeting this known router exploit is not being tagged with the corresponding CVE ID. This limits our ability to track and alert on this specific threat.

### Indicators of Interest:
*   **CVEs**: `CVE-2025-55182`, `CVE-2025-43989` (detection gap)
*   **Attacker IPs**: `193.32.162.28`, `193.142.146.230`, `5.187.35.142`, `128.199.225.7`, `3.131.220.121`, `9.234.8.125`, `43.106.124.70`, `205.210.31.79`, `18.116.101.220`, `8.216.4.35`, `14.135.74.131`, `47.236.167.82`, `205.210.31.216`, `152.32.213.168`, `148.153.56.174`, `65.49.1.222`, `3.134.216.108`, `3.130.168.2`, `207.90.244.12`, `14.116.219.149`, `117.80.234.157`, `3.129.187.38`, `47.245.142.0`, `77.90.185.118`, `149.86.227.60`, `124.117.192.167`.
*   **Attacker ASNs**: AS47890 (Romania, Unmanaged Ltd), AS213438 (Germany, ColocaTel Inc.), AS16509 (US, Amazon.com, Inc.), AS8075 (US, Microsoft Corporation), AS45102 (SG/JP/DE, Alibaba US Technology Co., Ltd.), AS14061 (SG/US, DigitalOcean, LLC), AS4134 (CN, Chinanet), AS6939 (US, Hurricane Electric LLC), AS206264 (NL, Amarutu Technology Ltd), AS174 (US, Cogent Communications, LLC), AS58466 (CN, CHINANET Guangdong province network), AS396982 (US, Google LLC), AS135377 (HK, UCLOUD INFORMATION TECHNOLOGY HK LIMITED), AS63199 (US, CDS Global Cloud Co., Ltd), AS201814 (PL, MEVSPACE sp. z o.o.), AS213790 (IR, Limited Network LTD).
*   **Targeted Paths**: `/api/route`, `/_next`, `/_next/server`, `/api`, `/app`, `/`, `/containers/json`, `/goform/formJsonAjaxReq`, `/version`, `/favicon.ico`.
*   **User Agents**: `Mozilla/5.0 (iPhone; CPU iPhone OS 17_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/134.0.6998.99 Mobile/15E148 Safari/604.1`, `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36 Edg/134.0.0.0`, `Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36`, `Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36`, `Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/605.1.15 (KHTML, like Gecko) Chrome/134.0.6998.135 Mobile Safari/537.36`, `Mozilla/5.0 (X11; CrOS x86_64 14541.0.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36`, `Mozilla/5.0 zgrab/0.x`, `Go-http-client/1.1`, `Custom-AsyncHttpClient`, `curl/7.64.1`, `visionheight.com/scan Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/126.0.0.0 Safari/537.36`, `Hello from Palo Alto Networks`, `Mozilla/5.0 (Windows NT 6.1; WOW64; rv:53.0) Gecko/20100101 Firefox/53.0`, `Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:136.0) Gecko/20100101 Firefox/136.`, `Mozilla/5.0 (Linux; Android 14; SM-F9560 Build/UP1A.231005.007; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/127.0.6533.103 Mobile Safari/537.36`, `Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.36`, `Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:146.0) Gecko/20100101 Firefox/146.0`, `Mozilla/5.0`.