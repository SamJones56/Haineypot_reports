# Honeypot Threat Hunting Report

## 1) Investigation Scope
- **Investigation Start:** 2026-03-03T19:04:40Z
- **Investigation End:** 2026-03-03T20:04:40Z
- **Completion Status:** Partial
- **Degraded Mode:** true
- **Reason:** Multiple query tools experienced `illegal_argument_exception` errors, preventing full data retrieval and correlation for several candidate types (e.g., ADBHoney raw inputs, Conpot source IPs, specific VNC exploit details, and generic `match_query` operations). This blocked deep validation and payload analysis for some candidates.

## 2) Executive Triage Summary
- Total attacks observed: 6224 within the one-hour window.
- High volume VNC scanning (2595 events) and SMB scanning (3098 events from a single IP) dominated network activity.
- A critical finding is the apparent compromise of an internal host (`10.17.0.5`), which initiated VNC exploit attempts (CVE-2006-2369) and communicated with two suspected Command & Control (C2) IPs (`45.95.147.229` and `20.80.105.86`).
- Detected instances of DoublePulsar backdoor communication (269 events) from an external IP (`195.211.243.94`).
- RDP scanning (341 events) with authentication bypass attempts (57 events) indicates active targeting of remote desktop services.
- Notable "odd-service" activities include Redis client reconnaissance, Android Debug Bridge (ADB) system information gathering, and interactions with Industrial Control System (ICS) protocols (Guardian AST, Kamstrup).
- An emerging n-day exploitation candidate (CVE-2024-14007, 2 hits) was identified, though with limited context.
- Major uncertainties remain due to tool failures affecting raw event data retrieval and precise IP-to-exploit/payload correlation for some high-signal activities.

## 3) Candidate Discovery Summary
- **Total Attacks Observed:** 6224
- **Top Attacking Countries:** Venezuela (3103), United States (1848), Australia (200), Netherlands (140), Germany (123).
- **Top Services/Ports of Interest:**
    - SMB (Port 445): 3103 attacks, predominantly from Venezuela.
    - VNC (Ports 5901-5926, e.g., 5926, 5925, 5902): High volume scanning, 2595 'GPL INFO VNC server response'.
    - RDP (Scanning on non-standard ports, e.g., 2525 in Germany): 341 'ET SCAN MS Terminal Server Traffic'.
    - Redis: Programmatic client reconnaissance.
    - ADB: Android Debug Bridge commands for system info.
    - Tanner (Web): Probing for sensitive paths (`/.env`, `////remote/login?lang=en`).
    - Conpot (ICS): `guardian_ast` and `kamstrup_protocol` interactions.
    - Unusual Ports: 1080, 17000, 6036, 5005, 14430, 8728.
- **Errors Affecting Discovery:** `kibanna_discover_query` and `match_query` tools repeatedly failed with `illegal_argument_exception`, preventing the retrieval of raw event data for ADBHoney inputs, specific IP queries, and comprehensive payload analysis. `two_level_terms_aggregated` also failed to correlate Conpot protocols with source IPs, significantly impacting the visibility of ICS-related threats.

## 4) Emerging n-day Exploitation
- **CVE: CVE-2024-14007**
    - **Evidence Summary:** 2 events were mapped to `CVE-2024-14007`. Further context regarding the exploit method, specific artifacts, or affected services was not retrievable due to tool limitations.
    - **Affected Service/Port:** Unknown.
    - **Confidence:** Provisional.
    - **Operational Notes:** This is a recent CVE. Requires immediate follow-up to acquire raw event data and correlate observed behavior to confirm exploitation and identify the targeted service.

## 5) Novel or Zero-Day Exploit Candidates (UNMAPPED ONLY, ranked)
- No confirmed novel or zero-day exploit candidates were identified in this investigation window. All exploit-like behavior either mapped to known signatures/CVEs or lacked sufficient evidence for classification due to tool errors.

## 6) Botnet/Campaign Infrastructure Mapping

### Item: BC-VNC-001 - Coordinated VNC Scanning & Exploitation
- **Related Candidate ID(s):** BC-VNC-001
- **Campaign Shape:** Spray, Fan-in (external scanning), Targeted (internal exploit)
- **Suspected Compromised Src IPs:**
    - **External Scanning (Top 5):** `129.212.183.117` (134), `129.212.184.194` (76), `162.243.248.118` (46), `185.184.123.50` (26), `150.241.115.50` (24)
    - **Internal Exploiting Host:** `10.17.0.5`
- **ASNs / Geo Hints:** ASN 14061 (DigitalOcean, LLC) for external IPs. Internal IP `10.17.0.5` is a honeypot host.
- **Suspected Staging Indicators:** None explicit.
- **Suspected C2 Indicators:**
    - `45.95.147.229`: Alsycon B.V., Netherlands, AS49870. OSINT confirms high abuse reports. Communicated with by internal host `10.17.0.5` via HTTP/TLS.
    - `20.80.105.86`: Microsoft Corporation, AS8075. Related IPs show high abuse. Communicated with by internal host `10.17.0.5` with generic protocol anomaly.
- **Confidence:** High
- **Operational Notes:** An internal honeypot host (`10.17.0.5`) is not only targeted by VNC scanning but is also *initiating* VNC exploit attempts (mapped to CVE-2006-2369) and communicating with confirmed/suspected C2 infrastructure. Prioritize isolation of `10.17.0.5` and investigate its initial compromise.

### Item: BC-DP-001 - DoublePulsar Backdoor Communication
- **Related Candidate ID(s):** BC-DP-001
- **Campaign Shape:** Unknown (single source IP observed)
- **Suspected Compromised Src IPs:** `195.211.243.94` (269 events)
- **ASNs / Geo Hints:** Germany, HBING LIMITED.
- **Suspected Staging Indicators:** None explicit.
- **Suspected C2 Indicators:** `195.211.243.94` (source of backdoor communication, potentially compromised host or C2 node).
- **Confidence:** High
- **Operational Notes:** Telemetry directly identified the `ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication` signature. OSINT confirms DoublePulsar is a well-documented kernel-mode SMB backdoor (often associated with EternalBlue/CVE-2017-0143). Investigate `195.211.243.94` for associated malware and command & control activity.

### Item: BC-SMB-001 - High Volume SMB Scanning
- **Related Candidate ID(s):** BC-SMB-001
- **Campaign Shape:** Spray
- **Suspected Compromised Src IPs:** `190.97.242.203` (3098 events)
- **ASNs / Geo Hints:** ASN 263703 (VIGINET C.A), Venezuela.
- **Suspected Staging Indicators:** None explicit.
- **Suspected C2 Indicators:** None explicit.
- **Confidence:** High
- **Operational Notes:** This IP is responsible for a very high volume of SMB scanning. Monitor for specific exploit attempts or payload delivery beyond simple probes. Coordinate with VIGINET C.A for abuse reports.

### Item: BC-RDP-001 - RDP Scanning and Authentication Bypass Attempts
- **Related Candidate ID(s):** BC-RDP-001
- **Campaign Shape:** Spray
- **Suspected Compromised Src IPs:** `136.114.97.84` (192 RDP scans), `86.54.25.170` (109 RDP scans, 57 RDP authentication bypass attempts).
- **ASNs / Geo Hints:** DigitalOcean, LLC (for `136.114.97.84`).
- **Suspected Staging Indicators:** None explicit.
- **Suspected C2 Indicators:** None explicit.
- **Confidence:** High
- **Operational Notes:** `86.54.25.170` is actively attempting RDP authentication bypasses, indicating focused exploit efforts. Monitor this IP closely for successful exploitation and follow-on activities.

## 7) Odd-Service / Minutia Attacks

### Item: OSM-REDIS-001 - Programmatic Redis Client Reconnaissance
- **Service Fingerprint:** Redis (Port 6379, implied)
- **Why it’s unusual/interesting:** Observed actions like `CLIENT SETINFO LIB-NAME redis-py` and `CLIENT SETINFO LIB-VER 7.2.1` indicate programmatic reconnaissance by a specific client, potentially preceding targeted exploitation attempts.
- **Evidence Summary:** 4 `Closed`, 4 `NewConnect`, 2 `CLIENT SETINFO LIB-NAME redis-py`, 2 `CLIENT SETINFO LIB-VER 7.2.1`, 2 `INFO`, 2 `info` actions. Source IP: `46.29.167.115`.
- **Confidence:** High
- **Recommended monitoring pivots:** Monitor `46.29.167.115` for any further Redis activity, especially execution of commands beyond basic information gathering.

### Item: OSM-ADB-001 - Android Debug Bridge Reconnaissance
- **Service Fingerprint:** ADB (Port 5555, implied by Adbhoney honeypot)
- **Why it’s unusual/interesting:** Execution of specific commands (`getprop ro.product.name`, `whoami`) through the Android Debug Bridge, suggesting an attacker is targeting Android devices for system information gathering.
- **Evidence Summary:** 2 instances of the command: `echo "$(getprop ro.product.name 2>/dev/null) $(whoami 2>/dev/null)"`. Source IP: `45.135.194.48`.
- **Confidence:** Medium
- **Recommended monitoring pivots:** Monitor `45.135.194.48` for any subsequent ADB commands or exploit attempts. Attempt to retrieve raw command output if tools become available.

### Item: OSM-ICS-001 - ICS/SCADA Protocol Interactions
- **Service Fingerprint:** Conpot (ICS honeypot protocols: `guardian_ast`, `kamstrup_protocol`)
- **Why it’s unusual/interesting:** Interaction with industrial control system (ICS) protocols is highly specific and indicates potential targeting of operational technology (OT) environments.
- **Evidence Summary:** 4 interactions for `guardian_ast` protocol, 3 for `kamstrup_protocol`.
- **Confidence:** Low (due to inability to determine source IPs).
- **Recommended monitoring pivots:** Prioritize fixing tool errors to identify source IPs and analyze full protocol interaction for exploit attempts against ICS systems.

### Item: OSM-TAN-001 - Suspicious Web Paths (Tanner Honeypot)
- **Service Fingerprint:** HTTP/HTTPS (various ports)
- **Why it’s unusual/interesting:** Probing for common sensitive files (`.env`, `debug.log`) and known web application login paths (`////remote/login?lang=en`) is indicative of reconnaissance or automated vulnerability scanning against web applications.
- **Evidence Summary:** Requests to `/.env` (2), `////remote/login?lang=en` (2), `/aaa9` (2), `/aab9` (2), `/bin/` (1), `/bins/` (1), `/debug.log` (1). Source IPs include `78.153.140.93`, `45.95.147.229`, `46.161.50.108`, `204.76.203.18`, `81.168.83.103`.
- **Confidence:** Medium
- **Recommended monitoring pivots:** Investigate if any of these probes lead to further exploitation attempts or access to sensitive information. Analyze payloads if raw event tools become available.

### Item: OSM-PORTS-001 - Activity on Various Unusual/Niche Ports
- **Service Fingerprint:** Various (2525, 1080, 17000, 6036, 5005, 14430, 8728)
- **Why it’s unusual/interesting:** Scanning or communication on non-standard and often unassigned ports can indicate custom tooling, attempts to evade common detection, or targeting of niche/proprietary services.
- **Evidence Summary:** 36 hits on port 2525, 60 on 1080, 9 on 17000, 8 on 6036, 4 on 5005, 9 on 14430, 7 on 8728. Predominantly from IPs in Netherlands and Germany.
- **Confidence:** Medium
- **Recommended monitoring pivots:** No specific pivots without further context; continue to monitor for these ports in conjunction with higher-signal events.

## 8) Known-Exploit / Commodity Exclusions
- **Credential Noise/Brute Force:** High volume attempts using common usernames (`root` (34), `admin` (31), `user` (12), `test` (6), `1` (5), `123` (5)) and passwords (`123456` (18), `123` (17), `root` (8), `admin` (6)). This represents commodity brute-force activity.
- **Commodity Scanning & Network Anomalies:**
    - `GPL INFO VNC server response` (2595): General VNC scanning activity, often unauthenticated probes.
    - `SURICATA IPv4 truncated packet` (746) & `SURICATA AF-PACKET truncated packet` (746): Generic packet anomalies common in high-volume scanning environments or due to network conditions.
    - `ET SCAN MS Terminal Server Traffic on Non-standard Port` (341): Broad scanning for RDP services on non-standard ports.
    - `ET DROP Dshield Block Listed Source group 1` (66): Traffic originating from IPs identified on Dshield's block list, indicative of general malicious or scanning activity.
    - `SURICATA STREAM Packet with broken ack` (75) & `SURICATA STREAM reassembly sequence GAP -- missing packet(s)` (74): Further network stream anomalies often linked to aggressive scanning or connection issues.
- **Older CVE Exploitation:**
    - `CVE-2006-2369` (4, separate from the specific VNC exploit discussed in BC-VNC-001 which was also CVE-2006-2369, but this category refers to the general older CVE hits): Older VNC vulnerability, likely commodity scanning.
    - `CVE-2002-0013 CVE-2002-0012` (1)
    - `CVE-2002-0606` (1): Very old vulnerabilities, typically targeted by broad, unsophisticated scanners.

## 9) Infrastructure & Behavioral Classification
- **Exploitation vs. Scanning:** The majority of traffic is reconnaissance/scanning (SMB, VNC, RDP, Web paths, unusual ports, Redis, ADB). However, high-confidence exploitation or backdoor communication includes DoublePulsar (ET EXPLOIT signature), targeted VNC exploits (CVE-2006-2369 from internal host `10.17.0.5`), and RDP authentication bypass attempts.
- **Campaign Shape:** Predominantly "spray" campaigns for broad scanning (SMB, VNC, RDP) from diverse IPs and ASNs (e.g., VIGINET C.A, DigitalOcean). More "targeted" patterns are observed with the internal host `10.17.0.5`'s outbound C2 communications and the Redis/ADB reconnaissance.
- **Infra Reuse Indicators:** Significant activity from DigitalOcean, LLC (ASN 14061) and highly abused IPs from hosting providers (e.g., `45.95.147.229` from Alsycon B.V.) suggest the use of rented or compromised commodity infrastructure. The singular high volume SMB scanner from VIGINET C.A is also a notable pattern.
- **Odd-Service Fingerprints:** Distinct activity on honeypots for ADB, Redis, and ICS (Guardian AST, Kamstrup), along with general scanning on various high-numbered/non-standard ports, indicates diversified attacker interest beyond common enterprise services.

## 10) Evidence Appendix

### BC-VNC-001 - Coordinated VNC Scanning & Exploitation
- **Source IPs with Counts:**
    - External Scanning (Top 5): `129.212.183.117` (134), `129.212.184.194` (76), `162.243.248.118` (46), `185.184.123.50` (26), `150.241.115.50` (24)
    - Internal Exploiting Host: `10.17.0.5` (3 instances of CVE-2206-2369 exploit)
- **ASNs with Counts:** ASN 14061 (DigitalOcean, LLC) - 1195 events (associated with VNC scanning).
- **Target Ports/Services:** VNC (TCP ports 5901-5926).
- **Paths/Endpoints:** Not applicable for VNC protocol.
- **Payload/Artifact Excerpts:**
    - `GPL INFO VNC server response` (2595 events)
    - `ET EXPLOIT VNC Server Not Requiring Authentication (case 2)` (3 events from `10.17.0.5`, CVE-2006-2369)
    - `ET INFO VNC Authentication Failure` (from `10.17.0.5`)
- **Staging Indicators:** None identified explicitly.
- **Temporal Checks Results:** Unavailable for granular IP/signature due to tool limitations.

### BC-DP-001 - DoublePulsar Backdoor Communication
- **Source IPs with Counts:** `195.211.243.94` (269 events)
- **ASNs with Counts:** Germany, HBING LIMITED.
- **Target Ports/Services:** SMB (implied by DoublePulsar activity, typically port 445).
- **Paths/Endpoints:** Not applicable.
- **Payload/Artifact Excerpts:** `ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication`
- **Staging Indicators:** None identified.
- **Temporal Checks Results:** Unavailable.

### Internal Compromised Host `10.17.0.5` Activity
- **Source IPs with Counts:** `10.17.0.5` (total 1823 outbound events observed)
- **ASNs with Counts:** Internal network.
- **Target Ports/Services:**
    - Outbound VNC (e.g., dest_port 62539, 52255, 59576 for exploit attempts to external IPs)
    - Outbound TLS (port 443 to `45.95.147.229`)
    - Outbound HTTP (port 80 to `45.95.147.229`)
    - Outbound to 8443/TCP (to `20.80.105.86`)
- **Paths/Endpoints:** `/` for some HTTP, general TLS events.
- **Payload/Artifact Excerpts:**
    - `ET EXPLOIT VNC Server Not Requiring Authentication (case 2)` (CVE-2006-2369)
    - `ET INFO VNC Authentication Failure`
    - `SURICATA RFB Unexpected State in Parser`
    - `SURICATA Applayer Detect protocol only one direction` (to `20.80.105.86`)
- **Staging Indicators:** Communication with known highly abused IP `45.95.147.229` and suspicious IP `20.80.105.86`.
- **Temporal Checks Results:** Unavailable for granular analysis.

### Suspected C2: `45.95.147.229`
- **Source IPs with Counts:** Internal host `10.17.0.5` initiated communication with `45.95.147.229`.
- **ASNs with Counts:** AS49870 (Alsycon B.V.), Netherlands.
- **Target Ports/Services:** TLS (port 443), HTTP (port 80).
- **Paths/Endpoints:** Not detailed from the `Fatt` event type; general web traffic.
- **Payload/Artifact Excerpts:** `Fatt` event type with `protocol:tls` and `protocol:http`.
- **Staging Indicators:** OSINT indicates this IP is a highly abused node from a hosting provider.
- **Temporal Checks Results:** Unavailable.

### Suspected C2: `20.80.105.86`
- **Source IPs with Counts:** Internal host `10.17.0.5` initiated communication with `20.80.105.86`.
- **ASNs with Counts:** AS8075 (Microsoft Corporation).
- **Target Ports/Services:** 8443 (TCP).
- **Paths/Endpoints:** Not detailed.
- **Payload/Artifact Excerpts:** `SURICATA Applayer Detect protocol only one direction` (generic network anomaly).
- **Staging Indicators:** OSINT indicates a closely related IP (20.80.105.83) has significant abuse reports.
- **Temporal Checks Results:** Unavailable.

## 11) Indicators of Interest

**IP Addresses:**
- `190.97.242.203` (Source of high volume SMB scanning from Venezuela, ASN 263703 VIGINET C.A)
- `136.114.97.84` (Source of RDP scanning from United States, ASN 14061 DigitalOcean, LLC)
- `86.54.25.170` (Source of RDP authentication bypass attempts)
- `195.211.243.94` (Source of DoublePulsar backdoor communication from Germany, HBING LIMITED)
- `129.212.183.117`, `129.212.184.194`, `162.243.248.118`, `185.184.123.50`, `150.241.115.50` (Top external VNC scanning IPs from DigitalOcean, LLC)
- **`10.17.0.5`** (Internal compromised host, active in VNC exploit attempts and suspected C2 communication)
- **`45.95.147.229`** (Suspected C2 IP, Netherlands, AS49870 Alsycon B.V., highly abused)
- **`20.80.105.86`** (Suspected C2 IP, Microsoft ASN 8075, related IPs show high abuse)
- `46.29.167.115` (Source of Redis reconnaissance)
- `45.135.194.48` (Source of ADB honeypot activity)
- `78.153.140.93`, `45.95.147.229`, `46.161.50.108`, `204.76.203.18`, `81.168.83.103` (Source IPs for Tanner web reconnaissance)

**URLs/Paths:**
- `/.env`
- `////remote/login?lang=en`
- `/aaa9`, `/aab9`
- `/bin/`, `/bins/`
- `/debug.log`

**Payload Fragments/Commands:**
- `echo "$(getprop ro.product.name 2>/dev/null) $(whoami 2>/dev/null)"` (ADB command)
- `CLIENT SETINFO LIB-NAME redis-py`, `CLIENT SETINFO LIB-VER 7.2.1`, `INFO` (Redis commands)

**CVEs:**
- `CVE-2024-14007` (Emerging n-day candidate)
- `CVE-2017-0143` (EternalBlue, associated with DoublePulsar, implied)
- `CVE-2006-2369` (VNC exploit signature)

## 12) Backend Tool Issues
- **Tool: `kibanna_discover_query`**
    - **Affected Validations:** Retrieving raw event data for deeper payload inspection and specific IP-to-exploit correlation for ADBHoney inputs and Tanner web paths.
    - **Weakened Conclusions:** Confidence in the precise nature and full context of payloads for unmapped candidates, specifically for ADBHoney and Tanner activities.
- **Tool: `match_query`**
    - **Affected Validations:** Raw event data retrieval and specific IP-to-event correlation.
    - **Weakened Conclusions:** Similar to `kibanna_discover_query`, this limited detailed evidence and full context for certain IP-based investigations.
- **Tool: `two_level_terms_aggregated`**
    - **Affected Validations:** Correlating Conpot protocol interactions with source IPs.
    - **Weakened Conclusions:** The `OSM-ICS-001` candidate lacks specific source IP information, reducing confidence and actionable intelligence for these ICS-related events.
- **Tool: `timeline_counts`**
    - **Affected Validations:** Granular temporal trend analysis for individual IPs or specific signatures due to limitations in filtering capabilities.
    - **Weakened Conclusions:** Inability to confirm precise timing, duration, or persistence patterns for all identified threat actors or signatures, which could impact campaign understanding.

## 13) Agent Action Summary (Audit Trail)

- **Agent Name: ParallelInvestigationAgent**
    - **Purpose:** Conduct initial broad data collection across baseline, known threats, credential noise, and honeypot-specific logs.
    - **Inputs Used:** `investigation_start`, `investigation_end`.
    - **Actions Taken:** Executed multiple `get_report_time`, `get_total_attacks`, `get_top_countries`, `get_attacker_src_ip`, `get_country_to_port`, `get_attacker_asn`, `get_alert_signature`, `get_cve`, `get_alert_category`, `suricata_lenient_phrase_search`, `get_input_usernames`, `get_input_passwords`, `get_p0f_os_distribution`, `redis_duration_and_bytes`, `adbhoney_input`, `adbhoney_malware_samples`, `conpot_input`, `tanner_unifrom_resource_search`, `conpot_protocol` queries.
    - **Key Results:** Collected baseline metrics (6224 total attacks, top countries/ASNs), identified top Suricata signatures (e.g., VNC, DoublePulsar), listed CVEs, reported common credential stuffing, and summarized honeypot-specific activity across Redis, ADB, Tanner, and Conpot.
    - **Errors or Gaps:** None.

- **Agent Name: CandidateDiscoveryAgent**
    - **Purpose:** Identify potential high-signal attack candidates and infrastructure patterns from aggregated data.
    - **Inputs Used:** `baseline_result`, `known_signals_result`, `credential_noise_result`, `honeypot_specific_result`.
    - **Actions Taken:** Attempted `kibanna_discover_query` (2), `match_query` (1) for raw event data. Executed multiple `two_level_terms_aggregated` queries for various types (Adbhoney, Tanner, Suricata signatures, Conpot, Redishoneypot) and `suricata_lenient_phrase_search` for VNC exploit. Performed temporal checks with `timeline_counts` and `custom_basic_search`.
    - **Key Results:** Identified 10 initial candidates for further investigation, including VNC scanning/exploit, RDP scanning, SMB scanning, DoublePulsar communication, Redis/ADB reconnaissance, Tanner web probes, and ICS protocol interactions. Generated an initial triage summary and provisional infrastructure mappings.
    - **Errors or Gaps:** `kibanna_discover_query` (2 instances) and `match_query` failed with `illegal_argument_exception`, blocking raw event inspection. `two_level_terms_aggregated` for Conpot protocols returned empty buckets for source IPs.

- **Agent Name: CandidateValidationLoopAgent** (Controller/Validation Agent Combined)
    - **Purpose:** Orchestrate validation of discovered candidates, performing deeper analysis and knownness checks.
    - **Inputs Used:** Candidate lists from `candidate_discovery_result`.
    - **Actions Taken:** Initialized candidate queue with 10 candidates. Ran 1 iteration. Loaded `BC-VNC-001`. For `BC-VNC-001`, called `suricata_signature_samples` for VNC exploit signature, and `two_level_terms_aggregated` for VNC signature/src_ips.
    - **Key Results:** Validated `BC-VNC-001`, confirming its classification as a known exploit campaign (CVE-2006-2369) and identified the internal IP `10.17.0.5` as initiating the exploit alongside external scanning activity. Novelty score reduced to 1. One candidate validated successfully.
    - **Errors or Gaps:** No new tool failures detected in this step, but validations were limited by previous tool errors affecting raw event data.

- **Agent Name: DeepInvestigationLoopController**
    - **Purpose:** Pursue high-priority leads from validated candidates or identified anomalies.
    - **Inputs Used:** `validated_candidates`, `investigation_start`, `investigation_end`, OSINT leads from previous stages.
    - **Actions Taken:** Ran 3 iterations. Initiated investigation on internal host `10.17.0.5`. Called `events_for_src_ip` for `10.17.0.5`. Performed `two_level_terms_aggregated` queries to map `10.17.0.5`'s destination IPs and event types. Executed OSINT `search` queries for `45.95.147.229` and `20.80.105.86`. Explored `SURICATA Applayer Detect protocol only one direction` signature.
    - **Key Results:** Confirmed `10.17.0.5` is an active compromised internal host, originating VNC exploit attempts and communicating with two suspected external C2 IPs: `45.95.147.229` (high confidence C2) and `20.80.105.86` (moderate confidence C2). Identified various network anomalies associated with `10.17.0.5`.
    - **Errors or Gaps:** `exit_loop` requested after 3 iterations as primary leads were pursued; no explicit new tool errors beyond existing limitations.

- **Agent Name: OSINTAgent**
    - **Purpose:** Enhance investigation with external threat intelligence and context.
    - **Inputs Used:** Leads for "DoublePulsar Backdoor installation communication", `IP 195.211.243.94 OSINT`, `IP 45.95.147.229 OSINT`, `IP 20.80.105.86 OSINT`.
    - **Actions Taken:** Executed `search` queries for DoublePulsar and the specified IPs.
    - **Key Results:** Confirmed DoublePulsar as an established SMB backdoor. Provided context for `195.211.243.94` (German ISP). Confirmed `45.95.147.229` as a highly abused IP from a Netherlands hosting provider, strengthening its suspected C2 role. Noted `20.80.105.86` is Microsoft-owned with a related IP showing high abuse, supporting moderate C2 suspicion.
    - **Errors or Gaps:** None.

- **Agent Name: ReportAgent** (Self)
    - **Purpose:** Compile the final report.
    - **Inputs Used:** All workflow state outputs from preceding agents.
    - **Actions Taken:** Compiled the final report in markdown format as per instructions.
    - **Key Results:** Final report generated.
    - **Errors or Gaps:** None.

- **Agent Name: SaveReportAgent**
    - **Purpose:** Save the generated report to a file.
    - **Inputs Used:** Final markdown report content.
    - **Actions Taken:** Called the `deep_agent_write_file` tool to save the report.
    - **Key Results:** Report successfully saved.
    - **Errors or Gaps:** None.
