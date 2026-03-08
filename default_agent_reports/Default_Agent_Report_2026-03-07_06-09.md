# Honeypot Threat Hunt Report

## 1) Investigation Scope
-   **investigation_start**: 2026-03-07T06:00:08Z
-   **investigation_end**: 2026-03-07T09:00:08Z
-   **completion_status**: Partial (degraded evidence)
-   **degraded_mode**: true (Direct correlation of Redis RCE actions to source IPs and Conpot ICS protocol interactions to source IPs were blocked.)

## 2) Executive Triage Summary
-   Total attacks observed: 21,740 within a 3-hour window.
-   Top observed services of interest include VNC (5900, 5902, 5903), SMB (445), Redis (potential RCE attempts), Tanner web exploits (PHPUnit RCE, PHP LFI/RCE, .env exposure), and Conpot ICS protocols (kamstrup_management_protocol, guardian_ast, kamstrup_protocol) on port 50100.
-   Significant known exploitation detected: High volume `ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication`, confirmed Redis Remote Code Execution (RCE) attempts, and established web vulnerabilities including PHPUnit RCE (CVE-2017-9841), PHP RCE (related to CVE-2024-4577), and `.env` file exposure.
-   Botnet/campaign activity identified with the DoublePulsar exploit, originating from IPs in Vietnam (ASN AS45899) and India (ASN AS45609), indicating a spray-type campaign.
-   Odd-service activity on TCP port 37777 (Dahua DVRs/NVRs, targeted by Mirai botnet) and TCP port 1515 (IANA ifor-protocol, also used by malware) are noted.
-   Major uncertainties exist in correlating specific source IPs to the observed Redis RCE actions and Conpot ICS protocol interactions due to query limitations.

## 3) Candidate Discovery Summary
Discovery processed 21,740 total attacks.
-   **Top Countries**: United States (6870), Vietnam (3442), France (2679).
-   **Top Source IPs**: 113.161.145.128 (3149), 79.98.102.166 (2571), 207.174.1.152 (2001).
-   **Top ASNs**: DigitalOcean, LLC (AS14061, 4690), VNPT Corp (AS45899, 3164), ADISTA SAS (AS16347, 2571).
-   **Top Alert Signatures**: `GPL INFO VNC server response` (17206), `ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication` (2260), `ET SCAN MS Terminal Server Traffic on Non-standard Port` (590).
-   **Top CVEs**: `CVE-2025-55182` (78).
-   **Honeypot Specifics**: Redis honeypot observed 7 `MODULE LOAD /tmp/exp.so` attempts and other RCE-indicative actions. Tanner honeypot detected requests to `/V2/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php`, `/?%ADd+allow_url_include%3d1+%ADd+auto_prepend_file%3dphp://input`, and `/.env`. Conpot honeypot observed 11 `kamstrup_management_protocol`, 5 `guardian_ast`, and 3 `kamstrup_protocol` interactions on port 50100.
-   **Credential Noise**: High volumes of brute-force attempts with common usernames (root, postgres, admin) and passwords (123, 123456, password).
-   **Evidence Gaps**: Direct correlation of Redis RCE actions to source IPs and Conpot ICS protocol interactions to source IPs was blocked due to query limitations.

## 4) Emerging n-day Exploitation
-   **CVE/Signature Mapping**: ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication (Signature ID 2024766)
    -   **Evidence Summary**: 2260 counts of this signature, primarily from IPs 113.160.148.67 (1303 counts) and 106.219.90.24 (957 counts).
    -   **Affected Service/Port**: SMB (TCP 445)
    -   **Confidence**: High
    -   **Operational Notes**: This is a well-documented kernel-mode implant associated with EternalBlue and WannaCry. Microsoft released patches (MS17-010) in 2017. Continued detection indicates scanning for unpatched systems or repurposed botnet activity.
-   **CVE/Signature Mapping**: Redis Remote Code Execution (RCE) via malicious module loading/replication abuse (Known Technique)
    -   **Evidence Summary**: 7 instances of `MODULE LOAD /tmp/exp.so`, and other actions like `config set dbfilename exp.so`, `config set dir /tmp/`, `SLAVEOF NO ONE`.
    -   **Affected Service/Port**: Redis (implied TCP 6379)
    -   **Confidence**: High
    -   **Operational Notes**: This represents active attempts to achieve RCE on Redis instances, often leveraging master-slave replication abuse. These are established attack vectors, and immediate patching or secure configuration (disabling dangerous commands, authentication) is recommended.
-   **CVE/Signature Mapping**: PHPUnit RCE (CVE-2017-9841), PHP RCE via allow_url_include/auto_prepend_file (related to CVE-2024-4577), and .env file exposure (Known Vulnerabilities)
    -   **Evidence Summary**: 1 count for `/V2/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php`, 1 count for `/?%ADd+allow_url_include%3d1+%ADd+auto_prepend_file%3dphp://input`, and 3 counts for `/.env`. Source IPs include 111.119.234.232 and 78.153.140.148.
    -   **Affected Service/Port**: HTTP/HTTPS (implied web server ports 80/443)
    -   **Confidence**: High
    -   **Operational Notes**: These are attempts to exploit known web application vulnerabilities, including a critical PHPUnit RCE, a recent PHP CGI bypass, and common misconfigurations exposing environment variables. Patching, secure web server configuration, and WAF rules are essential.

## 5) Novel or Zero-Day Exploit Candidates (UNMAPPED ONLY, ranked)
No novel or zero-day exploit candidates were identified in this investigation window. All exploit-like behavior was mapped to known vulnerabilities or techniques through OSINT.

## 6) Botnet/Campaign Infrastructure Mapping
-   **item_id**: BCM-001 (Related to DoublePulsar exploit)
    -   **campaign_shape**: spray
    -   **suspected_compromised_src_ips**: 113.160.148.67 (1303 counts), 106.219.90.24 (957 counts)
    -   **ASNs / geo hints**: AS45899 (VNPT Corp, Vietnam), AS45609 (Bharti Airtel Ltd., India)
    -   **suspected_staging indicators**: None identified explicitly, but source IPs act as launch points.
    -   **suspected_c2 indicators**: None explicitly identified. DoublePulsar reuses SMB port for C2.
    -   **Confidence**: High
    -   **Operational Notes**: The high volume and specific signature (`ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication`) indicate a coordinated scanning/exploitation campaign targeting SMB vulnerabilities. Focus containment on blocking these source IPs and ensuring SMBv1 is disabled/patched. Further OSINT on 113.160.148.67's specific ASN (AS45899 - VNPT Corp, Vietnam) confirms it belongs to a known ISP.

## 7) Odd-Service / Minutia Attacks
-   **item_id**: OSM-001
    -   **service_fingerprint**: kamstrup_management_protocol, guardian_ast, kamstrup_protocol on dest_port 50100. Also observed HTTP/VNC related flows on the same port.
    -   **why it’s unusual/interesting**: Port 50100 is not a standard ICS port, and the detected protocols (Kamstrup proprietary, guardian_ast) are niche, indicative of interactions with an industrial control system honeypot. Mixed HTTP/VNC traffic on this port is also anomalous for an ICS context.
    -   **evidence summary**: 11 instances of `kamstrup_management_protocol`, 5 instances of `guardian_ast`, 3 instances of `kamstrup_protocol`. HTTP GETs and VNC flows also observed.
    -   **Confidence**: Medium (OSINT inconclusive on specific exploit, but activity is definitively unusual)
    -   **recommended monitoring pivots**: Deeper inspection of raw Conpot events for payload details, behavioral analysis of source IP (8.222.169.202, AS45102 Alibaba US Technology Co., Ltd., Singapore) for further context. Monitor for similar activity on other non-standard ICS ports.
-   **item_id**: OSM-002
    -   **service_fingerprint**: TCP port 37777 (protocol unknown/Dahua DVR)
    -   **why it’s unusual/interesting**: Port 37777 is commonly associated with Dahua DVRs/NVRs/IP cameras and is a known target for botnets like Mirai due to historical vulnerabilities.
    -   **evidence summary**: Multiple flow events and Honeytrap/P0f events (187 hits in total) on port 37777.
    -   **Confidence**: Low (known commodity scanning)
    -   **recommended monitoring pivots**: None beyond current; activity is commodity scanning.
-   **item_id**: OSM-003
    -   **service_fingerprint**: TCP port 1515 (IANA: ifor-protocol; also potentially custom/malicious use)
    -   **why it’s unusual/interesting**: Port 1515 is IANA-assigned to a rarely used protocol, but OSINT indicates it can be used for custom applications or by Trojans/viruses. Observed scanning suggests probing for unknown services or specific malware.
    -   **evidence summary**: Multiple flow events and P0f events (50 hits in total) on port 1515.
    -   **Confidence**: Low (known commodity scanning)
    -   **recommended monitoring pivots**: None beyond current; activity is commodity scanning.

## 8) Known-Exploit / Commodity Exclusions
-   **VNC Scanning**: High volume `GPL INFO VNC server response` signature (17206 counts) indicating widespread VNC service discovery. (KEE-001)
-   **SMB Scanning**: High volume traffic on port 445 (SMB) from Vietnam and France, indicative of common SMB enumeration and brute force attempts. (KEE-002)
-   **SSH Scanning**: Traffic on port 22 (SSH) often with common credential attempts, typical of automated scanning. (KEE-003)
-   **MS Terminal Server Traffic on Non-standard Port**: Detection of RDP-like traffic on non-standard ports (590 counts), a known scanning pattern for misconfigured RDP services. (KEE-004)
-   **Credential Brute-Forcing**: Repeated attempts with common usernames (`root`, `postgres`, `admin`) and weak passwords (`123`, `123456`, `password`) across multiple services. (KEE-005)

## 9) Infrastructure & Behavioral Classification
-   **Exploitation vs Scanning**: The observed activity represents a mix. High-volume VNC, SMB, SSH, and port 37777/1515 activities are primarily scanning. The DoublePulsar alerts, Redis RCE attempts, and Tanner web exploit paths indicate targeted exploitation attempts against specific services. Conpot ICS interactions suggest anomalous probing of industrial control systems.
-   **Campaign Shape**: The DoublePulsar activity demonstrates a spray-like campaign, originating from a few high-volume IPs targeting many potential victims. Other scanning activities (VNC, SMB) also exhibit a broad, spray-and-pray approach.
-   **Infra Reuse Indicators**: Several source IPs (e.g., 113.160.148.67, 106.219.90.24) show high volumes across multiple events, suggesting dedicated infrastructure for attacks. ASNs like DigitalOcean, VNPT Corp, and Alibaba host significant attack traffic.
-   **Odd-Service Fingerprints**: Interactions with proprietary ICS protocols (Kamstrup, guardian_ast) on an unusual port (50100), as well as general scanning of known vulnerable IoT/CCTV ports (37777) and less common service ports (1515), highlight a broad probing for niche and misconfigured services.

## 10) Evidence Appendix

### Emerging n-day Exploitation
-   **DoublePulsar Backdoor (BCM-001)**
    -   **Source IPs with counts**: 113.160.148.67 (1303), 106.219.90.24 (957)
    -   **ASNs with counts**: AS45899 (VNPT Corp, Vietnam), AS45609 (Bharti Airtel Ltd., India)
    -   **Target ports/services**: TCP 445 (SMB)
    -   **Payload/artifact excerpts**: Signature: `ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication`
    -   **Temporal checks results**: Occurred within the investigation window (2260 total counts).
-   **Redis RCE (SUM-001)**
    -   **Source IPs with counts**: Not directly correlated due to query limitations.
    -   **ASNs with counts**: Not directly correlated.
    -   **Target ports/services**: Redis (implied TCP 6379)
    -   **Paths/endpoints**: N/A
    -   **Payload/artifact excerpts**: `MODULE LOAD /tmp/exp.so` (7 counts), `SLAVEOF NO ONE` (2), `config set dbfilename dump.rdb` (2), `config set dir .` (2), `CONFIG SET dbfilename exp.so` (1), `CONFIG SET dir /tmp/` (1), `FLUSHDB` (1).
    -   **Temporal checks results**: Occurred within the investigation window (73 total Redis actions).
-   **Tanner Web Exploits (SUM-002)**
    -   **Source IPs with counts**: 111.119.234.232 (2 counts), 78.153.140.148 (3 counts)
    -   **ASNs with counts**: AS58262 (Nrp Network), AS202306 (HOSTGLOBAL.PLUS LTD, UK)
    -   **Target ports/services**: HTTP/HTTPS (implied web ports)
    -   **Paths/endpoints**: `/V2/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php` (1), `/?%ADd+allow_url_include%3d1+%ADd+auto_prepend_file%3dphp://input` (1), `/.env` (3)
    -   **Payload/artifact excerpts**: `User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64; rv:53.0) Gecko/20100101 Firefox/53.0` for some requests.
    -   **Temporal checks results**: Occurred within the investigation window.

### Top Botnet Mapping Item
-   **DoublePulsar Backdoor (BCM-001)** (See details above in Emerging n-day Exploitation, as it directly maps to a known exploit).

### Odd-Service / Minutia Attacks
-   **Conpot ICS Protocols (OSM-001)**
    -   **Source IPs with counts**: 8.222.169.202 (multiple flows)
    -   **ASNs with counts**: AS45102 (Alibaba US Technology Co., Ltd., Singapore)
    -   **Target ports/services**: TCP 50100 (kamstrup_management_protocol, guardian_ast, kamstrup_protocol, HTTP, VNC flows)
    -   **Paths/endpoints**: HTTP GET /
    -   **Payload/artifact excerpts**: `b'\x01I20100'`, HTTP GET requests.
    -   **Temporal checks results**: Occurred within the investigation window.
-   **TCP Port 37777 Scanning (OSM-002)**
    -   **Source IPs with counts**: 37.60.224.127 (multiple flows)
    -   **ASNs with counts**: AS51167 (Contabo GmbH, France)
    -   **Target ports/services**: TCP 37777 (unknown protocol)
    -   **Paths/endpoints**: N/A
    -   **Payload/artifact excerpts**: Flow, Honeytrap, P0f events.
    -   **Temporal checks results**: Occurred within the investigation window.
-   **TCP Port 1515 Scanning (OSM-003)**
    -   **Source IPs with counts**: 170.187.163.117, 172.234.199.190, 143.42.1.128, 172.234.25.187 (multiple flows from each)
    -   **ASNs with counts**: AS63949 (Akamai Connected Cloud, United States)
    -   **Target ports/services**: TCP 1515 (ifor-protocol)
    -   **Paths/endpoints**: N/A
    -   **Payload/artifact excerpts**: Flow, P0f events.
    -   **Temporal checks results**: Occurred within the investigation window.

## 11) Indicators of Interest
-   **Source IPs**:
    -   113.160.148.67 (DoublePulsar exploit, AS45899 VNPT Corp, Vietnam)
    -   106.219.90.24 (DoublePulsar exploit, AS45609 Bharti Airtel Ltd., India)
    -   111.119.234.232 (Web exploits, AS58262 Nrp Network)
    -   78.153.140.148 (Web exploits, AS202306 HOSTGLOBAL.PLUS LTD, UK)
    -   8.222.169.202 (Conpot ICS activity, AS45102 Alibaba US Technology Co., Ltd., Singapore)
-   **Target Ports/Services**:
    -   TCP 445 (SMB)
    -   Redis (implied TCP 6379)
    -   TCP 50100 (ICS Honeypot - Kamstrup/Guardian_AST protocols, HTTP/VNC)
    -   TCP 37777 (Dahua DVRs)
    -   TCP 1515 (ifor-protocol)
-   **Paths/Endpoints**:
    -   `/V2/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php`
    -   `/?%ADd+allow_url_include%3d1+%ADd+auto_prepend_file%3dphp://input`
    -   `/.env`
-   **Payload Fragments/Commands**:
    -   `MODULE LOAD /tmp/exp.so`
    -   `SLAVEOF NO ONE`
    -   `config set dbfilename exp.so`

## 12) Backend Tool Issues
-   **Failed Queries**:
    -   `two_level_terms_aggregated` for `redis.action.keyword` with `type_filter`: Did not return expected aggregations for correlating Redis actions to source IPs.
    -   `two_level_terms_aggregated` for `conpot.protocol.keyword` with `type_filter`: Did not return expected aggregations for correlating Conpot protocols to source IPs.
    -   `kibanna_discover_query` for specific `redis.action.keyword` (`MODULE LOAD /tmp/exp.so`): Returned no hits.
    -   `kibanna_discover_query` for specific `conpot.protocol.keyword` (`kamstrup_management_protocol`): Returned no hits.
-   **Affected Validations**:
    -   Direct correlation of Redis RCE actions to source IPs.
    -   Direct correlation of Conpot ICS protocol interactions to source IPs.
-   **Weakened Conclusions**: The inability to directly link specific source IPs to the detailed Redis RCE commands and Conpot ICS protocol interactions reduces confidence in attributing these specific attack chains to unique actors, requiring reliance on broader flow/Suricata data for source IP context.

## 13) Agent Action Summary (Audit Trail)

-   **agent_name**: ParallelInvestigationAgent (orchestrator for sub-agents)
    -   **purpose**: To run multiple investigative branches concurrently.
    -   **inputs_used**: `gte_time_stamp`, `lte_time_stamp`.
    -   **actions_taken**: Orchestrated calls to Baseline, KnownSignal, CredentialNoise, and HoneypotSpecific agents.
    -   **key_results**: Gathered initial baseline metrics, known threat signals, credential noise, and honeypot-specific interactions.
    -   **errors_or_gaps**: None reported at the orchestrator level.

-   **agent_name**: BaselineAgent
    -   **purpose**: To establish a general understanding of attack volume, source geography, and top attackers.
    -   **inputs_used**: `investigation_start`, `investigation_end`.
    -   **actions_taken**: Queried for total attacks, top countries, top attacker IPs, country-to-port mapping, and attacker ASNs.
    -   **key_results**: 21740 total attacks; top countries: US, Vietnam, France; top IPs and ASNs identified; VNC (US), SMB (Vietnam, France) are top targeted services per country.
    -   **errors_or_gaps**: None.

-   **agent_name**: KnownSignalAgent
    -   **purpose**: To identify and categorize known threat signals (signatures, CVEs).
    -   **inputs_used**: `investigation_start`, `investigation_end`.
    -   **actions_taken**: Queried for alert signatures, CVEs, alert categories, and specific signature phrases.
    -   **key_results**: High volume VNC scans, DoublePulsar backdoor communications, MS Terminal Server traffic on non-standard ports, and CVE-2025-55182 detected.
    -   **errors_or_gaps**: None.

-   **agent_name**: CredentialNoiseAgent
    -   **purpose**: To characterize common brute-force and credential stuffing attempts.
    -   **inputs_used**: `investigation_start`, `investigation_end`.
    -   **actions_taken**: Queried for top usernames, passwords, and p0f OS distribution.
    -   **key_results**: Common usernames (root, postgres, admin) and weak passwords (123, 123456) are prevalent. Linux OS systems are frequently observed targets/sources.
    -   **errors_or_gaps**: None.

-   **agent_name**: HoneypotSpecificAgent
    -   **purpose**: To gather detailed interactions from specific honeypot types.
    -   **inputs_used**: `investigation_start`, `investigation_end`.
    -   **actions_taken**: Queried Redis, ADBHoney, Conpot, and Tanner honeypot logs for specific activities.
    -   **key_results**: Redis RCE attempts (`MODULE LOAD /tmp/exp.so`), Tanner web exploit paths (`/V2/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php`, `/.env`), and Conpot ICS protocol interactions (Kamstrup, guardian_ast) on port 50100 were observed. No ADBHoney activity.
    -   **errors_or_gaps**: None.

-   **agent_name**: CandidateDiscoveryAgent
    -   **purpose**: To identify potential novel/suspicious activity and categorize findings for reporting.
    -   **inputs_used**: All previous agent results (`baseline_result`, `known_signals_result`, `credential_noise_result`, `honeypot_specific_result`).
    -   **actions_taken**: Performed two-level aggregations on Redis, Tanner, Conpot, and Suricata data; ran `kibanna_discover_query` for specific ports/keywords; conducted `search` queries for ASN lookups and port common uses. Consolidated results and called `set_model_response`.
    -   **key_results**: Identified items for Emerging n-day Exploitation, Botnet/Campaign Mapping, Odd-Service/Minutia Attacks, Known-Exploit/Commodity Exclusions, and Suspicious Unmapped Activity to Monitor.
    -   **errors_or_gaps**: Multiple `two_level_terms_aggregated` and `kibanna_discover_query` tools failed to return results for Redis actions and Conpot protocols when filtered by `type_filter` or specific keywords, blocking direct correlation of these specific actions to source IPs. ASN lookup for 113.160.148.67 and 111.119.234.232 was not initially explicit, requiring further search.

-   **agent_name**: CandidateValidationLoopAgent
    -   **purpose**: To iteratively validate and enrich high-signal candidates.
    -   **inputs_used**: No specific candidates were passed to this agent for iterative validation as `CandidateDiscoveryAgent` processed and categorized them in a single step in this run.
    -   **actions_taken**: Exited loop upon request.
    -   **key_results**: 0 iterations run, 0 candidates validated in this explicit loop.
    -   **errors_or_gaps**: None (as no candidates were presented for validation in a loop).

-   **agent_name**: OSINTAgent
    -   **purpose**: To perform Open Source Intelligence (OSINT) lookups for validation and context enrichment.
    -   **inputs_used**: `botnet_campaign_mapping`, `suspicious_unmapped_monitor`, `odd_service_minutia_attacks` candidates from `CandidateDiscoveryAgent`.
    -   **actions_taken**: Performed `search` queries for DoublePulsar, Redis RCE techniques, PHPUnit/PHP/ .env exploits, Kamstrup/guardian_ast protocols, port 50100, port 37777, and port 1515. Also performed ASN lookups.
    -   **key_results**: Confirmed knownness of DoublePulsar, Redis RCE methods, and Tanner web exploits. Identified port 37777 as Dahua-related and a botnet target. Confirmed port 1515 IANA assignment. OSINT for Kamstrup/guardian_ast protocols and port 50100 was inconclusive regarding specific public exploits.
    -   **errors_or_gaps**: None.

-   **agent_name**: ReportAgent
    -   **purpose**: To compile the final investigation report.
    -   **inputs_used**: `investigation_start`, `investigation_end`, `baseline_result`, `known_signals_result`, `credential_noise_result`, `honeypot_specific_result`, `candidate_discovery_result`, `osint_validation_result`.
    -   **actions_taken**: Consolidated and formatted all workflow state outputs into a structured markdown report. Re-categorized candidates based on OSINT validation.
    -   **key_results**: Generated final comprehensive report.
    -   **errors_or_gaps**: None.

-   **agent_name**: SaveReportAgent
    -   **purpose**: To save the generated report to storage.
    -   **inputs_used**: Final markdown report content.
    -   **actions_taken**: Not explicitly called in the provided context.
    -   **key_results**: file write status: pending.
    -   **errors_or_gaps**: None (status pending implies no failure, just not yet executed in this context).
