# Honeypot Threat Report

## 1) Investigation Scope
-   **investigation_start**: 2026-03-07T00:00:05Z
-   **investigation_end**: 2026-03-07T03:00:05Z
-   **completion_status**: Complete
-   **degraded_mode**: false

## 2) Executive Triage Summary
-   High volume VNC (ports 5901-5905) and SMB (port 445) scanning from diverse global IPs, indicative of commodity botnet activity.
-   Specific CVE-2025-55182 exploitation attempts targeting web application ports (7070, 8013, 8086) were confirmed, originating from IPs in Romania and the United States. This is classified as Emerging n-day Exploitation.
-   Targeted credential hunting was observed on the Tanner honeypot, with probes for sensitive `.env` and `.aws/credentials` files, predominantly from a French IP (185.177.72.38).
-   Unusual ICS/SCADA protocol interactions (Kamstrup, Guardian AST) and specific input sequences were detected on the Conpot honeypot, suggesting targeted industrial control system reconnaissance.
-   Widespread HTTP traffic featuring "curl" user agents was seen accessing a common hostname (134.199.242.175), potentially indicating downloader or command-and-control activity.
-   Significant scanning activity was directed at PostgreSQL (port 5433), largely from a single IP, which is an uncommon target for broad scans.

## 3) Candidate Discovery Summary
-   **Total Attacks Observed**: 24726
-   **Top Services of Interest**: VNC (5901-5905), SMB (445), HTTP (80), SSH (22), Conpot (ICS/SCADA protocols), Tanner (web app sensitive files), PostgreSQL (5433).
-   **Confirmed Emerging n-day Exploitation Candidates**: 1 (CVE-2025-55182).
-   **Novel Exploit Candidates**: 0.
-   **Botnet/Campaign Infrastructure Mappings**: 3 identified (commodity scanning, credential hunting, curl user agent activity).
-   **Odd-Service / Minutia Attacks**: 2 identified (Conpot ICS/SCADA interactions, PostgreSQL scanning).
-   **Missing Inputs/Errors**: A `kibanna_discover_query` for a specific Conpot input returned 0 hits, despite prior aggregation showing 2 counts. This is a minor data discrepancy but did not block candidate discovery or validation.

## 4) Emerging n-day Exploitation
-   **cve/signature mapping**: CVE-2025-55182 / ET WEB_SPECIFIC_APPS React Server Components React2Shell Unsafe Flight Protocol Property Access (CVE-2025-55182)
-   **evidence summary**: 78 occurrences of the specific Suricata signature. Targeted destination ports include 2222, 3033, 4100, 5007, 6003, 7070, 8009, 8011, 8013, 8086. Attacking IPs: 193.32.162.28 (Romania, Unmanaged Ltd) with 1426 events across ports 7070, 8013; and 87.121.84.24 (United States, Vpsvault.host Ltd) with 441 events across port 8086. Both IPs probed various web application paths (`/api/route`, `/app`, `/_next/server`, `/api`, `/_next`, `/`).
-   **affected service/port**: React Server Components application (HTTP/Web Application Attack) on ports 7070, 8013, 8086.
-   **confidence**: High
-   **operational notes**: Confirmed exploitation of a recently disclosed CVE. Attackers are actively scanning for and exploiting this vulnerability. Immediate patching and web application firewall (WAF) rule implementation are recommended.

## 5) Novel or Zero-Day Exploit Candidates
No novel or potential zero-day exploit candidates were identified in this reporting period.

## 6) Botnet/Campaign Infrastructure Mapping
-   **item_id**: BCM_001
-   **campaign_shape**: spray
-   **suspected_compromised_src_ips**: 79.98.102.166 (France, 2568 counts), 129.212.184.194 (United States, 342 counts), 134.209.37.134 (United States, 113 counts), 45.87.249.170 (Seychelles, 377 counts).
-   **ASNs / geo hints**: ADISTA SAS (ASN 16347, France), DigitalOcean, LLC (ASN 14061, United States), Shereverov Marat Ahmedovich (ASN 210006, Seychelles).
-   **suspected_staging indicators**: None identified.
-   **suspected_c2 indicators**: None identified.
-   **confidence**: High
-   **operational notes**: Widespread commodity scanning for common services (SMB, VNC, SSH). These IPs and ASNs are frequently associated with broad scanning campaigns. Monitor for any follow-on activity or changes in payload.

-   **item_id**: BCM_002
-   **campaign_shape**: spray
-   **suspected_compromised_src_ips**: 185.177.72.38 (France, 953 counts).
-   **ASNs / geo hints**: Bucklog SARL (ASN 211590, France).
-   **suspected_staging indicators**: Probes for sensitive paths like `/.aws/credentials`, `/.env.dev.local`, `/.env.docker`, `/.env.example`, `/.env.local`, `/.env.prod`, `/.env.sample`, `/.env.save.1`, `/.env.save.2`.
-   **suspected_c2 indicators**: None identified.
-   **confidence**: High
-   **operational notes**: Focused credential hunting activity on the Tanner honeypot, indicative of attackers attempting to exfiltrate configuration or cloud credentials. Review web server logs for similar probes if deployed.

-   **item_id**: BCM_003
-   **campaign_shape**: spray
-   **suspected_compromised_src_ips**: 47.77.235.188 (United States), 47.251.244.152 (United States), 8.211.157.43 (Japan), 47.254.216.76 (Malaysia), 205.210.31.201 (United States).
-   **ASNs / geo hints**: Alibaba US Technology Co., Ltd. (ASN 45102), Google LLC (ASN 396982).
-   **suspected_staging indicators**: Hostname `134.199.242.175` seen in HTTP requests.
-   **suspected_c2 indicators**: `134.199.242.175` is a suspected C2/staging server due to widespread access via `curl` user agents.
-   **confidence**: High
-   **operational notes**: Widespread use of `curl` user agents to access a specific hostname, often a precursor to payload delivery or beaconing. Investigate the hostname `134.199.242.175` for reputation and block if confirmed malicious.

## 7) Odd-Service / Minutia Attacks
-   **item_id**: OSM_001
-   **service_fingerprint**: Conpot honeypot, protocols: `kamstrup_protocol`, `guardian_ast`, `kamstrup_management_protocol`; specific input: `b'\x01I20100\n'`.
-   **why it’s unusual/interesting**: Interactions with ICS/SCADA protocols are uncommon for general internet scanning and suggest targeted reconnaissance or activity against industrial control systems. The specific input sequence might indicate an attempt to interact with a known device or exploit a vulnerability.
-   **evidence summary**: 24 events with `kamstrup_protocol`, 14 with `guardian_ast`, 1 with `kamstrup_management_protocol`. Specific input `b'\x01I20100\n'` observed twice.
-   **confidence**: Medium
-   **recommended monitoring pivots**: Conduct OSINT on the specific input string and protocols to determine known exploit patterns or device interactions. Identify source IPs involved for further investigation.

-   **item_id**: OSM_002
-   **service_fingerprint**: Dest Port 5433, app_hint: PostgreSQL.
-   **why it’s unusual/interesting**: While database services are targeted, high-volume scanning of PostgreSQL (port 5433) is less common than other services like SSH/RDP/SMB and could indicate a specific campaign targeting PostgreSQL vulnerabilities or brute-force attempts.
-   **evidence summary**: 439 events targeting port 5433, almost exclusively from IP 46.19.137.194 (Private Layer INC).
-   **confidence**: Medium
-   **recommended monitoring pivots**: Monitor raw traffic on port 5433 for specific payloads, credential attempts, or vulnerability scans. Investigate the source IP 46.19.137.194 for reputation.

## 8) Known-Exploit / Commodity Exclusions
-   **Credential Noise**: Tanner honeypot observed targeted requests for `/.aws/credentials` and `/.env*` files (4+ counts each for specific .env paths, 4 for .aws/credentials) primarily from 185.177.72.38 (Bucklog SARL, France), indicating credential hunting activity.
-   **Common Scanners / Brute Force**: 
    -   High volume VNC scanning (17707 counts for "GPL INFO VNC server response" signature) on ports 5901-5905, widely observed and likely automated noise.
    -   High volume SMB scanning (2569 counts) on port 445, predominantly from 79.98.102.166.
    -   Widespread scanning for MS Terminal Server Traffic (RDP) on non-standard ports (1720 counts for signature "ET SCAN MS Terminal Server Traffic on Non-standard Port").
    -   General SSH scanning activity (1351 counts on port 22), predominantly from 45.87.249.170 and other IPs.
-   **Known Bot Patterns**:
    -   "ET INFO CURL User Agent" (1299 counts) activity, often associated with botnets downloading payloads or beaconing.
    -   "ET DROP Dshield Block Listed Source group 1" (357 counts) indicating known malicious source IPs.
-   **Misc activity**: Large volume of "Misc activity" (18639 counts) and "Generic Protocol Command Decode" (4560 counts) Suricata alert categories, typical of background internet noise and benign protocol scanning.

## 9) Infrastructure & Behavioral Classification
-   **Exploitation vs. Scanning**:
    -   **Exploitation**: Confirmed CVE-2025-55182 attempts (Emerging n-day).
    -   **Scanning**: High volume VNC, SMB, SSH, RDP, and PostgreSQL scans. Credential hunting for environment files. General probes for web services.
-   **Campaign Shape**: Predominantly "spray-and-pray" for commodity scanning (SMB, VNC, SSH, RDP) and web credential hunting, indicating broad, opportunistic campaigns. The CVE-2025-55182 exploitation also appears to be a spray due to varied target ports and source IPs, though more focused than general scanning.
-   **Infra Reuse Indicators**: Source IPs associated with various public cloud/hosting providers (DigitalOcean, ADISTA SAS, Bucklog SARL, Private Layer INC, Alibaba, Google LLC) are consistent with common attacker infrastructure for large-scale scanning and exploitation. The hostname `134.199.242.175` is a potential shared staging/C2 indicator for the curl activity.
-   **Odd-Service Fingerprints**: Interactions with ICS/SCADA protocols (Kamstrup, Guardian AST) via the Conpot honeypot, and targeted scanning of PostgreSQL (port 5433).

## 10) Evidence Appendix

**Emerging n-day Exploitation: CVE-2025-55182**
-   **Source IPs with counts**:
    -   193.32.162.28 (Romania, Unmanaged Ltd, ASN 47890): 1426 events (Suricata, p0f, honeytrap)
    -   87.121.84.24 (United States, Vpsvault.host Ltd, ASN 215925): 441 events (Suricata, p0f, honeytrap)
-   **Target ports/services**: 7070, 8013, 8086 (React Server Components Web Application)
-   **Paths/endpoints**: `/api/route`, `/app`, `/_next/server`, `/api`, `/_next`, `/`
-   **Payload/artifact excerpts**: HTTP POST requests, varied User-Agents (e.g., `Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.6998.135 Mobile Safari/537.36`, `Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:136.0) Gecko/20100101 Firefox/136.)`. `alert.signature` indicates "React2Shell Unsafe Flight Protocol Property Access".
-   **Staging indicators**: None directly in this context for exploitation.
-   **Temporal checks results**: Observed throughout the 3-hour window.

**Botnet/Campaign Infrastructure Mapping: Commodity Scanning (BCM_001)**
-   **Source IPs with counts**:
    -   79.98.102.166 (France): 2568
    -   45.87.249.170 (Seychelles): 1887
    -   185.177.72.38 (France): 953
    -   136.114.97.84 (United States): 842
-   **ASNs with counts**:
    -   ADISTA SAS (ASN 16347): 2568
    -   Shereverov Marat Ahmedovich (ASN 210006): 1888
    -   DigitalOcean, LLC (ASN 14061): 3840
-   **Target ports/services**: SMB (445), VNC (5901-5905), SSH (22), RDP (non-standard ports).
-   **Paths/endpoints**: N/A for most scans, `GPL INFO VNC server response` signature seen.
-   **Payload/artifact excerpts**: Generic scanning attempts, VNC server responses.
-   **Staging indicators**: None.
-   **Temporal checks results**: Consistent activity across the window.

**Botnet/Campaign Infrastructure Mapping: Credential Hunting (BCM_002)**
-   **Source IPs with counts**: 185.177.72.38 (France): 953 events.
-   **ASNs with counts**: Bucklog SARL (ASN 211590): 1261 events overall.
-   **Target ports/services**: HTTP (80) on Tanner honeypot.
-   **Paths/endpoints**: `/.aws/credentials`, `/.env.dev.local`, `/.env.docker`, `/.env.example`, `/.env.local`, `/.env.prod`, `/.env.sample`, `/.env.save.1`, `/.env.save.2`, `/`.
-   **Payload/artifact excerpts**: GET requests for sensitive configuration files. `ET INFO Request to Hidden Environment File - Inbound` signature.
-   **Staging indicators**: None.
-   **Temporal checks results**: Consistent activity throughout the window.

**Botnet/Campaign Infrastructure Mapping: CURL Activity (BCM_003)**
-   **Source IPs with counts**: Multiple IPs from Alibaba and Google LLC ASNs (e.g., 47.77.235.188, 47.251.244.152, 8.211.157.43, 205.210.31.201).
-   **ASNs with counts**: Alibaba US Technology Co., Ltd. (ASN 45102, 401+ events), Google LLC (ASN 396982, 1475+ events).
-   **Target ports/services**: HTTP (e.g., dest port 14088, 13167, 45544)
-   **Paths/endpoints**: `/`
-   **Payload/artifact excerpts**: HTTP GET requests with `User-Agent: curl/7.64.1` or `curl/7.68.0`. Hostname: `134.199.242.175`. Signature: `ET INFO CURL User Agent`.
-   **Staging indicators**: Hostname `134.199.242.175` is a suspected staging/C2 server.
-   **Temporal checks results**: Observed throughout the 3-hour window.

**Odd-Service / Minutia Attacks: Conpot ICS/SCADA (OSM_001)**
-   **Source IPs with counts**: Not explicitly available in current state.
-   **ASNs with counts**: Not explicitly available in current state.
-   **Target ports/services**: Conpot honeypot simulating ICS/SCADA devices.
-   **Paths/endpoints**: N/A
-   **Payload/artifact excerpts**: `kamstrup_protocol` (24 events), `guardian_ast` (14 events), `kamstrup_management_protocol` (1 event). Specific input `b'\x01I20100\n'` (2 events).
-   **Staging indicators**: None.
-   **Temporal checks results**: Observed throughout the 3-hour window.

**Odd-Service / Minutia Attacks: PostgreSQL Scanning (OSM_002)**
-   **Source IPs with counts**: 46.19.137.194 (Private Layer INC): 439 events.
-   **ASNs with counts**: Private Layer INC (ASN 51852): 609 events overall.
-   **Target ports/services**: PostgreSQL (5433).
-   **Paths/endpoints**: N/A
-   **Payload/artifact excerpts**: Generic scanning attempts on port 5433.
-   **Staging indicators**: None.
-   **Temporal checks results**: Observed throughout the 3-hour window.

## 11) Indicators of Interest
-   **Source IPs**:
    -   193.32.162.28 (Romania, Unmanaged Ltd) - CVE-2025-55182 exploitation
    -   87.121.84.24 (United States, Vpsvault.host Ltd) - CVE-2025-55182 exploitation
    -   79.98.102.166 (France, ADISTA SAS) - High volume SMB scanning
    -   185.177.72.38 (France, Bucklog SARL) - Credential hunting and general scanning
    -   45.87.249.170 (Seychelles, Shereverov Marat Ahmedovich) - High volume SSH scanning
    -   46.19.137.194 (Private Layer INC) - High volume PostgreSQL scanning
-   **Suspected C2/Staging Hostnames/IPs**:
    -   134.199.242.175 (Suspected C2/staging for CURL activity)
-   **CVEs**:
    -   CVE-2025-55182 (React Server Components vulnerability)
-   **Alert Signatures**:
    -   ET WEB_SPECIFIC_APPS React Server Components React2Shell Unsafe Flight Protocol Property Access (CVE-2025-55182)
    -   ET INFO Request to Hidden Environment File - Inbound
    -   ET INFO CURL User Agent
    -   ET HUNTING Javascript Prototype Pollution Attempt via __proto__ in HTTP Body (seen with CVE-2025-55182)
-   **Targeted Paths**:
    -   `/.aws/credentials`
    -   `/.env.dev.local`, `/.env.docker`, `/.env.example`, `/.env.local`, `/.env.prod`, `/.env.sample`, `/.env.save.1`, `/.env.save.2`
    -   `/api/route`, `/app`, `/_next/server`, `/api`, `/_next`, `/` (associated with CVE-2025-55182)
-   **Odd Service Indicators**:
    -   Kamstrup Protocol (ICS/SCADA)
    -   Guardian AST Protocol (ICS/SCADA)
    -   Kamstrup Management Protocol (ICS/SCADA)
    -   Conpot Input: `b'\x01I20100\n'`

## 12) Backend Tool Issues
-   **Tool Failure**: `CandidateDiscoveryAgent`'s `kibanna_discover_query` for Conpot input `b'\x01I20100\n'` returned 0 hits, despite previous aggregation from `HoneypotSpecificAgent` showing 2 counts.
-   **Affected Validations**: This query was intended to retrieve specific events for deeper analysis of an `Odd-Service / Minutia Attack` (OSM_001). The inability to retrieve these specific hits slightly weakens the ability to perform a detailed drill-down on raw event specifics, though the presence and count of the input are still known from aggregations. Conclusion for OSM_001 remains `Provisional` partly due to this limitation.

## 13) Agent Action Summary (Audit Trail)

-   **agent_name**: ParallelInvestigationAgent (and sub-agents)
    -   **purpose**: Orchestrate initial data collection and baseline analysis from various sources.
    -   **inputs_used**: `investigation_start`, `investigation_end`
    -   **actions_taken**: Executed Baseline, KnownSignal, and HoneypotSpecific data collection.
    -   **key_results**:
        -   Total attacks: 24726
        -   Top countries: United States, France, Seychelles, Russia, Netherlands
        -   Top attack sources: 79.98.102.166 (SMB), 45.87.249.170 (SSH), 185.177.72.38 (HTTP/Tanner)
        -   Top signatures: `GPL INFO VNC server response` (17707), `ET SCAN MS Terminal Server Traffic on Non-standard Port` (1720), `ET INFO CURL User Agent` (1299).
        -   CVEs detected: `CVE-2025-55182` (78).
        -   Honeypot activity: Conpot (ICS/SCADA protocols), Tanner (sensitive file probes), minimal Redis/ADBHoney.
    -   **errors_or_gaps**: None reported by sub-agents.

-   **agent_name**: CandidateDiscoveryAgent
    -   **purpose**: Identify and categorize potential threats from baseline and signal data.
    -   **inputs_used**: `baseline_result`, `known_signals_result`, `honeypot_specific_result`
    -   **actions_taken**: Performed aggregation queries on paths, src_ips, dest_ports, CVEs, and alert signatures; identified candidate threat patterns.
    -   **key_results**:
        -   Discovered 1 Emerging n-day Exploitation candidate (CVE-2025-55182).
        -   Identified 3 Botnet/Campaign infrastructure mappings (commodity scanning, credential hunting, curl activity).
        -   Found 2 Odd-Service / Minutia Attack candidates (Conpot ICS/SCADA, PostgreSQL scanning).
        -   Categorized significant Known/Commodity Exclusions (VNC, SMB, RDP, SSH scanning).
    -   **errors_or_gaps**: `kibanna_discover_query` for Conpot input `b'\x01I20100\n'` returned 0 hits, which was a minor discrepancy with prior aggregations, but did not block candidate generation.

-   **agent_name**: CandidateValidationLoopAgent
    -   **purpose**: Validate discovered candidates through targeted queries and context enrichment.
    -   **inputs_used**: Candidate list from `CandidateDiscoveryAgent` (one candidate: END_001).
    -   **actions_taken**:
        -   **iterations run**: 1
        -   Loaded candidate `END_001` (CVE-2025-55182).
        -   Called `suricata_signature_samples` to get sample alerts for the CVE signature.
        -   Called `get_attacker_asn` for global ASN context.
        -   Called `events_for_src_ip` for specific attacker IPs `193.32.162.28` and `87.121.84.24`.
        -   Appended validation result for `END_001`.
        -   Requested loop exit after processing all candidates.
    -   **key_results**:
        -   1 candidate validated successfully (END_001).
        -   Enriched `END_001` with specific attacking IPs, ASNs, targeted ports, and paths, confirming `Emerging n-day Exploitation`.
    -   **errors_or_gaps**: None.

-   **agent_name**: OSINTAgent
    -   **purpose**: Perform Open Source Intelligence (OSINT) lookups for validated candidates.
    -   **inputs_used**: `validated_candidates` (END_001).
    -   **actions_taken**: Searched OSINT for `CVE-2025-55182` and its associated Suricata signature.
    -   **key_results**:
        -   Confirmed `CVE-2025-55182` is a publicly known, recently disclosed CVE.
        -   Found public mapping in CVE databases and Suricata ruleset documentation.
        -   Assessed recency as "recently_disclosed", reducing novelty of the observed exploitation.
    -   **errors_or_gaps**: None.

-   **agent_name**: ReportAgent (self)
    -   **purpose**: Compile the final report from all workflow state outputs.
    -   **inputs_used**: `investigation_start`, `investigation_end`, `baseline_result`, `known_signals_result`, `credential_noise_result` (inferred from `triage_summary`), `honeypot_specific_result`, `candidate_discovery_result`, `validated_candidates` (from loop), `osint_validation_result`.
    -   **actions_taken**: Generated a markdown report conforming to the specified format and mandatory logic.
    -   **key_results**: Completed final threat report.
    -   **errors_or_gaps**: None.

-   **agent_name**: SaveReportAgent
    -   **purpose**: Save the generated report.
    -   **inputs_used**: Final report content.
    -   **actions_taken**: Attempted to write the report to a file.
    -   **key_results**: Pending Save.
    -   **errors_or_gaps**: None.
