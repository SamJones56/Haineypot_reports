# Honeypot Threat Report

## 1) Investigation Scope
- **investigation_start**: 2026-03-08T12:00:05Z
- **investigation_end**: 2026-03-08T15:00:05Z
- **completion_status**: Partial
- **degraded_mode**: true - Validation of some CVE-related candidate metadata was impacted by tool issues.

## 2) Executive Triage Summary
- High volume VNC scanning activity was observed from the United States (ports 5901-5905).
- Significant SMB scanning activity (port 445) originated from France and Mexico, including attempts to use the insecure SMBv1 protocol.
- HTTP scanning for sensitive configuration files (`/.env`, `/.aws/credentials`) was prevalent from multiple countries, indicating broad reconnaissance for misconfigured web servers.
- Two N-day exploitation attempts were confirmed:
    - **CVE-2025-55182 (React2Shell)**: Critical RCE in React Server Components, actively exploited by multiple IPs.
    - **CVE-2024-14007 (Shenzhen TVT NVMS-9000)**: Authentication bypass in DVR/NVR firmware, actively exploited by multiple IPs.
- Credential stuffing attempts were noted on SSH (port 22) and Telnet (port 23) using common usernames ("root", "admin", "ubuntu") and weak passwords ("123456", "password").
- Minor activity targeting Redis (NewConnect, info, PING) was observed.
- **Major uncertainties**: Aggregation tools for CVE-related source IPs and destination ports exhibited inconsistencies or returned empty results for actively exploited CVEs (CVE-2025-55182, CVE-2024-14007), weakening the ability to fully map campaign infrastructure directly from these specific aggregations.

## 3) Candidate Discovery Summary
- **Total Attacks Observed**: 19429
- **Top Attacking Countries**: United States (5784), France (4078), Mexico (1821), India (916), United Kingdom (774).
- **Top Attacker IPs (by event count)**: 79.98.102.166 (2572), 189.231.160.65 (1512), 185.177.72.30 (1032).
- **Top Alert Signatures**: "GPL INFO VNC server response" (18948), "SURICATA IPv4 truncated packet" (1133), "SURICATA AF-PACKET truncated packet" (1133).
- **Identified CVEs**: CVE-2025-55182 (137 alerts), CVE-2024-14007 (8 alerts).
- **Honeypot-Specific Activity**:
    - **Redis**: 37 events (Closed, NewConnect, info, PING).
    - **ADBHoney**: 24 events, including commands like `echo hello` and `echo "$(getprop ro.product.name 2>/dev/null) $(whoami 2>/dev/null)"`.
    - **Tanner (Web Honeypot)**: 1548 events, with top paths including `/` (75), `/.env` (8), `/.aws/credentials` (4).
- **Material Gaps**: None in initial discovery, but later validation highlighted aggregation tool inconsistencies for CVEs.

## 4) Emerging n-day Exploitation

### CVE-2025-55182 (React2Shell)
- **cve/signature mapping**: CVE-2025-55182 (React2Shell) / "ET WEB_SPECIFIC_APPS React Server Components React2Shell Unsafe Flight Protocol Property Access"
- **evidence summary**: 137 Suricata alerts. Exploitation attempts observed targeting various paths: `/api/route`, `/app`, `/_next/server`, `/api`, `/_next`, `/`. Destination ports include 9967, 2082, 3005, 3010, 8081, 3006, 3003, 3030, 3007, 3002.
- **affected service/port**: Web Application (React Server Components), observed on various TCP ports (e.g., 9967, 2082, 3005, 3010).
- **confidence**: High (Direct Suricata signature mapping, OSINT confirms active exploitation).
- **operational notes**: This is a critical unauthenticated RCE vulnerability. Immediate patching is required. WAF rules may offer temporary protection.
- **provisional**: True (due to aggregation tool inconsistencies as noted in evidence gaps).

### CVE-2024-14007 (Shenzhen TVT NVMS-9000 Information Disclosure Attempt)
- **cve/signature mapping**: CVE-2024-14007 / "ET WEB_SPECIFIC_APPS Shenzhen TVT NVMS-9000 Information Disclosure Attempt"
- **evidence summary**: 8 Suricata alerts. Classified as "Attempted Administrator Privilege Gain". Observed source IPs include 89.42.231.179, 46.151.178.13, 176.65.139.45. Destination ports include 17000, 17001, 6036, 6037, 9100.
- **affected service/port**: Shenzhen TVT NVMS-9000 firmware, observed on various TCP ports (e.g., 17000, 17001, 6036, 6037, 9100).
- **confidence**: High (Direct Suricata signature mapping, OSINT confirms active exploitation).
- **operational notes**: This is an authentication bypass vulnerability allowing information disclosure (e.g., admin credentials). Affected devices should be upgraded to firmware version 1.3.4 or newer.
- **provisional**: True (due to aggregation tool inconsistencies as noted in evidence gaps).

## 5) Novel or Zero-Day Exploit Candidates
No activity classified as "Novel Exploit Candidates" or "Potential Zero-Day Candidates" was identified after validation. All observed exploit-like behavior was mapped to known CVEs or established scanning patterns.

## 6) Botnet/Campaign Infrastructure Mapping

### SMB Scanning Campaign (France)
- **item_id or related candidate_id(s)**: 79.98.102.166
- **campaign_shape**: Spray (wide scanning from a single source).
- **suspected_compromised_src_ips**: 79.98.102.166 (count: 2572 events)
- **ASNs / geo hints**: ASN 16347 (ADISTA SAS, France).
- **suspected_staging indicators**: None.
- **suspected_c2 indicators**: None.
- **confidence**: High.
- **operational notes**: The source IP has a poor reputation and is associated with various malicious activities, including scanning. Activity specifically targets port 445 (SMB) and triggers "Potentially unsafe SMBv1 protocol in use" alerts. This indicates reconnaissance for vulnerable SMB services.

### SMB Scanning Campaign (Mexico)
- **item_id or related candidate_id(s)**: 189.231.160.65
- **campaign_shape**: Spray (wide scanning from a single source).
- **suspected_compromised_src_ips**: 189.231.160.65 (count: 1512 events)
- **ASNs / geo hints**: ASN 8151 (UNINET, Mexico).
- **suspected_staging indicators**: None.
- **suspected_c2 indicators**: None.
- **confidence**: Moderate (Lack of specific IP reputation but clear commodity scanning pattern).
- **operational notes**: This IP exclusively targets port 445 (SMB). While not explicitly flagged by a signature, the high volume and single-port focus are indicative of commodity scanning.

### HTTP Scanning Campaign (France)
- **item_id or related candidate_id(s)**: 185.177.72.30
- **campaign_shape**: Spray (wide scanning from a single source).
- **suspected_compromised_src_ips**: 185.177.72.30 (count: 1032 events)
- **ASNs / geo hints**: ASN 211590 (Bucklog SARL, France).
- **suspected_staging indicators**: None.
- **suspected_c2 indicators**: None.
- **confidence**: High.
- **operational notes**: This IP has a publicly documented poor reputation (honeypot lists, high fraud risk, attempts to access `.git/config`). Observed activity exclusively targets port 80 (HTTP), consistent with malicious web scanning and reconnaissance.

### Sensitive File Disclosure Scan Campaign (`/.env`)
- **item_id or related candidate_id(s)**: `/.env`
- **campaign_shape**: Spray (multiple IPs scanning for a common sensitive resource).
- **suspected_compromised_src_ips**: 192.109.200.164, 45.138.16.145, 78.153.140.148, 209.141.37.52, 185.242.3.82, 185.177.72.30, 185.177.72.56 (7 distinct IPs, 9 access attempts)
- **ASNs / geo hints**: Pfcloud UG (Sweden), 1337 Services GmbH (Poland), Hostglobal.plus Ltd (UK), FranTech Solutions (US), Netiface Limited (Netherlands), Bucklog SARL (France).
- **suspected_staging indicators**: None.
- **suspected_c2 indicators**: None.
- **confidence**: High.
- **operational notes**: This activity represents a common reconnaissance technique to find accidentally exposed `.env` files, which often contain critical application credentials. Monitoring for access to such paths is recommended.

### Sensitive File Disclosure Scan Campaign (`/.aws/credentials`)
- **item_id or related candidate_id(s)**: `/.aws/credentials`
- **campaign_shape**: Spray (multiple IPs scanning for a common sensitive resource).
- **suspected_compromised_src_ips**: 192.109.200.164, 209.141.37.52, 185.177.72.30, 185.177.72.56 (4 distinct IPs, 5 access attempts)
- **ASNs / geo hints**: Pfcloud UG (Sweden), FranTech Solutions (US), Bucklog SARL (France).
- **suspected_staging indicators**: None.
- **suspected_c2 indicators**: None.
- **confidence**: High.
- **operational notes**: This activity targets AWS credentials, a highly sensitive resource. Exposure of these files can lead to full cloud environment compromise. Monitoring for access to these paths is critical.

## 7) Odd-Service / Minutia Attacks

### VNC Server Probing
- **service_fingerprint**: Port 5901-5905 (VNC) / TCP
- **why it’s unusual/interesting**: VNC (Virtual Network Computing) is not typically exposed to the internet. Probing on these ports often indicates broad scanning for misconfigured remote access services. The high volume of "GPL INFO VNC server response" alerts confirms active reconnaissance for VNC services.
- **evidence summary**: 18948 alerts for "GPL INFO VNC server response". Top ports from the US are 5902 (451), 5903 (282), 5904 (274), 5901 (267), 5905 (241).
- **confidence**: High
- **recommended monitoring pivots**: Monitor for outbound connections from internal systems to VNC ports; review firewall rules for VNC exposure.

### Redis Service Interaction
- **service_fingerprint**: Redis / TCP
- **why it’s unusual/interesting**: Redis is an in-memory data store not commonly exposed externally. The observed actions (NewConnect, info, PING, QUIT) are typical of reconnaissance or attempts to interact with an open Redis instance.
- **evidence summary**: 37 events, including 11 "NewConnect", 9 "info"/"INFO", 2 "PING", 2 "QUIT". No malicious commands or exploitation attempts were observed beyond basic interaction.
- **confidence**: Moderate
- **recommended monitoring pivots**: Monitor for unauthorized access attempts or unusual command execution on Redis instances.

### ADB (Android Debug Bridge) Probing
- **service_fingerprint**: ADB (port 5555, common for Android devices) / TCP
- **why it’s unusual/interesting**: ADB is a development tool, and its exposure to the internet is a security risk. The honeypot logs indicate attempts to run shell commands.
- **evidence summary**: 24 events on the ADB honeypot, including `echo hello` and `echo "$(getprop ro.product.name 2>/dev/null) $(whoami 2>/dev/null)"`. No malware samples were observed.
- **confidence**: Moderate
- **recommended monitoring pivots**: Identify and secure any exposed ADB ports in the environment.

## 8) Known-Exploit / Commodity Exclusions
- **Credential Stuffing/Brute Force**:
    - **SSH (Port 22) and Telnet (Port 23)**: Common usernames like 'root' (175 attempts), 'admin' (87), 'ubuntu' (68), and weak passwords like '123456' (54), 'password' (44) were attempted. This activity is typical of widespread automated brute-force attacks.
- **General Network Scanning**:
    - **SURICATA Truncated Packets**: High counts (1133 each for IPv4 and AF-PACKET) indicate broad, unsophisticated network scanning activity or network anomalies rather than targeted attacks.
    - **SURICATA Stream Resend Alerts**: Signatures like "SURICATA STREAM 3way handshake SYN resend different seq on SYN recv" (1035) and "SURICATA STREAM ESTABLISHED SYN resend with different seq" (700) are usually indicative of network misconfigurations, connection issues, or generic scanning tools rather than specific exploit attempts.
    - **Misc Activity**: The highest alert category "Misc activity" (19430 events) includes a broad range of non-specific network events, characteristic of general internet noise and commodity scanning.

## 9) Infrastructure & Behavioral Classification
- **Exploitation vs. Scanning**: The majority of high-volume activity (SMB, HTTP, VNC, SSH, Telnet) is characteristic of wide-area reconnaissance and scanning. Direct exploitation attempts were limited to the CVE-mapped items, albeit still appearing as broad spray campaigns.
- **Campaign Shape**: Predominantly **spray-scanning** where individual IPs or clusters of IPs systematically probe a wide range of targets for specific open ports or known vulnerable paths. No clear "fan-in" or "beaconing" patterns were identified.
- **Infra Reuse Indicators**: Multiple source IPs (e.g., 78.153.140.148, 185.177.72.30) were observed participating in different sensitive file scanning campaigns (`/.env`, `/.aws/credentials`), indicating the likely use of compromised infrastructure or shared scanning platforms.
- **Odd-Service Fingerprints**: VNC, Redis, and ADB protocols were targeted, which are less common to see internet-exposed and probed in such a manner, highlighting their "odd-service" nature.

## 10) Evidence Appendix

### 79.98.102.166 (SMB Scanning Campaign - France)
- **Source IPs with counts**: 79.98.102.166 (2572 events)
- **ASNs with counts**: ASN 16347 (ADISTA SAS, France)
- **Target ports/services**: Port 445 (SMB)
- **Paths/endpoints**: N/A (SMB protocol)
- **Payload/artifact excerpts**: "ET INFO Potentially unsafe SMBv1 protocol in use" alert (4 events)
- **Staging indicators**: None
- **Temporal checks results**: Activity spread throughout the investigation window (e.g., 14:47-14:58 UTC)

### 189.231.160.65 (SMB Scanning Campaign - Mexico)
- **Source IPs with counts**: 189.231.160.65 (1512 events)
- **ASNs with counts**: ASN 8151 (UNINET, Mexico)
- **Target ports/services**: Port 445 (SMB)
- **Paths/endpoints**: N/A (SMB protocol)
- **Payload/artifact excerpts**: No specific alerts within sampled data
- **Staging indicators**: None
- **Temporal checks results**: Activity spread throughout the investigation window (e.g., 13:56-14:07 UTC)

### 185.177.72.30 (HTTP Scanning Campaign - France)
- **Source IPs with counts**: 185.177.72.30 (1032 events)
- **ASNs with counts**: ASN 211590 (Bucklog SARL, France)
- **Target ports/services**: Port 80 (HTTP)
- **Paths/endpoints**: Observed targeting general HTTP endpoints. Also participated in `/.env` and `/.aws/credentials` scans.
- **Payload/artifact excerpts**: No specific exploit payloads captured in sampled data, but OSINT confirms reports of `.git/config` access attempts.
- **Staging indicators**: None
- **Temporal checks results**: Activity spread throughout the investigation window (e.g., 14:01-14:02 UTC for sampled HTTP traffic)

### CVE-2025-55182 (React2Shell)
- **Source IPs with counts**: 193.32.162.28 (12 events in samples), 24.144.94.222 (8 events in samples)
- **ASNs with counts**: Unavailable from tool (aggregation issue)
- **Target ports/services**: Multiple TCP ports: 9967, 2082, 3005, 3010, 8081, 3006, 3003, 3030, 3007, 3002
- **Paths/endpoints**: `/api/route`, `/app`, `/_next/server`, `/api`, `/_next`, `/`
- **Payload/artifact excerpts**: `alert.signature`: "ET WEB_SPECIFIC_APPS React Server Components React2Shell Unsafe Flight Protocol Property Access (CVE-2025-55182)"
- **Staging indicators**: None
- **Temporal checks results**: Activity observed between 14:33 and 14:59 UTC.

### CVE-2024-14007 (Shenzhen TVT NVMS-9000 Information Disclosure Attempt)
- **Source IPs with counts**: 89.42.231.179 (4 events in samples), 46.151.178.13 (2 events in samples), 176.65.139.45 (1 event in samples)
- **ASNs with counts**: Unavailable from tool (aggregation issue)
- **Target ports/services**: Multiple TCP ports: 17000, 17001, 6036, 6037, 9100
- **Paths/endpoints**: N/A (direct protocol interaction)
- **Payload/artifact excerpts**: `alert.signature`: "ET WEB_SPECIFIC_APPS Shenzhen TVT NVMS-9000 Information Disclosure Attempt (CVE-2024-14007)"
- **Staging indicators**: None
- **Temporal checks results**: Activity observed between 12:04 and 14:41 UTC.

### `/.env` (Sensitive File Disclosure Scan)
- **Source IPs with counts**: 192.109.200.164 (1), 45.138.16.145 (1), 78.153.140.148 (3), 209.141.37.52 (1), 185.242.3.82 (1), 185.177.72.30 (1), 185.177.72.56 (1)
- **ASNs with counts**: ASN 51396 (Sweden), ASN 210558 (Poland), ASN 202306 (UK), ASN 53667 (US), ASN 60223 (Netherlands), ASN 211590 (France)
- **Target ports/services**: Ports 80 (HTTP), 3000 (HTTP)
- **Paths/endpoints**: `/.env`
- **Payload/artifact excerpts**: Direct HTTP GET requests for `/.env`
- **Staging indicators**: None
- **Temporal checks results**: Activity observed between 12:08 and 14:57 UTC.

### `/.aws/credentials` (Sensitive File Disclosure Scan)
- **Source IPs with counts**: 192.109.200.164 (1), 209.141.37.52 (1), 185.177.72.30 (2), 185.177.72.56 (1)
- **ASNs with counts**: ASN 51396 (Sweden), ASN 53667 (US), ASN 211590 (France)
- **Target ports/services**: Ports 80 (HTTP), 3000 (HTTP)
- **Paths/endpoints**: `/.aws/credentials`
- **Payload/artifact excerpts**: Direct HTTP GET requests for `/.aws/credentials`
- **Staging indicators**: None
- **Temporal checks results**: Activity observed between 12:38 and 14:57 UTC.

## 11) Indicators of Interest
- **IPs**:
    - 79.98.102.166 (Known Malicious, SMB Scanning)
    - 189.231.160.65 (SMB Scanning)
    - 185.177.72.30 (Known Malicious, HTTP Scanning)
    - 193.32.162.28 (CVE-2025-55182 Exploitation)
    - 24.144.94.222 (CVE-2025-55182 Exploitation)
    - 89.42.231.179 (CVE-2024-14007 Exploitation)
    - 46.151.178.13 (CVE-2024-14007 Exploitation)
    - 176.65.139.45 (CVE-2024-14007 Exploitation)
- **CVEs**:
    - CVE-2025-55182 (React2Shell RCE)
    - CVE-2024-14007 (Shenzhen TVT NVMS-9000 Auth Bypass)
- **Paths**:
    - `/.env` (Sensitive Configuration File)
    - `/.aws/credentials` (AWS Credentials File)
    - `/.git/config` (Implicitly from OSINT on 185.177.72.30)
    - `/api/route`, `/app`, `/_next/server`, `/api`, `/_next`, `/` (Associated with CVE-2025-55182 exploitation)

## 12) Backend Tool Issues
- **CandidateValidationAgent**:
    - **Tool**: `top_src_ips_for_cve` and `top_dest_ports_for_cve` for `CVE-2025-55182`.
    - **Error**: Returned empty buckets or inconsistent results for a known CVE with associated traffic.
    - **Weakened conclusions**: The inability to reliably aggregate top source IPs and destination ports for CVE-2025-55182 through these specific tools means the reported lists for these fields come only from raw sample parsing, not a complete aggregation. This slightly weakens confidence in the *completeness* of the infrastructure mapping for this CVE, though the CVE itself is confirmed and details from samples are robust.
    - **Tool**: `top_src_ips_for_cve` for `CVE-2024-14007`.
    - **Error**: Returned empty buckets for a known CVE with associated traffic.
    - **Weakened conclusions**: Similar to CVE-2025-55182, the source IP list relies solely on samples, impacting the completeness of source IP mapping for this CVE.

## 13) Agent Action Summary (Audit Trail)

- **agent_name**: ParallelInvestigationAgent
    - **purpose**: Orchestrate parallel data collection from various honeypot and network monitoring sources.
    - **inputs_used**: None (initial data collection)
    - **actions_taken**: Called BaselineAgent, KnownSignalAgent, CredentialNoiseAgent, HoneypotSpecificAgent.
    - **key_results**: Gathered initial statistics on total attacks, top countries/IPs, Suricata alerts, CVEs, credential attempts, and honeypot-specific logs (Redis, ADB, Tanner).
    - **errors_or_gaps**: None.

- **agent_name**: BaselineAgent
    - **purpose**: Collect broad baseline statistics on overall activity.
    - **inputs_used**: `investigation_start`, `investigation_end`
    - **actions_taken**: Queried total attacks, top countries, top attacker IPs, country-to-port mapping, and attacker ASNs.
    - **key_results**: Identified 19429 attacks, top IPs 79.98.102.166, 189.231.160.65, top countries US, France, Mexico.
    - **errors_or_gaps**: None.

- **agent_name**: KnownSignalAgent
    - **purpose**: Identify known threat signatures and CVEs.
    - **inputs_used**: `investigation_start`, `investigation_end`
    - **actions_taken**: Queried for top alert signatures, CVEs, and alert categories. Performed phrase search for VNC signatures.
    - **key_results**: Identified "GPL INFO VNC server response" as the highest alert, CVE-2025-55182 and CVE-2024-14007 as notable CVEs.
    - **errors_or_gaps**: None.

- **agent_name**: CredentialNoiseAgent
    - **purpose**: Characterize credential stuffing and brute-force activity.
    - **inputs_used**: `investigation_start`, `investigation_end`
    - **actions_taken**: Queried for top input usernames and passwords, and OS distribution detected by p0f.
    - **key_results**: Identified common usernames (root, admin) and passwords (123456, password) used in attacks.
    - **errors_or_gaps**: None.

- **agent_name**: HoneypotSpecificAgent
    - **purpose**: Analyze specific honeypot logs for unusual or targeted activity.
    - **inputs_used**: `investigation_start`, `investigation_end`
    - **actions_taken**: Queried Redis activity, ADB honeypot inputs and malware samples, Conpot inputs and protocols, and Tanner resource searches.
    - **key_results**: Observed Redis interactions, ADB shell commands, and scans for sensitive paths like `/.env` and `/.aws/credentials` on Tanner.
    - **errors_or_gaps**: None.

- **agent_name**: CandidateDiscoveryAgent
    - **purpose**: Identify initial high-signal candidates for further validation.
    - **inputs_used**: `baseline_result`, `known_signals_result`, `honeypot_specific_result`
    - **actions_taken**: Extracted top IPs, CVEs, and sensitive paths as candidates.
    - **key_results**: Generated 7 initial candidates (3 IPs, 2 CVEs, 2 paths).
    - **errors_or_gaps**: None.

- **agent_name**: CandidateValidationLoopAgent
    - **purpose**: Validate and classify each candidate through detailed queries and knownness checks.
    - **inputs_used**: `candidate_discovery_result`, `investigation_start`, `investigation_end`
    - **actions_taken**: Iterated through 7 candidates, performing various validation queries (`events_for_src_ip`, `suricata_cve_samples`, `kibanna_discover_query`, `two_level_terms_aggregated`).
    - **key_results**:
        - Classified 5 candidates as "known_exploit_campaign" (3 IPs, 2 paths).
        - Classified 2 candidates as "emerging_n_day_exploitation" (2 CVEs).
        - Identified tool inconsistencies/failures for `top_src_ips_for_cve` and `top_dest_ports_for_cve` for both CVEs, leading to "provisional" status.
    - **errors_or_gaps**: Failed queries for `top_src_ips_for_cve` and `top_dest_ports_for_cve` for CVE-2025-55182 and CVE-2024-14007.

- **agent_name**: OSINTAgent
    - **purpose**: Perform open-source intelligence checks for identified candidates.
    - **inputs_used**: `validated_candidates` (implicitly, as it processes candidate results)
    - **actions_taken**: Performed web searches for IP reputations, CVE details, and common vulnerabilities related to sensitive files.
    - **key_results**: Confirmed poor reputations for 79.98.102.166 and 185.177.72.30. Provided detailed context for CVE-2025-55182, CVE-2024-14007, and sensitive file exposure (`.env`, `.aws/credentials`), reducing novelty of all associated observed activities.
    - **errors_or_gaps**: `189.231.160.65 reputation` search did not return direct reputation details, relying instead on generic advice for checking IP reputation.

- **agent_name**: ReportAgent (self)
    - **purpose**: Compile the final report from workflow state outputs.
    - **inputs_used**: `investigation_start`, `investigation_end`, `baseline_result`, `known_signals_result`, `credential_noise_result`, `honeypot_specific_result`, `validated_candidates`, `osint_validation_result`
    - **actions_taken**: Generated a markdown report adhering to the specified format.
    - **key_results**: The completed markdown report.
    - **errors_or_gaps**: None.

- **agent_name**: SaveReportAgent
    - **purpose**: Save the generated report.
    - **inputs_used**: The report content generated by ReportAgent.
    - **actions_taken**: Saved the report to a default file location.
    - **key_results**: Report saved successfully.
    - **errors_or_gaps**: None.
