# Honeypot Threat Hunting Report

## 1) Investigation Scope
- **investigation_start**: 2026-03-08T09:00:07Z
- **investigation_end**: 2026-03-08T12:00:07Z
- **completion_status**: Complete
- **degraded_mode**: false

## 2) Executive Triage Summary
- Top services of interest include VNC (ports 5901, 5902, 5903), SMB (port 445), HTTP (port 80), ADB (port 5555), and SSH (port 22).
- One critical emerging n-day exploitation (CVE-2025-55182, "React2Shell" RCE) was identified with 54 alerts.
- A single IP from Qatar (AS8781) was responsible for high-volume scanning of SMB (port 445).
- Multiple IPs engaged in web scanning for sensitive files like `.env`, `.aws/credentials`, and `.git/config`.
- ADB (Android Debug Bridge) reconnaissance on port 5555 by a Spamhaus-listed IP from Germany was identified as an odd-service attack, not a novel exploit.
- Standard commodity activities like VNC scanning and SSH brute-force attempts continue to be prevalent.

## 3) Candidate Discovery Summary
- **Total Attacks**: 14830
- **Top Attacker Countries**: United States (4911), Netherlands (1608), Qatar (1395)
- **Top Attacker Source IPs**:
    - 178.153.127.226 (1395 events)
    - 136.114.97.84 (764 events)
    - 178.128.246.254 (575 events)
- **Top Attacker ASNs**:
    - AS14061 DigitalOcean, LLC (4930 events)
    - AS8781 Ooredoo Q.S.C. (1395 events)
    - AS396982 Google LLC (1163 events)
- **Top Ports Targeted**:
    - VNC (5902, 5901, 5903)
    - SMB (445)
    - SSH (22)
- **Top Suricata Alert Signatures**:
    - GPL INFO VNC server response (18380 events)
    - SURICATA IPv4 truncated packet (843 events)
    - ET SCAN MS Terminal Server Traffic on Non-standard Port (647 events)
- **CVEs Detected**:
    - CVE-2025-55182 (54 events) - React2Shell RCE
    - CVE-2024-14007 (7 events)
- **Credential Noise**: Top usernames 'admin' (87), 'root' (78); top passwords '123456' (45), 'password' (40).
- **Honeypot Specific Discoveries**:
    - Tanner honeypot detected scanning for web paths like `/`, `/.env`, `/.aws/credentials`, `/.git/config`.
    - Adbhoney honeypot detected specific ADB reconnaissance command.

## 4) Emerging n-day Exploitation
**cve/signature mapping**: CVE-2025-55182 (React2Shell)
- **evidence summary**: 54 alerts detected. Publicly known as a critical (CVSS 10.0) unauthenticated Remote Code Execution (RCE) vulnerability affecting React Server Components.
- **affected service/port**: HTTP/HTTPS (implied from React Server Components context)
- **confidence**: High
- **operational notes**: Widespread exploitation observed in the wild shortly after disclosure (Dec 2025), leveraging insecure deserialization in React "Flight" protocol. Requires deep-dive into HTTP POST request bodies to identify specific exploit payloads and attacker infrastructure.

## 5) Novel or Zero-Day Exploit Candidates (UNMAPPED ONLY, ranked)
No candidates currently classified as novel or zero-day exploitation after validation and OSINT checks. Initial candidate NEC-1 was reclassified as an Odd-Service / Minutia Attack.

## 6) Botnet/Campaign Infrastructure Mapping
- **item_id**: BCM-1
- **campaign_shape**: fan-in
- **suspected_compromised_src_ips**: 178.153.127.226 (1395 events)
- **ASNs / geo hints**: AS8781 - Ooredoo Q.S.C. (Qatar)
- **suspected_staging indicators**: None identified.
- **suspected_c2 indicators**: None identified.
- **confidence**: High
- **operational notes**: High-volume, targeted scanning for SMB (port 445) originating from a single IP in Qatar. Monitor for any lateral movement or exploit attempts following this reconnaissance.

- **item_id**: BCM-2
- **campaign_shape**: spray
- **suspected_compromised_src_ips**: 78.153.140.148 (2), 172.236.179.87 (1), 34.158.79.105 (1), 74.0.42.221 (1) - 4 unique IPs across 3 distinct ASNs identified for sensitive file scanning.
- **ASNs / geo hints**: AS197607 (Russia), AS20473 (US), AS14061 (US)
- **suspected_staging indicators**: None identified.
- **suspected_c2 indicators**: None identified.
- **confidence**: Medium
- **operational notes**: Dispersed scanning activity targeting common web application misconfigurations and sensitive file exposure (e.g., `.env`, `.git/config`, AWS credentials). Block these paths at the perimeter.

## 7) Odd-Service / Minutia Attacks
- **service_fingerprint**: ADB on TCP/5555
- **why it’s unusual/interesting**: Android Debug Bridge (ADB) is typically not exposed to the internet. Reconnaissance commands observed suggest an attacker is looking for vulnerable Android devices or services. The source IP is on the Spamhaus DROP list, indicating a known malicious actor.
- **evidence summary**: Two instances of the command `echo "$(getprop ro.product.name 2>/dev/null) $(whoami 2>/dev/null)"` executed by `45.135.194.48` targeting port 5555. This IP also triggered an "ET DROP Spamhaus DROP Listed Traffic Inbound group 6" alert.
- **confidence**: High
- **recommended monitoring pivots**: Continue to monitor `45.135.194.48` for any attempts to move from reconnaissance to exploitation (e.g., file uploads, arbitrary command execution). Monitor for other IPs using similar ADB reconnaissance commands.

## 8) Known-Exploit / Commodity Exclusions
- **VNC Scanning**: High volume of "GPL INFO VNC server response" alerts (18380 events) detected across various VNC ports (5901, 5902, 5903). This is commodity scanning activity.
- **SSH Brute-Force**: Persistent attempts to log in using common usernames (e.g., 'admin', 'root') and weak passwords (e.g., '123456', 'password') on port 22, indicative of widespread credential stuffing.
- **Generic Web Scanning**: Frequent requests to common web paths like `/`, `/backup/`, various `phpinfo` endpoints, and `/.env` from diverse IPs (Tanner honeypot data), typically indicative of automated vulnerability scanning.
- **SURICATA Truncated Packets**: High counts (843 events for IPv4 and AF-PACKET) of "SURICATA IPv4 truncated packet" alerts, which often signify network noise or benign scanning rather than specific exploitation attempts.
- **Spamhaus DROP List IP Scanning**: Multiple IPs, including `45.142.154.87`, triggered "ET DROP Spamhaus DROP Listed Traffic Inbound group 6" alerts while performing generic Nmap scanning activity on various ports, indicating general malicious network reconnaissance.

## 9) Infrastructure & Behavioral Classification
- **Exploitation vs Scanning**: The activity profile is predominantly scanning and reconnaissance (VNC, SSH, web paths, SMB, ADB, Nmap). One instance of confirmed CVE-mapped exploitation (CVE-2025-55182) was observed.
- **Campaign Shape**:
    - SMB scanning from 178.153.127.226 showed a "fan-in" pattern (single source, many targets/attempts).
    - Web scanning for sensitive files showed a "spray" pattern (multiple sources, diverse targets/paths).
    - ADB reconnaissance and Nmap scanning were isolated single-IP events within the timeframe.
- **Infra Reuse Indicators**: Several source IPs (including the ADB recon IP and a cluster of Nmap scanners) were identified on the Spamhaus DROP list, suggesting the use of known malicious or compromised infrastructure. However, no direct campaign coordination was found between the ADB recon IP and the Nmap scanning IPs, indicating separate activities utilizing publicly blacklisted ranges.
- **Odd-Service Fingerprints**: Targeted activity against the Android Debug Bridge (ADB) on TCP/5555 highlights an unusual attack vector, potentially targeting specific device types or misconfigured services.

## 10) Evidence Appendix

### Emerging n-day Exploitation
- **CVE-2025-55182 (React2Shell)**
    - **Alerts**: 54 instances
    - **Affected Service**: HTTP/HTTPS
    - **Operational Note**: Critical RCE vulnerability, actively exploited.

### Botnet/Campaign Infrastructure Mapping
- **BCM-1 (SMB Scanning)**
    - **Source IPs**: 178.153.127.226 (1395 counts)
    - **ASNs**: AS8781 - Ooredoo Q.S.C. (Qatar)
    - **Target Ports/Services**: 445 (SMB)
    - **Payload/Artifact Excerpts**: Not available in logs but implies SMB protocol negotiation.
    - **Temporal Checks**: Unavailable

- **BCM-2 (Web Scanning for Sensitive Files)**
    - **Source IPs**:
        - 78.153.140.148 (2 counts)
        - 172.236.179.87 (1 count)
        - 34.158.79.105 (1 count)
        - 74.0.42.221 (2 counts)
        - 87.121.84.76 (1 count)
    - **ASNs**: Not explicitly detailed for each IP in this context, but originating from diverse providers (e.g., AS197607, AS20473, AS14061).
    - **Target Ports/Services**: 80/443 (HTTP/HTTPS)
    - **Paths/Endpoints**:
        - `/.env` (4 counts)
        - `/.aws/credentials` (1 count)
        - `/.git/config` (1 count)
        - `/_profiler/phpinfo` (1 count)
        - `/admin/phpinfo.php` (1 count)
        - `/backup/` (1 count)
        - `/config.phpinfo` (1 count)
        - `/env.php` (1 count)
        - `/i.php` (1 count)
    - **Payload/Artifact Excerpts**: GET requests for the listed paths.
    - **Temporal Checks**: Unavailable

### Odd-Service / Minutia Attacks
- **NEC-1 (ADB Reconnaissance)**
    - **Source IPs**: 45.135.194.48 (2 command executions, 21 total events)
    - **ASNs**: AS51396 - Pfcloud UG (haftungsbeschrankt) (Germany)
    - **Target Ports/Services**: 5555 (ADB)
    - **Payload/Artifact Excerpts**: `echo "$(getprop ro.product.name 2>/dev/null) $(whoami 2>/dev/null)"`
    - **Staging Indicators**: None identified.
    - **Temporal Checks**: First seen: 2026-03-08T10:25:48.000Z, Last seen: 2026-03-08T10:37:36.796Z

## 11) Indicators of Interest
- **Source IPs**:
    - 178.153.127.226 (High-volume SMB scanning)
    - 45.135.194.48 (ADB reconnaissance, Spamhaus listed)
    - 78.153.140.148, 172.236.179.87, 34.158.79.105, 74.0.42.221 (Web scanning for sensitive files)
- **ASNs**:
    - AS8781 (Ooredoo Q.S.C.)
    - AS51396 (Pfcloud UG (haftungsbeschrankt))
- **Targeted Ports**: 445 (SMB), 5555 (ADB)
- **CVEs**: CVE-2025-55182
- **Paths/Endpoints**:
    - `/.env`
    - `/.aws/credentials`
    - `/.git/config`
    - `/_profiler/phpinfo`
    - `/admin/phpinfo.php`
- **ADB Reconnaissance Command**: `echo "$(getprop ro.product.name 2>/dev/null) $(whoami 2>/dev/null)"`

## 12) Backend Tool Issues
- During deep investigation, the `DeepInvestigationAgent` encountered an error with the `two_level_terms_aggregated` tool when attempting to correlate the source IP `45.135.194.48` with other destination ports. The tool returned data for an unrelated IP (`178.153.127.226`) instead of the requested one. This was identified and noted by the agent, which then pivoted to other leads. While a minor disruption, it was resolved by pivoting to alternative investigative approaches, therefore not critically impacting overall conclusions.

## 13) Agent Action Summary (Audit Trail)

- **ParallelInvestigationAgent**
    - **Purpose**: Conduct parallel investigations across various data sources to gather initial intelligence.
    - **Inputs Used**: `investigation_start`, `investigation_end`
    - **Actions Taken**: Called `get_total_attacks`, `get_top_countries`, `get_attacker_src_ip`, `get_country_to_port`, `get_attacker_asn` (via `BaselineAgent`). Called `get_alert_signature`, `get_cve`, `get_alert_category`, `suricata_lenient_phrase_search` (via `KnownSignalAgent`). Called `get_input_usernames`, `get_input_passwords`, `get_p0f_os_distribution` (via `CredentialNoiseAgent`). Called `redis_duration_and_bytes`, `adbhoney_input`, `adbhoney_malware_samples`, `conpot_input`, `tanner_unifrom_resource_search`, `conpot_protocol` (via `HoneypotSpecificAgent`).
    - **Key Results**: Gathered initial statistics on attack volume, geographic distribution, top attack sources, known alerts/CVEs, credential stuffing trends, and honeypot-specific interactions (Redis, ADB, Tanner web requests).
    - **Errors or Gaps**: None reported.

- **CandidateDiscoveryAgent**
    - **Purpose**: Identify potential high-signal attack candidates from the initial investigation data.
    - **Inputs Used**: Honeypot-specific results (Adbhoney, Tanner), Known Signal results (CVEs).
    - **Actions Taken**: Used `two_level_terms_aggregated` twice to aggregate Adbhoney inputs by src_ip and Tanner paths by src_ip. Performed `kibanna_discover_query` for an IP and `search` for CVE-2025-55182.
    - **Key Results**: Discovered initial candidates for ADB reconnaissance (NEC-1), web scanning for sensitive files (BCM-2), and highlighted CVE-2025-55182 (NDE-1) and high-volume SMB scanning (BCM-1).
    - **Errors or Gaps**: None reported.

- **CandidateValidationLoopAgent**
    - **Purpose**: Validate and refine the classification of discovered candidates.
    - **Inputs Used**: Candidates generated by `CandidateDiscoveryAgent`.
    - **Actions Taken**: Initialized queue with 1 candidate (`NEC-1`). Ran 1 iteration.
    - **Key Results**: `NEC-1` was processed and its validation was passed to the `CandidateValidationAgent`.
    - **Errors or Gaps**: None reported.

- **CandidateValidationAgent** (Sub-agent of CandidateValidationLoopAgent)
    - **Purpose**: Conduct detailed validation checks for a single candidate.
    - **Inputs Used**: `NEC-1` candidate details.
    - **Actions Taken**: Used `events_for_src_ip` to retrieve all events for `45.135.194.48`. Used `search` to research ADB vulnerabilities and reconnaissance commands.
    - **Key Results**: Confirmed `NEC-1` activity was isolated to ADB on port 5555. Determined the ADB command was a known reconnaissance technique, leading to reclassification from "novel exploit candidate" to "odd_service_minutia".
    - **Errors or Gaps**: None reported.

- **DeepInvestigationLoopController**
    - **Purpose**: Orchestrate in-depth investigations into high-priority leads from validated candidates.
    - **Inputs Used**: Validated candidate `NEC-1` (specifically the IP `45.135.194.48`).
    - **Actions Taken**: Ran 3 iterations. Consumed `src_ip:45.135.194.48`. Pivoted to `signature:"ET DROP Spamhaus DROP Listed Traffic Inbound group 6"`. Investigated `src_ip:45.142.154.87`. Pivoted back to `artifact:echo "$(getprop ro.product.name 2>/dev/null) $(whoami 2>/dev/null)"`. Exited loop.
    - **Key Results**: Confirmed the ADB activity was isolated to the initial source IP. Determined that the shared Suricata alert was a coincidence and did not indicate a broader campaign for the ADB reconnaissance. Investigation into `NEC-1` was completed.
    - **Errors or Gaps**: Identified a tool error with `two_level_terms_aggregated` that returned irrelevant data, but successfully navigated around it.

- **OSINTAgent**
    - **Purpose**: Integrate external threat intelligence and OSINT to contextualize findings.
    - **Inputs Used**: Validated candidate `NEC-1` details and classification.
    - **Actions Taken**: Performed OSINT searches for ADB vulnerabilities, the specific ADB reconnaissance command, and the Suricata "Spamhaus DROP" alert.
    - **Key Results**: Confirmed the ADB command is a well-documented reconnaissance technique, reducing the novelty of `NEC-1`. Confirmed the source IP's presence on the Spamhaus DROP list.
    - **Errors or Gaps**: None reported.

- **ReportAgent** (self)
    - **Purpose**: Compile the final report from all collected workflow state outputs.
    - **Inputs Used**: `investigation_start`, `investigation_end`, `baseline_result`, `known_signals_result`, `credential_noise_result`, `honeypot_specific_result`, `candidate_discovery_result`, `validated_candidates`, `osint_validation_result`, `deep_investigation_logs/state`.
    - **Actions Taken**: Compiled and structured the final report in Markdown format according to specified guidelines.
    - **Key Results**: Generation of this comprehensive threat hunting report.
    - **Errors or Gaps**: None.

- **SaveReportAgent**
    - **Purpose**: Save the generated report to persistent storage.
    - **Inputs Used**: The full Markdown content of this report.
    - **Actions Taken**: (The workflow state does not include the output of this tool call, only that it would be called downstream).
    - **Key Results**: (Expected: Report successfully saved to file system).
    - **Errors or Gaps**: The explicit output of the `deep_agent_write_file` tool call is not present in the provided workflow state.