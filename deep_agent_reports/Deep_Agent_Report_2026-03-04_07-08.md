# Honeypot Threat Hunting Report

## 1) Investigation Scope
- investigation_start: 2026-03-04T07:00:05Z
- investigation_end: 2026-03-04T08:00:05Z
- completion_status: Complete
- degraded_mode: false

## 2) Executive Triage Summary
- Total 7864 attack attempts observed within the one-hour window.
- Significant scanning activity targeting SSH (port 22) and VNC-related services (ports 5906, 5907, 5911, 5925, 5926) was identified.
- Industrial Control System (ICS) protocols, specifically Kamstrup and IEC104, were probed on Conpot honeypots, indicating targeted or wide-scale ICS scanning.
- Low-volume detections of CVE-2019-11500 (Pulse Connect Secure) and CVE-2024-14007 were noted (1 count each).
- The majority of high-volume scanning originated from DigitalOcean (ASN 14061), with specific IPs like 165.232.154.91 contributing 3537 attacks. This points to active botnet or compromised infrastructure.
- No novel or potential zero-day exploit candidates were discovered or validated in this window.

## 3) Candidate Discovery Summary
A total of 7864 attacks were observed. Top alert categories included "Misc activity" (2748), "Generic Protocol Command Decode" (821), and "Attempted Information Leak" (383). Despite significant activity, the candidate discovery process did not identify any high-signal novel exploit candidates for further validation in this investigation window. All workflow inputs were processed successfully without material errors affecting discovery.

## 4) Emerging n-day Exploitation
- **CVE-2024-14007**
    - **cve/signature mapping**: CVE-2024-14007
    - **evidence summary**: 1 count.
    - **affected service/port**: Not explicitly detailed, but detected.
    - **confidence**: Provisional
    - **operational notes**: Monitor for increased activity and contextualize for specific product.
- **CVE-2019-11500**
    - **cve/signature mapping**: CVE-2019-11500 (Pulse Connect Secure RCE)
    - **evidence summary**: 1 count.
    - **affected service/port**: Not explicitly detailed, but detected.
    - **confidence**: Provisional
    - **operational notes**: Common n-day exploit, often part of broader scanning.
- **VNC Server Scanning**
    - **cve/signature mapping**: GPL INFO VNC server response (Signature ID: 2100560)
    - **evidence summary**: 2600 counts.
    - **affected service/port**: VNC (ports 5906, 5907, 5911, 5925, 5926).
    - **confidence**: High
    - **operational notes**: Widespread scanning activity, likely looking for vulnerable VNC services.
- **MS Terminal Server Scanning**
    - **cve/signature mapping**: ET SCAN MS Terminal Server Traffic on Non-standard Port (Signature ID: 2023753)
    - **evidence summary**: 344 counts.
    - **affected service/port**: RDP (various non-standard ports).
    - **confidence**: High
    - **operational notes**: Indicates scanning for RDP services potentially moved off default port 3389.

## 5) Novel or Zero-Day Exploit Candidates (UNMAPPED ONLY, ranked)
No novel or potential zero-day exploit candidates were identified in this investigation window.

## 6) Botnet/Campaign Infrastructure Mapping
- **DigitalOcean & Cloud Provider Scanning Campaign**
    - **item_id or related candidate_id(s)**: N/A (general campaign)
    - **campaign_shape**: Spray / Mass Scanning
    - **suspected_compromised_src_ips**: 
        - 165.232.154.91 (3537 counts)
        - 138.68.85.52 (525 counts)
        - 64.226.109.105 (401 counts)
        - 46.19.137.194 (383 counts)
        - 136.114.97.84 (264 counts)
    - **ASNs / geo hints**: 
        - ASN 14061 (DigitalOcean, LLC) - 5712 counts (primarily US)
        - ASN 51852 (Private Layer INC) - 383 counts (Switzerland)
        - ASN 396982 (Google LLC) - 392 counts (US)
    - **suspected_staging indicators**: None explicitly observed
    - **suspected_c2 indicators**: None explicitly observed
    - **confidence**: High
    - **operational notes**: The overwhelming majority of traffic from DigitalOcean suggests compromised instances or dedicated scanning infrastructure. Focus monitoring on connections from these ASNs and IPs, especially for SSH/VNC attempts.

## 7) Odd-Service / Minutia Attacks
- **Kamstrup Protocol Probing**
    - **service_fingerprint**: kamstrup_protocol (on Conpot, port not specified in logs but typically ICS ports)
    - **why it’s unusual/interesting**: Kamstrup is an Industrial Control System (ICS) protocol for smart metering infrastructure, indicating specialized scanning or reconnaissance.
    - **evidence summary**: 3 counts of protocol interaction.
    - **confidence**: High
    - **recommended monitoring pivots**: Alert on any unexpected Kamstrup protocol activity on network segments.
- **IEC104 Protocol Probing**
    - **service_fingerprint**: IEC104 (on Conpot, port not specified in logs but typically ICS ports)
    - **why it’s unusual/interesting**: IEC 60870-5-104 is a widely used SCADA protocol for power utility automation, indicating specialized ICS scanning.
    - **evidence summary**: 1 count of protocol interaction.
    - **confidence**: High
    - **recommended monitoring pivots**: Alert on any unexpected IEC104 protocol activity, especially towards OT environments.
- **Redis Anomalous Traffic**
    - **service_fingerprint**: Redis (port 6379, implied by tool call) with non-Redis payloads.
    - **why it’s unusual/interesting**: Observed payloads like `\x16\x03\x03...` (SSL/TLS handshake attempt) and `GET / HTTP/1.1` indicate either misdirected traffic or generic scanners probing multiple services on common ports, not specifically targeting Redis.
    - **evidence summary**: 1 count of SSL/TLS handshake, 1 count of HTTP GET, amidst general Redis connection activity.
    - **confidence**: Medium
    - **recommended monitoring pivots**: Investigate source IPs sending non-Redis traffic to Redis ports; could indicate misconfiguration or broad scanning.

## 8) Known-Exploit / Commodity Exclusions
- **Credential Brute Force:**
    - High volume of common username attempts: 'root' (182), 'user' (82), 'oracle' (61), 'hadoop' (49), 'git' (22).
    - Common password attempts: '123456' (80), '123' (29), 'P@ssw0rd' (21), 'password' (20).
    - Primarily targeting SSH (port 22) and likely other administrative services.
- **Common Scanners & Reconnaissance:**
    - Widespread VNC server response scanning (2600 counts).
    - MS Terminal Server (RDP) scanning on non-standard ports (344 counts).
    - Generic URI scanning on web services, including common paths like `/` (33 counts), WordPress-related paths (15, 14 counts), `/.env` (2 counts), `/+CSCOE+/logon.html` (1 count), `/.aider.conf.yml` (1 count), `/.git/config` (1 count), `/admin/index.html` (1 count), `/blog/cifras?page=1` (1 count), `/index.html` (1 count).
- **Network Noise/Anomalies:**
    - Frequent SURICATA alerts for truncated packets (IPv4: 238, AF-PACKET: 238) and STREAM Packet with broken ack (112 counts), indicative of network-level disruptions or malformed packets often associated with scanning tools.

## 9) Infrastructure & Behavioral Classification
- **Exploitation vs Scanning**: The activity profile is overwhelmingly dominated by widespread scanning, reconnaissance, and brute-force attempts. Explicit exploitation attempts (CVEs) were present but in very low numbers, suggesting either targeted, rare attempts or noisy sensor triggers amidst commodity activity.
- **Campaign Shape**: Predominantly "spray" or mass scanning campaigns. Attackers are broadly targeting common services (SSH, VNC) and specific web application paths, as well as unique ICS protocols. The concentration of activity from specific cloud ASNs/IPs suggests organized botnet-like operations or dedicated scanning infrastructure.
- **Infra Reuse Indicators**: High utilization of DigitalOcean (ASN 14061) and other cloud providers (Google LLC, Private Layer INC) for originating attacks. This is a common pattern for commodity scanning and initial access campaigns.
- **Odd-Service Fingerprints**: Detection of Kamstrup and IEC104 protocols on ICS honeypots indicates a distinct focus on critical infrastructure scanning alongside more common internet-wide activities. Redis honeypots also observed non-standard traffic patterns, further highlighting generic or misdirected scanning.

## 10) Evidence Appendix

- **Emerging n-day: CVE-2024-14007**
    - **source IPs with counts**: Not directly linked in provided data.
    - **ASNs with counts**: Not directly linked in provided data.
    - **target ports/services**: Not directly linked in provided data.
    - **payload/artifact excerpts**: Not provided.
    - **staging indicators**: Not provided.
    - **temporal checks results**: Unavailable.
- **Emerging n-day: CVE-2019-11500**
    - **source IPs with counts**: Not directly linked in provided data.
    - **ASNs with counts**: Not directly linked in provided data.
    - **target ports/services**: Not directly linked in provided data.
    - **payload/artifact excerpts**: Not provided.
    - **staging indicators**: Not provided.
    - **temporal checks results**: Unavailable.
- **Botnet Mapping: DigitalOcean Scanning Activity**
    - **source IPs with counts**:
        - 165.232.154.91 (3537)
        - 138.68.85.52 (525)
        - 64.226.109.105 (401)
        - 46.19.137.194 (383)
        - 136.114.97.84 (264)
    - **ASNs with counts**:
        - ASN 14061 (DigitalOcean, LLC) (5712)
        - ASN 51852 (Private Layer INC) (383)
        - ASN 396982 (Google LLC) (392)
    - **target ports/services**: Port 22 (SSH), Port 5926 (VNC), Port 5925 (VNC), Port 5437, Port 25, Port 5906 (VNC), Port 5907 (VNC), Port 5911 (VNC), Port 15432, Port 8728, Port 8090, Port 5432.
    - **paths/endpoints**: `/`, `/wp-includes/js/jquery/jquery-migrate.min.js`, `/wp-includes/js/jquery/jquery.js`, `/.env`, `/+CSCOE+/logon.html`, `/.aider.conf.yml`, `/.git/config`, `/admin/index.html`, `/blog/cifras?page=1`, `/index.html` (from tanner_unifrom_resource_search).
    - **payload/artifact excerpts**: VNC server response (GPL INFO signature), common usernames/passwords ('root', '123456').
    - **staging indicators**: Not explicitly observed.
    - **temporal checks results**: Unavailable.
- **Odd-Service: Kamstrup Protocol**
    - **source IPs with counts**: Not directly linked in provided data.
    - **ASNs with counts**: Not directly linked in provided data.
    - **target ports/services**: Conpot honeypot, ICS protocol.
    - **payload/artifact excerpts**: Kamstrup protocol interactions.
    - **staging indicators**: Not provided.
    - **temporal checks results**: Unavailable.
- **Odd-Service: IEC104 Protocol**
    - **source IPs with counts**: Not directly linked in provided data.
    - **ASNs with counts**: Not directly linked in provided data.
    - **target ports/services**: Conpot honeypot, ICS protocol.
    - **payload/artifact excerpts**: IEC104 protocol interactions.
    - **staging indicators**: Not provided.
    - **temporal checks results**: Unavailable.

## 11) Indicators of Interest
- **Source IPs**:
    - 165.232.154.91
    - 138.68.85.52
    - 64.226.109.105
    - 46.19.137.194
    - 136.114.97.84
- **ASNs**:
    - ASN 14061 (DigitalOcean, LLC)
    - ASN 51852 (Private Layer INC)
- **Target Ports**:
    - 22 (SSH)
    - 25 (SMTP)
    - 5437 (PostgreSQL client?)
    - 5906, 5907, 5911, 5925, 5926 (VNC)
    - 6379 (Redis - for anomalous traffic)
    - 8090 (HTTP/Web)
    - 8728 (MikroTik WinBox)
    - 15432 (PostgreSQL)
- **Paths/Endpoints**:
    - `/wp-includes/js/jquery/jquery-migrate.min.js`
    - `/wp-includes/js/jquery/jquery.js`
    - `/.env`
    - `/+CSCOE+/logon.html`
    - `/.git/config`
- **Payload Fragments / Signatures**:
    - `GPL INFO VNC server response` (Suricata Signature 2100560)
    - `ET SCAN MS Terminal Server Traffic on Non-standard Port` (Suricata Signature 2023753)
    - Common usernames: `root`, `user`, `oracle`
    - Common passwords: `123456`, `123`, `P@ssw0rd`
- **CVEs**:
    - CVE-2019-11500
    - CVE-2024-14007

## 12) Backend Tool Issues
No backend tool failures or errors were identified during this investigation. All queries executed successfully.

## 13) Agent Action Summary (Audit Trail)

- **agent_name**: BaselineAgent
    - **purpose**: Establish baseline telemetry and overall attack statistics.
    - **inputs_used**: investigation_start, investigation_end
    - **actions_taken**: Queried total attacks, top countries, top attacker source IPs, country-to-port mapping, and top attacker ASNs.
    - **key_results**: Identified 7864 total attacks, top source countries (US, Germany, Switzerland), top attacker IPs (165.232.154.91, 138.68.85.52), top ASNs (DigitalOcean LLC), and common ports like 22 (SSH) and 59xx (VNC).
    - **errors_or_gaps**: None.

- **agent_name**: KnownSignalAgent
    - **purpose**: Identify known exploitation patterns, signatures, and CVEs.
    - **inputs_used**: investigation_start, investigation_end
    - **actions_taken**: Queried top alert signatures, CVEs, and alert categories. Performed a phrase search for "attack" in signatures (no results).
    - **key_results**: Detected high volume of VNC server response (2600) and MS Terminal Server scanning (344). Noted 1 count each for CVE-2019-11500 and CVE-2024-14007. Identified "Misc activity" and "Generic Protocol Command Decode" as top alert categories.
    - **errors_or_gaps**: None.

- **agent_name**: CredentialNoiseAgent
    - **purpose**: Identify common credential brute-force attempts and OS fingerprinting.
    - **inputs_used**: investigation_start, investigation_end
    - **actions_taken**: Queried top input usernames, top input passwords, and p0f OS distribution.
    - **key_results**: Identified common usernames ('root', 'user') and passwords ('123456', '123'). Detected prevalent OS fingerprints as "Windows NT kernel" and "Linux 2.2.x-3.x".
    - **errors_or_gaps**: None.

- **agent_name**: HoneypotSpecificAgent
    - **purpose**: Extract specific activity from honeypot deployments (Redis, ADBHoney, Conpot, Tanner).
    - **inputs_used**: investigation_start, investigation_end
    - **actions_taken**: Queried Redis duration/bytes, ADBHoney inputs/malware, Conpot inputs/protocols, and Tanner URI requests.
    - **key_results**: Observed Redis activity including non-Redis payloads. ADBHoney and Conpot inputs showed no activity, but Conpot detected Kamstrup (3) and IEC104 (1) protocols. Tanner honeypot recorded common URI requests like '/' and WordPress-related paths.
    - **errors_or_gaps**: None.

- **agent_name**: CandidateDiscoveryAgent
    - **purpose**: Discover high-signal events for potential novel exploitation.
    - **inputs_used**: baseline_result, known_signals_result, credential_noise_result, honeypot_specific_result
    - **actions_taken**: Evaluated telemetry against known patterns and thresholds.
    - **key_results**: No novel exploit candidates were identified for further validation based on the current window's telemetry.
    - **errors_or_gaps**: None (absence of candidates is a result, not an error).

- **agent_name**: CandidateValidationLoopAgent
    - **purpose**: Validate discovered candidates for novelty, knownness, and operational relevance.
    - **inputs_used**: candidate_discovery_result (effectively empty)
    - **actions_taken**: Initialized candidate queue and attempted to load next candidate.
    - **key_results**: Iterations run: 0. # candidates validated: 0. Loop exited early as no candidates were available.
    - **errors_or_gaps**: None (validation blocked due to absence of candidates).

- **agent_name**: DeepInvestigationLoopController
    - **purpose**: Orchestrate deep dives into high-signal leads.
    - **inputs_used**: validated_candidates (empty)
    - **actions_taken**: Attempted to load deep investigation leads.
    - **key_results**: Iterations run: 0. Key leads pursued: None. Loop stalled/exited due to no candidates requiring deep investigation.
    - **errors_or_gaps**: None (deep investigation blocked due to absence of candidates).

- **agent_name**: OSINTAgent
    - **purpose**: Perform OSINT lookups for validation and context.
    - **inputs_used**: No candidates provided for OSINT validation.
    - **actions_taken**: None.
    - **key_results**: No OSINT validation performed due to lack of candidates.
    - **errors_or_gaps**: No candidates for validation.

- **agent_name**: ReportAgent
    - **purpose**: Compile the final investigation report.
    - **inputs_used**: investigation_start, investigation_end, baseline_result, known_signals_result, credential_noise_result, honeypot_specific_result, candidate_discovery_result (implied empty), validated_candidates (empty), osint_validation_result (empty).
    - **actions_taken**: Consolidated data from all previous agent outputs into the specified report format.
    - **key_results**: Final report generated, summarizing observed activity, known threats, commodity exclusions, and infrastructure.
    - **errors_or_gaps**: None.

- **agent_name**: SaveReportAgent
    - **purpose**: Save the generated report to persistent storage.
    - **inputs_used**: (Report content from ReportAgent)
    - **actions_taken**: (Will be called by workflow to write file)
    - **key_results**: File write status pending/successful (post-agent execution).
    - **errors_or_gaps**: None (pending execution).