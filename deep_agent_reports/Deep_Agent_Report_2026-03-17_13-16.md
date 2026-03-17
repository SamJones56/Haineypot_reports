# Final Honeypot Threat Hunting Report

## 1) Investigation Scope
- **investigation_start**: 2026-03-17T13:00:15Z
- **investigation_end**: 2026-03-17T16:00:15Z
- **completion_status**: Partial (degraded evidence)
- **degraded_mode**: True. The `CandidateValidationLoopAgent` and `DeepInvestigationLoopController` exited prematurely. Only 1 out of 9 candidates ([NDE-01]) received full deep validation and temporal checks. Conclusions for the remaining candidates rely strictly on OSINT and baseline discovery data.

## 2) Executive Triage Summary
- **Top services/ports of interest**: SMB (445), VNC (5902-5904), SSH (22), Redis (6379), Web (3000, 3014, 9663), Kamstrup ICS Protocol (1025), Mikrotik API (8728), Printer (PJL).
- **Top confirmed known exploitation**: React2Shell (CVE-2025-55182) pre-auth RCE observed heavily targeting non-standard web ports; NVMS-9000 Auth Bypass (CVE-2024-14007); PHP CGI RCE (CVE-2024-4577).
- **Top unmapped exploit-like items**: None (The only initially unmapped candidate was successfully mapped by OSINT to the known h2Miner/HeadCrab Redis botnet).
- **Botnet/campaign mapping highlights**: A highly targeted credential spray campaign was observed focusing on the users `solana` and `sol`, indicating targeted reconnaissance against cryptocurrency infrastructure (RPC nodes/validators). Additionally, widespread spray attacks against Cisco ASA VPN interfaces were captured.
- **Major uncertainties if degraded**: Because deep validation was aborted, full infrastructure clustering, temporal persistence, and artifact chaining for 8 of the 9 identified candidates are missing.

## 3) Candidate Discovery Summary
- **Total Attacks Evaluated**: 15,915
- **Emerging n-day Exploitation Candidates**: 3
- **Botnet/Campaign Candidates**: 2
- **Novel Exploit Candidates**: 0 (1 reclassified to known malware)
- **Odd-Service / Minutia Attacks**: 2
- **Suspicious Unmapped Monitor**: 1
- **Missing Inputs/Errors**: Early termination of loop agents materially affected the depth of validation for all candidates except [NDE-01].

## 4) Emerging n-day Exploitation
- **[NDE-01] React2Shell (CVE-2025-55182) - Critical pre-auth RCE in React Server Components**
  - **cve/signature mapping**: CVE-2025-55182
  - **evidence summary**: 67 attacks targeting non-standard web ports via POST requests to `/`, `/api`, `/app`, `/_next/server`, and `/api/route`. Top attacking IPs include 193.32.162.28 and 193.26.115.178.
  - **affected service/port**: Web Application (Ports 3000, 3014, 9068, 9663, 10443, etc.)
  - **confidence**: High
  - **operational notes**: OSINT confirms this is an actively exploited critical pre-auth RCE in React Flight Protocol. Both IPs exhibited persistent fan-out behaviors across the time window.

- **[NDE-02] NVMS-9000 Firmware Auth Bypass**
  - **cve/signature mapping**: CVE-2024-14007
  - **evidence summary**: 5 attacks detected in Suricata alerts.
  - **affected service/port**: Surveillance/DVR Firmware
  - **confidence**: High (Provisional due to loop exit)
  - **operational notes**: Established vulnerability allowing remote administrative query commands against older NVR/DVR firmware.

- **[NDE-03] PHP CGI RCE**
  - **cve/signature mapping**: CVE-2024-4577
  - **evidence summary**: 4 attacks detected in alerts.
  - **affected service/port**: Web (PHP CGI)
  - **confidence**: High (Provisional due to loop exit)
  - **operational notes**: Widely exploited vulnerability bypassing Best-Fit encoding protections; often leveraged by ransomware groups (e.g., TellYouThePass).

## 5) Novel or Zero-Day Exploit Candidates (UNMAPPED ONLY)
*None.*
*Note: Candidate [NOV-01] (`MODULE LOAD /tmp/exp.so`) was initially classified as novel but was successfully mapped by OSINT to the known Redis Rogue Master exploitation technique associated with the h2Miner and HeadCrab botnets. It has been reclassified to Infrastructure Mapping / Commodity Exclusions.*

## 6) Botnet/Campaign Infrastructure Mapping
- **[BOT-01] Solana Infrastructure Targeting**
  - **campaign_shape**: Spray
  - **suspected_compromised_src_ips**: 2.57.122.96, 2.57.122.208 (Total of 31 attacks)
  - **ASNs**: 47890 (Unmanaged Ltd)
  - **suspected_staging indicators**: None
  - **suspected_c2 indicators**: None
  - **confidence**: Moderate (Provisional)
  - **operational notes**: Highly targeted credential brute-force explicitly against the usernames `solana` and `sol`. OSINT returned no public campaigns tracking this specific targeting behavior on SSH, indicating an unmapped but directed threat actor aiming at blockchain/validator infrastructure.

- **[BOT-02] Cisco ASA VPN Brute Force Spray**
  - **campaign_shape**: Spray
  - **suspected_compromised_src_ips**: 92.63.197.92, 185.156.73.167, 185.156.73.62, 92.63.197.23, 92.63.197.59
  - **ASNs**: Ukraine (ASN 211736) noted for 92.63.197.92
  - **suspected_staging indicators**: None
  - **suspected_c2 indicators**: None
  - **confidence**: High
  - **operational notes**: Coordinated spray across 630 connections targeting Cisco ASA honeypots. OSINT confirms active credential stuffing targeting these endpoints globally.

- **[NOV-01] Redis Rogue Master Exploitation (h2Miner/HeadCrab)**
  - **campaign_shape**: Fan-out
  - **suspected_compromised_src_ips**: 14.103.62.35 (7 counts)
  - **ASNs**: 4811 (China Telecom Group)
  - **suspected_staging indicators**: `/tmp/exp.so`
  - **suspected_c2 indicators**: None
  - **confidence**: High
  - **operational notes**: Well-documented botnet behavior establishing persistence on exposed Redis instances.

## 7) Odd-Service / Minutia Attacks
- **[ODD-01] Kamstrup Meter Protocol Targeting**
  - **service_fingerprint**: Port 1025 / Kamstrup Protocol (ICS/SCADA)
  - **why it’s unusual**: Direct interaction with proprietary smart energy meter protocols over the internet.
  - **evidence summary**: 76 requests captured in ConPot. Attacking IP: 172.236.228.111. Payload hex: `000e0401040302010203040105010601ff01`.
  - **confidence**: High
  - **recommended monitoring pivots**: Monitor port 1025 for unauthorized point-to-point KMP polling, which could indicate smart grid reconnaissance.

- **[MIN-01] Miniprint Printer Attacks**
  - **service_fingerprint**: Printer/PJL Simulation
  - **why it’s unusual**: Dedicated attempts to probe/exploit networked printers.
  - **evidence summary**: 32 attacks originating from 91.224.92.125 and 147.185.132.52.
  - **confidence**: Moderate
  - **recommended monitoring pivots**: Track PJL interactions or CORBA proxy probing.

- **[MON-01] Mikrotik API Scanning**
  - **service_fingerprint**: Port 8728 (Mikrotik API)
  - **why it’s unusual**: Targeting router management APIs instead of generic web surfaces.
  - **evidence summary**: 29 attacks from Canadian IPs.
  - **confidence**: High
  - **recommended monitoring pivots**: OSINT connects this to botnets using `MikrotikAPI-BF` and CVE-2023-30799 privilege escalation attempts.

## 8) Known-Exploit / Commodity Exclusions
- **Commodity SMB Scanning**: 3,151 high-volume port 445 attacks from a single IP (103.21.168.26 in the Philippines) captured by Dionaea. Consistent with WannaCry/Conficker background noise.
- **Commodity VNC Scanning**: 8,375 mass scanning alerts (`GPL INFO VNC server response`) on ports 5902, 5903, 5904 by multiple US IPs. Captured by Honeytrap.
- **Redis h2Miner/HeadCrab**: Commodity loading of `.so` modules into unauthenticated Redis databases for cryptojacking.

## 9) Infrastructure & Behavioral Classification
- **Exploitation vs Scanning**: The vast majority of traffic is ambient scanning (SMB, VNC). However, deliberate exploitation is occurring against React Web Apps, PHP CGI, Redis databases, and specialized services like Kamstrup.
- **Campaign Shape**:
  - *Fan-out*: React2Shell attackers (193.32.162.28, 193.26.115.178) targeting arrays of non-standard ports.
  - *Spray*: Cisco ASA credentials and Solana SSH user brute-forcing.
- **Infra Reuse Indicators**: AS47890 (Unmanaged Ltd, Romania) is serving as a nexus for multiple distinct malicious activities, including both React2Shell web exploitation and the Solana SSH credential spray.
- **Odd-Service Fingerprints**: Attackers are looking far beyond web/SSH, explicitly probing ICS energy meters (1025), Mikrotik routers (8728), and printers.

## 10) Evidence Appendix
**[NDE-01] React2Shell**
- **Source IPs**: 193.32.162.28, 193.26.115.178 (Unmanaged Ltd / AS47890)
- **Target Ports**: 3000, 3014, 9663, 9068, 10443, 8087, 30000, 2053, 3022, 1080
- **Paths**: `/`, `/api`, `/app`, `/_next/server`, `/api/route`, `/_next`
- **Payload excerpts**: `POST` requests mapped to `ET WEB_SPECIFIC_APPS React Server Components React2Shell` and `Javascript Prototype Pollution Attempt`.

**[BOT-01] Solana Validator SSH Spray**
- **Source IPs**: 2.57.122.96, 2.57.122.208
- **Target Ports**: 22 (Cowrie)
- **Targeted Usernames**: `solana`, `sol`

## 11) Indicators of Interest
- **IPs**: 193.32.162.28, 193.26.115.178 (React2Shell); 2.57.122.96, 2.57.122.208 (Solana Spray); 14.103.62.35 (Redis Rogue Master); 172.236.228.111 (Kamstrup Protocol Scanner).
- **Paths**: `/_next/server`, `/api/route`
- **File Artifacts**: `/tmp/exp.so`
- **Kamstrup Hex Payload**: `000e0401040302010203040105010601ff01`

## 12) Backend Tool Issues
- **CandidateValidationLoopAgent**: Requested early exit; validated only candidate [NDE-01].
- **DeepInvestigationLoopController**: Terminated prematurely via manual `exit_loop` call.
- **OSINTValidatorAgent**: Terminated prematurely via manual `exit_loop` call.
- **Affected Conclusions**: Due to these early exits, temporal persistence, first/last seen checks, and deeper infrastructure correlations are completely missing for 8 out of the 9 candidates. Findings for these 8 candidates rely strictly on broad Kibana discovery queries and OSINT mapping.

## 13) Agent Action Summary (Audit Trail)
- **ParallelInvestigationAgent**:
  - **Purpose**: Gather telemetry baseline, credentials, and honeypot-specific artifacts.
  - **Inputs used**: Time window (2026-03-17T13:00:15Z to 16:00:15Z).
  - **Actions taken**: `get_total_attacks`, `get_top_countries`, `get_alert_signature`, `get_cve`, `get_input_usernames`, `redis_duration_and_bytes`, `conpot_protocol`.
  - **Key results**: 15,915 attacks; discovered CVE-2025-55182 alerts; identified `solana` credential brute-force; identified Kamstrup protocol and Redis `MODULE LOAD` artifacts.
  - **Errors/gaps**: None.
- **CandidateDiscoveryAgent**:
  - **Purpose**: Discover, cluster, and prioritize attack candidates.
  - **Inputs used**: Parallel Investigation Agent outputs.
  - **Actions taken**: `discover_by_keyword`, `search`, `kibanna_discover_query`, `two_level_terms_aggregated`.
  - **Key results**: Successfully formed 9 distinct candidate structures representing n-day exploitation, campaigns, novel attempts, and odd-service probing.
  - **Errors/gaps**: None.
- **CandidateValidationLoopAgent**:
  - **Purpose**: Validate candidates and build historical context.
  - **Inputs used**: The 9 generated candidates.
  - **Actions taken**: `first_last_seen_src_ip`, `append_validated_candidate`.
  - **Key results**: Iterations run: 1. Fully validated 1 candidate ([NDE-01]).
  - **Errors/gaps**: Early loop exit triggered. Did not validate 8 candidates.
- **DeepInvestigationLoopController**:
  - **Purpose**: Deep dive into the infrastructure of top validated candidates.
  - **Inputs used**: Validated candidate [NDE-01].
  - **Actions taken**: `two_level_terms_aggregated`, `search`, `web_path_samples`, `first_last_seen_src_ip`, `top_http_urls_for_src_ip`, `exit_loop`.
  - **Key results**: Iterations run: 2. Profiled web paths (`/api/route`) and confirmed fan-out behavior for IPs 193.32.162.28 and 193.26.115.178.
  - **Errors/gaps**: Aborted prematurely via `exit_loop`.
- **OSINTAgent**:
  - **Purpose**: Correlate artifacts with public threat intelligence.
  - **Inputs used**: CVE IDs, strings (`solana`, `MODULE LOAD`), service names.
  - **Actions taken**: Multiple `search` calls for intelligence.
  - **Key results**: Confirmed React2Shell, mapped Redis payload to h2Miner/HeadCrab, identified Kamstrup protocol details, and confirmed Mikrotik API exploitation context.
  - **Errors/gaps**: None.
- **ReportAgent**:
  - **Purpose**: Compile the final markdown report.
  - **Inputs used**: Workflow state from all previous agents.
  - **Actions taken**: Aggregation and formatting of findings.
  - **Key results**: Report generated reflecting partial/degraded validation state.
  - **Errors/gaps**: Missing deep investigation data for 8 candidates due to upstream agent termination.
- **SaveReportAgent**:
  - **Purpose**: Write report to disk.
  - **Inputs used**: Final markdown string.
  - **Actions taken**: `deep_agent_write_file`.
  - **Key results**: Awaiting write confirmation.
  - **Errors/gaps**: None.