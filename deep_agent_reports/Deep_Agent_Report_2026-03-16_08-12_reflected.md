# Threat Hunting Honeypot Investigation Report

## 1) Investigation Scope
- **investigation_start**: 2026-03-16T08:00:10Z
- **investigation_end**: 2026-03-16T12:00:10Z
- **completion_status**: Complete
- **degraded_mode**: false. Initial investigation was partially degraded due to tool failures, but a reflection-driven follow-up investigation successfully resolved all critical visibility gaps.

## 2) Executive Triage Summary
- **Top Services of Interest**: High-volume scanning was observed on port 445 (SMB) and VNC ports (5902-5904). A major emerging campaign targeted numerous non-standard web development ports (3004, 3010, 3333, etc.).
- **Odd/Minutia Services**: The investigation confirmed and characterized reconnaissance activity against Industrial Control System (ICS) protocols, specifically `guardian_ast` and `kamstrup_protocol`, primarily targeting **TCP port 10001**.
- **Top Confirmed Known Exploitation**: Widespread, active exploitation of **CVE-2025-55182 (React2Shell)**, a critical and recently disclosed RCE in React Server Components.
- **Botnet/Campaign Mapping Highlights**: Two distinct campaigns were mapped:
    1.  The **React2Shell campaign** is comprised of both high-volume specialized scanners and low-volume generalist scanners.
    2.  The **ICS probing activity** was uncoordinated, originating from independent actors including a highly-targeted, short-duration scanner from a US-based cloud provider and a noisy, broad-spectrum scanner from Poland.
- **Major Uncertainties**: All major uncertainties from the initial run have been resolved.

## 3) Candidate Discovery Summary
The discovery process identified several key areas for investigation based on initial telemetry:
- **Known Exploits**: PHPUnit RCE (CVE-2017-9841).
- **Emerging Threats**: Recently disclosed CVEs, most notably CVE-2025-55182.
- **Credential Stuffing**: Use of an unusual but documented credential pair (`345gs5662d34` / `3245gs5662d34`) linked to botnets.
- **Odd-Service Activity**: Probes against Conpot ICS honeypots, which were successfully investigated after an initial failure.

## 4) Emerging n-day Exploitation
### CVE-2025-55182 (React2Shell) Exploitation Campaign
- **cve/signature mapping**: `CVE-2025-55182`, `ET WEB_SPECIFIC_APPS React Server Components React2Shell Unsafe Flight Protocol Property Access (CVE-2025-55182)`
- **evidence summary**: 120 events directly referencing the CVE were observed. Analysis of attacker behavior revealed thousands of related events. Key artifacts include targeted requests to Next.js paths like `/_next/server` and `/api/route`.
- **affected service/port**: A wide range of non-standard TCP web ports, including 3004, 3010, 3333, 5001, 8081, 8088, 8888, 9000, and 9443.
- **confidence**: High
- **operational notes**: This is a critical, recently disclosed (Dec 2025) unauthenticated RCE being actively and widely exploited. All internet-facing assets using React Server Components (especially Next.js) must be patched immediately.

## 5) Novel or Zero-Day Exploit Candidates
No novel exploit candidates were validated. The investigation into the anomalous ICS activity confirmed it to be reconnaissance and service probing rather than novel exploitation.

## 6) Botnet/Campaign Infrastructure Mapping
### CVE-2025-55182 (React2Shell) Campaign
- **item_id**: CVE-2025-55182
- **campaign_shape**: Coordinated spray from multiple distinct actors with different behavioral profiles.
- **suspected_compromised_src_ips**:
    - **Specialist Scanner**: `193.32.162.28` (1701 events) - High-volume, focused exclusively on this CVE, uses rotating user agents.
    - **Generalist Scanner**: `79.124.40.174` (248 events) - Lower-volume, scanned for multiple vulnerabilities including this CVE.
- **ASNs / geo hints**: AS 47890 (Unmanaged Ltd, Romania), AS 50360 (Tamatiya EOOD, Bulgaria).
- **confidence**: High
- **operational notes**: Block source IPs. Monitor for inbound traffic on unusual web ports targeting Next.js application paths, as this is a strong indicator of this campaign.

### ICS Reconnaissance Probing
- **item_id**: ICS-Probing-Campaign
- **campaign_shape**: Uncoordinated spray from independent actors with different profiles.
- **suspected_compromised_src_ips**:
    - **Targeted Scanner**: `147.185.132.39` (89 events) - Short duration, focused exclusively on port 10001.
    - **Broad Scanner**: `95.214.55.63` (885 events) - Long duration, scanned over 20 ports, with ICS probing being incidental.
    - **Other Sources**: `205.210.31.224`, `34.193.119.44`, `34.230.221.101`, `45.142.154.88`.
- **ASNs / geo hints**: AS 396982 (Google LLC, US), AS 201814 (MEVSPACE sp. z o.o., Poland).
- **confidence**: High
- **operational notes**: The activity consists of independent actors rather than a single campaign. Monitoring should focus on the port (10001/tcp) and differentiate between brief, targeted probes (higher potential interest) and noisy, broad scanners (lower interest).

## 7) Odd-Service / Minutia Attacks
### Industrial Control System (ICS) Probes
- **service_fingerprint**: `guardian_ast`, `kamstrup_protocol` interacting with **TCP port 10001**.
- **why it’s unusual/interesting**: Probing of specialized ICS protocols is operationally significant as it indicates reconnaissance against Operational Technology (OT) environments, which is far less common and potentially more targeted than typical web or SSH scans.
- **evidence summary**: The ConPot honeypot recorded 40 events across 6 source IPs. The activity was dominated by two actors with distinct profiles: `147.185.132.39` performed a highly targeted, two-minute probe of port 10001 using a `curl` user agent. In contrast, `95.214.55.63` conducted a noisy, four-hour scan across dozens of ports, with the hits on port 10001 being an incidental part of its broader reconnaissance.
- **confidence**: High
- **recommended monitoring pivots**: Monitor TCP port 10001 for connection attempts. Differentiate alerts based on behavior: short, focused connection attempts are of higher interest than broad, multi-port scanning activity.

## 8) Known-Exploit / Commodity Exclusions
- **Credential Noise & Brute Force**: High volume of generic usernames (`root`, `admin`). The use of `345gs5662d34` and `3245gs5662d34` was confirmed by OSINT to be linked to established botnet activity (e.g., Mirai variants) for SSH/Telnet brute-forcing.
- **Commodity Web Scanning**: Opportunistic scanning for old vulnerabilities like PHPUnit RCE (CVE-2017-9841) and general PHP RFI attempts.
- **High-Volume Port Scanning**: Widespread scanning of VNC (`GPL INFO VNC server response`), SMB (port 445), and RDP (`ET SCAN MS Terminal Server Traffic on Non-standard Port`).

## 9) Infrastructure & Behavioral Classification
- **CVE-2025-55182 Campaign**: Active **exploitation**. The campaign uses a **coordinated spray** shape, leveraging at least two distinct actor types: a high-volume, specialized scanner and a low-volume, generalist scanner.
- **ICS Probing Activity**: **Reconnaissance/Scanning**. The campaign shape is an **uncoordinated spray** from independent actors. Two distinct profiles were observed: a targeted, short-duration probe and a broad, long-duration scan. The key service fingerprint is `10001/tcp` (ICS).

## 10) Evidence Appendix
### Emerging n-day: CVE-2025-55182
- **source IPs**: `193.32.162.28` (1701 events), `79.124.40.174` (248 events)
- **ASNs**: 47890 (Romania), 50360 (Bulgaria)
- **target ports/services**: 3004/tcp, 3010/tcp, 3333/tcp, 5001/tcp, 8081/tcp, 8088/tcp, 9000/tcp, 9443/tcp
- **paths/endpoints**: `/_next/server`, `/api/route`, `/app`, `/`
- **payload/artifact excerpts**: Suricata Signature: `ET WEB_SPECIFIC_APPS React Server Components React2Shell Unsafe Flight Protocol Property Access (CVE-2025-55182)`

### Odd-Service: ICS Probing Campaign
- **source IPs**: `147.185.132.39` (89 events), `95.214.55.63` (885 events), `45.142.154.88` (85 events)
- **ASNs**: 396982 (US), 201814 (Poland), 9465 (Hong Kong)
- **target ports/services**: `10001/tcp`
- **paths/endpoints**: `N/A`
- **payload/artifact excerpts**: User Agent: `curl/7.68.0`. Log paths: `/data/conpot/log/conpot_guardian_ast.json`, `/data/conpot/log/conpot_kamstrup.json`
- **temporal checks**: `147.185.132.39` was active for < 2 minutes. `95.214.55.63` was active for ~4 hours.

## 11) Indicators of Interest
- **CVE**: `CVE-2025-55182`
- **Source IPs (React2Shell Campaign)**: `193.32.162.28`, `79.124.40.174`
- **Source IPs (ICS Probing)**: `147.185.132.39` (targeted), `95.214.55.63` (broad scanner)
- **Paths (React2Shell Indicators)**: `/_next/server`, `/api/route`
- **Port (ICS Indicator)**: `10001/tcp`
- **User Agent (ICS Indicator)**: `curl/7.68.0`
- **Credentials (Known Botnet)**: `345gs5662d34`, `3245gs5662d34`

## 12) Reflection Findings
- **What reflection candidates were discovered**: The initial investigation failed to analyze anomalous ICS activity on the Conpot honeypot, resulting in a "Partial" report with a critical visibility gap. This stalled investigation was selected as the reflection candidate.
- **Actions taken for reflection candidates**: A new deep investigation was launched. The agent used a broad keyword search (`discover_by_keyword`) to locate the data, successfully bypassing the incorrect field names that caused the initial failure. It then pivoted on the correct data type (`ConPot`) and the newly discovered source IPs to fully analyze the activity.
- **Findings of reflection candidates**: The investigation successfully characterized the ICS activity as uncoordinated reconnaissance from at least two distinct types of actors: a short-duration, highly-targeted scanner and a long-duration, broad-spectrum scanner. All source IPs, target ports, and behaviors were identified.
- **How reflection enhanced other findings**: The reflection directly resolved the "Partial" investigation status, turning it into a "Complete" one. It converted the "Odd-Service / Minutia Attacks" section from a provisional finding with Low confidence into a confirmed finding with High confidence, fully detailing the nature of the threat.

## 13) Backend Tool Issues
The initial investigation was hampered by query failures when trying to access Conpot honeypot data. The root cause was identified as a mismatch in the expected data structure: the honeypot type was indexed as `ConPot` (case-sensitive) instead of `Conpot`, and protocol information was not in a dedicated field. These issues were successfully bypassed in the reflection loop by using a broader keyword-based search tool (`discover_by_keyword`) to first locate the data and infer the correct structure.

## 14) Agent Action Summary (Audit Trail)
- **ParallelInvestigationAgent**:
    - **purpose**: Gather broad, concurrent telemetry streams.
    - **actions_taken**: Executed sub-agents for baseline, known signal, credential, and honeypot-specific data collection.
    - **key_results**: Provided initial data identifying VNC/SMB scanning, the emerging CVE-2025-55182, and anomalous ICS protocol events.
- **CandidateDiscoveryAgent**:
    - **purpose**: Synthesize initial telemetry into actionable investigation leads.
    - **actions_taken**: Formulated a 6-point investigation plan.
    - **key_results**: Prioritized PHPUnit, emerging CVEs, ICS activity, and unusual credentials for investigation.
- **CandidateValidationLoopAgent**:
    - **purpose**: Perform initial validation of a lead.
    - **actions_taken**: Ran for 1 iteration, validating the PHPUnit exploit candidate.
    - **key_results**: Confirmed PHPUnit activity was related to known vulnerability CVE-2017-9841.
- **DeepInvestigationLoopController**:
    - **purpose**: Conduct in-depth, iterative investigation of leads.
    - **actions_taken**: Ran for 5 iterations in the first loop, fully characterizing the CVE-2025-55182 campaign but stalling on the ICS lead. Ran for an additional 4 iterations during the reflection loop, successfully investigating the ICS activity.
    - **key_results**: Characterized two major campaigns (React2Shell and ICS Probing), identified multiple actor types, and resolved all initial unknowns.
- **OSINTAgent**:
    - **purpose**: Enrich findings with public threat intelligence.
    - **actions_taken**: Used search tool to research CVE-2017-9841, CVE-2025-55182, and the `345gs5662d34` credentials.
    - **key_results**: Confirmed all investigated items were publicly known, mapping them to established threats.
- **ReflectAgent**:
    - **purpose**: Review the investigation for gaps and trigger follow-up actions.
    - **actions_taken**: Identified the failed ICS investigation as a critical gap and generated a new `reflection_candidate` to re-investigate it.
    - **key_results**: Successfully initiated a second investigation loop that resolved the primary uncertainty from the first report.
- **ReportAgent**:
    - **purpose**: Compile the final report from all workflow state.
    - **actions_taken**: Assembled this markdown report, incorporating findings from both the initial and reflection-driven investigations.
    - **key_results**: The report you are reading.
- **SaveReportAgent**:
    - **purpose**: Persist the final report.
    - **actions_taken**: Will call `deep_agent_write_file`.
    - **key_results**: Pending.
