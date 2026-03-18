# Honeypot Threat Hunt Final Report

### 1) Investigation Scope
- **investigation_start:** 2026-03-13T04:00:07Z
- **investigation_end:** 2026-03-13T08:00:07Z
- **completion_status:** Partial (degraded evidence)
- **degraded_mode:** true. Key evidence retrieval queries (`kibanna_discover_query`, `two_level_terms_aggregated`) failed for multiple candidates, preventing full analysis of source IPs for CVE-2025-55182 and blocking any investigation into the source of observed ICS protocol activity.

### 2) Executive Triage Summary
- **Top Services/Ports of Interest:** The most significant activity centered on Port 5900 (VNC), which received over 25,000 events, primarily from a single source IP. Port 445 (SMB) also saw significant scanning traffic.
- **Top Confirmed Known Exploitation:** Widespread exploitation attempts for **CVE-2025-55182 (React2Shell)** were observed, confirmed by Suricata signatures. Additionally, known RCE attempts targeting the **ThinkPHP framework (CVE-2018-20062 / CVE-2019-9082)** were identified.
- **Unmapped Exploit-like Items:** No unmapped or novel exploit candidates were validated. The initial candidate (`NOV-01`) was reclassified as a known ThinkPHP exploit campaign.
- **Botnet/Campaign Mapping Highlights:** A high-volume VNC scanning campaign was mapped to the source IP **185.231.33.22**, originating from AS211720 (Datashield, Inc.) in Seychelles. This IP was responsible for over 25,000 events.
- **Odd-Service / Minutia Attacks:** Activity involving Industrial Control System (ICS) protocols (**guardian_ast, IEC104, kamstrup_protocol**) was observed in the Conpot honeypot. This suggests potential reconnaissance against energy or utility infrastructure.
- **Major Uncertainties:** The investigation into the ICS activity (`ODD-01`) is **provisional and inconclusive** due to backend query failures that prevented the retrieval of source IPs or event payloads. The full scope of the CVE-2025-55182 campaign could not be determined for the same reason.

### 3) Candidate Discovery Summary
- **Total Candidates Identified:** 5
- **Top Areas of Interest:**
    - Emerging n-day exploitation targeting CVE-2025-55182 (React2Shell).
    - A high-volume VNC scanning campaign dominating the traffic window.
    - A potential novel RCE (later identified as known ThinkPHP exploit).
    - Unusual ICS protocol monitoring.
- **Material Gaps:** The discovery phase was impacted by the failure of `kibanna_discover_query` to retrieve raw honeypot logs for a suspicious Tanner path, requiring further validation steps to identify the activity.

### 4) Emerging n-day Exploitation
- **CVE/Signature Mapping:** CVE-2025-55182 (React2Shell) / ET WEB_SPECIFIC_APPS React Server Components React2Shell Unsafe Flight Protocol Property Access (CVE-2025-55182)
- **Evidence Summary:**
    - **Counts:** 103 Suricata alerts
    - **Key Artifacts:** Exploitation attempts targeting HTTP endpoints such as `/api/route`, `/_next/server`, and `/app`.
- **Affected Service/Port:** HTTP (80, 443), also seen on non-standard ports (445, 8300, 9961).
- **Confidence:** High
- **Operational Notes:** This is a known critical RCE with widespread, active exploitation. All potentially vulnerable systems should be patched immediately. Source IPs `193.32.162.28` and `95.214.55.63` should be added to a blocklist.

### 5) Novel or Zero-Day Exploit Candidates (UNMAPPED ONLY, ranked)
*No validated novel or zero-day exploit candidates were identified in this window. The initial candidate, NOV-01, was re-classified as a known exploit campaign during validation.*

### 6) Botnet/Campaign Infrastructure Mapping

**Item ID: BOT-01 (VNC Scanning Campaign)**
- **Campaign Shape:** spray
- **Suspected Compromised Source IPs:** `185.231.33.22` (25,202 events), `150.241.230.75` (10 events), `87.121.84.67` (1 event).
- **ASNs/Geo Hints:** AS211720 (Datashield, Inc.), Seychelles.
- **Suspected Staging/C2 Indicators:** None observed; appears to be direct scanning.
- **Confidence:** High
- **Operational Notes:** This is a high-volume, low-sophistication scanning campaign. The primary IP `185.231.33.22` is a known bad actor and should be blocked.

**Item ID: NOV-01 (ThinkPHP RCE Campaign)**
- **Related Candidate ID(s):** NOV-01
- **Campaign Shape:** unknown
- **Suspected Compromised Source IPs:** `101.36.107.228` (2 events)
- **ASNs/Geo Hints:** Unavailable.
- **Suspected Staging/C2 Indicators:** None observed.
- **Confidence:** High
- **Operational Notes:** This activity represents exploitation attempts of known ThinkPHP RCE vulnerabilities (CVE-2018-20062 / CVE-2019-9082). While low volume in this window, it confirms active scanning for this vulnerability. Ensure WAF rules are in place to block these exploit patterns.

### 7) Odd-Service / Minutia Attacks
- **Service Fingerprint:** `guardian_ast`, `IEC104`, `kamstrup_protocol` (ICS/SCADA)
- **Why it’s unusual/interesting:** These are specialized protocols for Industrial Control Systems, specifically related to fuel tank monitoring (guardian_ast) and power grid/utility management (IEC104, Kamstrup). Unsolicited traffic on these protocols is a strong indicator of reconnaissance targeting critical infrastructure.
- **Evidence Summary:**
    - **Counts:** 27 events logged by the Conpot honeypot.
    - **Key Artifacts:** Protocol names are the only available data.
- **Confidence:** Low (Provisional)
- **Recommended Monitoring Pivots:** Investigation is blocked pending fixes to the Conpot data pipeline. Once data is available, analysis of source IPs, geolocations, and payloads is required to determine intent.

### 8) Known-Exploit / Commodity Exclusions
- **Commodity Scanning (SMB):** High-volume scanning on port 445 (SMB) from `45.95.214.24` (1,546 events). Validated as simple TCP flows with no exploit signatures. (Item ID: KEX-01)
- **Credential Noise:** Standard brute-force attempts observed across SSH and other services, using common usernames (`root`, `admin`, `ubuntu`) and passwords (`123456`, `password`).
- **Known Scanners:** Activity associated with signatures like `ET SCAN MS Terminal Server Traffic on Non-standard Port` and `ET SCAN NMAP -sS window 1024` was observed from multiple sources.

### 9) Infrastructure & Behavioral Classification
- **Exploitation vs Scanning:** Both were observed. The VNC and SMB activity was classified as scanning. The React2Shell and ThinkPHP activity was classified as active exploitation.
- **Campaign Shape:** The VNC campaign (`BOT-01`) was a clear "spray" from a single dominant source. Other campaigns were too low-volume to determine a shape.
- **Infra Reuse Indicators:** The IP `185.231.33.22` is a known scanner per public threat intelligence, indicating infrastructure reuse for scanning campaigns.
- **Odd-Service Fingerprints:** The Conpot honeypot detected ICS/SCADA protocols, suggesting targeted reconnaissance of OT networks.

### 10) Evidence Appendix

**NDE-01: Emerging n-day (CVE-2025-55182)**
- **Source IPs:** `193.32.162.28`, `95.214.55.63`
- **ASNs:** Unavailable due to query failure.
- **Target Ports/Services:** 80, 443, 445, 8300, 9961 (HTTP)
- **Paths/Endpoints:** `/api/route`, `/app`, `/_next/server`, `/api`, `/_next`, `/`
- **Payload/Artifact Excerpts:** Suricata Signature: `ET WEB_SPECIFIC_APPS React Server Components React2Shell Unsafe Flight Protocol Property Access (CVE-2025-55182)`
- **Temporal Checks:** Unavailable.

**BOT-01: Botnet Mapping (VNC Scanning)**
- **Source IPs:** `185.231.33.22` (25,202), `150.241.230.75` (10), `87.121.84.67` (1)
- **ASNs:** 211720 (Datashield, Inc.)
- **Target Ports/Services:** 5900 (VNC)
- **Payload/Artifact Excerpts:** Suricata Signature: `GPL INFO VNC server response`
- **Temporal Checks:** Consistent high-volume activity throughout the window.

**NOV-01: Known Campaign (ThinkPHP RCE)**
- **Source IPs:** `101.36.107.228`
- **ASNs:** Unavailable.
- **Target Ports/Services:** 80 (HTTP)
- **Paths/Endpoints:** `/?s=/Index/\think\app/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]=printenv`
- **Payload/Artifact Excerpts:** Suricata Signature: `ET WEB_SERVER ThinkPHP RCE Exploitation Attempt`
- **Temporal Checks:** Unavailable.

### 11) Indicators of Interest
- **IPs:**
    - `185.231.33.22` (High-volume VNC scanner)
    - `45.95.214.24` (SMB scanner)
    - `193.32.162.28` (CVE-2025-55182 exploitation)
    - `95.214.55.63` (CVE-2025-55182 exploitation)
    - `101.36.107.228` (ThinkPHP RCE exploitation)
- **CVEs:**
    - `CVE-2025-55182` (React2Shell)
    - `CVE-2018-20062` / `CVE-2019-9082` (ThinkPHP RCE)
- **Paths/Payloads:**
    - `/?s=/Index/\think\app/invokefunction&function=call_user_func_array&vars[0]=system...`

### 12) Backend Tool Issues
- **`kibanna_discover_query`:** This tool failed repeatedly when attempting to retrieve raw logs for Tanner and Conpot honeypots.
    - **Affected Validations:** Blocked retrieval of source IPs and payload details for the ThinkPHP candidate (`NOV-01`). Critically, it prevented *any* analysis of the source or nature of the ICS activity (`ODD-01`), rendering that finding provisional.
- **`two_level_terms_aggregated`:** This tool failed to aggregate source IPs for Suricata signatures and CVEs.
    - **Affected Validations:** Blocked the ability to map the full set of source IPs involved in the CVE-2025-55182 campaign (`NDE-01`), limiting infrastructure analysis.

### 13) Agent Action Summary (Audit Trail)

- **Agent Name:** ParallelInvestigationAgent
- **Purpose:** Executes initial broad data collection from different perspectives.
- **Inputs Used:** `investigation_start`, `investigation_end`.
- **Actions Taken:** Ran sub-agents (Baseline, KnownSignal, CredentialNoise, HoneypotSpecific) to query for total attacks, top IPs/ports, known signatures, CVEs, honeypot-specific interactions, and credential stuffing attempts.
- **Key Results:** Produced baseline statistics (49,919 attacks), identified VNC scanning as the top signal, flagged CVE-2025-55182, and noted unusual ICS protocols in Conpot.
- **Errors/Gaps:** None.

- **Agent Name:** CandidateDiscoveryAgent
- **Purpose:** Synthesizes parallel findings to identify and prioritize leads for validation.
- **Inputs Used:** `baseline_result`, `known_signals_result`, `credential_noise_result`, `honeypot_specific_result`.
- **Actions Taken:** Correlated high-volume traffic, CVEs, and honeypot logs to create 5 distinct candidates for investigation (`NDE-01`, `KEX-01`, `BOT-01`, `NOV-01`, `ODD-01`).
- **Key Results:** Generated a structured list of 5 candidates, including one emerging n-day, one botnet, one potential novel exploit, one odd service, and one known exclusion.
- **Errors/Gaps:** `kibanna_discover_query` failed during discovery, marking the `NOV-01` candidate as provisional from the start.

- **Agent Name:** CandidateValidationLoopAgent
- **Purpose:** Iteratively validates each discovered candidate to confirm or deny the initial hypothesis.
- **Inputs Used:** `candidate_discovery_result`.
- **Actions Taken:** Ran 5 validation iterations, one for each candidate. Performed OSINT searches, queried for event samples, and attempted infrastructure pivots.
- **Key Results:**
    - Confirmed `NDE-01` as CVE-2025-55182 exploitation.
    - Confirmed `KEX-01` and `BOT-01` as commodity scanning.
    - **Reclassified `NOV-01`** from "novel exploit" to "known exploit campaign" (ThinkPHP) based on OSINT and Suricata signature findings.
    - Confirmed `ODD-01` involved ICS protocols but could not investigate further.
- **Errors/Gaps:** Multiple `kibanna_discover_query` and `two_level_terms_aggregated` failures blocked the full analysis of `NDE-01` and `ODD-01`.

- **Agent Name:** DeepInvestigationLoopController
- **Purpose:** To perform deep, multi-step investigations on high-priority validated leads.
- **Inputs Used:** Not triggered in this workflow.
- **Actions Taken:** None.
- **Key Results:** None.
- **Errors/Gaps:** Not applicable.

- **Agent Name:** OSINTAgent
- **Purpose:** Enriches validated candidates with public threat intelligence.
- **Inputs Used:** `validated_candidates`.
- **Actions Taken:** Performed web searches for artifacts related to candidates `NOV-01`, `BOT-01`, `ODD-01`, and `NDE-01`.
- **Key Results:**
    - Confirmed `NOV-01` (ThinkPHP) is a well-known RCE.
    - Confirmed `BOT-01` IP is a publicly reported scanner.
    - Provided context on the ICS protocols for `ODD-01`.
    - Confirmed `NDE-01` (CVE-2025-55182) is a recent, widely exploited vulnerability.
- **Errors/Gaps:** An initial search for "guardian_ast protocol" failed, requiring a pivot to other protocols.

- **Agent Name:** ReportAgent
- **Purpose:** Compiles the final report from all workflow state outputs.
- **Inputs Used:** All preceding agent outputs.
- **Actions Taken:** Assembled this markdown report.
- **Key Results:** The report you are reading.
- **Errors/Gaps:** None.