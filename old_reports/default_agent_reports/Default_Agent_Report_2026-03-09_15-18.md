# Honeypot Threat Hunt - Final Report

## 1) Investigation Scope
- **investigation_start:** 2026-03-09T15:00:10Z
- **investigation_end:** 2026-03-09T18:00:10Z
- **completion_status:** Partial (degraded evidence)
- **degraded_mode:** true - Key queries failed during both discovery and validation, preventing full analysis of some activity.

## 2) Executive Triage Summary
- **Top Services/Ports of Interest:** VNC (multiple ports), SSH (22), RDP (non-standard ports), HTTP (80, 8000, 8001, 8002), and unusual activity on Redis (6379), ADB, and Conpot (Kamstrup protocol).
- **Top Confirmed Known Exploitation:** Activity matching CVE-2025-55182 (Critical RCE in React Server Components) was observed 99 times from a single source IP.
- **Top Unmapped Exploit-Like Items:** No high-confidence novel exploit candidates were validated. Initial "suspicious" items were re-classified as known scanning (Redis) or require further investigation (Kamstrup).
- **Botnet/Campaign Mapping Highlights:**
    - A widespread spray campaign was identified scanning for sensitive configuration files (`/.env`, `/.git/config`).
    - A credential-stuffing campaign was identified using the specific, non-standard username `345gs5662d34` from dozens of IPs.
- **Major Uncertainties:** A series of tool failures prevented the retrieval of source IPs and event details for 6 events involving the Kamstrup ICS protocol, making a full assessment of that activity impossible.

## 3) Candidate Discovery Summary
- The discovery phase identified several areas of interest by correlating baseline data, known signals, and honeypot-specific logs.
- **Emerging N-Day:** 99 events matching the signature for CVE-2025-55182 were flagged.
- **Botnet/Campaigns:** Two distinct campaigns were identified based on coordinated scanning for sensitive files and the use of a unique credential pair.
- **Odd-Service/Minutia:** Unusual activity was flagged on Conpot (Kamstrup protocol) and Redis (a binary command).
- **Discovery Gaps:** The initial discovery phase suffered from failed queries for source IPs related to the CVE and Conpot events, requiring the validation phase to perform redundant searches.

## 4) Emerging n-day Exploitation
**Item: CVE-2025-55182-RCE**
- **cve/signature mapping:** CVE-2025-55182, `ET WEB_SPECIFIC_APPS React Server Components React2Shell Unsafe Flight Protocol Property Access (CVE-2025-55182)`
- **evidence summary:** 99 alert events were triggered by a single source IP (`193.32.162.28`) across multiple destination ports. The attacker was also seen generating alerts for Javascript Prototype Pollution, a related technique.
- **affected service/port:** Next.js/React applications on ports 9898, 4321, 4430, 6007.
- **confidence:** High
- **operational notes:** This is active exploitation of a known, critical RCE. The source IP `193.32.162.28` should be considered malicious and blocked.

## 5) Novel or Zero-Day Exploit Candidates
No candidates were validated as novel or potential zero-day exploits in this window.

## 6) Botnet/Campaign Infrastructure Mapping
**Item: ENV-GIT-SPRAY-01**
- **item_id:** ENV-GIT-SPRAY-01
- **campaign_shape:** spray
- **suspected_compromised_src_ips:** 136.116.202.5, 94.26.88.31, 24.144.94.222, 34.78.178.202 (and others).
- **ASNs / geo hints:** Various.
- **suspected_staging indicators:** Payloads targeting web server root directories.
- **suspected_c2 indicators:** None.
- **confidence:** High
- **operational notes:** This is a coordinated, automated campaign searching for exposed sensitive configuration files. The IP `136.116.202.5` was particularly active, attempting to access multiple `.env` file variations.

**Item: CRED-STUFF-345gs5662d34**
- **item_id:** CRED-STUFF-345gs5662d34
- **campaign_shape:** spray
- **suspected_compromised_src_ips:** 114.34.106.146, 177.36.214.46, 103.164.221.138, 170.64.236.145, 118.194.230.250 (and others).
- **ASNs / geo hints:** Widely distributed across Taiwan, Brazil, Indonesia, Australia, Japan, etc.
- **suspected_staging indicators:** Use of a shared, unique username/password combo.
- **suspected_c2 indicators:** None.
- **confidence:** High
- **operational notes:** The use of the unique, non-standard username `345gs5662d34` across many disparate IPs indicates a specific, coordinated credential stuffing campaign. This username is a high-fidelity indicator of this campaign.

## 7) Odd-Service / Minutia Attacks
**Item: KAMSTRUP-CONPOT-01 (Provisional)**
- **service_fingerprint:** Conpot honeypot / `kamstrup_protocol`
- **why it’s unusual/interesting:** Kamstrup is a protocol used in Industrial Control Systems (ICS) for smart metering, which is not a commonly scanned internet protocol.
- **evidence summary:** 6 events were logged by the Honeypot-Specific agent, but all subsequent attempts to query and validate these events failed. The source IPs and nature of the interaction are unknown.
- **confidence:** Low
- **recommended monitoring pivots:** Manual investigation is required to find the missing Conpot logs. Pivots are blocked until source IPs can be identified.

**Item: REDIS-BINARY-CMD-01 (Re-classified as Scanner)**
- **service_fingerprint:** Redis (port 6379) receiving a TLS handshake.
- **why it’s unusual/interesting:** This was initially flagged as a suspicious binary command sent to Redis. Validation revealed it to be a TLS Client Hello packet.
- **evidence summary:** One source IP, `143.244.151.6`, sent a TLS handshake to the non-TLS Redis port. This is a common technique used by internet scanners to fingerprint services.
- **confidence:** High
- **recommended monitoring pivots:** The behavior itself is benign scanning. The source IP can be monitored for other, more malicious activity.

## 8) Known-Exploit / Commodity Exclusions
- **Credential Noise:** High volume of login attempts using common usernames (`root`, `admin`, `user`, `postgres`) and passwords (`123456`, `password`, `12345`).
- **VNC Scanning:** 21,129 events for `GPL INFO VNC server response`, indicating widespread, low-sophistication scanning for open VNC servers.
- **RDP Scanning:** 809 events for `ET SCAN MS Terminal Server Traffic on Non-standard Port`, indicating scanning for exposed RDP services.

## 9) Infrastructure & Behavioral Classification
- **Exploitation vs Scanning:** The investigation identified one clear case of active exploitation (CVE-2025-55182). The remaining majority of traffic was classified as scanning (VNC, RDP, .env files) or reconnaissance (Kamstrup, Redis-TLS).
- **Campaign Shape:** A `fan-out` pattern was observed for the CVE exploitation from a single IP to multiple ports. A `spray` pattern was seen for the configuration file scanning and credential stuffing campaigns.
- **Odd-Service Fingerprints:** The detection of the `kamstrup_protocol` (ICS) and unexpected TLS handshakes on the Redis port were the primary odd-service findings.

## 10) Evidence Appendix
**Emerging N-day: CVE-2025-55182-RCE**
- **Source IPs:** 193.32.162.28 (1563 total events, 99 CVE alerts)
- **ASNs:** 47890 (Unmanaged Ltd)
- **Target Ports:** 9898, 4321, 4430, 6007
- **Paths/Endpoints:** `/api/route`, `/_next/server`, `/app`, `/api`, `/_next`, `/`
- **Payload/Artifact Excerpts:** Suricata Signature: `ET WEB_SPECIFIC_APPS React Server Components React2Shell Unsafe Flight Protocol Property Access (CVE-2025-55182)`

**Botnet Mapping: ENV-GIT-SPRAY-01**
- **Source IPs (sample):** 136.116.202.5, 94.26.88.31, 172.236.179.87, 34.158.79.105
- **Target Ports:** Assumed HTTP/S (80/443).
- **Paths/Endpoints:** `/.git/config`, `/.env`, `/.env.bak`, `/.env.dev`, `/.env.development`

**Botnet Mapping: CRED-STUFF-345gs5662d34**
- **Source IPs (sample):** 114.34.106.146, 177.36.214.46, 103.164.221.138, 170.64.236.145, 118.194.230.250, 202.188.47.41
- **Target Ports:** Assumed SSH (22).
- **Payload/Artifact Excerpts:** `username: 345gs5662d34`, `password: 345gs5662d34`

## 11) Indicators of Interest
- **IP (Exploitation):** `193.32.162.28` (Exploiting CVE-2025-55182)
- **IPs (Scanning):** `136.116.202.5`, `94.26.88.31` (High-volume `.env`/`.git` scanners)
- **Paths:** `/.git/config`, `/.env`
- **Username:** `345gs5662d34`
- **CVE:** `CVE-2025-55182`

## 12) Backend Tool Issues
- **`top_src_ips_for_cve`:** This tool failed during the Candidate Discovery phase, returning no results for CVE-2025-55182 despite 99 events being present. This weakened the initial discovery.
- **`two_level_terms_aggregated`:** This tool also failed during discovery when attempting to find source IPs for Conpot events.
- **`kibanna_discover_query`:** This tool failed during the Candidate Validation phase to retrieve any of the 6 Conpot/Kamstrup events, blocking validation for that candidate and forcing it into a `Provisional` state. This indicates a potential data indexing or query syntax issue with the underlying data store for Conpot events.

## 13) Agent Action Summary (Audit Trail)
- **agent_name:** ParallelInvestigationAgent
- **purpose:** Gathers broad baseline, signal, credential, and honeypot data.
- **inputs_used:** Time window.
- **actions_taken:** Executed multiple parallel queries across different data sources (total attacks, top countries, top signatures, CVEs, usernames, honeypot interactions).
- **key_results:** Provided the foundational data for the investigation, totaling over 20,000 attacks and identifying key signatures like VNC scanning and CVE-2025-55182.
- **errors_or_gaps:** None.

- **agent_name:** CandidateDiscoveryAgent
- **purpose:** Analyzes initial data to identify and prioritize potential threats (candidates).
- **inputs_used:** All outputs from ParallelInvestigationAgent.
- **actions_taken:** Aggregated data, searched for CVE details, and correlated honeypot data to generate candidates.
- **key_results:** Identified 3 main candidates for validation: an emerging n-day (CVE-2025-55182), an odd ICS protocol (Kamstrup), and a suspicious Redis command. Also identified two botnet campaigns.
- **errors_or_gaps:** Multiple tool queries failed to return source IPs for CVE and Conpot events, marking the workflow as degraded.

- **agent_name:** CandidateValidationLoopAgent
- **purpose:** Orchestrates the detailed, iterative validation of each candidate.
- **inputs_used:** Candidate list from CandidateDiscoveryAgent.
- **actions_taken:** Successfully queued 3 candidates and looped through them, calling the validation agent for each one.
- **key_results:** All 3 candidates were processed through the validation loop.
- **errors_or_gaps:** None.

- **agent_name:** OSINTAgent
- **purpose:** Enriches validated findings with public, open-source intelligence.
- **inputs_used:** Validated candidate data.
- **actions_taken:** Performed web searches for key terms related to the validated candidates (CVE-2025-55182, Kamstrup protocol, Redis TLS scanning).
- **key_results:** Confirmed CVE-2025-55182 is a known exploited vulnerability. Re-classified the "binary" Redis command as a common TLS scanning technique. Confirmed Kamstrup is a legitimate ICS protocol emulated by Conpot.
- **errors_or_gaps:** None.

- **agent_name:** ReportAgent
- **purpose:** Compiles the final report from all available workflow state.
- **inputs_used:** All outputs from previous agents.
- **actions_taken:** Assembled this markdown report.
- **key_results:** This report.
- **errors_or_gaps:** None.

- **agent_name:** SaveReportAgent
- **purpose:** Writes the final report content to a file.
- **inputs_used:** The generated markdown from ReportAgent.
- **actions_taken:** Called the `default_write_file` tool.
- **key_results:** File write status.
- **errors_or_gaps:** None.
