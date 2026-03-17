# Honeypot Threat Hunting Final Report

## 1) Investigation Scope
* **Investigation Start:** 2026-03-17T09:00:04Z
* **Investigation End:** 2026-03-17T12:00:04Z
* **Completion Status:** Complete
* **Degraded Mode:** False (Minor tool failure surmounted with workaround; see Backend Tool Issues)

## 2) Executive Triage Summary
* **Top Services/Ports of Interest:** Port 5900 (VNC), Port 6379 (Redis), Port 443 (Conpot proxy/ICS anomaly), and Next.js default ports (3000, 8080).
* **Top Confirmed Known Exploitation:** 
  * Massive VNC scanning (10,830 counts) mapped to standard enumeration.
  * Active exploitation of **CVE-2025-55182 (React2Shell)** via multiple distinct botnet nodes.
* **Top Unmapped Exploit-Like Items:** None found during this window.
* **Botnet/Campaign Mapping Highlights:** 
  * Targeted SSH brute-force campaigns specifically aiming at Solana validator nodes using tailored usernames (`sol`, `solana`, `solv`).
  * Continuous Redis RCE attempts (`MODULE LOAD /tmp/exp.so`) tied to known cryptojacking botnets (e.g., Muhstik, P2PInfect).
  * High-volume credential stuffing employing known Polycom CX600 IoT default passwords.

## 3) Candidate Discovery Summary
* **Total Attacks Analyzed:** 13,928
* **Findings:**
  * 1 Emerging n-day Exploitation candidate (CVE-2025-55182).
  * 3 Distinct botnet/campaign infrastructure clusters mapped.
  * 2 Odd-service / minutia attacks logged.
  * 1 Suspicious unmapped monitor item captured.
* **Missing Inputs / Errors:** The `top_src_ips_for_cve` pipeline tool failed to return aggregation buckets for CVE-2025-55182. This did not materially affect discovery as keyword searches successfully extracted the telemetry.

## 4) Emerging n-day Exploitation
**Candidate: [NDE-01] React2Shell RCE**
* **CVE / Signature Mapping:** CVE-2025-55182 (`ET WEB_SPECIFIC_APPS React Server Components React2Shell Unsafe Flight Protocol Property Access (CVE-2025-55182)`)
* **Evidence Summary:** 66 observed exploitation attempts via POST requests targeting Next.js/React paths: `/api/route`, `/app`, `/_next/server`, `/api`, `/_next`.
* **Affected Service/Port:** Widespread fan-out across multiple ports including Next.js typical ports (3000, 8080, 8002, 18080, 3010) and non-standard/ephemeral ports (45678, 4444, 4443, 13000, 5050, 8663, 55555, 9003, 2233).
* **Confidence:** High
* **Operational Notes:** Two distinct attack strategies observed from different nodes. IP `193.32.162.28` sprayed high random ports, whereas IP `95.214.55.63` aggressively targeted standard Web/Next.js default ports.

## 5) Novel or Zero-Day Exploit Candidates
*(No unmapped novel or zero-day candidates identified in this time window.)*

## 6) Botnet/Campaign Infrastructure Mapping
**[BOT-01] Solana Validator Cryptojacking Campaign**
* **Campaign Shape:** Spray
* **Suspected Compromised Src IPs:** 195.178.110.218, 2.57.122.238, 2.57.122.208, 2.57.122.96 (49 total attempts)
* **ASNs / Geo Hints:** ASN 47890 (Unmanaged Ltd)
* **Suspected Staging:** Unknown
* **Suspected C2:** Unknown
* **Confidence:** High
* **Operational Notes:** Public threat intelligence strongly maps this targeted SSH credential attack (`sol`, `solana`, `solv`) to cryptomining botnets targeting vulnerable blockchain PoS nodes.

**[BOT-02] Redis Botnet (Muhstik / P2PInfect / h2Miner)**
* **Campaign Shape:** Unknown
* **Suspected Compromised Src IPs:** Not directly pivoted.
* **ASNs / Geo Hints:** N/A
* **Suspected Staging:** Rogue Master replication leveraging `/tmp/exp.so`
* **Suspected C2:** Unknown
* **Confidence:** High
* **Operational Notes:** Standardized exploitation sequence involving `SLAVEOF NO ONE` and `MODULE LOAD /tmp/exp.so`. Ensure Redis clusters are isolated from the public internet.

**[BOT-03] IoT Botnet (Polycom CX600 Credentials)**
* **Campaign Shape:** Spray
* **Suspected Compromised Src IPs:** 103.59.94.61, 154.117.199.56, 187.107.88.97, 187.16.96.250, 187.212.42.32
* **ASNs / Geo Hints:** Distributed
* **Suspected Staging:** Unknown
* **Suspected C2:** Unknown
* **Confidence:** High
* **Operational Notes:** SSH dictionary attack using the string `345gs5662d34`, a well-known default credential for Polycom IP phones reused as a botnet signature.

## 7) Odd-Service / Minutia Attacks
**[ODD-01] Proxy/CONNECT over ICS**
* **Service Fingerprint:** Port 443 / Kamstrup Management Protocol / Guardian AST
* **Why it’s unusual:** The Conpot ICS honeypot received standard HTTP CONNECT proxy requests to `www.google.com` wrapped inside Kamstrup and Guardian AST interactions.
* **Evidence Summary:** 6 `CONNECT` requests with Mozilla Chrome User-Agents.
* **Confidence:** Moderate
* **Recommended Monitoring:** Likely generic open-proxy misconfiguration scanning hitting ICS ports. Monitor for scanner script errors revealing attacker backend infrastructure.

**[MIN-01] Non-standard Regional Scanning**
* **Service Fingerprint:** Ports 3025, 3518, 3563 (Russia), 3312, 3352 (Ukraine), 2233, 4443 (Romania)
* **Why it’s unusual:** Low-volume connection attempts on obscure ephemeral ports grouped strongly by geography.
* **Evidence Summary:** Handful of connections per port.
* **Confidence:** Low
* **Recommended Monitoring:** Observe if counts climb; could represent botnet peer discovery or unmapped P2P staging channels.

**[MON-01] Suspicious Unmapped Monitor**
* **Service Fingerprint:** HTTP / Tanner
* **Why it’s unusual:** Anomalous query parameter `/?%3Cplay%3Ewithme%3C/%3E`
* **Evidence Summary:** Web request from IP 136.144.35.124. 
* **Confidence:** Moderate
* **Recommended Monitoring:** OSINT mapping is inconclusive. Monitor IP and payload as a generic WAF/XSS probe or scanner fingerprint.

## 8) Known-Exploit / Commodity Exclusions
* **VNC Mass Scanning:** Extremely high-volume VNC enumeration (ports 5900, 5901-5903) tied to standard tools (GPL INFO VNC server response).
* **Spring Boot Actuator Scanning:** Broad requests to `/actuator/gateway/routes` representing commodity Java exploitation.
* **Proxy/CONNECT Scanning:** HTTP CONNECT requests mapped directly to proxy capability verification.
* **Commodity SSH Brute Forcing:** High volume of SSH attempts utilizing basic credentials (`root`, `admin`, `user`, `123456`).

## 9) Infrastructure & Behavioral Classification
* **Exploitation vs Scanning:** Exploitation was surgically focused on Redis RCE and React2Shell. High-volume traffic was predominantly blind VNC and SSH scanning.
* **Campaign Shape:** React2Shell campaigns displayed robust fan-out application scanning. SSH botnets demonstrated distributed spraying using specific botnet dictionaries.
* **Infra Reuse Indicators:** ASN 47890 (Unmanaged Ltd) acted as a major source for both React2Shell exploitation and targeted Solana validator SSH campaigns.
* **Odd-Service Fingerprints:** Obscured HTTP payload drops against ICS protocols indicating primitive or broken scanner logic.

## 10) Evidence Appendix
**[NDE-01] React2Shell RCE Evidence**
* **Source IPs:** 193.32.162.28 (444 events), 95.214.55.63 (117 events)
* **ASNs:** 47890 (Unmanaged Ltd - RO), 201814 (MEVSPACE sp. z o.o. - PL)
* **Target Ports:** 45678, 4444, 4443, 13000, 5050, 8663, 55555, 9003, 2233, 8899, 7001, 8800, 3000, 8080
* **Target Paths:** `/api/route`, `/app`, `/_next/server`, `/api`, `/_next`
* **Temporal Checks:** Continuous scanning over a 3-hour window.

**[BOT-01] Solana Validator Campaign Evidence**
* **Source IPs:** 195.178.110.218 (26 counts), 2.57.122.238 (9 counts), 2.57.122.208 (6 counts), 2.57.122.96 (5 counts)
* **Target Ports:** 22 (SSH)
* **Usernames:** `sol`, `solana`, `solv`

**[BOT-02] Redis Botnet Evidence**
* **Target Ports:** 6379 (Redis)
* **Payload Excerpts:** `MODULE LOAD /tmp/exp.so`, `CONFIG SET dbfilename exp.so`, `SLAVEOF NO ONE`

## 11) Indicators of Interest
* **React2Shell Scanner IPs:** `193.32.162.28`, `95.214.55.63`
* **Solana Brute Force Clusters:** `195.178.110.218`, `2.57.122.238`, `2.57.122.208`, `2.57.122.96`
* **IoT/Polycom Brute Force Marker:** Credential `345gs5662d34`
* **Suspicious Payload:** `/?%3Cplay%3Ewithme%3C/%3E` (IP: `136.144.35.124`)

## 12) Backend Tool Issues
* **Failed Queries:** Tool `top_src_ips_for_cve` failed to fetch results for CVE-2025-55182.
* **Affected Validations:** Did not degrade final conclusions. Discovery Agent bypassed via `discover_by_keyword` resolving the evidence block.

## 13) Agent Action Summary (Audit Trail)
* **ParallelInvestigationAgent:** 
  * *Purpose:* Broadly triage honeypot telemetry. 
  * *Inputs Used:* Baseline, known signals, credential noise, and honeypot-specific time windows.
  * *Actions Taken:* Aggregated total attacks, IPs, CVEs, credentials, and app-layer payloads.
  * *Key Results:* Established 13,928 events and sourced React, Redis, and SSH indicators.
  * *Errors/Gaps:* None.
* **CandidateDiscoveryAgent:**
  * *Purpose:* Identify threat candidates from baseline.
  * *Inputs Used:* Triage summaries.
  * *Actions Taken:* Correlated IPs, parsed keywords, requested OSINT contexts.
  * *Key Results:* Generated 7 candidates encompassing botnets, CVEs, and anomalies.
  * *Errors/Gaps:* Noted `top_src_ips_for_cve` bucket error.
* **CandidateValidationLoopAgent:**
  * *Purpose:* Temporally and contextually validate candidates.
  * *Inputs Used:* NDE-01 Candidate logic.
  * *Actions Taken:* Queried IP flows and first/last seen data for `193.32.162.28`.
  * *Key Results:* 1 candidate validated (React2Shell). Iteration 1 concluded successfully.
  * *Errors/Gaps:* None.
* **DeepInvestigationLoopController:**
  * *Purpose:* Infrastructure pivoting and clustering.
  * *Inputs Used:* URL pathways and IP contexts.
  * *Actions Taken:* Pivoted on `/_next/server` generating new leads. Evaluated secondary IP `95.214.55.63`.
  * *Key Results:* Discovered distinct port-targeting methodologies across multiple IPs representing a fan-out campaign. Exited cleanly after 2 iterations.
  * *Errors/Gaps:* None.
* **OSINTAgent:**
  * *Purpose:* Enrich artifacts via external threat intelligence.
  * *Inputs Used:* Botnet payloads, usernames.
  * *Actions Taken:* Searched standard IOCs and strings.
  * *Key Results:* Mapped `sol` dictionary to Solana nodes; `/tmp/exp.so` to Muhstik/P2PInfect; `345gs5662d34` to Polycom CX600 defaults.
  * *Errors/Gaps:* None.
* **ReportAgent:**
  * *Purpose:* Compile intelligence summary.
  * *Inputs Used:* Complete workflow state.
  * *Actions Taken:* Collated final evidence into standardized markdown report.
  * *Key Results:* Complete report generated.
  * *Errors/Gaps:* None.
* **SaveReportAgent:**
  * *Purpose:* Persist intelligence document to disk.
  * *Inputs Used:* Markdown text.
  * *Actions Taken:* Executed `deep_agent_write_file` tool.
  * *Key Results:* Report saved.
  * *Errors/Gaps:* None.