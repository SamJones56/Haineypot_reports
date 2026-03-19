# Honeypot Threat Hunting Final Report

## 1) Investigation Scope
- **Investigation Start:** 2026-03-19T09:00:07Z
- **Investigation End:** 2026-03-19T12:00:07Z
- **Completion Status:** Partial (degraded evidence)
- **Degraded Mode:** True. The initial candidate validation and deep investigation loops exited prematurely after processing the first candidate ([NDE-01]). A subsequent reflection loop attempted to recover the 5 unvalidated candidates but only completed analysis for one ([REF-01] / [BOT-01]). The remaining 4 candidates lack deep pivots, OSINT validation, and temporal checks.

## 2) Executive Triage Summary
- **Top Services & Ports:** SMB (445), VNC (5902, 5903), SSH (22), Redis (6379), ICS/Guardian AST (10001), React Web Apps (3000-3012, 4020, 6006, 8080).
- **Top Confirmed Known Exploitation:** 259 initial alerts linked to active CVE-2025-55182 (React2Shell) exploitation targeting React/Next.js frameworks via prototype pollution.
- **Top Unmapped Exploit-like Items:** None strongly verified in this window.
- **Botnet / Campaign Highlights:** Broad SSH/Telnet brute-forcing utilizing a unique string dictionary (`345gs5662d34`), and isolated fan-out scanning for Spring Boot Actuator and PHPStorm.
- **Odd Services / Minutia:** Captured explicit interaction payloads against ConPot ICS environments (port 10001) and target-aware Redis honeypot command injections utilizing the string `MGLNDD`.
- **Major Uncertainties:** Because 4 of the 6 candidates generated during discovery were bypassed by both the primary and reflection validation loops, their corresponding findings remain strictly provisional.

## 3) Candidate Discovery Summary
- **Total Candidates Generated:** 6
  - 1 Emerging n-day ([NDE-01])
  - 2 Botnet campaigns ([BOT-01], [BOT-02])
  - 2 Odd-Service/Minutia ([ODD-01], [MIN-01])
  - 1 Suspicious Unmapped Monitor ([MON-01])
- **Missing Inputs/Errors:** Due to upstream backend loop exit errors, candidates `[BOT-02]`, `[ODD-01]`, `[MIN-01]`, and `[MON-01]` skipped all validation and deep context gathering. 

## 4) Emerging n-day Exploitation
### [NDE-01] React2Shell (CVE-2025-55182) Exploitation
- **CVE / Signature Mapping:** CVE-2025-55182 / ET WEB_SPECIFIC_APPS React Server Components React2Shell Unsafe Flight Protocol Property Access. The exploit correlates directly with `ET HUNTING Javascript Prototype Pollution Attempt via __proto__ in HTTP Body`.
- **Evidence Summary:** 259 initial alerts logged. Deep investigation exposed over 1,500 targeted HTTP POST requests leveraging prototype pollution mechanisms in the React Flight Protocol.
- **Affected Service/Port:** React/Next.js Web Applications. Ports 80, 443, 3000-3012, 4020, 6006, 8080, 9063.
- **Confidence:** High
- **Operational Notes:** Active exploitation demonstrates distinct tactics. Node `129.212.239.91` uses `Go-http-client/1.1` to aggressively spray the root path `/` across many ports. Node `193.32.162.28` actively spoofs randomized end-user User-Agents and explicitly targets Next.js endpoints like `/_next/server` and `/api/route`.

## 5) Novel or Zero-Day Exploit Candidates
*(No unmapped zero-day candidates met the threshold for inclusion in this reporting window.)*

## 6) Botnet/Campaign Infrastructure Mapping
### [BOT-01] Spring Boot / PHPStorm Scanner
- **Campaign Shape:** Fan-out
- **Suspected Compromised Src IPs:** 79.124.40.174 (Tamatiya EOOD, BG)
- **Suspected Staging Indicators:** None observed.
- **Suspected C2 Indicators:** Unknown.
- **Confidence:** High
- **Operational Notes:** Enhanced via reflection loop. Identified as an isolated, opportunistic scanner hitting Spring Boot Actuator routing endpoints (`/actuator/gateway/routes`) and PHPStorm XDEBUG endpoints (`/?XDEBUG_SESSION_START=phpstorm`). Generated 50 events exclusively on port 80 between 10:51:27Z and 11:54:44Z. No secondary payloads were delivered.

### [BOT-02] Specific String Brute-Force Botnet
- **Campaign Shape:** Spray
- **Suspected Compromised Src IPs:** 14.225.205.58 (VIETNAM POSTS AND TELECOMMUNICATIONS GROUP, VN)
- **Suspected Staging Indicators:** None.
- **Suspected C2 Indicators:** Unknown.
- **Confidence:** High (Provisional)
- **Operational Notes:** Observed 23 counts of highly specific unique password strings `345gs5662d34` and `3245gs5662d34` via Cowrie SSH/Telnet brute force. Recommended for future tracking to cluster botnet infrastructure.

## 7) Odd-Service / Minutia Attacks
### [MIN-01] ICS Guardian AST Probing
- **Service Fingerprint:** ICS / ConPot (10001) / guardian_ast
- **Why it’s unusual:** Direct interactions with industrial control system protocols.
- **Evidence Summary:** 19 hits logged on the `guardian_ast` protocol. Request payload recorded as: `b'\x01I20100\n'`. 
- **Confidence:** High (Provisional)
- **Recommended Monitoring Pivots:** Monitor port 10001 traffic and parse associated ICS payloads for potential staging commands.

### [ODD-01] Target-Aware Redis Command Injection
- **Service Fingerprint:** Redis (6379)
- **Why it’s unusual:** Attackers used an unusual string, `MGLNDD`, dynamically paired with the exact destination honeypot IP in Redis requests.
- **Evidence Summary:** Redishoneypot interactions where attackers issue specific commands formatting the target IP and port (e.g., `MGLNDD_167.71.255.16_6379`).
- **Confidence:** Medium (Provisional)
- **Recommended Monitoring Pivots:** Search for the `MGLNDD` identifier across broader NoSQL telemetry.

## 8) Known-Exploit / Commodity Exclusions
- **VNC Scanning Noise:** 15,411 counts of 'GPL INFO VNC server response'. High volume port 5902 and 5903 scanning predominantly from US IP addresses.
- **Commodity SMB Scanning:** 3,147 counts from a single Pakistani IP (119.155.24.186, PTCL) targeting port 445. Indicative of persistent Conficker or WannaCry-variant botnet noise.
- **Credential Noise:** Over 24,000 P0f-fingerprinted requests mapped to automated SSH/Telnet brute forcing utilizing common root/admin combinations.

## 9) Infrastructure & Behavioral Classification
- **Exploitation vs Scanning:** Massive generic scanning noise on SMB, VNC, and SSH/Telnet. High-severity, verified exploitation occurs via React2Shell (CVE-2025-55182) executing prototype pollution payloads over HTTP POST. 
- **Campaign Shape:** Focused web application exploit fan-out against React components and Spring Boot Actuators, contrasting sharply with blind broad-spray SSH brute forcing using deterministic credential dictionaries.
- **Infra Reuse Indicators:** Attackers targeting CVE-2025-55182 rotate multiple randomized User-Agents from singular nodes to evade standard detection thresholds.
- **Odd-Service Fingerprints:** Detectable probing and targeted inputs on niche services including ICS (10001 / guardian_ast) and Redis (6379).

## 10) Evidence Appendix
**[NDE-01] Emerging n-day Exploitation (CVE-2025-55182):**
- **Source IPs:** 129.212.239.91 (21 deeper event counts), 193.32.162.28 (1,561 deeper event counts).
- **ASNs:** 14061 (DigitalOcean, LLC), 47890 (Unmanaged Ltd).
- **Target Ports:** 3000-3012, 4020, 6006, 8080, 9063.
- **Paths/Endpoints:** `/`, `/api/route`, `/_next/server`, `/_next`, `/app`.
- **Payload/Artifact Excerpts:** Mapped to Suricata alerts `2066027` (React2Shell) and `2066197` (Javascript Prototype Pollution via __proto__ in HTTP Body).
- **Temporal Checks:** First seen `2026-03-19T09:12:25Z`, last seen `2026-03-19T11:58:45Z`. 

**[BOT-01] Actuator / PHPStorm Scanner:**
- **Source IPs:** 79.124.40.174
- **Target Ports:** 80
- **Paths:** `/actuator/gateway/routes`, `/?XDEBUG_SESSION_START=phpstorm`
- **Temporal Checks:** First seen `2026-03-19T10:51:27Z`, last seen `2026-03-19T11:54:44Z`.

**[BOT-02] Unique SSH/Telnet String Campaign:**
- **Source IPs:** 14.225.205.58
- **Artifact Excerpts:** Passwords `345gs5662d34`, `3245gs5662d34`
- **Temporal Checks:** Unavailable (Skipped Validation).

## 11) Indicators of Interest
**IP Addresses:**
- `129.212.239.91` (Aggressive React2Shell scanner)
- `193.32.162.28` (Targeted React2Shell exploitation, UA rotation)
- `79.124.40.174` (Spring Boot Actuator / PHPStorm isolated scanner)
- `14.225.205.58` (Botnet node using unique string brute force)
- `130.131.162.156` (Redis target-aware command injector)
- `204.76.203.233` (ICS ConPot Guardian AST scanner)

**Paths & Payloads:**
- `/_next/server`, `/api/route`, `/_next`
- `/actuator/gateway/routes`
- `/?XDEBUG_SESSION_START=phpstorm`
- `b'\x01I20100\n'` (ICS payload)
- `MGLNDD` (Redis payload format)
- `345gs5662d34` / `3245gs5662d34` (Botnet passwords)

## 12) Reflection Findings
- **Discovered Reflection Candidates:** [REF-01] via [BOT-01], [REF-02] via [BOT-02], [REF-03] via [MIN-01], [REF-04] via [ODD-01], and [REF-05] via [MON-01].
- **Actions Taken:** The deep reflection loop successfully extracted first/last seen mappings and isolated web path samples for IP `79.124.40.174` ([REF-01]).
- **Findings of Reflection Candidates:** Investigation determined [BOT-01] is an isolated, opportunistic campaign focusing strictly on Spring Boot and PHP installations without advancing to secondary staging execution in the current window.
- **Enhancements:** Reflection greatly improved the certainty of the [BOT-01] assessment by determining exact temporal parameters (active from 10:51:27Z to 11:54:44Z), overall footprint volume (50 hits), and explicitly disproving the download of subsequent payloads. 

## 13) Backend Tool Issues
- **Tool Failures:** `CandidateValidationLoopAgent`, `DeepInvestigationLoopController`, and `OSINTValidatorAgent` experienced early exits.
- **Affected Validations:** Loop exited prematurely after validating `[NDE-01]`. Candidates `[BOT-01]`, `[BOT-02]`, `[ODD-01]`, `[MIN-01]`, and `[MON-01]` skipped primary validation. The Reflection Loop subsequently crashed after addressing `[REF-01]`.
- **Weakened Conclusions:** Temporal analysis, deep pivots, and OSINT confirmation are entirely missing for 4 out of the 6 candidates, degrading overall confidence and limiting the depth of attribution for items like the unique SSH dictionary cluster and ICS probes.

## 14) Agent Action Summary (Audit Trail)
- **ParallelInvestigationAgent:**
  - **Purpose:** Gather baseline infrastructure, known signals, and honeypot-specific behaviors.
  - **Inputs used:** `report_time_window`.
  - **Actions taken:** Executed multi-threaded queries for top general attacks, top IPs/ASNs, Suricata CVE/alerts, P0f metrics, and distinct honeypot logs (Tanner, ConPot, Redishoneypot, Cowrie, ADBHoney).
  - **Key results:** Logged 20,211 generalized attacks; established baseline VNC/SMB noise floors; extracted initial React2Shell hits and diverse honeypot artifacts.
  - **Errors/gaps:** None.
- **CandidateDiscoveryAgent:**
  - **Purpose:** Synthesize outputs into actionable investigation candidates.
  - **Inputs used:** All Baseline and honeypot specific state structures.
  - **Actions taken:** Initiated Kibana correlation and aggregated metric tracking queries.
  - **Key results:** Yielded 6 distinct and prioritized candidates for validation.
  - **Errors/gaps:** None.
- **CandidateValidationLoopAgent:**
  - **Purpose:** Apply formal validation, knownness checks, and temporal mappings.
  - **Inputs used:** 6 candidate queues.
  - **Actions taken:** Fully processed `[NDE-01]` with timestamp boundaries and Suricata trace mappings.
  - **Key results:** Successfully verified `[NDE-01]` as a React2Shell event. 
  - **Errors/gaps:** Exited early; 5 candidates skipped validation due to loop failure.
- **DeepInvestigationLoopController:**
  - **Purpose:** Deep dive on validated candidate artifacts.
  - **Inputs used:** Validated `[NDE-01]`.
  - **Actions taken:** Executed 3 deep iterations tracing attacker IPs and endpoint web paths.
  - **Key results:** Connected React2Shell directly to Prototype Pollution vulnerabilities inside the HTTP body and mapped targeted Next.js endpoints paired with user-agent rotation evasion sequences.
  - **Errors/gaps:** Loop concluded after the initial candidate without proceeding down the queue.
- **OSINTAgent:**
  - **Purpose:** Validate threat behaviors against external security intelligence reporting.
  - **Inputs used:** Candidate `[NDE-01]` identifiers.
  - **Actions taken:** Searched for `CVE-2025-55182` and `React2Shell`.
  - **Key results:** Confirmed a critical pre-auth RCE in React's Flight protocol affecting Next.js, flawlessly aligning with observed honeypot traffic.
  - **Errors/gaps:** Exited the workflow loop abruptly, precluding queries for other candidates.
- **Reflection Agents (ReflectionCandidateDiscoverAgent, ReflectionCandidateLoopControllerAgent, ReflectDeepInvestigationAgent):**
  - **Purpose:** Assess gaps from early loop exits and execute recovery investigations.
  - **Inputs used:** 5 skipped candidates.
  - **Actions taken:** Discovered reflection priorities and deep dived into `[REF-01]` targeting `79.124.40.174`.
  - **Key results:** Delivered precise behavioral timelines and verified payload isolation for `[BOT-01]`.
  - **Errors/gaps:** Reflection loop also terminated early after concluding `[REF-01]`, leaving 4 reflections unattended.
- **ReportAgent:**
  - **Purpose:** Compile the final report from aggregated workflow states.
  - **Inputs used:** All successful investigation matrices, degraded mode logs, and reflection pipeline outputs.
  - **Actions taken:** Synthesized and structured a cohesive Markdown response.
  - **Key results:** Generated the finalized report output.
  - **Errors/gaps:** Degraded outputs due to multiple upstream module interruptions.
- **SaveReportAgent:**
  - **Purpose:** Write the final report to disk.
  - **Inputs used:** Formatted Markdown strings.
  - **Actions taken:** Attempted to execute file write configurations.
  - **Key results:** Written.
  - **Errors/gaps:** None.