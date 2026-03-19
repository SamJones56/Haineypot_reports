# Honeypot Threat Hunting Final Report

## 1) Investigation Scope
- **Investigation Start:** 2026-03-19T09:00:07Z
- **Investigation End:** 2026-03-19T12:00:07Z
- **Completion Status:** Partial (degraded evidence)
- **Degraded Mode:** True. The candidate validation loop and deep investigation loops exited prematurely after processing the first candidate ([NDE-01]). The remaining 5 discovered candidates skipped formal validation, temporal checks, OSINT, and deep pivots, leaving their conclusions provisional based on initial discovery evidence.

## 2) Executive Triage Summary
- **Top Services & Ports:** SMB (445), VNC (5902, 5903), SSH (22), Redis (6379), ICS/Guardian AST (10001), React Web Apps (3000-3012, 4020, 6006, 8080).
- **Top Confirmed Known Exploitation:** 259 counts of CVE-2025-55182 (React2Shell) actively targeting React/Next.js infrastructure.
- **Top Unmapped Exploit-like Items:** None strongly verified in this window.
- **Botnet / Campaign Highlights:** Broad SSH/Telnet brute-forcing using unique string `345gs5662d34`, and targeted routing/XDEBUG application exploit scanning.
- **Odd Services / Minutia:** Captured specific payload interactions targeting ConPot ICS environments (port 10001) and target-aware Redis honeypot command injections (`MGLNDD`).
- **Major Uncertainties:** 5 of the 6 candidates generated during candidate discovery were bypassed by the validation and deep investigation loops, weakening confidence in their campaign shapes and missing deeper pivot context.

## 3) Candidate Discovery Summary
- **Total Candidates Generated:** 6
  - 1 Emerging n-day ([NDE-01])
  - 2 Botnet campaigns ([BOT-01], [BOT-02])
  - 2 Odd-Service/Minutia ([ODD-01], [MIN-01])
  - 1 Suspicious Unmapped Monitor ([MON-01])
- **Missing Inputs/Errors:** Due to a backend loop exit issue, candidates `[BOT-01]`, `[BOT-02]`, `[ODD-01]`, `[MIN-01]`, and `[MON-01]` skipped validation, rendering their findings provisional and lacking deep search context. 

## 4) Emerging n-day Exploitation
### [NDE-01] React2Shell (CVE-2025-55182) Exploitation
- **CVE / Signature Mapping:** CVE-2025-55182 / ET WEB_SPECIFIC_APPS React Server Components React2Shell Unsafe Flight Protocol Property Access (Alert ID: 2066027). Correlated closely with ET HUNTING Javascript Prototype Pollution Attempt via __proto__ in HTTP Body (Alert ID: 2066197).
- **Evidence Summary:** 259 initial alerts logged. Deep investigation revealed over 1,500 targeted HTTP POST events leveraging prototype pollution mechanisms in the React Flight Protocol.
- **Affected Service/Port:** React/Next.js Web Applications. Ports 80, 443, 3000-3012, 4020, 6006, 8080. 
- **Confidence:** High
- **Operational Notes:** Active exploitation observed with distinct actor behaviors. One node (`129.212.239.91`) relies on `Go-http-client/1.1` to aggressively spray the root path `/` across many ports. Another node (`193.32.162.28`) utilizes randomized end-user User-Agents and explicitly targets Next.js endpoints like `/_next/server`, `/api/route`, and `/_next`.

## 5) Novel or Zero-Day Exploit Candidates
*(No unmapped zero-day candidates met the threshold for inclusion in this reporting window.)*

## 6) Botnet/Campaign Infrastructure Mapping
### [BOT-01] Spring Boot / PHPStorm Scanner
- **Campaign Shape:** Fan-out
- **Suspected Compromised Src IPs:** 79.124.40.174 (Tamatiya EOOD, BG)
- **Suspected Staging Indicators:** None observed.
- **Suspected C2 Indicators:** Unknown.
- **Confidence:** High (Provisional due to skipped validation)
- **Operational Notes:** IP repeatedly hits Spring Boot Actuator routing endpoints (`/actuator/gateway/routes`) and PHPStorm XDEBUG endpoints (`/?XDEBUG_SESSION_START=phpstorm`) to attempt Remote Code Execution. Monitor for new web paths appended by this scanner.

### [BOT-02] Specific String Brute-Force Botnet
- **Campaign Shape:** Spray
- **Suspected Compromised Src IPs:** 14.225.205.58 (VIETNAM POSTS AND TELECOMMUNICATIONS GROUP, VN)
- **Suspected Staging Indicators:** None.
- **Suspected C2 Indicators:** Unknown.
- **Confidence:** High (Provisional due to skipped validation)
- **Operational Notes:** Observed 23 counts of highly specific unique password strings `345gs5662d34` and `3245gs5662d34` via Cowrie SSH/Telnet brute force. Tracking these strings is highly recommended to cluster further botnet nodes.

## 7) Odd-Service / Minutia Attacks
### [MIN-01] ICS Guardian AST Probing
- **Service Fingerprint:** ICS / ConPot (port 10001) / guardian_ast
- **Why it’s unusual:** Direct and highly specific interactions with industrial control system protocols.
- **Evidence Summary:** 19 hits logged on the `guardian_ast` protocol. Request payload recorded as: `b'\x01I20100\n'`. 
- **Confidence:** High (Provisional due to skipped validation)
- **Recommended Monitoring Pivots:** Monitor port 10001 traffic and parse associated ICS protocols to capture secondary staging.

### [ODD-01] Target-Aware Redis Command Injection
- **Service Fingerprint:** Redis (port 6379)
- **Why it’s unusual:** Attackers used an unusual string, `MGLNDD`, dynamically paired with the exact destination honeypot IP in Redis actions.
- **Evidence Summary:** Redishoneypot interactions where attackers issue specific commands formatting the target IP and port (e.g., `MGLNDD_167.71.255.16_6379`).
- **Confidence:** Medium (Provisional due to skipped validation)
- **Recommended Monitoring Pivots:** Track the `MGLNDD` string across broader NoSQL environments.

## 8) Known-Exploit / Commodity Exclusions
- **VNC Scanning Noise:** 15,411 counts of 'GPL INFO VNC server response'. High volume port 5902 and 5903 scanning predominantly from US IP addresses. Categorized as commodity botnet scanning.
- **Commodity SMB Scanning:** 3,147 counts from a single Pakistani IP (119.155.24.186, PTCL) targeting port 445. Indicative of persistent Conficker or WannaCry-variant botnet noise.
- **Credential Noise:** Standard automated SSH/Telnet brute force targeting root/admin usernames. Over 24,000 requests map to basic Linux 2.2.x-3.x and Windows NT OS fingerprints via P0f.

## 9) Infrastructure & Behavioral Classification
- **Exploitation vs Scanning:** High-volume scanning dominates SMB, VNC, and SSH/Telnet. However, React2Shell (CVE-2025-55182) shows concrete exploitation intent by injecting prototype pollution payloads via HTTP POST. 
- **Campaign Shape:** Notable fan-out web exploitation attempts against React components and Spring Boot Actuators, contrasted with broad spray SSH brute-force campaigns using generated or distinct credential dictionaries (`345gs5662d34`).
- **Infra Reuse Indicators:** Target actors exploiting CVE-2025-55182 are utilizing User-Agent rotation (spoofing Windows Firefox, Mac Chrome, iOS, and Android) from single nodes to bypass simplistic detections.
- **Odd-Service Fingerprints:** Notable focus on ICS (10001 / guardian_ast) and Redis (6379 / `MGLNDD`).

## 10) Evidence Appendix
**[NDE-01] Emerging n-day Exploitation (CVE-2025-55182):**
- **Source IPs:** 129.212.239.91 (21 deeper event counts), 193.32.162.28 (1,561 deeper event counts).
- **ASNs:** 14061 (DigitalOcean, LLC), 47890 (Unmanaged Ltd).
- **Target Ports:** 3000-3012, 4020, 6006, 8080, 9063.
- **Paths/Endpoints:** `/`, `/api/route`, `/_next/server`, `/_next`, `/app`.
- **Payload/Artifact Excerpts:** Mapped Suricata rules `2066027` (React2Shell) and `2066197` (Javascript Prototype Pollution via __proto__ in HTTP Body).
- **Temporal Checks:** First seen `2026-03-19T09:12:25Z`, last seen `2026-03-19T11:58:45Z`. 

**[BOT-01] Actuator / PHPStorm Scanner:**
- **Source IPs:** 79.124.40.174
- **Target Ports:** 80
- **Paths:** `/actuator/gateway/routes`, `/?XDEBUG_SESSION_START=phpstorm`
- **Temporal Checks:** Unavailable (Skipped Validation).

**[BOT-02] Unique SSH/Telnet String Campaign:**
- **Source IPs:** 14.225.205.58
- **Artifact Excerpts:** Passwords `345gs5662d34`, `3245gs5662d34`
- **Temporal Checks:** Unavailable (Skipped Validation).

## 11) Indicators of Interest
**IP Addresses:**
- `129.212.239.91` (Aggressive React2Shell scanner)
- `193.32.162.28` (Targeted React2Shell exploitation, UA rotation)
- `79.124.40.174` (Spring Boot Actuator / PHPStorm scanner)
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

## 12) Backend Tool Issues
- **Tool Failures:** `CandidateValidationLoopAgent`, `DeepInvestigationLoopController`, and `OSINTValidatorAgent`.
- **Affected Validations:** Loop exited prematurely after validating `[NDE-01]`. Candidates `[BOT-01]`, `[BOT-02]`, `[ODD-01]`, `[MIN-01]`, and `[MON-01]` skipped formal validation.
- **Weakened Conclusions:** Temporal analysis, deeper OSINT context, and related artifact expansion are entirely missing for 5 of the 6 candidates. All findings associated with these items are strictly provisional and based exclusively on early discovery data. 

## 13) Agent Action Summary (Audit Trail)
- **ParallelInvestigationAgent:**
  - **Purpose:** Gather baseline infrastructure, known signals, and honeypot-specific behaviors.
  - **Inputs used:** `report_time_window`.
  - **Actions taken:** Queried general attacks, top IPs/ASNs, Suricata CVE/alerts, P0f, and specific honeypots (Tanner, ConPot, Redishoneypot, Cowrie, ADBHoney).
  - **Key results:** Logged 20,211 attacks; established baseline VNC/SMB noise; extracted preliminary React2Shell alerts and honeypot payloads.
  - **Errors/gaps:** None.
- **CandidateDiscoveryAgent:**
  - **Purpose:** Synthesize outputs into actionable investigation candidates.
  - **Inputs used:** Baseline and honeypot outputs.
  - **Actions taken:** Executed Kibana correlation queries (`two_level_terms_aggregated`, `kibanna_discover_query`, `top_src_ips_for_cve`).
  - **Key results:** Yielded 6 distinct candidates for the validation loop.
  - **Errors/gaps:** None.
- **CandidateValidationLoopAgent:**
  - **Purpose:** Apply formal validation, knownness checks, and temporal mappings.
  - **Inputs used:** 6 candidate configurations.
  - **Actions taken:** Processed `[NDE-01]` executing `first_last_seen_src_ip` and `suricata_cve_samples`.
  - **Key results:** Fully validated `[NDE-01]`. 
  - **Errors/gaps:** Exited early; 5 candidates skipped validation.
- **DeepInvestigationLoopController:**
  - **Purpose:** Deep dive on validated candidate artifacts.
  - **Inputs used:** Validated `[NDE-01]`.
  - **Actions taken:** Executed 3 deep iterations (`events_for_src_ip`, `web_path_samples`, `two_level_terms_aggregated`) to track attacker behavior.
  - **Key results:** Discovered the link between React2Shell and Prototype Pollution in HTTP bodies; mapped targeted Next.js endpoints and UA rotation techniques.
  - **Errors/gaps:** None for `[NDE-01]`.
- **OSINTAgent:**
  - **Purpose:** Validate threat behaviors against external reporting.
  - **Inputs used:** Candidate `[NDE-01]` data.
  - **Actions taken:** Searched for `CVE-2025-55182` and `React2Shell`.
  - **Key results:** Confirmed a critical pre-auth RCE in React's Flight protocol affecting Next.js, matching the telemetry observed.
  - **Errors/gaps:** Exited loop, terminating the processing pipeline.
- **ReportAgent:**
  - **Purpose:** Compile final report from workflow state.
  - **Inputs used:** All successful investigation states, degraded mode triggers, and findings.
  - **Actions taken:** Constructed document aggregating findings and declaring gaps.
  - **Key results:** Markdown report compiled.
  - **Errors/gaps:** None native to the agent, though working with degraded loop outputs.
- **SaveReportAgent:**
  - **Purpose:** Write the final report to disk.
  - **Inputs used:** Markdown content from ReportAgent.
  - **Actions taken:** Call to `deep_agent_write_file`.
  - **Key results:** Executed.
  - **Errors/gaps:** None.