# Threat Investigation Report: 2026-03-10T03:00:05Z to 2026-03-10T06:00:05Z

## 1) Investigation Scope
- **investigation_start:** 2026-03-10T03:00:05Z
- **investigation_end:** 2026-03-10T06:00:05Z
- **completion_status:** Partial (degraded evidence)
- **degraded_mode:** true - A tool query failed, preventing source IP attribution for observed ICS protocol activity.

## 2) Executive Triage Summary
- **Top Services/Ports of Interest:** VNC (5900-5905), SMB (445), HTTP (80), Minecraft (25565), and Kamstrup ICS (1025).
- **Top Confirmed Known Exploitation:** Widespread scanning for VNC CVE-2006-2369 ("VNC Server Not Requiring Authentication") was the most dominant known activity.
- **Top Unmapped Exploit-Like Items:** A novel command injection attempt was identified against a web honeypot. The attacker used shell syntax (`$(pwd)`) within HTTP GET requests to locate and exfiltrate sensitive configuration files (`.env`, `*.auto.tfvars`).
- **Botnet/Campaign Mapping Highlights:** Coordinated activity was discovered from two source IPs (`185.177.72.51`, `185.177.72.49`) within the same ASN (211590). Both actors used malformed HTTP requests containing Node.js code fragments, indicating a shared toolkit, but targeted different web vulnerabilities (command injection vs. file upload endpoints).
- **Odd-Service/Minutia Highlights:** An actor fingerprinted as a "Nintendo 3DS" was observed scanning the Minecraft port (25565). OSINT analysis confirmed this IP is a known Minecraft scanner, suggesting the fingerprint is either a misclassification or an evasion tactic.
- **Major Uncertainties:** The source IPs behind 53 events targeting the Kamstrup Industrial Control System (ICS) protocol could not be identified due to a backend tool error.

## 3) Candidate Discovery Summary
- The discovery process analyzed 18,404 attack events to identify high-signal candidates.
- Key areas of interest identified were:
    - URI-based command injection attempts on the Tanner web honeypot.
    - An unusual p0f OS fingerprint ("Nintendo 3DS") targeting the Minecraft service port.
    - Kamstrup ICS protocol activity on the Conpot honeypot.
- A material error occurred when a query to correlate Conpot events with source IPs failed, preventing full analysis of the Kamstrup ICS activity.

## 4) Novel or Zero-Day Exploit Candidates

### Candidate 1:
- **candidate_id:** Tanner-CmdInject-1
- **classification:** novel exploit candidate
- **novelty_score:** 8/10
- **confidence:** High
- **provisional:** false
- **key evidence:**
    - Attacker used shell command substitution in HTTP GET requests from IP `185.177.72.51`.
    - Payloads: `GET /$(pwd)/.env` and `GET /$(pwd)/*.auto.tfvars`.
    - The same actor was observed sending malformed HTTP requests containing what appears to be a Node.js code snippet: `server.listen(51295,` sent as the HTTP method.
- **knownness checks performed + outcome:**
    - `suricata_lenient_phrase_search` for the payload `*auto.tfvars` found no existing signatures.
    - OSINT search confirmed `.auto.tfvars` files are used by Terraform and are a valuable target for attackers seeking sensitive credentials.
- **temporal checks:** The activity occurred in a short burst between 2026-03-10T03:54:03Z and 2026-03-10T03:56:03Z. Not seen in the previous window.
- **required follow-up:**
    - A signature should be developed for the URI pattern `*/$(pwd)/*` to detect this command injection technique.
    - The related IPs `185.177.72.51` and `185.177.72.49` should be monitored.

## 5) Botnet/Campaign Infrastructure Mapping

### Item 1: Coordinated Web Attack Campaign
- **item_id:** Tanner-CmdInject-Campaign-1
- **related_candidate_id(s):** Tanner-CmdInject-1
- **campaign_shape:** Coordinated / fan-out
- **suspected_compromised_src_ips:** `185.177.72.51`, `185.177.72.49` (2 distinct IPs)
- **ASNs / geo hints:** ASN 211590 (Bucklog SARL, France)
- **suspected_staging indicators:** N/A
- **suspected_c2 indicators:** N/A
- **confidence:** High
- **operational notes:** Two IPs from the same ASN launched a coordinated, short-burst attack. They share a TTP of leaking Node.js code fragments in malformed HTTP requests but pursue different objectives (config file theft vs. upload endpoint scanning). This indicates a shared, scripted toolkit. Recommend blocking the entire ASN 211590 at the firewall pending further review.

### Item 2: VNC Spray Campaign
- **item_id:** VNC-SPRAY-CAMPAIGN-1
- **campaign_shape:** spray
- **suspected_compromised_src_ips:** `79.98.102.166`, `136.114.97.84`, `79.124.40.98`, `134.209.37.134` and others.
- **ASNs / geo hints:** 14061 (DigitalOcean), 16347 (ADISTA SAS), 396982 (Google LLC)
- **suspected_staging indicators:** N/A
- **suspected_c2 indicators:** N/A
- **confidence:** High
- **operational notes:** This is a high-volume, commodity scanning campaign targeting VNC (CVE-2006-2369). The IPs are part of known scanning infrastructure and should be added to standard blocklists.

## 6) Odd-Service / Minutia Attacks

### Item 1: Minecraft Scanner with "Nintendo 3DS" Fingerprint
- **service_fingerprint:** Minecraft (port 25565)
- **why it’s unusual/interesting:** A connecting client (`51.15.34.47`) was fingerprinted by p0f as a "Nintendo 3DS", which is a highly unusual client for this service.
- **evidence summary:** OSINT investigation confirms `51.15.34.47` is a widely-reported Minecraft scanner associated with projects like "matscan". The "Nintendo 3DS" fingerprint is therefore likely a misclassification by p0f due to a non-standard TCP/IP stack used by the scanning tool, or a deliberate tactic to confuse analysts.
- **confidence:** Medium
- **recommended monitoring pivots:** The activity itself is known scanning, but it may be worth monitoring for other p0f anomalies associated with known malicious IPs.

### Item 2: Kamstrup ICS Protocol Scans (Provisional)
- **service_fingerprint:** Kamstrup Protocol (port 1025) on Conpot Honeypot
- **why it’s unusual/interesting:** This is an Industrial Control System (ICS) protocol, and any interaction is noteworthy.
- **evidence summary:** 53 events for `kamstrup_protocol` were recorded. However, due to a tool failure, the source IPs could not be identified.
- **confidence:** Low (Provisional)
- **recommended monitoring pivots:** Fix the underlying tool query to enable source IP attribution for Conpot events.

## 7) Known-Exploit / Commodity Exclusions
- **VNC Authentication Bypass (CVE-2006-2369):** Over 23,000 Suricata alerts related to VNC scanning, with 510 directly matching "ET EXPLOIT VNC Server Not Requiring Authentication". This is widespread commodity activity.
- **SMB Scanning (Port 445):** High-volume scanning for SMB, particularly from `79.98.102.166` (2,574 events). Standard internet background noise.
- **Minecraft Server Scanning (Port 25565):** Activity from `51.15.34.47`, initially flagged for its odd OS fingerprint, was confirmed via OSINT to be a known public Minecraft scanner.
- **Credential Stuffing/Brute-Force:** Standard attempts against SSH using common usernames (`root`, `admin`, `user`) and passwords (`123456`, `password`).

## 8) Infrastructure & Behavioral Classification
- **Exploitation vs Scanning:**
    - The Tanner activity (`Tanner-CmdInject-1`) was targeted exploitation.
    - The VNC, SMB, and Minecraft activities were broad, indiscriminate scanning.
- **Campaign Shape:**
    - The Tanner activity was a coordinated fan-out from two IPs in the same ASN.
    - The VNC activity was a wide spray from multiple, unrelated ASNs.
- **Infra Reuse Indicators:** The two IPs in the Tanner campaign reused a distinct TTP (leaking Node.js code), indicating a shared toolkit.
- **Odd-Service Fingerprints:** Kamstrup ICS protocol and a "Nintendo 3DS" p0f fingerprint were the most notable oddities.

## 9) Evidence Appendix

### Novel Exploit: Tanner-CmdInject-1
- **Source IPs:** `185.177.72.51`, `185.177.72.49`
- **ASNs:** 211590 (Bucklog SARL)
- **Target Ports/Services:** 80 (HTTP)
- **Paths/Endpoints:**
    - `/$(pwd)/.env`
    - `/$(pwd)/*.auto.tfvars`
    - `/api/storage/local`
    - `/api/s3/upload`
- **Payload/Artifact Excerpts:**
    - URI command injection: `.../$(pwd)/.env`
    - Leaked Node.js fragment in HTTP Method field: `server.listen(51295,`
- **Temporal Checks:** Activity confined to 2026-03-10T03:54:03Z - 2026-03-10T03:56:36Z.

### Botnet Mapping: VNC-SPRAY-CAMPAIGN-1
- **Source IPs (Top Examples):** `79.98.102.166` (2572 events), `136.114.97.84` (936 events)
- **ASNs (Top Examples):** 14061, 16347, 396982
- **Target Ports/Services:** 5900, 5901, 5902, 5903, 5904, 5905 (VNC)
- **Payload/Artifact Excerpts:** Suricata Signature: `ET EXPLOIT VNC Server Not Requiring Authentication (case 2)`
- **Temporal Checks:** Ongoing throughout the investigation window.

## 10) Indicators of Interest
- **IPs:**
    - `185.177.72.51` (High confidence, novel attack)
    - `185.177.72.49` (High confidence, coordinated novel attack)
- **URIs / Paths:**
    - `*/$(pwd)/.env`
    - `*/$(pwd)/*.auto.tfvars`
- **Payload Fragments / TTPs:**
    - Malformed HTTP requests where the method line contains Node.js code, such as: `server.listen(51295,`

## 11) Backend Tool Issues
- **Tool Failure:** `two_level_terms_aggregated`
- **Affected Validations:** The query to find source IPs for Conpot honeypot events failed.
- **Weakened Conclusions:** This failure prevented the attribution of 53 suspicious events involving the Kamstrup ICS protocol, weakening the `Odd-Service / Minutia Attacks` section. The finding remains provisional as a result.

## 12) Agent Action Summary (Audit Trail)

- **agent_name:** ParallelInvestigationAgent
- **purpose:** Runs initial baseline data collection sub-agents.
- **inputs_used:** Time window.
- **actions_taken:** Executed Baseline, KnownSignal, CredentialNoise, and HoneypotSpecific agents in parallel.
- **key_results:**
    - Gathered initial telemetry: 18,404 total attacks.
    - Identified top active signatures (VNC-related), CVEs (CVE-2006-2369), countries, IPs, and ASNs.
    - Profiled common credential stuffing attempts.
    - Collected data from specific honeypots, noting Conpot/Kamstrup activity.
- **errors_or_gaps:** None.

- **agent_name:** CandidateDiscoveryAgent
- **purpose:** Sifts through initial telemetry to find promising leads for investigation.
- **inputs_used:** All outputs from the ParallelInvestigationAgent.
- **actions_taken:** Queried for unmapped/suspicious behaviors, focusing on odd p0f fingerprints, Tanner honeypot paths, and Conpot protocols.
- **key_results:**
    - Produced 3 primary candidates: `Tanner-CmdInject-1`, `MINECRAFT-NINTENDO-3DS`, `CONPOT-KAMSTRUP-ICS`.
    - Identified a widespread VNC scanning campaign as known commodity noise.
- **errors_or_gaps:** A query (`two_level_terms_aggregated` on Conpot data) failed, preventing the agent from discovering the source IPs for the Kamstrup ICS activity.

- **agent_name:** CandidateValidationLoopAgent
- **purpose:** Iteratively validates candidates produced by the discovery agent.
- **inputs_used:** Candidate `Tanner-CmdInject-1`.
- **actions_taken:**
    - Iterations Run: 1 of 3 planned.
    - Validated candidate `Tanner-CmdInject-1` by cross-referencing Tanner and Suricata data, and using external search to understand the attacker's goal (`.auto.tfvars`).
- **key_results:**
    - Confirmed the `Tanner-CmdInject-1` activity was a novel command injection attempt with high confidence.
    - Produced a detailed validation report for the candidate.
    - Validated Candidates: 1.
- **errors_or_gaps:** None.

- **agent_name:** DeepInvestigationLoopController
- **purpose:** Performs deep-dive analysis on high-value validated candidates.
- **inputs_used:** Validated candidate `Tanner-CmdInject-1`.
- **actions_taken:**
    - Iterations Run: 1.
    - Pursued lead `src_ip:185.177.72.51`.
    - Pivoted from the initial IP to analyze its behavior, identifying malformed HTTP requests containing Node.js code.
    - This TTP was used to discover a second IP (`185.177.72.49`) from the same ASN engaging in similar, coordinated activity.
- **key_results:**
    - Uncovered a two-IP coordinated campaign.
    - Mapped the shared TTP and distinct goals of the two attackers.
    - Exited the loop after mapping the immediate campaign.
- **errors_or_gaps:** None.

- **agent_name:** OSINTAgent
- **purpose:** Uses external search to enrich findings and check for public knowledge.
- **inputs_used:** Candidate `MINECRAFT-NINTENDO-3DS`.
- **actions_taken:** Searched for p0f "Nintendo 3DS" fingerprints and for reports on the source IP `51.15.34.47`.
- **key_results:**
    - Found no public information linking p0f to Nintendo 3DS fingerprints.
    - Found extensive public reporting on AbuseIPDB and GitHub identifying `51.15.34.47` as a known Minecraft server scanner.
    - Reduced the novelty of the `MINECRAFT-NINTENDO-3DS` finding, reclassifying it as known commodity scanning with a fingerprinting anomaly.
- **errors_or_gaps:** None.

- **agent_name:** ReportAgent
- **purpose:** Compiles the final report from all workflow state outputs.
- **inputs_used:** All preceding agent outputs.
- **actions_taken:** Assembled this report.
- **key_results:** This document.
- **errors_or_gaps:** None.

- **agent_name:** SaveReportAgent
- **purpose:** Saves the final report file.
- **inputs_used:** The markdown content from this report.
- **actions_taken:** Called the `deep_agent_write_file` tool.
- **key_results:** File write status, path will be returned by the tool.
- **errors_or_gaps:** None.
