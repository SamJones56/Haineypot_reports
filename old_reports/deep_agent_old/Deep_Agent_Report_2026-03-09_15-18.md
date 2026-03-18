# Honeypot Threat Hunting Final Report

### **1) Investigation Scope**
- **investigation_start:** `2026-03-09T15:00:10Z`
- **investigation_end:** `2026-03-09T18:00:10Z`
- **completion_status:** Partial (degraded evidence)
- **degraded_mode:** true
  - **Reason:** Key evidence validation steps failed due to backend tool errors. Analysis of activity related to CVE-2025-55182 and the Kamstrup ICS protocol was blocked.

### **2) Executive Triage Summary**
- **Top Services/Ports of Interest:** VNC (multiple 590x ports), SSH (22), HTTP (80, 8000-8002), Redis (6379), and unusual activity reported against the Kamstrup smart meter protocol.
- **Top Confirmed Known Exploitation:** Activity matching `CVE-2025-55182` (React2Shell) was detected (99 alerts), though source attribution was blocked. Widespread scanning for VNC and RDP was also observed.
- **Top Unmapped Exploit-like Items:** No high-confidence novel candidates were validated.
- **Botnet/Campaign Mapping Highlights:** Two distinct, high-volume scanning campaigns were identified:
    - A fan-out campaign from a single IP (`136.116.202.5`) systematically scanning for over 15 types of `.env` configuration files.
    - A spray campaign from multiple IPs scanning for exposed `/.git/config` files.
- **Major Uncertainties:** The inability to retrieve source IPs for the 99 `CVE-2025-55182` alerts prevents infrastructure mapping for this critical threat. The complete failure to retrieve telemetry for the Kamstrup protocol activity leaves a blind spot regarding potential ICS-focused attacks.

### **3) Candidate Discovery Summary**
The discovery phase successfully identified several clusters of activity from honeypot and signature data. Key areas included systematic web configuration file scanning, Redis reconnaissance, and potential ICS protocol interaction. However, the process was materially affected by tool failures that prevented the validation of two key leads: attributing source IPs to `CVE-2025-55182` activity and investigating unusual events on the Kamstrup protocol.

### **4) Emerging n-day Exploitation**

- **CVE/Signature Mapping:** `CVE-2025-55182` (React2Shell)
- **Evidence Summary:**
    - **Counts:** 99 alerts referencing the CVE were recorded.
    - **Artifacts:** Source IP correlation failed due to a backend tool error. OSINT confirms this is a critical (CVSS 10.0) pre-authentication RCE being actively exploited in the wild.
- **Affected Service/Port:** Assumed to be HTTP/S based on vulnerability description.
- **Confidence:** Medium (High confidence in CVE presence, but no validated source telemetry).
- **Operational Notes:** This represents a significant known threat. The failure to link this activity to source infrastructure is a critical gap. Monitoring for any HTTP requests matching React Server Component "Flight" protocol patterns is recommended.

### **5) Novel or Zero-Day Exploit Candidates (UNMAPPED ONLY, ranked)**
*No high-confidence unmapped exploit candidates were validated in this window.*

### **6) Botnet/Campaign Infrastructure Mapping**

- **Item ID:** `Tanner-env-scan-fan-out-1`
- **Campaign Shape:** fan-out
- **Suspected Compromised Src IPs:** `136.116.202.5` (multiple requests)
- **ASNs / Geo Hints:** AS396982 (Google LLC), United States
- **Suspected Staging Indicators:** N/A (Direct scanning)
- **Suspected C2 Indicators:** N/A
- **Confidence:** High
- **Operational Notes:** This activity is consistent with commodity scanners looking for exposed credentials. The source IP is a pivot point for identifying other targets of this actor. OSINT confirms this is a widely documented technique.

- **Item ID:** `Tanner-git-config-scan-spray-1`
- **Campaign Shape:** spray
- **Suspected Compromised Src IPs:** `94.26.88.31` (7 requests), `136.116.202.5` (1 request), `172.236.179.87` (1 request)
- **ASNs / Geo Hints:** Multiple ASNs involved.
- **Suspected Staging Indicators:** N/A (Direct scanning)
- **Suspected C2 Indicators:** N/A
- **Confidence:** Medium
- **Operational Notes:** Coordinated scanning for exposed git repositories. The shared behavior across multiple IPs suggests a common toolkit or campaign objective. OSINT confirms this is a common technique using tools like GitHacker.

### **7) Odd-Service / Minutia Attacks**

- **Item ID:** `Conpot-kamstrup-unverified-1`
- **Service Fingerprint:** `protocol: kamstrup_protocol` (ICS/Smart Meter) on Conpot honeypot.
- **Why it’s unusual/interesting:** Kamstrup is a niche protocol for industrial control systems (smart metering), and any unauthenticated interaction is anomalous and potentially significant.
- **Evidence Summary:**
    - **Counts:** Initial agent reported 6 events, but validation queries failed to retrieve any records.
    - **Artifacts:** None available.
- **Confidence:** Low (Provisional)
- **Recommended Monitoring Pivots:** Requires manual investigation of Conpot logs to confirm presence. If confirmed, all source IPs interacting with this protocol should be investigated.

- **Item ID:** `Redis-recon-1`
- **Service Fingerprint:** `port: 6379`, `protocol: redis`
- **Why it’s unusual/interesting:** Standard reconnaissance against a Redis data store.
- **Evidence Summary:**
    - **Counts:** Multiple commands observed from a single source.
    - **Artifacts:** `KEYS *` and various `GET` commands from `188.214.133.176`.
- **Confidence:** High
- **Recommended Monitoring Pivots:** The source IP `188.214.133.176` (AS16125, UAB Cherry Servers) is actively performing Redis enumeration.

### **8) Known-Exploit / Commodity Exclusions**
- **VNC Scanning:** Extremely high volume (21,129 alerts) of `GPL INFO VNC server response`, primarily from the US, targeting ports 5902, 5903, 5904, 5906, 5907. This is commodity VNC enumeration noise.
- **RDP Scanning:** Widespread scanning (809 alerts) for `ET SCAN MS Terminal Server Traffic on Non-standard Port`. This is commodity RDP scanning noise.
- **Credential Noise:** Standard brute-force attempts observed against SSH and other services, using common usernames (`root`, `user`, `admin`, `postgres`) and passwords (`123456`, `password`, `12345678`).
- **Web App Scanning:** Tanner honeypot observed common directory and file scanning for sensitive paths like `/.git/config`, `/.env`, and web server roots (`/`). This is typical automated scanner behavior.

### **9) Infrastructure & Behavioral Classification**
| Item ID / Description | Classification | Campaign Shape | Infra Reuse Indicators | Odd-Service Fingerprint |
| :--- | :--- | :--- | :--- | :--- |
| `CVE-2025-55182` Activity | Emerging n-day Exploitation | Unknown | Unknown (Tool Failure) | N/A |
| `.env` File Scanning | Commodity Scanning | Fan-out | Single Source IP `136.116.202.5` | N/A |
| `/.git/config` Scanning | Commodity Scanning | Spray | `136.116.202.5` reused from `.env` scan | N/A |
| Redis Reconnaissance | Reconnaissance | Point | Single Source IP `188.214.133.176` | `redis` on `6379` |
| Kamstrup Protocol Activity | Monitor (Unverified) | Unknown | Unknown (Tool Failure) | `kamstrup_protocol` |

### **10) Evidence Appendix**

- **Item:** `Emerging n-day Exploitation (CVE-2025-55182)`
    - **Source IPs with Counts:** `unavailable` (due to tool failure)
    - **ASNs with Counts:** `unavailable`
    - **Target Ports/Services:** HTTP/S (inferred)
    - **Paths/Endpoints:** React Server Component endpoints (inferred)
    - **Payload/Artifact Excerpts:** 99 alerts for `CVE-2025-55182`
    - **Temporal Checks:** `unavailable`

- **Item:** `Botnet Mapping (Tanner-env-scan-fan-out-1)`
    - **Source IPs with Counts:** `136.116.202.5` (at least 22 requests to various `.env` files)
    - **ASNs with Counts:** AS396982 (Google LLC)
    - **Target Ports/Services:** HTTP
    - **Paths/Endpoints:** `/.env`, `/.env.local`, `/.env.dev`, `/.env.production`, `/.env.bak`, etc.
    - **Payload/Artifact Excerpts:** N/A (HTTP GET requests)
    - **Temporal Checks:** Activity observed within the investigation window.

- **Item:** `Botnet Mapping (Tanner-git-config-scan-spray-1)`
    - **Source IPs with Counts:** `94.26.88.31` (7), `136.116.202.5` (1), `172.236.179.87` (1)
    - **ASNs with Counts:** Multiple
    - **Target Ports/Services:** HTTP
    - **Paths/Endpoints:** `/.git/config`
    - **Payload/Artifact Excerpts:** N/A (HTTP GET requests)
    - **Temporal Checks:** Activity observed within the investigation window.

### **11) Indicators of Interest**
- **CVE:** `CVE-2025-55182` (React2Shell)
- **Source IPs:**
    - `136.116.202.5` (High-volume `.env` and `/.git/config` scanning)
    - `94.26.88.31` (High-volume `/.git/config` scanning)
    - `188.214.133.176` (Redis reconnaissance)
- **Paths:**
    - `/.git/config`
    - `/.env` (and numerous variations like `/.env.local`, `/.env.dev`, `/.env.production`)
- **Payload Fragments / Commands:**
    - `KEYS *` (Redis command)

### **12) Backend Tool Issues**
- **Tool Failure:** `top_src_ips_for_cve`
  - **Effect:** The tool returned 0 results when queried for source IPs related to `CVE-2025-55182`, despite 99 alerts being present in the dataset.
  - **Weakened Conclusion:** This failure prevented the infrastructure mapping of an active exploitation campaign targeting a critical vulnerability. The scope and origin of the threat remain unknown.

- **Tool Failure:** `kibanna_discover_query` / `two_level_terms_aggregated`
  - **Effect:** Queries for `type:Conpot` and `protocol.keyword:kamstrup_protocol` returned 0 results, contradicting an earlier agent's report of 6 events.
  - **Weakened Conclusion:** The analysis of potentially malicious activity against an ICS protocol was completely blocked. It is impossible to confirm if this activity occurred or to assess its risk.

### **13) Agent Action Summary (Audit Trail)**

- **Agent:** `ParallelInvestigationAgent`
  - **Purpose:** To perform broad, parallel data collection on baseline metrics, known signals, credential noise, and honeypot-specific data.
  - **Inputs Used:** `investigation_start`, `investigation_end`.
  - **Actions Taken:** Executed multiple data gathering tools across its sub-agents (`BaselineAgent`, `KnownSignalAgent`, `CredentialNoiseAgent`, `HoneypotSpecificAgent`).
  - **Key Results:**
    - Identified ~20k total attacks, with top sources from US, India, Australia.
    - Found 21k alerts for "GPL INFO VNC server response" and 99 alerts for `CVE-2025-55182`.
    - Identified common credential stuffing usernames (`root`, `user`) and passwords (`123456`).
    - Found Tanner scanning for `.env`/`.git/config`, Redis recon commands, and Conpot `kamstrup_protocol` events.
  - **Errors or Gaps:** None.

- **Agent:** `CandidateDiscoveryAgent`
  - **Purpose:** To synthesize parallel data streams, identify anomalous clusters, and generate initial candidates for investigation.
  - **Inputs Used:** `baseline_result`, `known_signals_result`, `credential_noise_result`, `honeypot_specific_result`.
  - **Actions Taken:**
    - Ran `two_level_terms_aggregated` to group Tanner web scan activity by path and source IP.
    - Attempted to query Conpot, Redis, and CVE-related events using `kibanna_discover_query` and `top_src_ips_for_cve`.
  - **Key Results:**
    - Successfully clustered Tanner scanning into two campaigns (`.env` and `.git/config` scans).
    - Identified Redis reconnaissance activity.
    - Flagged Kamstrup protocol activity as an anomaly.
    - Noted the presence of `CVE-2025-55182` alerts.
  - **Errors or Gaps:** The queries for CVE source IPs and Kamstrup protocol events failed, which were documented as `evidence_gaps`.

- **Agent:** `CandidateValidationLoopAgent`
  - **Purpose:** To iteratively validate each discovered candidate against temporal, knownness, and infrastructure checks.
  - **Inputs Used:** `candidate_discovery_result`.
  - **Actions Taken:** The loop was exited immediately by its controller (`CandidateLoopControllerAgent`) before any iterations were run.
  - **Key Results:** 0 candidates were processed in this loop.
  - **Errors or Gaps:** The loop was bypassed, likely because the `CandidateDiscoveryAgent` had already identified the validation-blocking issues.

- **Agent:** `DeepInvestigationLoopController`
  - **Purpose:** To perform deep, stateful investigation on high-priority validated candidates.
  - **Inputs Used:** N/A.
  - **Actions Taken:** Loop was not initiated as there were no validated high-priority candidates to investigate.
  - **Key Results:** N/A.
  - **Errors or Gaps:** N/A.

- **Agent:** `OSINTAgent`
  - **Purpose:** To provide external context on identified candidates and artifacts.
  - **Inputs Used:** `candidate_discovery_result`.
  - **Actions Taken:** Performed `search` queries for `CVE-2025-55182`, `.env` file scanning, `/.git/config` file scanning, `kamstrup_protocol` vulnerabilities, and Redis `KEYS *` reconnaissance.
  - **Key Results:**
    - Confirmed `CVE-2025-55182` is a known, critical RCE.
    - Confirmed that scanning for `.env` and `.git/config` are established, commodity techniques.
    - Confirmed that Redis `KEYS *` is a standard reconnaissance method.
    - Found no public vulnerabilities for the Kamstrup protocol, noting it is proprietary.
  - **Errors or Gaps:** OSINT analysis for Kamstrup was inconclusive due to the lack of verifiable telemetry.

- **Agent:** `ReportAgent`
  - **Purpose:** To compile the final report from all available workflow state outputs.
  - **Inputs Used:** All preceding agent outputs.
  - **Actions Taken:** Assembled this report based on the mandatory format and logic.
  - **Key Results:** This markdown report.
  - **Errors or Gaps:** Noted degraded mode and backend tool issues as reported by upstream agents.

- **Agent:** `SaveReportAgent`
  - **Purpose:** To save the final report artifact.
  - **Inputs Used:** `report_content` (this document).
  - **Actions Taken:** Pending execution by the downstream workflow.
  - **Key Results:** Pending.
  - **Errors or Gaps:** Pending.
