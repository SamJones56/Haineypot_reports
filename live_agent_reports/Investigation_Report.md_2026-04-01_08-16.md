# Investigation Report: Minutia Attacks and Botnet Traces

## 1. Investigation Scope
- **investigation_start:** 2026-04-01T08:46:12Z
- **investigation_end:** 2026-04-01T16:46:12Z
- **completion_status:** Partial
- **degraded_mode:** true
- **Reason:** While the investigation initially identified the RedTail botnet with high confidence, subsequent attempts to re-query and validate the original telemetry failed. This indicates a potential data integrity or pipeline issue, preventing verification of the primary findings.

## 2. Investigation Summary
This investigation was initiated to identify minutia attacks and botnet activity over an 8-hour window. The workflow successfully filtered high-volume commodity scanning noise (VNC, SMB) to isolate three distinct activities of interest: targeted scanning for a probable Next.js vulnerability (BOT-01), probing of Industrial Control System (ICS) protocols (ODD-01), and a coordinated PHP exploitation campaign (BOT-02).

A user-directed deep-dive investigation into BOT-02 revealed it was part of a larger, multi-vulnerability scanning operation. By pivoting on a unique user agent (`libredtail-http`), the activity was identified with high confidence as the "RedTail" cryptomining botnet. An OSINT investigation confirmed this mapping and provided additional IOCs.

However, the investigation's final phase encountered a critical failure. Attempts to replicate the original queries that identified the RedTail botnet were unsuccessful, as the telemetry from the initial time window was no longer accessible. This evidence gap makes the primary findings provisional, pending a backend data infrastructure review.

### 2.1) Executive Triage Summary
*   **Top Services/Ports of Interest:**
    *   **5901-5903/tcp (VNC):** High-volume commodity scanning noise (46,000+ events).
    *   **445/tcp (SMB):** High-volume commodity scanning noise.
    *   **1025/tcp (Kamstrup/ICS):** Highly unusual probing of Industrial Control System (ICS) protocols, considered a high-signal minutia attack.
    *   **2053/tcp (HTTP):** Uncommon port used for targeted scanning of probable Next.js vulnerabilities.
*   **Top Confirmed Known Exploitation:**
    *   Activity associated with the **RedTail cryptomining botnet** was identified, targeting PHP vulnerabilities, ThinkPHP RCE, exposed Docker APIs, and more.
*   **Top Unmapped Exploit-like Items:**
    *   Targeted scanning from a single IP (`193.32.162.28`) against Next.js endpoints on port 2053, associated with a placeholder CVE (`CVE-2025-55182`).
*   **Botnet/Campaign Mapping Highlights:**
    *   **BOT-02 / RedTail:** Two IPs (`200.36.214.242`, `188.132.230.217`) were confirmed as part of the RedTail botnet, using the `libredtail-http` user agent for broad vulnerability scanning.
*   **Major Uncertainties:**
    *   The inability to re-query and validate the telemetry that led to the RedTail discovery makes the central finding unverifiable without a data pipeline investigation.

### 2.2) Candidate Discovery Summary
The initial discovery phase analyzed baseline, known signal, credential, and honeypot-specific data streams. It successfully merged these sources to produce three distinct candidates for investigation, filtering out tens of thousands of commodity events. A notable evidence gap was the initial failure of a direct query for `CVE-2025-55182`, requiring a pivot through the source IP to gather context.

### 2.4) Novel or Zero-Day Exploit Candidates (UNMAPPED ONLY, ranked)
This section is intentionally left blank as no candidates met the criteria for novel exploitation. The most significant unmapped activity (BOT-01) is detailed under Botnet/Campaign Mapping.

### 2.5) Botnet/Campaign Infrastructure Mapping
**Item ID:** BOT-02 (RedTail Cryptomining Botnet)
- **campaign_shape:** fan-out (distributed scanning)
- **suspected_compromised_src_ips:** `200.36.214.242` (Brazil), `188.132.230.217` (Türkiye)
- **ASNs / geo hints:** AS271383 (L R PROVEDOR DE INTERNET LTDA), AS200456 (VG Telekomunikasyon Ticaret Limited Sirketi)
- **suspected_staging indicators:** The user agent `libredtail-http` was a key indicator of the scanning tool.
- **suspected_c2 indicators:** Not directly observed in telemetry. OSINT indicates C2 communication for configuration downloads.
- **confidence:** High (based on initial telemetry and OSINT), but **Provisional** due to replication failure.
- **operational notes:** The campaign involves scanning for a wide array of vulnerabilities, including PHPUnit RCE, ThinkPHP RCE, PEAR LFI, and exposed Docker Engine APIs. All activity shares the `libredtail-http` user agent.

**Item ID:** BOT-01 (Next.js Vulnerability Scanning)
- **campaign_shape:** fan-out (single, aggressive source)
- **suspected_compromised_src_ips:** `193.32.162.28` (132 events)
- **ASNs / geo hints:** AS47890 (Unmanaged Ltd, Romania)
- **suspected_staging indicators:** N/A
- **suspected_c2 indicators:** N/A
- **confidence:** High
- **operational notes:** A single IP was responsible for nearly all alerts for a placeholder CVE (`CVE-2025-55182`), making POST requests to Next.js endpoints (`/_next/server`, `/api/route`) on the non-standard port 2053. This appears to be a highly targeted scanner.

### 2.6) Odd-Service / Minutia Attacks
**Item ID:** ODD-01 (ICS Protocol Probing)
- **service_fingerprint:** 1025/tcp (kamstrup_protocol, IEC104)
- **why it’s unusual/interesting:** This represents targeted reconnaissance against Industrial Control System (ICS) protocols, which is far less common than typical web or service scanning. Such activity often precedes more sophisticated attacks against operational technology (OT).
- **evidence summary:** The Conpot honeypot recorded 37 events from `86.54.31.34` and `16.58.56.214` probing for Kamstrup devices.
- **confidence:** High
- **recommended monitoring pivots:** Profile the source IPs for any other ICS-related activity. Monitor for follow-on connection attempts or exploit payloads targeting OT protocols.

### 2.7) Known-Exploit / Commodity Exclusions
- **VNC Scanning:** Extremely high volume (46,000+ alerts) of `GPL INFO VNC server response` signatures, primarily targeting ports 5901-5903. Classic opportunistic scanning noise.
- **SMB Scanning:** High-volume scanning of port 445 from multiple sources, characteristic of commodity scanners (e.g., WannaCry, EternalBlue) looking for open shares.
- **Credential Stuffing:** Standard brute-force attempts on SSH and other services using common username/password lists (e.g., `root`, `admin`, `123456`).

### 2.9) Evidence Appendix
**Item:** BOT-02 (RedTail Cryptomining Botnet) - *PROVISIONAL*
- **source IPs with counts:** `200.36.214.242` (~152 events), `188.132.230.217` (~151 events)
- **ASNs with counts:** AS271383 (L R PROVEDOR DE INTERNET LTDA), AS200456 (VG Telekomunikasyon Ticaret Limited Sirketi)
- **target ports/services:** 80/tcp (HTTP)
- **paths/endpoints:**
    - `/V2/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php`
    - `/?%ADd+allow_url_include%3d1+%ADd+auto_prepend_file%3dphp://input`
    - `/public/index.php?s=/index/\think\app/invokefunction`
    - `/containers/json`
- **payload/artifact excerpts:** User Agent: `libredtail-http`
- **temporal checks results:** Unavailable. Data could not be re-queried.

**Item:** BOT-01 (Next.js Vulnerability Scanning)
- **source IPs with counts:** `193.32.162.28` (132)
- **ASNs with counts:** AS47890 (Unmanaged Ltd) (132)
- **target ports/services:** 2053/tcp (HTTP)
- **paths/endpoints:** `/_next/server`, `/app`, `/_next`, `/api/route`
- **payload/artifact excerpts:** `http_method: POST`
- **temporal checks results:** Available.

**Item:** ODD-01 (ICS Protocol Probing)
- **source IPs with counts:** `86.54.31.34` (1), `16.58.56.214` (18)
- **ASNs with counts:** AS12989 (Black HOST Ltd), AS16509 (Amazon.com, Inc.)
- **target ports/services:** 1025/tcp (Conpot Honeypot)
- **paths/endpoints:** N/A (protocol-level interaction)
- **payload/artifact excerpts:** protocol: `kamstrup_protocol`
- **temporal checks results:** Available.

## 3) Indicators of Interest
- **User Agent:** `libredtail-http` (Indicator for RedTail cryptomining botnet)
- **IPs (RedTail Scanning):** `200.36.214.242`, `188.132.230.217`
- **IP (Next.js Scanning):** `193.32.162.28`
- **IPs (ICS Probing):** `86.54.31.34`, `16.58.56.214`
- **Paths (RedTail):**
    - `/containers/json` (Docker API)
    - `/?%ADd+allow_url_include%3d1+%ADd+auto_prepend_file%3dphp://input` (PHP LFI)
    - `/V2/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php` (PHPUnit RCE)
- **Paths (Next.js Scanning):** `/_next/server`, `/api/route`

## 4) Backend Tool Issues
- **Data Replicability Failure:** The most significant issue was the inability to re-run queries that led to the discovery of the RedTail botnet. The `complete_custom_search` tool failed to find the `libredtail-http` user agent in the original `2026-04-01T08:46:12Z` - `16:46:12Z` time window where it was previously found. This prevented validation of the core findings and suggests a critical issue with data retention, indexing, or the query pipeline itself.
- **Initial CVE Query Failure:** The `kibanna_discover_query` tool initially failed to find `CVE-2025-55182` because the data source contained a duplicated string (`CVE-2025-55182 CVE-2025-55182`). This required a manual pivot and indicates a data quality issue in the CVE field.
- **Tool Hallucination:** The `BaselineAgent` attempted to call `tanner_unifrom_resource_search`, which was not an available tool for that agent, causing a minor workflow error.

## 5) Agent Action Summary (Audit Trail)
- **ParallelInvestigationAgent:**
  - **Purpose:** To gather broad baseline and known-threat data.
  - **Inputs Used:** `investigation_start`, `investigation_end`.
  - **Actions Taken:** Executed parallel queries for baseline stats (top IPs, ASNs, ports), known signals (signatures, CVEs), credential noise (usernames, passwords), and honeypot-specific activity (Conpot, Tanner, Adbhoney).
  - **Key Results:** Identified high-volume VNC/SMB scanning, placeholder `CVE-2025-55182`, and ICS/web honeypot activity.
  - **Errors or Gaps:** `BaselineAgent` failed on one tool call (`tanner_unifrom_resource_search`).
- **CandidateDiscoveryAgent:**
  - **Purpose:** To synthesize parallel results and discover high-signal threat candidates.
  - **Inputs Used:** `baseline_result`, `known_signals_result`, `credential_noise_result`, `honeypot_specific_result`.
  - **Actions Taken:** Pivoted on high-count and unusual artifacts from the parallel results. Identified `BOT-01` (Next.js scanner), `BOT-02` (PHP exploits), and `ODD-01` (ICS probing).
  - **Key Results:** Produced three structured candidates, successfully separating them from background noise.
  - **Errors or Gaps:** Initial query for the placeholder CVE failed due to a data formatting issue.
- **CandidateValidationLoopAgent:**
  - **Purpose:** To iterate through candidates for validation.
  - **Actions Taken:** Loop was initiated but exited immediately as deep investigation was triggered by user request.
  - **Key Results:** N/A.
- **DeepInvestigationLoopController:**
  - **Purpose:** To conduct a deep-dive investigation on a selected candidate (BOT-02).
  - **Inputs Used:** Candidate `BOT-02` details.
  - **Actions Taken:** Ran one iteration on reflection candidate `REF-01`. Investigated source IPs `200.36.214.242` and `188.132.230.217`. Pivoted on the `libredtail-http` user agent.
  - **Key Results:** Confirmed both IPs were part of the same campaign, scanning for multiple vulnerabilities (PHP, Docker API) and using a shared user agent. Mapped the campaign to the "RedTail" cryptomining botnet.
  - **Errors or Gaps:** Internal tool queries for user agent aggregation failed multiple times, suggesting a tool or schema issue.
- **OSINTAgent:**
  - **Purpose:** To enrich internal findings with public threat intelligence.
  - **Inputs Used:** Candidate `BOT-02` and the term "RedTail".
  - **Actions Taken:** Performed a web search for `"RedTail cryptomining botnet" IOCs`.
  - **Key Results:** Successfully mapped BOT-02 to the RedTail botnet and retrieved additional IOCs, including filenames, IP addresses, and exploited CVEs.
  - **Errors or Gaps:** None.
- **ReportAgent (self):**
  - **Purpose:** To compile the final report.
  - **Inputs Used:** All available workflow state outputs.
  - **Actions Taken:** Assembled this report, noting the data replication failure as a critical evidence gap.
  - **Key Results:** This report.
  - **Errors or Gaps:** None.
- **SaveReportAgent:**
  - **Purpose:** To save the final report.
  - **Actions Taken:** Will be called downstream.
  - **Key Results:** Pending.