# Zero-Day Candidate Triage Report

### 1. Investigation Scope
- **investigation_start:** 2026-02-28T02:30:22Z
- **investigation_end:** 2026-02-28T03:00:23Z
- **completion_status:** Partial (degraded evidence)
  - *Note: Investigation was partially blocked by backend query failures, preventing a full assessment of CVE-related alerts and the scope of a web scanning campaign. See Section 12 for details.*

### 2. Candidate Discovery Summary
In the last 30 minutes, 1,889 attack events were recorded. The activity was dominated by high-volume, commodity scanning targeting VNC (874 events) and SSH (187+ events).

An initial candidate was identified involving an automated web scanner from `20.104.124.39` targeting specific PHP files. However, subsequent OSINT analysis mapped this activity to scanning for the well-known "Alfa-Shell" web shell, reclassifying it as known malicious activity rather than a novel exploit. Several low-volume CVE alerts were observed but could not be investigated due to data retrieval failures.

### 3. Known-Exploit Exclusions

- **Commodity VNC, SSH, and RDP Scanning:**
  - **Description:** Widespread, automated scanning and brute-force attempts targeting common remote access services.
  - **Key Evidence:** High-volume signatures including "GPL INFO VNC server response" (874 events), "SURICATA SSH invalid banner" (187 events), and "ET SCAN MS Terminal Server Traffic on Non-standard Port" (55 events).

- **"Alfa-Shell" Web Shell Scanning Campaign:**
  - **Description:** An automated web scanner was observed probing for specific PHP files. OSINT validation confirmed the primary indicator, `/alfa.php`, is a signature for scanners seeking the known "Alfa-Shell" post-exploitation tool.
  - **Key Evidence:** 151 requests from `20.104.124.39` to port 80 targeting paths including `/alfa.php`, `/cong.php`, `/rh.php`, and `/vx.php`.

- **Low-Volume Known CVE Alerts:**
  - **Description:** A small number of alerts for known vulnerabilities were detected.
  - **Key Evidence:** CVEs detected include `CVE-2024-14007` (2), `CVE-2019-11500` (1), and `CVE-2021-3449` (1). Analysis was blocked by query failures.

### 4. Novel Exploit Candidates (UNMAPPED ONLY, ranked)

The primary candidate identified during discovery (`CAND-20260228-001`) was reclassified as known activity based on OSINT findings that linked it to "Alfa-Shell" scanning.

**No novel exploit candidates were validated in this window.**

### 5. Suspicious Unmapped Activity to Monitor

- **Unverifiable CVE Alerts:**
  - **Description:** Low-volume alerts for `CVE-2024-14007` and an anomalous `CVE-2025-55182` were reported by an early-stage agent but could not be retrieved for deeper analysis due to backend query failures.
  - **Reason for Monitoring:** The inability to inspect these events creates an evidence gap. While likely background noise, this cannot be confirmed.

### 6. Infrastructure & Behavioral Classification

- **Web Shell Scanning (AS8075 - Microsoft Corporation):** The actor at `20.104.124.39` (Canada) is systematically probing web servers for a known malicious web shell ("Alfa-Shell").
- **VNC/SSH Scanning (AS210006, AS14061):** Multiple actors, including `45.87.249.170` (Seychelles), are engaged in broad, indiscriminate scanning of VNC and SSH ports, originating from various hosting providers like DigitalOcean.

### 7. Analytical Assessment
The activity within this 30-minute window consists almost entirely of commodity scanning and brute-force attacks. An initial candidate that appeared novel was de-escalated after OSINT analysis confirmed it was part of a known campaign to find existing web shell installations.

The final assessment is **degraded** due to significant evidence gaps. Multiple backend query failures prevented the validation of CVE-related alerts and a full determination of the scope of the web scanning campaign. While the visible evidence points to no novel threats, the uninspected events introduce uncertainty.

### 8. Confidence Breakdown

- **Overall Confidence:** Medium
  - Confidence in classifying the *observed* activity is high. However, the inability to retrieve specific, flagged events due to tool errors reduces the overall confidence that no novel threats were missed.

### 9. Evidence Appendix

**Item: Alfa-Shell Scanning (Formerly CAND-20260228-001)**
- **Source IPs:** `20.104.124.39` (count: 151)
- **ASNs:** `8075` (Microsoft Corporation) (count: 151+)
- **Target Ports/Services:** `80` (HTTP)
- **Paths/Endpoints:** `/alfa.php`, `/cong.php`, `/css.php`, `/.env`, `/rh.php`, `/vx.php`
- **Payload/Artifact Excerpts:**
  ```
  GET /rh.php HTTP/1.1
  Host: 167-71-255-16.cprapid.com
  
  GET /vx.php HTTP/1.1
  Host: 167-71-255-16.cprapid.com
  ```
- **Previous-window / 24h checks:** Unavailable

### 10. Indicators of Interest

- **IP Address:** `20.104.124.39` (Scanner for "Alfa-Shell")
- **File Paths:** `/alfa.php`, `/cong.php`, `/rh.php`, `/vx.php` (Indicators of web shell scanning)

### 11. Backend tool issues
The investigation was degraded by the following tool and data query failures:
- **Tool:** `two_level_terms_aggregated`
  - **Issue:** The query failed when attempting to aggregate on `http.url` and `http.url.keyword` fields due to an index configuration error (`fielddata is disabled`). This prevented the identification of other source IPs participating in the web shell scanning campaign.
- **Tool:** `match_query`
  - **Issue:** Failed to retrieve the single event record associated with the anomalous `CVE-2025-55182`, preventing any analysis of this lead.
- **Tool:** `top_src_ips_for_cve`
  - **Issue:** Failed to retrieve event records for `CVE-2024-14007`, preventing analysis of this potential emerging n-day activity.