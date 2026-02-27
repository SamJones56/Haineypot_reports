# Zero-Day Candidate Triage Report

### 1. Investigation Scope
- **investigation_start:** 2026-02-27T02:30:10Z
- **investigation_end:** 2026-02-27T03:00:10Z
- **completion_status:** Complete

### 2. Candidate Discovery Summary
The investigation analyzed 1,412 attacks within the 30-minute window. Initial discovery highlighted activity clusters related to a recently disclosed CVE (CVE-2024-14007), a suspicious web path (`/developmentserver/metadatauploader`), and heuristic-based RDP hunting alerts. All identified clusters were successfully investigated and dispositioned.

### 3. Emerging n-day Exploitation
- **CVE-2024-14007 (Shenzhen TVT NVMS-9000 Authentication Bypass)**
  - A single exploitation attempt was observed targeting a recently disclosed (November 2025) authentication bypass vulnerability in widely used DVR/NVR firmware.
  - The activity originated from an IP address engaged in broad, automated scanning, suggesting opportunistic rather than highly targeted exploitation.
  - The use of a known, recent exploit for information disclosure classifies this as a relevant emerging threat.

### 4. Known-Exploit Exclusions
- **CVE-2025-31324 (SAP NetWeaver RCE) Scanning**
  - **Reason:** Commodity scanning for a well-known critical vulnerability.
  - **Evidence:** A web request to `/developmentserver/metadatauploader` was validated and linked to CVE-2025-31324. The source IP (`40.119.41.94`) was confirmed to be a known scanner using the Zmap tool.

- **RDP Scanning on Non-Standard Ports**
  - **Reason:** Commodity scanning for open RDP services.
  - **Evidence:** Multiple `ET HUNTING RDP Authentication Bypass Attempt` alerts were triggered by a single source (`45.141.233.195`) across various non-standard ports. This activity was correlated with other RDP scanning signatures, confirming its nature as automated, opportunistic scanning.

- **Directory Traversal Scanning**
  - **Reason:** Common web vulnerability scanning.
  - **Evidence:** Alerts for `ET WEB_SERVER /etc/passwd Detected in URI` and honeypot logs for paths like `/..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd` were observed, representing low-sophistication, high-volume scanning noise.

### 5. Novel Exploit Candidates
No unmapped activity clusters were validated as novel exploit candidates in this investigation window. The primary candidate of interest was successfully mapped to commodity scanning for the known SAP vulnerability CVE-2025-31324.

### 6. Suspicious Unmapped Activity to Monitor
There was no suspicious, unmapped activity that warranted further monitoring from this period.

### 7. Infrastructure & Behavioral Classification
- **89.42.231.179 (AS206264 - Amarutu Technology Ltd):** Automated, opportunistic scanner observed exploiting the recent CVE-2024-14007 while also conducting broader, generic port scanning.
- **40.119.41.94:** Confirmed mass-scanner (Zmap) observed scanning for the critical SAP RCE vulnerability CVE-2025-31324.
- **45.141.233.195:** Automated scanner focused on identifying open RDP servers on a wide range of non-standard ports.
- **General Background Noise:** The period included significant levels of commodity SSH and VNC scanning from various sources, with DigitalOcean (AS14061) being a top source.

### 8. Analytical Assessment
The investigation was completed successfully. Analysis of sensor data identified one instance of emerging n-day exploitation (CVE-2024-14007) being tested in the wild by automated scanners. Other initially suspicious activities, including a unique web request and RDP hunting alerts, were confidently identified as commodity scanning for well-known vulnerabilities (CVE-2025-31324 and open RDP ports). No novel zero-day exploit candidates were found. Initial data query failures during the discovery phase were successfully bypassed during validation, allowing for a complete and confident analysis.

### 9. Confidence Breakdown
- **Overall Confidence:** High.
  - All identified candidates were fully validated using available logs and enriched with OSINT, leading to clear dispositions.
- **Per-item Confidence:**
  - **Emerging n-day (CVE-2024-14007):** High. Direct signature match for a recent CVE was confirmed with raw logs and OSINT.
  - **Known-Exploit Exclusions:** High. All excluded items were confidently mapped to well-understood, commodity scanning behaviors for known vulnerabilities.

### 10. Evidence Appendix
**Item: CVE-2024-14007 Exploitation**
- **source IPs:** `89.42.231.179` (1)
- **ASNs:** `206264 - Amarutu Technology Ltd` (1)
- **target ports/services:** 17000/tcp
- **paths/endpoints:** N/A (TCP-based exploit)
- **payload/artifact excerpts:** `<?xml version="1.0" encoding="UTF-8"?><request version="1.0" systemType="NVMS-9000" clientType="WEB" url="queryBasicCfg"/>`
- **staging indicators:** None observed.
- **previous-window / 24h checks:** Unavailable.

### 11. Indicators of Interest
- **IP:** `89.42.231.179` (Observed exploiting CVE-2024-14007)
- **IP:** `40.119.41.94` (Observed scanning for SAP RCE vulnerability CVE-2025-31324)
- **IP:** `45.141.233.195` (Observed scanning for RDP on non-standard ports)
- **URI Path:** `/developmentserver/metadatauploader` (Indicator for CVE-2025-31324 scanning)
- **CVE:** `CVE-2024-14007` (Shenzhen TVT NVMS-9000 Auth Bypass)
- **Signature:** `ET WEB_SPECIFIC_APPS Shenzhen TVT NVMS-9000 Information Disclosure Attempt (CVE-2024-14007)`

### 12. Backend tool issues
- The following queries failed during the initial discovery phase:
    - `kibanna_discover_query` for `http.uri.keyword:/developmentserver/metadatauploader`
    - `kibanna_discover_query` for `http.uri.keyword:/..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd`
- **Note:** These failures were successfully mitigated during the candidate validation phase using alternative queries (`web_path_samples`). The initial issues did not prevent a complete analysis or impact the final conclusions.