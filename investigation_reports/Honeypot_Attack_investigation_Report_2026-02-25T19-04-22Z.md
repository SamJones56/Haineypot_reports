# Zero-Day Candidate Triage Report

### 1. Investigation Scope
- **investigation_start:** 2026-02-25T18:30:07Z
- **investigation_end:** 2026-02-25T19:00:08Z
- **completion_status:** Complete

### 2. Candidate Discovery Summary
In the 30-minute window, 1,657 attack events were observed, primarily originating from the United States, Australia, and Romania. The dominant activity consisted of generic scanning and TCP stream anomalies. One specific pattern of interest was identified: HTTP requests targeting the `/actuator/gateway/routes` path, which was promoted for detailed validation.

### 3. Emerging n-day Exploitation
- **CVE-2022-22947 Reconnaissance (Spring Cloud Gateway RCE)**
    - **Classification:** Pre-Exploit Reconnaissance
    - **Description:** Activity from a single source IP was observed exclusively targeting the `/actuator/gateway/routes` endpoint. This path is a well-known indicator for CVE-2022-22947, a critical Remote Code Execution vulnerability in Spring Cloud Gateway. The observed GET requests are consistent with initial reconnaissance to identify vulnerable systems before attempting exploitation (which typically involves a POST request). This activity is notable as it was not flagged by any existing high-fidelity signatures in the system.

### 4. Known-Exploit Exclusions
- **Commodity Scanning:** Widespread scanning for common services like SSH, VNC, and RDP was observed and excluded as background noise. Signatures such as `GPL INFO VNC server response` and `ET SCAN MS Terminal Server Traffic on Non-standard Port` were indicative of this activity.
- **CVE-2006-2369:** A single alert for this obsolete (2006) vulnerability was observed and dismissed as noise.
- **Network Noise:** A high volume of TCP stream anomaly alerts (e.g., `SURICATA STREAM 3way handshake...`) were filtered out as non-specific network-level events.

### 5. Novel Exploit Candidates (UNMAPPED ONLY, ranked)
No unmapped novel exploit candidates were validated in this investigation period. The single candidate of interest was mapped to a known n-day vulnerability.

### 6. Suspicious Unmapped Activity to Monitor
No items met the criteria for this category.

### 7. Infrastructure & Behavioral Classification
- **CVE-2022-22947 Reconnaissance Actor:**
    - The actor (`79.124.40.174` / ASN 50360) exhibited highly targeted behavior, focusing exclusively on a single URI path known to be associated with a critical vulnerability. This indicates intentional reconnaissance rather than opportunistic scanning.
- **General Background Noise:**
    - The bulk of the low-value scanning and brute-force activity originated from major cloud and hosting providers (DigitalOcean, Akamai, UCLOUD), which is typical for internet-wide background noise.

### 8. Analytical Assessment
The investigation completed successfully. The primary finding is the identification of active, targeted reconnaissance for CVE-2022-22947, a critical Spring Cloud Gateway RCE vulnerability. Although the full exploit was not observed, the high specificity of the probes provides a clear and actionable indicator of attacker intent. This activity is currently bypassing existing signature-based detection rules, highlighting a potential gap in coverage for emerging n-day threats. The remaining observed activity is low-priority background noise consistent with normal operations.

### 9. Confidence Breakdown
- **CVE-2022-22947 Reconnaissance:** High (10/10). The targeted URI is a definitive indicator for this specific vulnerability, and the actor's exclusive focus on this path removes ambiguity.
- **Overall Assessment Confidence:** High. The primary finding is well-supported by direct evidence from multiple data sources.

### 10. Evidence Appendix
- **Item: CVE-2022-22947 Reconnaissance**
    - **source IPs with counts:**
        - `79.124.40.174`: 23 events
    - **ASNs with counts:**
        - ASN 50360 (Tamatiya EOOD): 23 events
    - **target ports/services:**
        - 80/HTTP
    - **paths/endpoints:**
        - `/actuator/gateway/routes`
    - **payload/artifact excerpts:**
        - **HTTP Method:** `GET`
        - **User-Agent:** `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/78.0.3904.108 Safari/537.36`
    - **staging indicators:**
        - None observed.
    - **previous-window / 24h checks:**
        - Unavailable.

### 11. Indicators of Interest
- **Source IP:** `79.124.40.174`
- **ASN:** `50360`
- **HTTP Path:** `/actuator/gateway/routes`
- **User Agent:** `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/78.0.3904.108 Safari/537.36`

### 12. Backend tool issues
- **two_level_terms_aggregated:** The tool's output was not granular enough to isolate the HTTP methods for the specific target URL. This was a minor limitation and was mitigated by analyzing the raw event data, which confirmed the use of GET requests.