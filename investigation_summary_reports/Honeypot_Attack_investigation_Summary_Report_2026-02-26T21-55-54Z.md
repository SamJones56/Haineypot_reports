# Zero-Day Candidate Triage Final Report

### 1. Executive Summary
This investigation, covering the period 2026-02-26T14:30:12Z to 2026-02-26T15:00:13Z, successfully triaged several potential threats. No novel zero-day exploits were conclusively validated. However, two significant malicious activities were identified and detailed: active exploitation of CVE-2025-55182 by a DigitalOcean IP and targeted reconnaissance against Apache Druid by a Microsoft-associated IP. The known Androxgh0st botnet was also observed. Critical intelligence gaps remain due to persistent backend tool failures preventing full analysis of Adbhoney events.

### 2. Confirmed Malicious Activity

#### A. CVE-2025-55182 Exploitation
*   **CVE ID:** CVE-2025-55182 (React Server Components React2Shell Unsafe Flight Protocol Property Access)
*   **Source IP:** `68.183.3.211` (DigitalOcean, LLC)
*   **Target:** Web applications, specifically Next.js/React, on port `3001`.
*   **Activity:** 5 distinct exploitation attempts observed, targeting paths such as `/api/action`, `/action`, `/api/formaction`, `/_rsc`, and `/formaction`. The attacker also scanned other common web ports (`3000`, `8080`, `8081`, `8888`).
*   **Assessment:** This is a critical Remote Code Execution (RCE) vulnerability with publicly available Proof-of-Concept (POC) exploits. The observed activity indicates active exploitation in the wild. The source IP shows sustained scanning behavior beyond the specific CVE. The previous failure to correlate source IPs was overcome by using `suricata_cve_samples`.

#### B. Targeted Apache Druid Reconnaissance
*   **Source IP:** `40.67.161.44` (Microsoft Corporation; AS8075)
*   **Target:** Apache Druid instances, specifically requesting `/druid/index.html` on port `80`.
*   **Activity:** Low-volume, focused reconnaissance using the `zgrab` scanner (User-Agent: `Mozilla/5.0 zgrab/0.x`). P0f data classified the IP with "known attacker" reputation.
*   **Assessment:** This IP is associated with prior malicious activity (Redis honeypot attacks, GambleForce) and shows targeted interest in Apache Druid. While no exploit was detected, the focused reconnaissance from a known malicious entity warrants close monitoring.

#### C. Androxgh0st Botnet Activity
*   **Source IP:** `78.153.140.39` (Hostglobal.plus Ltd; AS202306)
*   **TTPs:** Reconnaissance for `/.env` files followed by POST requests containing the `androxgh0st` payload.
*   **Assessment:** Confirmed known malware activity for credential theft. While not novel, its presence highlights a potential gap in existing signature-based detections as it did not trigger internal signatures previously.

### 3. Intelligence Gaps & Tooling Failures
*   **Adbhoney Events:** Despite reports of 2 Adbhoney events, raw logs and malware samples (`adbhoney_malware_samples`, `adbhoney_input`, `match_query(type=Adbhoney)`) could not be retrieved due to persistent backend query failures. The nature of these reported malware samples remains unknown, representing a critical blind spot.
*   **CVE Source IP Correlation:** The initial `top_src_ips_for_cve` tool failed, but a workaround using `suricata_cve_samples` successfully identified the source IP for CVE-2025-55182.

### 4. Indicators of Compromise (IoCs)
*   **Source IPs:**
    *   `68.183.3.211` (CVE-2025-55182 Exploitation)
    *   `40.67.161.44` (Apache Druid Scanning, known malicious)
    *   `78.153.140.39` (Androxgh0st Botnet)
*   **Payload String:** `androxgh0st`
*   **HTTP Paths:**
    *   `/.env` (Androxgh0st reconnaissance)
    *   `/druid/index.html` (Apache Druid reconnaissance)
    *   `/api/action`, `/action`, `/api/formaction`, `/_rsc`, `/formaction` (CVE-2025-55182 targets)
*   **User-Agent:** `Mozilla/5.0 zgrab/0.x` (Associated with `40.67.161.44`)

### 5. Confidence Breakdown
*   **Overall Confidence:** **Medium-High**
    *   High confidence in identifying and detailing the CVE-2025-55182 exploitation and the Apache Druid scanning due to successful data retrieval and OSINT correlation. The reclassification of Androxgh0st is also high-confidence.
    *   Confidence is degraded by the complete lack of visibility into the Adbhoney events, meaning potential novel threats from that sensor could have been missed.

### 6. Recommendations
1.  **Prioritize Adbhoney Data Retrieval Fix:** Address the backend query failures for `Adbhoney` logs to enable full analysis of reported events and potential malware samples.
2.  **Enhance Detection for CVE-2025-55182:** Review existing signatures and implement new ones to specifically detect exploitation attempts against React Server Components on port `3001` from `68.183.3.211` and similar IPs.
3.  **Monitor `40.67.161.44`:** Implement enhanced monitoring for `40.67.161.44` and other IPs targeting Apache Druid, especially for requests beyond basic `index.html` or for exploit-specific payloads.
4.  **Review Androxgh0st Signatures:** Evaluate and update current detection rules for Androxgh0st activity, particularly for reconnaissance patterns like `GET /.env` which may precede the known `androxgh0st` payload.
