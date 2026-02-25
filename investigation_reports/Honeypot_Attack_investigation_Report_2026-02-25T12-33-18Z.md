# Zero-Day Candidate Triage Report

### 1. Investigation Scope
- **investigation_start:** 2026-02-25T12:00:08Z
- **investigation_end:** 2026-02-25T12:30:09Z
- **completion_status:** Partial (degraded evidence)
- **Degradation Summary:** The investigation was significantly impaired by multiple query failures against the backend data store. Specifically, `fielddata` limitations on core text fields like `src_ip` and `http.url` prevented aggregations and direct correlation between source IPs and specific activity types. Furthermore, attempts to query raw event logs from the Tanner honeypot failed, blocking the validation of a potential candidate.

### 2. Candidate Discovery Summary
In the last 30-minute window, 2,761 attack events were observed. The activity was dominated by a high-volume (1,604 events) SMB exploit campaign from a single IP in Mozambique (`165.90.75.54`), which was confidently mapped to known DoublePulsar activity. A secondary, low-volume signal of web reconnaissance targeting sensitive files (`/.env`, `/bin/`) was identified but could not be fully validated due to the data access issues noted above.

### 3. Emerging n-day Exploitation
- **CVE-2024-14007**
  - **Classification:** Uncategorized
  - **Confidence:** Low
  - **Key Evidence:** Two events in the time window were tagged with `CVE-2024-14007`. Due to data aggregation, source IPs and target details for these specific events were not available. This activity warrants monitoring, but there is insufficient evidence for further assessment.

### 4. Known-Exploit Exclusions
- **DoublePulsar / EternalBlue Campaign**
  - **Classification:** Commodity Exploit Attempt
  - **Key Evidence:** A high volume of alerts for `ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication` (1,130 alerts) originating primarily from a single source (`165.90.75.54`) and targeting SMB (port 445).
  - **Exclusion Rationale:** This is a well-known, widely automated SMB exploit campaign that constitutes routine background noise.

### 5. Novel Exploit Candidates
*No unmapped activity met the criteria for a novel exploit candidate in this window.*

### 6. Suspicious Unmapped Activity to Monitor
- **candidate_id:** UM-HTTP-RECON-001
  - **classification:** Web Reconnaissance (Common Vulnerability Scanning)
  - **novelty_score:** 2
  - **confidence:** Low
  - **key_evidence:** Tanner honeypot detected low-volume, un-correlated HTTP requests for common sensitive paths: `/bin/` (5 hits), `/.env` (2 hits), and `/admin/config.php` (1 hit). OSINT confirms this pattern is highly indicative of generic web vulnerability scanners and not a targeted attack.
  - **provisional_flag:** True. Validation was blocked due to the inability to query the source Tanner honeypot logs to retrieve source IPs or other contextual data.

### 7. Infrastructure & Behavioral Classification
- **DoublePulsar Campaign:** Activity from `165.90.75.54` (ASN 37110, moztel-as) is classified as automated, high-volume scanning and exploitation against the SMB service.
- **Web Reconnaissance (UM-HTTP-RECON-001):** Behavior is consistent with generic, automated web vulnerability scanning tools probing for common application misconfigurations. The originating infrastructure is unknown due to evidence gaps.

### 8. Analytical Assessment
The threat landscape in this period was dominated by a known, high-volume commodity SMB exploit campaign, which was correctly triaged and excluded.

A secondary signal of unmapped web reconnaissance was identified but could not be validated. The investigation's ability to assess this activity was critically degraded by failures in the data pipeline, preventing direct queries against honeypot logs and correlation with other network events. OSINT analysis strongly suggests this unmapped activity is benign scanning noise.

Due to these evidence gaps, the overall assessment is that no *validated* novel threats were observed. The primary risk remains the potential for a threat to be missed due to the analytical blind spots identified during the workflow.

### 9. Confidence Breakdown
- **Overall Investigation Confidence:** Low. The inability to investigate or rule out suspicious activity due to query and data access failures reduces confidence in the completeness of the analysis.
- **CVE-2024-14007:** Low. The signal is based on only two events with no supporting context.
- **UM-HTTP-RECON-001:** Low. The signal is weak, unverified, and matches common, non-malicious scanning behavior.

### 10. Evidence Appendix

**Item: DoublePulsar Campaign**
- **source IPs with counts:**
  - `165.90.75.54`: 1604
- **ASNs with counts:**
  - `37110 (moztel-as)`: 1604
- **target ports/services:** 445 (SMB)
- **payload/artifact excerpts:**
  - Signature: `ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication`
- **24h checks:** Unavailable

**Item: Emerging n-day (CVE-2024-14007)**
- **source IPs with counts:** Unavailable
- **ASNs with counts:** Unavailable
- **target ports/services:** Unavailable
- **paths/endpoints:** Unavailable
- **payload/artifact excerpts:** None available
- **24h checks:** Unavailable

**Item: Suspicious Activity (UM-HTTP-RECON-001)**
- **source IPs with counts:** Unavailable (Validation Blocked)
- **ASNs with counts:** Unavailable
- **target ports/services:** 80 (HTTP) - Implied
- **paths/endpoints:**
  - `/bin/`: 5
  - `/.env`: 2
  - `/admin/config.php`: 1
- **payload/artifact excerpts:** None available
- **24h checks:** Unavailable

### 11. Indicators of Interest
- **IP Address:** `165.90.75.54` (Associated with commodity DoublePulsar scanning)
- **URL Paths:** `/.env`, `/bin/`, `/admin/config.php` (Associated with common web vulnerability scanning)