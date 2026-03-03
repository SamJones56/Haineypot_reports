# Zero-Day Candidate Triage Report

### 1. Investigation Scope
- **investigation_start**: 2026-02-27T09:30:20Z
- **investigation_end**: 2026-02-27T10:00:29Z
- **completion_status**: Partial (degraded evidence)
    - **Note**: The investigation was significantly impaired by backend query failures, which prevented the retrieval of source IPs and raw event data for a detected CVE. This blocked full validation and analysis of that activity.

### 2. Candidate Discovery Summary
In the last 30 minutes, 3,412 attacks were recorded. The majority consisted of commodity scanning and brute-force activity against SSH and VNC services. Two specific activities of interest were isolated:
1.  A known malware scanner (AndroxGh0st) targeting web servers for `.env` files.
2.  A single alert for CVE-2024-14007, targeting an uncommon TCP port (6036).

No novel exploit candidates were discovered.

### 3. Emerging n-day Exploitation
- **id**: CVE-2024-14007-ACTIVITY-001
- **classification**: Scanning for known vulnerability (CVE-2024-14007)
- **description**: A single alert was observed for CVE-2024-14007, a critical authentication bypass in NVMS-9000 firmware for video surveillance equipment. OSINT analysis confirmed the targeted port (6036) is the default control port for this vulnerable service. The activity is consistent with scanning for this recently disclosed vulnerability.
- **confidence**: High (in classification), Very Low (in evidence completeness)
- **provisional_flag**: True. Full analysis was blocked by multiple query failures, preventing identification of the source or payload.

### 4. Known-Exploit Exclusions
- **id**: KNOWN-SCANNER-ANDROXGH0ST-001
- **classification**: Commodity Malware Scanner
- **description**: Activity from source IP `78.153.140.39` was identified as the AndroxGh0st malware. The behavior included a GET request for `/.env` followed by a POST request containing the malware's signature payload, `androxgh0st`. This is well-documented, automated scanning activity.
- **confidence**: High

### 5. Novel Exploit Candidates
No unmapped activity meeting the criteria for a novel exploit candidate was identified during this investigation period.

### 7. Infrastructure & Behavioral Classification
- **CVE-2024-14007 Activity**:
    - **Infrastructure**: Source IP and ASN are unknown due to data retrieval failures.
    - **Behavior**: Targeted scanning for a specific, recently disclosed critical vulnerability (CVE-2024-14007) on its known default service port (6036).
- **AndroxGh0st Scanner**:
    - **Infrastructure**: Sourced from `78.153.140.39` (AS202306, Hostglobal.plus Ltd, GB).
    - **Behavior**: Automated, opportunistic scanning for exposed `.env` files, consistent with the AndroxGh0st malware campaign.

### 8. Analytical Assessment
The investigation successfully filtered out background noise and identified and excluded one known commodity scanner (AndroxGh0st).

A second activity, scanning for the recent and critical CVE-2024-14007, was also identified. OSINT validation confirmed the nature of this n-day threat. However, a critical visibility gap, caused by multiple backend tool failures, prevented any further analysis. The inability to retrieve the source IP, raw alert, or associated payload for this event means that while the *what* is known, the *who* and *how* remain unanswered.

**Conclusion**: No novel zero-day candidates were found. The primary finding is the observation of emerging n-day exploitation activity (CVE-2024-14007) that could not be fully triaged due to significant evidence gaps caused by tool failures. Addressing the backend query issues is the highest priority follow-up action.

### 9. Confidence Breakdown
- **Overall Investigation Confidence**: **Low**. While classification of observed events was possible, the failure to retrieve crucial evidence for a critical CVE alert severely degrades confidence in the investigation's completeness.
- **CVE-2024-14007-ACTIVITY-001**:
    - **Classification Confidence**: High
    - **Evidence Completeness Confidence**: Very Low
- **KNOWN-SCANNER-ANDROXGH0ST-001**:
    - **Classification Confidence**: High
    - **Evidence Completeness Confidence**: High

### 10. Evidence Appendix
**Item: CVE-2024-14007-ACTIVITY-001**
- **source IPs with counts**: Unavailable (Query Failed)
- **ASNs with counts**: Unavailable (Query Failed)
- **target ports/services**: 6036 (TCP)
- **paths/endpoints**: N/A
- **payload/artifact excerpts**: Unavailable (Query Failed)
- **staging indicators**: None observed
- **previous-window / 24h checks**: Unavailable

**Item: KNOWN-SCANNER-ANDROXGH0ST-001**
- **source IPs with counts**: 78.153.140.39 (2)
- **ASNs with counts**: AS202306 - Hostglobal.plus Ltd (1)
- **target ports/services**: 80 (HTTP)
- **paths/endpoints**: `/.env`, `/`
- **payload/artifact excerpts**: `post_data: {'0x[]': 'androxgh0st'}`
- **staging indicators**: None observed
- **previous-window / 24h checks**: Unavailable

### 11. Indicators of Interest
- **IP Address**: `78.153.140.39` (AndroxGh0st Scanner)
- **Payload/User-Agent**: `androxgh0st` in HTTP POST body
- **CVE**: `CVE-2024-14007`
- **Destination Port**: `6036`

### 12. Backend tool issues
- **suricata_lenient_phrase_search**: Failed with a parsing error: `[match_phrase] requires fieldName`.
- **top_src_ips_for_cve**: Failed to return any source IPs for CVE-2024-14007 despite a corresponding alert existing.
- **kibanna_discover_query**: Failed to retrieve raw event logs when querying for `alert.cve: "CVE-2024-14007"`.
- **Impact**: These failures created a critical visibility gap, making it impossible to perform a full analysis of the observed n-day exploitation activity.