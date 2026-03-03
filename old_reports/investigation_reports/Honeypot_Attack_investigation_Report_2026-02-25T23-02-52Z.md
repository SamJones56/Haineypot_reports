# Zero-Day Candidate Triage Report

### 1. Investigation Scope
- **investigation_start**: 2026-02-25T22:30:08Z
- **investigation_end**: 2026-02-25T23:00:08Z
- **completion_status**: Partial (degraded evidence)

### 2. Candidate Discovery Summary
The investigation analyzed 3,612 events over a 30-minute window. Activity was dominated by high-volume SMB scanning from a single source and widespread brute-force attempts. A cluster of suspicious, un-signatured HTTP activity involving probes for PHP files was identified as the primary candidate for analysis (`CANDIDATE-001`). Other specialized honeypots (ADB, Redis, Conpot) recorded no activity.

### 3. Emerging n-day Exploitation
*No significant emerging n-day exploitation was identified in this window.*

### 4. Known-Exploit Exclusions
- **Commodity SMB Scanning**: 1,266 events targeting port 445 originated from a single IP (`103.227.94.102`). This activity is consistent with high-volume, automated scanning and was excluded as background noise.
- **SSH and VNC Brute-Force**: Standard scanning and credential-stuffing activity targeting ports 22 and 5902, correlated with generic signatures (`SURICATA SSH invalid banner`, `GPL INFO VNC server response`) and common usernames (`admin`, `root`). This was excluded as routine noise.

### 5. Novel Exploit Candidates
*No activity met the criteria for a novel exploit candidate after final validation.*

### 6. Suspicious Unmapped Activity to Monitor
- **CANDIDATE-001: Generic Web Vulnerability Scanning**
    - **Description**: An actor from IP `20.104.61.138` initiated a new scanning campaign, probing for a wide variety of simple and sequentially-named PHP files (e.g., `/1.php`, `/123.php`). This activity did not trigger any specific PHP-related signatures within the monitoring system. OSINT validation confirms the source IP has a 100% abuse score and the observed behavior is a well-established TTP for discovering misconfigurations or previously dropped webshells, rather than a novel exploit.
    - **Key Evidence**: 
        - Source IP: `20.104.61.138`
        - Target Port: 80 (HTTP)
        - Paths Probed: `/.well-known/acme-challenge/index.php`, `/000.php`, `/0x.php`, `/1.php`, `/123.php`, `/erty.php`, etc.

### 7. Infrastructure & Behavioral Classification
- **SMB Scanning Cluster**: High-volume, automated scanning from a single source (`103.227.94.102`) originating from a broadband provider in India (AS151130 - Skytech Broadband Private Limited).
- **PHP Scanning Cluster (CANDIDATE-001)**: Targeted web reconnaissance from a known malicious IP (`20.104.61.138`) hosted on Microsoft infrastructure in Canada (AS8075 - Microsoft Corporation). The behavior is consistent with the initial phase of a web application attack.

### 8. Analytical Assessment
The investigation successfully triaged inbound traffic, isolating routine background noise from a more targeted scanning campaign (`CANDIDATE-001`). This candidate was initially flagged as potentially novel due to its evasion of internal signatures. However, OSINT validation provided critical context, reclassifying the activity as a common, established reconnaissance TTP originating from a known malicious actor.

The final assessment is that no evidence of zero-day exploitation was found. The primary activity of interest is commodity malicious scanning. The investigation's ability to perform deep-dive analysis was degraded by backend data access issues, which prevented direct inspection of HTTP payloads for `CANDIDATE-001`. This constitutes an evidence gap but does not alter the final conclusion based on the available behavioral and OSINT data.

### 9. Confidence Breakdown
- **Commodity Activity Classification**: High
- **CANDIDATE-001 Re-classification (Post-OSINT)**: High
- **Overall Assessment**: Medium (Confidence is lowered from High to Medium due to the inability to inspect raw log data for `CANDIDATE-001`, which prevented a definitive check for novel payloads despite the known TTP).

### 10. Evidence Appendix
- **Item**: Commodity SMB Scanning
    - **source IPs with counts**: `103.227.94.102` (1266)
    - **ASNs with counts**: AS151130 - Skytech Broadband Private Limited (1266)
    - **target ports/services**: 445 (SMB)
    - **payload/artifact excerpts**: Not applicable (filtered as noise).
    - **previous-window / 24h checks**: Not performed.

- **Item**: CANDIDATE-001 (Generic Web Vulnerability Scanning)
    - **source IPs with counts**: `20.104.61.138` (526 in 24h, all recent)
    - **ASNs with counts**: AS8075 - Microsoft Corporation
    - **target ports/services**: 80 (HTTP)
    - **paths/endpoints**: `/`, `/.well-known/acme-challenge/index.php`, `/000.php`, `/0x.php`, `/1.php`, `/123.php`, `/155.php`, `/erty.php`
    - **payload/artifact excerpts**: Unavailable due to query failure.
    - **previous-window / 24h checks**: 0 events in the 30 minutes prior to the investigation window. 526 events total in the last 24 hours, confirming the activity is very recent.

### 11. Indicators of Interest
- `103.227.94.102` (IP): High-volume SMB scanner.
- `20.104.61.138` (IP): Known malicious actor performing web vulnerability reconnaissance.

### 12. Backend tool issues
- **two_level_terms_aggregated**: The tool failed to correlate source IPs with Tanner honeypot URI paths. This appears to be a data segmentation issue, preventing direct attribution of web requests to source IPs in a single query.
- **kibanna_discover_query**: The tool failed to retrieve raw logs for the `Tanner` honeypot type. This blocked the primary validation step of inspecting HTTP request headers and payloads for `CANDIDATE-001`.