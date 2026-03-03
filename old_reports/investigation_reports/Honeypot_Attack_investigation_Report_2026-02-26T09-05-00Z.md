# Zero-Day Candidate Triage Report

### 1. Investigation Scope
- **investigation_start**: 2026-02-26T08:30:09Z
- **investigation_end**: 2026-02-26T09:00:09Z
- **completion_status**: Complete

### 2. Candidate Discovery Summary
A total of 2,261 attacks were observed in the 30-minute window. The overwhelming majority of activity (1,618 events) was attributed to a high-volume DoublePulsar SMB exploit campaign originating from a single source. Low-volume, opportunistic scanning for known n-day vulnerabilities (CVE-2023-46604, CVE-2024-14007) and commodity credential stuffing comprised the remainder of the notable traffic. No novel exploit candidates were discovered.

### 3. Emerging n-day Exploitation
- **CVE-2023-46604 (Apache ActiveMQ RCE)**
  - **Description**: Two exploit attempts were observed targeting a known critical RCE in Apache ActiveMQ.
  - **Source**: Activity originated from a single source IP (193.26.115.178) targeting the standard ActiveMQ port (61616).
  - **Assessment**: Low-volume, opportunistic n-day scanning.

- **CVE-2024-14007 (Shenzhen TVT NVMS-9000 Auth Bypass)**
  - **Description**: A single exploit attempt was observed targeting a known authentication bypass vulnerability in DVR/NVR firmware.
  - **Source**: Activity originated from a single source IP (89.42.231.179).
  - **Assessment**: Low-volume, opportunistic n-day scanning.

### 4. Known-Exploit Exclusions
- **DoublePulsar SMB Exploit Campaign**: High-volume (1,618 events) activity from IP `197.255.224.193` targeting port 445, matching the `ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication` signature (ID 2024766). This is a well-known, automated campaign.
- **Commodity Credential Abuse**: Standard brute-force attempts using common usernames (`test`, `root`, `guest`) and passwords (`123456`).
- **Benign Redis Reconnaissance**: Cross-protocol HTTP requests (`GET / HTTP/1.1`) sent to Redis port 6379. This activity was mapped via its User-Agent (`visionheight.com/scan`) to a known cybersecurity vendor conducting internet-wide reconnaissance.
- **Commodity Web Scanning**: Generic scanning for common paths (`/`, `/favicon.ico`, `/solr/admin/info/system`) was observed and excluded as background noise.

### 5. Novel Exploit Candidates
None identified. All significant activity was successfully mapped to known exploits or scanning campaigns.

### 6. Suspicious Unmapped Activity to Monitor
None. The single item initially flagged for monitoring (`MON-001`, HTTP on Redis) was subsequently identified as benign scanning from a security vendor and moved to exclusions.

### 7. Infrastructure & Behavioral Classification
- **DoublePulsar Campaign**: Sourced from AS36939 (ComoresTelecom), this activity represents a large-scale, automated exploit campaign from a single, dedicated IP.
- **n-day CVE Scanning**: The scanning for CVE-2023-46604 and CVE-2024-14007 is characteristic of low-volume, opportunistic probes from disparate sources, typical of scanning that follows a public vulnerability disclosure.
- **Redis Scanning**: Sourced from AS16509 (Amazon.com, Inc.), this activity is classified as benign internet-wide reconnaissance by a known security vendor.

### 8. Analytical Assessment
The investigation completed successfully, with all automated data collection and analysis tools functioning as expected. The threat activity within this timeframe was dominated by a well-known, high-volume SMB exploit campaign (DoublePulsar). All other activity was low-volume and conclusively identified as either opportunistic n-day scanning or benign internet reconnaissance. There is no evidence to suggest any novel or zero-day exploitation occurred during this period.

### 9. Confidence Breakdown
- **Overall Confidence**: High. The workflow completed without errors, and all observed malicious activity was mapped with high confidence to existing signatures and known threat campaigns.
- **CVE-2023-46604**: High. Activity matched a specific Suricata signature for this CVE.
- **CVE-2024-14007**: High. Activity matched a specific Suricata signature for this CVE.

### 10. Evidence Appendix

**Item: CVE-2023-46604**
- **source IPs**: `193.26.115.178` (2)
- **ASNs**: Not available
- **target ports/services**: 61616 (ActiveMQ)
- **payload/artifact excerpts**: `ET EXPLOIT Apache ActiveMQ Remote Code Execution Attempt (CVE-2023-46604)`
- **previous-window / 24h checks**: Not available

**Item: CVE-2024-14007**
- **source IPs**: `89.42.231.179` (1)
- **ASNs**: Not available
- **target ports/services**: 6037
- **payload/artifact excerpts**: `ET WEB_SPECIFIC_APPS Shenzhen TVT NVMS-9000 Information Disclosure Attempt (CVE-2024-14007)`
- **previous-window / 24h checks**: Not available

**Item: DoublePulsar Campaign (Excluded)**
- **source IPs**: `197.255.224.193` (426)
- **ASNs**: `36939 - ComoresTelecom` (426)
- **target ports/services**: 445 (SMB)
- **payload/artifact excerpts**: `ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication`
- **previous-window / 24h checks**: Not available

### 11. Indicators of Interest
- **IP Address**: `197.255.224.193` (DoublePulsar Exploit Source)
- **IP Address**: `193.26.115.178` (CVE-2023-46604 Scanner)
- **IP Address**: `89.42.231.179` (CVE-2024-14007 Scanner)
- **Signature ID**: `2024766` (ET EXPLOIT DoublePulsar)

### 12. Backend tool issues
None. All backend tools and queries completed successfully.