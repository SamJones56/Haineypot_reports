# Zero-Day Candidate Triage Report

### 1. Investigation Scope
- **investigation_start:** 2026-02-27T13:30:17Z
- **investigation_end:** 2026-02-27T14:00:18Z
- **completion_status:** Partial (degraded evidence)
- **Degradation Summary:** The investigation is marked as partial due to a backend tool failure during the validation phase. The `kibanna_discover_query` tool failed to retrieve raw event logs for the Conpot ICS honeypot, blocking a full analysis of the payloads and command sequences for the `ICS-Probing-Kamstrup` activity.

### 2. Candidate Discovery Summary
In the last 30 minutes, 2,405 attack events were analyzed. The activity was dominated by commodity scanning against VNC, SSH, and web services. Initial analysis identified two areas of interest: a broad web scanning campaign for various PHP files and low-volume, unmapped probing of an Industrial Control System (ICS) honeypot. No CVE-mapped activity was detected.

### 3. Known-Exploit Exclusions
- **Commodity VNC Scanning:** Widespread scanning activity (698 events) targeting VNC services, identified by the signature `GPL INFO VNC server response`. This is background reconnaissance noise.
- **SSH/RDP Scanning & Brute-Force:** Standard scanning and connection attempts against SSH and RDP-like services on standard and non-standard ports. This accounts for hundreds of common "noise" events.
- **Broad Web Vulnerability Scanning:** A significant scanning campaign was conducted by `20.220.196.236` (Microsoft Corporation, Canada). This actor made hundreds of requests for over 200 distinct, known PHP webshells and vulnerable paths, including `/ioxi.php` and `/wso.php`. OSINT validation confirmed these are well-documented backdoors. This activity is classified as non-targeted, commodity scanning.

### 4. Suspicious Unmapped Activity to Monitor
- **candidate_id:** ICS-Probing-Kamstrup
- **classification:** Suspicious Unmapped Monitor
- **novelty_score:** 4
- **confidence:** Low
- **key evidence:** Low-volume (56 events) of unmapped ICS activity targeting the Conpot honeypot. Probing used the proprietary Kamstrup smart meter protocol, with a specific non-public command identifier (`b'\\x01I20100'`) observed. Activity originated from multiple sources, including a known malicious scanner (`147.185.132.115`).
- **provisional flag:** **Provisional** - A backend tool failure blocked the retrieval of raw event data, preventing a full analysis of the session payloads and context.

### 5. Infrastructure & Behavioral Classification
- **`20.220.196.236` (ASN 8075, Microsoft Corporation):** Classified as a high-volume, indiscriminate web scanner. Its behavior consists of probing for a vast number of known PHP webshells and vulnerable files without targeting a specific technology.
- **`147.185.132.115` & `18.218.118.203`:** Classified as actors engaged in ICS reconnaissance. They were observed performing low-volume, unmapped probing against the Kamstrup smart meter protocol. OSINT confirms `147.185.132.115` is a known malicious scanner engaged in widespread campaigns.

### 6. Analytical Assessment
The investigation concluded that no validated novel exploit candidates were present in the analysis window. The predominant activity was attributable to background noise and known commodity scanning campaigns.

A single area of interest remains for monitoring: low-volume ICS probing activity targeting the Kamstrup protocol. While OSINT enrichment linked this activity to a known malicious scanner, reducing its novelty, a definitive classification was not possible due to a tool failure that prevents a full evidence drill-down. Therefore, this activity is flagged as a provisional, low-confidence item to monitor. The overall risk of an active zero-day exploitation event in this timeframe is assessed as low, with the caveat of incomplete evidence for the ICS activity.

### 7. Confidence Breakdown
- **Overall Confidence:** Medium-Low. The confidence is degraded by the tool failure that blocked complete validation of the most unusual signal (ICS probing).
- **ICS-Probing-Kamstrup:** Low. The `Provisional` status reflects the inability to analyze raw payloads. While context suggests reconnaissance, the exact intent and capability could not be fully determined.

### 8. Evidence Appendix
**Item: ICS-Probing-Kamstrup**
- **source IPs with counts:**
  - `18.218.118.203`: 33
  - `147.185.132.115`: 19
  - `45.141.233.195`: 2
  - `205.210.31.21`: 1
  - `205.210.31.227`: 1
- **ASNs with counts:** Unavailable from query results.
- **target ports/services:** Conpot (ICS Honeypot, Kamstrup Protocol)
- **paths/endpoints:** N/A (protocol-based)
- **payload/artifact excerpts:** `b'\\x01I20100'`
- **staging indicators:** None observed.
- **previous-window / 24h checks:** Unavailable.

### 9. Indicators of Interest
- **`147.185.132.115`** (IP): Known malicious scanner, observed conducting ICS reconnaissance.
- **`18.218.118.203`** (IP): Top source of unmapped Kamstrup protocol probing.
- **`20.220.196.236`** (IP): High-volume commodity web scanner.
- **`/ioxi.php`** (Path): Indicator of webshell scanning.

### 10. Backend tool issues
- **Tool Name:** `kibanna_discover_query`
- **Failure Details:** The tool failed to retrieve raw event logs during the validation of the `ICS-Probing-Kamstrup` candidate. The query for `type.keyword: Conpot` returned 0 results, directly contradicting aggregation tools that correctly identified 56 events in the same time window. This failure blocked the analysis of event payloads and prevented a definitive classification of the ICS activity.