# Zero-Day Candidate Triage Report

### 1. Investigation Scope
- **investigation_start:** 2026-02-25T21:00:09Z
- **investigation_end:** 2026-02-25T21:30:09Z
- **completion_status:** Partial (degraded evidence)

### 2. Candidate Discovery Summary
The investigation began by examining two promising leads: a single alert count associated with CVE-2024-14007 and a web request to `/admin/config.php`. However, backend queries failed to retrieve evidence for either of these leads, preventing validation. The investigation pivoted to analyzing high-volume scanning activity, which resulted in the validation of nine source IPs as commodity threats. No novel exploit candidates were discovered.

### 3. Known-Exploit Exclusions
All activity identified and validated during this investigation window was classified as commodity scanning, reconnaissance, or brute-force noise.

- **Candidate ID:** `178.153.127.226`
  - **Classification:** Commodity SMB Scanning
  - **Summary:** High-volume (1048 events) scanning focused exclusively on port 445 (SMB) from an ISP in Qatar. The activity did not trigger specific threat signatures and is consistent with ambient reconnaissance noise.

- **Candidate IDs:** `47.91.20.0`, `47.91.20.137`, `143.198.159.153`, `129.212.180.3`
  - **Classification:** Commodity SSH Brute-Force
  - **Summary:** These IPs, primarily from Alibaba and DigitalOcean cloud infrastructure, conducted high-volume, automated SSH brute-force attempts. Honeypot logs captured failed login attempts and consistent use of the `SSH-2.0-Go` client, a common signature for automated scanners.

- **Candidate IDs:** `129.212.184.194`, `170.64.152.136`, `165.245.138.210`, `170.64.156.232`
  - **Classification:** Commodity VNC Scanning
  - **Summary:** These IPs, all hosted by DigitalOcean, were observed scanning for open VNC servers on ports 5900-5915. OSINT searches confirmed these IPs are either blacklisted or associated with known malicious infrastructure, including the Mirai botnet.

### 4. Novel Exploit Candidates
No unmapped activity meeting the criteria for a novel exploit candidate was validated during this investigation.

### 5. Infrastructure & Behavioral Classification
- **Ooredoo Q.S.C. (AS8781):** Source of high-volume, single-protocol (SMB) reconnaissance.
- **Alibaba (AS45102):** Source of automated SSH brute-force attempts.
- **DigitalOcean (AS14061):** Source of widespread SSH brute-force and VNC reconnaissance from multiple distinct IPs. OSINT confirms this infrastructure is a known source of malicious scanning, with several IPs explicitly blacklisted or linked to the Mirai botnet.

### 6. Analytical Assessment
This investigation was significantly degraded due to backend tool failures that prevented the analysis of the two most promising initial leads: an alert potentially related to CVE-2024-14007 and a suspicious web request. This constitutes a critical evidence gap.

The remaining observable activity within the timeframe consists entirely of widespread, low-complexity, and high-volume scanning and brute-force attempts. The behaviors, source infrastructure (major cloud providers), and specific artifacts (e.g., `SSH-2.0-Go` client) are all hallmarks of well-understood, commodity threats. OSINT validation confirms that several of the involved IPs and their network neighbors are publicly documented as malicious.

**Conclusion:** No evidence of novel zero-day exploitation was found. All validated activity is classified as known-exploit or commodity noise. However, this conclusion is provisional and carries reduced confidence due to the inability to investigate the initial, higher-quality signals.

### 7. Confidence Breakdown
- **Overall Investigation Confidence:** **Medium-Low**. The confidence is lowered due to the failure to retrieve data on the most significant initial leads, creating an un-analyzable evidence gap.
- **Confidence in Exclusions:** **High**. The evidence for the nine validated IPs being commodity noise is strong, consistent across multiple internal data sources, and corroborated by external OSINT.

### 8. Evidence Appendix

**Item: `178.153.127.226` (SMB Scanner)**
- **Source IPs:** `178.153.127.226` (1048 events)
- **ASNs:** AS8781 (Ooredoo Q.S.C.)
- **Target Ports/Services:** 445 (SMB)
- **Payload/Artifact Excerpts:** No specific alerts triggered; activity was sub-signature reconnaissance.
- **24h Checks:** Unavailable

**Item: `47.91.20.0` / `47.91.20.137` / `143.198.159.153` / `129.212.180.3` (SSH Brute-Force)**
- **Source IPs:** `47.91.20.0` (505), `47.91.20.137` (391), `143.198.159.153` (240), `129.212.180.3` (223)
- **ASNs:** AS45102 (Alibaba), AS14061 (DigitalOcean)
- **Target Ports/Services:** 22 (SSH)
- **Payload/Artifact Excerpts:**
  - Client: `SSH-2.0-Go`
  - Failed Logins: `sugi/sugi`, `appuser/appuser`, `root/1Q2W3E4R`, `hadoop/12345`, `test/password`, `test/12345678`
- **24h Checks:** Unavailable

**Item: `129.212.184.194` / `170.64.152.136` / `165.245.138.210` / `170.64.156.232` (VNC Scanners)**
- **Source IPs:** `129.212.184.194` (57), `170.64.152.136` (56), `165.245.138.210` (53), `170.64.156.232` (51)
- **ASNs:** AS14061 (DigitalOcean)
- **Target Ports/Services:** 5900, 5901, 5902, 5904, 5906, 5907, 5908, 5909, 5910, 5911, 5912, 5913, 5914, 5915 (VNC)
- **Payload/Artifact Excerpts:**
  - Suricata Signature: `GPL INFO VNC server response`
- **24h Checks:** Unavailable

### 9. Indicators of Interest
The following source IPs were validated as sources of commodity scanning and brute-force attacks and can be used for blocking or monitoring:
- `178.153.127.226`
- `47.91.20.0`
- `47.91.20.137`
- `143.198.159.153`
- `129.212.180.3`
- `129.212.184.194`
- `170.64.152.136`
- `165.245.138.210`
- `170.64.156.232`

### 10. Backend tool issues
The investigation was degraded by the following query failures, which created an evidence gap and prevented analysis of the highest-priority leads:
- **`suricata_lenient_phrase_search`**: Failed to find any events containing the phrase `CVE-2024-14007`, despite initial data suggesting one event existed.
- **`kibanna_discover_query`**: A broader query also failed to find any logs containing the value `CVE-2024-14007`.
- **`kibanna_discover_query`**: A query for the web path `/admin/config.php` returned zero results, despite honeypot data indicating one event occurred.