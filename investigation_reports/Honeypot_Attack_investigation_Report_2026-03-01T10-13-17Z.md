# Investigation Report: Last 60 Minutes - Widespread Scanning & Reconnaissance Activity

**Timeframe:** 2026-03-01T09:06:06Z to 2026-03-01T10:06:06Z

## 1. Executive Summary

This investigation covers the last 60 minutes and reveals a high volume of attack activity, totaling 14,399 attacks. The primary activity appears to be widespread scanning and reconnaissance, originating predominantly from infrastructure hosted by DigitalOcean, LLC (ASN 14061).

Key findings include:
*   Significant commodity scanning for common services such as SSH (port 22), SMB (port 445), VNC/RDP-related ports (5902, 5925, 5926), and printer ports (9100).
*   Active attempts to locate and access sensitive `.env` configuration files on web applications.
*   Detection of "ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication" alerts, indicating a potential connection to known post-exploitation tooling used in major historical campaigns like WannaCry.
*   Credential brute-forcing attempts with common usernames and passwords.
*   Interaction with an Industrial Control System (ICS) protocol (guardian_ast) via a Conpot honeypot, suggesting targeted or opportunistic scanning of ICS environments.

Challenges were encountered in retrieving granular event details for specific alerts and correlating IPs due to recurring tool errors, which limited the depth of certain analyses.

## 2. Baseline Attack Overview

*   **Total Attacks:** 14,399
*   **Top Attacking Countries:**
    *   India: 4,308
    *   United States: 3,825
    *   Taiwan: 1,588
    *   Vietnam: 1,524
    *   Netherlands: 1,055
*   **Top Attacking Source IPs:**
    *   64.227.173.38: 4,058
    *   118.232.27.85: 1,534
    *   42.114.185.234: 1,403
    *   107.170.154.113: 804
    *   167.71.188.167: 560
*   **Top Attacking Autonomous System Numbers (ASNs):**
    *   ASN 14061 (DigitalOcean, LLC): 8,062 attacks
    *   ASN 38841 (kbro CO. Ltd.): 1,534 attacks
    *   ASN 18403 (FPT Telecom Company): 1,408 attacks
    *   ASN 263703 (VIGINET C.A): 514 attacks
    *   ASN 63949 (Akamai Connected Cloud): 343 attacks
*   **Common Targeted Ports by Country:**
    *   **India:** Port 22 (SSH - 860), 1433 (MS SQL - 11), 23 (Telnet - 1)
    *   **United States:** Port 9100 (Printer - 509), 22 (SSH - 351), 5926, 5925, 5902 (VNC/RDP related - 628 combined)
    *   **Taiwan:** Port 445 (SMB - 1,534), 22 (SSH - 10)
    *   **Vietnam:** Port 445 (SMB - 1,407), 22 (SSH - 10), 5902, 5903, 5904 (VNC/RDP related - 3 combined)
    *   **Netherlands:** Port 22 (SSH - 176), 80 (HTTP - 137), 8083 (Web - 8), 7443 (Web - 5), 3306 (MySQL - 4)

## 3. Known Signals and Alerts

*   **Top Alert Signatures:**
    *   **ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication (ID 2024766):** 1,862 counts. (Discussed further in Section 6.1)
    *   GPL INFO VNC server response (ID 2100560): 1,821 counts. (Likely commodity VNC scanning, see Section 6.3)
    *   SURICATA STREAM Packet with broken ack (ID 2210051): 853 counts. (Generic network noise, see Section 6.3)
    *   SURICATA IPv4 truncated packet (ID 2200003): 509 counts. (Generic network noise, see Section 6.3)
    *   SURICATA AF-PACKET truncated packet (ID 2200122): 509 counts. (Generic network noise, see Section 6.3)
*   **Common Vulnerabilities and Exposures (CVEs):**
    *   CVE-2006-2369: 29 counts. (Very old, likely commodity scanning/noise, see Section 6.3)
    *   CVE-2024-14007: 1 count. (Weak signal, inconclusive, see Section 8.1)
*   **Top Alert Categories:**
    *   Misc activity: 2,216 counts
    *   Generic Protocol Command Decode: 2,087 counts
    *   Attempted Administrator Privilege Gain: 1,896 counts
    *   Misc Attack: 344 counts
    *   Attempted Information Leak: 313 counts

## 4. Credential Noise

*   **Top Usernames Attempted:**
    *   guest (122), git (119), user (114), hadoop (75), admin (69), test (66), ftp (53), es (47), ec2-user (43), postgres (41)
*   **Top Passwords Attempted:**
    *   123456 (115), 123 (61), 12345678 (52), 1234 (48), 111111 (38), password (38), qwerty (33), 1q2w3e4r (29), 654321 (29), P@ssw0rd (27)
*   **Observed OS Distribution (from p0f):**
    *   Windows NT kernel: 9,292
    *   Linux 2.2.x-3.x: 8,152
    *   Windows 7 or 8: 3,807
    *   Linux 3.11 and newer: 566
    *   Linux 2.2.x-3.x (barebone): 387
    (This indicates a mix of Windows and Linux systems participating in the scanning/attack activity, reflecting typical internet-wide scanning sources.)

## 5. Honeypot Specific Activity

*   **Redis Honeypot:** 6 events, including 'Closed', 'NewConnect', and 'info' actions. (Low volume, no malicious commands observed, likely reconnaissance.)
*   **Adbhoney Honeypot:** 4 events, no specific inputs or malware samples captured.
*   **Conpot Honeypot (ICS):** 10 events, all related to the 'guardian_ast' protocol. (Discussed further in Section 7.1)
*   **Tanner Honeypot (Web Application):** 148 attempts to access `.env` related paths (e.g., `/.env`, `/.env.backup`, `/app/.env`). (Discussed further in Section 6.2)

## 6. Emerging / N-Day Exploitation & Known Exploit Analysis

### 6.1. Identified Threat: DoublePulsar Backdoor Installation Communication (ID 2024766)

*   **Classification:** Known Exploit (Malware Family)
*   **Summary:** The Suricata alert "ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication" (ID 2024766) was triggered 1,862 times. OSINT confirms DoublePulsar is a notorious kernel-mode backdoor developed by the NSA's Equation Group, leaked in 2017. It was infamously used with the EternalBlue exploit to target SMB vulnerabilities (TCP port 445) in campaigns like WannaCry.
*   **Evidence:** The high count of this signature (1,862) strongly correlates with baseline data showing significant scanning on port 445 (SMB) from Taiwan (1,534 counts) and Vietnam (1,407 counts), suggesting attempts to exploit SMB vulnerabilities or check for DoublePulsar presence.
*   **Confidence:** High
*   **Follow-up:** Attempt to correlate DoublePulsar alerts with specific source IPs from port 445 scanning data if possible with improved tools; investigate specific payloads if available.

### 6.2. Identified Threat: Web Application .env File Scanning (Tanner Honeypot)

*   **Classification:** Information Gathering / Scanner Tooling
*   **Summary:** Repeated attempts (135 total hits) were observed on the Tanner honeypot to access sensitive web application configuration files, specifically paths matching `*.env*`. Examples include `/.env`, `/app/.env`, `/web/.env`, `/shared/.env`, `/public/.env`, and various backup/development versions (`.env.backup`, `.env.dev`, etc.). This activity triggered the Suricata alert "ET INFO Request to Hidden Environment File - Inbound" (ID 2031502).
*   **Source IPs and ASNs:** The primary attackers were 89.248.168.239 (Netherlands, ASN 202425, IP Volume inc) and 78.153.140.149 (United Kingdom, ASN 202306, Hostglobal.plus Ltd).
*   **OSINT Findings:** OSINT confirms that scanning for `.env` files is a common information gathering technique to discover misconfigured web applications that inadvertently expose critical credentials (database, API keys, etc.). While not a direct exploit, successful access can lead to severe compromise. The Suricata signature indicates this is a recognized pattern of information gathering.
*   **Confidence:** High (confirmed widespread scanning for known sensitive files)
*   **Follow-up:** Monitor for successful exfiltration or follow-up exploitation attempts from identified source IPs; investigate if these IPs are associated with other known campaigns or threat actors.

### 6.3. Known Exploit Exclusions / Noise

*   **CVE-2006-2369:** 29 counts. This is a very old CVE, making it highly probable that these detections are simply noise from commodity scanning or outdated tooling rather than active, targeted exploitation.
*   **GPL INFO VNC server response (ID 2100560):** 1,821 counts. This indicates common VNC scanning activity, but no specific exploit or malicious interaction beyond the initial probing was detected.
*   **SURICATA Packet Anomalies (IDs 2210051, 2200003, 2200122):** These signatures (e.g., "Packet with broken ack", "IPv4 truncated packet") typically indicate generic network anomalies, packet fragmentation issues, or follow-up noise from other network events, rather than direct exploits.

## 7. Odd Service Minutiae Attacks

### 7.1. Conpot Guardian_AST Protocol Interaction

*   **Summary:** The Conpot honeypot recorded 10 events specifically related to the 'guardian_ast' protocol, which is associated with Industrial Control Systems (ICS).
*   **Why Unusual:** Interaction with an ICS protocol on a publicly exposed honeypot is uncommon for general internet scanning and could suggest targeted reconnaissance or opportunistic scanning for industrial control infrastructure.
*   **Confidence:** Medium (Activity is present but context is limited)
*   **Follow-up:** Investigate source IPs interacting with this protocol (e.g., 193.32.162.28 and 147.185.132.234 mentioned in earlier aggregations, though not directly linked to this specific event due to tool error); attempt to capture full session data if possible.

## 8. Suspicious Unmapped Monitor

### 8.1. CVE-2024-14007 Weak Signal

*   **Summary:** A single instance of CVE-2024-14007 was reported, targeting destination port 17001.
*   **Evidence Gaps:** There is extremely weak corroborating evidence; no associated source IPs were found, and attempts to retrieve raw event data were unsuccessful due to tool errors.
*   **Confidence:** Low
*   **Follow-up:** Monitor for future occurrences of this CVE. If more robust querying tools become available, re-investigate to gather more context.

## 9. Botnet / Campaign Mapping

### 9.1. DigitalOcean Widespread Scanning Campaign

*   **Campaign Shape:** Spray (widespread, indiscriminate scanning)
*   **Summary:** A high volume of attacks, totaling 8,062, originated from ASN 14061 (DigitalOcean, LLC). This infrastructure is frequently abused for commodity scanning.
*   **Infrastructure Indicators:**
    *   **Source IPs:** 64.227.173.38 (most frequent, 4,058 counts), 107.170.154.113, 167.71.188.167, 152.42.142.94, 146.190.229.77.
    *   **ASNs:** ASN 14061 (DigitalOcean, LLC) - 8,062 attacks. Also notable are ASN 38841 (kbro CO. Ltd.) with 1,534 attacks and ASN 18403 (FPT Telecom Company) with 1,408 attacks.
*   **Targeting:** Widespread targeting of common ports including SSH (22), SMB (445), VNC/RDP-related (5925, 5926, 5902), and printer ports (9100).
*   **Confidence:** High (clear indicators of large-scale, automated scanning)
*   **Follow-up:** Further analysis of specific targets and payloads from these IPs could reveal more about the intent and specific tooling if deeper data access becomes available.

## 10. Diagnostics and Limitations

*   **Evidence Gaps:**
    *   Unable to retrieve raw event data for "DoublePulsar" alerts, `.env` path attempts, or CVE-2024-14007 due to recurring `illegal_argument_exception` errors with the `kibanna_discover_query` tool.
    *   Inability to directly link specific source IPs to "DoublePulsar" alerts or "guardian_ast" protocol activity via `two_level_terms_aggregated` prevented more precise correlation.
    *   Specific payloads for `.env` requests are not available, limiting a deeper understanding of potential data exfiltration or follow-on commands.
*   **Failed Queries:**
    *   `kibanna_discover_query` for `alert.signature_id=2024766`
    *   `kibanna_discover_query` for `path.keyword=/.env`
    *   `kibanna_discover_query` for `alert.cve.keyword=CVE-2024-14007`
    *   `kibanna_discover_query` for `_all=/.env`
    *   `two_level_terms_aggregated` for `alert.signature_id -> src_ip.keyword`
    *   `two_level_terms_aggregated` for `alert.signature_id -> dest_port`
    *   `two_level_terms_aggregated` for `conpot.protocol.keyword -> src_ip.keyword`
*   **Blocked Validation Steps:**
    *   Detailed payload inspection for novel exploits.
    *   Precise source IP mapping for certain alerts and odd service interactions.
    *   Strong temporal checks due to difficulty in isolating specific event types for timeline comparison.

## 11. Conclusion and Recommendations

The past 60 minutes show a dynamic threat landscape characterized by extensive automated scanning and reconnaissance efforts. While many activities are indicative of commodity noise, the presence of DoublePulsar backdoor communications and systematic `.env` file scanning highlights more focused, potentially pre-exploitation, activity. The interaction with an ICS protocol on a honeypot warrants particular attention due to its sensitive nature.

**Recommendations:**

1.  **Enhance Monitoring for DoublePulsar:** Prioritize efforts to gain deeper visibility into events triggering the DoublePulsar signature, especially correlating with SMB (port 445) traffic, to identify specific compromised systems or persistent threats.
2.  **Bolster Web Application Security:** Implement strict access controls for sensitive configuration files like `.env`. Monitor web logs for frequent requests to these paths and consider using web application firewalls (WAFs) to block such reconnaissance attempts.
3.  **Investigate ICS Protocol Interactions:** Further investigate sources interacting with ICS protocols on honeypots to determine if this is targeted industrial espionage or broader, opportunistic scanning.
4.  **Improve Tooling for Granular Data:** Address the identified `illegal_argument_exception` errors with `kibanna_discover_query` and enhance aggregation capabilities to allow for more precise correlation of IPs, payloads, and timestamps with specific alert signatures and honeypot interactions. This will significantly improve the depth and accuracy of future investigations.
5.  **Monitor Top Attacking ASNs/IPs:** Continue to monitor activity from high-volume ASNs like DigitalOcean (ASN 14061) and their associated top IPs for any shift in tactics or more direct exploitation attempts.