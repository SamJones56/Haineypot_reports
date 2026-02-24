
**INVESTIGATION REPORT**

**Case ID:** 20260222-1615-MINUTIA
**Date of Investigation:** 2026-02-22
**Investigation Window:** 2026-02-22T12:15:24Z to 2026-02-22T16:15:24Z (4 hours)
**Investigator:** Senior Cyber Threat Investigator

**Objective:**
To identify, analyze, and report on low-frequency, high-interest attack vectors ("minutia attacks") observed within the honeypot network, distinguishing them from high-volume, automated scanning activity.

**Executive Summary:**
During the 4-hour investigation window, a total of 17,813 malicious events were recorded. While the majority of this traffic consisted of automated scanning from a small number of source IPs targeting common vulnerabilities and services (e.g., VNC, SSH, DoublePulsar), a deeper analysis of low-frequency events revealed several sophisticated and targeted attack vectors. These include specific probes for vulnerabilities in Industrial Control Systems (ICS) hardware, developer tools, and a critical remote code execution vulnerability in email server software. These findings indicate the presence of actors engaged in more targeted reconnaissance than is typically observed in mass-scanning campaigns. Pivoting from these leads to specific actor details was hampered by data retrieval discrepancies between aggregation and event-level query tools. However, the nature of the observed probes provides valuable insight into emerging or niche threats.

**Baseline Activity Analysis:**
A baseline of "background noise" was established to differentiate unusual activity.
- **Total Events:** 17,813
- **High-Frequency Source IPs:** A small number of IPs, such as `200.105.151.2` (1,805 events) and `45.10.175.246` (1,246 events), were responsible for a disproportionate amount of traffic.
- **Common Alert Signatures:** The most frequent alerts were related to well-known exploits and services, including "ET EXPLOIT [PTsecurity] DoublePulsar Backdoor" (1,297 events), "GPL INFO VNC server response" (894 events), and various SSH-related alerts. This activity is consistent with automated, non-targeted scanning campaigns.

**Key Investigative Leads & Findings:**

Despite the high volume of automated traffic, several low-frequency events were identified that indicate more specific and potentially sophisticated actor intent.

**1. Targeted Probing for Industrial Control Systems (ICS):**
- **Observation:** Analysis of web honeypot (Tanner) traffic revealed two requests for the URI `/portal/redlion`.
- **Analysis:** Red Lion Controls is a prominent manufacturer of industrial automation and networking hardware, including Human-Machine Interfaces (HMIs). A probe for this specific path is a strong indicator of an actor conducting reconnaissance for vulnerabilities in Red Lion's web-based management portals. This type of targeted scanning for ICS equipment is a significant finding, as a successful compromise could impact industrial processes.
- **Confidence:** High

**2. Probing for Misconfigured Developer Tools:**
- **Observation:** Two requests were observed for the URI `/?XDEBUG_SESSION_START=phpstorm`.
- **Analysis:** XDEBUG is a PHP extension for debugging. This query signature is a known method for detecting and potentially exploiting a publicly exposed XDEBUG listener, which can lead to session hijacking or remote code execution. This indicates an actor is targeting not just production services, but also potentially misconfigured development environments.
- **Confidence:** High

**3. Low-Frequency, High-Severity Vulnerability Scanning:**
- **Observation:** A low number of exploitation attempts (7 events) were recorded for `CVE-2019-11500`.
- **Analysis:** OSINT confirms CVE-2019-11500 is a critical (CVSS 9.8) unauthenticated remote code execution vulnerability in the Dovecot IMAP/POP3 server. While the volume is low, the specificity and severity of the vulnerability being scanned for are high. This demonstrates a level of targeting beyond generic vulnerability scanning and indicates a focus on high-impact mail server software.
- **Confidence:** Moderate (The specific event logs could not be retrieved, but the aggregated data is clear).

**4. Reconnaissance of Specialized Services (ICS & Android):**
- **Observation:** Connections were registered against specialized honeypots emulating ICS protocols (Conpot, 8 events) and the Android Debug Bridge (Adbhoney, 18 events).
- **Analysis:** Although specific commands were not successfully aggregated, the recorded connections to these non-standard services confirm that actors are actively seeking them out. This represents a deviation from typical scans for SSH, VNC, or RDP and points to actor interest in IoT, mobile, and industrial targets.
- **Confidence:** Moderate

**Challenges and Limitations:**
A significant challenge during this investigation was the inability to retrieve specific event logs corresponding to leads identified through aggregation queries. Multiple attempts to query for events related to CVE-2019-11500 and the `/portal/redlion` URI using various search tools (`kibanna_discover_query`, `custom_basic_search`, `suricata_lenient_phrase_search`) returned zero results, despite their clear presence in aggregated data (`get_cve`, `tanner_unifrom_resource_search`). This prevented the identification and further analysis of the specific actors responsible for these targeted probes.

**Conclusion:**
The 4-hour period of activity, while dominated by opportunistic mass-scanning, contained clear and significant evidence of more targeted and nuanced threat activity. The key takeaway is the presence of actors conducting specific reconnaissance for high-value targets, including ICS infrastructure, misconfigured developer tools, and critical vulnerabilities in mail servers.

While the inability to pivot to specific actor IPs limits the scope of this particular investigation, the detection of these "minutia" attack vectors themselves serves as a valuable intelligence finding. It confirms that a small but significant portion of malicious traffic is highly targeted and poses a more sophisticated threat than the high-volume background noise.
