## Honeypot Attack Research Report - Suspicious Activity (Zero-Day Hunt)

**Report Generation Time:** 2026-02-20T21:37:20Z
**Timeframe:** 2026-02-20T21:24:17Z to 2026-02-20T21:37:20Z (Past 10 minutes)

**List of Files Used to Generate the Report:**
*   `default_api.get_current_time()`
*   `default_api.get_total_attacks()`
*   `default_api.get_top_countries()`
*   `default_api.get_alert_category()`
*   `default_api.get_attacker_src_ip()`
*   `default_api.get_src_ip_reputation()`
*   `default_api.search_agent()` (for OSINT context)
*   `default_api.get_attacker_asn()`
*   `default_api.get_alert_signature()`
*   `default_api.get_input_usernames()`
*   `default_api.get_input_passwords()`
*   `default_api.conpot_input()`
*   `default_api.adbhoney_input()`
*   `default_api.adbhoney_malware_samples()`
*   `default_api.tanner_unifrom_resource_search()`

---

### **1. Executive Summary**

This report details suspicious activity observed across the honeypot network during a collaborative zero-day hunt over the past 10 minutes (2026-02-20T21:24:17Z to 2026-02-20T21:37:20Z). A significant volume of attacks were detected, primarily originating from Paraguay, with a strong focus on VNC and SSH services. A critical finding is the active probing for unauthenticated VNC servers, which could indicate attempts to exploit configuration weaknesses rather than a novel zero-day vulnerability. Widespread brute-force attacks against SSH and general network scanning were also prominent. Specialized honeypots such as Conpot, Adbhoney, and Tanner showed minimal to no direct interaction.

---

### **2. Attack Overview**

**2.1. Total Attacks:**
During the specified timeframe, a total of **2078 attacks** were recorded across the honeypot network.

**2.2. Top Attacking Countries:**
The attacks originated predominantly from the following countries:
*   **Paraguay**: 1595 attacks
*   **United States**: 206 attacks
*   **Germany**: 94 attacks
*   **Australia**: 65 attacks
*   **Latvia**: 54 attacks

**2.3. Top Alert Categories:**
The most frequent alert categories observed were:
*   **Generic Protocol Command Decode**: 127 instances
*   **Misc activity**: 78 instances
*   **Misc Attack**: 63 instances
*   **Attempted Information Leak**: 10 instances

---

### **3. Attacker Identification and OSINT**

**3.1. Attacker Source IPs and Reputation:**
The most active source IPs involved in the attacks were:
*   **45.175.157.3**: 1628 attacks
*   178.20.210.32: 100 attacks
*   134.199.171.153: 68 attacks
*   86.54.24.29: 54 attacks
*   185.242.226.45: 40 attacks

Notably, **332 instances** of source IPs were identified with a "known attacker" reputation, indicating that a significant portion of the observed activity stems from previously identified malicious entities.

**3.2. Attacker Autonomous System Numbers (ASN):**
Further OSINT investigation into the ASNs of the attacking IPs revealed:
*   **ASN: 267837, Organization: Vicente Sosa Peralta**: This organization is associated with the most active IP (45.175.157.3) and accounts for 1628 attacks, confirming its role as a major origin point for the observed malicious traffic, likely an ISP or hosting provider in Paraguay.
*   ASN: 14061, Organization: DigitalOcean, LLC: 119 attacks, indicating potential abuse of cloud hosting infrastructure.
*   ASN: 210006, Organization: Shereverov Marat Ahmedovich: 100 attacks.
*   ASN: 396982, Organization: Google LLC: 32 attacks, suggesting possible compromised services or instances within Google's network.

---

### **4. Detailed Attack Analysis**

**4.1. Alert Signatures - Nature of Attacks:**
An analysis of the specific alert signatures provides granular detail on the attack types:

*   **VNC Exploitation Attempts:**
    *   `GPL INFO VNC server response` (46 counts): Frequent VNC server enumeration.
    *   `ET EXPLOIT VNC Server Not Requiring Authentication (case 2)` (1 count): **This is a critical finding, indicating active probing for VNC servers configured without authentication, a severe security misconfiguration that could be exploited.**
    *   `ET INFO VNC Authentication Failure` (1 count): Failed attempts to authenticate to VNC.

*   **SSH Brute-Force and Scanning:**
    *   `SURICATA SSH invalid banner` (35 counts): Attackers presenting malformed SSH banners, likely for fingerprinting or evasion.
    *   `ET INFO SSH session in progress on Unusual Port` (18 counts) and `ET INFO SSH session in progress on Expected Port` (12 counts): Indications of active SSH probing and connection attempts.

*   **Network Reconnaissance:**
    *   `SURICATA IPv4 truncated packet` (40 counts) and `SURICATA AF-PACKET truncated packet` (40 counts): Common during network scanning or malformed packet generation.
    *   `ET SCAN NMAP -sS window 1024` (8 counts): Explicit NMAP scanning activity.

*   **Reputation-Based Blocks:**
    *   `ET DROP Dshield Block Listed Source` and `ET DROP Spamhaus DROP Listed Traffic`: Confirm traffic from known malicious sources.
    *   `ET CINS Active Threat Intelligence Poor Reputation IP group`: Further reinforces attacks from blacklisted IPs.

**4.2. Attempted Credentials:**
Analysis of input usernames and passwords indicates widespread brute-force activity:
*   **Usernames:** `root` was overwhelmingly the most common attempted username (331 counts), followed by `user` (13 counts) and `admin` (5 counts).
*   **Passwords:** Extremely weak passwords such as `1234`, `admin`, `dietpi`, and `password` were attempted multiple times.

**4.3. Honeypot Specific Activity:**
*   **Conpot (Industrial Control System Honeypot):** No input commands were captured, suggesting no direct interaction or successful compromise of ICS emulations.
*   **Adbhoney (Android Debug Bridge Honeypot):** Minimal activity was observed, with no aggregated command inputs or malware samples, indicating it was not a primary target during this period.
*   **Tanner (Web Honeypot):** No URI requests were captured, suggesting an absence of significant web-based attacks.

---

### **5. Conclusion and Recommendations**

While a specific "zero-day" vulnerability exploitation was not definitively identified, the investigation highlights aggressive and automated attack campaigns targeting exposed services. The most concerning finding for a zero-day hunt is the active scanning and exploitation attempt for **unauthenticated VNC servers**. This represents a critical configuration vulnerability that attackers are actively seeking to leverage.

**Recommendations:**
1.  **VNC Security Audit:** Immediately identify and secure all VNC servers to ensure they require strong authentication. Disable VNC access from the internet if not absolutely necessary.
2.  **SSH Hardening:** Implement strong password policies, multi-factor authentication, and consider disabling root login via SSH. Regularly review SSH logs for brute-force attempts.
3.  **IP Blocking:** Continue to monitor and block IPs identified as "known attackers," especially those from high-volume origins like ASN 267837 (Vicente Sosa Peralta).
4.  **Honeypot Monitoring:** Maintain vigilance over honeypot logs, especially for VNC and SSH related events, to detect any shifts in attack methodologies or newly exploited vulnerabilities.
5.  **Intelligence Sharing:** Share findings regarding the VNC exploitation attempts with relevant security communities to raise awareness.

This report provides a snapshot of current suspicious activity. Continuous monitoring and in-depth analysis are crucial for identifying and mitigating emerging threats.