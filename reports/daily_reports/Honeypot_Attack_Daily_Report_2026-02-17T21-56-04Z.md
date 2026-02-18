**Daily Honeypot Attack Summary Report - 2026-02-17T21-53-33Z**
**Timeframe:** Last 24 hours (2026-02-16T21:53:33Z to 2026-02-17T21:53:33Z)
**Report Generation Time:** 2026-02-17T21-53-33Z

**Files Used to Generate the Report:**
*   /home/user/Haineypot/reports/hourly_reports/Honeypot_Attack_Hourly_Report_2026-02-17T06-01-25Z.md
*   /home/user/Haineypot/reports/hourly_reports/Honeypot_Attack_Hourly_Report_2026-02-17T11-01-24Z.md
*   /home/user/Haineypot/reports/hourly_reports/Honeypot_Attack_Hourly_Report_2026-02-17T12-02-31Z.md
*   /home/user/Haineypot/reports/hourly_reports/Honeypot_Attack_Hourly_Report_2026-02-17T14-01-51Z.md
*   /home/user/Haineypot/reports/hourly_reports/Honeypot_Attack_Hourly_Report_2026-02-17T15-30-20Z.md
*   /home/user/Haineypot/reports/hourly_reports/Honeypot_Attack_Hourly_Report_2026-02-17T16-01-53Z.md
*   /home/user/Haineypot/reports/hourly_reports/Honeypot_Attack_Hourly_Report_2026-02-17T20-52-47Z.md

---

**Executive Summary**

The honeypot network experienced a significant volume of activity over the last 24 hours, recording a total of 36,716 attacks. The primary attacking countries were China, Singapore, and the United States, with a broad distribution of origins observed globally. Attacks predominantly targeted ports 1433 (MS SQL) and 445 (SMB), indicating a focus on database and file-sharing services. "Misc activity" and "Generic Protocol Command Decode" were the most frequent alert categories, with "GPL INFO VNC server response" being the leading signature, suggesting extensive reconnaissance and probing for VNC services. Several known attacker and mass scanner IPs were identified, with "Tencent Building, Kejizhongyi Avenue" and "China Mobile communications corporation" being the top associated AS organizations. Attackers consistently attempted common usernames like 'root' and 'admin' with predictable passwords. Notably, attempts to exploit recent CVEs such as CVE-2025-55182 and CVE-2024-14007 were detected. OSINT investigations provided detailed insights into these CVEs, while direct IP reputation lookups using general search agents proved limited.

---

**Detailed Analysis:**

**Our IPs:**
| Honeypot Name | IP Address       |
| :------------ | :--------------- |
| tpot-hive-ny  | 134.199.242.175  |

**Attacks by honeypot:**
Information on attacks per specific honeypot instance (e.g., tpot-hive-ny) is not explicitly aggregated in the hourly reports, which focus on network-wide statistics.

**Top source countries:**

| Country            | Attacks |
| :----------------- | :------ |
| China              | 13612   |
| Singapore          | 6409    |
| United States      | 4850    |
| France             | 4704    |
| India              | 2567    |
| Thailand           | 2200    |
| United Arab Emirates | 1240    |
| Netherlands        | 1187    |
| Romania            | 570     |
| Türkiye            | 407     |
| Vietnam            | 420     |
| Australia          | 224     |
| Germany            | 156     |
| Poland             | 169     |
| Switzerland        | 124     |
| Russia             | 105     |
| Slovakia           | 35      |
| United Kingdom     | 10      |
| Hong Kong          | 4       |
| South Korea        | 4       |
| Malaysia           | 3       |

**Top attacking IPs:**

| IP Address      | Count |
| :-------------- | :---- |
| 43.163.123.189  | 6388  |
| 36.129.24.144   | 6340  |
| 173.249.6.152   | 4477  |
| 110.49.3.20     | 1834  |
| 173.73.62.72    | 1591  |
| 5.31.128.119    | 1240  |
| 103.148.38.69   | 588   |
| 103.204.164.37  | 515   |
| 109.228.239.197 | 407   |
| 104.236.53.117  | 393   |
| 178.62.253.171  | 324   |
| 2.57.122.96     | 306   |
| 152.42.134.69   | 299   |
| 159.203.180.234 | 238   |
| 2.57.122.208    | 238   |
| 27.79.45.149    | 236   |
| 170.64.199.236  | 228   |
| 185.6.2.126     | 248   |
| 101.71.39.109   | 172   |
| 101.71.37.77    | 143   |
| 67.205.160.240  | 144   |
| 80.94.95.216    | 135   |
| 46.19.137.194   | 124   |
| 85.203.15.98    | 120   |
| 116.99.171.201  | 107   |
| 34.158.168.101  | 99    |
| 92.118.39.95    | 69    |
| 64.225.0.224    | 64    |
| 87.120.191.13   | 70    |
| 45.148.10.121   | 5     |
| 89.42.231.186   | 4     |
| 167.94.138.172  | 3     |
| 167.94.146.54   | 3     |

**Top targeted ports/protocols:**

| Port  | Protocol (Inferred) | Observed Count (across all countries/reports) |
| :---- | :------------------ | :------------------------------------------ |
| 1433  | MS SQL              | High (e.g., China: 6336, Singapore: 6381, France: 4477) |
| 445   | SMB                 | High (e.g., India: 588, Thailand: 1348, UAE: 677, Türkiye: 407) |
| 22    | SSH                 | Medium (e.g., US: 87, India: 109, Vietnam: 54, Netherlands: 65) |
| 8728  | RouterOS API        | Medium (e.g., US: 72, India: 28, Singapore: 14) |
| 80    | HTTP                | Medium (e.g., US: 66, Vietnam: 10, Netherlands: 19) |
| 30003 | Unknown             | Medium (e.g., China: 126, China: 122) |
| 6379  | Redis               | Low (e.g., US: 22, China: 9) |
| 9100  | Printer             | Low (e.g., Netherlands: 16, Russia: 13) |

**Most common CVEs:**

| CVE              | Count |
| :--------------- | :---- |
| CVE-2025-55182   | 6     |
| CVE-2024-14007   | 6     |
| CVE-2021-3449    | 5     |
| CVE-2019-11500   | 5     |
| CVE-2002-0013    | 3     |
| CVE-2002-0012    | 2     |
| CVE-2002-1149    | 2     |
| CVE-2023-46604   | 2     |

**Commands attempted by attackers:**
Explicit "Commands attempted by attackers" are not detailed in the provided hourly reports. Activities are broadly categorized under "Misc activity" and "Generic Protocol Command Decode".

**Signatures triggered:**

| Signature                                           | Count |
| :-------------------------------------------------- | :---- |
| GPL INFO VNC server response                        | 24410 |
| SURICATA IPv4 truncated packet                      | 3538  |
| SURICATA AF-PACKET truncated packet                 | 3538  |
| SURICATA STREAM spurious retransmission             | 945   |
| ET DROP Dshield Block Listed Source group 1         | 373   |
| SURICATA STREAM reassembly sequence GAP -- missing packet(s) | 339   |
| ET INFO SSH session in progress on Expected Port    | 274   |
| ET SCAN NMAP -sS window 1024                        | 204   |
| SURICATA STREAM Packet with broken ack              | 112   |
| ET INFO SSH-2.0-Go version string Observed in Network Traffic | 90    |
| SURICATA STREAM RST recv but no session             | 144   |
| ET SCAN MS Terminal Server Traffic on Non-standard Port | 130   |
| SURICATA STREAM FIN recv but no session             | 62    |
| SURICATA HTTP Response excessive header repetition  | 66    |
| SURICATA Applayer Detect protocol only one direction | 22    |
| SURICATA HTTP Request excessive header repetition   | 18    |
| ET DROP Spamhaus DROP Listed Traffic Inbound group 12 | 5     |
| ET CINS Active Threat Intelligence Poor Reputation IP group 115 | 5     |

**Users / login attempts:**

| Username      | Count | Password         | Count |
| :------------ | :---- | :--------------- | :---- |
| root          | 194   | 123456           | 78    |
| admin         | 99    | (empty string)   | 44    |
| ubuntu        | 94    | admin            | 29    |
| postgres      | 35    | 123              | 34    |
| test          | 29    | 1234             | 26    |
| oracle        | 24    | 12345678         | 26    |
| user          | 29    | password1        | 20    |
| guest         | 27    | 1q2w3e4r         | 21    |
| solana        | 16    | 12345            | 20    |
| ali           | 4     | qwerty123        | 11    |
| bot           | 4     | 123abc           | 13    |
| aaa           | 3     | root             | 7     |
| bob           | 3     | admin123         | 20    |
| botuser       | 3     | 1234567890       | 18    |
| abc           | 2     | password         | 10    |
| adam          | 2     | alex             | 2     |
| backup        | 9     | 654321           | 2     |
| mysql         | 5     | P@ssw0rd         | 2     |
| pi            | 9     | solana           | 4     |
| administrator | 9     | user             | 3     |
| ftpuser       | 9     | validator        | 3     |
| sol           | 11    | 000000           | 3     |
| sa            | 5     | 111111           | 4     |
| config        | 2     | 123123           | 4     |
| installer     | 2     | 12345            | 4     |
| support       | 4     | 123456           | 4     |
| ubnt          | 4     | 12345678         | 4     |
| centos        | 18    | 123456789        | 4     |
| trading       | 3     | password         | 4     |
| trader        | 3     | password1        | 4     |
| eth           | 2     | qwerty           | 4     |

**Files uploaded/downloaded:**
No information on files uploaded or downloaded was explicitly available in the provided hourly reports.

**HTTP User-Agents:**
No HTTP User-Agent information was explicitly available in the provided hourly reports.

**SSH clients and servers:**
No separate tables for SSH clients and servers are provided in the reports. However, signatures like "ET INFO SSH session in progress on Expected Port" and "ET INFO SSH-2.0-Go version string Observed in Network Traffic" indicate SSH-related activity.

**Top attacker AS organizations:**

| ASN       | Organization                                  | Count |
| :-------- | :-------------------------------------------- | :---- |
| 132203    | Tencent Building, Kejizhongyi Avenue          | 6394  |
| 56044     | China Mobile communications corporation       | 6340  |
| 51167     | Contabo GmbH                                  | 4480  |
| 14061     | DigitalOcean, LLC                             | 2889  |
| 133481    | AIS Fibre                                     | 1834  |
| 701       | Verizon Business                              | 1591  |
| 15802     | Emirates Integrated Telecommunications Company PJSC | 1240  |
| 396982    | Google LLC                                    | 500   |
| 213412    | ONYPHE SAS                                    | 495   |
| 47890     | Unmanaged Ltd                                 | 490   |
| 4837      | CHINA UNICOM China169 Backbone                | 352   |
| 7552      | Viettel Group                                 | 296   |
| 16509     | Amazon.com, Inc.                              | 248   |
| 215925    | Vpsvault.host Ltd                             | 250   |
| 135377    | UCLOUD INFORMATION TECHNOLOGY HK LIMITED      | 172   |
| 33868     | INEA sp. z o.o.                               | 114   |
| 8075      | Microsoft Corporation                         | 100   |
| 51852     | Private Layer INC                             | 71    |
| 6939      | Hurricane Electric LLC                        | 63    |
| 24086     | Viettel Corporation                           | 56    |
| 139564    | Broadway Communication Pvt Ltd                | 588   |
| 398324    | Censys, Inc.                                  | 8     |
| 48090     | Techoff Srv Limited                           | 5     |

**OSINT All Commands captured:**
Explicit commands captured were not available in the summarized hourly reports for OSINT.

**OSINT High frequency IPs and low frequency IPs Captured:**
*Due to limitations of the `google_search_agent` for direct, real-time IP reputation and detailed OSINT lookups, specific data for these IPs could not be retrieved. General web searches primarily return information about OSINT tools rather than direct lookup results for individual IPs.*

However, based on general threat intelligence practices for such IPs:
*   **High Frequency IPs (e.g., 43.163.123.189, 36.129.24.144, 173.249.6.152):** OSINT on these IPs would typically involve checking multiple threat intelligence platforms (e.g., AbuseIPDB, Talos Intelligence, VirusTotal, Shodan) to determine if they are listed as known malicious actors, part of botnets, engaged in mass scanning, or associated with specific attack campaigns. These platforms would provide historical abuse reports, open ports, and services exposed, which could offer insights into the attacker's infrastructure and intent. Their high attack counts strongly suggest they are automated bots or compromised systems.
*   **Low Frequency IPs (e.g., 45.148.10.121, 89.42.231.186, 167.94.138.172):** For low-frequency IPs, OSINT would similarly involve reputation checks. While they might not be heavily blacklisted due to lower activity, any historical reports or open ports could still reveal their nature. These could be opportunistic scanners, newly compromised hosts, or even misconfigured legitimate systems. The goal would be to understand if these represent targeted, low-volume attacks or simply part of broader background noise.

**OSINT on CVE's:**

*   **CVE-2025-55182 (React2Shell):**
    *   **Description:** Critical pre-authentication remote code execution (RCE) vulnerability with a CVSS score of 10.0, impacting React Server Components, Next.js, and other related frameworks. It stems from unsafe handling of incoming data during deserialization of attacker-crafted HTTP requests, allowing arbitrary code execution through a single malicious HTTP POST request.
    *   **Impact:** Full server compromise without authentication.
    *   **Exploitation:** Exploitation activity detected as early as December 5, 2025, with public proof-of-concept (PoC) code making widespread exploitation likely.
    *   **Mitigation:** Upgrade to patched versions (19.0.1, 19.1.2, 19.2.1), implement layered security (WAF, platform-level protections).

*   **CVE-2024-14007 (NVMS-9000 Authentication Bypass):**
    *   **Description:** Critical authentication bypass vulnerability affecting Shenzhen TVT Digital Technology Co., Ltd. NVMS-9000 firmware (and white-labeled DVR/NVR/IPC products). Versions prior to 1.3.4 are vulnerable.
    *   **Impact:** Unauthenticated remote attackers can invoke privileged administrative commands, leading to disclosure of sensitive information like administrator usernames and passwords (cleartext), network configurations, and device details.
    *   **Exploitation:** Exploitable by sending a specially crafted TCP payload to an exposed NVMS-9000 control port. Public exploits are known and readily available.
    *   **Mitigation:** Update firmware to version 1.3.4+, isolate devices via network segmentation, change default credentials, implement firewall rules.

*   **CVE-2021-3449 (OpenSSL TLS Server DoS):**
    *   **Description:** Medium-severity denial-of-service (DoS) vulnerability (CWE-476, NULL Pointer Dereference) affecting OpenSSL TLS servers.
    *   **Impact:** A maliciously crafted renegotiation ClientHello message can cause the server to crash.
    *   **Affected Systems:** OpenSSL 1.1.1 versions (up to 1.1.1j) with TLSv1.2 and renegotiation enabled (default). OpenSSL 1.0.2 and TLS clients are not affected.
    *   **Exploitation:** Included in CISA's Known Exploited Vulnerabilities Catalog, indicating active exploitation. Public PoC exploits available.
    *   **Mitigation:** Upgrade to OpenSSL 1.1.1k or later, or disable TLS renegotiation if not required.

---

**Key Observations and Anomalies**

*   **Hyper-aggressive IP Addresses:** A recurring set of IP addresses (e.g., 43.163.123.189, 36.129.24.144, 173.249.6.152, 110.49.3.20) consistently demonstrated exceptionally high attack volumes. These are indicative of dedicated scanning infrastructure, botnets, or compromised systems engaged in sustained malicious activity. Their presence underscores a continuous threat from these specific sources.

*   **Unusual Attacker Origins:** The reports highlight a broad geographic spread of attacks, including significant contributions from non-traditional cyberattack source countries like Thailand, United Arab Emirates, Vietnam, and Türkiye. This wide distribution suggests either a globally distributed botnet or a high degree of opportunistic scanning across various internet regions, expanding the attack surface beyond typical hotbeds.

*   **Targeted Service Exploitation:** The overwhelming focus on ports 1433 (MS SQL) and 445 (SMB) across multiple top attacking countries (China, Singapore, France for 1433; India, Thailand, UAE, Türkiye for 445) reveals specific campaigns aimed at compromising database and file-sharing services. This indicates attackers are actively seeking out and exploiting common vulnerabilities or weak credentials in these widely deployed services.

*   **Extensive VNC Probing and Truncated Packets:** The highest volume alert signatures, "GPL INFO VNC server response" and "SURICATA IPv4/AF-PACKET truncated packet," signify widespread reconnaissance and unusual network communication attempts potentially targeting VNC services. This suggests attackers are actively mapping networks for VNC servers, possibly in preparation for brute-force attacks or exploitation of known VNC vulnerabilities, or that the honeypot is effectively capturing malformed packets from aggressive scanning tools.

*   **Persistent Brute-Force Activity:** The continuous attempts using common usernames ('root', 'admin', 'ubuntu', 'test') and weak/default passwords ('123456', 'admin', empty string) underscore the prevalence of automated brute-force attacks. This highlights the importance of strong, unique credentials across all internet-facing services.

*   **Cryptocurrency-Related Targeting:** The appearance of usernames like "solana," "trader," "trading," and "eth," alongside "validator" as a password, suggests a potential, albeit lower-volume, targeting of cryptocurrency-related systems or financial services. This indicates specialized interests among some attackers.

*   **Blocklisted Malicious Sources:** The detection of "ET DROP Dshield Block Listed Source group 1" and "ET DROP Spamhaus DROP Listed Traffic Inbound group 12" confirms that a subset of attacking IPs are already identified as malicious by leading threat intelligence organizations. This reinforces the need for integrating such feeds into perimeter defenses.

*   **Active CVE Exploitation:** The repeated attempts to exploit CVE-2025-55182 (React2Shell), CVE-2024-14007 (NVMS-9000 Authentication Bypass), and CVE-2021-3449 (OpenSSL TLS Server DoS), even with low individual counts in hourly reports, collectively demonstrate that attackers are actively leveraging publicly known vulnerabilities. The criticality of CVE-2025-55182 (RCE) and CVE-2024-14007 (authentication bypass) makes their presence particularly concerning, indicating a high risk to unpatched systems.

*   **Lack of Explicit Attacker Signatures/Filenames:** The absence of explicit attacker "signatures," comments, "taunts," or blatant malware/botnet filenames in the summarized logs suggests that the attacks are either highly automated using generic tools that don't leave such traces, or the attackers are intentionally obfuscating their activities at this level of interaction with the honeypot.

---

**Unusual Attacker Origins - IP addresses from non-traditional sources**
As noted in the "Key Observations and Anomalies," the presence of top attacking countries like Thailand, United Arab Emirates, Vietnam, and Türkiye indicates a broader geographical spread of attack origins than might be considered "traditional" sources of cyberattacks. This suggests a highly distributed attack infrastructure, potentially comprising compromised systems worldwide, rather than attacks concentrated from a few well-known hostile regions. The diversity in origins complicates attribution and highlights the global nature of current cyber threats.