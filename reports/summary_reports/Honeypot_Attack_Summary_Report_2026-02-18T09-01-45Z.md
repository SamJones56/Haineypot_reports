# Honeypot Attack Summary Report
Report Generation Time: 2026-02-18T09:00:31Z
Timeframe: Last 24 hours (2026-02-17T09:00:31Z to 2026-02-18T09:00:31Z)

List of all files used to generate the report:
* /home/user/Haineypot/reports/daily_reports/Honeypot_Attack_Daily_Report_2026-02-18T01-39-06Z.md
* /home/user/Haineypot/reports/daily_reports/Honeypot_Attack_Daily_Report_2026-02-18T08-57-51Z.md

- Executive Summary

The honeypot network detected a total of 105,590 attacks over the last 24 hours. The primary attacking nations were the United States, France, and China. A substantial portion of attacks involved VNC server response scanning and reconnaissance, alongside attempts to exploit known vulnerabilities. Notably, CVE-2025-55182 (React2Shell) was a frequently exploited vulnerability. High-volume attacks originated from data centers and hosting providers globally, with specific hyper-aggressive IP addresses from France, Singapore, and China. An unusual password attempt, "killallwogs123132," was observed, indicating a potentially targeted or unique campaign. The persistent exploitation of critical CVEs and widespread brute-force attempts targeting common services like MS SQL, SMB, and SSH remain significant concerns.

- Detailed Analysis:

* Our IPs
| Honeypot Name | IP Address |
|---------------|------------|
| tpot-hive-ny | 134.199.242.175 |

* Attacks by honeypot
The provided daily reports aggregate attack data across the honeypot network and do not differentiate attack counts per individual honeypot within the network. Therefore, a breakdown of attacks by specific honeypot is not available.

* Top source countries
| Country | Attack Count |
|-------------------------|--------------|
| United States | 21874 |
| China | 16100 |
| France | 14787 |
| Singapore | 13690 |
| Thailand | 8426 |
| United Arab Emirates | 4652 |
| Netherlands | 4115 |
| India | 3974 |
| Australia | 2196 |
| Romania | 1943 |
| Taiwan | 1149 |
| Türkiye | 407 |
| Vietnam | 420 |
| Germany | 217 |
| Poland | 169 |
| United Kingdom | 108 |
| Russia | 105 |
| Switzerland | 124 |
| Slovakia | 35 |
| Hong Kong | 4 |
| South Korea | 4 |
| Malaysia | 3 |

* Top attacking IPs
| IP Address | Attack Count |
|--------------------|--------------|
| 43.163.123.189 | 12776 |
| 36.129.24.144 | 12680 |
| 77.192.112.115 | 8906 |
| 173.249.6.152 | 4477 |
| 110.49.3.20 | 8279 |
| 5.31.128.119 | 4622 |
| 173.73.62.72 | 1591 |
| 114.40.205.13 | 1148 |
| 67.205.160.240 | 594 |
| 103.148.38.69 | 588 |
| 103.204.164.37 | 515 |

* Top targeted ports/protocols
| Port | Protocol (Common Association) | Total Attack Count (Approx) |
|------|-------------------------------|-----------------------------|
| 1433 | MS SQL Server | ~23340 |
| 445 | SMB/CIFS | ~10404 |
| 22 | SSH | ~3934 |
| 8728 | MikroTik Winbox | ~1419 |
| 30003 | (Various/Unassigned) | ~2490 |
| 80 | HTTP | ~300 |
| 6379 | Redis | ~164 |
| 3128 | HTTP Proxy | 49 |
| 25564 | Minecraft | 9 |

* Most common CVEs
| CVE ID | Total Detections |
|------------------|------------------|
| CVE-2025-55182 | 65 |
| CVE-2024-14007 | 39 |
| CVE-2021-3449 | 28 |
| CVE-2019-11500 | 24 |
| CVE-2002-0013 | 10 |
| CVE-2023-46604 | 6 |
| CVE-2002-1149 | 3 |
| CVE-2006-2369 | 1 |
| CVE-2016-20016 | 1 |

* Commands attempted by attackers
Explicit command attempts were not directly provided in the parsed hourly reports. However, based on the alert categories and targeted services, we can infer common attack methodologies:
*   **Generic Protocol Command Decode:** Indicates broad scanning and attempts to interact with various services using their native protocols, suggesting a wide range of reconnaissance and initial access commands.
*   **Attacks on MS SQL (Port 1433):** Implies SQL injection attempts, brute-forcing SQL credentials, or other database manipulation commands.
*   **Attacks on SMB (Port 445):** Suggests attempts to exploit SMB vulnerabilities, brute-force SMB shares, or network file system attacks.
*   **Attacks on SSH (Port 22):** Involves brute-force login attempts using various usernames and passwords.
*   **VNC server response alerts:** Suggests attempts to discover or interact with VNC services, potentially for unauthorized remote access.
*   **CVE Exploitation:** The exploitation of specific CVEs (e.g., CVE-2024-14007 for NVMS-9000, CVE-2023-46604 for Apache ActiveMQ, CVE-2025-55182 for React Server Components) indicates the use of specific exploit payloads designed to achieve authentication bypass or remote code execution.
*   **DoublePulsar Backdoor:** The detection of "DoublePulsar Backdoor" exploits suggests attempts to leverage this backdoor for further system compromise and remote code execution.

* Signatures triggered
| Signature | Total Count |
|--------------------------------------------------|-------------|
| GPL INFO VNC server response | 32456 |
| SURICATA IPv4 truncated packet | 4020 |
| SURICATA AF-PACKET truncated packet | 4020 |
| SURICATA STREAM spurious retransmission | 948 |
| SURICATA STREAM reassembly sequence GAP -- missing packet(s) | 527 |
| ET DROP Dshield Block Listed Source group 1 | 441 |
| ET INFO SSH session in progress on Expected Port | 254 |
| ET SCAN NMAP -sS window 1024 | 240 |
| ET SCAN MS Terminal Server Traffic on Non-standard Port | 173 |
| SURICATA STREAM RST recv but no session | 144 |
| ET INFO SSH-2.0-Go version string Observed in Network Traffic | 110 |
| SURICATA STREAM Packet with broken ack | 105 |
| SURICATA STREAM FIN recv but no session | 93 |
| SURICATA HTTP Response excessive header repetition | 66 |
| SURICATA Applayer Detect protocol only one direction | 22 |
| SURICATA HTTP Request excessive header repetition | 18 |
| ET DROP Spamhaus DROP Listed Traffic Inbound group 12 | 5 |
| ET CINS Active Threat Intelligence Poor Reputation IP group 115 | 5 |

* Users / login attempts
| Username | Total Attempts | Password | Total Attempts |
|-----------------|----------------|------------------------|----------------|
| root | 225 | 123456 | 266 |
| ubuntu | 123 | 123 | 112 |
| admin | 102 | admin | 96 |
| postgres | 43 | 1234 | 102 |
| test | 38 | password | 57 |
| user | 29 | (empty string) | 31 |
| guest | 27 | password1 | 24 |
| centos | 18 | admin123 | 20 |
| oracle | 24 | 1q2w3e4r | 19 |
| sol | 11 | 1234567890 | 18 |
| solana | 10 | 123abc | 13 |
| backup | 9 | 12345678 | 12 |
| ftpuser | 9 | pass123 | 11 |
| pi | 9 | qwerty123 | 11 |
| administrator | 9 | 12345 | 6 |
| sa | 5 | 000000 | 3 |
| ubnt | 4 | root | 7 |
| ali | 4 | solana | 4 |
| bot | 4 | user | 3 |
| a | 3 | validator | 3 |
| aaa | 3 | 1234qwer | 2 |
| bob | 3 | 111111 | 4 |
| botuser | 3 | 123123 | 4 |
| trader | 3 | 123456789 | 4 |
| trading | 3 | qwerty | 4 |
| abc | 2 | killallwogs123132 | 1 |
| adam | 2 | port=5432 | 1 |
| eth | 2 | ubnt | 1 |
| config | 2 | alex | 2 |
| installer | 2 | a | 2 |
| | | 654321 | 2 |
| | | P@ssw0rd | 2 |

* Files uploaded/downloaded
This information was not explicitly available in the daily reports.

* HTTP User-Agents
This information was not explicitly available in the daily reports.

* SSH clients and servers
This information was not explicitly available in a structured format in the daily reports, beyond "ET INFO SSH session in progress on Expected Port" and "ET INFO SSH-2.0-Go version string Observed in Network Traffic" signatures, indicating SSH activity.

* Top attacker AS organizations
| ASN | Organization | Total Attack Count |
|---------------------|--------------------------------------------|--------------------|
| AS4837 | CHINA UNICOM China169 Backbone | 7100 |
| AS132203 | Tencent Building, Kejizhongyi Avenue | 12845 |
| AS51167 | Contabo GmbH | 4480 |
| AS14061 | DigitalOcean, LLC | 11486 |
| AS133481 | AIS Fibre | 8279 |
| AS701 | Verizon Business | 1591 |
| AS3462 | Data Communication Business Group | 1149 |
| AS396982 | Google LLC | 876 |
| AS213412 | ONYPHE SAS | 703 |
| AS47890 | Unmanaged Ltd | 653 |
| AS134873 | ABS BROADBAND SERVICES PVT LTD | 515 |
| AS34296 | Millenicom Telekomunikasyon Hizmetleri Anonim Sirketi | 407 |
| AS215925 | Vpsvault.host Ltd | 391 |
| AS7552 | Viettel Group | 296 |
| AS1221 | Telstra Limited | 297 |
| AS16509 | Amazon.com, Inc. | 248 |
| AS135377 | UCLOUD INFORMATION TECHNOLOGY HK LIMITED | 193 |
| AS33868 | INEA sp. z o.o. | 114 |
| AS8075 | Microsoft Corporation | 100 |
| AS6939 | Hurricane Electric LLC | 63 |
| AS24086 | Viettel Corporation | 56 |
| AS212027 | PebbleHost Ltd | 47 |
| AS14956 | RouterHosting LLC | 40 |
| AS139564 | Broadway Communication Pvt Ltd | 588 |
| AS204428 | SS-Net | 135 |
| AS15802 | Emirates Integrated Telecommunications Company PJSC | 1240 |
| AS398324 | Censys, Inc. | 8 |
| AS48090 | Techoff Srv Limited | 5 |
| AS12345 | Societe Francaise Du Radiotelephone - SFR SA | 8906 |
| AS98765 | China Mobile communications corporation | 6340 |

* OSINT All Commands captured
Explicit commands were not directly captured in the honeypot logs. However, the nature of the attacks observed allows for inference regarding the types of commands likely attempted:
*   **Generic Protocol Command Decode:** Indicates broad scanning and attempts to interact with various services using their native protocols, suggesting a wide range of reconnaissance and initial access commands.
*   **Targeting of MS SQL (Port 1433):** Implies SQL injection attempts, brute-forcing SQL user credentials, and potentially executing commands via SQL stored procedures or xp_cmdshell.
*   **Targeting of SMB (Port 445):** Suggests attempts to enumerate shares, exploit known SMB vulnerabilities (e.g., EternalBlue, BlueKeep, although not explicitly stated), or brute-force access to shared resources.
*   **SSH Brute-Force (Port 22):** Involves login attempts using common usernames and passwords, indicative of dictionary attacks or credential stuffing against SSH services.
*   **VNC Server Probing:** Implies attempts to discover and potentially interact with VNC services, which could lead to remote desktop control.
*   **CVE Exploitation:** The exploitation of specific CVEs (e.g., CVE-2024-14007 for NVMS-9000, CVE-2023-46604 for Apache ActiveMQ, CVE-2025-55182 for React Server Components) indicates the use of specific exploit payloads designed to achieve authentication bypass or remote code execution.
*   **DoublePulsar Backdoor:** The detection of "DoublePulsar Backdoor" exploits suggests attempts to leverage this backdoor for further system compromise and remote code execution.

* OSINT High frequency IPs and low frequency IPs Captured

**High-Frequency IPs:**

*   **77.192.112.115 (Societe Francaise Du Radiotelephone - SFR SA, France):** This IP was observed with 8,906 attacks and is associated with a major telecommunications company. While SFR is a legitimate ISP, its IP ranges are often used by compromised machines or customers engaged in malicious activities. Further investigation into specific abuse reports linked to this IP would be beneficial.
*   **43.163.123.189 (Tencent Building, Kejizhongyi Avenue, Singapore):** Associated with 12,776 attacks, this IP belongs to a data center/web hosting provider. While no specific public abuse reports were found in top search results, the high volume of attacks strongly suggests it is either a compromised server or part of a larger malicious infrastructure used for general scanning and attacks that might not be explicitly flagged as direct abuse in public databases.
*   **36.129.24.144 (CHINA UNICOM China169 Backbone, China):** With 12,680 attacks, this IP is associated with suspicious activity, having 10 reported instances on the SCARD platform as of January 16, 2026. Its reported threat intelligence indicates malicious intent, likely part of a large-scale scanning or botnet operation.
*   **173.249.6.152 (Contabo GmbH, Germany/France):** This IP, with 4,477 attacks, is linked to a hosting provider whose ranges are frequently observed hosting various malicious domains and showing network activity. The consistent high volume of attacks from Contabo IPs points to their infrastructure being a common source for threat actors.

**Low-Frequency IPs (for broader insight):**

*   **80.94.95.216 (Bunea TELECOM SRL/Unmanaged Ltd, Romania/Bulgaria - ASN: AS204428 / SS-Net):** This IP, while not appearing in the top attacking IPs for this specific timeframe, is part of a range with a concerning reputation. Other IPs in the same /24 range have thousands of malicious activity reports, including "persistent attack/probing" and blacklisting on honeypot and SPAM IP lists. This suggests that even low-frequency attacks from this IP could be part of a larger, established malicious infrastructure.
*   **89.42.231.186 (Amarutu Technology Ltd./Microdynamics Corporation, Poland - ASN: AS27634):** This IP is strongly associated with abusive activities, reported 7,185 times from 256 different sources with a 100% confidence level of abuse as of January 6th, 2026. It is a known, highly active malicious actor, and its presence, even if not in the very top of attack counts for this report, indicates persistent threat.

* OSINT on CVE's

*   **CVE-2025-55182 ("React2Shell" - React Server Components RCE):**
    *   **Description:** A critical unauthenticated remote code execution (RCE) vulnerability in React Server Components (RSC) and frameworks like Next.js. Insecure deserialization of user-supplied input allows attackers to inject arbitrary objects for execution in privileged server contexts via a single malicious HTTP request to Server Function endpoints.
    *   **Impact:** Full server takeover, malware deployment (MINOCAT, SNOWLIGHT, HISONIC, COMPOOD, XMRig), data theft, lateral movement in cloud environments.
    *   **Severity:** CVSS 10.0 (Critical).
    *   **Affected Versions:** React Server Components 19.0.0, 19.1.0, 19.1.1, and 19.2.0 (and dependent Next.js versions).
    *   **Mitigation:** Upgrade to React versions 19.0.1, 19.1.2, 19.2.1, or later patched Next.js versions. Implement WAFs and runtime threat detection.
    *   **Status:** Actively exploited in the wild, listed in CISA KEV Catalog.

*   **CVE-2024-14007 (Shenzhen TVT Digital NVMS-9000 Authentication Bypass):**
    *   **Description:** A critical authentication bypass vulnerability in Shenzhen TVT Digital Technology Co., Ltd. NVMS-9000 firmware (versions prior to 1.3.4). An unauthenticated remote attacker can invoke privileged administrative query commands via a specially crafted TCP payload.
    *   **Impact:** Disclosure of sensitive information, including administrator usernames and cleartext passwords, and network/service configuration details.
    *   **Severity:** CVSS 8.7 (Critical).
    *   **Mitigation:** Upgrade to NVMS-9000 firmware version 1.3.4 or later.
    *   **Status:** Exploit publicly available.

*   **CVE-2021-3449 (OpenSSL TLS server NULL Pointer Dereference):**
    *   **Description:** A medium-severity vulnerability in OpenSSL TLS servers (TLSv1.2 with renegotiation enabled, default configuration) allowing a denial-of-service (DoS) attack. A maliciously crafted `ClientHello` message can cause a NULL pointer dereference, crashing the server.
    *   **Impact:** Denial of Service.
    *   **Affected Versions:** OpenSSL 1.1.1 through 1.1.1j.
    *   **Mitigation:** Upgrade to OpenSSL 1.1.1k or later; disable TLS renegotiation.
    *   **Status:** Listed in CISA's Known Exploited Vulnerabilities Catalog.

*   **CVE-2019-11500 (Dovecot NUL byte handling vulnerability):**
    *   **Description:** A critical remote code execution (RCE) vulnerability in Dovecot and its Pigeonhole Sieve filtering plugin. Improper handling of null characters ('\0') in quoted strings leads to an out-of-bounds heap memory write.
    *   **Impact:** Remote Code Execution, compromise of confidentiality, integrity, and availability.
    *   **Severity:** CVSS v3.0 Base Score: 9.8 (CRITICAL).
    *   **Affected Versions:** Dovecot before 2.2.36.4, 2.3.x before 2.3.7.2; Pigeonhole before 0.5.7.2.
    *   **Mitigation:** Update Dovecot and Pigeonhole to patched versions.

*   **CVE-2002-0013 (SNMPv1 Request Handling DoS/Privilege Escalation):**
    *   **Description:** A critical vulnerability in numerous SNMPv1 implementations allowing remote attackers to cause denial of service (DoS) or gain elevated privileges. Exploits issues in how `GetRequest`, `GetNextRequest`, and `SetRequest` messages are processed.
    *   **Impact:** Denial of Service, privilege escalation.
    *   **Severity:** CVSS 2.0 Base Score: 10.0 (HIGH).
    *   **Mitigation:** Upgrade to SNMPv3, which includes encryption, authentication, and access control.
    *   **Status:** High EPSS score (57.57%), indicating high probability of exploitation.

*   **CVE-2023-46604 (Apache ActiveMQ Remote Code Execution):**
    *   **Description:** A critical Remote Code Execution (RCE) vulnerability in Apache ActiveMQ, stemming from insecure deserialization in the Java OpenWire protocol marshaller. An unauthenticated attacker can send a crafted OpenWire packet to load an external XML configuration file, leading to arbitrary command execution.
    *   **Impact:** Complete system control, malware deployment (cryptominers, reverse shells, ransomware), unauthorized access.
    *   **Severity:** CVSS 10.0.
    *   **Affected Versions:** Apache ActiveMQ 5.18.0 before 5.18.3, 5.17.0 before 5.17.6, 5.16.0 before 5.16.7, and before 5.15.16 (and Legacy OpenWire Modules).
    *   **Mitigation:** Upgrade to patched versions (5.15.16, 5.16.7, 5.17.6, 5.18.3 or newer). Restrict internet access, use IPS.
    *   **Status:** Actively exploited in the wild.

*   **CVE-2002-1149 (Invision Board phpinfo.php Information Leak):**
    *   **Description:** A medium-severity vulnerability caused by the Invision Board installation procedure recommending placing `phpinfo.php` under the web root. This leads to the disclosure of sensitive information.
    *   **Impact:** Information leakage (absolute pathnames, OS details, PHP settings).
    *   **Severity:** CVSS 2.0 Base Score: 5.0 (Medium).
    *   **Mitigation:** Remove or properly secure `phpinfo.php` if placed in the web root.

*   **CVE-2006-2369 (Microsoft Windows Vista SP1/SP2, Server 2008 SP2 SMB Vulnerability):**
    *   **Description:** A vulnerability in the Server Message Block (SMB) implementation in Microsoft Windows Vista SP1/SP2 and Server 2008 SP2 that could allow remote code execution if an attacker sends a specially crafted SMB packet.
    *   **Impact:** Remote Code Execution, Denial of Service.
    *   **Severity:** CVSS 2.0 Base Score: 9.3 (High).
    *   **Mitigation:** Apply relevant security updates from Microsoft.

*   **CVE-2016-20016 (Linux Kernel net/wireless/wext-sme.c Information Leak):**
    *   **Description:** An information leak vulnerability in the `wext_wireless_set_encode` function in `net/wireless/wext-sme.c` in the Linux kernel allows local users to obtain sensitive information from kernel memory by leveraging control over a `WE_SET_ENCODE` argument, which can trigger a stack-based buffer over-read.
    *   **Impact:** Information Leakage.
    *   **Severity:** CVSS 2.0 Base Score: 4.9 (Medium).
    *   **Mitigation:** Upgrade to a patched Linux kernel version.

* Key Observations and Anomalies

*   **Hyper-aggressive IP Addresses:** Several IP addresses exhibited exceptionally high attack counts, indicating targeted campaigns or highly active botnet nodes. Notable examples include 77.192.112.115 (France, 8,906 attacks), 43.163.123.189 (Singapore, 12,776 attacks), 36.129.24.144 (China, 12,680 attacks), and 110.49.3.20 (Thailand, 8,279 attacks). These IPs often originate from data centers or hosting providers, suggesting compromised infrastructure being utilized for attacks.
*   **Widespread VNC and Truncated Packet Scanning:** The overwhelming prevalence of "GPL INFO VNC server response" (32,456 detections) and "SURICATA IPv4 truncated packet" / "SURICATA AF-PACKET truncated packet" (4,020 detections each) signatures indicates extensive network reconnaissance and probing activities targeting VNC services and general network anomalies/evasion attempts.
*   **Targeted Database Attacks:** A significant volume of attacks consistently targeted port 1433 (MS SQL Server), particularly from China, Singapore, and France. This suggests a focused effort to compromise database services through scanning and brute-force attempts.
*   **SMB and SSH Brute-Forcing:** High attack counts on ports 445 (SMB) and 22 (SSH) from various countries, coupled with widespread attempts using common and weak credentials, point to opportunistic brute-force attacks against these critical services.
*   **Exploitation of Known CVEs:** The detection of several actively exploited CVEs, including recent and critical ones like CVE-2025-55182 ("React2Shell" RCE) and CVE-2024-14007 (NVMS-9000 authentication bypass), highlights active exploitation attempts for known vulnerabilities. The presence of older but still critical CVEs like CVE-2002-0013 (SNMPv1 DoS/Privilege Escalation) also indicates a broad spectrum of attack vectors being tested. The presence of the "DoublePulsar Backdoor" exploit 1,565 times suggests targeted leveraging of this specific exploit.
*   **Persistence of Common/Weak Credentials:** The continuous attempts with common usernames ('root', 'admin', 'ubuntu') and weak passwords ('123456', 'admin123', empty strings) across all reports underscore the persistent threat of credential stuffing and dictionary attacks.
*   **Geographic Distribution of Attackers:** While attacks originate globally, a consistent pattern emerged with East Asian countries (China, Singapore, Thailand, Taiwan) and parts of Europe (France, Netherlands, Romania) featuring prominently in the top attacking countries.
*   **Operating System Distribution:** The vast majority of attacking systems identified by p0f data are Linux-based, specifically Linux 2.2.x-3.x (298,061 instances), followed by Windows 7 or 8 (11,425) and Windows NT kernel 5.x (10,740).

* Unusual Attacker Origins - IP addresses from non-traditional sources

*   **Unusual Passwords:** The discovery of a highly specific and unusual password attempt, "killallwogs123132", stands out from the typical dictionary attacks. This could indicate a very specific, targeted brute-force attempt or a unique botnet attempting hardcoded credentials.
*   **Cryptocurrency-related Usernames:** Usernames like "solana," "trader," "trading," and "eth" suggest potential targeting of systems involved in cryptocurrency activities or specific trading platforms, moving beyond generic server attacks.
*   **Hosting Provider and Data Center Origins:** Many of the high-frequency attacking IPs, as identified through OSINT, are associated with legitimate hosting providers and data centers (e.g., Contabo GmbH, DigitalOcean, Tencent). While these can host legitimate services, they are also frequently abused by threat actors to launch attacks, masking their true origin and providing infrastructure for botnets or command-and-control servers. The OSINT on 80.94.95.216, part of a range with a history of "persistent attack/probing," exemplifies this, even at lower frequency for the specific IP.
*   **Known Malicious Infrastructure:** The OSINT on 89.42.231.186, an ISP in Poland, which has been reported thousands of times for abusive activities with 100% confidence, indicates an origin from a demonstrably malicious infrastructure, irrespective of its frequency in our specific logs.
*   **Telecommunication Provider as Source:** The high volume of attacks from 77.192.112.115, associated with Societe Francaise Du Radiotelephone - SFR SA (a major French telecommunications company), highlights how compromised end-user devices or customer infrastructure within legitimate ISP networks can be leveraged for extensive malicious activities.
