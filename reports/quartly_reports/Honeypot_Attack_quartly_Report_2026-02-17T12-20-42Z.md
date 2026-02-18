# Quarterly Honeypot Attack Summary Report

**Report Generation Time:** 2026-02-17T12:30:00Z
**Timeframe:** 2026-02-16T09:05:15Z to 2026-02-17T12:01:13Z

**Files Used to Generate Report:**
*   /home/user/Haineypot/reports/hourly_reports/Honeypot_Attack_Hourly_Report_2026-02-16T10-06-11Z.md
*   /home/user/Haineypot/reports/hourly_reports/Honeypot_Attack_Hourly_Report_2026-02-16T19-57-04Z.md
*   /home/user/Haineypot/reports/hourly_reports/Honeypot_Attack_Hourly_Report_2026-02-16T20-01-42Z.md
*   /home/user/Haineypot/reports/hourly_reports/Honeypot_Attack_Hourly_Report_2026-02-17T06-01-25Z.md
*   /home/user/Haineypot/reports/hourly_reports/Honeypot_Attack_Hourly_Report_2026-02-17T11-01-24Z.md
*   /home/user/Haineypot/reports/hourly_reports/Honeypot_Attack_Hourly_Report_2026-02-17T12-02-31Z.md

## Executive Summary

This report summarizes honeypot activity over the last 6 hours, from 2026-02-16T09:05:15Z to 2026-02-17T12:01:13Z, aggregating data from six hourly reports. A total of 24,890 attacks were detected across the honeypot network. The most prominent attacking countries were France, India, and the United States, with a significant number of attacks also originating from Australia and Thailand.

The most frequently observed alert category was "Misc activity," dominated by "GPL INFO VNC server response" alerts, indicating widespread VNC-related reconnaissance. "Generic Protocol Command Decode" was the second most common category.

Hyper-aggressive IP addresses were identified, with `173.249.6.152` (France), `103.218.135.57` (India), and `110.49.3.20` (Thailand) being the most prolific attackers. These IPs targeted ports 1433 (MS SQL), 445 (SMB), and 445 (SMB) respectively.

A variety of CVEs were targeted, with a mix of older and more recent vulnerabilities, including `CVE-2024-14007`, `CVE-2025-55182`, `CVE-2002-0013`, `CVE-2002-0012`, `CVE-2019-11500`, `CVE-2021-3449`, and `CVE-2023-46604`.

Brute-force attempts were common, with "root" and "ubuntu" being the most frequently targeted usernames, and simple passwords like "123456" and empty strings being the most common passwords. Some unusual usernames like "solana", "trader", and "trading" were also observed, suggesting potential targeting of cryptocurrency-related systems.

The majority of attacking systems were identified as Linux-based, with "Linux 2.2.x-3.x" being the most common OS distribution.

## Detailed Analysis

### Our IPs

| Honeypot Name | IP Address      |
|---------------|-----------------|
| tpot-hive-ny  | 134.199.242.175 |

### Attacks by Honeypot

| Honeypot Name | Attack Count |
|---------------|--------------|
| tpot-hive-ny  | 24890        |

### Top Source Countries

| Country            | Attack Count |
|--------------------|--------------|
| France             | 4758         |
| India              | 3762         |
| United States      | 4652         |
| Australia          | 2297         |
| Thailand           | 2713         |
| United Arab Emirates| 562          |
| Romania            | 1531         |
| Netherlands        | 1011         |
| China              | 812          |
| Germany            | 191          |

### Top Attacking IPs

| IP Address       | Country         | ASN                                      | Attack Count |
|------------------|-----------------|------------------------------------------|--------------|
| 173.249.6.152    | France          | AS51167 Contabo GmbH                      | 4477         |
| 103.218.135.57   | India           | AS59191 PEERCAST TELECOM INDIA PVT LTD     | 2538         |
| 110.49.3.20      | Thailand        | AS133481 AIS Fibre                        | 2694         |
| 144.130.11.9     | Australia       | ASN 1221 Telstra Limited                 | 1857         |
| 173.73.62.72     | United States   | ASN 701 Verizon Business                 | 793          |
| 5.31.128.119     | United Arab Emirates| AS15802 Emirates Integrated Telecommunications Company PJSC | 562          |
| 139.59.69.34     | India           | AS14061 DigitalOcean, LLC                 | 544          |
| 67.205.160.240   | United States   | AS14061 DigitalOcean, LLC                 | 594          |
| 103.204.164.37   | India           | AS134873 ABS BROADBAND SERVICES PVT LTD  | 515          |
| 2.57.121.22      | Romania         | AS47890 Unmanaged Ltd                     | 497          |

### Top Targeted Ports/Protocols

| Port  | Protocol | Service | Attack Count |
|-------|----------|---------|--------------|
| 445   | TCP      | SMB     | 8943         |
| 1433  | TCP      | MS-SQL  | 4481         |
| 8728  | TCP      | Mikrotik| 292          |
| 22    | TCP      | SSH     | 537          |
| 30003 | TCP      | -       | 537          |
| 25    | TCP      | SMTP    | 245          |
| 5901  | TCP      | VNC     | 84           |
| 80    | TCP      | HTTP    | 75           |
| 6379  | TCP      | Redis   | 32           |
| 5432  | TCP      | PostgreSQL| 76           |

### Most Common CVEs

| CVE ID        | Count |
|---------------|-------|
| CVE-2025-55182| 6     |
| CVE-2024-14007| 6     |
| CVE-2002-0013 | 4     |
| CVE-2002-0012 | 4     |
| CVE-2019-11500| 5     |
| CVE-2021-3449 | 4     |
| CVE-2023-46604| 2     |

### Commands Attempted by Attackers

No commands were captured in the logs.

### Signatures Triggered

| Signature                                             | ID      | Count |
|---------------------------------------------------------|---------|-------|
| GPL INFO VNC server response                            | 2100560 | 40236 |
| SURICATA IPv4 truncated packet                          | 2200003 | 3161  |
| SURICATA AF-PACKET truncated packet                     | 2200122 | 3161  |
| ET DROP Dshield Block Listed Source group 1             | 2402000 | 656   |
| ET SCAN MS Terminal Server Traffic on Non-standard Port | 2023753 | 1018  |
| ET HUNTING RDP Authentication Bypass Attempt            | 2034857 | 499   |
| SURICATA STREAM Packet with broken ack                  | 2210051 | 370   |
| SURICATA STREAM reassembly sequence GAP -- missing packet(s) | 2210048 | 247   |
| ET INFO SSH session in progress on Expected Port        | 2001978 | 200   |
| ET SCAN NMAP -sS window 1024                            | 2009582 | 200   |

### Users / Login Attempts

| Username      | Password      | Count |
|---------------|---------------|-------|
| root          | (empty string)| 44    |
| root          | 123456        | 38    |
| ubuntu        | 123456        | 16    |
| ubuntu        | admin123      | 14    |
| root          | admin         | 7     |
| admin         | admin         | 7     |
| root          | 123           | 14    |
| root          | password      | 7     |
| admin         | 123456        | 7     |
| backup        | 123456        | 9     |

### Files Uploaded/Downloaded

No files were uploaded or downloaded.

### HTTP User-Agents

No HTTP User-Agents were captured in the logs.

### SSH Clients and Servers

#### SSH Clients

| Client         | Count |
|----------------|-------|
| Go-http-client/1.1| 43 |
| -              | -     |

#### SSH Servers

| Server         | Count |
|----------------|-------|
| -              | -     |

### Top Attacker AS Organizations

| ASN      | Organization                                | Attack Count |
|----------|---------------------------------------------|--------------|
| AS51167  | Contabo GmbH                                 | 4480         |
| AS59191  | PEERCAST TELECOM INDIA PVT LTD                 | 2538         |
| AS133481 | AIS Fibre                                    | 2694         |
| AS1221   | Telstra Limited                              | 1857         |
| AS14061  | DigitalOcean, LLC                             | 2816         |
| AS701    | Verizon Business                             | 793          |
| AS15802  | Emirates Integrated Telecommunications Company PJSC | 562          |
| AS134873 | ABS BROADBAND SERVICES PVT LTD               | 515          |
| AS47890  | Unmanaged Ltd                                | 1103         |
| AS396982 | Google LLC                                   | 787          |

### OSINT All Commands Captured

No commands were captured in the logs.

### OSINT High Frequency IPs and Low Frequency IPs Captured

| IP Address       | Frequency | Country         | ASN                                      | OSINT Summary                                                                                                                                                                                            |
|------------------|-----------|-----------------|------------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| 173.249.6.152    | High      | France          | AS51167 Contabo GmbH                      | Associated with Contabo GmbH, a German web hosting company. While no direct abuse reports for this specific IP were found, other IPs from the same provider have been reported for malicious activities.    |
| 103.218.135.57   | High      | India           | AS59191 PEERCAST TELECOM INDIA PVT LTD     | Linked to Rv Broadband in Chennai, India. Historical data shows a low threat level and inclusion on a blacklist, but no current specific malicious activity is reported on major threat intelligence platforms. |
| 110.49.3.20      | High      | Thailand        | AS133481 AIS Fibre                        | Associated with a datacenter in Bangkok, Thailand. No public threat intelligence reports indicate malicious activity from this IP.                                                                           |
| 144.130.11.9     | High      | Australia       | ASN 1221 Telstra Limited                 | Identified as a source of brute-force, RDP, and SMB attacks. The IP has been flagged for malicious activity over an extended period.                                                                     |
| 2.57.121.22      | Low       | Romania         | AS47890 Unmanaged Ltd                     | No specific OSINT information available from the search.                                                                                                                                                 |

### OSINT on CVEs

| CVE ID        | Summary                                                                                                                                                                                                                                                                                                                      |
|---------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| CVE-2024-14007| A critical authentication bypass vulnerability in Shenzhen TVT Digital NVMS-9000 firmware, allowing unauthenticated remote attackers to execute privileged administrative query commands and disclose sensitive information.                                                                                                    |
| CVE-2025-55182| A critical pre-authentication RCE vulnerability in React Server Components (React2Shell), allowing attackers to execute arbitrary code by sending a malicious HTTP POST request. This vulnerability is under active exploitation.                                                                                              |
| CVE-2002-0013 & CVE-2002-0012 | Widespread vulnerabilities in SNMPv1 implementations from early 2002, allowing remote attackers to cause a denial-of-service or gain unauthorized privileges by sending malicious SNMP requests or traps.                                                                                                                |
| CVE-2019-11500| A critical RCE vulnerability in Dovecot and Pigeonhole due to an out-of-bounds write when handling NULL characters in quoted strings. An unauthenticated attacker could exploit this to compromise the system.                                                                                                               |
| CVE-2021-3449 | A denial-of-service vulnerability in OpenSSL where a maliciously crafted `ClientHello` message during TLSv1.2 renegotiation can cause a NULL pointer dereference, leading to a server crash.                                                                                                                                 |
| CVE-2023-46604| A critical RCE vulnerability in Apache ActiveMQ due to insecure deserialization of serialized object payloads in the OpenWire protocol. This allows an unauthenticated attacker to execute arbitrary shell commands.                                                                                                           |

### Key Observations and Anomalies

*   **High Volume of VNC Scanning:** The overwhelming number of "GPL INFO VNC server response" alerts suggests a massive, widespread campaign of VNC-related reconnaissance and scanning.
*   **Targeted Attacks on Specific Services:** The high number of attacks on port 1433 (MS-SQL) from France and port 445 (SMB) from India, Australia, and Thailand indicates targeted campaigns against these services from specific regions.
*   **Cryptocurrency-Related Usernames:** The appearance of usernames like "solana," "trader," and "trading" suggests that some attackers may be specifically targeting systems believed to be involved in cryptocurrency activities.
*   **Mix of Old and New CVEs:** The variety of CVEs being exploited, from very old vulnerabilities like those from 2002 to recent and actively exploited ones like `CVE-2025-55182`, shows that attackers are using a wide range of exploits to target unpatched systems.
*   **Hyper-Aggressive IPs:** The extreme concentration of attacks from a few IP addresses, such as `173.249.6.152` and `103.218.135.57`, indicates that these are likely dedicated attack servers or part of a botnet.

### Unusual Attacker Origins - IP addresses from non-traditional sources

*   **United Arab Emirates:** While not in the top 3, the UAE appeared as a significant source of attacks, with a high-frequency IP (`5.31.128.119`) targeting port 445. This is a less common source country for high-volume attacks in our logs.
*   **Thailand:** Similar to the UAE, Thailand emerged as a major source of attacks, with `110.49.3.20` being one of the most aggressive IPs observed, also targeting port 445.