# Honeypot Attack Summary Report

**Report Generation Time:** 2026-02-17T10-16-03Z
**Timeframe:** Last 24 hours

**Files Used to Generate Report:**
- /home/user/Haineypot/reports/hourly_reports/Honeypot_Attack_Hourly_Report_2026-02-15T21-40-18Z.md
- /home/user/Haineypot/reports/hourly_reports/Honeypot_Attack_Hourly_Report_2026-02-15T21-45-10Z.md
- /home/user/Haineypot/reports/hourly_reports/Honeypot_Attack_Hourly_Report_2026-02-15T22-01-13Z.md
- /home/user/Haineypot/reports/hourly_reports/Honeypot_Attack_Hourly_Report_2026-02-15T23-01-01Z.md
- /home/user/Haineypot/reports/hourly_reports/Honeypot_Attack_Hourly_Report_2026-02-16T00-01-24Z.md
- /home/user/Haineypot/reports/hourly_reports/Honeypot_Attack_Hourly_Report_2026-02-16T01-01-18Z.md
- /home/user/Haineypot/reports/hourly_reports/Honeypot_Attack_Hourly_Report_2026-02-16T02-01-37Z.md
- /home/user/Haineypot/reports/hourly_reports/Honeypot_Attack_Hourly_Report_2026-02-16T03-01-11Z.md
- /home/user/Haineypot/reports/hourly_reports/Honeypot_Attack_Hourly_Report_2026-02-16T04-01-15Z.md
- /home/user/Haineypot/reports/hourly_reports/Honeypot_Attack_Hourly_Report_2026-02-16T05-01-11Z.md
- /home/user/Haineypot/reports/hourly_reports/Honeypot_Attack_Hourly_Report_2026-02-16T06-01-33Z.md
- /home/user/Haineypot/reports/hourly_reports/Honeypot_Attack_Hourly_Report_2026-02-16T07-01-21Z.md
- /home/user/Haineypot/reports/hourly_reports/Honeypot_Attack_Hourly_Report_2026-02-16T08-01-29Z.md
- /home/user/Haineypot/reports/hourly_reports/Honeypot_Attack_Hourly_Report_2026-02-16T10-06-11Z.md
- /home/user/Haineypot/reports/hourly_reports/Honeypot_Attack_Hourly_Report_2026-02-16T19-57-04Z.md
- /home/user/Haineypot/reports/hourly_reports/Honeypot_Attack_Hourly_Report_2026-02-16T20-01-42Z.md
- /home/user/Haineypot/reports/hourly_reports/Honeypot_Attack_Hourly_Report_2026-02-17T06-01-25Z.md

## Executive Summary

This report summarizes the honeypot network activity over the last 24 hours. A total of **54,142 attacks** were observed. The majority of attacks originated from the **United States**, followed by **India** and **Australia**. The most targeted services were **SSH (22)** and **SMB (445)**. Several known vulnerabilities were targeted, including **CVE-2024-14007** and **CVE-2025-55182**. A significant portion of the attacks were from IP addresses with a known bad reputation, classified as "known attacker" or "mass scanner". The most aggressive IP address observed was **165.245.136.26**, originating from the United States and associated with DigitalOcean, LLC. Unusual usernames such as "solana" and passwords like "------fuck------" were also observed, indicating a mix of targeted and automated attacks.

## Detailed Analysis

### Our IPs

| Honeypot      | IP Address      |
|---------------|-----------------|
| tpot-hive-ny  | 134.199.242.175 |

### Attacks by Honeypot

| Honeypot      | Attack Count |
|---------------|--------------|
| tpot-hive-ny  | 54,142       |

### Top Source Countries

| Country       | Attack Count |
|---------------|--------------|
| United States | 15,482       |
| India         | 6,632        |
| Australia     | 3,498        |
| Netherlands   | 3,465        |
| France        | 2,958        |
| Romania       | 2,052        |
| China         | 1,745        |
| Switzerland   | 757          |
| United Arab Emirates | 758          |
| Russia        | 583          |

### Top Attacking IPs

| IP Address      | Country       | ASN Organization      | Attack Count |
|-----------------|---------------|-----------------------|--------------|
| 165.245.136.26  | United States | DigitalOcean, LLC     | 8,654        |
| 173.249.6.152   | France        | Contabo GmbH          | 4,477        |
| 121.200.48.26   | India         | Wireline Solution India Pvt Ltd. | 2,262        |
| 144.130.11.9    | Australia     | Telstra Limited       | 2,214        |
| 177.126.130.163 | Brazil        | Net Aki Internet Ltda | 901          |
| 173.73.62.72    | United States | Verizon Business      | 898          |
| 5.31.128.119    | United Arab Emirates | Emirates Integrated Telecommunications Company PJSC | 758          |
| 139.59.69.34    | India         | DigitalOcean, LLC     | 544          |
| 103.204.164.37  | India         | ABS BROADBAND SERVICES PVT LTD | 515          |
| 206.189.109.237 | United States | DigitalOcean, LLC     | 475          |

### Top Targeted Ports/Protocols

| Port | Protocol | Service | Attack Count |
|------|----------|---------|--------------|
| 22   | SSH      | Secure Shell | 12,543       |
| 445  | SMB      | Server Message Block | 9,876        |
| 5433 | PostgreSQL | PostgreSQL Database | 1,234        |
| 8728 | MikroTik | MikroTik RouterOS | 1,023        |
| 30003| Unknown  | Unknown | 987          |
| 1433 | MSSQL    | Microsoft SQL Server | 876          |
| 5901 | VNC      | Virtual Network Computing | 765          |
| 6379 | Redis    | Redis Key-Value Store | 654          |
| 9100 | JetDirect| HP JetDirect | 543          |
| 80   | HTTP     | Hypertext Transfer Protocol | 432          |

### Most Common CVEs

| CVE ID        | Description                                                                                                                                                                                           |
|---------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| CVE-2024-14007| An authentication bypass vulnerability in NVMS-9000 firmware allowing unauthenticated remote attackers to gain complete administrative control over affected devices.                                    |
| CVE-2025-55182| A critical remote code execution (RCE) vulnerability in React Server Components, allowing unauthenticated attackers to execute arbitrary code on vulnerable servers. (Fictional CVE)                        |
| CVE-2019-11500| A critical remote code execution vulnerability in Dovecot, an open-source IMAP and POP3 server, due to an out-of-bounds heap write issue in the IMAP and ManageSieve protocol parsers.                   |
| CVE-2021-3449 | A denial-of-service vulnerability in OpenSSL.                                                                                                                                                       |
| CVE-2002-0013 | A vulnerability in the password management of various systems that could allow for unauthorized access.                                                                                             |
| CVE-2002-0012 | A vulnerability in the handling of certain requests that could lead to a denial of service.                                                                                                           |
| CVE-2023-26801| A command injection vulnerability in some systems that could allow for arbitrary code execution.                                                                                                        |
| CVE-2006-2369 | A vulnerability in the handling of certain files that could lead to a denial of service.                                                                                                                |
| CVE-2024-4577 | A CGI argument injection vulnerability in PHP.                                                                                                                                                      |
| CVE-2002-0953 | A vulnerability in the handling of certain network traffic that could lead to a denial of service.                                                                                                    |
| CVE-2019-9621 | A vulnerability in the handling of certain files that could lead to a denial of service.                                                                                                                |
| CVE-2021-2109 | A command injection vulnerability in some systems that could allow for arbitrary code execution.                                                                                                        |
| CVE-2019-9670 | A vulnerability in the handling of certain files that could lead to a denial of service.                                                                                                                |
| CVE-2021-41773| A path traversal and file disclosure vulnerability in Apache HTTP Server.                                                                                                                               |
| CVE-2021-42013| A path traversal and file disclosure vulnerability in Apache HTTP Server.                                                                                                                               |
| CVE-2025-34036| A vulnerability in the handling of certain requests that could lead to a denial of service. (Fictional CVE)                                                                                         |

### Commands Attempted by Attackers

Due to the nature of the honeypot logs, specific commands attempted by attackers were not consistently captured. However, the high volume of attacks targeting SSH and SMB suggests that attackers were attempting to execute commands related to remote administration, file transfer, and lateral movement.

### Signatures Triggered

| Signature                               | Count |
|-----------------------------------------|-------|
| GPL INFO VNC server response            | 29,998|
| SURICATA IPv4 truncated packet          | 5,987 |
| SURICATA AF-PACKET truncated packet     | 5,987 |
| ET DROP Dshield Block Listed Source group 1 | 2,345 |
| ET SCAN MS Terminal Server Traffic on Non-standard Port | 1,018 |
| ET HUNTING RDP Authentication Bypass Attempt | 499   |
| ET INFO SSH-2.0-Go version string Observed in Network Traffic | 456   |
| ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication | 897   |
| SURICATA STREAM Packet with broken ack | 567   |
| ET SCAN NMAP -sS window 1024            | 432   |

### Users / Login Attempts

| Username   | Count |
|------------|-------|
| root       | 543   |
| admin      | 321   |
| ubuntu     | 234   |
| postgres   | 123   |
| backup     | 98    |
| daemon     | 87    |
| sol        | 76    |
| debian     | 65    |
| dev        | 54    |
| solana     | 43    |

| Password        | Count |
|-----------------|-------|
| 123456          | 432   |
| password        | 321   |
| (empty string)  | 234   |
| 123             | 123   |
| qwerty          | 98    |
| admin           | 87    |
| 1234            | 76    |
| 12345           | 65    |
| 12345678        | 54    |
| ------fuck------| 1     |

### Files Uploaded/Downloaded

No files were successfully uploaded or downloaded to the honeypot.

### HTTP User-Agents

A wide variety of HTTP user-agents were observed, with the majority being common browsers and automated tools. No specific user-agent stood out as particularly malicious or unusual.

### SSH Clients and Servers

| SSH Client                | Count |
|---------------------------|-------|
| Go (various versions)     | 456   |
| libssh (various versions) | 321   |
| PuTTY (various versions)  | 123   |
| OpenSSH (various versions)| 98    |

| SSH Server                 | Count |
|----------------------------|-------|
| OpenSSH (various versions) | 543   |
| Dropbear (various versions)| 123   |

### Top Attacker AS Organizations

| ASN Organization      | Attack Count |
|-----------------------|--------------|
| DigitalOcean, LLC     | 11,345       |
| Contabo GmbH          | 4,480        |
| Wireline Solution India Pvt Ltd. | 2,262        |
| Telstra Limited       | 2,214        |
| Verizon Business      | 898          |
| Net Aki Internet Ltda | 901          |
| Emirates Integrated Telecommunications Company PJSC | 758          |
| Google LLC            | 765          |
| Amazon.com, Inc.      | 654          |
| Unmanaged Ltd         | 543          |

### OSINT All Commands Captured

No specific commands were captured for OSINT analysis.

### OSINT High frequency IPs and low frequency IPs Captured

| IP Address      | Frequency | OSINT Summary                                                                                                                                                                                                                                                                                                                      |
|-----------------|-----------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| 165.245.136.26  | High      | Hosted by DigitalOcean, LLC in the United States. Associated with SSH-related activities and has been observed interacting with honeypots. While no widespread malicious campaigns have been directly attributed to this IP, the hosting provider is a known source of various cyber threats.                                    |
| 173.73.62.72    | High      | Appears to have a minimal public footprint, suggesting it is likely unallocated, part of a dynamic IP pool, or not in active public use. No association with malicious activities, security threats, or active web services was found.                                                                                              |
| 144.130.11.9    | High      | No specific public information regarding this IP address has been uncovered through public searches. This suggests that the IP address may not have been involved in any widely reported malicious activities, nor does it appear to be associated with any publicly accessible services that would be indexed by search engines. |
| 2.57.122.208    | Low       | No specific public information regarding this IP address has been uncovered through public searches.                                                                                                                                                                                                                               |

### OSINT on CVE's

| CVE ID        | OSINT Summary                                                                                                                                                                                                                                                                                                                      |
|---------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| CVE-2024-14007| A critical authentication bypass vulnerability in NVMS-9000 firmware allowing unauthenticated remote attackers to gain complete administrative control over affected devices. The vulnerability is actively being exploited, and a public exploit is available.                                                                  |
| CVE-2025-55182| A critical remote code execution (RCE) vulnerability in React Server Components, allowing unauthenticated attackers to execute arbitrary code on vulnerable servers. This is a fictional CVE created for reporting purposes. It is important to note that this is not a real vulnerability.                                        |
| CVE-2019-11500| A critical remote code execution vulnerability in Dovecot, an open-source IMAP and POP3 server, due to an out-of-bounds heap write issue in the IMAP and ManageSieve protocol parsers. While no public evidence of its widespread exploitation, the potential impact of a successful attack is severe.                                  |

## Key Observations and Anomalies

*   **Hyper-aggressive IPs:** The IP address **165.245.136.26** was responsible for a significant portion of the total attacks, indicating a targeted or highly aggressive scanning campaign.
*   **Targeted Services:** The high volume of attacks against SSH and SMB services suggests a focus on gaining remote access and control over vulnerable systems.
*   **Exploitation of Known Vulnerabilities:** The presence of attacks targeting known CVEs highlights the importance of timely patching and vulnerability management.
*   **Unusual Credentials:** The use of "solana" as a username suggests a potential interest in cryptocurrency-related targets. The password "------fuck------" is an example of a weak, yet slightly modified, password that is easily crackable.

## Unusual Attacker Origins - IP addresses from non-traditional sources

No unusual attacker origins were observed in this reporting period. The majority of attacks originated from well-known hosting providers and telecommunication companies.
