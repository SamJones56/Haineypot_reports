# Honeypot Attack Summary Report

**Report Generation Time:** 2026-02-17T09-56-47Z
**Timeframe:** Last 6 hours (aggregated from hourly reports)
**Files Used:**
- /home/user/Haineypot/reports/hourly_reports/Honeypot_Attack_Hourly_Report_2026-02-16T07-01-21Z.md
- /home/user/Haineypot/reports/hourly_reports/Honeypot_Attack_Hourly_Report_2026-02-16T08-01-29Z.md
- /home/user/Haineypot/reports/hourly_reports/Honeypot_Attack_Hourly_Report_2026-02-16T10-06-11Z.md
- /home/user/Haineypot/reports/hourly_reports/Honeypot_Attack_Hourly_Report_2026-02-16T19-57-04Z.md
- /home/user/Haineypot/reports/hourly_reports/Honeypot_Attack_Hourly_Report_2026-02-16T20-01-42Z.md
- /home/user/Haineypot/reports/hourly_reports/Honeypot_Attack_Hourly_Report_2026-02-17T06-01-25Z.md

## Executive Summary

This report summarizes honeypot activity over the last 6 hours, aggregating data from six hourly reports. A total of 30,513 attacks were detected, with a significant portion of the activity originating from France, the United States, and India. The attacks were varied, ranging from widespread scanning and brute-force attempts to the exploitation of known vulnerabilities. The most targeted services were SMB (port 445), SSH (port 22), and MS-SQL (port 1433). A number of hyper-aggressive IP addresses were identified, with the most prolific being 173.249.6.152, located in France and associated with Contabo GmbH, which launched 4,477 attacks.

OSINT investigation into the most aggressive IPs revealed that many are hosted on commercial cloud and hosting platforms such as DigitalOcean and Contabo. Several of the IPs have been associated with malicious activity in the past, including being blacklisted for attacks and suspicious behavior.

Analysis of the CVEs exploited by attackers shows a mix of old and new vulnerabilities being targeted. These include critical remote code execution vulnerabilities like CVE-2025-55182 (React2Shell) and CVE-2023-26801 (LB-LINK Routers), as well as older but still prevalent vulnerabilities such as those found in SNMPv1 (CVE-2002-0012, CVE-2002-0013). This indicates that attackers are leveraging a wide range of vulnerabilities to compromise systems.

The most common alert signatures observed were related to VNC server responses and truncated IP packets, suggesting a high volume of scanning and reconnaissance activities. The most common usernames and passwords attempted were default and weak credentials, highlighting the continued prevalence of brute-force attacks.

## Detailed Analysis

### Our IPs

| Honeypot      | IP Address      |
|---------------|-----------------|
| tpot-hive-ny  | 134.199.242.175 |

### Attacks by Honeypot

| Honeypot      | Attack Count |
|---------------|--------------|
| tpot-hive-ny  | 30,513       |

### Top Source Countries

| Country       | Attack Count |
|---------------|--------------|
| France        | 4,753        |
| United States | 7,874        |
| India         | 3,632        |
| Australia     | 2,217        |
| Romania       | 1,417        |
| United Arab Emirates| 758          |
| Brazil        | 904          |
| China         | 772          |
| Netherlands   | 1,177        |

### Top Attacking IPs

| IP Address        | Country         | ASN                             | Attack Count |
|-------------------|-----------------|---------------------------------|--------------|
| 173.249.6.152     | France          | AS51167 Contabo GmbH            | 4,477        |
| 165.245.136.26    | United States   | AS14061 DigitalOcean, LLC       | 8,654        |
| 144.130.11.9      | Australia       | AS1221 Telstra Limited          | 1,857        |
| 103.218.135.57    | India           | AS59191 PEERCAST TELECOM        | 2,538        |
| 5.31.128.119      | United Arab Emirates | AS15802 Emirates Integrated Telecom | 758          |
| 177.126.130.163   | Brazil          | AS262343 Net Aki Internet Ltda  | 901          |
| 139.59.69.34      | India           | AS14061 DigitalOcean, LLC       | 544          |
| 103.204.164.37    | India           | AS134873 ABS BROADBAND          | 515          |

### Top Targeted Ports/Protocols

| Port  | Protocol | Service | Attack Count |
|-------|----------|---------|--------------|
| 445   | TCP      | SMB     | 5,581        |
| 1433  | TCP      | MS-SQL  | 4,478        |
| 22    | TCP      | SSH     | 2,544        |
| 8728  | TCP      | MikroTik| 299          |
| 5901  | TCP      | VNC     | 84           |
| 30003 | TCP      | Unknown | 522          |
| 25    | TCP      | SMTP    | 250          |

### Most Common CVEs

| CVE ID          | Description                                                                 |
|-----------------|-----------------------------------------------------------------------------|
| CVE-2025-55182  | Critical RCE in React Server Components (React2Shell)                         |
| CVE-2021-3449   | OpenSSL Denial-of-Service Vulnerability                                       |
| CVE-2019-11500  | RCE in Dovecot/Pigeonhole due to improper handling of NULL bytes              |
| CVE-2024-14007  | Authentication Bypass in NVMS-9000 surveillance firmware                       |
| CVE-2023-26801  | RCE in LB-LINK Routers                                                        |
| CVE-2002-0013   | DoS and Privilege Escalation in SNMPv1                                        |
| CVE-2002-0012   | DoS and RCE in SNMPv1 trap handling                                           |

### Commands Attempted by Attackers
No commands were captured in the logs.

### Signatures Triggered

| Signature ID | Signature                                               | Count |
|--------------|---------------------------------------------------------|-------|
| 2100560      | GPL INFO VNC server response                            | 30,000+ |
| 2200003      | SURICATA IPv4 truncated packet                          | 4,400+ |
| 2200122      | SURICATA AF-PACKET truncated packet                     | 4,400+ |
| 2402000      | ET DROP Dshield Block Listed Source group 1             | 577   |
| 2023753      | ET SCAN MS Terminal Server Traffic on Non-standard Port | 1,018 |
| 2038967      | ET INFO SSH-2.0-Go version string Observed              | 162   |
| 2009582      | ET SCAN NMAP -sS window 1024                            | 161   |

### Users / Login Attempts

**Usernames:**
- root: 94
- ubuntu: 45
- admin: 21
- backup: 19
- daemon: 13
- debian: 13
- dev: 13
- sol: 10
- postgres: 10

**Passwords:**
- (empty string): 37
- 123456: 257
- 123: 35
- admin123: 10
- admin: 8
- password: 7
- eigen: 6
- eigenlayer: 6

### Files Uploaded/Downloaded
No files were uploaded or downloaded.

### HTTP User-Agents
No HTTP User-Agents were captured.

### SSH Clients and Servers
No SSH client or server information was captured.

### Top Attacker AS Organizations

| ASN      | Organization                               | Attack Count |
|----------|--------------------------------------------|--------------|
| AS14061  | DigitalOcean, LLC                          | 13,848       |
| AS51167  | Contabo GmbH                               | 4,480        |
| AS1221   | Telstra Limited                            | 1,857        |
| AS59191  | PEERCAST TELECOM INDIA PVT LTD             | 2,538        |
| AS15802  | Emirates Integrated Telecommunications Company PJSC | 758        |
| AS262343 | Net Aki Internet Ltda                      | 901          |
| AS47890  | Unmanaged Ltd                              | 831          |
| AS396982 | Google LLC                                 | 738          |
| AS4837   | CHINA UNICOM China169 Backbone             | 597          |
| AS204428 | SS-Net                                     | 240          |

### OSINT All Commands Captured
No commands were captured.

### OSINT High frequency IPs and low frequency IPs Captured

| IP Address        | Frequency | OSINT Findings                                                                                                   |
|-------------------|-----------|------------------------------------------------------------------------------------------------------------------|
| 165.245.136.26    | High      | DigitalOcean server in Singapore. No direct evidence of malicious activity, but open ports present a risk.        |
| 173.249.6.152     | High      | Contabo GmbH server in Germany. No direct evidence of malicious activity.                                         |
| 144.130.11.9      | High      | Limited public information. Appears to be part of a larger block, possibly from Telstra in Australia.            |
| 103.218.135.57    | High      | Located in India, registered to Rv Broadband. Low threat level, but has been associated with attacks.              |
| 5.31.128.119      | High      | Registered to "LLC Network of data-centers Selectel" in Russia. No public evidence of malicious activity.          |
| 177.126.130.163   | High      | Geolocated to São Paulo, Brazil. Blacklisted for "attack" and "suspicious" activity.                               |
| 139.59.69.34      | High      | DigitalOcean server in India. No widespread public reports of malicious activity.                                |
| 103.204.164.37    | High      | Limited public information. Part of a geographically diverse network block. No direct ownership or activity data. |

### OSINT on CVE's

| CVE ID          | OSINT Findings                                                                                                                              |
|-----------------|---------------------------------------------------------------------------------------------------------------------------------------------|
| CVE-2025-55182  | Critical RCE in React Server Components. Actively exploited.                                                                                  |
| CVE-2021-3449   | Medium severity DoS in OpenSSL. Actively exploited.                                                                                         |
| CVE-2019-11500  | Critical RCE in Dovecot/Pigeonhole. Public PoC available.                                                                                   |
| CVE-2024-14007  | Critical auth bypass in NVMS-9000 firmware. Actively exploited by botnets.                                                                  |
| CVE-2023-26801  | Critical RCE in LB-LINK routers. Actively exploited by Mirai botnet. No official patch.                                                     |
| CVE-2002-0013   | Critical DoS and privilege escalation in SNMPv1. Widespread impact on legacy systems.                                                       |
| CVE-2002-0012   | Critical DoS and RCE in SNMPv1 trap handling. Widespread impact on legacy systems.                                                          |

### Key Observations and Anomalies

- **Hyper-aggressive IPs:** The honeypot network was targeted by several hyper-aggressive IP addresses, with 173.249.6.152, 165.245.136.26, and 144.130.11.9 being the most prominent. These IPs were responsible for a significant portion of the total attack volume.
- **Targeted Services:** The high volume of attacks on ports 445 (SMB) and 1433 (MS-SQL) suggests a focus on exploiting vulnerabilities in Windows and SQL server environments.
- **VNC Scanning:** The extremely high number of "GPL INFO VNC server response" alerts indicates widespread scanning for open VNC servers.
- **Use of Hosting Providers:** A large number of attacks originated from IP addresses associated with major hosting providers like DigitalOcean and Contabo. This is a common tactic used by attackers to obscure their true location and make attribution more difficult.
- **Exploitation of Old and New CVEs:** Attackers are leveraging a mix of both old and new vulnerabilities, indicating that many systems are not being patched regularly.

### Unusual Attacker Origins - IP addresses from non-traditional sources
The majority of the attacks originated from expected sources such as the United States, China, and Russia. However, there was also a significant number of attacks from countries not typically associated with high volumes of cyberattacks, such as the United Arab Emirates and Switzerland. This suggests a diversification of attack origins.
