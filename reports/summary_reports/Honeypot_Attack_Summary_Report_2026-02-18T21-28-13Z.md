Honeypot Attack Summary Report – 2026-02-18T21:23:47Z

## Metadata

*   **Report Generation Time**: 2026-02-18T21:23:47Z
*   **Timeframe Covered**: 2026-02-17T21:23:47Z to 2026-02-18T21:23:47Z
*   **Files Used**:
    *   /home/user/Haineypot/reports/hourly_reports/Honeypot_Attack_Hourly_Report_2026-02-18T09-10-39Z.md
    *   /home/user/Haineypot/reports/hourly_reports/Honeypot_Attack_Hourly_Report_2026-02-18T10-01-29Z.md
    *   /home/user/Haineypot/reports/hourly_reports/Honeypot_Attack_Hourly_Report_2026-02-18T11-39-12Z.md
    *   /home/user/Haineypot/reports/hourly_reports/Honeypot_Attack_Hourly_Report_2026-02-18T18-41-44Z.md
    *   /home/user/Haineypot/reports/hourly_reports/Honeypot_Attack_Hourly_Report_2026-02-18T19-01-17Z.md
    *   /home/user/Haineypot/reports/hourly_reports/Honeypot_Attack_Hourly_Report_2026-02-18T19-12-31Z.md
    *   /home/user/Haineypot/reports/hourly_reports/Honeypot_Attack_Hourly_Report_2026-02-18T19-16-17Z.md
    *   /home/user/Haineypot/reports/hourly_reports/Honeypot_Attack_Hourly_Report_2026-02-18T20-01-20Z.md
    *   /home/user/Haineypot/reports/hourly_reports/Honeypot_Attack_Hourly_Report_2026-02-18T20-30-14Z.md
    *   /home/user/Haineypot/reports/hourly_reports/Honeypot_Attack_Hourly_Report_2026-02-18T21-06-40Z.md

## Executive Summary

This report summarizes 71,344 attacks detected over the last 24 hours. A significant portion of this activity was driven by two hyper-aggressive IP addresses: `77.192.112.115` in France (32,173 attacks) and `200.109.232.194` in Venezuela (11,302 attacks). These two IPs account for over 60% of the total attack volume.

The primary sources of attacks were France, Venezuela, and the United States. The most targeted services were VNC (port 5900), SMB (port 445) and SSH (port 22). Attackers were observed exploiting a range of vulnerabilities, with a focus on CVE-2024-14007, an authentication bypass in CCTV firmware, and CVE-2025-55182, a critical RCE in React Server Components.

One of the hourly reports indicated the presence of the DoublePulsar backdoor, a known NSA-developed tool.

## Detailed Analysis

### Our IPs

| Honeypot      | IP Address      |
|---------------|-----------------|
| tpot-hive-ny  | 134.199.242.175 |

### Attacks by Honeypot

| Honeypot      | Attacks |
|---------------|---------|
| tpot-hive-ny  | 71344   |

### Top Source Countries

| Country       | Attacks |
|---------------|---------|
| France        | 32388   |
| Venezuela     | 11303   |
| United States | 8858    |
| Canada        | 6524    |
| Netherlands   | 1432    |

### Top Attacking IPs

| IP Address        | Country     | Attacks |
|-------------------|-------------|---------|
| 77.192.112.115    | France      | 32173   |
| 200.109.232.194   | Venezuela   | 11302   |
| 129.212.183.188   | Unknown     | 1391    |
| 143.110.221.173   | Unknown     | 1329    |
| 110.49.3.20       | Thailand    | 566     |

### Top Targeted Ports/Protocols

| Port  | Protocol | Service | Attacks |
|-------|----------|---------|---------|
| 22    | TCP      | SSH     | High    |
| 445   | TCP      | SMB     | High    |
| 5900  | TCP      | VNC     | High    |
| 3389  | TCP      | RDP     | Medium  |
| 1433  | TCP      | MSSQL   | Medium  |

### Most Common CVEs

*   CVE-2025-55182
*   CVE-2024-14007
*   CVE-2023-46604
*   CVE-2021-3449
*   CVE-2019-11500
*   CVE-2023-26801
*   CVE-2002-0013
*   CVE-2002-0012
*   CVE-2002-0606
*   CVE-2024-4577
*   CVE-2002-0953
*   CVE-2021-41773
*   CVE-2021-42013

### Commands Attempted

No specific commands were captured in the aggregated reports.

### Signatures Triggered

| Signature                                | Count |
|------------------------------------------|-------|
| GPL INFO VNC server response             | High  |
| SURICATA IPv4 truncated packet           | High  |
| SURICATA AF-PACKET truncated packet      | High  |
| ET DROP Dshield Block Listed Source group 1 | Medium|
| SURICATA STREAM reassembly sequence GAP  | Medium|

### Users / Login Attempts

| Username | Passwords Used                          |
|----------|-----------------------------------------|
| root     | 1234, 123456, password, admin, 123     |
| admin    | 123456, admin, 1234, password         |
| sa       | 123123, 111111, password, 12345        |
| oracle   | (not specified)                         |
| ubuntu   | (not specified)                         |

### Files Uploaded/Downloaded

No files were uploaded or downloaded.

### HTTP User-Agents

No HTTP user-agents were recorded.

### SSH Clients and Servers

Not enough data to populate.

### Top Attacker AS Organizations

| ASN     | Organization                               | Attacks |
|---------|--------------------------------------------|---------|
| 15557   | Societe Francaise Du Radiotelephone - SFR SA | 32173   |
| 8048    | CANTV Servicios, Venezuela                 | 11302   |
| 14061   | DigitalOcean, LLC                          | 9431    |
| 209334  | Modat B.V.                                 | 2391    |
| 51852   | Private Layer INC                          | 564     |

## OSINT Section

### OSINT on Commands

No commands were logged in the provided reports.

### OSINT on High-Frequency IPs

*   **77.192.112.115**: This IP is associated with the French ISP Free SAS (AS12322). It has been observed in connection with several subdomains of `aminebabouri.fr` and has a history of being blacklisted for malicious activities. This suggests a potentially compromised residential or small business connection.
*   **200.109.232.194**: There is very limited public OSINT available for this IP address. It is associated with CANTV Servicios in Venezuela (AS8048). The lack of public information could indicate a recently activated IP, a dynamic IP, or a firewalled system with a low public profile.

### OSINT on Low-Frequency Unique IPs

Not enough data to perform OSINT on low-frequency IPs.

### OSINT on CVEs

*   **CVE-2025-55182**: A critical (CVSS 10.0) remote code execution vulnerability in React Server Components, dubbed "React2Shell". It is caused by insecure deserialization in the "Flight" protocol and can be exploited without authentication or user interaction. Exploitation has been observed in the wild.
*   **CVE-2024-14007**: A high-severity (CVSS 8.7) authentication bypass vulnerability in the NVMS-9000 firmware from Shenzhen TVT Digital Technology Co., Ltd., which is used in a wide range of CCTV products. The vulnerability allows an attacker to execute privileged commands and retrieve sensitive information, such as administrator credentials. Exploitation has been linked to the Mirai botnet.
*   **DoublePulsar Backdoor**: One of the reports mentioned the "ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication" signature. DoublePulsar is a kernel-mode backdoor developed by the NSA's Equation Group and was leaked by The Shadow Brokers in 2017. It was famously used in conjunction with the EternalBlue exploit in the WannaCry and NotPetya ransomware attacks.

## Key Observations and Anomalies

*   **Hyper-aggressive Actors**: The activity is dominated by two IP addresses, `77.192.112.115` and `200.109.232.194`, which are responsible for a combined total of over 43,000 attacks.
*   **Infrastructure Reuse**: The IP `77.192.112.115` has been consistently aggressive over a period of at least three hours. The IP `200.109.232.194` was also consistently aggressive for at least four hours.
*   **Campaign Indicators**: The high volume of attacks targeting VNC, SMB, and SSH, combined with the exploitation of known vulnerabilities like CVE-2024-14007, suggests widespread, automated scanning and exploitation campaigns. The presence of the DoublePulsar backdoor signature is a strong indicator of a sophisticated actor or botnet.
*   **Statistically Abnormal Behavior**: The concentration of over 60% of the attack volume from just two IP addresses is a significant deviation from normal background noise.

## Unusual Attacker Origins

*   **Venezuela**: While not a top-tier source of cyberattacks, the presence of a hyper-aggressive IP from Venezuela is noteworthy. The limited OSINT on this IP makes it difficult to determine the nature of the actor.
*   **Thailand**: The IP `110.49.3.20` from Thailand, associated with AIS Fibre, was responsible for 566 attacks in a single hour. This is an unusual source for a high volume of attacks.