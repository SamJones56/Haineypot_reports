# Honeypot Attack Summary Report

**Report Generation Time:** 2026-02-17T08:00:00Z
**Timeframe:** 2026-02-16T07:00:41Z to 2026-02-17T06:00:36Z (Last 6 hours)

**Files Used to Generate Report:**
- `/home/user/Haineypot/reports/hourly_reports/Honeypot_Attack_Hourly_Report_2026-02-16T07-01-21Z.md`
- `/home/user/Haineypot/reports/hourly_reports/Honeypot_Attack_Hourly_Report_2026-02-16T08-01-29Z.md`
- `/home/user/Haineypot/reports/hourly_reports/Honeypot_Attack_Hourly_Report_2026-02-16T10-06-11Z.md`
- `/home/user/Haineypot/reports/hourly_reports/Honeypot_Attack_Hourly_Report_2026-02-16T19-57-04Z.md`
- `/home/user/Haineypot/reports/hourly_reports/Honeypot_Attack_Hourly_Report_2026-02-16T20-01-42Z.md`
- `/home/user/Haineypot/reports/hourly_reports/Honeypot_Attack_Hourly_Report_2026-02-17T06-01-25Z.md`

---

## Executive Summary

This report summarizes the honeypot activity over the last 6 hours, from 2026-02-16T07:00:41Z to 2026-02-17T06:00:36Z. During this period, a total of **30513** attacks were recorded. The majority of attacks originated from the **United States**, **France**, and **Australia**.

A significant portion of the attacks were categorized as "Misc activity" and "Generic Protocol Command Decode", with "GPL INFO VNC server response" being the most frequently triggered signature. This suggests a high volume of scanning and reconnaissance activity, particularly targeting VNC services.

Several hyper-aggressive IP addresses were identified, with `165.245.136.26` (United States), `173.249.6.152` (France), and `144.130.11.9` (Australia) being the most prominent. These IPs were responsible for a large number of attacks, indicating targeted or automated campaigns.

A number of CVEs were observed being exploited, including both recent and older vulnerabilities. This indicates that attackers are attempting to leverage a wide range of known security flaws. The most common attack vectors included targeting of services like SMB (port 445), SSH (port 22), and MS SQL (port 1433).

OSINT analysis on the top attacking IPs revealed connections to major hosting providers like DigitalOcean and Contabo GmbH, which are known to be used for both legitimate and malicious activities.

Overall, the honeypot network experienced a high level of automated and targeted attacks, with a focus on reconnaissance and exploitation of common vulnerabilities.

---

## Detailed Analysis

### Our IPs

| Honeypot Name | IP Address      |
|---------------|-----------------|
| tpot-hive-ny  | 134.199.242.175 |

### Attacks by honeypot

| Honeypot Name | Total Attacks |
|---------------|---------------|
| tpot-hive-ny  | 30513         |

### Top source countries

| Country              | Attack Count |
|----------------------|--------------|
| United States        | 11391        |
| France               | 4757         |
| Australia            | 2217         |
| India                | 3632         |
| Romania              | 1417         |
| Netherlands          | 1138         |
| United Arab Emirates | 758          |
| China                | 692          |
| Brazil               | 904          |
| Switzerland          | 267          |

### Top attacking IPs

| IP Address         | Country         | ASN                             | Attack Count |
|--------------------|-----------------|---------------------------------|--------------|
| 165.245.136.26     | United States   | 14061: DigitalOcean, LLC        | 8654         |
| 173.249.6.152      | France          | 51167: Contabo GmbH             | 4477         |
| 144.130.11.9       | Australia       | 1221: Telstra Limited           | 1857         |
| 103.218.135.57     | India           | 59191: PEERCAST TELECOM INDIA   | 2538         |
| 5.31.128.119       | United Arab Emirates | 15802: Emirates Integrated Telecom | 758          |
| 177.126.130.163    | Brazil          | 262343: Net Aki Internet Ltda   | 901          |
| 139.59.69.34       | India           | 14061: DigitalOcean, LLC        | 544          |
| 103.204.164.37     | India           | 134873: ABS BROADBAND SERVICES  | 515          |
| 2.57.121.22        | Romania         | 47890: Unmanaged Ltd            | 497          |
| 80.94.95.216       | Romania         | 204428: SS-Net                  | 350          |

### Top targeted ports/protocols

| Port  | Protocol | Service | Attack Count |
|-------|----------|---------|--------------|
| 445   | TCP      | SMB     | 5370         |
| 1433  | TCP      | MS SQL  | 4478         |
| 22    | TCP      | SSH     | 2011         |
| 8728  | TCP      | MikroTik| 277          |
| 30003 | TCP      |         | 524          |
| 5901  | TCP      | VNC     | 84           |
| 25    | TCP      | SMTP    | 245          |
| 80    | TCP      | HTTP    | 79           |

### Most common CVEs

| CVE ID          |
|-----------------|
| CVE-2025-55182  |
| CVE-2021-3449   |
| CVE-2019-11500  |
| CVE-2024-14007  |
| CVE-2023-26801  |
| CVE-2002-0013   |
| CVE-2002-0012   |

### Commands attempted by attackers

No commands were captured in the logs.

### Signatures triggered

| Signature ID | Signature Name                                       | Trigger Count |
|--------------|------------------------------------------------------|---------------|
| 2100560      | GPL INFO VNC server response                         | 38898         |
| 2200003      | SURICATA IPv4 truncated packet                       | 4390          |
| 2200122      | SURICATA AF-PACKET truncated packet                  | 4390          |
| 2402000      | ET DROP Dshield Block Listed Source group 1          | 591           |
| 2023753      | ET SCAN MS Terminal Server Traffic on Non-standard Port | 1018          |
| 2038967      | ET INFO SSH-2.0-Go version string Observed           | 160           |
| 2210061      | SURICATA STREAM spurious retransmission              | 155           |
| 2009582      | ET SCAN NMAP -sS window 1024                         | 161           |
| 2210048      | SURICATA STREAM reassembly sequence GAP              | 118           |
| 2034857      | ET HUNTING RDP Authentication Bypass Attempt         | 499           |

### Users / login attempts

| Username   | Password      | Attempt Count |
|------------|---------------|---------------|
| root       | 123456        | 578           |
| root       | (empty string)| 44            |
| admin      | 123456        | 578           |
| ubuntu     | 123456        | 578           |
| root       | 123           | 70            |
| root       | 111111        | 44            |
| root       | 1qaz@WSX      | 37            |
| root       | !@#           | 39            |
| root       | password      | 7             |
| eigen      | eigen         | 6             |
| eigenlayer | eigenlayer    | 6             |
| sol        | (empty string)| 5             |
| solana     | (empty string)| 4             |

### Files uploaded/downloaded

No files were uploaded or downloaded.

### HTTP User-Agents

No HTTP User-Agents were captured in the logs.

### SSH clients and servers

No SSH client and server information was captured in the logs.

### Top attacker AS organizations

| ASN      | Organization                                | Attack Count |
|----------|---------------------------------------------|--------------|
| 14061    | DigitalOcean, LLC                           | 14251        |
| 51167    | Contabo GmbH                                | 4480         |
| 1221     | Telstra Limited                             | 1857         |
| 59191    | PEERCAST TELECOM INDIA PVT LTD              | 2538         |
| 15802    | Emirates Integrated Telecommunications Company PJSC | 758          |
| 262343   | Net Aki Internet Ltda                       | 901          |
| 396982   | Google LLC                                  | 738          |
| 47890    | Unmanaged Ltd                               | 1328         |
| 4837     | CHINA UNICOM China169 Backbone              | 644          |
| 204428   | SS-Net                                      | 240          |

### OSINT All Commands captured

No commands were captured in the logs.

### OSINT High frequency IPs and low frequency IPs Captured

| IP Address     | Country       | ASN                   | OSINT Summary                                                                                                                                                             |
|----------------|---------------|-----------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| 165.245.136.26 | United States | DigitalOcean, LLC     | Associated with DigitalOcean hosting. Observed in connection with SSH services. No specific malicious activity reported, but the hosting provider is known to be used for malicious purposes. |
| 173.249.6.152  | France        | Contabo GmbH          | Associated with Contabo GmbH, a German hosting provider. While no direct malicious activity is reported, Contabo servers have been used in malware campaigns.              |
| 144.130.11.9   | Australia     | Telstra Limited       | Registered to Telstra Limited in Australia. Limited public information available, but it is suspected to be part of a university network. No specific malicious activity reported. |
| 5.31.128.119   | United Arab Emirates | Emirates Integrated Telecom | Associated with a major telecommunications company in the UAE. Limited public information available.                                                              |
| 177.126.130.163| Brazil        | Net Aki Internet Ltda | Associated with a Brazilian internet provider. Limited public information available.                                                                                   |

### OSINT on CVE's

| CVE ID        | Summary                                                                                                                                                                                          |
|---------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| CVE-2021-3449 | A DoS vulnerability in OpenSSL that can be exploited by a remote attacker to crash a server. Affects OpenSSL versions 1.1.1 up to 1.1.1j.                                                         |
| CVE-2019-11500| A critical remote code execution vulnerability in Dovecot and Pigeonhole that can be exploited by an unauthenticated attacker.                                                                  |
| CVE-2024-14007| A critical authentication bypass vulnerability in NVMS-9000 firmware that allows for unauthorized access to sensitive information.                                                                 |
| CVE-2023-26801| A critical command injection vulnerability in multiple LB-LINK routers that allows unauthenticated attackers to execute arbitrary commands with root privileges.                                   |
| CVE-2002-0013 | A widespread vulnerability in SNMPv1 that could allow a remote attacker to cause a DoS or gain administrative privileges on an affected device.                                                    |
| CVE-2002-0012 | A widespread vulnerability in SNMPv1 that could allow a remote attacker to cause a DoS or gain administrative privileges on an affected device by sending malformed trap messages.                  |

---

## Key Observations and Anomalies

*   **Hyper-aggressive IPs:** A small number of IP addresses were responsible for a large percentage of the total attacks. This suggests that these IPs are part of automated botnets or targeted attack campaigns.
*   **VNC Scanning:** The high number of "GPL INFO VNC server response" alerts indicates widespread scanning for open VNC servers. This is a common tactic used by attackers to find vulnerable systems.
*   **Targeting of Common Services:** The most targeted ports were 445 (SMB), 1433 (MS SQL), and 22 (SSH). These are all well-known services that are often targeted by attackers.
*   **Use of Hosting Providers:** Many of the top attacking IPs were traced back to large hosting providers like DigitalOcean and Contabo. This is a common trend, as attackers often use compromised servers or cheap hosting to launch their attacks.
*   **Exploitation of Old and New CVEs:** The presence of both old and new CVEs suggests that attackers are using a variety of exploits to target a wide range of systems.
*   **Unusual Usernames/Passwords:** The use of "eigen" and "eigenlayer" as passwords, and "sol" and "solana" as usernames, could indicate targeted attacks against specific applications or services.

## Unusual Attacker Origins

The majority of attacks originated from expected sources, such as the United States, China, and various European countries. However, the high volume of attacks from a single IP in the United Arab Emirates is noteworthy. While the UAE is not an uncommon source of cyberattacks, the concentration of attacks from a single IP is unusual and warrants further investigation.

Additionally, the attacks from Australia, particularly from the IP `144.130.11.9`, are interesting. While the OSINT on this IP is limited, the suspicion that it may be part of a university network could suggest a compromised machine within the university network is being used to launch attacks.

---
