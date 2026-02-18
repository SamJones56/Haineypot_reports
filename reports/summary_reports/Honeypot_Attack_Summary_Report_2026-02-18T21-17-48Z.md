Honeypot Attack Summary Report – 2026-02-18T21:14:25Z

**Metadata Section:**
- Report generation time: 2026-02-18T21:14:25Z
- Timeframe covered: 2026-02-17T21:14:25Z to 2026-02-18T21:14:25Z
- List of all files used:
    - /home/user/Haineypot/reports/hourly_reports/Honeypot_Attack_Hourly_Report_2026-02-18T09-10-39Z.md
    - /home/user/Haineypot/reports/hourly_reports/Honeypot_Attack_Hourly_Report_2026-02-18T10-01-29Z.md
    - /home/user/Haineypot/reports/hourly_reports/Honeypot_Attack_Hourly_Report_2026-02-18T11-39-12Z.md
    - /home/user/Haineypot/reports/hourly_reports/Honeypot_Attack_Hourly_Report_2026-02-18T18-41-44Z.md
    - /home/user/Haineypot/reports/hourly_reports/Honeypot_Attack_Hourly_Report_2026-02-18T19-01-17Z.md
    - /home/user/Haineypot/reports/hourly_reports/Honeypot_Attack_Hourly_Report_2026-02-18T19-12-31Z.md
    - /home/user/Haineypot/reports/hourly_reports/Honeypot_Attack_Hourly_Report_2026-02-18T19-16-17Z.md
    - /home/user/Haineypot/reports/hourly_reports/Honeypot_Attack_Hourly_Report_2026-02-18T20-01-20Z.md
    - /home/user/Haineypot/reports/hourly_reports/Honeypot_Attack_Hourly_Report_2026-02-18T20-30-14Z.md
    - /home/user/Haineypot/reports/hourly_reports/Honeypot_Attack_Hourly_Report_2026-02-18T21-06-40Z.md

**Executive Summary:**
- High-level findings: The honeypot network observed a high volume of attacks, with a total of 61,354 attacks in the last 24 hours. The attacks were characterized by a small number of hyper-aggressive IPs, with a significant portion of the attacks originating from France and Venezuela. The most common attack vector was scanning for open VNC servers, and there was evidence of attempts to install the DoublePulsar backdoor.
- Most critical threat actors: The most critical threat actors were the operators of the IPs `77.192.112.115`, `200.109.232.194`, and `129.212.183.188`. These IPs were responsible for a large volume of attacks and were identified as known attackers.
- Most exploited services: The most exploited services were VNC, SMB, and SSH.
- Primary geographic and ASN sources: The primary geographic sources of attacks were France, Venezuela, and the United States. The primary ASN sources were Societe Francaise Du Radiotelephone - SFR SA (AS15557), CANTV Servicios, Venezuela (AS8048), and DigitalOcean, LLC (AS14061).
- Key anomalies: The most significant anomaly was the concentration of attacks from a small number of hyper-aggressive IPs. This suggests that these IPs are likely part of a botnet or are dedicated malicious infrastructure.

**Detailed Analysis:**

**Our IPs:**
- tpot-hive-ny: 134.199.242.175

**Attacks by honeypot:**
- The provided reports do not contain a breakdown of attacks by honeypot.

**Top source countries:**
- France: 32388
- Venezuela: 14203
- United States: 6200
- Canada: 4399
- Netherlands: 1532
- China: 1384
- Switzerland: 853
- Germany: 740
- Sudan: 340
- Kazakhstan: 222
- Thailand: 560
- India: 257

**Top attacking IPs:**
- 77.192.112.115: 32173
- 200.109.232.194: 11202
- 129.212.183.188: 1850
- 143.110.221.173: 1328
- 152.42.135.55: 731
- 46.19.137.194: 634
- 167.71.98.228: 481
- 137.184.211.127: 434
- 110.49.3.20: 566

**Top targeted ports/protocols:**
- 22 (SSH)
- 445 (SMB)
- 3389 (RDP)
- 5900 (VNC)
- 1433 (MSSQL)
- 3306 (MySQL)
- 5432 (PostgreSQL)

**Most common CVEs (LIST ALL):**
- CVE-2025-55182
- CVE-2024-14007
- CVE-2023-46604
- CVE-2021-3449
- CVE-2019-11500
- CVE-2023-26801
- CVE-2002-0013
- CVE-2002-0012
- CVE-2002-0606
- CVE-2024-4577
- CVE-2002-0953
- CVE-2021-41773
- CVE-2021-42013

**Commands attempted:**
- The provided reports do not contain a list of commands attempted.

**Signatures triggered:**
- GPL INFO VNC server response
- SURICATA IPv4 truncated packet
- SURICATA AF-PACKET truncated packet
- ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication

**Users / login attempts:**
- root
- admin
- sa
- oracle
- postgres
- user
- guest
- test
- ubnt
- sol
- 123
- ubuntu
- a

**Files uploaded/downloaded:**
- The provided reports do not contain a list of files uploaded or downloaded.

**HTTP User-Agents:**
- The provided reports do not contain a list of HTTP User-Agents.

**SSH clients and servers:**
- The provided reports do not contain a list of SSH clients and servers.

**Top attacker AS organizations:**
- Societe Francaise Du Radiotelephone - SFR SA (AS15557)
- CANTV Servicios, Venezuela (AS8048)
- DigitalOcean, LLC (AS14061)
- Private Layer INC (AS51852)
- UCLOUD INFORMATION TECHNOLOGY HK LIMITED (AS135377)
- Modat B.V. (AS209334)
- AIS Fibre (AS133481)
- PS Internet Company LLP (AS48716)

**OSINT Section:**

**OSINT on commands:**
- The provided reports do not contain any commands to perform OSINT on.

**OSINT on high-frequency IPs:**
- **77.192.112.115:** This IP address has a negative reputation and is associated with malicious activity. It is listed on multiple threat intelligence blocklists and is linked to the domain "aminebabouri.fr". The IP is registered to "fr.sfr", a French telecommunications company.
- **200.109.232.194:** This IP address is registered to Telecomunicaciones de Mexico, S.A. de C.V., a major telecommunications provider in Mexico. There is no public information to suggest that this IP address is involved in any malicious activities.
- **129.212.183.188:** This IP address is associated with DigitalOcean, LLC, a major cloud infrastructure provider. While no direct evidence of malicious activity has been attributed to this specific IP, its proximity to other reported IPs within the same network block warrants a degree of caution.

**OSINT on low-frequency unique IPs:**
- The provided reports do not contain any low-frequency unique IPs to perform OSINT on.

**OSINT on CVEs:**
- **DoublePulsar Backdoor:** The alert signature "ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication" suggests that attackers are attempting to install the DoublePulsar backdoor. DoublePulsar is a backdoor implant developed by the NSA and was leaked by the Shadow Brokers in 2017. It was used in the WannaCry ransomware attacks.

**Key Observations and Anomalies:**
- **Hyper-aggressive actors:** The IPs `77.192.112.115`, `200.109.232.194`, and `129.212.183.188` were responsible for a significant portion of the total attack volume.
- **Infrastructure reuse:** The ASN `DigitalOcean, LLC` (AS14061) was observed across multiple attack sources, indicating that this provider is being used to host malicious infrastructure.
- **Campaign indicators:** The presence of the "DoublePulsar Backdoor" signature suggests that there may be a campaign to compromise systems with this backdoor.
- **Any statistically abnormal behavior:** The concentration of attacks from a small number of IPs is statistically abnormal and suggests a targeted campaign rather than random background noise.

**Unusual Attacker Origins:**
- Venezuela was a top source of attacks, which is not a traditional attacker origin. This suggests that there may be a botnet or a group of threat actors operating from this region.
