
# Honeypot Attack Summary Report – 2026-02-20T00:46:59Z

## Metadata

- **Report Generation Time:** 2026-02-20T00:46:59Z
- **Timeframe Covered:** 2026-02-19T00:30:13Z - 2026-02-20T00:30:13Z
- **Files Used:**
    - `/home/user/Haineypot/reports/daily_reports/Honeypot_Attack_Daily_Report_2026-02-20T00-31-20Z.md`

## Executive Summary

Over the past 24 hours, the honeypot network observed 51,266 attacks, with a significant concentration of activity from Vietnam. A single IP address, 103.237.145.16, originating from ASN 131414 (Long Van Soft Solution JSC) in Vietnam, was responsible for over half of all recorded attacks (26,188). This hyper-aggressive activity appears to be linked to a targeted campaign, with OSINT confirming the IP's association with the Mirai botnet. The most frequently targeted vulnerability was CVE-2024-14007, an authentication bypass in DVR/NVR firmware also known to be exploited by Mirai variants. Credential stuffing attacks remained a common tactic, with "root" and "password" being the most frequently attempted credentials.

## Detailed Analysis

### Our IPs

| Honeypot       | IP Address      |
|----------------|-----------------|
| tpot-hive-ny   | 134.199.242.175 |

### Top Source Countries

| Country       | Attack Count |
|---------------|--------------|
| Vietnam       | 26,252       |
| United States | 6,857        |
| Germany       | 5,687        |
| Singapore     | 3,503        |
| India         | 2,000        |

### Top Attacking IPs

| IP Address      | Attack Count | ASN Organization             | Country       |
|-----------------|--------------|------------------------------|---------------|
| 103.237.145.16  | 26,188       | Long Van Soft Solution JSC   | Vietnam       |
| 4.145.113.4     | 2,441        | Microsoft Corporation        | United States |
| 139.59.82.171   | 1,608        | DigitalOcean, LLC            | India         |
| 207.154.239.37  | 1,503        | DigitalOcean, LLC            | United States |
| 207.154.211.38  | 1,300        | DigitalOcean, LLC            | United States |
| 104.248.249.212 | 1,275        | DigitalOcean, LLC            | United States |
| 165.227.161.214 | 1,249        | DigitalOcean, LLC            | United States |
| 134.199.173.128 | 970          | DigitalOcean, LLC            | United States |
| 134.199.153.94  | 923          | DigitalOcean, LLC            | United States |
| 152.42.206.51   | 520          | Google LLC                   | United States |

### Top Targeted Ports/Protocols

| Country       | Port | Attack Count |
|---------------|------|--------------|
| Vietnam       | 22   | 5,244        |
| Germany       | 22   | 1,071        |
| Singapore     | 5910 | 245          |
| India         | 22   | 377          |
| Australia     | 22   | 375          |
| United States | 22   | 165          |
| Netherlands   | 443  | 191          |
| Romania       | 22   | 116          |
| United Kingdom| 22   | 35           |
| Canada        | 8728 | 24           |

### Most Common CVEs

| CVE                               | Count |
|-----------------------------------|-------|
| CVE-2024-14007                    | 21    |
| CVE-2025-55182                    | 15    |
| CVE-2021-3449                     | 9     |
| CVE-2019-11500                    | 7     |
| CVE-2002-0013 CVE-2002-0012       | 3     |
| CVE-2003-0825                     | 2     |
| CVE-2006-2369                     | 2     |
| CVE-2010-0569                     | 2     |
| CVE-2024-4577 CVE-2002-0953       | 2     |
| CVE-2024-4577 CVE-2024-4577       | 2     |

### Signatures Triggered

| Signature                                         | Count  |
|---------------------------------------------------|--------|
| GPL INFO VNC server response                      | 14,682 |
| SURICATA IPv4 truncated packet                    | 9,303  |
| SURICATA AF-PACKET truncated packet               | 9,303  |
| ET DROP Dshield Block Listed Source group 1       | 776    |
| ET INFO SSH session in progress on Expected Port  | 470    |
| SURICATA STREAM reassembly sequence GAP -- missing packet(s) | 347    |
| ET INFO SSH-2.0-Go version string Observed in Network Traffic | 345    |
| ET SCAN NMAP -sS window 1024                      | 260    |
| SURICATA STREAM Packet with broken ack            | 174    |
| ET INFO SSH session in progress on Unusual Port   | 110    |

### Users / Login Attempts

| Username | Count |
|----------|-------|
| root     | 5,574 |
| admin    | 153   |
| sa       | 91    |
| backup   | 84    |
| docker   | 82    |
| oracle   | 82    |
| mysql    | 80    |
| guest    | 79    |
| postgres | 78    |
| debian   | 75    |

### Top Attacker AS Organizations

| ASN Organization           | Attack Count |
|----------------------------|--------------|
| Long Van Soft Solution JSC | 26,188       |
| DigitalOcean, LLC          | 12,797       |
| Microsoft Corporation      | 2,618        |
| Google LLC                 | 1,516        |
| Cogent Communications, LLC | 1,195        |
| UCLOUD INFORMATION TECHNOLOGY HK LIMITED | 809          |
| ONYPHE SAS                 | 743          |
| IP Volume inc              | 653          |
| Unmanaged Ltd              | 574          |
| Modat B.V.                 | 473          |

## OSINT Section

### OSINT on Hyper-Aggressive IPs
- **103.237.145.16:** OSINT analysis confirms this IP is listed on multiple threat intelligence blocklists, including "ci-badguys.txt" and "ipsum.txt". It has been specifically identified in lists of IPs associated with the Mirai botnet. The IP is registered to Long Van Soft Solution JSC, a hosting provider in Vietnam. The high volume of attacks from this single IP strongly indicates its use as part of a botnet infrastructure.

### OSINT on Attacker Infrastructure
- **AS131414 - Long Van Soft Solution JSC:** This Vietnamese hosting provider has a documented history of its infrastructure being used for malicious activities. Reports have linked an IP address within this ASN (45.118.144.151) to a Cobalt Strike Command-and-Control (C2) server. The consistent high volume of abuse reports across their network suggests either negligent management or knowing complicity in facilitating cybercrime.

### OSINT on CVEs
- **CVE-2024-14007:** This is a high-severity (CVSS 8.7) authentication bypass vulnerability in Shenzhen TVT Digital Technology's NVMS-9000 firmware, used in many white-labeled DVRs, NVRs, and IP cameras. Public proof-of-concept exploits are available, and the vulnerability is being actively exploited in the wild by a variant of the Mirai botnet to compromise IoT devices. The observed exploitation attempts in the honeypot align directly with this known global campaign.

## Key Observations and Anomalies

- **Hyper-Aggressive Actor:** The IP address 103.237.145.16 was responsible for 51% of all attack traffic, indicating a highly aggressive and focused campaign rather than random background scanning.
- **Campaign Indicators:** The combination of a Mirai-associated IP address, a hosting provider with a history of malicious activity, and the targeting of a specific CVE (CVE-2024-14007) known to be exploited by Mirai, strongly suggests this activity is part of a coordinated botnet campaign to compromise vulnerable IoT devices.
- **Geographic Concentration:** Over 50% of attacks originated from a single country, Vietnam, driven almost entirely by the single hyper-aggressive IP. This is a significant deviation from a more evenly distributed global spread of background noise.

## Unusual Attacker Origins

While the top attacking countries are common sources of malicious traffic, the extreme concentration of attacks from a single IP in Vietnam is a notable anomaly for this reporting period. This highlights a specific, targeted campaign rather than generalized scanning activity.
