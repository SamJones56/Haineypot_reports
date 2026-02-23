# Honeypot Attack Summary Report – 2026-02-23T00:45:14Z

## Metadata

- **Report Generation Time**: 2026-02-23T00:45:14Z
- **Timeframe Covered**: 2026-02-22T00:45:14Z to 2026-02-23T00:45:14Z
- **Files Used**:
    - `/home/user/Haineypot/reports/daily_reports/Honeypot_Attack_Daily_Report_2026-02-23T00-31-09Z.md`

## Executive Summary

- **High Attack Volume**: The honeypot network observed a total of 121,654 attacks in the past 24 hours, indicating a significant level of malicious activity.
- **Most Critical Threat Actors**: The IP address `209.38.80.88` (DigitalOcean, LLC) was the most aggressive, with 5,521 recorded attacks. Another IP, `178.20.210.32`, also showed significant activity and has a low reputation score according to OSINT.
- **Most Exploited Services**: The most targeted ports were 5902, 5903, 5901 (VNC) and 22 (SSH), with significant activity also observed on port 445 (SMB).
- **Primary Geographic and ASN Sources**: The United States was the top source of attacks, with Australia, India, Germany, and the United Kingdom also being major sources. ASN 14061 (DigitalOcean, LLC) was the most prominent source of attacks.
- **Key Anomalies**: The detection of the "DoublePulsar Backdoor" signature and exploitation attempts for a critical RCE vulnerability, "React2Shell" (CVE-2025-55182), are the most significant findings.

## Detailed Analysis

### Our IPs

| Honeypot       | IP Address      |
|---------------|-----------------|
| tpot-hive-ny  | 134.199.242.175 |

### Attacks by Honeypot

| Honeypot       | Attacks |
|----------------|---------|
| tpot-hive-ny   | 121,654 |

### Top Source Countries

| Country        | Count   |
|----------------|---------|
| United States  | 35,491  |
| Australia      | 16,288  |
| India          | 11,845  |
| Germany        | 10,563  |
| United Kingdom | 10,258  |

### Top Attacking IPs

| IP Address      | Count | ASN        |
|-----------------|-------|------------|
| 209.38.80.88    | 5,521 | 14061      |
| 178.20.210.32   | 5,235 | 210006     |
| 209.38.29.178   | 3,752 | 14061      |
| 59.145.41.149   | 3,700 | 9498       |
| 139.59.62.156   | 3,307 | 14061      |

### Top Targeted Ports/Protocols

| Country        | Port | Count |
|----------------|------|-------|
| United States  | 5902 | 2,743 |
| United States  | 5903 | 1,375 |
| United States  | 5901 | 1,356 |
| India          | 445  | 3,700 |
| Australia      | 22   | 3,210 |

### Most Common CVEs

| CVE             | Count |
|-----------------|-------|
| CVE-2025-55182  | 81    |
| CVE-2024-14007  | 76    |
| CVE-2021-3449   | 30    |
| CVE-2019-11500  | 26    |
| CVE-2023-46604  | 12    |

### Commands Attempted

*The daily report did not contain specific commands attempted.*

### Signatures Triggered

| Signature                                                           | Count |
|---------------------------------------------------------------------|-------|
| SURICATA IPv4 truncated packet                                      | 6,899 |
| SURICATA AF-PACKET truncated packet                                 | 6,899 |
| GPL INFO VNC server response                                        | 5,382 |
| SURICATA SSH invalid banner                                         | 5,061 |
| ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication | 2,458 |

### Users / Login Attempts

| Username | Count |
|----------|-------|
| root     | 2,627 |
| admin    | 1,149 |
| user     | 620   |
| postgres | 496   |
| test     | 454   |

### Files Uploaded/Downloaded

*The daily report did not contain information on file uploads or downloads.*

### HTTP User-Agents

*The daily report did not contain information on HTTP User-Agents.*

### SSH Clients and Servers

*The daily report did not contain specific information on SSH clients and servers.*

### Top Attacker AS Organizations

| ASN    | Organization               | Count  |
|--------|----------------------------|--------|
| 14061  | DigitalOcean, LLC          | 55,452 |
| 47890  | Unmanaged Ltd              | 8,926  |
| 210006 | Shereverov Marat Ahmedovich| 5,311  |
| 20473  | The Constant Company, LLC  | 4,555  |
| 396982 | Google LLC                 | 4,347  |

## OSINT Section

### OSINT on Commands

*No specific commands were available in the daily report for OSINT analysis.*

### OSINT on High-Frequency IPs

- **209.38.80.88**: This IP, hosted by DigitalOcean, was the most aggressive attacker. However, OSINT does not indicate any current public malicious reputation. This could suggest a newly compromised host or the beginning of a new attack campaign.
- **178.20.210.32**: OSINT reveals this IP has a low reputation score and is on at least one blocklist, which is consistent with the aggressive behavior observed.
- **59.145.41.149**: This IP is associated with a major Indian ISP (Bharti Airtel). OSINT shows no public record of malicious activity, suggesting it might be a compromised residential or mobile device.

### OSINT on CVEs

- **CVE-2025-55182 ("React2Shell")**: OSINT confirms this is a critical remote code execution (RCE) vulnerability with a CVSS score of 10.0. It is known to be actively exploited in the wild. The detection of this CVE, even in small numbers, is a significant finding.

### OSINT on Signatures

- **DoublePulsar Backdoor**: The "ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication" signature is a high-confidence indicator of compromise. DoublePulsar is a sophisticated backdoor developed by the NSA's Equation Group and leaked by the Shadow Brokers. It is often deployed after a successful SMB exploit, such as EternalBlue (CVE-2017-0144).

## Key Observations and Anomalies

- **Hyper-aggressive Actors**: The IP address `209.38.80.88` from DigitalOcean was responsible for a high volume of attacks, yet has a neutral public reputation. This discrepancy warrants continued monitoring.
- **Campaign Indicators**: The presence of both the DoublePulsar backdoor signature and exploitation attempts for the critical "React2Shell" (CVE-2025-55182) vulnerability suggests that the honeypot is observing active, sophisticated attack campaigns.
- **Infrastructure Reuse**: The high concentration of attacks from ASN 14061 (DigitalOcean, LLC) indicates that this hosting provider is a popular choice for malicious actors.

## Unusual Attacker Origins

While the top attacking countries are common sources of malicious traffic, the high volume of attacks from Australia is noteworthy. Further analysis would be needed to determine if this is part of a specific campaign or just random noise.
