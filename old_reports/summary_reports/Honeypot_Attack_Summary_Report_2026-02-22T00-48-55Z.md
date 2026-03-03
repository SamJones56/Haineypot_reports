# Honeypot Attack Summary Report – 2026-02-22T00:48:35Z

## Metadata

- **Report Generation Time:** 2026-02-22T00:48:35Z
- **Timeframe Covered:** 2026-02-21T00:30:23Z to 2026-02-22T00:30:23Z
- **Files Used:**
    - `/home/user/Haineypot/reports/daily_reports/Honeypot_Attack_Daily_Report_2026-02-22T00-31-14Z.md`

## Executive Summary

This report summarizes 92,870 attacks recorded over the past 24 hours. A significant volume of attacks originated from the United States, India, Germany, and China, with infrastructure primarily linked to hosting providers like DigitalOcean, Unmanaged Ltd, and Chinanet. Brute-force attempts remain a common tactic, with `root` / `123456` being the most frequently observed credential pair. Analysis revealed several hyper-aggressive IP addresses, with three IPs responsible for over 17,000 attacks combined. Investigation into reported CVEs indicates active exploitation of known vulnerabilities, including a critical authentication bypass (CVE-2024-14007) linked to the Mirai botnet. An anomalous future-dated CVE (CVE-2025-55182) was also noted, pointing to either a data error in reporting or observation of a highly sophisticated, pre-disclosed vulnerability campaign.

## Detailed Analysis

### Our IPs

| Honeypot      | IP Address      |
|---------------|-----------------|
| tpot-hive-ny  | 134.199.242.175 |

### Attacks by Honeypot

| Honeypot      | Attacks |
|---------------|---------|
| tpot-hive-ny  | 92,870  |

### Top Source Countries

| Country       | Attacks |
|---------------|---------|
| United States | 23,945  |
| India         | 9,038   |
| Germany       | 8,204   |
| China         | 8,109   |
| Singapore     | 5,717   |

### Top Attacking IPs

| IP Address      | Attacks |
|-----------------|---------|
| 218.21.0.230    | 6,386   |
| 178.20.210.32   | 5,974   |
| 128.199.198.62  | 5,411   |
| 170.64.225.183  | 3,361   |
| 103.53.231.159  | 3,345   |

### Top Targeted Ports/Protocols

| Country       | Port | Attacks |
|---------------|------|---------|
| India         | 445  | 5,492   |
| Germany       | 22   | 1,347   |
| United States | 2323 | 1,302   |
| China         | 22   | 1,276   |
| United States | 5902 | 1,190   |

### Most Common CVEs

| CVE           | Count |
|---------------|-------|
| CVE-2006-2369 | 209   |
| CVE-2024-14007| 80    |
| CVE-2025-55182| 52    |
| CVE-2021-3449 | 33    |
| CVE-2019-11500| 25    |

### Commands Attempted

(No commands reported in the aggregated data for this period.)

### Signatures Triggered

| Signature ID | Signature Description                 | Count |
|--------------|---------------------------------------|-------|
| 2200003      | SURICATA IPv4 truncated packet        | 15,328|
| 2200122      | SURICATA AF-PACKET truncated packet   | 15,328|
| 2100560      | GPL INFO VNC server response          | 5,840 |
| 2228000      | SURICATA SSH invalid banner           | 5,238 |
| 2001984      | ET INFO SSH session in progress on Unusual Port | 2,449 |

### Users / Login Attempts

| Username | Attempts |
|----------|----------|
| root     | 3,610    |
| admin    | 339      |
| user     | 235      |
| ubuntu   | 164      |
| test     | 128      |

| Password | Attempts |
|----------|----------|
| 123456   | 528      |
| (empty)  | 274      |
| 123      | 272      |
| 1234     | 239      |
| 12345678 | 228      |

### Files Uploaded/Downloaded

(No file transfers reported in the aggregated data for this period.)

### HTTP User-Agents

(No HTTP user agents reported in the aggregated data for this period.)

### SSH Clients and Servers

(No specific SSH client/server strings reported in the aggregated data for this period.)

### Top Attacker AS Organizations

| ASN      | Organization                | Count  |
|----------|-----------------------------|--------|
| 14061    | DigitalOcean, LLC           | 21,714 |
| 47890    | Unmanaged Ltd               | 7,351  |
| 4134     | Chinanet                    | 7,332  |
| 210006   | Shereverov Marat Ahmedovich | 6,107  |
| 396982   | Google LLC                  | 5,274  |

## OSINT Section

### OSINT on High-Frequency IPs

- **218.21.0.230:** This IP is geolocated to Yinchuan, China, and is associated with the Chinanet ASN (4134). It has a documented history of malicious SSH client activity and appears on at least one blocklist with a moderate risk score. The activity is consistent with large-scale scanning or brute-force campaigns.
- **178.20.210.32:** Located in the Netherlands and associated with the hostname `mortifiedly.banhkemcantho.com` and hosting provider "ITS HOSTED". This IP has a low reputation score, is present on blocklists, and has recent abuse reports, indicating it is a credible threat.
- **128.199.198.62:** This IP belongs to DigitalOcean in Singapore. While no direct malicious activity was found for this specific IP, it is part of a network (ASN 14061) that is frequently used by malicious actors for a wide range of cyber threats. Its high attack volume suggests it is being used for malicious scanning.

### OSINT on CVEs

- **CVE-2006-2369:** A moderate-severity integer underflow vulnerability in the `libsoup` HTTP library for GNOME. This flaw can lead to a buffer over-read, denial of service, or information disclosure. While no public exploits were found, the technical details are available, making it a potential target for exploit development. Its presence in logs suggests attackers are probing for older, unpatched Linux systems.
- **CVE-2024-14007:** A critical authentication bypass vulnerability in NVMS-9000 firmware used in DVRs, NVRs, and IP cameras from Shenzhen TVT Digital Technology. This CVE is actively exploited in the wild and has been linked to the Mirai botnet. Attackers are using it to absorb vulnerable IoT devices into a botnet for DDoS attacks.
- **CVE-2025-55182 ("React2Shell"):** A critical RCE vulnerability with a CVSS score of 10.0, affecting web applications using React Server Components. The CVE is actively exploited in the wild and is listed in CISA's KEV catalog. The appearance of this future-dated CVE in logs is highly anomalous and suggests either a data reporting error or that the honeypot detected activity related to a pre-disclosed, high-impact vulnerability.

## Key Observations and Anomalies

- **Hyper-Aggressive Actors:** Three IP addresses (218.21.0.230, 178.20.210.32, 128.199.198.62) were responsible for a combined 17,771 attacks, representing over 19% of the total daily attack volume. This indicates targeted, persistent scanning from a small set of sources.
- **Infrastructure Reuse:** The top attacking ASNs (DigitalOcean, Unmanaged Ltd, Chinanet) are consistently seen in attack reports. This highlights the persistent use of compromised or leniently policed hosting provider infrastructure for staging attacks.
- **Campaign Indicators:** The observed activity for CVE-2024-14007 aligns with known Mirai botnet campaigns targeting IoT devices. The high volume of probes for this vulnerability suggests a widespread and automated campaign is ongoing.
- **Anomalous CVE Reporting:** The detection of attacks targeting CVE-2025-55182 is a significant anomaly. A future-dated CVE should not be present in current attack data. This could be a mis-signature by the detection engine, a typo in the reporting tool, or, in a less likely scenario, the honeypot is detecting pre-release exploit development or a zero-day that has been erroneously assigned a future CVE identifier. This warrants further investigation into the signature source.

## Unusual Attacker Origins

The geographic sources of attacks in this period are consistent with typical global patterns, with high volumes from the United States, China, India, and Germany. No statistically significant "unusual" origins were noted in this reporting period.
