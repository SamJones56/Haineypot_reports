# Honeypot Attack Report - 2026-02-23T19:00:21Z

## Executive Summary:
- **High Attack Volume:** A total of 5,434 attacks were observed in the past hour, with a significant concentration from a single source IP.
- **Dominant Attacker:** The IP address 185.177.72.49, associated with AS211590 (Bucklog SARL) in France, was responsible for 1,772 attacks, representing over 32% of the total volume.
- **Geographic Concentration:** France was the top attacking country with 2,275 attacks, followed by the United States with 1,351.
- **Common Signatures:** The most frequent alert signatures were "SURICATA IPv4 truncated packet" and "SURICATA AF-PACKET truncated packet", each with 2,723 occurrences, indicating potential network anomalies or evasion attempts.
- **Credential Brute-Forcing:** Common username/password combinations like "admin"/"123456" were frequently used, suggesting widespread brute-force attempts.
- **Exploitation Activity:** The most observed CVE was CVE-2002-1149, related to a TCP sequence number generation vulnerability.

## Detailed Analysis:

**Total Attacks:**
- 5434

**Top Attacking Countries:**
- France: 2275
- United States: 1351
- Netherlands: 504
- Taiwan: 340
- Vietnam: 215

**Notable IP Reputations:**
- known attacker: 4633
- mass scanner: 78

**Common Alert Categories:**
- Generic Protocol Command Decode: 6325
- Attempted Information Leak: 2908
- Misc activity: 1041
- Misc Attack: 305
- Information Leak: 27

**Alert Signatures:**
- 2200003 (SURICATA IPv4 truncated packet): 2723
- 2200122 (SURICATA AF-PACKET truncated packet): 2723
- 2002824 (ET INFO CURL User Agent): 2296
- 2031502 (ET INFO Request to Hidden Environment File - Inbound): 663
- 2023753 (ET SCAN MS Terminal Server Traffic on Non-standard Port): 512

**ASN Information:**
- 211590 (Bucklog SARL): 2268
- 14061 (DigitalOcean, LLC): 834
- 135377 (UCLOUD INFORMATION TECHNOLOGY HK LIMITED): 529
- 208137 (Feo Prest SRL): 328
- 202425 (IP Volume inc): 259

**Source IP Addresses:**
- 185.177.72.49: 1772
- 178.128.245.160: 444
- 213.209.159.158: 296
- 103.53.231.159: 215
- 185.177.72.23: 184

**Country to Port Mapping:**
- France
  - 80: 2268
  - 3128: 4
  - 5998: 1
- Netherlands
  - 3388: 148
  - 3390: 148
  - 9999: 148
- Taiwan
  - 22: 64
  - 7170: 14
- United States
  - 5902: 115
  - 1293: 78
  - 5903: 57
- Vietnam
  - 22: 43

**CVEs Exploited:**
- CVE-2002-1149: 27
- CVE-2021-1499 CVE-2021-1499: 17
- CVE-2024-14007 CVE-2024-14007: 3
- CVE-2025-55182 CVE-2025-55182: 3
- CVE-2000-0868: 2

**Usernames:**
- admin: 26
- user: 18
- debian: 10
- ubnt: 10
- admin$: 8
- admin1: 8
- dominus: 6
- master: 5
- root: 5
- Accept-Encoding: gzip: 2

**Passwords:**
- 123456: 17
- 123: 12
- 1234: 11
- 12345678: 10
- 1234567890: 4

**OS Distribution:**
- Windows NT kernel: 19511
- Linux 2.2.x-3.x: 17950
- Linux 2.2.x-3.x (no timestamps): 428
- Linux 2.2.x-3.x (barebone): 415
- Windows NT kernel 5.x: 154

**Hyper-aggressive IPs:**
- 185.177.72.49: 1772 attacks
