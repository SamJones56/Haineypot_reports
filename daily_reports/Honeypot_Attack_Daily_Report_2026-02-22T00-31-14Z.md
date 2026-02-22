# Honeypot Attack Report - 2026-02-22T00:30:23Z

## Executive Summary:
- **High Attack Volume:** Over 92,000 attacks were recorded in the past 24 hours, with a significant concentration from the United States, India, Germany, and China.
- **Dominant Attacker Infrastructure:** A large portion of attacks originated from cloud and hosting providers, with DigitalOcean, Unmanaged Ltd, and Chinanet ASNs being the most prominent.
- **Common Brute-Force Attempts:** The most common credential pair used in attacks was `root` / `123456`.
- **Prevalent Signatures:** The network experienced a high volume of `SURICATA IPv4 truncated packet` and `SURICATA AF-PACKET truncated packet` alerts, indicating potential evasion techniques or network anomalies.
- **Hyper-Aggressive IPs:** A small number of IPs are responsible for a large number of attacks, with five IPs exceeding 3,000 attacks each.

## Detailed Analysis:

**Total Attacks:**
- 92870

**Top Attacking Countries:**
- United States: 23945
- India: 9038
- Germany: 8204
- China: 8109
- Singapore: 5717

**Notable IP Reputations:**
- known attacker: 42649
- mass scanner: 3128
- bot, crawler: 28
- tor exit node: 13

**Common Alert Categories:**
- Generic Protocol Command Decode: 40022
- Misc activity: 11024
- Misc Attack: 8350
- Attempted Information Leak: 2005
- Attempted Administrator Privilege Gain: 1997

**Alert Signatures:**
- ID: 2200003, Signature: SURICATA IPv4 truncated packet, Count: 15328
- ID: 2200122, Signature: SURICATA AF-PACKET truncated packet, Count: 15328
- ID: 2100560, Signature: GPL INFO VNC server response, Count: 5840
- ID: 2228000, Signature: SURICATA SSH invalid banner, Count: 5238
- ID: 2001984, Signature: ET INFO SSH session in progress on Unusual Port, Count: 2449

**ASN Information:**
- ASN: 14061, Organization: DigitalOcean, LLC, Count: 21714
- ASN: 47890, Organization: Unmanaged Ltd, Count: 7351
- ASN: 4134, Organization: Chinanet, Count: 7332
- ASN: 210006, Organization: Shereverov Marat Ahmedovich, Count: 6107
- ASN: 396982, Organization: Google LLC, Count: 5274

**Source IP Addresses:**
- 218.21.0.230: 6386
- 178.20.210.32: 5974
- 128.199.198.62: 5411
- 170.64.225.183: 3361
- 103.53.231.159: 3345

**Country to Port Mapping:**
- **China:**
  - 22: 1276
  - 23: 535
  - 1433: 97
  - 6379: 32
  - 2323: 23
- **Germany:**
  - 22: 1347
  - 6000: 106
  - 18789: 102
  - 20000: 42
  - 443: 27
- **India:**
  - 445: 5492
  - 22: 605
  - 80: 222
  - 3306: 71
  - 443: 70
- **Singapore:**
  - 22: 1085
  - 3306: 122
  - 6379: 34
  - 7170: 11
  - 9200: 10
- **United States:**
  - 2323: 1302
  - 5902: 1190
  - 5901: 529
  - 23: 507
  - 8728: 265

**CVEs Exploited:**
- CVE-2006-2369: 209
- CVE-2024-14007: 80
- CVE-2025-55182: 52
- CVE-2021-3449: 33
- CVE-2019-11500: 25

**Usernames:**
- root: 3610
- admin: 339
- user: 235
- ubuntu: 164
- test: 128
- sol: 111
- sa: 102
- guest: 93
- postgres: 85
- solana: 61

**Passwords:**
- 123456: 528
- (empty): 274
- 123: 272
- 1234: 239
- 12345678: 228

**OS Distribution:**
- Linux 2.2.x-3.x: 256010
- Windows NT kernel: 239305
- Linux 2.2.x-3.x (barebone): 8299
- Linux 2.2.x-3.x (no timestamps): 5358
- Windows NT kernel 5.x: 3590

**Hyper-aggressive IPs:**
- 218.21.0.230: 6386
- 178.20.210.32: 5974
- 128.199.198.62: 5411
- 170.64.225.183: 3361
- 103.53.231.159: 3345
