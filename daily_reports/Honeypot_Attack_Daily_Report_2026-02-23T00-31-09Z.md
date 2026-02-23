# Honeypot Attack Report - 2026-02-23T00:30:16Z

Executive Summary:
- **High Attack Volume:** The honeypot network observed a total of 121,654 attacks in the past 24 hours, indicating a significant level of malicious activity.
- **Geographic Concentration:** The majority of attacks originated from the United States, which accounted for 35,491 of the total attacks. Other major sources include Australia, India, Germany, and the United Kingdom.
- **Dominant Aggressor:** The most active IP address was 209.38.80.88, with 5,521 recorded attacks. This IP, along with other high-volume sources, is associated with ASN 14061 (DigitalOcean, LLC).
- **Common Tactics:** The most frequent alert category was "Generic Protocol Command Decode," suggesting a prevalence of reconnaissance and protocol-level attacks. Brute-force attempts were also common, with "root" and "admin" as the most targeted usernames.
- **Exploitation Activity:** While multiple CVEs were detected, none showed an overwhelming concentration. The most frequently observed was CVE-2025-55182, with 81 instances.
- **Operating System Landscape:** The attacking systems are predominantly Linux-based, with "Linux 2.2.x-3.x" being the most common OS signature.

Detailed Analysis:

Total Attacks:
- 121,654

Top Attacking Countries:
- United States: 35,491
- Australia: 16,288
- India: 11,845
- Germany: 10,563
- United Kingdom: 10,258

Notable IP Reputations:
- known attacker: 38,697
- mass scanner: 2,618
- bot, crawler: 31
- tor exit node: 6

Common Alert Categories:
- Generic Protocol Command Decode: 22,349
- Misc activity: 11,955
- Misc Attack: 7,368
- Attempted Administrator Privilege Gain: 2,765
- Attempted Information Leak: 2,246

Alert Signatures:
- 2200003: SURICATA IPv4 truncated packet: 6,899
- 2200122: SURICATA AF-PACKET truncated packet: 6,899
- 2100560: GPL INFO VNC server response: 5,382
- 2228000: SURICATA SSH invalid banner: 5,061
- 2024766: ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication: 2,458

ASN Information:
- 14061: DigitalOcean, LLC: 55,452
- 47890: Unmanaged Ltd: 8,926
- 210006: Shereverov Marat Ahmedovich: 5,311
- 20473: The Constant Company, LLC: 4,555
- 396982: Google LLC: 4,347

Source IP Addresses:
- 209.38.80.88: 5,521
- 178.20.210.32: 5,235
- 209.38.29.178: 3,752
- 59.145.41.149: 3,700
- 139.59.62.156: 3,307

Country to Port Mapping:
- Australia:
  - 22: 3,210
  - 80: 117
  - 8081: 10
- Germany:
  - 22: 1,801
  - 8000: 48
  - 23: 43
  - 80: 43
  - 6000: 38
- India:
  - 445: 3,700
  - 22: 1,528
  - 23: 132
  - 6443: 14
  - 25: 4
- United Kingdom:
  - 22: 1,678
  - 3306: 140
  - 80: 56
  - 443: 34
  - 4567: 16
- United States:
  - 5902: 2,743
  - 5903: 1,375
  - 5901: 1,356
  - 22: 1,336
  - 2323: 1,287

CVEs Exploited:
- CVE-2025-55182 CVE-2025-55182: 81
- CVE-2024-14007 CVE-2024-14007: 76
- CVE-2021-3449 CVE-2021-3449: 30
- CVE-2019-11500 CVE-2019-11500: 26
- CVE-2023-46604 CVE-2023-46604 CVE-2023-46604: 12

Usernames:
- root: 2,627
- admin: 1,149
- user: 620
- postgres: 496
- test: 454
- oracle: 447
- git: 337
- ubuntu: 325
- hadoop: 291
- mysql: 219

Passwords:
- 123456: 1,368
- 123: 457
- password: 418
- 1234: 388
- 12345678: 362

OS Distribution:
- Linux 2.2.x-3.x: 281,810
- Windows NT kernel: 114,155
- Linux 2.2.x-3.x (barebone): 7,848
- Windows NT kernel 5.x: 3,187
- Linux 2.2.x-3.x (no timestamps): 6,182

Hyper-aggressive IPs:
- 209.38.80.88: 5,521
- 178.20.210.32: 5,235
- 209.38.29.178: 3,752
- 59.145.41.149: 3,700
- 139.59.62.156: 3,307
