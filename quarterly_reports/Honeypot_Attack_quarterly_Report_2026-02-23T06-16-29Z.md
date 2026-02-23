# Honeypot Attack Report - 2026-02-23T06:15:33Z

Executive Summary:
- Over 43,000 attacks were observed in the past 6 hours, with the United States, India, and Australia being the top attacking countries.
- The most prominent attacker ASN is AS14061 (DigitalOcean, LLC), accounting for over half of all observed attacks.
- Two IPs, 209.38.80.88 and 183.82.0.100, were identified as hyper-aggressive, with over 3,000 attacks each.
- Common targets for attacks from India and Vietnam were on port 445 (SMB), while attacks from the United States, Australia and Germany primarily targeted port 22 (SSH).
- Brute force attacks are prevalent, with "root" and "admin" being the most common usernames and "123456" and "password" among the most common passwords.
- The most common alert signature is "GPL INFO VNC server response", indicating a high volume of VNC-related activity.

Detailed Analysis:

Total Attacks:
- 43804

Top Attacking Countries:
- United States: 12787
- India: 9216
- Australia: 7644
- Vietnam: 2942
- Germany: 2807

Notable IP Reputations:
- known attacker: 8397
- mass scanner: 1182
- bot, crawler: 4

Common Alert Categories:
- Generic Protocol Command Decode: 3551
- Misc activity: 3194
- Misc Attack: 2228
- Attempted Information Leak: 530
- Potentially Bad Traffic: 130

Alert Signatures:
- 2100560 - GPL INFO VNC server response: 1304
- 2228000 - SURICATA SSH invalid banner: 1139
- 2402000 - ET DROP Dshield Block Listed Source group 1: 823
- 2001978 - ET INFO SSH session in progress on Expected Port: 720
- 2210061 - SURICATA STREAM spurious retransmission: 640

ASN Information:
- 14061 - DigitalOcean, LLC: 23414
- 18209 - Atria Convergence Technologies Ltd.: 3157
- 9498 - BHARTI Airtel Ltd.: 2555
- 37693 - TUNISIANA: 2352
- 47890 - Unmanaged Ltd: 1915

Source IP Addresses:
- 209.38.80.88: 3245
- 183.82.0.100: 3157
- 59.145.41.149: 2555
- 197.14.55.168: 2352
- 14.177.96.230: 1744

Country to Port Mapping:
- Australia
  - 22: 1502
  - 8081: 10
  - 2222: 3
  - 2202: 1
  - 17000: 1
- Germany
  - 22: 508
  - 80: 49
  - 6443: 14
  - 3128: 9
  - 9029: 8
- India
  - 445: 5712
  - 22: 663
  - 45737: 56
  - 25: 4
  - 23: 3
- United States
  - 22: 1317
  - 5902: 676
  - 5901: 359
  - 5903: 336
  - 8728: 122
- Vietnam
  - 445: 1748
  - 22: 238
  - 7170: 7

CVEs Exploited:
- CVE-2024-14007 CVE-2024-14007: 28
- CVE-2002-0953: 8
- CVE-2025-55182 CVE-2025-55182: 7
- CVE-2019-11500 CVE-2019-11500: 3
- CVE-2021-3449 CVE-2021-3449: 3

Usernames:
- root: 896
- admin: 509
- user: 282
- test: 248
- oracle: 212
- postgres: 191
- ubuntu: 176
- guest: 140
- centos: 116
- hadoop: 104

Passwords:
- 123456: 444
- 123: 239
- 1234: 215
- 12345678: 188
- password: 175

OS Distribution:
- Linux 2.2.x-3.x: 67756
- Windows NT kernel: 35094
- Linux 2.2.x-3.x (barebone): 1503
- Windows NT kernel 5.x: 978
- Linux 2.2.x-3.x (no timestamps): 1272

Hyper-aggressive IPs:
- 209.38.80.88: 3245
- 183.82.0.100: 3157
