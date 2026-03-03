# Honeypot Attack Report - 2026-02-21T21:00:18Z

Executive Summary:
- Over 3000 attacks were observed in the past hour, with the United States, Germany, and the United Kingdom being the top three sources of attacks.
- The most prominent attacker IP was 143.110.164.137, with 409 attacks, associated with DigitalOcean, LLC.
- The majority of attacks were categorized as "Generic Protocol Command Decode", with "SURICATA IPv4 truncated packet" being the most frequent alert signature.
- The most commonly targeted ports were 22 (SSH) and various VNC-related ports (5900, 5901, 5902).
- Brute force attempts were prevalent, with "root" as the most common username and "123456" as the most common password.
- The attacking systems were predominantly identified as running Linux and Windows operating systems.

Detailed Analysis:

Total Attacks:
- 3009

Top Attacking Countries:
- United States: 1122
- Germany: 747
- United Kingdom: 443
- Vietnam: 272
- Switzerland: 86

Notable IP Reputations:
- known attacker: 1413
- mass scanner: 100
- bot, crawler: 1
- tor exit node: 1

Common Alert Categories:
- Generic Protocol Command Decode: 4483
- Misc activity: 816
- Misc Attack: 299
- Attempted Administrator Privilege Gain: 134
- Attempted Information Leak: 54

Alert Signatures:
- 2200003, SURICATA IPv4 truncated packet: 2072
- 2200122, SURICATA AF-PACKET truncated packet: 2072
- 2100560, GPL INFO VNC server response: 474
- 2228000, SURICATA SSH invalid banner: 241
- 2002920, ET INFO VNC Authentication Failure: 124

ASN Information:
- 14061, DigitalOcean, LLC: 939
- 210006, Shereverov Marat Ahmedovich: 355
- 47890, Unmanaged Ltd: 291
- 131427, AOHOAVIET: 260
- 202425, IP Volume inc: 192

Source IP Addresses:
- 143.110.164.137: 409
- 178.20.210.32: 355
- 209.38.212.28: 330
- 103.53.231.159: 260
- 37.19.210.5: 124

Country to Port Mapping:
- Germany
  - 22: 137
  - 6379: 12
  - 443: 11
  - 13403: 4
  - 45455: 4
- Switzerland
  - 5435: 85
  - 5432: 1
- United Kingdom
  - 22: 83
  - 9711: 8
  - 5432: 3
  - 80: 2
  - 24443: 2
- United States
  - 5900: 124
  - 5902: 115
  - 5901: 54
  - 5672: 16
  - 22: 15
- Vietnam
  - 22: 52
  - 9713: 7
  - 23: 1

CVEs Exploited:
- CVE-2006-2369: 125
- CVE-2024-14007 CVE-2024-14007: 4
- CVE-2021-3449 CVE-2021-3449: 3
- CVE-2019-11500 CVE-2019-11500: 2
- CVE-2013-7471 CVE-2013-7471: 1

Usernames:
- root: 25
- guest: 18
- test: 18
- user: 17
- centos: 15
- www: 14
- gerrit: 13
- git: 13
- hadoop: 13
- mysql: 13

Passwords:
- 123456: 31
- 123: 29
- 1234: 26
- 12345678: 24
- 12345: 16

OS Distribution:
- Linux 2.2.x-3.x: 10750
- Windows NT kernel: 11131
- Linux 2.2.x-3.x (barebone): 382
- Windows NT kernel 5.x: 122
- Linux 2.2.x-3.x (no timestamps): 292

Hyper-aggressive IPs:
- 143.110.164.137: 409
- 178.20.210.32: 355
- 209.38.212.28: 330
- 103.53.231.159: 260
