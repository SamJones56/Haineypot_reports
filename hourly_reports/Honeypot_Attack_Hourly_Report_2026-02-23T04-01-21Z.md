# Honeypot Attack Report - 2026-02-23T04:00:24Z

Executive Summary:
- Over 10,000 attacks were observed in the last hour, with India and the United States being the primary sources.
- A significant portion of attacks originated from ASN 14061 (DigitalOcean, LLC), indicating a cloud-based threat source.
- The most aggressive IP, 183.82.0.100, launched over 2,500 attacks, primarily targeting port 445 from India.
- Alert data shows a high volume of "Generic Protocol Command Decode" and "SURICATA STREAM spurious retransmission" events, suggesting network scanning and reconnaissance activities.
- Brute-force attempts are prevalent, with "admin" and "root" as the most common usernames and simple numerical sequences as the most common passwords.
- The majority of attacking systems appear to be running Windows and Linux operating systems.

Detailed Analysis:

Total Attacks:
- 10718

Top Attacking Countries:
- India: 3276
- United States: 3186
- Australia: 1279
- Tunisia: 1176
- Germany: 980

Notable IP Reputations:
- known attacker: 1371
- mass scanner: 241

Common Alert Categories:
- Generic Protocol Command Decode: 932
- Misc activity: 565
- Misc Attack: 359
- Attempted Information Leak: 74
- A Network Trojan was detected: 36

Alert Signatures:
- 2210061 - SURICATA STREAM spurious retransmission: 473
- 2100560 - GPL INFO VNC server response: 216
- 2228000 - SURICATA SSH invalid banner: 188
- 2001978 - ET INFO SSH session in progress on Expected Port: 150
- 2402000 - ET DROP Dshield Block Listed Source group 1: 144

ASN Information:
- 14061 - DigitalOcean, LLC: 4632
- 18209 - Atria Convergence Technologies Ltd.: 2592
- 37693 - TUNISIANA: 1176
- 9498 - BHARTI Airtel Ltd.: 682
- 47890 - Unmanaged Ltd: 324

Source IP Addresses:
- 183.82.0.100: 2592
- 197.14.55.168: 1176
- 59.145.41.149: 682
- 107.170.56.80: 580
- 165.22.12.14: 554

Country to Port Mapping:
- Australia
  - 22: 254
- Germany
  - 22: 190
  - 3128: 9
  - 1433: 5
- India
  - 445: 3274
  - 23: 1
- Tunisia
  - 445: 1176
- United States
  - 22: 421
  - 1111: 117
  - 5902: 114

CVEs Exploited:
- CVE-2002-0953: 8
- CVE-2024-14007 CVE-2024-14007: 5
- CVE-2025-55182 CVE-2025-55182: 2
- CVE-2002-1149: 1
- CVE-2019-11500 CVE-2019-11500: 1

Usernames:
- admin: 149
- root: 135
- user: 71
- postgres: 65
- oracle: 62
- test: 52
- ubuntu: 44
- guest: 37
- centos: 36
- git: 21

Passwords:
- 123: 49
- 1234: 47
- 123456: 40
- 12345678: 36
- password: 34

OS Distribution:
- Windows NT kernel: 12009
- Linux 2.2.x-3.x: 11047
- Linux 2.2.x-3.x (no timestamps): 244
- Linux 2.2.x-3.x (barebone): 175
- Windows NT kernel 5.x: 158

Hyper-aggressive IPs:
- 183.82.0.100: 2592
- 197.14.55.168: 1176
