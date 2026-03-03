# Honeypot Attack Report - 2026-02-23T03:00:27Z

Executive Summary:
- The honeypot network observed 6807 attacks in the past hour.
- The majority of attacks originated from the United States, followed by India and Germany.
- The most active attacker IP was 59.145.41.149 with 682 attacks, associated with ASN 9498 (BHARTI Airtel Ltd.).
- Dominant attack vectors included "Misc activity" and "Generic Protocol Command Decode".
- Common credential stuffing attempts involved usernames like "root", "test", and "user" with simple passwords such as "123" and "123456".
- The most frequently observed alert signature was "GPL INFO VNC server response".

Detailed Analysis:

Total Attacks:
- 6807

Top Attacking Countries:
- United States: 1891
- India: 1594
- Germany: 1005
- Australia: 866
- Netherlands: 575

Notable IP Reputations:
- known attacker: 1653
- mass scanner: 204
- bot, crawler: 2

Common Alert Categories:
- Misc activity: 540
- Generic Protocol Command Decode: 527
- Misc Attack: 381
- Attempted Information Leak: 126
- Potentially Bad Traffic: 36

Alert Signatures:
- 2100560, GPL INFO VNC server response: 224
- 2228000, SURICATA SSH invalid banner: 178
- 2402000, ET DROP Dshield Block Listed Source group 1: 144
- 2001978, ET INFO SSH session in progress on Expected Port: 131
- 2210061, SURICATA STREAM spurious retransmission: 115

ASN Information:
- 14061, DigitalOcean, LLC: 3658
- 9498, BHARTI Airtel Ltd.: 682
- 18209, Atria Convergence Technologies Ltd.: 570
- 396982, Google LLC: 310
- 47890, Unmanaged Ltd: 307

Source IP Addresses:
- 59.145.41.149: 682
- 183.82.0.100: 570
- 139.59.157.178: 485
- 143.198.162.55: 420
- 209.38.29.7: 400

Country to Port Mapping:
- Australia
  - 22: 167
  - 2202: 1
  - 2222: 1
- Germany
  - 22: 187
  - 2976: 4
  - 11906: 4
- India
  - 445: 1252
  - 22: 68
  - 25: 2
- Netherlands
  - 443: 98
  - 22: 83
  - 9100: 24
- United States
  - 22: 160
  - 5902: 115
  - 5903: 57

CVEs Exploited:
- CVE-2024-14007 CVE-2024-14007: 8
- CVE-2019-11500 CVE-2019-11500: 2
- CVE-2021-3449 CVE-2021-3449: 2
- CVE-2025-55182 CVE-2025-55182: 2
- CVE-2024-7120 CVE-2024-7120 CVE-2024-7120: 1

Usernames:
- root: 151
- test: 64
- user: 58
- hadoop: 57
- postgres: 43
- mysql: 40
- oracle: 39
- admin: 36
- centos: 36
- guest: 28

Passwords:
- 123: 46
- 1234: 45
- 123456: 41
- 12345678: 37
- password: 32

OS Distribution:
- Windows NT kernel: 13498
- Linux 2.2.x-3.x: 10549
- Linux 2.2.x-3.x (barebone): 250
- Windows NT kernel 5.x: 179
- Linux 2.2.x-3.x (no timestamps): 179

Hyper-aggressive IPs:
- 59.145.41.149: 682
- 183.82.0.100: 570
- 139.59.157.178: 485
- 143.198.162.55: 420
- 209.38.29.7: 400
