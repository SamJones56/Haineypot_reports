# Honeypot Attack Report - 2026-02-22T18:00:18Z

Executive Summary:
- This report covers 4695 attacks over the last hour.
- The majority of attacks originated from the United States, followed by Tunisia and Germany.
- The most prominent ASN is DigitalOcean, LLC, which is responsible for a significant portion of the attacks.
- The most common alert category is "Generic Protocol Command Decode," and the most frequent signature is related to the DoublePulsar Backdoor.
- The top attacking IP, 197.14.55.168 from Tunisia, is responsible for a high volume of attacks targeting port 445.
- Brute-force attempts are common, with "root" as the most targeted username and "123456" as the most common password.

Detailed Analysis:

Total Attacks:
- 4695

Top Attacking Countries:
- United States: 1399
- Tunisia: 819
- Germany: 486
- United Kingdom: 418
- Netherlands: 327

Notable IP Reputations:
- known attacker: 1881
- mass scanner: 55

Common Alert Categories:
- Generic Protocol Command Decode: 1743
- Attempted Administrator Privilege Gain: 929
- Misc activity: 496
- Misc Attack: 260
- Attempted Information Leak: 138

Alert Signatures:
- 2024766 - ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication: 920
- 2200003 - SURICATA IPv4 truncated packet: 726
- 2200122 - SURICATA AF-PACKET truncated packet: 726
- 2100560 - GPL INFO VNC server response: 228
- 2228000 - SURICATA SSH invalid banner: 188

ASN Information:
- 14061, DigitalOcean, LLC: 1700
- 37693, TUNISIANA: 819
- 135377, UCLOUD INFORMATION TECHNOLOGY HK LIMITED: 435
- 47890, Unmanaged Ltd: 365
- 210006, Shereverov Marat Ahmedovich: 335

Source IP Addresses:
- 197.14.55.168: 819
- 178.20.210.32: 335
- 159.223.42.2: 143
- 103.53.231.159: 130
- 138.68.135.71: 120

Country to Port Mapping:
- Germany:
  - 22: 89
  - 8089: 14
  - 30005: 14
  - 20692: 4
  - 26997: 4
- Netherlands:
  - 22: 50
  - 9100: 16
  - 6037: 12
  - 8728: 7
  - 9200: 7
- Tunisia:
  - 445: 819
- United Kingdom:
  - 22: 65
  - 4567: 16
  - 8856: 4
  - 443: 3
  - 1313: 2
- United States:
  - 51749: 228
  - 5902: 115
  - 5903: 64
  - 5901: 53
  - 22: 43

CVEs Exploited:
- CVE-2025-55182 CVE-2025-55182: 20
- CVE-2024-14007 CVE-2024-14007: 6
- CVE-2021-3449 CVE-2021-3449: 2
- CVE-2002-0013 CVE-2002-0012: 1
- CVE-2019-11500 CVE-2019-11500: 1

Usernames:
- root: 129
- oracle: 35
- admin: 34
- hadoop: 24
- ftpuser: 14
- postgres: 13
- ftp: 11
- user: 11
- ftptest: 10
- sol: 10

Passwords:
- 123456: 24
- 123: 18
- 1234: 18
- 12345678: 18
- password: 14

OS Distribution:
- Linux 2.2.x-3.x: 18761
- Windows NT kernel: 1919
- Linux 2.2.x-3.x (barebone): 337
- Windows NT kernel 5.x: 89
- Linux 2.2.x-3.x (no timestamps): 453

Hyper-aggressive IPs:
- 197.14.55.168: 819
