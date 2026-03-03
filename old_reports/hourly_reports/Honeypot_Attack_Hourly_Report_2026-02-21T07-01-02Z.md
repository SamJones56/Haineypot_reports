# Honeypot Attack Report - 2026-02-21T07:00:13Z

## Executive Summary:
- **High Attack Volume:** A total of 5,125 attacks were observed in the past hour, with a significant concentration from a single source IP.
- **Dominant Attacker:** The IP address 103.79.11.171, originating from India and associated with ASN 135806 (Kalpavruksha Communication Services Pvt.ltd), was responsible for the majority of the attacks (3,103).
- **Primary Attack Vector:** The most common alert category was "Generic Protocol Command Decode," indicating a high volume of protocol-level probes and commands. This is strongly correlated with the top alert signatures "SURICATA IPv4 truncated packet" and "SURICATA AF-PACKET truncated packet".
- **Geographic Concentration:** India was the top attacking country, accounting for over 60% of the total attack volume. The United States and the United Kingdom followed at a considerable distance.
- **Credential Brute Forcing:** Common usernames such as 'root', 'guest', and 'user' were frequently used in login attempts, though most attempts used blank passwords.
- **Exploitation Activity:** Low-level exploitation of several CVEs was noted, with CVE-2024-14007 being the most frequent.

## Detailed Analysis:

**Total Attacks:**
- 5125

**Top Attacking Countries:**
- India: 3104
- United States: 943
- United Kingdom: 436
- Romania: 158
- Netherlands: 76

**Notable IP Reputations:**
- known attacker: 999
- mass scanner: 154

**Common Alert Categories:**
- Generic Protocol Command Decode: 4271
- Misc activity: 437
- Misc Attack: 384
- Attempted Information Leak: 69
- Web Application Attack: 51

**Alert Signatures:**
- 2200003 - SURICATA IPv4 truncated packet: 1966
- 2200122 - SURICATA AF-PACKET truncated packet: 1966
- 2228000 - SURICATA SSH invalid banner: 235
- 2100560 - GPL INFO VNC server response: 228
- 2001984 - ET INFO SSH session in progress on Unusual Port: 111

**ASN Information:**
- 135806 - Kalpavruksha Communication Services Pvt.ltd: 3103
- 14061 - DigitalOcean, LLC: 584
- 47890 - Unmanaged Ltd: 292
- 396982 - Google LLC: 224
- 14956 - RouterHosting LLC: 125

**Source IP Addresses:**
- 103.79.11.171: 3103
- 134.209.180.181: 400
- 2.57.122.208: 110
- 172.86.126.140: 60
- 172.86.127.82: 60

**Country to Port Mapping:**
- India
  - 445: 3103
  - 14345: 1
- Netherlands
  - 17000: 12
  - 6036: 8
  - 6037: 8
- Romania
  - 22: 25
  - 1338: 2
  - 1807: 2
- United Kingdom
  - 22: 80
  - 80: 4
  - 10443: 2
- United States
  - 5984: 61
  - 2181: 42
  - 13390: 32

**CVEs Exploited:**
- CVE-2024-14007 CVE-2024-14007: 4
- CVE-2019-11500 CVE-2019-11500: 3
- CVE-2021-3449 CVE-2021-3449: 3
- CVE-2024-4577 CVE-2002-0953: 2
- CVE-2024-4577 CVE-2024-4577: 2

**Usernames:**
- root: 46
- guest: 44
- user: 23
- test: 18
- ubuntu: 5
- postgres: 4
- sol: 3
- solana: 2
- solv: 2
- trader: 2

**Passwords:**
- : 38
- 123456: 5
- 1234: 4
- password: 4
- qwerty: 4

**OS Distribution:**
- Linux 2.2.x-3.x: 10426
- Windows NT kernel: 12594
- Linux 2.2.x-3.x (barebone): 262
- Windows NT kernel 5.x: 162
- Linux 2.2.x-3.x (no timestamps): 90

**Hyper-aggressive IPs:**
- 103.79.11.171: 3103 attacks
- 134.209.180.181: 400 attacks

**Unusual Credential Patterns:**
- A high number of login attempts (38) were made with a blank password.

**Other Notable Deviations:**
- The vast majority of attacks from the top source IP (103.79.11.171) were directed at port 445.
- A high concentration of "truncated packet" alerts suggests either network issues, evasion attempts, or poorly formed attack traffic.