# Honeypot Attack Report - 2026-02-23T12:00:23Z

## Executive Summary:
- **High Attack Volume:** Over 5,500 attacks were observed in the past hour, indicating a significant level of malicious activity.
- **Geographic Concentration:** The majority of attacks originated from the United States, Germany, and India, with these three countries accounting for over half of all observed attacks.
- **Dominant Attacker ASN:** DigitalOcean, LLC (AS14061) was the most prominent source of attacks, with nearly 4,000 attacks originating from their network.
- **Common Attack Vectors:** The most frequent alert categories were "Misc activity," "Generic Protocol Command Decode," and "Misc Attack," suggesting a wide range of opportunistic attacks.
- **SSH and VNC Exploitation:** The most common alert signatures were related to SSH and VNC protocols, indicating a focus on compromising remote access services.
- **Credential Stuffing:** A large number of common usernames and passwords were used in attacks, with "admin," "root," and "user" being the most frequently attempted usernames, and "123456," "1234," and "qwerty" being the most common passwords.

## Detailed Analysis:

**Total Attacks:**
- 5508

**Top Attacking Countries:**
- United States: 1997
- Germany: 1129
- India: 639
- United Kingdom: 638
- Netherlands: 230

**Notable IP Reputations:**
- known attacker: 1414
- mass scanner: 188
- bot, crawler: 3

**Common Alert Categories:**
- Misc activity: 612
- Generic Protocol Command Decode: 481
- Misc Attack: 330
- Attempted Information Leak: 164
- Attempted Administrator Privilege Gain: 46
- Web Application Attack: 20
- access to a potentially vulnerable web application: 20
- Potentially Bad Traffic: 6
- Detection of a Network Scan: 2
- Detection of a Denial of Service Attack: 1

**Alert Signatures:**
- 2228000 - SURICATA SSH invalid banner: 219
- 2100560 - GPL INFO VNC server response: 218
- 2038967 - ET INFO SSH-2.0-Go version string Observed in Network Traffic: 163
- 2001978 - ET INFO SSH session in progress on Expected Port: 135
- 2402000 - ET DROP Dshield Block Listed Source group 1: 120
- 2001984 - ET INFO SSH session in progress on Unusual Port: 94
- 2023753 - ET SCAN MS Terminal Server Traffic on Non-standard Port: 86
- 2200003 - SURICATA IPv4 truncated packet: 57
- 2200122 - SURICATA AF-PACKET truncated packet: 57
- 2009582 - ET SCAN NMAP -sS window 1024: 43

**ASN Information:**
- 14061 - DigitalOcean, LLC: 3957
- 47890 - Unmanaged Ltd: 286
- 131427 - AOHOAVIET: 200
- 16509 - Amazon.com, Inc.: 145
- 202425 - IP Volume inc: 115
- 213412 - ONYPHE SAS: 102
- 210006 - Shereverov Marat Ahmedovich: 70
- 135377 - UCLOUD INFORMATION TECHNOLOGY HK LIMITED: 52
- 63949 - Akamai Connected Cloud: 48
- 215925 - Vpsvault.host Ltd: 47

**Source IP Addresses:**
- 64.227.125.176: 625
- 174.138.79.7: 486
- 209.38.79.140: 486
- 167.71.239.213: 240
- 159.65.81.102: 235
- 146.190.99.184: 215
- 103.53.231.159: 200
- 143.110.164.56: 200
- 167.71.140.87: 195
- 167.71.230.193: 194

**Country to Port Mapping:**
- France:
  - 3128: 2
  - 4117: 2
  - 4408: 2
  - 4419: 2
  - 5057: 2
  - 7500: 2
  - 8043: 2
  - 8103: 2
  - 8181: 2
  - 8321: 2
- Germany:
  - 22: 212
  - 10250: 14
  - 33690: 4
  - 8869: 3
  - 5902: 2
  - 443: 1
  - 5901: 1
  - 8090: 1
  - 30007: 1
- India:
  - 22: 125
  - 1574: 8
- Netherlands:
  - 22: 37
  - 9100: 16
  - 6037: 8
  - 17001: 8
  - 3478: 4
  - 8001: 2
  - 80: 1
  - 443: 1
  - 2223: 1
  - 3128: 1
- Romania:
    - 22: 11
    - 2386: 2
    - 3390: 2
    - 5902: 2
    - 10982: 2
    - 15804: 2
    - 19635: 2
    - 22200: 2
    - 29114: 2
    - 37085: 2
- Seychelles:
    - 60140: 2
    - 60144: 2
    - 60146: 2
    - 60154: 2
    - 60155: 2
    - 60157: 2
    - 60168: 2
    - 60174: 2
    - 60178: 2
    - 60179: 2
- Singapore:
    - 22: 43
    - 49671: 4
    - 19000: 3
    - 80: 2
    - 23: 1
    - 5901: 1
    - 5909: 1
    - 9385: 1
    - 22022: 1
- United Kingdom:
    - 22: 117
    - 8025: 2
    - 6036: 1
    - 8081: 1
    - 8085: 1
    - 9090: 1
    - 10110: 1
    - 32783: 1
- United States:
    - 22: 200
    - 5902: 115
    - 5901: 95
    - 5903: 57
    - 2375: 35
    - 10000: 35
    - 5500: 32
    - 3000: 18
    - 8728: 14
    - 2077: 12
- Vietnam:
    - 22: 40
    - 23: 1

**CVEs Exploited:**
- CVE-2025-55182 CVE-2025-55182: 20
- CVE-2024-14007 CVE-2024-14007: 4
- CVE-2002-0013 CVE-2002-0012: 1
- CVE-2019-11500 CVE-2019-11500: 1
- CVE-2020-11910: 1
- CVE-2021-3449 CVE-2021-3449: 1

**Usernames:**
- admin: 135
- root: 105
- user: 94
- ubuntu: 67
- guest: 56
- pi: 36
- postgres: 27
- backup: 26
- ftp: 25
- oracle: 23

**Passwords:**
- 123456: 50
- 1234: 34
- qwerty: 33
- 12345678: 30
- password: 29
- 12345: 28
- 123: 26
- 123456789: 25
- 654321: 25
- passw0rd: 25

**OS Distribution:**
- Windows NT kernel: 17086
- Linux 2.2.x-3.x: 15982
- Linux 2.2.x-3.x (no timestamps): 210
- Linux 2.2.x-3.x (barebone): 200
- Windows NT kernel 5.x: 200
- Linux 3.11 and newer: 35
- Mac OS X: 7
- Windows 7 or 8: 3
- Linux 2.4.x: 2
- Linux 3.1-3.10: 2

**Hyper-aggressive IPs:**
- 64.227.125.176: 625
- 174.138.79.7: 486
- 209.38.79.140: 486
- 167.71.239.213: 240
- 159.65.81.102: 235
- 146.190.99.184: 215
- 103.53.231.159: 200
- 143.110.164.56: 200
- 167.71.140.87: 195
- 167.71.230.193: 194
