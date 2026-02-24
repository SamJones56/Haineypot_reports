# Honeypot Attack Report - 2026-02-24T00:15:43Z

**Executive Summary:**

*   The honeypot network observed a total of 22,256 attacks in the past 6 hours, with the United States, Australia, and France being the most prominent sources of attacks.
*   The most aggressive attacker IP, 170.64.230.118, originating from Australia and associated with DigitalOcean, was responsible for 4,058 attacks alone.
*   The majority of attacks were categorized as "Generic Protocol Command Decode," with "SURICATA IPv4 truncated packet" and "SURICATA AF-PACKET truncated packet" being the most frequent alert signatures.
*   Attackers were observed attempting to exploit several vulnerabilities, with CVE-2024-14007 being the most targeted.
*   Default and simple credentials like "root," "admin," "123456," and "password" continue to be the most commonly used in brute-force attempts.
*   The most common operating system identified from the attackers' traffic is Windows NT kernel, followed by various versions of Linux.

**Detailed Analysis:**

**Total Attacks:**
22256

**Top Attacking Countries:**
*   United States: 7338
*   Australia: 4058
*   France: 2368
*   Netherlands: 1244
*   Seychelles: 1041

**Notable IP Reputations:**
*   known attacker: 15025
*   mass scanner: 472
*   bot, crawler: 23

**Common Alert Categories:**
*   Generic Protocol Command Decode: 12135
*   Misc activity: 2425
*   Misc Attack: 1757
*   Attempted Information Leak: 1308
*   Potentially Bad Traffic: 85
*   Attempted Administrator Privilege Gain: 79
*   Detection of a Network Scan: 19
*   Web Application Attack: 13
*   access to a potentially vulnerable web application: 12
*   Detection of a Denial of Service Attack: 9

**Alert Signatures:**
*   2200003 - SURICATA IPv4 truncated packet: 4996
*   2200122 - SURICATA AF-PACKET truncated packet: 4996
*   2100560 - GPL INFO VNC server response: 1300
*   2228000 - SURICATA SSH invalid banner: 1169
*   2023753 - ET SCAN MS Terminal Server Traffic on Non-standard Port: 955
*   2001984 - ET INFO SSH session in progress on Unusual Port: 547
*   2402000 - ET DROP Dshield Block Listed Source group 1: 403
*   2210048 - SURICATA STREAM reassembly sequence GAP -- missing packet(s): 357
*   2009582 - ET SCAN NMAP -sS window 1024: 287
*   2038967 - ET INFO SSH-2.0-Go version string Observed in Network Traffic: 259

**ASN Information:**
*   14061 - DigitalOcean, LLC: 7059
*   51167 - Contabo GmbH: 2346
*   47890 - Unmanaged Ltd: 1655
*   202425 - IP Volume inc: 1247
*   210006 - Shereverov Marat Ahmedovich: 1035
*   131427 - AOHOAVIET: 970
*   396982 - Google LLC: 959
*   209334 - Modat B.V.: 828
*   51852 - Private Layer INC: 657
*   16509 - Amazon.com, Inc.: 537

**Source IP Addresses:**
*   170.64.230.118: 4058
*   173.249.27.120: 2329
*   45.87.249.140: 1035
*   103.53.231.159: 970
*   178.128.245.160: 684
*   129.212.184.194: 681
*   46.19.137.194: 657
*   185.242.226.46: 476
*   213.209.159.158: 375
*   134.199.197.108: 343

**Country to Port Mapping:**
*   **Australia:**
    *   22: 810
*   **Canada:**
    *   8728: 14
    *   8889: 5
    *   1422: 4
    *   1998: 4
    *   2454: 4
*   **France:**
    *   443: 1545
    *   80: 784
    *   3128: 17
    *   8888: 4
    *   25566: 4
*   **Netherlands:**
    *   3388: 228
    *   3390: 228
    *   9999: 228
    *   9100: 64
    *   6036: 48
*   **Romania:**
    *   22: 121
    *   1454: 2
    *   2188: 2
    *   2292: 2
    *   2390: 2
*   **Seychelles:**
    *   22: 207
    *   22443: 2
    *   23: 1
    *   3976: 1
*   **Switzerland:**
    *   5434: 318
    *   5435: 169
    *   5433: 164
    *   5432: 6
*   **Taiwan:**
    *   22: 95
    *   37215: 4
    *   23: 2
*   **United States:**
    *   5902: 692
    *   5903: 353
    *   5901: 326
    *   80: 193
    *   1293: 117
*   **Vietnam:**
    *   22: 194
    *   3333: 11
    *   58603: 7
    *   23: 1

**CVEs Exploited:**
*   CVE-2024-14007 CVE-2024-14007: 27
*   CVE-2025-55182 CVE-2025-55182: 10
*   CVE-2021-3449 CVE-2021-3449: 9
*   CVE-2019-11500 CVE-2019-11500: 7
*   CVE-2002-0013 CVE-2002-0012: 3
*   CVE-2016-20016 CVE-2016-20016: 1

**Usernames:**
*   root: 213
*   admin: 137
*   user: 82
*   ubuntu: 27
*   postgres: 22
*   solana: 22
*   sol: 16
*   test: 16
*   user1: 16
*   debian: 15

**Passwords:**
*   123456: 262
*   123: 84
*   1234: 59
*   12345678: 57
*   admin: 22
*   password: 22
*   111111: 20
*   1: 13
*   solana: 13
*   1qaz@WSX: 11

**OS Distribution:**
*   Windows NT kernel: 122226
*   Linux 2.2.x-3.x: 85452
*   Linux 3.1-3.10: 2999
*   Linux 2.2.x-3.x (no timestamps): 2279
*   Linux 2.2.x-3.x (barebone): 2330
*   Linux 3.11 and newer: 2146
*   Linux 3.x: 1035
*   Windows NT kernel 5.x: 924
*   Windows 7 or 8: 977
*   Mac OS X: 106

**Hyper-aggressive IPs:**
*   170.64.230.118: 4058
*   173.249.27.120: 2329
*   45.87.249.140: 1035
