# Honeypot Attack Report - 2026-02-18T19:00:30Z

## Executive Summary:
- **Total Attacks:** 5,990 attacks were observed in the last hour.
- **Top Attacker:** A hyper-aggressive IP, 200.109.232.194, from Venezuela, was responsible for over half of the total attacks (3,250).
- **Top Attacking Countries:** The majority of attacks originated from Venezuela, followed by the United States, Canada, Germany, and China.
- **Common Attack Vectors:** The most common alert categories were "Misc activity" and "Generic Protocol Command Decode," with a focus on targeting port 445.
- **Credentials:** Brute force attempts were common, with "root" as the most attempted username and "123123" as a frequently used password.
- **Attacker OS:** The predominant operating system used by attackers was identified as Linux.

## Detailed Analysis:
- **Total Attacks:** 5,990
- **Top Attacking Countries:** Venezuela (3,250), United States (850), Canada (715), Germany (370), China (181)
- **Notable IP Reputations:** The majority of attacking IPs were classified as "known attacker" or "mass scanner".
- **Common Alert Categories and Signatures:**
    - Categories: "Misc activity" (2,078), "Generic Protocol Command Decode" (686), "Misc Attack" (260)
    - Signatures: "GPL INFO VNC server response" (1,977), "SURICATA IPv4 truncated packet" (198), "SURICATA AF-PACKET truncated packet" (198)
- **ASN Information:**
    - 8048 (CANTV Servicios, Venezuela): 3,250
    - 14061 (DigitalOcean, LLC): 1,025
    - 135377 (UCLOUD INFORMATION TECHNOLOGY HK LIMITED): 425
- **Source IPs:**
    - 200.109.232.194: 3,250 attacks
    - 143.110.221.173: 456 attacks
    - 207.154.201.105: 280 attacks
- **Country to Port Mapping:**
    - Venezuela -> 445
    - United States -> 3384, 22
    - Canada -> 22
    - Germany -> 22
    - China -> 30003, 1433
- **CVEs Exploited:** CVE-2024-14007, CVE-2025-55182, CVE-2002-0606
- **Usernames & Passwords:**
    - Usernames: root, sa, postgres, ubuntu, administrator
    - Passwords: 123123, 111111, 12345, password, 123456
- **OS Distribution:** Linux 2.2.x-3.x (17,464), Windows 7 or 8 (3,240)
- **Hyper-aggressive IPs:** 200.109.232.194 (3,250 attacks)
