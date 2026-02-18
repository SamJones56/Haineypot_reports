
# Honeypot Attack Report - 2026-02-18T19:15:25Z

## Executive Summary:
*   **Total Attacks**: 5,160 attacks were recorded in the past hour.
*   **Top Attacker**: Venezuela was the source of the highest number of attacks, with a single IP address, 200.109.232.194, being responsible for 2,015 attacks.
*   **Attack Profile**: The majority of attacks were categorized as "Misc activity" and triggered VNC-related alert signatures.
*   **Targets**: The most common targets were SMB (port 445) and SSH (port 22).
*   **Credentials**: Brute-force attempts primarily used common usernames like "root" and "admin" with simple passwords such as "123456" and "password".
*   **Attacker Landscape**: The attacker landscape is dominated by Linux-based systems, with a significant number of attacks also originating from Windows systems.

## Detailed Analysis:
*   **Total Attacks**: 5,160
*   **Top Attacking Countries**: Venezuela (2015), Canada (1366), United States (706), Germany (340), China (196)
*   **Notable IP Reputations**: "known attacker" (1394), "mass scanner" (187)
*   **Common Alert Categories and Signatures**: "Misc activity" (2161) and "GPL INFO VNC server response" (2040)
*   **ASN Information**: 
    *   AS8048 - CANTV Servicios, Venezuela (2015)
    *   AS14061 - DigitalOcean, LLC (1114)
    *   AS209334 - Modat B.V. (657)
*   **Source IPs**: 
    *   200.109.232.194 (2015)
    *   143.110.221.173 (593)
    *   207.154.201.105 (269)
*   **Country to Port Mapping**:
    *   Venezuela -> 445
    *   Canada -> 22, 1080
    *   United States -> 3384, 22
    *   Germany -> 22
    *   China -> 30003, 1433
*   **CVEs Exploited**: CVE-2024-14007, CVE-2024-4577, CVE-2002-0953, CVE-2002-0013, CVE-2002-0012, CVE-2002-0606
*   **Usernames & Passwords**:
    *   **Usernames**: root, sa, admin, user, ubuntu
    *   **Passwords**: 111111, 123456, password, 123123, 12345
*   **OS Distribution**: 
    *   Linux 2.2.x-3.x (17897)
    *   Windows 7 or 8 (2001)
*   **Hyper-aggressive IPs**: 200.109.232.194 (2015 attacks)
