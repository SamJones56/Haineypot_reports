# Honeypot Attack Report - 2026-02-18T18:40:55Z

## Executive Summary:
*   **High Attack Volume**: A total of 5,202 attacks were recorded in the past hour, with a significant portion originating from a single source.
*   **Dominant Attacker**: A single IP address, 200.109.232.194, from Venezuela, was responsible for the vast majority of attacks (3,250).
*   **Primary Attack Vector**: The most common alert signature was "GPL INFO VNC server response," indicating widespread scanning for open VNC servers.
*   **Common Credentials**: Weak and default credentials such as 'root', 'sa', and '123123' continue to be prime targets.
*   **Attacker OS**: The primary attacking operating system was identified as Linux.
*   **CVEs Targeted**: A small number of CVEs were targeted, including CVE-2025-55182.

## Detailed Analysis:
*   **Total Attacks**: 5,202
*   **Top Attacking Countries**:
    *   Venezuela: 3,251
    *   United States: 647
    *   Germany: 257
    *   Canada: 255
    *   China: 152
*   **Notable IP Reputations**:
    *   known attacker: 859
    *   mass scanner: 212
*   **Common Alert Categories and Signatures**:
    *   **Categories**: "Misc activity" (2,028), "Generic Protocol Command Decode" (879), "Misc Attack" (293)
    *   **Signatures**: "GPL INFO VNC server response" (1,970), "SURICATA IPv4 truncated packet" (289), "SURICATA AF-PACKET truncated packet" (289)
*   **ASN Information**:
    *   CANTV Servicios, Venezuela (AS8048): 3,250
    *   DigitalOcean, LLC (AS14061): 557
    *   UCLOUD INFORMATION TECHNOLOGY HK LIMITED (AS135377): 498
    *   ONYPHE SAS (AS213412): 119
    *   CHINA UNICOM China169 Backbone (AS4837): 114
*   **Source IPs**:
    *   200.109.232.194: 3,250
    *   143.110.221.173: 251
    *   207.154.201.105: 150
    *   162.243.39.36: 113
    *   101.71.39.109: 63
*   **Country to Port Mapping**:
    *   Venezuela: 445 (3250)
    *   United States: 3384 (87)
    *   Canada: 22 (51)
    *   Germany: 22 (36)
    *   China: 30003 (112)
*   **CVEs Exploited**:
    *   CVE-2025-55182
    *   CVE-2002-0013
    *   CVE-2002-0012
    *   CVE-2024-14007
*   **Usernames & Passwords**:
    *   **Usernames**: 'root' (69), 'sa' (20), 'oracle' (9)
    *   **Passwords**: '123123' (11), '' (10), '111111' (8)
*   **OS Distribution**:
    *   Linux 2.2.x-3.x: 17,576
    *   Windows 7 or 8: 3,241
    *   Linux 2.2.x-3.x (barebone): 268
*   **Hyper-aggressive IPs**:
    *   200.109.232.194 (3,250 attacks)
*   **Unusual credential patterns**: None observed
*   **Attacker signatures/taunts**: None observed
*   **Malware/botnet filenames**: None observed
*   **Other high-signal deviations**: The overwhelming concentration of attacks from a single IP address (200.109.232.194) is the most significant deviation in this reporting period.