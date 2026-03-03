# Hourly Honeypot Attack Report - 2026-02-16T01:00:32Z
        - Executive Summary - This can be long.
        - Detailed Analysis:
            - Total Attacks: 1218
            - Top Attacking Countries: ['United States', 'China', 'Romania', 'Seychelles', 'Netherlands', 'Switzerland', 'Peru', 'Hong Kong', 'Singapore', 'Indonesia']
            - Notable IP Reputations: ['known attacker', 'mass scanner', 'bot, crawler']
            - Common Alert Categories and Signatures: {'Generic Protocol Command Decode': 6722, 'Misc Attack': 211, 'Attempted Administrator Privilege Gain': 177, 'Misc activity': 70, 'Attempted Information Leak': 56, 'Potentially Bad Traffic': 23, 'A Network Trojan was detected': 2, 'Detection of a Network Scan': 2, 'Not Suspicious Traffic': 1, 'Web Application Attack': 1}
            - ASN Information of Attackers: {'4837': 'CHINA UNICOM China169 Backbone', '396982': 'Google LLC', '47890': 'Unmanaged Ltd', '14061': 'DigitalOcean, LLC', '16509': 'Amazon.com, Inc.', '42624': 'Global-Data System IT Corporation', '215925': 'Vpsvault.host Ltd', '135377': 'UCLOUD INFORMATION TECHNOLOGY HK LIMITED', '6939': 'Hurricane Electric LLC', '398324': 'Censys, Inc.'}
            - Source IP Addresses of Attackers: ['2.57.122.96', '101.71.39.109', '212.11.64.219', '101.71.37.77', '87.120.191.13', '46.19.137.194', '18.218.118.203', '92.118.39.76', '161.132.37.26', '216.180.246.52']
            - Country to Port Mapping: {'United States': {8728: 56, 15671: 34, 49080: 23, 22: 14, 443: 14, 8000: 13, 8010: 12, 9500: 12, 22227: 12, 18443: 11}, 'China': {30003: 138, 2154: 7, 5984: 7, 1194: 6, 8886: 5, 30004: 5, 2128: 4, 6379: 3, 63000: 3, 80: 2}, 'Romania': {22: 16, 40398: 1}, 'Seychelles': {22222: 72, 9042: 1}, 'Netherlands': {8728: 14, 9100: 8, 17001: 8, 25: 7, 80: 6, 7005: 4, 25565: 3, 81: 2, 9042: 2, 22: 1}, 'Switzerland': {5433: 36, 443: 1, 5432: 1}, 'Peru': {22: 34}, 'Hong Kong': {2108: 10, 4433: 7, 3306: 2, 80: 1, 1610: 1, 2774: 1, 3372: 1, 10286: 1, 25955: 1}, 'Singapore': {8728: 21, 12448: 3}, 'Indonesia': {22: 4}}
            - CVEs Exploited: ['CVE-2024-14007', 'CVE-2025-55182']
            - Common Usernames and Passwords Attempted: {'passwords': ['ubuntu', 'sol', 'solana', '123', '1234', '123456', 'a', 'admin', 'centos']}
            - OS Distribution of Attackers Based on p0f Data: {'Linux 2.2.x-3.x': 7203, 'Mac OS X': 442, 'Windows NT kernel 5.x': 235, 'Linux 2.2.x-3.x (barebone)': 214, 'Linux 3.11 and newer': 187, 'Linux 2.2.x-3.x (no timestamps)': 76, 'Windows NT kernel': 15, 'Windows 7 or 8': 6, 'Nintendo 3DS': 2, 'Linux 3.1-3.10': 1}
            - Hyper-aggressive IP Addresses: ['2.57.122.96', '101.71.39.109', '212.11.64.219', '101.71.37.77']
            - Unusual or Specific Usernames/Passwords: Due to a tool error, no usernames were retrieved.
            - Attacker Signatures, Comments, or Taunts: None observed.
            - Blatant Malware or Botnet Filenames: None observed.
            - Other Notable Deviations from Background Noise: The detection of a Nintendo 3DS as an attacking operating system is highly unusual and warrants further investigation. The high volume of 'SURICATA IPv4 truncated packet' and 'SURICATA AF-PACKET truncated packet' alerts may indicate fragmented packet attacks or network configuration issues. The alert for 'ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication' is a critical finding, suggesting an attempt to install a sophisticated backdoor.
        Constraints:
            - Use only values in the logs (dont invent).
            - List all CVEs.
            - Professional tone.
    