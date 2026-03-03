
# Honeypot Attack Summary Report – 2026-02-24T00:46:36Z

## Metadata

- **Report Generation Time:** 2026-02-24T00:46:36Z
- **Timeframe Covered:** 2026-02-23T00:30:23Z to 2026-02-24T00:30:23Z
- **Files Used:**
  - `/home/user/Haineypot/reports/daily_reports/Honeypot_Attack_Daily_Report_2026-02-24T00-31-24Z.md`

## Executive Summary

The honeypot network recorded a high volume of 133,162 attacks over the past 24 hours. A significant portion of this activity originated from the United States, with DigitalOcean (AS14061) being the dominant source network. Threat actors focused on exploiting recent, critical vulnerabilities, notably CVE-2025-55182 (React2Shell) and CVE-2024-14007 (TVT NVMS-9000). A single IP address, 165.245.134.97, was identified as hyper-aggressive, launching 5,829 attacks. Standard credential-stuffing attacks against services like SSH remain a constant threat, with "root" and "admin" being the most attempted usernames.

## Detailed Analysis

### Our IPs

| Honeypot      | IP Address      |
|---------------|-----------------|
| tpot-hive-ny  | 134.199.242.175 |

### Attacks by Honeypot

| Honeypot      | Total Attacks |
|---------------|---------------|
| tpot-hive-ny  | 133,162       |

### Top Source Countries

| Country       | Attack Count |
|---------------|--------------|
| United States | 49,136       |
| India         | 14,910       |
| Australia     | 11,988       |
| Germany       | 10,657       |
| Vietnam       | 6,273        |

### Top Attacking IPs

| IP Address        | Attack Count |
|-------------------|--------------|
| 165.245.134.97    | 5,829        |
| 103.53.231.159    | 4,365        |
| 170.64.230.118    | 4,058        |
| 183.82.0.100      | 3,157        |
| 129.212.184.194   | 2,704        |
| 59.145.41.149     | 2,555        |
| 173.249.27.120    | 2,329        |
| 64.32.31.2        | 1,874        |
| 185.177.72.49     | 1,772        |
| 14.177.96.230     | 1,744        |

### Top Targeted Ports/Protocols

| Port | Protocol | Country         | Count |
|------|----------|-----------------|-------|
| 445  | SMB      | India, Vietnam  | 7,460 |
| 22   | SSH      | Multiple        | 9,042 |
| 5902 | VNC      | United States   | 2,722 |
| 1080 | SOCKS    | United States   | 1,874 |
| 5901 | VNC      | United States   | 1,477 |
| 5903 | VNC      | United States   | 1,378 |

### Most Common CVEs

| CVE               | Count |
|-------------------|-------|
| CVE-2025-55182    | 136   |
| CVE-2024-14007    | 99    |
| CVE-2021-3449     | 30    |
| CVE-2002-1149     | 29    |
| CVE-2019-11500    | 25    |
| CVE-2021-1499     | 17    |
| CVE-2002-0013     | 8     |
| CVE-2002-0953     | 8     |
| CVE-2024-4577     | 6     |

### Signatures Triggered

| Signature                                           | Count |
|-------------------------------------------------------|-------|
| SURICATA IPv4 truncated packet                        | 9,349 |
| SURICATA AF-PACKET truncated packet                   | 9,349 |
| GPL INFO VNC server response                          | 5,270 |
| SURICATA SSH invalid banner                           | 4,546 |
| ET DROP Dshield Block Listed Source group 1           | 2,773 |
| ET INFO CURL User Agent                               | 2,387 |
| ET INFO SSH session in progress on Expected Port      | 2,384 |
| ET INFO SSH-2.0-Go version string Observed in Network Traffic | 2,216 |
| ET INFO SSH session in progress on Unusual Port       | 2,083 |
| ET SCAN MS Terminal Server Traffic on Non-standard Port | 1,610 |

### Users / Login Attempts

| Username | Attempts |
|----------|----------|
| root     | 2,981    |
| admin    | 1,631    |
| user     | 885      |
| test     | 720      |
| oracle   | 564      |
| guest    | 542      |
| ubuntu   | 529      |
| postgres | 514      |
| mysql    | 302      |
| centos   | 275      |

### Top Attacker AS Organizations

| ASN     | Organization               | Attack Count |
|---------|----------------------------|--------------|
| 14061   | DigitalOcean, LLC          | 73,284       |
| 47890   | Unmanaged Ltd              | 7,273        |
| 131427  | AOHOAVIET                  | 4,365        |
| 18209   | Atria Convergence Technologies Ltd. | 3,157        |
| 202425  | IP Volume inc              | 2,801        |
| 209334  | Modat B.V.                 | 2,669        |
| 9498    | BHARTI Airtel Ltd.         | 2,555        |
| 51167   | Contabo GmbH               | 2,504        |
| 396982  | Google LLC                 | 2,433        |
| 211590  | Bucklog SARL               | 2,268        |

## OSINT Section

### OSINT on High-Frequency IPs
- **165.245.134.97:** Geoloacted to the United States. This IP has been flagged in abuse databases as "recently reported" for malicious activity, though specifics of the campaigns are not public.
- **103.53.231.159:** Attributed to China Telecom. The IP is listed on the Binary Defense Systems (BDS) Artillery Threat Intelligence Feed and Banlist for association with phishing and malware distribution.
- **170.64.230.118:** Hosted by DigitalOcean (AS14061) in Australia/United States. While this specific IP has no direct public abuse reports, its ASN is a known major source of malicious traffic.

### OSINT on ASNs
- **AS14061 (DigitalOcean, LLC):** Numerous threat intelligence reports confirm that DigitalOcean's network is a significant source of malicious activity, widely used for malware distribution, phishing campaigns, and port scanning. The high volume of attacks (73,284) from this ASN is consistent with these reports.

### OSINT on Signatures
- **SURICATA IPv4/AF-PACKET truncated packet:** These high-volume alerts (18,698 combined) often indicate network configuration issues, such as hardware offloading, rather than a direct attack. However, they can also be used by threat actors in an attempt to evade detection by security systems. The sheer volume suggests either a misconfiguration in the honeypot's capture environment or widespread scanning using this technique.

### OSINT on CVEs
- **CVE-2025-55182 (React2Shell):** A critical (CVSS 10.0) remote code execution vulnerability in React Server Components. It is actively exploited in the wild to deploy cryptominers and establish backdoors. Its appearance in honeypot logs indicates automated scanning and exploitation campaigns are widespread.
- **CVE-2024-14007:** A critical authentication bypass vulnerability affecting TVT NVMS-9000 network video recorders. This flaw is heavily exploited by IoT botnets, most notably Mirai, to absorb vulnerable devices into their infrastructure for DDoS attacks.

## Key Observations and Anomalies

- **Hyper-Aggressive Actor:** The IP address **165.245.134.97** demonstrated hyper-aggressive behavior, accounting for 5,829 attacks alone. This level of activity from a single IP is indicative of a dedicated malicious host or a compromised server being used for attacks.
- **Infrastructure Reuse:** The overwhelming dominance of **AS14061 (DigitalOcean)**, contributing over 55% of all observed attacks, highlights how threat actors leverage legitimate cloud infrastructure for malicious campaigns at scale. The provider's lax abuse policies or sheer size make it a favored choice.
- **Campaign Indicators:** The targeting of **CVE-2024-14007** strongly suggests that the honeypot is being probed by Mirai botnet variants seeking to expand their network. The exploitation attempts against **CVE-2025-55182** reflect the rapid weaponization of new, high-impact vulnerabilities by threat actors.
- **Targeting Anomalies:** A high concentration of VNC scanning (ports 5901, 5902, 5903) was observed originating from the United States, suggesting a specific campaign focused on unprotected remote access systems.

## Unusual Attacker Origins

While the top attacking countries (United States, India, Germany) are common sources of internet noise and malicious activity, the presence of **Vietnam** in the top five, with a strong focus on SMB (port 445) and SSH (port 22), is notable. This may indicate a regional botnet or a focused campaign originating from this area.
