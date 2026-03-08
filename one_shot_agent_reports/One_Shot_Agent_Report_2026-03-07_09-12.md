## Investigation Scope
- investigation_start: 2026-03-07T09:00:08Z
- investigation_end: 2026-03-07T12:00:08Z
- completion_status: Complete
- degraded_mode: false

## Executive Triage Summary
- Top services/ports of interest: VNC (port 5900), SSH (port 22), SMB (port 445), various honeypot ports (e.g., Conpot protocols). Unusual ports 5901, 5902, 5903, 5906, 5907, 9999, 6000, and specific CVE-related ports (3013, 3015, 6789, 7003, 7382) indicate a mix of common services and targeted activity.
- Top confirmed known exploitation: Extensive "GPL INFO VNC server response" (17463 events) and "ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication" (1679 events).
- Top unmapped exploit-like items: While CVEs are mapped, the "CVE-2025-55182" activity targeting specific high ports might warrant further investigation if its true nature isn't fully captured by the CVE alone.
- Botnet/campaign mapping highlights: Significant activity from DigitalOcean, LLC and Alibaba US Technology Co., Ltd. ASNs. Repeated brute-force attempts with common usernames/passwords suggest commodity botnet activity.
- Major uncertainties if degraded: None.

## Candidate Discovery Summary
- Total attack events: 24733
- Top 5 Attacking Countries: United States (6770), India (6289), Singapore (2609), Qatar (1397), Australia (1138)
- Top 5 Attacker Source IPs: 143.244.131.140 (3528), 168.144.22.238 (2522), 178.153.127.226 (1397), 74.207.237.5 (1349), 136.114.97.84 (754)
- Top 5 Alert Categories: Misc activity (18123), Generic Protocol Command Decode (2592), Attempted Administrator Privilege Gain (1699), Misc Attack (1224), Attempted Information Leak (857)
- Top 5 Alert Signatures: GPL INFO VNC server response (17463), ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication (1679), SURICATA IPv4 truncated packet (844), SURICATA AF-PACKET truncated packet (844), ET SCAN MS Terminal Server Traffic on Non-standard Port (617)
- Top 5 CVEs: CVE-2025-55182 (95), CVE-2020-2551 (6), CVE-2024-14007 (4), CVE-2021-3449 (3), CVE-2002-0013 (2)
- Top 5 Attacker ASNs: DigitalOcean, LLC (AS14061, 9654), Alibaba US Technology Co., Ltd. (AS45102, 2002), Akamai Connected Cloud (AS63949, 1538), Ooredoo Q.S.C. (AS8781, 1397), Google LLC (AS396982, 1363)
- Top 5 P0f OS Distribution: Linux 2.2.x-3.x (32787), Linux 3.11 and newer (2899), Windows NT kernel (2165), Linux 2.2.x-3.x (barebone) (1237), Windows NT kernel 5.x (417)
- Top 5 Input Usernames: root (461), user (60), ubuntu (43), admin (42), 345gs5662d34 (35)
- Top 5 Input Passwords: 123456 (159), 1234 (55), 123 (51), password (47), 12345678 (37)
- Top 3 IP Reputations: known attacker (15213), mass scanner (519), bot, crawler (6)
- Tanner Honeypot: 104 events, top paths include "/", "/.env", "/134.199.242.175/.env"
- Redis Honeypot: 35 events, actions include "Closed", "NewConnect", "info"
- Adbhoney Honeypot: 42 events, no specific malware samples or command inputs identified.
- Conpot Honeypot: 60 events, inputs like "USER test", "GET / HTTP/1.0", protocols "kamstrup_management_protocol", "guardian_ast".

## Emerging n-day Exploitation
- **CVE-2025-55182**
    - cve/signature mapping: CVE-2025-55182
    - evidence summary: 95 events. Targeted destination ports observed include 3013, 3015, 6789, 7003, 7382.
    - affected service/port: Various high ports (3013, 3015, 6789, 7003, 7382)
    - confidence: High
    - operational notes: Monitor traffic to these specific ports and investigate the nature of the associated vulnerability.

## Novel or Zero-Day Exploit Candidates (UNMAPPED ONLY, ranked)
None identified.

## Botnet/Campaign Infrastructure Mapping
- **Commodity Scanning & Brute-Forcing Campaign**
    - item_id or related candidate_id(s): Associated with multiple source IPs and common credential attempts.
    - campaign_shape: Spray (wide distribution targeting common services like SSH and VNC).
    - suspected_compromised_src_ips: Top IPs include 143.244.131.140 (3528), 168.144.22.238 (2522), 178.153.127.226 (1397).
    - ASNs / geo hints: DigitalOcean, LLC (US), Alibaba US Technology Co., Ltd. (CN), Akamai Connected Cloud (US).
    - suspected_staging indicators: N/A
    - suspected_c2 indicators: N/A
    - confidence: High (based on repetitive, low-effort attacks across various IPs and common credentials).
    - operational notes: Block known attacker IPs and implement strong credential policies.

## Odd-Service / Minutia Attacks
- **VNC Services on Various Ports**
    - service_fingerprint: VNC (primarily port 5900, but also 5901, 5902, 5903, 5906, 5907)
    - why it’s unusual/interesting: The high volume of VNC activity (17463 events, "GPL INFO VNC server response") suggests broad scanning or targeted enumeration of VNC services, potentially indicating reconnaissance for access. Activity on non-standard VNC ports (5901-5907) is also noteworthy.
    - evidence summary: 17463 events related to "GPL INFO VNC server response". A sample shows VNC activity from 129.212.183.98 to 10.17.0.5 on port 5900.
    - confidence: High
    - recommended monitoring pivots: Monitor for VNC connections from external IPs, especially those not expected to access VNC. Review VNC server logs for unusual access attempts or successful connections.

- **Conpot ICS/SCADA Honeypot Interactions**
    - service_fingerprint: Conpot (Kamstrup management protocol, Guardian AST)
    - why it’s unusual/interesting: Interactions with ICS/SCADA honeypots indicate actors probing industrial control systems. The identified protocols are specific to ICS environments, suggesting targeted or opportunistic scanning for such systems.
    - evidence summary: 60 events, including inputs like "USER test" and "GET / HTTP/1.0", and identified protocols "kamstrup_management_protocol" (38 events) and "guardian_ast" (20 events).
    - confidence: High
    - recommended monitoring pivots: Monitor for traffic targeting known ICS/SCADA ports and protocols. Investigate the source IPs interacting with these honeypots for potential real-world targets.

## Known-Exploit / Commodity Exclusions
- **Credential Noise**: Brute-force attempts against common usernames ("root", "user", "admin") and weak passwords ("123456", "password") are widespread, indicating commodity scanning and botnet activity across many IPs. (Counts: thousands of login attempts).
- **Common Scanners**: Signatures like "ET SCAN MS Terminal Server Traffic on Non-standard Port" point to automated scanning for open services.
- **Generic Protocol Command Decode**: High volume of "Generic Protocol Command Decode" alerts (2592 events) often indicates broad port scanning and protocol probing.

## Infrastructure & Behavioral Classification
- **VNC Exploitation/Scanning**: Exploitation/scanning, Spray, Infra reuse indicators (multiple IPs targeting VNC), Odd-service fingerprints (VNC on standard and non-standard ports).
- **CVE-2025-55182 Activity**: Exploitation, Unknown campaign shape (likely targeted probing or exploitation), Unknown infra reuse, Odd-service fingerprints (various high ports).
- **Conpot ICS/SCADA Probing**: Scanning/Reconnaissance, Spray (probing various ICS protocols), Infra reuse indicators (multiple IPs), Odd-service fingerprints (Kamstrup, Guardian AST protocols).
- **General Brute-Forcing**: Scanning/Brute-forcing, Spray, High infra reuse (many IPs, often from cloud providers), No specific odd-service fingerprints (targets common services like SSH).

## Evidence Appendix
- **Emerging n-day Exploitation: CVE-2025-55182**
    - source IPs with counts: Missing (top_src_ips_for_cve returned no specific IPs)
    - ASNs with counts: Missing (no direct link to CVE-specific ASNs)
    - target ports/services: 3013 (6), 3015 (6), 6789 (6), 7003 (6), 7382 (6)
    - paths/endpoints: Missing
    - payload/artifact excerpts: Missing (raw event data not retrieved for all CVEs)
    - staging indicators: Missing
    - temporal checks: Unavailable

- **Botnet/Campaign Infrastructure Mapping: Commodity Scanning & Brute-Forcing Campaign**
    - source IPs with counts: 143.244.131.140 (3528), 168.144.22.238 (2522), 178.153.127.226 (1397), 74.207.237.5 (1349), 136.114.97.84 (754)
    - ASNs with counts: DigitalOcean, LLC (AS14061, 9654), Alibaba US Technology Co., Ltd. (AS45102, 2002), Akamai Connected Cloud (AS63949, 1538), Ooredoo Q.S.C. (AS8781, 1397), Google LLC (AS396982, 1363)
    - target ports/services: Predominantly SSH (port 22) and VNC (port 590x), also SMB (port 445).
    - paths/endpoints: Varies, often basic probes or login attempts. Example Tanner paths: "/", "/.env".
    - payload/artifact excerpts: Common usernames (root, user, admin), common passwords (123456, password).
    - staging indicators: N/A
    - temporal checks: Unavailable

- **Odd-Service / Minutia Attacks: VNC Services on Various Ports**
    - source IPs with counts: 129.212.183.98 (example from sample)
    - ASNs with counts: Missing (specific ASN for 129.212.183.98 not retrieved, but likely from observed top ASNs)
    - target ports/services: 5900 (primary VNC port), also 5901, 5902, 5903, 5906, 5907.
    - paths/endpoints: N/A (VNC protocol)
    - payload/artifact excerpts: "GPL INFO VNC server response" (signature text).
    - staging indicators: Missing
    - temporal checks: Unavailable

## Indicators of Interest
- **IPs**: 143.244.131.140, 168.144.22.238, 178.153.127.226, 74.207.237.5, 136.114.97.84, 129.212.183.98
- **CVEs**: CVE-2025-55182, CVE-2020-2551, CVE-2024-14007
- **Ports**: 22, 80, 445, 5900, 5901, 5902, 5903, 5906, 5907, 3013, 3015, 6789, 7003, 7382, 9999, 6000
- **Paths/Endpoints**: /, /.env, /134.199.242.175/.env, /hudson (from Tanner honeypot)
- **Payload Fragments**: "root", "123456" (common credentials)

## Backend Tool Issues
None.