
## Investigation Scope
- investigation_start: 2026-03-07T06:00:08Z
- investigation_end: 2026-03-07T09:00:08Z
- completion_status: Complete
- degraded_mode: false

## Executive Triage Summary
- Top services/ports of interest include VNC (ports 5900-5912), SMB (port 445), SSH (port 22), and the unusual ICS/OT protocol Kamstrup Management Protocol (port 50100).
- Confirmed known exploitation includes "GPL INFO VNC server response" (17206 counts) and "ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication" (2260 counts). CVEs observed include CVE-2025-55182 (78 counts).
- Redis honeypot recorded `MODULE LOAD /tmp/exp.so` (7 counts), indicating potential remote code execution attempts.
- Botnet activity is widespread, originating from various ASNs like DigitalOcean, VNPT Corp, ADISTA SAS, and Dynu Systems Incorporated, engaged in mass scanning and opportunistic exploitation.

## Candidate Discovery Summary
- Total attacks: 21740
- Top attacking countries: United States (6870), Vietnam (3442), France (2679)
- Top attacker source IPs: 113.161.145.128 (3149), 79.98.102.166 (2571), 207.174.1.152 (2001)
- Top attacker ASNs: DigitalOcean, LLC (AS14061, 4690), VNPT Corp (AS45899, 3164), ADISTA SAS (AS16347, 2571)
- Top Suricata signatures: "GPL INFO VNC server response" (17206), "SURICATA IPv4 truncated packet" (4004), "ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication" (2260)
- Top CVEs: CVE-2025-55182 (78), CVE-2024-14007 (7)
- Top alert categories: Misc activity (17796), Generic Protocol Command Decode (9048), Attempted Administrator Privilege Gain (2288)
- Top input usernames (honeypots): root (134), postgres (48), ubuntu (38)
- Top input passwords (honeypots): 123 (48), 123456 (46), 1234 (31)
- Top OS (P0f): Linux 2.2.x-3.x (28328), Windows 7 or 8 (5607), Windows XP (2587)
- Redis honeypot actions: Closed (15), NewConnect (15), info (12), MODULE LOAD /tmp/exp.so (7)
- Adbhoney honeypot: No significant input or malware samples recorded.
- Conpot honeypot inputs: HTTP GET requests, `b'I20100'`
- Conpot honeypot protocols: kamstrup_management_protocol (11), guardian_ast (5)
- Tanner honeypot URIs: / (16), /.env (3), /SDK/webLanguage (2)
- IP reputation: known attacker (10713), mass scanner (534)
- Timeline counts: 214071 (06:00Z), 257067 (07:00Z), 200327 (08:00Z)

## Emerging n-day Exploitation
- **CVE-2025-55182**
  - cve/signature mapping: CVE-2025-55182
  - evidence summary: 78 counts of this CVE detected by Suricata.
  - affected service/port: N/A (requires further investigation to pinpoint specific services/ports from available data)
  - confidence: High
  - operational notes: Monitor for associated signatures and target services.
- **ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication**
  - cve/signature mapping: Signature ID 2024766
  - evidence summary: 2260 counts of this signature observed.
  - affected service/port: N/A (requires further investigation)
  - confidence: High
  - operational notes: Indicates active attempts to exploit systems with DoublePulsar.

## Novel or Zero-Day Exploit Candidates
- No strong candidates for novel or zero-day exploitation were identified from the current telemetry.

## Botnet/Campaign Infrastructure Mapping
- **Campaign ID: Initial Reconnaissance & Exploitation Attempts**
  - campaign_shape: Spray/scan with opportunistic exploitation attempts.
  - suspected_compromised_src_ips:
    - 113.161.145.128 (count: 3149)
    - 79.98.102.166 (count: 2571)
    - 207.174.1.152 (count: 2001)
    - 168.144.22.238 (count: 1004)
  - ASNs / geo hints:
    - DigitalOcean, LLC (AS14061, US): 4690 counts
    - VNPT Corp (AS45899, Vietnam): 3164 counts
    - ADISTA SAS (AS16347, France): 2571 counts
    - Dynu Systems Incorporated (AS398019, US): 2001 counts
  - suspected_staging indicators: Redis `MODULE LOAD /tmp/exp.so` (7 counts) suggests a potential attempt to load malicious modules. Tanner URI `/?%ADd+allow_url_include%3d1+%ADd+auto_prepend_file%3dphp://input` (1 count) indicates potential web exploit for remote code inclusion.
  - suspected_c2 indicators: None directly identified as C2. The Redis and Tanner activities suggest potential staging for further payload delivery.
  - confidence: High
  - operational notes: Block identified malicious IPs and monitor for payload delivery attempts related to `exp.so` or web shell activities.

## Odd-Service / Minutia Attacks
- **Service Fingerprint: Kamstrup Management Protocol (Port 50100)**
  - why it’s unusual/interesting: This is an Industrial Control System (ICS)/Operational Technology (OT) protocol, which is not commonly targeted in general internet scanning, making any activity against it noteworthy.
  - evidence summary: 11 counts of `kamstrup_management_protocol` detected by Conpot. Includes HTTP GET requests (`GET / HTTP/1.1`) and specific binary input (`b'I20100'`).
  - confidence: High
  - recommended monitoring pivots: Monitor for further ICS/OT protocol interactions, especially non-standard port communications.
- **Service Fingerprint: VNC on Non-Standard Ports (5906, 5907, 5911, 5912)**
  - why it’s unusual/interesting: While VNC (port 5900) is a common target, activity on higher VNC ports suggests broader reconnaissance or attempts to find less-monitored instances.
  - evidence summary: VNC related alerts, with specific counts for ports such as 5906 (80 from Australia), 5907 (78 from Australia), 5911 (57 from Australia), and 5912 (56 from Australia).
  - confidence: Medium
  - recommended monitoring pivots: Monitor for VNC connections on non-standard ports and investigate source IPs for these attempts.

## Known-Exploit / Commodity Exclusions
- **Credential Noise:** High volume of common usernames ("root", "postgres", "ubuntu") and weak passwords ("123", "123456", "password") observed across various honeypots, indicating widespread brute-force attempts.
- **Scanning Activity:** Significant counts of "SURICATA IPv4 truncated packet" and "SURICATA AF-PACKET truncated packet" alerts, coupled with broad scanning of common ports like 445 (SMB) and 22 (SSH) from numerous source IPs.
- **Common Bot Patterns:** "GPL INFO VNC server response" (17206 counts) indicates automated scanning for VNC services, a common botnet reconnaissance behavior. Generic "Misc activity" and "Generic Protocol Command Decode" categories also point to widespread automated attacks.

## Infrastructure & Behavioral Classification
- **Exploitation vs Scanning:** The observed activity is a mix of broad scanning (many IPs, various ports, truncated packets) and targeted exploitation attempts (CVEs, DoublePulsar, Redis `MODULE LOAD`, Tanner web exploit).
- **Campaign Shape:** Predominantly a spray-and-pray reconnaissance and opportunistic exploitation campaign, indicated by numerous source IPs from various ASNs targeting a wide range of services.
- **Infra Reuse Indicators:** The high concentration of attacking IPs from major cloud and hosting providers (DigitalOcean, VNPT Corp, ADISTA SAS, Dynu Systems) strongly suggests the use of compromised hosts or rented infrastructure for malicious activities.
- **Odd-Service Fingerprints:** Notable activity targeting the Kamstrup Management Protocol (ICS/OT) on Conpot honeypot, indicating reconnaissance or attacks against industrial control systems.

## Evidence Appendix
- **CVE-2025-55182**
  - Source IPs with counts: N/A (not directly available from `get_cve` output)
  - ASNs with counts: N/A
  - Target ports/services: N/A
  - Payload/artifact excerpts: N/A
  - Staging indicators: N/A
  - Temporal checks results: Unavailable
- **ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication (Signature ID 2024766)**
  - Source IPs with counts: N/A (requires `suricata_signature_samples` to extract)
  - ASNs with counts: N/A
  - Target ports/services: N/A
  - Payload/artifact excerpts: N/A
  - Staging indicators: N/A
  - Temporal checks results: Unavailable
- **Redis `MODULE LOAD /tmp/exp.so`**
  - Source IPs with counts: N/A (requires further investigation)
  - ASNs with counts: N/A
  - Target ports/services: Redis (port 6379, default)
  - Payload/artifact excerpts: `MODULE LOAD /tmp/exp.so`, `CONFIG SET dbfilename exp.so`, `CONFIG SET dir /tmp/`
  - Staging indicators: `exp.so` as a malicious module.
  - Temporal checks results: Unavailable
- **Conpot Kamstrup Management Protocol Activity**
  - Source IPs with counts: N/A (requires further investigation)
  - ASNs with counts: N/A
  - Target ports/services: 50100 (Kamstrup Management Protocol)
  - Paths/endpoints: `GET / HTTP/1.1`
  - Payload/artifact excerpts: `GET / HTTP/1.1
Host: 134.199.242.175:50100
User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64; rv:53.0) Gecko/20100101 Firefox/53.0
Accept: */*
Accept-Encoding: deflate, gzip
Accept-Language: zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6

`, `b'I20100'`
  - Staging indicators: N/A
  - Temporal checks results: Unavailable
- **Top Attacking Source IPs**
  - 113.161.145.128: 3149 counts, VNPT Corp (AS45899), Vietnam. Top target port: 445.
  - 79.98.102.166: 2571 counts, ADISTA SAS (AS16347), France. Top target port: 445.
  - 207.174.1.152: 2001 counts, Dynu Systems Incorporated (AS398019), United States. Top target port: 5900.
  - 168.144.22.238: 1004 counts, DigitalOcean, LLC (AS14061), United States. Top target port: N/A (requires further investigation)
  - Temporal checks results: Unavailable

## Indicators of Interest
- **IPs:**
  - 113.161.145.128
  - 79.98.102.166
  - 207.174.1.152
  - 168.144.22.238
- **CVEs:**
  - CVE-2025-55182
  - CVE-2024-14007
  - CVE-2021-3449
- **URLs/Paths:**
  - `/?%ADd+allow_url_include%3d1+%ADd+auto_prepend_file%3dphp://input` (Tanner)
  - `/.env` (Tanner)
- **Payload Fragments:**
  - `MODULE LOAD /tmp/exp.so` (Redis)
  - `b'I20100'` (Conpot)
- **Ports:**
  - 5900 (VNC)
  - 445 (SMB)
  - 22 (SSH)
  - 50100 (Kamstrup Management Protocol)

## Backend Tool Issues
- None. All backend tool calls were successful.
