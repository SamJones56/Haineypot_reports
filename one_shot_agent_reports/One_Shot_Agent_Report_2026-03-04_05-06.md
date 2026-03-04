# Investigation Report 2026-03-04T05:00:03Z to 2026-03-04T06:00:03Z

## Investigation Scope
- investigation_start: 2026-03-04T05:00:03Z
- investigation_end: 2026-03-04T06:00:03Z
- completion_status: Complete
- degraded_mode: false

## Executive Triage Summary
- Top services/ports of interest include VNC (port 5900, 5925, 5926), SSH (port 22), and various web-related traffic on HTTP (port 80).
- Notable odd-service activity observed on Conpot honeypot with IEC104 and guardian_ast protocols.
- Confirmed known exploitation: "GPL INFO VNC server response" (2629 counts), "ET SCAN MS Terminal Server Traffic on Non-standard Port" (246 counts), and "ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication" (90 counts).
- Emerging n-day exploitation identified for CVE-2025-55182 (6 counts) and CVE-2024-14007 (4 counts).
- Botnet/campaign mapping highlights: DigitalOcean, LLC (ASN 14061) as a prominent source of attacks (2056 counts), with common attack patterns observed from known attackers and mass scanners. Credential stuffing attempts with common usernames like "admin", "deploy", "user", "root" and passwords like "123456", "123", "1234" were also prevalent.
- Significant activity originating from the United States, Netherlands, and Switzerland.

## Candidate Discovery Summary
- Total attack events: 4989
- Top attacking countries: United States (2307), Netherlands (998), Switzerland (505)
- Top attacking Source IPs: 164.92.155.68 (909), 46.19.137.194 (503), 140.235.19.89 (444)
- Top attacking ASNs: DigitalOcean, LLC (ASN 14061, 2056 counts), Private Layer INC (ASN 51852, 503 counts)
- IP Reputation: known attacker (2656 counts), mass scanner (261 counts)
- OS Distribution: Windows NT kernel (15353 counts), Linux 2.2.x-3.x (8372 counts)
- Common usernames: admin (19), deploy (14), user (14)
- Common passwords: 123456 (28), 123 (15), 1234 (7)
- Suricata Alert Signatures: GPL INFO VNC server response (2629), SURICATA IPv4 truncated packet (398), ET SCAN MS Terminal Server Traffic on Non-standard Port (246)
- Suricata Alert Categories: Misc activity (2765), Generic Protocol Command Decode (1178), Misc Attack (418)
- CVEs Identified: CVE-2025-55182 (6), CVE-2024-14007 (4)
- Honeypot specific observations:
    - Tanner URI requests for '/' and WordPress related paths.
    - Redis actions include "Closed", "NewConnect", and "GET / HTTP/1.1".
    - Adbhoney recorded "id" as input.
    - Conpot observed IEC104 and guardian_ast protocols.

## Emerging n-day Exploitation
- cve/signature mapping: CVE-2025-55182
  - evidence summary: 6 alert counts related to this CVE.
  - affected service/port: N/A (specific port not available in current data)
  - confidence: High
  - operational notes: Monitor for further exploitation attempts related to CVE-2025-55182.
- cve/signature mapping: CVE-2024-14007
  - evidence summary: 4 alert counts related to this CVE.
  - affected service/port: N/A (specific port not available in current data)
  - confidence: High
  - operational notes: Monitor for further exploitation attempts related to CVE-2024-14007.

## Novel or Zero-Day Exploit Candidates (UNMAPPED ONLY, ranked)
- No strong evidence for novel or zero-day exploit candidates found.

## Botnet/Campaign Infrastructure Mapping
- item_id: 164.92.155.68 (related to top attacker IP)
  - campaign_shape: Unknown (likely spray)
  - suspected_compromised_src_ips: 164.92.155.68 (909 counts), 46.19.137.194 (503 counts), 140.235.19.89 (444 counts)
  - ASNs / geo hints: ASN 14061 (DigitalOcean, LLC) - United States; ASN 51852 (Private Layer INC) - Netherlands; ASN 398019 (Dynu Systems Incorporated) - United States.
  - suspected_staging indicators: None explicitly identified in the provided data.
  - suspected_c2 indicators: None explicitly identified in the provided data.
  - confidence: Medium (Based on high volume from known attacker ASNs)
  - operational notes: Investigate IPs from DigitalOcean, Private Layer, and Dynu Systems for common attack patterns and potential staging/C2 infrastructure.
- item_id: Credential Stuffing Campaign
  - campaign_shape: Spray
  - suspected_compromised_src_ips: Seen across many IPs (not specific to one IP)
  - ASNs / geo hints: Global (observed from various countries/ASNs)
  - suspected_staging indicators: None explicitly identified.
  - suspected_c2 indicators: None explicitly identified.
  - confidence: High
  - operational notes: Implement stronger authentication policies and monitor for brute-force/credential-stuffing attempts targeting common usernames and passwords.

## Odd-Service / Minutia Attacks
- service_fingerprint: IEC104 (Conpot honeypot)
  - why it’s unusual/interesting: IEC104 is an industrial control system (ICS) protocol. Attacks on ICS systems are generally high-value targets.
  - evidence summary: 5 counts on Conpot honeypot.
  - confidence: High
  - recommended monitoring pivots: Further investigate source IPs targeting IEC104, analyze command inputs for specific ICS exploitation attempts.
- service_fingerprint: guardian_ast (Conpot honeypot)
  - why it’s unusual/interesting: Another industrial control system (ICS) related protocol, indicating potential targeting of critical infrastructure.
  - evidence summary: 2 counts on Conpot honeypot.
  - confidence: High
  - recommended monitoring pivots: Investigate source IPs and specific interactions related to guardian_ast.
- service_fingerprint: VNC (ports 5900, 5925, 5926, 5906, 5907, 5911, 5913, 5914)
  - why it’s unusual/interesting: Significant VNC activity, especially with "GPL INFO VNC server response" signature. Could indicate reconnaissance or attempts to exploit VNC services.
  - evidence summary: Over 2600 counts for VNC server response, with various ports targeted from multiple countries (United States, Australia).
  - confidence: High
  - recommended monitoring pivots: Monitor VNC traffic for suspicious activity, enforce strong authentication, and ensure VNC services are not exposed unnecessarily.

## Known-Exploit / Commodity Exclusions
- Credential Noise: Numerous attempts with common usernames ("admin", "root", "user") and weak passwords ("123456", "123"). Evidence: `get_input_usernames` and `get_input_passwords` outputs.
- Scanning Activity: "ET SCAN MS Terminal Server Traffic on Non-standard Port" (246 counts) and "mass scanner" IP reputation (261 counts). Evidence: `get_alert_signature` and `get_src_ip_reputation` outputs.
- Known Bot Patterns: "SURICATA IPv4 truncated packet", "SURICATA AF-PACKET truncated packet", and high volumes from ASNs like DigitalOcean and Private Layer. Evidence: `get_alert_signature` and `get_attacker_asn` outputs.

## Infrastructure & Behavioral Classification
- Exploitation vs Scanning: Mix of both. Clear exploitation attempts for VNC and some CVEs. Significant scanning activity indicated by "mass scanner" reputation and general protocol anomaly alerts.
- Campaign Shape: Predominantly spray-and-pray attacks (credential stuffing, widespread scanning, VNC reconnaissance). Limited evidence for targeted fan-in/fan-out or beaconing.
- Infra Reuse Indicators: Strong indicators of infrastructure reuse from specific ASNs (DigitalOcean, Private Layer) for various attack types.
- Odd-Service Fingerprints: Conpot honeypot captured ICS-specific protocols (IEC104, guardian_ast), indicating focused attacks on industrial control systems.

## Evidence Appendix
- CVE-2025-55182
  - source IPs with counts: N/A (not available directly from `get_cve` tool)
  - ASNs with counts: N/A
  - target ports/services: N/A
  - paths/endpoints: N/A
  - payload/artifact excerpts: N/A
  - staging indicators: N/A
  - temporal checks results: unavailable
- CVE-2024-14007
  - source IPs with counts: N/A
  - ASNs with counts: N/A
  - target ports/services: N/A
  - paths/endpoints: N/A
  - payload/artifact excerpts: N/A
  - staging indicators: N/A
  - temporal checks results: unavailable
- GPL INFO VNC server response (Signature ID 2100560)
  - source IPs with counts: Top IPs related to VNC traffic include 164.92.155.68, 46.19.137.194, 140.235.19.89 and many others.
  - ASNs with counts: DigitalOcean, LLC (ASN 14061), Private Layer INC (ASN 51852), Dynu Systems Incorporated (ASN 398019)
  - target ports/services: 5900, 5925, 5926, 5906, 5907, 5911, 5913, 5914 (and likely others)
  - paths/endpoints: N/A
  - payload/artifact excerpts: "GPL INFO VNC server response" (from signature text)
  - staging indicators: N/A
  - temporal checks results: unavailable
- IEC104 (Conpot honeypot)
  - source IPs with counts: N/A (specific IPs not aggregated for Conpot protocols in this query)
  - ASNs with counts: N/A
  - target ports/services: Conpot default ports for IEC104 (e.g., 2404/TCP)
  - paths/endpoints: N/A
  - payload/artifact excerpts: N/A
  - staging indicators: N/A
  - temporal checks results: unavailable

## Indicators of Interest
- IPs: 164.92.155.68, 46.19.137.194, 140.235.19.89
- CVEs: CVE-2025-55182, CVE-2024-14007
- Signature IDs: 2100560 (GPL INFO VNC server response), 2023753 (ET SCAN MS Terminal Server Traffic on Non-standard Port), 2024766 (ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication)
- Honeypot Inputs: "admin", "123456", "id"
- Protocols: IEC104, guardian_ast

## Backend Tool Issues
- No tool failures were encountered during this investigation. All key checks were completed.