# Investigation Report

## 1) Investigation Scope
- investigation_start: 2026-03-04T02:00:05Z
- investigation_end: 2026-03-04T03:00:05Z
- completion_status: Complete
- degraded_mode: true - The 'url_path' field was not present in the dataset, limiting deep analysis of some web-based attack patterns.

## 2) Executive Triage Summary
- Top services/ports of interest: VNC (5902, 5903, 5905, 5906, 5907, 5911, 5912, 5913, 5925, 5926), Dovecot/IMAPS/SMTPS (993, 995, 465), MS Terminal Server (non-standard ports), MySQL (3306), SSH (22).
- Top confirmed known exploitation: CVE-2019-11500 (Dovecot Memory Corruption) and CVE-2021-3449 (OpenSSL TLSv1.2 DoS).
- Top unmapped exploit-like items: None definitively identified as novel/unmapped exploit candidates; observed activity is primarily mapped to known CVEs and signatures.
- Botnet/campaign mapping highlights: Significant activity from DigitalOcean, Google LLC, and Private Layer INC ASNs. Evidence of mass scanning and known attacker activity.
- Major uncertainties if degraded: Lack of a populated 'url_path' field means some web traffic analysis relied on other path fields, which might not be as comprehensive.

## 3) Candidate Discovery Summary
- Total attack events: 3509
- Top attacking countries: United States (1912), Switzerland (238), Ukraine (228)
- Top attacking ASNs: DigitalOcean, LLC (1170), Google LLC (458)
- Top alert categories: Misc activity (2759), Generic Protocol Command Decode (999)
- Discovered CVEs: CVE-2019-11500 (4), CVE-2021-3449 (3), CVE-2024-14007 (2), CVE-2025-55182 (2), CVE-2006-2369 (1), CVE-2018-10562 CVE-2018-10561 (1)
- Missing inputs/errors: The 'url_path' field was explicitly noted as missing in the field presence check. Adbhoney honeypot showed no activity.

## 4) Emerging n-day Exploitation
- **CVE-2019-11500: Possible Dovecot Memory Corruption Inbound**
    - cve/signature mapping: CVE-2019-11500, ET EXPLOIT Possible Dovecot Memory Corruption Inbound (CVE-2019-11500)
    - evidence summary: 4 events. Source IPs include 85.217.149.25, 173.255.225.224, 104.237.144.61, 159.203.19.40.
    - affected service/port: IMAPS (993), SMTPS (995)
    - confidence: High
    - operational notes: Monitor traffic to ports 993 and 995 for indicators of this CVE.

- **CVE-2021-3449: Possible OpenSSL TLSv1.2 DoS Inbound**
    - cve/signature mapping: CVE-2021-3449, ET EXPLOIT Possible OpenSSL TLSv1.2 DoS Inbound (CVE-2021-3449)
    - evidence summary: 3 events. Source IPs include 45.33.65.100, 173.255.225.224, 104.237.144.61.
    - affected service/port: SMTPS (465), IMAPS (993), SMTPS (995)
    - confidence: High
    - operational notes: Monitor traffic to ports 465, 993, and 995 for indicators of this CVE.

## 5) Novel or Zero-Day Exploit Candidates
- No novel or zero-day exploit candidates were identified in this investigation window. All exploit-like behavior was mapped to known CVEs or signatures.

## 6) Botnet/Campaign Infrastructure Mapping
- **DigitalOcean and Cloud Provider Activity**
    - item_id or related candidate_id(s): Related to general "known attacker" and "mass scanner" activity.
    - campaign_shape: Spray/scanning
    - suspected_compromised_src_ips: Top IPs include 136.114.97.84 (ASN 14061 - DigitalOcean, LLC), 129.212.188.196 (ASN 14061 - DigitalOcean, LLC), 129.212.179.18 (ASN 14061 - DigitalOcean, LLC).
    - ASNs / geo hints: DigitalOcean, LLC (ASN 14061) - Predominantly United States.
    - suspected_staging indicators: None explicitly identified, but metrics requests like '/v1/metrics/droplet_id/553005910' from 167.71.255.16 (DigitalOcean) could indicate compromised infrastructure reporting to C2.
    - suspected_c2 indicators: See suspected staging indicators; further analysis needed to confirm C2 roles.
    - confidence: Medium (for staging/C2, high for scanning activity)
    - operational notes: Block known malicious IPs from DigitalOcean and other cloud providers. Investigate recurrent HTTP URLs from these IPs for C2 patterns.

## 7) Odd-Service / Minutia Attacks
- **VNC Server Traffic on Non-standard Ports**
    - service_fingerprint: VNC (various ports, e.g., 5902, 5903, 5905-5907, 5911-5913, 5925, 5926)
    - why it’s unusual/interesting: Detection of VNC server responses on non-standard ports (beyond typical 5900-590x range) indicates potential attempts to bypass security monitoring or target misconfigured services.
    - evidence summary: 2649 events (GPL INFO VNC server response), 244 events (ET SCAN MS Terminal Server Traffic on Non-standard Port), observed across various IPs and countries.
    - confidence: High
    - recommended monitoring pivots: Monitor VNC traffic on any port outside the standard range (5900-5910). Investigate source IPs involved in these scans for further malicious activity.

- **Conpot Kamstrup Protocol Interaction**
    - service_fingerprint: Kamstrup protocol (port not specified in output, but typically ICS-related)
    - why it’s unusual/interesting: Interaction with ICS/OT honeypots like Conpot using industrial protocols is notable, even with low volume. Kamstrup protocol is used in smart meters and utility systems.
    - evidence summary: 1 event with 'kamstrup_protocol'.
    - confidence: Medium (low volume, but high signal for ICS interest)
    - recommended monitoring pivots: Enhance monitoring for ICS protocol interactions, specifically Kamstrup, on relevant network segments.

## 8) Known-Exploit / Commodity Exclusions
- **Credential Noise**: Frequent attempts with common usernames like "wallet", "root", "sol", "admin" and blank/simple passwords like "" and "solana". (107 username events, 108 password events).
- **Scanning Activity**: Widespread scanning from "mass scanner" IPs (281 events), targeting various ports including MS Terminal Server on non-standard ports (244 events) and MySQL (67 events). General "Misc activity" (2759 events) and "Generic Protocol Command Decode" (999 events) likely include broad scanning.
- **Common Bot Patterns**: Activity from "known attacker" IPs (1224 events) and "Dshield Block Listed Source" (102 events) indicates interaction with commodity botnets.
- **Truncated Packets**: High counts of SURICATA IPv4 truncated packet (342 events) and SURICATA AF-PACKET truncated packet (342 events) likely indicate network anomalies or attempts to evade detection rather than specific exploits.

## 9) Infrastructure & Behavioral Classification
- **Exploitation vs Scanning**: Significant scanning activity (e.g., VNC, MS Terminal Server, MySQL ports), alongside targeted exploitation attempts for CVE-2019-11500 (Dovecot) and CVE-2021-3449 (OpenSSL DoS).
- **Campaign Shape**: Primarily spray-and-pray scanning from cloud provider IPs, with some targeted exploitation against specific vulnerable services.
- **Infra Reuse Indicators**: High volume from DigitalOcean ASNs suggests compromised hosts or attacker-controlled infrastructure within cloud environments.
- **Odd-Service Fingerprints**: VNC on non-standard ports, and a single instance of Kamstrup protocol interaction in Conpot.

## 10) Evidence Appendix
- **CVE-2019-11500: Possible Dovecot Memory Corruption Inbound**
    - source IPs with counts: 85.217.149.25 (1), 173.255.225.224 (1), 104.237.144.61 (1), 159.203.19.40 (1)
    - ASNs with counts: Missing from specific CVE aggregation, but source IPs are likely associated with DigitalOcean/other cloud providers based on overall ASN data.
    - target ports/services: 993 (IMAPS), 995 (SMTPS)
    - paths/endpoints: Not available in samples, but context implies email server interaction.
    - payload/artifact excerpts: `alert.signature: ET EXPLOIT Possible Dovecot Memory Corruption Inbound (CVE-2019-11500)`
    - staging indicators: unavailable
    - temporal checks: Within reported window

- **CVE-2021-3449: Possible OpenSSL TLSv1.2 DoS Inbound**
    - source IPs with counts: 45.33.65.100 (1), 173.255.225.224 (1), 104.237.144.61 (1)
    - ASNs with counts: Missing from specific CVE aggregation.
    - target ports/services: 465 (SMTPS), 993 (IMAPS), 995 (SMTPS)
    - paths/endpoints: Not available in samples.
    - payload/artifact excerpts: `alert.signature: ET EXPLOIT Possible OpenSSL TLSv1.2 DoS Inbound (CVE-2021-3449)`
    - staging indicators: unavailable
    - temporal checks: Within reported window

- **DigitalOcean and Cloud Provider Activity (Botnet/Campaign Infrastructure)**
    - source IPs with counts: 136.114.97.84 (324), 129.212.188.196 (263), 129.212.179.18 (262), 167.71.255.16 (5250)
    - ASNs with counts: DigitalOcean, LLC (ASN 14061, 1170), Google LLC (ASN 396982, 458)
    - target ports/services: Broad range due to scanning, including VNC (many ports), SSH, MySQL, various web services.
    - paths/endpoints: /v1/metrics/droplet_id/553005910, /, /static/wp-content/themes/twentyeleven/js/html5.js, /favicon.ico, /geoserver/web/, /login, /GponForm/diag_Form?images/
    - payload/artifact excerpts: No specific exploit payloads, mostly reconnaissance and login attempts.
    - staging indicators: '/v1/metrics/droplet_id/' seen from DigitalOcean IP 167.71.255.16 is a potential staging/C2 indicator.
    - temporal checks: Within reported window

## 11) Indicators of Interest
- **IPs**:
    - 136.114.97.84
    - 129.212.188.196
    - 129.212.179.18
    - 46.19.137.194
    - 77.83.39.212
    - 167.71.255.16 (associated with potential staging/C2 indicator)
    - 85.217.149.25 (CVE-2019-11500)
    - 173.255.225.224 (CVE-2019-11500, CVE-2021-3449)
    - 104.237.144.61 (CVE-2019-11500, CVE-2021-3449)
    - 159.203.19.40 (CVE-2019-11500)
    - 45.33.65.100 (CVE-2021-3449)
- **CVEs**:
    - CVE-2019-11500
    - CVE-2021-3449
- **URLs/Paths**:
    - /v1/metrics/droplet_id/553005910 (potential C2/staging)
    - /.env (Tanner honeypot)
    - /developmentserver/metadatauploader (Tanner honeypot)
    - /geoserver/web/ (Tanner honeypot)
    - /login
    - /GponForm/diag_Form?images/
- **Payload Fragments**:
    - "wallet", "root", "sol" (usernames)
    - "" (blank password)
    - "solana" (password)
- **Signatures**:
    - ET EXPLOIT Possible Dovecot Memory Corruption Inbound (CVE-2019-11500)
    - ET EXPLOIT Possible OpenSSL TLSv1.2 DoS Inbound (CVE-2021-3449)
    - GPL INFO VNC server response
    - ET SCAN MS Terminal Server Traffic on Non-standard Port
    - ET DROP Dshield Block Listed Source group 1
    - ET CINS Active Threat Intelligence Poor Reputation IP group 109

## 12) Backend Tool Issues
- `has_url_path` check returned 0, indicating this field was not populated. This weakened the ability to comprehensively analyze certain web-based attack paths.