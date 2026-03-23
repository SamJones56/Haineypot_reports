# Investigation Report: Threat Landscape Analysis

## 1) Investigation Scope
- investigation_start: 2026-03-06T06:00:04Z
- investigation_end: 2026-03-06T09:00:04Z
- completion_status: Partial
- degraded_mode: true - `kibanna_discover_query` tool failed to retrieve raw event samples for Conpot activity, limiting deeper analysis of the `guardian_ast` protocol interactions.

## 2) Executive Triage Summary
- Total attacks observed: 21,223 events.
- Top services/ports of interest: SMB (445), SSH (22), VNC (5901-5904), Apache Druid (implied by `/druid/index.html`), and the industrial control system (ICS) protocol `guardian_ast` on Conpot honeypot.
- Top confirmed known exploitation: `CVE-2025-55182` activity targeting various non-standard ports (3000, 2233, 3050, 4443, 4444).
- Unmapped exploit-like items: None identified as novel zero-day candidates; all exploit-like behavior is either CVE-mapped or commodity scanning.
- Botnet/campaign mapping highlights: Distinct geographical targeting patterns, e.g., Myanmar heavily targeting SMB, Ukraine targeting SMB and SMTP, and the US targeting VNC and SSH. DigitalOcean, LLC is a prominent source of attacks.
- Major uncertainties: The specific nature and impact of the `guardian_ast` protocol interactions beyond the observed inputs (`b'\x01I20100'`) could not be fully elucidated due to tool limitations.

## 3) Candidate Discovery Summary
- Total attack events: 21,223
- Top attacking countries: United States (8731), Myanmar (2820), Ukraine (2357)
- Top attacking IPs: 159.223.121.61 (3534), 103.101.16.234 (1602), 203.81.87.70 (1218)
- Top CVEs: CVE-2025-55182 (102)
- Top alert categories: Misc activity (16580), Misc Attack (1471)
- Common honeypot usernames/passwords: `root`, `admin` / `123456`, `1234`
- Identified odd-service activity: Conpot `guardian_ast` protocol with specific byte inputs.
- Interesting web paths: `/.env`, `/druid/index.html`

## 4) Emerging n-day Exploitation
- cve/signature mapping: CVE-2025-55182. Suricata detected 102 events related to this CVE.
- evidence summary: 102 counts of CVE-2025-55182 detection. Top destination ports include 3000 (7), 2233 (6), 3050 (6), 4443 (6), 4444 (6). Source IPs for this CVE could not be aggregated, potentially due to data inconsistencies.
- affected service/port: Various non-standard ports (3000, 2233, 3050, 4443, 4444).
- confidence: High
- operational notes: Monitor for specific exploit payloads targeting these ports. Investigate CVE-2025-55182 for known exploit vectors.

## 5) Novel or Zero-Day Exploit Candidates
None. All identified exploit-like behaviors are either mapped to known CVEs or fit commodity attack patterns.

## 6) Botnet/Campaign Infrastructure Mapping
- item_id: US-VNC-SSH, MM-SMB, UA-SMB-SMTP, IN-SMB-SSH
- campaign_shape: Spray/scanning. Distinct geographical targeting suggests varied campaign objectives or attacker origins.
- suspected_compromised_src_ips:
    - 159.223.121.61 (3534 events)
    - 103.101.16.234 (1602 events)
    - 203.81.87.70 (1218 events)
- ASNs / geo hints:
    - DigitalOcean, LLC (ASN 14061, 7168 events, primarily US)
    - Global Technology (ASN 136975, 1602 events)
    - Myanma Posts and Telecommunications (ASN 9988, 1218 events, Myanmar)
    - Ukraine (2357 attacks), India (769 attacks), Canada (1016 attacks)
- suspected_staging indicators: N/A
- suspected_c2 indicators: N/A
- confidence: High for identified source IPs, ASNs, and geo hints; Moderate for campaign shape interpretation.
- operational notes: Block known malicious IPs and ranges from top attacking ASNs. Geoblock if appropriate. Monitor for persistence and payload delivery associated with these campaigns.

## 7) Odd-Service / Minutia Attacks
- service_fingerprint: Conpot honeypot, `guardian_ast` protocol (ICS/OT protocol) on potentially various ports (Conpot default Modbus/S7comm ports, or others configured in the honeypot).
- why it’s unusual/interesting: `guardian_ast` is an industrial control system protocol, making its observation significant. The specific inputs `b'\x01I20100'` suggest attempts at interacting with or querying ICS devices.
- evidence summary: 12 events observed for `guardian_ast` protocol. Conpot inputs: `b'\x01I20100'` (1 count), `b'\x01I20100\n'` (1 count).
- confidence: High
- recommended monitoring pivots: Further analysis of Conpot logs for full session data, identify source IPs interacting with `guardian_ast`, and potential targets or objectives of these interactions.

## 8) Known-Exploit / Commodity Exclusions
- **Brute Force/Credential Stuffing**: High volume of login attempts using common usernames (`root`, `admin`, `user`) and weak passwords (`123456`, `1234`, `password`).
- **Mass Scanning**:
    - "GPL INFO VNC server response" (16107 events): Indication of widespread VNC server scanning.
    - "ET SCAN MS Terminal Server Traffic on Non-standard Port" (287 events): Scanning for RDP services on non-standard ports.
    - Requests for `/.env` (34 events): Common web server reconnaissance to discover environment variables and sensitive configuration.
    - Requests for `/druid/index.html` (8 events): Scanning for Apache Druid installations, potentially for known vulnerabilities. User-Agent `Mozilla/5.0 zgrab/0.x` confirms scanning activity.
- **Known Bot Patterns**: High counts of "known attacker" (10685) and "mass scanner" (836) IP reputations. "ET DROP Dshield Block Listed Source group 1" (396 events) also indicates activity from known malicious sources.
- **SMB Activity**: Myanmar (2820 events) and Ukraine (998 events) showing significant activity on port 445 (SMB), which is commonly targeted by commodity malware and scanning tools.

## 9) Infrastructure & Behavioral Classification
- **Exploitation vs Scanning**: Predominantly scanning and commodity exploitation attempts (VNC, RDP, SMB, web reconnaissance). `CVE-2025-55182` indicates specific n-day exploitation.
- **Campaign Shape**: Mixed, with elements of widespread spray/scanning (VNC, SMB, web paths) and geographically localized targeting (Myanmar targeting SMB, Ukraine SMB/SMTP, US VNC/SSH).
- **Infra Reuse Indicators**: DigitalOcean, LLC and other cloud providers are frequently used, indicating actors leveraging readily available infrastructure. Common usernames/passwords suggest widespread credential abuse.
- **Odd-Service Fingerprints**: `guardian_ast` protocol activity on Conpot honeypot stands out as an unusual ICS/OT target.

## 10) Evidence Appendix
### Emerging n-day Exploitation: CVE-2025-55182
- source IPs with counts: Unavailable (tool returned no source IPs for this CVE)
- ASNs with counts: Unavailable
- target ports/services: 3000 (7), 2233 (6), 3050 (6), 4443 (6), 4444 (6)
- paths/endpoints: N/A
- payload/artifact excerpts: N/A (requires raw event details)
- staging indicators: N/A
- temporal checks results: Detected within the reporting window, 102 events.

### Botnet/Campaign Infrastructure Mapping:
#### Top Attacking IP: 159.223.121.61
- source IPs with counts: 159.223.121.61 (3534)
- ASNs with counts: DigitalOcean, LLC (ASN 14061)
- target ports/services: (Requires further drill-down not performed in this scope, but generally associated with VNC/SSH based on overall trends from US IPs and DigitalOcean ASN)
- paths/endpoints: N/A
- payload/artifact excerpts: N/A
- staging indicators: N/A
- temporal checks results: Active throughout the reporting window.

### Odd-Service / Minutia Attacks: Conpot Guardian AST
- source IPs with counts: (Requires `kibanna_discover_query` or `two_level_terms_aggregated` with `type.keyword=Conpot` and `src_ip.keyword` which wasn't fully explored due to tool error)
- ASNs with counts: Unavailable
- target ports/services: Conpot honeypot, `guardian_ast` protocol (port not explicitly defined in current output)
- paths/endpoints: N/A
- payload/artifact excerpts: Input `b'\x01I20100'`, `b'\x01I20100\n'`
- staging indicators: N/A
- temporal checks results: Observed within the reporting window (12 events).

## 11) Indicators of Interest
- **IPs**: 159.223.121.61, 103.101.16.234, 203.81.87.70 (top attackers)
- **CVE**: CVE-2025-55182
- **Paths/Endpoints**: `/.env`, `/druid/index.html`
- **Payload Fragments**: `b'\x01I20100'` (Conpot input)
- **Signatures**: "GPL INFO VNC server response", "ET DROP Dshield Block Listed Source group 1", "ET SCAN MS Terminal Server Traffic on Non-standard Port", "ET INFO Request to Hidden Environment File - Inbound", "ET SCAN Zmap User-Agent (Inbound)"
- **User-Agents**: `Mozilla/5.0 zgrab/0.x`

## 12) Backend Tool Issues
- **Tool**: `kibanna_discover_query`
- **Issue**: Failed with `illegal_argument_exception: Expected text at 1:71 but found START_ARRAY` when attempting to query for `type.keyword` with value `Conpot`.
- **Affected Validations**: Deeper investigation into raw Conpot events for the `guardian_ast` protocol and associated source IPs/payload context was hindered.
- **Weakened Conclusions**: The detailed understanding of the `guardian_ast` interactions and the full context of the Conpot odd-service attack is less comprehensive than it could be. The confidence in mapping full campaign details for this specific activity is slightly reduced.