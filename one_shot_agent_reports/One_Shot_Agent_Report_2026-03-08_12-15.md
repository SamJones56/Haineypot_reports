# Investigation Report

## 1) Investigation Scope
- investigation_start: 2026-03-08T12:00:05Z
- investigation_end: 2026-03-08T15:00:05Z
- completion_status: Complete
- degraded_mode: false

## 2) Executive Triage Summary
- Top services/ports of interest include VNC (implied by signature), SMB (port 445), HTTP (port 80), SSH (port 22), Telnet (port 23), and VNC-related ports (5902, 5903, 5904).
- Confirmed known exploitation for CVE-2025-55182, CVE-2024-14007, CVE-2021-3449, CVE-2019-11500, and CVE-2024-38816.
- A significant portion of attacks are categorized as "Misc activity" and "Generic Protocol Command Decode," indicating a mix of scanning and potentially automated activities.
- High volume of "known attacker" source IPs, suggesting active malicious campaigns.
- Honeypot interactions show attempts to enumerate system information and common credential brute-force attempts.

## 3) Candidate Discovery Summary
- Total attacks observed: 19429
- Top attacking countries: United States, France, Mexico, India, United Kingdom.
- Top attacker source IPs are dominated by a few IPs with high counts.
- CVEs are present, with CVE-2025-55182 having a significantly higher count.
- Suricata alerts are mostly related to VNC server responses and IPv4/AF-PACKET truncated packets.
- Honeypot data indicates common username/password brute-forcing and some command execution attempts.
- No Adbhoney malware samples or Conpot input/protocol data were found.
- The field presence check shows a high presence of source IP and alert signatures, but no `url_path` field.

## 4) Emerging n-day Exploitation
- **cve/signature mapping**: CVE-2025-55182
    - **evidence summary**: 137 instances of CVE-2025-55182.
    - **affected service/port**: Not explicitly specified, but likely associated with services targeted by the CVE.
    - **confidence**: High
    - **operational notes**: Monitor for specific indicators related to CVE-2025-55182.
- **cve/signature mapping**: CVE-2024-14007
    - **evidence summary**: 8 instances of CVE-2024-14007.
    - **affected service/port**: Not explicitly specified.
    - **confidence**: High
    - **operational notes**: Investigate further for context.
- **cve/signature mapping**: CVE-2021-3449
    - **evidence summary**: 6 instances of CVE-2021-3449.
    - **affected service/port**: Not explicitly specified.
    - **confidence**: High
    - **operational notes**: Investigate further for context.
- **cve/signature mapping**: CVE-2019-11500
    - **evidence summary**: 4 instances of CVE-2019-11500.
    - **affected service/port**: Not explicitly specified.
    - **confidence**: High
    - **operational notes**: Investigate further for context.
- **cve/signature mapping**: CVE-2024-38816
    - **evidence summary**: 3 instances of CVE-2024-38816.
    - **affected service/port**: Not explicitly specified.
    - **confidence**: High
    - **operational notes**: Investigate further for context.

## 5) Novel or Zero-Day Exploit Candidates
- No strong evidence for novel or zero-day exploit candidates was found during this investigation.

## 6) Botnet/Campaign Infrastructure Mapping
- **item_id**: Botnet/Scanning Activity
    - **campaign_shape**: Spray (indicated by broad scanning across many IPs and ports)
    - **suspected_compromised_src_ips**: 79.98.102.166 (2572), 189.231.160.65 (1512), 185.177.72.30 (1032)
    - **ASNs / geo hints**: DigitalOcean, LLC (ASN 14061, United States), ADISTA SAS (ASN 16347, France), UNINET (ASN 8151, Mexico)
    - **suspected_staging indicators**: No clear staging indicators identified.
    - **suspected_c2 indicators**: No clear C2 indicators identified.
    - **confidence**: Medium (based on high volume of attacks from specific IPs/ASNs with known attacker reputation)
    - **operational notes**: Block identified malicious IPs and monitor traffic from associated ASNs.

## 7) Odd-Service / Minutia Attacks
- **service_fingerprint**: Port 37777 (France)
    - **why it’s unusual/interesting**: This port is not commonly associated with standard services and could indicate a custom application or a less common protocol.
    - **evidence summary**: 25 attacks targeting port 37777 from France.
    - **confidence**: Medium
    - **recommended monitoring pivots**: Deep packet inspection for port 37777, correlation with other attack vectors from France.

## 8) Known-Exploit / Commodity Exclusions
- **Brute Force/Credential Noise**:
    - Usernames: "root", "admin", "ubuntu", "test", "centos" (counts: 175, 87, 68, 48, 36 respectively)
    - Passwords: "123456", "password", "12345678", "1234", "12345" (counts: 54, 44, 42, 37, 36 respectively)
    - This indicates widespread automated brute-force attempts against various services.
- **Common Scanners**:
    - High number of "Misc activity" alerts (19430) and "Generic Protocol Command Decode" (5235) likely points to scanning activity.
    - "mass scanner" reputation for 342 source IPs.
- **Known Bot Patterns**:
    - "known attacker" reputation for 10886 source IPs.
    - "bot, crawler" reputation for 14 source IPs.
    - The presence of the "GPL INFO VNC server response" signature (18948 counts) suggests automated reconnaissance or exploitation targeting VNC services.
    - Tanner honeypot hits for common configuration files like `/.env`, `/.aws/credentials`, `/.aws/config`, `/.env.backup` are indicative of automated vulnerability scanning.

## 9) Infrastructure & Behavioral Classification
- **Exploitation vs Scanning**: The activity is a mix of widespread scanning (many "Misc activity" alerts, common credential brute-forcing, and `.env` file checks) and targeted exploitation (specific CVEs identified).
- **Campaign Shape**: Predominantly spray-and-pray scanning across various IPs, with some evidence of more focused attacks on specific ports (e.g., SMB, VNC).
- **Infra Reuse Indicators**: The same source IPs often contribute to multiple attack categories and honeypot hits, suggesting infrastructure reuse. ASNs like DigitalOcean and Google LLC are frequently observed, which are known to host both legitimate and malicious traffic.
- **Odd-Service Fingerprints**: Port 37777 in France stands out as an unusual target.

## 10) Evidence Appendix
- **Emerging n-day Exploitation (CVE-2025-55182)**:
    - **Source IPs with counts**: Not explicitly broken down per CVE by the tool, but overall top IPs are 79.98.102.166, 189.231.160.65, 185.177.72.30.
    - **ASNs with counts**: Not explicitly broken down per CVE, but top ASNs are DigitalOcean, ADISTA SAS, UNINET.
    - **Target ports/services**: Not explicitly specified for the CVE.
    - **Paths/endpoints**: Not explicitly specified.
    - **Payload/artifact excerpts**: Not explicitly provided by the tool.
    - **Staging indicators**: None identified.
    - **Temporal checks results**: Occurred within the investigation window.
- **Botnet/Campaign Infrastructure Mapping (General)**:
    - **Source IPs with counts**: 79.98.102.166 (2572), 189.231.160.65 (1512), 185.177.72.30 (1032), 136.114.97.84 (772), 165.232.181.62 (521)
    - **ASNs with counts**: DigitalOcean, LLC (14061, 5173), ADISTA SAS (16347, 2572), UNINET (8151, 1821), Google LLC (396982, 1548), Bucklog SARL (211590, 1463)
    - **Target ports/services**: 445 (SMB), 80 (HTTP), 5902, 5903, 5904 (VNC), 22 (SSH), 23 (Telnet), 37777 (unusual)
    - **Paths/endpoints**: / (75), /.env (8), /.aws/credentials (4), /.aws/config (3), /.env.backup (3) from Tanner honeypot.
    - **Payload/artifact excerpts**: "echo hello" and "echo \"$(getprop ro.product.name 2>/dev/null) $(whoami 2>/dev/null)\"" from Adbhoney.
    - **Staging indicators**: None explicitly identified.
    - **Temporal checks results**: Occurred within the investigation window.

## 11) Indicators of Interest
- **IPs**: 79.98.102.166, 189.231.160.65, 185.177.72.30, 136.114.97.84, 165.232.181.62
- **CVEs**: CVE-2025-55182, CVE-2024-14007, CVE-2021-3449, CVE-2019-11500, CVE-2024-38816
- **Paths**: `/.env`, `/.aws/credentials`, `/.aws/config`, `/.env.backup`
- **Keywords/Commands**: "echo hello", "echo \"$(getprop ro.product.name 2>/dev/null) $(whoami 2>/dev/null)\""
- **Unusual Port**: 37777

## 12) Backend Tool Issues
- No backend tool failures were encountered during this investigation. All tool calls returned valid responses.