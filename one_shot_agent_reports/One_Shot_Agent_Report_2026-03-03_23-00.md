# Investigation Report

## 1) Investigation Scope
- investigation_start: 2026-03-03T23:00:09Z
- investigation_end: 2026-03-04T00:00:09Z
- completion_status: Complete
- degraded_mode: false

## 2) Executive Triage Summary
- Total attacks observed: 7028.
- Top attacking countries are United States, Canada, and Ukraine.
- Significant "Misc activity" and "GPL INFO VNC server response" indicate widespread scanning and reconnaissance.
- Identified known attacker IPs (1113 counts) and mass scanner IPs (187 counts).
- Observed recent CVE exploitation (CVE-2024-14007) targeting Shenzhen TVT NVMS-9000.
- Honeypots captured common credential brute-force attempts with usernames like "user", "root", "admin" and passwords such as "password", "123456".
- Tanner honeypot detected reconnaissance for common web paths and PHP version files.
- Conpot honeypot observed ICS/SCADA-related protocols (Kamstrup Management Protocol, Guardian AST) and an HTTP request with a 'zgrab/0.x' user agent on a non-standard port (50100).
- Adbhoney honeypot captured a reconnaissance command to enumerate system properties (`echo "$(getprop ro.product.name 2>/dev/null) $(whoami 2>/dev/null)"`).

## 3) Candidate Discovery Summary
- Total attack events: 7028
- Top 5 attacking countries: United States (5437), Canada (282), Ukraine (228), Australia (201), Romania (160)
- Top 5 attacking source IPs: 207.174.0.19 (3716), 136.114.97.84 (329), 129.212.188.196 (266), 129.212.179.18 (264), 77.83.39.212 (224)
- Top 5 ASNs: Dynu Systems Incorporated (AS398019 - 3716), DigitalOcean, LLC (AS14061 - 1186), Google LLC (AS396982 - 471), Modat B.V. (AS209334 - 264), Kprohost LLC (AS214940 - 224)
- Top 5 alert categories: Misc activity (2790), Misc Attack (353), Attempted Information Leak (298), Generic Protocol Command Decode (289), Potentially Bad Traffic (15)
- Top 5 alert signatures: GPL INFO VNC server response (2661), ET SCAN MS Terminal Server Traffic on Non-standard Port (248), ET DROP Dshield Block Listed Source group 1 (71), SURICATA IPv4 truncated packet (52), SURICATA AF-PACKET truncated packet (52)
- Observed CVEs: CVE-2024-14007 (2), CVE-2002-0013 CVE-2002-0012 (1), CVE-2006-2369 (1), CVE-2019-11500 (1)
- Source IP reputations: known attacker (1113), mass scanner (187), bot, crawler (2)
- Top P0f OS distributions: Linux 2.2.x-3.x (18759), Windows NT kernel (15093), Windows 7 or 8 (3742)
- Top 5 common usernames: user (10), mysql (7), root (7), nexus (6), admin (5)
- Top 5 common passwords: password (3), 123456 (2), qwerty12345 (2), secret (2), " " (1)
- Top 5 Tanner URI's: / (23), /admin/views/phpversions.php (4), /assets/phpversions.php (4), /recordings/misc/phpversions.php (4), /_asterisk/phpversions.php (2)
- Redis actions: Closed (2), NewConnect (2), MGLNDD_134.199.242.175_6379 (1), info (1)
- Adbhoney inputs: echo "$(getprop ro.product.name 2>/dev/null) $(whoami 2>/dev/null)" (1)
- Adbhoney malware samples: None
- Conpot inputs: GET / HTTP/1.1... (1)
- Conpot protocols: kamstrup_management_protocol (3), guardian_ast (1)
- Key investigative fields present: alert_cve_id (5), alert_signature (3757), http_url (570), src_ip (296774). Missing url_path.

## 4) Emerging n-day Exploitation
- **CVE-2024-14007: Shenzhen TVT NVMS-9000 Information Disclosure Attempt**
  - cve/signature mapping: ET WEB_SPECIFIC_APPS Shenzhen TVT NVMS-9000 Information Disclosure Attempt (CVE-2024-14007)
  - evidence summary: 2 events, targeting dest_ports 6037 and 17000.
  - affected service/port: Network Video Management System (NVMS), ports 6037, 17000.
  - confidence: High
  - operational notes: Monitor for further exploitation attempts against NVMS-9000 instances.
- **CVE-2019-11500**
  - cve/signature mapping: Mentioned in alert.
  - evidence summary: 1 event.
  - affected service/port: Unknown from current data.
  - confidence: Medium (due to limited context)
  - operational notes: Further investigation required to determine specific attack vector and target.
- **CVE-2002-0013 CVE-2002-0012**
  - cve/signature mapping: Mentioned in alert.
  - evidence summary: 1 event.
  - affected service/port: Unknown from current data.
  - confidence: Medium (due to limited context)
  - operational notes: Legacy CVEs, potentially opportunistic scanning.
- **CVE-2006-2369**
  - cve/signature mapping: Mentioned in alert.
  - evidence summary: 1 event.
  - affected service/port: Unknown from current data.
  - confidence: Medium (due to limited context)
  - operational notes: Legacy CVE, potentially opportunistic scanning.

## 5) Novel or Zero-Day Exploit Candidates
None identified.

## 6) Botnet/Campaign Infrastructure Mapping
- **item_id**: 1
  - campaign_shape: Unknown (likely spray)
  - suspected_compromised_src_ips: 207.174.0.19 (3716 counts), 136.114.97.84 (329 counts), 129.212.188.196 (266 counts)
  - ASNs / geo hints: Dynu Systems Incorporated (AS398019 - United States), DigitalOcean, LLC (AS14061 - United States), Google LLC (AS396982 - 471), Modat B.V. (AS209334 - Netherlands), Kprohost LLC (AS214940 - 224)
  - suspected_staging indicators: None explicitly identified, but these IPs are highly active.
  - suspected_c2 indicators: None explicitly identified, but the high volume and reputation suggest potential botnet activity.
  - confidence: Medium
  - operational notes: Monitor these IPs for sustained activity and attempt to identify common attack patterns or payloads. The concentration of activity from Dynu Systems Incorporated and DigitalOcean suggests potential compromised infrastructure or bulletproof hosting.

## 7) Odd-Service / Minutia Attacks
- **service_fingerprint**: `MS Terminal Server Traffic on Non-standard Port` (Signature ID 2023753)
  - why it’s unusual/interesting: RDP/Terminal Services typically runs on port 3389. Activity on non-standard ports often indicates evasion attempts or scanning for misconfigured services.
  - evidence summary: 248 events.
  - confidence: High
  - recommended monitoring pivots: Monitor for RDP/Terminal Server connections on unusual ports, especially those from external IPs.
- **service_fingerprint**: `Conpot honeypot with Kamstrup Management Protocol and Guardian AST`
  - why it’s unusual/interesting: These are Industrial Control System (ICS) / Operational Technology (OT) protocols, indicating targeting of critical infrastructure or specialized embedded systems.
  - evidence summary: 3 events for kamstrup_management_protocol, 1 event for guardian_ast.
  - confidence: High
  - recommended monitoring pivots: Prioritize monitoring of ICS/OT network segments for activity related to these protocols. Investigate source IPs targeting these services for intent and origin.
- **service_fingerprint**: `HTTP request with zgrab/0.x user agent on port 50100`
  - why it’s unusual/interesting: `zgrab` is a fast, modular application-layer scanner. Targeting port 50100 (non-standard for HTTP) suggests reconnaissance for specific web services or applications potentially running on unusual ports.
  - evidence summary: 1 event captured by Conpot honeypot.
  - confidence: Medium
  - recommended monitoring pivots: Correlate `zgrab` activity with other scanning attempts. Investigate services running on non-standard HTTP ports.

## 8) Known-Exploit / Commodity Exclusions
- **Brute Force/Credential Noise**:
  - `user`, `root`, `admin`, `mysql`, `nexus` (10, 7, 7, 6, 5 counts respectively) as usernames.
  - `password`, `123456`, `qwerty12345`, `secret` (3, 2, 2, 2 counts respectively) as passwords. Seen across multiple honeypots.
- **Common Scanners/Reconnaissance**:
  - "Misc activity" (2790 counts) and "Generic Protocol Command Decode" (289 counts) categories indicate general scanning.
  - "GPL INFO VNC server response" (2661 counts) suggests widespread VNC scanning.
  - "ET SCAN NMAP -sS window 1024" (35 counts) indicates Nmap scanning.
  - Activity from IPs with "mass scanner" reputation (187 counts).
  - Tanner honeypot requests for `/admin/views/phpversions.php`, `/assets/phpversions.php`, `/recordings/misc/phpversions.php` (4 counts each) and `/` (23 counts) are common web reconnaissance paths.
  - Redis actions like "NewConnect" and "Closed" are generic connection attempts (2 counts each).
- **Known Commodity Bot Patterns**:
  - "ET DROP Dshield Block Listed Source group 1" (71 counts) and "ET CINS Active Threat Intelligence Poor Reputation IP group 109" (34 counts) indicate activity from known malicious IPs.
  - IPs with "known attacker" (1113 counts) and "bot, crawler" (2 counts) reputation.

## 9) Infrastructure & Behavioral Classification
- **Exploitation vs Scanning**: Predominantly scanning and reconnaissance activity observed, with a few instances of specific CVE exploitation (CVE-2024-14007). Brute-forcing attempts also present.
- **Campaign Shape**: Likely spray-and-pray scanning campaigns given the high volume of "Misc activity" and broad signature matches. Some concentration from specific ASNs suggests potential botnet or compromised infrastructure.
- **Infra Reuse Indicators**: High counts from certain ASNs (Dynu Systems, DigitalOcean) and consistent appearance of known attacker/mass scanner IPs point to potential reuse of compromised or dedicated malicious infrastructure.
- **Odd-Service Fingerprints**: ICS/OT protocols (Kamstrup, Guardian AST) and non-standard RDP/HTTP ports are distinct odd-service fingerprints.

## 10) Evidence Appendix
- **CVE-2024-14007**
  - source IPs with counts: 46.151.178.13 (1), 89.42.231.179 (1)
  - ASNs with counts: Missing (not directly aggregated, but can be derived from IP lookups)
  - target ports/services: 6037, 17000
  - paths/endpoints: Not available from Suricata alert.
  - payload/artifact excerpts: `ET WEB_SPECIFIC_APPS Shenzhen TVT NVMS-9000 Information Disclosure Attempt (CVE-2024-14007)`
  - staging indicators: unavailable
  - temporal checks results: Events observed at 2026-03-03T23:43:55Z and 2026-03-03T23:35:53Z within the investigation window.
- **Botnet/Campaign - AS398019 (Dynu Systems Incorporated)**
  - source IPs with counts: 207.174.0.19 (3716)
  - ASNs with counts: AS398019 (Dynu Systems Incorporated, 3716)
  - target ports/services: Broad range (VNC, MS Terminal Server, various honeypots imply diverse targets)
  - paths/endpoints: Varied, including `/` for Tanner honeypot.
  - payload/artifact excerpts: Not directly available for the entire ASN, but associated with "GPL INFO VNC server response".
  - staging indicators: unavailable
  - temporal checks results: Activity seen consistently throughout the window.

## 11) Indicators of Interest
- **IPs**:
  - 207.174.0.19 (High volume, AS398019 - Dynu Systems Incorporated, associated with VNC scanning)
  - 136.114.97.84 (High volume, AS14061 - DigitalOcean, LLC)
  - 129.212.188.196 (High volume)
  - 46.151.178.13 (Source for CVE-2024-14007)
  - 89.42.231.179 (Source for CVE-2024-14007)
- **CVEs**:
  - CVE-2024-14007
- **Alert Signatures**:
  - `GPL INFO VNC server response` (Signature ID 2100560)
  - `ET SCAN MS Terminal Server Traffic on Non-standard Port` (Signature ID 2023753)
  - `ET DROP Dshield Block Listed Source group 1` (Signature ID 2402000)
- **Honeypot Artifacts**:
  - Tanner paths: `/admin/views/phpversions.php`, `/assets/phpversions.php`, `/recordings/misc/phpversions.php`
  - Adbhoney input: `echo "$(getprop ro.product.name 2>/dev/null) $(whoami 2>/dev/null)"`
  - Conpot protocols: `kamstrup_management_protocol`, `guardian_ast`
  - Conpot user agent: `zgrab/0.x`
  - Usernames: `user`, `root`, `admin`
  - Passwords: `password`, `123456`

## 12) Backend Tool Issues
No tool failures or material issues observed during the investigation.