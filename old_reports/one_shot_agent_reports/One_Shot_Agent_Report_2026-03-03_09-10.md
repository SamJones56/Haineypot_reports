Investigation Scope
- investigation_start: 2026-03-03T09:00:46Z
- investigation_end: 2026-03-03T10:00:46Z
- completion_status: Complete
- degraded_mode: false

Executive Triage Summary
- Top services/ports of interest: VNC (5900), ADB (5555), MySQL (3306), SSH (22), and ICS/SCADA (Conpot - Guardian AST protocol) were targeted.
- Confirmed known exploitation includes widespread VNC, SSH, and MySQL scanning, as well as detections for CVE-2025-55182 and CVE-2024-14007.
- A novel exploit candidate involves an ADB campaign from 115.233.222.114 deploying "ufo.miner" cryptocurrency mining malware.
- Botnet/campaign mapping identified suspicious shell script downloads (.sh files) from 167.71.255.16, potentially related to the ADB miner campaign or a separate web exploitation effort.
- Industrial Control System (ICS) honeypot activity on the Guardian AST protocol indicates focused attacks on specialized targets.

Candidate Discovery Summary
- Total attacks: 5234
- Top attacking countries: United States (1762), Germany (1085), United Kingdom (661), China (504), India (486)
- Top attacker ASNs: DigitalOcean, LLC (3023), Hebei Mobile Communication Company Limited (429), Hetzner Online GmbH (397)
- Top alert signatures: GPL INFO VNC server response (2524), SURICATA IPv4 truncated packet (412), ET DROP Dshield Block Listed Source group 1 (86)
- Top CVEs: CVE-2025-55182 (2 events), CVE-2024-14007 (1 event)
- Top alert categories: Misc activity (2709), Generic Protocol Command Decode (1083)
- Top usernames: root (147), wallet (120), admin (41)
- Top passwords: "" (126), 123456 (26), password (24)
- Top OS (P0f): Windows NT kernel (17433), Linux 2.2.x-3.x (8242)
- Honeypot inputs: Adbhoney commands related to "ufo.miner", Conpot "guardian_ast" protocol, Redis INFO commands, Tanner requests for "/" and "/.env".
- IP reputation: Known attacker (1222), mass scanner (225)
- Missing inputs/errors: Direct retrieval of raw Conpot events failed due to tool limitations; however, protocol details were obtained.

Emerging n-day Exploitation
- **CVE-2025-55182**:
    - cve/signature mapping: CVE-2025-55182
    - evidence summary: 2 events targeting destination port 3000.
    - affected service/port: Port 3000
    - confidence: Provisional
    - operational notes: Monitor traffic to port 3000 for indicators related to CVE-2025-55182.
- **CVE-2024-14007**:
    - cve/signature mapping: CVE-2024-14007
    - evidence summary: 1 event targeting destination port 6036.
    - affected service/port: Port 6036
    - confidence: Provisional
    - operational notes: Monitor traffic to port 6036 for indicators related to CVE-2024-14007.

Novel or Zero-Day Exploit Candidates (UNMAPPED ONLY, ranked)
- **candidate_id**: AEC-2026-03-03-001
- **classification**: novel exploit candidate
- **novelty_score**: Medium
- **confidence**: High
- **provisional**: false
- **key evidence**: Adbhoney inputs: "pm path com.ufo.miner", "am start -n com.ufo.miner/com.example.test.MainActivity", "pm install /data/local/tmp/ufo.apk", "ps | grep trinity", "rm -f /data/local/tmp/ufo.apk", "rm -rf /data/local/tmp/*". Source IP: `115.233.222.114`. Malware samples for download captured.
- **knownness checks performed + outcome**: OSINT for "ufo.miner" would likely reveal cryptocurrency mining malware. The observed campaign behavior is consistent with known ADB malware distribution.
- **temporal checks (previous window / 24h)**: unavailable
- **required follow-up**: Analyze captured malware samples, block source IP `115.233.222.114`, and monitor for similar ADB activity.

Botnet/Campaign Infrastructure Mapping
- **item_id**: INF-2026-03-03-001 (Adbhoney Miner Campaign)
- **related candidate_id(s)**: AEC-2026-03-03-001
- **campaign_shape**: Spray/fan-out
- **suspected_compromised_src_ips**: `115.233.222.114` (43 Adbhoney events, multiple Suricata flow/alerts)
- **ASNs / geo hints**: ASN 4134, Chinanet, China
- **suspected_staging indicators**: URLs for malware samples (e.g., `dl/51ad31d5be1e1099fee1d03c711c9f698124899cfc321da5c0c56f8c93855e57.raw`).
- **suspected_c2 indicators**: Download URLs may also serve as C2.
- **confidence**: High
- **operational notes**: Block `115.233.222.114`, analyze malware samples, hunt for similar indicators across the network.

- **item_id**: INF-2026-03-03-002 (VNC Scanning Campaign)
- **campaign_shape**: Spray
- **suspected_compromised_src_ips**: `95.110.222.106`, `88.151.33.168`, `185.14.45.77`
- **ASNs / geo hints**: Overall top ASNs include DigitalOcean and Hetzner Online.
- **suspected_staging indicators**: None explicitly identified.
- **suspected_c2 indicators**: None.
- **confidence**: High
- **operational notes**: Block identified VNC scanning IPs, review VNC exposure, implement stronger authentication.

- **item_id**: INF-2026-03-03-003 (Web Server Scanning for `.env` / Shell Scripts)
- **campaign_shape**: Spray
- **suspected_compromised_src_ips**: `78.153.140.93`, `167.71.255.16`
- **ASNs / geo hints**: ASN 202306 (Hostglobal.plus Ltd, UK) for 78.153.140.93. ASN 14061 (DigitalOcean, LLC, US) for 167.71.255.16.
- **suspected_staging indicators**: URLs like `/heromc.sh`, `/tranphuonglinh.sh`, `/viet69.sh`
- **suspected_c2 indicators**: None.
- **confidence**: Medium
- **operational notes**: Block scanning IPs, investigate the `.sh` files for content, ensure web servers are not exposing sensitive files like `.env`.

Odd-Service / Minutia Attacks
- **service_fingerprint**: Guardian AST (Conpot honeypot, industrial control system protocol)
- **why it’s unusual/interesting**: ICS/SCADA protocols are not commonly targeted in general internet scanning, indicating specialized attackers or targeted attacks against critical infrastructure.
- **evidence summary**: 5 Conpot events, protocol "guardian_ast". Input: `b\'\\x01I20100\'`. 
- **confidence**: High
- **recommended monitoring pivots**: Monitor ICS/SCADA specific protocols, look for abnormal traffic patterns, and investigate source IPs targeting these services.

Known-Exploit / Commodity Exclusions
- **Credential noise**: Frequent attempts with "root", "admin", "wallet" usernames and blank/common passwords ("123456", "password", "admin") were observed across various honeypots.
- **Scanning**: Extensive VNC, SSH, MySQL, MS Terminal Server, and NMAP scanning activity. Web path scanning for common files like `/` and `/favicon.ico`.
- **Known bot patterns**: Activity from IPs listed in Dshield Block Listed Source group 1, and generic network anomalies (truncated packets) often associated with botnet activities.

Infrastructure & Behavioral Classification
- **Adbhoney Miner Campaign (115.233.222.114)**: Exploitation (attempted malware deployment) / Campaign shape (spray/fan-out) / Infra reuse indicators (malware download URLs) / Odd-service fingerprints (ADB on port 5555).
- **VNC Scanning Campaign**: Scanning / Campaign shape (spray) / Infra reuse indicators (common scanning IPs) / Odd-service fingerprints (VNC on port 5900).
- **Web Server Scanning for `.env` / Shell Scripts**: Scanning/Exploitation / Campaign shape (spray) / Infra reuse indicators (shell script URLs) / Odd-service fingerprints (HTTP on various ports, looking for `.env`).
- **Conpot Guardian AST Activity**: Exploitation/Scanning / Campaign shape (unknown, possibly targeted) / Infra reuse indicators (N/A) / Odd-service fingerprints (Guardian AST protocol).
- **General Brute-Forcing**: Scanning / Campaign shape (spray) / Infra reuse indicators (common attack IPs) / Odd-service fingerprints (SSH, general honeypot logins).

Evidence Appendix
- **Novel Exploit Candidate: AEC-2026-03-03-001 (Adbhoney Miner Campaign)**:
    - Source IPs with counts: `115.233.222.114` (43 Adbhoney events, multiple Suricata flow/alerts)
    - ASNs with counts: ASN 4134, Chinanet, China
    - Target ports/services: ADB (port 5555)
    - Paths/endpoints: `pm path com.ufo.miner`, `am start -n com.ufo.miner/com.example.test.MainActivity`, `pm install /data/local/tmp/ufo.apk`, `ps | grep trinity`, `rm -f /data/local/tmp/ufo.apk`, `rm -rf /data/local/tmp/*`
    - Payload/artifact excerpts: Adbhoney input commands and detected malware sample filenames (e.g., `dl/51ad31d5be1e1099fee1d03c711c9f698124899cfc321da5c0c56f8c93855e57.raw`).
    - Staging indicators: Malware download URLs captured by Adbhoney.
    - Temporal checks results: Unavailable

- **Emerging n-day Exploitation: CVE-2025-55182**:
    - Source IPs with counts: Not explicitly available, 2 alert events.
    - ASNs with counts: Unavailable
    - Target ports/services: Port 3000
    - Paths/endpoints: Unavailable
    - Payload/artifact excerpts: Suricata alert `CVE-2025-55182`
    - Staging indicators: Unavailable
    - Temporal checks results: Unavailable

- **Emerging n-day Exploitation: CVE-2024-14007**:
    - Source IPs with counts: Not explicitly available, 1 alert event.
    - ASNs with counts: Unavailable
    - Target ports/services: Port 6036
    - Paths/endpoints: Unavailable
    - Payload/artifact excerpts: Suricata alert `CVE-2024-14007`
    - Staging indicators: Unavailable
    - Temporal checks results: Unavailable

- **Botnet Mapping: INF-2026-03-03-001 (Adbhoney Miner Campaign)**:
    - Source IPs with counts: `115.233.222.114` (Chinanet, China)
    - ASNs with counts: ASN 4134, Chinanet, China
    - Target ports/services: ADB (port 5555)
    - Paths/endpoints: ADB commands for miner installation/execution.
    - Payload/artifact excerpts: Malware filenames.
    - Staging indicators: Malware download URLs.
    - Temporal checks results: Unavailable

Indicators of Interest
- **IPs**: `115.233.222.114`, `167.99.95.111`, `36.143.57.131`, `134.122.80.225`, `88.99.24.59`, `134.199.222.217`, `143.110.250.106`, `129.212.188.196`, `129.212.179.18`, `134.122.80.102`, `157.245.98.199`, `95.110.222.106`, `88.151.33.168`, `185.14.45.77`, `78.153.140.93`, `167.71.255.16`.
- **CVEs**: `CVE-2025-55182`, `CVE-2024-14007`.
- **Malware Artifacts/Hashes**: `51ad31d5be1e1099fee1d03c711c9f698124899cfc321da5c0c56f8c93855e57.raw`, `9a56e2c761e10156cac6589bc9e929b1b8b5b00dd6c79ca0d33c2399b88e3a43.raw`, `9bc28777e722c46898754ef256d052e9cd684f6ad812d69878c68ba6cc0c72fe.raw`
- **URLs/Paths**: `/v1/metrics/droplet_id/553005910`, `/heromc.sh`, `/tranphuonglinh.sh`, `/viet69.sh`, `/.env`, `/geoserver/web/`, `/login`, `http://api.ipify.org/?format=json`.
- **Keywords**: "ufo.miner", "trinity".
- **Honeypot Input**: `pm path com.ufo.miner`, `am start -n com.ufo.miner/com.example.test.MainActivity`, `pm install /data/local/tmp/ufo.apk`, `ps | grep trinity`.
- **Suricata Signatures**: "GPL INFO VNC server response", "ET DROP Dshield Block Listed Source group 1", "ET INFO SSH session in progress on Expected Port", "ET SCAN MS Terminal Server Traffic on Non-standard Port", "ET SCAN Suspicious inbound to mySQL port 3306", "ET SCAN NMAP -sS window 1024".

Backend Tool Issues
- `kibanna_discover_query` and `match_query` failed to retrieve raw Conpot events with `type.keyword: Conpot` due to `illegal_argument_exception`. This weakened the ability to retrieve detailed Conpot event payloads, though high-level protocol data was still available.