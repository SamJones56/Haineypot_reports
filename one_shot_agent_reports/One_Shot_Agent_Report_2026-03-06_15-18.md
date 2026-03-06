# Investigation Report

## 1) Investigation Scope
- investigation_start: 2026-03-06T15:00:06Z
- investigation_end: 2026-03-06T18:00:06Z
- completion_status: Complete
- degraded_mode: false

## 2) Executive Triage Summary
- Top services/ports of interest include VNC (5900, 5900-5913), SSH (22), Elasticsearch/Kibana (9200), and various web application ports (3000s).
- Confirmed known exploitation includes widespread scanning for VNC and SSH, as well as a significant number of alerts for CVE-2025-55182 (React Server Components).
- Unmapped exploit-like items include path traversal attempts targeting `/etc/passwd` on port 9200, which is also associated with an ElasticPot exploit event.
- Botnet/campaign mapping highlights reveal significant activity from DigitalOcean and China Mobile ASNs, with common credential attempts ("root", "admin", "123456").
- Adbhoney and Conpot honeypots recorded minimal to no specific input, suggesting these particular honeypot types were not heavily targeted by input-based attacks during this period, or that input was not captured effectively.

## 3) Candidate Discovery Summary
- Total attack events: 19643
- Top countries: United States (7803), Ukraine (1309), Hong Kong (1233)
- Top alert categories: Misc activity (17191), Generic Protocol Command Decode (1526), Misc Attack (1189)
- Top CVEs: CVE-2025-55182 (119), CVE-2024-14007 (7)
- Top attacker ASNs: DigitalOcean, LLC (4525), Dynu Systems Incorporated (1895), Google LLC (1260)
- Missing inputs/errors: `get_input_usernames` and `get_input_passwords` for Adbhoney and Conpot yielded no results, indicating no specific command or protocol interactions were recorded for these honeypots.

## 4) Emerging n-day Exploitation
- **CVE-2025-55182: React Server Components React2Shell Unsafe Flight Protocol Property Access**
    - cve/signature mapping: ET WEB_SPECIFIC_APPS React Server Components React2Shell Unsafe Flight Protocol Property Access (CVE-2025-55182)
    - evidence summary: 119 alerts. Key artifacts include traffic from 24.144.94.222 to 10.17.0.5 on various ports (3001, 3002, 3005, 3008, 3011) with HTTP URL `/`.
    - affected service/port: Web applications on ports 3001, 3002, 3005, 3008, 3011.
    - confidence: High
    - operational notes: Active exploitation/scanning for a recently disclosed web application vulnerability. Monitor affected applications.

## 5) Novel or Zero-Day Exploit Candidates (UNMAPPED ONLY, ranked)
- **candidate_id**: NCE001
    - classification: Novel exploit candidate
    - novelty_score: High
    - confidence: Provisional (due to limited context on ElasticPot exploit)
    - provisional: true
    - key evidence: Path traversal attempts (28 events) targeting `/etc/passwd` via URLs like `/export/classroom-course-statistics?fileNames[]=../../../../../../../etc/passwd` and `/vpn/user/download/client?ostype=../../../../../../../../../etc/passwd`. Associated with an ElasticPot exploit event `/bsh.servlet.BshServlet` on port 9200.
    - knownness checks performed + outcome: `web_path_samples` and `discover_by_keyword` performed; specific path traversal variants identified, but the full exploit chain/malware family from the ElasticPot event requires further analysis.
    - temporal checks (previous window / 24h) or “unavailable”: Unavailable
    - required follow-up: Investigate the ElasticPot exploit context and the associated malware samples more deeply. Analyze the source IPs (167.71.255.16, 117.188.115.86) for other suspicious activities and campaign infrastructure.

## 6) Botnet/Campaign Infrastructure Mapping
- **item_id**: BCM001 (Associated with NCE001)
    - campaign_shape: Spray/Fan-out (multiple source IPs, varied targets for path traversal/ElasticPot)
    - suspected_compromised_src_ips:
        - 167.71.255.16 (DigitalOcean, US) - involved in path traversal
        - 117.188.115.86 (China Mobile, China) - involved in path traversal and ElasticPot exploit (Elasticsearch/Kibana honeypot)
    - ASNs / geo hints: AS14061 (DigitalOcean, US), AS9808 (China Mobile Communications Group Co., Ltd., China)
    - suspected_staging indicators: None explicitly identified, but the malware samples from Adbhoney (e.g., `dl/689b47e85e5f2dde8c935d6b05b6a2db1d7d1686ee158b84e34e86f787844b21.raw`) could be related to a download stage.
    - suspected_c2 indicators: None explicitly identified from the current data.
    - confidence: Medium (due to indirect links between malware samples and the observed exploits)
    - operational notes: Monitor traffic from 167.71.255.16 and 117.188.115.86 for further suspicious activity, especially targeting port 9200 or other web services. Analyze downloaded malware samples for C2 indicators.

## 7) Odd-Service / Minutia Attacks
- **service_fingerprint**: VNC (Port 5900, 5901, 5902, 5903, 5904, 5906, 5907, 5912, 5913)
    - why it’s unusual/interesting: Extensive scanning and probing for VNC services, indicated by 16516 "GPL INFO VNC server response" alerts. While VNC itself isn't odd, the sheer volume suggests broad scanning for vulnerable or exposed VNC servers.
    - evidence summary: 16516 events with signature "GPL INFO VNC server response". Top source IPs include 8.222.131.221, 129.212.183.117, 139.59.28.253.
    - confidence: High
    - recommended monitoring pivots: Monitor VNC port activity for connections from known malicious IPs, unusual VNC protocol commands, and attempts at brute-forcing VNC passwords.

- **service_fingerprint**: Elasticsearch/Kibana (Port 9200) with Web Application Exploitation
    - why it’s unusual/interesting: Path traversal attempts and an ElasticPot exploit event targeting port 9200 suggest attackers are actively probing and exploiting Elasticsearch/Kibana instances. This is a critical service and attacks can lead to data exfiltration or remote code execution.
    - evidence summary: 28 path traversal attempts, 1 ElasticPot exploit event (`/bsh.servlet.BshServlet`). Source IPs 167.71.255.16 and 117.188.115.86.
    - confidence: High
    - recommended monitoring pivots: Monitor all traffic to port 9200, especially for unusual GET/POST requests containing path traversal sequences or known exploit patterns for Elasticsearch/Kibana vulnerabilities.

## 8) Known-Exploit / Commodity Exclusions
- **Credential Noise**:
    - Brute-force attempts using common usernames ("root", "admin", "ubuntu") and passwords ("123456", "1234", "password"). (Total 227 "root" username attempts, 40 "123456" password attempts).
- **Scanning Activity**:
    - Widespread VNC scanning (16516 events for "GPL INFO VNC server response").
    - MS Terminal Server traffic on non-standard ports (608 events).
    - SSH session attempts on expected ports (374 events).
    - IP reputation identified 10878 events from "known attacker" and 522 from "mass scanner" IPs.

## 9) Infrastructure & Behavioral Classification
- **CVE-2025-55182 Exploitation**: Exploitation, campaign shape unknown (likely spray/opportunistic).
- **Path Traversal / ElasticPot Exploitation**: Exploitation, spray/fan-out campaign, infra reuse observed (117.188.115.86 for both path traversal and ElasticPot).
- **VNC Scanning**: Scanning, spray campaign, common attacker infrastructure (various IPs).
- **SSH Scanning/Brute-force**: Scanning, spray campaign, common attacker infrastructure.
- **Odd-service fingerprints**: VNC (5900-5913), SSH (22), Elasticsearch/Kibana (9200).

## 10) Evidence Appendix
- **Emerging n-day Exploitation: CVE-2025-55182**
    - source IPs with counts: 24.144.94.222 (119)
    - ASNs with counts: Missing (not retrieved for this specific IP during CVE drill-down)
    - target ports/services: 3001, 3002, 3005, 3008, 3011 (Web applications)
    - paths/endpoints: `/`
    - payload/artifact excerpts: `alert.signature: "ET WEB_SPECIFIC_APPS React Server Components React2Shell Unsafe Flight Protocol Property Access (CVE-2025-55182)"`
    - staging indicators: Missing
    - temporal checks results or “unavailable”: Unavailable

- **Novel Exploit Candidate: NCE001 (Path Traversal / ElasticPot)**
    - source IPs with counts: 167.71.255.16 (multiple events), 117.188.115.86 (multiple events)
    - ASNs with counts: AS14061 (DigitalOcean, US), AS9808 (China Mobile Communications Group Co., Ltd., China)
    - target ports/services: 9200 (Elasticsearch/Kibana)
    - paths/endpoints: `/export/classroom-course-statistics?fileNames[]=../../../../../../../etc/passwd`, `/vpn/user/download/client?ostype=../../../../../../../../../etc/passwd`, `/bsh.servlet.BshServlet`
    - payload/artifact excerpts: `http.url` containing path traversal sequences. `event_type: Exploit`, `http.url: /bsh.servlet.BshServlet` (for ElasticPot).
    - staging indicators: Adbhoney malware samples (e.g., `dl/689b47e85e5f2dde8c935d6b05b6a2db1d7d1686ee158b84e34e86f787844b21.raw`) could be related.
    - temporal checks results or “unavailable”: Unavailable

- **Top Botnet Mapping Item: BCM001 (DigitalOcean/China Mobile Recon/Exploitation)**
    - source IPs with counts: 167.71.255.16 (various), 117.188.115.86 (various)
    - ASNs with counts: AS14061 (DigitalOcean, US), AS9808 (China Mobile Communications Group Co., Ltd., China)
    - target ports/services: 9200 (Elasticsearch/Kibana), 22 (SSH), various others.
    - paths/endpoints: Path traversal attempts on web paths, various SSH activity.
    - payload/artifact excerpts: `http.url` with path traversal, common username/password attempts.
    - staging indicators: Possible Adbhoney malware download paths.
    - temporal checks results or “unavailable”: Unavailable

## 11) Indicators of Interest
- **IPs**:
    - 24.144.94.222 (Source for CVE-2025-55182 exploitation)
    - 167.71.255.16 (Source for path traversal, DigitalOcean)
    - 117.188.115.86 (Source for path traversal and ElasticPot exploit, China Mobile)
    - 8.222.131.221, 129.212.183.117, 139.59.28.253 (Top sources for VNC scanning)
    - 207.174.0.19 (Top overall attacking IP)
- **URLs/Paths**:
    - `/export/classroom-course-statistics?fileNames[]=../../../../../../../etc/passwd`
    - `/vpn/user/download/client?ostype=../../../../../../../../../etc/passwd`
    - `/bsh.servlet.BshServlet` (ElasticPot exploit)
- **Payload Fragments**:
    - `dl/689b47e85e5f2dde8c935d6b05b6a2db1d7d1686ee158b84e34e86f787844b21.raw` (Adbhoney malware sample)
- **CVEs**:
    - CVE-2025-55182

## 12) Backend Tool Issues
- `adbhoney_input` and `conpot_input`/`conpot_protocol` returned no results. This might indicate no activity on these specific honeypots during the timeframe, or an issue with the underlying data collection/field mapping. Conclusions regarding Adbhoney and Conpot activity are therefore limited to "no observed activity" and the Adbhoney malware samples are assessed indirectly. This makes the assessment of comprehensive honeypot activity partially weakened for these specific types.
- `top_src_ips_for_cve` for CVE-2025-55182 returned 0 source IPs, despite `suricata_cve_samples` showing a source IP. This suggests a potential field mapping issue or inconsistency in how source IPs are associated with CVEs in the underlying data for this specific aggregation, weakening the direct link between a CVE and its primary attackers.