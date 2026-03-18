1) Investigation Scope
- investigation_start: 2026-03-04T06:00:04Z
- investigation_end: 2026-03-04T07:00:04Z
- completion_status: Partial
- degraded_mode: true (DeepInvestigationLoopController exited early due to recurring tool errors, limiting comprehensive aggregation for some leads.)

2) Executive Triage Summary
- High volume of "ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication" events observed, indicating a widespread SMB exploitation campaign from multiple source IPs and ASNs.
- Extensive scanning for VNC, SSH, and RDP services, including RDP on non-standard ports.
- Significant credential brute-forcing activity against common usernames and passwords.
- Targeted web reconnaissance attempts, including access to sensitive `.env` configuration files and automated scanning for WordPress jQuery vulnerabilities.
- Low-volume interactions with Industrial Control System (ICS) protocols (Guardian AST) on a Conpot honeypot.
- Uncategorized activity detected on uncommon TCP port 37777 requiring further monitoring.
- Several backend tool errors during deep investigation prevented full aggregation of associated IPs and signatures for some identified activities.

3) Candidate Discovery Summary
- Total attacks observed: 11326
- Top services of interest: SMB (445), SSH (22), VNC (5925, 5926), SMTP (25), various non-standard ports (e.g., 17000, 37777, 8728, 49673, 3333, 3392, 33895, 9009, 43389, 5500, 8800, 9999), and ICS protocols (IEC104, guardian_ast).
- Top known signals include: "GPL INFO VNC server response" (2551 events), "ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication" (1303 events), "ET SCAN MS Terminal Server Traffic on Non-standard Port" (254 events).
- Credential noise highlights: 'root' (195), 'postgres' (63) and '123456' (58), 'password' (19).
- Honeypot-specific detections: Tanner honeypot detected requests for sensitive files like '/.env' and WordPress jQuery-related web paths. Conpot recorded low-volume interactions with ICS protocols.
- Initial candidate count: 5 (including 2 for infrastructure mapping, 1 novel exploit candidate, 2 odd-service/suspicious unmapped).

4) Emerging n-day Exploitation
- **DoublePulsar Backdoor Communication (DP_SMB_CAMPAIGN_01)**
    - cve/signature mapping: `ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication` (Signature ID 2024766). OSINT confirms mapping to the established DoublePulsar malware family.
    - evidence summary: 1303 Suricata alert events. High volumes from source IPs `79.98.102.166` (7706 hits), `200.105.151.2` (5403 hits), and `202.63.102.75` (1308 hits). Raw SMB payload data observed.
    - affected service/port: SMB (TCP 445).
    - confidence: High.
    - operational notes: Confirmed widespread campaign. Monitor for staging host identification or further exploit stages.
- **.env File Information Disclosure Attempt (TANNER_DOT_ENV_01)**
    - cve/signature mapping: No direct CVE or specific signature mapping from internal tools. OSINT confirms this is an established exploit technique for sensitive data exposure.
    - evidence summary: 1 HTTP GET request for `/.env` on Tanner honeypot from `78.153.140.147`, resulting in HTTP 404. User-Agent `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.5845.140 Safari/537.36`.
    - affected service/port: HTTP/S (Tanner honeypot, TCP 80).
    - confidence: High.
    - operational notes: Targeted reconnaissance for sensitive configuration. Monitor for recurrence and activity from `78.153.140.147`.

5) Novel or Zero-Day Exploit Candidates (UNMAPPED ONLY, ranked)
- None. The candidate `TANNER_DOT_ENV_01`, initially considered novel, was reclassified as an emerging n-day exploitation due to OSINT confirming it as an established technique.

6) Botnet/Campaign Infrastructure Mapping
- **DoublePulsar SMB Campaign (DP_SMB_CAMPAIGN_01)**
    - item_id or related candidate_id(s): DP_SMB_CAMPAIGN_01
    - campaign_shape: Spray
    - suspected_compromised_src_ips: `79.98.102.166` (7706 hits), `200.105.151.2` (5403 hits), `202.63.102.75` (1308 hits).
    - ASNs / geo hints: ASN 17771 (Southern Online Bio Technologies Ltd, India), ASN 16347 (ADISTA SAS, France), ASN 26210 (AXS Bolivia S. A., Bolivia).
    - suspected_staging indicators: None explicitly identified in logs.
    - suspected_c2 indicators: None explicitly identified, payload is for backdoor installation.
    - confidence: High.
    - operational notes: Significant, widespread campaign. Investigate full SMB traffic for post-exploitation or staging indicators.
- **Automated WordPress Vulnerability Scanning (TANNER_JQUERY_WEB_EXPLOIT_01)**
    - item_id or related candidate_id(s): TANNER_JQUERY_WEB_EXPLOIT_01
    - campaign_shape: Spray
    - suspected_compromised_src_ips: `152.42.255.97`.
    - ASNs / geo hints: ASN 14061 (DigitalOcean, LLC, Singapore).
    - suspected_staging indicators: Repeated access to WordPress-related jQuery paths (e.g., `/wp-includes/js/jquery/jquery.js,...`).
    - suspected_c2 indicators: None.
    - confidence: High.
    - operational notes: Common automated scanning for known WordPress vulnerabilities. Monitor activity from `152.42.255.97` for further exploitation attempts.

7) Odd-Service / Minutia Attacks
- **Guardian AST ICS Protocol Interaction (CONPOT_GUARDIAN_AST_01)**
    - service_fingerprint: Conpot honeypot, `guardian_ast` protocol, TCP dest_port 10001.
    - why it’s unusual/interesting: Interaction with an Industrial Control System (ICS) protocol, indicating potential targeting of operational technology.
    - evidence summary: 1 event of `NEW_CONNECTION` with `guardian_ast` protocol from `204.76.203.207`.
    - confidence: Moderate (protocol is known, but source IP exhibits broad scanning behavior).
    - recommended monitoring pivots: Monitor for increased ICS protocol interactions or more focused scanning from `204.76.203.207`.
- **Uncommon Port 37777 Activity (UNCOMMON_PORT_37777_01)**
    - service_fingerprint: TCP dest_port 37777.
    - why it’s unusual/interesting: No officially assigned service or widely documented malware/botnet associations found via OSINT.
    - evidence summary: 5 hits on port 37777, originating from France.
    - confidence: Low.
    - recommended monitoring pivots: Monitor for increased activity on this port, specific payload identification, or correlation with other IOCs.

8) Known-Exploit / Commodity Exclusions
- **Generic VNC Scanning**: `GPL INFO VNC server response` (2551 events)
- **Network Layer Noise**: `SURICATA IPv4 truncated packet` (1930 events), `SURICATA AF-PACKET truncated packet` (1930 events), and various `SURICATA STREAM` alerts (e.g., reassembly sequence GAP, broken ack, spurious retransmission).
- **RDP Scanning**: `ET SCAN MS Terminal Server Traffic on Non-standard Port` (254 events), observed on various non-standard ports including 3333, 3392, 33895, 9009, 43389, 5500, 8800, 9999, primarily from `136.114.97.84`.
- **SSH Scanning/Traffic**: `ET INFO SSH-2.0-Go version string Observed in Network Traffic` (67 events), `ET INFO SSH session in progress on Expected Port` (45 events), `ET SCAN Potential SSH Scan` (11 events).
- **Credential Brute-Forcing**: High volume of attempts targeting common usernames like 'root' (195), 'postgres' (63) and passwords like '123456' (58), 'password' (19).
- **Reputation-Based Alerts**: Widespread alerts from `ET DROP Dshield Block Listed Source` (159 events) and `ET CINS Active Threat Intelligence Poor Reputation IP` (numerous groups), indicating traffic from known malicious or suspicious sources.
- **Common Web Scans**: `ET WEB_SERVER /etc/passwd Detected in URI` (14 events).

9) Infrastructure & Behavioral Classification
- **Exploitation vs. Scanning**: DoublePulsar activity represents direct exploitation attempts. WordPress jQuery paths, `.env` file access, RDP, VNC, SSH, and uncommon port activity are primarily reconnaissance or vulnerability scanning.
- **Campaign Shape**: The DoublePulsar and WordPress jQuery activities exhibit a "spray" pattern, targeting many potential victims. The `.env` file access and Guardian AST interaction appear as more focused, single-IP activities within a broader scanning context. RDP scanning also follows a spray pattern across diverse ports.
- **Infra Reuse Indicators**: Attacking IPs are sourced from various cloud/hosting providers (e.g., DigitalOcean, ADISTA SAS, AXS Bolivia S. A., Google LLC), suggesting potentially compromised hosts or rented infrastructure. Multiple IPs are involved in the DoublePulsar campaign.
- **Odd-Service Fingerprints**: Detection of ICS protocol `guardian_ast` and scans against numerous non-standard high-numbered TCP ports (e.g., 37777, 10001, 17000, 8728, 49673, 3333, 3392, 33895, 9009, 43389, 5500, 8800, 9999).

10) Evidence Appendix
- **DoublePulsar Backdoor Communication (DP_SMB_CAMPAIGN_01)**
    - Source IPs: `202.63.102.75` (1308 events), `79.98.102.166` (7706 hits), `200.105.151.2` (5403 hits).
    - ASNs: `ASN 17771` (Southern Online Bio Technologies Ltd, IN), `ASN 16347` (ADISTA SAS, FR), `ASN 26210` (AXS Bolivia S. A., BO).
    - Target ports/services: TCP 445 (SMB).
    - Paths/endpoints: SMB protocol communication (no specific HTTP paths).
    - Payload/artifact excerpts: Binary SMB protocol data, signature `ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication`. Example payload snippet (truncated): `AAAQTv9TTUIyAAAAABgHwAAAAAAAAAAAAAAAAP////4AAEIADwwAABABAAAAAAAAACWJGgAAAAwAQgAAEE4AAQAOAA0QAFoAZl5SYzZeUsMyXo0vxMAc/WU1NLIqhCrG/ikREjOkRkahTVlS89zXxZvwTsgDGZOGVIAM8Kg/YZee725OSRVYjD+WlmG6uz/Uh4xEECAUYXsz8MKv6Ryrag3vjE53kpwgDToBL/DVnpwM1Z/a/ViQrDP61sOSiqYPon6mQWJz8brRrJYoKylls8NpDImceYOG1xAx/Ou/TmK/VX9oKEDr6TyJlhltMdbEJjI0dprFmzwEtapQoFGmVfoAPWQIujX0A65DwLQsO1VHxdtCbSWHwukN/H0iDKdeaQTKxYXtGTwTE4TrBozB0h8MYj9e1cmH0NcpxFfpRk4V6Wnikn/0BNm56gwAevb/2LgHiwZwdWC7MxHapFiENY6/PVIYqXLNJJBCwM3iCVXRAYTKul9GMWAZo3HDrt0+w2y40LUZAhkqtI81etY9c7yWlsne5J87VKUU6476pHtxFj1sT2tMGvf6veeUtKhTaN2Kr8ZlmmUaTMoBBJVFnFGw+it9GoNQcOgmRjeLG2AH/wPK0Ffkc0NeCzzfuQWmdN5PtIVSS6+JZbj9qXAX/57sKzXrsPDe8gopGBxEPfvPTHhXhTpnk10BRyW7Aw/DYnZl9nH0ouexbpLUZ8jvTpvJwvTRqpb9BreD/RlFITG/MFxJcXFn1z0/gZN5M7nvn6adVygqDgN8r+Wvs6C6kk9BzqcZYzidNn0pWiz/g+01OxMgR31qvip7+UvROy98DwWtWMUGhbHU8gdmCNxS5Y3klJ/0ILikicvuGFqpAVuOnOpHCgfZg7cCBDbHvSh0oJVBjtCYq8p+vL8HOUjfN+KmbRPWxIy/l67Ji9OjlYoPCOY1OqVZO31jq9OkGi6MzDhYUFEZN+Q8vLXPDR2UzfbaiZ4fgb1rfen3/67h/JXpyc8ZQ2GCurhvM/cuwxyQffG2ZJ13Da5pi44pM4nBFs/8EBg/2XUbD09MfzOUs1i1ip4FtLCItySuxdQN0pMqAk6huK1od4l+hOyyNq+G++zciekS+mBew5QQxdy/qU+8Y3CF2Sa8wQnYJkIS8hS8KmlrAyWpKJi6xoqT7iHu0uH5cMgBD3/on5/U2MAP9KjC3PLg4K6ulNdFNewagSah/SPLF6AUTYyQyjsc5ghzVNNuCUb1ozhDl+sYkX4DsW6wkN1Qzbp6B141J1pJ1maX7ZKjpTrHIOdNjyNTxz6sQeZQQjHmwFfiGdPaYvkjVy774ZS69+Zs0ZN9qRwAz5M9QWxZLD74qb3rAETNFDJ35zkesRTY0PiWgXHVe/5ywXfmbCUnKo0nVRFFy2jwpQbesf5DbvP6FIvS723HTv8jzqtcgyAcXUYi4zkn8QnYcDJtBlWcGAbYElZNEKbQe8XDq7A+iOGNFsWhyx7y97a++Ho8/7fLR/BIf7++4sMTuwR/Z2ssjxyUITcCL5UIxFteoDOyz/ip8CMTeAmZNx5KmjaWP4+TSRIg99Hec9WrNyP6hHuPYzs/wdMBBB4xL6jtNqLQnJs2PpCDiNcwJ7cfN5rEN6yAThVb7ihiezx7W/pTvH6mpP+kjfF4UqAgDiv49BX0TfLJh2Ppj/X+UI2m/VnsCFVirrNQyvwFgGHchtIk8HjFzEtcCeKLpkaLIQ8YI2d0OKKYb8koVMyZS95Pho1F3YAKWvDsFROAcXqSkXQ2UvmZkewFXA/RIin2R3w23L++xYy3fQ5wGNUcLrFi2zrG2EiIdfxR+Fxl1qQ7CeuV7grqcfArec97MOMFG1AOXd5JjVkqRz3j/5ja9zuRcOCR0j/HbjI28h1NU+2l0OlPw3yFxRFhQOg3IAwAsAqfzuNfsJMjIA1nPGxnxFl0a60Twwk=`.
    - Staging indicators: Unavailable.
    - Temporal checks: `2026-03-04T06:00:04Z` to `2026-03-04T06:29:45Z` (across multiple IPs).
- **.env File Information Disclosure Attempt (TANNER_DOT_ENV_01)**
    - Source IPs: `78.153.140.147` (1 event).
    - ASNs: `ASN 14061` (DigitalOcean, LLC, US).
    - Target ports/services: TCP 80 (HTTP).
    - Paths/endpoints: `/.env`, `/`.
    - Payload/artifact excerpts: `GET /.env HTTP/1.1`, `User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.5845.140 Safari/537.36`.
    - Staging indicators: Unavailable.
    - Temporal checks: `2026-03-04T06:40:06Z` to `2026-03-04T06:41:13Z`.
- **Automated WordPress Vulnerability Scanning (TANNER_JQUERY_WEB_EXPLOIT_01)**
    - Source IPs: `152.42.255.97`.
    - ASNs: `ASN 14061` (DigitalOcean, LLC, SG).
    - Target ports/services: TCP 80, 8080 (HTTP).
    - Paths/endpoints: `/`, `/wp-includes/js/jquery/jquery.js,qver=1.12.4.pagespeed.jm.pPCPAKkkss.js`, `/wp-includes/js/jquery/jquery-migrate.min.js,qver=1.4.1.pagespeed.jm.C2obERNcWh.js`, `/static/wp-content/themes/twentyeleven/js/html5.js`.
    - Payload/artifact excerpts: HTTP GET requests, `User-Agent: Go-http-client/1.1`.
    - Staging indicators: Attempts to access known WordPress-related JavaScript files as part of scanning.
    - Temporal checks: `2026-03-04T06:00:54Z` to `2026-03-04T06:59:45Z`.

11) Indicators of Interest
- **IPs**:
    - `202.63.102.75` (DoublePulsar activity, IN)
    - `79.98.102.166` (DoublePulsar activity, FR)
    - `200.105.151.2` (DoublePulsar activity, BO)
    - `78.153.140.147` (`.env` file access, GB)
    - `152.42.255.97` (WordPress scanning, SG)
    - `136.114.97.84` (RDP scanning on non-standard ports, US)
    - `204.76.203.207` (Guardian AST protocol interaction, NL)
- **Signatures**:
    - `ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication` (ID 2024766)
    - `ET SCAN MS Terminal Server Traffic on Non-standard Port` (ID 2023753)
- **Paths/Endpoints**:
    - `/.env`
    - `/wp-includes/js/jquery/jquery.js,qver=1.12.4.pagespeed.jm.pPCPAKkkss.js`
    - `/wp-includes/js/jquery/jquery-migrate.min.js,qver=1.4.1.pagespeed.jm.C2obERNcWh.js`
- **User Agents**:
    - `Go-http-client/1.1`
    - `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.5845.140 Safari/537.36` (associated with `.env` scan)
- **Ports**:
    - TCP 445 (SMB, DoublePulsar)
    - TCP 37777 (Unusual activity)
    - TCP 10001 (Guardian AST)
    - TCP 3333, 3392, 33895, 9009, 43389 (RDP scanning on non-standard ports)

12) Backend Tool Issues
- `match_query`: Failed with `illegal_argument_exception` for `alert.signature.keyword` queries.
- `kibanna_discover_query`: Failed with `illegal_argument_exception` for various `path.keyword` and `type.keyword` queries.
- `two_level_terms_aggregated`: Repeatedly failed with `illegal_argument_exception` when attempting to aggregate secondary fields like `alert.signature.keyword` or `http.user_agent.keyword` for specific source IPs or primary signatures.
- These issues occurred during candidate discovery and deep investigation, leading to an incomplete aggregation of data for specific signals and IPs. Manual extraction from raw logs was necessary to mitigate some gaps.

13) Agent Action Summary (Audit Trail)
- **ParallelInvestigationAgent**
    - Purpose: Conduct parallel initial investigations across different data sources.
    - Inputs used: `investigation_start`, `investigation_end`.
    - Actions taken: Executed `BaselineAgent`, `KnownSignalAgent`, `CredentialNoiseAgent`, and `HoneypotSpecificAgent` in parallel, performing various `get_*` and `_search` queries.
    - Key results: Collected baseline metrics (11326 attacks, top countries/IPs/ASNs/ports), identified top known alert signatures (e.g., VNC, DoublePulsar) and CVEs, summarized credential noise (e.g., 'root', '123456'), and gathered honeypot-specific data (Tanner web paths, Conpot protocols).
    - Errors or gaps: None reported.
- **CandidateDiscoveryAgent**
    - Purpose: Consolidate parallel investigation results and identify potential high-signal candidates.
    - Inputs used: `baseline_result`, `known_signals_result`, `credential_noise_result`, `honeypot_specific_result`.
    - Actions taken: Merged parallel outputs, performed triage, generated 5 initial candidates, classified known exploit exclusions, and executed multiple `two_level_terms_aggregated`, `match_query`, `kibanna_discover_query`, `discover_by_keyword`, `complete_custom_search`, and `timeline_counts` queries.
    - Key results: Identified DoublePulsar SMB campaign, WordPress jQuery web exploit, `.env` file access, Conpot Guardian AST interaction, and uncommon port 37777 activity as candidates. Noted initial tool errors in `match_query` and `kibanna_discover_query`.
    - Errors or gaps: Several `match_query` and `kibanna_discover_query` tool calls failed with `illegal_argument_exception` errors.
- **CandidateValidationLoopAgent (Controller/Reducer)**
    - Purpose: Orchestrate validation of discovered candidates through deep investigation and OSINT.
    - Inputs used: Initial candidates from `CandidateDiscoveryAgent`.
    - Actions taken: Initialized candidate queue with 5 candidates; initiated validation for `DP_SMB_CAMPAIGN_01`. Appended `DP_SMB_CAMPAIGN_01` to validated candidates.
    - Key results: `DP_SMB_CAMPAIGN_01` was passed to Deep Investigation. The validation loop exited early following a request from `DeepInvestigationLoopController`.
    - Errors or gaps: Deep Investigation requested early exit, implicitly stopping further candidates from full deep-dive validation in this pass.
- **DeepInvestigationLoopController**
    - Purpose: Conduct in-depth analysis on high-signal leads generated during candidate validation.
    - Iterations run: 7.
    - Key leads pursued: `src_ip:202.63.102.75`, `src_ip:79.98.102.166`, `src_ip:136.114.97.84`, `signature:ET SCAN MS Terminal Server Traffic on Non-standard Port`, `src_ip:152.42.255.97`, `src_ip:78.153.140.147`, `service:guardian_ast/10001`.
    - Stall/exit reason: Agent initiated early exit due to `stall_count: 2` (multiple tool errors encountered and no new high-value leads generated).
    - Errors or gaps: Recurring `illegal_argument_exception` from `two_level_terms_aggregated` and `kibanna_discover_query` tools, hindering comprehensive aggregation of associated IPs, ports, and signatures for some leads.
- **OSINTAgent**
    - Purpose: Perform external open-source intelligence lookups for validated candidates.
    - Inputs used: All 5 candidates initially discovered by `CandidateDiscoveryAgent`.
    - Actions taken: Performed OSINT searches using various terms for each candidate's key attributes (signatures, paths, protocols, user agents).
    - Key results: Confirmed DoublePulsar as established malware, WordPress jQuery scanning as automated tooling, `.env` file access as an established exploit technique, and Guardian AST as a known ICS protocol. Found no public mapping for TCP port 37777.
    - Errors or gaps: None reported.
- **ReportAgent (self)**
    - Purpose: Compile the final report from workflow state outputs.
    - Inputs used: All workflow state outputs provided (`investigation_start`, `investigation_end`, `baseline_result`, `known_signals_result`, `credential_noise_result`, `honeypot_specific_result`, `candidate_discovery_result`, `validated_candidates` (implicitly covered by OSINT), `osint_validation_result`, `deep_investigation_logs/state`).
    - Actions taken: Synthesized and structured all available information into the mandatory markdown report format, including final classifications based on OSINT.
    - Key results: Generated the complete markdown report.
    - Errors or gaps: None.
- **SaveReportAgent**
    - Purpose: Save the final report to storage.
    - File write status: Not explicitly provided in workflow state.
    - Path/identifier: Not explicitly provided.
