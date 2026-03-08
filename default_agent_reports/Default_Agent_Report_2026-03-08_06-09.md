# Honeypot Threat Hunting Report

## 1) Investigation Scope
- **investigation_start**: 2026-03-08T06:00:04Z
- **investigation_end**: 2026-03-08T09:00:04Z
- **completion_status**: Complete
- **degraded_mode**: false

## 2) Executive Triage Summary
- High volume VNC scanning (28877 hits) observed across standard ports (5901-5905), primarily from the United States.
- Significant credential brute-forcing activity targeting common usernames and passwords.
- Emerging N-Day exploitation attempts observed for CVE-2025-55182 (90 hits) and CVE-2019-11500 (11 hits).
- Two distinct Android malware campaign indicators identified: one involving an "ufo.miner" check (China Mobile) and another for "tv.apk" installation and launch (China Unicom).
- Persistent reconnaissance for sensitive `.env` files and probing for exposed Docker API on port 2375 using a Go HTTP client.
- Unusual TLS Client Hello probes detected on a non-SSL Redis port (6379), suggesting specialized reconnaissance.

## 3) Candidate Discovery Summary
A total of 17,623 attacks were observed within the 3-hour window. Discovery agents identified multiple areas of interest, including high-volume VNC and SMB scanning, credential noise, and several honeypot-specific interactions.
The following items were identified as high-signal candidates for further validation:
- Reconnaissance for sensitive `.env` configuration files.
- Unusual SSL/TLS probing activity on the Redis honeypot.
- Scanning for exposed Docker API endpoints.
- Android malware installation and miner detection commands in the ADB honeypot.

All discovery processes completed successfully with no missing inputs or errors that materially affected discovery.

## 4) Emerging n-day Exploitation
- **CVE-mapped exploitation:**
    - **cve/signature mapping**: CVE-2025-55182
    - **evidence summary**: 90 instances observed.
    - **affected service/port**: Not specified in telemetry.
    - **confidence**: High
    - **operational notes**: Monitor for specific exploits associated with this CVE.
    - **cve/signature mapping**: CVE-2019-11500
    - **evidence summary**: 11 instances observed.
    - **affected service/port**: Not specified in telemetry.
    - **confidence**: High
    - **operational notes**: Monitor for specific exploits associated with this CVE.
- **Signature-mapped scanning/reconnaissance:**
    - **cve/signature mapping**: ET SCAN MS Terminal Server Traffic on Non-standard Port (Signature ID 2023753)
    - **evidence summary**: 643 instances from various source IPs.
    - **affected service/port**: MS Terminal Server (RDP) on non-standard ports.
    - **confidence**: High
    - **operational notes**: Indicates broad scanning for misconfigured RDP services. Review firewall logs for RDP exposure on non-standard ports.

## 5) Novel or Zero-Day Exploit Candidates (UNMAPPED ONLY, ranked)
No truly novel or zero-day exploit candidates were identified after OSINT validation. All initial candidates were reclassified as known scanning or reconnaissance techniques.

## 6) Botnet/Campaign Infrastructure Mapping
- **item_id**: android_malware_china_unicom
    - **campaign_shape**: unknown
    - **suspected_compromised_src_ips**: 110.18.137.191 (1 count)
    - **ASNs / geo hints**: AS4837 / CHINA UNICOM China169 Backbone (China)
    - **suspected_staging indicators**: Implied by `tv.apk` installation command.
    - **suspected_c2 indicators**: None explicit, activity implies post-compromise C2 via application launch.
    - **confidence**: High
    - **operational notes**: Isolate and analyze `tv.apk` if possible. Monitor IP 110.18.137.191 for further activity and potential C2 communication.
- **item_id**: android_miner_china_mobile
    - **campaign_shape**: unknown
    - **suspected_compromised_src_ips**: 223.104.83.218 (2 counts)
    - **ASNs / geo hints**: AS56040 / China Mobile communications corporation (China)
    - **suspected_staging indicators**: None explicit.
    - **suspected_c2 indicators**: None explicit, activity implies check for existing miner (ufo.miner).
    - **confidence**: High
    - **operational notes**: Correlate with other Android miner campaigns. Investigate `com.ufo.miner` context for further IOCs.

## 7) Odd-Service / Minutia Attacks
- **service_fingerprint**: Docker API (port 2375)
    - **why it’s unusual/interesting**: Exposed Docker API without authentication/encryption is a critical attack surface that can lead to full system compromise. While scanning for it is common, its presence indicates a high-value target for adversaries.
    - **evidence summary**: 110 requests to dest_port 2375, primarily `HTTP GET /version` with User-Agent `Go-http-client/1.1`. Also scanning on ports 8080 and 8888.
    - **confidence**: High
    - **recommended monitoring pivots**: Monitor 193.142.146.230 for further interaction with exposed Docker APIs. Implement strict firewall rules and TLS for Docker API access. Investigate other frequently requested URLs like `/goform/set_LimitClient_cfg` from this IP.

## 8) Known-Exploit / Commodity Exclusions
- **VNC Scanning**: High volume (28,877 hits) of VNC server response queries, primarily from the United States, targeting standard VNC ports (5901-5905). (Signature: `GPL INFO VNC server response`)
- **SMB Scanning**: Significant activity (945 hits) on port 445 (SMB) originating from Türkiye.
- **SSH/Telnet Scanning**: Common brute-forcing and scanning activity targeting ports 22 (SSH) and 23 (Telnet) from various countries (Indonesia, India, UK).
- **Credential Brute-Forcing**: Numerous attempts using common usernames (`root`, `admin`, `user`) and passwords (`1234`, `123456`, `password`), alongside some observed unique alphanumeric strings.
- **`.env` File Reconnaissance**: Attempts to retrieve sensitive `.env` configuration files via HTTP GET requests to `/.env` (3 hits) from 78.153.140.148 (Hostglobal.plus Ltd, UK). OSINT indicates this is a common, established reconnaissance technique.
- **Redis SSL/TLS Probing**: Binary data, identified as TLS Client Hello messages, sent to the Redis honeypot on port 6379 (2 hits) from 3.151.241.153 (Amazon.com, Inc., US). OSINT confirms this is consistent with common TLS/SSL port scanning or misconfiguration checks rather than a novel exploit. The source IP also engaged in broad scanning activities.

## 9) Infrastructure & Behavioral Classification
- **Exploitation vs Scanning**: The majority of observed activity is scanning and reconnaissance, including VNC, SMB, SSH/Telnet, `.env` file probing, and Docker API scanning. Direct exploitation attempts linked to CVEs were observed but without explicit payload details. Android malware deployment attempts suggest a higher intent.
- **Campaign Shape**:
    - **Broad Spray/Scanning**: VNC, SMB, SSH/Telnet, `.env` reconnaissance, and Redis TLS probing show characteristics of broad, opportunistic scanning campaigns, often originating from various IPs and ASNs.
    - **Targeted Android Campaigns**: The Android-related activities (miner check, APK install) appear more targeted, potentially part of specific botnet recruitment or malware distribution efforts, though exact campaign shapes (e.g., fan-in/fan-out) are unknown from current data.
- **Infra Reuse Indicators**:
    - The IP 3.151.241.153 (Amazon.com, Inc., US) engaged in Redis probing as well as broad scanning across SSH, Postgres, and other services, indicating multi-purpose scanning infrastructure.
    - China-based IPs (110.18.137.191 and 223.104.83.218) were linked to Android malware and miner activities, possibly part of distinct campaigns utilizing similar infrastructure patterns.
- **Odd-Service Fingerprints**: Exposed Docker API on port 2375, VNC on standard ports (though high volume), and Redis with unexpected TLS probes highlight services often targeted due to misconfiguration or vulnerability.

## 10) Evidence Appendix

**Botnet/Campaign Infrastructure Mapping:**

- **item_id**: android_malware_china_unicom
    - **source IPs with counts**: 110.18.137.191 (1)
    - **ASNs with counts**: AS4837 (CHINA UNICOM China169 Backbone)
    - **target ports/services**: ADB (Android Debug Bridge) honeypot
    - **paths/endpoints**: N/A (commands executed)
    - **payload/artifact excerpts**: `pm install /data/local/tmp/tv.apk`, `am start -n com.google.home.tv/com.example.test.MainActivity`, `rm -rf /data/local/tmp/*`
    - **staging indicators**: `/data/local/tmp/tv.apk`
    - **temporal checks results**: First seen: 2026-03-08T08:26:56Z, Last seen: 2026-03-08T08:27:04Z

- **item_id**: android_miner_china_mobile
    - **source IPs with counts**: 223.104.83.218 (2)
    - **ASNs with counts**: AS56040 (China Mobile communications corporation)
    - **target ports/services**: ADB (Android Debug Bridge) honeypot
    - **paths/endpoints**: N/A (commands executed)
    - **payload/artifact excerpts**: `pm path com.ufo.miner`
    - **staging indicators**: N/A
    - **temporal checks results**: First seen: 2026-03-08T06:17:50Z, Last seen: 2026-03-08T06:22:51Z

**Odd-Service / Minutia Attacks:**

- **item_id**: docker_api_scanning
    - **source IPs with counts**: 193.142.146.230 (110)
    - **ASNs with counts**: AS213438 (ColocaTel Inc., Germany)
    - **target ports/services**: 2375 (Docker API), 8080, 8888
    - **paths/endpoints**: `/version`, `/goform/set_LimitClient_cfg`
    - **payload/artifact excerpts**: HTTP GET /version, User-Agent: `Go-http-client/1.1`
    - **staging indicators**: N/A
    - **temporal checks results**: First seen: 2026-03-08T06:33:42Z, Last seen: 2026-03-08T08:49:43Z

**Known-Exploit / Commodity Exclusions:**

- **item_id**: tanner_env_recon
    - **source IPs with counts**: 78.153.140.148 (3 requests for /.env, 58 total events)
    - **ASNs with counts**: AS202306 (Hostglobal.plus Ltd, United Kingdom)
    - **target ports/services**: 80 (HTTP)
    - **paths/endpoints**: `/.env`, `/`
    - **payload/artifact excerpts**: HTTP GET request for `/.env`
    - **staging indicators**: N/A
    - **temporal checks results**: First seen: 2026-03-08T06:00:53Z, Last seen: 2026-03-08T07:52:45Z

- **item_id**: redis_ssl_probe
    - **source IPs with counts**: 3.151.241.153 (2 requests for TLS, 496 total events)
    - **ASNs with counts**: AS16509 (Amazon.com, Inc., United States)
    - **target ports/services**: 6379 (Redis), also 22, 5432, 30000, 8282, 24000, 7000, 9500, 2087
    - **paths/endpoints**: N/A
    - **payload/artifact excerpts**: Binary data identified as TLS Client Hello (`\x15\x03\x01\x00\x02\x02\x16`, `\x16\x03\x01\x00{...`)
    - **staging indicators**: N/A
    - **temporal checks results**: First seen: 2026-03-08T06:00:53Z, Last seen: 2026-03-08T08:47:38Z

## 11) Indicators of Interest
- **IPs**:
    - 110.18.137.191 (Suspected Android malware deployment)
    - 223.104.83.218 (Suspected Android miner activity)
    - 193.142.146.230 (Docker API scanner)
    - 78.153.140.148 (`.env` file reconnaissance)
    - 3.151.241.153 (Redis TLS/SSL probing and broad scanner)
    - 45.95.214.24 (Top attacker IP by count)
- **CVEs**:
    - CVE-2025-55182
    - CVE-2019-11500
- **Paths/Endpoints**:
    - `/.env`
    - `/version` (when targeting port 2375)
    - `/goform/set_LimitClient_cfg`
- **Payload Fragments**:
    - `pm install /data/local/tmp/tv.apk`
    - `pm path com.ufo.miner`
    - `Go-http-client/1.1` (User-Agent for Docker API scanning)
- **ASNs**:
    - AS4837 (CHINA UNICOM China169 Backbone)
    - AS56040 (China Mobile communications corporation)
    - AS213438 (ColocaTel Inc.)
    - AS202306 (Hostglobal.plus Ltd)
    - AS16509 (Amazon.com, Inc.)

## 12) Backend Tool Issues
No backend tool issues or query failures were reported during this investigation.

## 13) Agent Action Summary (Audit Trail)
- **agent_name**: ParallelInvestigationAgent
    - **purpose**: Orchestrates parallel data collection from various sources.
    - **inputs_used**: `investigation_start`, `investigation_end`
    - **actions_taken**: Called `BaselineAgent`, `KnownSignalAgent`, `CredentialNoiseAgent`, `HoneypotSpecificAgent`.
    - **key_results**:
        - Baseline: 17623 total attacks, top countries (US, Indonesia, Türkiye), top attacker IPs and ASNs.
        - Known Signals: Top alert signatures (VNC server response, SURICATA packet issues, MS Terminal Server scan), top CVEs (CVE-2025-55182, CVE-2019-11500).
        - Credential Noise: Top usernames (`root`, `admin`) and passwords (`345gs5662d34`, `123456`), p0f OS distribution.
        - Honeypot Specific: Redis connection/info/malformed requests, ADBHoney commands (miner check, apk install, rm -rf), Tanner `.env` and other path requests. Conpot showed no activity.
    - **errors_or_gaps**: None

- **agent_name**: CandidateDiscoveryAgent
    - **purpose**: Identifies potential high-signal candidates for further investigation.
    - **inputs_used**: `baseline_result`, `known_signals_result`, `credential_noise_result`, `honeypot_specific_result`
    - **actions_taken**: Queried for specific interesting events (e.g., `/.env` path, `pm path com.ufo.miner`, `pm install`, `am start`, `rm -rf`, Redis malformed commands, Docker API port 2375). Merged findings into candidates.
    - **key_results**:
        - Identified `tanner_env_recon` (recon for sensitive files).
        - Identified `redis_ssl_probe` (unusual Redis protocol interaction).
        - Identified `docker_api_scanning` (scanning for exposed Docker API).
        - Identified two Android-related botnet/campaign indicators.
        - Consolidated commodity activity into exclusions.
    - **errors_or_gaps**: None

- **agent_name**: CandidateValidationLoopAgent
    - **purpose**: Iteratively validates each candidate identified by the discovery agent.
    - **inputs_used**: Candidates from `CandidateDiscoveryAgent`.
    - **actions_taken**:
        - Initialized candidate queue with 3 candidates.
        - Iterated through `tanner_env_recon`, `redis_ssl_probe`, `docker_api_scanning`.
        - For each, performed additional queries (`two_level_terms_aggregated`, `top_http_urls_for_src_ip`, `events_for_src_ip`, `get_cve`, `suricata_lenient_phrase_search`, `first_last_seen_src_ip`) to gather more context, knownness, and temporal data.
    - **key_results**:
        - `tanner_env_recon` validated: High confidence, novel exploit candidate due to specific recon, but OSINT later reclassified.
        - `redis_ssl_probe` validated: Moderate confidence, novel exploit candidate due to unusual protocol, but OSINT later reclassified.
        - `docker_api_scanning` validated: High confidence, odd-service minutia attack due to targeting critical Docker API.
    - **errors_or_gaps**: None, all candidates were processed.

- **agent_name**: OSINTAgent
    - **purpose**: Performs OSINT lookups to assess knownness and recency of identified threats.
    - **inputs_used**: `tanner_env_recon`, `redis_ssl_probe`, `docker_api_scanning` candidates.
    - **actions_taken**: Performed targeted web searches for each candidate's key characteristics.
    - **key_results**:
        - `tanner_env_recon` mapped to `scanner_tooling` (`.env` Information Leak / Reconnaissance), `reduces_novelty`.
        - `redis_ssl_probe` mapped to `scanner_tooling` (Redis TLS/SSL port scanning/probing), `reduces_novelty`.
        - `docker_api_scanning` mapped to `scanner_tooling` (Exposed Docker API Scanning), `reduces_novelty`.
    - **errors_or_gaps**: None

- **agent_name**: ReportAgent
    - **purpose**: Compiles the final report from all workflow state outputs.
    - **inputs_used**: `investigation_start`, `investigation_end`, `baseline_result`, `known_signals_result`, `credential_noise_result`, `honeypot_specific_result`, `candidate_discovery_result`, `validated_candidates`, `osint_validation_result`.
    - **actions_taken**: Consolidated and formatted all gathered information into the specified markdown report structure, applying classification logic based on OSINT outcomes.
    - **key_results**: Generated the final markdown report.
    - **errors_or_gaps**: None (compilation only)

- **agent_name**: SaveReportAgent (Hypothetical, as per prompt, not explicitly run here)
    - **purpose**: Saves the generated report to a file.
    - **inputs_used**: Final markdown report content.
    - **actions_taken**: (Would call `default_write_file` tool).
    - **key_results**: (Would be file saved status and path).
    - **errors_or_gaps**: Not applicable for this step.
