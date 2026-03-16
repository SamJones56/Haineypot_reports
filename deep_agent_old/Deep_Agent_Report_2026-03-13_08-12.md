# Honeypot Threat Hunting Report

## 1) Investigation Scope
- **investigation_start**: 2026-03-13T08:00:10Z
- **investigation_end**: 2026-03-13T12:00:10Z
- **completion_status**: Partial (degraded evidence)
- **degraded_mode**: true. The investigation was unable to correlate source IP addresses for an emerging n-day threat (CVE-2025-55182) and for unusual ICS protocol activity due to tool query failures.

## 2) Executive Triage Summary
- **Top Services of Interest**: The most significant malicious activity targeted Android Debug Bridge (ADB) on port 5555. Unusual probing was observed against uncommon Industrial Control System (ICS) protocols (kamstrup, guardian_ast). Commodity scanning targeted VNC (5900), SSH (22), and web services (80/443).
- **Top Confirmed Known Exploitation**: A campaign exploiting the Android ADB interface to deploy the "ADB.Miner" cryptocurrency mining malware was fully mapped to a source IP. A separate campaign spraying the known PHPUnit RCE vulnerability (CVE-2017-9841) was also identified.
- **Top Unmapped Exploit-like Items**: Activity matching signatures for a recently disclosed React2Shell vulnerability (CVE-2025-55182) was detected (133 events), but source IPs could not be identified. This is tracked as a provisional emerging threat.
- **Botnet/Campaign Mapping Highlights**: Two distinct campaigns were mapped:
    - **BOT-01**: A focused attack from a single IP (`112.224.144.211`) deploying Android crypto-mining malware.
    - **BOT-02**: A coordinated RCE spray from two source IPs (`103.218.243.42`, `159.65.119.52`) targeting a known PHPUnit vulnerability.
- **Major Uncertainties**: The primary uncertainty is the scope and source of the emerging React2Shell (CVE-2025-55182) exploitation and the actors behind the ICS protocol probing. Both are blocked pending investigation of data pipeline or tool issues.

## 3) Candidate Discovery Summary
The discovery phase successfully triaged over 40,000 events and identified four main areas of interest:
- **Android Malware Campaign**: A clear execution chain for the "trinity" and "ufo.miner" malware was captured in the Adbhoney honeypot.
- **PHP Exploitation Campaign**: A coordinated spray targeting a known PHPUnit RCE vulnerability (CVE-2017-9841) was observed in the Tanner honeypot.
- **Emerging N-day Activity**: 133 Suricata alerts were raised for the recent React2Shell vulnerability (CVE-2025-55182).
- **Odd-Service Probing**: The Conpot honeypot recorded interactions with rare ICS/SCADA protocols.

Data correlation for the emerging n-day and odd-service items failed, preventing the identification of source IPs for these candidates.

## 4) Emerging n-day Exploitation
### NDE-01: React2Shell Exploitation (Provisional)
- **cve/signature mapping**: CVE-2025-55182 / "ET WEB_SPECIFIC_APPS React Server Components React2Shell Unsafe Flight Protocol Property Access"
- **evidence summary**: 133 Suricata alert events.
- **affected service/port**: HTTP/S (Assumed Web)
- **confidence**: Medium
- **operational notes**: This activity is marked as provisional because the query to retrieve the associated source IPs failed. The high alert count suggests an emerging threat that requires follow-up. The immediate priority is to investigate the data pipeline failure.

## 6) Botnet/Campaign Infrastructure Mapping
### BOT-01: ADB.Miner Android Botnet
- **item_id**: BOT-01
- **campaign_shape**: fan-out
- **suspected_compromised_src_ips**: `112.224.144.211` (single source)
- **ASNs / geo hints**: AS4837 - CHINA UNICOM China169 Backbone (China)
- **suspected_staging indicators**: None observed. The payload was executed directly via ADB commands.
- **suspected_c2 indicators**: None observed.
- **confidence**: High
- **operational notes**: This is a known, commodity Android botnet that spreads by exploiting open ADB ports (TCP/5555) to install cryptocurrency miners. The source IP should be blocked.

### BOT-02: PHPUnit RCE Campaign
- **item_id**: BOT-02
- **campaign_shape**: spray
- **suspected_compromised_src_ips**: `103.218.243.42`, `159.65.119.52`
- **ASNs / geo hints**: Unavailable
- **suspected_staging indicators**: The exploit paths themselves are the primary indicators:
    - `/V2/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php`
    - `/?%ADd+allow_url_include%3d1+%ADd+auto_prepend_file%3dphp://input`
- **suspected_c2 indicators**: None observed.
- **confidence**: High
- **operational notes**: This campaign exploits the well-known PHPUnit RCE vulnerability CVE-2017-9841. The source IPs should be monitored for further hostile activity.

## 7) Odd-Service / Minutia Attacks
### ODD-01: ICS/SCADA Protocol Probing (Provisional)
- **service_fingerprint**: kamstrup_protocol, guardian_ast, kamstrup_management_protocol
- **why it’s unusual/interesting**: These are uncommon Industrial Control System (ICS) protocols. Probing for these services is not typical of commodity internet scanners and may indicate targeted reconnaissance against operational technology (OT).
- **evidence summary**: 26 total interaction events logged by the Conpot honeypot.
- **confidence**: Medium
- **recommended monitoring pivots**: This item is provisional as the source IPs could not be identified due to a query failure. Investigating the tool/pipeline failure is the required next step.

## 8) Known-Exploit / Commodity Exclusions
- **VNC Scanning**: Massive, single-source scanning (17,769 events) on port 5900 from `185.231.33.22` (AS211720), matching benign VNC server responses.
- **Credential Noise**: Standard brute-force attempts on SSH using common usernames (`root`, `admin`) and passwords (`123456`, `password`).
- **Benign Internet Scanners**: Deep investigation confirmed `176.65.139.38` is a Shodan scanner (`Shodan-Pull/1.0` user-agent) and `45.156.87.24` is an automated scanner performing simple ADB probes.
- **Known Scanning Signatures**: Activity was dominated by common scanner signatures such as "ET SCAN MS Terminal Server Traffic on Non-standard Port" and Dshield blocklist hits.

## 9) Infrastructure & Behavioral Classification
- **BOT-01 (ADB.Miner)**: Classified as **Exploitation**. Exhibits a **fan-out** campaign shape from a single IP. The service fingerprint is TCP/5555 (ADB). No infrastructure reuse was observed.
- **BOT-02 (PHPUnit RCE)**: Classified as **Exploitation**. Exhibits a **spray** campaign shape. Shows infrastructure reuse with two IPs using identical tactics. The service fingerprint is TCP/80, TCP/443.
- **NDE-01 (React2Shell)**: Classified as **Exploitation (Provisional)**. Campaign shape and infrastructure reuse are unknown due to missing IP data.
- **ODD-01 (ICS Probing)**: Classified as **Scanning/Reconnaissance (Provisional)**. Campaign shape and infrastructure reuse are unknown due to missing IP data. The service fingerprint is uncommon ICS protocols.

## 10) Evidence Appendix
### For: BOT-01 (ADB.Miner)
- **source IPs**: `112.224.144.211` (54 events)
- **ASNs**: `AS4837 - CHINA UNICOM China169 Backbone` (54 events)
- **target ports/services**: 5555/tcp (ADB)
- **payload/artifact excerpts**:
    - `rm -rf /data/local/tmp/*`
    - `chmod 0755 /data/local/tmp/trinity`
    - `/data/local/tmp/nohup /data/local/tmp/trinity`
    - `am start -n com.ufo.miner/com.example.test.MainActivity`
- **temporal checks results**: First seen: `2026-03-13T09:24:26.000Z`, Last seen: `2026-03-13T09:37:39.873Z`

### For: BOT-02 (PHPUnit RCE)
- **source IPs**: `103.218.243.42`, `159.65.119.52`
- **ASNs**: Unavailable
- **target ports/services**: 80/tcp, 443/tcp (HTTP/S)
- **paths/endpoints**:
    - `/V2/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php`
    - `/?%ADd+allow_url_include%3d1+%ADd+auto_prepend_file%3dphp://input`
- **temporal checks results**: Unavailable

### For: NDE-01 (React2Shell)
- **source IPs**: Unavailable
- **ASNs**: Unavailable
- **target ports/services**: HTTP/S (Assumed)
- **payload/artifact excerpts**: "ET WEB_SPECIFIC_APPS React Server Components React2Shell Unsafe Flight Protocol Property Access (CVE-2025-55182)"
- **temporal checks results**: Unavailable

## 11) Indicators of Interest
- **IPs**:
    - `112.224.144.211` (ADB.Miner Bot)
    - `103.218.243.42` (PHPUnit RCE Scanner)
    - `159.65.119.52` (PHPUnit RCE Scanner)
- **Paths / Payloads**:
    - `/V2/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php`
    - `/?%ADd+allow_url_include%3d1+%ADd+auto_prepend_file%3dphp://input`
    - `trinity` (filename)
    - `com.ufo.miner` (Android package)
- **CVEs**:
    - `CVE-2017-9841` (PHPUnit RCE)
    - `CVE-2025-55182` (React2Shell)
- **Malware Hashes**:
    - `dl/76ae6d577ba96b1c3a1de8b21c32a9faf6040f7e78d98269e0469d896c29dc64.raw`
    - `dl/a1b6223a3ecb37b9f7e4a52909a08d9fd8f8f80aee46466127ea0f078c7f5437.raw`
    - `dl/d7188b8c575367e10ea8b36ec7cca067ef6ce6d26ffa8c74b3faa0b14ebb8ff0.raw`

## 12) Backend Tool Issues
- **top_src_ips_for_cve**: This tool failed to return any source IPs for `CVE-2025-55182`, despite 133 matching alerts in the dataset. This blocked validation for candidate `NDE-01`.
- **two_level_terms_aggregated**: This tool failed to correlate source IPs with Conpot protocol events. This blocked validation for candidate `ODD-01`.

These failures mean the conclusions for `NDE-01` and `ODD-01` are provisional and require remediation of the underlying data pipeline or query tool.

## 13) Agent Action Summary (Audit Trail)
- **agent_name**: ParallelInvestigationAgent
- **purpose**: Gathers broad, parallel data streams for initial triage.
- **inputs_used**: `investigation_start`, `investigation_end`.
- **actions_taken**: Executed 15+ initial data queries across baseline, known signal, credential noise, and honeypot-specific tools.
- **key_results**:
    - Identified ~40k total attacks.
    - Highlighted massive VNC scanning activity from Seychelles / `185.231.33.22`.
    - Captured 133 alerts for CVE-2025-55182.
    - Logged ADB malware commands and PHPUnit RCE paths.
    - Recorded unusual ICS protocol activity.
- **errors_or_gaps**: None.

- **agent_name**: CandidateDiscoveryAgent
- **purpose**: Synthesizes parallel data to identify high-signal candidates for deep investigation.
- **inputs_used**: `baseline_result`, `known_signals_result`, `credential_noise_result`, `honeypot_specific_result`.
- **actions_taken**: Aggregated data by source IP and artifact. Used OSINT search to map a vulnerability. Generated 4 candidates.
- **key_results**:
    - Created `BOT-01` (ADB.Miner), `BOT-02` (PHPUnit RCE), `NDE-01` (React2Shell), and `ODD-01` (ICS Probing).
    - Mapped PHPUnit paths to CVE-2017-9841.
    - Excluded VNC scanning as commodity noise.
- **errors_or_gaps**: Two key correlation queries (`top_src_ips_for_cve` for NDE-01, `two_level_terms_aggregated` for ODD-01) failed, returning 0 results. This prevented IP identification for two candidates.

- **agent_name**: CandidateValidationLoopAgent
- **purpose**: Performs detailed validation of a single candidate from the queue.
- **iterations run**: 1
- **# candidates validated**: 1
- **early exit reason**: Only one candidate (`BOT-01`) was processed in the provided workflow logs.
- **actions_taken**: Queried raw logs for the candidate's source IP (`112.224.144.211`). Used OSINT search to confirm the identity of the "trinity" and "ufo.miner" malware.
- **key_results**: Confirmed `BOT-01` is the well-known ADB.Miner campaign from 2018.
- **errors_or_gaps**: None.

- **agent_name**: DeepInvestigationLoopController
- **purpose**: Conducts iterative, deep-dive pivots on validated candidates to map infrastructure.
- **iterations run**: 3
- **key leads pursued**: `112.224.144.211` (malicious), `176.65.139.38` (benign), `45.156.87.24` (benign).
- **stall/exit reason**: Loop exited after the stall count reached the threshold of 2, as pivots from the initial high-signal lead resulted in only benign scanners.
- **actions_taken**: Pivoted from source IP to raw events (`events_for_src_ip`). Determined activity timeline (`first_last_seen_src_ip`). Pivoted from malware artifacts back to source IPs to check for other attackers.
- **key_results**:
    - Fully scoped the `BOT-01` attack to a 13-minute window from a single IP.
    - Confirmed no other IPs were using the same malware TTPs.
    - Identified and excluded two benign scanners (Shodan and a generic ADB scanner).
- **errors_or_gaps**: One query failed but was successfully retried with a different tool.

- **agent_name**: OSINTAgent
- **purpose**: Provides external intelligence context on observables.
- **inputs_used**: Requests from other agents via the `search` tool.
- **actions_taken**: Responded to search queries for "PHPUnit RCE" and "ADB.Miner".
- **key_results**: Provided the CVE for the PHPUnit vulnerability and confirmed the identity and TTPs of the Android malware.
- **errors_or_gaps**: None.

- **agent_name**: ReportAgent
- **purpose**: Builds final report from workflow state (no new searching).
- **inputs_used**: `investigation_start`, `investigation_end`, `baseline_result`, `known_signals_result`, `credential_noise_result`, `honeypot_specific_result`, `candidate_discovery_result`, `validated_candidates`, `investigation_log`.
- **actions_taken**: Compiled this markdown report.
- **key_results**: This document.
- **errors_or_gaps**: Report compiled in `degraded_mode` due to evidence gaps from `CandidateDiscoveryAgent`.

- **agent_name**: SaveReportAgent
- **purpose**: Writes the final report to a file.
- **inputs_used**: Report content from `ReportAgent`.
- **actions_taken**: Calling `deep_agent_write_file`.
- **key_results**: File write status.
- **errors_or_gaps**: None anticipated.
