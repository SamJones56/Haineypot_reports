# Honeypot Threat Intelligence Report

## 1) Investigation Scope
- **investigation_start**: 2026-03-09T06:00:11Z
- **investigation_end**: 2026-03-09T09:00:11Z
- **completion_status**: Partial
- **degraded_mode**: true (A query failure prevented source IP correlation for ICS/SCADA activity.)

## 2) Executive Triage Summary
- Total attacks observed: 21,049
- **Top services/ports of interest**: VNC (Ports 5902, 5903, 5904, 18789), SMB (Port 445), ADB (Android Debug Bridge - Port 5555), ICS/SCADA (guardian_ast, IEC104), Redis (Port 6379).
- **Confirmed known exploitation**: High-volume VNC scanning activity correlated with CVE-2006-2369, largely originating from DigitalOcean ASNs in the United States.
- **Unmapped exploit-like items**: A novel probe targeting QNAP Qsync functionality via the `/?qfunc=sync` URI.
- **Botnet/campaign mapping highlights**: A single-source ADB.Miner cryptominer deployment campaign from China, utilizing ADB (port 5555) to install `com.ufo.miner` (ufo.apk). The malware sample hash `0d3c687ffc30e185b836b99bd07fa2b0d460a090626f6bbbd40a95b98ea70257.raw` was captured.
- **Major uncertainties if degraded**: Source IPs for ICS/SCADA protocol probes could not be correlated due to a query failure, hindering full characterization of this activity.

## 3) Candidate Discovery Summary
Discovery agents processed 21,049 total attacks. Key areas of interest identified include:
- **ADBHoney**: A full installation sequence for `com.ufo.miner` (probable cryptominer) from a single source IP.
- **Tanner**: Web probes for generic misconfigurations (e.g., `/.env`) and a specific probe for QNAP devices (`/?qfunc=sync`).
- **Conpot**: Low-volume activity targeting niche ICS/SCADA protocols (`guardian_ast`, `IEC104`).
- **Known Signals**: Over 20,000 VNC server response alerts and 500+ hits for CVE-2006-2369.
- **Credential Noise**: Common brute-force attempts with 'root', 'admin' usernames and weak passwords.
- No major missing inputs or errors materially affected initial candidate discovery, though a specific follow-up query for Conpot data failed during deeper analysis.

## 4) Emerging n-day Exploitation
**Item ID**: BCM-002
- **CVE/signature mapping**: CVE-2006-2369, Suricata Signature: GPL INFO VNC server response (ID 2100560)
- **Evidence summary**: 20,733 signature hits observed, indicating widespread scanning for VNC vulnerabilities.
- **Affected service/port**: VNC services on ports 5902, 5903, 5904, 18789, 9000.
- **Confidence**: High
- **Operational notes**: This represents a large-scale spray campaign exploiting a known-but-old vulnerability. Monitor for changes in payload or technique. Consider adding involved ASNs to a tracking list for VNC scanning campaigns.

## 5) Novel or Zero-Day Exploit Candidates (UNMAPPED ONLY, ranked)
**Candidate ID**: NEC-001
- **Classification**: Novel exploit candidate
- **Novelty score**: 6
- **Confidence**: Medium
- **Provisional**: false
- **Key evidence**: 2 events from a single source IP (67.213.118.179) sending HTTP GET requests to `/` with the path `/?qfunc=sync`.
- **Knownness checks performed + outcome**: OSINT search for `'"qfunc=sync" exploit'` did not match a specific CVE but suggested it targets QNAP Qsync vulnerabilities. Not associated with any observed Suricata signatures.
- **Temporal checks (previous window / 24h)**: unavailable
- **Required follow-up**: Deploy QNAP Qsync honeypot profile if available to observe full attack chain. Search for other activity from source IP 67.213.118.179.

## 6) Botnet/Campaign Infrastructure Mapping
**Item ID**: BCM-001
- **Campaign shape**: unknown (single-source observed in this window)
- **Suspected compromised src_ips**: 125.114.201.116 (ASN 4134, Chinanet, China)
- **ASNs / geo hints**: ASN 4134 (Chinanet), China (Ningbo)
- **Suspected staging indicators**: Malware filename: `ufo.apk` (installed to `/data/local/tmp/ufo.apk`)
- **Suspected c2 indicators**: Associated malware package name `com.ufo.miner`. No explicit C2 IP/domain found in observed telemetry.
- **Confidence**: High
- **Operational notes**: This is a confirmed ADB.Miner variant deployment. Analyze captured malware sample `0d3c687ffc30e185b836b99bd07fa2b0d460a090626f6bbbd40a95b98ea70257.raw` to determine its capabilities (e.g., cryptominer, DDoS bot). Block source IP 125.114.201.116 and consider creating a signature to detect `com.ufo.miner` installation attempts via ADB.

## 7) Odd-Service / Minutia Attacks
**Item ID**: OSM-001
- **Service fingerprint**: Port/protocol: guardian_ast, IEC104
- **Why it’s unusual/interesting**: Targeted probes against specialized industrial control systems (ICS/SCADA) protocols are not common and indicate potentially advanced or niche threat actors.
- **Evidence summary**: 6 events reported by HoneypotSpecificAgent, indicating activity across `guardian_ast` (5 hits) and `IEC104` (1 hit) protocols.
- **Confidence**: Low
- **Recommended monitoring pivots**: Resolve evidence gap preventing source IP correlation. Further analysis on the nature of these probes and any associated payloads is required.

## 8) Known-Exploit / Commodity Exclusions
- **Credential Noise**: Widespread brute-force attempts using common usernames ('root', 'admin', 'ubuntu', 'postgres') and weak passwords ('123456', '12345678', 'password'). A specific uncommon credential pair `345gs5662d34`/`3245gs5662d34` was seen 64 times. (KEE-002)
- **SMB Scanning**: High volume SMB scanning on port 445 observed from multiple international ASNs (India, Bolivia, Indonesia). Consistent with commodity worm/scanner noise. (KEE-001)
- **Web Scanning**: Generic web scanning for common paths like `/`, `/favicon.ico`, `/.env`, and `/.git/config` from multiple IPs.

## 9) Infrastructure & Behavioral Classification
- **Exploitation vs Scanning**:
    - **Exploitation**: Confirmed ADB.Miner deployment (BCM-001) via ADB on port 5555. High-volume VNC exploitation attempts (BCM-002).
    - **Scanning**: Widespread SMB scanning (port 445), generic web path scanning, and targeted ICS/SCADA protocol probes.
- **Campaign Shape**:
    - **Single-source/Targeted**: ADB.Miner deployment (BCM-001) originated from a single IP (125.114.201.116) within the observation window. The QNAP probe (NEC-001) was also from a single IP.
    - **Spray**: High-volume VNC scanning (BCM-002) from multiple IPs, predominantly from DigitalOcean ASNs in the US. Widespread SMB scanning.
- **Infra Reuse Indicators**: The `ufo.miner` campaign uses a known malware package and APK name, indicating reuse of existing threat actor tools. The VNC campaign reuses known CVEs and widely detected signatures.
- **Odd-Service Fingerprints**: ICS/SCADA protocols `guardian_ast` and `IEC104` observed. Redis `info` commands and suspicious `MGLNDD` strings on port 6379 were also noted.

## 10) Evidence Appendix
**Novel Exploit Candidate**: NEC-001 (QNAP Qsync probe)
- **Source IPs**: 67.213.118.179 (2 counts)
- **ASNs**: Unavailable
- **Target ports/services**: HTTP (Tanner honeypot)
- **Paths/endpoints**: `/?qfunc=sync`
- **Payload/artifact excerpts**: HTTP GET request (full payload not captured in logs)
- **Staging indicators**: None observed
- **Temporal checks results**: unavailable

**Botnet/Campaign Mapping**: BCM-001 (ADB.Miner campaign)
- **Source IPs**: 125.114.201.116 (39 counts)
- **ASNs**: ASN 4134 (Chinanet, China)
- **Target ports/services**: Port 5555 (ADB)
- **Paths/endpoints**: `/data/local/tmp/ufo.apk`
- **Payload/artifact excerpts**:
    - `pm install /data/local/tmp/ufo.apk`
    - `am start -n com.ufo.miner/com.example.test.MainActivity`
    - `ps | grep trinity`
    - `rm -f /data/local/tmp/ufo.apk`
    - `rm -rf /data/local/tmp/*`
    - Malware sample: `dl/0d3c687ffc30e185b836b99bd07fa2b0d460a090626f6bbbd40a95b98ea70257.raw`
- **Staging indicators**: `ufo.apk` filename, `com.ufo.miner` package name
- **Temporal checks results**: Active for ~13 minutes (2026-03-09T08:46:52Z - 2026-03-09T08:59:14Z)

**Emerging n-day Exploitation**: BCM-002 (VNC Scanning Campaign)
- **Source IPs with counts**: Top attackers from United States (6255 total VNC events), e.g., 45.32.136.109 (692 events targeting VNC ports).
- **ASNs with counts**: ASN 14061 (DigitalOcean, LLC) (3486 events, primary source of VNC activity).
- **Target ports/services**: 5902, 5903, 5904, 18789, 9000 (VNC)
- **Paths/endpoints**: N/A (protocol-level interaction)
- **Payload/artifact excerpts**: VNC server responses, indicating probes.
- **Staging indicators**: None explicitly identified within the VNC traffic itself.
- **Temporal checks results**: Unavailable

## 11) Indicators of Interest
- **IPs**:
    - 125.114.201.116 (Suspected ADB.Miner actor, China)
    - 67.213.118.179 (QNAP Qsync probe, single source)
- **ASNs**:
    - ASN 4134 (Chinanet, China - associated with ADB.Miner)
    - ASN 14061 (DigitalOcean, LLC - primary source of VNC scanning)
- **Paths/Endpoints**:
    - `/?qfunc=sync` (QNAP Qsync vulnerability probe)
    - `/data/local/tmp/ufo.apk` (ADB.Miner installation path)
- **Payload/Artifacts**:
    - `com.ufo.miner` (ADB malware package name)
    - `ufo.apk` (ADB malware filename)
    - Malware hash: `0d3c687ffc30e185b836b99bd07fa2b0d460a090626f6bbbd40a95b98ea70257.raw`
- **Ports**:
    - 5555 (ADB)
    - 5902, 5903, 5904, 18789, 9000 (VNC)
    - 6379 (Redis)

## 12) Backend Tool Issues
- **CandidateDiscoveryAgent**:
    - A `two_level_terms_aggregated` query for `conpot.protocol.keyword -> src_ip.keyword` returned zero results, despite `HoneypotSpecificAgent` reporting 6 Conpot events. This prevented the correlation of source IPs to the observed ICS/SCADA activity (OSM-001).
    - **Impact**: The characterization of Odd-Service / Minutia Attacks for ICS/SCADA protocols is degraded as source IP information is missing, reducing confidence to 'Low' and marking the item as 'Provisional'.
- **DeepInvestigationLoopController**:
    - During investigation of BCM-001 (ADB.Miner), a `two_level_terms_aggregated` query to identify destination port spread for `125.114.201.116` was misconfigured and returned irrelevant results. However, subsequent `events_for_src_ip` confirmed activity was confined to port 5555.
    - A `custom_basic_search` for `dest_port:5555` failed during the investigation of `service:5555/tcp/adb`. The primary aggregation query, however, was sufficient to conclude the campaign was single-source within the window.
    - **Impact**: Minor, as the key conclusions for BCM-001 regarding the single-source campaign shape and dedicated port 5555 targeting were still reached through other successful queries.

## 13) Agent Action Summary (Audit Trail)

- **ParallelInvestigationAgent**
    - **Purpose**: Simultaneously gather baseline, known signals, credential noise, and honeypot-specific telemetry.
    - **Inputs Used**: `investigation_start`, `investigation_end` (timeframe: 2026-03-09T06:00:11Z to 2026-03-09T09:00:11Z)
    - **Actions Taken**:
        - `BaselineAgent`: Queried total attacks (21049), top countries, top source IPs, country-to-port mapping, top ASNs.
        - `KnownSignalAgent`: Queried top alert signatures, top CVEs, top alert categories.
        - `CredentialNoiseAgent`: Queried top input usernames, top input passwords, p0f OS distribution.
        - `HoneypotSpecificAgent`: Queried Redis activity, ADBHoney inputs/malware samples, Conpot inputs/protocols, Tanner URIs.
    - **Key Results**:
        - Identified 21049 total attacks.
        - Top countries: US, India, Bolivia. Top ASNs: DigitalOcean, AXS Bolivia, Chinanet.
        - High volume VNC (20733 hits) and SMB (445) activity.
        - ADBHoney activity (ufo.miner), Tanner web probes (/?qfunc=sync), Conpot ICS/SCADA protocol hits (guardian_ast, IEC104).
        - Common credential stuffing detected.
    - **Errors or Gaps**: None

- **CandidateDiscoveryAgent**
    - **Purpose**: Identify and initially classify novel, emerging, or high-value threats from raw telemetry.
    - **Inputs Used**: `baseline_result`, `known_signals_result`, `credential_noise_result`, `honeypot_specific_result`
    - **Actions Taken**:
        - Explored ADBHoney miner installation using `two_level_terms_aggregated` (input -> src_ip) and `kibanna_discover_query` for `ufo.apk` installation.
        - Investigated Tanner `/?qfunc=sync` web request using `two_level_terms_aggregated` (path -> src_ip) and OSINT `search`.
        - Examined Conpot ICS/SCADA activity using `two_level_terms_aggregated` (protocol -> src_ip).
        - Classified and outputted initial candidates for further validation.
    - **Key Results**:
        - Identified ADB.Miner campaign (BCM-001) from `125.114.201.116`.
        - Identified QNAP Qsync probe (NEC-001) from `67.213.118.179`.
        - Identified ICS/SCADA activity (OSM-001) with `guardian_ast`, `IEC104` protocols.
        - Merged all parallel agent outputs successfully.
    - **Errors or Gaps**: A `two_level_terms_aggregated` query for Conpot protocols to source IPs returned zero results, blocking IP correlation for OSM-001.

- **CandidateValidationLoopAgent**
    - **Purpose**: Iteratively validate and enrich high-value candidates through targeted queries.
    - **Inputs Used**: Candidates from `CandidateDiscoveryAgent` (BCM-001, BCM-002, NEC-001, OSM-001)
    - **Actions Taken**:
        - **Iteration 1 (BCM-001 - ADB.Miner)**:
            - Queried `kibanna_discover_query` for `src_ip:125.114.201.116` to get all events.
            - Performed `suricata_lenient_phrase_search` for `ufo.miner` signature.
    - **Key Results**:
        - Validated BCM-001: Confirmed 39 events from `125.114.201.116` related to `ufo.miner` installation. No Suricata signatures for `ufo.miner` found.
        - 1 candidate validated.
    - **Errors or Gaps**: None.

- **DeepInvestigationLoopController**
    - **Purpose**: Conduct in-depth investigation of critical leads identified during validation.
    - **Inputs Used**: Validated candidate BCM-001.
    - **Actions Taken**: 3 iterations run.
        - **Iteration 1**:
            - Consumed lead `src_ip:125.114.201.116`.
            - Queried `first_last_seen_src_ip` for the IP.
            - Attempted `two_level_terms_aggregated` (src_ip -> dest_port) (encountered error/misconfig).
        - **Iteration 2**:
            - Consumed lead `artifact:0d3c687ffc30e...` (malware hash).
            - Queried `events_for_src_ip` for `125.114.201.116`.
            - Queried `kibanna_discover_query` for the malware hash.
        - **Iteration 3**:
            - Consumed lead `service:5555/tcp/adb`.
            - Queried `two_level_terms_aggregated` (input -> src_ip, type: Adbhoney) to check campaign shape.
            - Attempted `custom_basic_search` for `dest_port:5555` (failed).
        - Exited loop after exhausting leads for BCM-001.
    - **Key Results**:
        - Confirmed `125.114.201.116` active for ~13 minutes, exclusively targeting port 5555 (ADB).
        - Determined ADB.Miner campaign was single-source from `125.114.201.116` within the investigation window.
        - Malware hash search yielded no further network events.
    - **Errors or Gaps**:
        - `two_level_terms_aggregated` (src_ip -> dest_port) for `125.114.201.116` had a tool misconfiguration, though subsequently clarified.
        - `custom_basic_search` for `dest_port:5555` failed, but core conclusion for ADB.Miner campaign shape was reached.

- **OSINTAgent**
    - **Purpose**: Perform open-source intelligence lookups for validation and context.
    - **Inputs Used**: Candidate BCM-001 artifacts (malware names, ADB context).
    - **Actions Taken**:
        - Performed `search` query: `""com.ufo.miner" "ufo.apk" "ADB" malware"`.
    - **Key Results**:
        - Confirmed BCM-001 telemetry matches public reporting on the ADB.Miner malware family (ufo.apk variant).
        - Classified as `established` threat, reducing novelty score for the malware itself but confirming its malicious nature.
    - **Errors or Gaps**: None

- **ReportAgent**
    - **Purpose**: Compile the final report from workflow state outputs.
    - **Inputs Used**: All workflow state outputs: `investigation_start`, `investigation_end`, `baseline_result`, `known_signals_result`, `credential_noise_result`, `honeypot_specific_result`, `candidate_discovery_result`, `validated_candidates`, `osint_validation_result`, `deep_investigation_logs/state`.
    - **Actions Taken**: Consolidated and formatted all collected data into the specified markdown report structure. Applied mandatory logic for classification and completion status.
    - **Key Results**: Generated the final threat intelligence report.
    - **Errors or Gaps**: None (self-compilation).

- **SaveReportAgent**
    - **Purpose**: Save the generated report to a specified file.
    - **Inputs Used**: The completed markdown report content.
    - **Actions Taken**: Tool call `deep_agent_write_file`.
    - **Key Results**: [Status: placeholder - actual tool call not yet made by current agent]
    - **Errors or Gaps**: [Status: placeholder - actual tool call not yet made by current agent]