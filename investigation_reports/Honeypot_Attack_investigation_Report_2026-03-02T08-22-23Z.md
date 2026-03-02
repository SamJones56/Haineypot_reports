# Investigation Report: Threat Hunting Analysis (2026-03-02)

### 1) Investigation Scope
- **investigation_start**: 2026-03-02T07:17:09Z
- **investigation_end**: 2026-03-02T08:17:09Z
- **completion_status**: Partial (degraded evidence)
- **degraded_mode**: true - Key backend tool `kibanna_discover_query` failed repeatedly, preventing raw log retrieval and payload inspection for the primary campaign actor. The `credential_noise_result` input was also missing.

### 2) Executive Triage Summary
- **Top Services/Ports of Interest**:
    - Port 80 (HTTP): Low volume but hosted the highest-quality signal: a multi-exploit RCE campaign from a single actor.
    - Port 22 (SSH) & 445 (SMB): High volume of commodity scanning and suspected brute-force activity.
    - Odd Port Cluster (5926, 5925, 5436, 5902): An unusual concentration of scanning was observed on this cluster of high, unassigned ports via the Honeytrap honeypot.
- **Top Confirmed Known Exploitation**:
    - A focused campaign was identified from source IP `37.120.213.13` attempting to exploit multiple known PHP vulnerabilities, most prominently the PHPUnit RCE (CVE-2017-9841).
- **Unmapped Exploit-like Items**:
    - No novel or zero-day exploit candidates were validated in this window.
- **Botnet/Campaign Mapping Highlights**:
    - A single source IP (`37.120.213.13`) exhibited a clear "fan-out" attack pattern, spraying 46 unique exploit payloads for various PHP vulnerabilities (PHPUnit, ThinkPHP, pearcmd) in a brief 96-second burst.
- **Major Uncertainties**:
    - The inability to retrieve raw logs for `37.120.213.13` prevented inspection of HTTP POST bodies or full payloads. The classification is based entirely on URL artifacts.

### 3) Candidate Discovery Summary
- **Total Events Analyzed**: 8,471
- **Honeypots with Most Activity**: Cowrie (SSH, 4,783 events), Honeytrap (Network Services, 2,787 events).
- **Top Areas of Interest Identified**:
    - A high-confidence, multi-exploit RCE campaign from a single IP (`37.120.213.13`) detected on the Tanner (HTTP) honeypot.
    - A cluster of unusual high-port scanning activity on Honeytrap.
- **Material Gaps**: The absence of the `credential_noise_result` input limited the ability to systematically filter out common SSH brute-force attempts.

### 6) Botnet/Campaign Infrastructure Mapping
**Item ID**: BC-20260302-01
- **Campaign Shape**: fan-out (one source, many exploit paths)
- **Suspected Compromised Source IPs**:
    - `37.120.213.13` (152 total events, 46 unique Tanner paths)
- **ASNs / Geo Hints**: ASN 9009 (M247 Europe SRL), Zurich, Switzerland
- **Suspected Staging Indicators**: None observed.
- **Suspected C2 Indicators**: None observed.
- **Confidence**: High
- **Operational Notes**: This IP is conducting automated scanning for a wide range of known PHP vulnerabilities. The activity is focused and aggressive but not novel. Recommend blocking the source IP.

### 7) Odd-Service / Minutia Attacks
**Service Fingerprint**:
- **Ports/Protocol**: 5926/tcp, 5925/tcp, 5436/tcp, 5902/tcp
- **Application Hint**: Honeytrap (Network Services)
- **Why Unusual**: This represents a targeted cluster of high, mostly unassigned ports. While 5902 is related to VNC, the specific combination suggests scanning for a non-standard application or a tool that probes this specific set of ports.
- **Evidence Summary**: Hundreds of events observed across this port set, indicating automated and repeated scanning.
- **Confidence**: Moderate
- **Recommended Monitoring Pivots**: Continue to monitor this port cluster to fingerprint the underlying protocol or identify the scanner/tool responsible.

### 8) Known-Exploit / Commodity Exclusions
- **PHP RCE Scanning (CVE-2017-9841, etc.)**: Activity from `37.120.213.13` targeting the PHPUnit RCE vulnerability and other known PHP exploits is classified as commodity scanning for well-documented vulnerabilities.
- **Credential Noise**: High volume of activity on port 22 (SSH) captured by Cowrie is consistent with widespread, automated brute-force and credential stuffing attacks.
- **VNC/RDP Scanning**: Signatures such as `GPL INFO VNC server response` and `ET SCAN MS Terminal Server Traffic on Non-standard Port` indicate generic scanning for remote access services.
- **Commodity LFI Scanning**: Signatures like `ET WEB_SERVER /etc/passwd Detected in URI` were observed from diffuse sources and represent low-sophistication probes.

### 9) Infrastructure & Behavioral Classification
- **Exploitation vs Scanning**: The activity from `37.120.213.13` is classified as active exploitation attempts, not just reconnaissance. All other activity appears to be scanning and probing.
- **Campaign Shape**: A clear `fan-out` pattern was identified from `37.120.213.13`.
- **Infra Reuse Indicators**: No infrastructure reuse was observed. The primary actor and exploit paths were unique within this time window.
- **Odd-Service Fingerprints**: The port cluster {5926, 5925, 5436, 5902} serves as a fingerprint for suspicious scanning activity to monitor.

### 10) Evidence Appendix
**Item**: BC-20260302-01 (Multi-exploit Campaign)
- **Source IPs**: `37.120.213.13` (count: 152)
- **ASNs**: `AS9009 M247 Europe SRL` (count: 152)
- **Target Ports/Services**: 80/tcp (HTTP)
- **Paths/Endpoints (Sample)**:
    - `/V2/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php` (CVE-2017-9841)
    - `/?%ADd+allow_url_include%3d1+%ADd+auto_prepend_file%3dphp://input` (PHP LFI)
    - `/index.php?s=/index/\think\app/invokefunction&function=call_user_func_array...` (ThinkPHP RCE)
    - `/cgi-bin/%%32%65%%32%65/%%32%65%%32%65/bin/sh` (Shellshock-like CGI injection)
- **Staging Indicators**: None
- **Temporal Checks**: Actor was active for a brief 96-second period from 2026-03-02T07:48:07Z to 2026-03-02T07:49:43Z.

### 11) Indicators of Interest
- **IP**: `37.120.213.13`
- **Path Fragment**: `/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php`
- **Path Fragment**: `?s=/index/\think\app/invokefunction`
- **Port Cluster**: `5926,5925,5436,5902`

### 12) Backend Tool Issues
- **Tool**: `kibanna_discover_query`
- **Failures**: This tool failed on every attempt with a `status_code: 400` and `reason: 'Expected text at 1:71 but found START_ARRAY'`.
- **Affected Validations**:
    - **Payload Inspection**: It was not possible to retrieve raw event logs, preventing the inspection of HTTP POST bodies or full request headers for the primary campaign actor (`37.120.213.13`).
    - **Threat Classification**: Classification of the campaign activity had to rely solely on URL artifacts and OSINT, without direct confirmation from Suricata signatures or payload contents.

### 13) Agent Action Summary (Audit Trail)
- **agent_name**: CandidateDiscoveryAgent
  - **purpose**: Perform initial data sweep to find interesting leads for investigation.
  - **inputs_used**: `baseline_result`, `known_signals_result`, `honeypot_specific_result`. Missing: `credential_noise_result`.
  - **actions_taken**: Ran aggregation queries for top Suricata signatures, CVEs, destination ports, and honeypot types. Analyzed Tanner logs for suspicious web paths.
  - **key_results**:
    - Identified a single IP (`37.120.213.13`) responsible for numerous PHP RCE attempts.
    - Identified an unusual cluster of scanning activity on high ports (5902, 5925, 5926, 5436).
    - Generated two primary candidates: `BC-20260302-01` and `SUM-20260302-01`.
  - **errors_or_gaps**: `kibanna_discover_query` failed twice during initial triage, blocking raw log retrieval.
- **agent_name**: CandidateValidationLoopAgent
  - **purpose**: Validate and classify the candidates discovered in the previous stage.
  - **inputs_used**: `candidate_discovery_result`.
  - **actions_taken**: Performed 1 validation iteration on candidate `BC-20260302-01`. Ran Suricata signature searches and OSINT checks for `eval-stdin.php`.
  - **key_results**:
    - Classified `BC-20260302-01` as a `known_exploit_campaign`.
    - Confirmed the exploit path is linked to CVE-2017-9841 via OSINT.
    - Found no specific Suricata signatures that fired for the activity.
  - **errors_or_gaps**: `kibanna_discover_query` failed again, blocking payload inspection.
- **agent_name**: DeepInvestigationLoopController
  - **purpose**: Perform a deep-dive analysis on the most significant validated candidate.
  - **inputs_used**: `validated_candidates` (specifically `BC-20260302-01`).
  - **actions_taken**: Ran 3 investigation iterations. The primary lead was `src_ip:37.120.213.13`. Pivoted from the IP to find all associated paths, then pivoted from key paths to find other source IPs.
  - **key_results**:
    - Confirmed the attacker's activity was confined to a 96-second window.
    - Mapped the full "fan-out" pattern of 46 unique exploit paths from the single source IP.
    - Confirmed no other source IPs were using the same exploit paths in this window.
  - **errors_or_gaps**: Exited loop after 2 stalled pivots (no new leads were generated).
- **agent_name**: OSINTAgent
  - **purpose**: Enrich findings with open-source intelligence.
  - **inputs_used**: `validated_candidates`, `candidate_discovery_result`.
  - **actions_taken**: Performed web searches for "PHPUnit eval-stdin.php vulnerability" and "Honeytrap port scanning cluster 5926 5925 5436 5902".
  - **key_results**:
    - Confirmed the PHPUnit activity is tied to CVE-2017-9841, an established vulnerability.
    - Provided context on the ports in the odd-service cluster, but found no mapping to a named threat.
  - **errors_or_gaps**: None.
- **agent_name**: ReportAgent
  - **purpose**: Compile the final report from all workflow state outputs.
  - **inputs_used**: `investigation_start`, `investigation_end`, `candidate_discovery_result`, `validated_candidates`, `deep_investigation_log`, `osint_validation_result`.
  - **actions_taken**: Synthesized all inputs into the final formatted markdown report.
  - **key_results**: This report.
  - **errors_or_gaps**: Noted degraded mode due to upstream tool failures.
- **agent_name**: SaveReportAgent
  - **purpose**: Save the final report artifact.
  - **inputs_used**: Final report content from ReportAgent.
  - **actions_taken**: Called `investigation_write_file`.
  - **key_results**: Pending.
  - **errors_or_gaps**: None.
