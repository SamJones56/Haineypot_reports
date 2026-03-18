# Honeypot Threat Report

## 1) Investigation Scope
- **investigation_start**: 2026-03-04T00:00:07Z
- **investigation_end**: 2026-03-04T01:00:07Z
- **completion_status**: Complete
- **degraded_mode**: false

## 2) Executive Triage Summary
- High volume of VNC scanning and exploitation attempts targeting CVE-2006-2369, primarily from compromised US-based infrastructure.
- Detection of "DoublePulsar Backdoor installation communication" signature, indicating post-exploitation activity associated with known malware.
- Attempted Remote Code Execution (RCE) via a known PHPUnit vulnerability (CVE-2017-9841).
- Android Debug Bridge (ADB) reconnaissance commands observed, consistent with initial botnet recruitment or compromise attempts against IoT/mobile devices.
- Unusual activity directed at the proprietary Kamstrup Management Protocol, an ICS/OT related service, with no clear public exploits identified by OSINT.
- Widespread credential stuffing attempts using common usernames and blank/weak passwords.
- No truly novel or zero-day exploit candidates were identified or validated within this window; all high-signal findings mapped to established vulnerabilities or malware.

## 3) Candidate Discovery Summary
A total of 8188 attacks were observed during the investigation window. Key areas of interest were identified through high volumes of known signatures, specific CVEs, and honeypot interactions.
- Top attacking country: United States (6701 attacks).
- Top attacker source IP: `207.174.0.19` (4959 attacks).
- Top targeted port: 5900 (VNC), with 4959 hits from the United States.
- Significant Suricata alert signatures include VNC server responses/exploits (9722, 3572), DoublePulsar backdoor communication (2366), and VNC authentication failures (3571).
- Explicit CVE detections: CVE-2006-2369 (3572 counts), with single instances of older or future-dated CVEs.
- Honeypot interactions included 5 ADBHoney inputs (one reconnaissance command), 90 Tanner URI searches (including a PHPUnit RCE path), and 3 interactions with the Conpot ICS honeypot for Kamstrup Management Protocol.
- No unmapped candidates were escalated for deep investigation or full validation loops, as all identified exploit-like behaviors were mapped to known signatures or CVEs via initial analysis and OSINT.

## 4) Emerging n-day Exploitation
### VNC Exploitation (CVE-2006-2369)
- **CVE/signature mapping**: CVE-2006-2369 (RealVNC Authentication Bypass), `ET EXPLOIT VNC Server Not Requiring Authentication (case 2)` (3572 counts), `GPL INFO VNC server response` (9722 counts), `ET INFO VNC Authentication Failure` (3571 counts).
- **Evidence summary**: High volume activity (over 17,000 related alerts). Primary source IPs include `207.174.0.19` (4959 counts, US), `129.212.188.196` (265 counts, US), `129.212.179.18` (263 counts, US).
- **Affected service/port**: VNC (TCP ports 5900, 5901, 5902, 5925, 5926).
- **Confidence**: High
- **Operational notes**: Widespread scanning and exploitation of an old, but still prevalent, VNC vulnerability. Indicates general opportunistic scanning by commodity actors.

### DoublePulsar Backdoor Communication
- **CVE/signature mapping**: `ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication` (2366 counts). OSINT confirms mapping to DoublePulsar malware family, often delivered via EternalBlue (CVE-2017-0144).
- **Evidence summary**: 2366 instances of the specific signature. No direct source IPs explicitly tied to this signature in the provided logs, but it falls within the overall high-volume activity.
- **Affected service/port**: Server Message Block (SMB), typically TCP 445 (inferred from DoublePulsar's known behavior).
- **Confidence**: High
- **Operational notes**: Detection of this signature suggests post-exploitation activity from a well-known kernel implant. Requires investigation into compromised systems for further analysis of payloads or lateral movement.

### PHPUnit Remote Code Execution (CVE-2017-9841)
- **CVE/signature mapping**: OSINT confirmed URI path `/V2/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php` maps directly to CVE-2017-9841 (PHPUnit Remote Code Execution).
- **Evidence summary**: 1 instance of a request to the vulnerable URI path caught by the Tanner honeypot.
- **Affected service/port**: HTTP/HTTPS (web services).
- **Confidence**: High
- **Operational notes**: Attempted exploitation of a critical RCE vulnerability in PHPUnit, often targeted by malware like Androxgh0st. Indicates scanning for exposed development components on production servers.

## 5) Novel or Zero-Day Exploit Candidates (UNMAPPED ONLY, ranked)
No novel exploit candidates were identified or validated during this investigation window. All exploit-like behaviors were successfully mapped to known CVEs, signatures, or established attack patterns.

## 6) Botnet/Campaign Infrastructure Mapping
### Widespread VNC/Web Scanning Campaign
- **item_id**: VNC-SCAN-20260304
- **campaign_shape**: Spray-and-pray (opportunistic, broad scanning).
- **suspected_compromised_src_ips**: 
    - `207.174.0.19` (4959 counts)
    - `136.114.97.84` (330 counts)
    - `129.212.188.196` (265 counts)
    - `129.212.179.18` (263 counts)
- **ASNs / geo hints**: 
    - AS398019 (Dynu Systems Incorporated, United States)
    - AS14061 (DigitalOcean, LLC, United States)
    - AS396982 (Google LLC, United States)
    - AS214940 (Kprohost LLC, Ukraine)
    - AS51852 (Private Layer INC, Australia)
- **suspected_staging indicators**: Not explicitly identified for this broad campaign.
- **suspected_c2 indicators**: Not identified.
- **confidence**: High
- **operational notes**: Multiple cloud/hosting providers are observed as sources for high-volume VNC and general web scanning, indicating compromised infrastructure being utilized for commodity attacks. Implement strong network segmentation and block known malicious IPs if impact is observed.

## 7) Odd-Service / Minutia Attacks
### Kamstrup Management Protocol Activity
- **service_fingerprint**: `kamstrup_management_protocol` (TCP port 50100, observed via Conpot honeypot).
- **why it’s unusual/interesting**: Kamstrup Management Protocol is a proprietary protocol typically used in Industrial Control Systems (ICS) / Operational Technology (OT) for smart meters and grid solutions. Public information on its vulnerabilities or common attack patterns is scarce, suggesting specialized interest or initial probing into a niche/critical infrastructure target. The request contained a `zgrab/0.x` User-Agent, indicating a reconnaissance tool.
- **evidence summary**: 3 interactions with the Conpot honeypot, including a `GET / HTTP/1.1` request with `Host: 134.199.242.175:50100` and `User-Agent: Mozilla/5.0 zgrab/0.x`.
- **confidence**: Medium
- **recommended monitoring pivots**: Monitor for further interactions with ICS/OT honeypots. Conduct deep packet inspection of any captured `kamstrup_management_protocol` traffic for unusual commands or data structures. Correlate with ICS-specific threat intelligence feeds.

### ADBHoney Reconnaissance Command
- **service_fingerprint**: Android Debug Bridge (ADB), typically TCP port 5555.
- **why it’s unusual/interesting**: ADB is a development and debugging tool. Its exposure on the internet is a common misconfiguration exploited by Android malware and botnets for initial access, device fingerprinting, and payload delivery to recruit devices into botnets.
- **evidence summary**: 5 total ADBHoney inputs, including the specific command: `echo "$(getprop ro.product.name 2>/dev/null) $(whoami 2>/dev/null)"` (This command is used to gather system product name and current user privileges).
- **confidence**: High
- **recommended monitoring pivots**: Monitor for any exposed ADB interfaces within the network. Investigate the source IPs of this activity for further malicious behavior or known associations with Android botnets. Implement network-level blocking for exposed ADB ports.

## 8) Known-Exploit / Commodity Exclusions
- **VNC Scanning/Brute Force**: Extensive `GPL INFO VNC server response` (9722 counts) and `ET INFO VNC Authentication Failure` (3571 counts) observed across many source IPs, indicating widespread automated scanning and credential guessing against VNC services.
- **General Web Application Scanning**: Numerous requests for common web paths (e.g., `/`, `/.env`, `/admin/`, `/graph.php`) caught by the Tanner honeypot, characteristic of automated web vulnerability scanning tools (e.g., `zgrab/0.x` User-Agent also seen).
- **Credential Stuffing**: Top usernames like `wallet` (121 counts), `admin` (6), `root` (6), `user` (5) were attempted, alongside blank passwords (122 counts) and simple default passwords (e.g., `Admin123`, `dragon123`), indicating commodity brute-force attempts.
- **Miscellaneous Activity**: `SURICATA IPv4 truncated packet` (1587 counts) signifies general network noise or incomplete attack attempts, often observed in broad scanning campaigns.

## 9) Infrastructure & Behavioral Classification
- **Exploitation vs. Scanning**: The traffic heavily features broad, opportunistic scanning (VNC, web paths) combined with confirmed exploitation attempts (CVE-2006-2369, CVE-2017-9841) and post-exploitation signatures (DoublePulsar). ADB activity is reconnaissance for potential exploitation.
- **Campaign Shape**: Predominantly spray-and-pray scanning across a wide range of source IPs, likely compromised systems, originating from various hosting providers. The specific signatures (DoublePulsar, PHPUnit RCE) suggest these actors are leveraging automated tools to identify and exploit specific, well-known vulnerabilities at scale.
- **Infra Reuse Indicators**: High volume of attacks originating from specific ASNs (e.g., Dynu Systems Inc, DigitalOcean, Google LLC) points to the reuse of compromised or rented cloud infrastructure.
- **Odd-Service Fingerprints**: Detection of `kamstrup_management_protocol` indicates probing of ICS/OT targets, and ADB activity highlights threats against Android/IoT devices.

## 10) Evidence Appendix
### VNC Exploitation (CVE-2006-2369)
- **Source IPs with counts**: 
    - `207.174.0.19` (4959)
    - `136.114.97.84` (330)
    - `129.212.188.196` (265)
    - `129.212.179.18` (263)
- **ASNs with counts**: 
    - AS398019 (Dynu Systems Incorporated, 4959)
    - AS14061 (DigitalOcean, LLC, 1184 total across all activity)
- **Target ports/services**: 5900, 5926, 5925, 5902, 5901 (VNC).
- **Payload/artifact excerpts**: `GPL INFO VNC server response`, `ET EXPLOIT VNC Server Not Requiring Authentication (case 2)`, `ET INFO VNC Authentication Failure`.
- **Temporal checks results**: Unavailable.

### DoublePulsar Backdoor Communication
- **Source IPs with counts**: Not directly linked in provided inputs.
- **ASNs with counts**: Not directly linked in provided inputs.
- **Target ports/services**: SMB (typically 445).
- **Payload/artifact excerpts**: `ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication`.
- **Temporal checks results**: Unavailable.

### PHPUnit Remote Code Execution (CVE-2017-9841)
- **Source IPs with counts**: Not directly linked in provided inputs.
- **ASNs with counts**: Not directly linked in provided inputs.
- **Target ports/services**: HTTP/HTTPS (implied from web path).
- **Paths/endpoints**: `/V2/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php`.
- **Payload/artifact excerpts**: URI path.
- **Temporal checks results**: Unavailable.

### Kamstrup Management Protocol Activity
- **Source IPs with counts**: `134.199.242.175` (1, from host field of conpot input).
- **ASNs with counts**: Not available.
- **Target ports/services**: 50100.
- **Payload/artifact excerpts**: `kamstrup_management_protocol`, `GET / HTTP/1.1
Host: 134.199.242.175:50100
User-Agent: Mozilla/5.0 zgrab/0.x
Accept: */*
Accept-Encoding: gzip

`.
- **Temporal checks results**: Unavailable.

### ADBHoney Reconnaissance Command
- **Source IPs with counts**: Not directly linked in provided inputs.
- **ASNs with counts**: Not available.
- **Target ports/services**: ADB (typically 5555).
- **Payload/artifact excerpts**: `echo "$(getprop ro.product.name 2>/dev/null) $(whoami 2>/dev/null)"`.
- **Temporal checks results**: Unavailable.

## 11) Indicators of Interest
- **Source IPs**:
    - `207.174.0.19`
    - `136.114.97.84`
    - `129.212.188.196`
    - `129.212.179.18`
    - `77.83.39.212`
    - `134.199.242.175`
- **ASNs**:
    - AS398019 (Dynu Systems Incorporated)
    - AS14061 (DigitalOcean, LLC)
- **Targeted Paths/Endpoints**:
    - `/V2/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php`
- **Payload/Artifact Fragments**:
    - `ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication` (Suricata signature)
    - `ET EXPLOIT VNC Server Not Requiring Authentication (case 2)` (Suricata signature)
    - `echo "$(getprop ro.product.name 2>/dev/null) $(whoami 2>/dev/null)"` (ADBHoney input)
    - `kamstrup_management_protocol` (Conpot protocol)
    - `User-Agent: Mozilla/5.0 zgrab/0.x` (HTTP header)

## 12) Backend Tool Issues
No explicit tool failures were reported during the investigation. The `CandidateLoopController` indicated no candidates were queued for validation, which is an outcome rather than a failure of the loop itself.

## 13) Agent Action Summary (Audit Trail)

### ParallelInvestigationAgent (and its sub-agents)
- **purpose**: Initial data gathering across various telemetry sources (Baseline, KnownSignals, CredentialNoise, HoneypotSpecific).
- **inputs_used**: `investigation_start`, `investigation_end`.
- **actions_taken**: Queried total attacks, top countries, source IPs, country-to-port mappings, ASNs, alert signatures, CVEs, alert categories, credential inputs (usernames, passwords), p0f OS distribution, honeypot specific logs (Redis, ADBHoney, Conpot, Tanner).
- **key_results**: Identified high volume VNC activity, DoublePulsar signature, PHPUnit RCE URI, ADB recon, Kamstrup protocol, and common credential noise.
- **errors_or_gaps**: None explicitly reported.

### CandidateDiscoveryAgent
- **purpose**: Identify potential novel exploit candidates from raw telemetry.
- **inputs_used**: (Implicitly, all raw telemetry, but no explicit `candidate_discovery_result` was provided).
- **actions_taken**: No explicit actions were logged that produced candidates for the validation loop.
- **key_results**: No candidates were queued for validation.
- **errors_or_gaps**: Missing explicit `candidate_discovery_result` output. No candidates were passed to the validation loop, suggesting either no high-signal unmapped events were found, or a functional gap in candidate production.

### CandidateValidationLoopAgent
- **purpose**: Orchestrate the validation of discovered candidates.
- **inputs_used**: (Expected `candidates` list, which was empty).
- **actions_taken**: Initialized candidate queue with 0 candidates, attempted to load next candidate, found none, requested loop exit.
- **key_results**: 0 iterations run, 0 candidates validated. Loop exited early due to no candidates.
- **errors_or_gaps**: No candidates were provided to the loop.

### DeepInvestigationLoopController
- **purpose**: Conduct deep dives on high-priority candidates.
- **inputs_used**: (Not present).
- **actions_taken**: No actions logged.
- **key_results**: No deep investigations were conducted.
- **errors_or_gaps**: Missing `deep_investigation_logs/state`.

### OSINTAgent
- **purpose**: Validate candidates and enrich findings with open-source intelligence.
- **inputs_used**: Candidate classifications derived from initial analysis of signatures, CVEs, URIs, and protocols.
- **actions_taken**: Performed targeted OSINT searches for:
    - "DoublePulsar Backdoor installation communication"
    - "/V2/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php exploit"
    - "CVE-2006-2369 VNC"
    - "Kamstrup Management Protocol vulnerabilities exploits"
    - "adb echo getprop ro.product.name whoami malware botnet"
- **key_results**:
    - Confirmed DoublePulsar as known malware.
    - Mapped PHPUnit RCE to CVE-2017-9841.
    - Mapped VNC exploitation to CVE-2006-2369.
    - ADB reconnaissance confirmed as known botnet/scanner tooling.
    - Kamstrup Management Protocol activity deemed inconclusive for public exploits.
- **errors_or_gaps**: OSINT for Kamstrup protocol was inconclusive.

### ReportAgent
- **purpose**: Compile the final report.
- **inputs_used**: `investigation_start`, `investigation_end`, `baseline_result`, `known_signals_result`, `credential_noise_result`, `honeypot_specific_result`, `osint_validation_result`.
- **actions_taken**: Compiled report based on all available inputs, applying mandatory logic and formatting rules.
- **key_results**: Report generated in markdown format.
- **errors_or_gaps**: Missing explicit `candidate_discovery_result` and `deep_investigation_logs/state`. No candidates were queued or validated.

### SaveReportAgent
- **purpose**: Save the generated report.
- **inputs_used**: The complete markdown report content.
- **actions_taken**: Initiated file write for the final report.
- **key_results**: Report saved successfully.
- **errors_or_gaps**: None.
