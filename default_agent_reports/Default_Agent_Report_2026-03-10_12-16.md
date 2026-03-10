# Threat Investigation Report: 2026-03-10T12:00:08Z to 2026-03-10T16:00:08Z

## 1) Investigation Scope
- **investigation_start:** 2026-03-10T12:00:08Z
- **investigation_end:** 2026-03-10T16:00:08Z
- **completion_status:** Partial
- **degraded_mode:** true
  - **Reason:** Query failures during candidate validation blocked infrastructure analysis for web scanning and ICS probing activities, preventing a complete assessment.

## 2) Executive Triage Summary
- **Top Services/Ports of Interest:** VNC (5902, 5903), SMB (445), ADB (5555), Web/HTTP (80), SSH (22), and odd-services including ICS/SCADA protocols (kamstrup, guardian_ast) and Redis (6379).
- **Top Confirmed Known Exploitation:** Activity consistent with the "Trinity" cryptocurrency mining campaign (ca. 2019) was observed via the Adbhoney sensor, exploiting open ADB ports. Widespread scanning for CVE-2006-2369 (RealVNC Auth Bypass) was also noted.
- **Top Unmapped Exploit-like Items:** Probing of proprietary ICS protocols (`kamstrup_protocol`) was observed on the Conpot honeypot. This activity is unmapped and considered provisional due to a lack of source IP data.
- **Botnet/Campaign Mapping Highlights:**
    - A single source IP (106.122.101.255) from China (AS4134) executed a full ADB-based miner installation sequence.
    - A coordinated cluster of IPs from AS211590 (Bucklog SARL, France) systematically scanned for sensitive web configuration files (`.env`, `.git/config`).
- **Major Uncertainties:** The source IP(s) and infrastructure behind the ICS protocol probing remain unknown due to tool/query failures, making it impossible to assess the campaign shape or origin.

## 3) Candidate Discovery Summary
- The discovery phase identified **3** primary candidates for validation from the period's telemetry.
- **Top Areas of Interest:**
    - **Adbhoney:** A multi-step attack sequence from a single IP installing a cryptocurrency miner.
    - **Tanner:** Coordinated scanning for sensitive files (`.env`, `.git/config`) from a cluster of related IPs.
    - **Conpot:** Probing of unusual ICS/SCADA protocols.
- **Missing Inputs/Errors:** Initial discovery queries failed to correlate source IPs with Conpot events, requiring the `ODD-ICS-PROBE-001` candidate to be marked as provisional from the outset.

## 4) Novel or Zero-Day Exploit Candidates (UNMAPPED ONLY, ranked)
*No candidates met the criteria for novel or potential zero-day exploits in this window.*

## 5) Botnet/Campaign Infrastructure Mapping
### Item 1: Trinity/UFO Miner Campaign
- **item_id:** BC-ADB-MINER-001
- **campaign_shape:** fan-out (from a single observed source)
- **suspected_compromised_src_ips:** 106.122.101.255 (ASN 4134, China)
- **ASNs / geo hints:** AS4134 (Chinanet), China
- **suspected_staging indicators:** No download URLs were captured. Payloads (`trinity`, `ufo.apk`) were present in honeypot logs.
- **suspected_c2 indicators:** None observed.
- **confidence:** High
- **operational notes:** This is a known, commodity cryptomining campaign from ~2019 targeting exposed ADB ports. The primary indicator is the IP `106.122.101.255`. Associated malware hash is `0d3c687ffc30e185b836b99bd07fa2b0d460a090626f6bbbd40a95b98ea70257`.

### Item 2: Sensitive File Scanning Campaign
- **item_id:** BC-WEB-SCAN-001
- **campaign_shape:** spray
- **suspected_compromised_src_ips:** 185.177.72.22, 185.177.72.49, 185.177.72.51, 185.177.72.52
- **ASNs / geo hints:** AS211590 (Bucklog SARL), France
- **suspected_staging indicators:** Not applicable; these IPs are the source of scanning.
- **suspected_c2 indicators:** None observed.
- **confidence:** High
- **operational notes:** This is a coordinated scanning effort from a single ASN to find exposed credentials and configuration files. This behavior is common, but the coordination from a single provider is notable for infrastructure tracking.

## 6) Odd-Service / Minutia Attacks
### Item 1: ICS Protocol Probing
- **item_id:** ODD-ICS-PROBE-001
- **service_fingerprint:** Conpot honeypot, protocols: `kamstrup_protocol` (19 events), `guardian_ast` (11 events).
- **why it’s unusual/interesting:** Kamstrup is a proprietary protocol for smart meters. Probing against it is not common background noise and suggests targeted reconnaissance against Operational Technology (OT).
- **evidence summary:** Low volume probes detected. No payload data or source IPs could be retrieved.
- **confidence:** Low (Provisional)
- **recommended monitoring pivots:** Investigate Conpot logging to ensure source IPs are captured. Continue monitoring for any probes against these protocols.

## 7) Known-Exploit / Commodity Exclusions
- **VNC Scanning (CVE-2006-2369):** High-volume activity (24,692 `GPL INFO VNC server response` alerts) targeting a well-known, dated RealVNC authentication bypass. Classified as commodity scanning.
- **SMB Scanning:** Widespread, high-volume traffic to port 445 from sources like `41.225.17.210` and `79.98.102.166`. Standard internet background noise.
- **Credential Stuffing:** Brute-force attempts using common username/password lists (`root`/`admin`, `123456`/`password`) against various services.

## 8) Infrastructure & Behavioral Classification
- **Exploitation vs. Scanning:**
    - The ADB "Trinity" activity was **exploitation**.
    - The Tanner web and Conpot ICS activity were **scanning/reconnaissance**.
- **Campaign Shape:**
    - ADB Miner: **Fan-out** (single source targeting many).
    - Web Scanner: **Spray** (multiple sources targeting many).
    - ICS Prober: **Unknown**.
- **Infra Reuse Indicators:**
    - The web scanning campaign showed clear infrastructure reuse, with multiple IPs originating from the same ASN (211590).
- **Odd-Service Fingerprints:**
    - Probing of `kamstrup_protocol` and `guardian_ast` on the Conpot honeypot.

## 9) Evidence Appendix
### BC-ADB-MINER-001 (Trinity Miner)
- **Source IPs:** `106.122.101.255` (34 Adbhoney events, 63 total events)
- **ASNs:** 4134 (Chinanet)
- **Target Ports/Services:** 5555 (Adbhoney)
- **Payload/Artifact Excerpts:**
    - `chmod 0755 /data/local/tmp/trinity`
    - `pm install /data/local/tmp/ufo.apk`
    - `am start -n com.ufo.miner/com.example.test.MainActivity`
    - `/data/local/tmp/nohup /data/local/tmp/trinity`
- **Temporal Checks:** All activity from this IP occurred within the investigation window.

### BC-WEB-SCAN-001 (Web Scanner)
- **Source IPs:** `185.177.72.49` (153 events), `185.177.72.52` (153 events), `185.177.72.22` (91 events), `185.177.72.51` (91 events)
- **ASNs:** 211590 (Bucklog SARL)
- **Target Ports/Services:** 80 (Tanner/HTTP)
- **Paths/Endpoints:** `/.env`, `/.aws/credentials`, `/.git/config`, `/%2eenv`, `/.EnV`
- **Temporal Checks:** All activity from these IPs occurred within the investigation window.

### ODD-ICS-PROBE-001 (ICS Prober)
- **Source IPs:** unavailable
- **ASNs:** unavailable
- **Target Ports/Services:** Conpot (ICS honeypot)
- **Payload/Artifact Excerpts:** `kamstrup_protocol`, `guardian_ast`
- **Temporal Checks:** unavailable

## 10) Indicators of Interest
- **IPs:**
    - `106.122.101.255` (ADB Miner)
    - `185.177.72.22` (Web Scanner)
    - `185.177.72.49` (Web Scanner)
    - `185.177.72.51` (Web Scanner)
    - `185.177.72.52` (Web Scanner)
- **ASNs:**
    - `211590` (Bucklog SARL)
- **Malware Hashes:**
    - `0d3c687ffc30e185b836b99bd07fa2b0d460a090626f6bbbd40a95b98ea70257` (Associated with Adbhoney artifact)
- **Paths:**
    - `/.env`
    - `/.git/config`
    - `/.aws/credentials`
- **Malware Artifacts:**
    - `trinity`
    - `ufo.apk`
    - `com.ufo.miner`

## 11) Backend Tool Issues
- **`two_level_terms_aggregated` (in CandidateDiscoveryAgent):** The tool failed to retrieve source IPs for Conpot activity. This weakened the `ODD-ICS-PROBE-001` candidate from its creation.
- **`kibanna_discover_query` (in CandidateValidationAgent):** This tool was misused multiple times, weakening conclusions:
    - For candidate `BC-WEB-SCAN-001`, the query was run without a `type: Tanner` filter, returning irrelevant Suricata flow logs instead of the desired Tanner logs. This blocked direct inspection of the web request payloads.
    - For candidate `ODD-ICS-PROBE-001`, a query for Conpot events (`conpot.protocol.keyword: kamstrup_protocol`) returned 0 hits, despite other data showing 19 events. This completely blocked all infrastructure analysis and suggests a data indexing or schema problem for Conpot logs.

## 12) Agent Action Summary (Audit Trail)
- **agent_name:** ParallelInvestigationAgent
  - **purpose:** Collect broad baseline and signal telemetry across multiple domains.
  - **inputs_used:** investigation_start, investigation_end.
  - **actions_taken:** Executed sub-agents for baseline, known signals, credential noise, and honeypot-specific data collection.
  - **key_results:** Total attacks (28,590), top countries (US, France), top CVEs (CVE-2006-2369), top signatures (VNC), and honeypot-specific data from Adbhoney, Conpot, etc.
  - **errors_or_gaps:** None.
- **agent_name:** CandidateDiscoveryAgent
  - **purpose:** Analyze initial telemetry to identify and prioritize potential threats.
  - **inputs_used:** Outputs from all ParallelInvestigationAgent sub-agents.
  - **actions_taken:** Aggregated data across honeypot types and attack patterns.
  - **key_results:** Identified 3 candidates: `BC-ADB-MINER-001` (Adbhoney), `BC-WEB-SCAN-001` (Tanner), `ODD-ICS-PROBE-001` (Conpot).
  - **errors_or_gaps:** Failed to correlate source IPs for Conpot activity, weakening the `ODD-ICS-PROBE-001` candidate.
- **agent_name:** CandidateValidationLoopAgent
  - **purpose:** Orchestrate the iterative validation of each discovered candidate.
  - **inputs_used:** List of 3 candidates from CandidateDiscoveryAgent.
  - **actions_taken:** Ran a validation loop for 3 iterations, processing one candidate each time. Exited normally when the candidate queue was empty.
  - **key_results:** All 3 candidates were processed, and detailed validation reports were generated.
  - **errors_or_gaps:** Loop control was successful, but validation steps within the loop encountered tool failures (see Backend Tool Issues).
- **agent_name:** OSINTAgent
  - **purpose:** Enrich validated findings with open-source intelligence.
  - **inputs_used:** Validated candidate reports.
  - **actions_taken:** Performed searches for "Trinity" malware and scanners for sensitive files like `.env`.
  - **key_results:** Correctly identified the ADB activity as the known "Trinity/UFO Miner" campaign and confirmed that scanning for `.env` files is a common technique.
  - **errors_or_gaps:** None.
- **agent_name:** ReportAgent
  - **purpose:** Compile the final report from all workflow state outputs.
  - **inputs_used:** All available state keys from previous agents.
  - **actions_taken:** Assembled this markdown report.
  - **key_results:** This report.
  - **errors_or_gaps:** Noted `Partial` status due to upstream errors.
- **agent_name:** SaveReportAgent
  - **purpose:** Persist the final report to the filesystem.
  - **inputs_used:** Content of this report.
  - **actions_taken:** Called `default_write_file`.
  - **key_results:** Pending tool execution.
  - **errors_or_gaps:** None.
