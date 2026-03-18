# Honeypot Threat Intelligence Report

## 1) Investigation Scope
- **Investigation Start**: 2026-03-09T03:00:03Z
- **Investigation End**: 2026-03-09T06:00:03Z
- **Completion Status**: Partial
- **Degraded Mode**: true
- **Reason**: The initial candidate discovery phase experienced a data query failure when attempting to identify Conpot events by their `type.keyword` due to a case-sensitivity issue. Although this specific data access challenge was subsequently resolved during candidate validation, the initial discovery was affected.

## 2) Executive Triage Summary
- **Total Attacks Observed**: 24,395 events during the 3-hour window.
- **Top Services of Interest**: VNC (ports 5902, 5907), SMB (port 445), SSH (port 22), as well as a novel focus on Ollama (port 11434), Milvus (port 19530), Radmin (port 4891), and ICS/IEC104 (port 2404).
- **Top Confirmed Known Exploitation**: Widespread commodity VNC scanning (over 17,000 events) and common SMB scanning. General SSH/Telnet brute-forcing was prevalent. A multi-port scanner (VisionHeight) was identified, leveraging infrastructure already flagged as hostile.
- **Top Unmapped Exploit-like Items**: A distinct scanning campaign targeting modern AI/ML infrastructure (Ollama LLM and Milvus Vector Database) and the Radmin remote access tool was identified as a novel exploit candidate.
- **Botnet/Campaign Mapping Highlights**: A coordinated credential stuffing campaign targeting SSH using the unique username/password pair "345gs5662d34" was mapped across diverse source IPs.
- **Major Uncertainties**: The initial technical issue with Conpot data access was resolved during validation, leading to high confidence in the characterization of all identified threats.

## 3) Candidate Discovery Summary
A total of 24,395 attacks were observed. Top source countries included the United States (8,930), Indonesia (3,151), and the Netherlands (965). Key source ASNs were DigitalOcean (4,916), PT. Telekomunikasi Selular (2,267), and The Constant Company, LLC (1,934). The most frequent alert signature was "GPL INFO VNC server response" (17,436 hits), indicating widespread VNC scanning. Top CVEs identified were CVE-2025-55182 (60 hits) and a cluster of older CVEs (CVE-2006-3602, CVE-2006-4458, CVE-2006-4542) with 57 hits.

Discovery identified:
- 1 Novel Exploit Candidate (NEC-01: targeted scans for AI/ML infrastructure and Radmin).
- 3 Botnet/Campaign Infrastructure Mappings (BCM-01: massive VNC scanning, BCM-02: coordinated credential stuffing, BCM-03: high volume SMB scanning).
- 1 Odd-Service/Minutia Attack (OSM-01: ICS/IEC104-related activity that later resolved to known scanning).

Initial discovery for Conpot events was hampered by a `kibanna_discover_query` failure (returned 0 results for `type.keyword: Conpot`), which was later resolved during validation by targeting `dest_port: 2404` and using the correct case-sensitive type `ConPot`.

## 4) Emerging n-day Exploitation
(No specific emerging n-day exploitations were identified that could be CVE-mapped or strongly signature-mapped to plausibly explain behavior distinct from novel or commodity activities.)

## 5) Novel or Zero-Day Exploit Candidates (UNMAPPED ONLY, ranked)

**Candidate ID: NEC-01**
- **Classification**: Novel exploit candidate
- **Novelty Score**: 8
- **Confidence**: High
- **Provisional**: false
- **Key Evidence**: 1,477 events. Targeted reconnaissance activity from a single source IP. Probing for Ollama large language model servers (dest_port: 11434, path: /api/tags), Milvus vector databases (dest_port: 19530, path: /v2/vectordb/collections/list), and Radmin remote access tool (dest_port: 4891). Distinct `http_user_agent: node` observed.
- **Knownness Checks Performed + Outcome**: Cross-referenced against known CVEs and Suricata signatures from initial triage; no matches found. Behavior does not match other known commodity scanning patterns in the dataset.
- **Temporal Checks**: Unavailable
- **Required Follow-up**: Recommend signature development for Ollama and Milvus API probes. Analyze other IPs from AS20473 for similar behavior to determine the full scope of this targeting methodology.

## 6) Botnet/Campaign Infrastructure Mapping

**Item ID: BCM-01**
- **Campaign Shape**: Spray / Fan-in
- **Suspected Compromised Source IPs**: Large number of IPs, primarily from US and Australia (e.g., top IPs `144.202.106.26`, `107.170.66.78`, `136.114.97.84` were major contributors to overall traffic and likely involved).
- **ASNs / Geo Hints**: Widespread, including AS14061 (DigitalOcean, US) and AS20473 (The Constant Company, LLC, US). Top countries include United States, Indonesia, Netherlands, Hong Kong, Australia.
- **Suspected Staging Indicators**: None observed.
- **Suspected C2 Indicators**: None observed.
- **Confidence**: High
- **Operational Notes**: This is commodity VNC scanning activity. Focus should be on general detection and blocking, rather than deep infrastructure analysis, unless specific exploit payloads are observed.

**Item ID: BCM-02**
- **Campaign Shape**: Spray
- **Suspected Compromised Source IPs**: `12.156.67.18`, `198.98.62.211`, `92.205.57.72`, `50.6.202.106`, and multiple others.
- **ASNs / Geo Hints**: Diverse, including AS7018 (AT&T Enterprises, LLC, US), AS53667 (FranTech Solutions, US), AS21499 (Host Europe GmbH, FR), AS19871 (Network Solutions, LLC, US).
- **Suspected Staging Indicators**: None observed.
- **Suspected C2 Indicators**: None observed.
- **Confidence**: High
- **Operational Notes**: Block source IPs and monitor for attempts using the specific credential pair (`345gs5662d34`). This indicates a coordinated credential stuffing campaign.

**Item ID: BCM-03**
- **Campaign Shape**: Fan-out / Regional Spray
- **Suspected Compromised Source IPs**: Primarily `182.8.193.5`.
- **ASNs / Geo Hints**: AS23693 (PT. Telekomunikasi Selular, Indonesia).
- **Suspected Staging Indicators**: None observed.
- **Suspected C2 Indicators**: None observed.
- **Confidence**: High
- **Operational Notes**: High volume SMB scanning from a single dominant source IP in Indonesia. Block this source IP and monitor for associated known SMB vulnerabilities.

## 7) Odd-Service / Minutia Attacks

**Item ID: OSM-01**
- **Service Fingerprint**: Port 2404 (IEC-104), Protocol: TCP. Application Hint: ICS/SCADA. Observed SSH and HTTP activity on this port.
- **Why it’s unusual/interesting**: Port 2404 is a standard port for IEC-104, an ICS/SCADA protocol. The observed attempts to communicate via SSH and HTTP on this port are anomalous for an ICS service.
- **Evidence Summary**: 36 events from `src_ip:3.131.220.121` targeting the `ConPot` honeypot. Suricata alerts, including "ET COMPROMISED Known Compromised or Hostile Host Traffic group 15", were triggered. HTTP requests contained a distinctive user agent: `visionheight.com/scan Mozilla/5.0...`.
- **Confidence**: High
- **Recommended Monitoring Pivots**: Monitor for `visionheight.com` domains, the `visionheight.com/scan` user agent, and any activity triggering the `ET COMPROMISED` Suricata signature, particularly group 15. The source IP `3.131.220.121` is a broad, multi-port scanner now attributed to a known security research firm (VisionHeight) but is also on threat intelligence blocklists.

## 8) Known-Exploit / Commodity Exclusions
- **Credential Noise**:
    - Ubiquitous brute-force attempts on SSH/Telnet services using common usernames (e.g., `root`, `admin`, `test`, `user`) and weak passwords (e.g., `123456`, `password`). This activity was observed across numerous source IPs and is typical low-value background noise.
- **VNC Scanning**:
    - Massive (17,436 events) reconnaissance targeting VNC services (ports 5902, 5906, 5907, 5915), flagged by the "GPL INFO VNC server response" Suricata signature (ID: 2100560). This is routine commodity scanning.
- **SMB Scanning**:
    - Common automated scanning activity for Server Message Block (SMB) services on port 445, particularly a high volume originating from Indonesia. This is indicative of commodity worm activity or botnet reconnaissance.
- **Web Configuration Scanning**:
    - Opportunistic scanning for common sensitive files and configuration endpoints (e.g., `/`, `/.env`, `/actuator/gateway/routes`, `/.aws/credentials`) detected by the Tanner honeypot. These are standard reconnaissance attempts without evidence of novel exploitation payloads.

## 9) Infrastructure & Behavioral Classification
- **NEC-01 (AI/ML & Radmin Scans)**: Targeted reconnaissance and service fingerprinting for specific, modern AI/ML applications and remote administration tools. This represents a more sophisticated form of scanning. Campaign shape is "Fan-out" from the observed source IP. No clear infra reuse beyond the single observed source.
- **BCM-01 (VNC Scanning)**: Broad-area commodity scanning. Campaign shape is "Spray / Fan-in" due to numerous IPs contributing to widespread VNC probes.
- **BCM-02 (Credential Stuffing)**: Brute-force/credential testing, likely by a botnet. Campaign shape is "Spray" as multiple, geographically diverse IPs are using a distinct, shared credential pair. Infra reuse is indicated by the shared credential and diverse source IPs.
- **BCM-03 (SMB Scanning)**: Commodity scanning. Campaign shape is "Fan-out / Regional Spray" due to a single dominant IP driving high volume traffic to a specific service.
- **OSM-01 (VisionHeight Multi-Protocol Scanner)**: Active scanning by a known security research/telemetry platform. Behavior involves service fingerprinting and attempts to interpret various protocols (SSH, HTTP) on an unusual ICS port. This scanner's infrastructure (`3.131.220.121`) is part of a larger, managed scanning network that is concurrently flagged by threat intelligence as hostile (ET COMPROMISED groups).

## 10) Evidence Appendix

### NEC-01: Novel AI/ML Infrastructure and Radmin Scan
- **Source IPs with counts**: `144.202.106.26` (1477 events)
- **ASNs with counts**: AS20473 (The Constant Company, LLC, US)
- **Target Ports/Services**: 11434 (Ollama LLM), 19530 (Milvus Vector DB), 4891 (Radmin)
- **Paths/Endpoints**: `/api/tags`, `/v2/vectordb/collections/list`
- **Payload/Artifact Excerpts**: `http_user_agent: node`
- **Staging Indicators**: None observed.
- **Temporal Checks Results**: Unavailable

### BCM-01: Massive VNC Scanning Campaign
- **Source IPs with counts**: Large number of IPs, including `144.202.106.26` (also in NEC-01), `107.170.66.78` (1030 events), `136.114.97.84` (902 events)
- **ASNs with counts**: AS14061 (DigitalOcean, 4916 total events), AS20473 (The Constant Company, LLC, 1934 total events)
- **Target Ports/Services**: 5902, 5906, 5907, 5915 (VNC)
- **Paths/Endpoints**: Not explicitly detailed in raw events at this level.
- **Payload/Artifact Excerpts**: `alert.signature: GPL INFO VNC server response`
- **Staging Indicators**: None observed.
- **Temporal Checks Results**: Unavailable

### BCM-02: Coordinated Credential Stuffing Campaign
- **Source IPs with counts**: `12.156.67.18` (multiple events), `198.98.62.211` (multiple events), `92.205.57.72` (multiple events), `50.6.202.106` (multiple events)
- **ASNs with counts**: AS7018 (AT&T Enterprises, LLC, US), AS53667 (FranTech Solutions, US), AS21499 (Host Europe GmbH, FR), AS19871 (Network Solutions, LLC, US)
- **Target Ports/Services**: Port 22 (SSH/Telnet, Cowrie honeypot)
- **Paths/Endpoints**: Not applicable.
- **Payload/Artifact Excerpts**: `username: 345gs5662d34`, `password: 345gs5662d34`
- **Staging Indicators**: None observed.
- **Temporal Checks Results**: Unavailable

### BCM-03: High Volume SMB Scanning Campaign (Indonesia)
- **Source IPs with counts**: `182.8.193.5` (~2360 events targeting port 445)
- **ASNs with counts**: AS23693 (PT. Telekomunikasi Selular, Indonesia)
- **Target Ports/Services**: 445 (SMB)
- **Paths/Endpoints**: Not explicitly detailed in raw events.
- **Payload/Artifact Excerpts**: Not explicitly detailed in raw events.
- **Staging Indicators**: None observed.
- **Temporal Checks Results**: Unavailable

### OSM-01: Multi-Protocol Scanning of ICS Port 2404 by VisionHeight
- **Source IPs with counts**: `3.131.220.121` (36 Conpot-specific events; 402 total events from this IP)
- **ASNs with counts**: AS16509 (Amazon.com, Inc., US)
- **Target Ports/Services**: Primarily 2404 (IEC-104), also 110 (POP3), 8088, 2000, 7777, 8181 (SSH), 465 (SMTPS), 8728, 30000.
- **Paths/Endpoints**: `/` (for observed HTTP requests on port 2404)
- **Payload/Artifact Excerpts**: `http_user_agent: visionheight.com/scan Mozilla/5.0...`, `alert.signature: ET COMPROMISED Known Compromised or Hostile Host Traffic group 15`, `type: ConPot`.
- **Staging Indicators**: None observed.
- **Temporal Checks Results**: First seen: 2026-03-09T03:04:34Z, Last seen: 2026-03-09T04:55:43Z.

## 11) Indicators of Interest
- **Source IPs**:
    - `144.202.106.26` (Novel AI/ML & Radmin scans, also VNC scanning)
    - `3.131.220.121` (VisionHeight scanner, ET COMPROMISED group 15, multi-port scanner)
    - `182.8.193.5` (High volume SMB scanner)
    - `12.156.67.18`, `198.98.62.211`, `92.205.57.72`, `50.6.202.106` (Credential stuffing campaign)
    - `213.209.159.159`, `2.57.121.25`, `2.57.121.112` (ET COMPROMISED groups 13 & 14, SSH scanners)
- **Target Ports**: `11434` (Ollama), `19530` (Milvus), `4891` (Radmin), `2404` (IEC-104)
- **Paths/Endpoints**: `/api/tags`, `/v2/vectordb/collections/list`, `/.env`, `/.aws/credentials`
- **User Agents**: `node`, `visionheight.com/scan Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/126.0.0.0 Safari/537.36`
- **Credentials**: `username: 345gs5662d34`, `password: 345gs5662d34`
- **Domains**: `visionheight.com` (associated with scanning activity)
- **Suricata Signature IDs**: `2500028` (ET COMPROMISED Known Compromised or Hostile Host Traffic group 15), `2001984` (ET INFO SSH session in progress on Unusual Port), `2038967` (ET INFO SSH-2.0-Go version string Observed in Network Traffic)

## 12) Backend Tool Issues
- **Tool**: `kibanna_discover_query`
- **Issue**: During the Candidate Discovery phase, a query for `term="type.keyword", value="Conpot"` returned 0 results, indicating a data access issue.
- **Affected Validations**: This initially prevented the direct identification and validation of source IPs and full context for the ICS protocol activity reported by the HoneypotSpecificAgent.
- **Impact**: The initial characterization of the ICS activity (OSM-01) remained provisional until the Candidate Validation Agent successfully re-queried for events on `dest_port: 2404` and discovered the correct case-sensitive `type: ConPot` field, resolving the data discrepancy. This issue contributed to the overall `degraded_mode` status for the discovery phase, although the underlying data was eventually retrieved.

## 13) Agent Action Summary (Audit Trail)

- **ParallelInvestigationAgent (and its sub-agents)**
    - **Purpose**: Collect baseline telemetry and initial signals for known activity, credential-related events, and honeypot-specific interactions.
    - **Inputs Used**: Investigation time window.
    - **Actions Taken**: Queried for total attacks, top countries, source IPs, ASNs, country-to-port mappings, top alert signatures, CVEs, alert categories, common usernames/passwords, OS distributions, and honeypot-specific activity (Redis, Adbhoney, Conpot, Tanner).
    - **Key Results**: Identified 24,395 attacks, dominant VNC scanning (17,436 alerts), unique credential stuffing attempts, and ICS protocol activity on Conpot.
    - **Errors or Gaps**: None.

- **CandidateDiscoveryAgent**
    - **Purpose**: Identify and initially classify high-signal candidates from raw telemetry for further investigation.
    - **Inputs Used**: `baseline_result`, `known_signals_result`, `credential_noise_result`, `honeypot_specific_result`.
    - **Actions Taken**: Attempted to query for `Conpot` events, queried for `src_ip:144.202.106.26` (related to VNC activity), and queried for `username.keyword:345gs5662d34` (related to credential stuffing). Classified 1 Novel Exploit Candidate, 3 Botnet/Campaign Mappings, and 1 provisional Odd-Service/Minutia Attack.
    - **Key Results**: Identified novel AI/ML and Radmin scanning, mapped a coordinated credential stuffing campaign, and categorized high-volume VNC/SMB scanning. Provisionally noted ICS activity due to query issue.
    - **Errors or Gaps**: `kibanna_discover_query` for `type.keyword: Conpot` returned 0 results, creating an initial gap in identifying Conpot activity sources.

- **CandidateValidationLoopAgent**
    - **Purpose**: Validate and enrich identified candidates, resolving ambiguities or data inconsistencies.
    - **Inputs Used**: Candidate queue (containing `OSM-01`).
    - **Actions Taken**: Ran 1 iteration. Loaded `OSM-01`. Performed `kibanna_discover_query` for `type.keyword: Conpot` (failed) and then `kibanna_discover_query` for `dest_port: 2404` (succeeded).
    - **Key Results**: Successfully validated `OSM-01`, resolving the initial data access issue by identifying `type: ConPot`. Confirmed ICS-related events from `3.131.220.121`.
    - **Errors or Gaps**: Overcame the initial `Conpot` query failure by pivoting to `dest_port` for validation.

- **DeepInvestigationLoopController**
    - **Purpose**: Conduct in-depth analysis on high-priority leads from validated candidates.
    - **Inputs Used**: Validated candidate `OSM-01` and related telemetry.
    - **Actions Taken**: Ran 5 iterations. Pursued `src_ip:3.131.220.121` (from OSM-01), then `ua:visionheight.com/scan`, then `signature:ET COMPROMISED Known Compromised or Hostile Host Traffic`, and finally `src_ip:213.209.159.159`. Exited loop after characterizing all relevant leads.
    - **Key Results**: Identified `3.131.220.121` as a VisionHeight scanner, triggering "ET COMPROMISED" alerts. Discovered other IPs associated with "ET COMPROMISED" groups (13, 14) as distinct SSH scanners. Fully characterized the initial ICS anomaly.
    - **Errors or Gaps**: None.

- **OSINTAgent**
    - **Purpose**: Enrich candidate information with public intelligence.
    - **Inputs Used**: Leads from Deep Investigation (specifically the `visionheight.com/scan` user agent).
    - **Actions Taken**: Performed an OSINT search for "What is the visionheight.com/scan user agent?".
    - **Key Results**: Confirmed `visionheight.com` is a security company operating scanners, mapping `OSM-01` activity to known scanner tooling and reducing its novelty.
    - **Errors or Gaps**: None.

- **ReportAgent**
    - **Purpose**: Compile the final report from aggregated workflow state outputs.
    - **Inputs Used**: All collected workflow state (baseline, known signals, credential noise, honeypot specific, candidate discovery, validated candidates, OSINT results, deep investigation logs).
    - **Actions Taken**: Compiled the final report according to the strict markdown format and mandatory logic.
    - **Key Results**: Generated a comprehensive threat report.
    - **Errors or Gaps**: None.

- **SaveReportAgent**
    - **Purpose**: Save the generated report to a persistent storage.
    - **Inputs Used**: (The complete markdown report content)
    - **Actions Taken**: (Implicit file write operation)
    - **Key Results**: (Status to be determined by downstream save agent)
    - **Errors or Gaps**: Not applicable for this audit trail; status will be known downstream.
