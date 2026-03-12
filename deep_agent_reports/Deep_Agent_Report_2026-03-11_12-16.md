# Threat Hunt Final Report

## 1. Investigation Scope
- **investigation_start**: 2026-03-11T12:00:05Z
- **investigation_end**: 2026-03-11T16:00:05Z
- **completion_status**: Partial (degraded evidence)
- **degraded_mode**: true. Evidence gathering was blocked for two candidates (ODD-01, BOT-01) due to backend tool failures, preventing full infrastructure analysis.

## 2. Executive Triage Summary
- **Top Services of Interest**: The investigation window was dominated by scanning and exploitation of VNC services (5900 series). Significant activity was also observed against web services (HTTP), SSH/Telnet, and the unencrypted Docker Engine API port (2375).
- **Odd/Minutia Services**: Probes against Industrial Control System (ICS) protocols, including IEC104 and Kamstrup, were recorded by the Conpot honeypot.
- **Top Confirmed Known Exploitation**: A large-scale campaign targeting a vintage VNC vulnerability (CVE-2006-2369) was the most voluminous event. A separate, more sophisticated web scanning campaign targeted multiple known vulnerabilities, including CVE-2017-9841 (PHPUnit) and CVE-2019-9082 (ThinkPHP).
- **Novel Exploit Candidates**: One initial candidate for a novel web exploit (NOV-01) was investigated. Validation and OSINT research confirmed that all associated activity mapped to multiple, well-known public CVEs. No novel exploit candidates were confirmed.
- **Botnet/Campaign Highlights**:
    - A multi-exploit web scanning campaign was mapped, originating from `178.251.232.252` and linked to `47.253.5.130`. This campaign systematically tested for a wide range of common web application vulnerabilities.
    - A widespread credential stuffing campaign was identified using the username 'solana', consistent with known botnet activity targeting cryptocurrency-related infrastructure.
- **Major Uncertainties**:
    - The full scope and source infrastructure of the VNC exploitation campaign (BOT-01) could not be mapped due to a logging anomaly.
    - No source IPs or infrastructure details could be gathered for the ICS protocol scanning (ODD-01) due to a data pipeline failure for the Conpot honeypot.

## 3. Candidate Discovery Summary
- The discovery phase analyzed 18,826 attacks and synthesized baseline, known signal, credential, and honeypot-specific data streams.
- Five candidates were generated for validation:
    - **NOV-01**: Web exploit attempts (CGI, PHP RFI, PHPUnit) seen in the Tanner honeypot.
    - **BOT-01**: High-volume VNC exploitation mapped to CVE-2006-2369.
    - **ODD-01**: ICS protocol (IEC104, Kamstrup) activity in the Conpot honeypot.
    - **ODD-02**: A suspected TLS handshake on a non-TLS Redis port.
    - **MIN-01**: A cluster of credential stuffing attempts using the username 'solana'.
- Discovery was materially affected by an initial inability to query for the 'solana' username events, which was resolved during the validation phase.

## 4. Botnet/Campaign Infrastructure Mapping

### item_id: MULTI-EXPLOIT-01 (Related to NOV-01)
- **campaign_shape**: fan-out
- **suspected_compromised_src_ips**: `178.251.232.252` (primary), `112.51.27.81`, `47.253.5.130`
- **ASNs / geo hints**: AS214673 (mijn.host B.V., NL), AS9808 (China Mobile, CN), AS45102 (Alibaba US Technology Co., Ltd., US)
- **suspected_staging indicators**: None identified.
- **suspected_c2 indicators**: None identified.
- **confidence**: High
- **operational_notes**: A coordinated, multi-vulnerability web scanner. The link between `178.251.232.252` and `47.253.5.130` was confirmed through shared targeting of the Docker Engine API.

### item_id: CRYPTO-CREDS-01 (MIN-01)
- **campaign_shape**: spray
- **suspected_compromised_src_ips**: `2.57.122.96`, `159.65.19.149`, `209.38.145.27`, `137.184.173.103`, `138.197.206.65` (and others).
- **ASNs / geo hints**: AS47890 (Unmanaged Ltd, RO), AS14061 (DigitalOcean, LLC, US/CA/GB)
- **suspected_staging indicators**: None identified.
- **suspected_c2 indicators**: None identified.
- **confidence**: High
- **operational_notes**: Confirmed as a known credential stuffing pattern targeting cryptocurrency services by using the 'solana' username. Infrastructure is distributed across multiple hosting providers.

### item_id: VNC-EXPLOIT-01 (BOT-01)
- **campaign_shape**: fan-in (Provisional, based on flawed data)
- **suspected_compromised_src_ips**: `79.124.40.98` (Provisional, only IP visible due to logging anomaly)
- **ASNs / geo hints**: Unavailable
- **suspected_staging indicators**: None identified.
- **suspected_c2 indicators**: None identified.
- **confidence**: Medium
- **operational_notes**: Commodity scanning for CVE-2006-2369. The infrastructure mapping is incomplete and unreliable due to a backend logging issue preventing correct attribution of external source IPs.

## 5. Odd-Service / Minutia Attacks

### service_fingerprint: ICS Protocol Probing (ODD-01, Provisional)
- **why it’s unusual/interesting**: Probing of uncommon Industrial Control System (ICS) protocols suggests either targeted reconnaissance against operational technology or broad, non-specific scanning for any open industrial ports.
- **evidence_summary**:
    - Protocol `IEC104`: 18 counts
    - Protocol `kamstrup_protocol`: 12 counts
    - Protocol `guardian_ast`: 10 counts
- **confidence**: Low
- **recommended monitoring pivots**: This finding is provisional. The immediate follow-up is to troubleshoot the data pipeline for the Conpot honeypot to enable source IP and payload analysis in future investigations.

## 6. Known-Exploit / Commodity Exclusions
- **VNC Exploitation (CVE-2006-2369)**: High-volume scanning (`~19.8k` events) and exploitation (517 events) of a well-known 2006 VNC authentication bypass vulnerability. This is considered commodity background noise.
- **Multi-Vulnerability Web Scanning**: The activity from candidate `NOV-01` was reclassified here. It consists of a scanner testing for a playbook of known web vulnerabilities, including PHPUnit RCE (CVE-2017-9841), ThinkPHP RCE (CVE-2019-9082), pearcmd LFI-to-RCE, and Docker API enumeration.
- **Credential Stuffing**: Standard brute-force attempts using common usernames (`root`, `admin`) and passwords (`123456`, `password`). The 'solana' campaign, while themed, is also a known commodity pattern.
- **Benign Internet Scanning**: An apparent TLS handshake on the Redis port (candidate `ODD-02`) was sourced from `66.132.153.135` (AS398324, Censys, Inc.) and is confirmed as benign research scanning.
- **Miscellaneous Scanning**: Generic scanning for Microsoft Terminal Server on non-standard ports was observed and excluded as noise.

## 7. Infrastructure & Behavioral Classification
- **Exploitation vs Scanning**: The VNC, web, and credential stuffing campaigns were all classified as automated **exploitation**. The ICS activity is classified as **scanning**.
- **Campaign Shape**: The web exploit campaign showed a **fan-out** shape (one IP, many exploit paths). The 'solana' credential stuffing was a **spray** (many IPs, one target theme). The VNC campaign appeared as a **fan-in** due to flawed data.
- **Infra Reuse Indicators**: The web scanning actor (`178.251.232.252`) reused infrastructure to launch multiple different attacks. It was linked to a second IP (`47.253.5.130`) through a shared target (Docker API). The 'solana' campaign reused infrastructure across two primary ASNs (DigitalOcean, Unmanaged Ltd).
- **Odd-Service Fingerprints**: ICS protocols `IEC104` and `Kamstrup` were the primary odd-service fingerprints observed.

## 8. Evidence Appendix

### Appendix Item: Multi-Exploit Web Scanner (MULTI-EXPLOIT-01)
- **source IPs**: `178.251.232.252` (189 events), `47.253.5.130` (1 event), `112.51.27.81` (1 event)
- **ASNs**: AS214673 (mijn.host B.V.), AS45102 (Alibaba US Technology Co., Ltd.), AS9808 (China Mobile)
- **target ports/services**: HTTP (Tanner Honeypot), Docker API (port 2375)
- **paths/endpoints**:
    - `/cgi-bin/.%2e/.../bin/sh`
    - `/V2/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php` (CVE-2017-9841)
    - `/?%ADd+allow_url_include%3d1+%ADd+auto_prepend_file%3dphp://input`
    - `/index.php?s=/index/\think\app/invokefunction...` (CVE-2019-9082)
    - `/index.php?lang=../../.../pearcmd&+config-create...`
    - `/containers/json` (Docker API)
- **temporal checks**: Activity from primary IP `178.251.232.252` spanned from 2026-03-11T12:03:06Z to 2026-03-11T14:45:07Z.

### Appendix Item: 'solana' Credential Stuffing Campaign (CRYPTO-CREDS-01)
- **source IPs with counts**: `2.57.122.96` (12), `159.65.19.149` (10), `209.38.145.27` (8), `137.184.173.103` (8), `138.197.206.65` (5), and more.
- **ASNs with counts**: AS14061 (DigitalOcean, LLC), AS47890 (Unmanaged Ltd)
- **target ports/services**: SSH/Telnet (Cowrie Honeypot)
- **payload/artifact excerpts**: `username: "solana"`

### Appendix Item: VNC Exploitation Campaign (VNC-EXPLOIT-01)
- **source IPs with counts**: `79.124.40.98` (Provisional, count unavailable)
- **ASNs with counts**: Unavailable
- **target ports/services**: VNC (multiple ports)
- **payload/artifact excerpts**: `alert.signature: "ET EXPLOIT VNC Server Not Requiring Authentication (case 2)"`, `alert.cve_id: "CVE-2006-2369"`
- **temporal checks**: Unavailable due to logging issues.

## 9. Indicators of Interest
- **IPs**:
    - `178.251.232.252` (Primary multi-vulnerability web scanner)
    - `47.253.5.130` (Linked Docker API scanner)
    - `2.57.122.96` (Top 'solana' credential stuffer)
    - `159.65.19.149` (Top 'solana' credential stuffer)
- **Paths**:
    - `/V2/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php`
    - `/index.php?s=/index/\think\app/invokefunction`
    - `/index.php?lang=../../../../../../../../usr/local/lib/php/pearcmd`
    - `/containers/json`
- **Payload Fragments / Usernames**:
    - `username: solana`

## 10. Backend Tool Issues
- **kibanna_discover_query**: The tool failed to return any results for `type:Conpot`. This completely blocked the validation of source IPs, payloads, and infrastructure for the ICS scanning candidate (`ODD-01`), reducing its confidence to Low and marking it Provisional.
- **two_level_terms_aggregated**: The tool failed to return any results when attempting to aggregate source IPs for the VNC exploit signature (`BOT-01`). This failure, combined with anomalous raw logs showing an internal source IP, prevented a full mapping of the VNC campaign's external infrastructure and weakened conclusions about its shape.

## 11. Agent Action Summary (Audit Trail)

### ParallelInvestigationAgent
- **purpose**: Perform initial broad data gathering.
- **inputs_used**: `investigation_start`, `investigation_end`.
- **actions_taken**: Executed four sub-agents (Baseline, KnownSignal, CredentialNoise, HoneypotSpecific) which ran 15+ initial data collection queries.
- **key_results**: Established baseline of 18,826 attacks; identified VNC CVE-2006-2369 as top signal; found 'solana' username cluster; discovered web exploit paths in Tanner and ICS protocols in Conpot.
- **errors_or_gaps**: None.

### CandidateDiscoveryAgent
- **purpose**: Merge parallel results into a unified view and generate investigation candidates.
- **inputs_used**: `baseline_result`, `known_signals_result`, `credential_noise_result`, `honeypot_specific_result`.
- **actions_taken**: Synthesized inputs, ran 3 clarifying queries, and defined 5 candidates, exclusions, and initial triage summary.
- **key_results**: Produced candidates `NOV-01`, `BOT-01`, `ODD-01`, `ODD-02`, `MIN-01`.
- **errors_or_gaps**: Initial query for 'solana' events failed, but this was corrected later in the pipeline.

### CandidateValidationLoopAgent
- **purpose**: Iteratively validate, classify, and enrich each candidate.
- **inputs_used**: `candidate_discovery_result`.
- **actions_taken**: Ran 5 iterations, validating all 5 candidates. Performed 10+ queries (`kibanna_discover_query`, `search`, etc.) to get event details and OSINT context.
- **key_results**: Reclassified `NOV-01` as a known exploit campaign. Mapped `ODD-02` to a benign scanner. Mapped `MIN-01` to a known botnet pattern. Gathered initial infrastructure for all candidates where data was available.
- **errors_or_gaps**: Blocked on `ODD-01` due to a `kibanna_discover_query` failure. Partially blocked on `BOT-01` due to a `two_level_terms_aggregated` failure.

### DeepInvestigationLoopController
- **purpose**: Conduct deep-dive analysis on high-value leads from validated candidates.
- **inputs_used**: `validated_candidates`.
- **actions_taken**: Ran 5 iterations. Consumed 5 leads related to the web scanning campaign (`NOV-01`) and the Docker API service (`service:2375`). Generated 13 new leads for future investigation.
- **key_results**: Mapped the playbook of the web scanner at `178.251.232.252`. Linked its activity to a second IP (`47.253.5.130`). Discovered a wider set of scanners targeting port 2375.
- **errors_or_gaps**: Exited loop after 5 iterations; 8 leads remained in the queue.

### OSINTAgent
- **purpose**: Provide public-domain context and knownness assessment for all validated candidates.
- **inputs_used**: `validated_candidates`.
- **actions_taken**: Ran 5 sets of OSINT searches against indicators for each of the 5 candidates.
- **key_results**: Confirmed all identified activities correspond to established, publicly documented exploits, botnet patterns, or benign scanners. This reduced the novelty score of all candidates to zero.
- **errors_or_gaps**: None.

### ReportAgent
- **purpose**: Compile the final report from all workflow state outputs.
- **inputs_used**: All preceding agent outputs.
- **actions_taken**: Assembled this markdown report.
- **key_results**: The report content.
- **errors_or_gaps**: None.

### SaveReportAgent
- **purpose**: Persist the final report.
- **inputs_used**: `ReportAgent` output.
- **actions_taken**: Will call `deep_agent_write_file` with the generated report content.
- **key_results**: File write status (pending).
- **errors_or_gaps**: None.
