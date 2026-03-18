# Honeypot Threat Hunting Final Report

### **1) Investigation Scope**
- **investigation_start**: 2026-03-09T18:00:09Z
- **investigation_end**: 2026-03-09T21:00:09Z
- **completion_status**: Partial (degraded evidence)
- **degraded_mode**: true
  - **Reason**: Data pipeline or indexing issues prevented the correlation of source IPs for two key activities: Redis RCE attempts and Kamstrup ICS protocol scanning. This blocked full infrastructure analysis for these events.

### **2) Executive Triage Summary**
- **Top Services of Interest**:
  - **Redis (Port 6379)**: Observed attempts to achieve Remote Code Execution (RCE) using the `MODULE LOAD` command, a known exploitation technique.
  - **HTTP (Port 80)**: A coordinated web scanning campaign was identified, systematically probing for file upload and webhook-related vulnerabilities (`/form/*` and `/webhook/*` paths).
  - **Kamstrup Protocol (Conpot Honeypot)**: Targeted scanning activity was observed against this uncommon Industrial Control System (ICS) protocol used in smart utility meters.
- **Top Confirmed Known Exploitation**:
  - The observed Redis activity, involving `CONFIG SET` and `MODULE LOAD` commands, is a well-documented RCE technique.
  - The widespread HTTP scanning for administrative paths (`/form/admin/upload`) and webhook endpoints is indicative of a botnet searching for common web application vulnerabilities.
- **Botnet/Campaign Mapping Highlights**:
  - A high-confidence botnet campaign, `botnet-form-scan-fr`, was mapped. It originates from AS211590 (Bucklog SARL, France), involves a cluster of coordinated source IPs, and uses a consistent user agent (`curl/8.7.1`) to probe for vulnerabilities.
- **Major Uncertainties**:
  - The source IPs and infrastructure responsible for the Redis RCE attempts and the Kamstrup protocol scanning remain unknown due to backend data correlation failures.

### **3) Candidate Discovery Summary**
- The initial discovery phase successfully triaged over 26,000 events to identify three primary areas of interest:
  - **Redis RCE Attempts**: `MODULE LOAD` commands were detected in the Redis honeypot, indicating a clear attempt at exploitation.
  - **Coordinated Web Scanning**: A cluster of IPs from a single ASN (211590) were found systematically scanning for `/form/*` paths on the Tanner web honeypot.
  - **ICS Protocol Scanning**: The Conpot honeypot registered 30 events exclusively targeting the `kamstrup_protocol`, an unusual signal pointing to specialized scanning.
- Data pipeline failures were noted at this stage, as attempts to correlate Redis and Conpot events with source IPs returned no results, flagging these as provisional candidates requiring further validation.

### **6) Botnet/Campaign Infrastructure Mapping**

**Item 1: Webhook & File Upload Scanning Botnet**
- **item_id**: botnet-form-scan-fr
- **campaign_shape**: spray
- **suspected_compromised_src_ips**: `185.177.72.51`, `185.177.72.52`, `185.177.72.22`, `185.177.72.23`, `185.177.72.30`
- **ASNs / geo hints**: AS211590 (Bucklog SARL, France)
- **suspected_staging indicators**: N/A
- **suspected_c2 indicators**: N/A
- **confidence**: High
- **operational_notes**: This is a highly coordinated campaign systematically probing for a wide range of file upload and webhook-related vulnerabilities. All identified activity uses the user agent `curl/8.7.1`. Detection can be based on the combination of source ASN, the consistent user agent, and requests for paths like `/form/admin/upload` or `/webhook/multipart`.

**Item 2: Unattributed Redis RCE Attempts**
- **item_id**: redis-rce-campaign-provisional
- **related_candidate_id(s)**: exploit-redis-rce-1
- **campaign_shape**: unknown
- **suspected_compromised_src_ips**: Unknown (Data Gap)
- **ASNs / geo hints**: Unknown (Data Gap)
- **suspected_staging indicators**: The payload `exp.so` suggests a staging artifact, likely delivered via a separate mechanism.
- **suspected_c2 indicators**: N/A
- **confidence**: Medium (that this is part of a campaign), Low (on infrastructure details)
- **operational_notes**: While the source is unknown, the observed TTPs (using `CONFIG SET` and `MODULE LOAD`) are a known method for RCE. The immediate operational priority is to fix the data pipeline to attribute future, similar events to their source.

### **7) Odd-Service / Minutia Attacks**

**Item 1: Kamstrup Smart Meter Scanning**
- **service_fingerprint**: kamstrup_protocol (ICS/SCADA Smart Meter)
- **why it’s unusual/interesting**: This is a proprietary protocol for smart utility meters. Targeted scanning indicates actors are specifically seeking out and enumerating specialized ICS infrastructure, which is a higher-signal activity than general-purpose port scanning.
- **evidence summary**: 30 events recorded on the Conpot honeypot, all targeting `kamstrup_protocol`.
- **confidence**: Medium (Provisional)
- **recommended monitoring pivots**: Fix the data pipeline issue to enable source IP correlation. Monitor any identified IPs for further ICS-related scanning activity (e.g., Modbus, S7).

### **8) Known-Exploit / Commodity Exclusions**
- **Redis RCE Attempts**: The observed sequence of `CONFIG SET` and `MODULE LOAD` commands is a well-documented RCE technique. OSINT validation confirmed this is an established, non-novel attack pattern.
- **VNC Scanning**: Widespread commodity scanning activity identified by 20,162 hits for the signature "GPL INFO VNC server response". This is background noise.
- **Credential Brute-Force/Stuffing**: Standard attempts using common usernames (`root`, `admin`, `user`) and predictable passwords (`123456`, `password`, `12345678`).
- **Terminal Server Scanning**: 819 events matching "ET SCAN MS Terminal Server Traffic on Non-standard Port" indicate broad scanning for exposed RDP or similar services.

### **9) Infrastructure & Behavioral Classification**
- **botnet-form-scan-fr**:
  - **Classification**: Coordinated Exploitation Scanning.
  - **Campaign Shape**: Spray (multiple IPs from one ASN).
  - **Infra Reuse**: High (Source IPs from a single /24 range within ASN 211590, consistent `curl/8.7.1` user agent).
  - **Fingerprint**: HTTP (port 80) requests targeting a large, scripted list of `/form/*` and `/webhook/*` paths.
- **redis-rce-campaign-provisional**:
  - **Classification**: Exploitation.
  - **Campaign Shape**: Unknown.
  - **Infra Reuse**: Unknown.
  - **Fingerprint**: Redis (port 6379) command sequence: `CONFIG SET dir`, `CONFIG SET dbfilename`, `MODULE LOAD`.
- **odd-service-kamstrup**:
  - **Classification**: Scanning.
  - **Campaign Shape**: Unknown.
  - **Infra Reuse**: Unknown.
  - **Fingerprint**: Probing of the proprietary `kamstrup_protocol` on the Conpot honeypot.

### **10) Evidence Appendix**

**Item: botnet-form-scan-fr**
- **source IPs with counts**: `185.177.72.51` (862+ events), `185.177.72.52` (431+ events), `185.177.72.22` (154+ events), `185.177.72.23` (154+ events), `185.177.72.30` (154+ events).
- **ASNs with counts**: AS211590 (Bucklog SARL) accounts for the majority of this activity.
- **target ports/services**: 80 (HTTP).
- **paths/endpoints**: `/form/admin/upload`, `/form/admin/files`, `/form/api/asset`, `/webhook-test/import`, `/webhook/multipart`, `/webhook/file-upload`, `/webhook/account/avatar`, and many others.
- **payload/artifact excerpts**: `http.user_agent: 'curl/8.7.1'`
- **temporal checks results**: Activity observed in a concentrated burst around 2026-03-09T20:35:00Z.

**Item: redis-rce-campaign-provisional (exploit-redis-rce-1)**
- **source IPs with counts**: Unknown - Data Gap.
- **ASNs with counts**: Unknown - Data Gap.
- **target ports/services**: 6379 (Redis).
- **paths/endpoints**: N/A.
- **payload/artifact excerpts**: `redis.action: 'MODULE LOAD /tmp/exp.so'`, `redis.action: 'CONFIG SET dir /tmp/'`, `redis.action: 'CONFIG SET dbfilename exp.so'`.
- **temporal checks results**: unavailable.

**Item: odd-service-kamstrup**
- **source IPs with counts**: Unknown - Data Gap.
- **ASNs with counts**: Unknown - Data Gap.
- **target ports/services**: Unknown (Conpot default).
- **paths/endpoints**: N/A.
- **payload/artifact excerpts**: `conpot.protocol: kamstrup_protocol`.
- **temporal checks results**: unavailable.

### **11) Indicators of Interest**
- **IPs**: `185.177.72.51`, `185.177.72.52`, `185.177.72.22`, `185.177.72.23`, `185.177.72.30` (All part of `botnet-form-scan-fr`).
- **ASN**: `211590` (Bucklog SARL).
- **User Agent**: `curl/8.7.1` (Associated with `botnet-form-scan-fr`).
- **Paths**: `/webhook/multipart`, `/webhook/file-upload`, `/form/admin/upload`, `/webhook-test/import`.
- **Payload Fragments**: `MODULE LOAD /tmp/exp.so`.

### **12) Backend Tool Issues**
- **`two_level_terms_aggregated`**: This tool failed to correlate `redis.action.keyword` and `conpot` events with their source IPs (`src_ip.keyword`). This failure prevented attribution for the Redis RCE and Kamstrup scanning campaigns.
- **`kibanna_discover_query`**: During candidate validation, this tool failed to retrieve any raw logs for the Redis `MODULE LOAD` events, despite aggregation queries confirming their existence. This strongly indicates a data indexing or pipeline issue for Redis honeypot logs.
- **Weakened Conclusions**: The inability to attribute sources to the Redis RCE and Kamstrup scanning means that any conclusions about campaign shape, infrastructure, and actor identity for these events are blocked. The findings are marked as **Provisional**.

### **13) Agent Action Summary (Audit Trail)**

- **agent_name**: ParallelInvestigationAgent
- **purpose**: Gathers initial telemetry across different categories.
- **inputs_used**: `investigation_start`, `investigation_end`.
- **actions_taken**: Executed parallel queries for baseline statistics (total attacks, IPs, ASNs), known threat signatures (Suricata alerts, CVEs), credential noise (usernames, passwords), and honeypot-specific interactions (Redis, Conpot, Tanner).
- **key_results**:
  - Found 26,268 total attacks.
  - Identified Redis `MODULE LOAD` commands.
  - Identified `kamstrup_protocol` activity in Conpot.
  - Identified web scanning on Tanner honeypots.
  - Identified high-volume VNC scanning noise.
- **errors_or_gaps**: None.

- **agent_name**: CandidateDiscoveryAgent
- **purpose**: Sifts through parallel results to find high-signal candidates for investigation.
- **inputs_used**: `baseline_result`, `known_signals_result`, `credential_noise_result`, `honeypot_specific_result`.
- **actions_taken**: Aggregated honeypot data to identify coordinated activity. Used OSINT searches to contextualize findings.
- **key_results**:
  - Created candidate `exploit-redis-rce-1` for the Redis `MODULE LOAD` activity.
  - Created botnet mapping `botnet-form-scan-fr` for the coordinated web scanning from ASN 211590.
  - Created odd-service item `odd-service-kamstrup` for the ICS protocol scanning.
- **errors_or_gaps**: `two_level_terms_aggregated` failed to correlate IPs for Redis and Conpot events, noting a data gap in the output.

- **agent_name**: CandidateValidationLoopAgent
- **purpose**: Performs structured validation on discovered candidates.
- **iterations run**: 1 of 1.
- **actions_taken**: Attempted to query raw logs for `exploit-redis-rce-1` using `kibanna_discover_query`.
- **key_results**:
  - Confirmed the `exploit-redis-rce-1` candidate was valid but could not be attributed to a source.
  - Re-classified it as `known_exploit_campaign` based on its characteristics.
- **errors_or_gaps**: The `kibanna_discover_query` tool returned 0 results, contradicting aggregation data and blocking source IP validation.

- **agent_name**: DeepInvestigationLoopController
- **purpose**: Conducts deep-dive, context-driven analysis on high-confidence leads.
- **iterations run**: 6.
- **key_leads_pursued**: `asn:211590`, `path:/form/admin/upload`, `src_ip:185.177.72.51`, `src_ip:185.177.72.52`.
- **stall/exit reason**: The loop was exited after multiple pivots confirmed the TTPs of the `botnet-form-scan-fr` campaign were consistent and well-understood, yielding diminishing returns.
- **key_results**:
  - Expanded the known target list for `botnet-form-scan-fr` to include dozens of `/webhook/*` paths.
  - Identified the consistent user agent `curl/8.7.1` used by the campaign.
  - Confirmed the behavior was identical across multiple source IPs from the same ASN.
  - Debunked `/libhtp::request_uri_not_seen` as a logging artifact.
- **errors_or_gaps**: None.

- **agent_name**: OSINTAgent
- **purpose**: Enriches findings with open-source intelligence.
- **inputs_used**: `validated_candidates`.
- **actions_taken**: Searched for the Redis command sequence `CONFIG SET` and `MODULE LOAD`.
- **key_results**:
  - Confirmed that the Redis activity is a well-documented RCE technique.
  - This finding reduced the novelty score of the event and moved it into the "Known Exploitation" category.
- **errors_or_gaps**: None.

- **agent_name**: ReportAgent
- **purpose**: Builds finale report from workflow state (no new searching).
- **inputs_used**: All workflow state outputs.
- **actions_taken**: Synthesized all evidence, data gaps, and agent conclusions into this final report.
- **key_results**: This markdown report was generated.
- **errors_or_gaps**: Missing inputs were noted, and the `completion_status` was set to `Partial`.

- **agent_name**: SaveReportAgent
- **purpose**: Saves the final report file.
- **inputs_used**: The completed markdown report from the ReportAgent.
- **actions_taken**: Will call the file-saving tool.
- **key_results**: File write status (pending).
- **errors_or_gaps**: None.
