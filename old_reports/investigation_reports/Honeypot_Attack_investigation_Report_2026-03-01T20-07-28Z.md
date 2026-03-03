# Honeypot Threat Hunting Report

### **1) Investigation Scope**
- **investigation_start:** 2026-03-01T19:00:14Z
- **investigation_end:** 2026-03-01T20:01:10Z
- **completion_status:** Partial (degraded evidence)
- **degraded_mode:** true. The investigation was significantly impaired by persistent tool failures, primarily with the `kibanna_discover_query` tool. This prevented the retrieval of raw event data for key candidates, blocking critical validation and deep investigation steps.

### **2) Executive Triage Summary**
- **Top Services of Interest:** High-volume scanning was observed against port 445 (SMB) and port 80 (HTTP).
- **Odd/Minutia Service Activity:** Highly unusual activity involving the `kamstrup_protocol`, a protocol for smart utility meters, was detected on an Industrial Control System (ICS) honeypot. The source and intent could not be determined due to tool failures.
- **Top Confirmed Known Exploitation:** No specific n-day exploits were confirmed; however, activity consistent with scanning for known vulnerabilities (e.g., SMB exploits like EternalBlue) was widespread.
- **Unmapped Exploit-like Items:** No new exploit candidates were validated. The anomalous ICS protocol activity (`ODD-1`) remains unclassified pending manual investigation.
- **Botnet/Campaign Highlights:**
    - A coordinated web probing campaign (**BCM-1**) was identified from a cluster of IPs within `185.177.72.0/24` (AS211590, Bucklog SARL), systematically targeting specific API and form endpoints.
    - A high-volume, single-source SMB scanner (**BCM-2**) was identified from `115.84.105.205` (AS9873, Lao Telecom).
- **Major Uncertainties:** The inability to query raw event data for the `kamstrup_protocol` activity (`ODD-1`) means its source, methods, and objective are completely unknown. This is a critical intelligence gap.

### **3) Candidate Discovery Summary**
The discovery process successfully identified three items of interest from the initial telemetry: a coordinated web probing campaign (`BCM-1`), a high-volume SMB scanner (`BCM-2`), and anomalous ICS protocol activity (`ODD-1`). However, the discovery was degraded by the failure of the `kibanna_discover_query` tool, which prevented the immediate enrichment of the `ODD-1` candidate with source IP and payload context.

### **6) Botnet/Campaign Infrastructure Mapping**
**Item:** BCM-1 (Coordinated Web Probing Campaign)
- **campaign_shape:** spray
- **suspected_compromised_src_ips:** `185.177.72.13`, `185.177.72.30`, `185.177.72.51`, `185.177.72.56`
- **ASNs / geo hints:** AS211590 (Bucklog SARL, France)
- **suspected_staging indicators:**
    - `/rest/settings`
    - `/form/account/avatar`
    - `/form/admin/files`
    - `/form/admin/import`
    - `/form/admin/upload`
    - `/form/api/asset`
    - `/form/api/assets`
- **suspected_c2 indicators:** None identified.
- **confidence:** High
- **operational notes:** OSINT validation suggests this is automated reconnaissance consistent with generic API vulnerability scanners. The sequential activity from IPs in the same subnet confirms coordination. Monitor `185.177.72.0/24` for further activity.

**Item:** BCM-2 (High-Volume SMB Scanner)
- **campaign_shape:** fan-out
- **suspected_compromised_src_ips:** `115.84.105.205` (3,104 events)
- **ASNs / geo hints:** AS9873 (Lao Telecom Communication, LTC, Laos)
- **suspected_staging indicators:** None identified.
- **suspected_c2 indicators:** None identified.
- **confidence:** High
- **operational notes:** This is commodity scanning activity targeting the high-risk SMB port 445. The behavior is consistent with actors searching for unpatched systems vulnerable to exploits like EternalBlue. The source IP should be blocked.

### **7) Odd-Service / Minutia Attacks**
**Item:** ODD-1 (Kamstrup Protocol Interaction)
- **service_fingerprint:** protocol: `kamstrup_protocol`, app_hint: `Conpot (ICS Honeypot)`
- **why it’s unusual/interesting:** This is a niche protocol used for smart utility meters. Unsolicited interaction is highly anomalous and suggests specific, targeted interest in Operational Technology (OT) or Industrial Control Systems (ICS), which is distinct from general internet noise.
- **evidence summary:** 3 events were recorded by the Conpot honeypot. All attempts to validate this activity and retrieve source IP or payload data failed due to recurring tool errors.
- **confidence:** Low (Provisional)
- **recommended monitoring pivots:** This requires high-priority manual investigation. Direct queries must be run against Conpot logs for the investigation timeframe to identify the source actor and their methods.

### **8) Known-Exploit / Commodity Exclusions**
- **Credential Noise:** Standard SSH brute-force attempts using common usernames (`root`, `admin`, `user`) and passwords (`123456`, `password`) were observed and are classified as background noise.
- **Known Scanning Patterns:**
    - High-volume scanning on port 445 (SMB) from `115.84.105.205` is consistent with well-known commodity scanners searching for vulnerable Windows services.
    - Scanning on ports 5925 and 5926 triggering "GPL INFO VNC server response" alerts is typical of broad, untargeted VNC reconnaissance.
- **Generic Web Probing:** The coordinated scanning of common API and form endpoints (Campaign `BCM-1`) is characteristic of generic vulnerability scanners and is excluded as a novel threat.

### **9) Infrastructure & Behavioral Classification**
- **BCM-1 (Web Probing):** Classified as **scanning**. Campaign shape is **spray** from a coordinated block of IPs (`185.177.72.0/24`) showing infrastructure reuse. The targeted paths are an odd-service fingerprint for API vulnerability discovery.
- **BCM-2 (SMB Scanning):** Classified as **scanning**. Campaign shape is **fan-out** from a single, high-volume source. The target (port 445) is a standard, high-risk service.
- **ODD-1 (ICS Protocol):** Classified as **monitor**. The intent is unknown (could be scanning or exploitation attempt). Campaign shape and infrastructure are unknown due to evidence gaps. The service fingerprint (`kamstrup_protocol`) is highly unusual.

### **10) Evidence Appendix**
**Item:** BCM-1
- **source IPs:** `185.177.72.13`, `185.177.72.30`, `185.177.72.51`, `185.177.72.56`
- **ASNs:** 211590 (Bucklog SARL)
- **target ports/services:** 80 (HTTP)
- **paths/endpoints:** `/`, `/rest/settings`, `/form/account/avatar`, `/form/admin/files`, `/form/admin/import`, `/form/admin/upload`, `/form/api/asset`, `/form/api/assets`, `/form/api/attachment`, `/form/api/attachments`
- **payload/artifact excerpts:** Unavailable due to tool failures.
- **temporal checks results:** IPs were active in short, sequential bursts, e.g., `185.177.72.13` (19:27-19:40 UTC) followed by `185.177.72.30` (19:43-19:57 UTC).

**Item:** BCM-2
- **source IPs:** `115.84.105.205` (3104 events)
- **ASNs:** 9873 (Lao Telecom Communication, LTC)
- **target ports/services:** 445 (SMB)
- **payload/artifact excerpts:** Unavailable.
- **temporal checks results:** Activity was continuous throughout the 60-minute window.

**Item:** ODD-1
- **source IPs:** unavailable
- **ASNs:** unavailable
- **target ports/services:** `kamstrup_protocol` (Conpot)
- **payload/artifact excerpts:** unavailable
- **temporal checks results:** unavailable

### **11) Indicators of Interest**
- **IPs:**
    - `185.177.72.13` (API Scanner)
    - `185.177.72.30` (API Scanner)
    - `185.177.72.51` (API Scanner)
    - `185.177.72.56` (API Scanner)
    - `115.84.105.205` (SMB Scanner)
- **ASN:**
    - `211590` (Bucklog SARL)
- **Paths (for API security monitoring):**
    - `/rest/settings`
    - `/form/api/asset`
    - `/form/api/attachments`
- **Protocols (for monitoring):**
    - `kamstrup_protocol`

### **12) Backend Tool Issues**
- **`kibanna_discover_query`:** This tool failed repeatedly with an `illegal_argument_exception`.
    - **Affected Validations:** This failure directly blocked the validation of candidate `ODD-1`, preventing the identification of the source IP(s) and payloads for the anomalous `kamstrup_protocol` activity. It also blocked the deep investigation of campaign `BCM-1` by preventing the retrieval of application-layer details from Tanner honeypot events.
- **`two_level_terms_aggregated`:** This tool returned zero results during the validation of `ODD-1`, contradicting initial evidence from the honeypot agent and compounding the data retrieval issue.
- **Weakened Conclusions:** Confidence in the nature and risk of the `ODD-1` activity is critically low. The depth of analysis for campaign `BCM-1` was limited to flow data, missing key details on attacker TTPs.

### **13) Agent Action Summary (Audit Trail)**
- **agent_name:** ParallelInvestigationAgent
  - **purpose:** Gathers initial baseline, known signal, credential, and honeypot-specific telemetry.
  - **inputs_used:** investigation timeframe.
  - **actions_taken:** Executed parallel queries for total attacks, top IPs/ASNs/countries, alert signatures, CVEs, credential stuffing, and honeypot-specific data.
  - **key_results:**
    - Identified 14,028 total attacks.
    - Flagged high-volume SMB scanning from `115.84.105.205`.
    - Detected commodity VNC and web scanning signatures.
    - Noted 3 events for the unusual `kamstrup_protocol` on the Conpot honeypot.
  - **errors_or_gaps:** None.
- **agent_name:** CandidateDiscoveryAgent
  - **purpose:** Merges parallel data streams to identify and rank potential threat candidates.
  - **inputs_used:** baseline_result, known_signals_result, credential_noise_result, honeypot_specific_result.
  - **actions_taken:** Aggregated data to identify coordinated activity and anomalies.
  - **key_results:**
    - Identified web probing campaign `BCM-1`.
    - Identified SMB scanning campaign `BCM-2`.
    - Identified odd-service candidate `ODD-1` (kamstrup_protocol).
  - **errors_or_gaps:** The `kibanna_discover_query` tool failed, creating an evidence gap for the `ODD-1` candidate from the start.
- **agent_name:** CandidateValidationLoopAgent
  - **purpose:** Performs focused validation checks on a single candidate.
  - **inputs_used:** candidate `ODD-1` from discovery.
  - **actions_taken:** Ran 1 iteration. Attempted to query for raw events and source IPs related to Conpot and `kamstrup_protocol`.
  - **key_results:** Validation completely failed. The candidate `ODD-1` was marked as `provisional` with `Low` confidence.
  - **errors_or_gaps:** Blocked by multiple tool failures (`kibanna_discover_query`, `two_level_terms_aggregated`), preventing source IP identification and payload inspection.
- **agent_name:** DeepInvestigationLoopController
  - **purpose:** Conducts iterative, deep-dive analysis on high-value leads.
  - **inputs_used:** leads from discovery (`BCM-1`) and failed validation (`ODD-1`).
  - **actions_taken:** Ran 3 iterations. Attempted to investigate `ODD-1` lead (stalled). Pivoted to `BCM-1` lead, analyzing two related source IPs.
  - **key_results:**
    - Confirmed the `kamstrup_protocol` lead was un-investigable due to data visibility issues.
    - Confirmed IPs in campaign `BCM-1` operated in a sequential, automated fashion.
  - **errors_or_gaps:** Exited loop after 2 stalls caused by the recurring `kibanna_discover_query` tool failure, which blocked deeper analysis of both leads.
- **agent_name:** OSINTAgent
  - **purpose:** Enriches validated candidates with open-source intelligence.
  - **inputs_used:** candidates `ODD-1`, `BCM-1`, `BCM-2`.
  - **actions_taken:** Performed web searches for protocols, IPs, and URL paths.
  - **key_results:**
    - Confirmed `kamstrup_protocol` is a legitimate but niche ICS protocol, increasing concern over unsolicited activity.
    - Confirmed that behaviors for `BCM-1` and `BCM-2` are consistent with established, commodity scanning tools, reducing their novelty.
  - **errors_or_gaps:** None.
- **agent_name:** ReportAgent
  - **purpose:** Builds finale report from workflow state (no new searching).
  - **inputs_used:** all previous state outputs.
  - **actions_taken:** Compiled this final report.
  - **key_results:** Report generated.
  - **errors_or_gaps:** None.
- **agent_name:** SaveReportAgent
  - **purpose:** Writes the final report to its destination.
  - **inputs_used:** final report content.
  - **actions_taken:** Awaiting action to save the report.
  - **key_results:** Pending.
  - **errors_or_gaps:** Pending.