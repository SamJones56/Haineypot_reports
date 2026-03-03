# Threat Hunting Investigation Report: 2026-03-02

### 1) Investigation Scope
- **investigation_start:** 2026-03-02T10:00:08Z
- **investigation_end:** 2026-03-02T11:00:08Z
- **completion_status:** Partial (degraded evidence)
- **degraded_mode:** true. Investigation was materially impacted by repeated tool failures, which prevented source IP identification for multiple leads.

### 2) Executive Triage Summary
- **Top Services of Interest:** Activity was concentrated on VNC (port 5900), Android Debug Bridge (port 5555), and Redis (port 6379), alongside common services like SSH and SMB.
- **Top Unmapped/Minutia Activity:** Probing of an uncommon ICS/SCADA service (`kamstrup_protocol`) was observed but could not be fully validated due to tool errors.
- **Top Confirmed Known Exploitation:** A targeted campaign deploying the **Trinity (ADB.Miner) botnet** against exposed Android Debug Bridge interfaces was fully mapped to a single source IP.
- **Botnet/Campaign Highlights:** The Trinity botnet campaign originated from `218.205.95.160` (AS56041 - China Mobile, CN) and involved a clear, multi-step malware installation sequence.
- **Major Uncertainties:** The source of a Redis RCE attempt (`MODULE LOAD /tmp/exp.so`) and the source of the Kamstrup ICS probing could not be determined due to persistent back-end query failures, weakening the conclusions for these events.

### 3) Candidate Discovery Summary
The discovery phase identified three primary areas of interest from over 9,000 events:
- **Adbhoney:** A clear malware installation chain associated with the Trinity botnet.
- **Redishoneypot:** An RCE attempt using a `MODULE LOAD` command.
- **Conpot:** Unusual probing of the `kamstrup_protocol`, an ICS/SCADA protocol.

Discovery was materially affected by tool failures (`kibanna_discover_query`), which prevented the retrieval of source IPs for the Redis and Conpot activity streams during this phase.

### 4) Botnet/Campaign Infrastructure Mapping
**Item ID:** BOT-TRINITY-ADB
- **Campaign Shape:** Fan-out (from a single source to multiple honeypot sensors).
- **Suspected Compromised Source IPs:** `218.205.95.160` (68 events observed).
- **ASNs / Geo:** AS56041 (China Mobile communications corporation), China.
- **Suspected Staging Indicators:** The attacker used the target's `/data/local/tmp/` directory to stage malware components (`trinity`, `nohup`, `ufo.apk`). No external staging URLs were observed in the telemetry.
- **Suspected C2 Indicators:** Not directly observed. The malware `com.ufo.miner` is a known cryptominer, suggesting C2 is for mining coordination.
- **Confidence:** High.
- **Operational Notes:** The activity from this IP was self-contained and focused exclusively on ADB exploitation. The full attack chain was observed. Monitoring this IP for further ADB scanning is recommended.

### 5) Odd-Service / Minutia Attacks
**Item ID:** ICS-KAMSTRUP-PROBE
- **Service Fingerprint:** `kamstrup_protocol` (Conpot Honeypot).
- **Why Unusual:** Kamstrup is a provider of smart metering solutions for energy and water. Probing of its specific protocol is highly unusual and suggests targeted reconnaissance against ICS/SCADA or utility infrastructure.
- **Evidence Summary:** 7 events recorded, indicating low-volume probing.
- **Confidence:** Low.
- **Provisional:** True. Source IP and other details could not be retrieved due to tool failures.
- **Recommended Monitoring Pivots:** Monitor for any increase in `kamstrup_protocol` activity. A manual query review is required to resolve the data retrieval issues for Conpot events.

### 6) Known-Exploit / Commodity Exclusions
- **Trinity Botnet Deployment (ADB.Miner):** While mapped as a campaign, the Trinity botnet and its method of exploiting open ADB ports is a well-known, commodity threat.
- **Redis RCE Attempt (Known Technique):** The `MODULE LOAD /tmp/exp.so` command is a widely documented and non-novel technique for RCE against Redis. OSINT confirmed it is a feature of public exploit scripts and other known malware. The event remains provisionally attributed due to the inability to identify the source IP.
- **VNC Scanning:** High-volume scanning for VNC services (2,036 events) was identified by the signature "GPL INFO VNC server response". This is typical, non-targeted scanning behavior.
- **Credential Noise:** Widespread brute-force attempts were observed across multiple services (e.g., SSH), using common default usernames (`root`, `admin`, `user`) and passwords (`123456`, `password`).
- **Common Scanning Signatures:** Activity was attributed to routine scanning via signatures like "ET SCAN MS Terminal Server Traffic on Non-standard Port".

### 7) Infrastructure & Behavioral Classification
- **Exploitation vs. Scanning:**
    - **BOT-TRINITY-ADB (`218.205.95.160`):** Confirmed exploitation.
    - **Redis RCE Attempt:** Confirmed exploitation attempt.
    - **ICS-KAMSTRUP-PROBE:** Reconnaissance / Scanning.
    - **VNC/SSH/Web:** Widespread scanning.
- **Campaign Shape:**
    - **BOT-TRINITY-ADB:** Fan-out from a single IP.
- **Odd-Service Fingerprints:**
    - `kamstrup_protocol` on Conpot is a high-signal indicator of potential ICS-related interest.

### 8) Evidence Appendix
**BOT-TRINITY-ADB Campaign:**
- **Source IPs:** `218.205.95.160` (68 events)
- **ASNs:** AS56041 (China Mobile communications corporation) (68 events)
- **Target Ports/Services:** 5555/tcp (Android Debug Bridge)
- **Payload/Artifact Excerpts:**
    - `rm -rf /data/local/tmp/*`
    - `chmod 0755 /data/local/tmp/trinity`
    - `/data/local/tmp/nohup /data/local/tmp/trinity`
    - `pm install /data/local/tmp/ufo.apk`
    - `am start -n com.ufo.miner/com.example.test.MainActivity`
- **Related Signatures:**
    - `ET INFO Executable and linking format (ELF) file download` (SID: 2000418)
    - `ET INFO ZIP file download` (SID: 2000428)
- **Temporal Checks:** All activity occurred within a 14-minute window from 2026-03-02T10:41:12Z to 2026-03-02T10:55:10Z.

**ICS-KAMSTRUP-PROBE & REDIS-RCE-01:**
- Detailed evidence, including source IPs and temporal checks, is unavailable due to backend tool failures.

### 9) Indicators of Interest
- **IP:** `218.205.95.160` (Trinity Botnet Source)
- **ASN:** `56041` (China Mobile communications corporation)
- **Port:** `5555/tcp` (Targeted for ADB exploitation)
- **Malware Artifacts:**
    - `/data/local/tmp/trinity`
    - `com.ufo.miner`
    - `ufo.apk`
- **Command:** `MODULE LOAD /tmp/exp.so` (Redis RCE artifact)
- **Protocol:** `kamstrup_protocol` (Unusual ICS activity)

### 10) Backend Tool Issues
- **`kibanna_discover_query`:** This tool failed repeatedly with a `400 Bad Request` error (`illegal_argument_exception`) when querying for `Redishoneypot` events. This directly blocked the validation of the **REDIS-RCE-01** candidate.
- **`two_level_terms_aggregated`:** This tool failed to return results for Conpot and Redishoneypot events, preventing the association of source IPs with the **ICS-KAMSTRUP-PROBE** and **REDIS-RCE-01** candidates.
- **Weakened Conclusions:** The inability to retrieve source data for the Redis RCE and Kamstrup probing means their potential connection to broader campaigns or specific threat actors could not be established. The assessment for these items is provisional and has low confidence.

### 11) Agent Action Summary (Audit Trail)
- **Agent: ParallelInvestigationAgent**
    - **Purpose:** Conduct initial parallel data gathering on baseline activity, known signals, credential noise, and honeypot-specific events.
    - **Inputs Used:** `investigation_start`, `investigation_end`.
    - **Actions Taken:** Executed multiple data aggregation queries across its four sub-agents.
    - **Key Results:**
        - Established a baseline of 9,272 attacks.
        - Identified high-volume VNC scanning signatures.
        - Confirmed standard credential stuffing patterns.
        - Found specific malware artifacts in Adbhoney, an RCE attempt in Redis, and ICS probing in Conpot.
    - **Errors or Gaps:** None.
- **Agent: CandidateDiscoveryAgent**
    - **Purpose:** Sift through parallel results to identify and triage potential leads for investigation.
    - **Inputs Used:** All four outputs from the `ParallelInvestigationAgent`.
    - **Actions Taken:** Analyzed honeypot data, identified 3 leads (Kamstrup, Redis, Adbhoney), and attempted to enrich them with source IPs.
    - **Key Results:**
        - Created `BOT-TRINITY-ADB` candidate from Adbhoney data, successfully identifying source IP `218.205.95.160`.
        - Created `REDIS-RCE-01` candidate.
        - Created `ICS-KAMSTRUP-PROBE` candidate.
    - **Errors or Gaps:** Encountered `kibanna_discover_query` failure when trying to get the source IP for the Redis event.
- **Agent: CandidateValidationLoopAgent**
    - **Purpose:** Iteratively validate candidates passed from the discovery phase.
    - **Inputs Used:** `novel_exploit_candidates` queue.
    - **Actions Taken:** Loaded and attempted to validate one candidate (`REDIS-RCE-01`).
    - **Key Results:** Ran for 1 iteration. The validation was blocked. The candidate's confidence was lowered and it was marked as provisional.
    - **Errors or Gaps:** Multiple tool calls (`kibanna_discover_query`, `two_level_terms_aggregated`) failed, preventing the agent from finding the source IP and raw event data for the Redis RCE attempt.
- **Agent: DeepInvestigationLoopController**
    - **Purpose:** Perform a deep dive on high-confidence leads that require further correlation.
    - **Inputs Used:** `validated_candidates`, `botnet_campaign_mapping`.
    - **Actions Taken:** Ran for 2 iterations. First attempted to investigate the Redis RCE artifact but was blocked by tool failure. Pivoted to the high-confidence IP `218.205.95.160`.
    - **Key Results:** Fully mapped the activity of `218.205.95.160`, confirming its exclusive focus on the Trinity ADB botnet campaign within the time window and enriching it with Geo/ASN data and related Suricata signatures.
    - **Errors or Gaps:** Initial investigation into the Redis artifact was blocked by the same `kibanna_discover_query` error seen previously.
- **Agent: OSINTAgent**
    - **Purpose:** Enrich validated candidates with public intelligence.
    - **Inputs Used:** `validated_candidates`.
    - **Actions Taken:** Performed OSINT search on the "MODULE LOAD /tmp/exp.so" artifact.
    - **Key Results:** Confirmed that the Redis RCE technique is well-documented and associated with known malware/exploit scripts, thereby reducing its novelty classification.
    - **Errors or Gaps:** None.
- **Agent: ReportAgent**
    - **Purpose:** Compile the final report from all available workflow state outputs.
    - **Inputs Used:** All preceding agent outputs and tool failure diagnostics.
    - **Actions Taken:** Assembled this report.
    - **Key Results:** Report generated.
    - **Errors or Gaps:** None.
- **Agent: SaveReportAgent**
    - **Purpose:** Save the final report to the investigation record.
    - **Inputs Used:** Final report content.
    - **Actions Taken:** Called `investigation_write_file`.
    - **Key Results:** Report will be saved by the downstream tool.
    - **Errors or Gaps:** None.
