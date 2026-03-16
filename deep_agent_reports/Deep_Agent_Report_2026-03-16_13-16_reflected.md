# Honeypot Threat Hunting Report: Final

## 1. Investigation Scope
- **investigation_start**: 2026-03-16T13:00:10Z
- **investigation_end**: 2026-03-16T16:00:10Z
- **completion_status**: Complete
- **degraded_mode**: false
  - **Reason**: Initial query failures blocking the investigation of ICS activity were successfully resolved during a reflection cycle.

## 2. Executive Triage Summary
- **Top Services/Ports of Interest**:
  - **ICS/SCADA (Conpot)**: Activity was de-anonymized, revealing two distinct actors: one (`85.217.149.46`) probing `kamstrup_protocol` for utility meters, and another (`167.94.138.51` - Censys) scanning for the insecure `IEC104` protocol.
  - **VNC (5901-5905)**: Subjected to high-volume commodity scanning.
  - **Multiple Web Ports (80, 2000, 3011, 7000+)**: Targeted by two separate, automated web vulnerability scanning campaigns.
  - **Android Debug Bridge (Adbhoney)**: Targeted by low-volume reconnaissance.
- **Top Confirmed Known Exploitation**:
  - **CVE-2025-55182 (React2Shell)**: A high-volume, wide fan-out scanning campaign from a single IP (`193.32.162.28`).
  - **CVE-2017-9841 & CVE-2024-4577**: A multi-purpose scanner (`62.171.133.187`) targeting both old and recent PHP vulnerabilities.
- **Novel Exploit Candidates**:
  - No novel or zero-day candidates were validated. All exploit-like activity was mapped to known vulnerabilities.
- **Botnet/Campaign Mapping Highlights**:
  - Four distinct, single-source campaigns were fully mapped: two targeting web vulnerabilities and two targeting specialized ICS protocols with different TTPs.

## 3. Candidate Discovery Summary
The discovery phase identified four primary candidates. Initial analysis was partially blocked by query failures related to Industrial Control System (ICS) honeypot data. These gaps were successfully resolved in a subsequent reflection-driven investigation, allowing for a complete analysis.

- **Emerging n-day Exploitation Candidates**: 1 (CVE-2025-55182)
- **Botnet/Campaign Mapping Candidates**: 1 (PHPUnit/PHP RFI Scanner)
- **Odd-Service/Minutia Attack Candidates**: 2 (Adbhoney Recon, Conpot ICS Probing)

## 4. Emerging n-day Exploitation

### NDE-01: CVE-2025-55182 (React2Shell) Scanning Campaign
- **cve/signature mapping**: CVE-2025-55182 / `ET WEB_SPECIFIC_APPS React Server Components React2Shell Unsafe Flight Protocol Property Access (CVE-2025-55182)`
- **evidence summary**:
  - 82 events directly matched the CVE signature.
  - All activity originated from a single source IP, `193.32.162.28`, which was responsible for 1,409 total events.
  - The attacker used a fixed set of 6 URLs (e.g., `/_next`, `/api/route`) consistent with exploiting this vulnerability.
- **affected service/port**: A wide range of web ports including 2000, 3006, 3007, 3011, 7000, 7777, and 8181.
- **confidence**: High
- **operational notes**: This is a high-volume, automated scanning campaign for the recently disclosed and critical CVE-2025-55182. The campaign shape is a classic fan-out scan from a single source.

## 5. Novel or Zero-Day Exploit Candidates (UNMAPPED ONLY, ranked)
*No candidates met the criteria for this category in the current investigation window. All identified exploit-like behavior was mapped to known vulnerabilities.*

## 6. Botnet/Campaign Infrastructure Mapping

### Item: NDE-01-Campaign - CVE-2025-55182 Scanner
- **related candidate_id(s)**: NDE-01
- **campaign_shape**: fan-out
- **suspected_compromised_src_ips**: `193.32.162.28` (1,409 events)
- **ASNs / geo hints**: ASN 47890 (Unmanaged Ltd)
- **suspected_staging indicators**: Paths consistent with React2Shell exploit: `/`, `/_next`, `/api`, `/app`, etc.
- **confidence**: High
- **operational notes**: A single-purpose, automated scanner exclusively focused on finding CVE-2025-55182 across numerous web service ports.

### Item: BOT-01 - Multi-Exploit Web Scanner
- **related candidate_id(s)**: BOT-01
- **campaign_shape**: spray
- **suspected_compromised_src_ips**: `62.171.133.187` (151 events)
- **ASNs / geo hints**: ASN 51167 (Contabo GmbH)
- **suspected_staging indicators**: 
  - `/V2/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php` (CVE-2017-9841)
  - `/?%ADd+allow_url_include%3d1+%ADd+auto_prepend_file%3dphp://input` (CVE-2024-4577)
- **confidence**: High
- **operational notes**: A "kitchen sink" scanner testing for multiple, distinct web vulnerabilities in a rapid burst. OSINT confirms the source IP has a known-bad abuse reputation.

### Item: ODD-02A - Kamstrup ICS Scanner
- **related candidate_id(s)**: ODD-02
- **campaign_shape**: unknown
- **suspected_compromised_src_ips**: `85.217.149.46` (21 events)
- **ASNs / geo hints**: ASN 209334 (Modat B.V.)
- **suspected_staging indicators**: All activity targeted the Conpot honeypot on port 1025 using the `kamstrup_protocol`.
- **confidence**: Moderate
- **operational notes**: This actor conducted targeted scanning of a specialized utility meter protocol. The same IP was also observed scanning common services like SMB (port 445), indicating broader scanning behavior.

### Item: ODD-02B - IEC104 Internet Scanner (Censys)
- **related candidate_id(s)**: ODD-02
- **campaign_shape**: unknown
- **suspected_compromised_src_ips**: `167.94.138.51` (14 events)
- **ASNs / geo hints**: ASN 398324 (Censys, Inc.)
- **suspected_staging indicators**: All activity targeted the Conpot honeypot on port 2404 using the `IEC104` protocol.
- **confidence**: High
- **operational notes**: This activity is attributed to Censys, a known internet-wide scanner. While targeting a sensitive ICS protocol, the intent is likely research and data collection, not a direct malicious attack.

## 7. Odd-Service / Minutia Attacks

### Item: ODD-02 - ICS/SCADA Protocol Probing
- **service_fingerprint**: Conpot (ICS/SCADA Honeypot)
- **why it’s unusual/interesting**: The targeted protocols are highly specialized and used in critical infrastructure, making any interaction noteworthy.
- **evidence summary**: The activity was resolved into two distinct campaigns:
  - **Kamstrup Protocol**: 39 events from `85.217.149.46` targeting port 1025.
  - **IEC104 Protocol**: 14 events from `167.94.138.51` (Censys) targeting port 2404.
- **confidence**: High
- **recommended monitoring pivots**: Monitor `85.217.149.46` for further ICS-related probing. Activity from the Censys IP can likely be de-prioritized as internet research.

### Item: ODD-01 - Android Debug Bridge (ADB) Reconnaissance
- **service_fingerprint**: Adbhoney (port 5555/TCP)
- **why it’s unusual/interesting**: Represents enumeration of a non-standard mobile/IoT service.
- **evidence summary**: A single event from `45.135.194.48` executed the command: `echo "$(getprop ro.product.name 2>/dev/null) $(whoami 2>/dev/null)"`.
- **confidence**: Low
- **recommended monitoring pivots**: This is a common fingerprinting command. Monitor the source IP for any follow-on exploit attempts against IoT infrastructure.

## 8. Known-Exploit / Commodity Exclusions
- **VNC Scanning**: 14,938 events for `GPL INFO VNC server response` were observed, indicative of commodity scanning.
- **RDP Scanning**: 551 events for `ET SCAN MS Terminal Server Traffic on Non-standard Port` were observed, classified as common scanning noise.
- **Credential Noise**: Standard brute-force attempts were observed, including `root`/`admin` and common passwords.
- **Known Web Exploits**: PHPUnit (CVE-2017-9841) and PHP RFI (CVE-2024-4577) attempts were tracked as part of the BOT-01 campaign.

## 9. Infrastructure & Behavioral Classification
- **Exploitation vs. Scanning**: Activity from `193.32.162.28` and `62.171.133.187` was confirmed exploitation. Activity from `85.217.149.46` and `167.94.138.51` was classified as reconnaissance scanning.
- **Campaign Shape**: `NDE-01` was a **fan-out** campaign. `BOT-01` was a **spray** campaign. The ICS campaigns were targeted probes.
- **Infra Reuse Indicators**: No infrastructure reuse was observed between the four distinct campaigns.
- **Odd-Service Fingerprints**: **ICS/SCADA** (`kamstrup_protocol`, `IEC104`) and **Android/IoT** (Adbhoney recon command).

## 10. Evidence Appendix

### NDE-01 / CVE-2025-55182 Campaign
- **Source IPs**: `193.32.162.28` (1,409)
- **ASNs**: 47890 (Unmanaged Ltd)
- **Target Ports**: 2000, 3006, 3007, 3011, 7000, 7777, 8181
- **Paths/Endpoints**: `/`, `/_next`, `/_next/server`, `/api`, `/api/route`, `/app`

### BOT-01 / Multi-Exploit Scanner
- **Source IPs**: `62.171.133.187` (151)
- **ASNs**: 51167 (Contabo GmbH)
- **Target Ports**: 80
- **Paths/Endpoints**: `/V2/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php`, `/?%ADd+allow_url_include...`

### ODD-02 / ICS Scanners
- **Source IPs**: `85.217.149.46` (21), `167.94.138.51` (14)
- **ASNs**: 209334 (Modat B.V.), 398324 (Censys, Inc.)
- **Target Ports/Services**: 1025 (`kamstrup_protocol`), 2404 (`IEC104`)

## 11. Indicators of Interest
- **IPs**:
  - `193.32.162.28` (High-volume CVE-2025-55182 scanner)
  - `62.171.133.187` (Multi-exploit web scanner, known-bad reputation)
  - `85.217.149.46` (ICS utility meter scanner)
  - `167.94.138.51` (Censys internet scanner, lower priority)
- **URLs/Paths**:
  - `/V2/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php`
  - `/?%ADd+allow_url_include%3d1+%ADd+auto_prepend_file%3dphp://input`
- **CVEs**:
  - `CVE-2025-55182`
  - `CVE-2017-9841`
  - `CVE-2024-4577`

## 12. Reflection Findings
- **What reflection candidates were discovered**:
  - A high-priority intelligence gap was identified: the inability to investigate unusual ICS protocol activity (`kamstrup_protocol`, `IEC104`) on the Conpot honeypot due to persistent query failures.
- **Actions taken for reflection candidates**:
  - A new deep investigation was initiated with a specific mandate to resolve the ICS activity.
  - Corrected query syntax (`type: "ConPot"`) discovered in the final moments of the previous loop was attempted.
  - When that failed, the investigation pivoted to indirect methods: querying by a known source IP (`85.217.149.46`) and performing a broad keyword search for the protocol string "IEC104".
- **Findings of reflection candidates**:
  - The indirect methods were successful. It was confirmed that the Kamstrup activity originated exclusively from `85.217.149.46`.
  - The IEC104 activity was confirmed to originate exclusively from `167.94.138.51`, which was identified as a Censys internet scanner.
- **Enhancement of other findings**:
  - The reflection resolved the primary uncertainty of the investigation, changing the report's `completion_status` from `Partial` to `Complete`. It successfully deconflicted the two types of ICS scanning into two distinct, single-actor campaigns and allowed for a more accurate risk assessment of each.

## 13. Backend Tool Issues
- Several tools (`two_level_terms_aggregated`, `kibanna_discover_query`) repeatedly failed to access Conpot honeypot data using direct filters (`type: 'ConPot'`). This blocked the initial investigation.
- The intelligence gap was ultimately resolved through indirect queries (`events_for_src_ip`, `discover_by_keyword`). While the conclusion is now complete, the backend issue with direct Conpot data access remains and should be investigated by engineering.

## 14. Agent Action Summary (Audit Trail)
- **ParallelInvestigationAgent**:
  - **purpose**: Gathered baseline statistics and initial threat data.
  - **key_results**: Produced structured data on attack volume, CVEs, signatures, and honeypot events.
- **CandidateDiscoveryAgent**:
  - **purpose**: Identified high-signal leads from the initial data.
  - **key_results**: Generated four distinct candidates for validation.
- **CandidateValidationLoopAgent**:
  - **purpose**: Conducted initial validation of the first high-priority candidate.
  - **key_results**: Confirmed `NDE-01` as a high-confidence campaign from a single source IP.
- **DeepInvestigationLoopController**:
  - **purpose**: Performed in-depth analysis of leads, including a reflection-driven cycle.
  - **actions_taken**: Ran 7 iterations. Fully mapped two web exploit campaigns. The initial investigation into ICS activity stalled. A reflection cycle was initiated, which successfully used indirect queries to pivot and fully attribute the two distinct ICS scanning campaigns to their source IPs.
  - **key_results**: All four campaigns were successfully mapped. The critical intelligence gap around Conpot ICS activity was resolved. The loop exited after hitting its stall limit during the reflection cycle, but after the final pieces of evidence were secured.
- **OSINTAgent**:
  - **purpose**: Enriched findings with open-source intelligence.
  - **key_results**: Confirmed all exploit activity maps to known public vulnerabilities. Confirmed ICS protocols are sensitive and targeted by researchers and threat actors.
- **ReportAgent**:
  - **purpose**: Compiled the final report from all available workflow state.
  - **key_results**: This report, updated with findings from the reflection cycle.
- **SaveReportAgent**:
  - **purpose**: Persist the final report.
  - **key_results**: Report successfully saved.
