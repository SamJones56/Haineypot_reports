# Final Investigation Report

### 1. Investigation Scope
- **Reports Ingested:** 4 triage reports were analyzed.
- **Time Range Investigated:** 2026-02-25T12:30:08Z to 2026-02-26T12:30:10Z.
- **Investigation Iterations Run:** 5 iterations were completed in the deep investigation phase.
- **Completion Status:** Partial.
- **Rationale for Status:** The investigation successfully analyzed and de-escalated a suspicious Industrial Control System (ICS) scanning event, classifying it as non-targeted background noise. However, the primary investigation into suspected exploitation of a critical RCE vulnerability (CVE-2025-55182, "React2Shell") was completely blocked due to persistent backend data retrieval failures. These failures created a significant evidence gap, making a conclusive assessment of the overall threat landscape impossible.

### 2. Executive Summary
- **Primary Finding:** The investigation's most critical finding is the repeated failure of backend data retrieval tools. These failures prevented the validation of alerts for a critical RCE vulnerability (CVE-2025-55182, "React2Shell") and hampered analysis of other suspicious web activity, creating a major visibility gap.
- **Observed Exploit Activity:** Alerts for emerging n-day vulnerabilities, including CVE-2025-55182 and CVE-2024-14007, were present in initial reports. However, attempts to validate the extent and success of this activity were blocked by tool failures.
- **CVE Mapping:** While some commodity scanning was successfully mapped to known CVEs (e.g., CVE-2023-46604, CVE-2024-14007 in one instance) and signatures (DoublePulsar), the most concerning alerts could not be validated against their CVE tags.
- **High-Impact Unknowns:** The nature and scope of the unverified "React2Shell" activity remains the highest-impact unknown. It is unclear if this represents active, successful exploitation or simply opportunistic scanning that is currently invisible to deep analysis.
- **Confirmed Threats:** Suspicious ICS scanning was de-escalated to non-targeted background noise from a known malicious scanning network. A separate, un-signatured web reconnaissance campaign scanning for PHP files was also identified but could not be fully analyzed.
- **High-Confidence IOCs:** Several IPs associated with high-volume scanning and web reconnaissance have been identified and are listed in the Indicators section.

### 3. Key Observations From Initial Reports
The initial analysis of four triage reports highlighted three primary areas of concern alongside a critical operational issue:
- **Persistent Web Vulnerability Alerts:** Multiple reports flagged activity associated with CVE-2025-55182 ("React2Shell") and CVE-2024-14007. In most cases, these alerts could not be validated due to backend query failures.
- **Anomalous ICS Probing:** Low-volume, un-signatured scanning was observed targeting the `kamstrup_protocol`, a protocol used in smart utility meters.
- **Un-signatured Web Reconnaissance:** An actor from IP `20.104.61.138` was observed probing for sequentially-named PHP files, a known TTP that was not being detected by existing signatures.
- **Overarching Theme:** Three of the four reports were rated "Inconclusive" or "Partial" due to critical failures in backend data retrieval tools, preventing analysts from accessing the raw evidence needed to validate alerts.

### 4. Deep Investigation Results
The deep investigation focused on the highest-priority leads from the initial reports, but was significantly hampered by the previously identified tool failures.
- The investigation first prioritized **CVE-2025-55182 ("React2Shell")**. An OSINT search confirmed its status as a critical, unauthenticated RCE. However, an internal query to find associated source IPs failed, returning zero results despite initial alerts.
- A second attempt was made to hunt for this activity using specific string patterns (`"status":"resolved_model"`) derived from OSINT. This query also failed, returning no data. The investigation into this CVE was declared **blocked**.
- The focus then pivoted to the anomalous **ICS `kamstrup_protocol` scanning**. This query was **successful** and retrieved six events, identifying two source IPs: `91.196.152.154` and `91.196.152.158`.
- Further investigation into these IPs revealed they belonged to the same subnet (`91.196.152.0/24`, ONYPHE SAS), which OSINT confirmed is a known "cybercrime subnet" with a 100% abuse score, used for mass internet scanning. The activity was brief and consisted only of connection attempts.
- Based on this, the ICS scanning lead was **resolved and de-escalated**, re-classified as non-targeted background noise from a known malicious scanning source. With the primary lead blocked and the secondary lead resolved, the investigation concluded.

### 5. Classification & Assessment

**Finding 1: ICS Protocol Scanning (`kamstrup_protocol`)**
- **Classification:** Suspicious Unmapped Activity (Re-classified as Known Commodity Scanning)
- **Evidence:** 6 connection events targeting port 1025 from `91.196.152.154` and `91.196.152.158` (AS213412 - ONYPHE SAS). OSINT confirms this subnet is widely reported for mass scanning and malicious activity.
- **Confidence:** High
- **Rationale:** The activity was successfully attributed to a known malicious scanning block. The behavior is consistent with broad, non-targeted port scanning, not a focused attack on ICS infrastructure.

**Finding 2: Suspected "React2Shell" Exploitation (CVE-2025-55182)**
- **Classification:** Emerging n-day (Provisional)
- **Evidence:** Initial triage reports contained alerts for this CVE. However, all deep investigation queries (`top_src_ips_for_cve`, `web_path_samples`) to retrieve associated events failed, returning zero results.
- **Confidence:** Low
- **Rationale:** Confidence is low because no direct evidence could be retrieved during the deep investigation. The classification is provisional and rests entirely on unvalidated alerts from the initial triage phase.

**Finding 3: Un-signatured PHP Web Reconnaissance**
- **Classification:** Suspicious Unmapped Activity
- **Evidence:** As noted in an initial report, source IP `20.104.61.138` probed for numerous simple and sequentially-named PHP files (e.g., `/1.php`, `/123.php`).
- **Confidence:** Moderate (that the scanning occurred), Low (on its specific intent).
- **Rationale:** The activity was confirmed in a source report, but its purpose remains uncertain because backend failures (as documented in that report) prevented inspection of payloads or response data. It is a known TTP, but novelty cannot be ruled out without evidence.

### 6. Indicators of Interest (Actionable)
*Indicators are sourced from across all analyzed reports. Validation status may vary.*

**Source IPs:**
- `91.196.152.154` (ICS / Mass Scanner)
- `91.196.152.158` (ICS / Mass Scanner)
- `20.104.61.138` (PHP Web Reconnaissance)
- `197.255.224.193` (DoublePulsar SMB Exploit Campaign)
- `103.227.94.102` (Commodity SMB Scanner)
- `193.26.115.178` (CVE-2023-46604 Scanner)
- `89.42.231.179` (CVE-2024-14007 Scanner)

**ASNs:**
- `AS213412` (ONYPHE SAS)
- `AS8075` (Microsoft Corporation)
- `AS36939` (ComoresTelecom)
- `AS151130` (Skytech Broadband Private Limited)
- `AS14061` (DigitalOcean, LLC)

**Vulnerabilities to Monitor:**
- `CVE-2025-55182` ("React2Shell")
- `CVE-2024-14007` (Shenzhen TVT NVMS-9000 Auth Bypass)
- `CVE-2023-46604` (Apache ActiveMQ RCE)

**Suspicious Paths / Endpoints (from PHP scanning):**
- `/.well-known/acme-challenge/index.php`
- `/000.php`
- `/1.php`
- `/123.php`
- `/erty.php`

### 7. Recommended Follow-Ups
- **(Critical) Remediate Backend Data Pipeline:** The highest priority is to escalate and fix the underlying data access issues. The documented failures in this report should be used to demonstrate the critical impact on security visibility.
- **Re-run Blocked Queries:** Once the backend is confirmed stable, immediately re-run the failed queries for CVE-2025-55182 and CVE-2024-14007 to validate the scope of any potential exploitation.
- **Analyze PHP Scanner Payloads:** Once access is restored, retrieve and analyze the raw logs and payloads associated with source IP `20.104.61.138` to rule out novel threats.
- **Operational Actions:** Block IPs associated with the `91.196.152.0/24` subnet. Add other confirmed malicious IPs to relevant blocklists.

### 8. Backend Tool Issues & Data Gaps
Numerous tool failures across multiple reports and the deep investigation phase were the primary obstacle to a conclusive assessment.
- **`top_src_ips_for_cve`:** Failed to retrieve any results for `CVE-2025-55182` and `CVE-2024-14007` in multiple instances, despite initial alerts indicating events were present. This prevented basic alert validation and attribution.
- **`web_path_samples`:** Failed to find events matching OSINT-derived IoCs for "React2Shell", indicating a deeper data visibility problem.
- **`kibanna_discover_query`:** Failed in several initial reports to retrieve raw logs for `Tanner` honeypot events, blocking payload inspection for web attacks. Specific failures were noted for paths like `/jndi-datasource-examples-howto.html` and `/.env`.
- **Mapping/Indexing Errors:** One report cited a `"Fielddata is disabled"` error, pointing to a potential backend indexing issue that prevents correlation and aggregation on key fields.
- **Impact:** These failures created a critical blind spot regarding potential exploitation of a 10.0 CVSS RCE vulnerability. They also prevented full characterization of a targeted web reconnaissance campaign. The overall confidence in the security posture is low until these data gaps are resolved.

### 9. Appendix (Evidence Snippets / References)

**OSINT Summary for CVE-2025-55182 (from deep_log iteration 1):**
> "React2Shell," is a critical unauthenticated remote code execution (RCE) vulnerability with a CVSS score of 10.0... The flaw stems from an unsafe deserialization vulnerability within React's Flight protocol, allowing attackers to execute arbitrary code on vulnerable servers with a single, specially crafted HTTP request. Indicators of Compromise (IoCs): ...HTTP POST requests...with `next-action` or `rsc-action-id` headers...Request bodies containing `$@` patterns...Request bodies containing `"status":"resolved_model"` patterns.

**Sample `kamstrup_protocol` Event (from deep_log iteration 3):**
```json
{
  "_source": {
    "data_type": "kamstrup_protocol",
    "dest_port": 1025,
    "event_type": "NEW_CONNECTION",
    "geoip": {
      "ip": "91.196.152.154",
      "country_name": "France",
      "asn": 213412,
      "as_org": "ONYPHE SAS"
    },
    "sensorid": "conpot",
    "timestamp": "2026-02-26T12:01:25.169043",
    "type": "ConPot",
    "src_ip": "91.196.152.154"
  }
}
```

**Probed PHP Paths (from initial report `CANDIDATE-001`):**
- `/.well-known/acme-challenge/index.php`
- `/000.php`
- `/0x.php`
- `/1.php`
- `/123.php`
- `/155.php`
- `/erty.php`