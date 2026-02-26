# Zero-Day Candidate Triage Report

### 1. Investigation Scope
- **investigation_start:** 2026-02-25T18:39:04Z
- **investigation_end:** 2026-02-25T19:39:05Z
- **completion_status:** Partial (degraded evidence)
  - The investigation was completed using workarounds. Failures in the `complete_custom_search` tool prevented a full, automated enumeration of all source IPs involved in the primary candidate campaign, requiring manual correlation and alternative tools.

### 2. Candidate Discovery Summary
During the one-hour window, 3,589 attacks were recorded. Analysis filtered out high-volume commodity scanning (SSH, VNC) to focus on two areas of interest:
1.  A coordinated, multi-IP campaign targeting exposed Android Debug Bridge (ADB) interfaces on port 5555 to deploy cryptomining malware.
2.  Targeted reconnaissance against Industrial Control System (ICS) protocols, including Kamstrup and the known-vulnerable IEC-104.

### 3. Emerging n-day Exploitation
- No emerging n-day exploitation patterns were identified in this window.

### 4. Known-Exploit Exclusions
- **ADB.Miner / "ufo.miner" Campaign:** Activity initially triaged as a novel candidate (`CAND-20260225-1`) was positively identified via OSINT as the well-documented "ufo.miner" cryptomining botnet, active since at least 2018. The observed TTPs are a direct match to this known threat.
- **Ancient IIS CVE Scan (CVE-2002-0606):** A single event was observed, consistent with widespread, non-targeted vulnerability scanner noise.
- **Widespread SSH Scanning & Brute-Force:** High-volume, generic scanning and credential stuffing attempts were observed against port 22, using common usernames (`root`, `admin`) and passwords. This is considered commodity background noise.
- **Web Reconnaissance Scanning:** Probing for common sensitive files such as `/.env` was observed, consistent with automated, non-targeted scanning.

### 5. Novel Exploit Candidates
- No unmapped, high-confidence novel exploit candidates were validated in this investigation period. The primary candidate discovered was re-classified as a known exploit following OSINT validation.

### 6. Suspicious Unmapped Activity to Monitor
- **Activity:** Targeted Probing of Industrial Control System (ICS) Protocols
- **Description:** The Conpot honeypot recorded specific, non-random commands targeting multiple ICS protocols, notably `kamstrup_protocol` and `IEC104`.
- **Reasoning:** While the specific command sequence is unmapped, OSINT confirms IEC-104 is a known insecure protocol targeted by sophisticated malware (e.g., Industroyer2) in attacks on critical infrastructure. This activity is not commodity noise and represents targeted reconnaissance against a high-value, vulnerable protocol stack. Continued monitoring is warranted.

### 7. Infrastructure & Behavioral Classification
- **"ufo.miner" Campaign:** A distributed, automated cryptomining malware deployment campaign. Actors from multiple geolocations (Russia, South Korea) were observed performing different stages of the attack chain against exposed ADB interfaces (port 5555).
- **ICS Reconnaissance:** Targeted, low-volume reconnaissance activity against specialized ICS protocols. The behavior appears to be information gathering and fingerprinting rather than active exploitation.

### 8. Analytical Assessment
The investigation successfully differentiated between commodity background noise and two distinct, targeted campaigns.

The primary finding was a multi-stage malware installation over ADB. While initially appearing novel due to its coordinated nature, OSINT validation conclusively identified it as the established "ufo.miner" cryptomining botnet. This allows the activity to be correctly classified and de-prioritized as a non-novel threat.

The secondary finding of targeted ICS protocol reconnaissance is of higher concern. The specific targeting of the known-vulnerable IEC-104 protocol elevates this from random probing to potential pre-exploitation activity against critical infrastructure.

The investigation's conclusions are solid, but efficiency was hampered by backend tool failures, which required manual workarounds and prevented a complete enumeration of the distributed ADB campaign's infrastructure.

### 9. Confidence Breakdown
- **Overall Confidence:** High. Despite tool issues, the primary findings were successfully identified, correlated, and validated against external intelligence.
- **"ufo.miner" Re-classification:** Very High. The match between observed TTPs and public documentation for this known botnet is exact.
- **ICS Reconnaissance Concern:** High. The activity targets specific, non-trivial ICS protocols, one of which (IEC-104) has a documented history of being exploited in real-world attacks.

### 10. Evidence Appendix

**Item: ADB.Miner / "ufo.miner" Campaign**
- **Source IPs with Counts:**
  - `94.142.248.2`: 1+ (Observed performing reconnaissance)
  - `118.47.245.12`: 1+ (Observed performing installation)
- **ASNs with Counts:**
  - `AS205784` (NV Telecom LLC, Russia): 1+
  - `AS4766` (Korea Telecom, South Korea): 1+
- **Target Ports/Services:** `5555/tcp` (ADB)
- **Payload/Artifact Excerpts (Execution Chain):**
  - `pm path com.ufo.miner`
  - `pm install /data/local/tmp/ufo.apk`
  - `am start -n com.ufo.miner/com.example.test.MainActivity`
  - `rm -rf /data/local/tmp/*`
- **Staging Indicators:**
  - Malware Sample Hash: `0d3c687ffc30e185b836b99bd07fa2b0d460a090626f6bbbd40a95b98ea70257`
- **Previous-window / 24h checks:** Activity was present in the 24-hour window preceding the investigation period.

**Item: Suspicious ICS Reconnaissance**
- **Source IPs with Counts:** Unavailable (Investigation did not pivot to enumerate sources due to tool issues and focus on ADB campaign).
- **ASNs with Counts:** Unavailable.
- **Target Ports/Services:** Associated with Conpot honeypot (e.g., Modbus, IEC-104 default ports).
- **Payload/Artifact Excerpts:**
  - Protocols Targeted: `kamstrup_protocol`, `guardian_ast`, `IEC104`
  - Raw Kamstrup Requests: `b'\x01I20100\n'`, `b'000e0401040302010203040105010601ff01'`
- **Previous-window / 24h checks:** Activity was present in the 24-hour window preceding the investigation period.

### 11. Indicators of Interest
- **IPv4:** `94.142.248.2`
- **IPv4:** `118.47.245.12`
- **SHA256:** `0d3c687ffc30e185b836b99bd07fa2b0d460a090626f6bbbd40a95b98ea70257`
- **Malware Name:** `com.ufo.miner`
- **TTP:** Public scanning and exploitation of open Android Debug Bridge (ADB) on port 5555/tcp.

### 12. Backend tool issues
- **Failed Tool:** `complete_custom_search`
- **Issue:** The tool repeatedly failed to return results for correlated queries involving the `type` and `src_ip.keyword` fields. Events were confirmed to exist using the `kibanna_discover_query` tool, but the aggregation and search tool was unreliable.
- **Impact:** This blocked the ability to quickly and automatically enumerate all source IPs involved in the ADB malware campaign, forcing the analyst to use slower, less direct methods to validate the distributed nature of the attack.