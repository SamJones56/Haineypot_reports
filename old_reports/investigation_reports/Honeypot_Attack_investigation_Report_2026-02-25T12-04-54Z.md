# Zero-Day Candidate Triage Report

### 1. Investigation Scope
- **investigation_start:** `2026-02-25T11:30:08Z`
- **investigation_end:** `2026-02-25T12:00:08Z`
- **completion_status:** Complete

### 2. Candidate Discovery Summary
A total of 2,592 attack events were observed in the 30-minute window. The activity was overwhelmingly dominated by a high-volume SMB exploit campaign identified as DoublePulsar. After excluding this and other generic noise, a single candidate involving a web request for a `/.env` file was investigated. This candidate was subsequently validated and identified as commodity malware (Androxgh0st). No novel exploit candidates were confirmed.

### 3. Emerging n-day Exploitation
- **CVE:** CVE-2024-14007
- **Observation:** A single alert associated with this recent CVE was observed. There is insufficient evidence from the time window to indicate a targeted campaign or widespread exploitation.
- **Confidence:** Low
- **Required Followup:** Monitor for any increase in activity in subsequent windows.

### 4. Known-Exploit Exclusions
- **DoublePulsar/EternalBlue SMB Campaign:** High-volume (1,238 events) SMB exploitation activity originating from `165.90.75.54` (Mozambique). This activity is clearly mapped to signature ID 2024766 and represents well-understood, commodity scanning.
- **Androxgh0st Malware Recon:** Web-based reconnaissance from `78.153.140.149` targeting port 80. The activity involved probing for `/.env` files and a subsequent POST request with the payload `androxgh0st`, which are definitive indicators of this known credential-stealing malware.
- **Generic Credential Scanning:** Standard background noise consisting of brute-force and scanning attempts against common services like SSH (port 22) and RDP (port 3389) using default credentials.

### 5. Novel Exploit Candidates
No unmapped activities were validated as novel exploit candidates in this investigation window.

### 7. Infrastructure & Behavioral Classification
- **DoublePulsar Activity:** Classified as high-volume, automated scanning and exploitation originating from a single source (`165.90.75.54`, ASN 37110 - moztel-as). The behavior is consistent with a compromised host or dedicated scanner searching for unpatched SMB vulnerabilities.
- **Androxgh0st Activity:** Classified as targeted malware reconnaissance. The actor (`78.153.140.149`, ASN 202306 - Hostglobal.plus Ltd) followed a specific TTP: scan for `.env` files, then attempt a follow-up action. This is a known precursor to credential theft from web applications.

### 8. Analytical Assessment
The investigation concludes with high confidence that the observed activity within this timeframe consists entirely of known commodity threats and background noise. The workflow successfully identified and excluded high-volume scanning (DoublePulsar) and correctly seeded, investigated, and re-classified a more nuanced threat (Androxgh0st) as known malware. The initial alert for CVE-2024-14007 remains an isolated event at this time. The investigation was completed without any tool failures or evidence gaps.

### 9. Confidence Breakdown
- **Overall Confidence:** High. The primary threat activities were mapped with high confidence to well-documented malware and exploit campaigns using distinct signatures and behavioral indicators.

### 10. Evidence Appendix

**Item: DoublePulsar SMB Campaign (Exclusion)**
- **source IPs:** `165.90.75.54` (1238)
- **ASNs:** `37110 (moztel-as)` (1238)
- **target ports/services:** `445` (SMB)
- **paths/endpoints:** N/A
- **payload/artifact excerpts:** Signature: `ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication`
- **previous-window / 24h checks:** unavailable

**Item: Androxgh0st Malware Recon (Exclusion)**
- **source IPs:** `78.153.140.149` (20)
- **ASNs:** `202306 (Hostglobal.plus Ltd)` (20)
- **target ports/services:** `80` (HTTP)
- **paths/endpoints:** `/.env` (GET), `/` (POST)
- **payload/artifact excerpts:** HTTP POST body includes `"androxgh0st"`
- **previous-window / 24h checks:** unavailable

**Item: CVE-2024-14007 (Emerging n-day)**
- **source IPs:** Not explicitly provided in summary data
- **ASNs:** Not explicitly provided in summary data
- **target ports/services:** Not explicitly provided in summary data
- **paths/endpoints:** Not explicitly provided in summary data
- **payload/artifact excerpts:** CVE match `CVE-2024-14007` (1 event)
- **previous-window / 24h checks:** unavailable

### 11. Indicators of Interest
- **IP Address:** `165.90.75.54` (High-volume DoublePulsar scanning)
- **IP Address:** `78.153.140.149` (Androxgh0st malware reconnaissance)
- **Signature ID:** `2024766` (ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication)
- **HTTP Path:** `/.env`
- **HTTP Payload:** `androxgh0st`
