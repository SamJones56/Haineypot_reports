## Investigation Report: Last 60 Minutes (2026-03-03T04:00:11Z - 2026-03-03T05:00:11Z)

### Executive Summary

This report summarizes an investigation into activity observed during the last 60 minutes, from 2026-03-03T04:00:11Z to 2026-03-03T05:00:11Z. A total of 4054 attacks were recorded. The primary findings include significant Android Debug Bridge (ADB) exploitation attempts, a widespread VNC scanning campaign, targeted web application probing, and interactions with industrial control system (ICS/SCADA) honeypots. While some activity is attributed to known commodity campaigns, a specific ADBHoney exploitation event originating from South Korea warrants further investigation.

### Key Findings

#### 1. ADBHoney Exploitation and Malware Delivery (High Priority - Previously Novel, Now Mapped to Known Botnets)

**Description:** Direct evidence of command execution attempts and associated malware delivery on an ADBHoney instance. This activity originates from a single source IP, `118.47.245.12`, located in Gimhae, South Korea (ASN 4766, Korea Telecom), and targeted destination port `5555` (ADB service).

**Observed Actions:**
*   `rm -rf /data/local/tmp/*`: Recursive removal of temporary files, likely for cleanup or staging.
*   `chmod 0755 /data/local/tmp/log`: Changing permissions of a file, likely a malicious payload.
*   `/data/local/tmp/nohup /data/local/tmp/log`: Execution of a payload with `nohup` for persistence.
*   `pm install /data/local/tmp/tv.apk`: Installation of an Android application package (`tv.apk`), indicative of malware delivery.
*   Other commands include `am start -n com.google.home.tv/com.example.test.MainActivity`, `pm path com.google.home.tv`, `ps | grep log`, and `ps | grep rig`.

**Malware Artifacts:** Multiple malware file hashes were observed as being delivered, for example: `dl/4251293b2d3765833f16988c2dbec30362df1c84dfe33c58dcc0815596d31353.raw`, `dl/9a56e2c761e10156cac6589bc9e929b1b8b5b00dd6c79ca0d33c2399b88e3a43.raw`, `dl/9bc28777e722c46898754ef256d052e9cd684f6ad812d69878c68ba6cc0c72fe.raw`, etc.

**OSINT Context:** OSINT searches confirmed that these commands and methods are characteristic of established ADB exploitation techniques, commonly used by Android botnets and malware families such as ADB.Miner, Kimwolf Botnet, and Trinity Malware. These threats target exposed ADB interfaces on port 5555 for initial access and persistence. While the specific malware hashes did not yield direct OSINT hits, the command patterns are well-known.

**Timeline:** Activity from `118.47.245.12` was observed between `2026-03-03T04:01:08Z` and `2026-03-03T04:15:22Z`.

**Confidence:** High (due to explicit command execution and OSINT mapping).

**Required Follow-up:** Further analysis of malware samples (hashes provided) for functionality and Command and Control (C2) infrastructure.

#### 2. VNC Scanning Campaign (Known Exploit Campaign)

**Description:** A high volume of VNC scanning activity was detected, primarily characterized by the `GPL INFO VNC server response` Suricata signature (2064 counts). This activity is associated with `CVE-2006-2369` (11 counts), an old and well-known vulnerability, and targets VNC ports (e.g., 5900) as well as various ephemeral ports.

**Top Attacking Countries/ASNs (for general attacks):**
*   United States (1951 attacks)
*   Netherlands (657 attacks)
*   Australia (451 attacks)
*   Switzerland (192 attacks)
*   Romania (144 attacks)

**Associated Source IPs for CVE-2006-2369:**
*   `10.17.0.5` (internal IP - 10 counts)
*   `167.94.146.58` (external IP - 1 count)

**Confidence:** High (well-defined signature and CVE association).

#### 3. Conpot ICS/SCADA Protocol Interactions (Unusual/Minutia Attack)

**Description:** Interactions were observed with industrial control system (ICS/SCADA) protocols on a Conpot honeypot. Specifically, `guardian_ast` (6 counts) and `IEC104` (1 count) protocols were engaged. These are uncommon protocols and suggest targeted reconnaissance or probing of ICS/SCADA environments.

**Confidence:** Moderate (based on initial honeypot data, but deeper queries were inconclusive).

#### 4. Tanner Web Application Probing (Unusual/Minutia Attack)

**Description:** Targeted probing for sensitive web application files and paths was observed on a Tanner honeypot.

**Observed Probes and Associated Source IPs:**
*   `/.env`: probed by `78.153.140.93`
*   `/sites/default/files/js/js_vtafjxmrvougazqzyta3wrjkx9wcwhjp0g4znnqrama.js` (Drupal-like JS path): probed by `77.83.39.139`

**Confidence:** High (clear indicators of targeted web application reconnaissance).

#### 5. Uncommon Destination Port Probes (Unusual/Minutia Attack)

**Description:** Probing activity was detected on several non-standard destination ports from various source countries.

**Observed Ports and Top Countries:**
*   `5436` (Switzerland - 191 counts)
*   `9100` (Netherlands - 16 counts)
*   `17000` (Netherlands - 8 counts)
*   `6969` (Romania - 6 counts)

**Confidence:** Moderate (identifies unusual activity, but specific intent requires further investigation).

#### 6. Dshield Block Listed Source Activity (Botnet/Campaign Infrastructure)

**Description:** 82 events originated from sources listed on the ET DROP Dshield Block Listed Source group 1, indicating known malicious actors or infrastructure.

**Confidence:** High (direct correlation with known blocklists).

### Commodity Noise and Exclusions

*   **Commodity Credential Brute-Forcing:** Frequent attempts with common usernames (`root`, `admin`, `postgres`, `mysql`) and passwords (`1234`, `123456`, `password`) were observed. This is typical background noise and is excluded from further detailed investigation unless correlated with other high-signal events.
*   **General SSH Scanning (Port 22):** Consistent scanning on port 22 from various countries is also considered commodity activity without further exploit-like indicators.

### Technical Details

**Time Window:** `2026-03-03T04:00:11Z` to `2026-03-03T05:00:11Z`

**Total Attacks:** 4054

**Top Attacker Source IPs (Overall):**
*   `178.62.222.52` (464 counts)
*   `207.174.1.152` (413 counts)
*   `170.64.149.79` (275 counts)
*   `129.212.179.18` (234 counts)
*   `129.212.188.196` (234 counts)

**Top Attacker ASNs:**
*   DigitalOcean, LLC (ASN 14061) - 1708 counts
*   Dynu Systems Incorporated (ASN 398019) - 413 counts
*   IP Volume inc (ASN 202425) - 221 counts
*   Private Layer INC (ASN 51852) - 192 counts
*   Google LLC (ASN 396982) - 172 counts

**Top Alert Categories:**
*   Misc activity (2195 counts)
*   Generic Protocol Command Decode (1150 counts)
*   Misc Attack (351 counts)
*   Attempted Information Leak (89 counts)
*   Attempted Administrator Privilege Gain (14 counts)

**Operating System Distribution (P0f):**
*   Windows NT kernel (14264 counts)
*   Linux 2.2.x-3.x (6832 counts)
*   Linux 2.2.x-3.x (barebone) (361 counts)
*   Windows 7 or 8 (442 counts)
*   Linux 3.11 and newer (453 counts)

### Conclusion

The investigation highlights a mix of commodity scanning and more targeted attacks. The ADBHoney exploitation is the most significant finding, exhibiting clear exploit-like behavior and strong links to established Android botnet campaigns. Further analysis of the collected malware samples is crucial to understand the full scope and capabilities of this threat. The ICS/SCADA and web application probing also represent targeted, albeit lower-volume, activity that warrants continued monitoring.

### Remediation and Mitigation Recommendations

*   **ADB Vulnerabilities:** Immediately identify and secure any internet-exposed Android Debug Bridge (ADB) interfaces, especially those on port 5555. Implement strong authentication, restrict access to trusted networks, or disable ADB when not actively in use for development.
*   **Malware Analysis:** Conduct in-depth analysis of the identified malware samples (hashes provided) to determine their exact functionality, C2 infrastructure, and potential impact.
*   **Network Segmentation:** Implement network segmentation to isolate critical systems, particularly ICS/SCADA environments, from less trusted networks.
*   **Vulnerability Management:** Regularly patch and update systems to address known vulnerabilities, even older ones, to mitigate risks from commodity scanning campaigns.
*   **Threat Intelligence Integration:** Integrate Dshield and similar blocklists into security controls to automatically block known malicious source IPs.
*   **Monitoring and Alerting:** Enhance monitoring for unusual activity on uncommon ports and for specific commands/patterns observed in ADBHoney, Conpot, and Tanner honeypots.