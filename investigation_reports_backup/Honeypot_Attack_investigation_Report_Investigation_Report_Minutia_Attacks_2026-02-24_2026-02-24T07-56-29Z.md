
**INVESTIGATION REPORT**

**Case ID:** T-POT-IR-20260224-01
**Date of Investigation:** 2026-02-24
**Timeframe:** 2026-02-24T03:55:32Z to 2026-02-24T07:55:32Z (4-hour window)
**Investigator:** Senior Cyber Threat Investigator

**Objective:**
This investigation was initiated to identify, analyze, and report on low-frequency, high-interest attack vectors, also referred to as "minutia attacks." The goal was to filter internet background noise and isolate targeted campaigns, novel techniques, or other anomalous activities suggesting deliberate, focused hostile action.

**Summary of Findings:**
The investigation successfully identified two distinct, concurrent attack campaigns that rise above the level of general opportunistic scanning. Both campaigns were characterized by their low volume, concentrated infrastructure, and use of specific, scripted exploit payloads targeting known vulnerabilities on non-standard ports.

---

**Finding 1: Targeted RDP Authentication Bypass Campaign**

*   **Description:** A coordinated campaign was observed attempting to gain access via a Remote Desktop Protocol authentication bypass vulnerability. The activity was persistent throughout the investigation window.
*   **Indicators of Compromise (IOCs):**
    *   **Source IP Addresses:**
        *   `195.178.136.18` (AS213137, Contrust Solutions S.R.L., Ukraine)
        *   `91.224.92.114` (AS209605, UAB Host Baltic, United Kingdom)
    *   **Signature:** `ET HUNTING RDP Authentication Bypass Attempt` (ID: 2034857)
    *   **Payload Artifact:** All 32 attempts contained the payload `Cookie: mstshash=Administr`, indicating a common exploit script.

*   **Tactics, Techniques, and Procedures (TTPs):**
    *   **Exploit Public-Facing Application (MITRE T1190):** The actors are using a known exploit against the RDP service.
    *   **Use of Alternate-Port (Implied):** The campaign systematically targeted a wide array of non-standard TCP ports, a common technique to evade basic firewall rules and discovery.
    *   **Automated Tooling:** The identical nature of the payload across two disparate source IPs indicates the use of the same automated tool.

*   **Assessment:** This is a focused, automated campaign by a small set of actors aimed at gaining initial access to potentially misconfigured servers. The IP `91.224.92.114` was already flagged on reputation lists, indicating it is part of known hostile infrastructure. The low volume but high specificity of the attack pattern makes it a noteworthy threat. **Confidence Level: High.**

---

**Finding 2: Targeted IoT/CCTV Exploit Campaign (CVE-2024-14007)**

*   **Description:** A second, parallel campaign was identified targeting a specific information disclosure vulnerability (CVE-2024-14007) in Shenzhen TVT NVMS-9000, a type of network video management software used in IoT and CCTV systems.
*   **Indicators of Compromise (IOCs):**
    *   **Source IP Addresses:**
        *   `89.42.231.184` (AS206264, Amarutu Technology Ltd, Netherlands)
        *   `89.42.231.241` (AS206264, Amarutu Technology Ltd, Netherlands)
    *   **Signature:** `ET WEB_SPECIFIC_APPS Shenzhen TVT NVMS-9000 Information Disclosure Attempt (CVE-2024-14007)` (ID: 2065916)
    *   **Payload Artifact:** All 17 attempts utilized an identical XML-based payload targeting the `queryBasicCfg` function of the NVMS-9000 system.

*   **Tactics, Techniques, and Procedures (TTPs):**
    *   **Exploit Public-Facing Application (MITRE T1190):** The activity is a clear attempt to exploit a recently disclosed, named CVE.
    *   **Use of Alternate-Port (Implied):** Like the RDP campaign, this actor scanned a variety of non-standard ports to locate vulnerable services.
    *   **Infrastructure Reuse:** Both source IPs belong to the same hosting provider and subnet, and both are already flagged as "known attacker," confirming the use of dedicated hostile infrastructure.

*   **Assessment:** This is a highly targeted, automated campaign focused on exploiting a known vulnerability in IoT infrastructure. The objective is likely information gathering as a precursor to further compromise. The concentration of source IPs and the specificity of the payload demonstrate a deliberate, non-opportunistic attack. **Confidence Level: High.**

---

**Overall Conclusion:**

Within a 4-hour period, focused actors were observed conducting at least two separate, targeted exploit campaigns against the honeypot infrastructure. These "minutia attacks" are significant as they demonstrate specific intent and capability beyond the common, high-volume background noise of the internet. Both campaigns utilized automated tooling to scan for vulnerable services on non-standard ports, indicating a degree of operational awareness intended to bypass simple security measures.

**END OF REPORT**
