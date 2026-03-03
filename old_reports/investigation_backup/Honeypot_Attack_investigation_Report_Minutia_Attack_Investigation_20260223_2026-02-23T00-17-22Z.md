
**CONFIDENTIAL - CYBER THREAT INVESTIGATION REPORT**

**CASE ID:** CTI-20260223-001
**DATE:** 2026-02-23 00:15:37 UTC
**INVESTIGATOR:** Senior Cyber Threat Investigator
**SUBJECT:** Analysis of Low-Volume, High-Interest Attack Vectors on Honeypot Network

**1.0 EXECUTIVE SUMMARY**

This report documents the findings of a four-hour investigation into anomalous threat activity on the honeypot network, focusing on identifying "minutia attacks"—low-volume, high-sophistication events that deviate from baseline noise. The investigation successfully identified two concurrent, targeted campaigns actively exploiting specific, high-impact vulnerabilities. These campaigns are distinct from the typical high-volume SSH and SMB scanning that constitutes the majority of network traffic. Evidence suggests that infrastructure is being shared between these two separate campaigns, indicating a potential link between the operators.

**Investigation Timeframe:**
*   **Start:** 2026-02-22T20:15:37Z
*   **End:** 2026-02-23T00:15:37Z

**Key Findings:**
*   **Finding 1: Coordinated Scanning for IoT Vulnerability (CVE-2024-14007):** A distributed, low-and-slow campaign was identified scanning for a critical authentication bypass in Shenzhen TVT NVMS-9000 (an IoT video management system). Actors used IPs from at least two different ASNs to systematically probe a wide range of non-standard ports.
*   **Finding 2: Multi-Stage Exploitation of Web Application Vulnerability (CVE-2025-55182):** A multi-stage campaign was identified targeting the "React2Shell" vulnerability. The actors first probed for the flaw before attempting to deliver a malware payload designed to download and execute a binary and establish a reverse shell.
*   **Finding 3: Shared Attacker Infrastructure:** The IP address `87.120.191.67` (AS215925) was observed participating in both of the distinct campaigns detailed above. This provides a concrete link between two otherwise separate operations.

**Confidence Level:** High

---

**2.0 BASELINE ACTIVITY ANALYSIS**

During the four-hour window, a total of 32,159 attack events were recorded. The majority of this activity constituted baseline noise, characterized by:
*   **High-Frequency Sources:** The top 10 source IPs, led by `209.38.80.88`, accounted for a significant portion of all traffic.
*   **Common Service Targeting:** Attacks were predominantly aimed at SSH (port 22) and SMB (port 445), consistent with broad, automated brute-force and scanning activity.
*   **Generic Signatures:** The most frequent alert signatures were generic, such as `SURICATA IPv4 truncated packet` and `GPL INFO VNC server response`, indicating non-targeted probes.

This baseline of automated noise was filtered out to isolate the more deliberate and targeted activities detailed below.

---

**3.0 INVESTIGATIVE FINDINGS**

**3.1 Finding 1: Targeted Campaign Against IoT Devices (CVE-2024-14007)**

*   **Description:** A low-volume (23 events) but highly specific campaign was identified targeting CVE-2024-14007, a critical authentication bypass in Shenzhen TVT NVMS-9000. OSINT confirms this is a publicly known and easily exploitable vulnerability that allows unauthenticated administrative access.
*   **Evidence:**
    *   **Attack Signature:** `ET WEB_SPECIFIC_APPS Shenzhen TVT NVMS-9000 Information Disclosure Attempt (CVE-2024-14007)`
    *   **Attacker IPs and Infrastructure:**
        *   `89.42.231.241` & `89.42.231.184` (AS206264 - Amarutu Technology Ltd, NL)
        *   `45.194.92.199` & `87.121.84.86` (AS215925 - Vpsvault.host Ltd, US)
    *   **TTPs:** The actors systematically probed a wide range of non-standard ports (e.g., 6037, 17001, 9100) using a consistent XML payload (`url="queryBasicCfg"`) designed to test for the vulnerability.
*   **Assessment:** This is a coordinated and intelligence-driven campaign to identify vulnerable IoT control systems. The use of multiple IPs across different providers and the probing of numerous ports indicate a level of sophistication beyond simple botnet scanning.

**3.2 Finding 2: Multi-Stage React2Shell Exploitation (CVE-2025-55182)**

*   **Description:** A campaign (17 events) was identified exploiting a vulnerability in React Server Components. The activity demonstrated a clear, multi-stage approach, escalating from a simple check to an attempt to deploy malware.
*   **Evidence:**
    *   **Attack Signature:** `ET WEB_SPECIFIC_APPS React Server Components React2Shell Unsafe Flight Protocol Property Access (CVE-2025-55182)`
    *   **Attacker IPs and Infrastructure:**
        *   `64.89.161.198` (AS205759 - Ghosty Networks LLC, GB)
        *   `87.120.191.67` (AS215925 - Vpsvault.host Ltd, US)
        *   `91.224.92.177` (AS209605 - UAB Host Baltic, GB)
    *   **TTPs:** The campaign involved two distinct payloads:
        1.  **Vulnerability Probe:** An initial POST request with a payload using `execSync('echo VULN')` to confirm exploitability.
        2.  **Malware Dropper / Reverse Shell:** A second, more complex payload designed to download and execute a binary (`xd.x86`) from `94.156.152.67` and/or initiate a reverse shell back to the attacking IP `87.120.191.67`.
*   **Assessment:** This activity shows a clear intent to compromise vulnerable web servers for malware deployment and persistent access. The actor(s) are using automated tools (`Go-http-client/1.1`) to first identify and then exploit vulnerable targets in a methodical manner.

**3.3 Finding 3: Infrastructure Overlap**

*   **Evidence:** The source IP `87.120.191.67` (AS215925) was an actor in both the CVE-2024-14007 and CVE-2025-55182 campaigns.
*   **Assessment:** This overlap provides a concrete link between two distinct, targeted operations. It indicates that the actor(s) either have a diverse set of objectives or that the infrastructure is part of a shared platform or service used for staging different exploit campaigns. This is a significant finding that elevates the importance of monitoring all activity from this ASN.

---

**4.0 CONCLUSION**

This investigation successfully moved beyond the analysis of high-volume noise to uncover evidence of at least two concurrent, targeted attack campaigns. These "minutia" attacks represent a more significant threat than typical background scanning due to their use of specific, high-impact exploits and their clear intent to compromise systems for further exploitation or malware deployment. The shared infrastructure between the two campaigns is a critical lead that strongly suggests a common actor or platform is responsible.

**END OF REPORT**
