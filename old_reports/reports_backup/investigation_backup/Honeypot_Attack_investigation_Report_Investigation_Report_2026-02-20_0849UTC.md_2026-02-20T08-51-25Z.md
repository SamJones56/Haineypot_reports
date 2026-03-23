### INVESTIGATION REPORT

**CASE ID:** 6HR-20260220-0849
**DATE:** 2026-02-20 08:49:10 UTC
**INVESTIGATOR:** Senior Cyber Threat Investigator

---

**1.0 INVESTIGATION SCOPE**

*   **Objective:** To conduct a threat investigation into activities recorded on the `tpot-hive-ny` honeypot (134.199.242.175) over a defined six-hour period. The investigation aimed to establish a baseline of threat activity, identify significant actors and infrastructure, and analyze notable tactics, techniques, and procedures (TTPs).
*   **Timeframe:**
    *   **Start:** 2026-02-20T02:49:10Z UTC
    *   **End:** 2026-02-20T08:49:10Z UTC

---

**2.0 EXECUTIVE SUMMARY**

During the six-hour analysis window, 23,477 malicious or anomalous events were recorded. The activity was broadly characterized by high-volume, automated scanning from a diverse set of global sources. Three specific threat actors or campaigns were identified as particularly significant and were subject to focused investigation:

1.  **High-Frequency SMB Scanning (Indonesia):** A single IP address, `182.10.97.25` (AS23693 - PT. Telekomunikasi Selular), was identified as a prolific scanner of the SMB service on port 445. This activity was directly correlated with alerts for the DoublePulsar backdoor, indicating a systematic search for systems vulnerable to the EternalBlue exploit.
2.  **Systematic VNC Scanning Campaign (Singapore):** A single IP address, `4.145.113.4`, hosted on Microsoft Azure infrastructure (AS8075) in Singapore, was responsible for over 2,200 events. This actor conducted a methodical scan across multiple non-standard VNC ports, accounting for the highest volume of `VNC server response` alerts.
3.  **Widespread Abuse of Cloud Infrastructure:** The most active autonomous system was AS14061 (DigitalOcean, LLC), which accounted for over 6,300 events from numerous distinct IP addresses. This indicates a persistent pattern of various threat actors abusing DigitalOcean's cloud infrastructure to conduct opportunistic scanning and attacks.

The investigation concludes that the majority of the threat landscape in this period was dominated by opportunistic, automated campaigns rather than targeted attacks. The primary intent appears to be the identification and potential exploitation of common, unpatched vulnerabilities (SMB) and exposed remote access services (VNC).

---

**3.0 BASELINE ANALYSIS**

A baseline of activity was established to contextualize the threat landscape.

*   **Total Attack Volume:** 23,477 events.
*   **Top Attacker Countries:** United States (5,993), Indonesia (3,219), Germany (2,856), Singapore (2,315).
*   **Top Attacker ASNs:** AS14061 (DigitalOcean, LLC: 6,375), AS23693 (PT. Telekomunikasi Selular: 3,146), AS8075 (Microsoft Corporation: 2,425).
*   **Top Alert Signatures:**
    *   `GPL INFO VNC server response` (13,556 events)
    *   `ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication` (1,384 events)
*   **Credential Stuffing:** Common credentials such as `root`, `admin`, `test` with passwords like `password`, `123456`, and `admin` were prevalent, indicating widespread brute-force attempts.
*   **CVEs:** Low-volume probing for a variety of CVEs was observed, with the most frequent being `CVE-2024-14007` (20 events). This activity appears exploratory.

---

**4.0 INVESTIGATIVE FINDINGS & HYPOTHESIS TESTING**

**4.1 Lead 1: High-Frequency SMB Scanning from 182.10.97.25**

*   **Hypothesis:** The high volume of traffic from `182.10.97.25` originating in Indonesia is an automated campaign specifically targeting the SMB protocol to exploit vulnerabilities related to EternalBlue/DoublePulsar.
*   **Validation:**
    *   Initial data showed `182.10.97.25` was the most active single IP address with 3,146 events.
    *   The country-to-port analysis revealed that traffic from Indonesia almost exclusively targeted port 445 (SMB).
    *   The `ET EXPLOIT...DoublePulsar` signature was one of the most frequent alerts.
    *   A targeted query on `182.10.97.25` confirmed its activity was composed entirely of connection attempts to port 445, validating the hypothesis with high confidence.
*   **Conclusion:** This actor is an opportunistic scanner focused on a single, well-known vulnerability. The activity is automated and not targeted at the honeypot specifically.

**4.2 Lead 2: Systematic VNC Scanning from 4.145.113.4**

*   **Hypothesis:** An actor or botnet operating from Singaporean infrastructure is conducting a systematic scan for open VNC servers.
*   **Validation:**
    *   Initial data showed highly uniform scanning from Singapore across multiple VNC-related ports (5904, 5906, 5907, etc.), correlating with the top alert signature, `GPL INFO VNC server response`.
    *   A targeted query on port 5904 revealed all observed traffic originated from a single IP address: `4.145.113.4`.
    *   This IP was identified as the second-most active attacker overall (2,275 events), linking the high-volume attacker to the specific VNC scanning TTP.
    *   OSINT confirmed the IP is hosted on Microsoft Azure (AS8075) in Singapore. While the IP itself has no public negative reputation, the honeypot data provides direct evidence of its malicious scanning activity.
*   **Conclusion:** A single actor operating from `4.145.113.4` is responsible for a high-volume, methodical VNC scanning campaign. This demonstrates the use of legitimate cloud infrastructure for malicious reconnaissance.

**4.3 Lead 3: Abuse of DigitalOcean Hosting (AS14061)**

*   **Hypothesis:** DigitalOcean's infrastructure is a primary source of attack traffic due to its widespread abuse by multiple, independent actors for opportunistic scanning.
*   **Validation:**
    *   AS14061 was the top originating ASN with 6,375 events.
    *   Analysis of the top 10 attacker IPs revealed that at least five of them resolve to DigitalOcean (`138.68.109.50`, `64.227.172.219`, etc.).
    *   The distribution of attacks across numerous distinct IPs from the same cloud provider strongly supports the hypothesis that this is not a single, coordinated actor but a pattern of infrastructure abuse by many.
*   **Conclusion:** The data supports, with moderate confidence, that DigitalOcean is a favored platform for actors conducting low-sophistication, high-volume attacks, consistent with industry-wide observations of cloud service abuse.

---

**5.0 ANALYTICAL CONCLUSION**

The threat activity within the six-hour window was characterized by automated, opportunistic scanning campaigns. The key actors identified were highly focused in their objectives, with one dedicated to SMB exploitation and another to VNC reconnaissance. The heavy reliance on disposable cloud infrastructure (DigitalOcean, Microsoft Azure) for these operations is a significant and persistent trend. There is no evidence to suggest any of the observed activity was specifically targeted at the honeypot or represented a novel or sophisticated threat.

**Confidence Level: High**

---
***END OF REPORT***
