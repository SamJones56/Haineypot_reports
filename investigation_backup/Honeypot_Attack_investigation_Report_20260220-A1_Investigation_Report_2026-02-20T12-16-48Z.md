**INVESTIGATION REPORT**

**Case ID:** 20260220-A1
**Date:** 2026-02-20
**Investigator:** Senior Cyber Threat Investigator
**Status:** Open/Monitoring

---

**1.0 INVESTIGATION SCOPE**

*   **Objective:** To analyze threat activity against the tpot-hive-ny honeypot, establish a baseline of normal activity, identify significant threat actors and campaigns, and assess the nature of the observed threats.
*   **Timeframe:** 2026-02-20 06:15:39Z to 2026-02-20 12:15:39Z (6-hour window).

---

**2.0 EXECUTIVE SUMMARY**

During the defined 6-hour window, the honeypot registered 32,811 malicious events. The threat landscape was dominated by high-volume, automated scanning from a small number of sources, alongside widespread, generic credential brute-force attempts.

Two primary actors were identified, operating from single IP addresses in Azerbaijan and Indonesia, who were exclusively responsible for a coordinated and intense scanning campaign against the SMB protocol (TCP/445).

Additionally, a significant number of alerts (1,384) indicating the presence of the **DoublePulsar backdoor** were observed. However, attribution of this activity was not possible due to data field limitations in the logging environment. This activity represents the most critical potential threat identified during the investigation period, despite being unattributed. The remainder of the activity was assessed as low-sophistication, opportunistic background noise.

---

**3.0 BASELINE ANALYSIS & THREAT LANDSCAPE**

A baseline of activity was established to contextualize the threat environment.

*   **Total Attack Volume:** 32,811 events.
*   **Geographic Distribution:** Activity was observed from numerous countries, with the top sources being Germany (5,035 events), the United States (5,033 events), Indonesia (3,123 events), and Azerbaijan (3,108 events).
*   **Infrastructure Distribution:** The most active Autonomous System (AS) was AS14061 (DigitalOcean, LLC) with 9,789 events, indicating broad scanning from cloud infrastructure. This was followed by AS28787 (Aztelekom LLC) and AS23693 (PT. Telekomunikasi Selular).
*   **Commonly Targeted Services:** The most frequently targeted service was SMB (TCP/445), followed by SSH (TCP/22), Telnet (TCP/23), and Redis (TCP/6379).
*   **Common Attack Signatures:** The most prevalent signature was `GPL INFO VNC server response` (13,680 events), indicative of basic reconnaissance scanning.

---

**4.0 LEAD DEVELOPMENT & HYPOTHESIS TESTING**

**4.1. Lead 1: High-Volume SMB Scanning Campaign**

*   **Observation:** Two source IPs were responsible for a disproportionately high volume of events that correlated directly with the total activity from their respective ASNs and countries.
    *   **Actor 1:** IP `213.154.18.82` (AS28787, Aztelekom LLC, Azerbaijan) generated 3,108 events.
    *   **Actor 2:** IP `182.10.97.25` (AS23693, PT. Telekomunikasi Selular, Indonesia) generated 3,101 events.

*   **Hypothesis:** These actors are engaged in a coordinated, automated campaign targeting a specific service.

*   **Validation:** Querying for port activity from these geographic locations confirmed the hypothesis. 100% of the events from both Azerbaijan (3,108) and Indonesia (3,101) were directed at TCP port 445 (SMB).

*   **Assessment:** This behavior is characteristic of a widespread, opportunistic worm or scanner attempting to identify and exploit SMB vulnerabilities. The activity is high-volume but low in sophistication, relying on scanning a single service from a static IP address.

**4.2. Lead 2: DoublePulsar Backdoor Activity**

*   **Observation:** A significant number of high-severity alerts were identified:
    *   **Signature:** `ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication`
    *   **Volume:** 1,384 events.

*   **Hypothesis:** One or more threat actors are attempting to deploy or communicate with the DoublePulsar backdoor, which is commonly associated with the EternalBlue exploit (CVE-2017-0144).

*   **Validation:** Multiple attempts were made to correlate these alert signatures with source IP addresses using `custom_nested_search` and `suricata_lenient_phrase_search`. These attempts failed due to an Elasticsearch configuration that prevents aggregation on the `alert.signature` text field.

*   **Assessment:** The presence of DoublePulsar-related activity is a significant finding, indicating attempts to use a powerful, wormable backdoor. **However, a critical gap in data accessibility prevents the attribution of this activity to any specific actor.** This remains the most serious, albeit unresolved, threat in this report.

**4.3. Background Noise: Credential Brute-Force Activity**

*   **Observation:** Analysis of captured credentials revealed patterns consistent with automated brute-force attacks.
    *   **Top Usernames:** `root`, `admin`, `ubuntu`, `oracle`, `postgres`.
    *   **Top Passwords:** `123456`, `password`, `12345`, `<blank>`.

*   **Assessment:** This activity represents generic, untargeted attempts to gain access using common default credentials. It constitutes background noise and is assessed as low-sophistication.

---

**5.0 CONCLUSION**

The 6-hour period was characterized by two distinct types of threat activity:

1.  **High-Volume, Low-Sophistication Scanning:** A significant portion of the total attack volume was generated by two single actors scanning for SMB. This activity is considered opportunistic and automated.

2.  **Significant but Unattributed Exploitation Attempts:** The detection of 1,384 DoublePulsar backdoor alerts is of high concern. This indicates a more sophisticated level of threat than simple scanning. The inability to attribute this activity to a source represents a significant investigative limitation and is the highest priority for further monitoring.

**Confidence Level:**
*   **High Confidence** in the assessment of the SMB scanning campaigns and general brute-force activity.
*   **Low Confidence** in the ability to attribute the DoublePulsar activity due to technical constraints.

**Recommendations:**
*   Monitor for any further activity from `213.154.18.82` and `182.10.97.25`.
*   Investigate data indexing limitations to enable future attribution of critical alert signatures like DoublePulsar.
*   Maintain awareness of the potential for active exploitation related to the EternalBlue/DoublePulsar toolset.

---
**END OF REPORT**
---