**INVESTIGATION REPORT**

**Case ID:** 2024-MINUTIA-01
**Date:** 2026-02-24
**Investigator:** Senior Cyber Threat Investigator
**Status:** Closed

**1.0 Executive Summary**

This investigation was initiated to identify and analyze low-frequency, high-interest attack vectors, distinct from high-volume automated scanning. The investigation successfully identified a sophisticated, multi-stage remote code execution (RCE) attempt against a Redis honeypot. The activity originated from source IP `120.48.108.130` and utilized a separate command and control (C2) server at `103.236.67.60`. The focused, complex nature of the attack chain indicates a skilled actor and stands in stark contrast to the baseline of opportunistic scanning observed during the same period.

**2.0 Investigation Scope and Timeframe**

*   **Objective:** Identify interesting attack vectors and low-engagement, high-interest attackers.
*   **Timeframe:** 2026-02-23T20:15:55Z to 2026-02-24T00:15:55Z (4 hours).

**3.0 Baseline Analysis**

A baseline of activity was established to filter out common, automated threats:

*   **Total Events:** 13,613 events were recorded.
*   **Top Attacker:** The most frequent external attacker was `173.249.27.120` (2,329 events), typifying automated scanning behavior.
*   **Common Vulnerabilities:** Probing for common CVEs such as `CVE-2024-14007` was observed.
*   **Common Web Scans:** Requests for root paths (`/`) and sensitive files (`.env`) were most frequent.

The baseline confirmed the environment is dominated by low-sophistication, high-volume scanning, providing a clear context against which to identify anomalies.

**4.0 Lead Identification and Hypothesis**

A review of Redis honeypot logs revealed a sequence of commands from `120.48.108.130` starting at `2026-02-23T21:17:46Z`. This activity was flagged as highly anomalous and indicative of a targeted attack.

*   **Hypothesis:** The actor at `120.48.108.130` was not a simple scanner but was actively attempting to exploit the Redis server to gain remote code execution on the underlying host.

**5.0 Investigation of Malicious Activity**

**5.1 Attacker IP: 120.48.108.130**
*   **ASN:** 38365, Beijing Baidu Netcom Science and Technology Co., Ltd., China.
*   **Observed TTPs:** The actor executed a classic Redis RCE attack pattern:
    1.  Connected to the Redis server.
    2.  Executed `CONFIG SET` to change the database directory and filename to `/tmp/exp.so`.
    3.  Used the `SLAVEOF` command to instruct the Redis server to replicate from a remote, actor-controlled server (`103.236.67.60`), effectively writing a malicious shared object file to disk.
    4.  Attempted to load the malicious payload using `MODULE LOAD /tmp/exp.so`.
    5.  Attempted to execute a reverse shell command via `system.exec` to download and run a second-stage payload from the same C2 server.
    6.  Conducted cleanup operations (`MODULE UNLOAD`, `rm -rf`).
*   **Corroborating Evidence:** Internal Suricata logs independently flagged the source IP with the signature "ET CINS Active Threat Intelligence Poor Reputation IP". OSINT queries did not link the IP to any major known botnets, suggesting a more independent operator.

**5.2 C2 Infrastructure: 103.236.67.60**
*   **Role:** This IP acted as the payload delivery and C2 server. It hosted the `exp.so` library and the second-stage `linux` payload.
*   **Activity:** No direct attacks originated from this IP. It served only as passive infrastructure for the primary attacker. This separation of concerns is a common operational security practice.
*   **OSINT:** No public threat intelligence was found for this IP, suggesting it may be new or purpose-built for this campaign.

**6.0 Analytical Conclusion**

The evidence strongly supports the hypothesis that `120.48.108.130` is a skilled threat actor who executed a targeted, multi-stage RCE attack. This activity is of high interest and significantly more sophisticated than the background noise of automated scanners.

*   **Nature of Activity:** Targeted exploitation attempt.
*   **Operational Sophistication:** Moderate to High. The actor used a known but complex attack chain and employed separate infrastructure for C2, but used an IP with a pre-existing poor reputation.
*   **Potential Intent:** To gain an initial foothold on the target system for further exploitation, data exfiltration, or to add the host to a botnet.
*   **Confidence Level:** High.

This investigation successfully fulfilled its objective by identifying and detailing an attack that, while low in volume (a single, focused event), was high in operational significance.

**7.0 Recommendations**

*   The IP address `103.236.67.60` should be blacklisted as a malicious C2 server.
*   The IP address `120.48.108.130` should be added to watchlists for any further malicious activity.

**-- END OF REPORT --**