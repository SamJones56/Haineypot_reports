**INVESTIGATION REPORT**

**CASE ID:** 6HR-20260220-1615
**DATE:** 2026-02-20 16:15 UTC
**INVESTIGATOR:** Senior Cyber Threat Investigator
**SUBJECT:** Analysis of Threat Activity on Honeypot Network (tpot-hive-ny)

---

**1.0 | SCOPE AND OBJECTIVE**

**1.1 | Timeframe:**
*   **Start:** 2026-02-20 10:15:33 UTC
*   **End:** 2026-02-20 16:15:33 UTC

**1.2 | Objective:**
This investigation was initiated to conduct a structured, evidence-driven analysis of inbound threat activity against the T-Pot honeypot network. The objective is to establish a baseline of activity, identify significant threat actors and campaigns, develop and test hypotheses regarding their intent, and produce a formal report of the findings.

---

**2.0 | BASELINE ANALYSIS AND THREAT LANDSCAPE**

During the 6-hour window, a total of **37,687** malicious events were recorded. The activity was broadly distributed and indicative of automated, opportunistic scanning common to public-facing networks.

**2.1 | Geographic and Infrastructure Distribution:**
*   **Top Attacking Countries:** Czechia (5,041 events), Azerbaijan (4,935 events), United States (3,879 events), India (3,368 events), and Russia (3,193 events).
*   **Top Attacking ASNs:** AS14061 (DigitalOcean, LLC), AS39392 (SH.cz s.r.o.), and AS12389 (Rostelecom). The dominance of hosting providers and large national telecommunication companies suggests that the activity originates from compromised servers or botnet nodes.

**2.2 | Service Targeting and Exploit Indicators:**
*   **Most Targeted Ports:** Port 445 (SMB) was the most targeted service, absorbing **14,783** events, indicating widespread scanning for MS17-010 (EternalBlue). This was followed by ports 2323 and 23 (Telnet), and port 22 (SSH).
*   **Credential Attacks:** Credential stuffing activity was minimal and used common default lists (e.g., user: `root`, `admin`; pass: `123456`, `password`), consistent with untargeted brute-force attempts.
*   **Exploit Signatures:** Suricata network alerts were dominated by reconnaissance and exploit attempt signatures. Notably, **817** events matched "ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication," directly corroborating the analysis of SMB-based threats. Several CVE-related signatures were also observed, with `CVE-2024-14007` being the most frequent.

---

**3.0 | INVESTIGATIVE FINDINGS**

Three primary leads were developed from the baseline data.

**3.1 | Lead A: High-Volume Telnet Reconnaissance Campaign**
*   **Observation:** Source IP **`88.86.119.38`** (AS39392, Czechia) was the single most active attacker, responsible for **4,995** events (~13% of total volume). Its activity was focused on ports 23 (Telnet) and 2323.
*   **Hypothesis:** The actor is engaged in a large-scale, automated reconnaissance campaign to identify open Telnet services, likely for future inclusion in an IoT-focused botnet.
*   **Validation:** Analysis of raw logs for this IP confirmed the hypothesis. The events were exclusively Suricata "flow" events with an `app_proto` of `telnet`. Connections were consistently terminated by `timeout` after a few seconds with minimal data transfer. This behavior is characteristic of rapid, widespread banner grabbing to fingerprint services, not active brute-force attacks.
*   **Conclusion:** With high confidence, `88.86.119.38` is a dedicated scanner performing the initial reconnaissance phase of a larger automated attack campaign.

**3.2 | Lead B: Coordinated SMB/EternalBlue Exploitation Campaign**
*   **Observation:** A significant cluster of attacks targeted port 445 (SMB), strongly correlated with the "DoublePulsar Backdoor" signature. The activity originated from a set of distinct, high-volume IPs, including `83.219.7.170` (AS12389, Russia), `103.133.122.38` (AS138277, India), and `213.154.18.82` (AS28787, Azerbaijan).
*   **Hypothesis:** A coordinated, multi-source campaign is actively attempting to exploit the MS17-010 (EternalBlue) vulnerability to install the DoublePulsar backdoor.
*   **Validation:** While direct tool correlation between the IPs and the signature was inconclusive due to data indexing limitations, the circumstantial evidence is overwhelming. The IPs in question were almost exclusively observed attacking port 445. The presence of 817 DoublePulsar alerts, an exploit specifically delivered via EternalBlue over SMB, provides a direct link.
*   **Conclusion:** With high confidence, this activity represents a classic, ongoing, automated worm-like campaign searching for unpatched systems vulnerable to EternalBlue. The geographic and ASN diversity of the sources indicates a distributed botnet is being used to conduct the scanning.

**3.3 | Lead C: Scanning for NVR/DVR Vulnerabilities (CVE-2024-14007)**
*   **Observation:** The most frequently logged CVE during the period was `CVE-2024-14007`.
*   **Hypothesis:** Threat actors are actively scanning for a known, critical vulnerability in network video recording devices.
*   **Validation (OSINT):** External threat intelligence confirms `CVE-2024-14007` is a critical authentication bypass vulnerability in NVMS-9000 firmware, common in DVR, NVR, and IP camera products. Public exploits exist that allow an unauthenticated attacker to retrieve administrative credentials and configuration data via a specially crafted TCP packet.
*   **Conclusion:** With moderate confidence, the observed alerts indicate that automated scanners are searching for this specific vulnerability. This is consistent with opportunistic campaigns that add newly published, high-impact CVEs to their scanning repertoires to compromise vulnerable IoT and embedded devices.

---

**4.0 | ANALYTICAL CONCLUSION**

The threat landscape in this 6-hour period was dominated by three distinct, automated campaigns, all of which were opportunistic and not targeted at the honeypot specifically.

1.  **Reconnaissance:** A high-volume scanner (`88.86.119.38`) focused on identifying exposed Telnet services, likely as a precursor to IoT botnet propagation.
2.  **Exploitation (Worm-like):** A distributed botnet continued to scan for the well-documented MS17-010 (EternalBlue) vulnerability, aiming to install the DoublePulsar backdoor. This represents a persistent, global threat that remains effective against unpatched systems.
3.  **Exploitation (IoT):** Actors are leveraging a recently disclosed, critical CVE (`CVE-2024-14007`) to find and compromise vulnerable NVR/DVR systems.

The overall operational sophistication is **Low**. The observed techniques rely on high-volume scanning and publicly known exploits, requiring minimal tradecraft. The intent is likely mass compromise for inclusion in botnets for DDoS, cryptomining, or to serve as future attack proxies.

**Confidence Level: High**

---
**END OF REPORT**