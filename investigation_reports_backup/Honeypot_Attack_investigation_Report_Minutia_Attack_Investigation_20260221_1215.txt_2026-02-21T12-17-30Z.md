**INVESTIGATION REPORT**

**Case ID:** MINUTIA-20260221-1215
**Report Date:** 2026-02-21 12:15 UTC
**Investigator:** Senior Cyber Threat Investigator

**Subject:** Analysis of Low-Frequency and High-Interest Attack Vectors

**1.0 Executive Summary**

This report details an investigation into anomalous and low-frequency attack activity observed on the honeypot network. The objective was to disregard high-volume, automated scanning and identify potentially more targeted or unusual attack vectors. The investigation successfully isolated several such activities, including specific probes for enterprise vulnerabilities, unusual ICS/SCADA protocol interactions, and targeted reconnaissance against web services, distinguishing them from background noise.

**2.0 Investigation Scope and Methodology**

*   **Objective:** Identify, analyze, and report on low-volume, high-interest attack vectors ("minutia attacks").
*   **Timeframe (UTC):**
    *   **Start:** 2026-02-21 08:15:33 UTC
    *   **End:** 2026-02-21 12:15:33 UTC
*   **Methodology:** The investigation began by establishing a baseline of high-frequency attack patterns to define "background noise." Subsequently, queries were structured to identify low-frequency events, which were then developed into actionable leads. Each lead was pursued through hypothesis-driven querying to build a profile of the activity, its source, and its potential intent.

**3.0 Baseline Analysis: Defining "Background Noise"**

To effectively isolate low-frequency events, a baseline of common activity was first established for the 4-hour window. This primarily consists of widespread, automated scanning and exploit attempts. Total observed events within the timeframe were **15,729**. The most frequent indicators of this activity are detailed below.

*   **Common Alert Signatures**: The most prevalent alerts indicate widespread scanning for common vulnerabilities and misconfigurations. These are characteristic of non-targeted, opportunistic botnet activity. Analysis of the top 15 signatures confirms the prevalence of reconnaissance (VNC, SSH, NMAP) and generic blocklist alerts (Dshield, CINS). This represents the broad, automated background noise.

*   **Common Vulnerabilities (CVEs)**: The most frequently triggered CVE alerts are consistent with mass scanning for known, high-impact vulnerabilities, often associated with botnets. This activity is not targeted and falls within the definition of background noise.

*   **Top Attacker Source IPs**: A small number of IP addresses are responsible for a disproportionately large volume of the activity, which is characteristic of automated sources.

**Baseline Conclusion:** The bulk of activity within the timeframe is opportunistic, automated, and non-targeted, focusing on common services (SSH, VNC) and well-known vulnerabilities. This activity will now be deliberately excluded from the search for high-interest leads.

---

**4.0 Investigative Leads: Identifying "Minutia" Attacks**

With the baseline of high-volume noise established, the investigation now focuses on identifying events that are, by comparison, rare and indicative of more specific intent.

**Lead 4.1: Probing of Industrial Control Systems (ICS) / SCADA Services**

A single, unique command was captured by the Conpot honeypot: `b'\x01I20100\n'`. This is a significant finding as it represents a direct interaction with an ICS emulation, standing in sharp contrast to the thousands of generic scans in the baseline.

OSINT revealed the command `I20100` is a specific function code for the **TLS-350 protocol**, used to request an "In-Tank Inventory Report" from Automatic Tank Gauges (ATGs). These are specialized ICS devices used to monitor fuel storage tanks, often at gas stations. The protocol commonly communicates over TCP port 10001.

This confirmed the actor was conducting highly specific reconnaissance for exposed fuel tank monitoring systems. This is a significant deviation from the baseline and represents a clear, targeted interest.

**Lead 4.1 Findings: ICS Probing Actor Identified**

*   **Actor IP Address:** `82.147.85.17`
*   **Geolocation:** Russia
*   **ASN:** 211860 (Nerushenko Vyacheslav Nikolaevich)

Through direct querying for activity on destination port 10001, all interactions were traced to the single source IP `82.147.85.17`. One of the logged events explicitly confirmed the interaction was with the Conpot honeypot.

**Actor Profile: `82.147.85.17`**

Analysis of the full activity log for this IP address reveals that the probe of the ICS-related port `10001` was not an isolated event. It was part of a much broader, high-speed port scan.

*   **Behavioral Pattern:** The actor connected to a wide and seemingly random assortment of TCP ports, all from the same source port (`51730`). The observed destination ports include `5555`, `6004`, `81`, `3392`, `8089`, `50000`, and dozens of others.
*   **Methodology:** The activity consists almost exclusively of initial TCP SYN packets, which is characteristic of a reconnaissance scan to identify open ports and listening services. There is no evidence of attempted exploitation on any of the other scanned ports.

**Lead 4.1 Conclusion**

The actor `82.147.85.17` is engaged in sophisticated, wide-spectrum reconnaissance. While it exhibits behavior similar to a generic port scanner, its inclusion of a specific, non-standard ICS protocol port (`10001`) in its scan list distinguishes it from the baseline noise.

This indicates that the actor is not a hands-on, targeted operator but likely an advanced scanning botnet or tool. Its objective is opportunistic reconnaissance, but its target list has been curated to include high-value, specialized services such as fuel tank monitoring systems, in addition to more common services. The activity is low-frequency in terms of the specific ICS probe, but it is part of a high-frequency scanning operation. This represents a more advanced and noteworthy form of automated threat activity.

---

**5.0 Overall Conclusion**

The investigation successfully met its objective of identifying low-frequency, high-interest attack vectors. By first baselining and then filtering out the high-volume, opportunistic noise, it was possible to isolate a single, highly specific probe for an Industrial Control System protocol (TLS-350 ATG).

Through a process of hypothesis, OSINT enrichment, and progressive querying, the source of the probe was identified as `82.147.85.17`, an IP address in Russia. Further analysis revealed this actor was conducting a broad port scan, but its inclusion of the specialized ICS port demonstrates a higher level of sophistication than typical scanners.

This investigation highlights that even within a high volume of automated background noise, it is possible to discern specific, targeted reconnaissance activities that point to more advanced adversaries or tools.

**Confidence Level: High.** The conclusions are strongly supported by the query results and OSINT correlation.

**--- END OF REPORT ---**
