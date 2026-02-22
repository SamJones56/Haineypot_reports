
**CASE ID:** CTI-20240101-001
**DATE:** 2026-02-22
**INVESTIGATOR:** Senior Cyber Threat Investigator
**SUBJECT:** Investigation into Low-Volume, High-Interest Attack Vectors within a 4-Hour Window.

**1.0 OBJECTIVE**
To identify and analyze "minutia" attack vectors—low-frequency but operationally significant activities—observed against the tpot-hive-ny honeypot (134.199.242.175) during the period of 2026-02-22T08:15:45Z to 2026-02-22T12:15:45Z.

**2.0 SUMMARY OF FINDINGS**
This investigation successfully isolated a targeted, multi-service reconnaissance campaign from the significant background noise of generic internet scanning. Despite technical challenges preventing the analysis of initial leads from ICS and ADB honeypots, a subsequent pivot to alert data analysis identified a single actor operating from multiple cloud-based IPs. This actor utilized a custom tool to methodically search for misconfigured Apache Solr, Docker Registry, and InfluxDB instances, demonstrating a higher level of sophistication and more specific intent than the majority of observed traffic.

**3.0 BASELINE ACTIVITY (08:15Z - 12:15Z)**
A baseline of activity was established to distinguish between common background noise and anomalous events.
- **Total Events:** 16,080 events were recorded.
- **Dominant Actors:** Activity was dominated by a small number of source IPs and ASNs, with AS14061 (DigitalOcean, LLC) accounting for over 45% of all traffic. The top source IP, `139.59.62.156`, was responsible for over 3,300 events.
- **Common Targets:** The most frequently targeted ports were standard services perpetually scanned on the internet: SSH (22), SMB (445), and VNC (5901-5903).
- **Prevalent Alerts:** The most common alert signatures were informational or related to generic scanning (e.g., `SURICATA SSH invalid banner`, `GPL INFO VNC server response`), confirming the low-sophistication nature of the baseline activity.

**4.0 INVESTIGATIVE LEADS**

**4.1 Abandoned Leads: ICS and ADB Probing**
Initial queries revealed low-frequency interactions with the Conpot (ICS) and Adbhoney (ADB) honeypots. These leads were promising as they represented attacks against less common targets. However, repeated attempts to retrieve the full event data for these interactions failed, preventing the identification of the source actors and forcing the abandonment of these lines of inquiry. This data retrieval anomaly is noted as a technical limitation encountered during the investigation.

**4.2 Confirmed Lead: Targeted Reconnaissance Campaign (Actor "SOLR-GO-RECON")**
A pivot to analyzing low-frequency alert signatures revealed a cluster of 11 events for "ET INFO Apache Solr System Information Request" (SID 2031504). This lead was successfully developed and attributed to a single coordinated campaign.

- **Infrastructure:** The campaign originated from three source IPs, all hosted within AS14061 (DigitalOcean, LLC):
    - `157.230.81.78` (Primary)
    - `159.203.177.245`
    - `142.93.164.45`

- **Tactics, Techniques, and Procedures (TTPs):**
    - **Custom Tooling:** The actor consistently used a `Go-http-client/1.1` User-Agent, indicating the use of a custom-written tool in the Go language.
    - **Multi-Target Probing:** The investigation revealed that this actor was not solely focused on Solr. Their tool was observed making specific, unauthenticated API requests to fingerprint a variety of services:
        - **Apache Solr:** `GET /solr/admin/info/system` and `GET /solr/admin/cores?action=STATUS&wt=json`
        - **Docker Registry:** `GET /v2/_catalog`
        - **InfluxDB (or similar):** `GET /query?q=SHOW+DIAGNOSTICS`
    - **Wide Port Scanning:** The reconnaissance was not limited to default service ports. The actor scanned a broad range of ports (including 80, 1434, 2181, 8087, 9200, 15671), attempting to find the targeted services running in non-standard configurations.

**5.0 ANALYTICAL CONCLUSION**
The "SOLR-GO-RECON" actor exhibits a **moderate level of sophistication** that is significantly distinct from the baseline noise. The campaign is automated, targeted, and methodical. The actor's intent is assessed with **high confidence** as **intelligence gathering**—specifically, to identify and catalog vulnerable, misconfigured web-based services (search platforms, container registries, databases) for future exploitation.

This activity represents a more focused and potentially more dangerous threat than the opportunistic scanners that comprise the bulk of inbound traffic. The actor's TTPs suggest a focus on modern infrastructure and services commonly found in cloud environments.

**6.0 END OF REPORT**
