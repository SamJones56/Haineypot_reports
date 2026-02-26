# Zero-Day Candidate Triage Report

### 1. Investigation Scope
- **investigation_start**: 2026-02-26T07:00:08Z
- **investigation_end**: 2026-02-26T07:30:08Z
- **completion_status**: Complete

### 2. Candidate Discovery Summary
A total of 1,381 attack events were analyzed in this 30-minute window. The majority of activity consists of broad, opportunistic scanning for common services such as VNC, SSH, and SMB from geographically dispersed sources. No strong candidates for novel zero-day exploits were identified. However, two distinct, unmapped activities were flagged for monitoring: a high concentration of traffic from a single Swiss IP to the non-standard port 15433, and minor probing of an Industrial Control System (ICS) protocol.

### 3. Known-Exploit Exclusions
The following known activities and low-priority alerts were excluded from novel candidate consideration:
- **Commodity Scanning**: Widespread scanning and brute-force attempts against common services including VNC (ports 5902, 5906, 5907, 5911), SSH (port 22), Telnet (port 23), and SMB (port 445).
- **Generic Scan Signatures**: Network reconnaissance alerts such as `ET SCAN NMAP -sS window 1024` and blocklist hits like `ET DROP Dshield Block Listed Source group 1` were classified as background noise.
- **Low-Volume CVE Activity**: Minor, isolated events matching signatures for `CVE-2019-11500`, `CVE-2021-3449`, and `CVE-2024-14007` (2 events each) were observed and excluded as they do not appear to be part of a coordinated campaign.

### 4. Novel Exploit Candidates
No activity meeting the criteria for a novel exploit candidate was identified during this investigation period.

### 5. Suspicious Unmapped Activity to Monitor
The following activities lack clear exploit signatures but exhibit unusual characteristics and warrant continued monitoring:

- **Activity Cluster 1: Focused Probing on Non-Standard Port 15433**
  - **Description**: A significant volume of traffic (99 events) was directed at TCP port 15433, originating exclusively from the IP address `46.19.137.194` in Switzerland. This port is not commonly associated with a standard service, and the focused nature of the traffic suggests targeted reconnaissance or an attempt to exploit a proprietary or custom application.
  - **Supporting Evidence**: `BaselineAgent` data shows Switzerland targeting port 15433 with 99 events, and `46.19.137.194` as the top source IP with 101 total events.

- **Activity Cluster 2: ICS Protocol Probing**
  - **Description**: The Conpot honeypot detected two events targeting the 'guardian_ast' protocol. Any interaction with ICS-related protocols is noteworthy due to the potential for attacks against critical infrastructure. While the volume is very low, it indicates actor interest in this uncommon protocol.
  - **Supporting Evidence**: `HoneypotSpecificAgent` reported 2 events for the 'guardian_ast' protocol.

### 6. Infrastructure & Behavioral Classification
- **Port 15433 Activity**: The activity originates from AS51852 (Private Layer INC), a hosting provider in Switzerland. The behavior is classified as **Focused Service Probing**, characterized by a single source attempting to interact with a specific, non-standard port at scale.
- **ICS Probing**: The source of this activity is not specified in the data, but the behavior is classified as **Targeted Reconnaissance** against specialized ICS protocols.
- **General Scanning**: A wide baseline of activity originates from various cloud and hosting providers, including DigitalOcean (AS14061), Google (AS396982), and Amazon (AS16509). This behavior is classified as **Opportunistic Mass Scanning**.

### 7. Analytical Assessment
The investigation was completed successfully with no tool failures or evidence gaps. The threat landscape in this period is dominated by background scanning noise. The primary items of interest are the focused activity on port 15433 and the ICS protocol probing. Neither of these provides direct evidence of an exploit, but their deviation from baseline scanning patterns makes them priorities for ongoing monitoring. The port 15433 traffic is the most anomalous signal due to its volume and single-source origin.

### 8. Confidence Breakdown
- **Overall Assessment Confidence**: High
  - The analysis was based on a complete set of data from all sensor platforms. There were no tool errors or degradations reported that would impact the final conclusions.

### 9. Evidence Appendix
- **Item: Focused Probing on Non-Standard Port 15433**
  - **source IPs with counts**: `46.19.137.194` (101)
  - **ASNs with counts**: AS51852 / Private Layer INC (101)
  - **target ports/services**: 15433
  - **paths/endpoints**: N/A
  - **payload/artifact excerpts**: Evidence not available.
  - **previous-window / 24h checks**: Evidence not available.

- **Item: ICS Protocol Probing**
  - **source IPs with counts**: Evidence not available.
  - **ASNs with counts**: Evidence not available.
  - **target ports/services**: guardian_ast (protocol)
  - **paths/endpoints**: N/A
  - **payload/artifact excerpts**: Evidence not available.
  - **previous-window / 24h checks**: Evidence not available.

### 10. Indicators of Interest
- **IP Address**: `46.19.137.194` (High-volume, single-source scanning of non-standard port 15433)
- **Port**: `15433/TCP` (Target of focused, unmapped activity)
- **Protocol**: `guardian_ast` (ICS protocol being probed)

### 11. Backend tool issues
- None. All backend tools and queries completed successfully.