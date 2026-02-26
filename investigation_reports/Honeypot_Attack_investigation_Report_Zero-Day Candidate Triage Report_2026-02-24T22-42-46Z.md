# Zero-Day Candidate Triage Report

## 1. Investigation Scope
- **Investigation Start:** 2026-02-24T22:23:52Z
- **Investigation End:** 2026-02-24T22:33:54Z
- **Completion Status:** Complete

## 2. Candidate Discovery Summary
- **Total Attacks Analyzed:** 1098
- **Top Services:**
  - SMB (Port 445): 6457 events (High volume negotiation)
  - VNC (Ports 5900-5905): 6181 events (Generic scanning/noise)
  - SSH (Port 22): 45 events (Targeted reconnaissance)
- **Candidates Identified:** 2 (1 Novel, 1 Known/Low-Priority)

## 3. Emerging n-day Exploitation
**Status:** Monitored / Low Priority
- **CVE-2024-14007 (Wyze Cam RCE):** Single instance detected. Classified as background scanning noise rather than active targeted exploitation in this window.

## 4. Known-Exploit Exclusions
- **SMB Scanning (Worm-like):** Source IP `197.249.6.172` (Mozambique) generated high-volume SMB1/SMB2 negotiation traffic typical of legacy worm behavior (e.g., WannaCry) or aggressive scanning. Excluded as commodity noise.
- **VNC Server Response Flood:** High volume of `GPL INFO VNC server response` alerts (85% of total volume) correlated with generic scanning from US IPs. Determined to be honeypot chatter.

## 5. Novel Exploit Candidates

### CAND-01: Campaign 'Firedancer' - Distributed Solana Validator Reconnaissance
- **Classification:** Novel Exploit Candidate
- **Novelty Score:** 9/10
- **Confidence:** High
- **Provisional:** No
- **Key Evidence:**
  - **Distributed Infrastructure:** Attacks originated from 5 distinct IPs across 3 continents (US, Vietnam, Romania) within a 10-minute window, indicating coordinated botnet activity.
  - **Specific Targeting:** The campaign explicitly targets the username `firedancer`, referring to the new high-performance C++ validator client for the Solana blockchain (live Mainnet Dec 2024). This indicates specific intent to compromise cryptocurrency infrastructure.
  - **Advanced Tooling:** The attackers utilize a Go-based SSH client (`SSH-2.0-Go`) configured with **Post-Quantum Cryptography** (`mlkem768x25519-sha256`). OSINT analysis confirms this algorithm is standard in very recent OpenSSH/Go versions (late 2024/2025), but its presence in an active botnet payload is highly unusual and suggests modern, actively maintained offensive tooling.
  - **Fingerprint:** All sources share the unique HASSH fingerprint `16443846184eafde36765c9bab2f4397`.
  - **Behavior:** Successful login followed immediately by OS enumeration (`uname -s -v -n -r -m`) and session termination.

## 6. Suspicious Unmapped Activity to Monitor
- **Solana Username Spraying:** The following IPs participated in the coordinated spraying of `solana`, `root`, and `firedancer` usernames but did not successfully execute payloads in this window:
  - `165.227.58.151` (US, DigitalOcean)
  - `80.94.92.186` (Romania, Unmanaged Ltd)
  - `157.230.132.221` (US, DigitalOcean)
  - `103.53.231.159` (Vietnam, AOHOAVIET)

## 7. Infrastructure & Behavioral Classification
- **Campaign 'Firedancer':**
  - **Infrastructure:** Leverages cloud providers (DigitalOcean) and budget hosting (Unmanaged Ltd, AOHOAVIET) for attack nodes.
  - **Tooling:** Custom or recently updated Go-based scanners capable of modern crypto negotiation.
  - **Intent:** Reconnaissance of specific cryptocurrency validator nodes.

## 8. Analytical Assessment
We assess with **High Confidence** that CAND-01 represents a targeted reconnaissance campaign aimed at the Solana cryptocurrency ecosystem, specifically the 'Firedancer' validator client. The use of Post-Quantum Cryptography (ML-KEM) in the attack tooling is a notable deviation from standard commodity botnets (Mirai/Gafgyt), suggesting the actor is using bleeding-edge or custom-compiled tools (Go 1.24+). While the observed payload was limited to system enumeration (`uname`), the specificity of the username targeting poses a credible threat to node operators.

## 9. Confidence Breakdown
- **CAND-01:** High. Evidence is multi-sourced (Cowrie, Suricata), distinct (unique HASSH), and validated via OSINT (confirmation of algo novelty and target relevance).
- **Exclusions:** High. Volume and signatures matches known commodity noise patterns.

## 10. Evidence Appendix

### CAND-01 Evidence
- **Source IPs:**
  - `178.128.176.175` (DigitalOcean, US) - Successful Login
  - `165.227.58.151` (DigitalOcean, US)
  - `157.230.132.221` (DigitalOcean, US)
  - `103.53.231.159` (AOHOAVIET, VN)
  - `80.94.92.186` (Unmanaged Ltd, RO)
- **Target Service:** SSH (Port 22)
- **Target Usernames:** `firedancer`, `solana`, `sol`, `root`
- **Tool Fingerprint (HASSH):** `16443846184eafde36765c9bab2f4397`
- **Key Exchange Algorithm:** `mlkem768x25519-sha256` (Post-Quantum)
- **Observed Command:** `/bin/./uname -s -v -n -r -m`

## 11. Indicators of Interest
- **HASSH:** `16443846184eafde36765c9bab2f4397`
- **Usernames:** `firedancer`
- **IPs:** `178.128.176.175`, `165.227.58.151`, `157.230.132.221`, `103.53.231.159`, `80.94.92.186`
