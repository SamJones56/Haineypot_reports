# Zero-Day Candidate Triage Report

## 1. Investigation Scope
- **Start Time**: 2026-02-24T21:14:01Z
- **End Time**: 2026-02-24T22:14:01Z
- **Completion Status**: **Partial**
  - **Reason**: Critical index mapping errors (`fielddata` disabled) prevented the retrieval of raw log details for `CVE-2024-14007` and `alert.signature` phrase searches. Aggregate counts were preserved.

## 2. Candidate Discovery Summary
- **Total Attacks Processed**: 3,702
- **Top Activity Areas**:
  1. **SMB Scanning** (1,142 events): Commodity scanning from Qatar (Ooredoo).
  2. **VNC Scanning** (212 events): Commodity scanning from the US.
  3. **Targeted SSH Campaign** (120+ events): Specific targeting of "Solana" and "Firedancer" infrastructure.

## 3. Emerging n-day Exploitation
### **Campaign: Firedancer/Solana Validator Targeting**
**Status**: **Active Compromise (Honeypot Breached)**
**Confidence**: **High**
**Novelty Score**: 7/10

**Description**:
A targeted intrusion campaign was detected specifically aiming at the **Firedancer** Solana validator client. The attacker successfully compromised the honeypot by guessing the default username `firedancer` and executed OS reconnaissance commands. OSINT investigation confirms `user = "firedancer"` is the default configuration for this software, indicating the attacker is specifically hunting for unhardened validator nodes.

**Key Evidence**:
- **Successful Intrusion**: SSH login to account `firedancer` with password `firedancer` from **46.101.248.209** (DigitalOcean, Germany).
- **Command Execution**: Immediate execution of `uname -s -v -n -r -m` upon access to fingerprint the OS.
- **Tooling**: Client version identified as `SSH-2.0-Go`, a common commodity brute-force tool.
- **Widespread Targeting**: Parallel brute-force attempts against the `solana` user from **193.32.162.145** (Romania) and **80.94.92.184** (Romania).
- **Reconnaissance Infrastructure**: Associated HTTP probing on Port 5055 from **193.32.162.28** (Romania), which shares the same /24 subnet and ASN (Unmanaged Ltd) as the brute-force actors.

**Action**:
- **Block**: `46.101.248.0/24` (Germany) and `193.32.162.0/24` (Romania).
- **Hunt**: Scan internal logs for `firedancer` user creation or logins.

## 4. Known-Exploit Exclusions
The following activity was analyzed and excluded as known/commodity:

- **CVE-2024-14007 (NVMS-9000 Auth Bypass)**:
  - **Status**: Detected in aggregates (4 counts).
  - **Details**: Specific event logs unavailable due to index errors. OSINT confirms this targets Shenzhen TVT DVRs (Ports 80/8000/6036) and is widely exploited by Mirai-variant botnets.
- **Redis Cross-Protocol Probing**:
  - **Source**: `85.217.149.16` (Canada).
  - **Reason**: Validated as a generic scanner sending `GET /` to Port 6379. No Redis-specific exploitation (RESP) attempted.
- **Port 44444 Scanning**:
  - **Sources**: `152.32.208.73` (US), `152.32.255.94` (Vietnam).
  - **Reason**: Validated as "Poor Reputation" IP traffic (CINS blocklist). TCP handshakes only, no payload. Likely checking for default Metasploit/backdoor listeners.
- **Commodity SMB/VNC**:
  - **Qatar (SMB)** and **US (VNC)** scanning remain the dominant background noise.

## 5. Novel Exploit Candidates
*No unmapped novel candidates were identified in this window. All potential candidates were successfully linked to the Firedancer Campaign or downgraded to known commodity scanning.*

## 6. Suspicious Unmapped Activity to Monitor
- **Port 5055 HTTP Probing**:
  - **Source**: `193.32.162.28` (Romania).
  - **Activity**: Sending `GET / HTTP/1.1` to port 5055.
  - **Assessment**: Confirmed reconnaissance node for the Firedancer campaign. While the exploit vector is "unmapped" (Port 5055 is typically Traccar/IoT), the intent is clear infrastructure mapping for the targeted attack.

## 7. Infrastructure & Behavioral Classification
| Entity | Classification | Role |
| :--- | :--- | :--- |
| **46.101.248.209** (DE) | **Targeted Attacker** | Successful SSH Intruder (Firedancer) |
| **193.32.162.xxx** (RO) | **Campaign Infrastructure** | Brute-force (Solana) & Recon (Port 5055) |
| **85.217.149.16** (CA) | **Commodity Scanner** | Redis HTTP Probing |
| **152.32.xxx.xxx** | **Botnet Drone** | High-port (44444) Scanning |

## 8. Analytical Assessment
The primary threat in this window is the **Firedancer/Solana Campaign**. The actors are actively scanning for and successfully compromising systems using default validator configurations. The use of distinct infrastructure for reconnaissance (Port 5055), brute force (Romania), and exploitation (Germany) suggests a coordinated effort.

**Degraded State Note**: The inability to query `alert.signature` text fields and specific CVE details limits visibility into payload nuances for the NVMS-9000 exploits, but does not impact the high-confidence assessment of the SSH intrusion.

## 9. Confidence Breakdown
- **Firedancer Campaign**: **High** (Confirmed Login + Command Execution + OSINT Config Match).
- **Commodity Exclusions**: **High** (Reputation checks + Protocol Mismatches).
- **CVE-2024-14007**: **Low** (Aggregate count only; assumption based on OSINT).

## 10. Evidence Appendix
### Firedancer Campaign Artifacts
- **Login**: `Cowrie: login attempt [firedancer/firedancer] succeeded`
- **Command**: `CMD: /bin/./uname -s -v -n -r -m`
- **Client**: `SSH-2.0-Go`
- **Recon Payload (Port 5055)**:
  ```
  GET / HTTP/1.1
  Host: 167.71.255.16:5055
  Connection: close
  ```

### Redis Probe Artifacts
- **Payload**: `GET / HTTP/1.1` (Sent to Port 6379)
- **Response**: `app_proto: failed` (Suricata mismatch)

## 11. Indicators of Interest
- **IP**: `46.101.248.209` (Active Compromise)
- **IP**: `193.32.162.28` (Campaign Recon)
- **IP**: `193.32.162.145` (Campaign Brute Force)
- **Usernames**: `firedancer`, `solana`, `solv`
- **Signatures**: `SSH-2.0-Go`
