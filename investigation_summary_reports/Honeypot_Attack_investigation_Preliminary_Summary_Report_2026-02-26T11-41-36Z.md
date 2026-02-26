# Preliminary Report on Suspicious ICS Protocol Reconnaissance

## Summary
This report details findings from the investigation period of 2026-02-25T18:39:04Z to 2026-02-25T19:39:05Z. While no new zero-day exploits were confirmed, a highly suspicious and potentially novel reconnaissance campaign targeting Industrial Control System (ICS) protocols was identified. This activity is of high concern due to its targeted nature and the criticality of the protocols involved.

## Key Suspicious Activity
The most significant finding is the targeted probing of the `kamstrup_protocol` and the known-vulnerable `IEC-104` protocol. This is not commodity background noise but rather specific, targeted reconnaissance against a high-value, vulnerable protocol stack.

**Key Evidence:**
- **Targeted Protocols:** `kamstrup_protocol`, `IEC104`
- **Unmapped Commands:** The investigation noted specific, non-random commands that are not mapped to known TTPs.
- **Raw Kamstrup Requests:** Specific byte sequences were captured, indicating interaction beyond simple port scanning:
  - `b'\\x01I20100\\n'`
  - `b'000e0401040302010203040105010601ff01'`

## Analysis and Reasoning for Concern
The targeting of `IEC-104` is particularly alarming. This protocol is known to be insecure and has been exploited by sophisticated malware in the past, such as Industroyer2, in attacks against critical infrastructure. This activity strongly suggests a precursor to a more advanced attack. The use of specific, unmapped commands against the Kamstrup protocol further suggests an actor with specialized knowledge attempting to fingerprint or discover vulnerabilities in ICS environments.

## De-prioritized Activity
A significant volume of activity was attributed to the **"ufo.miner" cryptomining botnet**, which exploited open Android Debug Bridge (ADB) interfaces. This campaign was positively identified as a well-documented, known threat and is therefore not considered novel.

## Conclusion and Next Steps
The targeted ICS reconnaissance represents the most critical finding from this period. It is assessed with high confidence as potential pre-exploitation activity. Further investigation is required to:
1.  Identify the source infrastructure of the ICS probing campaign.
2.  Fully decode and understand the intent of the unmapped Kamstrup commands.
3.  Monitor for any escalation from reconnaissance to active exploitation attempts against these protocols.
