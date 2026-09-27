# MITRE ATT&CK Mapping

## Techniques Observed in This Lab

| Technique | ID | Detected? | Detection Source |
| --- | --- | --- | --- |
| Remote System Discovery | T1018 | Yes | Windows Firewall log (ICMP drops) |
| Network Service Discovery | T1046 | Partially | Windows Firewall log (3 of 1000 ports) |
| Active Scanning | T1595 | No | Requires network-layer telemetry (Zeek, Suricata) |

## Technique Descriptions

**T1018 — Remote System Discovery**
Adversaries attempt to enumerate hosts on a network. In this lab, this was
performed with `nmap -sn`, which sends ICMP echo requests to every host in a
subnet. Every request was logged by the Windows Firewall and blocked.

**T1046 — Network Service Discovery**
Adversaries attempt to enumerate services running on remote hosts. In this lab,
this was performed with `nmap -sS -p 1-1000`. Only 3 of 1000 ports generated
firewall log entries because the other 997 ports returned RST responses that
are not logged.

**T1595 — Active Scanning**
Adversaries probe victim infrastructure to gather information. This technique
covers the general class of scanning activity. On the host side, only partial
visibility exists. Network-layer telemetry is required to see the full scan.

## Additional Techniques the Detection Rule Addresses

| Technique | ID | Relevance |
| --- | --- | --- |
| Indicator Removal on Host | T1070 | Attacker may clear the firewall log to evade detection |
| Impair Defenses | T1562 | Attacker may disable firewall logging |
| Command and Scripting Interpreter | T1059 | Used in later phases (not part of this lab) |

## References

- [MITRE ATT&CK T1018](https://attack.mitre.org/techniques/T1018/)
- [MITRE ATT&CK T1046](https://attack.mitre.org/techniques/T1046/)
- [MITRE ATT&CK T1595](https://attack.mitre.org/techniques/T1595/)
- [MITRE ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/)