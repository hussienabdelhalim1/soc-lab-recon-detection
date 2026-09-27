 SOC Lab: Reconnaissance Detection and Sensor Blind Spots

 What This Is.

A purple team lab I built to answer one question: 
"does a rate-based detection rule actually catch network reconnaissance, or does it just look like it does?"

The setup is small a Kali VM attacking a Windows 10 VM  but the findings
apply to real environments. I ran two scans, measured what each sensor actually
recorded, and found that the obvious detection rule would have missed the
attack entirely.

This repo documents the lab, the telemetry, the detection logic, and the gaps
that remain.

## The Short Version

- A 1000-port SYN scan produced 6 firewall log entries and zero Sysmon events.
- A detection rule that counts log entries would have missed it. While A detection rule that counts distinct destination ports catches it.
- Even that rule can be evaded by slowing down the scan.

The interesting part isn't the rule  it's the gap between what I assumed the
sensors recorded and what they actually recorded.

 ----Environment--------

| Component | Details |
| Attacker | Kali Linux — `192.0.2.55` |
| Victim | Windows 10 VM — `192.0.2.19` |
| Endpoint telemetry | Sysmon 15.22 (Olaf Hartong modular config) |
| Network telemetry | Windows Firewall log (allowed and blocked) |
| Analysis host | Windows 10, PowerShell 5.1 |

All IP addresses use the IETF documentation range (`192.0.2.0/24`). No real lab
network details are published here.

## Experiment A — Fast Reconnaissance

Two scans from Kali against the Windows 10 host.

### A1: ICMP ping sweep

```bash
nmap -sn 192.0.2.0/24
```

### A2: TCP SYN scan (1000 ports)

```bash
nmap -sS -p 1-1000 192.0.2.19
```

### What the sensors actually recorded

| Sensor | ICMP sweep | TCP SYN scan |
| --- | --- | --- |
| Windows Firewall log | 113 DROP entries | 6 DROP entries |
| Sysmon Event ID 3 (NetworkConnect) | 0 | 0 |
| Sysmon Event ID 1 (ProcessCreate) | 0 | 0 |

**Why the ICMP count is high**: Windows Firewall has an explicit inbound block
rule for ICMP. Every ping packet hits that rule and generates a log entry.

**Why the TCP count is low**: The firewall only logs packets it **blocks**. Ports
135, 139, and 445 have explicit block rules — those three ports produced the 6
entries (each probed twice). The other 997 ports were allowed through to a
closed TCP stack, which responded with RST. **RST responses are not logged by
Windows Firewall.**

**Why Sysmon saw nothing**: Sysmon's `NetworkConnect` event fires only when a
TCP connection is established (SYN → SYN-ACK → ACK). A SYN scan never completes
the handshake, so the event never fires. Sysmon is blind to half-open scans.

## The Detection Rule

The obvious rule — "alert if more than 10 DROP entries in 60 seconds" — does not
fire. The scan produced 6 entries.

The rule that works counts **distinct destination ports**, not log entries:

```powershell
# Distinct-ports detection rule
# Alerts when a single source touches N or more distinct destination ports
# on a single target.

$kali      = "192.0.2.55"
$fwlog     = "C:\Windows\System32\LogFiles\Firewall\pfirewall.log"
$threshold = 3

$distinctPorts = (Get-Content $fwlog |
    Where-Object { $_ -match "DROP TCP" -and $_ -match $kali } |
    ForEach-Object {
        if ($_ -match "DROP TCP \S+ \S+ \S+ (\d+)") { $matches[1] }
    } |
    Sort-Object -Unique)

if ($distinctPorts.Count -ge $threshold) {
    Write-Warning "Port scan detected: $($distinctPorts.Count) distinct ports targeted."
    $distinctPorts
}
```

**Why this works**: A legitimate client retries the same port repeatedly. A
scanner touches many different ports. Counting distinct ports captures intent;
counting entries captures noise.

## Evasion

Every rule with a fixed threshold can be evaded. This section documents how.

**Against entry-count rules**: Scan only ports that produce RST responses. In
this lab, 997 of 1000 ports fell into that category. An entry-count rule never
fires.

**Against distinct-port rules with a tight window**: Slow the scan. Spreading 30
ports across 15 minutes defeats any rule with a 60-second window.

**Against any rate-based rule**: Distribute the scan across multiple source IPs.
No single source accumulates enough events to trigger the rule.

**The takeaway**: Detection is a cost trade-off, not a solved problem. The goal
of a detection engineer is to make evasion more expensive than the attack is
worth — not to write an unbreakable rule.

## MITRE ATT&CK Mapping

| Technique | ID | Observed? |
| --- | --- | --- |
| Remote System Discovery | T1018 | Yes — via ICMP drops in firewall log |
| Network Service Discovery | T1046 | Partially — 3 of 1000 ports logged |
| Active Scanning | T1595 | No — requires network-layer telemetry |

## Lessons Learned

1. **Measure your sensors before writing rules.** What a sensor records is not
   the same as what an attack does. The 1000-port scan produced 6 log entries.

2. **Count the right thing.** Distinct destinations, distinct users, distinct
   hosts. Not raw event volume.

3. **Time windows are attack surfaces.** Any fixed window can be evaded by
   stretching the attack.

4. **Rules fail silently.** A rule returning zero results does not mean no
   attack. It means the rule's conditions were not met. Always test rules
   against known-bad data before trusting them.

5. **Layered detection beats perfect detection.** There is no unbreakable rule.
   There is only a portfolio of rules whose combined evasion cost exceeds the
   value of the attack.


## Repo Structure

- [01-setup/environment.md](01-setup/environment.md) — Lab environment and VM configuration
- [02-attacks/experiment-a-fast-scan.md](02-attacks/experiment-a-fast-scan.md) — Detailed writeup of the two scans
- [03-telemetry/firewall-log-analysis.md](03-telemetry/firewall-log-analysis.md) — Firewall log format and field analysis
- [04-detections/distinct-ports-rule.ps1](04-detections/distinct-ports-rule.ps1) — The detection rule, ready to run
- [05-analysis/evasion-and-tradeoffs.md](05-analysis/evasion-and-tradeoffs.md) — Analysis of evasion techniques and detection trade-offs
- [06-references/mitre-mapping.md](06-references/mitre-mapping.md) — MITRE ATT&CK technique mapping

```
soc-lab-recon-detection/
├── README.md
├── 01-setup/
│   └── environment.md
├── 02-attacks/
│   └── experiment-a-fast-scan.md
├── 03-telemetry/
│   └── firewall-log-analysis.md
├── 04-detections/
│   └── distinct-ports-rule.ps1
├── 05-analysis/
│   └── evasion-and-tradeoffs.md
└── 06-references/
    └── mitre-mapping.md
```

## What's Next

This is the first lab in a series. Next steps:

- Port the detection rule to Wazuh and confirm it fires on the same scan.
- Add network-layer telemetry (Zeek or Suricata) to catch what Sysmon misses.
- Build a Python script that enriches alerts with IP reputation data.
- Extend to identity telemetry (Windows Security event log).

## References

- [Sysmon — Microsoft Learn](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [Olaf Hartong Sysmon Modular](https://github.com/olafhartong/sysmon-modular)
- [MITRE ATT&CK](https://attack.mitre.org/)
- [Windows Firewall logging](https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/windows-firewall/)