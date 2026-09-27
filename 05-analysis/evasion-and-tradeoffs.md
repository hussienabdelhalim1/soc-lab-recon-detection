# Evasion Techniques and Detection Trade-offs

## The Core Problem

Every detection rule has a **threshold** and a **time window**. Both are
attack surfaces.

A rule that says "alert if a single source touches 3+ distinct ports in 60
seconds" tells the attacker two things:

1. Stay under 3 distinct ports, or
2. Spread the ports over more than 60 seconds.

The attacker doesn't need to change tools. They just need to slow down.

This file documents the specific ways the detection rule from Experiment A can
be evaded, and what a defense against each evasion looks like.

## The Baseline Rule

```powershell
# Alert if a single source touches 3+ distinct ports on a single target.
$distinctPorts = (Get-Content $fwlog |
    Where-Object { $_ -match "DROP TCP" -and $_ -match $sourceIp } |
    ForEach-Object { if ($_ -match "DROP TCP \S+ \S+ \S+ (\d+)") { $matches[1] } } |
    Sort-Object -Unique)

if ($distinctPorts.Count -ge 3) {
    Write-Warning "Port scan detected."
}
```

This rule works against fast scans. It fails against the evasions below.

## Evasion 1 — Slow Down

**How the attacker evades it**: Spread the scan so that no short time window
contains enough distinct ports.

Example:
- Port 135 at T+0
- Port 139 at T+90 seconds
- Port 445 at T+180 seconds

No 60-second window contains 3 distinct ports. The rule does not fire.

**Counter**: Add a second rule with a **longer window**:

```
Rule A (fast):  3+ distinct ports in 60 seconds
Rule B (slow):  5+ distinct ports in 60 minutes
```

The attacker now has to spread the scan over **more than 60 minutes** to evade
both. That is a real cost — the reconnaissance phase becomes slow and visible
in other ways (long-lived processes, unusual timing).

## Evasion 2 — Scan Silent Ports

**How the attacker evades it**: Only scan ports that don't have explicit block
rules.

In Experiment A, 997 of 1000 ports were silent because they had no block rule.
Only 135, 139, 445 produced log entries. An attacker who knows the target's
firewall policy can scan only the silent ports and leave no trace in the log.

**Counter**: This evasion is invisible to the firewall log. It requires a
**network-layer sensor** — Zeek, Suricata, or NetFlow — to see the packets
that the firewall allowed through.

| Sensor | Sees Silent Ports? |
| --- | --- |
| Windows Firewall log | No |
| Sysmon Event ID 3 | No (SYN scan doesn't complete) |
| Zeek | Yes |
| Suricata | Yes |
| NetFlow | Yes |

## Evasion 3 — Distribute Across Sources

**How the attacker evades it**: Split the scan across multiple source IPs.

If Rule A has a threshold of 3 distinct ports, the attacker uses 10 source IPs,
each touching 1 port. No single source triggers the rule.

**Counter**: Correlate across sources. Instead of "single source touches 3+
ports," use "the same target receives SYN packets to 10+ distinct ports from
any sources in 60 seconds." This catches distributed scans but adds noise
because legitimate traffic from many sources can look similar.

## Evasion 4 — Use Legitimate Ports

**How the attacker evades it**: Scan only common ports (80, 443) that are
open. No DROP entries. No log.

**Counter**: This is not detectable at the firewall log level. It requires
application-layer telemetry — HTTP request logs, TLS handshake analysis, or
connection volume analysis. Different sensor, different detection.

## The Trade-off Triangle

Detection rules trade off three things:

| Goal | Effect |
| --- | --- |
| Catch fast attacks | Short windows, low thresholds |
| Catch slow attacks | Long windows, higher thresholds |
| Low false positives | Narrow conditions, allowlists |

You cannot maximize all three. Every rule picks a point on the triangle.

| Rule Tuned For | Misses | Adds |
| --- | --- | --- |
| Speed | Slow attacks | False positives from retries |
| Coverage | Fast attacks (loose threshold) | Volume of alerts |
| Precision | Attacks that resemble legit traffic | Attack subtypes |

## What Good Detection Engineering Actually Does

**Not**: write an unbreakable rule.
**But**: build a portfolio of rules whose combined cost of evasion exceeds the
value of the attack.

For port scans, that means:

1. **Fast rule** (3+ ports in 60s) — catches script kiddies and automated
   tools. High precision, low volume.
2. **Slow rule** (5+ ports in 60 minutes) — catches deliberate, slow scans.
   Lower precision, moderate volume.
3. **Network-layer rule** (Zeek/Suricata alert on SYN patterns) — catches
   silent-port scans that bypass the firewall log entirely.
4. **Cross-source correlation** (same target receiving SYNs to N distinct
   ports from any sources) — catches distributed scans.

**Each rule alone can be evaded. Together they raise the cost of evasion.**

## The Underlying Principle

The detection engineer's job is not to write perfect rules. It is to answer
one question for every rule:

> **"What does the attacker have to do to evade this — and does that evasion
> itself create new detection opportunities?"**

If slowing down the scan creates a long-lived suspicious process, that is a
new detection opportunity. If distributing across sources creates traffic from
many unusual IPs, that is a new detection opportunity. If using legitimate
ports creates volume anomalies, that is a new detection opportunity.

**The goal is to make evasion visible in a different way.**