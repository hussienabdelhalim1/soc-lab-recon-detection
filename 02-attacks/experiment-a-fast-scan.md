# Experiment A: Fast Reconnaissance

## Objective

I wanted to understand what reconnaissance looks like from the defender's side.
Textbooks say "port scans show up in firewall logs" — but I've never verified
that myself with a real sensor in a real environment.

The goal was simple: run a scan, check the telemetry, and see what actually got
recorded. I expected the logs to show the full attack. They didn't. That gap
between expectation and reality is what this writeup documents.

## Setup

| Component | Detail |
| --- | --- |
| Attacker | Kali Linux — 192.0.2.55 |
| Victim | Windows 10 VM — 192.0.2.19 |
| Endpoint telemetry | Sysmon 15.22 with Olaf Hartong modular config |
| Network telemetry | Windows Firewall log (allowed and blocked traffic) |

Windows Firewall logging was enabled before the experiment:

```powershell
Set-NetFirewallProfile -Profile Domain,Public,Private `
    -LogAllowed True -LogBlocked True
```

## Attack 1 — ICMP Ping Sweep

### Command

```bash
nmap -sn 192.0.2.0/24
```

### What I Expected

The firewall log would show a handful of ICMP drop entries. Maybe one per host
in the subnet.

### What I Actually Saw

113 DROP ICMP entries in the firewall log, all from 192.0.2.55 to hosts in the
192.0.2.0/24 range. A sample:

```
2026-09-20 15:48:03 DROP ICMP 192.0.2.55 192.0.2.19 - - 84 - - - - 8 0 - RECEIVE
2026-09-20 15:48:04 DROP ICMP 192.0.2.55 192.0.2.19 - - 84 - - - - 8 0 - RECEIVE
2026-09-20 15:48:05 DROP ICMP 192.0.2.55 192.0.2.19 - - 84 - - - - 8 0 - RECEIVE
```

### Finding

The firewall logged **every** ICMP packet. This is because Windows Firewall has
an explicit block rule for inbound ICMP, and every ping hits that rule.

**This is good detection coverage.** A rule that counts ICMP drops from a single
source in a short time window would catch this scan easily.

## Attack 2 — TCP SYN Scan

### Command

```bash
nmap -sS -p 1-1000 192.0.2.19
```

### What I Expected

Hundreds of DROP TCP entries in the firewall log. One per port scanned.

### What I Actually Saw

Only **6 DROP TCP entries**, covering **3 distinct ports** (135, 139, 445):

```
2026-09-20 17:38:12 DROP TCP 192.0.2.55 192.0.2.19 39745 445 44 S 745723516 0 1024 - - - RECEIVE
2026-09-20 17:38:12 DROP TCP 192.0.2.55 192.0.2.19 39745 135 44 S 745723516 0 1024 - - - RECEIVE
2026-09-20 17:38:12 DROP TCP 192.0.2.55 192.0.2.19 39745 139 44 S 745723516 0 1024 - - - RECEIVE
2026-09-20 17:38:12 DROP TCP 192.0.2.55 192.0.2.19 39747 135 44 S 745592446 0 1024 - - - RECEIVE
2026-09-20 17:38:12 DROP TCP 192.0.2.55 192.0.2.19 39747 445 44 S 745592446 0 1024 - - - RECEIVE
2026-09-20 17:38:12 DROP TCP 192.0.2.55 192.0.2.19 39747 139 44 S 745592446 0 1024 - - - RECEIVE
```

Sysmon Event ID 3 (NetworkConnect) recorded **nothing** during the scan.

### Finding

Three separate sensor behaviors combined to make the scan almost invisible:

1. **The firewall only logs packets it blocks.** Ports 135, 139, and 445 have
   explicit block rules, so those 3 ports generated log entries. The other 997
   ports were allowed through to a closed TCP stack, which responded with RST.
   **RST responses are not logged.**

2. **Sysmon is blind to half-open scans.** Sysmon's `NetworkConnect` event fires
   when a TCP connection completes (SYN → SYN-ACK → ACK). A SYN scan never
   completes the handshake. No handshake, no event.

3. **The scan touched 1000 ports but left 6 log entries.** A detection rule that
   counts entries ("more than 10 DROP entries in 60 seconds") would miss it
   entirely.

## Comparison

| Sensor | ICMP sweep | TCP SYN scan |
| --- | --- | --- |
| Windows Firewall log | 113 DROP entries | 6 DROP entries (3 distinct ports) |
| Sysmon Event ID 3 | 0 | 0 |
| Sysmon Event ID 1 | 0 | 0 |

## What This Means

The assumption "the firewall logs every scan" is wrong. It logs every packet
that **hits a block rule**. Ports without a block rule never generate an entry —
they pass through to the OS, which responds with RST, and the firewall is done
with them.

From the attacker's perspective, this is a gift. Scan ports that don't have
explicit block rules and you leave almost no trace. The three ports that *did*
get logged (135, 139, 445) are the usual suspects — SMB, RPC, NetBIOS — which
most networks block anyway. An attacker doing reconnaissance knows which ports
will be silent and can target them specifically.

## Detection Implication

The detection rule cannot count log entries. It has to count **distinct
destination ports**.

A legitimate client retries the same port repeatedly. A scanner touches many
different ports. Counting distinct ports captures intent; counting entries
captures noise.

The rule that catches this scan:

```powershell
$distinctPorts = (Get-Content $fwlog |
    Where-Object { $_ -match "DROP TCP" -and $_ -match $sourceIp } |
    ForEach-Object { if ($_ -match "DROP TCP \S+ \S+ \S+ (\d+)") { $matches[1] } } |
    Sort-Object -Unique)

if ($distinctPorts.Count -ge 3) {
    Write-Warning "Port scan detected: $($distinctPorts.Count) distinct ports."
}
```

Three distinct ports from one source against one target is abnormal behavior.
It doesn't matter how many log entries were produced.