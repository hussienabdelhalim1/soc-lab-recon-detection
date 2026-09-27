# Windows Firewall Log — Format and Field Analysis

## Overview

Windows Firewall can log every packet it allows or blocks. The log is off by
default and must be enabled explicitly. Once on, it writes plain-text entries
to `pfirewall.log`, one line per decision.

This file documents the log format and explains what each field means, using
real entries from Experiment A.

## Enabling the Log

```powershell
Set-NetFirewallProfile -Profile Domain,Public,Private `
    -LogAllowed True -LogBlocked True `
    -LogFileName "%systemroot%\system32\LogFiles\Firewall\pfirewall.log"
```

Verify:

```powershell
Get-NetFirewallProfile | Select-Object Name, LogAllowed, LogBlocked
```

All three profiles (Domain, Private, Public) should show `True` for both
logging options.

**Note**: Reading the log requires administrator privileges. Running the
detection rule as a normal user will fail with `Access is denied`.

## Log Format

Each line represents one packet the firewall evaluated. The fields are
space-separated. Sample entries from Experiment A:

```
2026-09-20 15:48:03 DROP ICMP 192.0.2.55 192.0.2.19 - - 84 - - - - 8 0 - RECEIVE
2026-09-20 17:38:12 DROP TCP 192.0.2.55 192.0.2.19 39745 445 44 S 745723516 0 1024 - - - RECEIVE
```

## Field Reference

| Position | Field | Example | Meaning |
| --- | --- | --- | --- |
| 1 | Date | 2026-09-20 | Date of the packet |
| 2 | Time | 15:48:03 | Time of the packet |
| 3 | Action | DROP | ALLOW or DROP |
| 4 | Protocol | ICMP / TCP / UDP | Protocol used |
| 5 | Source IP | 192.0.2.55 | Origin of the packet |
| 6 | Destination IP | 192.0.2.19 | Target of the packet |
| 7 | Source Port | 39745 | Only for TCP/UDP |
| 8 | Destination Port | 445 | Only for TCP/UDP |
| 9 | Size | 44 | Packet size in bytes |
| 10 | TCP Flags | S | SYN, ACK, FIN, RST, etc. |
| 11 | TCP Sequence | 745723516 | TCP sequence number |
| 12 | TCP Ack | 0 | TCP acknowledgment number |
| 13 | TCP Window | 1024 | TCP window size |
| 14 | ICMP Type | 8 | Echo request |
| 15 | ICMP Code | 0 | Standard |
| 16 | Info | - | Reserved |
| 17 | Path | RECEIVE | SEND or RECEIVE |

## Interpreting the Two Sample Entries

### Sample 1 — ICMP ping from Kali

```
2026-09-20 15:48:03 DROP ICMP 192.0.2.55 192.0.2.19 - - 84 - - - - 8 0 - RECEIVE
```

- The firewall **dropped** an ICMP packet.
- The packet came from the attacker (192.0.2.55) toward the victim (192.0.2.19).
- ICMP type 8, code 0 = **echo request** (a ping).
- No ports — ICMP doesn't use them.
- **This entry exists because Windows Firewall has an explicit inbound ICMP
  block rule.** Every ping hits the rule. Every ping gets logged.

### Sample 2 — TCP SYN to port 445

```
2026-09-20 17:38:12 DROP TCP 192.0.2.55 192.0.2.19 39745 445 44 S 745723516 0 1024 - - - RECEIVE
```

- The firewall **dropped** a TCP packet.
- The packet was a **SYN** (TCP flag `S`) — the first step of a TCP handshake.
- Destination port 445 = **SMB**. Windows Firewall blocks this inbound by default.
- The SYN was never answered. Connection was never established.

## Why Some Ports Are Missing

A 1000-port scan produced only 6 log entries (3 distinct ports). The other 997
ports were **not blocked** — they were allowed through to a closed TCP stack,
which responded with RST (connection refused).

**RST responses are not logged.** The firewall only logs what it decides on.
Once it allows a packet through, it's done with it. What happens after — a RST,
a SYN-ACK, a timeout — is the OS's business.

This is the key insight: **the firewall log is a record of firewall decisions,
not a record of network traffic.**

## Detecting Scans From This Log

Because only blocked packets appear in the log, counting entries is unreliable.
A scanner that targets only open ports (or ports with no block rule) will
generate very few entries.

The reliable approach is to count **distinct destination ports** from a single
source. A legitimate client retries the same port. A scanner touches many
different ports.

```powershell
$distinctPorts = (Get-Content $fwlog |
    Where-Object { $_ -match "DROP TCP" -and $_ -match $sourceIp } |
    ForEach-Object { if ($_ -match "DROP TCP \S+ \S+ \S+ (\d+)") { $matches[1] } } |
    Sort-Object -Unique)
```

The full rule is in `04-detections/distinct-ports-rule.ps1`.

## Limitations

- **Only logs blocked packets.** Allowed traffic generates no entry unless
  `LogAllowed` is also enabled (which greatly increases volume).
- **Doesn't log RST responses.** The OS handles these silently.
- **Doesn't capture established connections.** Once the firewall allows the
  handshake, the rest of the session is invisible.
- **Requires administrator access to read.**
- **Log rotates at a fixed size** (default 4 MB). Older entries are overwritten.

## Complementary Sensors

The gaps above require additional telemetry:

| Gap | Sensor That Fills It |
| --- | --- |
| RST responses | Network IDS (Zeek, Suricata) |
| Established connections | Sysmon Event ID 3 (on the victim host) |
| Packet content | Full packet capture (pcap) |
| Flow volume | NetFlow / IPFIX from a router or switch |