# Lab Environment

## Overview

A two-VM lab used to test reconnaissance detection. Kali attacks, Windows 10
victim, Sysmon captures endpoint activity, Windows Firewall logs network-level
events.

## Network

| Host | Role | IP |
| --- | --- | --- |
| Kali Linux | Attacker | 192.0.2.55 |
| Windows 10 | Victim | 192.0.2.19 |

Both VMs run on the same bridgednetwork segment. This places them on the
same subnet as the host's physical network, which is realistic for a lab
simulating an internal attacker. No traffic leaves the local network during
the experiments.

## Attacker — Kali Linux

| Component | Details |
| --- | --- |
| OS | Kali Linux (rolling) |
| Primary tool | nmap |
| Purpose | Generate reconnaissance traffic against the victim |

## Victim — Windows 10

| Component | Details |
| --- | --- |
| OS | Windows 10 |
| Endpoint telemetry | Sysmon 15.22 (Olaf Hartong modular config) |
| Network telemetry | Windows Firewall log |
| Log location | C:\Windows\System32\LogFiles\Firewall\pfirewall.log |

## Sysmon Configuration

Sysmon 15.22 was installed with the Olaf Hartong modular configuration. The
module files were merged into a single config with a schema version of 4.91
to match the Sysmon binary.

Config location: `C:\Users\analyst\Desktop\sysmon-modular-master\sysmonconfig-built.xml`

Install command:

```cmd
sysmon64.exe -accepteula -i sysmonconfig-built.xml
```

To reload the config after changes:

```cmd
sysmon64.exe -c sysmonconfig-built.xml
```

## Firewall Logging Configuration

Windows Firewall logging was disabled by default. It was enabled with:

```powershell
Set-NetFirewallProfile -Profile Domain,Public,Private `
    -LogAllowed True -LogBlocked True `
    -LogFileName "%systemroot%\system32\LogFiles\Firewall\pfirewall.log"
```

Verify logging is enabled:

```powershell
Get-NetFirewallProfile | Select-Object Name, LogAllowed, LogBlocked
```

All three profiles (Domain, Private, Public) should show `True` for both.

## Privileges

Reading the firewall log requires administrator access. The detection rule
script must be run from an elevated PowerShell session, or deployed as a
scheduled task under a privileged account.

## Reproducing This Lab

1. Stand up a Kali VM and a Windows 10 VM on the same network segment.
2. Install Sysmon 15.22 on the Windows 10 VM using the Olaf Hartong modular
   config (schema 4.91).
3. Enable Windows Firewall logging for all profiles.
4. Confirm Sysmon events are flowing:
   ```powershell
   Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 5
   ```
5. Confirm firewall logging is working by pinging the Windows 10 VM from
   Kali. The ping should be blocked and appear as `DROP ICMP` in the log.
6. Run the experiments in `02-attacks/`.