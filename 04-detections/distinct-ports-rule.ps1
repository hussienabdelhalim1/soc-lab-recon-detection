<#
.SYNOPSIS
    Detects TCP port scan activity by counting distinct destination ports
    from a single source against a single target.

.DESCRIPTION
    A port scan touches many different ports on a target in a short time.
    Legitimate clients retry the same port repeatedly.
    Counting log entries misses the scan (Windows Firewall only logs
    blocked packets; RST'd packets are not logged).
    Counting distinct destination ports catches it.

    This rule reads the Windows Firewall log and counts unique destination
    ports from a given source IP.

.PARAMETER SourceIp
    The attacker IP to monitor. Defaults to 192.0.2.55 (documentation range).

.PARAMETER LogPath
    Path to the Windows Firewall log.

.PARAMETER Threshold
    Number of distinct ports required to trigger. Default is 3.

.EXAMPLE
    .\distinct-ports-rule.ps1
    Runs with default parameters.

.EXAMPLE
    .\distinct-ports-rule.ps1 -SourceIp "192.0.2.100" -Threshold 5
    Runs against a different source IP with a higher threshold.

.NOTES
       Privileges:
        The Windows Firewall log requires administrator access to read.
        Run this script from an elevated PowerShell session, or deploy it
        as a scheduled task under a privileged service account.
    Windows Firewall logging must be enabled:
        Set-NetFirewallProfile -Profile Domain,Public,Private `
            -LogAllowed True -LogBlocked True
#>

param(
    [string]$SourceIp  = "192.0.2.55",
    [string]$LogPath   = "C:\Windows\System32\LogFiles\Firewall\pfirewall.log",
    [int]$Threshold    = 3
)

if (-not (Test-Path $LogPath)) {
    Write-Error "Firewall log not found at $LogPath. Enable logging first."
    exit 1
}

$distinctPorts = (Get-Content $LogPath |
    Where-Object { $_ -match "DROP TCP" -and $_ -match $SourceIp } |
    ForEach-Object {
        if ($_ -match "DROP TCP \S+ \S+ \S+ (\d+)") { $matches[1] }
    } |
    Sort-Object -Unique)

if ($distinctPorts.Count -ge $Threshold) {
    Write-Warning "Port scan detected: $($distinctPorts.Count) distinct ports targeted by $SourceIp."
    Write-Host "Ports: $($distinctPorts -join ', ')"
    exit 0
} else {
    Write-Host "No detection. $($distinctPorts.Count) distinct ports seen (threshold: $Threshold)."
    exit 1
}