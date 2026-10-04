<#
.SYNOPSIS
    Detects slow port scan activity by counting distinct destination ports
    from a single source over a longer time window.

.DESCRIPTION
    The fast-scan rule (distinct-ports-rule.ps1) uses a short window and
    catches rapid scans. It fails against slow scans because no short
    window contains enough distinct ports.

    This rule uses a 30-minute window. It catches the slow-scan evasion
    at the cost of more potential false positives.

.PARAMETER SourceIp
    The source IP to monitor.

.PARAMETER WindowMinutes
    Time window in minutes. Default is 30.

.PARAMETER Threshold
    Number of distinct ports required to trigger. Default is 5.

.NOTES
    Privileges:
        The Windows Firewall log requires administrator access to read.
        Run this script from an elevated PowerShell session.

    Execution policy:
        Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
#>

param(
    [string]$SourceIp       = "192.0.2.55",
    [string]$LogPath        = "C:\Windows\System32\LogFiles\Firewall\pfirewall.log",
    [int]$WindowMinutes     = 30,
    [int]$Threshold         = 5
)

if (-not (Test-Path $LogPath)) {
    Write-Error "Firewall log not found at $LogPath."
    exit 1
}

$cutoff = (Get-Date).AddMinutes(-$WindowMinutes)

$distinctPorts = (Get-Content $LogPath |
    Where-Object {
        if ($_ -match "^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})") {
            $ts = [datetime]::ParseExact($matches[1], "yyyy-MM-dd HH:mm:ss", $null)
            $ts -gt $cutoff -and $_ -match "DROP TCP" -and $_ -match $SourceIp
        }
    } |
    ForEach-Object {
        if ($_ -match "DROP TCP \S+ \S+ \S+ (\d+)") { $matches[1] }
    } |
    Sort-Object -Unique)

if ($distinctPorts.Count -ge $Threshold) {
    Write-Warning "Slow scan detected: $($distinctPorts.Count) distinct ports in $WindowMinutes minutes from $SourceIp."
    Write-Host "Ports: $($distinctPorts -join ', ')"
} else {
    Write-Host "No detection. $($distinctPorts.Count) distinct ports in $WindowMinutes minutes (threshold: $Threshold)."
}