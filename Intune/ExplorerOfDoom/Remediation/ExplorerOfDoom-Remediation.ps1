<#
.SYNOPSIS
    Intune Remediations REMEDIATION script - "OneDrive and the Explorer of Doom".

.DESCRIPTION
    Runs when ExplorerOfDoom-Detection.ps1 exits 1. Rebuilds the Windows Search index, releasing a
    bloated SearchIndexer.exe and restoring fast folder status lookups in OneDrive (Explorer stops
    hanging, folder status icons return promptly).

    Steps:
      1. Record "before" metrics (SearchIndexer memory, index size, query latency).
      2. Stop the Windows Search service (WSearch); if it doesn't stop within
         $ServiceStopTimeoutSeconds, terminate the service's SearchIndexer process by PID.
      3. Set HKLM\SOFTWARE\Microsoft\Windows Search\SetupCompletedSuccessfully = 0 (forces a rebuild).
      4. Delete the index database files (<DataDirectory>\Applications\Windows).
      5. Always restart WSearch (even if an earlier step failed).
      6. Write LastRebuildUtc to $MarkerRegistryKey (used by detection for its cool-down).
      7. Record "after" metrics.

    While the index rebuilds, Start menu / Explorer / Outlook search results are incomplete for a while.
    No reboot is required or performed.

    Exit codes: 0 = remediation succeeded, 1 = remediation failed (see the CMTrace log).

.NOTES
    Intune settings: Run this script using the logged-on credentials = No (runs as SYSTEM; admin rights needed)
                     Enforce script signature check = No
                     Run script in 64-bit PowerShell = Yes (the script relaunches itself in 64-bit if needed)
    Save as UTF-8 without BOM. Compatible with Windows PowerShell 5.1.
#>

[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingEmptyCatchBlock', '', Justification = 'Best-effort probes and logging must never break an Intune script run')]
param()

#region ---------------------------- Locations (keep identical in BOTH scripts) ----------------------------
# CMTrace log. The IME Logs folder is included in Intune "Collect diagnostics". Falls back to %TEMP% if not writable.
$LogFolder                = "$env:ProgramData\Microsoft\IntuneManagementExtension\Logs"
$LogFileName              = 'ExplorerOfDoom.log'                      # One log shared by detection and remediation
$MaxLogSizeMB             = 4                                         # Rolled over to .lo_ when exceeded

# Registry key the remediation writes after a rebuild (LastRebuildUtc, LastRebuildBefore); detection reads it for the cool-down.
$MarkerRegistryKey        = 'HKLM:\SOFTWARE\ExplorerOfDoom'

# Windows Search configuration key (DataDirectory = index location). Microsoft-defined; change only if Windows does.
$WindowsSearchRegistryKey = 'HKLM:\SOFTWARE\Microsoft\Windows Search'
#endregion --------------------------------------------------------------------------------------------------

#region ---------------------------- Remediation settings (edit to suit) ----------------------------
$ServiceStopTimeoutSeconds  = 120    # A bloated indexer can take over a minute to stop
$ServiceStartTimeoutSeconds = 60
$PostCheckDelaySeconds      = 30     # Let the fresh indexer settle before measuring
$QueryTimeoutSeconds        = 60
$WhatIfMode                 = $false # $true = log what would happen without changing anything
#endregion --------------------------------------------------------------------------------------------------

$ScriptVersion = '1.0.0'
$ProgressPreference = 'SilentlyContinue'   # Keep progress records out of Intune's output streams
$Component     = 'Remediation'

# Relaunch in 64-bit PowerShell when started from a 32-bit host so HKLM and ProgramData aren't redirected.
if ($env:PROCESSOR_ARCHITEW6432 -and -not [Environment]::Is64BitProcess) {
    $native = Join-Path $env:WINDIR 'SysNative\WindowsPowerShell\v1.0\powershell.exe'
    if (Test-Path -LiteralPath $native) {
        & $native -NoProfile -ExecutionPolicy Bypass -File $PSCommandPath
        exit $LASTEXITCODE
    }
}

#region ---------------------------- CMTrace logging ----------------------------
$script:LogPath = $null

function Initialize-CMLog {
    try {
        if (-not (Test-Path -LiteralPath $LogFolder)) { New-Item -Path $LogFolder -ItemType Directory -Force | Out-Null }
        $script:LogPath = Join-Path $LogFolder $LogFileName
        if ((Test-Path -LiteralPath $script:LogPath) -and ((Get-Item -LiteralPath $script:LogPath).Length -gt ($MaxLogSizeMB * 1MB))) {
            $rolled = [IO.Path]::ChangeExtension($script:LogPath, '.lo_')
            Remove-Item -LiteralPath $rolled -Force -ErrorAction SilentlyContinue
            Rename-Item -LiteralPath $script:LogPath -NewName (Split-Path $rolled -Leaf) -Force
        }
        # Prove the log is writable (folder may exist but be read-only for this account)
        $fs = [IO.File]::Open($script:LogPath, [IO.FileMode]::Append, [IO.FileAccess]::Write, [IO.FileShare]::ReadWrite)
        $fs.Dispose()
    }
    catch {
        $script:LogPath = Join-Path $env:TEMP $LogFileName
    }
}

function Write-CMLog {
    param(
        [Parameter(Mandatory)][string]$Message,
        [ValidateSet(1, 2, 3)][int]$Severity = 1   # 1 = Information, 2 = Warning, 3 = Error
    )
    if (-not $script:LogPath) { Initialize-CMLog }
    $now    = Get-Date
    $bias   = -[int][TimeZoneInfo]::Local.GetUtcOffset($now).TotalMinutes
    $time   = '{0}{1}{2:000}' -f $now.ToString('HH:mm:ss.fff'), $(if ($bias -lt 0) { '-' } else { '+' }), [Math]::Abs($bias)
    $caller = (Get-PSCallStack)[1]
    $file   = '{0}:{1}' -f $(if ($PSCommandPath) { Split-Path -Leaf $PSCommandPath } else { 'ExplorerOfDoom-Remediation.ps1' }), $caller.ScriptLineNumber
    $line   = '<![LOG[{0}]LOG]!><time="{1}" date="{2}" component="{3}" context="{4}" type="{5}" thread="{6}" file="{7}">' -f `
        $Message, $time, $now.ToString('MM-dd-yyyy'), $Component, [Security.Principal.WindowsIdentity]::GetCurrent().Name,
        $Severity, [Threading.Thread]::CurrentThread.ManagedThreadId, $file
    try { [IO.File]::AppendAllText($script:LogPath, $line + [Environment]::NewLine, (New-Object Text.UTF8Encoding($false))) } catch { }
}
#endregion

#region ---------------------------- Helpers ----------------------------
function Get-SearchDataDirectory {
    $dir = $null
    try { $dir = (Get-ItemProperty -Path $WindowsSearchRegistryKey -Name DataDirectory -ErrorAction Stop).DataDirectory } catch { }
    if (-not $dir) { $dir = Join-Path $env:ProgramData 'Microsoft\Search\Data\' }
    Join-Path ([Environment]::ExpandEnvironmentVariables($dir)) 'Applications\Windows'
}

function Get-IndexerMemoryGB {
    $p = Get-Process -Name SearchIndexer -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($p) { [Math]::Round($p.PrivateMemorySize64 / 1GB, 2) } else { $null }
}

function Get-IndexSizeMB {
    try { [Math]::Round(((Get-ChildItem -LiteralPath (Get-SearchDataDirectory) -Recurse -File -Force -ErrorAction Stop | Measure-Object Length -Sum).Sum) / 1MB) }
    catch { $null }
}

function Measure-SearchQueryLatency {
    # Child process with a hard timeout: an unhealthy index can block a query indefinitely.
    $child = @'
$ProgressPreference = 'SilentlyContinue'
try {
    $c = New-Object -ComObject ADODB.Connection
    $c.Open("Provider=Search.CollatorDSO;Extended Properties='Application=Windows';")
    $times = @()
    for ($i = 0; $i -lt 3; $i++) {
        $sw = [Diagnostics.Stopwatch]::StartNew()
        $r = $c.Execute('SELECT TOP 50 System.ItemPathDisplay FROM SYSTEMINDEX')
        while (-not $r.EOF) { $r.MoveNext() }
        $r.Close(); $times += $sw.ElapsedMilliseconds
    }
    $c.Close()
    'OK|' + (($times | Sort-Object)[1])
} catch { 'ERR|' + $_.Exception.Message }
'@
    $psi = New-Object Diagnostics.ProcessStartInfo
    $psi.FileName  = Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $psi.Arguments = '-NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand ' + [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($child))
    $psi.UseShellExecute = $false; $psi.CreateNoWindow = $true; $psi.RedirectStandardOutput = $true; $psi.RedirectStandardError = $true
    $proc   = [Diagnostics.Process]::Start($psi)
    $stdout = $proc.StandardOutput.ReadToEndAsync()
    $null   = $proc.StandardError.ReadToEndAsync()   # Drain stderr so the child's progress records never reach Intune's error output
    if (-not $proc.WaitForExit($QueryTimeoutSeconds * 1000)) {
        try { Stop-Process -Id $proc.Id -Force -ErrorAction Stop } catch { }
        return "timeout >$($QueryTimeoutSeconds)s"
    }
    $out = $stdout.Result -split "`r?`n" | Where-Object { $_ -match '^(OK|ERR)\|' } | Select-Object -Last 1
    if ($out -like 'OK|*') { return "$($out.Substring(3)) ms" }
    "unknown ($(if ($out) { $out.Substring(4) } else { 'no output' }))"
}

function Get-IndexHealthSnapshot([string]$Label) {
    $m = [pscustomobject]@{ IndexerGB = Get-IndexerMemoryGB; IndexMB = Get-IndexSizeMB; Query = Measure-SearchQueryLatency }
    Write-CMLog "$Label metrics: SearchIndexer $($m.IndexerGB) GB, index files $($m.IndexMB) MB, median query $($m.Query)"
    $m
}

function Wait-ServiceStatus([string]$Status, [int]$TimeoutSeconds) {
    $sc = New-Object ServiceProcess.ServiceController('WSearch')
    try { $sc.WaitForStatus($Status, [TimeSpan]::FromSeconds($TimeoutSeconds)); return $true }
    catch { return $false }
    finally { $sc.Dispose() }
}
#endregion

#region ---------------------------- Main ----------------------------
Add-Type -AssemblyName System.ServiceProcess
Initialize-CMLog
Write-CMLog "==== Explorer of Doom remediation v$ScriptVersion starting (PowerShell $($PSVersionTable.PSVersion), 64-bit process: $([Environment]::Is64BitProcess), WhatIfMode: $WhatIfMode) ===="
Write-CMLog "Log file: $script:LogPath"

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-CMLog 'Remediation requires administrator rights (run as SYSTEM: set "Run this script using the logged-on credentials" to No).' 3
    Write-Output 'Failed: not running with administrator rights'
    exit 1
}

$svc = Get-CimInstance Win32_Service -Filter "Name='WSearch'" -ErrorAction SilentlyContinue
if (-not $svc -or $svc.StartMode -eq 'Disabled') {
    Write-CMLog 'Windows Search is not installed or is disabled - nothing to remediate.' 2
    Write-Output 'Not applicable: Windows Search not installed or disabled'
    exit 0
}

$indexDir = Get-SearchDataDirectory
Write-CMLog "Index folder: $indexDir"
$before   = Get-IndexHealthSnapshot 'Before'
$failed   = $null

try {
    # 1. Stop Windows Search
    if ($WhatIfMode) {
        Write-CMLog "WhatIf: would stop WSearch (state $($svc.State), PID $($svc.ProcessId)), reset SetupCompletedSuccessfully and delete $indexDir\*" 2
    }
    else {
        if ($svc.State -ne 'Stopped') {
            Write-CMLog "Stopping WSearch (PID $($svc.ProcessId)), timeout $ServiceStopTimeoutSeconds s"
            $sw = [Diagnostics.Stopwatch]::StartNew()
            & sc.exe stop WSearch | Out-Null
            if (-not (Wait-ServiceStatus 'Stopped' $ServiceStopTimeoutSeconds)) {
                $pidNow = (Get-CimInstance Win32_Service -Filter "Name='WSearch'").ProcessId
                Write-CMLog "WSearch did not stop within $ServiceStopTimeoutSeconds s - terminating PID $pidNow" 2
                if ($pidNow) { Stop-Process -Id $pidNow -Force -ErrorAction Stop }
                if (-not (Wait-ServiceStatus 'Stopped' 30)) { throw 'WSearch could not be stopped' }
            }
            Write-CMLog "WSearch stopped after $([int]$sw.Elapsed.TotalSeconds) s"
        }

        # 2. Force a rebuild on next start
        Set-ItemProperty -Path $WindowsSearchRegistryKey -Name SetupCompletedSuccessfully -Value 0 -Type DWord -ErrorAction Stop
        Write-CMLog 'Set SetupCompletedSuccessfully = 0'

        # 3. Delete the index database (retry for lingering file locks)
        if (Test-Path -LiteralPath $indexDir) {
            for ($attempt = 1; $attempt -le 3; $attempt++) {
                Get-ChildItem -LiteralPath $indexDir -Force -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
                $left = @(Get-ChildItem -LiteralPath $indexDir -Recurse -File -Force -ErrorAction SilentlyContinue)
                if ($left.Count -eq 0) { break }
                Write-CMLog "Attempt $($attempt): $($left.Count) index file(s) still locked, retrying in 5 s" 2
                Start-Sleep -Seconds 5
            }
            if ($left.Count -gt 0) { throw "$($left.Count) index file(s) could not be deleted" }
            Write-CMLog "Deleted index files ($($before.IndexMB) MB)"
        }
        else {
            Write-CMLog "Index folder not found; the service will create a new one" 2
        }
    }
}
catch {
    $failed = $_.Exception.Message
    Write-CMLog "Remediation step failed: $failed (line $($_.InvocationInfo.ScriptLineNumber))" 3
}
finally {
    # 4. Always bring Windows Search back
    if (-not $WhatIfMode) {
        try {
            if ((Get-Service WSearch).Status -ne 'Running') {
                Start-Service -Name WSearch -ErrorAction Stop
                if (-not (Wait-ServiceStatus 'Running' $ServiceStartTimeoutSeconds)) { throw "WSearch did not reach Running within $ServiceStartTimeoutSeconds s" }
            }
            Write-CMLog 'WSearch running'
        }
        catch {
            $failed = (@($failed, "service start: $($_.Exception.Message)") | Where-Object { $_ }) -join '; '
            Write-CMLog "Failed to start WSearch: $($_.Exception.Message)" 3
        }
    }
}

if ($failed) {
    Write-CMLog "RESULT: Remediation FAILED - exit 1. $failed" 3
    Write-Output "Failed: $failed"
    exit 1
}

if (-not $WhatIfMode) {
    # 5. Cool-down marker for the detection script
    try {
        if (-not (Test-Path $MarkerRegistryKey)) { New-Item -Path $MarkerRegistryKey -Force | Out-Null }
        Set-ItemProperty -Path $MarkerRegistryKey -Name LastRebuildUtc -Value ((Get-Date).ToUniversalTime().ToString('o')) -Type String
        Set-ItemProperty -Path $MarkerRegistryKey -Name LastRebuildBefore -Value ("Indexer {0} GB; index {1} MB; query {2}" -f $before.IndexerGB, $before.IndexMB, $before.Query) -Type String
        Write-CMLog "Wrote LastRebuildUtc to $MarkerRegistryKey"
    }
    catch { Write-CMLog "Could not write marker: $($_.Exception.Message)" 2 }

    Write-CMLog "Waiting $PostCheckDelaySeconds s before re-measuring"
    Start-Sleep -Seconds $PostCheckDelaySeconds
}
$after = Get-IndexHealthSnapshot 'After'

$result = 'Index rebuilt. Before: indexer {0} GB, index {1} MB, query {2}. After: indexer {3} GB, query {4}.' -f `
    $before.IndexerGB, $before.IndexMB, $before.Query, $after.IndexerGB, $after.Query
if ($WhatIfMode) { $result = $result.Replace('Index rebuilt.', 'WhatIf - no changes made, index NOT rebuilt.') }
Write-CMLog "RESULT: Success - exit 0. $result"
Write-Output $result
exit 0
#endregion
