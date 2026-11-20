<#
.SYNOPSIS
    Intune Remediations DETECTION script - "OneDrive and the Explorer of Doom".

.DESCRIPTION
    Detects a bloated / unhealthy Windows Search index, the hidden cause of File Explorer hanging in
    OneDrive folders, folders missing their OneDrive status icons and CPU spikes when browsing.
    Explorer works out the sync status of each cloud folder using Windows Search queries, so when the
    index is slow every folder view stalls.

    Checks (all read-only):
      1. SearchIndexer.exe private memory            -> issue if above $MemoryThresholdGB
      2. Windows Search query latency (SYSTEMINDEX)  -> issue if median above $QueryThresholdMs
      3. Search index database size                  -> informational
      4. Explorer "Cross-process" hangs (event 1002) -> informational / supporting evidence
      5. OneDrive SyncDiagnostics.log per profile    -> informational: if OneDrive itself is busy and the
                                                        index is healthy, OneDrive is the bottleneck

    Exit codes (per Intune Remediations):
      exit 1 = issue detected   -> Intune runs ExplorerOfDoom-Remediation.ps1
      exit 0 = healthy, not applicable, within the rebuild cool-down, or detection could not complete
               (fails safe: never triggers an index rebuild on uncertain data)

    All activity is written to a CMTrace-format log in $LogFolder.

.NOTES
    Intune settings: Run this script using the logged-on credentials = No (runs as SYSTEM)
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

#region ---------------------------- Detection settings (edit to suit) ----------------------------
$MemoryThresholdGB      = 4      # SearchIndexer private memory considered unhealthy
$QueryThresholdMs       = 1000   # Median SYSTEMINDEX query time considered unhealthy (healthy ~100 ms)
$QueryTimeoutSeconds    = 60     # Hard timeout for the query probe (an unhealthy index can hang)
$IndexSizeWarnGB        = 4      # Informational only; large mailboxes legitimately grow the index
$HangEventDaysBack      = 7      # Look-back for Explorer "Cross-process" hang events
$RebuildCooldownHours   = 72     # Don't request another rebuild within this window
#endregion --------------------------------------------------------------------------------------------------

$ScriptVersion = '1.0.0'
$ProgressPreference = 'SilentlyContinue'   # Keep progress records out of Intune's output streams
$Component     = 'Detection'

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
    $file   = '{0}:{1}' -f $(if ($PSCommandPath) { Split-Path -Leaf $PSCommandPath } else { 'ExplorerOfDoom-Detection.ps1' }), $caller.ScriptLineNumber
    $line   = '<![LOG[{0}]LOG]!><time="{1}" date="{2}" component="{3}" context="{4}" type="{5}" thread="{6}" file="{7}">' -f `
        $Message, $time, $now.ToString('MM-dd-yyyy'), $Component, [Security.Principal.WindowsIdentity]::GetCurrent().Name,
        $Severity, [Threading.Thread]::CurrentThread.ManagedThreadId, $file
    try { [IO.File]::AppendAllText($script:LogPath, $line + [Environment]::NewLine, (New-Object Text.UTF8Encoding($false))) } catch { }
}
#endregion

#region ---------------------------- Checks ----------------------------
function Get-SearchDataDirectory {
    $dir = $null
    try { $dir = (Get-ItemProperty -Path $WindowsSearchRegistryKey -Name DataDirectory -ErrorAction Stop).DataDirectory } catch { }
    if (-not $dir) { $dir = Join-Path $env:ProgramData 'Microsoft\Search\Data\' }
    Join-Path ([Environment]::ExpandEnvironmentVariables($dir)) 'Applications\Windows'
}

function Test-SearchIndexerMemory {
    $p = Get-Process -Name SearchIndexer -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $p) { return [pscustomobject]@{ Name = 'IndexerMemory'; Issue = $false; Warn = $false; Value = 'not running'; Detail = 'SearchIndexer.exe not running' } }
    $gb = [Math]::Round($p.PrivateMemorySize64 / 1GB, 2)
    [pscustomobject]@{
        Name = 'IndexerMemory'; Issue = ($gb -gt $MemoryThresholdGB); Warn = $false; Value = "$gb GB"
        Detail = "SearchIndexer PID $($p.Id) private memory $gb GB (threshold $MemoryThresholdGB GB)"
    }
}

function Test-SearchQueryLatency {
    # Runs in a child process with a hard timeout: an unhealthy index can block a query indefinitely.
    $child = @'
$ProgressPreference = 'SilentlyContinue'
$ErrorActionPreference = 'Stop'
try {
    $c = New-Object -ComObject ADODB.Connection
    $c.Open("Provider=Search.CollatorDSO;Extended Properties='Application=Windows';")
    $times = @(); $rows = 0
    for ($i = 0; $i -lt 3; $i++) {
        $sw = [Diagnostics.Stopwatch]::StartNew()
        $r = $c.Execute('SELECT TOP 50 System.ItemPathDisplay FROM SYSTEMINDEX')
        $n = 0; while (-not $r.EOF) { $n++; $r.MoveNext() }
        $r.Close(); $sw.Stop(); $times += $sw.ElapsedMilliseconds; $rows = $n
    }
    $c.Close()
    'OK|' + ($times -join ',') + '|' + $rows
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
        return [pscustomobject]@{ Name = 'QueryLatency'; Issue = $true; Warn = $false; Value = ">$($QueryTimeoutSeconds)s"
            Detail = "Windows Search query did not return within $QueryTimeoutSeconds s (probe PID $($proc.Id) terminated)" }
    }
    $out = $stdout.Result -split "`r?`n" | Where-Object { $_ -match '^(OK|ERR)\|' } | Select-Object -Last 1
    if (-not $out -or $out -like 'ERR|*') {
        # Can't measure: don't treat as an issue (fail safe), but log it.
        return [pscustomobject]@{ Name = 'QueryLatency'; Issue = $false; Warn = $true; Value = 'unknown'
            Detail = "Query probe failed: $(if ($out) { $out.Substring(4) } else { 'no output' })" }
    }
    $parts  = $out.Split('|')
    $times  = @($parts[1].Split(',') | ForEach-Object { [int]$_ } | Sort-Object)
    $median = $times[[int][Math]::Floor($times.Count / 2)]
    [pscustomobject]@{
        Name = 'QueryLatency'; Issue = ($median -gt $QueryThresholdMs); Warn = $false; Value = "$median ms"
        Detail = "SYSTEMINDEX query times $($parts[1]) ms (median $median ms, threshold $QueryThresholdMs ms, rows $($parts[2]))"
    }
}

function Test-IndexDatabaseSize {
    $dir = Get-SearchDataDirectory
    try {
        $files = @(Get-ChildItem -LiteralPath $dir -Recurse -File -Force -ErrorAction Stop)
        $total = ($files | Measure-Object Length -Sum).Sum
        $db    = $files | Where-Object { $_.Name -in 'Windows.db', 'Windows.edb' } | Select-Object -First 1
        $gb    = [Math]::Round($total / 1GB, 2)
        [pscustomobject]@{
            Name = 'IndexSize'; Issue = $false; Warn = ($gb -gt $IndexSizeWarnGB); Value = "$gb GB"
            Detail = "Index folder $gb GB$(if ($db) { "; $($db.Name) $([Math]::Round($db.Length / 1MB)) MB" })"
        }
    }
    catch { [pscustomobject]@{ Name = 'IndexSize'; Issue = $false; Warn = $false; Value = 'unknown'; Detail = "Could not read index folder (needs admin/SYSTEM): $($_.Exception.Message)" } }
}

function Test-ExplorerHangEvent {
    $events = @()
    try {
        $events = @(Get-WinEvent -FilterHashtable @{ LogName = 'Application'; Id = 1002; StartTime = (Get-Date).AddDays(-$HangEventDaysBack) } -ErrorAction Stop |
            Where-Object { $_.Properties.Count -gt 0 -and $_.Properties[0].Value -eq 'explorer.exe' -and ($_.Properties | Where-Object { "$($_.Value)" -match 'Cross-process' }) })
    }
    catch { }   # "No events found" is raised as an error
    [pscustomobject]@{
        Name = 'ExplorerHangs'; Issue = $false; Warn = ($events.Count -gt 0); Value = $events.Count
        Detail = "$($events.Count) explorer.exe Cross-process hang(s) in last $HangEventDaysBack day(s)$(if ($events.Count) { "; latest $($events[0].TimeCreated.ToString('s'))" })"
    }
}

function Test-OneDriveBusy {
    $busy = 0; $seen = 0
    foreach ($userDir in Get-ChildItem -LiteralPath (Join-Path $env:SystemDrive 'Users') -Directory -Force -ErrorAction SilentlyContinue) {
        $logs = Join-Path $userDir.FullName 'AppData\Local\Microsoft\OneDrive\logs'
        foreach ($diag in Get-ChildItem -LiteralPath $logs -Filter SyncDiagnostics.log -Recurse -File -ErrorAction SilentlyContinue) {
            if ($diag.LastWriteTime -lt (Get-Date).AddDays(-2)) { continue }
            $seen++
            $text    = Get-Content -LiteralPath $diag.FullName -Raw -ErrorAction SilentlyContinue
            $changes = if ($text -match 'ChangesToProcess\s*=\s*(\d+)') { [int]$Matches[1] } else { 0 }
            if ($changes -gt 0 -or $text -match 'syncStallDetected\s*=\s*1') { $busy++ }
        }
    }
    [pscustomobject]@{ Name = 'OneDriveBusy'; Issue = $false; Warn = ($busy -gt 0); Value = "$busy/$seen"
        Detail = "$busy of $seen recent OneDrive sync log(s) show pending changes or a stall" }
}
#endregion

#region ---------------------------- Main ----------------------------
Initialize-CMLog
Write-CMLog "==== Explorer of Doom detection v$ScriptVersion starting (PowerShell $($PSVersionTable.PSVersion), 64-bit process: $([Environment]::Is64BitProcess)) ===="
Write-CMLog "Log file: $script:LogPath"

try {
    $svc = Get-CimInstance Win32_Service -Filter "Name='WSearch'" -ErrorAction SilentlyContinue
    if (-not $svc) {
        Write-CMLog 'Windows Search service (WSearch) not installed - not applicable.' 2
        Write-Output 'Not applicable: Windows Search not installed'
        exit 0
    }
    Write-CMLog "WSearch state $($svc.State), start mode $($svc.StartMode)"
    if ($svc.StartMode -eq 'Disabled') {
        Write-CMLog 'Windows Search is disabled by configuration - not applicable.' 2
        Write-Output 'Not applicable: Windows Search disabled'
        exit 0
    }

    $checks = @(
        Test-SearchIndexerMemory
        Test-SearchQueryLatency
        Test-IndexDatabaseSize
        Test-ExplorerHangEvent
        Test-OneDriveBusy
    )
    foreach ($c in $checks) {
        $sev = if ($c.Issue) { 3 } elseif ($c.Warn) { 2 } else { 1 }
        Write-CMLog "[$($c.Name)] $($c.Detail)" $sev
    }

    $issues  = @($checks | Where-Object { $_.Issue })
    $summary = ($checks | ForEach-Object { "$($_.Name)=$($_.Value)" }) -join '; '

    if ($issues.Count -eq 0) {
        Write-CMLog "RESULT: Healthy - exit 0. $summary"
        Write-Output "Healthy: $summary"
        exit 0
    }

    # Cool-down: avoid rebuild loops while a freshly rebuilt index is still re-crawling.
    $last = $null
    try {
        $raw  = (Get-ItemProperty -Path $MarkerRegistryKey -Name LastRebuildUtc -ErrorAction Stop).LastRebuildUtc
        $last = [datetime]::Parse($raw, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AdjustToUniversal)
    }
    catch { }
    if ($last) {
        $age = [Math]::Round(((Get-Date).ToUniversalTime() - $last).TotalHours, 1)
        if ($age -lt $RebuildCooldownHours) {
            Write-CMLog "RESULT: Issue detected but the index was rebuilt $age h ago (cool-down $RebuildCooldownHours h) - exit 0. $summary" 2
            Write-Output "Cool-down: rebuilt $age h ago. $summary"
            exit 0
        }
    }

    Write-CMLog "RESULT: Issue detected ($(($issues | ForEach-Object { $_.Name }) -join ', ')) - exit 1 to trigger remediation. $summary" 3
    Write-Output "Issue detected: $summary"
    exit 1
}
catch {
    Write-CMLog "Detection failed: $($_.Exception.Message) (line $($_.InvocationInfo.ScriptLineNumber))" 3
    Write-Output "Detection error: $($_.Exception.Message)"
    exit 0   # Fail safe: never trigger a rebuild on an incomplete detection
}
#endregion
