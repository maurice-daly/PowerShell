<#
.SYNOPSIS
    Captures and analyses Explorer / OneDrive hangs with Process Monitor and packages the results for review.

.DESCRIPTION
    1. Collects system context (OneDrive version, mapped drives, filter drivers, AV, third-party shell
       extensions, recent Application Hang events).
    2. Starts Procmon with an embedded configuration that adds the Duration and TID columns and (in
       Focused mode) only keeps Explorer / OneDrive / shell-helper processes.
    3. Lets you reproduce the hang. Press H each time Explorer freezes to drop a timestamped marker,
       and S to stop the capture.
    4. Converts the PML to CSV and analyses it: slow operations, threads that stalled, error results,
       network/UNC access, third-party DLLs loaded into Explorer, and activity around each marker.
    5. Zips everything into a single file for review.

    Your existing Procmon settings (HKCU\Software\Sysinternals\Process Monitor) are restored afterwards.
    The script self-elevates because Procmon needs administrator rights to capture.

.PARAMETER ProcmonPath
    Folder containing Procmon.exe / Procmon64.exe / Procmon64a.exe. Defaults to the script's folder.

.PARAMETER OutputPath
    Root folder for the trace output. A timestamped sub-folder and zip are created inside it.

.PARAMETER DurationSeconds
    Stop automatically after this many seconds. 0 (default) = wait until you press S.

.PARAMETER CaptureMode
    Focused (default) keeps only Explorer/OneDrive/shell-related processes, keeping the log small.
    Full captures every process (use if Focused does not reveal the cause, e.g. a third-party agent).

.PARAMETER SlowThresholdMs
    Operations taking at least this long are reported as slow. Default 500 ms.

.PARAMETER GapThresholdSeconds
    Explorer threads that go silent for at least this long are reported as possible stalls. Default 2 s.

.PARAMETER IncludePml
    Also put the raw PML in the zip (can be large). Needed if the reviewer wants call stacks.

.PARAMETER AnalyzePml
    Skip capturing and just analyse an existing PML file.

.EXAMPLE
    .\Invoke-ExplorerHangTrace.ps1
    Capture until you press S, then analyse and zip the results to C:\ExplorerHangTrace.
    (Output deliberately avoids OneDrive-synced folders so the trace doesn't generate sync activity itself.)

.EXAMPLE
    .\Invoke-ExplorerHangTrace.ps1 -DurationSeconds 180 -CaptureMode Full -IncludePml
#>
[CmdletBinding()]
param(
    [string]$ProcmonPath,
    [string]$OutputPath = (Join-Path $env:SystemDrive 'ExplorerHangTrace'),
    [ValidateRange(0, 86400)][int]$DurationSeconds = 0,
    [ValidateSet('Focused', 'Full')][string]$CaptureMode = 'Focused',
    [ValidateRange(1, 600000)][int]$SlowThresholdMs = 500,
    [ValidateRange(0.1, 3600)][double]$GapThresholdSeconds = 2,
    [switch]$IncludePml,
    [string]$AnalyzePml
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

# Procmon configurations generated with procmon-parser. Columns: Time of Day, Process Name, PID, TID,
# Operation, Path, Result, Duration, Detail. Focused = include-list of shell processes + drop filtered events.
$FocusedPmcBase64 = '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'
$FullPmcBase64 = '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'

$FocusProcesses = @(
    'explorer.exe', 'OneDrive.exe', 'OneDrive.Sync.Service.exe', 'FileCoAuth.exe', 'FileSyncHelper.exe',
    'Microsoft.SharePoint.exe', 'dllhost.exe', 'prevhost.exe', 'SearchProtocolHost.exe', 'SearchIndexer.exe',
    'SearchFilterHost.exe', 'SearchHost.exe', 'RuntimeBroker.exe', 'sihost.exe', 'ShellExperienceHost.exe',
    'StartMenuExperienceHost.exe', 'MsMpEng.exe', 'MpDefenderCoreService.exe', 'smartscreen.exe'
)
$ShellProcesses = @('explorer.exe', 'OneDrive.exe', 'FileCoAuth.exe', 'dllhost.exe', 'prevhost.exe')
$ProcmonRegKey = 'HKCU\Software\Sysinternals\Process Monitor'

#region Helpers

function Write-Step([string]$Message) { Write-Host "`n==> $Message" -ForegroundColor Cyan }
function Write-Note([string]$Message) { Write-Host "    $Message" -ForegroundColor Gray }

function Test-IsAdmin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    ([Security.Principal.WindowsPrincipal]$id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-ProcmonExe([string]$Folder) {
    $isArm = $false
    try { $isArm = (Get-CimInstance Win32_Processor | Select-Object -First 1).Architecture -eq 12 } catch { }
    $candidates = if ($isArm) { 'Procmon64a.exe', 'Procmon64.exe', 'Procmon.exe' }
    elseif ([Environment]::Is64BitOperatingSystem) { 'Procmon64.exe', 'Procmon.exe' }
    else { 'Procmon.exe' }
    foreach ($c in $candidates) {
        $p = Join-Path $Folder $c
        if (Test-Path -LiteralPath $p) { return $p }
    }
    throw "Process Monitor was not found in '$Folder'. Use -ProcmonPath to point at the folder containing Procmon64.exe."
}

function Invoke-Procmon([string]$Exe, [string[]]$Arguments, [switch]$NoWait, [int]$TimeoutSeconds = 1800) {
    $quoted = $Arguments | ForEach-Object { if ($_ -match '\s') { "`"$_`"" } else { $_ } }
    $proc = Start-Process -FilePath $Exe -ArgumentList $quoted -PassThru -WindowStyle Minimized
    if ($NoWait) { return $proc }
    if (-not $proc.WaitForExit($TimeoutSeconds * 1000)) {
        throw "Procmon did not finish within $TimeoutSeconds seconds (args: $($Arguments -join ' '))."
    }
    return $proc
}

function Convert-TimeOfDay([string]$Value) {
    # Procmon writes e.g. "21:13:41.0115827" or "9:13:41.0115827 PM" depending on locale.
    $m = [regex]::Match($Value, '(\d{1,2}):(\d{2}):(\d{2})[.,](\d+)\s*([AaPp][Mm])?')
    if (-not $m.Success) { return $null }
    $h = [int]$m.Groups[1].Value
    if ($m.Groups[5].Success) {
        $ampm = $m.Groups[5].Value.ToUpperInvariant()
        if ($ampm -eq 'PM' -and $h -lt 12) { $h += 12 }
        if ($ampm -eq 'AM' -and $h -eq 12) { $h = 0 }
    }
    $frac = [double]('0.' + $m.Groups[4].Value)
    return ($h * 3600) + ([int]$m.Groups[2].Value * 60) + [int]$m.Groups[3].Value + $frac
}

function Convert-Duration([string]$Value) {
    if ([string]::IsNullOrWhiteSpace($Value)) { return 0.0 }
    $d = 0.0
    if ([double]::TryParse($Value.Replace(',', '.'), [Globalization.NumberStyles]::Float,
            [Globalization.CultureInfo]::InvariantCulture, [ref]$d)) { return $d }
    return 0.0
}

function Format-Tod([double]$Seconds) {
    if ($Seconds -lt 0) { $Seconds += 86400 }
    $ts = [TimeSpan]::FromSeconds($Seconds)
    '{0:00}:{1:00}:{2:00}.{3:000}' -f [int][Math]::Floor($ts.TotalHours), $ts.Minutes, $ts.Seconds, $ts.Milliseconds
}

function Save-Csv($Data, [string]$Path) {
    if ($Data) { $Data | Export-Csv -LiteralPath $Path -NoTypeInformation -Encoding UTF8 }
}

# reg.exe writes its success message to stderr, which Windows PowerShell treats as an error; run it via cmd.
function Invoke-Reg([string]$Arguments) {
    & cmd.exe /c "reg.exe $Arguments >nul 2>&1"
    return $LASTEXITCODE
}

#endregion

#region System context

function Get-SystemContext([string]$Folder) {
    $sb = New-Object System.Text.StringBuilder
    function Add([string]$Title, [scriptblock]$Body) {
        [void]$sb.AppendLine("===== $Title =====")
        try { [void]$sb.AppendLine(((& $Body) | Out-String -Width 400).TrimEnd()) }
        catch { [void]$sb.AppendLine("  (failed: $($_.Exception.Message))") }
        [void]$sb.AppendLine()
    }

    Add 'Operating system' {
        $cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
        $os = Get-CimInstance Win32_OperatingSystem
        [pscustomobject]@{
            Caption = $os.Caption; DisplayVersion = $cv.DisplayVersion
            Build = "$($cv.CurrentBuild).$($cv.UBR)"; Architecture = $os.OSArchitecture
            LastBoot = $os.LastBootUpTime; FreeMemoryMB = [int]($os.FreePhysicalMemory / 1KB)
        } | Format-List
    }

    Add 'OneDrive client' {
        $paths = @("$env:LOCALAPPDATA\Microsoft\OneDrive\OneDrive.exe",
            "${env:ProgramFiles}\Microsoft OneDrive\OneDrive.exe",
            "${env:ProgramFiles(x86)}\Microsoft OneDrive\OneDrive.exe")
        $paths | Where-Object { Test-Path -LiteralPath $_ } | ForEach-Object {
            [pscustomobject]@{ Path = $_; Version = (Get-Item -LiteralPath $_).VersionInfo.FileVersion }
        } | Format-Table -AutoSize
        Get-Process OneDrive -ErrorAction SilentlyContinue |
            Select-Object Id, @{n = 'CPU(s)'; e = { [int]$_.CPU } }, @{n = 'WorkingSetMB'; e = { [int]($_.WorkingSet64 / 1MB) } }, Responding |
            Format-Table -AutoSize
    }

    Add 'OneDrive accounts (sync roots)' {
        Get-ChildItem 'HKCU:\Software\Microsoft\OneDrive\Accounts' -ErrorAction SilentlyContinue | ForEach-Object {
            $p = Get-ItemProperty $_.PSPath
            if ($p.PSObject.Properties['UserFolder']) {
                [pscustomobject]@{ Account = $_.PSChildName; UserFolder = $p.UserFolder
                    Business = if ($p.PSObject.Properties['Business']) { $p.Business } else { '' } }
            }
        } | Format-Table -AutoSize
    }

    Add 'Cloud sync roots (registered with Cloud Files API)' {
        Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\SyncRootManager' -ErrorAction SilentlyContinue |
            ForEach-Object {
                $p = Get-ItemProperty $_.PSPath
                [pscustomobject]@{ SyncRoot = $_.PSChildName
                    DisplayName = if ($p.PSObject.Properties['DisplayNameResource']) { $p.DisplayNameResource } else { '' } }
            } | Format-Table -AutoSize
    }

    Add 'Mapped drives and network connections' {
        Get-CimInstance Win32_MappedLogicalDisk -ErrorAction SilentlyContinue |
            Select-Object Name, ProviderName, Status | Format-Table -AutoSize
        & net.exe use 2>&1
        Get-ChildItem 'HKCU:\Network' -ErrorAction SilentlyContinue | ForEach-Object {
            [pscustomobject]@{ PersistentDrive = $_.PSChildName; RemotePath = (Get-ItemProperty $_.PSPath).RemotePath }
        } | Format-Table -AutoSize
    }

    Add 'File system minifilter drivers (fltmc)' { & fltmc.exe filters 2>&1 }

    Add 'Antivirus products' {
        Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction SilentlyContinue |
            Select-Object displayName, pathToSignedProductExe, productState | Format-Table -AutoSize
    }

    Add 'Windows Search service' { Get-Service WSearch -ErrorAction SilentlyContinue | Select-Object Name, Status, StartType }

    Add 'Recent Explorer/OneDrive hangs and crashes (Application log, last 14 days)' {
        $start = (Get-Date).AddDays(-14)
        Get-WinEvent -FilterHashtable @{ LogName = 'Application'; Id = 1000, 1002; StartTime = $start } -ErrorAction SilentlyContinue |
            Where-Object { $_.Message -match 'explorer\.exe|OneDrive|FileCoAuth|dllhost' } |
            Select-Object -First 25 TimeCreated, Id, ProviderName,
            @{n = 'Message'; e = { ($_.Message -split "`r?`n" | Select-Object -First 6) -join ' | ' } } |
            Format-List
    }

    Add 'Non-Microsoft shell extensions (approved list)' {
        Get-ThirdPartyShellExtensions | Format-Table -AutoSize -Wrap
    }

    $sb.ToString() | Set-Content -LiteralPath (Join-Path $Folder 'system-context.txt') -Encoding UTF8
}

function Get-ThirdPartyShellExtensions {
    $approved = @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Approved',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Approved')
    $blocked = @{}
    foreach ($b in 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked') {
        $k = Get-Item $b -ErrorAction SilentlyContinue
        if ($k) { $k.GetValueNames() | ForEach-Object { $blocked[$_.ToUpperInvariant()] = $true } }
    }
    $seen = @{}
    foreach ($a in $approved) {
        $key = Get-Item $a -ErrorAction SilentlyContinue
        if (-not $key) { continue }
        foreach ($clsid in $key.GetValueNames()) {
            if (-not $clsid.StartsWith('{') -or $seen.ContainsKey($clsid)) { continue }
            $seen[$clsid] = $true
            $inproc = Get-ItemProperty "Registry::HKEY_CLASSES_ROOT\CLSID\$clsid\InprocServer32" -ErrorAction SilentlyContinue
            if (-not $inproc -or -not $inproc.PSObject.Properties['(default)']) { continue }
            $dll = [Environment]::ExpandEnvironmentVariables([string]$inproc.'(default)').Trim('"')
            if (-not $dll) { continue }
            $company = ''
            if (Test-Path -LiteralPath $dll) { $company = (Get-Item -LiteralPath $dll).VersionInfo.CompanyName }
            if ($company -like '*Microsoft*') { continue }
            [pscustomobject]@{
                Name    = [string]$key.GetValue($clsid)
                CLSID   = $clsid
                Dll     = $dll
                Company = if (Test-Path -LiteralPath $dll) { $company } else { '(DLL missing)' }
                Blocked = $blocked.ContainsKey($clsid.ToUpperInvariant())
            }
        }
    }
}

#endregion

#region Analysis

function Invoke-TraceAnalysis {
    param(
        [string]$CsvPath,
        [string]$ReportFolder,
        [object[]]$Markers,
        [string]$Mode
    )

    $slowSec = $SlowThresholdMs / 1000.0
    $focus = @{}; $FocusProcesses | ForEach-Object { $focus[$_.ToLowerInvariant()] = $true }
    $shell = @{}; $ShellProcesses | ForEach-Object { $shell[$_.ToLowerInvariant()] = $true }
    $errorResults = @('ACCESS DENIED', 'SHARING VIOLATION', 'BAD NETWORK PATH', 'BAD NETWORK NAME', 'NETWORK NAME DELETED',
        'IO TIMEOUT', 'TIMEOUT', 'CANCELLED', 'OPLOCK HANDLE CLOSED', 'OPLOCK BREAK IN PROGRESS', 'FILE LOCKED WITH WRITERS',
        'DELETE PENDING', 'CLOUD FILE PROVIDER NOT RUNNING', 'CLOUD FILE NETWORK UNAVAILABLE', 'CLOUD FILE REQUEST TIMEOUT',
        'CLOUD FILE IN USE', 'CLOUD FILE UNSUCCESSFUL', 'CLOUD FILE ACCESS DENIED', 'CLOUD FILE REQUEST ABORTED',
        'CLOUD FILE PINNED', 'CLOUD FILE DEHYDRATION DISALLOWED', 'NETWORK UNREACHABLE', 'HOST UNREACHABLE',
        'CONNECTION REFUSED', 'NO SUCH DEVICE', 'DEVICE NOT READY', 'INSUFFICIENT RESOURCES')

    $slow = New-Object System.Collections.Generic.List[object]
    $nearMarker = New-Object System.Collections.Generic.List[object]
    $gaps = New-Object System.Collections.Generic.List[object]
    $lastByThread = @{}
    $resultCounts = @{}
    $processStats = @{}
    $network = @{}
    $modules = @{}
    $cloud = @{}
    $first = $null; $last = $null; $rows = 0

    $markerTimes = @($Markers | ForEach-Object { $_.Seconds })

    Write-Note "Parsing $([Math]::Round((Get-Item -LiteralPath $CsvPath).Length / 1MB, 1)) MB of Procmon CSV..."
    Import-Csv -LiteralPath $CsvPath | ForEach-Object {
        $rows++
        if (($rows % 200000) -eq 0) { Write-Note ("  {0:N0} events..." -f $rows) }

        $procName = $_.'Process Name'
        $procKey = $procName.ToLowerInvariant()
        if ($Mode -eq 'Focused' -and -not $focus.ContainsKey($procKey)) { return }

        $t = Convert-TimeOfDay $_.'Time of Day'
        if ($null -eq $t) { return }
        if ($null -eq $first) { $first = $t }
        $last = $t
        $dur = Convert-Duration $_.Duration
        $op = $_.Operation; $path = $_.Path; $result = $_.Result

        if (-not $processStats.ContainsKey($procName)) {
            $processStats[$procName] = [pscustomobject]@{ Process = $procName; Events = 0; SlowOps = 0; TotalSlowSeconds = 0.0; MaxSeconds = 0.0 }
        }
        $ps = $processStats[$procName]; $ps.Events++

        $evt = $null
        $isWait = ($op -eq 'NotifyChangeDirectory') -or
            ($op -eq 'FileSystemControl' -and $_.Detail -match 'FSCTL_(READ_USN_JOURNAL|PIPE_LISTEN|PIPE_WAIT|REQUEST_(BATCH_|FILTER_)?OPLOCK|REQUEST_OPLOCK_LEVEL)') -or
            (-not $shell.ContainsKey($procKey) -and $path -match '^\\Device\\(NamedPipe|Mailslot)')
        if ($isWait) { $dur = 0.0 }
        if ($dur -gt $ps.MaxSeconds) { $ps.MaxSeconds = $dur }
        if ($dur -ge $slowSec -or ($markerTimes.Count -gt 0 -and $dur -ge 0.05)) {
            $evt = [pscustomobject]@{
                Time = $_.'Time of Day'; Seconds = $t; DurationMs = [Math]::Round($dur * 1000, 1)
                Process = $procName; PID = $_.PID; TID = $_.TID; Operation = $op; Path = $path; Result = $result; Detail = $_.Detail
            }
        }
        if ($dur -ge $slowSec) {
            $slow.Add($evt); $ps.SlowOps++; $ps.TotalSlowSeconds += $dur
        }
        if ($markerTimes.Count -gt 0 -and $null -ne $evt) {
            # Procmon timestamps an event when it starts; include anything that overlaps the 20s before a marker.
            foreach ($m in $markerTimes) {
                if ($t -le ($m + 2) -and ($t + $dur) -ge ($m - 20)) { $nearMarker.Add($evt); break }
            }
        }

        if ($result -and $result -ne 'SUCCESS') {
            $rk = "$procName|$result"
            if (-not $resultCounts.ContainsKey($rk)) {
                $resultCounts[$rk] = [pscustomobject]@{ Process = $procName; Result = $result; Count = 0; ExamplePath = $path; IsConcerning = ($errorResults -contains $result) }
            }
            $resultCounts[$rk].Count++
        }

        if ($path -match '^\\\\(?!\?\\|\.\\)([^\\]+)\\?([^\\]*)' -and $op -notmatch '^(TCP|UDP)') {
            $share = "\\$($Matches[1])\$($Matches[2])"
            if (-not $network.ContainsKey($share)) {
                $network[$share] = [pscustomobject]@{ Share = $share; Events = 0; Failures = 0; TotalSeconds = 0.0; MaxMs = 0.0; Processes = @{} }
            }
            $n = $network[$share]; $n.Events++; $n.TotalSeconds += $dur
            if ($result -ne 'SUCCESS') { $n.Failures++ }
            if ($dur * 1000 -gt $n.MaxMs) { $n.MaxMs = [Math]::Round($dur * 1000, 1) }
            $n.Processes[$procName] = $true
        }

        if ($op -eq 'Load Image' -and $shell.ContainsKey($procKey) -and -not $modules.ContainsKey($path)) {
            $modules[$path] = $procName
        }

        if ($result -like 'CLOUD FILE*' -or $_.Detail -match 'RECALL_ON_DATA_ACCESS|RECALL_ON_OPEN|Reparse' -or $op -like '*Cloud*') {
            $ck = "$procName|$op|$result"
            if (-not $cloud.ContainsKey($ck)) {
                $cloud[$ck] = [pscustomobject]@{ Process = $procName; Operation = $op; Result = $result; Count = 0; TotalSeconds = 0.0; ExamplePath = $path }
            }
            $cloud[$ck].Count++; $cloud[$ck].TotalSeconds += $dur
        }

        if ($procKey -eq 'explorer.exe') {
            $tk = "$($_.PID):$($_.TID)"
            if ($lastByThread.ContainsKey($tk)) {
                $prev = $lastByThread[$tk]
                $gap = $t - $prev.End
                if ($gap -lt -43200) { $gap += 86400 }
                if ($gap -ge $GapThresholdSeconds) {
                    $gaps.Add([pscustomobject]@{
                            GapSeconds = [Math]::Round($gap, 2); PID = $_.PID; TID = $_.TID
                            LastBefore = "$($prev.Time) $($prev.Op) $($prev.Path) [$($prev.Result)]"
                            FirstAfter = "$($_.'Time of Day') $op $path [$result]"
                            GapStart = $prev.End
                        })
                }
            }
            $lastByThread[$tk] = @{ End = $t + $dur; Time = $_.'Time of Day'; Op = $op; Path = $path; Result = $result }
        }
    }

    if ($rows -eq 0 -or $null -eq $first) {
        Write-Warning 'The Procmon export contained no usable events for the selected processes.'
    }

    # Third-party modules loaded into shell processes during the capture.
    $thirdParty = foreach ($m in $modules.GetEnumerator()) {
        $company = ''; $desc = ''; $ver = ''
        if (Test-Path -LiteralPath $m.Key) {
            $vi = (Get-Item -LiteralPath $m.Key).VersionInfo
            $company = $vi.CompanyName; $desc = $vi.FileDescription; $ver = $vi.FileVersion
        }
        if ($company -notlike '*Microsoft*') {
            [pscustomobject]@{ Process = $m.Value; Module = $m.Key; Company = $company; Description = $desc; Version = $ver }
        }
    }

    $slowSorted = $slow | Sort-Object DurationMs -Descending
    $slowGrouped = $slow | Group-Object Process, Operation, Path | ForEach-Object {
        $s = $_.Group | Measure-Object DurationMs -Sum -Maximum
        [pscustomobject]@{ Process = $_.Group[0].Process; Operation = $_.Group[0].Operation; Path = $_.Group[0].Path
            Count = $_.Count; TotalMs = [Math]::Round($s.Sum, 1); MaxMs = $s.Maximum; Results = (($_.Group.Result | Sort-Object -Unique) -join ', ') }
    } | Sort-Object TotalMs -Descending
    $gapsSorted = $gaps | Sort-Object GapSeconds -Descending
    $resultsSorted = $resultCounts.Values | Sort-Object @{e = 'IsConcerning'; Descending = $true }, @{e = 'Count'; Descending = $true }
    $networkList = $network.Values | ForEach-Object {
        [pscustomobject]@{ Share = $_.Share; Events = $_.Events; Failures = $_.Failures; TotalSeconds = [Math]::Round($_.TotalSeconds, 2)
            MaxMs = $_.MaxMs; Processes = ($_.Processes.Keys -join ', ') }
    } | Sort-Object TotalSeconds -Descending
    $cloudList = $cloud.Values | Sort-Object TotalSeconds -Descending
    $procList = $processStats.Values | ForEach-Object { $_.TotalSlowSeconds = [Math]::Round($_.TotalSlowSeconds, 2); $_.MaxSeconds = [Math]::Round($_.MaxSeconds, 3); $_ } |
        Sort-Object TotalSlowSeconds -Descending

    Save-Csv $slowSorted (Join-Path $ReportFolder 'slow-operations.csv')
    Save-Csv $slowGrouped (Join-Path $ReportFolder 'slow-operations-grouped.csv')
    Save-Csv $gapsSorted (Join-Path $ReportFolder 'explorer-thread-stalls.csv')
    Save-Csv $resultsSorted (Join-Path $ReportFolder 'non-success-results.csv')
    Save-Csv $networkList (Join-Path $ReportFolder 'network-paths.csv')
    Save-Csv $cloudList (Join-Path $ReportFolder 'cloud-files-activity.csv')
    Save-Csv $thirdParty (Join-Path $ReportFolder 'third-party-modules-in-shell.csv')
    Save-Csv $procList (Join-Path $ReportFolder 'process-summary.csv')
    Save-Csv ($nearMarker | Sort-Object Seconds) (Join-Path $ReportFolder 'activity-near-markers.csv')

    # Human-readable summary
    $r = New-Object System.Text.StringBuilder
    function L([string]$s = '') { [void]$r.AppendLine($s) }
    function T($data, [int]$take = 15) {
        if (-not $data) { L '  (none)'; return }
        L ((@($data) | Select-Object -First $take | Format-Table -AutoSize | Out-String -Width 4096).TrimEnd())
    }

    L 'EXPLORER / ONEDRIVE HANG TRACE - SUMMARY'
    L ('=' * 60)
    L "Computer       : $env:COMPUTERNAME"
    L "Generated      : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    L "Capture mode   : $Mode"
    if ($null -ne $first) { L "Capture window : $(Format-Tod $first) - $(Format-Tod $last) ($([Math]::Round($last - $first, 1)) s)" }
    L ("Events parsed  : {0:N0}" -f $rows)
    L "Slow threshold : $SlowThresholdMs ms   Stall threshold: $GapThresholdSeconds s"
    L "Hang markers   : $(@($Markers).Count)"
    foreach ($m in $Markers) { L "  - $($m.Label) at $(Format-Tod $m.Seconds)" }
    L

    L '1. SLOWEST INDIVIDUAL OPERATIONS'
    L '   Long durations on CreateFile/QueryDirectory/QueryOpen etc. usually point straight at the cause'
    L '   (offline UNC/mapped drive, cloud file hydration, AV/DLP filter driver, slow shell extension).'
    L '   By-design waits (directory change notifications, oplock/USN/pipe-listen FSCTLs, pipe reads in'
    L '   non-shell processes) are excluded; they remain in procmon-export.csv.'
    T ($slowSorted | Select-Object Time, DurationMs, Process, TID, Operation, Result, Path) 25
    L

    L '2. SLOW OPERATIONS GROUPED (by total time)'
    T ($slowGrouped | Select-Object TotalMs, Count, MaxMs, Process, Operation, Results, Path) 20
    L

    L '3. EXPLORER THREAD STALLS'
    L '   A thread that goes silent then resumes. Stalls that line up with a hang marker are significant;'
    L '   otherwise they may just be idle threads. LastBefore = what the thread did right before stalling.'
    T ($gapsSorted | Select-Object GapSeconds, TID, @{n = 'StallStart'; e = { Format-Tod $_.GapStart } }, LastBefore, FirstAfter) 20
    L

    if (@($Markers).Count -gt 0) {
        L '4. ACTIVITY IN THE 20s BEFORE EACH HANG MARKER (ops >= 50 ms)'
        foreach ($m in $Markers) {
            L "   -- $($m.Label) at $(Format-Tod $m.Seconds) --"
            $win = $nearMarker | Where-Object { $_.Seconds -le ($m.Seconds + 2) -and ($_.Seconds + $_.DurationMs / 1000) -ge ($m.Seconds - 20) }
            T ($win | Sort-Object DurationMs -Descending | Select-Object Time, DurationMs, Process, TID, Operation, Result, Path) 15
            $stalls = $gapsSorted | Where-Object { $_.GapStart -le ($m.Seconds + 2) -and ($_.GapStart + $_.GapSeconds) -ge ($m.Seconds - 20) }
            if ($stalls) { L '   Explorer threads stalled across this marker:'; T ($stalls | Select-Object GapSeconds, TID, LastBefore) 10 }
            L
        }
    }

    L '5. NETWORK / UNC PATHS TOUCHED'
    L '   Explorer touching unreachable shares or disconnected mapped drives is a classic hang cause.'
    T ($networkList | Select-Object Share, Events, Failures, TotalSeconds, MaxMs, Processes) 20
    L

    L '6. CLOUD FILES (OneDrive placeholders / hydration)'
    T ($cloudList | Select-Object Process, Operation, Result, Count, @{n = 'TotalSeconds'; e = { [Math]::Round($_.TotalSeconds, 2) } }, ExamplePath) 20
    L

    L '7. NOTABLE NON-SUCCESS RESULTS'
    T ($resultsSorted | Where-Object IsConcerning | Select-Object Process, Result, Count, ExamplePath) 25
    L

    L '8. THIRD-PARTY MODULES LOADED INTO EXPLORER / SHELL PROCESSES DURING CAPTURE'
    L '   Shell extensions, overlay icon handlers, AV/DLP hooks. Compare against slow operations above.'
    T ($thirdParty | Select-Object Process, Company, Description, Module) 40
    L

    L '9. PER-PROCESS SUMMARY'
    T ($procList | Select-Object Process, Events, SlowOps, TotalSlowSeconds, MaxSeconds) 25
    L

    L 'FILES IN THIS PACKAGE'
    L '  summary.txt                         - this file'
    L '  system-context.txt                  - OS, OneDrive, mapped drives, filter drivers, AV, shell extensions, hang events'
    L '  slow-operations*.csv                - every op over the slow threshold (raw and grouped)'
    L '  explorer-thread-stalls.csv          - Explorer threads that went silent'
    L '  activity-near-markers.csv           - ops >= 50 ms around each H marker'
    L '  network-paths.csv, cloud-files-activity.csv, non-success-results.csv, third-party-modules-in-shell.csv'
    L '  procmon-export.csv                  - full Procmon export (Time, Process, PID, TID, Operation, Path, Result, Duration, Detail)'
    L '  *.pml (only with -IncludePml)       - open in Procmon; Event Properties > Stack shows call stacks for slow events'

    $summaryPath = Join-Path $ReportFolder 'summary.txt'
    $r.ToString() | Set-Content -LiteralPath $summaryPath -Encoding UTF8
    return $summaryPath
}

#endregion

#region Main

# Resolve paths before elevating so the elevated copy writes to the invoking user's folders.
if (-not $ProcmonPath) { $ProcmonPath = Split-Path -Parent $MyInvocation.MyCommand.Path }
$ProcmonPath = [IO.Path]::GetFullPath($ProcmonPath)
$OutputPath = [IO.Path]::GetFullPath($OutputPath)
if ($AnalyzePml) { $AnalyzePml = [IO.Path]::GetFullPath($AnalyzePml) }

if (-not $AnalyzePml -and -not (Test-IsAdmin)) {
    Write-Host 'Process Monitor needs administrator rights - relaunching elevated...' -ForegroundColor Yellow
    $hostExe = (Get-Process -Id $PID).Path
    $argList = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-NoExit', '-File', "`"$PSCommandPath`"",
        '-ProcmonPath', "`"$ProcmonPath`"", '-OutputPath', "`"$OutputPath`"",
        '-DurationSeconds', $DurationSeconds, '-CaptureMode', $CaptureMode,
        '-SlowThresholdMs', $SlowThresholdMs, '-GapThresholdSeconds', $GapThresholdSeconds.ToString([Globalization.CultureInfo]::InvariantCulture))
    if ($IncludePml) { $argList += '-IncludePml' }
    Start-Process -FilePath $hostExe -ArgumentList $argList -Verb RunAs
    return
}

$procmon = Get-ProcmonExe $ProcmonPath
$stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$runFolder = Join-Path $OutputPath "Trace_${env:COMPUTERNAME}_$stamp"
$rawFolder = Join-Path $runFolder 'raw'
$reportFolder = Join-Path $runFolder 'report'
New-Item -ItemType Directory -Path $rawFolder, $reportFolder -Force | Out-Null

$pmcPath = Join-Path $rawFolder "$CaptureMode.pmc"
$pmcBase64 = if ($CaptureMode -eq 'Focused') { $FocusedPmcBase64 } else { $FullPmcBase64 }
[IO.File]::WriteAllBytes($pmcPath, [Convert]::FromBase64String($pmcBase64))
$csvPath = Join-Path $reportFolder 'procmon-export.csv'
$markers = New-Object System.Collections.Generic.List[object]

Write-Host "Explorer / OneDrive hang trace -> $runFolder" -ForegroundColor Green
Write-Note "Procmon: $procmon"

# Procmon persists /LoadConfig settings to HKCU on exit; back up so the user's GUI settings are restored.
$regBackup = Join-Path $rawFolder 'procmon-settings-backup.reg'
$hadSettings = $false
if ((Invoke-Reg "query `"$ProcmonRegKey`"") -eq 0) {
    $hadSettings = ((Invoke-Reg "export `"$ProcmonRegKey`" `"$regBackup`" /y") -eq 0)
}

try {
    if ($AnalyzePml) {
        if (-not (Test-Path -LiteralPath $AnalyzePml)) { throw "PML not found: $AnalyzePml" }
        $pmlPath = $AnalyzePml
    }
    else {
        Write-Step 'Collecting system context'
        Get-SystemContext $reportFolder
        Write-Note 'Saved system-context.txt'

        $pmlPath = Join-Path $rawFolder 'capture.pml'
        Write-Step "Starting Process Monitor ($CaptureMode capture)"
        Invoke-Procmon $procmon @('/AcceptEula', '/Terminate') -TimeoutSeconds 60 | Out-Null
        $capture = Invoke-Procmon $procmon @('/AcceptEula', '/Quiet', '/Minimized', '/BackingFile', $pmlPath, '/LoadConfig', $pmcPath) -NoWait
        Invoke-Procmon $procmon @('/AcceptEula', '/WaitForIdle') -TimeoutSeconds 120 | Out-Null
        $captureStart = Get-Date
        Write-Note 'Capture running.'

        Write-Host ''
        Write-Host '  Reproduce the problem now: browse the slow folders, right-click / copy / rename files, etc.' -ForegroundColor Yellow
        Write-Host '  Press  H  the moment Explorer hangs (or as soon as it recovers) to drop a marker.' -ForegroundColor Yellow
        Write-Host '  Press  S  (or Q / Enter) to stop the capture.' -ForegroundColor Yellow
        if ($DurationSeconds -gt 0) { Write-Host "  Capture stops automatically after $DurationSeconds seconds." -ForegroundColor Yellow }
        Write-Host ''

        $interactive = $true
        try { [void][Console]::KeyAvailable } catch { $interactive = $false }
        while ($true) {
            if ($DurationSeconds -gt 0 -and ((Get-Date) - $captureStart).TotalSeconds -ge $DurationSeconds) { break }
            if ($capture.HasExited) { Write-Warning 'Procmon exited unexpectedly.'; break }
            if ($interactive) {
                if ([Console]::KeyAvailable) {
                    $key = [Console]::ReadKey($true)
                    if ($key.Key -eq 'H') {
                        $now = Get-Date
                        $label = "Hang #$($markers.Count + 1)"
                        $markers.Add([pscustomobject]@{ Label = $label; Seconds = $now.TimeOfDay.TotalSeconds; Time = $now })
                        Write-Host "  [$($now.ToString('HH:mm:ss'))] $label marked" -ForegroundColor Magenta
                    }
                    elseif ($key.Key -in 'S', 'Q', 'Enter', 'Escape') { break }
                }
                Start-Sleep -Milliseconds 200
            }
            elseif ($DurationSeconds -gt 0) { Start-Sleep -Seconds 1 }
            else {
                $line = Read-Host 'Type H + Enter to mark a hang, or just Enter to stop'
                if ($line -match '^\s*h') {
                    $now = Get-Date
                    $markers.Add([pscustomobject]@{ Label = "Hang #$($markers.Count + 1)"; Seconds = $now.TimeOfDay.TotalSeconds; Time = $now })
                }
                else { break }
            }
        }

        Write-Step 'Stopping Process Monitor'
        Invoke-Procmon $procmon @('/AcceptEula', '/Terminate') -TimeoutSeconds 300 | Out-Null
        if (-not $capture.WaitForExit(300000)) { Write-Warning 'Capture process is still running after /Terminate.' }
        if (-not (Test-Path -LiteralPath $pmlPath)) { throw "Procmon did not produce $pmlPath." }
        Write-Note ("PML size: {0:N1} MB" -f ((Get-ChildItem -LiteralPath $rawFolder -Filter 'capture*.pml' | Measure-Object Length -Sum).Sum / 1MB))
        if ($markers.Count) { $markers | Select-Object Label, Time | Export-Csv (Join-Path $reportFolder 'hang-markers.csv') -NoTypeInformation -Encoding UTF8 }
    }

    Write-Step 'Converting PML to CSV (this can take a few minutes for large captures)'
    Invoke-Procmon $procmon @('/AcceptEula', '/Quiet', '/Minimized', '/OpenLog', $pmlPath, '/LoadConfig', $pmcPath, '/SaveAs', $csvPath) -TimeoutSeconds 3600 | Out-Null
    if (-not (Test-Path -LiteralPath $csvPath)) { throw 'Procmon did not produce the CSV export.' }

    Write-Step 'Analysing trace'
    $summary = Invoke-TraceAnalysis -CsvPath $csvPath -ReportFolder $reportFolder -Markers $markers -Mode $CaptureMode

    if ($IncludePml) {
        Get-ChildItem -LiteralPath (Split-Path $pmlPath) -Filter "$([IO.Path]::GetFileNameWithoutExtension($pmlPath))*.pml" |
            Copy-Item -Destination $reportFolder
    }

    Write-Step 'Packaging results'
    $zipPath = Join-Path $OutputPath "ExplorerHangTrace_${env:COMPUTERNAME}_$stamp.zip"
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    if (Test-Path -LiteralPath $zipPath) { Remove-Item -LiteralPath $zipPath -Force }
    [IO.Compression.ZipFile]::CreateFromDirectory($reportFolder, $zipPath, [IO.Compression.CompressionLevel]::Optimal, $false)

    Write-Host ''
    Write-Host "Done. Send this file for review:" -ForegroundColor Green
    Write-Host "  $zipPath" -ForegroundColor White
    Write-Note "Summary: $summary"
    Write-Note "Raw PML: $pmlPath$(if (-not $IncludePml) { '  (not in zip - re-run with -IncludePml or send separately if call stacks are needed)' })"
    Get-Content -LiteralPath $summary -TotalCount 60 | Write-Host
}
finally {
    if (-not $AnalyzePml) {
        try { Invoke-Procmon $procmon @('/AcceptEula', '/Terminate') -TimeoutSeconds 60 | Out-Null } catch { }
    }
    $null = Invoke-Reg "delete `"$ProcmonRegKey`" /f"
    if ($hadSettings) { $null = Invoke-Reg "import `"$regBackup`"" }
}

#endregion
