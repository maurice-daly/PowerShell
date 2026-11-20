# Explorer of Doom: Windows Search index health for OneDrive

Tools to detect and fix a **bloated or unresponsive Windows Search index**. When the index is in that state, File Explorer hangs in OneDrive folders, folders lose their OneDrive status icons, and CPU spikes while you browse.

Explorer works out the sync status of each cloud folder (the tick/cloud icons and the *Status* column) using Windows Search queries. When the index is unhealthy, every one of those queries is slow, so every folder view stalls. OneDrive gets the blame, but the sync client can be completely idle. In the case that prompted these scripts:

| Measurement | Unhealthy | After rebuilding the index |
|---|---|---|
| `SearchIndexer.exe` memory | ~17 GB | ~40 MB |
| Windows Search query (TOP 50) | ~2,700 ms | ~107 ms |
| Status of 82 OneDrive folders | 2-48 s **each** (one never returned) | 472 ms total |

## Contents

| Path | Purpose |
|---|---|
| [`Remediation/ExplorerOfDoom-Detection.ps1`](Remediation/ExplorerOfDoom-Detection.ps1) | Intune Remediations **detection** script. Read-only health check; `exit 1` when an issue is found. |
| [`Remediation/ExplorerOfDoom-Remediation.ps1`](Remediation/ExplorerOfDoom-Remediation.ps1) | Intune Remediations **remediation** script. Rebuilds the Windows Search index. |
| [`Troubleshooting/Invoke-ExplorerHangTrace.ps1`](Troubleshooting/Invoke-ExplorerHangTrace.ps1) | Process Monitor capture and analysis for investigating Explorer/OneDrive hangs on a single device. |

---

## Intune Remediations: detection and remediation

### What detection checks

| Check | Raises an issue? | Default threshold |
|---|---|---|
| `SearchIndexer.exe` private memory | Yes, if above threshold | `$MemoryThresholdGB = 4` |
| Windows Search query latency (median of three `SYSTEMINDEX` queries via `Search.CollatorDSO`) | Yes, if above threshold **or** the query doesn't return within the timeout | `$QueryThresholdMs = 1000`, `$QueryTimeoutSeconds = 60` |
| Index database size | No, logged as a warning above `$IndexSizeWarnGB` (large mailboxes can legitimately grow the index) | `$IndexSizeWarnGB = 4` |
| Explorer `Cross-process` hang events (Application log, event 1002) | No, supporting evidence only | `$HangEventDaysBack = 7` |
| OneDrive `SyncDiagnostics.log` for each profile (pending changes or a sync stall) | No. If OneDrive is busy and the index is healthy, OneDrive is the bottleneck, not the index | - |

The query probe runs in a child PowerShell process with a hard timeout, because an unhealthy index can block a query indefinitely.

### Exit codes

| Script | Exit code | Meaning |
|---|---|---|
| Detection | `1` | Issue detected; Intune runs the remediation script |
| Detection | `0` | Healthy, not applicable (Windows Search disabled or not installed), within the rebuild cool-down, or detection couldn't complete (it **fails safe** and never triggers a rebuild on incomplete data) |
| Remediation | `0` | Index rebuilt (or `$WhatIfMode` dry run completed) |
| Remediation | `1` | Rebuild failed, or not running with administrator rights; see the log |

Each script writes a single summary line to standard output, which appears in the Intune report:

```text
Issue detected: IndexerMemory=16.8 GB; QueryLatency=2706 ms; IndexSize=1.77 GB; ExplorerHangs=1; OneDriveBusy=0/1
Index rebuilt. Before: indexer 16.8 GB, index 1817 MB, query 2706 ms. After: indexer 0.04 GB, query 107 ms.
```

### What remediation does

1. Records before metrics (indexer memory, index size, query latency).
2. Stops the Windows Search service (`WSearch`). If it hasn't stopped within `$ServiceStopTimeoutSeconds`, it terminates the service's `SearchIndexer.exe` process by PID.
3. Sets `SetupCompletedSuccessfully = 0` under the Windows Search registry key to force a rebuild.
4. Deletes the index database files (`<DataDirectory>\Applications\Windows`), retrying briefly if any are still locked.
5. **Always** restarts Windows Search, even if an earlier step failed.
6. Writes the cool-down marker to the registry, waits `$PostCheckDelaySeconds` and logs after metrics.

While the index rebuilds, Start menu, Explorer and Outlook search results are incomplete, for anything from a few minutes to a couple of hours. No reboot is needed or performed.

### Deploying in Intune

1. In the Intune admin center, go to **Devices** > **Manage devices** > **Scripts and remediations** > **Create script package**.
2. Upload `ExplorerOfDoom-Detection.ps1` as the **detection script** and `ExplorerOfDoom-Remediation.ps1` as the **remediation script**. Upload the files rather than pasting them into the browser, so they stay UTF-8 without a BOM.
3. Settings:

   | Setting | Value |
   |---|---|
   | Run this script using the logged-on credentials | **No** (runs as SYSTEM; the rebuild needs admin rights) |
   | Enforce script signature check | **No** (or sign the scripts) |
   | Run script in 64-bit PowerShell | **Yes** (the scripts also relaunch themselves in 64-bit if needed) |

4. Assign to a device group. A **daily** schedule outside core hours is plenty.

**Recommended rollout:**

1. Deploy to a pilot group with `$WhatIfMode = $true` in the remediation script. Detection reports which devices are unhealthy, and the remediation logs what it *would* do without changing anything.
2. Set `$WhatIfMode = $false` for the pilot, then roll out widely.
3. For a user who is stuck now, use **Run remediation (preview)** on the device in the Intune admin center.

### Configuration

All settings are variables at the top of each script; Intune doesn't pass parameters.

#### Locations (keep identical in **both** scripts)

| Variable | Default | Purpose |
|---|---|---|
| `$LogFolder` | `%ProgramData%\Microsoft\IntuneManagementExtension\Logs` | Folder for the CMTrace log. The default is collected by Intune **Collect diagnostics**. Any folder SYSTEM can write to works. |
| `$LogFileName` | `ExplorerOfDoom.log` | One log shared by both scripts, so a whole detect, remediate and re-detect cycle reads as one timeline. |
| `$MaxLogSizeMB` | `4` | The log is rolled over to `ExplorerOfDoom.lo_` above this size. |
| `$MarkerRegistryKey` | `HKLM:\SOFTWARE\ExplorerOfDoom` | Remediation writes `LastRebuildUtc` (ISO 8601 UTC) and `LastRebuildBefore` (before metrics) here; detection reads `LastRebuildUtc` for the cool-down. |
| `$WindowsSearchRegistryKey` | `HKLM:\SOFTWARE\Microsoft\Windows Search` | Microsoft's Windows Search key. `DataDirectory` is read to locate the index; `SetupCompletedSuccessfully` is reset by the remediation. Leave unchanged. |

#### Detection settings

| Variable | Default | Purpose |
|---|---|---|
| `$MemoryThresholdGB` | `4` | `SearchIndexer.exe` private memory considered unhealthy |
| `$QueryThresholdMs` | `1000` | Median query time considered unhealthy (a healthy index answers in roughly 100 ms or less) |
| `$QueryTimeoutSeconds` | `60` | Hard timeout for the query probe; a timeout counts as an issue |
| `$IndexSizeWarnGB` | `4` | Index size that is logged as a warning (informational) |
| `$HangEventDaysBack` | `7` | Look-back period for Explorer `Cross-process` hang events |
| `$RebuildCooldownHours` | `72` | No new rebuild is requested within this window after a rebuild |

#### Remediation settings

| Variable | Default | Purpose |
|---|---|---|
| `$ServiceStopTimeoutSeconds` | `120` | Time allowed for `WSearch` to stop before `SearchIndexer.exe` is terminated |
| `$ServiceStartTimeoutSeconds` | `60` | Time allowed for `WSearch` to start |
| `$PostCheckDelaySeconds` | `30` | Pause before measuring the fresh index |
| `$QueryTimeoutSeconds` | `60` | Hard timeout for the after-measurement query |
| `$WhatIfMode` | `$false` | `$true` = log what would happen without changing anything |

### Logging

Both scripts write [CMTrace](https://learn.microsoft.com/intune/configmgr/core/support/cmtrace)-format entries, including severity (information, warning, error), component (`Detection` or `Remediation`), account context, thread and source line. Open the log in CMTrace and filter on the component to follow a run.

- If `$LogFolder` can't be written to, the scripts fall back to `%TEMP%\ExplorerOfDoom.log` (usually `C:\Windows\Temp` as SYSTEM).
- To see when a device was last rebuilt, and what it looked like beforehand, run `Get-ItemProperty 'HKLM:\SOFTWARE\ExplorerOfDoom'`.
- To reset the cool-down, delete the `LastRebuildUtc` value (or the key).

### Testing locally

From an elevated Windows PowerShell 5.1 prompt (the remediation needs admin rights):

```powershell
# Detection: prints a summary line; check the exit code
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Remediation\ExplorerOfDoom-Detection.ps1
$LASTEXITCODE

# Remediation dry run: set $WhatIfMode = $true in a copy of the script first
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Remediation\ExplorerOfDoom-Remediation.ps1
$LASTEXITCODE
```

To test as SYSTEM, which is how Intune runs the scripts, use a temporary scheduled task running as `NT AUTHORITY\SYSTEM`, or PsExec (`psexec -s`).

### Requirements and notes

- Windows 10/11 with the Windows Search service; Windows PowerShell 5.1. No modules or external dependencies.
- If Windows Search is disabled or not installed, detection reports *not applicable* and exits `0`.
- Running as SYSTEM, the scripts can't time a signed-in user's Explorer folder status directly. Instead they measure the underlying cause: indexer memory and query latency.
- Repeated rebuilds on the same device, each time the cool-down expires, mean something keeps feeding the index. Look for large, fast-changing folder trees (move them or exclude them in **Indexing Options**), check whether OneDrive ever settles, or capture a trace with the troubleshooting script below.

---

## Troubleshooting: `Invoke-ExplorerHangTrace.ps1`

Captures and analyses Explorer/OneDrive hangs on a single device with Sysinternals Process Monitor, then packages the results into a zip for review.

1. **Records the scene:** a snapshot of the device, covering:
   - the OneDrive version and sync roots;
   - Cloud Files API registrations;
   - file system minifilter drivers;
   - antivirus products;
   - mapped drives;
   - the Windows Search service;
   - non-Microsoft shell extensions;
   - Application log crash (1000) and hang (1002) events for Explorer, OneDrive, FileCoAuth and dllhost from the last 14 days.
2. **Captures** with an embedded Procmon configuration that adds the **Duration** and **Thread ID** columns. In the default *Focused* mode it keeps only Explorer, the OneDrive processes, the shell helpers, the Windows Search processes and Defender.
3. **Marks the moment:** press **H** each time Explorer hangs to drop a timestamped marker, and **S** to stop.
4. **Analyses** the capture and writes CSV reports:
   - slow operations (500 ms or more);
   - Explorer threads that went silent for 2 seconds or more;
   - activity in the 20 seconds before each marker;
   - `CLOUD FILE` and other error results;
   - network access;
   - non-Microsoft DLLs loaded into shell processes.

```powershell
# Focused capture: press H when Explorer hangs, S to stop
.\Invoke-ExplorerHangTrace.ps1

# Capture every process, stop after 3 minutes, include the raw PML for call stacks
.\Invoke-ExplorerHangTrace.ps1 -CaptureMode Full -DurationSeconds 180 -IncludePml

# Re-analyse an existing capture (no elevation needed)
.\Invoke-ExplorerHangTrace.ps1 -AnalyzePml C:\ExplorerHangTrace\Trace_PC01_20261120_101500\raw\capture.pml
```

| Parameter | Default | Purpose |
|---|---|---|
| `-ProcmonPath` | Script folder | Folder containing `Procmon64.exe` / `Procmon64a.exe` / `Procmon.exe` |
| `-OutputPath` | `C:\ExplorerHangTrace` | Output root, deliberately outside OneDrive-synced folders |
| `-DurationSeconds` | `0` (until **S**) | Stop automatically after this many seconds |
| `-CaptureMode` | `Focused` | `Full` captures every process (e.g. to catch a third-party agent) |
| `-SlowThresholdMs` | `500` | Operations at or above this are reported as slow |
| `-GapThresholdSeconds` | `2` | Explorer threads silent for this long are reported as stalls |
| `-IncludePml` | Off | Include the raw PML in the zip (needed for call stacks) |
| `-AnalyzePml` | - | Analyse an existing PML instead of capturing |

### What you'll need

- **Process Monitor.** It isn't bundled (Sysinternals licensing doesn't allow redistribution). Download it from [Microsoft Sysinternals](https://learn.microsoft.com/sysinternals/downloads/procmon) and extract it next to the script, or use `-ProcmonPath`. The script picks `Procmon64a.exe` on ARM64 and `Procmon64.exe` on x64, falling back to `Procmon.exe`. The EULA is accepted with `/AcceptEula`.
- **Administrator rights.** The script relaunches itself elevated (expect a UAC prompt). `-AnalyzePml` doesn't need elevation.
- **No other Procmon session.** The script runs `Procmon /Terminate` before and after the capture, which **closes any open Procmon window**. Your Procmon settings are backed up and restored.
- **A driver your security stack allows.** Procmon loads its own signed driver at runtime. Strict application control (WDAC/App Control) or some EDR products may block it.
- **Disk space outside OneDrive.** Captures can run to hundreds of megabytes or more, and the CSV conversion roughly doubles that.
- **Symbols, only for call stacks.** The CSV analysis doesn't need them. Viewing stacks in the raw PML uses `dbghelp.dll` and the Microsoft public symbol server, so it needs internet access.
- Windows PowerShell 5.1 or PowerShell 7.

> **Tip:** Procmon can't see a thread blocked on a COM/ALPC call to another process. A cross-process hang shows up as an Explorer thread that simply stops (see `explorer-thread-stalls.csv`), not as a slow file operation. That silence is the clue that sent this investigation to Windows Search.

---

## Disclaimer

These scripts are provided as-is under the repository's [MIT licence](../../LICENSE). Test them on a pilot group before deploying widely. Rebuilding the index temporarily degrades search results on the affected device.
