<#
.SYNOPSIS
    Updates and installs OneDrive 64-bit in machine-wide context.

.DESCRIPTION
    Downloads and installs the latest OneDrive sync client in per-machine mode.
    Includes certificate validation, URL health checks, and comprehensive logging.
    Designed to run as SYSTEM account in deployment scenarios.

.EXAMPLE
    .\Update-OneDriveSyncAgent.ps1

.NOTES
    Version:        2.0
    Author:         Jan Ketil Skanke (original), Maurice Daly (updated code and optimisations)
    Contact:        @JankeSkanke / @modaly_it
    Creation Date:  2022-01-01
    Updated:        2025-11-14
    
    Version History:
        1.0.0 - (2022-10-23) Initial release
        2.0.0 - (2025-11-14) Complete rewrite with optimizations:
                             - Replaced Invoke-WebRequest with .NET WebClient
                             - Added HEAD request for URL validation
                             - Enhanced certificate validation
                             - Improved error handling and logging
                             - Better cleanup and resource management
                             - Optimized for SYSTEM context execution
#>

# Requires -RunAsAdministrator

[CmdletBinding()]
param()

#region Configuration
$script:Config = @{
    LogFileName       = "OneDriveSetup.log"
    LogPath           = "$env:SystemRoot\Temp"
    SetupFolder       = "$env:SystemRoot\Temp\OneDriveSetup"
    DownloadUrl       = "https://go.microsoft.com/fwlink/p/?LinkID=2182910"
    SetupFileName     = "OneDriveSetup.exe"
    InstallArgs       = "/allusers /update"
    MaxRetries        = 3
    RetryDelaySeconds = 5
    DownloadTimeout   = 300 # 5 minutes
    OneDriveExePath   = "$env:ProgramFiles\Microsoft OneDrive\OneDrive.exe"
}
#endregion

#region Logging Functions

function Write-LogEntry {
    <#
    .SYNOPSIS
        Writes a CMTrace-compatible log entry.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Value,
        
        [Parameter(Mandatory = $true)]
        [ValidateSet("1", "2", "3")]
        [string]$Severity
    )
    
    try {
        # Ensure log directory exists
        if (-not (Test-Path -Path $script:Config.LogPath)) {
            New-Item -Path $script:Config.LogPath -ItemType Directory -Force | Out-Null
        }
        
        $LogFilePath = Join-Path -Path $script:Config.LogPath -ChildPath $script:Config.LogFileName
        
        # Construct CMTrace format log entry
        $Time = -join @((Get-Date -Format "HH:mm:ss.fff"), "+", (Get-CimInstance -ClassName Win32_TimeZone | Select-Object -ExpandProperty Bias))
        $Date = Get-Date -Format "MM-dd-yyyy"
        $Context = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
        
        $LogText = "<![LOG[$Value]LOG]!><time=`"$Time`" date=`"$Date`" component=`"OneDriveSetup`" context=`"$Context`" type=`"$Severity`" thread=`"$PID`" file=`"`">"
        
        # Write to log file
        Add-Content -Path $LogFilePath -Value $LogText -Encoding UTF8 -ErrorAction Stop
        
        # Console output
        switch ($Severity) {
            "1" { Write-Verbose -Message $Value }
            "2" { Write-Warning -Message $Value }
            "3" { Write-Error -Message $Value }
        }
    }
    catch {
        Write-Warning -Message "- Critical Error - Failed to write log entry: $($_.Exception.Message)"
    }
}

function Write-Log {
    <#
    .SYNOPSIS
        Simplified logging wrapper.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [string]$Message,
        
        [Parameter(Position = 1)]
        [ValidateSet('Info', 'Warning', 'Error')]
        [string]$Level = 'Info'
    )
    
    $severityMap = @{
        'Info'    = '1'
        'Warning' = '2'
        'Error'   = '3'
    }
    
    Write-LogEntry -Value $Message -Severity $severityMap[$Level]
    Write-Host $Message
}

#endregion

#region URL Validation

function Test-UrlAvailability {
    <#
    .SYNOPSIS
        Validates URL accessibility and retrieves file metadata using HEAD request.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Url,
        
        [int]$TimeoutSeconds = 30
    )
    
    Write-Log "- Validating URL accessibility: $Url" -Level Info
    
    try {
        # Create HTTP request
        $request = [System.Net.HttpWebRequest]::Create($Url)
        $request.Method = "HEAD"
        $request.Timeout = $TimeoutSeconds * 1000
        $request.AllowAutoRedirect = $true
        $request.UserAgent = "OneDrive-Updater/2.0"
        
        # Set TLS 1.2+
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12 -bor [System.Net.SecurityProtocolType]::Tls13
        
        # Get response
        $response = $request.GetResponse()
        $statusCode = [int]$response.StatusCode
        $contentLength = $response.ContentLength
        
        # Get the final redirected URL (where the actual file is)
        $finalUrl = $response.ResponseUri.AbsoluteUri
        
        # Try to extract version from Content-Disposition header or URL
        $contentDisposition = $response.Headers['Content-Disposition']
        $lastModified = $response.LastModified
        
        $response.Close()
        
        Write-Log "- URL validation successful - Status: $statusCode" -Level Info
        Write-Log "- Content-Length: $([math]::Round($contentLength / 1MB, 2)) MB" -Level Info
        Write-Log "- Final URL: $finalUrl" -Level Info
        if ($lastModified) {
            Write-Log "- Last-Modified: $($lastModified.ToString('yyyy-MM-dd HH:mm:ss'))" -Level Info
        }
        
        return @{
            Success           = $true
            StatusCode        = $statusCode
            ContentLength     = $contentLength
            IsAccessible      = ($statusCode -eq 200)
            FinalUrl          = $finalUrl
            LastModified      = $lastModified
            ContentDisposition = $contentDisposition
        }
        
    }
    catch [System.Net.WebException] {
        $statusCode = [int]$_.Exception.Response.StatusCode
        Write-Log "- URL validation failed - Status: $statusCode, Error: $($_.Exception.Message)" -Level Error
        
        return @{
            Success      = $false
            StatusCode   = $statusCode
            IsAccessible = $false
            ErrorMessage = $_.Exception.Message
        }
    }
    catch {
        Write-Log "- URL validation failed - Error: $($_.Exception.Message)" -Level Error
        
        return @{
            Success      = $false
            IsAccessible = $false
            ErrorMessage = $_.Exception.Message
        }
    }
}

function Get-OneDriveVersionFromUrl {
    <#
    .SYNOPSIS
        Downloads only the PE header portion to extract version without downloading entire file.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Url
    )
    
    Write-Log "- Retrieving version information from remote file (without full download)" -Level Info
    
    try {
        # Set TLS 1.2+
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12 -bor [System.Net.SecurityProtocolType]::Tls13
        
        # Download only first 64KB (enough to get PE headers and version resource)
        $request = [System.Net.HttpWebRequest]::Create($Url)
        $request.Method = "GET"
        $request.UserAgent = "OneDrive-Updater/2.0"
        $request.AddRange(0, 65535) # Request only first 64KB
        $request.Timeout = 30000
        
        $response = $request.GetResponse()
        $stream = $response.GetResponseStream()
        
        # Create temporary file for partial download
        $tempFile = [System.IO.Path]::GetTempFileName()
        $tempFileRenamed = "$tempFile.exe"
        Rename-Item -Path $tempFile -NewName $tempFileRenamed -Force
        
        try {
            # Write partial content to temp file
            $fileStream = [System.IO.File]::OpenWrite($tempFileRenamed)
            $buffer = New-Object byte[] 8192
            $totalRead = 0
            
            while ($totalRead -lt 65536) {
                $read = $stream.Read($buffer, 0, $buffer.Length)
                if ($read -eq 0) { break }
                $fileStream.Write($buffer, 0, $read)
                $totalRead += $read
            }
            
            $fileStream.Close()
            $stream.Close()
            $response.Close()
            
            Write-Log "- Downloaded $totalRead bytes for version detection" -Level Info
            
            # Try to read version info (may fail if version resource isn't in first 64KB)
            try {
                $versionInfo = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($tempFileRenamed)
                $version = $versionInfo.FileVersion
                
                if (-not [string]::IsNullOrWhiteSpace($version)) {
                    Write-Log "- Successfully extracted version from partial download: $version" -Level Info
                    return [version]$version
                }
            }
            catch {
                Write-Log "- Warning - Could not extract version from partial download: $($_.Exception.Message)" -Level Warning
            }
            
            # If partial download didn't work, return null to trigger full download
            Write-Log "- Version information not available in file header, full download required" -Level Info
            return $null
            
        }
        finally {
            # Cleanup temp file
            if (Test-Path $tempFileRenamed) {
                Remove-Item -Path $tempFileRenamed -Force -ErrorAction SilentlyContinue
            }
        }
        
    }
    catch {
        Write-Log "- Warning - Failed to get version from URL: $($_.Exception.Message)" -Level Warning
        Write-Log "- Will proceed with full download to determine version" -Level Info
        return $null
    }
}

#endregion

#region Download Functions

function Start-FileDownload {
    <#
    .SYNOPSIS
        Downloads a file using .NET WebClient with progress and validation.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Url,
        
        [Parameter(Mandatory = $true)]
        [string]$DestinationPath,
        
        [int]$TimeoutSeconds = 300
    )
    
    Write-Log "- Starting download from: $Url" -Level Info
    Write-Log "- Destination: $DestinationPath" -Level Info
    
    try {
        # Ensure destination directory exists
        $destinationDir = Split-Path -Path $DestinationPath -Parent
        if (-not (Test-Path -Path $destinationDir)) {
            New-Item -Path $destinationDir -ItemType Directory -Force | Out-Null
            Write-Log "- Created destination directory: $destinationDir" -Level Info
        }
        
        # Set TLS 1.2+
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12 -bor [System.Net.SecurityProtocolType]::Tls13
        
        # Create WebClient
        $webClient = New-Object System.Net.WebClient
        $webClient.Headers.Add("user-agent", "OneDrive-Updater/2.0")
        
        # Register progress event (optional, for visibility in logs)
        $progressEventId = Register-ObjectEvent -InputObject $webClient -EventName DownloadProgressChanged -Action {
            $percent = $EventArgs.ProgressPercentage
            if ($percent % 10 -eq 0) {
                Write-Verbose "- Download progress: $percent%"
            }
        }
        
        # Start async download with timeout
        $downloadTask = $webClient.DownloadFileTaskAsync($Url, $DestinationPath)
        
        # Wait with timeout
        if (-not $downloadTask.Wait($TimeoutSeconds * 1000)) {
            $webClient.CancelAsync()
            throw "Download timed out after $TimeoutSeconds seconds"
        }
        
        # Clean up
        if ($progressEventId) {
            Unregister-Event -SourceIdentifier $progressEventId.Name -ErrorAction SilentlyContinue
        }
        $webClient.Dispose()
        
        # Validate file exists and has content
        if (-not (Test-Path -Path $DestinationPath)) {
            throw "Downloaded file not found at destination"
        }
        
        $fileSize = (Get-Item -Path $DestinationPath).Length
        if ($fileSize -eq 0) {
            throw "Downloaded file is empty (0 bytes)"
        }
        
        $fileSizeMB = [math]::Round($fileSize / 1MB, 2)
        Write-Log "- Download completed successfully - File size: $fileSizeMB MB" -Level Info
        
        return @{
            Success  = $true
            FilePath = $DestinationPath
            FileSize = $fileSize
        }
        
    }
    catch {
        Write-Log "- Download failed: $($_.Exception.Message)" -Level Error
        
        # Cleanup partial download
        if (Test-Path -Path $DestinationPath) {
            Remove-Item -Path $DestinationPath -Force -ErrorAction SilentlyContinue
        }
        
        throw
    }
}

#endregion

#region Certificate Validation

function Test-FileCertificate {
    <#
    .SYNOPSIS
        Validates file is signed by Microsoft with valid certificate chain.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$FilePath
    )
    
    Write-Log "- Validating file certificate: $FilePath" -Level Info
    
    try {
        # Get signature
        $signature = Get-AuthenticodeSignature -FilePath $FilePath -ErrorAction Stop
        
        if ($null -eq $signature.SignerCertificate) {
            Write-Log "- Critical Error - File is not digitally signed" -Level Error
            return $false
        }
        
        # Check signature status
        if ($signature.Status -ne 'Valid') {
            Write-Log "- Critical Error - Signature status is invalid: $($signature.Status)" -Level Error
            return $false
        }
        
        # Verify Microsoft as signer
        $cert = $signature.SignerCertificate
        if ($cert.Subject -notmatch "O=Microsoft Corporation") {
            Write-Log "- Critical Error - File not signed by Microsoft Corporation" -Level Error
            return $false
        }
        
        Write-Log "- Certificate signed by: $($cert.Subject)" -Level Info
        
        # Validate certificate chain
        $chain = New-Object System.Security.Cryptography.X509Certificates.X509Chain
        $chain.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::Online
        $chain.ChainPolicy.RevocationFlag = [System.Security.Cryptography.X509Certificates.X509RevocationFlag]::ExcludeRoot
        $chain.ChainPolicy.VerificationFlags = [System.Security.Cryptography.X509Certificates.X509VerificationFlags]::NoFlag
        
        $chainIsValid = $chain.Build($cert)
        
        if (-not $chainIsValid) {
            Write-Log "- Critical Error -Certificate chain validation failed" -Level Warning
            # Log chain status
            foreach ($status in $chain.ChainStatus) {
                Write-Log "- Chain status: $($status.Status) - $($status.StatusInformation)" -Level Warning
            }
        }
        
        # Verify root certificate is Microsoft
        $rootCert = $chain.ChainElements | 
            Select-Object -ExpandProperty Certificate | 
            Where-Object { $_.Subject -match "CN=Microsoft Root" } |
            Select-Object -First 1
        
        if ($null -eq $rootCert) {
            Write-Log "- Critical Error - Microsoft root certificate not found in chain" -Level Error
            return $false
        }
        
        # Verify root cert is in trusted store
        $trustedRoot = Get-ChildItem -Path "Cert:\LocalMachine\Root" -Recurse | 
            Where-Object { $_.Thumbprint -eq $rootCert.Thumbprint } |
            Select-Object -First 1
        
        if ($null -eq $trustedRoot) {
            Write-Log "- Critical Error - Root certificate not found in local trusted store" -Level Error
            return $false
        }
        
        Write-Log "- Certificate validation successful - Issuer: $($cert.Issuer)" -Level Info
        return $true
        
    }
    catch {
        Write-Log "- Critical Error - Certificate validation failed: $($_.Exception.Message)" -Level Error
        return $false
    }
}

#endregion

#region Cleanup

function Remove-SetupFolder {
    <#
    .SYNOPSIS
        Safely removes the setup folder with retry logic.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )
    
    if (-not (Test-Path -Path $Path)) {
        return
    }
    
    Write-Log "- Cleaning up setup folder: $Path" -Level Info
    
    $retryCount = 0
    $maxRetries = 3
    
    while ($retryCount -lt $maxRetries) {
        try {
            Remove-Item -Path $Path -Recurse -Force -ErrorAction Stop
            Write-Log "- Setup folder removed successfully" -Level Info
            return
        }
        catch {
            $retryCount++
            if ($retryCount -lt $maxRetries) {
                Write-Log "- Warning - Cleanup failed (attempt $retryCount of $maxRetries), retrying..." -Level Warning
                Start-Sleep -Seconds 2
            }
            else {
                Write-Log "- Critical Error - Failed to cleanup setup folder after $maxRetries attempts: $($_.Exception.Message)" -Level Warning
            }
        }
    }
}

#endregion

#region Version Comparison

function Get-InstalledOneDriveVersion {
    <#
    .SYNOPSIS
        Gets the currently installed OneDrive version and file metadata.
    #>
    [CmdletBinding()]
    param()
    
    Write-Log "- Checking for existing OneDrive installation" -Level Info
    
    try {
        $oneDrivePath = $script:Config.OneDriveExePath
        
        if (-not (Test-Path -Path $oneDrivePath)) {
            Write-Log "- OneDrive executable not found at: $oneDrivePath" -Level Info
            Write-Log "- No existing installation detected" -Level Info
            return @{
                Version      = $null
                LastModified = $null
                FileExists   = $false
            }
        }
        
        $fileInfo = Get-Item -Path $oneDrivePath
        $versionInfo = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($oneDrivePath)
        $version = $versionInfo.FileVersion
        $lastModified = $fileInfo.LastWriteTime
        
        if ([string]::IsNullOrWhiteSpace($version)) {
            Write-Log "- Warning - Could not determine OneDrive version from executable" -Level Warning
            Write-Log "- File last modified: $($lastModified.ToString('yyyy-MM-dd HH:mm:ss'))" -Level Info
            return @{
                Version      = $null
                LastModified = $lastModified
                FileExists   = $true
            }
        }
        
        Write-Log "- Found installed OneDrive version: $version" -Level Info
        Write-Log "- File last modified: $($lastModified.ToString('yyyy-MM-dd HH:mm:ss'))" -Level Info
        
        return @{
            Version      = [version]$version
            LastModified = $lastModified
            FileExists   = $true
        }
        
    }
    catch {
        Write-Log "- Warning - Failed to get installed OneDrive information: $($_.Exception.Message)" -Level Warning
        return @{
            Version      = $null
            LastModified = $null
            FileExists   = $false
        }
    }
}

function Compare-OneDriveVersions {
    <#
    .SYNOPSIS
        Compares installed version with download version, falls back to date comparison.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [version]$DownloadedVersion,
        
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [version]$InstalledVersion,
        
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [datetime]$RemoteLastModified,
        
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [datetime]$LocalLastModified
    )
    
    Write-Log "- Comparing OneDrive versions and dates" -Level Info
    
    # Try version comparison first
    if ($null -ne $DownloadedVersion) {
        Write-Log "-- Remote version: $DownloadedVersion" -Level Info
        
        if ($null -eq $InstalledVersion) {
            Write-Log "-- Installed version: Not installed" -Level Info
            Write-Log "- Version comparison result: Installation required (no existing version)" -Level Info
            return $true  # Proceed with installation
        }
        
        Write-Log "-- Installed version: $InstalledVersion" -Level Info
        
        if ($DownloadedVersion -gt $InstalledVersion) {
            Write-Log "- Version comparison result: Update available ($InstalledVersion → $DownloadedVersion)" -Level Info
            return $true  # Proceed with installation
        }
        elseif ($DownloadedVersion -eq $InstalledVersion) {
            Write-Log "- Version comparison result: OneDrive is already up-to-date (v$InstalledVersion)" -Level Info
            return $false  # Skip installation
        }
        else {
            Write-Log "- Version comparison result: Installed version is newer ($InstalledVersion > $DownloadedVersion)" -Level Warning
            Write-Log "- Skipping installation - installed version is already newer" -Level Warning
            return $false  # Skip installation
        }
    }
    
    # Fall back to date comparison if version not available
    Write-Log "- Version comparison not possible, using date comparison instead" -Level Warning
    
    if ($null -eq $RemoteLastModified) {
        Write-Log "-- Remote last-modified: Not available" -Level Warning
        Write-Log "- Date comparison not possible - will proceed with download" -Level Warning
        return $true  # Can't compare, proceed with download
    }
    
    Write-Log "-- Remote last-modified: $($RemoteLastModified.ToString('yyyy-MM-dd HH:mm:ss'))" -Level Info
    
    if ($null -eq $LocalLastModified) {
        Write-Log "-- Local last-modified: File not found" -Level Info
        Write-Log "- Date comparison result: Installation required (no local file)" -Level Info
        return $true  # Proceed with installation
    }
    
    Write-Log "-- Local last-modified: $($LocalLastModified.ToString('yyyy-MM-dd HH:mm:ss'))" -Level Info
    
    # Compare dates
    if ($RemoteLastModified -gt $LocalLastModified) {
        $timeDiff = $RemoteLastModified - $LocalLastModified
        Write-Log "- Date comparison result: Remote file is newer by $($timeDiff.TotalHours.ToString('F2')) hours" -Level Info
        Write-Log "- Proceeding with download" -Level Info
        return $true  # Proceed with installation
    }
    elseif ($RemoteLastModified -eq $LocalLastModified) {
        Write-Log "- Date comparison result: Files have same modification date" -Level Info
        Write-Log "- Skipping download - local file appears current" -Level Info
        return $false  # Skip installation
    }
    else {
        $timeDiff = $LocalLastModified - $RemoteLastModified
        Write-Log "- Date comparison result: Local file is newer by $($timeDiff.TotalHours.ToString('F2')) hours" -Level Warning
        Write-Log "- Skipping download - local file is already newer" -Level Warning
        return $false  # Skip installation
    }
}

#endregion

#region Main Installation Logic

function Install-OneDriveMachineWide {
    <#
    .SYNOPSIS
        Main installation orchestration function.
    #>
    [CmdletBinding()]
    param()
    
    Write-Log "[OneDrive Machine-Wide Setup] - Starting installation" -Level Info
    Write-Log "- Running as: $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)" -Level Info
    
    $exitCode = 0
    
    try {
        # Step 1: Check current installation version and metadata
        Write-Log "Step 1: Checking current OneDrive installation" -Level Info
        $installedInfo = Get-InstalledOneDriveVersion
        $installedVersion = $installedInfo.Version
        $localLastModified = $installedInfo.LastModified
        
        if ($installedVersion) {
            Write-Log "- Current installed version: $installedVersion" -Level Info
        } else {
            Write-Log "- Current installed version: Unable to determine" -Level Warning
        }
        
        if ($localLastModified) {
            Write-Log "- Current file date: $($localLastModified.ToString('yyyy-MM-dd HH:mm:ss'))" -Level Info
        }
        
        # Step 2: Cleanup any existing setup folder
        Remove-SetupFolder -Path $script:Config.SetupFolder
        
        # Step 3: Validate URL availability and get file metadata
        Write-Log "Step 2: Validating download URL and retrieving file information" -Level Info
        $urlCheck = Test-UrlAvailability -Url $script:Config.DownloadUrl -TimeoutSeconds 30
        
        if (-not $urlCheck.IsAccessible) {
            throw "Download URL is not accessible (Status: $($urlCheck.StatusCode))"
        }
        
        $fileSizeMB = [math]::Round($urlCheck.ContentLength / 1MB, 2)
        $remoteLastModified = $urlCheck.LastModified
        
        Write-Log "- Remote file size: $fileSizeMB MB" -Level Info
        if ($remoteLastModified) {
            Write-Log "- Remote file date: $($remoteLastModified.ToString('yyyy-MM-dd HH:mm:ss'))" -Level Info
        }
        
        # Step 4: Attempt to get version from remote file without full download
        Write-Log "Step 3: Attempting to retrieve version from remote file" -Level Info
        $remoteVersion = Get-OneDriveVersionFromUrl -Url $urlCheck.FinalUrl
        
        # Step 5: Compare versions/dates before downloading
        Write-Log "Step 4: Comparing local vs remote file" -Level Info
        $shouldInstall = Compare-OneDriveVersions `
            -DownloadedVersion $remoteVersion `
            -InstalledVersion $installedVersion `
            -RemoteLastModified $remoteLastModified `
            -LocalLastModified $localLastModified
        
        if (-not $shouldInstall) {
            Write-Log "[OneDrive Already Up-to-Date] - No download or installation needed" -Level Info
            
            if ($remoteVersion -and $installedVersion) {
                Write-Log "- Version check: Local ($installedVersion) matches remote ($remoteVersion)" -Level Info
            } elseif ($remoteLastModified -and $localLastModified) {
                Write-Log "- Date check: Local file is current or newer than remote" -Level Info
                Write-Log "  Local: $($localLastModified.ToString('yyyy-MM-dd HH:mm:ss'))" -Level Info
                Write-Log "  Remote: $($remoteLastModified.ToString('yyyy-MM-dd HH:mm:ss'))" -Level Info
            }
            
            Write-Log "- Saved bandwidth: $fileSizeMB MB not downloaded" -Level Info
            Write-Log "- Exiting with success code (0)" -Level Info
            return 0  # Exit code 0 - success, no action needed
        }
        
        # Log what triggered the update
        if ($remoteVersion -and $installedVersion) {
            Write-Log "- Update triggered by version difference: $installedVersion → $remoteVersion" -Level Info
        } elseif ($remoteLastModified -and $localLastModified) {
            $timeDiff = $remoteLastModified - $localLastModified
            Write-Log "- Update triggered by newer remote file (difference: $($timeDiff.TotalHours.ToString('F2')) hours)" -Level Info
        } else {
            Write-Log "- Update triggered: Unable to compare versions or dates, proceeding with download" -Level Info
        }
        
        Write-Log "- Proceeding with download ($fileSizeMB MB)" -Level Info
        
        # Step 6: Download setup file with retry logic
        Write-Log "Step 5: Downloading OneDrive setup ($fileSizeMB MB)" -Level Info
        $setupPath = Join-Path -Path $script:Config.SetupFolder -ChildPath $script:Config.SetupFileName
        
        $downloadSuccess = $false
        $retryCount = 0
        
        while (-not $downloadSuccess -and $retryCount -lt $script:Config.MaxRetries) {
            try {
                $downloadResult = Start-FileDownload -Url $script:Config.DownloadUrl -DestinationPath $setupPath -TimeoutSeconds $script:Config.DownloadTimeout
                $downloadSuccess = $downloadResult.Success
            }
            catch {
                $retryCount++
                if ($retryCount -lt $script:Config.MaxRetries) {
                    Write-Log "- Warning - Download failed (attempt $retryCount of $($script:Config.MaxRetries)): $($_.Exception.Message)" -Level Warning
                    Start-Sleep -Seconds $script:Config.RetryDelaySeconds
                }
                else {
                    throw "- Critical Error - Download failed after $($script:Config.MaxRetries) attempts: $($_.Exception.Message)"
                }
            }
        }
        
        # Step 7: Get downloaded version information
        Write-Log "Step 6: Verifying downloaded setup version" -Level Info
        $versionInfo = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($setupPath)
        $downloadedVersionString = $versionInfo.FileVersion
        Write-Log "- Downloaded OneDrive setup version: $downloadedVersionString" -Level Info
        
        # Parse version
        $downloadedVersion = [version]$downloadedVersionString
        
        # Step 8: Final safety check (shouldn't trigger if pre-download check worked)
        if (-not $remoteVersion) {
            Write-Log "Step 7: Final version/date comparison" -Level Info
            
            $downloadedFileInfo = Get-Item -Path $setupPath
            $downloadedLastModified = $downloadedFileInfo.LastWriteTime
            
            $shouldInstall = Compare-OneDriveVersions `
                -DownloadedVersion $downloadedVersion `
                -InstalledVersion $installedVersion `
                -RemoteLastModified $downloadedLastModified `
                -LocalLastModified $localLastModified
            
            if (-not $shouldInstall) {
                Write-Log "[OneDrive Already Up-to-Date] - No installation needed after download verification" -Level Info
                Write-Log "- Exiting with success code (0)" -Level Info
                return 0  # Exit code 0 - success, no action needed
            }
        }
        
        # Step 9: Validate certificate
        Write-Log "Step 8: Validating file certificate" -Level Info
        if (-not (Test-FileCertificate -FilePath $setupPath)) {
            throw "- Critical Error - Certificate validation failed - setup file is not trusted"
        }
        
        # Step 10: Run installation
        Write-Log "Step 9: Starting OneDrive installation (machine-wide mode)" -Level Info
        Write-Log "- Install arguments: $($script:Config.InstallArgs)" -Level Info
        
        $process = Start-Process -FilePath $setupPath -ArgumentList $script:Config.InstallArgs -Wait -PassThru -NoNewWindow -ErrorAction Stop
        $exitCode = $process.ExitCode
        
        if ($exitCode -eq 0) {
            Write-Log "- OneDrive installation completed successfully (Exit Code: $exitCode)" -Level Info
            
            # Verify new version
            $newInstalledInfo = Get-InstalledOneDriveVersion
            if ($newInstalledInfo.Version) {
                Write-Log "- Post-installation verification: OneDrive version is now $($newInstalledInfo.Version)" -Level Info
            }
            if ($newInstalledInfo.LastModified) {
                Write-Log "- Post-installation verification: File date is now $($newInstalledInfo.LastModified.ToString('yyyy-MM-dd HH:mm:ss'))" -Level Info
            }
        }
        else {
            Write-Log "- OneDrive installation completed with exit code: $exitCode" -Level Warning
        }
        
        Write-Log "[OneDrive Machine-Wide Setup] - Completed Successfully" -Level Info
        
    }
    catch {
        Write-Log "- Critical Error - Installation failed: $($_.Exception.Message)" -Level Error
        Write-Log "- Stack trace: $($_.ScriptStackTrace)" -Level Error
        $exitCode = 1
    }
    finally {
        # Cleanup
        Remove-SetupFolder -Path $script:Config.SetupFolder
    }
    
    return $exitCode
}

#endregion

#region Script Entry Point

# Execute installation
$result = Install-OneDriveMachineWide

# Exit with appropriate code
exit $result

#endregion