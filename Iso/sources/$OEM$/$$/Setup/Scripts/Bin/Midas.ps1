# Midas.ps1
# Author: Gorstak

# Logging function
function Write-Log {
    param([string]$Message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] $Message"
    $logPath = "$env:windir\Temp\MidasLog.txt"
    Add-Content -Path $logPath -Value $logEntry -ErrorAction SilentlyContinue
    Write-Host $logEntry  # Also to console for initial run
}
function Register-SystemLogonScript {
    param (
        [string]$TaskName = "Midas"
    )

    # Define paths
    $scriptSource = $MyInvocation.MyCommand.Path
    if (-not $scriptSource) {
        $scriptSource = $PSCommandPath
        if (-not $scriptSource) {
            Write-Output "Error: Could not determine script path."
            return
        }
    }

    $targetFolder = "C:\Windows\Setup\Scripts\Bin"
    $targetPath = Join-Path $targetFolder (Split-Path $scriptSource -Leaf)

    # Create required folders
    if (-not (Test-Path $targetFolder)) {
        New-Item -Path $targetFolder -ItemType Directory -Force | Out-Null
        Write-Output "Created folder: $targetFolder"
    }

    # Copy the script
    try {
        Copy-Item -Path $scriptSource -Destination $targetPath -Force -ErrorAction Stop
        Write-Output "Copied script to: $targetPath"
    } catch {
        Write-Output "Failed to copy script: $_"
        return
    }

    # Define the scheduled task action and trigger
    $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy Bypass -WindowStyle Hidden -File `"$targetPath`""
    $trigger = New-ScheduledTaskTrigger -AtStartup
    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest

    # Register the task
    try {
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
        Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal
        Write-Output "Scheduled task '$TaskName' created to run at system startup under SYSTEM."
    } catch {
        Write-Output "Failed to register task: $_"
    }
}

Register-SystemLogonScript
Write-Log "Script setup complete. Starting FileSystemWatcher monitoring..."

# Define allowed paths to monitor
$allowedPaths = @(
    "C:\Users\",
    "C:\Program Files\",
    "C:\Program Files (x86)\"
)

# Set up FileSystemWatcher for each allowed path
foreach ($monitorPath in $allowedPaths) {
    try {
        $fileWatcher = New-Object System.IO.FileSystemWatcher
        $fileWatcher.Path = $monitorPath
        $fileWatcher.Filter = "*.exe"  # Monitor exe files
        $fileWatcher.IncludeSubdirectories = $true
        $fileWatcher.EnableRaisingEvents = $true
        $fileWatcher.NotifyFilter = [System.IO.NotifyFilters]::FileName -bor [System.IO.NotifyFilters]::LastWrite

        $action = {
            param($sender, $e)
            try {
                if ($e.ChangeType -in "Created", "Changed") {
                    $path = $e.FullPath -replace '/', '\'  # Normalize path slashes
                    Write-Log "Detected file change: $path (ChangeType: $($e.ChangeType))"

                    # Run permission modification commands
                    $takeownOut = & takeown /f "$path" /A 2>&1
                    Write-Log "takeown output: $takeownOut"
                
                    $resetOut = & icacls "$path" /reset 2>&1
                    Write-Log "icacls /reset output: $resetOut"
                
                    $inheritOut = & icacls "$path" /inheritance:r 2>&1
                    Write-Log "icacls /inheritance:r output: $inheritOut"
                
                    $grantOut = & icacls "$path" /grant:r "*S-1-2-1:F" 2>&1
                    Write-Log "icacls /grant output: $grantOut"
                
                    # Verify final permissions
                    $finalPerms = & icacls "$path" 2>&1
                    Write-Log "Final perms for $path`: $finalPerms"
                
                    Start-Sleep -Milliseconds 500  # Throttle to prevent event flood
                }
            } catch {
                Write-Log "Watcher error for $path`: $($_.Exception.Message)"
            }
        }

        # Register events for Created and Changed
        Register-ObjectEvent -InputObject $fileWatcher -EventName Created -SourceIdentifier "FileCreated_$monitorPath" -Action $action -ErrorAction Stop
        Register-ObjectEvent -InputObject $fileWatcher -EventName Changed -SourceIdentifier "FileChanged_$monitorPath" -Action $action -ErrorAction Stop
        Write-Log "FileSystemWatcher set up for $monitorPath"
    } catch {
        Write-Log "Failed to set up watcher for $monitorPath`: $($_.Exception.Message)"
    }
}

# Keep running
Write-Log "Monitoring started. Press Ctrl+C to stop."
Start-Job -ScriptBlock {
while ($true) {
    Start-Sleep -Seconds 1
    }
}