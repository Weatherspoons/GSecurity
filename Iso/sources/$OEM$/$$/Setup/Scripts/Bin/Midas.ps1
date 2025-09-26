# Midas.ps1 by Gorstak
# Run as Administrator. Logs to C:\Temp\MidasLog.txt

# Logging function
function Write-Log {
    param([string]$Message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] $Message"
    $logPath = "C:\Temp\MidasLog.txt"
    if (-not (Test-Path "C:\Temp")) { New-Item -Path "C:\Temp" -ItemType Directory -Force | Out-Null }
    Add-Content -Path $logPath -Value $logEntry -ErrorAction SilentlyContinue
    Write-Host $logEntry  # Also to console for initial run
}

function Register-SystemLogonScript {
    param ([string]$TaskName = "RunMidasAtLogon")

    $scriptSource = $MyInvocation.MyCommand.Path
    if (-not $scriptSource) { $scriptSource = $PSCommandPath }
    if (-not $scriptSource) {
        Write-Log "Error: Could not determine script path."
        return
    }

    $targetFolder = "C:\Windows\Setup\Scripts\Bin"
    $targetPath = Join-Path $targetFolder (Split-Path $scriptSource -Leaf)

    if (-not (Test-Path $targetFolder)) {
        New-Item -Path $targetFolder -ItemType Directory -Force | Out-Null
        Write-Log "Created folder: $targetFolder"
    }

    try {
        Copy-Item -Path $scriptSource -Destination $targetPath -Force -ErrorAction Stop
        Write-Log "Copied script to: $targetPath"
    } catch {
        Write-Log "Failed to copy script: $_"
        return
    }

    # Configure the scheduled task to run as the logged-on user and hide the window
    $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-WindowStyle Hidden -ExecutionPolicy Bypass -File `"$targetPath`""
    $trigger = New-ScheduledTaskTrigger -AtLogOn
    $principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType Interactive -RunLevel Highest

    try {
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
        Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal
        Write-Log "Scheduled task '$TaskName' created to run at user logon for user '$env:USERNAME'."
    } catch {
        Write-Log "Failed to register task: $_"
    }
}

# Run the function
Register-SystemLogonScript
Write-Log "Script setup complete. Starting WMI monitoring..."

# Define the WMI query for process start events
$query = "SELECT * FROM Win32_ProcessStartTrace"

# Define the action block
$action = {
    $eventArgs = $Event.SourceEventArgs.NewEvent
    $processName = $eventArgs.ProcessName
    $pid = $eventArgs.ProcessID

    Write-Log "Event triggered: Process '$processName' (PID: $pid)"

    try {
        $process = Get-Process -Id $pid -ErrorAction SilentlyContinue
        if ($process) {
            $path = $process.MainModule.FileName
            if ($path) {
                # Get the current user's profile path and Program Files paths
                $userProfile = $env:USERPROFILE
                $programFiles = "C:\Program Files"
                $programFilesX86 = "C:\Program Files (x86)"

                # Check if the file path is within the user's profile directory or Program Files
                if ($path -like "$userProfile*" -or $path -like "$programFiles*" -or $path -like "$programFilesX86*") {
                    $location = if ($path -like "$userProfile*") { "user folder ($userProfile)" }
                                elseif ($path -like "$programFiles*") { "Program Files" }
                                else { "Program Files (x86)" }
                    Write-Log "Full path resolved: $path (within $location)"

                    # Run commands and capture output
                    $takeownOut = & takeown /f "$path" /A 2>&1
                    Write-Log "takeown output: $takeownOut"
                    
                    $resetOut = & icacls "$path" /reset 2>&1
                    Write-Log "icacls /reset output: $resetOut"
                    
                    $inheritOut = & icacls "$path" /inheritance:r 2>&1
                    Write-Log "icacls /inheritance:r output: $inheritOut"
                    
                    $grantOut = & icacls "$path" /grant:r "*S-1-2-1:F" 2>&1
                    Write-Log "icacls /grant output: $grantOut"
                    
                    # Verify final perms
                    $finalPerms = & icacls "$path" 2>&1
                    Write-Log "Final perms for $path`: $finalPerms"
                } else {
                    Write-Log "Path $path is outside user folder ($userProfile), Program Files, or Program Files (x86). Skipping."
                }
            } else {
                Write-Log "Failed to get MainModule.FileName for PID $pid"
            }
        } else {
            Write-Log "Get-Process failed for PID $pid (process may have exited)"
        }
    } catch {
        Write-Log "Error in action block for PID $pid`: $_"
    }
}

# Register the WMI event
try {
    Register-WmiEvent -Query $query -SourceIdentifier "ProcessStartMonitor" -Action $action
    Write-Log "WMI event registered successfully."
} catch {
    Write-Log "Failed to register WMI event: $_"
}

# Keep running
Write-Log "Monitoring started. Press Ctrl+C to stop."
while ($true) {
    Start-Sleep -Seconds 1
}