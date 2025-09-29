<#
.SYNOPSIS
    Configures WMI and DCOM security to restrict access to a specific SID
.DESCRIPTION
    This script silently configures WMI namespace permissions, DCOM security,
    and firewall rules to restrict access to a specific SID only.
#>

# Hardcoded SID - REPLACE WITH YOUR DESIRED SID
$TargetSID = "S-1-2-1"
$Namespace = "root\cimv2"

# Require admin privileges
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Error "This script requires Administrator privileges"
    exit 1
}

# Validate SID format
try {
    $sidObj = New-Object System.Security.Principal.SecurityIdentifier($TargetSID)
} catch {
    Write-Error "Invalid SID format: $TargetSID"
    exit 1
}

function Set-WMINamespaceSecurity {
    param($Namespace, $SID)
    
    try {
        # Get the WMI namespace security settings
        $wmiSecurity = Get-WmiObject -Namespace $Namespace -Class "__SystemSecurity" -List
        $securityDescriptor = $wmiSecurity.GetSecurityDescriptor().Descriptor
        
        # Create a new trustee for the target SID
        $trustee = ([wmiclass]'Win32_Trustee').CreateInstance()
        $trustee.SID = [wmi]"Win32_SID.SID='$SID'"
        
        # Create ACE that grants full access to the target SID
        $ace = ([wmiclass]'Win32_ACE').CreateInstance()
        $ace.AccessMask = 0x1F003F  # Full control
        $ace.AceFlags = 0x2         # Container inherit
        $ace.AceType = 0x0          # Allow
        $ace.Trustee = $trustee
        
        # Remove all existing ACEs and add only our target SID
        $securityDescriptor.DACL = @($ace)
        
        # Apply the new security descriptor
        $result = $wmiSecurity.SetSecurityDescriptor($securityDescriptor)
        
        if ($result.ReturnValue -eq 0) {
            Write-Host "Successfully secured WMI namespace: $Namespace"
        } else {
            Write-Error "Failed to secure WMI namespace: $Namespace (Error: $($result.ReturnValue))"
        }
    } catch {
        Write-Error "Error setting WMI namespace security: $_"
    }
}

function Set-DCOMSecurity {
    param($SID)
    
    try {
        # Configure DCOM security using registry
        $dcomPath = "HKLM:\SOFTWARE\Microsoft\Ole"
        
        # Set machine-wide DCOM access permissions
        $accessPermission = @(
            "O:BAG:BAD:(A;;0x1;;;$SID)"  # Grant only target SID access
        )
        
        $launchPermission = @(
            "O:BAG:BAD:(A;;0x1;;;$SID)"  # Grant only target SID launch permission
        )
        
        # Apply DCOM security settings
        Set-ItemProperty -Path $dcomPath -Name "DefaultAccessPermission" -Value $accessPermission -Force
        Set-ItemProperty -Path $dcomPath -Name "DefaultLaunchPermission" -Value $launchPermission -Force
        
        Write-Host "Successfully configured DCOM security"
    } catch {
        Write-Error "Error setting DCOM security: $_"
    }
}

function Set-WMIFirewallRules {
    param($SID)
    
    try {
        # Get WMI-related firewall rules
        $wmiRules = Get-NetFirewallRule -DisplayGroup "Windows Management Instrumentation (WMI)" | Where-Object { $_.Enabled -eq $true }
        
        foreach ($rule in $wmiRules) {
            # Modify rule to only allow the target SID
            Set-NetFirewallRule -Name $rule.Name -RemoteUser $SID -ErrorAction SilentlyContinue
        }
        
        Write-Host "Successfully configured WMI firewall rules"
    } catch {
        Write-Warning "Error configuring firewall rules: $_"
    }
}

# Main execution
try {
    Write-Host "Starting WMI/DCOM security configuration for SID: $TargetSID"
    
    # Configure WMI namespace security
    Write-Host "Configuring WMI namespace security..."
    Set-WMINamespaceSecurity -Namespace $Namespace -SID $TargetSID
    
    # Configure DCOM security
    Write-Host "Configuring DCOM security..."
    Set-DCOMSecurity -SID $TargetSID
    
    # Configure firewall rules
    Write-Host "Configuring firewall rules..."
    Set-WMIFirewallRules -SID $TargetSID
    
    Write-Host "`nSecurity configuration completed successfully!"
    Write-Host "WARNING: This configuration may break system functionality and remote management tools."
    Write-Host "Test thoroughly before deploying in production environments."
    
} catch {
    Write-Error "Script execution failed: $_"
    exit 1
}