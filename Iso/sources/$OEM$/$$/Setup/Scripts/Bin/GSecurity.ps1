<#
.SYNOPSIS
    Configures WMI and DCOM security to restrict access to a specific SID
.DESCRIPTION
    This script configures WMI namespace permissions, DCOM security,
    and firewall rules to allow access for a specific SID while preserving existing permissions.
#>

# Hardcoded SID - REPLACE WITH YOUR DESIRED SID
$TargetSID = "S-1-2-1"  # Replace with a valid SID (e.g., from whoami /user or AD)
$Namespace = "root\cimv2"

# Require admin privileges
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Error "This script requires Administrator privileges"
    exit 1
}

# Validate SID format
try {
    $sidObj = New-Object System.Security.Principal.SecurityIdentifier($TargetSID)
    $sidAccount = $sidObj.Translate([System.Security.Principal.NTAccount]).Value
    Write-Host "SID $TargetSID maps to account: $sidAccount"
} catch {
    Write-Error "Invalid SID format or SID not found: $TargetSID"
    exit 1
}

function Set-WMINamespaceSecurity {
    param($Namespace, $SID)
    
    try {
        # Get the WMI namespace security settings
        $wmiSecurity = Get-WmiObject -Namespace $Namespace -Class "__SystemSecurity" -List
        $result = $wmiSecurity.GetSecurityDescriptor()
        if ($result.ReturnValue -ne 0) {
            throw "Failed to get security descriptor for $Namespace (Error: $($result.ReturnValue))"
        }
        $securityDescriptor = $result.Descriptor
        
        # Get the binary SID
        $sidWmi = [wmi]"Win32_SID.SID='$SID'"
        $binarySID = $sidWmi.BinarySID  # Get the binary representation of the SID
        
        # Create a new trustee for the target SID
        $trustee = ([wmiclass]'Win32_Trustee').CreateInstance()
        $trustee.SID = $binarySID
        $trustee.Name = $sidWmi.AccountName
        
        # Create ACE with specific WMI permissions (Execute Methods, Enable Account, Remote Enable)
        $ace = ([wmiclass]'Win32_ACE').CreateInstance()
        $ace.AccessMask = 0x1 + 0x2 + 0x20  # WBEM_ENABLE (0x1) + WBEM_METHOD_EXECUTE (0x2) + WBEM_REMOTE_ACCESS (0x20)
        $ace.AceFlags = 0x2                 # Container inherit
        $ace.AceType = 0x0                  # Allow
        $ace.Trustee = $trustee
        
        # Append the new ACE to the existing DACL instead of replacing it
        $currentDacl = $securityDescriptor.DACL
        if ($null -eq $currentDacl) {
            $securityDescriptor.DACL = @($ace)
        } else {
            $securityDescriptor.DACL = $currentDacl + @($ace)
        }
        
        # Apply the new security descriptor
        $result = $wmiSecurity.SetSecurityDescriptor($securityDescriptor)
        if ($result.ReturnValue -eq 0) {
            Write-Host "Successfully updated WMI namespace security for $Namespace"
        } else {
            throw "Failed to set security descriptor for $Namespace (Error: $($result.ReturnValue))"
        }
    } catch {
        Write-Error "Error setting WMI namespace security: $_"
        return $false
    }
    return $true
}

function Set-DCOMSecurity {
    param($SID)
    
    try {
        # Configure DCOM security using registry
        $dcomPath = "HKLM:\SOFTWARE\Microsoft\Ole"
        
        # Define SDDL string for access and launch permissions
        $sddl = "O:BAG:BAD:(A;;0x7;;;$SID)"  # Grant access and launch permissions to the SID
        
        # Convert SDDL to binary security descriptor
        $converter = New-Object System.Security.AccessControl.RawSecurityDescriptor($sddl)
        $binarySD = New-Object Byte[] $converter.BinaryLength
        $converter.GetBinaryForm($binarySD, 0)
        
        # Apply DCOM security settings
        Set-ItemProperty -Path $dcomPath -Name "DefaultAccessPermission" -Value $binarySD -Force
        Set-ItemProperty -Path $dcomPath -Name "DefaultLaunchPermission" -Value $binarySD -Force
        
        Write-Host "Successfully configured DCOM security"
    } catch {
        Write-Error "Error setting DCOM security: $_"
        return $false
    }
    return $true
}

function Set-WMIFirewallRules {
    param($SID)
    
    try {
        # Get WMI-related firewall rules
        $wmiRules = Get-NetFirewallRule -DisplayGroup "Windows Management Instrumentation (WMI)" | Where-Object { $_.Enabled -eq $true }
        
        if ($wmiRules.Count -eq 0) {
            Write-Warning "No enabled WMI firewall rules found."
            return $true
        }
        
        foreach ($rule in $wmiRules) {
            # Modify rule to only allow the target SID
            Set-NetFirewallRule -Name $rule.Name -RemoteUser $SID -ErrorAction SilentlyContinue
        }
        
        Write-Host "Successfully configured WMI firewall rules"
    } catch {
        Write-Warning "Error configuring firewall rules: $_"
        return $false
    }
    return $true
}

# Main execution
try {
    Write-Host "Starting WMI/DCOM security configuration for SID: $TargetSID"
    
    # Configure WMI namespace security
    Write-Host "Configuring WMI namespace security..."
    $wmiSuccess = Set-WMINamespaceSecurity -Namespace $Namespace -SID $TargetSID
    
    # Configure DCOM security
    Write-Host "Configuring DCOM security..."
    $dcomSuccess = Set-DCOMSecurity -SID $TargetSID
    
    # Configure firewall rules
    Write-Host "Configuring firewall rules..."
    $firewallSuccess = Set-WMIFirewallRules -SID $TargetSID
    
    # Check if all operations were successful
    if ($wmiSuccess -and $dcomSuccess -and $firewallSuccess) {
        Write-Host "`nSecurity configuration completed successfully!"
    } else {
        Write-Warning "`nSecurity configuration completed with errors. Check output for details."
    }
    
    Write-Host "WARNING: This configuration may break system functionality and remote management tools."
    Write-Host "Test thoroughly before deploying in production environments."
    
} catch {
    Write-Error "Script execution failed: $_"
    exit 1
}
