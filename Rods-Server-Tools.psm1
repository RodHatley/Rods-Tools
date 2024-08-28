
function Get-AdminStatus {
    Return ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-FailedWindowsLogons 
{
    <#
    .SYNOPSIS
    Get-FailedWindowsLogons finds failed logon events in the local systems security event log.
    .DESCRIPTION
    This cmdlet does not require any parameters, but will default to return on the last 24 hours of failed
    logon event.
    .NOTES
    Will not show IP addresses for failed logons for local processes.  Failed logon IPs via IIS can be found in IIS logs.
    #>
    param ([int]$Hours)

    # If no Hours were specified, set to 24 hours
    if($Hours -eq 0){$Hours = 24}
  

    Write-Host "Serching Windows Event Log for failed logon attempts for the last $Hours hours...`n"

    $FailedLogins = Get-EventLog -LogName Security -After (get-date).AddHours(-$Hours) | Where-Object { $_.EventID -eq 4625 }


    foreach ($Event in $FailedLogins) {
        $UserName = $Event.ReplacementStrings[5]
        $SourceIP = $Event.ReplacementStrings[19]
        $EventTime = $Event.TimeGenerated
        Write-Host "Failed login attempt for user '$UserName' from IP address '$SourceIP' at $EventTime"  
    }

}

function Set-WindowsUpdateConfig
{
<#
.SYNOPSIS
    .Sets Windows Update Settings on Windows Server 2016 and higher.
.DESCRIPTION
    .Sets Windows Update to install updates on Sunday mornings by default at 3AM local time if no command line arguments are used.
.EXAMPLE
------- Example 1: Set updates to be installed at 3AM local time (default) ----------
    C:\PS> Set-WindowsUpdateConfig

------- Example 2: Set earlier install at 1AM local time ----------------------------
    C:\PS> Set-WindowsUpdateConfig -Early

.NOTES
    Author: Rod Hatley
#>
    param ([Switch] $Early,[Switch] $Late)

    # Check Admin Elevation Status
    if ((Get-AdminStatus) -ieq $false)
    {
        Write-Host "TERMINATING: This script needs to run from elevated PowerShell console." -ForegroundColor Red
        Return
    }
    
    if ($Early)
    {
        if($Early -eq $Late)
        {
            Write-Host "Conflicting Command Line Arguments used.  Cannot use -Early and -Late at the same time" -ForegroundColor Red
            Write-Host "No changes were made."
            Return
        }
    }

    $time = 3
    if ($Early)
    {
        $time = 1
    }

    if ($Late)
    {
        $time = 5
    }

    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "AlwaysAutoRebootAtScheduledTime" -Value 1 -Type Dword -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "AlwaysAutoRebootAtScheduledTimeMinutes" -Value 15 -Type Dword -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "DetectionFrequencyEnabled" -Value 1 -Type Dword -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "DetectionFrequency" -Value 12 -Type Dword -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoUpdate" -Value 0 -Type Dword -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "AUOptions" -Value 4 -Type Dword -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "ScheduledInstallDay" -Value 1 -Type Dword -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "ScheduledInstallTime" -Value $time -Type Dword -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "ScheduledInstallEveryWeek" -Value 1 -Type Dword -Force

    Write-Host "Windows Update Settings have been updated."
    Write-Host "This server will install updates every Sunday at $time AM local time"

}