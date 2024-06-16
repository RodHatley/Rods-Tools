
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

