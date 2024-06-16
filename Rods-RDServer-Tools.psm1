
function Get-AdminStatus {
    Return ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-RDGWLogons
{
     # Show RD Gateway Connection Log (Successful Connections)
    Get-WinEvent -FilterHashTable @{LogName='Microsoft-Windows-TerminalServices-Gateway/Operational';ID='302'}
}


function Enable-OfficeSharedActivation 
{
    # Check Admin Elevation Status
    if ((Get-AdminStatus) -ieq $false)
    {
        Write-Host "TERMINATING: This script needs to run from elevated PowerShell console." -ForegroundColor Red
        Return
    }

    Set-ItemProperty -Path "HKLM:\Software\Microsoft\Office\ClickToRun\Configuration" -Name "SharedComputerLicensing" -Value 1 -Type String -Force
    
    Write-Host "Microsoft Offce 365 Apps Shared Computer Activation is now enabled on this system."    
}
 








###############################
# RD Web Bad Actors
###############################
function Get-RDWebBadActorIPs 
{
    # Scan latest IIS Log (Daily) for multiple failed logon attempts that exceed threshold

    # Command Line Paramters
    param([string]$Firewall,[int]$Days,[switch]$Clip,[switch]$EventLog,[int]$LogonAttempts)

    # Debugging output
    $debug = 0

    Write-Host "Get-RDWebBadActorIPs v24.5.5" -ForegroundColor Yellow

    # Check Admin Elevation Status
    if ((Get-AdminStatus) -ieq $false)
    {
        Write-Host "TERMINATING: This script needs to run from elevated PowerShell console." -ForegroundColor Red
        Return
    }
   
    # If no days specified in arguments, set to 2 (today and yesterday)
    if($Days -eq 0){$Days = 2}

    # If no LogonAttempts value set in arguments, set the number of of logon attempts to 20
    if ($LogonAttempts -eq 0) {$LogonAttempts = 20}

    # Count the number of failed logons in the Log
    $Instances = 0

    # Set the path to the log folder
    $logFolderPath = "C:\inetpub\logs\LogFiles\W3SVC1"  
    
    Write-Host "Starting scan of $Days IIS log files located at $logFolderPath"
    Write-Host "Failed Logon Attempts threshold set to $LogonAttempts"

    # Get the latest log file in the folder
    $latestLogFile = Get-ChildItem -Path $logFolderPath -Filter "*.log" | Sort-Object LastWriteTime -Descending | Select-Object -First $Days

    # Search for lines with HTTP code 200 and 'POST' method in the log files
    $ipCount = @{}
    Get-Content -Path $latestLogFile.FullName | Where-Object {
        # Only process lines with HTTP code 200 and 'POST' method
        $_ -match 'POST' -and $_ -match ' 200 ' -and [DateTime]::ParseExact($_.Substring(0, 19), 'yyyy-MM-dd HH:mm:ss', $null)
    } | ForEach-Object {
        # Extract timestamp and IP address from each matching line
        $Instances++
        $line = $_
        $ipAddress = ($line -split ' ')[-7]
        # IP Filtering
        $regexPattern = "^(?:10|127|172\.(?:1[6-9]|2[0-9]|3[01])|192\.168)\..*"
        # Check if IP is private or public
        if ($ipaddress -match $regexPattern) {
                # Debugging output
                if ($debug -eq 1) {Write-Host "Skipping $ipaddress"}
            } else {
                # Count the occurrences of the IP address
                if ($ipCount.containskey($ipaddress)) {
                    $ipCount[$ipaddress]++
                } else {
                    $ipCount[$ipaddress] = 1
                }
            }
    }

    Write-Host "Found $Instances failed logons from the selected log files"

    $BadIPAddresses = @()

    # Send IPs that occur more than a defined number of times
    $ipCount.getenumerator() | Where-Object { $_.value -gt $LogonAttempts } | ForEach-Object {
        $ipaddress = $_.name
        $BadIPAddresses += $_.name
        if ($debug -eq 1) {Write-Host "`tIPv4: $ipaddress"}
        # Debugging output
        #if ($debug -eq 1) {Write-Host "Many failed logons from: $ipaddress"}
    }


    # Determine if UPDATE Firewall arg was used, if so
    if ($Firewall -ieq "update")
        {
        Write-Host "Firewall will be updated with new IPs found in the log"
        $RuleExists = Get-NetFirewallRule -DisplayName "RDWeb Bad Actors - Blocked IP addresss" 2> $null
        if ($null -eq $RuleExists)
            {
                Write-Host "Existing Firewall Rule does not exist.  Creating new one..."
                New-NetFirewallRule -DisplayName "RDWeb Bad Actors - Blocked IP addresss" -Direction Inbound -LocalPort Any -Protocol Any -Action Block -RemoteAddress $BadIPAddresses
                $FWCountAfter = $BadIPAddresses.Count
                Write-Host "Firewall Rule added with $FWCountAfter IPs blocked.`n"
                if ($Clip)
                {
                    Write-Host "`nCopying all blocked IPs to Windows Clipboard"
                    $BadIPAddresses | clip.exe  
                }

                if ($EventLog)
                {
                    New-EventLog -Source "Aktion" -LogName Application 2> $null
                    Write-EventLog -LogName "Application" -Source "Aktion" -EventID 1001 -EntryType Information -Message "$Instances failed logons from the selected log files`n`nFirewall Rule added with $FWCountAfter IPs blocked."
                }
            
            } else {
                Write-Host "Updating existing Firewall Rule..."
                $ExistingBlockedIPs = (Get-NetFirewallRule -DisplayName "RDWeb Bad Actors - Blocked IP addresss" | Get-NetFirewallAddressFilter ).RemoteAddress
                $UpdatedBlockedIPs = $BadIPAddresses + $ExistingBlockedIPs
                $UpdatedBlockedIPs = $UpdatedBlockedIPs | Select-Object -Unique | Sort-Object
                Set-NetFirewallRule -DisplayName "RDWeb Bad Actors - Blocked IP addresss" -RemoteAddress $UpdatedBlockedIPs
                $FWCountBefore = $ExistingBlockedIPs.Count
                $FWCountAfter = $UpdatedBlockedIPs.Count
                $FWDelta = $FWCountAfter - $FWCountBefore
                Write-Host "`nOriginal number of IPs Blocked: $FWCountBefore"
                Write-Host "New Bad Actor IPs found this run: $FWDelta"
                Write-Host "Total Number of IPs now being blocked: $FWCountAfter"
                
                if ($Clip)
                {
                    Write-Host "`nCopying all blocked IPs to Windows Clipboard"
                    $UpdatedBlockedIPs | clip.exe
                }

                if ($EventLog)
                {
                    New-EventLog -Source "Aktion" -LogName Application 2> $null
                    $MessageDetails = "$Instances failed logons from the selected log files`n`nOriginal number of IPs Blocked: $FWCountBefore`nNew Bad Actor IPs found this run: $FWDelta`nTotal Number of IPs now being blocked: $FWCountAfter"
                    Write-EventLog -LogName "Application" -Source "Aktion" -EventID 1001 -EntryType Information -Message $MessageDetails  
                }

                Write-Host "`nOperation complete."
            }
            
        }
        else {Write-Host "Firewall was not updated since -Firewall update parameter was not used`n"}
}
function Import-PublicBlackListIPs {
    
    Write-Host "Import-PublicBlackListIPs v24.5.5" -ForegroundColor Yellow

    # Check Admin Elevation Status
    if ((Get-AdminStatus) -ieq $false)
    {
        Write-Host "TERMINATING: This script needs to run from elevated PowerShell console." -ForegroundColor Red
        Return
    }

    # https://binarydefense.com/banlist.txt
    # https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt
    # https://rules.emergingthreats.net/blockrules/compromised-ips.txt
    If(!(Test-Path -Path "C:\Temp"))
    {
        New-Item -Path "C:\Temp" -ItemType Directory | Out-Null
    }

    Write-Host "Downloading Blocklist Files from Internet..."
    Invoke-WebRequest "https://binarydefense.com/banlist.txt" -outfile "c:\temp\banlist.txt"
    Invoke-WebRequest "https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt" -outfile "c:\temp\emerging-Block-IPs.txt"
    Invoke-WebRequest "https://rules.emergingthreats.net/blockrules/compromised-ips.txt" -outfile "c:\temp\compromised-ips.txt"


    $file1 = Get-Content -Path 'c:\temp\banlist.txt'
    $file1 = $file1 | Where-Object { $_ -match '\S' -and $_ -notmatch '^#' }
    
    $file2 = Get-Content -Path 'c:\temp\compromised-ips.txt'
    $file2 = $file2 | Where-Object { $_ -match '\S' -and $_ -notmatch '^#' }
    
    $file3 = Get-Content -Path 'c:\temp\emerging-block-ips.txt'
    $file3 = $file3 | Where-Object { $_ -match '\S' -and $_ -notmatch '^#' }
    
    $PublicBlockedIPs = $file1 + $file2 + $file3
    
    $PublicBlockedIPs = $PublicBlockedIPs | Select-Object -Unique | Sort-Object -Unique
    
    Write-Host "Updating existing Firewall Rule..."
    $ExistingBlockedIPs = (Get-NetFirewallRule -DisplayName "RDWeb Bad Actors - Blocked IP addresss" | Get-NetFirewallAddressFilter ).RemoteAddress
    $UpdatedBlockedIPs = $PublicBlockedIPs + $ExistingBlockedIPs
    $UpdatedBlockedIPs = $UpdatedBlockedIPs | Select-Object -Unique | Sort-Object -Unique
    Set-NetFirewallRule -DisplayName "RDWeb Bad Actors - Blocked IP addresss" -RemoteAddress $UpdatedBlockedIPs
    $FWCountBefore = $ExistingBlockedIPs.Count
    $FWCountAfter = $UpdatedBlockedIPs.Count
    $FWDelta = $FWCountAfter - $FWCountBefore
    Write-Host "`nOriginal number of IPs Blocked by Firewall: $FWCountBefore"
    Write-Host "New unique IPs imported from public blacklists: $FWDelta"
    Write-Host "Total Number of IPs now being blocked by Firewall: $FWCountAfter"
    
}

function Export-BlockedIPs {
    # Check Admin Elevation Status
    if ((Get-AdminStatus) -ieq $false)
    {
       Write-Host "TERMINATING: This script needs to run from elevated PowerShell console." -ForegroundColor Red
       Return
    } 

    $ExistingBlockedIPs = (Get-NetFirewallRule -DisplayName "RDWeb Bad Actors - Blocked IP addresss" | Get-NetFirewallAddressFilter ).RemoteAddress

    $ExistingBlockedIPs | Out-File "BlockedIPs.txt"

}
