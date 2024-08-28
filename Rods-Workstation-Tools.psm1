# Get Admin Status
function Get-AdminStatus 
{
    Return ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}


# Unpin Icons from Windows Task Bar
function UnPinFromTaskBar ([String] $name)
{
    $ErrorActionPreference = "SilentlyContinue"
    ((New-Object -Com Shell.Application).NameSpace('shell:::{4234d49b-0245-4df3-b780-3893943456e1}').Items() | Where-Object {$_.Name -eq $name}).Verbs() | Where-Object {$_.Name.replace('&','') -match 'Unpin from Taskbar'} | ForEach-Object {$_.DoIt()}
    $ErrorActionPreference = "Continue"
}

# Remove unwanted apps, supress error messages
function RemoveApp ([String] $name)
{
    $ErrorActionPreference = "SilentlyContinue"
    Get-AppxPackage $name | Remove-AppxPackage
    $ErrorActionPreference = "Continue"
}

# Download default Windows 11 Start Menu and Apply to current user
function UpdateStartMenu
{
    $StartMenuFile = "https://raw.githubusercontent.com/RodHatley/Rods-Tools/main/Resources/start2.bin"
 
    $WebClient = New-Object System.Net.WebClient 
    $WebClient.DownloadFile($StartMenuFile,"$env:UserProfile\AppData\Local\Packages\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\LocalState\start2.new") 

    Rename-Item "$env:UserProfile\AppData\Local\Packages\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\LocalState\start2.bin" "$env:UserProfile\AppData\Local\Packages\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\LocalState\start2.bak"
    Rename-Item "$env:UserProfile\AppData\Local\Packages\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\LocalState\start2.new" "$env:UserProfile\AppData\Local\Packages\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\LocalState\start2.bin"

    Stop-Process -Name StartMenuExperienceHost -Force
}


#############################
# Optimize-Win11
#############################
function Optimize-Win11
{
    <#
    .SYNOPSIS
    Optimizes the user and system settings on a new Windows 11 workstation
    .DESCRIPTION
    Removes applications that are not needed and tweaks some user and system settings to improve system
    performance and reliability.
    .NOTES
    Must be run as Admin as some settings are system wide.
    
    Attempts to update App Installer (WINGET) using WINGET.  This works in 24H2, but earlier versions of Windows may have to update App Installer manually.
	Remove Applications
		Personal / Consumer version of Microsoft Teams
		Gaming and Xbox and associates applications 
		Spotify
		Mixed Reality Portal
	Unpin from TaskBar
		TaskView
		Chat (Personal Teams)
		Microsoft Store
		Amazon.com
		MyHP
		HP Audio Control
		AI Meeting Manager
	Update Start Menu to show more pined applications and less Recommendations
	Optional - Update Start Menu (deletes existing and replaces with cleaner version)
	Sets default Terminal to Windows Terminal
	System Tray icons visible (not hidden
		Microsoft Teams (New and Classic)
		OneDrive
	Power Changes
		Disable Windows Fast Startup
		Disable Standby / Sleep / Hibernate on AC Power
    Disable Adobe Outlook Add-in from sending PDF as link using Adobe Cloud.
    #>
    
    param([Switch]$ClearStartMenu)
    
    Write-Host "Optimize Windows 11" -ForegroundColor Yellow
    Write-Host "v24.6.14" -ForegroundColor Yellow

    # Check Admin Elevation Status
    if ((Get-AdminStatus) -ieq $false)
    {
        Write-Host "TERMINATING: This script needs to run from elevated PowerShell console." -ForegroundColor Red
        Return
    }

    # Set Timezone to EST
    #Set-TimeZone -Id "Eastern Standard Time"

    # Update Winget if needed
    #Add-AppxPackage -RegisterByFamilyName -MainPackage Microsoft.DesktopAppInstaller_8wekyb3d8bbwe
    Write-Host "`nChecking for updates for the Microsoft App Installer (Winget)..."
    WINGET upgrade Microsoft.AppInstaller --accept-source-agreements


    # Uninstall Consumer (Personal) Teams from user's profile
    Write-Host "`nRemoving Personal Microsoft Teams and other consumer focused apps and games..."
    RemoveApp 'MicrosoftTeams'

    # Remove other unwanted Xbox apps
    RemoveApp "*xbox*"
    RemoveApp "gam"
    RemoveApp "Spotify*"
    winget uninstall xbox
    winget uninstall "Mixed Reality Portal"

    Write-Host "`nApplying Taskbar and Start Menu optimizations..."
    # Remove Taskview and Chat Icons from Taskbar
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowTaskViewButton" -Value 0 -Type Dword -Force
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarMn" -Value 0 -Type Dword -Force

    # Set Windows 11 to show more pins and less recommendations
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Start_Layout" -Value 1 -Type Dword -Force

    # Remove Microsoft Store Shortcut from Taskbar
    UnPinFromTaskBar 'Microsoft Store'
    UnPinFromTaskBar 'Amazon.com'
    UnPinFromTaskBar 'MyHP'
    UnPinFromTaskBar 'HP Audio Control'
    UnPinFromTaskBar "AI Meeting Manager"

    # Set Default Terminal Application to Windows Terminal
    if(!(Test-Path -Path "HKCU:Console\%%Startup"))
        {New-Item -Path "HKCU:Console\%%Startup"}
    New-ItemProperty -Path "HKCU:Console\%%Startup" -Name "DelegationConsole" -Value "{2EACA947-7F5F-4CFA-BA87-8F7FBEEFBE69}" -Type String -Force | Out-Null
    New-ItemProperty -Path "HKCU:Console\%%Startup" -Name "DelegationTerminal" -Value "{E12CFF52-A866-4C77-9A90-F570A7AA2C6B}" -Type String -Force | Out-Null

    Write-Host "`nUpdating System Tray to Show OneDrive and Teams icons (apps must be already running and logged in)..."
    # Set OneDrive Icon to always be visable in System Tray
    $key = Get-ChildItem -LiteralPath "hkcu:\Control Panel\NotifyIconSettings" | Get-ItemProperty | Where-Object { $_.ExecutablePath -like "*OneDrive.exe" }
    if ($key.PSPath) { Set-ItemProperty -Path $key.PSPath -Name "IsPromoted" -Value 1 -Force }

    # Set Teams Icon to always be visable in System Tray
    $key = Get-ChildItem -LiteralPath "hkcu:\Control Panel\NotifyIconSettings" | Get-ItemProperty | Where-Object { $_.ExecutablePath -like "*\Teams.exe" }
    if ($key.PSPath) { Set-ItemProperty -Path $key.PSPath -Name "IsPromoted" -Value 1 -Force }

    # Set New Teams Icon to always be visable in System Tray
    $key = Get-ChildItem -LiteralPath "hkcu:\Control Panel\NotifyIconSettings" | Get-ItemProperty | Where-Object { $_.ExecutablePath -like "*\ms-teams.exe" }
    if ($key.PSPath) { Set-ItemProperty -Path $key.PSPath -Name "IsPromoted" -Value 1 -Force }

    Write-Host "`nDisabling Windows Fast Startup and Set to never sleep on AC Power..."
    # Disable Windows Fast Startup
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power" -Name "HiberbootEnabled" -Value 0 -Type Dword -Force

    # Disable Sleep / Standby on AC Power
    powercfg.exe -X standby-timeout-ac 0
    powercfg.exe -X hibernate-timeout-ac 0

    Write-Host "`nApplying final optimziations..."
    # Disable Adobe Outlook Add-in send PDF as link
    reg add "HKCU\software\Adobe\Adobe Send for Microsoft Outlook\DC\Settings" /v "UploadMode" /t REG_DWORD /d 2 /f | Out-Null
    
    if ($ClearStartMenu)
    {
        Write-Host "`nClearing Start Menu..."
        UpdateStartMenu
    }

    Write-Host "`nOptimizations now complete." -ForegroundColor Yellow
}



###############################
# Entra ID PIN Disable / Enable
###############################
function Disable-EntraIdPIN 
{
    # Check Admin Elevation Status
    if ((Get-AdminStatus) -ieq $false)
    {
        Write-Host "TERMINATING: This script needs to run from elevated PowerShell console." -ForegroundColor Red
        Return
    }
        
    #Disable Entra ID PIN requirement
    $path = "HKLM:\SOFTWARE\Policies\Microsoft"
    $key = "PassportForWork"
    $name = "Enabled"
    $value = "0"
    
    New-Item -Path $path -Name $key -Force | Out-Null
    
    New-ItemProperty -Path $path\$key -Name $name -Value $value -PropertyType DWORD -Force | Out-Null
    
    #Delete existing pins
    $passportFolder = "C:\Windows\ServiceProfiles\LocalService\AppData\Local\Microsoft\Ngc"
    
    if(Test-Path -Path $passportFolder)
    {
        Takeown /f $passportFolder /r /d "Y" | Out-Null
        ICACLS $passportFolder /reset /T /C /L /Q | Out-Null
        
        Remove-Item -path $passportFolder -recurse -force | Out-Null
    }
    Write-Host "Entra ID PIN for system sign in is now disabled on this system."
}

function Enable-EntraIdPIN 
{
    # Check Admin Elevation Status
    if ((Get-AdminStatus) -ieq $false)
    {
        Write-Host "TERMINATING: This script needs to run from elevated PowerShell console." -ForegroundColor Red
        Return
    }

    $path = "HKLM:\SOFTWARE\Policies\Microsoft"
    $key = "PassportForWork"
    $name = "Enabled"
    $value = "1"
     
    New-Item -Path $path -Name $key -Force | Out-Null
     
    New-ItemProperty -Path $path\$key -Name $name -Value $value -PropertyType DWORD -Force | Out-Null
    
    Write-Host "Entra ID PIN for system sign in is now enabled on this system."
}

###############################
# Fast Startup Disable / Enable
###############################
function Disable-FastStartup
{
    # Check Admin Elevation Status
    if ((Get-AdminStatus) -ieq $false)
    {
        Write-Host "TERMINATING: This script needs to run from elevated PowerShell console." -ForegroundColor Red
        Return
    }

    #Disable Windows Fast Startup
    $path = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager"
    $key = "Power"
    $name = "HiberbootEnabled"
    $value = "0"
    New-ItemProperty -Path $path\$key -Name $name -Value $value -PropertyType DWORD -Force | Out-Null
    Write-Host "Windows Fast Startup is now Disabled."
}

function Enable-FastStartup
{
    # Check Admin Elevation Status
    if ((Get-AdminStatus) -ieq $false)
    {
        Write-Host "TERMINATING: This script needs to run from elevated PowerShell console." -ForegroundColor Red
        Return
    }
        
    #Enable Windows Fast Startup
    $path = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager"
    $key = "Power"
    $name = "HiberbootEnabled"
    $value = "1"
    New-ItemProperty -Path $path\$key -Name $name -Value $value -PropertyType DWORD -Force | Out-Null
    Write-Host "Windows Fast Startup is now Enabled."
}

###########################################
# Win11 Context Menu Style Disable / Enable
###########################################
function Disable-Win11ContextMenuStyle 
{
    reg add 'HKCU\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32' /f /ve | Out-Null
    Write-Host "Windows 11 Simple Context Menus are now DISABLED.  A restart of Windows Explorer may be required"    
}

function Enable-Win11ContextMenuStyle 
{
    reg delete 'HKCU\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32' /f | Out-Null
    Write-Host "Windows 11 Simple Context Menus are now ENABLED.  A restart of Windows Explorer may be required"    
}


###############################
# Wolf Security Uninstallation
###############################
function Uninstall-WolfSecurity 
{
    # Check Admin Elevation Status
    if ((Get-AdminStatus) -ieq $false)
    {
        Write-Host "TERMINATING: This script needs to run from elevated PowerShell console." -ForegroundColor Red
        Return
    }
    
    Write-Host "Uninstalling Wolf Security and related services..." -ForegroundColor Yellow

    winget uninstall "HP Wolf Security" --silent
    winget uninstall "HP Wolf Security - Console" --silent
    winget uninstall "HP Assess and Respond" --silent
    winget uninstall "HP Security Update Service" --silent
    winget uninstall "HP Sure Run" --silent
    winget uninstall "HP Sure Recover" --silent
    winget uninstall "HP Client Security Manager" --silent

    Write-Host "Script completed." -ForegroundColor Yellow
    Write-Host "If there were errors there are two common issues:" 
    Write-Host "1) Microsoft App Installer (WINGET) needs to be updated"
    Write-Host "2) Wolf Security is in an update state and is installed twice. Let the update finish and reboot and try again."
}

##################################
# Win11 Upgrade on Unsupported HW
##################################
function Enable-Win11onUnsupportedHW
{
    reg add 'HKLM\SYSTEM\Setup\MoSetup' /v 'AllowUpgradesWithUnsupportedTPMOrCPU' /t REG_DWORD /d 1 /f
    reg add 'HKLM\SYSTEM\Setup\LabConfig' /f  /v 'BypassSecureBootCheck' /t REG_DWORD /d 1
    reg add 'HKLM\SYSTEM\Setup\LabConfig' /f  /v 'BypassTPMCheck' /t REG_DWORD /d 1
    Write-Host "Ready for upgrade to Windows 11"
}

