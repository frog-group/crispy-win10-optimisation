# elevate instance
    if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) { Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs; exit }

# start logging this script (mainly for debugging)
    Start-Transcript -Path "$PSScriptRoot\Optimise.log"

# add win security exclusion
    Write-Host "Adding script dir as temporary exclusion in Windows Security..."
    Add-MpPreference -ExclusionPath $PSScriptRoot

#load stuff
    Write-Host "Setting up..."
    #for yes/no prompt
    [System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms")
    
    #load custom functions for this script
    Import-Module "$PSScriptRoot\CoreModule.psm1"

#make restore point
    Write-Host "Making a restore point..."
    Enable-ComputerRestore -Drive "C:\"
    Checkpoint-Computer -Description "pre-optimisations" -RestorePointType "MODIFY_SETTINGS"

<#software download
    $DownloadLinks = @{
        'QuickCpuSetup64.zip' = 'https://coderbag.com/assets/downloads/cpm/currentversion/QuickCpuSetup64.zip'
        'TCPOptimizer.exe' = 'https://www.speedguide.net/files/TCPOptimizer.exe'
        'DDU v18.0.4.5.exe' = 'https://www.wagnardsoft.com/DDU/download/DDU v18.0.4.5.exe'
        'ISLC v1.0.2.6.exe' = 'https://www.wagnardsoft.com/ISLC/ISLC v1.0.2.6.exe'
        'privatezilla.zip' = 'https://github.com/builtbybel/privatezilla/releases/download/0.50.0/privatezilla.zip'
        'OOSU10.exe' = 'https://dl5.oo-software.com/files/ooshutup10/OOSU10.exe'
        'ooshutup10.cfg' = 'https://raw.githubusercontent.com/ChrisTitusTech/win10script/master/ooshutup10.cfg'
    }#>

# hosts file
    $WinHostsFile = "$Env:SystemRoot\System32\drivers\etc\hosts"
    $TempHostsFile = "$PSScriptRoot\hosts"
    $WinTelHosts = "$PSScriptRoot\TelemetryHosts"
    $ExistingHosts = "$PSScriptRoot\ExistingHosts"
    $BlackHosts = "$PSScriptRoot\BlackHosts"
    $CombinedHosts = "$PSScriptRoot\CombinedHosts"

    #add exclusion for the windows hosts file
    Add-MpPreference -ExclusionPath $WinHostsFile

    Write-Host "Saving existing hosts file..."
    Copy-Item -Path $WinHostsFile -Destination $ExistingHosts

    Write-Host "Downloading StevenBlack hosts..."
    Start-BitsTransfer -Source "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/fakenews-gambling-porn-social/hosts" -Destination $BlackHosts

    #process the host files into one combined file
    @($BlackHosts,$WinTelHosts,$ExistingHosts) | Convert-HostsFile

    <#$WindowsHostsFile = "$Env:SystemRoot\System32\drivers\etc\hosts"
    $TempHostsFile = "$PSScriptRoot\hosts"
    $TelemetryHosts = "$PSScriptRoot\TelemetryHosts"
    $BlackHosts = "$PSScriptRoot\BlackHosts"
    # add AV exclusion 
    Write-Host "Adding Windows Security exclusion to hosts file to prevent Windows from blocking this"
    Add-MpPreference -ExclusionPath $WindowsHostsFile
    #save current hosts file
    Write-Host "Saving current hosts file to temporary hosts file"
    Copy-Item -Path $WindowsHostsFile -Destination $TempHostsFile
    #download Steven Black hosts
    Write-Host "Downloading StevenBlack hosts file"
    Start-BitsTransfer -Source "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/fakenews-gambling-porn-social/hosts" -Destination $BlackHosts

    # ask user if they want to keep the contents of their host file
    $OverwriteHosts = [System.Windows.Forms.MessageBox]::Show('Do you wish to overwrite your existing hosts file? If you do not know what that means, click "Yes".' , "Info" , 4)
    if ($OverwriteHosts -eq 'Yes') {
        #clear hosts file
        Remove-Item -Path $TempHostsFile
        #ask if they want steven black hosts
        $UseStevenHosts = [System.Windows.Forms.MessageBox]::Show('Do you wish to use the Steven Black hosts file? If you do not know what that means, click "No".' , "Info" , 4)
        if ($UseStevenHosts -eq 'Yes') {
            Write-Host "Downloading StevenBlack hosts file and overwriting temporary file"
            # minimal: https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts
            # maximal: https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/fakenews-gambling-porn-social/hosts
            Start-BitsTransfer -Source "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/fakenews-gambling-porn-social/hosts" -Destination $TempHostsFile
        }
    }
    # add win telemetry addresses to temp hosts file
    Write-Host "Appending extra addresses to temporary hosts file"
    "`n# win10-optimisation" | Add-Content -Passthru $TempHostsFile
    foreach ($Domain in Get-Content $TelemetryHosts) {
        if (-Not (Select-String -Path $TempHostsFile -Pattern $Domain)) {
            "0.0.0.0 $Domain" | Add-Content -Passthru $TempHostsFile
        }
    }
    # replace real hosts file with new temp one
    Write-Host "Replacing existing hosts file with temporary one"
    Move-Item -Path $TempHostsFile -Destination $WindowsHostsFile -Force#>

# windows firewall
    $TelemetryFirewall = Get-Content "$PSScriptRoot\TelemetryFirewall"
    Write-Output "Re-adding firewall rules to block Windows telemetry IPs..."
    #delete existing rules from previous uses of this script
    Remove-NetFirewallRule -DisplayName "win10-optimisation Outbound" -ErrorAction SilentlyContinue
    Remove-NetFirewallRule -DisplayName "win10-optimisation Inbound" -ErrorAction SilentlyContinue
    #add the rules using the TelemetryFirewall file
    New-NetFirewallRule -DisplayName "win10-optimisation Outbound" -Direction Outbound -Action Block -RemoteAddress ([string[]]$TelemetryFirewall)
    New-NetFirewallRule -DisplayName "win10-optimisation Inbound" -Direction Inbound -Action Block -RemoteAddress ([string[]]$TelemetryFirewall)

<# services optimisation
    # servives to disable
    $ServicesDisable = @(
    )
    foreach ($Service in $ServicesDisable) {
        Write-Output "Trying to disable and stop $Service"
        Get-Service $Service -ErrorAction SilentlyContinue | Set-Service -StartupType Disabled -PassThru | Stop-Service -WarningAction SilentlyContinue
    }
    # services to set to manual
    #>

# script cleanup
    #remove the temp exclusion for the script folder
    Write-Host "Removing the temporary Windows Security exclusion..."
    Remove-MpPreference -ExclusionPath $PSScriptRoot
    #stop the log
    Stop-Transcript