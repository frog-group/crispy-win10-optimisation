# elevate instance
    if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) { Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs; exit }

# start logging this script (mainly for debugging)
    Start-Transcript -Path "$PSScriptRoot\optimise.log"

# add win security exclusion
    Write-Host "Adding temporary exclusion to Windows Security for the script folder to prevent errors"
    Add-MpPreference -ExclusionPath $PSScriptRoot

#load stuff
    #for yes/no prompt
    [System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms")
    
    #Replacement for 'force-mkdir' to uphold PowerShell conventions. Thanks to raydric, this function should be used instead of 'mkdir -force'. Because 'mkdir -force' doesn't always work well with registry operations.
    <#
    function New-FolderForced {
        [CmdletBinding(SupportsShouldProcess = $True)]
        param (
		    [Parameter(Position = 0, Mandatory, ValueFromPipeline, ValueFromPi pelineByPropertyName)]
		    [string]
            $Path
        )

        process {
            if (-not (Test-Path $Path)) {
                Write-Verbose "-- Creating full path to:  $Path"
                New-Item -Path $Path -ItemType Directory -Force
            }
        }
    }#>

#make restore point
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
    $WindowsHostsFile = "$Env:SystemRoot\System32\drivers\etc\hosts"
    $TempHostsFile = "$PSScriptRoot\hosts"
    $TelemetryHosts = "$PSScriptRoot\TelemetryHosts"
    # add AV exclusion 
    Write-Host "Adding Windows Security exclusion to hosts file to prevent Windows from blocking this"
    Add-MpPreference -ExclusionPath $WindowsHostsFile
    #save current hosts file
    Write-Host "Saving current hosts file to temporary hosts file"
    Copy-Item -Path $WindowsHostsFile -Destination $TempHostsFile
    # ask user if they want to keep the contents of their host file
    $OverwriteHosts = [System.Windows.Forms.MessageBox]::Show('Do you wish to overwrite your existing hosts file? If you do not know what that means, click "Yes".' , "Info" , 4)
    if ($OverwriteHosts -eq 'Yes') {
        #clear hosts file
        Remove-Item -Path $TempHostsFile
        #ask if they want steven black hosts
        $UseStevenHosts = [System.Windows.Forms.MessageBox]::Show('Do you wish to download and use the Steven Black hosts file? If you do not know what that means, click "No".' , "Info" , 4)
        if ($UseStevenHosts -eq 'Yes') {
            Write-Host "Downloading StevenBlack hosts file and overwriting temporary file"
            # minimal: https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts
            # maximal: https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/fakenews-gambling-porn-social/hosts
            Start-BitsTransfer -Source "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts" -Destination $TempHostsFile
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
    Move-Item -Path $TempHostsFile -Destination $WindowsHostsFile -Force

# windows firewall
    $TelemetryFirewall = Get-Content "$PSScriptRoot\TelemetryFirewall"
    Write-Output "Adding telemetry ips to firewall or updating existing ones from this repo"
    Remove-NetFirewallRule -DisplayName "win10-optimisation Outbound" -ErrorAction SilentlyContinue
    Remove-NetFirewallRule -DisplayName "win10-optimisation Inbound" -ErrorAction SilentlyContinue
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
    Write-Host "Removing the temporary Windows Security exclusion"
    Remove-MpPreference -ExclusionPath $PSScriptRoot
    #stop the log
    Stop-Transcript