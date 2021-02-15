# elevate instance
if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Start-Process PowerShell -Verb RunAs "-NoProfile -ExecutionPolicy Bypass -Command `"cd '$pwd'; & '$PSCommandPath';`"";
    exit;
}

# install chocolatey & enable environment refresh
Write-Host "Installing chocolatey..."
iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
$env:chocolateyInstall = Convert-Path "$((Get-Command choco).Path)\..\.."
Import-Module "$env:chocolateyInstall\helpers\chocolateyProfile.psm1"

# refresh env
Write-Host "Refreshing environment..."
refreshenv

# install git using chocolatey
Write-Host "Installing Git..."
choco install -y  git

# refresh env
Write-Host "Refreshing environment..."
refreshenv

# move to scripts dir
cd scripts

# begin cloning repositories
Write-Host "Begin cloning repositories..."

# repo win10script handling
Write-Host "Checking if win10script repository already exists..."
if(Test-Path -Path 'win10script'){
	Write-Host "Deleting existing win10script repository..."
	del /f /s /q win10script 1>nul
	rmdir /s /q win10script
}
git clone https://github.com/ChrisTitusTech/win10script

Write-Host "Checking if Windows10Debloater repository already exists..."
if(Test-Path -Path 'Windows10Debloater'){
	Write-Host "Deleting existing Windows10Debloater repository..."
	del /f /s /q Windows10Debloater 1>nul
	rmdir /s /q Windows10Debloater
}
git clone https://github.com/Sycnex/Windows10Debloater

Write-Host "Checking if Debloat-Windows-10 repository already exists..."
if(Test-Path -Path 'Debloat-Windows-10'){
	Write-Host "Deleting existing Debloat-Windows-10 repository..."
	del /f /s /q Debloat-Windows-10 1>nul
	rmdir /s /q Debloat-Windows-10
}
git clone https://github.com/W4RH4WK/Debloat-Windows-10

# move to root, unblock scripts and set execution policy
cd ..
Write-Host "Setting execution policy & unblocking files..."
Set-ExecutionPolicy Unrestricted -Scope CurrentUser
ls -Recurse *.ps*1 | Unblock-File

# move to software dir
cd software

# download software
Write-Host "Begin downloading software..."
Write-Host "Downloading latest QuickCpu..."
Invoke-WebRequest 'https://coderbag.com/assets/downloads/cpm/currentversion/QuickCpuSetup64.zip' -OutFile 'QuickCpuSetup64.zip'
Write-Host "Downloading latest TCPOptimizer..."
Invoke-WebRequest 'https://www.speedguide.net/files/TCPOptimizer.exe' -OutFile 'TCPOptimizer.exe'
Write-Host "Downloading DDU v18.0.3.6..."
Invoke-WebRequest 'https://www.wagnardsoft.com/DDU/download/DDU v18.0.3.6.exe' -OutFile 'DDU v18.0.3.6.exe'
Write-Host "Downloading ISLC v1.0.2.2..."
Invoke-WebRequest 'https://www.wagnardsoft.com/ISLC/ISLC v1.0.2.2.exe' -OutFile 'ISLC v1.0.2.2.exe'
Write-Host "Downloading Privatezilla 0.43.0..."
Invoke-WebRequest 'https://github.com/builtbybel/privatezilla/releases/download/0.43.0/privatezilla.zip' -OutFile 'privatezilla.zip'

# cleanup
Write-Host "Work done! Cleaning up..."
# define useful funcs
function Remove-Choco {
	Remove-Item -Recurse -Force "$env:ChocolateyInstall"
	[System.Text.RegularExpressions.Regex]::Replace([Microsoft.Win32.Registry]::CurrentUser.OpenSubKey('Environment').GetValue('PATH', '', [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames).ToString(), [System.Text.RegularExpressions.Regex]::Escape("$env:ChocolateyInstall\bin") + '(?>;)?', '', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase) | %{[System.Environment]::SetEnvironmentVariable('PATH', $_, 'User')}
	[System.Text.RegularExpressions.Regex]::Replace([Microsoft.Win32.Registry]::LocalMachine.OpenSubKey('SYSTEM\CurrentControlSet\Control\Session Manager\Environment\').GetValue('PATH', '', [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames).ToString(),  [System.Text.RegularExpressions.Regex]::Escape("$env:ChocolateyInstall\bin") + '(?>;)?', '', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase) | %{[System.Environment]::SetEnvironmentVariable('PATH', $_, 'Machine')}
	if ($env:ChocolateyBinRoot -ne '' -and $env:ChocolateyBinRoot -ne $null) { Remove-Item -Recurse -Force "$env:ChocolateyBinRoot" }
	if ($env:ChocolateyToolsRoot -ne '' -and $env:ChocolateyToolsRoot -ne $null) { Remove-Item -Recurse -Force "$env:ChocolateyToolsRoot" }
	[System.Environment]::SetEnvironmentVariable("ChocolateyBinRoot", $null, 'User')
	[System.Environment]::SetEnvironmentVariable("ChocolateyToolsLocation", $null, 'User')
}
function Remove-Git {
	choco uninstall -y git
}

# get user input
$title = "Cleanup Options"
$message = "Do you wish to remove Chocolatey and/or Git? If you don't know then select Chocolatey."

$choco = New-Object System.Management.Automation.Host.ChoiceDescription "&Chocolatey"
$git = New-Object System.Management.Automation.Host.ChoiceDescription "&Git"
$none = New-Object System.Management.Automation.Host.ChoiceDescription "&No"
$options = [System.Management.Automation.Host.ChoiceDescription[]]($choco, $git, $none)

$result = $host.ui.PromptForChoice($title, $message, $options, 0) 

switch ($result)
{
    0 {
		Remove-Git
	    Remove-Choco
	}
    1 {
		Remove-Git
	}
    2 {
		"Not removing anything."
	}
}

# exit
exit