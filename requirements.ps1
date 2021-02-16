# elevate instance
if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Start-Process PowerShell -Verb RunAs "-NoProfile -ExecutionPolicy Bypass -Command `"cd '$pwd'; & '$PSCommandPath';`"";
    exit;
}

# install chocolatey & enable environment refresh
Write-Host 'Installing chocolatey...'
iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
$env:chocolateyInstall = Convert-Path "$((Get-Command choco).Path)\..\.."
Import-Module "$env:chocolateyInstall\helpers\chocolateyProfile.psm1"

# refresh env
Write-Host 'Refreshing environment...'
refreshenv

# install git using chocolatey
Write-Host 'Installing Git...'
choco install -y  git

# refresh env
Write-Host 'Refreshing environment...'
refreshenv

# move to scripts dir
cd scripts

# begin cloning repositories
Write-Host 'Begin cloning repositories...'

# repo win10script handling
Write-Host 'Checking if win10script repository already exists...'
if(Test-Path -Path 'win10script'){
	Write-Host 'Deleting existing win10script repository...'
	Remove-Item -Path 'win10script' -Recurse -Force
}
git clone https://github.com/ChrisTitusTech/win10script
Write-Host 'Cleaning up repository...'
Remove-Item -Path 'win10script\.git' -Recurse -Force
Remove-Item -Path 'win10script\*.png'
Remove-Item -Path 'win10script\README.md'

Write-Host 'Checking if Windows10Debloater repository already exists...'
if(Test-Path -Path 'Windows10Debloater'){
	Write-Host 'Deleting existing Windows10Debloater repository...'
	Remove-Item -Path 'Windows10Debloater' -Recurse -Force
}
git clone https://github.com/Sycnex/Windows10Debloater
Write-Host 'Cleaning up repository...'
Remove-Item -Path 'Windows10Debloater\.git' -Recurse -Force
Remove-Item -Path 'Windows10Debloater\Individual Scripts' -Recurse
Remove-Item -Path 'Windows10Debloater\LICENSE'
Remove-Item -Path 'Windows10Debloater\README.md'
Remove-Item -Path 'Windows10Debloater\Windows10SysPrepDebloater.ps1'

Write-Host 'Checking if Debloat-Windows-10 repository already exists...'
if(Test-Path -Path 'Debloat-Windows-10'){
	Write-Host 'Deleting existing Debloat-Windows-10 repository...'
	Remove-Item -Path 'Debloat-Windows-10' -Recurse -Force
}
git clone https://github.com/W4RH4WK/Debloat-Windows-10
Write-Host 'Cleaning up repository...'
Remove-Item -Path 'Debloat-Windows-10\.git' -Recurse -Force
Remove-Item -Path 'Debloat-Windows-10\.gitattributes'
Remove-Item -Path 'Debloat-Windows-10\LICENSE'
Remove-Item -Path 'Debloat-Windows-10\README.md'
Remove-Item -Path 'Debloat-Windows-10\utils\start_vert.png'
Remove-Item -Path 'Debloat-Windows-10\scripts\disable-windows-defender.ps1'
Remove-Item -Path 'Debloat-Windows-10\utils\dark-theme.reg'
Remove-Item -Path 'Debloat-Windows-10\utils\boot-advanced-startup.bat'
Remove-Item -Path 'Debloat-Windows-10\utils\install-basic-software.ps1'
# ssd choice
$ssdTitle = 'SSD Choice'
$ssdMessage = "Do you use a SSD (Solid-State Drive) as your boot drive? If you don't know, select No."
$ssdYes = New-Object System.Management.Automation.Host.ChoiceDescription "&Yes"
$ssdNo = New-Object System.Management.Automation.Host.ChoiceDescription "&No"
$ssdOptions = [System.Management.Automation.Host.ChoiceDescription[]]($ssdYes, $ssdNo)
$ssdResult = $host.ui.PromptForChoice($ssdTitle, $ssdMessage, $ssdOptions, 1) 
switch ($ssdResult)
{
    0 {
		Write-Host 'SSD selected...'
	}
    1 {
		Write-Host 'NOT SSD selected...'
		Remove-Item -Path 'Debloat-Windows-10\utils\ssd-tune.ps1'
	}
}

# unblock scripts, move to root
Write-Host 'Unblocking files...'
ls -Recurse *.ps*1 | Unblock-File
cd ..

# move to software dir
cd software

# download software
# QuickCpu
Write-Host 'Begin downloading software...'
Write-Host 'Downloading latest QuickCpu...'
Invoke-WebRequest 'https://coderbag.com/assets/downloads/cpm/currentversion/QuickCpuSetup64.zip' -OutFile 'QuickCpuSetup64.zip'
Write-Host 'Checking if QuickCpuSetup64 folder already exists...'
if(Test-Path -Path 'QuickCpuSetup64'){
	Write-Host 'Deleting existing QuickCpuSetup64 folder...'
	Remove-Item -Path 'QuickCpuSetup64' -Recurse -Force
}
Write-Host 'Extracting...'
Expand-Archive -Path 'QuickCpuSetup64.zip' -DestinationPath 'QuickCpuSetup64'
Remove-Item -Path 'QuickCpuSetup64.zip'

# TCPOptimizer
Write-Host 'Downloading latest TCPOptimizer...'
Invoke-WebRequest 'https://www.speedguide.net/files/TCPOptimizer.exe' -OutFile 'TCPOptimizer.exe'

# DDU
Write-Host 'Downloading DDU v18.0.3.6...'
Invoke-WebRequest 'https://www.wagnardsoft.com/DDU/download/DDU v18.0.3.6.exe' -OutFile 'DDU v18.0.3.6.exe'
Write-Host 'Checking if DDU v18.0.3.6 folder already exists...'
if(Test-Path -Path 'DDU v18.0.3.6'){
	Write-Host 'Deleting existing DDU v18.0.3.6 folder...'
	Remove-Item -Path 'DDU v18.0.3.6' -Recurse -Force
}
Write-Host 'Extracting...'
.\'DDU v18.0.3.6.exe' -y -gm2 -InstallPath='DDU v18.0.3.6'

# ISLC
Write-Host 'Downloading ISLC v1.0.2.2...'
Invoke-WebRequest 'https://www.wagnardsoft.com/ISLC/ISLC v1.0.2.2.exe' -OutFile 'ISLC v1.0.2.2.exe'
Write-Host 'Checking if ISLC v1.0.2.2 folder already exists...'
if(Test-Path -Path 'ISLC v1.0.2.2'){
	Write-Host 'Deleting existing ISLC v1.0.2.2 folder...'
	Remove-Item -Path 'ISLC v1.0.2.2' -Recurse -Force
}
Write-Host 'Extracting...'
.\'ISLC v1.0.2.2.exe' -y -gm2 -InstallPath='ISLC v1.0.2.2'

# Privatezilla
Write-Host 'Downloading Privatezilla 0.43.0...'
Invoke-WebRequest 'https://github.com/builtbybel/privatezilla/releases/download/0.43.0/privatezilla.zip' -OutFile 'privatezilla.zip'
Write-Host 'Checking if privatezilla folder already exists...'
if(Test-Path -Path 'privatezilla'){
	Write-Host 'Deleting existing privatezilla folder...'
	Remove-Item -Path 'privatezilla' -Recurse -Force
}
Write-Host 'Extracting...'
Expand-Archive -Path 'privatezilla.zip' -DestinationPath 'privatezilla'
Remove-Item -Path 'privatezilla.zip'

# cleanup
cd ..
Write-Host 'Work done! Cleaning up...'
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
Remove-Item -Path "software\ISLC v1.0.2.2.exe"
Remove-Item -Path "software\DDU v18.0.3.6.exe"

# cleanup choice
$cleanupTitle = 'Cleanup Options'
$cleanupMessage = "Do you wish to remove Chocolatey and/or Git? If you don't know then select Chocolatey."
$cleanupChoco = New-Object System.Management.Automation.Host.ChoiceDescription "&Chocolatey"
$cleanupGit = New-Object System.Management.Automation.Host.ChoiceDescription "&Git"
$cleanupNone = New-Object System.Management.Automation.Host.ChoiceDescription "&No"
$cleanupOptions = [System.Management.Automation.Host.ChoiceDescription[]]($cleanupChoco, $cleanupGit, $cleanupNone)
$cleanupResult = $host.ui.PromptForChoice($cleanupTitle, $cleanupMessage, $cleanupOptions, 0) 
switch ($cleanupResult)
{
    0 {
		Write-Host 'Removing Git...'
		Remove-Git
		Write-Host 'Removing Chocolatey...'
	    Remove-Choco
	}
    1 {
		Write-Host 'Removing Git...'
		Remove-Git
	}
    2 {
		'Not removing anything.'
	}
}

# exit
Write-Host 'Exiting...'
exit