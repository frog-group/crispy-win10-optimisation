# elevate instance
if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Start-Process PowerShell -Verb RunAs "-NoProfile -ExecutionPolicy Bypass -Command `"cd '$pwd'; & '$PSCommandPath';`"";
    exit;
}

# install chocolatey for greater automation
Write-Host "Installing chocolatey..."
iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
Write-Host "Done!"

# install git using chocolatey
Write-Host "Installing Git..."
choco install -y  git
Write-Host "Done!"

# enable env refresh w/o creating a new instance then refresh
Write-Host "Refreshing environment..."
$env:chocolateyInstall = Convert-Path "$((Get-Command choco).Path)\..\.."
Import-Module "$env:chocolateyInstall\helpers\chocolateyProfile.psm1"
refreshenv
Write-Host "Done!"

# move to scripts dir
cd scripts

# repo win10script handling
Write-Host "Checking if win10script repository already exists..."
if(![System.IO.File]::Exists("win10scriptt")){
	Write-Host "Found!"
	Write-Host "Deleting existing win10script repository..."
	del /f /s /q win10script 1>nul
	rmdir /s /q win10script
	Write-Host "Done!"
} else {
	Write-Host "Not found!"
}
git clone https://github.com/ChrisTitusTech/win10script

# repo windows10-debloat handling
Write-Host "Checking if windows10-debloat repository already exists..."
if(![System.IO.File]::Exists("windows10-debloat")){
	Write-Host "Found!"
	Write-Host "Deleting existing windows10-debloat repository..."
	del /f /s /q windows10-debloat 1>nul
	rmdir /s /q windows10-debloat
	Write-Host "Done!"
} else {
	Write-Host "Not found!"
}
git clone https://github.com/Daksh777/windows10-debloat

# repo Windows10Debloater handling
Write-Host "Checking if Windows10Debloater repository already exists..."
if(![System.IO.File]::Exists("Windows10Debloater")){
	Write-Host "Found!"
	Write-Host "Deleting existing Windows10Debloater repository..."
	del /f /s /q Windows10Debloater 1>nul
	rmdir /s /q Windows10Debloater
	Write-Host "Done!"
} else {
	Write-Host "Not found!"
}
git clone https://github.com/Sycnex/Windows10Debloater

# unblock scripts and set execution policy
Set-ExecutionPolicy Unrestricted
ls -Recurse *.ps*1 | Unblock-File

# move back to root then software dir
cd ..
cd software

# download software
Invoke-WebRequest 'https://coderbag.com/assets/downloads/cpm/currentversion/QuickCpuSetup64.zip' -OutFile 'QuickCpuSetup64.zip'
Invoke-WebRequest 'https://www.speedguide.net/files/TCPOptimizer.exe' -OutFile 'TCPOptimizer.exe'
Invoke-WebRequest 'https://www.wagnardsoft.com/DDU/download/DDU v18.0.3.5.exe' -OutFile 'DDU v18.0.3.5.exe'
Invoke-WebRequest 'https://www.wagnardsoft.com/ISLC/ISLC v1.0.2.2.exe' -OutFile 'ISLC v1.0.2.2.exe'

# cleanup
choco uninstall -y git

# exit
exit