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
refreshenv

# install git using chocolatey
choco install -y  git

# refresh env
refreshenv

#define useful dicts, arrays
# FORMAT:
#   'USER'     =   'REPOSITORY'
$gitRepos = @{
    'ChrisTitusTech' = 'win10script'
    'Sycnex' = 'Windows10Debloater'
    'W4RH4WK' = 'Debloat-Windows-10'
}

#FORMAT:
#   'OutFile'           =   'URL'
$softwareLinks = @{
    'QuickCpuSetup64.zip' = 'https://coderbag.com/assets/downloads/cpm/currentversion/QuickCpuSetup64.zip'
    'TCPOptimizer.exe' = 'https://www.speedguide.net/files/TCPOptimizer.exe'
    'DDU v18.0.4.5.exe' = 'https://www.wagnardsoft.com/DDU/download/DDU v18.0.4.5.exe'
    'ISLC v1.0.2.6.exe' = 'https://www.wagnardsoft.com/ISLC/ISLC v1.0.2.6.exe'
    'privatezilla.zip' = 'https://github.com/builtbybel/privatezilla/releases/download/0.50.0/privatezilla.zip'
}

#FORMAT:
#   'SFX NAME (OMITTING EXTENSION)'
$sfxes = @(
    'DDU v18.0.4.5'
    'ISLC v1.0.2.6'
)

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

# move to scripts dir
Write-Host 'Moving to scripts dir...'
cd scripts

# delet existing folders(repos)
Write-Host 'Deleting old repo folders...'
Get-ChildItem -Directory | Remove-Item -Recurse -Force

# clone repos loop
Write-Host 'Begin cloning repositories...'
foreach ($repo in $gitRepos.GetEnumerator()) {
    $link = -join('https://github.com/',$repo.Name,'/',$repo.Value)
    git clone $link
}

# unblock scripts, move to root
Write-Host 'Unblocking files...'
ls -Recurse *.ps*1 | Unblock-File
Write-Host 'Moving to root dir...'
cd ..

# move to software dir
Write-Host 'Moving to software dir...'
cd software

# download software loop
Write-Host 'Begin downloading software...'
foreach ($url in $softwareLinks.GetEnumerator()) {
    $downloadText = -join ('Downloading ',$url.Name,'...')
    Write-Host $downloadText
    Invoke-WebRequest $url.Value -OutFile $url.Name
}

#clear prev archives
Write-Host 'Deleting old archive folders...'
Get-ChildItem -Directory | Remove-Item -Recurse -Force

# Extract archives loop
Write-Host 'Begin extracting archives...'
$zips = Get-ChildItem *.zip
foreach ($zip in $zips) {
    $text = -join('Extracting ',$zip,'...')
    Write-Host $text
    Expand-Archive -Path $zip
}

#extract 7z sfx archives
Write-Host 'Begin extracting SFX archives...'
foreach ($sfx in $sfxes) {
    $sfxExe = -join('"',$sfx,'.exe"')
    $sfxDir = -join('"',$sfx,'"')
    Write-Host "Extracting $sfx.exe..."
    Invoke-Expression ".\$sfxExe -y -gm2 -InstallPath=$sfxDir"
}

# remove ssd script if no ssd
Write-Host 'Moving to root dir...'
cd ..
Write-Host 'Moving to scripts dir....'
cd scripts

$ssdTitle = 'SSD Options'
$ssdMessage = "Do you use a SSD (Solid-State Drive)? If you don't know, select No."
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

# choco git cleanup choices
$cleanupTitle = 'Chocolatey/Git Cleanup Options'
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