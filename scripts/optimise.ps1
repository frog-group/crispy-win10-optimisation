# elevate instance
if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Start-Process PowerShell -Verb RunAs "-NoProfile -ExecutionPolicy Bypass -Command `"cd '$pwd'; & '$PSCommandPath';`"";
    exit;
}
#Start-Transcript -Path optimise.ps1.log
#define useful dicts, lists
$scriptsExclude = @(
    'disable-windows-defender.ps1'
)

$utilsExclude = @(
    'boot-advanced-startup.bat'
    '*.reg'
    'install-basic-software.ps1'
    'start_vert.png'
)

#run scripts from this repo
Write-Host 'Run scripts from this repo...'
.\old.bat
reg import regtweaks.reg

# run Windows10Debloater
Write-Host 'Running second script...'
Invoke-Item info2.txt
.\Windows10Debloater\Windows10DebloaterGUI.ps1

# run Debloat-Windows-10 scripts
Write-Host 'Begin running Debloat-Windows-10 scripts...'
#scripts
$scriptsToRun = Get-ChildItem -Path 'Debloat-Windows-10\scripts\*' -Exclude $scriptsExclude
foreach($script in $scriptsToRun) {
    $scriptText = -join('Running ',$script,'...')
    Write-Host $scriptText
    Invoke-Expression $script
}
#utils -no reg yet
$utilsToRun = Get-ChildItem -Path 'Debloat-Windows-10\utils\*' -Exclude $utilsExclude
foreach ($util in $utilsToRun) {
    $utilText = -join('Running ',$util,'...')
    Write-Host $utilText
    Invoke-Expression $util
}
#utils -reg!
$regToRun = Get-ChildItem -Path 'Debloat-Windows-10\utils\*' -Filter '*.reg' -Exclude 'dark-theme.reg'
foreach ($reg in $regToRun) {
    $regText = -join('Adding ',$reg,' to the registry...')
    Write-Host $regText
    Invoke-Command {reg import $reg}
}

# run win10script
Write-Host 'Running final script...'
Invoke-Item info1.txt
.\win10script\win10debloat.ps1

#restart pc
Write-Host 'Restarting PC after 15 seconds...'
Start-Sleep -s 15
Restart-Computer