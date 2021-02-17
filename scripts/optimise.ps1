# elevate instance
if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Start-Process PowerShell -Verb RunAs "-NoProfile -ExecutionPolicy Bypass -Command `"cd '$pwd'; & '$PSCommandPath';`"";
    exit;
}
Start-Transcript -Path optimise.ps1.log
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
# run win10script first time
Write-Host 'Running first script...'
Write-Host '[INFO] At this stage, you should run "Essential Tweaks", "Action Center", "Background Apps", "Cortana", "OneDrive"(CHECK IF YOU HAVE ONEDRIVE DOCUMENTS ON YOUR PC -- THEY WILL BE DELETED SO BACK THEM UP FIRST), "Visual FX", "Windows Search" & "Security Updates Only". At this stage DO NOT run "High" under "Security". You can run the others at your discretion. You may want to run "Dark Mode". Close the window when you are finished.'
.\win10script\win10debloat.ps1

# run Windows10Debloater once
Write-Host 'Running second script...'
Write-Host '[INFO] You should run "Remove All Bloatware", "Disable Cortana", "Stop Edge PDF Takeover", "Uninstall OneDrive", "Disable Telemetry/Tasks", "Remove Bloatware Regkeys". You can run the others at your discretion. You way want to run "Unpin Tiles From Start Menu". Close the window when you are finished.'
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

#run scripts from this repo
Write-Host 'Run scripts from this repo...'
.\cmd-optimiser.bat
reg import reg-optimise.reg