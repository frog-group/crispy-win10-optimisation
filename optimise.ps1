# elevate instance
    if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Start-Process PowerShell -Verb RunAs "-NoProfile -ExecutionPolicy Bypass -Command `"cd '$pwd'; & '$PSCommandPath';`"";
        exit;
    }

#other func
If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Force
}

#make restore point
    Enable-ComputerRestore -Drive "C:\"
    Checkpoint-Computer -Description "pre-optimisations" -RestorePointType "MODIFY_SETTINGS"

#software download
    $downloadLinks = @{
        'QuickCpuSetup64.zip' = 'https://coderbag.com/assets/downloads/cpm/currentversion/QuickCpuSetup64.zip'
        'TCPOptimizer.exe' = 'https://www.speedguide.net/files/TCPOptimizer.exe'
        'DDU v18.0.4.5.exe' = 'https://www.wagnardsoft.com/DDU/download/DDU v18.0.4.5.exe'
        'ISLC v1.0.2.6.exe' = 'https://www.wagnardsoft.com/ISLC/ISLC v1.0.2.6.exe'
        'privatezilla.zip' = 'https://github.com/builtbybel/privatezilla/releases/download/0.50.0/privatezilla.zip'
        'OOSU10.exe' = 'https://dl5.oo-software.com/files/ooshutup10/OOSU10.exe'
        'ooshutup10.cfg' = 'https://raw.githubusercontent.com/ChrisTitusTech/win10script/master/ooshutup10.cfg'
    }

# INVISIBLE CHANGES
    bcdedit /set useplatformtick yes
    bcdedit /set useplatformclock false
    bcdedit /set disabledynamictick yes
    bcdedit /set `{current`} bootmenupolicy Legacy
    #telemetry schtsk
    $disableTasks = @(
        "Microsoft\Windows\AppID\SmartScreenSpecific"
        "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser"
        "Microsoft\Windows\Application Experience\ProgramDataUpdater"
        "Microsoft\Windows\Application Experience\StartupAppTask"
        "Microsoft\Windows\Customer Experience Improvement Program\Consolidator"
        "Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask"
        "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip"
        "Microsoft\Windows\Customer Experience Improvement Program\Uploader"
        "Microsoft\Windows\Shell\FamilySafetyUpload"
        "Microsoft\Office\OfficeTelemetryAgentLogOn"
        "Microsoft\Office\OfficeTelemetryAgentFallBack"
        "Microsoft\Office\Office 15 Subscription Heartbeat"
        "Microsoft\Windows\Autochk\Proxy"
        "Microsoft\Windows\CloudExperienceHost\CreateObjectTask"
        "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector"
        "Microsoft\Windows\DiskFootprint\Diagnostics"
        "Microsoft\Windows\FileHistory\File History (maintenance mode)"
        "Microsoft\Windows\Maintenance\WinSAT"
        "Microsoft\Windows\NetTrace\GatherNetworkInfo"
        "Microsoft\Windows\PI\Sqm-Tasks"
        "Microsoft\Windows\Time Synchronization\ForceSynchronizeTime"
        "Microsoft\Windows\Time Synchronization\SynchronizeTime"
        "Microsoft\Windows\Windows Error Reporting\QueueReporting"
        "Microsoft\Windows\WindowsUpdate\Automatic App Update"
        "Microsoft\Windows\Feedback\Siuf\DmClient"
        "Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload"
    )
    foreach ($task in $disableTasks) {
        Disable-ScheduledTask -TaskName $task
    }
    # regkeys
    #make
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Force
    }
    If (!(Test-Path "HKLM:\Software\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting")) {
        New-Item -Path "HKLM:\Software\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" -Force
    }
    If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Siuf\Rules")) {
        New-Item -Path "HKCU:\SOFTWARE\Microsoft\Siuf\Rules" -Force
    }
    If (!(Test-Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent")) {
        New-Item -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Force
    }
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo"
    }
    If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config")) {
        New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config"
    }
    If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings")) {
        New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings"
    }
    If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People")) {
        New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People"
    }
    If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager")) {
        New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager"
    }
    If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer")) {
        New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Force
    }
    #alter
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Device Metadata" -Name "PreventDeviceMetadataFromNetwork" -Type Dword -Value 1
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Type Dword -Value 0
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\MRT" -Name "DontOfferThroughWUAU" -Type Dword -Value 1
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\SQMClient\Windows" -Name "CEIPEnable" -Type Dword -Value 0
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat" -Name "AITEnable" -Type Dword -Value 0
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat" -Name "DisableUAR" -Type Dword -Value 1
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Type Dword -Value 0
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\WMI\AutoLogger\AutoLogger-Diagtrack-Listener" -Name "Start" -Type Dword -Value 0
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\WMI\AutoLogger\SQMLogger" -Name "Start" -Type Dword -Value 0
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "ContentDeliveryAllowed" -Type DWord -Value 0
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "OemPreInstalledAppsEnabled" -Type DWord -Value 0
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "PreInstalledAppsEnabled" -Type DWord -Value 0
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "PreInstalledAppsEverEnabled" -Type DWord -Value 0
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SilentInstalledAppsEnabled" -Type DWord -Value 0
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338387Enabled" -Type DWord -Value 0
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338388Enabled" -Type DWord -Value 0
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338389Enabled" -Type DWord -Value 0
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353698Enabled" -Type DWord -Value 0
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SystemPaneSuggestionsEnabled" -Type DWord -Value 0
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsConsumerFeatures" -Type DWord -Value 1
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" -Name "Enabled" -Type Dword -Value 0
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost" -Name "EnableWebContentEvaluation" -Type Dword -Value 0
    Set-ItemProperty -Path "HKCU:\Control Panel\International\User Profile" -Name "HttpAcceptLanguageOptOut" -Type Dword -Value 1
    Set-ItemProperty -Path "HKLM:\Software\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" -Name "Value" -Type DWord -Value 0
    Set-ItemProperty -Path "HKLM:\Software\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" -Name "Value" -Type DWord -Value 0
    Set-ItemProperty -Path "HKLM:\Software\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" -Name "value" -Type Dword -Value 0
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" -Name "UxOption" -Type Dword -Value 1
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" -Name "DODownloadMode" -Type Dword -Value 0
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Start_TrackDocs" -Type Dword -Value 0
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "LaunchTo" -Type Dword -Value 1
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableActivityFeed" -Type DWord -Value 0
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "PublishUserActivities" -Type DWord -Value 0
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "UploadUserActivities" -Type DWord -Value 0
    Set-ItemProperty -Path "HKLM:\SYSTEM\Maps" -Name "AutoUpdateEnabled" -Type DWord -Value 0
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Siuf\Rules" -Name "NumberOfSIUFInPeriod" -Type DWord -Value 0
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "DoNotShowFeedbackNotifications" -Type DWord -Value 1
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableTailoredExperiencesWithDiagnosticData" -Type DWord -Value 1
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" -Name "DisabledByGroupPolicy" -Type DWord -Value 1
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" -Name "DODownloadMode" -Type DWord -Value 1
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" -Name "fAllowToGetHelp" -Type DWord -Value 0
    Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Session Manager\Power" -Name "HibernteEnabled" -Type Dword -Value 0
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" -Name "ShowHibernateOption" -Type Dword -Value 0
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager" -Name "EnthusiastMode" -Type DWord -Value 1
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowTaskViewButton" -Type DWord -Value 0
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" -Name "PeopleBand" -Type DWord -Value 0
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "EnableAutoTray" -Type DWord -Value 1
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Type DWord -Value 0
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "LaunchTo" -Type DWord -Value 1
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "IRPStackSize" -Type DWord -Value 20
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds" -Name "EnableFeeds" -Type DWord -Value 0
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Feeds" -Name "ShellFeedsTaskbarViewMode" -Type DWord -Value 2
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "HideSCAMeetNow" -Type DWord -Value 1
    #delete key
    Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}" -Recurse
    #service stop
    Stop-Service "HomeGroupProvider"
    Stop-Service "HomeGroupListener"
    Stop-Service "dmwappushservice"
    Stop-Service "DiagTrack"
    Stop-Service "SysMain"
    #disable services
    Set-Service "DiagTrack" -StartupType Disabled
    Set-Service "dmwappushservice" -StartupType Disabled
    Set-Service "HomeGroupListener" -StartupType Disabled
    Set-Service "HomeGroupProvider" -StartupType Disabled
    Set-Service "SysMain" -StartupType Disabled
    #manual services
    $services = @(
        "diagnosticshub.standardcollector.service"     # Microsoft (R) Diagnostics Hub Standard Collector Service
        "DiagTrack"                                    # Diagnostics Tracking Service
        "DPS"
        "dmwappushservice"                             # WAP Push Message Routing Service (see known issues)
        "lfsvc"                                        # Geolocation Service
        "MapsBroker"                                   # Downloaded Maps Manager
        "NetTcpPortSharing"                            # Net.Tcp Port Sharing Service
        "RemoteAccess"                                 # Routing and Remote Access
        "RemoteRegistry"                               # Remote Registry
        "SharedAccess"                                 # Internet Connection Sharing (ICS)
        "TrkWks"                                       # Distributed Link Tracking Client
        #"WbioSrvc"                                     # Windows Biometric Service (required for Fingerprint reader / facial detection)
        #"WlanSvc"                                      # WLAN AutoConfig
        "WMPNetworkSvc"                                # Windows Media Player Network Sharing Service
        #"wscsvc"                                       # Windows Security Center Service
        "WSearch"                                      # Windows Search
        "XblAuthManager"                               # Xbox Live Auth Manager
        "XblGameSave"                                  # Xbox Live Game Save Service
        "XboxNetApiSvc"                                # Xbox Live Networking Service
        "XboxGipSvc"                                   #Disables Xbox Accessory Management Service
        "ndu"                                          # Windows Network Data Usage Monitor
        "WerSvc"                                       #disables windows error reporting
        #"Spooler"                                      #Disables your printer
        "Fax"                                          #Disables fax
        "fhsvc"                                        #Disables fax histroy
        "gupdate"                                      #Disables google update
        "gupdatem"                                     #Disable another google update
        "stisvc"                                       #Disables Windows Image Acquisition (WIA)
        "AJRouter"                                     #Disables (needed for AllJoyn Router Service)
        "MSDTC"                                        # Disables Distributed Transaction Coordinator
        "WpcMonSvc"                                    #Disables Parental Controls
        "PhoneSvc"                                     #Disables Phone Service(Manages the telephony state on the device)
        "PrintNotify"                                  #Disables Windows printer notifications and extentions
        "PcaSvc"                                       #Disables Program Compatibility Assistant Service
        "WPDBusEnum"                                   #Disables Portable Device Enumerator Service
        #"LicenseManager"                               #Disable LicenseManager(Windows store may not work properly)
        "seclogon"                                     #Disables  Secondary Logon(disables other credentials only password will work)
        "SysMain"                                      #Disables sysmain
        "lmhosts"                                      #Disables TCP/IP NetBIOS Helper
        "wisvc"                                        #Disables Windows Insider program(Windows Insider will not work)
        "FontCache"                                    #Disables Windows font cache
        "RetailDemo"                                   #Disables RetailDemo whic is often used when showing your device
        "ALG"                                          # Disables Application Layer Gateway Service(Provides support for 3rd party protocol plug-ins for Internet Connection Sharing)
        #"BFE"                                         #Disables Base Filtering Engine (BFE) (is a service that manages firewall and Internet Protocol security)
        #"BrokerInfrastructure"                         #Disables Windows infrastructure service that controls which background tasks can run on the system.
        "SCardSvr"                                      #Disables Windows smart card
        "EntAppSvc"                                     #Disables enterprise application management.
        "BthAvctpSvc"                                   #Disables AVCTP service (if you use  Bluetooth Audio Device or Wireless Headphones. then don't disable this)
        #"FrameServer"                                   #Disables Windows Camera Frame Server(this allows multiple clients to access video frames from camera devices.)
        "Browser"                                       #Disables computer browser
        "BthAvctpSvc"                                   #AVCTP service (This is Audio Video Control Transport Protocol service.)
        #"BDESVC"                                        #Disables bitlocker
        "iphlpsvc"                                      #Disables ipv6 but most websites don't use ipv6 they use ipv4     
        "edgeupdate"                                    # Disables one of edge update service  
        "MicrosoftEdgeElevationService"                 # Disables one of edge  service 
        "edgeupdatem"                                   # disbales another one of update service (disables edgeupdatem)                          
        "SEMgrSvc"                                      #Disables Payments and NFC/SE Manager (Manages payments and Near Field Communication (NFC) based secure elements)
        #"PNRPsvc"                                      # Disables peer Name Resolution Protocol ( some peer-to-peer and collaborative applications, such as Remote Assistance, may not function, Discord will still work)
        #"p2psvc"                                       # Disbales Peer Name Resolution Protocol(nables multi-party communication using Peer-to-Peer Grouping.  If disabled, some applications, such as HomeGroup, may not function. Discord will still work)
        #"p2pimsvc"                                     # Disables Peer Networking Identity Manager (Peer-to-Peer Grouping services may not function, and some applications, such as HomeGroup and Remote Assistance, may not function correctly.Discord will still work)
        "PerfHost"                                      #Disables  remote users and 64-bit processes to query performance .
        "BcastDVRUserService_48486de"                   #Disables GameDVR and Broadcast   is used for Game Recordings and Live Broadcasts
        "CaptureService_48486de"                        #Disables ptional screen capture functionality for applications that call the Windows.Graphics.Capture API.  
        "cbdhsvc_48486de"                               #Disables   cbdhsvc_48486de (clipboard service it disables)
        #"BluetoothUserService_48486de"                  #disbales BluetoothUserService_48486de (The Bluetooth user service supports proper functionality of Bluetooth features relevant to each user session.)
        "WpnService"                                    #Disables WpnService (Push Notifications may not work )
        #"StorSvc"                                       #Disables StorSvc (usb external hard drive will not be reconised by windows)
        "RtkBtManServ"                                  #Disables Realtek Bluetooth Device Manager Service
        "QWAVE"                                         #Disables Quality Windows Audio Video Experience (audio and video might sound worse)
         #Hp services
        "HPAppHelperCap"
        "HPDiagsCap"
        "HPNetworkCap"
        "HPSysInfoCap"
        "HpTouchpointAnalyticsService"
        #hyper-v services
         "HvHost"                          
        "vmickvpexchange"
        "vmicguestinterface"
        "vmicshutdown"
        "vmicheartbeat"
        "vmicvmsession"
        "vmicrdv"
        "vmictimesync" 
        # Services which cannot be disabled
        #"WdNisSvc"
    )
    foreach ($service in $services) {
        Get-Service -Name $service | Set-Service -StartupType Manual
    }
    #task man
    $taskmgr = Start-Process -WindowStyle Hidden -FilePath taskmgr.exe -PassThru
    Do {
        Start-Sleep -Milliseconds 100
        $preferences = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\TaskManager" -Name "Preferences"
    } Until ($preferences)
    Stop-Process $taskmgr
    $preferences.Preferences[28] = 0
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\TaskManager" -Name "Preferences" -Type Binary -Value $preferences.Preferences
    # num lock
    If (!(Test-Path "HKU:")) {
        New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS
    }
    Set-ItemProperty -Path "HKU:\.DEFAULT\Control Panel\Keyboard" -Name "InitialKeyboardIndicators" -Type DWord -Value 2147483650
    Add-Type -AssemblyName System.Windows.Forms
    If (!([System.Windows.Forms.Control]::IsKeyLocked('NumLock'))) {
        $wsh = New-Object -ComObject WScript.Shell
        $wsh.SendKeys('{NUMLOCK}')
    }
    # Group svchost.exe processes
    $ram = (Get-CimInstance -ClassName Win32_PhysicalMemory | Measure-Object -Property Capacity -Sum).Sum / 1kb
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control" -Name "SvcHostSplitThresholdInKB" -Type DWord -Value $ram -Force
    #Removing AutoLogger file and restricting directory...
    $autoLoggerDir = "$env:PROGRAMDATA\Microsoft\Diagnosis\ETLLogs\AutoLogger"
    If (Test-Path "$autoLoggerDir\AutoLogger-Diagtrack-Listener.etl") {
        Remove-Item "$autoLoggerDir\AutoLogger-Diagtrack-Listener.etl"
    }
    icacls $autoLoggerDir /deny SYSTEM:`(OI`)`(CI`)F
    #OOSU
    ./OOSU10.exe ooshutup10.cfg /quiet

#OPTIONAL CHANGES
    # Remove Apps
    PowerShell -Command "Get-AppxPackage *3DBuilder* | Remove-AppxPackage"
    PowerShell -Command "Get-AppxPackage *Getstarted* | Remove-AppxPackage"
    PowerShell -Command "Get-AppxPackage *WindowsAlarms* | Remove-AppxPackage"
    PowerShell -Command "Get-AppxPackage *WindowsCamera* | Remove-AppxPackage"
    PowerShell -Command "Get-AppxPackage *bing* | Remove-AppxPackage"
    PowerShell -Command "Get-AppxPackage *MicrosoftOfficeHub* | Remove-AppxPackage"
    PowerShell -Command "Get-AppxPackage *OneNote* | Remove-AppxPackage"
    PowerShell -Command "Get-AppxPackage *people* | Remove-AppxPackage"
    PowerShell -Command "Get-AppxPackage *WindowsPhone* | Remove-AppxPackage"
    PowerShell -Command "Get-AppxPackage *photos* | Remove-AppxPackage"
    PowerShell -Command "Get-AppxPackage *SkypeApp* | Remove-AppxPackage"
    PowerShell -Command "Get-AppxPackage *solit* | Remove-AppxPackage"
    PowerShell -Command "Get-AppxPackage *WindowsSoundRecorder* | Remove-AppxPackage"
    PowerShell -Command "Get-AppxPackage *windowscommunicationsapps* | Remove-AppxPackage"
    PowerShell -Command "Get-AppxPackage *zune* | Remove-AppxPackage"
    PowerShell -Command "Get-AppxPackage *WindowsCalculator* | Remove-AppxPackage"
    PowerShell -Command "Get-AppxPackage *WindowsMaps* | Remove-AppxPackage"
    PowerShell -Command "Get-AppxPackage *Sway* | Remove-AppxPackage"
    PowerShell -Command "Get-AppxPackage *CommsPhone* | Remove-AppxPackage"
    PowerShell -Command "Get-AppxPackage *ConnectivityStore* | Remove-AppxPackage"
    PowerShell -Command "Get-AppxPackage *Microsoft.Messaging* | Remove-AppxPackage"
    PowerShell -Command "Get-AppxPackage *Facebook* | Remove-AppxPackage"
    PowerShell -Command "Get-AppxPackage *Twitter* | Remove-AppxPackage"
    PowerShell -Command "Get-AppxPackage *Drawboard PDF* | Remove-AppxPackage"
    # Keep Location Tracking commented out if you want the ability to locate your device
    Write-Host "Disabling Location Tracking..."
    If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location")) {
        New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -Force
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -Name "Value" -Type String -Value "Deny"
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" -Name "SensorPermissionState" -Type DWord -Value 0
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration" -Name "Status" -Type DWord -Value 0
    #Disabling Error reporting...
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting" -Name "Disabled" -Type DWord -Value 1
    Disable-ScheduledTask -TaskName "Microsoft\Windows\Windows Error Reporting\QueueReporting"



########################################################################################################################################################################################
   

    
    
    






Stop-Service "DiagTrack"

Set-Service "DiagTrack" -StartupType Disabled





    


    





