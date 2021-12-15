# elevate instance
    if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Start-Process PowerShell -Verb RunAs "-NoProfile -ExecutionPolicy Bypass -Command `"cd '$pwd'; & '$PSCommandPath';`"";
        exit;
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
    $regCreate = @(
        "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent"
        "HKLM:\Software\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting"
        "HKCU:\SOFTWARE\Microsoft\Siuf\Rules"
        "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent"
        "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo"
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config"
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings"
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People"
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager"
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"
    )
    foreach ($key in $regCreate) {
        If (!(Test-Path $key)) {
            New-Item -Path $key -Force
        }
    }
    #alter
    $regModify = @(
        @("HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Device Metadata","PreventDeviceMetadataFromNetwork","Dword","1")
        @("HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection","AllowTelemetry","Dword","0")
        @("HKLM:\SOFTWARE\Policies\Microsoft\MRT","DontOfferThroughWUAU","Dword","1")
        @("HKLM:\SOFTWARE\Policies\Microsoft\SQMClient\Windows","CEIPEnable","Dword","0")
        @("HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat","AITEnable","Dword","0")
        @("HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat","DisableUAR","Dword","1")
        @("HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection","AllowTelemetry","Dword","0")
        @("HKLM:\SYSTEM\CurrentControlSet\Control\WMI\AutoLogger\AutoLogger-Diagtrack-Listener","Start","Dword","0")
        @("HKLM:\SYSTEM\CurrentControlSet\Control\WMI\AutoLogger\SQMLogger","Start","Dword","0")
        @("HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager","ContentDeliveryAllowed","DWord","0")
        @("HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager","OemPreInstalledAppsEnabled","DWord","0")
        @("HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager","PreInstalledAppsEnabled","DWord","0")
        @("HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager","PreInstalledAppsEverEnabled","DWord","0")
        @("HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager","SilentInstalledAppsEnabled","DWord","0")
        @("HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager","SubscribedContent-338387Enabled","DWord","0")
        @("HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager","SubscribedContent-338388Enabled","DWord","0")
        @("HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager","SubscribedContent-338389Enabled","DWord","0")
        @("HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager","SubscribedContent-353698Enabled","DWord","0")
        @("HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager","SystemPaneSuggestionsEnabled","DWord","0")
        @("HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent","DisableWindowsConsumerFeatures","DWord","1")
        @("HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo","Enabled","Dword","0")
        @("HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost","EnableWebContentEvaluation","Dword","0")
        @("HKCU:\Control Panel\International\User Profile","HttpAcceptLanguageOptOut","Dword","1")
        @("HKLM:\Software\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting","Value","DWord","0")
        @("HKLM:\Software\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots","Value","DWord","0")
        @("HKLM:\Software\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots","value","Dword","0")
        @("HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings","UxOption","Dword","1")
        @("HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config","DODownloadMode","Dword","0")
        @("HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced","Start_TrackDocs","Dword","0")
        @("HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced","LaunchTo","Dword","1")
        @("HKLM:\SOFTWARE\Policies\Microsoft\Windows\System","EnableActivityFeed","DWord","0")
        @("HKLM:\SOFTWARE\Policies\Microsoft\Windows\System","PublishUserActivities","DWord","0")
        @("HKLM:\SOFTWARE\Policies\Microsoft\Windows\System","UploadUserActivities","DWord","0")
        @("HKLM:\SYSTEM\Maps","AutoUpdateEnabled","DWord","0")
        @("HKCU:\SOFTWARE\Microsoft\Siuf\Rules","NumberOfSIUFInPeriod","DWord","0")
        @("HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection","DoNotShowFeedbackNotifications","DWord","1")
        @("HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent","DisableTailoredExperiencesWithDiagnosticData","DWord","1")
        @("HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo","DisabledByGroupPolicy","DWord","1")
        @("HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config","DODownloadMode","DWord","1")
        @("HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance","fAllowToGetHelp","DWord","0")
        @("HKLM:\System\CurrentControlSet\Control\Session Manager\Power","HibernteEnabled","Dword","0")
        @("HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings","ShowHibernateOption","Dword","0")
        @("HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager","EnthusiastMode","DWord","1")
        @("HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced","ShowTaskViewButton","DWord","0")
        @("HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People","PeopleBand","DWord","0")
        @("HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer","EnableAutoTray","DWord","1")
        @("HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced","HideFileExt","DWord","0")
        @("HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced","LaunchTo","DWord","1")
        @("HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters","IRPStackSize","DWord","20")
        @("HKCU:\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds","EnableFeeds","DWord","0")
        @("HKCU:\Software\Microsoft\Windows\CurrentVersion\Feeds","ShellFeedsTaskbarViewMode","DWord","2")
        @("HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer","HideSCAMeetNow","DWord","1")
    )
    foreach ($key in $regModify) {
        Set-ItemProperty -Path $key[0] -Name $key[1] -Type $key[2] -Value $key[3]
    }
    #delete key
    $regDelete = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}"
    )
    foreach ($key in $regDelete) {
        Remove-Item-Path $key -Recurse
    }
    #service stop
    $svcStop = @(
        "HomeGroupProvider"
        "HomeGroupListener"
        "dmwappushservice"
        "DiagTrack"
        "SysMain"
    )
    foreach ($svc in $svcStop) {
        Stop-Service $svc
    }
    #manual services
    $svcManual = @(
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
    foreach ($svc in $svcManual) {
        Get-Service -Name $svc | Set-Service -StartupType Manual
    }
    #disable services
    $svcDisable = @(
        "DiagTrack"
        "dmwappushservice"
        "HomeGroupListener"
        "HomeGroupProvider"
        "SysMain"
    )
    foreach ($svc in $svcDisable) {
        Get-Service -Name $svc | Set-Service -StartupType Disabled
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
    #remove garbage appx
    $appxRemove = @(
        #Wildcard zone
        "*3DBuilder*"
        "*Getstarted*"
        "*WindowsAlarms*"
        "*bing*"
        "*people*"
        "*WindowsPhone*"
        "*photos*"
        "*solit*"
        "*WindowsSoundRecorder*"
        "*windowscommunicationsapps*"
        "*zune*"
        "*WindowsCalculator*"
        "*WindowsMaps*"
        "*Sway*"
        "*CommsPhone*"
        "*ConnectivityStore*"
        "*Microsoft.Messaging*"
        "*Facebook*"
        "*Twitter*"
        "*Drawboard PDF*"
    )

    #OOSU
    ./OOSU10.exe ooshutup10.cfg /quiet

#OPTIONAL CHANGES
    # Remove Apps
        #$appxRemove += "*SkypeApp*"
        #$appxRemove += "*WindowsCamera*"
        #$appxRemove += "*MicrosoftOfficeHub*"
        #$appxRemove += "*OneNote*"
        foreach ($appx in $appxRemove) {
            Get-AppxPackage $appx | Remove-AppxPackage
        }
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
   



