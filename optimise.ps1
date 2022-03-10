# elevate instance
    if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Start-Process PowerShell -Verb RunAs "-NoProfile -ExecutionPolicy Bypass -Command `"cd '$pwd'; & '$PSCommandPath';`"";
        exit;
    }

#make restore point
    Enable-ComputerRestore -Drive "C:\"
    Checkpoint-Computer -Description "pre-optimisations" -RestorePointType "MODIFY_SETTINGS"

#software download
    $DownloadLinks = @{
        'QuickCpuSetup64.zip' = 'https://coderbag.com/assets/downloads/cpm/currentversion/QuickCpuSetup64.zip'
        'TCPOptimizer.exe' = 'https://www.speedguide.net/files/TCPOptimizer.exe'
        'DDU v18.0.4.5.exe' = 'https://www.wagnardsoft.com/DDU/download/DDU v18.0.4.5.exe'
        'ISLC v1.0.2.6.exe' = 'https://www.wagnardsoft.com/ISLC/ISLC v1.0.2.6.exe'
        'privatezilla.zip' = 'https://github.com/builtbybel/privatezilla/releases/download/0.50.0/privatezilla.zip'
        'OOSU10.exe' = 'https://dl5.oo-software.com/files/ooshutup10/OOSU10.exe'
        'ooshutup10.cfg' = 'https://raw.githubusercontent.com/ChrisTitusTech/win10script/master/ooshutup10.cfg'
    }

# hosts file
    $HostsFile = "$Env:SystemRoot\System32\drivers\etc\hosts"
    # custom addidions
    # this list is smaller than the hosts you find in this script's sources, that is because I have tested and determined that the others are already in StevenBlack's hosts file
    $HostsDomains = @(
        "184-86-53-99.deploy.static.akamaitechnologies.com"
        "a-0001.a-msedge.net"
        "a-0002.a-msedge.net"
        "a-0003.a-msedge.net"
        "a-0004.a-msedge.net"
        "a-0005.a-msedge.net"
        "a-0006.a-msedge.net"
        "a-0007.a-msedge.net"
        "a-0008.a-msedge.net"
        "a-0009.a-msedge.net"
        "a1621.g.akamai.net"
        "a1856.g2.akamai.net"
        "a1961.g.akamai.net"
        #"a248.e.akamai.net"            # makes iTunes download button disappear (#43)
        "a978.i6g1.akamai.net"
        "ac3.msn.com"
        "any.edge.bing.com"
        "choice.microsoft.com"
        "choice.microsoft.com.nsatc.net"
        "compatexchange.cloudapp.net"
        "corpext.msitadfs.glbdns2.microsoft.com"
        "corp.sts.microsoft.com"
        "cs1.wpc.v0cdn.net"
        "diagnostics.support.microsoft.com"
        "e2835.dspb.akamaiedge.net"
        "e7341.g.akamaiedge.net"
        "e7502.ce.akamaiedge.net"
        "e8218.ce.akamaiedge.net"
        "fe2.update.microsoft.com.akadns.net"
        "feedback.search.microsoft.com"
        "feedback.windows.com"
        "h2.msn.com"
        "hostedocsp.globalsign.com"
        "i1.services.social.microsoft.com"
        "i1.services.social.microsoft.com.nsatc.net"
        #"ipv6.msftncsi.com"                    # Issues may arise where Windows 10 thinks it doesn't have internet
        #"ipv6.msftncsi.com.edgesuite.net"      # Issues may arise where Windows 10 thinks it doesn't have internet
        "lb1.www.ms.akadns.net"
        #"msftncsi.com"
        "msnbot-65-55-108-23.search.msn.com"
        "oca.telemetry.microsoft.com"
        "oca.telemetry.microsoft.com.nsatc.net"
        "onesettings-db5.metron.live.nsatc.net"
        "pre.footprintpredict.com"
        "redir.metaservices.microsoft.com"
        "services.wes.df.telemetry.microsoft.com"
        "settings-sandbox.data.microsoft.com"
        #"settings-win.data.microsoft.com"       # may cause issues with Windows Updates
        "sls.update.microsoft.com.akadns.net"
        #"sls.update.microsoft.com.nsatc.net"    # may cause issues with Windows Updates
        "sqm.df.telemetry.microsoft.com"
        "sqm.telemetry.microsoft.com.nsatc.net"
        "ssw.live.com"
        "statsfe1.ws.microsoft.com"
        "statsfe2.update.microsoft.com.akadns.net"
        "survey.watson.microsoft.com"
        "telecommand.telemetry.microsoft.com.nsatc.net"
        "telemetry.appex.bing.net"
        "telemetry.urs.microsoft.com"
        "vortex-bn2.metron.live.com.nsatc.net"
        "vortex-cy2.metron.live.com.nsatc.net"
        "vortex-sandbox.data.microsoft.com"
        "vortex-win.data.microsoft.com"
        "cy2.vortex.data.microsoft.com.akadns.net"
        "watson.live.com"
        "watson.ppe.telemetry.microsoft.com"
        "watson.telemetry.microsoft.com.nsatc.net"
        "win10.ipv6.microsoft.com"
        "www.bingads.microsoft.com"
        "www.go.microsoft.akadns.net"
        #"www.msftncsi.com"                         # Issues may arise where Windows 10 thinks it doesn't have internet
        "client.wns.windows.com"
        #"wdcp.microsoft.com"                       # may cause issues with Windows Defender Cloud-based protection
        #"dns.msftncsi.com"                         # This causes Windows to think it doesn't have internet
        #"storeedgefd.dsx.mp.microsoft.com"         # breaks Windows Store
        "wdcpalt.microsoft.com"
        "settings-ssl.xboxlive.com"
        "settings-ssl.xboxlive.com-c.edgekey.net"
        "settings-ssl.xboxlive.com-c.edgekey.net.globalredir.akadns.net"
        "e87.dspb.akamaidege.net"
        "insiderservice.microsoft.com"
        "insiderservice.trafficmanager.net"
        "e3843.g.akamaiedge.net"
        "flightingserviceweurope.cloudapp.net"
        #"sls.update.microsoft.com"                 # may cause issues with Windows Updates
        "p.static.ads-twitter.com"                  # may cause issues with Twitter login
        "hubspot.net.edge.net"
        "e9483.a.akamaiedge.net"
        #"padgead2.googlesyndication.com"
        #"mirror1.malwaredomains.com"
        #"mirror.cedia.org.ec"
        "adservice.google.de"
        "hubspot.net.edgekey.net"
        "insiderppe.cloudapp.net"                   # Feedback-Hub
        "livetileedge.dsx.mp.microsoft.com"
        # extra
        "m.hotmail.com"
        # epic games trackers
        "dev.epicgames.com"
        "api.epicgames.dev"
        "et.epicgames.com"
        "et2.epicgames.com"
        "udn.epicgames.com"
        "etsource.epicgames.com"
        "metrics.ol.epicgames.com"
        "datarouter.ol.epicgames.com"
        # can cause issues with Skype (#79) or other services (#171)
        "apps.skype.com"
        # "login.live.com"                  # prevents login to outlook and other live apps
        "pricelist.skype.com"
        "s.gateway.messenger.live.com"
        "ui.skype.com"
    )
    # minimal: https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts
    # maximal: https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/fakenews-gambling-porn-social/hosts
    Write-Host "Downloading StevenBlack hosts file and replacing existing hosts file"
    Start-BitsTransfer -Source "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/fakenews-gambling-porn-social/hosts" -Destination $HostsFile
    
    Write-Host "Appending custom addresses to hosts file"
    "`n# win10-optimisation additions" | Add-Content -Passthru $HostsFile
    foreach ($Domain in $HostsDomains) {
        "0.0.0.0 $Domain" | Add-Content -Passthru $HostsFile
    }