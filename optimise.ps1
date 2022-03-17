# elevate instance
    if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Start-Process PowerShell -Verb RunAs "-NoProfile -ExecutionPolicy Bypass -Command `"cd '$pwd'; & '$PSCommandPath';`"";
        exit;
    }

#make restore point
    Enable-ComputerRestore -Drive "C:\"
    Checkpoint-Computer -Description "pre-optimisations" -RestorePointType "MODIFY_SETTINGS"

#software download
    #$DownloadLinks = @{
        #'QuickCpuSetup64.zip' = 'https://coderbag.com/assets/downloads/cpm/currentversion/QuickCpuSetup64.zip'
        #'TCPOptimizer.exe' = 'https://www.speedguide.net/files/TCPOptimizer.exe'
        #'DDU v18.0.4.5.exe' = 'https://www.wagnardsoft.com/DDU/download/DDU v18.0.4.5.exe'
        #'ISLC v1.0.2.6.exe' = 'https://www.wagnardsoft.com/ISLC/ISLC v1.0.2.6.exe'
        #'privatezilla.zip' = 'https://github.com/builtbybel/privatezilla/releases/download/0.50.0/privatezilla.zip'
        #'OOSU10.exe' = 'https://dl5.oo-software.com/files/ooshutup10/OOSU10.exe'
        #'ooshutup10.cfg' = 'https://raw.githubusercontent.com/ChrisTitusTech/win10script/master/ooshutup10.cfg'
    #}

# hosts file
    $HostsFile = "$Env:SystemRoot\System32\drivers\etc\hosts"
    # custom addidions
    # this list is smaller than the hosts you find in this script's sources, that is because I have tested and determined that the others are already in StevenBlack's hosts file
    $HostsDomains = @(
        # may cause breakages
        #"msftncsi.com"
        #"padgead2.googlesyndication.com"
        #"login.live.com"
        #"mirror1.malwaredomains.com"
        #"wdcp.microsoft.com"
        #"settings-win.data.microsoft.com"
        #"storeedgefd.dsx.mp.microsoft.com"
        #"sls.update.microsoft.com"
        #"dns.msftncsi.com"
        #"ipv6.msftncsi.com"
        #"www.msftncsi.com"
        #"mirror.cedia.org.ec"
        #"a248.e.akamai.net"
        #"ipv6.msftncsi.com.edgesuite.net"
        #"sls.update.microsoft.com.nsatc.net"
        "p.static.ads-twitter.com"
        "184-86-53-99.deploy.static.akamaitechnologies.com"
        "any.edge.bing.com"
        "dev.epicgames.com"
        "et.epicgames.com"
        "et2.epicgames.com"
        "etsource.epicgames.com"
        "datarouter.ol.epicgames.com"
        "metrics.ol.epicgames.com"
        "udn.epicgames.com"
        "pre.footprintpredict.com"
        "hostedocsp.globalsign.com"
        "m.hotmail.com"
        "s.gateway.messenger.live.com"
        "ssw.live.com"
        "watson.live.com"
        "www.bingads.microsoft.com"
        "choice.microsoft.com"
        "settings-sandbox.data.microsoft.com"
        "vortex-sandbox.data.microsoft.com"
        "vortex-win.data.microsoft.com"
        "corpext.msitadfs.glbdns2.microsoft.com"
        "insiderservice.microsoft.com"
        "win10.ipv6.microsoft.com"
        "redir.metaservices.microsoft.com"
        "livetileedge.dsx.mp.microsoft.com"
        "feedback.search.microsoft.com"
        "i1.services.social.microsoft.com"
        "corp.sts.microsoft.com"
        "diagnostics.support.microsoft.com"
        "sqm.df.telemetry.microsoft.com"
        "services.wes.df.telemetry.microsoft.com"
        "oca.telemetry.microsoft.com"
        "watson.ppe.telemetry.microsoft.com"
        "telemetry.urs.microsoft.com"
        "survey.watson.microsoft.com"
        "wdcpalt.microsoft.com"
        "statsfe1.ws.microsoft.com"
        "ac3.msn.com"
        "h2.msn.com"
        "msnbot-65-55-108-23.search.msn.com"
        "apps.skype.com"
        "pricelist.skype.com"
        "ui.skype.com"
        "feedback.windows.com"
        "client.wns.windows.com"
        "settings-ssl.xboxlive.com"
        "adservice.google.de"
        "api.epicgames.dev"
        "cy2.vortex.data.microsoft.com.akadns.net"
        "fe2.update.microsoft.com.akadns.net"
        "sls.update.microsoft.com.akadns.net"
        "statsfe2.update.microsoft.com.akadns.net"
        "settings-ssl.xboxlive.com-c.edgekey.net.globalredir.akadns.net"
        "www.go.microsoft.akadns.net"
        "lb1.www.ms.akadns.net"
        "a1621.g.akamai.net"
        "a1961.g.akamai.net"
        "a1856.g2.akamai.net"
        "a978.i6g1.akamai.net"
        "e87.dspb.akamaidege.net"
        "e9483.a.akamaiedge.net"
        "e7502.ce.akamaiedge.net"
        "e8218.ce.akamaiedge.net"
        "e2835.dspb.akamaiedge.net"
        "e3843.g.akamaiedge.net"
        "e7341.g.akamaiedge.net"
        "a-0001.a-msedge.net"
        "a-0002.a-msedge.net"
        "a-0003.a-msedge.net"
        "a-0004.a-msedge.net"
        "a-0005.a-msedge.net"
        "a-0006.a-msedge.net"
        "a-0007.a-msedge.net"
        "a-0008.a-msedge.net"
        "a-0009.a-msedge.net"
        "telemetry.appex.bing.net"
        "compatexchange.cloudapp.net"
        "flightingserviceweurope.cloudapp.net"
        "insiderppe.cloudapp.net"
        "hubspot.net.edge.net"
        "settings-ssl.xboxlive.com-c.edgekey.net"
        "hubspot.net.edgekey.net"
        "vortex-bn2.metron.live.com.nsatc.net"
        "vortex-cy2.metron.live.com.nsatc.net"
        "choice.microsoft.com.nsatc.net"
        "i1.services.social.microsoft.com.nsatc.net"
        "oca.telemetry.microsoft.com.nsatc.net"
        "sqm.telemetry.microsoft.com.nsatc.net"
        "telecommand.telemetry.microsoft.com.nsatc.net"
        "watson.telemetry.microsoft.com.nsatc.net"
        "onesettings-db5.metron.live.nsatc.net"
        "insiderservice.trafficmanager.net"
        "cs1.wpc.v0cdn.net"
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