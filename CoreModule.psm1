# add hosts from a file into another file, dodging comments and duplicates (maybe)
function Combine-HostsFile {
    [CmdletBinding()]
    param(
        [Parameter(Position = 0, Mandatory, ValueFromPipeline)][string]$InFile,
        [Parameter(Position = 1)][string]$OutFile = "$PSScriptRoot\CombinedHostsFile"
    )
    process{
        Write-Host "Combining $InFile into $OutFile..."
        New-Item -Path $OutFile -ErrorAction SilentlyContinue
        $CurrentContents = Get-Content $OutFile
        Get-Content $InFile | Where-Object{$PSItem -match '^[a-zA-Z0-9.:]'} | Where-Object{$PSItem -notin $CurrentContents} | Foreach-Object{Add-Content $PSItem -Path $OutFile}
    }
}

# compress a pure hosts file to 9 adresses per line
function Compress-HostsFile {
    [CmdletBinding()]
    param(
        [Parameter(Position = 0, Mandatory, ValueFromPipeline)][string]$InFile,
        [Parameter(Position = 1)][string]$OutFile = "$PSScriptRoot\CompressedHostsFile"
    )
    process{
        Write-Host "Compressing $InFile into $OutFile..."
    }
}
#Replacement for 'force-mkdir' to uphold PowerShell conventions. Thanks to raydric, this function should be used instead of 'mkdir -force'. Because 'mkdir -force' doesn't always work well with registry operations.
<#
function New-FolderForced {
    [CmdletBinding(SupportsShouldProcess = $True)]
    param (
		[Parameter(Position = 0, Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
		[string]
        $Path
    )

    process {
        if (-not (Test-Path $Path)) {
            Write-Verbose "-- Creating full path to:  $Path"
            New-Item -Path $Path -ItemType Directory -Force
        }
    }
}#>
Export-ModuleMember -Function Combine-HostsFile