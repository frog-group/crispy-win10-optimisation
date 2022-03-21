# converts hosts file with comments and adresses to just a list of adresses sans redirects
function Convert-HostsFile {
    [CmdletBinding()]
    param(
        [Parameter(Position = 0, Mandatory, ValueFromPipeline)][string]$InFile,
        [Parameter(Position = 1)][string]$OutFile = "$PSScriptRoot\CombinedHosts"
    )
    process{
        Write-Host "TEST - Processing $InFile into $OutFile..."
        Get-Content $InFile | Add-Content $OutFile
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
Export-ModuleMember -Function Convert-HostsFile