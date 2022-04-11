# converts hosts file with comments and adresses to just a list of adresses sans redirects
function Make-ZeroHostsList {
    [CmdletBinding()]
    param(
        [Parameter(Position = 0, Mandatory, ValueFromPipeline)][string]$InFile,
        [Parameter(Position = 1)][string]$OutFile = "$PSScriptRoot\Hosts\ZeroHostsList"
    )
    process{
        Write-Host "Processing $InFile into $OutFile..."
        Get-Content $InFile | Where-Object{$PSItem -match '^0\.0\.0\.0\s'} | ForEach-Object{
            $PSItem = $PSItem -replace '^0\.0\.0\.0\s',''
            Add-Content -Value $PSItem -Path $OutFile
        }
    }
}
function Make-OtherHostsList {
    [CmdletBinding()]
    param(
        [Parameter(Position = 0, Mandatory, ValueFromPipeline)][string]$InFile,
        [Parameter(Position = 1)][string]$OutFile = "$PSScriptRoot\Hosts\OtherHostsList"
    )
    process{
        Write-Host "Processing $InFile into $OutFile..."
        Get-Content $InFile | Where-Object{$PSItem -match '(^0\.0\.0\.0\s)|(^\n)|()'} | ForEach-Object{
            $PSItem = $PSItem -replace '^0\.0\.0\.0\s',''
            Add-Content -Value $PSItem -Path $OutFile
        }
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
Export-ModuleMember -Function Make-ZeroHostsList