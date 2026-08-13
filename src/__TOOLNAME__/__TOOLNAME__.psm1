#Requires -Version 7.4

Set-StrictMode -Version Latest

$script:ToolName = '__TOOLNAME__'
$script:ManifestPath = Join-Path -Path $PSScriptRoot -ChildPath '__TOOLNAME__.psd1'

function Get-ToolStatus {
    <#
    .SYNOPSIS
        Returns the current status of the __TOOLNAME__ module.

    .DESCRIPTION
        Get-ToolStatus reports the module name, the version declared in the module
        manifest, and the UTC timestamp at which the status was produced. It is the
        reference implementation for this template: every function added to the module
        should follow the same shape (advanced function, comment-based help, declared
        output type, pipeline-friendly object output, no host writes).

    .EXAMPLE
        PS> Get-ToolStatus

        Tool          Version Timestamp
        ----          ------- ---------
        __TOOLNAME__  0.1.0   2026-01-01T00:00:00Z

        Returns the module status as a pscustomobject.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param()

    Write-Verbose -Message "Reading module manifest from '$script:ManifestPath'."

    $manifest = Import-PowerShellDataFile -Path $script:ManifestPath

    [pscustomobject]@{
        Tool      = $script:ToolName
        Version   = [string]$manifest.ModuleVersion
        Timestamp = [datetime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ', [cultureinfo]::InvariantCulture)
    }
}

Export-ModuleMember -Function 'Get-ToolStatus'
