#Requires -Version 7.4

<#
.SYNOPSIS
    Packages the module into a distributable zip under dist\.

.DESCRIPTION
    Locates the single module folder under src\, reads ModuleVersion from its manifest,
    and produces dist\<ModuleName>-v<Version>.zip containing the module folder plus
    README.md and CHANGELOG.md. The artifact path is written to the pipeline.

.EXAMPLE
    PS> .\build\package.ps1

    Creates dist\ADForestAssessment-v0.1.0.zip and prints its full path.
#>
[CmdletBinding()]
param(
    # Directory that receives the zip. Defaults to dist\ at the repository root.
    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$OutputDirectory
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Path $PSScriptRoot -Parent
$sourceRoot = Join-Path -Path $repoRoot -ChildPath 'src'

if (-not $PSBoundParameters.ContainsKey('OutputDirectory')) {
    $OutputDirectory = Join-Path -Path $repoRoot -ChildPath 'dist'
}

$moduleDirectories = @(Get-ChildItem -Path $sourceRoot -Directory)
if ($moduleDirectories.Count -ne 1) {
    throw "Expected exactly one module folder under '$sourceRoot'; found $($moduleDirectories.Count)."
}

$moduleDirectory = $moduleDirectories[0]
$moduleName = $moduleDirectory.Name
$manifestPath = Join-Path -Path $moduleDirectory.FullName -ChildPath "$moduleName.psd1"

if (-not (Test-Path -LiteralPath $manifestPath)) {
    throw "Module manifest not found at '$manifestPath'."
}

$moduleVersion = (Import-PowerShellDataFile -Path $manifestPath).ModuleVersion
Write-Verbose -Message "Packaging '$moduleName' version '$moduleVersion'."

$stagingRoot = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath "$moduleName-package-$PID"
if (Test-Path -LiteralPath $stagingRoot) {
    Remove-Item -LiteralPath $stagingRoot -Recurse -Force
}
$null = New-Item -Path $stagingRoot -ItemType Directory -Force

try {
    $null = New-Item -Path (Join-Path -Path $stagingRoot -ChildPath $moduleName) -ItemType Directory -Force
    Copy-Item -Path (Join-Path -Path $moduleDirectory.FullName -ChildPath '*') `
        -Destination (Join-Path -Path $stagingRoot -ChildPath $moduleName) -Recurse -Force

    foreach ($document in @('README.md', 'CHANGELOG.md')) {
        $documentPath = Join-Path -Path $repoRoot -ChildPath $document
        if (-not (Test-Path -LiteralPath $documentPath)) {
            throw "Required file '$document' not found at the repository root."
        }
        Copy-Item -Path $documentPath -Destination $stagingRoot -Force
    }

    if (-not (Test-Path -LiteralPath $OutputDirectory)) {
        $null = New-Item -Path $OutputDirectory -ItemType Directory -Force
    }

    $archivePath = Join-Path -Path $OutputDirectory -ChildPath "$moduleName-v$moduleVersion.zip"
    if (Test-Path -LiteralPath $archivePath) {
        Remove-Item -LiteralPath $archivePath -Force
    }

    Compress-Archive -Path (Join-Path -Path $stagingRoot -ChildPath '*') -DestinationPath $archivePath -Force

    Write-Output (Resolve-Path -LiteralPath $archivePath).Path
}
finally {
    if (Test-Path -LiteralPath $stagingRoot) {
        Remove-Item -LiteralPath $stagingRoot -Recurse -Force
    }
}
