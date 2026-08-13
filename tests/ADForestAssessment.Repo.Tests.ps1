#Requires -Version 5.1
<#
.SYNOPSIS
    Repository-contract tests added when the tool was extracted onto template-ps-tool.
.DESCRIPTION
    Invoke-ADForestAssessment.Tests.ps1 covers the tool's own logic and came across from
    infra-scripting-suite. This file covers the things the extraction introduced: the
    packaging manifest, the layout the harnesses depend on, and the repository-wide
    analyzer gate.
#>

BeforeAll {
    $script:RepoRoot = Split-Path -Parent $PSScriptRoot
    $script:ToolRoot = Join-Path $script:RepoRoot 'src/ADForestAssessment'
    $script:ManifestPath = Join-Path $script:ToolRoot 'ADForestAssessment.psd1'
    $script:ScriptPath = Join-Path $script:ToolRoot 'Invoke-ADForestAssessment.ps1'
    $script:SettingsPath = Join-Path $script:RepoRoot 'PSScriptAnalyzerSettings.psd1'
}

Describe 'Packaging manifest' {

    It 'passes Test-ModuleManifest' {
        $script:ManifestPath | Should -Exist
        { Test-ModuleManifest -Path $script:ManifestPath -ErrorAction Stop } | Should -Not -Throw
    }

    It 'lists the assessment script in FileList' {
        (Import-PowerShellDataFile -Path $script:ManifestPath).FileList | Should -Contain 'Invoke-ADForestAssessment.ps1'
    }

    It 'exports nothing - this is a script tool, not a module' {
        $manifest = Import-PowerShellDataFile -Path $script:ManifestPath
        $manifest.FunctionsToExport | Should -BeNullOrEmpty
        $manifest.RootModule | Should -BeNullOrEmpty
    }

    It 'still declares PowerShell 5.1 so the script runs on a stock domain controller' {
        $manifest = Import-PowerShellDataFile -Path $script:ManifestPath
        $manifest.PowerShellVersion | Should -Be '5.1'
        $manifest.CompatiblePSEditions | Should -Contain 'Desktop'
        $manifest.CompatiblePSEditions | Should -Contain 'Core'
    }

    It 'keeps the script itself on the 5.1 floor' {
        Get-Content -Path $script:ScriptPath -Raw | Should -Match '(?im)^#requires\s+-version\s+5\.1'
    }
}

Describe 'Repository layout' {

    It 'places the assessment script where the manifest and harnesses expect it' {
        $script:ScriptPath | Should -Exist
    }

    It 'ships the dependency-free harnesses' -ForEach @(
        @{ Name = 'Run-Validation.ps1' }
        @{ Name = 'Run-SmokeTest.ps1' }
    ) {
        Join-Path $PSScriptRoot "harness/$Name" | Should -Exist
    }

    It 'points every harness at the extracted script path' -ForEach @(
        @{ Name = 'Run-Validation.ps1' }
        @{ Name = 'Run-SmokeTest.ps1' }
    ) {
        $harness = Join-Path $PSScriptRoot "harness/$Name"
        $resolved = [regex]::Match((Get-Content -Path $harness -Raw), "Join-Path[^\r\n]*'(?<rel>src/ADForestAssessment/Invoke-ADForestAssessment\.ps1)'")
        $resolved.Success | Should -BeTrue -Because "$Name must resolve the script at its extracted location"
        Join-Path $script:RepoRoot $resolved.Groups['rel'].Value | Should -Exist
    }
}

Describe 'Static analysis' {

    It 'reports no PSScriptAnalyzer findings for the repository' {
        $script:SettingsPath | Should -Exist

        $findings = Invoke-ScriptAnalyzer -Path $script:RepoRoot -Recurse -Settings $script:SettingsPath
        $report = ($findings | Format-Table -AutoSize | Out-String)

        $findings.Count | Should -Be 0 -Because "PSScriptAnalyzer reported:`n$report"
    }
}
