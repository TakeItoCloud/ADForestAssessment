#Requires -Version 7.4
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

BeforeAll {
    $script:RepoRoot = Split-Path -Path $PSScriptRoot -Parent
    $script:SourceRoot = Join-Path -Path $script:RepoRoot -ChildPath 'src'
    $script:ManifestPath = Join-Path -Path $script:SourceRoot -ChildPath '__TOOLNAME__/__TOOLNAME__.psd1'
    $script:SettingsPath = Join-Path -Path $script:RepoRoot -ChildPath 'PSScriptAnalyzerSettings.psd1'
    $script:ModuleName = '__TOOLNAME__'
}

AfterAll {
    Remove-Module -Name $script:ModuleName -Force -ErrorAction SilentlyContinue
}

Describe '__TOOLNAME__' {

    Context 'Module import' {

        It 'has a manifest that passes Test-ModuleManifest' {
            $script:ManifestPath | Should -Exist
            { Test-ModuleManifest -Path $script:ManifestPath -ErrorAction Stop } | Should -Not -Throw
        }

        It 'imports from the manifest path without error' {
            { Import-Module -Name $script:ManifestPath -Force -ErrorAction Stop } | Should -Not -Throw
            Get-Module -Name $script:ModuleName | Should -Not -BeNullOrEmpty
        }
    }

    Context 'Get-ToolStatus' {

        BeforeAll {
            Import-Module -Name $script:ManifestPath -Force -ErrorAction Stop
        }

        It 'is exported by the module' {
            $command = Get-Command -Name 'Get-ToolStatus' -Module $script:ModuleName -ErrorAction SilentlyContinue
            $command | Should -Not -BeNullOrEmpty
            $command.CommandType | Should -Be 'Function'
        }

        It 'returns an object exposing Tool, Version and Timestamp' {
            $status = Get-ToolStatus
            $status | Should -BeOfType ([pscustomobject])

            $names = $status.PSObject.Properties.Name
            $names | Should -Contain 'Tool'
            $names | Should -Contain 'Version'
            $names | Should -Contain 'Timestamp'
        }

        It 'reports the module name and the manifest version' {
            $status = Get-ToolStatus
            $expectedVersion = (Import-PowerShellDataFile -Path $script:ManifestPath).ModuleVersion

            $status.Tool | Should -Be $script:ModuleName
            $status.Version | Should -Be $expectedVersion
        }

        It 'reports a UTC ISO 8601 timestamp' {
            (Get-ToolStatus).Timestamp | Should -Match '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$'
        }
    }

    Context 'Static analysis' {

        It 'reports no PSScriptAnalyzer findings under src' {
            $script:SettingsPath | Should -Exist

            $findings = Invoke-ScriptAnalyzer -Path $script:SourceRoot -Recurse -Settings $script:SettingsPath
            $report = ($findings | Format-Table -AutoSize | Out-String)

            $findings.Count | Should -Be 0 -Because "PSScriptAnalyzer reported:`n$report"
        }
    }
}
