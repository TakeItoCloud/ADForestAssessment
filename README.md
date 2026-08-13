# __TOOLNAME__

## Purpose

__TOOLNAME__ is a PowerShell 7 tool module scaffolded from
[template-ps-tool](https://github.com/TakeItoCloud/template-ps-tool). Replace this
paragraph with what the tool actually does, who runs it, and what it reports on or
changes. Tools default to read-only/report mode; anything that writes must be opt-in
and support `-WhatIf`.

## Requirements

- PowerShell 7.4 or later (`$PSVersionTable.PSVersion`)
- [Pester](https://pester.dev) 5.0 or later — for running the test suite
- [PSScriptAnalyzer](https://github.com/PowerShell/PSScriptAnalyzer) 1.21 or later — for linting

```powershell
Install-Module Pester, PSScriptAnalyzer -Scope CurrentUser -Force
```

## Install

### For development — clone the repository

```powershell
git clone https://github.com/TakeItoCloud/__TOOLNAME__.git
Set-Location .\__TOOLNAME__
Import-Module .\src\__TOOLNAME__\__TOOLNAME__.psd1 -Force
```

### For use — download the packaged zip from GitHub Releases

```powershell
gh release download -R TakeItoCloud/__TOOLNAME__ --pattern "*.zip"
Expand-Archive -Path .\__TOOLNAME__-v0.1.0.zip -DestinationPath .\__TOOLNAME__
Import-Module .\__TOOLNAME__\__TOOLNAME__\__TOOLNAME__.psd1 -Force
```

## Usage

```powershell
PS> Get-ToolStatus

Tool         Version Timestamp
----         ------- ---------
__TOOLNAME__ 0.1.0   2026-01-01T00:00:00Z
```

## Development

Run the tests:

```powershell
Invoke-Pester
```

Run the linter:

```powershell
Invoke-ScriptAnalyzer -Path . -Recurse -Settings .\PSScriptAnalyzerSettings.psd1
```

Both must be clean — zero failing tests, zero analyzer findings — before a phase in
[PORT-PLAN.md](PORT-PLAN.md) may be marked Done. The same two commands run in CI on every
push and pull request (see [.github/workflows/ci.yml](.github/workflows/ci.yml)).

Package a release artifact:

```powershell
.\build\package.ps1
```

This writes `dist\__TOOLNAME__-v<version>.zip` and prints the artifact path.
