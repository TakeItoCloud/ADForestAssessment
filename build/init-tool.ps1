#Requires -Version 7.4

<#
.SYNOPSIS
    Renames the template placeholder to the real tool name.

.DESCRIPTION
    Run once, immediately after creating a repository from template-ps-tool. Renames every
    file and folder whose name contains the placeholder token, then replaces the token in
    the content of every tracked text file. Supports -WhatIf.

.EXAMPLE
    PS> .\build\init-tool.ps1 -ToolName ContosoAudit -WhatIf

    Shows every rename and rewrite that would happen, without changing anything.

.EXAMPLE
    PS> .\build\init-tool.ps1 -ToolName ContosoAudit

    Renames the module folder, module files and test file, rewrites the token everywhere,
    and prints the next steps.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    # PascalCase name of the new tool, e.g. ContosoAudit. Also the module and repo name.
    [Parameter(Mandatory)]
    [ValidatePattern('^[A-Za-z][A-Za-z0-9]+$')]
    [string]$ToolName
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Assembled from parts so this script does not rewrite its own token definition.
$token = '__' + 'TOOLNAME' + '__'

$repoRoot = Split-Path -Path $PSScriptRoot -Parent
Write-Verbose -Message "Repository root: $repoRoot"

$textExtensions = @('.md', '.ps1', '.psm1', '.psd1', '.yml', '.yaml', '.json', '.txt', '.xml', '.editorconfig')
$textFileNames = @('.gitignore', '.gitattributes', 'LICENSE')
$skipDirectories = @('.git', 'dist')

function Test-IsTextFile {
    param([Parameter(Mandatory)][System.IO.FileInfo]$File)

    return ($textExtensions -contains $File.Extension.ToLowerInvariant()) -or
           ($textFileNames -contains $File.Name)
}

function Get-CandidateItem {
    param([switch]$Directory)

    $items = if ($Directory) {
        Get-ChildItem -LiteralPath $repoRoot -Recurse -Force -Directory
    }
    else {
        Get-ChildItem -LiteralPath $repoRoot -Recurse -Force -File
    }

    $items |
        Where-Object {
            $relative = $_.FullName.Substring($repoRoot.Length).TrimStart([System.IO.Path]::DirectorySeparatorChar)
            $head = ($relative -split '[\\/]')[0]
            $skipDirectories -notcontains $head
        }
}

# --- 1. Take the tracked-file list BEFORE renaming, so the git index still matches the disk.
$trackedPaths = @()
$gitOutput = & git -C $repoRoot ls-files 2>$null
if ($LASTEXITCODE -eq 0 -and $gitOutput) {
    $trackedPaths = @($gitOutput | ForEach-Object { Join-Path -Path $repoRoot -ChildPath $_ })
}

if ($trackedPaths.Count -eq 0) {
    Write-Verbose -Message 'No git index available; falling back to a filesystem scan.'
    $trackedPaths = @(Get-CandidateItem | ForEach-Object { $_.FullName })
}

# --- 2. Rename files and folders (deepest first, so parent renames do not invalidate paths).
$itemsToRename = @(
    @(Get-CandidateItem) + @(Get-CandidateItem -Directory) |
        Where-Object { $_.Name -like "*$token*" } |
        Sort-Object -Property { $_.FullName.Length } -Descending
)

if ($itemsToRename.Count -eq 0) {
    Write-Warning -Message "No file or folder name contains '$token'. Has this repository already been initialized?"
}

foreach ($item in $itemsToRename) {
    $newName = $item.Name.Replace($token, $ToolName)
    if ($PSCmdlet.ShouldProcess($item.FullName, "Rename to '$newName'")) {
        Rename-Item -LiteralPath $item.FullName -NewName $newName -Force
    }
    else {
        Write-Verbose -Message "Would rename '$($item.FullName)' to '$newName'."
    }
}

# --- 3. Replace the token in file content, following the renames applied above.
$rewritten = 0
foreach ($trackedPath in $trackedPaths) {
    # The step above may have moved this file; the new path is the old one with the token
    # substituted. Under -WhatIf nothing moved, so fall back to the original path.
    $currentPath = $trackedPath.Replace($token, $ToolName)
    if (-not (Test-Path -LiteralPath $currentPath -PathType Leaf)) {
        $currentPath = $trackedPath
    }
    if (-not (Test-Path -LiteralPath $currentPath -PathType Leaf)) { continue }

    $file = Get-Item -LiteralPath $currentPath
    if (-not (Test-IsTextFile -File $file)) { continue }

    $content = Get-Content -LiteralPath $file.FullName -Raw
    if ([string]::IsNullOrEmpty($content) -or -not $content.Contains($token)) { continue }

    if ($PSCmdlet.ShouldProcess($file.FullName, "Replace '$token' with '$ToolName'")) {
        Set-Content -LiteralPath $file.FullName -Value $content.Replace($token, $ToolName) -NoNewline -Encoding utf8NoBOM
        $rewritten++
    }
    else {
        Write-Verbose -Message "Would rewrite '$($file.FullName)'."
    }
}

Write-Information -MessageData "Renamed $($itemsToRename.Count) path(s); rewrote $rewritten file(s)." -InformationAction Continue
Write-Information -MessageData '' -InformationAction Continue
Write-Information -MessageData 'Next steps:' -InformationAction Continue
Write-Information -MessageData "  1. Invoke-Pester -Output Detailed" -InformationAction Continue
Write-Information -MessageData "  2. Invoke-ScriptAnalyzer -Path . -Recurse -Settings .\PSScriptAnalyzerSettings.psd1" -InformationAction Continue
Write-Information -MessageData "  3. Fill in Purpose in README.md and PORT-PLAN.md, then delete docs\NEW-TOOL.md" -InformationAction Continue
Write-Information -MessageData "  4. git add -A; git commit -m 'Initialize $ToolName from template'; git push" -InformationAction Continue
