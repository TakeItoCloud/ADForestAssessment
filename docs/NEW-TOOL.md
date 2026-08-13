# Creating a new tool from template-ps-tool

Every new PowerShell tool starts from this template. Do not scaffold one by hand.

## 1. Create the repository from the template

```powershell
gh repo create TakeItoCloud/<NewTool> --template TakeItoCloud/template-ps-tool --private --clone
```

## 2. Rename the placeholder

```powershell
cd <NewTool>
.\build\init-tool.ps1 -ToolName <NewTool>
```

`init-tool.ps1` renames `src\__TOOLNAME__` and its module files, renames the test file,
and replaces the `__TOOLNAME__` token in the content of every tracked text file. Add
`-WhatIf` first if you want to see what it would touch.

## 3. Run the quality gate

```powershell
Invoke-Pester -Output Detailed
Invoke-ScriptAnalyzer -Path . -Recurse -Settings .\PSScriptAnalyzerSettings.psd1
```

Both must be clean before the first commit.

## 4. Commit and push

```powershell
git add -A
git commit -m "Initialize <NewTool> from template"
git push
```

CI runs the same lint and test steps on the push. Confirm it is green:

```powershell
gh run list -R TakeItoCloud/<NewTool> --limit 1
```

## 5. Fill in the anchors

- `README.md` — Purpose and Usage sections describe the real tool.
- `PORT-PLAN.md` — replace the purpose placeholder and the three example phase rows with
  the actual plan.
- `CHANGELOG.md` — record work under `## [Unreleased]` as each phase lands.
- Delete `docs\NEW-TOOL.md` — this file belongs to the template, not to the new tool.
