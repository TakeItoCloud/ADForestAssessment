# __TOOLNAME__ — Port Plan

## Purpose

One paragraph: what __TOOLNAME__ is being built or ported to do, what it replaces, and
what "finished" means for it. Replace this placeholder before the first phase starts —
every phase below is judged against it.

## Phases

| Phase | Scope | Status | Date |
| --- | --- | --- | --- |
| P1 | Scaffold: module, tests, lint settings, CI green on an empty tool | Planned | |
| P2 | Core read-only functionality: gather and report, no writes | Planned | |
| P3 | Packaging and first tagged release | Planned | |

## Rules

- A phase is **Done** only at GREEN: `Invoke-Pester` all-pass **and**
  `Invoke-ScriptAnalyzer -Path . -Recurse -Settings .\PSScriptAnalyzerSettings.psd1`
  with zero findings, and no stubs, placeholders, or `TODO` markers left in the code.
  Anything short of that stays `In progress`.
- Every phase updates **this file** (Status and Date on its row) and **CHANGELOG.md**
  (an entry under `## [Unreleased]`) in the same commit as the code.
- Nothing is deferred silently. Work moved out of a phase becomes a **new row** in the
  table above with its own scope and `Planned` status — it is never dropped in a comment
  or left implicit in the commit message.
- Read-only/report mode is the default. Any phase that introduces a state-changing
  operation must ship it behind `SupportsShouldProcess` and cover `-WhatIf` in tests.
- No fabricated data: sample output, fixtures, and documentation examples reflect what
  the code actually produces.
