# ADForestAssessment — Port Plan

## Purpose

ADForestAssessment is the extracted, versioned home of the AD forest assessment that lived at
`infra-scripting-suite/powershell/Assessments/ActiveDirectory/Invoke-ADForestAssessment.ps1`.
It audits a forest read-only and reports only what it could verify. "Finished" means: it runs
clean against a real multi-domain forest from this repository, the analyzer suspensions below
are gone, and the return-shape fragility in P3 is closed.

The suite's own build plan — the 17-section coverage checklist, the verdict model, the
5.1-safe design note — is kept verbatim at
[docs/PORT-PLAN-source.md](docs/PORT-PLAN-source.md). All 17 sections were Done before
extraction; this plan starts from there.

## Phases

| Phase | Scope | Status | Date |
| --- | --- | --- | --- |
| P1 | Extraction onto template-ps-tool: packaging manifest, harness repointing, repo tests, CI green | Done | 2026-08-13 |
| P2 | Retire the analyzer suspensions that are real debt (see below) | Planned | |
| P3 | Fix the `return , @()` shape so an empty result is empty at any call site | Done | 2026-08-31 |
| P4 | Runtime verification against a live multi-domain forest with real trusts | Superseded by R4 | |
| P5 | Wire the dependency-free harnesses into CI as a second gate | Planned | |
| P6 | Packaging and first tagged release | Superseded by R4 | |

## Recovery track (post-incident assessment)

Added for assessing a forest during/after a restore-from-backup recovery. R0 (v1.4.0)
landed without a row in this table, breaking the rule that the plan and the changelog move
in the same commit — recorded here after the fact rather than silently.

| Phase | Scope | Status | Date |
| --- | --- | --- | --- |
| R0 | v1.4.0: six recovery sections (DNS vs AD, DSA CNAMEs, GC consistency, port matrix, DC secure channel, DS events) + recommendation engine | Done (retro-logged) | 2026-08-30 |
| R1 | v1.5.0 defects: inbound trust verified ON the partner DC (was a false local Verified); all DNS checks per-server with divergence summaries (was one resolver's view); recommendation map section-scoped (trust failures got machine-account advice); versions aligned; LICENSE added | Done | 2026-08-30 |
| R2 | Depth: dcdiag 15-test grid, repadmin `/showrepl * /csv` cross-check, `/showbackup` per DC, opt-in advisory-mode lingering-object scan | Done | 2026-08-30 |
| R2.1 | v1.5.1: render/export sections whose rows differ in shape (first live run) | Done | 2026-08-30 |
| R2.2 | v1.6.0: **silent multi-domain data loss** — 12 sections collected and discarded on any `-AllDomains` run. Closes P3 (the `return ,` idiom, root cause), adds defensive flattening, loud reporting of uninterpretable rows, per-section coverage reconciliation, and the multi-domain smoke pass that was missing | Done | 2026-08-31 |
| R3 | HTML report restructured for a recovery audience: coverage panel first, findings with evidence + recommendation + validation command, then detail sections | Planned | |
| R4 | Runtime verification against a live multi-domain forest (or a lab with a deliberately broken trust and stale _msdcs), then tag and package (absorbs P4/P6) | Planned | |

## Health & readiness track (post-ransomware recovery, Exchange SE readiness)

Added for a forest recovered from a ransomware incident that is about to take Exchange
Server SE in phases. Scope is deep AD/DC health; Exchange SE coverage is deliberately
minimal — forest/domain functional level and DC OS versions against the supported matrix,
verdict only.

| Phase | Scope | Status | Date |
| --- | --- | --- | --- |
| H1 | v1.7.0: JSON report (`Assessment.json`) with a self-reconciling summary; smoke-test SID stub fidelity | Done | 2026-09-21 |
| H2 | Event-log coverage guard: a cleared or truncated Directory Service log must report `Not Assessed`, never `Pass` | Done | 2026-09-21 |
| H3 | Empty-catch cause reporting — 7 real sites, incl. the three in `Invoke-Main`'s DC enumeration; plus `[AllowEmptyCollection()]` on the five pre-v1.4.0 per-DC collectors, which aborted the run outright when DC enumeration failed | Done | 2026-09-21 |
| H4 | `ExchangeSeReadiness`: FFL + DC OS vs the supported matrix, from a versioned config table | Done | 2026-09-21 |
| H5a | SYSVOL/DFSR depth: SYSVOL+NETLOGON share presence per DC, `msDFSR-Enabled` / `msDFSR-options` per DC with the cross-DC "exactly one authoritative" rule, and a DFS Replication event scan reusing the H2 coverage guard | Done | 2026-09-21 |
| H5b | SYSVOL **backlog** both ways against each domain's PDC emulator, opt-in via `-IncludeSysvolBacklog`. Handles `Get-DfsrBacklog`'s 100-record cap by preferring the verbose total and reporting a floor as "at least N" when it cannot be read | Done | 2026-09-21 |
| H6 | Replication convergence: parse `repadmin /replsummary` into findings; `/showutdvec` lag per DC per NC | Planned | |
| H7 | Restore integrity: the `Dsa Not Writable` registry marker (USN-rollback forensics that survive the event log being cleared), `invocationId` clone detection plus a per-DC baseline, DS events 2170/2181, dcdiag `CheckSecurityError` + `VerifyEnterpriseReferences`. `msDS-GenerationId` was dropped: nothing about it is concludable from a single read, and events 2170/2181 carry the same signal actionably | Done | 2026-09-22 |
| H8 | `_msdcs` delegation; PDC external time source and Hyper-V time-sync conflict; per-site writeable-GC assertion | Planned | |
| H9 | Forest and domain resolution guarded: an unreadable forest is now the report's headline `Fail` instead of a raw abort with no report; an unreadable current domain falls back to the forest root as a loud `Warning` naming the scope change | Done | 2026-09-21 |

| Phase | Scope | Status | Date |
| --- | --- | --- | --- |
| R5 | Runtime verification of the H-track checks against a live forest. **Operator-owned** — the build environment is Linux with no directory and no Windows PowerShell 5.1, so every AD call, `Get-WinEvent -ComputerName`, `dfsrmig` and `repadmin` path is exercised against stubs only | Planned | |
| R6 | HTML badges and the log's `Summary:` line under-count: the four counters do not match `Info`, so 17 of 123 findings on the three-domain fixture are counted nowhere. The JSON summary reconciles (v1.7.0); correcting the HTML and the log changes output already shown to people, so it is the operator's call | Planned | |

**R4 is the gate for trusting the recovery sections in production**: every R0-R2 check is
covered by pure-logic tests with stubs and CI runs on ubuntu — nothing has yet exercised
`Get-WinEvent -ComputerName`, `Invoke-Command`, `dcdiag /s:` or per-server `Resolve-DnsName`
against a real directory.

## The 5.1 constraint — read before changing anything

The assessment script is written with 5.1-safe idioms on purpose: **no `??`, no `?:`, no
ternary**, so it runs on a stock domain controller's Windows PowerShell 5.1 as well as on
pwsh 7. The manifest declares `PowerShellVersion = '5.1'` and
`CompatiblePSEditions = @('Desktop','Core')`, and `PSUseCompatibleSyntax` targets both `5.1`
and `7.4`. A test asserts all of it.

This is the one place in the extracted toolset where the house "add `#Requires -Version 7.4`"
rule is deliberately **not** applied. Running on the DC is the point.

## Backlog detail

### P2 — Analyzer suspensions

**Count correction (2026-09-21).** The table below says nine `PSAvoidUsingEmptyCatchBlock` hits
"all in the assessment script". Measured on the v1.7.0 tree there were **eleven** `catch { }`
sites, of which **seven** were real debt and four are deliberate and remain: the log append in
`Write-Log` (logging a logging failure would recurse), the `$p.Kill()` in the external-tool
timeout path (best-effort), and `Start-Transcript` / `Stop-Transcript` (host-dependent and not
worth failing a run over). H3 closed the seven. The rule stays excluded for those four.

`PSScriptAnalyzerSettings.psd1` excludes nine rules. Only some are debt; the file records the
split, and it matters because most of the volume is in the test harness, not the tool.

**Real debt, in the assessment script:**

| Rule | Hits in the script | What the fix means |
| --- | --- | --- |
| `PSAvoidUsingEmptyCatchBlock` | 9 | Every optional module or external tool degrades to `Not Assessed`, which is the fail-closed contract working as designed — but the catch should still record *why* through `Write-Log`. Right now "not installed" and "threw" are indistinguishable in the report. |
| `PSAvoidOverwritingBuiltInCmdlets` | 1 | The script defines `Write-Log`, colliding with a cmdlet present in some PowerShell profiles. |
| `PSUseShouldProcessForStateChangingFunctions` | 4 | The `New-*` functions build in-memory finding objects and write the local report bundle. Nothing touches the directory, so this is a naming artifact rather than a safety gap — but house standards still want it. |
| `PSReviewUnusedParameter` | 12 | Collectors take the shared collector parameter set for interface symmetry. Carried over from the tool's own settings, which documented exactly this. |

**Harness-only, and correct as written — do not "fix":**

`PSAvoidUsingWriteHost` (25), `PSReviewUnusedParameter` (53),
`PSAvoidAssignmentToAutomaticVariable` (3), `PSAvoidOverwritingBuiltInCmdlets` (3),
`PSAvoidUsingPlainTextForPassword` (1), `PSUsePSCredentialType` (1) and
`PSUseSingularNouns` (1) all land in `tests\harness\`. Those runners print their own results
to the console by design, stub `Import-Module` / `Start-Transcript` / `Stop-Transcript` so a
smoke run never touches the real host, and declare the real cmdlets' parameters on stubs for
signature fidelity. The credential findings are on a stub `Get-ADTrust`; no credential is
ever handled.

The clean way to close this without weakening the tool's gate is to lint `src\` and
`tests\harness\` with different settings, rather than one union of exclusions.

### P3 — `return , @()` returns one empty array, not nothing

`Get-AdfaTrustSecurityWarning` ends with `return , $warnings.ToArray()`. The comma stops a
single warning unrolling to a scalar — but in the empty case it writes *one object* (the
empty array) to the pipeline. So:

```powershell
@(Get-AdfaTrustSecurityWarning -Trust $cleanTrust).Count   # 1  <- surprising
$w = Get-AdfaTrustSecurityWarning -Trust $cleanTrust
@($w).Count                                                # 0  <- correct
```

Every caller in the script assigns first, so **the tool reports clean trusts correctly** —
verified end to end during extraction, and now covered by a test. But the contract is a trap,
and the inherited Pester file fell into it: its "returns nothing for a clean trust" case used
the first form and had been failing. That test was corrected during extraction rather than
deleted, and a second test now asserts the end-to-end verdict is `Healthy`.

Audit every `return , …` in the script and settle on one shape that is empty at any call
site.

### P4 — Runtime verification

The extraction was gated on static analysis and the pure-logic test suite. The script has not
been run against a forest from this repository. Run it against a multi-domain forest with at
least one external and one forest trust, and confirm: both trust directions verify
independently, an intentionally broken direction reports `Failed` and not `Not Assessed`,
optional modules that are absent produce `Not Assessed` sections, and the HTML plus
CSV-per-topic bundle lands in Documents.

### P5 — Harnesses in CI

`tests\harness\Run-Validation.ps1` and `Run-SmokeTest.ps1` are dependency-free by design, for
hosts where PSGallery is blocked. They are not `*.Tests.ps1`, so `Invoke-Pester` skips them
and CI never runs them today. Add a CI step that executes both and fails on a non-zero exit —
they are the gate that works everywhere, and letting them rot defeats the reason they exist.

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
- The tool stays read-only against the directory. Any phase that introduces a write must
  ship it behind `SupportsShouldProcess` and cover `-WhatIf` in tests.
- Coverage-aware and fail-closed is not negotiable: anything not collected is
  `Not Assessed`, never a false `Pass` or `0`, and an untested trust direction is never
  reported as `Verified`.
- The 5.1 floor stays until someone decides otherwise on the record.
