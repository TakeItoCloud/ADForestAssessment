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
| H6 | Replication convergence: `repadmin /replsummary` parsed into findings, and per-link lag derived from the `/showrepl * /csv` data already collected — closing a gap where a link with zero failures and a weeks-old last success reported `Pass`. **`/showutdvec` was not used**: its output format is not documented on Microsoft Learn, and the CSV already carries `Last Success Time` per link per NC in a stable format, so building verdicts on undocumented console text would have been the worse choice | Done | 2026-09-22 |
| H7 | Restore integrity: the `Dsa Not Writable` registry marker (USN-rollback forensics that survive the event log being cleared), `invocationId` clone detection plus a per-DC baseline, DS events 2170/2181, dcdiag `CheckSecurityError` + `VerifyEnterpriseReferences`. `msDS-GenerationId` was dropped: nothing about it is concludable from a single read, and events 2170/2181 carry the same signal actionably | Done | 2026-09-22 |
| H8 | `_msdcs` delegation (own-zone SOA check, delegation NS, glue, and NS hosts cross-checked against the DC inventory — all per DNS server); time hierarchy (`w32tm /query /computer:<dc> /source` per DC, the hypervisor time provider per KB 976924, and the forest root PDC's source and client `Type` against the event-ID-12 rule); per-site writeable-GC coverage, which closes the gap the H4 Exchange SE section disclaimed. `Resolve-AdfaDnsRecord` gained `NS`/`A`/`SOA`; **`SOA` is refused through the `nslookup` fallback** because its output does not label the answering zone in any documented way, and a guessed apex would turn a healthy delegation into a confident `Fail`. Where Microsoft's guidance on host time sync **diverges for the PDC**, the finding names both positions rather than picking one | Done | 2026-09-22 |
| H9 | Forest and domain resolution guarded: an unreadable forest is now the report's headline `Fail` instead of a raw abort with no report; an unreadable current domain falls back to the forest root as a loud `Warning` naming the scope change | Done | 2026-09-21 |
| H10 | A `Not Assessed` dcdiag cell recorded **no cause** - found on the first live run, where `VerifyEnterpriseReferences` was unassessed on every DC and the report could not say whether dcdiag had failed or said something unrecognised. New pure `Get-AdfaDcdiagTestOutcome` (`Pass`/`Fail`/`Unparsed`/`ToolFailed`) and `Get-AdfaDcdiagUnassessedCause`; the cause now reaches the `Failures` column and therefore the consolidated findings. The verdict is read **before** the exit code, because dcdiag exits non-zero for a failed test | Done | 2026-09-22 |
| H11 | A DNS server with **no forwarders** threw `You cannot call a method on a null-valued expression` and was reported `Not Assessed` - a measured absence presented as a failed measurement. New pure `Get-AdfaForwarderAddress`; none-configured is now `Info` with a plain statement. Two unreachable null guards were removed rather than added, because neither could be demonstrated able to fail | Done | 2026-09-22 |
| H12 | `dcdiag /test:DNS /DnsAll` added as the 18th grid test - the grid had **no DNS test at all**, on a tool built for an engagement whose stated problem is DNS. Found while implementing it: **`Intersite` was a false `Pass`**. It was invoked without `/a` or `/e`, which Learn says lets the test "run but skip actual testing", so the column has read `Pass` on every DC since the R2 grid. Both now go through a pure `Get-AdfaDcdiagArgument` so the arguments are asserted, not assumed | Done | 2026-09-22 |
| H16 | **The DC inventory asked the wrong DC.** `Get-ADComputer` was splatted `$AdParams` instead of the per-domain `$p`, so it carried no `-Server` and a child-domain DN was looked up against a forest-root DC, which answers with an LDAP referral. Every DC outside the tool's own domain lost its `OperatingSystem`, and the Exchange SE verdict called them "unverified, not compatible" - wrong for three of four domains on the live forest that found it. Also: the cause reached only the warning stream (H10's defect, missed here), and the remediation text blamed credentials for a referral. Fixed, with the field error reproduced as a smoke fixture | Done | 2026-09-26 |
| H17 | **A forest above the supported functional levels was told to raise its level.** The Exchange SE verdict tested membership of a mode-name list, so a Windows Server 2025 level forest got "Setup will not proceed until the forest functional level is raised" and `Set-ADForestMode ... Windows2016Forest`. The config comment also stated that Windows Server 2016 is the highest forest functional level ever shipped, which Learn contradicts. The verdict now reads the numeric `msDS-Behavior-Version` from the Partitions container: below = `Fail` with the raise wording, above = `Fail` as not listed in the matrix with no remediation command, unrecognised = `Not Assessed` with the raw value, unreadable = `Not Assessed` with the cause. **Run against stubs only** - see H17-R | Done | 2026-11-12 |
| H17-R | First run of the H17 forest-level read against a real forest: confirm `Get-ADObject -Identity <PartitionsContainer> -Properties msDS-Behavior-Version` returns the attribute under Windows PowerShell 5.1 on a DC, and, where a Windows Server 2025 level forest is available, that it returns 10. **Operator-owned** | Planned | |
| H18 | The raise-level recommendation says the change "is a one-way change and cannot be reverted without a forest recovery". Learn's "Lower domain and forest functional levels" page says raising a level is no longer permanent, subject to prerequisites. Only the search excerpt of that page was read during H17, so the text was left unchanged. Read the full page, then correct the wording with URL and read date. **Owner: operator to approve the new wording** | Planned | |
| H15 | Parse `dcdiag /test:DNS`'s per-category summary (Auth / Basc / Forw / Del / Dyn / RReg) instead of one overall verdict - that table is where the delegation and record-registration detail lives. `/x:<XMLLog.xml>` would give structured output and remove the localisation fragility, but **the XML schema is not published on Microsoft Learn**, so it cannot be coded to blind. Needs one real `dcdiag /test:DNS /x:` sample from a live DC first | Planned | |
| H13 | `-EventLookbackDays` parameter (1-365, default 14) feeding both event windows, which were constants with **no runtime override** - so a restore older than 14 days could not be reached without editing the script. Safe to widen because the H2 coverage guard reports `Truncated` when the window outruns the log rather than fabricating coverage | Done | 2026-09-22 |
| H14 | Measured clock **offset** per DC via `w32tm /stripchart /rdtsc` - chosen over `/monitor`, whose output format Learn does not publish. `/rdtsc` carries a **documented CSV contract** (`NtpOffset` in seconds), making it the only external-tool output in this repository whose format the vendor publishes. Vendor 300s Kerberos limit and our 60s bar kept apart and labelled as such; judged on the **worst** sample, not the mean; an unparseable sample is dropped rather than read as zero. States that it measures divergence from the host running it, not absolute correctness | Done | 2026-09-22 |

| Phase | Scope | Status | Date |
| --- | --- | --- | --- |
| R5 | Runtime verification of the H-track checks against a live forest. **First run done 2026-09-22** against a single-domain four-DC forest: it found H10 and H11, and confirmed the `_msdcs`, time-hierarchy and site-GC collectors execute. A **multi-domain** live run followed on 2026-09-26 against a four-domain forest and immediately found H16, a cross-domain referral that broke the Exchange SE verdict in three of four domains - the single highest-value finding of the whole track, and unreachable from any single-domain run or fixture. Still outstanding, the lingering-object scan (opt-in, not exercised), and a non-English Windows (every console-text parser matches English verdict strings). **Operator-owned** — the build environment is Linux with no directory and no Windows PowerShell 5.1, so every AD call, `Get-WinEvent -ComputerName`, `dfsrmig`, `repadmin`, `w32tm /query /computer:` and per-server `Resolve-DnsName` path is exercised against stubs only. Two H8 paths need naming specifically: (a) `w32tm /query /configuration` — the KEY names are published but the **line format is not**, so `ConvertFrom-AdfaW32tmConfiguration` is tolerant by design and reports `Not Assessed` on a non-match; the first live run must confirm the parse actually matches, or the root PDC client-type row will read `Not Assessed` everywhere. (b) `Resolve-DnsName -Type SOA` against a delegated child zone — the apex-comparison logic is tested against fixtures, but that the real cmdlet surfaces the **parent** apex for a non-delegated subdomain is asserted from vendor documentation, not measured | Planned | |
| R6 | HTML badges and the log's `Summary:` line under-count: the four counters do not match `Info`, so 17 of 123 findings on the three-domain fixture are counted nowhere. The JSON summary reconciles (v1.7.0); correcting the HTML and the log changes output already shown to people, so it is the operator's call | Planned | |

## Coverage track (gaps against the AdAssessment26 finding catalogue)

**Approved by the operator 2026-11-13, scope and order as listed.** Source:
[docs/GAP-ANALYSIS.md](docs/GAP-ANALYSIS.md), which maps all 89 catalogue rows to this tool
(15 Covered, 44 Partly, 30 Missing) with evidence per row. One row per group of checks; one
branch and one pull request per row. C1 to C8 are in the operator's stated priority order; C9 to
C15 are the remainder in a proposed order.

Every check built under this track runs against stubs only until C17, and each changelog entry
must say so. Vendor facts are re-read on Microsoft Learn in the session that builds the check;
the reference repository's recorded facts are a starting point, not a source.

| Phase | Scope | Status | Date |
| --- | --- | --- | --- |
| C1 | v1.16.0: new `-Sections DcSystem`. **OS lifecycle** per DC from the directory against a versioned table of Microsoft extended-support and ESU end dates (read 2026-11-13), with a `-DcSystemConfigPath` override: past extended support is `Fail`, stating whether an ESU programme is running, ended or unpublished and that enrolment is not assessed; an unlisted or unreadable OS is `Not Assessed` with the raw values. **Patch level** per DC over remote CIM (build, uptime, latest update install date) as inventory only - by operator decision no threshold is applied, because Microsoft publishes none. Adds a per-run port-probe cache so a DC is probed once per port. Catalogue: OSL-001, INV-003. **Run against stubs only** - first real run is C17 | Done | 2026-11-13 |
| C1a | Update revision within the build (the fourth part of a version such as 17763.9487) is not read by C1: `Win32_OperatingSystem` does not carry it, and the registry value that does was not verified on Microsoft Learn. Verify the value name and meaning on Learn, then add it to the `DcSystem` patch-level row. **Owner: operator to confirm it is wanted** | Planned | |
| C1b | Existing per-DC sections (`DcHardening`, `RestoreIntegrity`, `PortMatrix` and others) still probe each DC themselves; only `DcSystem` uses the shared probe cache added in C1. Move them onto `Test-AdfaDcPort` as each is touched by C3 and later rows, not as one sweep | Planned | |
| C2 | Free disk space on the NTDS database, NTDS log and SYSVOL volumes. Catalogue: DISK-001. New section `DcDisk` | Planned | |
| C3 | LDAP channel binding, LDAP signing enforcement, SMB server and client signing, LmCompatibilityLevel. Catalogue: LDAP-001..003, SMB-001..002, NTLM-001, INV-019. Section: `DcHardening` | Planned | |
| C4 | Windows LAPS: DSRM password management, and enabled non-DC computers without LAPS. Catalogue: LAPS-001..002. New section `Laps` | Planned | |
| C5 | Domain controller certificate inventory and expiry. Catalogue: CERT-001, INV-020. New section `DcCertificates` | Planned | |
| C6 | RID pool: allocation enabled, global RID space consumed, per-DC pool. Catalogue: RID-001..002, INV-004. New section `RidPool` | Planned | |
| C7 | SIDHistory populated. Catalogue: OBJ-009. Section: `SecurityPosture` | Planned | |
| C8 | GPO version in AD versus GPT.INI in SYSVOL. Catalogue: GPO-001. Section: `Gpo` | Planned | |
| C9 | Dangerous rights: the domain root rule and a SID allowlist in place of name matching, AdminSDHolder, GPOs. Catalogue: ACL-001..003. Section: `Acl` | Planned | |
| C10 | Privileged groups and delegation: Schema and Enterprise Admins rule, adminCount orphans, constrained delegation, protocol transition, RBCD, SPN on privileged accounts. Catalogue: PRIV-001..002, OBJ-001..004, OBJ-006, INV-005, INV-017. Sections: `PrivilegedAccounts`, `PrivilegedHygiene`, `Kerberos` | Planned | |
| C11 | dcdiag tests not in the grid, and the per-partition and per-scope verdict rule. Catalogue: DCDIAG-001, 008, 009; REPL-001, 004, 006..010; SYSVOL-002..003. Section: `DcDiagnostics` | Planned | |
| C12 | dcdiag DNS per-category results. Catalogue: DNSDIAG-001..007. **Overlaps H15** - merge the two rows rather than run both | Planned | |
| C13 | DNS: dynamic update, scavenging, locator SRV, DC A records, records naming absent DCs; zone configuration, record export, DC DNS client servers. Catalogue: DNS-001..005, INV-013, 014, 016. Sections: `Dns`, `DnsAdConsistency`, `DomainControllers`, new `DnsRecordExport` | Planned | |
| C14 | Reachability classes, subnets without a site, clock offset reference, stale enabled objects, SYSVOL replication engine. Catalogue: REACH-001..002, SITE-001, TIME-001, STALE-001..002, SYSVOL-004 | Planned | |
| C15 | Inventory depth: topology, trusts, suffixes, object counts, stale disabled objects, groups, GPOs, events, w32tm configuration. Catalogue: INV-001, 006..012, 015 | Planned | |
| C16 | Triage of the 30 promises the README and help text make that the code does not keep (table in docs/GAP-ANALYSIS.md): for each, fix the code, fix the wording, or accept. Several read as defects in shipped checks, among them `Get-AdfaDfsrSubscription` reading a property no inventory row carries, and the README's `-SkipVerification` example naming a parameter that does not exist. One claim, that `nltest /sc_verify` is not read-only, rests on a vendor fact that could not be verified when the analysis was written and must be read on Microsoft Learn first. **Owner: operator** | Planned | |
| C17 | First run against a real forest of every check added under C1 to C15. **Owner: operator** | Planned | |

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
