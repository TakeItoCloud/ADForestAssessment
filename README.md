# ADForestAssessment

## Purpose

ADForestAssessment audits an Active Directory forest end to end and reports what it could
*actually* verify. Its distinguishing feature is genuine two-way trust health: each trust
direction is verified independently through `nltest` / `netdom`, and a direction that could
not be tested from the local side is reported `Not Assessed` — never `Verified`.

The whole tool is **coverage-aware and fail-closed**: any value that could not be collected
comes back `Not Assessed`, never a false `Pass` or `0`.

It is strictly read-only. No directory writes; the external verification tools are invoked
in read-only modes (`/verify`, `/sc_verify`, `/sc_query`, `getmigrationstate`).

Extracted from
`infra-scripting-suite/powershell/Assessments/ActiveDirectory/Invoke-ADForestAssessment.ps1`.

## Coverage

| Area | What it collects |
| --- | --- |
| Forest & domains | Functional levels, FSMO role holders |
| Domain controllers | OS, GC, site, IP, read-only status |
| Replication | Partner metadata, failures, queue; sites, subnets, site links, connection objects |
| **Trusts** | Forest and domain trusts with per-direction secure-channel verification, SID filtering, selective authentication, TGT delegation, encryption posture |
| Diagnostics | `dcdiag` key tests and core service state, parsed to PASS/FAIL |
| DNS | Zones, scavenging, forwarders, zone transfer, critical SRV records, secure dynamic updates |
| SYSVOL | DFSR migration state |
| Group Policy | Linked / unlinked GPOs, WMI filters, central store |
| Policy | Default and fine-grained password and lockout policy |
| Privilege | DA/EA/SA/Administrators membership, adminCount orphans, SPNs on privileged accounts, Protected Users |
| Security posture | krbtgt password age, AD Recycle Bin, tombstone lifetime, machine account quota, AdminSDHolder, stale / never-expiring / RC4-DES accounts |
| AD CS / PKI | Enrolment CAs, ESC1-susceptible certificate templates |
| Dangerous ACLs | Non-default principals holding DCSync rights on the domain head |
| Kerberos exposure | Kerberoastable (SPN) users, AS-REP-roastable accounts, delegation |
| DC hardening | Print Spooler, SMBv1, LDAP signing requirement (remote CIM / registry) |
| Resilience | Directory backup status (`repadmin /showbackup`), time sync (`w32tm`), DC count, duplicate SPNs |
| Identity export | Full user and computer export with every populated attribute (CSV; HTML shows a summary) |
| Exchange | Schema markers |

## Requirements

- **Windows PowerShell 5.1 or PowerShell 7** — the script is deliberately written with
  5.1-safe idioms so it runs on a stock domain controller *and* on pwsh 7. Do not "modernise"
  it without reading the note in [PORT-PLAN.md](PORT-PLAN.md).
- RSAT `ActiveDirectory` module — required
- `DnsServer`, `GroupPolicy`, DFSR modules — optional; their sections degrade to `Not Assessed`
- `nltest`, `netdom`, `dcdiag`, `repadmin`, `w32tm` — optional; used read-only where present
- [Pester](https://pester.dev) 5.0+ and
  [PSScriptAnalyzer](https://github.com/PowerShell/PSScriptAnalyzer) 1.21+ — for the quality gate

## Permissions

Domain read access is enough for most sections. Trust verification, remote DC hardening
checks (CIM / registry) and `dcdiag` need administrative rights on the domain controllers.

## Usage

```powershell
.\src\ADForestAssessment\Invoke-ADForestAssessment.ps1

# Every domain in the forest
.\src\ADForestAssessment\Invoke-ADForestAssessment.ps1 -AllDomains

# Skip trust secure-channel verification
.\src\ADForestAssessment\Invoke-ADForestAssessment.ps1 -SkipVerification
```

The report bundle lands in the logged-on user's Documents:

```text
%USERPROFILE%\Documents\AdAssessment\yyyy-MM-dd_HH-mm-ss\
    Assessment.html
    csv\        one CSV per topic
    raw\        optional repadmin / dcdiag capture
    transcript
```

Off Windows it falls back to `$HOME/Documents`.

## Verdict model

`Pass | Warning | Fail | Not Assessed`. Trust directions are reported per direction as
`Verified | Failed | Not Assessed`. Nothing is inferred: an untested direction is never
reported as verified, and a section that could not run is never reported as clean.

## Development

Development workflow (branching, PRs, releases): [`docs/WORKFLOW.md`](docs/WORKFLOW.md).

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

### Green gate

The commands that prove GREEN in this repository, per section 7 of
[`docs/WORKFLOW.md`](docs/WORKFLOW.md):

```powershell
Invoke-Pester -CI
Invoke-ScriptAnalyzer -Path . -Recurse -Settings .\PSScriptAnalyzerSettings.psd1
```

Both must report zero failures and zero findings. This is the default gate named in
section 7 of the workflow, run from the repository root, and it is what
[.github/workflows/ci.yml](.github/workflows/ci.yml) runs.

### The dependency-free harnesses

`tests\harness\Run-Validation.ps1` and `tests\harness\Run-SmokeTest.ps1` reproduce the
pure-logic coverage without Pester or PSScriptAnalyzer, for hosts where PSGallery is blocked.
They stub `nltest`, `netdom` and the AD cmdlets, so they never touch a real directory.

```powershell
.\tests\harness\Run-Validation.ps1
.\tests\harness\Run-SmokeTest.ps1
```

They are not `*.Tests.ps1`, so `Invoke-Pester` does not pick them up. Run them by hand.

### Original documentation

[docs/README-ADForestAssessment.md](docs/README-ADForestAssessment.md),
[docs/CHANGELOG-ADForestAssessment.md](docs/CHANGELOG-ADForestAssessment.md) and
[docs/PORT-PLAN-source.md](docs/PORT-PLAN-source.md) are the files as they stood in the
suite, kept for provenance. [PORT-PLAN.md](PORT-PLAN.md) at the root is the live plan.

Package a release artifact:

```powershell
.\build\package.ps1
```

This writes `dist\ADForestAssessment-v<version>.zip` and prints the artifact path.
