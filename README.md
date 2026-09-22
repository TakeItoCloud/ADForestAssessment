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
| Replication | Partner metadata, failures, queue; sites, subnets, site links, connection objects; `repadmin /showrepl * /csv` cross-check (catches links the AD cmdlets miss when a partner is unreachable) |
| **Replication convergence** | `repadmin /replsummary` **parsed into findings** — the largest delta and fails/total per DSA, in both directions — plus **per-link convergence lag**: a link with **zero failures** whose last success is old is reported, because that is the silent stall where nothing errors since nothing is being attempted. An unreadable delta or last-success time is `Not Assessed`, never treated as recent |
| **Trusts** | Forest and domain trusts with per-direction secure-channel verification — outbound from the local side, **inbound executed on a partner-domain DC over WinRM** (a direction that cannot be tested from the correct side is `Not Assessed`, never `Verified`) — plus SID filtering, selective authentication, TGT delegation, encryption posture |
| Diagnostics | `dcdiag` parsed to PASS/FAIL across 17 tests (Netlogons, Services, Replications, FsmoCheck, Advertising, SysVolCheck, MachineAccount, ObjectsReplicated, RidManager, KccEvent, VerifyReferences, CrossRefValidation, KnowsOfRoleHolders, Intersite, DFSREvent, **CheckSecurityError**, **VerifyEnterpriseReferences** — the last two specifically post-restore) |
| DNS | Zones, scavenging, forwarders, zone transfer, critical SRV records, secure dynamic updates |
| **SYSVOL / DFSR** | DFSR migration state; **SYSVOL and NETLOGON share presence per DC** (SMB-unreachable is reported as unknown, never as a missing share); and the two attributes a D2/D4-equivalent rebuild edits by hand — `msDFSR-Enabled=FALSE` (replication switched off) and `msDFSR-options=1` (authoritative member), with **more than one authoritative member reported as a conflict**, which no single DC can reveal |
| **SYSVOL backlog** | Opt-in (`-IncludeSysvolBacklog`): pending SYSVOL files **in both directions** between every DC and its domain's PDC emulator. `Get-DfsrBacklog` shows at most 100 records with the true total only in its verbose stream, so where that cannot be read the figure is reported as **"at least N"**, never as a total |
| **DFS Replication events** | Per-DC DFSR log scan for dirty shutdown (2213), content freshness stop (4012), membership disabled (4114/4144), waiting for initial sync (4614) and successful initialisation (4604) — **gated on log coverage** like the Directory Service scan, and silence with no 4604 is a `Warning`, not a pass |
| Group Policy | Linked / unlinked GPOs, WMI filters, central store |
| Policy | Default and fine-grained password and lockout policy |
| Privilege | DA/EA/SA/Administrators membership, adminCount orphans, SPNs on privileged accounts, Protected Users |
| Security posture | krbtgt password age, AD Recycle Bin, tombstone lifetime, machine account quota, AdminSDHolder, stale / never-expiring / RC4-DES accounts |
| AD CS / PKI | Enrolment CAs, ESC1-susceptible certificate templates |
| Dangerous ACLs | Non-default principals holding DCSync rights on the domain head |
| Kerberos exposure | Kerberoastable (SPN) users, AS-REP-roastable accounts, delegation |
| DC hardening | Print Spooler, SMBv1, LDAP signing requirement (remote CIM / registry) |
| Resilience | Directory backup status (`repadmin /showbackup`), time sync (`w32tm`), DC count, duplicate SPNs |
| **Recovery: DNS vs AD** | DC locator SRV records compared against the DCs the directory actually contains — **on every DC's DNS server separately**, with a divergence summary ("3 of 7 answering servers advertise a DC that no longer exists"); plus the PDC locator record per server |
| **Recovery: DSA CNAMEs** | Per-DC `<DSA-GUID>._msdcs` alias verification (missing / wrong target, per DNS server) — the usual cause of RPC 1722 after metadata cleanup or restore — and orphaned NTDS Settings objects |
| **Recovery: GC consistency** | Global Catalog flag in AD vs `_gc._tcp` DNS advertisement, per DNS server |
| **Recovery: lingering objects** | Opt-in (`-IncludeLingeringObjectScan`) advisory-mode `repadmin /removelingeringobjects` pass per DC against the domain PDC — finds lingering objects before they block replication; changes nothing in the directory |
| **Recovery: port matrix** | Per-DC reachability on the replication port set (88/135/389/445 critical; 636/3268/9389 optional), separating "unresolvable" from "port closed" |
| **Recovery: secure channels** | DC machine-account password age from the replicated `pwdLastSet` (collected centrally) and per-DC `nltest /sc_verify` over WinRM where reachable |
| **Recovery: restore integrity** | `-Sections RestoreIntegrity`: the **`Dsa Not Writable` registry marker** per DC — the forensic evidence of a USN rollback that Microsoft names as the fallback when event 2095 *"may be overwritten before [it is] observed"*, so it is the one restore signal that does not depend on the event log surviving. Plus `invocationId` per DSA: a **shared value across two DCs is a cloned database** (`Fail`), and the per-DC values are emitted as a baseline so diffing `Assessment.json` between runs shows a DC that was restored in between |
| **Recovery: DS events** | Per-DC Directory Service log scan for lingering objects (1988), tombstone-lifetime exceeded (2042), USN rollback (2095), unsupported restore (2103), source-GUID DNS failures (2087/2088), KCC failures (1311/1865/1925/1084) — **gated on log coverage**: the oldest retained record is compared against the lookback window, and a clean scan over a cleared, wrapped or unreadable log reports `Not Assessed` naming where coverage begins, never `Pass`. A count taken from a partial log is reported as a minimum |
| **Recovery: dcdiag grid** | 18 parsed tests per DC, including `/test:DNS /DnsAll` (delegations, forwarders, dynamic update, record registration) and `Intersite` with the `/a` it needs to actually test anything as Pass/Fail columns. Every cell that could **not** be assessed carries its cause in the `Failures` column - the exit code, the error, and an excerpt of what dcdiag actually printed - so "Not Assessed" can never again mean "we are not telling you why". Note the verdict match is the literal English `passed test <name>`: on a non-English Windows the cells report `Not Assessed` with that named as the likely reason, rather than guessing |
| **Recovery: `_msdcs` delegation** | `-Sections MsdcsDelegation`: whether `_msdcs.<forest>` is a **zone of its own** (an SOA query answered by the *parent* zone means it is only a subdomain, which will not serve the forest-wide locator records), whether the parent holds delegation **NS** records, whether each NS target has a resolvable **glue (A)** record, and whether each NS host is a DC this run inventoried — stale NS records are what a metadata cleanup leaves behind. All four measured **per DNS server**, because the zone is AD-integrated and with replication broken the answer differs between servers |
| **Recovery: time hierarchy** | `-Sections TimeHierarchy`: every DC's time source via `w32tm /query /computer:<dc> /source`. A DC sourcing time from its **virtualisation host** is a `Warning` — per KB 976924 two time sources can make a DC's clock jump, which *"can cause lingering objects to be left in caches, and may cause replication to stop"*. The **forest root PDC emulator** must not take time from the domain hierarchy it is the top of (W32Time logs event ID 12 for that), so its source and its configured client `Type` each get a row. Where Microsoft's own guidance on host time sync diverges for the PDC, the finding names **both** positions instead of picking one |
| **Recovery: per-site GC coverage** | `-Sections SiteGc`: joins `Site`, `IsGlobalCatalog` and `IsReadOnly` — which the DC inventory already collects and nothing correlated. A site holding DCs but none that is **both writeable and a GC** is a `Warning` naming what is actually there, because Microsoft requires the AD site hosting an Exchange server to contain at least one writeable domain controller that is also a global catalog server, and an Exchange server cannot be deployed in a site containing only read-only directory servers |
| Identity export | Full user and computer export with every populated attribute (CSV; HTML shows a summary) |
| Exchange | Schema markers |
| **Exchange SE compatibility** | Forest functional level and **every DC's operating system** against the Exchange Server SE supported matrix, plus the read-only-DC caveat — from a versioned config table with a `-ExchangeSeConfigPath` override. Deliberately narrow: it does *not* cover schema/organisation object versions, Exchange server inventory or coexistence builds. The per-site writeable-GC requirement is covered separately, as an AD health check, by `-Sections SiteGc` |

Every Fail / Warning / Broken / Degraded finding in the consolidated output carries a
**best-practice remediation recommendation** (a `Recommendation` column in
`csv\Findings-Consolidated.csv`, `|| FIX:` lines in the detailed log, and the HTML lead
section). A finding with no verified guidance carries an empty value — recommendations are
mapped, never invented.

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

# Exchange Server SE compatibility only (forest functional level + DC operating systems)
.\src\ADForestAssessment\Invoke-ADForestAssessment.ps1 -Sections Forest,Domains,DomainControllers,ExchangeSeReadiness

# ...judged against your own prerequisite table instead of the built-in one
.\src\ADForestAssessment\Invoke-ADForestAssessment.ps1 -Sections ExchangeSeReadiness `
    -ExchangeSeConfigPath C:\Scripts\exchange-se-prereqs.json

# Post-incident triage: the recovery sections plus the health checks they depend on,
# including the advisory-mode lingering-object scan (writes events on target DCs, changes nothing)
# and the SYSVOL backlog (two RPC round trips per DC, read-only)
.\src\ADForestAssessment\Invoke-ADForestAssessment.ps1 -AllDomains -IncludeLingeringObjectScan -IncludeSysvolBacklog -Sections `
    DnsAdConsistency,DsaCname,GcConsistency,MsdcsDelegation,PortMatrix,Replication,Trusts,DcSecureChannel,DsEvents,RestoreIntegrity,TimeSync,TimeHierarchy,SiteGc,Sysvol,Backup
```

The report bundle lands in the logged-on user's Documents:

```text
%USERPROFILE%\Documents\AdAssessment\yyyy-MM-dd_HH-mm-ss\
    Assessment.html
    Assessment.json                 the whole run, machine-readable (see below)
    csv\Findings-Consolidated.csv   all findings, severity-sorted, with recommendations
    csv\Section-Coverage.csv        rows collected vs findings reported, per section
    csv\        one CSV per topic
    raw\        optional repadmin / dcdiag capture
    transcript
```

### `Assessment.json`

The machine-readable twin of the HTML, for diffing one run against the next — re-run the
assessment between the phases of a staged deployment and compare, rather than eyeballing two
HTML files. It carries `schemaVersion`, the tool version, the run's scope, the roll-up, every
finding with its recommendation, the section-coverage reconciliation, and every section's rows:

```text
{ schemaVersion, tool{name,version}, run{forest,generated,runBy,domainsScoped,dcCount,sectionsRun},
  summary{pass,warning,fail,notAssessed,info,unclassified,total},
  findings[], coverage[], sections{<section name>: [rows]} }
```

`summary` is self-reconciling: the buckets sum to `total`, and a status that matches none of
them lands in `unclassified` rather than going uncounted. The four named counters are the same
ones the HTML badges and the log's `Summary:` line use — note that those two do **not** count
`Info` findings (PORT-PLAN R6), which is why `info` is broken out here.

Nothing is collected for the JSON: it serialises what the run already assembled, after the
CSVs and the log are on disk, so a serialisation fault costs no data.

`Section-Coverage.csv` (and the matching panel in the HTML) reconciles what each section
collected against what it contributed to the findings. A status-bearing section showing
`FindingsReported = 0` is either pure inventory or data loss — the report says which rather
than leaving the two indistinguishable.

Off Windows it falls back to `$HOME/Documents`.

## Exchange Server SE compatibility

`-Sections ExchangeSeReadiness` answers only what the directory itself can answer:

| Gate | Supported for Exchange Server SE |
| --- | --- |
| Forest functional level | `Windows2016Forest`, `Windows2012R2Forest` — a lower level is a `Fail` |
| DC operating system, **every DC in the forest** | Windows Server 2025 / 2022 / 2019 / 2016 / 2012 R2 — one unsupported DC anywhere is a `Fail` |
| Read-only DCs | Not supported; reported as a `Warning`, since an RODC in a site no Exchange server enters does not stop Setup |

Values come from
[the supportability matrix](https://learn.microsoft.com/exchange/plan-and-deploy/supportability-matrix#supported-active-directory-environments)
(read 2026-09-21) and live in a versioned table in the script, not scattered through the code.
When Microsoft revises the matrix, override it rather than editing code:

```json
{
  "SupportedForestModes": [ "Windows2016Forest", "Windows2012R2Forest" ],
  "SupportedDomainControllerOs": [
    { "Label": "Windows Server 2025", "Pattern": "(?i)windows server\\s*2025" }
  ]
}
```

Keys you omit keep their built-in value. A missing or malformed file is a **terminating error**,
not a silent fall back to the defaults — a run that judged the forest against the wrong table
while you believed yours was in force would be worse than one that stopped. An override that
would leave a gate empty is rejected for the same reason. When an override is in force, findings
cite the file rather than Microsoft Learn.

**What this is not.** It is not an Exchange SE readiness assessment. Schema and organisation
object versions, the requirement that each Exchange site hold a writeable global catalog,
Exchange server inventory and coexistence build levels are out of scope here and belong to
`ExchangeAssessment`. The section says so in its own output rather than leaving you to infer it.

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

## Licence

ADForestAssessment is proprietary software; see [LICENSE](LICENSE) at the repository
root. No licence to use, copy, modify, or distribute it is granted by possession of a
copy — any use requires a separate written licence agreement signed by the copyright
holder. Assessment reports generated from a customer's environment contain that
customer's data and are not claimed by this licence.
