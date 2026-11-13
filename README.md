# ADForestAssessment

## Purpose

ADForestAssessment audits an Active Directory forest end to end and reports what it could
*actually* verify. Its distinguishing feature is genuine two-way trust health: each trust
direction is verified independently through `nltest` / `netdom`, and a direction that could
not be tested from the local side is reported `Not Assessed` — never `Verified`.

The whole tool is **coverage-aware and fail-closed**: any value that could not be collected
comes back `Not Assessed`, never a false `Pass` or `0`.

The script writes nothing to the directory itself. From v1.18.0, every command it can run
that Microsoft documents as changing something, and that this project knows of, is off unless
you give its switch. That is a statement about what is known, not a guarantee: the other
commands a default run invokes have not each been audited. See
[What a run can change](#what-a-run-can-change).

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
| Diagnostics | `dcdiag` parsed to PASS/FAIL per DC, an 18-test grid. **16 run by default**: Netlogons, Services, Replications, FsmoCheck, Advertising, SysVolCheck, MachineAccount, ObjectsReplicated, RidManager, KccEvent, VerifyReferences, CrossRefValidation, KnowsOfRoleHolders, DFSREvent, **CheckSecurityError** and **VerifyEnterpriseReferences** (the last two specifically post-restore). **2 run only with `-IncludeDcdiagActiveTests`**, because they change state: Intersite and DNS (see [What a run can change](#what-a-run-can-change)) |
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
| **DC system** | `-Sections DcSystem`. **OS lifecycle**: each DC's operating system against Microsoft's extended support end date, from a versioned table. Past the date is a `Fail` whose text says whether an Extended Security Updates (ESU) programme is still running, has also ended, or was never published — and always that **ESU enrolment is not assessed**. An OS the table does not list, or one that could not be read, is `Not Assessed` with the raw values, never `Pass`. Reads only the directory, so it needs no rights on any DC. **Patch level**: per DC, OS build, uptime and the latest update install date over remote CIM. This half is **inventory** (`Info` or `Not Assessed`, never `Pass`): Microsoft publishes no maximum uptime or update age for a DC, so none is applied. Unreachable, access denied and other read failures are three different results |
| Resilience | Directory backup status (`repadmin /showbackup`), time sync (`w32tm`), DC count, duplicate SPNs |
| **Recovery: DNS vs AD** | DC locator SRV records compared against the DCs the directory actually contains — **on every DC's DNS server separately**, with a divergence summary ("3 of 7 answering servers advertise a DC that no longer exists"); plus the PDC locator record per server |
| **Recovery: DSA CNAMEs** | Per-DC `<DSA-GUID>._msdcs` alias verification (missing / wrong target, per DNS server) — the usual cause of RPC 1722 after metadata cleanup or restore — and orphaned NTDS Settings objects |
| **Recovery: GC consistency** | Global Catalog flag in AD vs `_gc._tcp` DNS advertisement, per DNS server |
| **Recovery: lingering objects** | Opt-in (`-IncludeLingeringObjectScan`) advisory-mode `repadmin /removelingeringobjects` pass per DC against the domain PDC — finds lingering objects before they block replication; changes nothing in the directory |
| **Recovery: port matrix** | Per-DC reachability on the replication port set (88/135/389/445 critical; 636/3268/9389 optional), separating "unresolvable" from "port closed" |
| **Recovery: secure channels** | DC machine-account password age from the replicated `pwdLastSet` (collected centrally) and, per DC over WinRM where reachable, the secure channel's last recorded status from `nltest /sc_query` (read-only; the live `nltest /sc_verify` test only with `-IncludeSecureChannelVerify`) |
| **Recovery: restore integrity** | `-Sections RestoreIntegrity`: the **`Dsa Not Writable` registry marker** per DC — the forensic evidence of a USN rollback that Microsoft names as the fallback when event 2095 *"may be overwritten before [it is] observed"*, so it is the one restore signal that does not depend on the event log surviving. Plus `invocationId` per DSA: a **shared value across two DCs is a cloned database** (`Fail`), and the per-DC values are emitted as a baseline so diffing `Assessment.json` between runs shows a DC that was restored in between |
| **Recovery: DS events** | Per-DC Directory Service log scan for lingering objects (1988), tombstone-lifetime exceeded (2042), USN rollback (2095), unsupported restore (2103), source-GUID DNS failures (2087/2088), KCC failures (1311/1865/1925/1084) — **gated on log coverage**: the oldest retained record is compared against the lookback window, and a clean scan over a cleared, wrapped or unreadable log reports `Not Assessed` naming where coverage begins, never `Pass`. A count taken from a partial log is reported as a minimum |
| **Recovery: dcdiag grid** | 18 columns per DC, 16 of them tested in a default run. `/test:DNS /DnsAll` (delegations, forwarders, dynamic update, record registration) and `Intersite` with the `/a` it needs to actually test anything are run only with `-IncludeDcdiagActiveTests`; without it those two cells read `Not Assessed` and the row's `NotRun` column says why. Every cell of a test that was attempted and could **not** be assessed carries its cause in the `Failures` column - the exit code, the error, and an excerpt of what dcdiag actually printed - so "Not Assessed" can never again mean "we are not telling you why". Note the verdict match is the literal English `passed test <name>`: on a non-English Windows the cells report `Not Assessed` with that named as the likely reason, rather than guessing |
| **Recovery: `_msdcs` delegation** | `-Sections MsdcsDelegation`: whether `_msdcs.<forest>` is a **zone of its own** (an SOA query answered by the *parent* zone means it is only a subdomain, which will not serve the forest-wide locator records), whether the parent holds delegation **NS** records, whether each NS target has a resolvable **glue (A)** record, and whether each NS host is a DC this run inventoried — stale NS records are what a metadata cleanup leaves behind. All four measured **per DNS server**, because the zone is AD-integrated and with replication broken the answer differs between servers |
| **Recovery: time hierarchy** | `-Sections TimeHierarchy`: every DC's **measured clock offset** via `w32tm /stripchart /rdtsc` (the one external-tool output Microsoft publishes a schema for) against the 300s Kerberos maximum, judged on the worst sample and stating that it measures divergence from the host running the assessment rather than absolute correctness; plus every DC's time source via `w32tm /query /computer:<dc> /source`. A DC sourcing time from its **virtualisation host** is a `Warning` — per KB 976924 two time sources can make a DC's clock jump, which *"can cause lingering objects to be left in caches, and may cause replication to stop"*. The **forest root PDC emulator** must not take time from the domain hierarchy it is the top of (W32Time logs event ID 12 for that), so its source and its configured client `Type` each get a row. Where Microsoft's own guidance on host time sync diverges for the PDC, the finding names **both** positions instead of picking one |
| **Recovery: per-site GC coverage** | `-Sections SiteGc`: joins `Site`, `IsGlobalCatalog` and `IsReadOnly` — which the DC inventory already collects and nothing correlated. A site holding DCs but none that is **both writeable and a GC** is a `Warning` naming what is actually there, because Microsoft requires the AD site hosting an Exchange server to contain at least one writeable domain controller that is also a global catalog server, and an Exchange server cannot be deployed in a site containing only read-only directory servers |
| Identity export | Full user and computer export with every populated attribute (CSV; HTML shows a summary) |
| Exchange | Schema markers |
| **Exchange SE compatibility** | Forest functional level (read as the numeric `msDS-Behavior-Version`, so a level above the matrix is not mistaken for one below it) and **every DC's operating system** against the Exchange Server SE supported matrix, plus the read-only-DC caveat — from a versioned config table with a `-ExchangeSeConfigPath` override. Deliberately narrow: it does *not* cover schema/organisation object versions, Exchange server inventory or coexistence builds. The per-site writeable-GC requirement is covered separately, as an AD health check, by `-Sections SiteGc` |

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
- `nltest`, `netdom`, `dcdiag`, `repadmin`, `w32tm` — optional; used where present. Not all of
  their uses are read-only: see [What a run can change](#what-a-run-can-change)
- [Pester](https://pester.dev) 5.0+ and
  [PSScriptAnalyzer](https://github.com/PowerShell/PSScriptAnalyzer) 1.21+ — for the quality gate

## Permissions

Domain read access is enough for most sections. Trust verification, remote DC hardening
checks (CIM / registry), the patch-level half of `DcSystem` (CIM) and `dcdiag` need
administrative rights on the domain controllers. The OS lifecycle half of `DcSystem` needs
domain read only.

## Usage

```powershell
.\src\ADForestAssessment\Invoke-ADForestAssessment.ps1

# Every domain in the forest
.\src\ADForestAssessment\Invoke-ADForestAssessment.ps1 -AllDomains

# Skip trust secure-channel verification
.\src\ADForestAssessment\Invoke-ADForestAssessment.ps1 -SkipTrustVerification

# Live secure channel test with nltest /sc_verify. NOT read-only: it resets a channel that is
# not working. See "Secure channel checks" below before using it.
.\src\ADForestAssessment\Invoke-ADForestAssessment.ps1 -Sections Trusts,DcSecureChannel -IncludeSecureChannelVerify

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
| Forest functional level | Windows Server 2016 (`msDS-Behavior-Version` 7) and Windows Server 2012 R2 (6). A lower level is a `Fail` that says to raise it. A **higher** level — Windows Server 2025 is 10 — is a `Fail` that says the level is not listed in the matrix, with no remediation command. An unreadable level is `Not Assessed` with its cause; a value that is not a known level is `Not Assessed` with the raw value shown |
| DC operating system, **every DC in the forest** | Windows Server 2025 / 2022 / 2019 / 2016 / 2012 R2 — one unsupported DC anywhere is a `Fail` |
| Read-only DCs | Not supported; reported as a `Warning`, since an RODC in a site no Exchange server enters does not stop Setup |

Values come from
[the supportability matrix](https://learn.microsoft.com/exchange/plan-and-deploy/supportability-matrix#supported-active-directory-environments)
(read 2026-11-12) and live in a versioned table in the script, not scattered through the code.

The forest level verdict is taken from the **number** the directory stores
(`msDS-Behavior-Version` on the Partitions container), not from the `ForestMode` name, because
only a number can tell "below the supported levels" from "above them". The name
`Get-ADForest` reports is shown for information. Each name in `SupportedForestModes` must exist
in the script's `ForestFunctionalLevels` table, which maps names to numbers; a supported mode
the table does not know is a terminating error. That table can be overridden too, to add a level
Microsoft ships later, but an override **replaces the whole table** rather than merging row by
row, so it must list every level the supported modes need.

When an override is in force, a level above the listed ones is reported as not listed in "the
supplied config table", not "the supportability matrix": the tool does not attribute your
table's verdict to Microsoft.
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

## DC operating system lifecycle and patch level

`-Sections DomainControllers,DcSystem` (or the default `All`). The lifecycle verdict reads the
operating system the `DomainControllers` section collected, so name both.

| Release | Extended support ends | ESU programme ends |
| --- | --- | --- |
| Windows Server 2025 | 2034-11-14 | not published |
| Windows Server 2022 | 2031-10-14 | not published |
| Windows Server 2019 | 2029-01-09 | not published |
| Windows Server 2016 | 2027-01-12 | 2030-01-08 |
| Windows Server 2012 R2, 2012 | 2023-10-10 | 2026-10-13 |

Dates are from the
[Windows Server release information](https://learn.microsoft.com/windows-server/get-started/windows-server-release-info)
and [Extended Security Updates FAQ](https://learn.microsoft.com/lifecycle/faq/extended-security-updates)
pages, read 2026-11-13. The end date itself counts as supported; the day after is past. The
tool does not warn ahead of a date: a DC is `Pass` until the date and `Fail` after it, and the
`Pass` text states the date.

A release is identified only when its name and its build number agree. A build number alone is
not enough: the Semi-Annual Channel release "Windows Server, version 1809" shares build 17763
with Windows Server 2019 and does not share its dates. A DC whose name and build point at
different releases, or whose name is not recognised, reports `Not Assessed` with both raw
values. Where the version carries no build, or the table lists none (2012, 2012 R2), the name
decides. Windows Server 2008 R2 and older are not in the table and report `Not Assessed`; add
them, or a release newer than this build knows, with a JSON file:

```json
{
  "OsLifecycle": [
    { "Label": "Windows Server 2025", "Build": 26100, "Pattern": "(?i)windows server\\s*2025",
      "ExtendedEnd": "2034-11-14", "EsuEnd": null }
  ]
}
```

```powershell
.\src\ADForestAssessment\Invoke-ADForestAssessment.ps1 -Sections DomainControllers,DcSystem `
    -DcSystemConfigPath C:\Scripts\dc-system.json
```

A file that supplies `OsLifecycle` replaces the whole list, so include every release you want
judged. The file must be one JSON object, and its only keys are `OsLifecycle`, `WsmanPort` and
`RpcPort`. Anything else stops the run: a missing or malformed file, a top-level array, an
empty object, a misspelt key, a `null` value, a row with a bad date or nothing to match on, or
a port that is not a port. A finding cites your file for its dates only when the file supplied
them.

The patch-level rows need local Administrators rights on each DC. They try WinRM (5985) first
and DCOM (RPC 135) second, and each DC is probed once per port. Each CIM operation is given
`-ExternalToolTimeoutSeconds` as its timeout; one DC involves up to three operations per
transport, so a DC that answers slowly on both can take several times that value. How DCOM
behaves under that timeout has not been measured. Two limits to keep in mind when reading the
rows:

- The latest update date comes from `Win32_QuickFixEngineering`, which Microsoft documents as
  listing only updates supplied by Component Based Servicing. It is the latest of those.
- That class returns install dates as text with no stated culture. A date such as `11/10/2026`
  is read only when another record from the same DC proves the day/month order; otherwise the
  row says how many records could not be read, and does not guess.

## What a run can change

Known, with Microsoft's own wording (read on Learn 2026-11-13):

| What | When | What Microsoft documents |
| --- | --- | --- |
| `dcdiag /test:DNS /DnsAll`, per DC | Only with `-IncludeDcdiagActiveTests` | The dynamic update test performs "registration of a test record (_dcdiag_test_record)... The test record is deleted automatically after the test." |
| `dcdiag /test:Intersite /a`, per DC | Only with `-IncludeDcdiagActiveTests` | Works by "reporting back any replication failures after triggering a replication." |
| `nltest /sc_verify`; `netdom trust /Verify` as its fallback | Only with `-IncludeSecureChannelVerify` | `/sc_verify`: "If the secure channel does not work, this parameter removes the existing channel, and then builds a new one." |
| `repadmin /removelingeringobjects ... /advisory_mode` | Only with `-IncludeLingeringObjectScan` | Advisory mode removes nothing; it writes events to the target DCs' Directory Service logs |
| `dcdiag /c /v` raw capture | Only with `-IncludeDcdiag` | `/c`: "Comprehensive. Runs all tests except DCPromo and RegisterInDNS, including non-default tests." By that description it includes `CutoffServers`, which "triggers replication on the DCs", **and the DNS test in the first row** |

The two `dcdiag` switches are independent. `-IncludeDcdiagActiveTests` controls the parsed
grid; `-IncludeDcdiag` controls the raw capture, and by Microsoft's description of `/c` the raw
capture runs the DNS test whether or not the other switch is given. A run with `-IncludeDcdiag`
alone therefore shows DNS as "not run" in the grid while the capture ran it.

Up to v1.17.0 the two `dcdiag` tests in the first two rows ran in every default run. From
v1.18.0 they do not: without the switch, the **DNS** and **Intersite** cells of the DC
Diagnostics grid read `Not Assessed`, each DC's row says why in its `NotRun` column and names
the switch, and the row's own status is taken from the other 16 tests. A default run therefore no longer tests DNS
dynamic update, DNS delegation and record registration through `dcdiag`, or intersite
replication. The `Dns`, `DnsDepth`, `DnsAdConsistency` and `MsdcsDelegation` sections still
read DNS without `dcdiag`.

Everything a default run does invoke is used as a query: `nltest /sc_query` and `/dsgetdc`,
`dfsrmig /getglobalstate`, `repadmin /replsummary`, `/showrepl * /csv` and `/showbackup`,
`w32tm /query` and `/stripchart`, `nslookup`, the other 16 `dcdiag` tests, and remote reads
over WinRM, CIM, the remote registry, the DNS Server cmdlets and the event log. No side effect
of those is documented by Microsoft that this project has found. They have not each been
audited; that audit is PORT-PLAN H20a.

## Secure channel checks

Three checks look at a Netlogon secure channel: the outbound direction of each trust (on the
host running the assessment), the inbound direction (on a domain controller of the trust
partner, over WinRM), and `-Sections DcSecureChannel` (on every DC of the scoped domains, over
WinRM).

| | Default | With `-IncludeSecureChannelVerify` |
| --- | --- | --- |
| Command | `nltest /sc_query` | `nltest /sc_verify` |
| Changes anything | No | **Yes, when the channel is not working** |
| What the result is | The status recorded the last time the channel was used | A live test |

Microsoft's [`nltest` reference](https://learn.microsoft.com/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc731935(v=ws.11))
(read 2026-11-13) says of `/sc_verify`: "If the secure channel does not work, this parameter
removes the existing channel, and then builds a new one." Up to v1.16.0 this tool ran
`/sc_verify` by default while calling itself strictly read-only. From v1.17.0 it does not.

What that means when you read a report:

- **A default result is not a live test.** `Verified` or `Pass` means the last recorded status
  was `NERR_Success`. A channel that has broken since it was last used can still read that way.
  Every such row says so and names the switch.
- **A v1.17.0 default result and a result from an earlier version are not the same claim.** Do
  not diff the two as if they were.
- **With the switch, the tool can repair what it reports on.** A channel that was broken before
  the run may be reported healthy because the run rebuilt it. On a forest you are assessing
  after an incident, decide deliberately whether you want that.
- The default result is read from one line of English text
  (`Trusted DC Connection Status Status = 0 0x0 NERR_Success`). On a host with another display
  language the row is `Not Assessed` and quotes what was printed.
- **`netdom` is not run by default.** `netdom trust /Verify` is a live test; it is the fallback
  for the outbound direction only when the switch is given.

## Verdict model

`Pass | Warning | Fail | Not Assessed`. Trust directions are reported per direction as
`Verified | Failed | Not Assessed`. Nothing is inferred: an untested direction is never
reported as verified, and a section that could not run is never reported as clean. By default
`Verified` for a trust direction is the secure channel's last recorded status, not a live test;
see the section above.

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
