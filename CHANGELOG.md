# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

The tool's own changelog from before the extraction is kept at
[docs/CHANGELOG-ADForestAssessment.md](docs/CHANGELOG-ADForestAssessment.md).

## [Unreleased]

### Added — 2026-09-22 (restore integrity that survives a cleared event log, tool v1.9.0)

Every restore-integrity signal the tool had came from the Directory Service log. On a forest
recovered from a ransomware incident that log is exactly what cannot be trusted — v1.7.0 stopped
the tool *reporting `Pass`* from a wiped log, but it could still only say "unassessed". This adds
a signal that does not depend on the log at all.

**The `Dsa Not Writable` registry marker.** Microsoft documents event 2095 as the USN-rollback
signal, then says plainly that it *"may be overwritten before [it is] observed by an
administrator"* and names the fallback:

> `HKLM\System\CurrentControlSet\Services\NTDS\Parameters` → `Dsa Not Writable = 0x4`
> "provides forensic evidence that a USN rollback has occurred"

— [detect and recover from USN rollback](https://learn.microsoft.com/troubleshoot/windows-server/active-directory/detect-and-recover-from-usn-rollback),
[safely virtualizing AD DS](https://learn.microsoft.com/windows-server/identity/ad-ds/introduction-to-active-directory-domain-services-ad-ds-virtualization-level-100) (read 2026-09-21).

Read per DC over remote registry, the same mechanism the DC-hardening checks already use, against
the same NTDS key. Value 4 → `Fail`, naming the quarantine that follows (Net Logon paused, inbound
and outbound replication disabled) and warning that deleting the value removes the quarantine and
permanently diverges the DC. An undocumented value → `Warning`, reported as found rather than
interpreted. Unreadable → `Not Assessed`.

Absence is a `Pass` **with its limit stated**: no marker means no forensic evidence of a rollback
*on this operating-system installation*, which is not the same as proving none ever happened — a
DC rebuilt after an incident carries no history either way. A test asserts the wording does not
claim health.

**`invocationId`, and exactly one conclusion drawn from it.** The attribute identifies the
*instantiation* of a DC's database; a supported restore resets it, an unsupported one does not.
From a single read one thing is safe to conclude and it is worth having: **two DSAs sharing an
invocationId means one database was cloned from the other** — a copied VHD, disk image, or a P2V
whose original kept running — so every replication partner believes both DCs already hold each
other's changes and originating updates on either can be dropped with no replication error at all.
That is a `Fail`.

What is deliberately **not** claimed: a rollback cannot be detected from one read, because that
needs the value compared with a previous one. So the per-DC values are emitted as an `Info`
baseline, which is what makes the v1.7.0 JSON output pay off — re-run before and after a change
window, diff `Assessment.json`, and an `invocationId` that moved means that DC was restored in
between. The passing finding says this rather than implying the check rules a rollback out.

**Also:** Directory Service events **2170** (VM-Generation ID change) and **2181** (VM reverted)
added with vendor-sourced meanings — 2170 is the *safe* path, where the hypervisor supplied a new
generation ID and AD reset its own invocation ID and RID pool, but it still means a snapshot was
applied to a DC. And dcdiag gains **`CheckSecurityError`** and **`VerifyEnterpriseReferences`**,
the two post-restore tests, taking the grid from 15 to 17.

**`msDS-GenerationId` was considered and dropped.** Nothing about it is concludable from a single
point-in-time read, and events 2170/2181 carry the same signal in an actionable form. Adding an
attribute the tool could only echo would have looked like coverage without being any.

### Fixed — 2026-09-22 (remediation advised a retired demotion command, tool v1.9.0)

The USN-rollback remediation advised `dcpromo /forceremoval`. That is the Windows 2000 / Server
2003 era command — the KB documenting it is scoped to those releases — and it does not exist on
any OS this tool supports (WS2012 R2 and later, per the Exchange SE matrix the tool itself
encodes). Replaced with `Uninstall-ADDSDomainController -ForceRemoval -DemoteOperationMasterRole`
([ADDSDeployment](https://learn.microsoft.com/powershell/module/addsdeployment/uninstall-addsdomaincontroller),
read 2026-09-21), plus what the vendor says around it: forced demotion discards every change that
originated on that DC and had not replicated out, and metadata cleanup must follow immediately.

A test asserts no entry in the recommendation map advises the retired command — checked against
the advice text rather than the file, so the comment recording why it changed can stay.


### Added — 2026-09-21 (SYSVOL backlog, opt-in, tool v1.8.0)

`-IncludeSysvolBacklog` measures pending SYSVOL files **in both directions** between every DC and
its domain's PDC emulator — the DC where Group Policy edits are normally written, and therefore
the one the others should be catching up with. Both directions are measured because a backlog
*to* the PDC and one *from* it are different faults and testing one would miss half of them.

Opt-in, because it costs two RPC round trips per DC and needs the optional DFSR module. Absent
module, unreachable DC or failed call all report `Not Assessed` with the cause, never zero.

**The trap this check exists to avoid.** `Get-DfsrBacklog` returns **at most 100 records**, and
the true total appears only in its verbose stream
([docs](https://learn.microsoft.com/powershell/module/dfsr/get-dfsrbacklog), read 2026-09-21). So
the obvious implementation — count the returned objects — silently reports **a floor as if it
were a total**: a backlog of 2,400 and one of exactly 100 look identical. The verbose stream is
captured and parsed for the real figure, anchored on the vendor's documented wording so an
unrelated verbose line cannot be misread as a count. Where it cannot be read, the finding says
**"at least 100"** and states plainly that the true figure may be far higher. A test pins that an
exact figure carries no such caveat, so the wording stays meaningful.

Thresholds are **ours, not the vendor's, and the finding says so.** Microsoft states a backlog
"is not necessarily an indication of problems" and "indicates latency". The tighter bar applied
here is reasoned rather than borrowed: SYSVOL changes only when Group Policy changes, so it should
sit at or near zero, and a standing backlog means a policy edit is not reaching that DC. Both
thresholds live in the config table so an operator can move them without touching code, and the
`Fail` threshold is set at the cmdlet's own 100-record cap — the point beyond which the true size
stops being observable from the object count at all.

Demonstrated able to fail: marking an at-cap count as exact turns the floor assertion red.
Restored byte-for-byte, hash verified.


### Added — 2026-09-21 (SYSVOL/DFSR depth: shares, subscription state, DFSR events, tool v1.8.0)

The SYSVOL section was one check — `dfsrmig /getglobalstate` — which says whether the domain
migrated to DFSR years ago and nothing about whether SYSVOL is replicating *now*. Divergent or
unshared SYSVOL after a restore is silent, breaks Group Policy delivery, and nothing here
detected it.

**SYSVOL and NETLOGON share presence, per DC.** The vendor's own first diagnostic for broken
SYSVOL replication: DFSR does not share SYSVOL until the replicated folder has initialised, so a
DC that never logged event 4604 silently serves no policy. SMB (445) is probed first, so an
unreachable DC is `Not Assessed` — never reported as a missing share, and never as healthy.

**The two attributes a D2/D4-equivalent rebuild edits by hand**, per
[KB 2218556](https://learn.microsoft.com/troubleshoot/windows-server/group-policy/force-authoritative-non-authoritative-synchronization)
(read 2026-09-21), on each DC's `CN=SYSVOL Subscription,CN=Domain System Volume,CN=DFSR-LocalSettings,…`:

| State | Verdict |
| --- | --- |
| `msDFSR-Enabled=FALSE` | `Fail` — SYSVOL replication is switched off on that DC; only ever set by hand, so a rebuild was started and not finished |
| `msDFSR-options=1` on **more than one** DC | `Fail` — the procedure marks exactly one member authoritative; two means SYSVOL content depends on which initialises first |
| `msDFSR-options=1` on exactly one DC | `Warning` — expected during a deliberate rebuild, unexpected otherwise |

The conflict case is why this is a **domain-wide** verdict rather than a per-DC one: "exactly one
member is authoritative" cannot be checked by looking at any single DC. Neither attribute appeared
anywhere in this report before, and both are easy to leave behind after a recovery.

**A DFS Replication event scan**, gated on log coverage by reusing the guard added for the
Directory Service log — the coverage classifier and its caveat wording are now log-agnostic rather
than duplicated. Events and meanings are taken from the vendor's troubleshooting articles, not
inferred: 2213 (dirty shutdown, replication paused), 4012 (content freshness stop), 4114/4144
(membership disabled), 4614 (waiting for initial sync), 4604 (initialised — the healthy end
state), plus 2212/2214 and 5002/5014. Events whose meaning the vendor does not publish are absent
rather than guessed.

Note the deliberate asymmetry with the Directory Service scan: **finding no DFSR events is a
`Warning`, not a `Pass`**, even over a fully covered window. SYSVOL health is proven by seeing
4604, not by silence.

**Remediation routes each failure to its own fix.** The pre-existing generic `sysvol|dfsr` entry
answered everything with "perform a D4"; reinitialising is the vendor's last resort — unnecessary
in most cases and able to lose data. A dirty shutdown now routes to the `ResumeReplication` WMI
method, content freshness to non-authoritative recovery fanning out from a healthy DC (naming the
one case where authoritative is correct: every DC logged 4012), a conflict to deciding which DC
holds the content worth keeping, and missing shares to reading the DFSR log *before* rebuilding
anything. Tests pin that these do not bleed into one another.

Both new guards were demonstrated able to fail: classifying an unreachable DC as `Shared` turns
two assertions red, and treating two authoritative members as one turns another red. Restored
byte-for-byte after each, hash verified.

**Backlog is deliberately not here** — split out as plan row **H5b**. It needs the optional DFSR
module and O(n) member pairs, and `Get-DfsrBacklog` caps its output at 100 records with the true
count only in the verbose stream, so a naive count would report a floor as a total. Microsoft also
states a backlog "is not necessarily an indication of problems", so the verdict needs thought
rather than a threshold picked here.


### Fixed — 2026-09-21 (an unreadable forest aborted the run with no report, tool v1.8.0)

`Invoke-Main` called `Get-ADForest` and `Get-ADDomain` **unguarded** while resolving which
domains to scope, before any section ran. A forest that could not be contacted killed the run
with a raw exception and produced **no report at all** — on a damaged or partly-recovered forest,
which is the case this tool exists for, the operator got a stack trace instead of an artefact
naming the cause. Recorded as PORT-PLAN H9 when the H3 harness had to be narrowed around it.

Both calls are now guarded and the failure becomes the report's **headline finding**:

- **Forest unreadable** → a `Fail` row leading the report, carrying the underlying error and
  saying plainly that nothing in the report was assessed, plus what to check (ADWS 9389, LDAP
  389, credentials, `-Server` pointed at a known-healthy DC). Every section then degrades around
  it, which is only possible because the collectors were made to tolerate an empty domain and DC
  list in the preceding change.
- **Current domain unreadable but the forest readable** → the run falls back to the forest root
  domain, which is a genuine recovery on a damaged forest. Because it **changes the scope**, it is
  a `Warning` row naming the substitution and telling the reader to confirm it was the intended
  domain — never done quietly.
- **Forest readable but reporting no domains** → a `Fail` row, rather than a run that silently
  assesses nothing.
- `Import-Module ActiveDirectory` still terminates, since without it there is no directory access
  and nothing to report on, but it now names the requirement instead of surfacing a raw
  module-load error.

A fourth smoke-test scenario runs `Invoke-Main` with `Get-ADForest` throwing and asserts the run
completes, the HTML/JSON/CSV bundle still lands, the failure is a single `Fail` headline carrying
its cause — and the property that matters, that **nothing reports `Pass` when nothing could be
read**. Measured: 18 findings, 0 passes. Before this change the same scenario produced no report.

Demonstrated able to fail: removing the guard reproduces the original abort and turns two
assertions red. Restored byte-for-byte, hash verified.


### Fixed — 2026-09-21 (collection failures were swallowed; a failed DC enumeration aborted the run, tool v1.7.0)

Seven `catch { }` blocks discarded the reason a collector failed, so "not installed", "access
denied" and "it threw" were indistinguishable from a clean result. Each now reports its cause.
Four remain and are deliberate: the log append in `Write-Log` (logging a logging failure would
recurse), `$p.Kill()` in the external-tool timeout path, and `Start-Transcript` /
`Stop-Transcript`.

| Site | Was | Now |
| --- | --- | --- |
| DNS forwarders | the forwarders row vanished | `Not Assessed` naming the error |
| Fine-grained password policies | no row at all — indistinguishable from "none exist" | `Not Assessed` saying absence was not measured |
| Lingering-object scan | verdict already fail-closed, but the cause was lost | names whether the DSA inventory threw or simply had no match |
| DSA inventory | a DC with an unreadable host name became a silent blank that would not correlate with the DNS checks | logged, naming the DSA and the consequence |
| DC enumeration (`Invoke-Main`) | silent; every per-DC section then said "no DCs enumerated" | first-class `Not Assessed` finding carrying the cause |
| Domain summary, per domain | the domain silently disappeared from the section | a row per failed domain |
| FSMO roles, per domain | same | a row per failed domain |

The last three are the ones that mattered: they sit in the orchestration every per-DC section
depends on, and the failure shape — a collector throws, its rows quietly do not appear, the
report looks complete — is the same one this repo already shipped once in v1.6.0.

**And the more serious defect the new regression test exposed.** With `$dcNames` empty, the run
did not merely report poorly — it **aborted**, with
`Cannot bind argument to parameter 'DomainControllers' because it is an empty array`, before any
report was written. Five collectors predating v1.4.0 declared `[Parameter(Mandatory)][string[]]`
without `[AllowEmptyCollection()]`: `Get-AdfaReplicationHealth`, `Get-AdfaDcDiagnostic`,
`Get-AdfaDnsHealth`, `Get-AdfaDcHardening` and `Get-AdfaSiteHealthFinding`. The recovery sections
added in v1.4.0 already allowed an empty list; these did not. All five now accept one and report
`Not Assessed` with a named cause, so a forest whose DC enumeration fails still produces a full
report saying what it could not assess — which is the entire point of the tool on a damaged forest.

A third smoke-test scenario runs `Invoke-Main` end to end with those collectors throwing and
asserts 17 properties of the result: the run completes, findings are written, each failure appears
as `Not Assessed` carrying its cause, and — the non-vacuity check — that **nothing reports `Pass`
off the back of a failure**. Measured: 50 findings, 29 `Not Assessed`, 0 false passes. Before this
change the same scenario produced no report at all.

Both guards were demonstrated able to fail: restoring the silent catch turns the cause assertion
red, and reverting one `[AllowEmptyCollection()]` reproduces the original abort. Script restored
byte-for-byte after each, hash verified.

Two things found and deliberately **not** fixed here, recorded as plan rows rather than widened
into this change:

- **H9** — `Invoke-Main` calls `Get-ADForest` / `Get-ADDomain` unguarded while resolving which
  domains to scope, before any section runs. A forest where those throw still aborts with a raw
  exception. The failure-mode harness had to be narrowed to avoid it, which is how it was found.
- **PORT-PLAN P2 count** — the plan said nine `PSAvoidUsingEmptyCatchBlock` hits; there were
  eleven, seven of them real. Corrected in place rather than restated.

### Added — 2026-09-21 (Exchange Server SE compatibility verdict, tool v1.7.0)

`-Sections ExchangeSeReadiness` answers the two Exchange SE prerequisites the directory can
answer on its own, and says plainly that it answers nothing else.

| Gate | Supported | Verdict when not met |
| --- | --- | --- |
| Forest functional level | `Windows2016Forest`, `Windows2012R2Forest` | `Fail`, naming what is supported |
| DC operating system, **every DC in the forest** | WS 2025 / 2022 / 2019 / 2016 / 2012 R2 | `Fail`, naming the offending DCs |
| Read-only DCs | not supported | `Warning` |

Forest level and DC OS were already collected as inventory strings (`ForestMode`,
`OperatingSystem`) and never compared to anything.

A single unsupported DC **anywhere in the forest** is a `Fail`, not a warning, because the
requirement is that all of them run a supported version — not only the ones in the Exchange
site. Read-only DCs are a `Warning` rather than a blocker: an RODC in a site no Exchange server
is installed into does not stop Setup. What does stop it is a target site with no writeable
global catalog, and that check is **not** claimed here.

Fail-closed, and the distinction is deliberate: a DC whose `OperatingSystem` could not be read
is `Not Assessed` on a row of its own, never counted as supported and never counted as
unsupported either — an absent measurement and a measured failure are different claims. The
separate row exists so a pass on the readable DCs cannot hide it.

Values live in a **versioned config table** with `-ExchangeSeConfigPath` to override it, so a
revision to Microsoft's matrix is a config edit rather than a code change. The table carries its
source URL and read date
([supportability matrix](https://learn.microsoft.com/exchange/plan-and-deploy/supportability-matrix#supported-active-directory-environments),
read 2026-09-21). A missing or malformed override file is a terminating error, not a silent fall
back to the built-in table — judging a forest against the wrong table while the operator believes
theirs is in force is worse than stopping. An override that would leave a gate empty is rejected.
When an override is in force, provenance is rewritten so findings cite the file and not Learn.

Domain functional levels are reported as `Info`, not judged: the supportability matrix states a
forest requirement and does not state a domain one, and inventing a domain gate would be a
fabricated vendor requirement.

**Scope is stated in the output itself**, as an `Info` row, so the section cannot be mistaken for
Exchange SE readiness. Schema and organisation object versions, the per-site writeable-GC
requirement, Exchange server inventory and coexistence builds are `ExchangeAssessment`'s remit.

Both gates were demonstrated able to fail: loosening the `2012 R2` pattern to bare `2012` turns
three assertions red (it would otherwise pass an unsupported DC), and counting an unreadable OS
as supported turns two red. Script restored byte-for-byte after each, hash verified. A test also
pins that a narrowed override really changes the verdict, so the config path is not decoration.

### Fixed — 2026-09-21 (a cleared Directory Service log reported Pass, tool v1.7.0)

**A domain controller whose Directory Service log had been wiped reported `Pass`.** The event
scan concluded from silence: zero matching events in the window produced
`New-Finding ... -Status Pass`, and the `catch` mapped "No events were found" to `Pass` as
well. So on exactly the environment this section exists for — a forest recovered from a
ransomware incident, where logs are routinely cleared — the checks that matter most read clean:
USN rollback (2095), unsupported restore (2103), lingering objects (1988), tombstone lifetime
exceeded (2042).

Absence of an event is only evidence if the log goes back far enough to have recorded one.
Every DC's log coverage is now measured before any conclusion is drawn from it, by comparing
the oldest record the log still retains against the start of the lookback window:

| Verdict | Meaning |
| --- | --- |
| `Covered` | the log reaches back to or past the window start — absence is meaningful |
| `Truncated` | the log starts inside the window — cleared or wrapped; nothing can be said about the period before it |
| `Empty` | no records at all — nothing can be concluded |
| `Unknown` | the log could not be inspected (unreachable, access denied, absent) |

A clean scan over anything but `Covered` now reports **`Not Assessed`, naming where coverage
begins**, never `Pass`. A scan that *does* find events over an incomplete window reports its
count as a **minimum** rather than a total. Each DC also gets an explicit `Log coverage on <dc>`
row, so the coverage question is answered in the report rather than left implicit.

One measurement covers every way the window can be incomplete — cleared, wrapped, or a DC
rebuilt more recently than the window. **No "log was cleared" event ID is used.** One was
considered and rejected: Microsoft Learn does not publish such a marker for an arbitrary log
(searched 2026-09-21), and it would add nothing, because clearing a log necessarily moves its
oldest retained record forward. Guessing an ID would have been an invented vendor fact.

`Get-AdfaEventLogCoverage` and `Get-AdfaDsEventCoverageDetail` are pure and tested directly,
including the boundary case and all four ways coverage degrades. The guard was demonstrated
able to fail — forcing the classifier to return `Covered` turns three assertions red — and the
script restored byte-for-byte, hash verified.

Findings carry remediation pointing at **recovering the evidence**, not resetting the DC:
archived `.evtx`, SIEM or log-forwarding copies, corroboration through
`repadmin /showrepl /errorsonly` and `/showutdvec`, raising the log size so the next run can
conclude, and the advisory lingering-object scan, which does not depend on the event log at
all. A test pins the routing in both directions, since the map is first-match-wins: a coverage
finding must not get secure-channel advice, and a real 2095 must still get rollback advice.

Also fixes a precedence bug found by these tests: in `"a {0}" + "b" -f $x`, `-f` binds only to
the second string, so the timestamp in the `Truncated` caveat stayed a literal `{0}`. A sweep
of the file found no other instance.

### Added — 2026-09-21 (JSON report, tool v1.7.0)

`Assessment.json` is written beside `Assessment.html`, so a run can be diffed against the
next one. The immediate driver is a phased Exchange Server SE rollout: the assessment is
re-run between phases, and comparing two HTML files or two folders of CSVs by hand is not a
control. Findings, the section-coverage reconciliation and every section's rows are all in
the document, alongside `schemaVersion`, the tool version and the run's scope.

Nothing is collected for the JSON. `Export-AdfaJsonReport` serialises what `Invoke-Main` has
already assembled, and runs after the CSVs and the itemised log are on disk, under its own
try/catch — so a serialisation fault can neither cost data nor take the HTML report down with
it. Rows go through `ConvertTo-AdfaRowSet`, the same normalisation the CSVs use, so a
heterogeneous section cannot lose its later rows' columns on this third output path the way
it did on the first two (v1.5.1, v1.6.0).

`New-AdfaReportDocument` and `New-AdfaReportSummary` are pure and separately tested, in the
style of `Get-AdfaDnsQueryOutcome`.

**The roll-up under-counted, and still does outside the JSON.** The four counters
`Invoke-Main` computes for the log's `Summary:` line and the HTML badges match
`Pass|Healthy`, `Warning|Degraded`, `Fail|Broken` and `Not Assessed` — but not `Info`, which
is a valid `New-Finding` status. Measured on the three-domain fixture: **123 findings, 106
counted, 17 `Info` counted nowhere.** No finding was ever lost — all 123 are in the CSV, the
HTML and the JSON — but the headline numbers did not reconcile with them.

The JSON summary therefore carries `info`, an `unclassified` catch-all for any status none of
the filters match, and `total`. A consumer can assert that the buckets sum to the total, and a
status that escapes every filter in future shows up in `unclassified` instead of vanishing.
The four original counters are passed through unchanged, so the JSON agrees with the HTML and
the log rather than telling a third story.

**The HTML badges and the log line are deliberately left as they are.** Correcting them
changes output that has already been shown to people, which is the operator's call and not
this change's business. Recorded as PORT-PLAN row **R6**.

### Fixed — 2026-09-21 (smoke-test stub fidelity)

`Run-SmokeTest.ps1` stubbed `Get-ADDomain`'s `DomainSID` as `[pscustomobject]@{ Value = ... }`.
The real cmdlet returns a `System.Security.Principal.SecurityIdentifier`, whose `ToString()`
is the SID string; the stub's was `@{Value=S-1-5-21-1-2-3}`, and
`Get-AdfaDomainSummary`'s `[string]$d.DomainSID` duly wrote that into the report. The new JSON
depth guard caught it on its first run.

`SecurityIdentifier` cannot be constructed off Windows and this harness must run anywhere, so
the stub overrides `ToString()` instead and keeps `.Value` — the collector reads it both ways
(`[string]$d.DomainSID` at `Get-AdfaDomainSummary`, `.DomainSID.Value` in the privileged-group
and Kerberos collectors). Product code is unchanged: against a real directory the output was
always correct.


### Fixed — 2026-08-31 (silent multi-domain data loss, tool v1.6.0)

**Twelve sections were collected and then discarded without any error**, including the two
that matter most after a restore: DNS-vs-AD consistency and DC secure channel /
machine-account passwords. Any `-AllDomains` run against a forest with more than one domain
was affected. Single-domain runs were not, which is why every test to date passed.

**Cause.** Collectors ended in `return , @($rows)`. The leading comma emits the array as a
single object, which protects a one-element result from unrolling — but the per-domain
aggregation pattern is

```powershell
$rows = foreach ($d in $targetDomains) { Get-AdfaSomething -DomainName $d }
$sectionData['X'] = @($rows)
```

With one domain that yields the rows. With N domains it yields an array OF N ARRAYS, and
`@()` does not flatten that. Every downstream consumer then examined an array where it
expected a finding: the consolidated-findings builder looked for a `Status` property,
found none, and hit `continue` — silently. `Export-Csv` wrote the array's own metadata
(`Length`, `Rank`, `Count`) as the section CSV. Nothing threw, nothing was logged, and the
report looked complete.

Measured on the three-domain regression fixture: **39 findings reported where 123 existed —
68% discarded.**

**Fix, in four parts.**

1. The idiom is gone: all 60 `return , ...` statements are now plain returns, so multi-row
   and multi-domain aggregation flattens naturally. This is PORT-PLAN P3, which was open
   and which I twice noted and did not close; it was not a cosmetic empty-array wrinkle.
2. `Expand-AdfaRowList` flattens nested collections defensively on every output path, so a
   future shape mistake cannot silently cost data.
3. The consolidated builder no longer skips in silence: a row that is not a plain object is
   logged at ERROR, counted, and the run warns that the findings are INCOMPLETE.
4. New `csv\Section-Coverage.csv` and a "Section Coverage" panel in the HTML reconcile
   rows collected against findings reported for every section, so an empty section is
   visible in the report itself rather than being indistinguishable from a clean one.

`Resolve-AdfaTrustHealth` is now null-safe on its warning list, since a plain return yields
`$null` when empty and `$null.Count` throws under StrictMode.

**Test coverage that was missing.** The end-to-end smoke test only ever ran a
single-domain forest, so it could not observe an aggregation fault. It now runs a second
pass against a three-domain forest and asserts that each per-domain section reaches the
consolidated findings, that every scoped domain appears, that section CSVs contain findings
rather than array metadata, and that the reconciliation reports no lost section. Verified
against the pre-fix script: the new pass fails with 6 errors, naming the discarded
sections and the `Length,LongLength,Rank,...` CSV. A Pester guard also fails the build if
the `return ,` idiom is reintroduced.

### Fixed — 2026-08-30 (first live-forest run, tool v1.5.1)

First execution against a real multi-domain forest (the start of R4) failed while writing
the report:

```
ConvertTo-AdfaHtmlSection : The property 'FailureDetail' cannot be found on this object.
```

**Cause.** A section's rows are not always the same shape. `Get-AdfaReplicationHealth`
emitted a row *without* `FailureDetail` for an unreachable DC and one *with* it for a
reachable DC. The HTML renderer took its column list from row 0 and then read every column
off every row, so under `Set-StrictMode -Version Latest` the shorter row threw
`PropertyNotFoundStrict`. A forest where the first DC answers and a later one does not —
precisely the state this tool exists to report — could not render its own report.

The same heterogeneity silently damaged CSV output: `Export-Csv` takes its columns from the
first object only, so whenever a short row sorted first, the extra columns of every later
row were dropped from the file without warning.

**Fix.** A shared `ConvertTo-AdfaRowSet` normalises any collection to one column set
(first-seen order, missing values as `''`) and is applied by both output paths — `Save-Csv`
and `ConvertTo-AdfaHtmlSection` — so any heterogeneous section, present or future, renders
and exports completely. `Get-AdfaReplicationHealth` also emits a uniform shape at source.
The same latent fault existed in the trusts section, where `-AllDomains` concatenates full
trust rows with `(enumeration failed)` / `(no trusts)` rows from other domains; it is
covered by the same fix and by a regression test.

**Also:** HTML rendering is no longer fatal to the run. The CSVs and the itemised log are
already on disk when it starts, and collection may not be cheap to repeat during a
recovery, so a rendering fault is now logged loudly, leaves the findings intact, and still
closes the transcript and returns the run summary.

### Fixed — 2026-08-30 (recovery defects R1 + depth R2, tool v1.5.0)

Three defects found in review of v1.4.0, all fixed:

- **Inbound trust false-Verified (critical).** The inbound direction of every trust was
  "verified" by running `nltest /sc_verify:<ourOwnDomain>` locally, which checks the local
  machine's own channel and succeeds on any healthy DC regardless of the trust's real
  state. Inbound is now verified by executing `nltest /sc_verify:<ourDomain>` ON a DC of
  the partner domain over WinRM (`Test-AdfaRemoteSecureChannel`); where the partner DC
  cannot be remoted to, the direction reports `Not Assessed` naming the exact command to
  run there — never a fabricated Verified.
- **DNS checks trusted one resolver.** `DnsAdConsistency`, `DsaCname` and `GcConsistency`
  queried only the local resolver, printing one DNS server's view as forest truth — in a
  forest with broken replication the AD-integrated zone content genuinely differs per
  server, and that divergence is the thing being hunted. All three now query every DC's
  DNS plus the local resolver, report per-server divergence rows, and add a consensus
  summary ("3 of 7 answering DNS servers diverge from AD"). "No such record" is
  distinguished from "server did not answer" (`Get-AdfaDnsQueryOutcome`) so a dead DNS
  server cannot masquerade as a missing record.
- **Recommendation mis-routing on trust failures.** First-match-wins over the
  concatenated text sent a broken trust (whose reason reads "secure channel verification
  FAILED") to the machine-account remediation (`netdom resetpwd`) instead of the trust
  remediation (`netdom trust /reset`). Map entries can now be scoped to a Section regex;
  trust and machine-password guidance are section-scoped and cannot be hijacked by detail
  wording.

Depth (R2): the dcdiag grid grew from 6 to 15 tests (adds MachineAccount,
ObjectsReplicated, RidManager, KccEvent, VerifyReferences, CrossRefValidation,
KnowsOfRoleHolders, Intersite, DFSREvent); replication is cross-checked with
`repadmin /showrepl * /csv` (one Fail finding per failing link — repadmin sees edges the
Get-ADReplication* cmdlets miss when a partner is unreachable); backup status now runs
`repadmin /showbackup` per DC with a parsed age verdict (correlate an old backup date with
a stale machine-account password to date a restored DC); and a new opt-in
`-IncludeLingeringObjectScan` runs `repadmin /removelingeringobjects ... /advisory_mode`
per DC against the domain PDC — advisory mode changes nothing in the directory but finds
lingering objects BEFORE they block replication with event 1988 (opt-in because it writes
events 1938/1942/1946 on the target DCs).

Process: manifest and script versions aligned at 1.5.0 (a repo test now asserts parity —
the HTML report prints the script value); proprietary LICENSE added at the repository root
with a copyright header in the script, matching the Assessments repository; PORT-PLAN.md
reconciled with a Recovery track table (R0 retro-logged, R1/R2 Done, R3/R4 Planned).
Runtime verification against a live forest (R4) is still outstanding: all new coverage is
pure-logic with stubs.

### Added — 2026-08-30 (recovery & consistency sections, tool v1.4.0)

Six new sections aimed at assessing a forest during or after a restore-from-backup
recovery, where some DCs replicate and others do not and DNS divergence masquerades as
network failure. All are single-machine collectors: they query every DC remotely and
degrade to `Not Assessed` (with the exact command to run locally) where a remote interface
is unreachable.

- `DnsAdConsistency` — DC locator SRV records (`_ldap`/`_kerberos` under `dc._msdcs`, plus
  the PDC record) compared against the DCs the directory actually contains. Stale entries
  for removed DCs and live DCs not advertised are reported per host, Fail.
- `DsaCname` — per-DC `<DSA-GUID>._msdcs.<forest>` CNAME verification (missing / pointing
  at the wrong host), plus orphaned NTDS Settings objects. Replication resolves source DCs
  through this alias; a broken one is the classic post-cleanup RPC 1722.
- `GcConsistency` — forest `GlobalCatalogs` vs `_gc._tcp` advertisement, both directions.
- `PortMatrix` — per-DC TCP reachability on 88/135/389/445 (critical) and 636/3268/9389
  (optional), with "unresolvable in DNS" reported separately from "port closed".
- `DcSecureChannel` — DC machine-account password age from the replicated `pwdLastSet`
  attribute (centrally collectable; a stale value fingerprints a DC restored from an old
  backup), and `nltest /sc_verify` executed on each DC over WinRM where port 5985 answers.
- `DsEvents` — per-DC Directory Service event log scan (14 days) for 1988, 2042, 2095,
  2103, 2087, 2088, 1311, 1865, 1925, 1084, each mapped to a severity and a plain-language
  meaning.

Every Fail / Warning / Broken / Degraded row in the consolidated findings now carries a
best-practice `Recommendation` (table-driven map in the script; first match wins; empty
when nothing verified applies — never invented). The recommendation appears in
`csv\Findings-Consolidated.csv`, as `|| FIX:` in the detailed log, and in the HTML lead
section. New pure functions (`Compare-AdfaDnsAdvertisement`,
`Resolve-AdfaDcPasswordVerdict`, `Get-AdfaRecommendation`, `Resolve-AdfaDnsRecord`) are
covered in both the Pester suite and the dependency-free harness (56 harness checks).

### Changed — 2026-08-14 (phase P5.3)

The three workflow files backfilled in P4.4 are refreshed from
`TakeItoCloud/template-ps-tool`, which moved a phase ahead in P5.2. All three are copied
byte-for-byte from the template's `main` and verified by git blob SHA, so this repository's
mirrors are identical to the canonical files rather than merely similar to them.

- `.github/pull_request_template.md` — the seven-item self-review checklist is replaced by
  three evidence lines (`- **Read-only default:**`, `- **No fabricated data:**`,
  `- **Verified against real data:**`), each of which must state **how** the property was
  verified. The checklist was ticked by whoever wrote the change, so it recorded a claim
  rather than controlling anything.
- `.github/workflows/pr-hygiene.yml` — the Conventional Commits title check is unchanged.
  The unticked-box check is replaced by an evidence check that fails, naming each line, when
  a label carries nothing after its colon, and fails when the `## Evidence` section is
  absent. `- [ ]` no longer fails anything anywhere: a grep cannot tell a stray box inside
  pasted gate output from a real unticked item.
- `docs/WORKFLOW.md` — §2 to §6 are rewritten around the three commands in `ps-toolbox`
  (`Start-ToolChange`, `Complete-ToolChange`, `Publish-ToolRelease`), plus a section on
  where they come from and on a repository with no CI reporting `CiChecks / NotAssessed` and
  merging anyway. §1 and §7 to §11 are unchanged, including the "Rewriting `main`"
  prohibition and §8's account of what the Free plan actually enforces.

Nothing outside those three files changed: `.githooks/pre-push` and `.gitattributes` were
compared against the template by blob SHA and already matched, and `README.md`, `ci.yml`,
`src/` and `tests/` are untouched.

### Added — 2026-08-13 (phase P4.4)

- Trunk-based workflow conventions backfilled from `TakeItoCloud/template-ps-tool`, which
  gained them after this repository was created: [`docs/WORKFLOW.md`](docs/WORKFLOW.md) (a
  mirror of the canonical rulebook), `.github/pull_request_template.md` (the PR self-review
  checklist), `.github/workflows/pr-hygiene.yml` (fails a PR on unticked checklist boxes or
  on a PR title that is not a Conventional Commit), and `.githooks/pre-push` (refuses direct
  pushes to `main`).
- `.gitattributes` forcing LF on `.githooks/**`, so a Windows checkout cannot hand the hook a
  CRLF shebang and silently break it.
- README: a pointer to `docs/WORKFLOW.md`, and a **Green gate** section. This repository
  uses the default gate — `Invoke-Pester -CI` plus the analyzer, both run from the
  repository root.

Git hooks are not cloned with a repository. Each existing clone needs
`git config core.hooksPath .githooks` run once before the pre-push hook is live.

### Added

- Initial extraction from infra-scripting-suite
  (`powershell/Assessments/ActiveDirectory/Invoke-ADForestAssessment.ps1`), together with its
  Pester suite and both dependency-free harnesses (`Run-Validation.ps1`,
  `Run-SmokeTest.ps1`, now under `tests\harness\`).
- `ADForestAssessment.psd1` — a metadata manifest holding the version and file list. This is
  a script tool: no `RootModule`, nothing exported. It exists so `build\package.ps1` produces
  a versioned artifact.
- `tests\ADForestAssessment.Repo.Tests.ps1` — covers what the extraction introduced: the
  manifest, the 5.1 floor on both the manifest and the script, the harnesses shipping, each
  harness resolving the script at its new path, and the repository-wide analyzer gate.
- A test asserting a clean trust resolves to `Healthy` end to end, not just that it produces
  no warnings.
- The suite's README, changelog and build plan preserved under `docs\` for provenance.

### Changed

- The script moved to `src\ADForestAssessment\`, and the three test harnesses were repointed
  at that path. They previously resolved the script as a sibling of their own folder.
- `PSScriptAnalyzerSettings.psd1` keeps the three exclusions the tool shipped with
  (`PSAvoidUsingWriteHost`, `PSUseShouldProcessForStateChangingFunctions`,
  `PSReviewUnusedParameter`) and adds six more. The settings file separates real debt in the
  assessment script from findings that are correct-as-written in the test harness — most of
  the volume is the latter. Tracked as phase P2 in [PORT-PLAN.md](PORT-PLAN.md).
- `PSUseCompatibleSyntax` now targets **both** `5.1` and `7.4`, so the 5.1-safe design is
  enforced rather than assumed.

### Fixed

- **A failing test in the inherited Pester suite.** `Get-AdfaTrustSecurityWarning` ends with
  `return , $warnings.ToArray()`; the comma stops a single warning unrolling to a scalar, but
  in the empty case it writes one object — the empty array — to the pipeline. So
  `@(Get-AdfaTrustSecurityWarning -Trust $clean).Count` is `1`, and the test asserting `0`
  had been failing.

  The tool itself is correct: every caller assigns the result first, and `@($assigned).Count`
  is `0`. That was verified end to end before touching anything — a clean trust resolves to
  `Healthy`. The test was corrected to the form callers actually use, with a comment
  explaining why, and a second test now pins the end-to-end verdict. The underlying
  return-shape trap is phase P3 in [PORT-PLAN.md](PORT-PLAN.md).

  The suite's build plan noted that PSGallery was blocked in its sandbox and the Pester file
  was "provided for the DC/CI run" — so it had most likely never been executed.
- `$matches` renamed to `$backupLines` in the directory-backup collector. `$matches` is an
  automatic variable populated by every `-match` operation; the surrounding code happened to
  be safe, but the name was a live hazard.
- Removed a dead `$subnetSites` assignment in the replication-topology findings.

### Not carried over

- Nothing else in `powershell/Assessments/ActiveDirectory/` — that folder also holds
  `Start-ADAssessment.ps1`, `AdAudit.ps1`, `ADxRay.ps1`, `ADDS_Inventory_V3.ps1`,
  `Get-ADHealth.ps1` and a vendored `PSWinDocumentation-master`, none of which belong to this
  tool.

### Not done

- **Runtime verification against a forest is deferred.** This extraction was gated on
  PSScriptAnalyzer and the tool's pure-logic test suite, all of which stub the directory. The
  script has not been run against a real forest from this repository — see phase P4 in
  [PORT-PLAN.md](PORT-PLAN.md).
- The dependency-free harnesses are not wired into CI; `Invoke-Pester` does not collect them
  because they are not `*.Tests.ps1`. Phase P5.

## [0.1.0] - 2026-08-13

### Added

- Initial scaffold from template-ps-tool.
