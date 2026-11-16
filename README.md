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
| **DC hardening** | `-Sections DcHardening`. Per DC, six registry values and three CIM classes read in one session: **LDAP server signing** (`LDAPServerIntegrity`) and its Windows Server 2025 **enforcement** (`LDAPServerEnforceIntegrity`), **LDAP channel binding** (`LdapEnforceChannelBinding`), **SMB server and client signing** (`RequireSecuritySignature`), the **LAN Manager authentication level** (`LmCompatibilityLevel`), the **Print Spooler** service and the **SMBv1** server. Each value is graded against what Microsoft's security baselines expect on a domain controller. A value that is **not set** is graded on the default Microsoft documents for the DC's OS build where it documents one, named as a default; where it documents none it is `Not Assessed`, never a pass and never a failure. Unreachable, access denied, not set, key absent and wrong type are separate results. These rows show the **configured policy, not what a client and the DC negotiate on the wire**. The **SMBv1** row is `Not Assessed` on any DC whose SMB configuration class returns no instance to a query, which is what the one host measured does (PORT-PLAN C3f). Details under [DC hardening](#dc-hardening) |
| **DC system** | `-Sections DcSystem`. **OS lifecycle**: each DC's operating system against Microsoft's extended support end date, from a versioned table. Past the date is a `Fail` whose text says whether an Extended Security Updates (ESU) programme is still running, has also ended, or was never published — and always that **ESU enrolment is not assessed**. An OS the table does not list, or one that could not be read, is `Not Assessed` with the raw values, never `Pass`. Reads only the directory, so it needs no rights on any DC. **Patch level**: per DC, OS build, uptime and the latest update install date over remote CIM. This half is **inventory** (`Info` or `Not Assessed`, never `Pass`): Microsoft publishes no maximum uptime or update age for a DC, so none is applied. Unreachable, access denied and other read failures are three different results |
| **DC disk space** | `-Sections DcDisk`. Free space on the volumes that hold the **NTDS database**, the **NTDS logs** and **SYSVOL**, per DC. The three paths are read from each DC's own registry and matched to a volume by the longest mount path, so a database under a mounted folder is judged on the right volume. One row per distinct volume, listing the roles it holds. `Fail` below 10 % free or below 2 GB free, `Warning` below 20 % or below 5 GB — **tool defaults, not Microsoft values**, labelled as such in every finding and overridable with `-ConfigOverridePath`. A path or a volume that could not be read is `Not Assessed` with its cause; unreachable, access denied, a registry value that is not set and any other read failure are different results. Covers the DCs of every scoped domain, with or without `DomainControllers` selected; a domain whose DCs could not be enumerated gets its own `Not Assessed` row. Needs local Administrators rights on each DC |
| **Windows LAPS** | `-Sections Laps`. Directory reads only, with domain read access. **Schema**: whether the forest schema carries the six attributes `Update-LapsADSchema` adds, and the legacy Microsoft LAPS ones; absent, present and "the query failed" are three different results. **DSRM password backup**, one row per domain controller: `Pass` where a Windows LAPS expiry time that is not past is visible on the DC's computer object, `Info` (not applicable) for a DC below Windows Server 2019 or a domain below functional level 2016, `Warning` where nothing is visible although the account can read the attribute elsewhere in the domain. **LAPS coverage**, one row per scoped domain: how many enabled Windows computers that can run Windows LAPS have **no LAPS expiry time visible to this account** (Windows LAPS or legacy), with counts for every class left out of the population and a capped list of names. The section **never reads a password**: no password, encrypted password or password history attribute is ever requested. An attribute the account has no right to read looks exactly like one that is not set, and a device that backs its password up to Microsoft Entra ID has nothing here either, so no row calls a computer unmanaged with certainty; where nothing at all is visible in a domain the rows are `Not Assessed`. The thresholds are **tool defaults, not Microsoft values**, overridable with `-ConfigOverridePath`. The policy in each DC's registry is not read (PORT-PLAN C4a). Details under [Windows LAPS](#windows-laps) |
| **DC certificates** | `-Sections DcCertificates`. Per DC, two instruments, each named in every row's `Evidence` column. **Directory** (always, domain read access): the certificates a CA published on the DC's computer object (`userCertificate`), one row per certificate, graded on expiry. No published value is `Info`, never "no certificate": Microsoft's *Domain Controller Authentication* and *Kerberos Authentication* templates do not publish to the directory, and a value the account cannot read looks the same as none. **LDAPS** (only with `-IncludeLdapsHandshake`): the certificate the DC presents on port 636, read with one TLS handshake that sends no LDAP request, no bind and no credential and needs no right on the DC; without the switch each DC's `LDAPS certificate` row is `Not Assessed` and says why. Expired is `Fail`, at most 30 days left is `Warning`, not yet valid is `Warning` (this tool's rule) — the windows are **tool defaults, not Microsoft values**, overridable with `-ConfigOverridePath`. Refused, timed out, unresolved, handshake timed out and handshake failed are separate `Not Assessed` results, none of them read as "no certificate"; a refusal is told apart from a time-out within the handshake's own 5000 ms connection bound, and the whole handshake is bounded too. A published value that is not a single certificate (a PFX, a PKCS7 blob) is refused unopened. Trust, name and EKUs are reported in their own columns, not graded. The DC's own certificate stores are not read (PORT-PLAN C5a). Details under [DC certificates](#dc-certificates) |
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

Domain read access is enough for most sections. Trust verification, `DcHardening` (CIM), the
patch-level half of `DcSystem` (CIM), `DcDisk` (CIM) and `dcdiag` need administrative rights on
the domain controllers. The OS lifecycle half of `DcSystem` needs
domain read only.

`Laps` reads the directory only. What it can see depends on what the account can read: the
LAPS expiry time of a computer is returned only where the account has read access to that
attribute. Microsoft publishes, in general terms, that authenticated users can read every
attribute that is not confidential, and that the Windows LAPS expiry attribute is not
confidential; it publishes no LAPS-specific statement of who can read the expiry attributes,
and permissions can be changed per organizational unit. Run with more rights and the section
may see more; it never asks for a password attribute, whatever the rights.

`DcCertificates` reads the directory with domain read access, and its opt-in LDAPS handshake
needs no right on the DC at all - only that port 636 is reachable from the host running the
assessment.

**Running `Identity` (part of `All`) with rights to read LAPS passwords.** The Identity export
asks for every attribute of every computer (`Get-ADComputer -Properties *`), and the directory
hands an account with those rights the attributes that hold LAPS passwords too. Since v1.21.0
they are left out of `AllComputers_<domain>.csv`; before it they were written there, the
legacy one in clear text. They are still requested (PORT-PLAN C4b). Delete any
`AllComputers_*.csv` an earlier version produced under such an account.

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

# Free space on each DC's NTDS database, NTDS log and SYSVOL volumes, against your own thresholds
.\src\ADForestAssessment\Invoke-ADForestAssessment.ps1 -Sections DomainControllers,DcDisk `
    -ConfigOverridePath C:\Scripts\adfa-overrides.json

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
them. The two port keys change the port that is probed before a read, not the port the CIM
session connects to, which is always the default one (PORT-PLAN C3g).

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

## DC disk space

`-Sections DcDisk` (or the default `All`). The section covers the domain controllers of
**every scoped domain**, and each row carries its domain. With `DomainControllers` also
selected it takes them from the DC inventory; without it, it enumerates each scoped domain
itself. A scoped domain whose DCs could not be enumerated, or that returned none, gets a
`Not Assessed` row of its own (`Disk space - <domain>`) with the cause; it is never left out.
If no scoped domain gave a single DC, the section falls back to the DCs the default server
returns. Those carry no domain, and each domain's row then says that it is not known whether
they include its DCs, instead of claiming that nothing was read.

**This has run only against stubs.** It has not been executed against a real domain
controller. The first real run is PORT-PLAN C17.

**What is read, per DC.** Three registry values, which exist only in the registry of the DC
itself:

| Role | Registry value under `HKLM\SYSTEM\CurrentControlSet\Services` |
| --- | --- |
| NTDS database | `NTDS\Parameters`, `DSA Database File` (the path of the database file) |
| NTDS logs | `NTDS\Parameters`, `Database Log Files Path` |
| SYSVOL | `Netlogon\Parameters`, `SysVol` |

([Defender exclusions on Windows Server](https://learn.microsoft.com/defender-endpoint/microsoft-defender-antivirus-exclusions-windows-server)
and [Backing up and restoring an FRS-replicated SYSVOL folder](https://learn.microsoft.com/windows/win32/vss/backing-up-and-restoring-an-frs-replicated-sysvol-folder),
read 2026-11-13.) Then `Win32_Volume` for each volume's name, type, capacity and free bytes
([Win32_Volume](https://learn.microsoft.com/previous-versions/windows/desktop/legacy/aa394515(v=vs.85)),
read 2026-11-13). Each path is matched to the volume whose mount path is its longest prefix,
which is the Win32 rule for a path under a mounted folder.

**Thresholds. These are tool defaults, not Microsoft values.**

| Result | Free space, as a share of the volume | Or free space, absolute |
| --- | --- | --- |
| `Fail` | below 10 % | below 2 GB |
| `Warning` | below 20 % | below 5 GB |
| `Pass` | 20 % or more | and 5 GB or more |

Either test is enough, and the finding says which one fired. "Below" is strict: exactly 10 %
is a `Warning`, exactly 20 % is a `Pass`. Microsoft publishes no free-space threshold for these
volumes. The three figures it does publish are all relative to the size of the database, not
to the volume: free space of 110 % of the `ntds.dit` size to allow offline defragmentation,
300 % of it as "a safe way to accommodate growth and defragging" where the storage allows, and
a fixed VHD of at least 210 % of it
([capacity planning](https://learn.microsoft.com/windows-server/administration/performance-tuning/role/active-directory-server/capacity-planning-for-active-directory-domain-services),
read 2026-11-13). This section does not read the size of the database file, so it evaluates
none of them, and the row for the database volume says so (PORT-PLAN C2a). 20 % and
10 % are the pair the AdAssessment26 catalogue lists for this check as operator-set; the
absolute floor is this tool's addition, because 25 % of an 8 GB volume is 2 GB. A dedicated
volume smaller than a floor can never pass it: lower the floors, or set both to 0. The figures
in a finding are cut off after two decimals, never rounded, so a volume one byte under 10 %
reads "9.99 % free", not "10.00 % free ... below 10 %".

Change them with `-ConfigOverridePath` (next section):

```json
{ "DcDisk": { "WarnBelowPercent": 25, "FailBelowPercent": 15, "WarnBelowFreeGB": 10, "FailBelowFreeGB": 5 } }
```

**Rows.** One row per distinct volume per DC, naming the roles it holds: a DC with everything
on `C:` gives one row, `Disk space: <dc> C:\ (NTDS database, NTDS logs, SYSVOL)`. Every role is
accounted for by exactly one row. Where a role could not be judged it gets its own
`Not Assessed` row, and the cause is one of these, kept apart:

| Cause | What the row says |
| --- | --- |
| No port answered | `Unreachable`: neither WinRM (5985) nor RPC (135); no read attempted |
| The DC refused the session or the read, or the provider returned 5 or `0x80041003` | `Access denied`: local Administrators rights on the DC are needed |
| The registry value is not set (the provider returned 1) | `Not found`, read as the value not being set. **No default path is assumed in its place** |
| The registry key does not exist (the provider returned 2) | `Not found`, read as the key not existing |
| The value exists and is not a string (the provider returned `0x80041005`) | Says so |
| Any other failure | `Read failed`, with the DC's own text or the return code, quoted and not interpreted |
| The value is empty, or holds an unexpanded `%VARIABLE%` | Says so, with the value |
| The path is on no volume the DC returned | Names the path and the volumes |
| The volume returned no capacity (offline, unformatted) | `Not Assessed` for that volume, with the values returned |

No row is `Info`, and none is `Pass` unless both the capacity and the free space were read.

**What the return codes rest on.** Microsoft documents the return value of the two methods as
0 for success and otherwise an error code from WinError.h or, for script callers, from
WbemErrorEnum
([GetStringValue](https://learn.microsoft.com/previous-versions/windows/desktop/regprov/getstringvalue-method-in-class-stdregprov),
[WbemErrorEnum](https://learn.microsoft.com/windows/win32/api/wbemdisp/ne-wbemdisp-wbemerrorenum),
read 2026-11-13). It does not publish which code the provider returns for which condition.
`5`, `0x80041003` and `0x80041005` are read by the names those two lists give them
(`ERROR_ACCESS_DENIED`, `wbemErrAccessDenied`, `wbemErrTypeMismatch`). **1 and 2 are read on a
measurement, not on a Microsoft statement**: on the one host where it was measured - a
Windows 11 workstation, not a domain controller, with the same two methods - the provider
returned 1 for a value that does not exist under a key that does, and 2 for a key that does
not exist. WinError.h's own name for 1, `ERROR_INVALID_FUNCTION`, does not describe that. Each
`Not found` row says the reading is measured and not published. Whether a domain controller
answers the same way is for the first real run to confirm (PORT-PLAN C17). Whatever the code,
the role is `Not Assessed`.

**Reading the registry is a CIM method call. Only this section and `DcHardening` make any.** The values are
read through the WMI registry provider, `StdRegProv`, over the same CIM session as the volume
query, so WinRM and the DCOM fallback both carry them and the Remote Registry service is not
needed. `StdRegProv` exposes no instances: a value can be read through it only by calling a
method. Two are called, `GetStringValue` and — where that returns nothing usable —
`GetExpandedStringValue`, which Microsoft documents as getting the string value and the
expanded string value of a named value
([StdRegProv](https://learn.microsoft.com/previous-versions/windows/desktop/regprov/stdregprov),
read 2026-11-13). Microsoft lists the class's 20 methods in one table and does not sort them
into reading and writing methods; that sorting is this tool's, made from each method's own
description. The methods described as creating, deleting or setting (`CreateKey`, `DeleteKey`,
`DeleteValue`, the `Set*` methods) are never called; a test reads every method call from the
parsed script and fails on any other name. Microsoft does not state in so many words that the
`Get*` methods have no side effect: this rests on their documented purpose and signature.
`-WhatIf` and `-Confirm` are forced off on the two reads and on closing the CIM session, so a
preference in your session can neither skip a read nor leave a session open.

Limits to keep in mind:

- That `Win32_Volume.Name` holds the mount path is observed behaviour, not something
  Microsoft documents. If a real DC returns something else, the affected roles report
  `Not Assessed` naming the volumes returned; they are never matched to a nearby volume.
- SYSVOL is judged on the volume of the path the `SysVol` value names. Whether DFSR staging or
  a junction target sits on another volume is not examined.
- Which return code the provider gives for a value that is not set, as against a key that
  does not exist, is not published. 1 and 2 are read as measured on one workstation (above),
  and each row says so.
- The timeout note under the patch-level rows above applies here too: up to seven CIM
  operations per transport for one DC.

## DC hardening

`-Sections DcHardening` (or the default `All`). Like `DcDisk`, the section covers the domain
controllers of **every scoped domain**, each row carrying its domain: from the DC inventory
when `DomainControllers` is also selected, otherwise from its own enumeration of each scoped
domain. A scoped domain with no DC row gets a `Not Assessed` row of its own,
`DC hardening - <domain>`.

**This shows configured policy, not what a client and a DC negotiate on the wire.** Every value
below is read from the registry of the DC. No LDAP bind and no SMB session is attempted, and
each row says so. LDAP signing applies only to SASL binds that are not over TLS, and channel
binding only to TLS with SASL; SMB signing is used when either side requires it, so one side's
value does not settle what a given connection does. Microsoft's own live check of LDAP signing
is a simple bind on port 389 that "sends simple-bind credentials without TLS. Run it only in an
isolated lab", which is why this tool does not make one.

**What is read, per DC**, in one CIM session (WinRM first, DCOM second, no retry after a
refusal), needing local Administrators rights on the DC:

| Row | Registry value under `HKLM\SYSTEM\CurrentControlSet` | Passes at | Not set means |
| --- | --- | --- | --- |
| `LDAP server signing: <dc>` | `Services\NTDS\Parameters`, `LDAPServerIntegrity` | 2 (Require signing) | Windows Server 2022 and earlier: the documented default, None, a `Warning`. Windows Server 2025: see below |
| `LDAP server signing enforcement: <dc>` | `Services\NTDS\Parameters`, `LDAPServerEnforceIntegrity` | 1 | Windows Server 2025 only; `Info`, not applicable, on earlier builds. See below |
| `LDAP channel binding: <dc>` | `Services\NTDS\Parameters`, `LdapEnforceChannelBinding` | 2 (Always) | 2022 and earlier: documented default Never, a `Warning`. 2025: `Not Assessed` - the default "When supported" is published for new deployments only |
| `SMB server signing: <dc>` | `Services\LanManServer\Parameters`, `RequireSecuritySignature` | 1 | Not published for a DC on any build: graded on the SMB server's own configuration where the DC returned it (see "second instrument" below - on the one host measured it is not returned), otherwise `Not Assessed` |
| `SMB client signing: <dc>` | `Services\LanManWorkstation\Parameters`, `RequireSecuritySignature` | 1 | 2022 and earlier: documented default Disabled, a `Warning`. 2025: documented default required, a `Pass` named as a default |
| `LAN Manager authentication level: <dc>` | `Control\Lsa`, `LmCompatibilityLevel` | 5 | 2008 R2 to 2022: documented default 3, a `Warning`. 2025: `Not Assessed` - NTLMv1 is removed there and the default is not restated |
| `Print Spooler: <dc>` | `Win32_Service`, not the registry | Stopped | - |
| `SMBv1: <dc>` | `MSFT_SmbServerConfiguration.EnableSMB1Protocol`, by instance query | False | - |

**The SMBv1 row may be `Not Assessed` on every DC.** It asks for the instance of
`MSFT_SmbServerConfiguration`. Measured on 2026-11-15 on one host - a Windows 11 (build 26100)
workstation, not a domain controller, not elevated, under PowerShell 7 and Windows PowerShell
5.1 - that query returns **no instance and no error**, while `Get-SmbServerConfiguration` on the
same host returns the configuration: the cmdlet calls the class's static method
`GetConfiguration`. This tool does not invoke that method. It is not one of the three `Get*`
registry methods the script is held to, Microsoft Learn documents the cmdlet and not the class
or its methods, and adding it is the operator's decision (PORT-PLAN C3f). So where a DC answers
as that host did, the row reads `Not read: MSFT_SmbServerConfiguration returned no instance`,
`Not Assessed`, never `Pass` - and it is kept apart from access denied and from a query that
failed. What a real DC returns has not been measured (PORT-PLAN C17). Until one of those two rows
is done, check SMBv1 with Microsoft's own command on the DC:
`Get-SmbServerConfiguration | Select EnableSMB1Protocol`.

The OS build that decides the default is the one the DC itself reports
(`Win32_OperatingSystem.BuildNumber`), read in the same session. The only boundary Microsoft
publishes for these defaults is "Windows Server 2022 or earlier" against "Windows Server 2025
or later", so the table is keyed on build 20348 and below, and 26100 and above. A build
between the two, or a build that could not be read, has no documented default: a value that is
not set is then `Not Assessed`. The LAN Manager level has a lower bound as well: its documented
default is for Windows Server 2008 R2 and later, build 7101 and above.

A value that **is** set is graded whatever the build for four of the six settings: channel
binding, SMB server signing, SMB client signing and the LAN Manager level. The two LDAP signing
rows are the exception, because on Windows Server 2025 they are decided together:

- `LDAPServerIntegrity` at 2 passes on every build. Below 2 it is a `Warning` up to Windows
  Server 2022, `Not Assessed` when the build was not read, and on Windows Server 2025 it follows
  the table below.
- `LDAPServerEnforceIntegrity`, set or not, is `Info` (not applicable) below Windows Server
  2025 and `Not Assessed` when the build was not read. In both cases the row still says what
  the read of the value gave - the number, "not set", or the refusal.

A value below the expectation is a `Warning`, the rule the AdAssessment26 catalogue gives for
these rows. The expected value is Microsoft's, cited in the row; the status a DC gets for
missing it is **a tool default, not a Microsoft value**, each such row says so, and it can be
set to `Fail` per setting (below). A number Microsoft publishes no meaning for is
`Not Assessed`. `EnableSecuritySignature` is not read: Microsoft documents it as ignored for
SMB2 and later.

**LDAP signing on Windows Server 2025.** The enforcement value decides together with the older
one, and the two rows say how:

| `LDAPServerEnforceIntegrity` | `LDAPServerIntegrity` | Signing row | Enforcement row |
| --- | --- | --- | --- |
| 1 | any value, or not set | `Pass` - the enforcement policy takes precedence | `Pass` |
| 0 | 2 | `Pass` | `Warning` |
| 0 | below 2 | `Warning` | `Warning` |
| 0 | not set | `Not Assessed` | `Warning` |
| not set | not set | `Pass`, the documented 2025 default | `Pass`, the documented default |
| not set | 2 | `Pass` | `Pass` |
| not set | 0 or 1 | `Not Assessed` | `Not Assessed` |
| not set | a number with no published meaning (3 ...) | `Not Assessed` | `Not Assessed` |
| a number that is neither 0 nor 1 | 2 | `Pass` | `Not Assessed` |
| a number that is neither 0 nor 1 | below 2, or not set | `Not Assessed` | `Not Assessed` |
| not read (refused, key absent, wrong type) | 2 | `Pass` | `Not Assessed` |
| not read (refused, key absent, wrong type) | below 2, or not set | `Not Assessed` | `Not Assessed` |

"Not set, 0 or 1" is `Not Assessed` because Microsoft documents both that an upgrade to Windows
Server 2025 "maintains your current settings" and that an enforcement policy left Not
Configured "has the same effect as Enabled", and the registry does not show which applies. A
number Microsoft publishes no meaning for decides nothing in either row: the enforcement row
does not take a signing value of 3 for "at least 2, so signing is required", and the signing
row says of an enforcement value of 2 that it was read and what it holds, not that it was not
read.

**SMB server signing has a second instrument, where the DC returns one.** The section asks
for the instance of `MSFT_SmbServerConfiguration` for SMBv1, and that instance also carries
`RequireSecuritySignature`. Microsoft's own verification is the **cmdlet**
(`Get-SmbServerConfiguration | FL RequireSecuritySignature`: "If the returned information is
True, then SMB signing is enabled"), which returns an object of that class; this tool does not
run the cmdlet, it queries the class, and on the one host measured that query returns no
instance (see the SMBv1 note above). So:

- Where the instance was returned and the registry value is set, the row is graded on the
  registry and says whether the second instrument agrees; if the two **disagree** the row is
  `Not Assessed`.
- Where the instance was returned and the registry value is not set, the row is graded on the
  second instrument, which is a measurement.
- Where no instance was returned - the measured case - a registry value that is set is graded
  on the registry alone and the row says the second instrument was not read and why; a registry
  value that is not set is `Not Assessed`.

The SMB client has no second instrument here.

**What is not published on Microsoft Learn**, and is labelled so in the config table and, where
a finding relies on it, in the finding:

- The registry path of `LDAPServerIntegrity` for AD DS. Learn gives the path for AD LDS only;
  `NTDS\Parameters` is where it publishes the two sibling values. Every `LDAP server signing`
  row says the path is inferred, whatever its verdict.
- What `LDAPServerIntegrity` = 1 means. Learn publishes 0 (for AD LDS) and 2. A value of 1 is
  reported as "not 2", a `Warning`, with that said.
- A value table for `LDAPServerEnforceIntegrity`. The Windows Server 2025 baseline expects 1;
  0 = Disabled is inferred from that, and the row says "inferred".
- The return codes of `GetDWORDValue`. 1 is read as the value not being set and 2 as its key
  not existing, **measured on one Windows 11 workstation**, not a domain controller; each such
  row says so. Whether a DC answers the same way is for the first real run (PORT-PLAN C17).

**Changing the expectation.** With `-ConfigOverridePath`, under `DcHardening`, per setting id:
`ExpectedMinimum` (only to a value the tool can grade against - `LmCompatibilityLevel` 3, 4 or
5; `LdapEnforceChannelBinding` 1 or 2; the other four have one possible value) and
`OtherStatus` (`Warning` or `Fail`). A finding then cites the file. For the two settings whose
expectation can be moved, the recommendation does not name a value of its own: it says to raise
the setting to at least the expected minimum the finding names, and gives Microsoft's baseline
value (channel binding Always, `LmCompatibilityLevel` 5) as Microsoft's.

The two ports cannot be changed for this section. `WsmanPort` and `RpcPort` under `DcHardening`
are refused: the CIM session is always opened on the default WinRM port, or through the RPC
endpoint mapper for DCOM, so a port set in the file would change what is probed and not what is
connected to. `DcDisk` still accepts the two keys and has that same gap (PORT-PLAN C3g).

```json
{ "DcHardening": { "Settings": { "LmCompatibilityLevel": { "ExpectedMinimum": 3, "OtherStatus": "Fail" } } } }
```

Limits to keep in mind:

- None of this has met a real domain controller. The reads have run against stubs only; the
  first run against a real forest is PORT-PLAN C17.
- The timeout note under the patch-level rows above applies here too: up to nine CIM
  operations per transport for one DC (six registry reads and three queries).
- The SMBv1 row, and the second instrument of SMB server signing, depend on a query that
  returned nothing on the one host it was measured on; both may be `Not Assessed` on every DC
  until PORT-PLAN C3f is decided.
- A value delivered by Group Policy and a value set by hand look the same in the registry, and
  the section does not say which it is (PORT-PLAN C3d).
- `Print Spooler` is graded on whether the service is running. Its start mode is stated in the
  row and not graded, so a spooler that is stopped but not disabled passes (PORT-PLAN C3b).
- One status covers every value below an expectation: `LmCompatibilityLevel` 0 and 4 are both
  a `Warning` unless a config file says otherwise (PORT-PLAN C3c).

**Changed in v1.20.0.** The rows are named family first (`Print Spooler: <dc>`, where it was
`<dc>: Print Spooler`), the old `<dc>: LDAP signing required` row is now
`LDAP server signing: <dc>`, and a DC that could not be read is `DC hardening: <dc>`. Print
Spooler and SMBv1 are read through the same CIM session as everything else, so they honour
`-Credential` and work under PowerShell 7; a missing `EnableSMB1Protocol` property, which used
to pass, is now `Not Assessed`, and so is a class that returns no instance at all. The registry values are read with `StdRegProv` `GetDWORDValue`,
a third `Get*` method beside the two `DcDisk` uses, on the same reasoning.

## Windows LAPS

`-Sections Laps`, part of the default `All` run. Added in v1.21.0 (PORT-PLAN C4; catalogue rows
ADA-LAPS-001 and ADA-LAPS-002). **It has run only against stubs**: no query in it has met a real
directory (PORT-PLAN C17).

**The section never reads a password.** It reads attribute *definitions* in the schema
partition, `msDS-Behavior-Version` on each domain head, and this fixed list on computer
objects: `operatingSystem`, `operatingSystemVersion`, `userAccountControl`,
`lastLogonTimestamp`, `dNSHostName`, `objectClass`, plus `msLAPS-PasswordExpirationTime` and
`ms-Mcs-AdmPwdExpirationTime` where the schema defines them. The seven attributes that hold a
password, an encrypted password, a password history or the password version
(`msLAPS-Password`, `msLAPS-EncryptedPassword`, `msLAPS-EncryptedPasswordHistory`,
`msLAPS-EncryptedDSRMPassword`, `msLAPS-EncryptedDSRMPasswordHistory`,
`msLAPS-CurrentPasswordVersion`, `ms-Mcs-AdmPwd`) are never put in a property list and never
used in a search filter on a computer object. The list is checked where it is built and again
where it is sent; a list holding one of those names, a wildcard or any other password-like
name is refused before the directory is asked, and tests fail if one of the names appears in
the script outside the config table. No cmdlet of the LAPS module is called -
`Get-LapsADPassword` returns the password.

**What it reports.**

| Row | From | Status |
| --- | --- | --- |
| `Windows LAPS schema` (one, forest) | Attribute definitions in the schema partition, by name, with `operatingSystemVersion` asked for in the same query as a control | `Pass` all six `Update-LapsADSchema` attributes; `Warning` some of them; `Info` none (legacy only, or neither); `Not Assessed` the query failed, or answered without the control attribute |
| `DSRM password backup: <dc>` (one per DC computer object) | `msLAPS-PasswordExpirationTime` on the DC's computer object, the DC's `operatingSystemVersion`, the domain's `msDS-Behavior-Version` | `Pass` an expiry time not more than 7 days past; `Warning` one further past, or none visible while another object of the domain returned one, or no such attribute in the schema; `Info` not applicable (DC below build 17763, or domain below level 7); `Not Assessed` otherwise |
| `DSRM password backup - <domain>` | - | `Not Assessed`: the domain's read failed, or returned no DC object, or returned an object without `userAccountControl` that may be a DC |
| `LAPS coverage: <domain>` (one per scoped domain) | Either expiry attribute on each computer object in population | `Pass` every one has an expiry time visible; `Warning` any has none; `Fail` only where a config file sets a threshold; `Info` nothing in population; `Not Assessed` see below |

**Not set and not readable look the same.** A directory does not say "you may not read this
attribute"; it leaves it out. So a computer with no expiry time in the answer is reported as
"no LAPS expiry time visible to this account", never as unmanaged. Microsoft publishes that
`msLAPS-PasswordExpirationTime` is not confidential, and in general terms that authenticated
users can read every attribute that is not, but no LAPS-specific statement of who can read it,
and nothing at all about the legacy attribute's flags. The rule the section applies (decision D13
of the AdAssessment26 plan):

- the schema has **neither** expiry attribute: no computer can have a LAPS password in this
  directory, a measured absence, graded;
- the schema has one and **at least one** computer object in the domain returned a value: the
  account can read the attribute somewhere in the domain, so absences are counted - still
  worded as "not visible", because permissions can differ between organizational units;
- the schema has one and **no** object in the domain returned a value: `Not Assessed`. Not
  deployed, not readable and "every device backs up to Microsoft Entra ID" cannot be told apart.

**Microsoft Entra ID.** A device backs its password up to Active Directory or to Microsoft
Entra ID, never both, and a forest that uses only Entra ID does not need the schema extension.
This read cannot see Entra ID, and every graded row says so.

**The population of the coverage row**, stated in the row with a count for each class left out:
enabled computer accounts that are not domain controllers and not managed service accounts,
whose `operatingSystem` begins with `Windows`, whose OS build can run Windows LAPS, and whose
`lastLogonTimestamp` is within `-StaleDays` (default 90, the threshold the `StaleObjects`
section uses; there is no second one). Left out, each with its own count: domain controllers
(they have the DSRM rows), managed service accounts, disabled accounts, objects with no
`operatingSystem` (which is also how cluster and other virtual computer objects are left out -
a tool heuristic, no Microsoft-documented marker was found), non-Windows computers, Windows
computers whose build could not be read, Windows releases that cannot run Windows LAPS (with
how many of them show a legacy LAPS expiry time), accounts with no logon recorded, stale
accounts, and objects whose `userAccountControl` was not returned.

An object whose `userAccountControl` was not returned, or a Windows computer whose build could
not be read, is **not measured**, not measured-out: while there is one, the coverage row is
never `Pass` and never `Info` ("nothing to grade") - it is `Not Assessed` and names them, up to
`SampleLimit`. A `Warning` or `Fail` stands, and says that the share is over the computers that
could be classified. An object without `userAccountControl` may also be a domain controller,
so the domain gets a `DSRM password backup - <domain>` `Not Assessed` row naming it beside the
rows of the DCs that were recognised.

"Can run Windows LAPS" is the OS build: 17763, or 19041 and later, from the builds Microsoft's
LAPS CSP page lists. The directory holds the build and not the revision, so it does not show
whether the April 11, 2023 update that brought Windows LAPS is installed: capable means the
release, not the patch level. A Windows release older than that is out of the population even
though legacy Microsoft LAPS may manage it; the row counts how many of those show a legacy
expiry time.

**The DSRM rows rest on an inference.** The attribute that holds the DSRM password is
confidential and is not read. The row uses `msLAPS-PasswordExpirationTime` on the DC's own
computer object. Microsoft does not state in prose that DSRM password backup writes it; its
`Get-LapsADPassword` example shows an expiration time for a DC whose source is the DSRM
password. Every DSRM row says this. A DC promoted from a member server that Windows LAPS
managed can carry a value from before the promotion until it expires. A read-only domain
controller with nothing visible is `Not Assessed`: Microsoft does not say, on the pages read,
whether the feature is supported there. That a DC without DSRM password backup is a `Warning`
is the catalogue's rule; Microsoft documents the feature as off by default, not as a
requirement.

**Thresholds are tool defaults, not Microsoft values**: Warning above 0 % (any computer), Fail
above 100 % (never, unless a file lowers it), 25 names per row, 7 days of grace on a DC's
expiry time. Microsoft publishes none of them. See
[`-ConfigOverridePath`](#one-override-file-for-section-config--configoverridepath).

**Four different failures.** A domain whose query threw is `Not Assessed` and begins
`Unreachable:`, `Access denied:`, `Timed out:` or `Read failed:`, told apart by the type of the
exception and then by its text. A timeout or a "server too busy" answer is not called
unreachable: it can come from a server that accepted the query and then took too long, which
the one unpaged computer query over a large domain makes likely. Microsoft does not publish the
exceptions the ActiveDirectory cmdlets throw, and none of them has been produced by a real
directory in a test of this tool.

**A domain whose rows could not be built** - an exception inside the grading, a defect of the
tool - gets its two rows as `Not Assessed` with the error, and the other domains are still
graded. An expiry time at the end of the calendar (an administrator who set it to "never") is a
time not past, so a DC carrying one is `Pass`; before the fix it threw out of the section and
ended the run.

**Not read**: the Windows LAPS policy in each DC's registry (`BackupDirectory`,
`ADBackupDSRMPassword`, `ADPasswordEncryptionEnabled`), which is what would say whether DSRM
backup is *configured* - PORT-PLAN C4a. The presence of the confidential DSRM attribute is not
tested either - PORT-PLAN C4d.

**No paging or size limit is set.** The computer query relies on the paging the
ActiveDirectory module does by itself, as every other query in this script does. Its time and
memory on a very large domain have not been measured.

## DC certificates

`-Sections DcCertificates` (part of `All`) answers two questions per domain controller: which
certificate does it hand its LDAPS clients, and which certificates has a CA published for it in
the directory - and when does each expire. **Run against stubs only** so far; the first run
against a real forest is PORT-PLAN C17.

| Row | Instrument | Results |
| --- | --- | --- |
| `LDAPS certificate: <dc>` (exactly one per DC) | A TLS handshake to port 636, only with `-IncludeLdapsHandshake`, after the shared port probe answered | `Pass` / `Warning` / `Fail` on expiry; `Not Assessed` with its own cause for: not run (no switch), port did not answer the probe, refused, timed out, unresolved, handshake timed out, handshake failed, no certificate, unreadable certificate |
| `Directory certificate: <dc> [<thumbprint>]` (one per published value) | `Get-ADComputer` with `userCertificate`, against the DC's domain | `Pass` / `Warning` / `Fail` on expiry; `Not Assessed` for a value that is not a certificate |
| `Directory certificates: <dc>` | The same read, when it returns no value or fails | `Info` no value visible; `Not Assessed` unreachable, access denied, timed out, read failed, no object or more than one object with the DC's DNS host name |
| `DC certificates - <domain>`, `DC certificates` | Population | `Not Assessed`: a scoped domain whose DCs were not enumerated, or no DC at all |

**Why the handshake, and why it is opt-in.** Microsoft documents that AD DS takes its LDAPS
certificate from the NTDS service store before the local computer store, and that a DC with
several usable certificates may present any of them - so reading a certificate store cannot say
which certificate clients are given; the handshake sees it whichever store holds it. TLS is
negotiated before any LDAP traffic, and the tool sends nothing after the handshake: no LDAP
request, no bind, no credential, and it needs no right on the DC. The validation callback
records the certificate and returns *true*, so this tool neither trusts nor rejects it and does
not abort the handshake. But Microsoft documents Schannel error logging as on by default and
does not state that a handshake leaves no trace on the server: a DC that cannot complete it may
log a Schannel error event in its System log. Like the other commands with a possible effect on
a DC, it runs only when you ask for it. Building the certificate chain on the host running the
assessment may also fetch issuer certificates from the addresses a certificate names.

**What is graded.** Expiry only, in UTC against the time of the run: already expired (including
expiring at that instant) is `Fail`; at most `WarnWithinDays` whole days left (30) is `Warning`;
a Fail window `FailWithinDays` exists and is 0, off, by default; a certificate whose start date
is still in the future is a `Warning` - **this tool's rule**, as Microsoft publishes none. The
windows are **tool defaults, not Microsoft values**: Microsoft publishes no warning window for
a DC certificate. Subject, issuer, subject alternative names, the EKUs (Server Authentication,
Client Authentication, KDC Authentication and Smart Card Logon are named) and what the platform
reported about the chain and the name (`SslPolicyErrors`, `ChainStatus`) are in their own
columns and are not graded: they describe the trust of the host running the assessment.

**No published certificate is not "no certificate".** Of Microsoft's default domain controller
templates, *Domain Controller* (version 1) is published to the directory, while *Domain
Controller Authentication* and *Kerberos Authentication* certificates are not, and publication
is a separate operation from issuance. Who can read `userCertificate` by default is not
published either. And a published certificate is not necessarily a DC certificate: Microsoft's
table also lists *Directory E-mail Replication* (a computer template) as published, so check a
published certificate's EKUs before acting on it.

**A published value is opened only if it is one certificate.** Whoever can write
`userCertificate` chooses its bytes, and the .NET constructor that reads them would also accept
a PKCS12 (PFX) file and import its private key on the host running the assessment. A value that
`X509Certificate2.GetCertContentType` does not call a single certificate is refused unopened and
reported `Not Assessed` (`Read failed:`).

**Every handshake is bounded.** Its TCP connection by `ConnectTimeoutMs` and the whole
handshake by `HandshakeTimeoutMs` (5000 ms each, tool defaults): when the handshake bound runs
out the connection is closed, so a DC - or anything answering on its port - that trickles bytes
cannot hold the run. The connection bound is above the shared port probe's 1200 ms on purpose:
Windows reported a refused loopback connection only after about 2 s in this tool's tests, and a
shorter bound reports a refusal as a time-out.

**A certificate's own text never chooses advice.** The subject is set by whoever requested the
certificate; it is kept out of the text the recommendation is chosen from.

**Not read**: the DC's certificate stores (`LocalMachine\My` and the NTDS service store), which
would inventory every certificate the DC holds - PORT-PLAN C5a; revocation.

## One override file for section config: `-ConfigOverridePath`

A JSON file whose top-level keys are section names. Each value is checked by that section's own
rules. Four sections can be named so far, `DcDisk`, `DcHardening`, `Laps` and `DcCertificates`;
later checks add their own key.

```json
{
  "DcDisk": {
    "WarnBelowPercent": 25,
    "FailBelowPercent": 15,
    "WarnBelowFreeGB": 10,
    "FailBelowFreeGB": 5,
    "WsmanPort": 5985,
    "RpcPort": 135
  },
  "DcHardening": {
    "Settings": {
      "LmCompatibilityLevel": { "ExpectedMinimum": 3 },
      "SmbServerSigning": { "OtherStatus": "Fail" }
    }
  },
  "Laps": {
    "WarnAbovePercent": 5,
    "FailAbovePercent": 50,
    "SampleLimit": 25,
    "ExpiredGraceDays": 7
  },
  "DcCertificates": {
    "WarnWithinDays": 45,
    "FailWithinDays": 7,
    "HandshakeTimeoutMs": 5000,
    "ConnectTimeoutMs": 5000
  }
}
```

```powershell
.\src\ADForestAssessment\Invoke-ADForestAssessment.ps1 -ConfigOverridePath C:\Scripts\adfa-overrides.json
```

- Keys you omit keep their built-in value, and a finding cites your file only for the values
  the file supplied. With the file above reduced to `WarnBelowPercent`, a finding reads
  "...adfa-overrides.json (loaded 2026-11-13) for WarnBelowPercent; tool default, not a
  Microsoft value, for FailBelowPercent, WarnBelowFreeGB, FailBelowFreeGB".
- The file is read once, before the directory is contacted. **Anything wrong with it stops the
  run before anything is collected**: a missing or empty file, text that is not JSON, JSON that
  is not one object (`null`, an array, a string), an unknown section, a section set to `null`,
  an unknown key, or a value its section cannot use.
- The file must begin with `{`. An array is refused even when it holds exactly one valid
  object: PowerShell 7 would unwrap it and Windows PowerShell 5.1 would not, and the same file
  must get the same answer on both.
- A key or a section written twice is refused, naming it (`'DcDisk.WarnBelowPercent' more than
  once`). A JSON parser keeps only the last of them without an error, so a file that
  contradicts itself would otherwise be applied and cited as the source.
- For `DcDisk` a value must be a JSON number, without quotes. Percentages are 0 to 100, floors
  are 0 or more, `Fail` may not be above `Warning` once your values are merged with the
  built-in ones, at least one threshold must remain above 0, and a port is a whole number from
  1 to 65535. `Paths`, `SourceUrl` and `ReadDate` cannot be set from the file.
- For `DcHardening` the one key is `Settings`; `WsmanPort` and `RpcPort` are refused there (see
  [DC hardening](#dc-hardening)). `Settings` is an object
  keyed by setting id - a list is refused - and under an id only `ExpectedMinimum` and
  `OtherStatus` can be set. `ExpectedMinimum` must be a JSON number and one of the values the
  setting can be graded against - none of which is a value that means off or never - and
  `OtherStatus` must be `Warning` or `Fail`, so a value below the
  expectation can never be configured to read as a pass. The registry key and value a setting
  reads, the meanings of its numbers, its documented defaults and its sources cannot be set
  from the file.
- For `Laps` the four keys above are the only ones, and each must be a JSON number.
  `WarnAbovePercent` and `FailAbovePercent` are 0 to 100, `Fail` may not be below `Warning`
  once merged, and a `WarnAbovePercent` of 100 is refused because no share can exceed it and
  no domain would ever be reported. `SampleLimit` is a whole number from 0 to 1000 (0 lists no
  computer name) and `ExpiredGraceDays` a whole number from 0 to 365. **No attribute name can be
  set from the file**: `NeverRead`, `WindowsExpiry`, `ComputerProperties` and every other key
  of the built-in table are refused as unknown, so a file cannot make the tool request a
  password attribute.
- For `DcCertificates` the four keys above are the only ones, each a whole JSON number:
  `WarnWithinDays` and `FailWithinDays` from 0 to 3650 (0 switches that window off; an expired
  certificate is always a `Fail`), `Fail` not above `Warning` once merged (equal is allowed), and
  `HandshakeTimeoutMs` and `ConnectTimeoutMs` from 100 to 60000. `LdapsPort` and the EKU names
  are refused.
- For `DcDisk`, `WsmanPort` and `RpcPort` change the port that is **probed** before a read. The
  CIM session itself is opened without a port, so it still goes to the default one: setting
  either key to anything but the default can make a reachable DC read as unreachable, and does
  not make a DC on another port readable (PORT-PLAN C3g).
- The file is validated in full even when `-Sections` leaves out the section it names; the
  log then says the section was validated and not used.
- `-ExchangeSeConfigPath` and `-DcSystemConfigPath` are unchanged and separate. Their tables
  cannot be set from this file: `"DcSystem"` or `"ExchangeSe"` as a top-level key is refused as
  an unknown section.

## What a run can change

Known, with Microsoft's own wording (read on Learn 2026-11-13):

| What | When | What Microsoft documents |
| --- | --- | --- |
| `dcdiag /test:DNS /DnsAll`, per DC | Only with `-IncludeDcdiagActiveTests` | The dynamic update test performs "registration of a test record (_dcdiag_test_record)... The test record is deleted automatically after the test." |
| `dcdiag /test:Intersite /a`, per DC | Only with `-IncludeDcdiagActiveTests` | Works by "reporting back any replication failures after triggering a replication." |
| `nltest /sc_verify`; `netdom trust /Verify` as its fallback | Only with `-IncludeSecureChannelVerify` | `/sc_verify`: "If the secure channel does not work, this parameter removes the existing channel, and then builds a new one." |
| `repadmin /removelingeringobjects ... /advisory_mode` | Only with `-IncludeLingeringObjectScan` | Advisory mode removes nothing; it writes events to the target DCs' Directory Service logs |
| TLS handshake to port 636, per DC | Only with `-IncludeLdapsHandshake` | Nothing is written. Schannel event logging is on by default ("error messages are logged"), and no Microsoft page read states that a handshake leaves no trace, so a DC that cannot complete it may log a Schannel error event in its System log (read 2026-11-16) |
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

Two of those remote reads are CIM method calls rather than instance queries: `DcDisk` reads
three registry values per DC with `StdRegProv` `GetStringValue` and `GetExpandedStringValue`,
and `DcHardening` reads six with `GetDWORDValue`. Why they are treated as reads, and what
Microsoft does and does not say about it, is under [DC disk space](#dc-disk-space).

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
