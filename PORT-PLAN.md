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
| H19 | v1.17.0: **the tool was not read-only.** It ran `nltest /sc_verify` by default at three places - the outbound trust direction on the host, the inbound direction on a partner DC, and every DC in `DcSecureChannel` - and Microsoft documents that `/sc_verify` "removes the existing channel, and then builds a new one" when the channel does not work. The default is now `nltest /sc_query`, which changes nothing and reports the last recorded status; the live test is opt-in behind `-IncludeSecureChannelVerify`, by operator decision, and `netdom trust /Verify`, also a live test, moved behind the same switch. Every default result says it is not a live test. Also fixes the README example that named a parameter that does not exist (`-SkipVerification`), and the help text that listed `/sc_query` and `getmigrationstate` as modes used when neither was. **Run against stubs only** - see H19-R | Done | 2026-11-13 |
| H20a | Audit every command a default run still invokes for a side effect Microsoft documents: the 16 remaining dcdiag tests, `repadmin /replsummary`, `/showrepl * /csv` and `/showbackup`, the `w32tm` queries, `nltest /sc_query` and `/dsgetdc`, `dfsrmig /getglobalstate`, `nslookup`, and the remote reads over WinRM, CIM, the remote registry, the DNS Server cmdlets and the event log. Read each on Microsoft Learn; move anything that changes state behind a switch and add it to the README's "What a run can change" table. Until this is done the tool's claim is "every known state-changing command is opt-in", not "a default run changes nothing". **Owner: operator to schedule** | Planned | |
| H20 | **Done 2026-11-13 as v1.18.0** - both tests moved behind `-IncludeDcdiagActiveTests`, by operator decision; the wider audit split out as H20a. Original row follows. **A default run is still not read-only.** Found by the review of H19. `DcDiagnostics`, part of the default `All`, runs `dcdiag /test:DNS /DnsAll` on every DC, and Microsoft documents that its dynamic update test performs "registration of a test record (_dcdiag_test_record)" which "is deleted automatically after the test"; it also runs `dcdiag /test:Intersite /a`, which Microsoft documents as "reporting back any replication failures after triggering a replication" (both read on Learn 2026-11-13; H12 added the DNS test and gave the existing Intersite test the `/a` that makes it actually test). Decide per test: drop the writing sub-test from the default (`/DnsAll` without the dynamic update test), move it behind an opt-in switch, or accept it and say so. Then audit every other command a default run invokes for a documented side effect; the README lists them and states they have not each been audited. Also say in the `-IncludeDcdiag` help that `/c` includes `CutoffServers`, which Microsoft documents as triggering replication. **Owner: operator to choose per test.** **Run against stubs only** - see H20-R | Done | 2026-11-13 |
| H20-R | First run of the H20 change against a real forest: a default run leaves no `_dcdiag_test_record` behind and its DC Diagnostics grid shows DNS and Intersite as `Not Assessed` with the switch named; a run with `-IncludeDcdiagActiveTests` reads both cells. **Operator-owned** | Planned | |
| H19-R | First run of the H19 change against a real forest: confirm what `nltest /sc_query:<domain>` prints on a domain controller and on a member server, for a trusted domain and for the machine's own domain, and that the connection status line matches the form Microsoft publishes. Until then a real run may read `Not Assessed` where the output differs. **Operator-owned** | Planned | |
| H21 | The assessment script predates the operator's script house rules and does not meet several of them: `.NOTES` does not carry the Owner / Version / Created / Last updated / Requires lines; the default output folder is the user's Documents, where the house rules say `C:\Scripts\Cannes` and this repository's `CLAUDE.md` says `C:\Scripts\Securnet\Reports\<ScriptName>-<yyyyMMdd-HHmmss>\` - the two disagree with each other as well; the log does not close with duration, totals and an exit code; the run does not set exit codes 0 / 1 / 2; and the internal functions carry `.SYNOPSIS` and `.DESCRIPTION` but no `.PARAMETER` or `.EXAMPLE` entries. Noted while building C2, which followed the script's existing conventions and changed none of this. Each item changes behaviour or output that people already rely on, so it needs a decision, starting with which output convention wins. **Owner: operator to decide** | Planned | |
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
| C2 | v1.19.0: new `-Sections DcDisk`. **Free space per DC** on the volumes that hold the NTDS database, the NTDS logs and SYSVOL: the three paths from each DC's own registry (`DSA Database File`, `Database Log Files Path`, `SysVol`; read on Learn 2026-11-13), each matched to a `Win32_Volume` by its longest mount path, one row per distinct volume naming the roles it holds. `Fail` below 10 % or 2 GB free, `Warning` below 20 % or 5 GB: **tool defaults, not Microsoft values** - Microsoft publishes none for these volumes - and every finding says so. Unreachable, access denied, a registry value that is not set and any other read failure are separate `Not Assessed` results; an absent value is never replaced by a default path, and nothing is `Pass` unless both figures were read. The provider's return of 1 is read as the value not being set and 2 as its key not existing: **measured on one workstation, not published by Microsoft**, and each such row says so. The section covers the DCs of **every scoped domain**, enumerating them itself when the `DomainControllers` section was not selected, and a scoped domain with no DC row gets its own `Not Assessed` row. The registry is read with `StdRegProv` `GetStringValue` and `GetExpandedStringValue`, **the script's first and only CIM method calls**: accepted as reads on Microsoft's description of each of them, which does not include a statement that they have no side effect, and held to those two literal method names by a test that reads the parsed script. `-WhatIf` and `-Confirm` are forced off on the two reads and on closing the session. Also adds the generic **`-ConfigOverridePath`**: one JSON file, one top-level key per section, each value checked by that section's own validator through a registry a later row adds one line to; read before the directory is contacted, and anything wrong with it stops the run - including an array holding one object and a key written twice, both found in the file's text because the parser hides them. `-ExchangeSeConfigPath` and `-DcSystemConfigPath` are unchanged. Found on the way and fixed: `Get-Help` could not read the script's help at all, because the licence banner touched the help block. An independent review of the diff before commit confirmed 22 findings, all fixed in the same change and listed in the changelog entry. Catalogue: DISK-001. **Run against stubs only** - first real run is C17, which for this row must confirm that `Win32_Volume.Name` holds the mount path, that a DC's provider returns 1 for a value that is not set, 2 for a key that does not exist and 5 for a refusal as the workstation measured did, that the per-domain enumeration returns every DC, and the rights the reads need | Done | 2026-11-13 |
| C2a | Free space against the figures Microsoft publishes for the database volume - 110 % of the `ntds.dit` size for offline defragmentation, 300 % where the storage allows, 210 % as the size of a fixed VHD, all relative to the database and none to the volume - is not evaluated by C2: it needs the size of the database FILE, which `Win32_Volume` does not give. A read-only way to read a file size on a DC (`CIM_DataFile` is the candidate) was not looked up on Microsoft Learn. Verify the class and property on Learn, then report the figure beside the C2 verdict. Until then the database volume's row says it was not measured. **Owner: operator to confirm it is wanted** | Planned | |
| C2b | C2 reads each registry value with `GetStringValue` and, failing that, `GetExpandedStringValue`, because this row was limited to `Get*` methods. Consequences: the value's registry type is never read, and an absent value is told from an absent key only by a return code (1 against 2) whose meaning was measured on one workstation and is not published. `StdRegProv` `EnumValues` returns the names and types under a key and would settle both; Microsoft describes it as "Enumerates the named values of a key" in the same single table as every other method of the class - it does not sort them into reading and writing methods - and it is not a `Get*` method. Decide whether it is acceptable under the read-only rule, then use it and add it to the method allow-list test. **Owner: operator to decide** | Planned | |
| C2c | Locations C2 does not judge: `DSA Working Directory` (Temp.edb and Edb.chk; documented on Learn beside the two values C2 reads, and not part of DISK-001), and whatever part of SYSVOL is not on the volume the `SysVol` value names - whether the DFSR staging folder or a junction target can sit on another volume was not checked. **Owner: operator to confirm they are wanted** | Planned | |
| C2d | `-ConfigOverridePath` carries only `DcDisk`. The Exchange SE and DC system tables keep `-ExchangeSeConfigPath` and `-DcSystemConfigPath`, and naming either as a section of the new file is refused. Moving them in needs two decisions first: what happens when both sources name the same section, and whether the Exchange SE merge, which skips nulls and accepts unknown keys, is tightened to the stricter contract on the way. **Owner: operator to decide** | Planned | |
| C2e | Found by the review of C2. Every per-DC section except `DcDisk` still takes its DC list from `$dcNames`, which, when `DomainControllers` is not among `-Sections`, is one unscoped `Get-ADDomainController -Filter *` against the default server: the current domain's DCs only. On `-AllDomains` such a run covers one domain in `DcHardening`, `Backup`, the patch-level half of `DcSystem`, `PortMatrix` and the others, with no row naming the domains left out. C2 fixed it for `DcDisk` only (`Get-AdfaDcTargetsByDomain`, and a row per scoped domain). Move the other per-DC sections onto the same per-domain enumeration and population rows, as each is touched by C3 and later rows; until then name `DomainControllers` with them. **Owner: operator to confirm the order** | Planned | |
| C2f | The override file is checked for a key written twice by a small scanner of the JSON text (`Get-AdfaJsonDuplicateKey`), because `ConvertFrom-Json` keeps the last value silently on both PowerShell editions. `-ExchangeSeConfigPath` and `-DcSystemConfigPath` do not have that check, nor the refusal of a top-level array holding one object, which PowerShell 7 unwraps. Add both to those two loaders, or fold them into `-ConfigOverridePath` under C2d. **Owner: operator to decide with C2d** | Planned | |
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
