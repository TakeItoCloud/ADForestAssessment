# ADForestAssessment

## Purpose

ADForestAssessment audits an Active Directory forest end to end and reports what it could
*actually* verify. Its distinguishing feature is two-way trust health: each trust direction is
read on its own with `nltest` - the outbound direction on a DC of the domain assessed, the
inbound one on a DC of the partner - and a direction that could not be read is reported
`Not Assessed`, never `Verified`. The roll-up `Health` of a trust is a different claim: a
bidirectional trust with one direction `Verified` and the other `Not Assessed` is `Healthy`, with
the untested direction named in `Reasons`, and a trust whose partner answers neither TCP 135 nor
389 from the host running the assessment is `Broken` (PORT-PLAN C16a).

The whole tool is **coverage-aware and fail-closed**: any value that could not be collected
comes back `Not Assessed`, never a false `Pass` or `0`.

The script writes nothing to the directory itself. Since v1.37.0 every command, console tool
form (started through `Invoke-ExternalCommand` or directly), CIM class and method, static .NET
member, `New-Object` type and instance method name the script holds is listed in
[docs/SIDE-EFFECT-AUDIT.md](docs/SIDE-EFFECT-AUDIT.md), and a test fails on any the list does
not hold (PORT-PLAN H20a). Not every row rests on a page that was read: where the Learn page
was read (2026-11-18, or the earlier date the row gives), the row says what it documents; where
it was not read, or there is none, the row says `not documented`, and reading the unread pages
is PORT-PLAN H20c. Of the pages that were read, none documents a change of state for anything a
default run invokes, and everything Microsoft documents as changing state is off unless you
give its switch. That is not a claim about the pages not read, and it is not a statement that a
default run leaves no trace: logon auditing on each DC, whether reading the remote registry
starts the Remote Registry service, and the DNS client cache of the host running the assessment
are not covered by any page read. See [What a run can change](#what-a-run-can-change).

Extracted from
`infra-scripting-suite/powershell/Assessments/ActiveDirectory/Invoke-ADForestAssessment.ps1`.

## Coverage

| Area | What it collects |
| --- | --- |
| Forest & domains | Functional levels, FSMO role holders And, in its own report section **Topology Inventory** (since v1.32.0, `-Sections Forest`, inventory only - every row `Info` or `Not Assessed` with its cause): the raw forest and domain functional levels (`msDS-Behavior-Version`, named as MS-ADTS names them; 8, 9 or a value not returned is `Not Assessed`), the five FSMO holders from `fSMORoleOwner` (a value naming a deleted NTDS Settings object is `Not Assessed`), the UPN suffixes of `CN=Partitions`, each domain's `msDS-AllowedDNSSuffixes`, each DC's DNS suffix against its domain (Disjoint Yes or No, not graded) and the runner DC (rootDSE `dnsHostName`). |
| Domain controllers | OS, GC, site, IP, read-only status; and, in its own report section **DC DNS Client** (since v1.30.0), each DC's DNS server list from its enabled adapters (`Win32_NetworkAdapterConfiguration` where `IPEnabled`, remote CIM, local admin on the DC; no method is called). A single DNS server where more than one DC is known is a `Warning` (Microsoft: a single point of failure, tolerable only in a single-DC forest; the grade is a tool default, or the override file that set it); with one DC known it is `Info` only when the run covered every domain of the forest, otherwise `Not Assessed`; itself or loopback first, no other DC listed, and an address that is no known DC (Microsoft: do not point DCs at ISP DNS; an address alone cannot show it) are `Info`. Unreachable, access denied, a failed read, a read that listed no adapter and a DNS server list that was not returned are separate `Not Assessed` causes |
| Replication | Partner metadata, failures, queue (a DC is a `Pass` only when both reads succeeded and a partner reported a recent last success; metadata read but empty, or with no last-success time, is `Not Assessed`, since v1.36.0); sites, subnets, site links, connection objects (the last two read with declared property lists since v1.33.0, each failing on a `Not Assessed` row of its own without taking the sites and subnets with it); `repadmin /showrepl * /csv` cross-check (catches links the AD cmdlets miss when a partner is unreachable); and, in **Site Health** (since v1.31.0, outside the DC inventory gate), **Subnets without a site** - every subnet object's `siteObject`, a `Warning` when any has none (a tool default; that an empty `siteObject` means "no site" is reasoning, and the row says so), `Not Assessed` when the read failed or returned nothing - and, per DC, **Clients without a site**: the `NO_CLIENT_SITE:` lines of its `netlogon.log` (Netlogon event 5807: the first word after the marker is the client name, the second its address), read-only over `\\<dc>\ADMIN$\debug\netlogon.log` (administrative rights on the DC; the last 4 MB only, a tool default; `netlogon.bak` not read). Clients found are a `Warning`; none found is `Info`, never `Pass`; unreachable, access denied, not found, timed out and SMB silent are each their own `Not Assessed` cause. Names and addresses are in their own columns
| **Replication convergence** | `repadmin /replsummary` **parsed into findings** — the largest delta and fails/total per DSA, in both directions — plus **per-link convergence lag**: a link with **zero failures** whose last success is old is reported, because that is the silent stall where nothing errors since nothing is being attempted. An unreadable delta or last-success time is `Not Assessed`, never treated as recent |
| **Trusts** | Forest and domain trusts of the scoped domains with a per-direction secure-channel read — **outbound asked of the PDC emulator of the domain assessed** (`nltest /server:<dc> /sc_query:<partner>`, since v1.36.0; before, `nltest` ran against the host's own Netlogon, which is not that domain's trust channel; with no DC resolved the direction is `Not Assessed`), **inbound executed on a partner-domain DC over WinRM** (a direction that cannot be tested from the correct side is `Not Assessed`, never `Verified`) — plus SID filtering, selective authentication, TGT delegation, encryption posture And, since v1.32.0, **Trust Inventory**: every `trustedDomain` object of every scoped domain, read from that domain with a listed attribute set, `trustAttributes` decoded by its MS-ADTS names (an unnamed bit kept as "unknown 0x.."), direction and type named, transitivity, the SID filtering flags, `CROSS_ORGANIZATION` by its raw name (Learn does not call it selective authentication) and TGT delegation from the MS-KILE rule; inventory only. Since v1.33.0 the trust health rows ask `Get-ADTrust` for the fourteen properties they read (`DirectoryRead.TrustHealthProperties`), never every attribute and never `trustAuthIncoming`/`trustAuthOutgoing`; a read that was refused, failed (unreachable and access denied worded apart) or returned more than `MaxObjects` trusts is one `Not Assessed` row. |
| Diagnostics | `-Sections DcDiagnostics`. `dcdiag` from the host running the assessment, one `/test:<name> /s:<server>` per invocation, its en-US output parsed and **each verdict attributed to the block dcdiag prints it in** - a DC, a partition or the enterprise - so a partition's result is graded per partition and never counted as an unrelated DC's failure (since v1.28.0). **Per DC**, a 21-test grid, each row carrying the DC's domain; **19 run by default**, Connectivity first (when it fails, nothing more is started on that DC, and the cell carries Microsoft's ICMP caveat; the grid's `Ping` column is a TCP 135 probe from the host running the assessment, not ICMP, PORT-PLAN C11g): Connectivity, Replications, Advertising, Services, Netlogons, SysVolCheck, DFSREvent, FrsEvent, KccEvent, RidManager, KnowsOfRoleHolders, MachineAccount, ObjectsReplicated, NCSecDesc, VerifyReferences, VerifyReplicas, FsmoCheck (not in Microsoft's dcdiag reference; kept, PORT-PLAN C11c), **CheckSecurityError** and **VerifyEnterpriseReferences** (the last two specifically post-restore). **Per scoped domain**: Topology once, against a writable DC (Microsoft: it analyses "without actually replicating changes"), and a coverage row. **Per forest**: CheckSDRefDom and CrossRefValidation once each, one row **per partition** and a roll-up. **Only with `-IncludeDcdiagActiveTests`**, because Microsoft's text says they change state: DNS and SystemLog per DC, and Intersite **once per site** that holds a DC (see [What a run can change](#what-a-run-can-change)). **LocatorCheck is never run**: it is not in Microsoft's table of dcdiag tests (a row says so). **DNS summary per test group** (since v1.29.0, with `-IncludeDcdiagActiveTests`): the DNS test's summary table, read from the same output with no further invocation, is graded per DC and per test group - Auth, Basc, Forw, Del, Dyn, RReg, Ext - with PASS `Pass`, FAIL `Fail`, WARN `Warning`, `n/a` `Not Assessed` (Microsoft does not publish what it means) except under Ext, which `/DnsAll` does not ask for (`Info`), and rolled up per domain and test group over every DC of the domain; the header is found by its tokens and the cells mapped by order (Learn shows the table once, KB 2102154), and a missing table, row, column or cell is `Not Assessed`. Without the switch, one "dcdiag DNS not run" row per domain. `/x` (XML) is not used: Microsoft publishes no schema. Unreachable, access denied, an event log that "could not be queried" (KB 2512643), and output not recognised (possibly a localised Windows) are each their own `Not Assessed` cause, never `Pass`. Not seen: whether SYSVOL uses FRS or DFSR on each DC, so FrsEvent and DFSREvent are both graded from their own output (PORT-PLAN C11e) |
| DNS | `-Sections Dns` (since v1.30.0). Every DC of every scoped domain asked as a DNS server through the `DnsServer` module of the host running the assessment (`Get-DnsServerZone`, `Get-DnsServerScavenging`, `Get-DnsServerZoneAging`, `Get-DnsServerForwarder`; reads only). Per domain and primary zone, over every DNS server of the domain: **zone dynamic update** - `Nonsecure and secure` on an AD-integrated zone is a `Fail` (Microsoft recommends **Secure only** for AD-integrated zones; `Warning` by override), a zone that is not AD-integrated `Info`; **aging and scavenging** - zone aging off, or no hosting server with scavenging enabled (`ScavengingInterval` above zero), is a `Warning` (tool defaults: Microsoft says both must be enabled for cleanup but publishes no requirement). A zone replicated forest-wide (`Forest` or `Custom` scope) is graded once over the DNS servers of every scoped domain, and "no hosting server scavenges" is said of it only when the run covered the whole forest; a zone whose scope does not name its servers (`Legacy`, none) never gets that `Warning`. A DC that could not be read keeps every zone of its domain from passing; a value not returned or not recognised is `Not Assessed`. One `Zone configuration` inventory row per zone and server (type, replication scope, AD-integrated, dynamic update, aging). Forwarders and zone transfer as before, and since v1.36.0 a server with no zone open to transfer to any server gets a zone transfer `Pass` row over its primary zones (`Not Assessed` where a primary zone's setting was not returned, or no primary zone was read; secondary, stub and forwarder zones carry no such setting on Learn and are not counted) instead of no row. `-Credential` is **not** used for these reads: the `DnsServer` cmdlets are called with `-ComputerName` only and run as the account running the script. Unreachable, access denied, DNS provider missing, timed out and the module missing are separate causes. `-Sections DnsDepth` keeps the two critical SRV queries through the local resolver (a lookup that fails without saying the record does not exist is `Not Assessed`, not a `Fail`, and only answers of type SRV count, so a name that answers with its zone's SOA only is a `Fail`, since v1.36.0; root hints are not read, PORT-PLAN C13c); its secure dynamic update row now says where the check moved |
| **SYSVOL / DFSR** | DFSR migration global state of **the domain of the computer running the assessment only** (`dfsrmig /getglobalstate` on that computer; Microsoft says to run it on the PDC emulator, which is not checked; the row carries that domain and says so; per-domain engines are below); **SYSVOL and NETLOGON share presence per DC** (SMB-unreachable is reported as unknown, never as a missing share); and the two attributes a D2/D4-equivalent rebuild edits by hand — `msDFSR-Enabled=FALSE` (replication switched off) and `msDFSR-options=1` (authoritative member), with **more than one authoritative member reported as a conflict**, which no single DC can reveal - since v1.36.0 read by the SYSVOL engine read below from each scoped domain's own DCs (before, from a DC inventory property no row carried, so no subscription was ever read), and `Not Assessed`, never `Pass`, where no subscription was read or `msDFSR-Enabled` was not returned (an unset value and one this account cannot read look the same), each DC with its own cause; and (since v1.31.0) the **SYSVOL replication engine** per DC and per scoped domain, from the directory of that domain: the DC's DFSR SYSVOL subscription (`CN=SYSVOL Subscription,CN=Domain System Volume,CN=DFSR-LocalSettings,<DC>`) and its NTFRS subscriber (`CN=Domain System Volume (SYSVOL share),CN=NTFRS Subscriptions,<DC>`). A writable DC still on FRS or between FRS and DFSR is a `Warning` (`Fail` by override; FRS was removed in Windows Server 2019, and a 2019 or later DC cannot be promoted into an FRS domain); every writable DC on DFSR is a `Pass`; a refused or failed read is `Not Assessed`, never read as an absent object. `msDFSR-Flags` on `CN=DFSR-GlobalSettings` is quoted as corroboration only
| **SYSVOL backlog** | Opt-in (`-IncludeSysvolBacklog`): pending SYSVOL files **in both directions** between every DC and its domain's PDC emulator. `Get-DfsrBacklog` shows at most 100 records with the true total only in its verbose stream, so where that cannot be read the figure is reported as **"at least N"**, never as a total |
| **DFS Replication events** | Per-DC DFSR log scan for dirty shutdown (2213), content freshness stop (4012), membership disabled (4114/4144), waiting for initial sync (4614) and successful initialisation (4604) — **gated on log coverage** like the Directory Service scan, and silence with no 4604 is a `Warning`, not a pass
| Group Policy | Linked / unlinked GPOs (GroupPolicy module; `Get-GPO` has no `-Credential`, so it runs as the account running the script; the GPO central store is under Resilience); and **GPO version consistency** per scoped domain (part of `-Sections Gpo`, no module needed): each GPO's version in the directory (`versionNumber`) against its `GPT.INI` in SYSVOL, user and computer halves, both read from the domain's **PDC emulator**. A difference is a `Warning` (a **tool default**, `Fail` by override) that names the half and both numbers and says it can be replication in flight; a GPO that could not be compared is `Not Assessed` with its cause (unreachable, access denied, folder or `GPT.INI` absent, not parsed, `versionNumber` not returned, a `gPCFileSysPath` that is not the GPO's own folder); a SYSVOL folder named by a GPO GUID with no container visible is a `Warning`. A per-domain summary row states the containers read, compared, mismatched and not compared, and passes only when every one was compared and none differs. Details under [GPO version consistency](#gpo-version-consistency) And, since v1.32.0, **GPO Directory Inventory** (no module needed, inventory only): each GPO's status flags, WMI filter (`gPCWQLFilter` matched to its `msWMI-Som` object by GUID) and links, the `gPLink` entries of every site, domain and OU (disabled and enforced counted; `gPOptions` shown raw, since the value meaning block inheritance is not published) and per domain the linked and unlinked GPOs. A GPO whose links could not be read is never called unlinked, and because a GPO can be linked from any domain of the forest, "unlinked" is stated only when the `gPLink` of every forest domain was read (`-AllDomains`); otherwise a GPO with none found is "no link found" and the summary is `Not Assessed`. A link from another scoped domain's OU is credited to the GPO the link's DN names. |
| Policy | The default domain password policy and its lockout **threshold**; fine-grained password policies as inventory. Lockout duration, the observation window and the precedence and applies-to of fine-grained policies are not read (PORT-PLAN C16b) |
| Privilege | `-Sections PrivilegedAccounts` and `PrivilegedHygiene`. Per scoped domain, every privileged group located by SID (never by name) and expanded transitively - nested groups, primary-group members, foreign security principals by SID - with Schema Admins and Enterprise Admins graded (forest root; Warning at one member, a tool default) and every other group counted; a member that could not be resolved makes a count Not Assessed, never lower. adminCount=1 objects outside every protected group, enabled privileged users with an SPN, privileged accounts that can be delegated, Protected Users members. See [Privileged groups and delegation](#privileged-groups-and-delegation) |
| Security posture | krbtgt password age, AD Recycle Bin, tombstone lifetime, machine account quota (a value not returned is `Not Assessed`, since v1.36.0), and accounts with reversible password encryption or DES-only keys; **RC4 is not evaluated** (`msDS-SupportedEncryptionTypes` is not graded, PORT-PLAN C16b), stale and never-expiring accounts are under Stale objects below, and the permissions of AdminSDHolder are in Dangerous ACLs; and **SID history** per scoped domain (directory reads only, `sIDHistory` never written): the principals that carry it (`Warning` when any - a tool default, `Info` by override; `Pass` worded "none visible to this account" when the read succeeded and returned none), a historic SID of the principal's own domain (`Fail`), a privileged well-known RID or SID (`Fail`, named), and the source domains (`Info`: this forest, a trust partner, or "unresolved"). Details under [SID history](#sid-history). **Stale objects** (since v1.31.0, per scoped domain): enabled users and computers with no logon recorded for `-StaleDays` days, **never-logged-on accounts included** (no `lastLogonTimestamp`, `whenCreated` older than the cutoff), from a listed-property, capped read (never every property); every row states the domain's `msDS-LogonTimeSyncInterval` (14 days when not set) and that the real last logon can be up to that many days more recent, never more (Microsoft: updated when the value is "9 to 14 days older" under the default). Each domain's enabled users and computers are counted first as the declared population: a read that found nothing passes only when that count is at least one. **Enabled users with an old password** (`pwdLastSet` older than 365 days, a tool default; `pwdLastSet` 0 with `UF_DONT_EXPIRE_PASSWD` clear, "must change at next logon", counted, not graded; `pwdLastSet` 0 with it set is a password of unknown age, listed in its own column, and the row cannot pass while one exists). A failed or capped read, an interval of 0, a `-StaleDays` not longer than the sync interval, and an empty or uncounted population behind an empty result are `Not Assessed` And, in **Stale Objects** since v1.32.0, **Stale disabled users** and **Stale disabled computers** per domain: disabled accounts with no logon recorded for `-StaleDays` days (or never, and created before that), counted against the disabled accounts as the declared population, names in a column, inventory only (Microsoft publishes no stale threshold). |
| AD CS / PKI | Enrolment CAs, and an **ESC1 heuristic over the configuration of every certificate template object**: whether a CA publishes the template and who may enrol (the template ACL) are not read, so a `Fail` names a configuration to check, not a confirmed exposure (PORT-PLAN C16b) |
| Dangerous ACLs | `-Sections Acl`. Directory reads of `nTSecurityDescriptor` only, per scoped domain, read in memory (nothing written). Every principal is a **SID**, matched by SID against an allowlist - Microsoft's published default holders plus labelled tool defaults - and **never by name**, so a group named like a default group is still flagged. **DCSync rights** (a replication right on the domain head, alone or through all extended rights or full control), **Domain root control rights** (WriteDacl, WriteOwner, write of all properties, full control, or a non-default owner), **AdminSDHolder rights**, and one row per **GPO** with a per-domain summary. A flagged SID is a `Warning` (a **tool default**, `Fail` by override) and every row says the allowlist is **provisional**. A descriptor not returned, without a DACL, or unreadable is `Not Assessed` with its cause; unreachable, access denied and timed out are told apart. Details under [Dangerous rights in the directory](#dangerous-rights-in-the-directory) |
| Kerberos exposure | `-Sections Kerberos`. Kerberoastable (SPN) users, AS-REP-roastable accounts; per scoped domain, unconstrained delegation and protocol transition outside the domain controllers (excluded by the DN of their computer account from the configuration partition, never by name), Kerberos-only constrained delegation (inventory) and resource-based constrained delegation with the SIDs it allows |
| **DC hardening** | `-Sections DcHardening`. Per DC, six registry values, two CIM classes and the SMB server configuration (`Get-SmbServerConfiguration`) read in one session: **LDAP server signing** (`LDAPServerIntegrity`) and its Windows Server 2025 **enforcement** (`LDAPServerEnforceIntegrity`), **LDAP channel binding** (`LdapEnforceChannelBinding`), **SMB server and client signing** (`RequireSecuritySignature`), the **LAN Manager authentication level** (`LmCompatibilityLevel`), the **Print Spooler** service and the **SMBv1** server. Each value is graded against what Microsoft's security baselines expect on a domain controller. A value that is **not set** is graded on the default Microsoft documents for the DC's OS build where it documents one, named as a default; where it documents none it is `Not Assessed`, never a pass and never a failure. Unreachable, access denied, not set, key absent and wrong type are separate results. These rows show the **configured policy, not what a client and the DC negotiate on the wire**. The **SMBv1** row and the second instrument of SMB server signing are read with Microsoft's documented cmdlet `Get-SmbServerConfiguration` in the same session (PORT-PLAN C3f); SMBv1 is a `Pass` only where the DC returned `EnableSMB1Protocol` False. Details under [DC hardening](#dc-hardening) |
| **DC system** | `-Sections DcSystem`. **OS lifecycle**: each DC's operating system against Microsoft's extended support end date, from a versioned table. Past the date is a `Fail` whose text says whether an Extended Security Updates (ESU) programme is still running, has also ended, or was never published — and always that **ESU enrolment is not assessed**. An OS the table does not list, or one that could not be read, is `Not Assessed` with the raw values, never `Pass`. Reads only the directory, so it needs no rights on any DC. **Patch level**: per DC, OS build, uptime and the latest update install date over remote CIM; since v1.37.0 the build is shown in full (for example `17763.6532`), its fourth part the registry value `UBR` read with `StdRegProv` `GetDWORDValue` in the same session, display only (PORT-PLAN C1a). This half is **inventory** (`Info` or `Not Assessed`, never `Pass`): Microsoft publishes no maximum uptime or update age for a DC, so none is applied. Unreachable, access denied and other read failures are three different results
| **DC disk space** | `-Sections DcDisk`. Free space on the volumes that hold the **NTDS database**, the **NTDS logs** and **SYSVOL**, per DC. The three paths are read from each DC's own registry and matched to a volume by the longest mount path, so a database under a mounted folder is judged on the right volume. One row per distinct volume, listing the roles it holds. `Fail` below 10 % free or below 2 GB free, `Warning` below 20 % or below 5 GB — **tool defaults, not Microsoft values**, labelled as such in every finding and overridable with `-ConfigOverridePath`. A path or a volume that could not be read is `Not Assessed` with its cause; unreachable, access denied, a registry value that is not set and any other read failure are different results. Covers the DCs of every scoped domain, with or without `DomainControllers` selected; a domain whose DCs could not be enumerated gets its own `Not Assessed` row. Needs local Administrators rights on each DC |
| **Windows LAPS** | `-Sections Laps`. Directory reads only, with domain read access. **Schema**: whether the forest schema carries the six attributes `Update-LapsADSchema` adds, and the legacy Microsoft LAPS ones; absent, present and "the query failed" are three different results. **DSRM password backup**, one row per domain controller: `Pass` where a Windows LAPS expiry time that is not past is visible on the DC's computer object, `Info` (not applicable) for a DC below Windows Server 2019 or a domain below functional level 2016, `Warning` where nothing is visible although the account can read the attribute elsewhere in the domain. **LAPS coverage**, one row per scoped domain: how many enabled Windows computers that can run Windows LAPS have **no LAPS expiry time visible to this account** (Windows LAPS or legacy), with counts for every class left out of the population and a capped list of names. The section **never reads a password**: no password, encrypted password or password history attribute is ever requested. An attribute the account has no right to read looks exactly like one that is not set, and a device that backs its password up to Microsoft Entra ID has nothing here either, so no row calls a computer unmanaged with certainty; where nothing at all is visible in a domain the rows are `Not Assessed`. The thresholds are **tool defaults, not Microsoft values**, overridable with `-ConfigOverridePath`. The policy in each DC's registry is not read (PORT-PLAN C4a). Details under [Windows LAPS](#windows-laps) |
| **DC certificates** | `-Sections DcCertificates`. Per DC, two instruments, each named in every row's `Evidence` column. **Directory** (always, domain read access): the certificates a CA published on the DC's computer object (`userCertificate`), one row per certificate, graded on expiry. No published value is `Info`, never "no certificate": Microsoft's *Domain Controller Authentication* and *Kerberos Authentication* templates do not publish to the directory, and a value the account cannot read looks the same as none. **LDAPS** (only with `-IncludeLdapsHandshake`): the certificate the DC presents on port 636, read with one TLS handshake that sends no LDAP request, no bind and no credential and needs no right on the DC; without the switch each DC's `LDAPS certificate` row is `Not Assessed` and says why. Expired is `Fail`, at most 30 days left is `Warning`, not yet valid is `Warning` (this tool's rule) — the windows are **tool defaults, not Microsoft values**, overridable with `-ConfigOverridePath`. Refused, timed out, unresolved, handshake timed out and handshake failed are separate `Not Assessed` results, none of them read as "no certificate"; a refusal is told apart from a time-out within the handshake's own 5000 ms connection bound, and the whole handshake is bounded too. A published value that is not a single certificate (a PFX, a PKCS7 blob) is refused unopened. Trust, name and EKUs are reported in their own columns, not graded. The DC's own certificate stores are not read (PORT-PLAN C5a). Details under [DC certificates](#dc-certificates) |
| **RID pool** | `-Sections RidPool`. Directory reads only, with domain read access. Per scoped domain, two rows from `CN=RID Manager$,CN=System`: **RID pool allocation** - `msDS-RIDPoolAllocationEnabled` FALSE is a `Fail` (Microsoft: the RID master sets it at the RID ceiling and then issues no RID pool to any DC), TRUE is a `Pass`; an attribute that is not returned is `Not Assessed`, never a pass, because Microsoft documents that a read succeeds without the properties the caller may not read, so "not set" (the default) cannot be told from "not readable"; and an attribute the schema lacks is `Not Assessed` because Microsoft publishes no meaning for that; **Global RID space** - the two halves of `rIDAvailablePool` (RIDs issued, and the size of the space as read, never assumed), `Warning` from 10 % used and `Fail` from 90 % used, Microsoft's own points (event 16658 and the RID ceiling), overridable with `-ConfigOverridePath`; a size that is neither 1,073,741,823 nor 2,147,483,647 is `Not Assessed`. The 31-bit unlock is never claimed as read: `SidCompatibilityVersion` cannot be read with any tool, and the 31-bit size is matched by value. Per DC, as `Info`, the RID Set object `rIDSetReferences` names: current pool, next RID, what remains, and the prefetched next pool. A DC whose RID Set is absent (reference empty or dangling **and** a one-level search finds none - a known DC defect, KB 2618669), a refused read and an unreachable server are three different `Not Assessed` results. No dcdiag test is run. Details under [RID pool](#rid-pool) |
| DNS record export | Opt-in: `-Sections DnsRecordExport` is **not** part of `All`. Every record of every zone of every DC's DNS server (`Get-DnsServerResourceRecord -ZoneName`) to `csv\DnsRecords_<server>_<zone>.csv`, capped per zone at `RecordExportCap` (50000, a tool default; `Dns` override key), with one row per zone saying how many records were exported of how many and whether the cap was reached, and a total |
| Resilience | Directory backup status (`repadmin /showbackup`); the **time source of the computer running the assessment** (`w32tm /query /source`, which reads that computer only - each DC's time is under Recovery: time hierarchy; a query that failed or printed nothing is `Not Assessed`); DC count (read with `-Credential` since v1.36.0); the **GPO central store** (`PolicyDefinitions` in `\\<domain>\SYSVOL\<domain>\Policies`: a folder that could not be listed is `Not Assessed` with its class, a listed folder without it a `Warning`, a tool default - Microsoft publishes no severity); duplicate SPNs. FSMO concentration is not evaluated And, in **Time Configuration** since v1.32.0 (`-Sections TimeHierarchy`), each DC's W32Time `Type` and `NtpServer` (`W32Time\Parameters`) and `AnnounceFlags` (`W32Time\Config`), read with the two StdRegProv Get methods the tool already uses (local Administrators on the DC); inventory only. The Group Policy area that overrides them is not read, and each row says so.
| **Recovery: DNS vs AD** | DC locator SRV records compared against the DCs the directory actually contains — **on every DC's DNS server separately**, with a divergence summary ("3 of 7 answering servers advertise a DC that no longer exists"); plus the PDC locator record per server. Since v1.30.0, **per DC**: `DC locator records` - named by `_ldap._tcp.dc._msdcs` and `_kerberos._tcp.dc._msdcs` on every DNS server, by **two instruments** (the server's own zone with `Get-DnsServerResourceRecord`, and `Resolve-DnsName -DnsOnly -Server`); `Fail` only when both agree a record is missing, `Warning` (tool default) when only one could say so, `Info` for an RODC; the server's zone is read only when it is the zone that holds the name - a server holding only a parent zone with the name delegated below it, a stub or forwarder zone, or no zone, is an unread instrument, never an absence, and only Win32 9701/9714 ("DNS record/name does not exist") counts as no such record; `DC A record` - every A record for the DC's name is an IPv4 address its adapters hold (`Warning` otherwise, a tool default); and `Stale DC record` - a locator SRV target, or a `<guid>._msdcs` CNAME, that matches no domain controller in the directory (`Warning`, RODCs counted as known)
| **Recovery: DSA CNAMEs** | Per-DC `<DSA-GUID>._msdcs` alias verification (missing / wrong target, per DNS server) — the usual cause of RPC 1722 after metadata cleanup or restore — and orphaned NTDS Settings objects
| **Recovery: GC consistency** | Global Catalog flag in AD vs `_gc._tcp` DNS advertisement, per DNS server
| **Recovery: lingering objects** | Opt-in (`-IncludeLingeringObjectScan`) advisory-mode `repadmin /removelingeringobjects` pass per DC against the domain PDC, in the **domain naming context only** (the configuration partition, application partitions and global catalog partial replicas are not scanned, PORT-PLAN C16b) — finds lingering objects there before they block replication; changes nothing in the directory, writes events. Output with no count this tool can read is `Not Assessed`, never `Pass` (since v1.36.0) |
| **Recovery: port matrix** | Per-DC reachability on the replication port set (88/135/389/445 critical; 636/3268/9389 optional), separating "unresolvable" from "port closed"; and (since v1.31.0) a **DC reachability** class per DC of every scoped domain, decided **once per run before the first per-DC section** and reused by every per-DC section (since v1.34.0, PORT-PLAN C14c: a DC classified Unreachable is `Not Assessed` with its class in every section that connects to it - the port matrix row, the GPO SYSVOL read of a PDC and the partner DC of a trust included - and is probed by its name on no port again (the trust check still probes the trusted domain's own name, which is not a DC host name); only `PortMatrix` classifies, `Topology` alone does not; every other probe goes through the shared per-run cache, C1b): name resolution, LDAP (389) on each address, then WinRM (5985) and RPC (135). Unreachable by name resolution, refused, no answer or no route is a `Fail`; LDAP with both default management ports silent a `Warning`; LDAP with WinRM, or with RPC (DCOM), a `Pass`. No ICMP, one attempt per port, 3000 ms (a tool default). Access denied is not a reachability class Since v1.34.0 the port matrix takes the DCs of every scoped domain (PORT-PLAN C2e) and uses the classification's name resolution instead of resolving again |
| **Recovery: secure channels** | DC machine-account password age from the replicated `pwdLastSet` (collected centrally) and, per DC over WinRM where reachable, the secure channel's last recorded status from `nltest /sc_query` (read-only; the live `nltest /sc_verify` test only with `-IncludeSecureChannelVerify`)
| **Recovery: restore integrity** | `-Sections RestoreIntegrity`: the **`Dsa Not Writable` registry marker** per DC — the forensic evidence of a USN rollback that Microsoft names as the fallback when event 2095 *"may be overwritten before [it is] observed"*, so it is the one restore signal that does not depend on the event log surviving. Plus `invocationId` per DSA: a **shared value across two DCs is a cloned database** (`Fail`), and the per-DC values are emitted as a baseline so diffing `Assessment.json` between runs shows a DC that was restored in between
| **Recovery: DS events** | Per-DC Directory Service log scan for lingering objects (1988), tombstone-lifetime exceeded (2042), USN rollback (2095), unsupported restore (2103), source-GUID DNS failures (2087/2088), KCC failures (1311/1865/1925/1084) — **gated on log coverage**: the oldest retained record is compared against the lookback window, and a clean scan over a cleared, wrapped or unreadable log reports `Not Assessed` naming where coverage begins, never `Pass`. A count taken from a partial log is reported as a minimum And, since v1.32.0, **Event Inventory**: on every DC, the System, Directory Service, DFS Replication, DNS Server and File Replication Service logs read by level (Critical, Error, Warning) over `-EventLookbackDays`, at most 2000 events per log (`EventMaxEvents`, a tool default), grouped by event ID (at most 50 groups, `EventGroupCap`); a missing log is `Info` "log absent", a refusal or an unreachable DC `Not Assessed`, and a count at the bound or over a log that does not reach back is a floor, on the log row and on each event group row. "No events" is taken only after a one-event read of the log succeeds, because the filtered read answers a refusal as "no events". Inventory only.
| **Recovery: dcdiag grid** | 21 columns per DC, 19 of them tested in a default run (since v1.28.0; 18 and 16 before). `/test:DNS /DnsAll` (delegations, forwarders, dynamic update, record registration) and `SystemLog` are run only with `-IncludeDcdiagActiveTests`; without it those two cells read `Not Assessed` and the row's `NotRun` column says why. The `DNS` cell is the test's overall verdict; since v1.29.0 its summary table is also graded per test group in rows of their own (see Diagnostics above). `Intersite`, with the `/a` it needs to actually test anything, left the grid in v1.28.0 and runs once per site (see Diagnostics above). Every cell of a test that was attempted and could **not** be assessed carries its cause in the `Failures` column - the exit code, the error, and an excerpt of what dcdiag actually printed - so "Not Assessed" can never again mean "we are not telling you why". `FsmoCheck` and the opt-in `DNS`, which dcdiag prints under its "Running enterprise tests on" block, are graded from that block of the invocation against the DC, and a failed summary wins over the server block's "passed". When `Connectivity` fails, the tests not started on that DC are named in `NotRun`, not `Failures`. Note the verdict match is the literal English `passed test <name>`: on a non-English Windows the cells report `Not Assessed` with that named as the likely reason, rather than guessing |
| **Recovery: `_msdcs` delegation** | `-Sections MsdcsDelegation`: whether `_msdcs.<forest>` is a **zone of its own** (an SOA query answered by the *parent* zone means it is only a subdomain, which will not serve the forest-wide locator records), whether the parent holds delegation **NS** records, whether each NS target has a resolvable **glue (A)** record, and whether each NS host is a DC this run inventoried — stale NS records are what a metadata cleanup leaves behind. All four measured **per DNS server**, because the zone is AD-integrated and with replication broken the answer differs between servers |
| **Recovery: time hierarchy** | `-Sections TimeHierarchy`: every DC's **measured clock offset** via `w32tm /stripchart /rdtsc` (the one external-tool output Microsoft publishes a schema for) against the 300s Kerberos maximum, judged on the worst sample and stating that it measures divergence from the host running the assessment rather than absolute correctness; plus every DC's time source via `w32tm /query /computer:<dc> /source`. A DC sourcing time from its **virtualisation host** is a `Warning` — per KB 976924 two time sources can make a DC's clock jump, which *"can cause lingering objects to be left in caches, and may cause replication to stop"*. The **forest root PDC emulator** must not take time from the domain hierarchy it is the top of (W32Time logs event ID 12 for that), so its source and its configured client `Type` each get a row. Where Microsoft's own guidance on host time sync diverges for the PDC, the finding names **both** positions instead of picking one; and (since v1.31.0) **Clock offset vs forest root PDC** per DC: the difference between its stripchart reading and the forest root PDC emulator's, `Fail` at 300 s (Kerberos), `Warning` at 60 s (a tool default), with an error bound from the round trips (tool reasoning); a reference or DC not measured is `Not Assessed`
| **Recovery: per-site GC coverage** | `-Sections SiteGc`: joins `Site`, `IsGlobalCatalog` and `IsReadOnly` — which the DC inventory already collects and nothing correlated. A site holding DCs but none that is **both writeable and a GC** is a `Warning` naming what is actually there, because Microsoft requires the AD site hosting an Exchange server to contain at least one writeable domain controller that is also a global catalog server, and an Exchange server cannot be deployed in a site containing only read-only directory servers |
| Identity export | User and computer export (CSV; HTML shows a summary) with a **declared attribute list** per kind (`DirectoryRead.UserExportProperties`, 21 attributes; `DirectoryRead.ComputerExportProperties`, 18), never every attribute - **a breaking change in v1.33.0**, see below. Each domain is read from itself with the C15 seam (`Get-ADObject`, LDAP filter `(&(objectCategory=person)(objectClass=user))` or `(objectClass=computer)`, capped at `MaxObjects`); a capped read writes at most `MaxObjects` rows, each marked `ListComplete` "No", and a refused, failed, capped or empty read is `Not Assessed` in the summary with its cause. And, since v1.32.0, **Object Counts** (users, computers and groups each split enabled/disabled or security/distribution, contacts, OUs, gMSA, sMSA) from capped reads with listed properties - not from the export - and **Group Inventory** (scope and type, empty groups with a primaryGroupID caveat, direct member counts; 1500 values or more, the MaxValRange default, is not counted exactly; one row per group in `csv\Groups_<domain>.csv`, marked `ListComplete` "No" on every row when the read reached its cap). A failed export is `Not Assessed` in the summary, no longer 0. |
| Exchange | One schema marker, `ms-Exch-Schema-Version-Pt` `rangeUpper`, as inventory with no verdict; the organisation and domain `objectVersion` are not read (PORT-PLAN C16b) |
| **Exchange SE compatibility** | Forest functional level (read as the numeric `msDS-Behavior-Version`, so a level above the matrix is not mistaken for one below it) and **every DC's operating system** against the Exchange Server SE supported matrix, plus the read-only-DC caveat — from a versioned config table with a `-ExchangeSeConfigPath` override. The DC gate reads the DC inventory, so name `DomainControllers` with it, and it is a `Pass` only when every domain of the forest was read (`-AllDomains`) and no DC's operating system is unread; otherwise it is `Not Assessed` (since v1.36.0; a measured unsupported DC is a `Fail` either way). Deliberately narrow: it does *not* cover schema/organisation object versions, Exchange server inventory or coexistence builds. The per-site writeable-GC requirement is covered separately, as an AD health check, by `-Sections SiteGc` |

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
- `nltest`, `netdom`, `dcdiag`, `repadmin`, `w32tm` — optional; used where present. The uses
  Microsoft documents as changing state are opt-in: see [What a run can change](#what-a-run-can-change)
  and [docs/SIDE-EFFECT-AUDIT.md](docs/SIDE-EFFECT-AUDIT.md)
- [Pester](https://pester.dev) 5.0+ and
  [PSScriptAnalyzer](https://github.com/PowerShell/PSScriptAnalyzer) 1.21+ — for the quality gate

## Permissions

Domain read access is enough for most sections. Trust verification, `DcHardening` (CIM), the
patch-level half of `DcSystem` (CIM), `DcDisk` (CIM) and `dcdiag` need administrative rights on
the domain controllers. The OS lifecycle half of `DcSystem` needs
domain read only. For the opt-in `dcdiag` DNS test Microsoft documents more: "Membership in
Enterprise Admins, or equivalent, is the minimum requirement to complete the DNS tests" (KB
event 2087 page, read 2026-11-16; not verified against a real run, PORT-PLAN C12a).

The DC DNS client read (`DomainControllers`) reads each DC's adapters over remote CIM and needs
local Administrators rights on the DC, as `DcDisk` does. The `Dns`, `DnsAdConsistency` and
`DnsRecordExport` reads of each DNS server go through the `DnsServer` module of the host running
the assessment; Microsoft documents the rights needed to *configure* a DNS server (DnsAdmins or local
Administrators) but not those needed to read one, so a refusal is reported as access denied and no
minimum is claimed (PORT-PLAN C13a).

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

`RidPool` reads the directory with domain read access. Microsoft's default security descriptors
of the RID-Manager and RID-Set classes grant Authenticated Users read access. A changed ACL that
refuses the whole read shows as `Access denied`. One that hides a single attribute cannot be seen:
Microsoft documents that a read then succeeds without that attribute. That is why an allocation
attribute or a `rIDAvailablePool` that is not returned, and a RID Set that is not found, are
`Not Assessed` and never a pass; the tool does not evaluate the ACL (PORT-PLAN C6d).

The GPO version check of `Gpo` reads the `groupPolicyContainer` objects with domain read access
(Microsoft's default security descriptor grants Authenticated Users read; a GPO whose permissions
deny the account is not returned and not counted) and reads `GPT.INI` over the PDC's `SYSVOL`
share as the account running the script, with SMB (TCP 445) reachable from the host running the
assessment. `-Credential` is not used for those file reads. The default ACL of the SYSVOL share
was not found on Microsoft Learn, so a refused read is reported as `Access denied` and no default is
claimed.

**No read asks for every attribute (since v1.33.0, PORT-PLAN C4b) - a breaking change of the
`AllUsers_` and `AllComputers_` CSV files.** Up to v1.32.0 the Identity export ran
`Get-ADUser -Properties *` and `Get-ADComputer -Properties *`, and the trust health, site link and
connection reads did the same. Microsoft documents `*` as "all of the attributes that are set on the
object"; an account with the rights - a Domain Admin, the usual way this tool is run - is handed
confidential attributes with them (Microsoft: "only Administrators can read confidential
attributes"), among them the LAPS passwords, the legacy one in clear text; and a Windows Server 2025
DC logs Directory Service event 3079 for such a search over an unencrypted session and silently
leaves those attributes out. Every one of those reads now names its attributes in the `DirectoryRead`
config table, which no file can change. **What changes in the output:** the export's columns are no
longer "every attribute some object had" but the declared list, in its order, with raw LDAP names
and values (`objectSid`, `pwdLastSet` and `lastLogonTimestamp` as the directory stores them, a
multi-valued attribute joined with `;`), then `Enabled` (from the ACCOUNTDISABLE bit of
`userAccountControl`, empty when it was not returned) and `ListComplete`. The LAPS expiry time is no
longer an export column (the `Laps` section reads it). The computer export still includes managed
service accounts, which are computer subclasses. `Replication Connections` now has the columns
Name, FromServer (`fromServer`), DistinguishedName, Enabled (`enabledConnection`) and Options (raw
`options`); ToServer and AutoGenerated are gone, because Microsoft does not publish those property
names (PORT-PLAN C4b3). No list names a password, a password hash, a LAPS password, the gMSA password,
a trust secret or a BitLocker or TPM secret, and a test fails if one ever does, or if any read in the
script asks for every attribute through `-Properties`, its alias `-Property` or an abbreviation of
either. At run time each list is checked again before it is sent, and a list holding a wildcard, a
secret name, or a name that is not a plain attribute name (an option such as `;binary`, a range, an
OID) is refused and that read is `Not Assessed`. A capped read says whether its cap
(`Inventory.MaxObjects`) is the tool default or was set in the `-ConfigOverridePath` file. Delete any
`AllComputers_*.csv` that v1.20.0 or earlier produced under a privileged account: it may hold LAPS
passwords.

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

# Exchange Server SE compatibility only (forest functional level + DC operating systems);
# the DC gate needs the DC inventory of every domain of the forest
.\src\ADForestAssessment\Invoke-ADForestAssessment.ps1 -AllDomains -Sections Forest,Domains,DomainControllers,ExchangeSeReadiness

# ...judged against your own prerequisite table instead of the built-in one
.\src\ADForestAssessment\Invoke-ADForestAssessment.ps1 -AllDomains -Sections Forest,Domains,DomainControllers,ExchangeSeReadiness `
    -ExchangeSeConfigPath C:\Scripts\exchange-se-prereqs.json

# Free space on each DC's NTDS database, NTDS log and SYSVOL volumes, against your own thresholds
.\src\ADForestAssessment\Invoke-ADForestAssessment.ps1 -Sections DomainControllers,DcDisk `
    -ConfigOverridePath C:\Scripts\adfa-overrides.json

# Post-incident triage: the recovery sections plus the health checks they depend on,
# including the advisory-mode lingering-object scan (writes events on target DCs, changes nothing)
# and the SYSVOL backlog (two RPC round trips per DC, read-only)
.\src\ADForestAssessment\Invoke-ADForestAssessment.ps1 -AllDomains -IncludeLingeringObjectScan -IncludeSysvolBacklog -Sections `
    DomainControllers,DnsAdConsistency,DsaCname,GcConsistency,MsdcsDelegation,PortMatrix,Replication,Trusts,DcSecureChannel,DsEvents,RestoreIntegrity,TimeSync,TimeHierarchy,SiteGc,Sysvol,Backup
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
| Forest functional level | Windows Server 2016 (`msDS-Behavior-Version` 7) and Windows Server 2012 R2 (6). A lower level is a `Fail` that says to raise it; since v1.37.0 (PORT-PLAN H18) that advice no longer calls the raise permanent: Microsoft documents that a forest can be lowered again to a supported earlier level (no lower than Windows Server 2016 while any Windows Server 2025 DC is in the forest, otherwise Windows Server 2008), unless a feature tied to the new level has been enabled ([Lower domain and forest functional levels](https://learn.microsoft.com/windows-server/identity/ad-ds/plan/lower-domain-forest-functional-levels), read 2026-11-18). A **higher** level — Windows Server 2025 is 10 — is a `Fail` that says the level is not listed in the matrix, with no remediation command. An unreadable level is `Not Assessed` with its cause; a value that is not a known level is `Not Assessed` with the raw value shown |
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
judged. The file must be one JSON object, and its only key is `OsLifecycle`. Anything else stops
the run: a missing or malformed file, a top-level array, an empty object, a misspelt key, a
`null` value, or a row with a bad date or nothing to match on. A finding cites your file for its
dates only when the file supplied them. Since v1.34.0 `WsmanPort` and `RpcPort` are refused,
with the reason, as they are for `DcHardening` (PORT-PLAN C3g): the CIM session is always opened
on the default WinRM port (5985), or through the RPC endpoint mapper (135) for DCOM, so a port
set in the file changed only what was probed. `New-CimSession -Port` needs a WinRM listener on
that port, which only a change on the DC creates, and DCOM has no port option (Microsoft Learn,
read 2026-11-17).

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
- Since v1.37.0 (PORT-PLAN C1a) the build is shown in full, for example `Build 17763.6532`. The
  fourth part is the update build revision: the registry value `UBR` under
  `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion`. Microsoft names that value and key and
  compares it as an integer
  ([Deploy Windows update packages in Intune](https://learn.microsoft.com/intune/app-management/deployment/deploy-win32-update-package),
  read in full 2026-11-18), and calls it "the revision number of windows"
  ([OEM deployment of Windows desktop editions](https://learn.microsoft.com/windows-hardware/manufacture/desktop/oem-deployment-of-windows-desktop-editions),
  a search excerpt, 2026-11-18). `Win32_OperatingSystem` does not carry it. It is read with
  `StdRegProv` `GetDWORDValue` in the same CIM session: no new CIM method (the seam `DcHardening`
  already uses), but `DcSystem` now makes one CIM method call per DC.
  It is shown, never graded. A revision that could not be read - not set, key absent, access
  denied, not a `REG_DWORD` (Microsoft does not publish the registry type) or any other failure -
  is written as `Update build revision not read` with its cause, and the build is shown without
  it, never with `.0`. The key and value name cannot be set from `-DcSystemConfigPath`.

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

**Reading the registry is a CIM method call. Four sections make one: this section, `DcHardening`,
`TimeHierarchy` (the W32Time configuration, since v1.32.0) and `DcSystem` (the update build
revision, since v1.37.0); no other section does.** The values are
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
| `SMB server signing: <dc>` | `Services\LanManServer\Parameters`, `RequireSecuritySignature` | 1 | Not published for a DC on any build: graded on the SMB server's own configuration where `Get-SmbServerConfiguration` returned it (see "second instrument" below), otherwise `Not Assessed` |
| `SMB client signing: <dc>` | `Services\LanManWorkstation\Parameters`, `RequireSecuritySignature` | 1 | 2022 and earlier: documented default Disabled, a `Warning`. 2025: documented default required, a `Pass` named as a default |
| `LAN Manager authentication level: <dc>` | `Control\Lsa`, `LmCompatibilityLevel` | 5 | 2008 R2 to 2022: documented default 3, a `Warning`. 2025: `Not Assessed` - NTLMv1 is removed there and the default is not restated |
| `Print Spooler: <dc>` | `Win32_Service`, not the registry | Stopped | - |
| `SMBv1: <dc>` | `EnableSMB1Protocol` from `Get-SmbServerConfiguration -CimSession`, not the registry | False | - |

**SMBv1 is read with Microsoft's documented cmdlet (PORT-PLAN C3f, v1.35.0).** Microsoft's
detection of SMBv1 on a server is `Get-SmbServerConfiguration | Select EnableSMB1Protocol`, and
the cmdlet "Retrieves the SMB server configuration" and takes a `-CimSession`. The section runs
it in the session it already opened to the DC, with `-WhatIf:$false -Confirm:$false` (the
module declares this Get cmdlet with ConfirmImpact Medium), bounded by the session's timeout.
Before v1.35.0 the class was asked for as instances, and on the one host measured that query
returns nothing, so the row could never be graded. The row is a `Pass` only on a returned
`False`, and a `Fail` on `True`. Each other result is `Not Assessed` with its own cause:
the cmdlet not available on the computer running the assessment (the `SmbShare` module is
needed there), access denied, the class or its namespace not present on the DC, a read that
failed, no object returned, more than one object returned, and a property not returned as true
or false. A cause the tool wrote itself is said to be the tool's, never "Reported by the DC", and
the access-denied row names no rights, because the rights a remote read needs are not published.
The `LanmanServer\Parameters\SMB1` registry value is not read: Microsoft documents its absence as
the default, Enabled, only for Windows 7, Windows Server 2008 R2, Windows Vista and Windows Server
2008, and publishes no meaning of an absent value for later builds, so it could not grade the row
where it is not set. Measured on
one Windows 11 workstation (not a DC): the cmdlet runs under Windows PowerShell 5.1 and
PowerShell 7 and returns both properties as booleans. What a real DC returns, over WSMan and
DCOM, with which rights and with which error codes is PORT-PLAN C17a.

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

**SMB server signing has a second instrument.** The same `Get-SmbServerConfiguration` read
that gives the SMBv1 row also carries `RequireSecuritySignature`, and that cmdlet is Microsoft's
own verification ("If the returned information is True, then SMB signing is enabled"). So:

- Where the cmdlet returned the property and the registry value is set, the row is graded on
  the registry and says whether the second instrument agrees; if the two **disagree** the row is
  `Not Assessed`.
- Where the cmdlet returned the property and the registry value is not set, the row is graded
  on the second instrument, which is a measurement.
- Where it did not - any of the causes listed for SMBv1 - a registry value that is set is graded
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
connected to. Since v1.34.0 `DcDisk` and `-DcSystemConfigPath` refuse them in the same way
(PORT-PLAN C3g).

```json
{ "DcHardening": { "Settings": { "LmCompatibilityLevel": { "ExpectedMinimum": 3, "OtherStatus": "Fail" } } } }
```

Limits to keep in mind:

- None of this has met a real domain controller. The reads have run against stubs only; the
  first run against a real forest is PORT-PLAN C17.
- The timeout note under the patch-level rows above applies here too: up to nine CIM
  operations per transport for one DC (six registry reads, two queries and the
  `Get-SmbServerConfiguration` call, which has no timeout of its own and is bounded by the
  session's).
- The SMBv1 row, and the second instrument of SMB server signing, need the `SmbShare` module on
  the computer running the assessment; without it both are `Not Assessed` and say so. The cmdlet
  has been run against one Windows 11 workstation only, never against a DC (PORT-PLAN C17a).
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

**Changed in v1.35.0 (PORT-PLAN C3f).** The SMB server configuration is read with
`Get-SmbServerConfiguration -CimSession` instead of an instance query of
`MSFT_SmbServerConfiguration`, so the SMBv1 row can be graded and SMB server signing has its
second instrument. A `SmbServer` key in a `DcHardening` override is refused: the read is not
configurable.

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

## RID pool

`-Sections RidPool` (part of `All`) answers three questions: is RID pool allocation blocked in
each domain, how much of each domain's global RID space has been issued, and what RID pool each
domain controller holds now. **Run against stubs only** so far; the first run against a real
forest is PORT-PLAN C17, and C6a lists what that run must confirm.

| Row | Read from | Results |
| --- | --- | --- |
| `RID pool allocation: <domain>` | `msDS-RIDPoolAllocationEnabled` on `CN=RID Manager$,CN=System,<domain>` | FALSE `Fail`; TRUE `Pass`; `Not Assessed` when the attribute is not returned (Microsoft documents NOT SET as its default, but also that a read succeeds without the properties the caller may not read, so an unset value and an unreadable one look the same), where the schema does not define it, or could not be read, or the read failed |
| `Global RID space: <domain>` | `rIDAvailablePool` on the same object: the lower half is the RIDs issued, the upper half the size of the space | `Warning` from 10 % used, `Fail` from 90 % used; `Not Assessed` for a size that is neither documented value, a size of 0, or more issued than the size |
| `RID pool: <dc>` | `rIDSetReferences` on the DC's computer object, then the RID Set object: `rIDPreviousAllocationPool`, `rIDAllocationPool`, `rIDNextRID` | `Info` with the current pool, the next RID, what remains in the pool and the prefetched pool; `Not Assessed` otherwise, with one of the causes below |
| `RID pool - <domain>` | | `Not Assessed`: a scoped domain whose DCs could not be enumerated |

**The thresholds are Microsoft's.** Microsoft logs event 16658 at the first 10 % of the global
RID space used and calls it "not expected"; at 90 % used the RID master stops issuing RID pools
(event 16657) and sets `msDS-RIDPoolAllocationEnabled` to FALSE. Both points can be changed with
`-ConfigOverridePath` (`WarnAtPercentUsed`, `FailAtPercentUsed`), and a finding then cites your
file. The comparison is on integers: on the 30-bit space the Warning starts at 107,374,183 RIDs
issued and the Fail at 966,367,641, one RID past the figures Microsoft gives, because the
attribute holds where the next pool begins: the allocation of the pool that contains Microsoft's RID
leaves the lower half one past it at least, so the row turns on that same allocation. The
percentage shown is truncated to four decimals, never rounded up, so a row graded below a point
never shows that point (107,374,182 RIDs issued shows 9.9999 %).

**The size of the space is read, not assumed.** 1,073,741,823 is the default 30-bit space and
2,147,483,647 the 31-bit space after the unlock. That the attribute holds the second value after
the unlock is an inference from Microsoft's dcdiag example; the unlock itself is stored in
`SidCompatibilityVersion`, which Microsoft says cannot be read with ADSIEdit, LDP or other tools,
so the tool never claims to have read it.

**Per DC, the causes are kept apart:** `RID Set object absent` (the reference is empty or does
not resolve, and a one-level search under the computer object finds no RID Set either - a known
DC defect that Microsoft names as a RID pool leak, except on a read-only DC, for which Microsoft
publishes nothing), `Access denied`, `Unreachable`, `Timed out`, `Read failed`, `Not found` and
`Ambiguous` (no computer object or several), `Multiple references`, `RID Set empty` and
`Inconsistent` (the next RID outside the current pool). "Remaining in pool" is end - next + 1,
this tool's derivation: Microsoft does not say whether the end of a pool is inclusive. The
halves of the prefetched pool are read as Microsoft documents them for the current pool, which
is an inference and is said in the row.

**Not read**: `SidCompatibilityVersion`; the Directory-Services-SAM events 16653 to 16658; the
RID Block Size registry value; and `dcdiag /test:RidManager`, which this section does not run (the
DC Diagnostics section runs it, on Microsoft's description of it as checks only: the RID master
"is accessible", "contains the proper information", "can be located and contacted" and "has valid
RID pool values"; Learn does not say in so many words that it never requests a pool - PORT-PLAN
C6e, closed 2026-11-16).
Nothing is written: no attribute is set, and neither `msDS-RIDPoolAllocationEnabled` nor
`SidCompatibilityVersion` is ever touched.

## SID history

`-Sections SecurityPosture` (part of `All`) gives every scoped domain four SID history rows beside
the section's older rows. **Run against stubs only** so far; the first run against a real forest is
PORT-PLAN C17, and C7a lists what that run must confirm.

| Row | Read from | Results |
| --- | --- | --- |
| `SID history: <domain>` | `Get-ADObject -LDAPFilter '(sIDHistory=*)' -Server <domain>`, asking for `sIDHistory`, `objectSid`, `objectClass`, `sAMAccountName`, `distinguishedName` and `userAccountControl` only | `Warning` when any principal carries SID history (a **tool default**, the catalogue rule ADA-OBJ-009; `Info` by override); `Pass` when the read succeeded and returned none, worded "none visible to this account"; counts by class and enabled state, and the names up to a cap in their own column |
| `SID history same-domain: <domain>` | the same answer and the domain's own SID (`Get-ADDomain`) | `Fail` when a historic SID belongs to the principal's own domain; `Pass` when none does, or when no principal was returned; `Not Assessed` when the domain's SID was not read, or a value could not be parsed or a returned principal had no `sIDHistory` value read, and none failed |
| `SID history privileged: <domain>` | the same answer | `Fail` when a historic SID is a privileged RID (500, 502, 512, 516, 517, 518, 519, 520, 526, 527, on an account-domain SID) or SID (S-1-5-32-544, -548, -549, -550, -551, S-1-5-9), naming each by name and count in Detail ("Domain Admins (RID 512)", "Administrators (well-known SID)") and the SIDs in `HistoricSids`; `Pass`; `Not Assessed` as above |
| `SID history sources: <domain>` | the same answer, the trusted domain objects under `CN=System` (`securityIdentifier`), and the SID of every forest domain | `Info`: each source domain part with its count, labelled as a domain of this forest, a trust partner, builtin or well-known, not an account-domain SID, or "unresolved"; `Not Assessed` when principals were returned and no value was read on any of them |
| `SID history (no domain scoped)`, `SID history` | | `Not Assessed`: no domain scoped, or the forest unreadable |

**An empty answer is not proof.** By the schema's default security descriptors Authenticated
Users can read `sIDHistory` on users, groups and computers, but Microsoft documents that a search
returns no object or property the caller has no access to. The `Pass` therefore says "none visible
to this account". An unreachable domain, a refused read and a timed-out read are each their own
`Not Assessed` result, and all four rows of that domain carry the cause.

**Where Microsoft is silent, the tool says so.** Microsoft publishes no grade for SID history that
is present; it names eliminating SID history as one way to reduce token size, and Defender for
Identity reports "unsecure" SID history for removal. The `Warning` is this tool's default. The
same-domain `Fail` rests on Microsoft's DsAddSidHistory constraint (source and destination in
different forests, so that duplicate SIDs are not created in one forest) and on a move keeping the
SID of the domain the object left: that such a value indicates tampering is this tool's inference.
The privileged list is this tool's, read from Microsoft's well-known SID tables; Microsoft gives
only the Enterprise Admins example.

**SID parsing** reads bytes, text and SecurityIdentifier objects. Bytes are checked against the
SID layout first (revision 1, at most 15 sub-authorities, exact length), read by arithmetic that
keeps a RID of 4294967295 on Windows PowerShell 5.1 and PowerShell 7, and cross-checked with .NET
`SecurityIdentifier` where the platform has it: a value the platform refuses, or reads differently,
is not read. A malformed value is reported as not parsed, never as a crash and never as clean.

**Not read, not done**: whether a trust filters SID history (SID filtering, quarantine) is in the
Trusts section; the trusted domain objects of other forest domains; the security event log
("Add Sid History" events). Nothing is written: no `Set-ADUser -Remove`, no `netdom`, no
`SetSidFilteringStatus`. Names and SIDs are in their own columns (`Principals`, `HistoricSids`,
`SourceDomains`, `DomainSid`), never in the text a recommendation is chosen from.

## GPO version consistency

`-Sections Gpo` (part of `All`) gives every scoped domain a version check after the section's
inventory rows, which keep their shape. (One defect in them was fixed with C8: an unlinked GPO's
report has no `LinksTo` element, and reading it under StrictMode threw, so every domain holding
one unlinked GPO got the `(enumeration failed)` row instead of its linked and unlinked rows.) **Run against stubs only** so far; the first run against a
real forest is PORT-PLAN C17, and C8a lists what that run must confirm.

**What it reads, all from the domain's PDC emulator** - the DC Group Policy editing targets by
default - so that a difference is a difference on one DC, not between two:

1. `Get-ADDomain -Identity <domain>` for the PDC emulator and the domain's DN.
2. `Get-ADObject -Server <PDC> -SearchBase CN=Policies,CN=System,<domain DN> -SearchScope OneLevel
   -LDAPFilter '(objectClass=groupPolicyContainer)'`, asking for `versionNumber`, `gPCFileSysPath`,
   `displayName` and `flags` only (domain read access).
3. A probe of SMB, TCP 445, on the PDC. With no answer nothing in SYSVOL is read, and every GPO is
   `Not Assessed` as unreachable - a file is never reported absent unless the DC answered.
4. The folder names under `\\<PDC>\SYSVOL\<domain>\Policies`, and each GPO's `GPT.INI`, opened
   for read access only and sharing read, write and delete with every other handle - so a GPMC
   save or a DFSR install of the same file on the PDC is never refused because the tool holds it -
   and taken only up to 64 KB (a tool default). File reads run as the account running the
   script: `-Credential` is not passed to them. When the listing fails, the files are still read
   one by one only if it was refused as access denied; after any other failure (unreachable, timed
   out, not found) no file is read and every GPO is `Not Assessed` with the listing's cause.

The `GPT.INI` path is built from the PDC's name and the container's GUID. The host written in
`gPCFileSysPath` is **never contacted**: it is a value in the directory, and reading a path it names
would send this account's credentials to whatever host was written there. A `gPCFileSysPath` that is
not `\\<domain>\sysvol\<domain>\policies\<GUID>` for this domain and this GPO makes that GPO
`Not Assessed`, because the file clients read is then not the one this tool would read.

| Row | Results |
| --- | --- |
| `GPO version: {GUID}` | Written only when there is something to say. `Warning` (a **tool default**, the catalogue rule ADA-GPO-001; `Fail` by override) when the directory and `GPT.INI` versions differ, naming the half that differs - user (upper 16 bits) or computer (lower 16 bits), as Microsoft's MS-GPOL publishes - and both numbers, and saying that it can be replication still in flight. `Not Assessed`, each in its own words: `Unreachable:`, `Access denied:`, `Timed out:`, `Not found:` (the GPO's folder is not on this DC - an orphaned container or a folder not yet replicated - or the folder holds no `GPT.INI`), `Not parsed:` (no `[General]` section, no or two `Version` keys, not a 32-bit number), `Not returned:` (`versionNumber` not set or not readable), `Not read:` (a file above the size bound), `Not assessed:` (`gPCFileSysPath` not the GPO's own folder) |
| `GPO folder without container: {GUID}` | `Warning` (a tool default; `Info` by override): a folder under `Policies` named by a GPO GUID with no `groupPolicyContainer` visible to this account. Folders not named by a GUID, such as `PolicyDefinitions`, are counted and not graded |
| `GPO folder listing: <domain>` | `Not Assessed` when the `Policies` folder could not be listed, with the cause |
| `GPO version summary: <domain>` | Always one per scoped domain, with the containers read (`Population`), `Compared`, `Mismatched`, `NotAssessedCount` and `FoldersWithoutContainer` in their own columns; `Evidence` says `directory and SYSVOL` only when the `Policies` folder was listed or a `GPT.INI` version read, `directory` otherwise, `none` when the containers were not read. `Pass` only when at least one container was read, every one was compared and none differs; the mismatch status when any differs; otherwise `Not Assessed`. No container at all is `Not Assessed` - a domain holds at least the Default Domain Policy |
| `GPO version (no domain scoped)`, `GPO version` | `Not Assessed`: no domain scoped, or the forest unreadable |

**Where Microsoft is silent, the tool says so.** Microsoft publishes how the two versions are laid
out and that both are updated on every edit, but no grade for a difference and no time after which
one stops being transient; the `Warning` and the advice ("run again once replication has
converged") are this tool's. The `versionNumber` attribute is a signed 32-bit integer, so a user
half of 32768 or more reads as a negative number; it is taken as its 32-bit pattern, an inference
from the type. A `GPT.INI` is read as ANSI, as MS-GPOL requires, and a UTF-16 or UTF-8 file is
tolerated and named in the `Encoding` column.

**Not read, not done**: the `GroupPolicy` module's own version properties (Learn does not document
them; they are a second instrument for C17, PORT-PLAN C8b); the other DCs' SYSVOL copies; a
container this account cannot read, which is not counted and makes its folder look orphaned.
Nothing is written: no `Set-GP*`, no `Backup-GPO`, no `gpupdate`, and `GPT.INI` is never opened for
writing. A GPO's display name and its `gPCFileSysPath` are in their own columns (`GPOName`,
`FileSysPath`), never in the text a recommendation is chosen from.

## Dangerous rights in the directory

`-Sections Acl` (part of `All`) replaces the old DCSync check, which matched principals by **name**
(`Not Domain Controllers` passed because it contains `Domain Controllers`, and a localised name
failed), read through the `AD:` drive with `Get-Acl` (which ignores `-Server` and `-Credential`),
and turned every error into one row. It covers the AdAssessment26 catalogue rows ADA-ACL-001
(domain root), ADA-ACL-002 (AdminSDHolder) and ADA-ACL-003 (GPOs). **Run against stubs only** so
far; the first run against a real forest is PORT-PLAN C17, and C9a lists what it must confirm.

**What it reads**, per scoped domain, each from that domain (`-Server <domain>`, with
`-Credential` when given), asking for `nTSecurityDescriptor` and nothing else:

1. `Get-ADDomain -Identity <domain>` for the domain's DN and SID, and once for the forest root
   domain's SID (Enterprise Admins and Enterprise Read-only Domain Controllers are root SIDs).
2. `Get-ADObject -Identity <domain DN>` - the domain head.
3. `Get-ADObject -Identity CN=AdminSDHolder,CN=System,<domain DN>`.
4. `Get-ADObject -SearchBase CN=Policies,CN=System,<domain DN> -SearchScope OneLevel
   -LDAPFilter '(objectClass=groupPolicyContainer)'` - every GPO, linked or not.

The descriptor is turned into its binary form and read in memory with `RawSecurityDescriptor`:
the owner SID, whether a DACL is present, and every ACE in order. Not `GetAccessRules`: measured
on 2026-11-16, it reports a descriptor with **no DACL** as one "Everyone, full control" rule.
Reading the owner and the DACL needs `READ_CONTROL` on each object; Microsoft's default descriptors
give it to Authenticated Users on the domain head and on GPOs, and AdminSDHolder's default DACL is
not published. Which descriptor parts the ActiveDirectory module asks for is not published either:
if it asks for the SACL, an ordinary account may get `Not returned:` everywhere (PORT-PLAN C9a).
The SACL is not read. Nothing is written: no `Set-Acl`, no `Set-ADObject`, no `Persist`.

**How a right is decided** - by access mask bits, never by a rights name:
full control (`0xF01FF`, or the GENERIC_ALL bit), `WriteDacl` (`0x40000`), `WriteOwner`
(`0x80000`), write of all properties (`WriteProperty` with no object type, or GENERIC_WRITE),
all extended rights (`ExtendedRight` with no object type, which includes the three replication
rights), and each replication right by its GUID. A write scoped to one property, or another
extended right (Apply-Group-Policy on a GPO), is not graded. An object ACE scoped to the object's
own class or a class above it (for the domain head domainDNS, domain and top) is graded as if it had
no object type - the object itself is the top of the object type list, and a grant there applies to
everything below it; reading the whole class chain as the object is a tool rule that may over-report
and never under-reports. An object ACE scoped to any other GUID grants only that node: never
`WriteDacl`, `WriteOwner` or full control on the object, and only the replication right whose GUID it
names. An inherit-only ACE is skipped; an ACE
scoped to a child class without inherit-only **is** effective on the object (Microsoft documents
this) and is graded. A deny ACE cancels a grant only when it names the same SID, comes first,
applies to the object and covers every graded bit. The owner is graded as holding `WriteDacl`.

**The allowlist**, by SID only (`Config.Acl.Allowlist`):

| Principal | Where | Rights | Origin |
| --- | --- | --- | --- |
| SYSTEM `S-1-5-18` | domain head | all | Microsoft (domainDNS default descriptor) |
| SYSTEM `S-1-5-18` | AdminSDHolder | all | **tool default** (D14) |
| Administrators `S-1-5-32-544` | domain head, AdminSDHolder | all | Microsoft |
| Administrators `S-1-5-32-544` | GPOs | all | **tool default** (D14) |
| Domain Admins `<domain>-512` | domain head, AdminSDHolder | all | Microsoft |
| Enterprise Admins `<root>-519` | domain head, AdminSDHolder | all | Microsoft |
| Domain Admins, Enterprise Admins, SYSTEM, CREATOR OWNER `S-1-3-0` | GPOs | WriteDacl, WriteOwner, write of all properties | Microsoft (groupPolicyContainer default descriptor, which grants them no control access) |
| Domain Admins, Enterprise Admins, SYSTEM, CREATOR OWNER | GPOs | all extended rights, the replication rights | **tool default** (C9) |
| Enterprise Domain Controllers `S-1-5-9` | domain head | Get-Changes, In-Filtered-Set | Microsoft (domainDNS default descriptor) |
| Enterprise Domain Controllers `S-1-5-9` | domain head | Get-Changes-All | Microsoft (the RODC article: "only writeable DCs"; the domainDNS descriptor does not list it - the two pages disagree, PORT-PLAN C9d) |
| Domain Controllers `<domain>-516` | domain head | Get-Changes-All | Microsoft |
| Enterprise Read-only DCs `<root>-498` | domain head | Get-Changes **only** | Microsoft (RODCPREP; Get-Changes-All held by them is the misconfiguration Microsoft says to change back) |

A GPO's creator gets full control and ownership through Creator Owner, so a delegated creator is
flagged on purpose, so that the delegation is seen. Legitimate non-default holders exist -
Microsoft documents both replication rights for the Entra Connect AD DS connector account - and
are added by SID with `AdditionalAllowed` in the `Acl` section of the override file (below).

| Row | Results |
| --- | --- |
| `DCSync rights: <domain>` | ADA-ACL-001. The flagged grade (`Warning`, a tool default; `Fail` by override) naming each SID outside the allowlist that holds a replication right, and which; `Pass` otherwise |
| `Domain root control rights: <domain>` | ADA-ACL-001. The same for `WriteDacl`, `WriteOwner`, write of all properties, full control and ownership |
| `AdminSDHolder rights: <domain>` | ADA-ACL-002. Every graded right and ownership |
| `GPO rights: {GUID}` | ADA-ACL-003. One per GPO the search returned |
| `GPO rights summary: <domain>` | `Population`, `ReadCount`, `FlaggedCount`, `NotAssessedCount`; `Not Assessed` as a defect in the tool unless there is one GPO row per container returned. The flagged grade when any GPO is flagged; `Not Assessed` when any could not be read, when none is visible (a domain holds its two default GPOs) or when the search failed; `Pass` only when every GPO was read and none is flagged |
| `Dangerous ACLs (no domain scoped)`, `Dangerous ACLs` | `Not Assessed`: no domain scoped, or the forest unreadable |

`Not Assessed`, each in its own words: `Unreachable:`, `Access denied:`, `Timed out:`, `Read
failed:`, `Not returned:` (the answer held no `nTSecurityDescriptor` - a read can succeed without
the attributes the account may not see), `No DACL returned:` (cannot be told from an object with no
DACL, which lets anyone do anything), `Not read:` (not a descriptor), an ACE of a type the tool
does not interpret, and an account SID that could not be decided because a domain SID was not
read (with the forest root's SID unread, the scoped domain's own -519 and -498 too). The last two
apply only when no SID is flagged: a flagged SID takes the grade, and the Detail names what was not
interpreted or decided. A NULL DACL (`NULL DACL:` - the present flag set and no ACL), which Microsoft
documents as granting full access to any user, is graded as Everyone (`S-1-1-0`) holding every right
of the row. Detail names SIDs only; display names are in the `Principals` column, resolved for display
only and marked `unresolved` when they cannot be, and never used for a decision.

**Not read, not done**: the SACL; group membership (a group is graded as its own SID, and a deny on
a group the principal belongs to is not honoured); the permissions of a GPO's folder in SYSVOL
(PORT-PLAN C9b); objects other than the three kinds above. Which .NET type the ActiveDirectory
module returns for `nTSecurityDescriptor`, and which descriptor parts it asks for, is not
published; an `ActiveDirectorySecurity` and a byte array are both read, and anything else is
`Not Assessed`.

## Privileged groups and delegation

`-Sections PrivilegedAccounts`, `PrivilegedHygiene` and `Kerberos` (all part of `All`) share one set
of directory reads, made once per run for the sections selected. They cover the AdAssessment26
catalogue rows ADA-PRIV-001 and -002 (Schema Admins, Enterprise Admins), ADA-INV-005 (privileged
group counts), ADA-OBJ-001 (adminCount orphans), ADA-OBJ-002, -003 and -004 (unconstrained
delegation, protocol transition, resource-based delegation), ADA-OBJ-006 (SPN on a privileged
account) and ADA-INV-017 (Kerberos-only constrained delegation), and add one row of their own
(privileged accounts that can be delegated). **Run against stubs only** so far; the first run
against a real forest is PORT-PLAN C17, and C10a lists what it must confirm.

**What it reads**, read-only, each from the domain it is about (`-Server <domain>`, with
`-Credential` when given):

1. `Get-ADDomain` for every domain of the forest: its DN and SID, so that a member DN is read from
   the domain that holds it, and its `DomainMode` (whether Protected Users blocks delegation there).
2. Per scoped domain, each group of `Config.Privileged.Groups` with `Get-ADObject -LDAPFilter
   '(objectSid=<SID as escaped bytes>)'` - by SID, never by name. Every member DN with
   `Get-ADObject -Identity <DN>` from its own domain; nested groups followed, security and
   distribution alike (Learn: protection follows either); and `(primaryGroupID=<RID>)` for every
   group with a domain SID, because primary-group membership is not in `member` (with
   `-ResultSetSize` set to one more than what is left of `MaxExpandedObjects`).
3. Per scoped domain, `(adminCount=1)`, and one delegation search:
   `(|(userAccountControl:1.2.840.113556.1.4.803:=524288)(userAccountControl:1.2.840.113556.1.4.803:=16777216)(msDS-AllowedToDelegateTo=*)(msDS-AllowedToActOnBehalfOfOtherIdentity=*))`.
   The Kerberoast and AS-REP reads are unchanged.
4. Once per run, whichever of the three sections runs, under `CN=Sites` of the configuration
   partition, every `nTDSDSA` object and every `server` object's `serverReference`: a server holding
   an `nTDSDSA` child is a domain controller, and its `serverReference` is the DN of its computer
   account. The population is used only when it is complete: at least one `nTDSDSA` object (a
   forest always has a DC), every DC server object with a `serverReference`, and every `nTDSDSA`
   object matched to its server. And `dSHeuristics` on `CN=Directory Service,CN=Windows NT,CN=Services`.

**Declared populations** (each checked before anything is passed):

- The group reads of a domain must find each DC registered for it among the members of Domain
  Controllers or Read-only Domain Controllers (directly, nested or by `primaryGroupID` 516/521,
  Microsoft's defaults). Otherwise the population row is `Not Assessed`, and an empty Schema Admins
  or Enterprise Admins is not passed.
- The `(adminCount=1)` search must return the domain's built-in Administrator (RID 500): Appendix C
  lists it as protected, and Learn says a protected account has `adminCount` set to 1. The
  privileged-account population of the SPN and delegable rows must hold it too.
- The delegation search must return every DC registered for the domain (its computer account in the
  domain's own naming context, not a child's): Learn documents that a writable DC carries
  `TRUSTED_FOR_DELEGATION` and an RODC `TRUSTED_TO_AUTH_FOR_DELEGATION` by default, and the search
  asks for either bit. This expectation is a tool rule built on those defaults.

When one fails, no row built on it is `Pass` (the Constrained count is not given); a row that found
accounts keeps its grade and says the search may be incomplete.

Named attributes only (`objectClass`, `objectSid`, `sAMAccountName`, `userAccountControl`,
`adminCount`, `servicePrincipalName`, `primaryGroupID`, `member`, `msDS-AllowedToDelegateTo`,
`msDS-AllowedToActOnBehalfOfOtherIdentity`, `serverReference`, `dSHeuristics`), never a wildcard.
Nothing is written: no `Set-AD*`, no `Add-ADGroupMember`, no `Set-ADAccountControl`, and never the
rootDSE modify `RunProtectAdminGroupsTask` that Appendix C documents for triggering SDProp.

**The groups** (`Config.Privileged.Groups`, from Learn's security-groups reference): Administrators,
Account, Server, Print and Backup Operators and Replicator (builtin SIDs, every domain); Domain
Admins, Domain Controllers, Read-only Domain Controllers, Key Admins, Cert Publishers, Group Policy
Creator Owners and Protected Users (`<domain>-RID`, every domain); Schema Admins, Enterprise Admins,
Enterprise Read-only Domain Controllers and Enterprise Key Admins (`<root>-RID`, forest root only).
The protected ones are Appendix C's list plus Enterprise Read-only Domain Controllers, which the
security-groups page marks as protected and Appendix C does not (the pages disagree; counting it can
only keep an object from being called an orphan). Learn's pages also disagree on Key Admins and
Enterprise Key Admins: -526 is looked up in every domain; -527 in the forest root only, because the
domain-wide updates page (Operation 85) names "rootdomain\Enterprise Key Admins" and calls a
domain-relative -527 in a nonroot domain "a nonresolvable -527 SID" - the root's group then counts as
a protected source for every child domain. One that is absent is "not present" (Learn: both are
created only once a Windows Server 2016 DC holds the PDC emulator role). DnsAdmins (variable RID,
not protected) is not read: PORT-PLAN C10b.

| Row | Results |
| --- | --- |
| `Schema Admins members: <root>` | ADA-PRIV-001. `Warning` (a tool default; `Fail` by override) at one transitive member or more - users, computers and foreign security principals, nested groups followed but not counted; `Pass` when none is visible; `Not Assessed` when the group was not read, or none was resolved and a reference was not. A member found stands even when another reference could not be resolved, and the row says the true number may be higher. Learn: Schema Admins "is intended to be populated only temporarily and occasionally" |
| `Enterprise Admins members: <root>` | ADA-PRIV-002. The same. Learn's default member and "possible exception" - the forest root's built-in Administrator - is counted, as the catalogue rule says, and quoted; `EnterpriseAdminsExemptRootAdministrator: true` leaves it out |
| `Privileged group: <name>: <domain>` | ADA-INV-005. `Info` with the count; `Not Assessed` with the count left empty when any reference was not resolved (never a lower number); `Info` "Not present" for a group Learn documents only from a later level (RODCs, Key Admins, Enterprise Key Admins, Protected Users, Enterprise RODCs); `Not Assessed` for one that must exist. 17 rows in the forest root, 13 in a child domain |
| `Privileged group population: <domain>` | `Pass` when every declared group was located and expanded completely, or is optional and absent, and the domain's registered DCs were found in its DC groups; `Not Assessed` otherwise, naming the groups or the check that failed |
| `adminCount orphans: <domain>` | ADA-OBJ-001. Every object `(adminCount=1)` returned - users, computers and groups, enabled or not - that no protected group of the domain or the forest root reaches (a protected group's own object, its nested groups and its foreign members count as reached), and that is not the domain's Administrator or krbtgt: `Warning` (tool default). `Not Assessed` when any protected group was not read completely (the objects are listed as candidates), when the search did not return the domain's Administrator (RID 500), or when an object is protected only through Account, Server, Print or Backup Operators and `dSHeuristics`' `dwAdminSDExMask` (character 16) is not `0` or was not read - Learn does not publish which bit removes which group. Learn says "formerly protected"; "orphan" is this tool's word |
| `Privileged accounts with SPN: <domain>` | ADA-OBJ-006. Enabled user accounts of the domain that are protected-group members or carry adminCount=1 and have a `servicePrincipalName`: `Warning`. Computer accounts and krbtgt are not in the population; the SPNs are in `Targets`, for the same accounts `Principals` lists. `Not Assessed`, never `Pass`, when the population is empty or lacks the domain's Administrator |
| `Privileged accounts delegable: <domain>` | Not a catalogue row: a C10 addition. Enabled privileged user accounts (protected-group members and the Administrator; disabled ones are left out) that can be delegated: `Warning`. `NOT_DELEGATED` ("Account is sensitive and cannot be delegated") always protects. Transitive Protected Users membership protects only at domain functional level Windows Server 2012 R2 or later (`DomainMode` `Windows2012R2Domain`, `Windows2016Domain` or `Windows2025Domain`): Learn says the DC-side restrictions, delegation among them, need that level. Below it the member is delegable and graded; with the level unread or not one of those values it is undecided. Undecided, never a finding, when Protected Users was not read; `Not Assessed` on an empty population |
| `Protected Users members: <domain>` | `Info` with the count, or "Not present" |
| `Kerberoastable user accounts (SPN set)`, `AS-REP roastable accounts (no pre-auth)` | Unchanged grades; names moved from Detail to `Principals` |
| `Unconstrained delegation: <domain>` | ADA-OBJ-002. `TRUSTED_FOR_DELEGATION` (524288) on an account that is not a registered DC: `Warning`. DCs and RODCs are excluded by the DN of their computer account (from `serverReference`) - never by name, and never by `primaryGroupID` 516/521, which an account can carry without being a DC (such accounts are graded, and counted in Detail). `Not Assessed` when the DC population was not read completely, and - with no account found - when the search did not return every DC registered for the domain |
| `Protocol transition delegation: <domain>` | ADA-OBJ-003. `TRUSTED_TO_AUTH_FOR_DELEGATION` (16777216), with the same exclusion: an RODC carries it by default (Learn, replication error 8453) |
| `Constrained delegation: <domain>` | ADA-INV-017. `Info`: `msDS-AllowedToDelegateTo` set and protocol transition not; targets in `Targets` |
| `Resource-based delegation: <domain>` | ADA-OBJ-004. `msDS-AllowedToActOnBehalfOfOtherIdentity` present: `Warning`. Its descriptor is read in memory (the C9 converter) and the SIDs it allows and denies are listed in `AllowedSids`; one that could not be read is counted and marked |
| `... (no domain scoped)`, `Privileged groups`, `Privileged hygiene`, `Kerberos exposure` | `Not Assessed`: no domain scoped, or the forest unreadable |

`Not Assessed`, each in its own words: `Unreachable:`, `Access denied:`, `Timed out:`, `Read
failed:`, `Not found:`, and for a member reference "out of scope" (a forest domain this run did not
scope - `-AllDomains` scopes them all; the reference rule, AdAssessment26 decision 56), "domain not
decided", "not found", or a member list of exactly 1500 or 5000 values, which may be cut at
`MaxValRange` (whether the ActiveDirectory module does range retrieval is not published). A run
reads at most `MaxExpandedObjects` (5000, a tool default) objects - member reads and primary-group
search results together. A member in a scoped domain whose own `Get-ADDomain` read failed carries
that domain's cause (unreachable, access denied, timed out), not "out of scope". A SID lookup that
returns two objects is "ambiguous", not a refusal. Names, SIDs, DNs and SPNs
are in `Principals`, `PrincipalSids`, `ForeignSids`, `Unresolved`, `Targets` and `AllowedSids`, never
in Detail, so they cannot change the advice.

## One override file for section config: `-ConfigOverridePath`

A JSON file whose top-level keys are section names. Each value is checked by that section's own
rules. Ten sections can be named so far, `DcDisk`, `DcHardening`, `Laps`, `DcCertificates`,
`RidPool`, `SidHistory` (used by `SecurityPosture`), `Gpo`, `Acl`, `Privileged` (used by
`PrivilegedAccounts`, `PrivilegedHygiene` and `Kerberos`) and `DcDiag` (used by `DcDiagnostics`:
`TestTimeoutSeconds`, 5-600, and `Retries`, 1-10, per dcdiag invocation; tool defaults, not
Microsoft values; no test list can be set, so a file can never add a dcdiag test); later checks
add their own key.

```json
{
  "DcDisk": {
    "WarnBelowPercent": 25,
    "FailBelowPercent": 15,
    "WarnBelowFreeGB": 10,
    "FailBelowFreeGB": 5
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
  },
  "RidPool": {
    "WarnAtPercentUsed": 10,
    "FailAtPercentUsed": 90
  },
  "SidHistory": {
    "PresentStatus": "Warning",
    "NameListCap": 25
  },
  "Gpo": {
    "MismatchStatus": "Warning",
    "OrphanFolderStatus": "Warning"
  },
  "Acl": {
    "FlaggedStatus": "Warning",
    "AdditionalAllowed": [
      {
        "Sid": "S-1-5-21-1-2-3-1105",
        "Objects": [ "DomainRoot" ],
        "Rights": [ "DS-Replication-Get-Changes", "DS-Replication-Get-Changes-All" ],
        "Reason": "Entra Connect AD DS connector account"
      }
    ]
  },
  "Privileged": {
    "SchemaAdminsStatus": "Warning",
    "EnterpriseAdminsExemptRootAdministrator": false,
    "NameListCap": 25,
    "MaxExpandedObjects": 5000
  },
  "DcDiag": {
    "TestTimeoutSeconds": 180,
    "Retries": 2
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
  built-in ones, and at least one threshold must remain above 0. `Paths`, `SourceUrl` and
  `ReadDate` cannot be set from the file, and `WsmanPort` and `RpcPort` are refused (see below).
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
- For `RidPool` the two keys above are the only ones, each a whole JSON number from 1 to 99, and
  `FailAtPercentUsed` must be above `WarnAtPercentUsed` once merged. The known sizes of the
  global RID space, the location of `CN=RID Manager$` and every attribute name are refused, so a
  file cannot make the tool read another attribute or grade against a size it did not read.
- For `SidHistory` the two keys above are the only ones: `PresentStatus` is the text `Warning` or
  `Info` (SID history that is present is never a pass, and same-domain and privileged values
  stay a `Fail`), and `NameListCap` a whole JSON number from 0 to 1000. The privileged RIDs and
  SIDs, the filters and the property lists are refused, so a file cannot make the tool ask for
  every attribute or stop a privileged SID from failing.
- For `Gpo` the two keys above are the only ones: `MismatchStatus` is the text `Warning` or
  `Fail`, and `OrphanFolderStatus` the text `Warning` or `Info` (neither is ever a pass). The
  filter, the property list, the share, the folder and file names, the port and the size bound
  are refused, so a file cannot make the tool read another path or ask for every attribute.
- For `Acl` the two keys above are the only ones: `FlaggedStatus` is the text `Warning` or `Fail`
  (a principal outside the allowlist is never a pass), and `AdditionalAllowed` a non-empty list
  of objects with exactly `Sid` (a SID in its text form - a name is refused), `Objects`
  (`DomainRoot`, `AdminSDHolder`, `Gpo`), `Rights` (`WriteDacl`, `WriteOwner`,
  `WriteAllProperties`, `AllExtendedRights`, `DS-Replication-Get-Changes`,
  `DS-Replication-Get-Changes-All`, `DS-Replication-Get-Changes-In-Filtered-Set`; no `*`) and a
  `Reason` that is not blank. Everyone, Anonymous Logon, Authenticated Users, Users, Guests and
  RIDs 513, 514 and 515 of any domain can never be added. The built-in allowlist, the masks, the
  GUIDs, the filter and the property list are refused.
- For `DcDisk`, `WsmanPort` and `RpcPort` are refused since v1.34.0 (PORT-PLAN C3g), as for
  `DcHardening`. Until then they changed only the port that was **probed** before a read: the CIM
  session is opened without a port, so it still went to the default one. A file that names either
  key now stops the run with that reason; remove the key. This is a breaking change for a file
  written for v1.33.0 or earlier.
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
| `dcdiag /test:SystemLog`, per DC | Only with `-IncludeDcdiagActiveTests` (since v1.28.0) | "Validates the System Event Log's health by reading and writing entries from the past 60 minutes for any errors and warnings." Microsoft does not say what is written, and the wording may be a documentation error; until Microsoft says it only reads, it is treated as changing state (read 2026-11-16) |
| `dcdiag /test:Intersite /a`, once per site that holds a DC (per DC before v1.28.0) | Only with `-IncludeDcdiagActiveTests` | Works by "reporting back any replication failures after triggering a replication." |
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

From v1.28.0 `SystemLog` joins them (Microsoft's text says it writes), and `Intersite` runs once
per site rather than once per DC; without the switch one "dcdiag Intersite: not run" row says so.

From v1.29.0 the DNS test, when the switch is given, is graded per test group from its summary
table (Auth, Basc, Forw, Del, Dyn, RReg, Ext), per DC and per domain, with no further `dcdiag`
invocation and no further switch; without the switch one "dcdiag DNS not run" row per domain
says so.

From v1.30.0 the DNS sections (PORT-PLAN C13) read DNS with `Get-DnsServerZone`,
`Get-DnsServerScavenging`, `Get-DnsServerZoneAging`, `Get-DnsServerForwarder`,
`Get-DnsServerResourceRecord` and `Resolve-DnsName -DnsOnly`, and each DC's adapters with
`Win32_NetworkAdapterConfiguration` instances: no `Set-`, `Add-`, `Remove-`, `Start-` or
`Clear-DnsServer` cmdlet, no method of the adapter class, no `dnscmd`, no `ipconfig` (its
`/registerdns` re-registers a computer's DNS records; Microsoft's dynamic update page tells DHCP
clients to use `ipconfig /renew` rather than `/registerdns`, and its DC DNS client page tells you to
run `/registerdns` after changing the settings - either way it writes, so this tool never runs it)
and no `nltest /dsregdns` or `/dsderegdns`. A test parses the script and fails on a DnsServer or
DnsClient cmdlet that writes, on `dnscmd` or `ipconfig` named as a command or as a string argument of
any command (the script starts console tools through `Invoke-ExternalCommand -FilePath '<tool>.exe'`),
and on a registration or cache switch (`/registerdns`, `/dsregdns`, `/dsderegdns`, `/flushdns`,
`/release`, `/renew`) in any string literal outside the recommendation map, whose advice names them
for the operator to run. What it cannot see: a switch assembled at run time from pieces.

From v1.31.0 (PORT-PLAN C14) a default run also resolves each DC's name and opens one TCP
connection to LDAP 389, WinRM 5985 and RPC 135, sending no data; opens each DC's
`\\<dc>\ADMIN$\debug\netlogon.log` for reading only, sharing read, write and delete with Netlogon,
which keeps writing it; runs `w32tm /stripchart` once more for the forest root PDC when it is not
among the DCs asked; and reads `msDS-LogonTimeSyncInterval`, the stale accounts (listed properties
only), `CN=DFSR-GlobalSettings` and each DC's SYSVOL subscription and NTFRS subscriber. No
`dfsrmig /setglobalstate`, no `w32tm /resync`, `/config`, `/register`, `/unregister` or `/debug`, no
`Set-AD*`, `Disable-ADAccount` or `Remove-*`, no registry write through `Set-`, `New-`, `Remove-`,
`Rename-` or `Clear-ItemProperty` or a `StdRegProv` `Set*`, `Create*` or `Delete*` method; a test parses
the script and fails on any of them outside the recommendation map and the finding rows. That test
reads command names only. A registry write through a .NET instance method (`SetValue`, or a key
opened for writing with a two-argument `OpenSubKey`) is caught by the H20a test below instead.

Everything a default run invokes is listed in
[docs/SIDE-EFFECT-AUDIT.md](docs/SIDE-EFFECT-AUDIT.md) (PORT-PLAN H20a), one row per command,
console tool form (through `Invoke-ExternalCommand` or started directly, as `nltest.exe` is in the
script block run over WinRM), CIM class and method, static .NET member, `New-Object` type and
instance method name. Not every row was read on Microsoft Learn: 38 default rows rest on a page
that was not read on 2026-11-18 (the ActiveDirectory Get cmdlets other than `Get-ADObject`,
`Remove-CimSession`, most of the .NET entry points and the instance methods with reach), so they
say `not documented`, and reading them is PORT-PLAN H20c. A test parses the script and fails on any
command, tool form or instance method name the inventory does not hold, on a row the script no
longer reaches, on a tool started with a name or arguments the test cannot read (a direct start is
keyed by its tool form, never by the bare tool name), on `OpenSubKey` with more than one argument,
on a method name it cannot read, on a dynamic call outside four named ones, and on a default row
that carries a documented change. What it cannot see: the object an instance method is called on
(a listed name called on another object passes), property assignments, and what a tool does that
its page does not say. The result: of the pages read, none documents a change of state for anything
a default run invokes, and no command had to be moved behind a new switch; nothing is claimed for
the pages not read. The rows, by verdict:

| Verdict | Rows |
| --- | --- |
| documented read | 56 |
| documented change, opt-in | 7 |
| not documented | 54 |
| local output (by design) | 6 |
| in-process | 127 |

`documented read` means Learn describes it as a query, read or display; `not documented` means
Learn says nothing either way, the page was not read in this session, or there is no page - never
that nothing happens. `repadmin /showbackup` has no Learn reference page and `dcdiag
/test:FsmoCheck` is not in Learn's dcdiag reference (PORT-PLAN C11c); both stay in the default run
as `not documented`. `repadmin /showrepl * /csv` contacts every DC of the forest, and Learn warns
that the wildcard can cause "a significant increase in network traffic". Four effects no page read
covers are rows of their own: logon auditing on each DC, whether reading the remote registry
starts the Remote Registry service (Learn documents only that the service must be running and
stops after ten idle minutes), the DNS client cache of the host running the assessment, and
Schannel events of the opt-in LDAPS handshake.

Four sections' remote reads are CIM method calls rather than instance queries: `DcDisk` reads
three registry values per DC with `StdRegProv` `GetStringValue` and `GetExpandedStringValue`,
`DcHardening` reads six with `GetDWORDValue`, `TimeHierarchy` reads the W32Time `Type`,
`NtpServer` and `AnnounceFlags` values with `GetStringValue` and `GetDWORDValue` (since v1.32.0),
and `DcSystem` reads `UBR` with `GetDWORDValue` (since v1.37.0). Why they are treated as reads, and what
Microsoft does and does not say about it, is under [DC disk space](#dc-disk-space).

## Secure channel checks

Three checks look at a Netlogon secure channel: the outbound direction of each trust (asked
from the host running the assessment of the PDC emulator of the domain assessed, with
`nltest /server:<dc>`, the form of Microsoft's Example 3; since v1.36.0), the inbound direction (on a domain controller of the trust
partner, over WinRM), and `-Sections DcSecureChannel` (on every DC of the scoped domains, over
WinRM).

| | Default | With `-IncludeSecureChannelVerify` |
| --- | --- | --- |
| Command | `nltest /sc_query` | `nltest /sc_verify` |
| Changes anything | No | **Yes, when the channel is not working** |
| What the result is | The status recorded the last time the channel was used | A live test |

Microsoft's [`nltest` reference](https://learn.microsoft.com/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc731935(v=ws.11))
(read 2026-11-13, re-read 2026-11-18) says of `/sc_verify`: "If the secure channel does not work, this parameter
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
see the section above. A trust's roll-up `Health` is `Healthy | Degraded | Broken | Not Assessed`:
`Healthy` can stand with one direction of a bidirectional trust `Not Assessed` (named in
`Reasons`), and a partner that answers neither TCP 135 nor 389 from the host running the
assessment is `Broken`, a reachability result rather than a secure channel read (PORT-PLAN C16a).

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
