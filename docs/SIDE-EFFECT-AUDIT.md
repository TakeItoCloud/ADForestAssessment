# Side-effect audit of every command the script can run

PORT-PLAN H20a, v1.37.0; updated by H21, v1.38.0. Read 2026-11-18 on Microsoft Learn unless a row says otherwise.

This file is the inventory of everything `src/ADForestAssessment/Invoke-ADForestAssessment.ps1`
can reach outside its own PowerShell process, and of every command, type and static member it
uses inside it. A Pester test (`H20a` in `tests/Invoke-ADForestAssessment.Tests.ps1`) parses the
script and fails when:

- the script holds a command, an external tool form, a CIM class, a CIM method, a static .NET
  member, a `New-Object` type or an instance method name that has no row here (a new reach has
  not been audited);
- a row names something the script no longer holds (a stale row);
- `Invoke-ExternalCommand` is given a tool name that is not a literal, or arguments built in a
  way the test cannot name (only a literal, a `"format" -f ...` literal, a variable assigned from
  such literals in the same function, and the two argument builders `Get-AdfaNltestScArgument`
  and `Get-AdfaDcdiagArgument`, which the test runs for every value they can produce);
- a console tool is started directly (`& nltest.exe ...`, any command whose name ends in `.exe`)
  with arguments other than literals or the parameter of a script block whose `ArgumentList`,
  beside it in the same hashtable, is a literal or a variable assigned only from
  `Get-AdfaNltestScArgument` in the same function. Such a call is keyed by its tool form exactly
  like an `Invoke-ExternalCommand` call (`Tool:nltest.exe /sc_query:<domain>`), never by the bare
  tool name, and the inventory may hold no `Command:<tool>.exe` row;
- `OpenSubKey` is called with anything but one argument: Learn documents `OpenSubKey(String)` as
  "Retrieves a subkey as read-only", and every other overload as taking a write access flag or
  rights;
- an instance method is called by a name the test cannot read (`$x.$name()`);
- a dynamic call (`& $x`) is anything other than a script block assigned in the same function,
  or one of four named exceptions (`$ReadCommand`, bound by a `[ValidateSet]` of four reader
  functions; `$merge`, checked to be a function of this script; `$NameResolver` and `$reader`,
  script-block parameters);
- a row's verdict is outside the vocabulary below, a default row carries a documented change, or
  an opt-in row names a switch the script does not have.

What that test cannot see: the receiver of an instance method. Instance methods are keyed by
name only (`Method:SetValue`), because the type of `$x` in `$x.SetValue()` is not known from the
source; a new method name fails the test, but a name already listed, called on a different
object, does not. Property reads and property assignments are not keyed at all. Nor can it see
anything a vendor tool does that its Learn page does not say.

## Verdicts

| Verdict | Meaning |
| --- | --- |
| documented read | Learn describes the command, verb or method as a query, read, retrieval or display. Learn does not say in so many words that it leaves no trace; the verdict rests on the documented purpose. |
| documented change, opt-in | Learn documents a change of state (a write, a replication, an event logged, a channel rebuilt). Every such row runs only behind the switch in its Run column. |
| not documented | Learn says nothing either way, the page was not read in this session, or there is no Learn page. This is never a claim that nothing happens. |
| local output (by design) | Writes the run's own output folder on the host running the assessment. |
| in-process | Runs inside the PowerShell process, or reads the local computer only; reaches no DC and no other computer. |

The Run column says when the row runs: `Default` (a run with no switch, `-Sections All`), or
`Opt-in: -Switch`.

## Result

Of the Learn pages read, none documents a change of state for anything a default run invokes.
That claim covers only the pages read: 38 default rows rest on a page that was not read in this
session (the ActiveDirectory Get cmdlets other than `Get-ADObject`, `Remove-CimSession`, most of
the .NET entry points and the instance methods with reach), and reading them is PORT-PLAN H20c;
what Learn would say on them is not known. Every command Microsoft documents as changing state
is opt-in, behind the switch named in its row:
`dcdiag /test:DNS /DnsAll`, `/test:SystemLog` and `/test:Intersite /a`
(`-IncludeDcdiagActiveTests`), the raw `dcdiag /c /v` capture (`-IncludeDcdiag`),
`nltest /sc_verify` in both forms (`-IncludeSecureChannelVerify`) and
`repadmin /removelingeringobjects /advisory_mode` (`-IncludeLingeringObjectScan`). No command
had to be moved behind a new switch.

That is not a statement that a default run leaves no trace. The rows marked `not documented` are
ones Learn says nothing about, and the four `Effect:` rows at the end name what the pages read do
not cover: logon auditing on each DC, whether reading the remote registry starts the Remote
Registry service, the DNS client cache of the host running the assessment, and Schannel events
of the opt-in LDAPS handshake. `repadmin /showrepl * /csv` contacts every DC of the forest, and
Learn warns that the wildcard can cause "a significant increase in network traffic".

Decisions taken where Learn was silent:

- `netdom trust /Verify` stays opt-in (operator decision, H19) although Learn documents it only as
  verifying the secure channel secrets; its verdict is `not documented`, not a documented change.
- `dcdiag /test:FsmoCheck` stays in the default run (PORT-PLAN C11c); Learn's dcdiag reference
  does not list it, so its verdict is `not documented`.
- `repadmin /showbackup` has no Learn reference page; Learn mentions it only as the command that
  checks backup status. It stays in the default run as `not documented`.
- The ActiveDirectory module's Get cmdlets other than `Get-ADObject`, most of the .NET entry
  points and instance methods, and `Remove-CimSession` are `not documented`: their pages were
  not read in this session (PORT-PLAN H20c).
- `OpenSubKey` is `documented read` only in its one-argument form, which Learn documents as
  "Retrieves a subkey as read-only" (read 2026-11-18); the test refuses any other form.

## Summary

| Verdict | Rows |
| --- | --- |
| documented read | 56 |
| documented change, opt-in | 7 |
| not documented | 54 |
| local output (by design) | 7 |
| in-process | 127 |

## External console tools: every form the script can start

| Key | Where | Run | Learn source (read 2026-11-18 unless stated) | What Learn documents | Verdict |
| --- | --- | --- | --- | --- | --- |
| `Tool:dcdiag.exe /test:Advertising /s:<dc>` | Invoke-AdfaDcdiagTest, per DC (DcDiagnostics) | Default | https://learn.microsoft.com/windows-server/administration/windows-commands/dcdiag | Checks whether each domain controller advertises itself in the roles that it should be capable of performing. | documented read |
| `Tool:dcdiag.exe /test:CheckSDRefDom /s:<dc>` | Invoke-AdfaDcdiagTest, once per forest (DcDiagnostics) | Default | https://learn.microsoft.com/windows-server/administration/windows-commands/dcdiag | Checks that all application directory partitions have appropriate security descriptor reference domains. Uses LDAP. | documented read |
| `Tool:dcdiag.exe /test:CheckSecurityError /s:<dc>` | Invoke-AdfaDcdiagTest, per DC (DcDiagnostics) | Default | https://learn.microsoft.com/windows-server/administration/windows-commands/dcdiag | Performs various security checks; among them it sends non-fragmenting ICMP packets to test Kerberos over UDP fragmentation. | documented read |
| `Tool:dcdiag.exe /test:Connectivity /s:<dc>` | Invoke-AdfaDcdiagTest, per DC (DcDiagnostics) | Default | https://learn.microsoft.com/windows-server/administration/windows-commands/dcdiag | Verifies that the DSA and DNS are registered and reachable using LDAP and RPC. | documented read |
| `Tool:dcdiag.exe /test:CrossRefValidation /s:<dc>` | Invoke-AdfaDcdiagTest, once per forest (DcDiagnostics) | Default | https://learn.microsoft.com/windows-server/administration/windows-commands/dcdiag | Retrieves a list of naming contexts with their cross references and validates them. Uses LDAP. | documented read |
| `Tool:dcdiag.exe /test:DFSREvent /s:<dc>` | Invoke-AdfaDcdiagTest, per DC (DcDiagnostics) | Default | https://learn.microsoft.com/windows-server/administration/windows-commands/dcdiag | Checking the DFSR event log warning and error entries from the past 24 hours. | documented read |
| `Tool:dcdiag.exe /test:DNS /DnsAll /s:<dc>` | Invoke-AdfaDcdiagTest, per DC (DcDiagnostics) | Opt-in: -IncludeDcdiagActiveTests | https://learn.microsoft.com/windows-server/administration/windows-commands/dcdiag (DNS syntax) and https://learn.microsoft.com/windows-server/identity/ad-ds/manage/troubleshoot/verify-dns-functionality-to-support-directory-replication (Verifying dynamic update) | The dcdiag reference: /DnsAll performs all tests except /DnsResolveExtName; /DnsDynamicUpdate determines if dynamic update is enabled in the Active Directory zone (it says nothing of a record). The verify-DNS page: the dynamic update test is used to perform registration of a test record (_dcdiag_test_record), which is deleted automatically after the test. Both re-read 2026-11-18. | documented change, opt-in |
| `Tool:dcdiag.exe /test:FrsEvent /s:<dc>` | Invoke-AdfaDcdiagTest, per DC (DcDiagnostics) | Default | https://learn.microsoft.com/windows-server/administration/windows-commands/dcdiag | Checks to see if there are errors in the File Replication Service (FRS) event log from the past 24 hours. | documented read |
| `Tool:dcdiag.exe /test:FsmoCheck /s:<dc>` | Invoke-AdfaDcdiagTest, per DC (DcDiagnostics) | Default | No Learn page: not in the known-tests table of https://learn.microsoft.com/windows-server/administration/windows-commands/dcdiag | Learn does not describe this test (PORT-PLAN C11c). | not documented |
| `Tool:dcdiag.exe /test:Intersite /s:<dc> /a` | Invoke-AdfaDcdiagTest, once per site (DcDiagnostics) | Opt-in: -IncludeDcdiagActiveTests | https://learn.microsoft.com/windows-server/administration/windows-commands/dcdiag | Reporting back any replication failures after triggering a replication. | documented change, opt-in |
| `Tool:dcdiag.exe /test:KccEvent /s:<dc>` | Invoke-AdfaDcdiagTest, per DC (DcDiagnostics) | Default | https://learn.microsoft.com/windows-server/administration/windows-commands/dcdiag | Queries the KCC on the DC for errors and warnings generated in the Directory Services event log during the last 15 minutes. | documented read |
| `Tool:dcdiag.exe /test:KnowsOfRoleHolders /s:<dc>` | Invoke-AdfaDcdiagTest, per DC (DcDiagnostics) | Default | https://learn.microsoft.com/windows-server/administration/windows-commands/dcdiag | Returns the DCs knowledge of the five FSMO roles. | documented read |
| `Tool:dcdiag.exe /test:MachineAccount /s:<dc>` | Invoke-AdfaDcdiagTest, per DC (DcDiagnostics) | Default | https://learn.microsoft.com/windows-server/administration/windows-commands/dcdiag | Checks whether the machine account has properly registered. Its two repair options (/RecreateMachineAccount, /FixMachineAccount) are not used. | documented read |
| `Tool:dcdiag.exe /test:NCSecDesc /s:<dc>` | Invoke-AdfaDcdiagTest, per DC (DcDiagnostics) | Default | https://learn.microsoft.com/windows-server/administration/windows-commands/dcdiag | Checks permissions on all the naming contexts on the source DC. Uses LDAP. | documented read |
| `Tool:dcdiag.exe /test:Netlogons /s:<dc>` | Invoke-AdfaDcdiagTest, per DC (DcDiagnostics) | Default | https://learn.microsoft.com/windows-server/administration/windows-commands/dcdiag | Validates that the user running DCDiag can connect to and read the SYSVOL and NETLOGON shares. | documented read |
| `Tool:dcdiag.exe /test:ObjectsReplicated /s:<dc>` | Invoke-AdfaDcdiagTest, per DC (DcDiagnostics) | Default | https://learn.microsoft.com/windows-server/administration/windows-commands/dcdiag | Checks that the Machine Account and DSA objects have replicated. | documented read |
| `Tool:dcdiag.exe /test:Replications /s:<dc>` | Invoke-AdfaDcdiagTest, per DC (DcDiagnostics) | Default | https://learn.microsoft.com/windows-server/administration/windows-commands/dcdiag | Checks all AD replication connection objects ... if the last replication attempted was successful. | documented read |
| `Tool:dcdiag.exe /test:RidManager /s:<dc>` | Invoke-AdfaDcdiagTest, per DC (DcDiagnostics) | Default | https://learn.microsoft.com/windows-server/administration/windows-commands/dcdiag | Checks whether the RID master is accessible ... has valid RID pool values. Uses LDAP and RPC. | documented read |
| `Tool:dcdiag.exe /test:Services /s:<dc>` | Invoke-AdfaDcdiagTest, per DC (DcDiagnostics) | Default | https://learn.microsoft.com/windows-server/administration/windows-commands/dcdiag | Validates that various AD-dependent services are running, accessible, and set to specific start types. | documented read |
| `Tool:dcdiag.exe /test:SystemLog /s:<dc>` | Invoke-AdfaDcdiagTest, per DC (DcDiagnostics) | Opt-in: -IncludeDcdiagActiveTests | https://learn.microsoft.com/windows-server/administration/windows-commands/dcdiag | Validates the System Event Log's health by reading and writing entries from the past 60 minutes. | documented change, opt-in |
| `Tool:dcdiag.exe /test:SysVolCheck /s:<dc>` | Invoke-AdfaDcdiagTest, per DC (DcDiagnostics) | Default | https://learn.microsoft.com/windows-server/administration/windows-commands/dcdiag | Reads the DCs Netlogon SysVolReady registry key to validate that SYSVOL is ready. | documented read |
| `Tool:dcdiag.exe /test:Topology /s:<dc>` | Invoke-AdfaDcdiagTest, once per scoped domain (DcDiagnostics) | Default | https://learn.microsoft.com/windows-server/administration/windows-commands/dcdiag | Uses DsReplicaSyncAll with DS_REPSYNCALL_DO_NOT_SYNC: analyzes and validates replication topology without actually replicating changes. | documented read |
| `Tool:dcdiag.exe /test:VerifyEnterpriseReferences /s:<dc>` | Invoke-AdfaDcdiagTest, per DC (DcDiagnostics) | Default | https://learn.microsoft.com/windows-server/administration/windows-commands/dcdiag | Checks that specified system references are intact ... across all objects in the enterprise. | documented read |
| `Tool:dcdiag.exe /test:VerifyReferences /s:<dc>` | Invoke-AdfaDcdiagTest, per DC (DcDiagnostics) | Default | https://learn.microsoft.com/windows-server/administration/windows-commands/dcdiag | Checks that certain system references are intact for the FRS and replication infrastructure. | documented read |
| `Tool:dcdiag.exe /test:VerifyReplicas /s:<dc>` | Invoke-AdfaDcdiagTest, per DC (DcDiagnostics) | Default | https://learn.microsoft.com/windows-server/administration/windows-commands/dcdiag | Checks that all application directory partitions are fully instantiated on all replica servers. | documented read |
| `Tool:dcdiag.exe /s:{0} /c /v` | Invoke-Main raw capture, per DC | Opt-in: -IncludeDcdiag | https://learn.microsoft.com/windows-server/administration/windows-commands/dcdiag | /c runs all tests except DCPromo and RegisterInDNS, including CutoffServers, which uses DsReplicaSyncAll, which triggers replication on the DCs; and the DNS test. | documented change, opt-in |
| `Tool:nltest.exe /sc_query:<domain>` | Test-AdfaRemoteSecureChannel and Get-AdfaDcSecureChannel, started directly (`& nltest.exe $a`) in the script block run on a DC over WinRM, with the argument Get-AdfaNltestScArgument built (Trusts, DcSecureChannel) | Default | https://learn.microsoft.com/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc731935(v=ws.11) | Reports on the state of the secure channel the last time that you used it. | documented read |
| `Tool:nltest.exe /server:<dc> /sc_query:<domain>` | Test-AdfaSecureChannel, outbound trust direction asked of the PDC emulator (Trusts) | Default | https://learn.microsoft.com/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc731935(v=ws.11) | /server: runs nltest at a remote domain controller; /sc_query reports on the state of the secure channel the last time that you used it. | documented read |
| `Tool:nltest.exe /sc_verify:<domain>` | The same three places, only with the switch | Opt-in: -IncludeSecureChannelVerify | https://learn.microsoft.com/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc731935(v=ws.11) | If the secure channel does not work, this parameter removes the existing channel, and then builds a new one. | documented change, opt-in |
| `Tool:nltest.exe /server:<dc> /sc_verify:<domain>` | Test-AdfaSecureChannel, only with the switch | Opt-in: -IncludeSecureChannelVerify | https://learn.microsoft.com/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc731935(v=ws.11) | If the secure channel does not work, this parameter removes the existing channel, and then builds a new one. | documented change, opt-in |
| `Tool:nltest.exe /dsgetdc:{0}` | Get-AdfaTrustHealth, per trust (Trusts) | Default | https://learn.microsoft.com/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc731935(v=ws.11) | Queries the DNS server for a list of domain controllers and their IP addresses, and contacts each domain controller to check for connectivity. Its /FORCE value runs against the DNS server instead of looking in the cache: without it a local cache is consulted. No change on a DC is described. | documented read |
| `Tool:netdom.exe trust {0} /Domain:{1} /Verify` | Test-AdfaSecureChannel fallback, only with the switch | Opt-in: -IncludeSecureChannelVerify | https://learn.microsoft.com/windows-server/administration/windows-commands/netdom-trust | /verify: Verifies the secure channel secrets for a specific trust relationship. Resetting is the separate /reset. Kept opt-in as a live test by operator decision (H19). | not documented |
| `Tool:repadmin.exe /replsummary` | Get-AdfaReplsummaryHealth (Replication) | Default | https://learn.microsoft.com/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc835092(v=ws.11) | Identifies domain controllers that are failing inbound replication or outbound replication, and summarizes the results in a report. | documented read |
| `Tool:repadmin.exe /replsummary * /bysrc /bydest /sort:delta` | Invoke-Main raw capture | Opt-in: -IncludeRepadmin | https://learn.microsoft.com/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc835092(v=ws.11) | Identifies domain controllers that are failing replication and summarizes the results in a report. | documented read |
| `Tool:repadmin.exe /showrepl * /csv` | Get-AdfaRepadminReplication (Replication) | Default | https://learn.microsoft.com/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc742066(v=ws.11) and https://learn.microsoft.com/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc770963(v=ws.11) | Displays the replication status when the specified DC last attempted inbound replication. The * wildcard targets every DC of the forest: improper use of this wildcard character can cause a significant increase in network traffic. Repadmin in general: incorrect use can adversely impact the replication topology (it also has verbs that do; none is used here). | documented read |
| `Tool:repadmin.exe /showrepl {0} /errorsonly` | Invoke-Main raw capture, per DC | Opt-in: -IncludeRepadmin | https://learn.microsoft.com/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc742066(v=ws.11) | Displays the replication status when the specified DC last attempted inbound replication. | documented read |
| `Tool:repadmin.exe /showbackup` | Get-AdfaBackupStatus (Resilience) | Default | No Learn page: no reference page for /showbackup; mentioned only as the command to check backup status in https://learn.microsoft.com/services-hub/microsoft-engage-center/health/remediation-steps-ad/investigate-why-active-directory-directory-partitions-are-not-backed-up-for-longer-than-half-the-tom | Use the following command to check the backup status of all NCs. Nothing either way about a change. | not documented |
| `Tool:repadmin.exe /showbackup {0}` | Get-AdfaBackupStatus, per DC (Resilience) | Default | No Learn page: no reference page for /showbackup; see https://learn.microsoft.com/services-hub/microsoft-engage-center/health/remediation-steps-ad/investigate-why-active-directory-directory-partitions-are-not-backed-up-for-longer-than-half-the-tom | As the row above. | not documented |
| `Tool:repadmin.exe /removelingeringobjects {0} {1} "{2}" /advisory_mode` | Get-AdfaLingeringObjectScan, per DC | Opt-in: -IncludeLingeringObjectScan | https://learn.microsoft.com/troubleshoot/windows-server/active-directory/active-directory-replication-event-id-1388-1988 | /advisory_mode: Logs the lingering objects that will be removed so that you can review them, but does not remove them. It writes to the DCs (events). | documented change, opt-in |
| `Tool:w32tm.exe /query /source` | Get-AdfaTimeSync, the host running the assessment (Resilience) | Default | https://learn.microsoft.com/windows-server/networking/windows-time-service/windows-time-service-tools-and-settings | /query displays the computer's W32Time information; /source displays the time source. The verbs that change state (/config, /resync, /register, /unregister, /debug) are not used. | documented read |
| `Tool:w32tm.exe /query /computer:{0} /source` | Get-AdfaTimeHierarchyHealth, per DC (TimeHierarchy) | Default | https://learn.microsoft.com/windows-server/networking/windows-time-service/windows-time-service-tools-and-settings | Displays the time source of the named computer. | documented read |
| `Tool:w32tm.exe /query /computer:{0} /configuration` | Get-AdfaTimeHierarchyHealth (TimeHierarchy) | Default | https://learn.microsoft.com/windows-server/networking/windows-time-service/windows-time-service-tools-and-settings | Displays the run-time configuration. | documented read |
| `Tool:w32tm.exe /stripchart /computer:{0} /dataonly /samples:{1} /rdtsc` | Get-AdfaStripchartSample, per DC (TimeHierarchy) | Default | https://learn.microsoft.com/windows-server/networking/windows-time-service/windows-time-service-tools-and-settings | Displays the offset to another computer; it sends NTP requests from an ephemeral UDP source port to prevent conflicts with the built-in NTP client. | documented read |
| `Tool:dfsrmig.exe /getglobalstate` | Get-AdfaSysvolHealth, the host running the assessment (Sysvol) | Default | https://learn.microsoft.com/windows-server/administration/windows-commands/dfsrmig | Retrieves the current global migration state for the domain from the local copy of the AD DS database, when run on the PDC emulator. The state-changing verbs (/setglobalstate, /createglobalobjects, /deleterontfrsmember, /deleterodfsrmember) are not used. | documented read |
| `Tool:nslookup.exe $lookupArgs = -type={0} {1}` | Resolve-AdfaDnsRecord, the fallback after Resolve-DnsName (DNS sections) | Default | https://learn.microsoft.com/windows-server/administration/windows-commands/nslookup | Displays information that you can use to diagnose DNS infrastructure. Noninteractive form: a record type and a name. Whether a query fills the local DNS client cache: see Effect:dns-client-cache. | documented read |
| `Tool:nslookup.exe $lookupArgs = {0} {1}` | Resolve-AdfaDnsRecord: the same query sent to a named server | Default | https://learn.microsoft.com/windows-server/administration/windows-commands/nslookup | As the row above, with the DNS server to ask. | documented read |

## Remote reads: cmdlets, CIM classes and methods

| Key | Where | Run | Learn source (read 2026-11-18 unless stated) | What Learn documents | Verdict |
| --- | --- | --- | --- | --- | --- |
| `Command:Invoke-Command` | Test-AdfaRemoteSecureChannel and Get-AdfaDcSecureChannel, over WinRM | Default | https://learn.microsoft.com/powershell/module/microsoft.powershell.core/invoke-command | Runs commands on a local or remote computer and returns all output from the commands. The effect is that of the command run (Tool:nltest.exe /sc_query:<domain>, or /sc_verify only with -IncludeSecureChannelVerify). Learn says nothing either way about a trace of the session itself; see Effect:logon-audit. | not documented |
| `Command:Get-CimInstance` | Every CIM read (DcSystem, DcDisk, DcHardening, DC DNS Client) | Default | https://learn.microsoft.com/powershell/module/cimcmdlets/get-ciminstance | Returns one or more CIM instance objects representing a snapshot of the CIM instances present on the CIM server. | documented read |
| `Command:New-CimSession` | Get-AdfaDcSystemRaw, Get-AdfaDcDiskRaw, Get-AdfaDcHardeningRaw, Get-AdfaDcNetworkRaw, Get-AdfaDcW32TimeRaw | Default | https://learn.microsoft.com/powershell/module/cimcmdlets/new-cimsession | A CIM session is a client-side object representing a connection to a local computer or a remote computer (WSMan by default, DCOM by option). What the remote side records of the connection is not described; see Effect:logon-audit. | not documented |
| `Command:Remove-CimSession` | The same five functions, in finally | Default | API reference not read in this session (No Learn page read for a side effect) | Closes the client-side session opened above. | not documented |
| `Command:Invoke-CimMethod` | Get-AdfaStdRegStringValue, Get-AdfaStdRegDwordValue | Default | https://learn.microsoft.com/powershell/module/cimcmdlets/invoke-cimmethod | Invokes a method of a CIM class. Learn's own example calls Win32_Process Create, so the cmdlet is audited per method: the three CimMethod rows, each a literal StdRegProv Get method (a test fails on any other). | not documented |
| `CimMethod:StdRegProv.GetDWORDValue` | Get-AdfaStdRegDwordValue (DcHardening, TimeHierarchy, DcSystem UBR since v1.37.0) | Default | https://learn.microsoft.com/previous-versions/windows/desktop/regprov/getdwordvalue-method-in-class-stdregprov | The GetDWORDValue method returns the data value for a named value whose data type is REG_DWORD. Microsoft names the Set methods separately as the ones that create or change values. | documented read |
| `CimMethod:StdRegProv.GetStringValue` | Get-AdfaStdRegStringValue (DcDisk, TimeHierarchy) | Default | https://learn.microsoft.com/previous-versions/windows/desktop/regprov/getstringvalue-method-in-class-stdregprov (read 2026-11-13, PORT-PLAN C2; not re-read) | Returns the data value for a named value whose data type is REG_SZ. | documented read |
| `CimMethod:StdRegProv.GetExpandedStringValue` | Get-AdfaStdRegStringValue (DcDisk) | Default | https://learn.microsoft.com/previous-versions/windows/desktop/regprov/getexpandedstringvalue-method-in-class-stdregprov (read 2026-11-13, PORT-PLAN C2; not re-read) | Returns the data value for a named value whose data type is REG_EXPAND_SZ. | documented read |
| `CimClass:Win32_NetworkAdapterConfiguration` | Get-AdfaDcNetworkRaw (DC DNS Client) | Default | https://learn.microsoft.com/powershell/module/cimcmdlets/get-ciminstance | Read with Get-CimInstance (a snapshot of the instances) and a listed property set. No method of the class is called. | documented read |
| `CimClass:Win32_OperatingSystem` | Get-AdfaDcSystemRaw, Get-AdfaDcHardeningRaw | Default | https://learn.microsoft.com/powershell/module/cimcmdlets/get-ciminstance and https://learn.microsoft.com/windows/win32/cimwin32prov/win32-operatingsystem | Read with Get-CimInstance (a snapshot of the instances) and a listed property set. No method of the class is called. | documented read |
| `CimClass:Win32_QuickFixEngineering` | Get-AdfaDcSystemRaw (DcSystem) | Default | https://learn.microsoft.com/powershell/module/cimcmdlets/get-ciminstance | Read with Get-CimInstance (a snapshot of the instances) and a listed property set. No method of the class is called. | documented read |
| `CimClass:Win32_Service` | Get-AdfaDcHardeningRaw, the Spooler service (DcHardening) | Default | https://learn.microsoft.com/powershell/module/cimcmdlets/get-ciminstance | Read with Get-CimInstance (a snapshot of the instances) and a listed property set. No method of the class is called. | documented read |
| `CimClass:Win32_Volume` | Get-AdfaDcDiskRaw (DcDisk) | Default | https://learn.microsoft.com/powershell/module/cimcmdlets/get-ciminstance | Read with Get-CimInstance (a snapshot of the instances) and a listed property set. No method of the class is called. | documented read |
| `Command:Get-SmbServerConfiguration` | Get-AdfaDcHardeningRaw (DcHardening) | Default | https://learn.microsoft.com/powershell/module/smbshare/get-smbserverconfiguration | The Get-SmbServerConfiguration cmdlet retrieves the SMB server configuration. Its writer is Set-SmbServerConfiguration, not used. | documented read |
| `Command:Get-WinEvent` | DS, DFSR and inventory event scans, per DC | Default | https://learn.microsoft.com/powershell/module/microsoft.powershell.diagnostics/get-winevent | Gets events from event logs and event tracing log files on local and remote computers. | documented read |
| `Command:Resolve-DnsName` | DnsDepth SRV queries, DNS vs AD second instrument | Default | https://learn.microsoft.com/powershell/module/dnsclient/resolve-dnsname | Performs a DNS query for the specified name. Whether a query fills the local DNS client cache is not stated; see Effect:dns-client-cache. | documented read |
| `Command:Get-DnsServerZone` | Dns, DnsAdConsistency | Default | https://learn.microsoft.com/powershell/module/dnsserver/get-dnsserverzone | Gets the zones that exist on a DNS server. | documented read |
| `Command:Get-DnsServerForwarder` | Dns | Default | https://learn.microsoft.com/powershell/module/dnsserver/get-dnsserverforwarder | Gets configuration settings on a DNS server. | documented read |
| `Command:Get-DnsServerResourceRecord` | DnsAdConsistency (default) and DnsRecordExport (-Sections DnsRecordExport only) | Default | https://learn.microsoft.com/powershell/module/dnsserver/get-dnsserverresourcerecord | Gets resource records from a specified DNS zone. | documented read |
| `Command:Get-DnsServerScavenging` | Dns | Default | https://learn.microsoft.com/windows-server/networking/dns/configure-aging-scavenging | Retrieve the current scavenging settings from a DNS server. Start-DnsServerScavenging, which starts a deletion pass, is not used. | documented read |
| `Command:Get-DnsServerZoneAging` | Dns | Default | https://learn.microsoft.com/windows-server/networking/dns/configure-aging-scavenging | Listed with the Get cmdlets that retrieve settings; Set-DnsServerZoneAging is the writer, not used. | documented read |
| `Command:Get-GPO` | GPO inventory (Gpo) | Default | https://learn.microsoft.com/powershell/module/grouppolicy/get-gpo | The Get-GPO cmdlet gets one Group Policy Object (GPO) or all the GPOs in a domain. | documented read |
| `Command:Get-DfsrBacklog` | SYSVOL backlog | Opt-in: -IncludeSysvolBacklog | https://learn.microsoft.com/powershell/module/dfsr/get-dfsrbacklog | Retrieves pending updates between two computers that participate in DFS Replication. | documented read |
| `Command:Get-ADObject` | Most directory reads (the C15 seam and others) | Default | https://learn.microsoft.com/powershell/module/activedirectory/get-adobject | Gets an Active Directory object or performs a search to get multiple objects. | documented read |
| `Command:Get-ADComputer` | Directory reads | Default | https://learn.microsoft.com/powershell/module/activedirectory/get-adcomputer (API reference not read in this session (No Learn page read for a side effect)) | A Get cmdlet of the ActiveDirectory module, which, as Get-ADObject, reads over AD Web Services. Its own page was not read on 2026-11-18, so nothing is claimed from it. | not documented |
| `Command:Get-ADDefaultDomainPasswordPolicy` | Directory reads | Default | https://learn.microsoft.com/powershell/module/activedirectory/get-addefaultdomainpasswordpolicy (API reference not read in this session (No Learn page read for a side effect)) | A Get cmdlet of the ActiveDirectory module, which, as Get-ADObject, reads over AD Web Services. Its own page was not read on 2026-11-18, so nothing is claimed from it. | not documented |
| `Command:Get-ADDomain` | Directory reads | Default | https://learn.microsoft.com/powershell/module/activedirectory/get-addomain (API reference not read in this session (No Learn page read for a side effect)) | A Get cmdlet of the ActiveDirectory module, which, as Get-ADObject, reads over AD Web Services. Its own page was not read on 2026-11-18, so nothing is claimed from it. | not documented |
| `Command:Get-ADDomainController` | Directory reads | Default | https://learn.microsoft.com/powershell/module/activedirectory/get-addomaincontroller (API reference not read in this session (No Learn page read for a side effect)) | A Get cmdlet of the ActiveDirectory module, which, as Get-ADObject, reads over AD Web Services. Its own page was not read on 2026-11-18, so nothing is claimed from it. | not documented |
| `Command:Get-ADFineGrainedPasswordPolicy` | Directory reads | Default | https://learn.microsoft.com/powershell/module/activedirectory/get-adfinegrainedpasswordpolicy (API reference not read in this session (No Learn page read for a side effect)) | A Get cmdlet of the ActiveDirectory module, which, as Get-ADObject, reads over AD Web Services. Its own page was not read on 2026-11-18, so nothing is claimed from it. | not documented |
| `Command:Get-ADForest` | Directory reads | Default | https://learn.microsoft.com/powershell/module/activedirectory/get-adforest (API reference not read in this session (No Learn page read for a side effect)) | A Get cmdlet of the ActiveDirectory module, which, as Get-ADObject, reads over AD Web Services. Its own page was not read on 2026-11-18, so nothing is claimed from it. | not documented |
| `Command:Get-ADOptionalFeature` | Directory reads | Default | https://learn.microsoft.com/powershell/module/activedirectory/get-adoptionalfeature (API reference not read in this session (No Learn page read for a side effect)) | A Get cmdlet of the ActiveDirectory module, which, as Get-ADObject, reads over AD Web Services. Its own page was not read on 2026-11-18, so nothing is claimed from it. | not documented |
| `Command:Get-ADReplicationConnection` | Directory reads | Default | https://learn.microsoft.com/powershell/module/activedirectory/get-adreplicationconnection (API reference not read in this session (No Learn page read for a side effect)) | A Get cmdlet of the ActiveDirectory module, which, as Get-ADObject, reads over AD Web Services. Its own page was not read on 2026-11-18, so nothing is claimed from it. | not documented |
| `Command:Get-ADReplicationFailure` | Directory reads | Default | https://learn.microsoft.com/powershell/module/activedirectory/get-adreplicationfailure (API reference not read in this session (No Learn page read for a side effect)) | A Get cmdlet of the ActiveDirectory module, which, as Get-ADObject, reads over AD Web Services. Its own page was not read on 2026-11-18, so nothing is claimed from it. | not documented |
| `Command:Get-ADReplicationPartnerMetadata` | Directory reads | Default | https://learn.microsoft.com/powershell/module/activedirectory/get-adreplicationpartnermetadata (API reference not read in this session (No Learn page read for a side effect)) | A Get cmdlet of the ActiveDirectory module, which, as Get-ADObject, reads over AD Web Services. Its own page was not read on 2026-11-18, so nothing is claimed from it. | not documented |
| `Command:Get-ADReplicationQueueOperation` | Directory reads | Default | https://learn.microsoft.com/powershell/module/activedirectory/get-adreplicationqueueoperation (API reference not read in this session (No Learn page read for a side effect)) | A Get cmdlet of the ActiveDirectory module, which, as Get-ADObject, reads over AD Web Services. Its own page was not read on 2026-11-18, so nothing is claimed from it. | not documented |
| `Command:Get-ADReplicationSite` | Directory reads | Default | https://learn.microsoft.com/powershell/module/activedirectory/get-adreplicationsite (API reference not read in this session (No Learn page read for a side effect)) | A Get cmdlet of the ActiveDirectory module, which, as Get-ADObject, reads over AD Web Services. Its own page was not read on 2026-11-18, so nothing is claimed from it. | not documented |
| `Command:Get-ADReplicationSiteLink` | Directory reads | Default | https://learn.microsoft.com/powershell/module/activedirectory/get-adreplicationsitelink (API reference not read in this session (No Learn page read for a side effect)) | A Get cmdlet of the ActiveDirectory module, which, as Get-ADObject, reads over AD Web Services. Its own page was not read on 2026-11-18, so nothing is claimed from it. | not documented |
| `Command:Get-ADReplicationSubnet` | Directory reads | Default | https://learn.microsoft.com/powershell/module/activedirectory/get-adreplicationsubnet (API reference not read in this session (No Learn page read for a side effect)) | A Get cmdlet of the ActiveDirectory module, which, as Get-ADObject, reads over AD Web Services. Its own page was not read on 2026-11-18, so nothing is claimed from it. | not documented |
| `Command:Get-ADRootDSE` | Directory reads | Default | https://learn.microsoft.com/powershell/module/activedirectory/get-adrootdse (API reference not read in this session (No Learn page read for a side effect)) | A Get cmdlet of the ActiveDirectory module, which, as Get-ADObject, reads over AD Web Services. Its own page was not read on 2026-11-18, so nothing is claimed from it. | not documented |
| `Command:Get-ADTrust` | Directory reads | Default | https://learn.microsoft.com/powershell/module/activedirectory/get-adtrust (API reference not read in this session (No Learn page read for a side effect)) | A Get cmdlet of the ActiveDirectory module, which, as Get-ADObject, reads over AD Web Services. Its own page was not read on 2026-11-18, so nothing is claimed from it. | not documented |
| `Command:Get-ADUser` | Directory reads | Default | https://learn.microsoft.com/powershell/module/activedirectory/get-aduser (API reference not read in this session (No Learn page read for a side effect)) | A Get cmdlet of the ActiveDirectory module, which, as Get-ADObject, reads over AD Web Services. Its own page was not read on 2026-11-18, so nothing is claimed from it. | not documented |

## .NET entry points with network, file or process reach

| Key | Where | Run | Learn source (read 2026-11-18 unless stated) | What Learn documents | Verdict |
| --- | --- | --- | --- | --- | --- |
| `DotNet:[Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey` | Get-AdfaUsnRollbackRaw, per DC (RestoreIntegrity) | Default | https://learn.microsoft.com/dotnet/api/microsoft.win32.registrykey.openremotebasekey | Opens a new RegistryKey that represents the requested key on a remote machine; both machines must be running the remote registry service, and have remote administration enabled. Whether the call starts a stopped service is not stated; see Effect:remote-registry-service. | not documented |
| `DotNet:[System.IO.Directory]::GetDirectories` | The SYSVOL Policies listing, \\<domain>\SYSVOL\<domain>\Policies (Gpo) | Default | API reference not read in this session (No Learn page read for a side effect) | Lists folders over SMB. | not documented |
| `DotNet:[System.IO.FileStream]::new` | GPT.INI per GPO, and netlogon.log on \\<dc>\ADMIN$, opened with FileAccess Read and sharing read, write and delete | Default | API reference not read in this session (No Learn page read for a side effect) | Opens a file over SMB for reading. | not documented |
| `DotNet:[System.Net.Dns]::BeginGetHostAddresses` | Name resolution of each DC (PortMatrix reachability class) | Default | API reference not read in this session (No Learn page read for a side effect) | Resolves a name with the runner's resolver; see Effect:dns-client-cache. | not documented |
| `DotNet:[System.Net.Dns]::EndGetHostAddresses` | As the row above | Default | API reference not read in this session (No Learn page read for a side effect) | Completes the resolution started above. | not documented |
| `NewObject:System.Net.Sockets.TcpClient` | Test-TcpPort, the reachability probe, and the LDAPS handshake | Default | API reference not read in this session (No Learn page read for a side effect) | Opens one TCP connection to a port and sends no data (the LDAPS handshake, opt-in, is in its own row). | not documented |
| `NewObject:System.Net.Security.SslStream` | The LDAPS certificate read (DcCertificates) | Opt-in: -IncludeLdapsHandshake | API reference not read in this session (No Learn page read for a side effect) | One TLS handshake to port 636, no LDAP request and no bind. A DC that cannot complete it may log a Schannel event; see Effect:schannel. | not documented |
| `DotNet:[powershell]::Create` | The bounded runspace of the LDAPS handshake | Opt-in: -IncludeLdapsHandshake | API reference not read in this session (No Learn page read for a side effect) | A runspace inside this process that runs the handshake above with a time bound. | not documented |
| `NewObject:System.Diagnostics.Process` | Invoke-ExternalCommand only | Default | API reference not read in this session (No Learn page read for a side effect) | Starts the console tools named in the Tool rows, and nothing else (a test fails on a FilePath that is not a literal). | not documented |
| `NewObject:System.Diagnostics.ProcessStartInfo` | Invoke-ExternalCommand only | Default | API reference not read in this session (No Learn page read for a side effect) | The start settings of the process above. | not documented |
| `DotNet:[System.Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties` | The domain of the host running the assessment (Sysvol) | Default | API reference not read in this session (No Learn page read for a side effect) | Reads the local computer's network properties. | not documented |

## Instance methods, by name

Keyed by method name only: the test cannot tell the type of the object a method is called on
(see above). A row with reach names the object it is called on in this script today.

| Key | Where | Run | Learn source (read 2026-11-18 unless stated) | What Learn documents | Verdict |
| --- | --- | --- | --- | --- | --- |
| `Method:OpenSubKey` | Get-AdfaUsnRollbackRaw, per DC, on the remote key OpenRemoteBaseKey opened (RestoreIntegrity) | Default | https://learn.microsoft.com/dotnet/api/microsoft.win32.registrykey.opensubkey | OpenSubKey(String): Retrieves a subkey as read-only. The overloads that take a Boolean, a RegistryKeyPermissionCheck or RegistryRights can open it for writing; a test fails on any call with more than one argument. | documented read |
| `Method:GetValue` | Get-AdfaUsnRollbackRaw, per DC, on the remote key above (RestoreIntegrity) | Default | API reference not read in this session (No Learn page read for a side effect) | Reads one value of the key opened read-only above. | not documented |
| `Method:GetValueNames` | Get-AdfaUsnRollbackRaw, per DC, on the remote key above (RestoreIntegrity) | Default | API reference not read in this session (No Learn page read for a side effect) | Lists the value names of the key opened read-only above. | not documented |
| `Method:Close` | The remote registry keys of Get-AdfaUsnRollbackRaw and the TcpClient of Test-TcpPort, Test-AdfaTcpAddress and the LDAPS handshake | Default | API reference not read in this session (No Learn page read for a side effect) | Closes a key or a connection this script opened. | not documented |
| `Method:Dispose` | The FileStream of GPT.INI and netlogon.log, the empty log file New-AdfaRunFolder creates to claim the run folder (since v1.38.0, PORT-PLAN H21), and the runspace, event and SslStream of the opt-in LDAPS handshake | Default | API reference not read in this session (No Learn page read for a side effect) | Releases an object this script created. | not documented |
| `Method:BeginConnect` | The TcpClient of Test-TcpPort, Test-AdfaTcpAddress and the LDAPS handshake | Default | API reference not read in this session (No Learn page read for a side effect) | Starts the one TCP connection of the TcpClient row. | not documented |
| `Method:EndConnect` | As the row above | Default | API reference not read in this session (No Learn page read for a side effect) | Completes the connection started above. | not documented |
| `Method:Read` | The FileStream of GPT.INI (Gpo) and netlogon.log (Site Health), opened for reading | Default | API reference not read in this session (No Learn page read for a side effect) | Reads bytes from a file opened over SMB for reading. | not documented |
| `Method:Seek` | The FileStream of netlogon.log (Site Health) | Default | API reference not read in this session (No Learn page read for a side effect) | Moves the read position to the last 4 MB of the file. | not documented |
| `Method:GenerateReport` | Get-AdfaGpoInventory, on each GPO Get-GPO returned (Gpo) | Default | API reference not read in this session (No Learn page read for a side effect) | Builds the report of one GPO from the domain. | not documented |
| `Method:Translate` | Resolve-AdfaAclSidName, a SecurityIdentifier turned into an account name (DangerousRights) | Default | API reference not read in this session (No Learn page read for a side effect) | Looks up the name of a SID. | not documented |
| `Method:Start` | Invoke-ExternalCommand only, the Process of the NewObject:System.Diagnostics.Process row | Default | API reference not read in this session (No Learn page read for a side effect) | Starts the console tools named in the Tool rows, and nothing else. | not documented |
| `Method:Kill` | Invoke-ExternalCommand only, on time-out, the process it started | Default | API reference not read in this session (No Learn page read for a side effect) | Stops the console tool this script started on the host running the assessment. What that tool leaves half done on a DC is not documented. | not documented |
| `Method:GetStream` | The TcpClient of the LDAPS handshake (DcCertificates) | Opt-in: -IncludeLdapsHandshake | API reference not read in this session (No Learn page read for a side effect) | The stream the TLS handshake runs over. | not documented |
| `Method:AuthenticateAsClient` | The SslStream of the LDAPS handshake (DcCertificates) | Opt-in: -IncludeLdapsHandshake | API reference not read in this session (No Learn page read for a side effect) | The one TLS handshake of the SslStream row; see Effect:schannel. | not documented |
| `Method:AddArgument` | The bounded runspace of the LDAPS handshake | Opt-in: -IncludeLdapsHandshake | n/a: reaches no DC and no other computer | Runs in the PowerShell process or reads the local computer only. | in-process |
| `Method:AddScript` | The bounded runspace of the LDAPS handshake | Opt-in: -IncludeLdapsHandshake | n/a: reaches no DC and no other computer | Runs in the PowerShell process or reads the local computer only. | in-process |
| `Method:BeginInvoke` | The bounded runspace of the LDAPS handshake | Opt-in: -IncludeLdapsHandshake | n/a: reaches no DC and no other computer | Runs in the PowerShell process or reads the local computer only. | in-process |
| `Method:EndInvoke` | The bounded runspace of the LDAPS handshake | Opt-in: -IncludeLdapsHandshake | n/a: reaches no DC and no other computer | Runs in the PowerShell process or reads the local computer only. | in-process |
| `Method:Set` | The time-out event of the LDAPS handshake | Opt-in: -IncludeLdapsHandshake | n/a: reaches no DC and no other computer | Runs in the PowerShell process or reads the local computer only. | in-process |
| `Method:Stop` | The stopwatch of the run in Invoke-Main's finally (every run, since v1.38.0, PORT-PLAN H21) and the stopwatch of the LDAPS handshake | Default | n/a: reaches no DC and no other computer | Runs in the PowerShell process or reads the local computer only. | in-process |
| `Method:Add` | In-process helper | Default | n/a: reaches no DC and no other computer | Runs in the PowerShell process or reads the local computer only. | in-process |
| `Method:AddDays` | In-process helper | Default | n/a: reaches no DC and no other computer | Runs in the PowerShell process or reads the local computer only. | in-process |
| `Method:Append` | In-process helper | Default | n/a: reaches no DC and no other computer | Runs in the PowerShell process or reads the local computer only. | in-process |
| `Method:AppendLine` | In-process helper | Default | n/a: reaches no DC and no other computer | Runs in the PowerShell process or reads the local computer only. | in-process |
| `Method:Contains` | In-process helper | Default | n/a: reaches no DC and no other computer | Runs in the PowerShell process or reads the local computer only. | in-process |
| `Method:ContainsKey` | In-process helper | Default | n/a: reaches no DC and no other computer | Runs in the PowerShell process or reads the local computer only. | in-process |
| `Method:Dequeue` | In-process helper | Default | n/a: reaches no DC and no other computer | Runs in the PowerShell process or reads the local computer only. | in-process |
| `Method:EndsWith` | In-process helper | Default | n/a: reaches no DC and no other computer | Runs in the PowerShell process or reads the local computer only. | in-process |
| `Method:Enqueue` | In-process helper | Default | n/a: reaches no DC and no other computer | Runs in the PowerShell process or reads the local computer only. | in-process |
| `Method:Format` | In-process helper | Default | n/a: reaches no DC and no other computer | Runs in the PowerShell process or reads the local computer only. | in-process |
| `Method:GetSecurityDescriptorBinaryForm` | In-process helper | Default | n/a: reaches no DC and no other computer | Runs in the PowerShell process or reads the local computer only. | in-process |
| `Method:GetString` | In-process helper | Default | n/a: reaches no DC and no other computer | Runs in the PowerShell process or reads the local computer only. | in-process |
| `Method:GetType` | In-process helper | Default | n/a: reaches no DC and no other computer | Runs in the PowerShell process or reads the local computer only. | in-process |
| `Method:IndexOf` | In-process helper | Default | n/a: reaches no DC and no other computer | Runs in the PowerShell process or reads the local computer only. | in-process |
| `Method:LastIndexOf` | In-process helper | Default | n/a: reaches no DC and no other computer | Runs in the PowerShell process or reads the local computer only. | in-process |
| `Method:ReadToEndAsync` | In-process helper (the output of the console tool Invoke-ExternalCommand started) | Default | n/a: reaches no DC and no other computer | Runs in the PowerShell process or reads the local computer only. | in-process |
| `Method:RemoveAt` | In-process helper | Default | n/a: reaches no DC and no other computer | Runs in the PowerShell process or reads the local computer only. | in-process |
| `Method:Replace` | In-process helper | Default | n/a: reaches no DC and no other computer | Runs in the PowerShell process or reads the local computer only. | in-process |
| `Method:Reset` | In-process helper (an X509Certificate2 copy) | Default | n/a: reaches no DC and no other computer | Runs in the PowerShell process or reads the local computer only. | in-process |
| `Method:Split` | In-process helper | Default | n/a: reaches no DC and no other computer | Runs in the PowerShell process or reads the local computer only. | in-process |
| `Method:StartsWith` | In-process helper | Default | n/a: reaches no DC and no other computer | Runs in the PowerShell process or reads the local computer only. | in-process |
| `Method:Substring` | In-process helper | Default | n/a: reaches no DC and no other computer | Runs in the PowerShell process or reads the local computer only. | in-process |
| `Method:ToArray` | In-process helper | Default | n/a: reaches no DC and no other computer | Runs in the PowerShell process or reads the local computer only. | in-process |
| `Method:ToCharArray` | In-process helper | Default | n/a: reaches no DC and no other computer | Runs in the PowerShell process or reads the local computer only. | in-process |
| `Method:ToFileTimeUtc` | In-process helper | Default | n/a: reaches no DC and no other computer | Runs in the PowerShell process or reads the local computer only. | in-process |
| `Method:ToLower` | In-process helper | Default | n/a: reaches no DC and no other computer | Runs in the PowerShell process or reads the local computer only. | in-process |
| `Method:ToLowerInvariant` | In-process helper | Default | n/a: reaches no DC and no other computer | Runs in the PowerShell process or reads the local computer only. | in-process |
| `Method:ToString` | In-process helper | Default | n/a: reaches no DC and no other computer | Runs in the PowerShell process or reads the local computer only. | in-process |
| `Method:ToUniversalTime` | In-process helper | Default | n/a: reaches no DC and no other computer | Runs in the PowerShell process or reads the local computer only. | in-process |
| `Method:ToUpperInvariant` | In-process helper | Default | n/a: reaches no DC and no other computer | Runs in the PowerShell process or reads the local computer only. | in-process |
| `Method:Trim` | In-process helper | Default | n/a: reaches no DC and no other computer | Runs in the PowerShell process or reads the local computer only. | in-process |
| `Method:TrimEnd` | In-process helper | Default | n/a: reaches no DC and no other computer | Runs in the PowerShell process or reads the local computer only. | in-process |
| `Method:TrimStart` | In-process helper | Default | n/a: reaches no DC and no other computer | Runs in the PowerShell process or reads the local computer only. | in-process |
| `Method:Wait` | In-process helper (the output tasks of Invoke-ExternalCommand) | Default | n/a: reaches no DC and no other computer | Runs in the PowerShell process or reads the local computer only. | in-process |
| `Method:WaitForExit` | In-process helper (the process Invoke-ExternalCommand started) | Default | n/a: reaches no DC and no other computer | Runs in the PowerShell process or reads the local computer only. | in-process |
| `Method:WaitOne` | In-process helper (a wait handle of a connection or name resolution) | Default | n/a: reaches no DC and no other computer | Runs in the PowerShell process or reads the local computer only. | in-process |

## Local output of the run

| Key | Where | Run | Learn source (read 2026-11-18 unless stated) | What Learn documents | Verdict |
| --- | --- | --- | --- | --- | --- |
| `Command:Add-Content` | The run's own output folder (log, CSV, JSON, HTML, transcript) | Default | n/a: writes the output folder of the run only | Writes files of the run on the host running the assessment, in one new folder per run under -OutputPath (default C:\Scripts\Securnet\Reports since v1.38.0, PORT-PLAN H21). | local output (by design) |
| `Command:New-Item` | The run's own output folder (log, CSV, JSON, HTML, transcript) | Default | n/a: writes the output folder of the run only | Writes files of the run on the host running the assessment, in one new folder per run under -OutputPath (default C:\Scripts\Securnet\Reports since v1.38.0, PORT-PLAN H21). | local output (by design) |
| `Command:Export-Csv` | The run's own output folder (log, CSV, JSON, HTML, transcript) | Default | n/a: writes the output folder of the run only | Writes files of the run on the host running the assessment, in one new folder per run under -OutputPath (default C:\Scripts\Securnet\Reports since v1.38.0, PORT-PLAN H21). | local output (by design) |
| `Command:Out-File` | The run's own output folder (log, CSV, JSON, HTML, transcript) | Default | n/a: writes the output folder of the run only | Writes files of the run on the host running the assessment, in one new folder per run under -OutputPath (default C:\Scripts\Securnet\Reports since v1.38.0, PORT-PLAN H21). | local output (by design) |
| `Command:Start-Transcript` | The run's own output folder (log, CSV, JSON, HTML, transcript) | Default | n/a: writes the output folder of the run only | Writes files of the run on the host running the assessment, in one new folder per run under -OutputPath (default C:\Scripts\Securnet\Reports since v1.38.0, PORT-PLAN H21). | local output (by design) |
| `Command:Stop-Transcript` | The run's own output folder (log, CSV, JSON, HTML, transcript) | Default | n/a: writes the output folder of the run only | Writes files of the run on the host running the assessment, in one new folder per run under -OutputPath (default C:\Scripts\Securnet\Reports since v1.38.0, PORT-PLAN H21). | local output (by design) |
| `DotNet:[System.IO.File]::Open` | New-AdfaRunFolder: creates the run's empty log file with FileMode CreateNew to claim the run folder, so two runs started in the same second never share one (since v1.38.0, PORT-PLAN H21, independent review fix) | Default | https://learn.microsoft.com/dotnet/api/system.io.filemode | CreateNew: "Specifies that the operating system should create a new file... If the file already exists, an IOException exception is thrown." The FileMode parameter is the one the Open methods of File take. Writes one empty file in the run folder on the host running the assessment. | local output (by design) |

## In-process commands, types and members

| Key | Where | Run | Learn source (read 2026-11-18 unless stated) | What Learn documents | Verdict |
| --- | --- | --- | --- | --- | --- |
| `Method:GetUnresolvedProviderPathFromPSPath` | Resolve-AdfaOutputRoot: resolves -OutputPath, or the default root, to a provider path and its provider, to refuse any provider but FileSystem (since v1.38.0, PORT-PLAN H21) | Default | https://learn.microsoft.com/dotnet/api/system.management.automation.pathintrinsics.getunresolvedproviderpathfrompspath | Converts a drive or provider qualified absolute or relative path into a provider-internal path, without resolving wildcards; throws DriveNotFoundException for a drive that cannot be found. Nothing about a change of state. | in-process |
| `Command:Add-Member` | In-process helper | Default | n/a: reaches no DC and no other computer | Runs in the PowerShell process or reads the local computer only. | in-process |
| `Command:ConvertFrom-Csv` | In-process helper | Default | n/a: reaches no DC and no other computer | Runs in the PowerShell process or reads the local computer only. | in-process |
| `Command:ConvertFrom-Json` | In-process helper | Default | n/a: reaches no DC and no other computer | Runs in the PowerShell process or reads the local computer only. | in-process |
| `Command:ConvertTo-Json` | In-process helper | Default | n/a: reaches no DC and no other computer | Runs in the PowerShell process or reads the local computer only. | in-process |
| `Command:ForEach-Object` | In-process helper | Default | n/a: reaches no DC and no other computer | Runs in the PowerShell process or reads the local computer only. | in-process |
| `Command:Get-Command` | Reads the local computer or the session only | Default | n/a: reaches no DC and no other computer | Runs in the PowerShell process or reads the local computer only. | in-process |
| `Command:Get-Content` | Reads a local config file named by a -*ConfigPath parameter | Default | n/a: reaches no DC and no other computer | Runs in the PowerShell process or reads the local computer only. | in-process |
| `Command:Get-Date` | In-process helper | Default | n/a: reaches no DC and no other computer | Runs in the PowerShell process or reads the local computer only. | in-process |
| `Command:Get-Module` | Reads the local computer or the session only | Default | n/a: reaches no DC and no other computer | Runs in the PowerShell process or reads the local computer only. | in-process |
| `Command:Group-Object` | In-process helper | Default | n/a: reaches no DC and no other computer | Runs in the PowerShell process or reads the local computer only. | in-process |
| `Command:Import-Module` | Loads a module on the host running the assessment (ActiveDirectory, DnsServer, GroupPolicy, DFSR) | Default | n/a: reaches no DC and no other computer | Runs in the PowerShell process or reads the local computer only. | in-process |
| `Command:Join-Path` | Reads the local computer or the session only | Default | n/a: reaches no DC and no other computer | Runs in the PowerShell process or reads the local computer only. | in-process |
| `Command:Measure-Object` | In-process helper | Default | n/a: reaches no DC and no other computer | Runs in the PowerShell process or reads the local computer only. | in-process |
| `Command:New-CimSessionOption` | In-process helper | Default | n/a: reaches no DC and no other computer | Runs in the PowerShell process or reads the local computer only. | in-process |
| `Command:New-Object` | In-process helper | Default | n/a: reaches no DC and no other computer | Runs in the PowerShell process or reads the local computer only. | in-process |
| `Command:New-TimeSpan` | In-process helper | Default | n/a: reaches no DC and no other computer | Runs in the PowerShell process or reads the local computer only. | in-process |
| `Command:Out-Null` | In-process helper | Default | n/a: reaches no DC and no other computer | Runs in the PowerShell process or reads the local computer only. | in-process |
| `Command:Out-String` | In-process helper | Default | n/a: reaches no DC and no other computer | Runs in the PowerShell process or reads the local computer only. | in-process |
| `Command:Select-Object` | In-process helper | Default | n/a: reaches no DC and no other computer | Runs in the PowerShell process or reads the local computer only. | in-process |
| `Command:Set-StrictMode` | In-process helper | Default | n/a: reaches no DC and no other computer | Runs in the PowerShell process or reads the local computer only. | in-process |
| `Command:Sort-Object` | In-process helper | Default | n/a: reaches no DC and no other computer | Runs in the PowerShell process or reads the local computer only. | in-process |
| `Command:Split-Path` | Reads the local computer or the session only | Default | n/a: reaches no DC and no other computer | Runs in the PowerShell process or reads the local computer only. | in-process |
| `Command:Start-Sleep` | In-process helper | Default | n/a: reaches no DC and no other computer | Runs in the PowerShell process or reads the local computer only. | in-process |
| `Command:Test-Path` | Reads the local computer or the session only | Default | n/a: reaches no DC and no other computer | Runs in the PowerShell process or reads the local computer only. | in-process |
| `Command:Where-Object` | In-process helper | Default | n/a: reaches no DC and no other computer | Runs in the PowerShell process or reads the local computer only. | in-process |
| `Command:Write-Information` | In-process helper | Default | n/a: reaches no DC and no other computer | Runs in the PowerShell process or reads the local computer only. | in-process |
| `Command:Write-Warning` | In-process helper | Default | n/a: reaches no DC and no other computer | Runs in the PowerShell process or reads the local computer only. | in-process |
| `DotNet:[array]::Sort` | In-process helper | Default | n/a: reaches no DC and no other computer | Runs in the PowerShell process or reads the local computer only. | in-process |
| `DotNet:[BitConverter]::GetBytes` | In-process helper | Default | n/a: reaches no DC and no other computer | Runs in the PowerShell process or reads the local computer only. | in-process |
| `DotNet:[BitConverter]::ToInt64` | In-process helper | Default | n/a: reaches no DC and no other computer | Runs in the PowerShell process or reads the local computer only. | in-process |
| `DotNet:[Convert]::ToInt64` | In-process helper | Default | n/a: reaches no DC and no other computer | Runs in the PowerShell process or reads the local computer only. | in-process |
| `DotNet:[datetime]::FromFileTimeUtc` | In-process helper | Default | n/a: reaches no DC and no other computer | Runs in the PowerShell process or reads the local computer only. | in-process |
| `DotNet:[datetime]::Parse` | In-process helper | Default | n/a: reaches no DC and no other computer | Runs in the PowerShell process or reads the local computer only. | in-process |
| `DotNet:[datetime]::SpecifyKind` | In-process helper | Default | n/a: reaches no DC and no other computer | Runs in the PowerShell process or reads the local computer only. | in-process |
| `DotNet:[datetime]::TryParse` | In-process helper | Default | n/a: reaches no DC and no other computer | Runs in the PowerShell process or reads the local computer only. | in-process |
| `DotNet:[datetime]::TryParseExact` | In-process helper | Default | n/a: reaches no DC and no other computer | Runs in the PowerShell process or reads the local computer only. | in-process |
| `DotNet:[decimal]::Truncate` | In-process helper | Default | n/a: reaches no DC and no other computer | Runs in the PowerShell process or reads the local computer only. | in-process |
| `DotNet:[decimal]::TryParse` | In-process helper | Default | n/a: reaches no DC and no other computer | Runs in the PowerShell process or reads the local computer only. | in-process |
| `DotNet:[double]::IsInfinity` | In-process helper | Default | n/a: reaches no DC and no other computer | Runs in the PowerShell process or reads the local computer only. | in-process |
| `DotNet:[double]::IsNaN` | In-process helper | Default | n/a: reaches no DC and no other computer | Runs in the PowerShell process or reads the local computer only. | in-process |
| `DotNet:[double]::TryParse` | In-process helper | Default | n/a: reaches no DC and no other computer | Runs in the PowerShell process or reads the local computer only. | in-process |
| `DotNet:[hashtable]::Synchronized` | In-process helper | Default | n/a: reaches no DC and no other computer | Runs in the PowerShell process or reads the local computer only. | in-process |
| `DotNet:[int]::TryParse` | In-process helper | Default | n/a: reaches no DC and no other computer | Runs in the PowerShell process or reads the local computer only. | in-process |
| `DotNet:[int64]::TryParse` | In-process helper | Default | n/a: reaches no DC and no other computer | Runs in the PowerShell process or reads the local computer only. | in-process |
| `DotNet:[IO.Path]::GetInvalidFileNameChars` | In-process helper | Default | n/a: reaches no DC and no other computer | Runs in the PowerShell process or reads the local computer only. | in-process |
| `DotNet:[math]::Abs` | In-process helper | Default | n/a: reaches no DC and no other computer | Runs in the PowerShell process or reads the local computer only. | in-process |
| `DotNet:[math]::Floor` | In-process helper | Default | n/a: reaches no DC and no other computer | Runs in the PowerShell process or reads the local computer only. | in-process |
| `DotNet:[math]::Min` | In-process helper | Default | n/a: reaches no DC and no other computer | Runs in the PowerShell process or reads the local computer only. | in-process |
| `DotNet:[math]::Pow` | In-process helper | Default | n/a: reaches no DC and no other computer | Runs in the PowerShell process or reads the local computer only. | in-process |
| `DotNet:[math]::Round` | In-process helper | Default | n/a: reaches no DC and no other computer | Runs in the PowerShell process or reads the local computer only. | in-process |
| `DotNet:[regex]::Escape` | In-process helper | Default | n/a: reaches no DC and no other computer | Runs in the PowerShell process or reads the local computer only. | in-process |
| `DotNet:[regex]::Match` | In-process helper | Default | n/a: reaches no DC and no other computer | Runs in the PowerShell process or reads the local computer only. | in-process |
| `DotNet:[regex]::Matches` | In-process helper | Default | n/a: reaches no DC and no other computer | Runs in the PowerShell process or reads the local computer only. | in-process |
| `DotNet:[regex]::new` | In-process helper | Default | n/a: reaches no DC and no other computer | Runs in the PowerShell process or reads the local computer only. | in-process |
| `DotNet:[regex]::Replace` | In-process helper | Default | n/a: reaches no DC and no other computer | Runs in the PowerShell process or reads the local computer only. | in-process |
| `DotNet:[string]::Equals` | In-process helper | Default | n/a: reaches no DC and no other computer | Runs in the PowerShell process or reads the local computer only. | in-process |
| `DotNet:[string]::IsNullOrEmpty` | In-process helper | Default | n/a: reaches no DC and no other computer | Runs in the PowerShell process or reads the local computer only. | in-process |
| `DotNet:[string]::IsNullOrWhiteSpace` | In-process helper | Default | n/a: reaches no DC and no other computer | Runs in the PowerShell process or reads the local computer only. | in-process |
| `DotNet:[System.Array]::Sort` | In-process helper | Default | n/a: reaches no DC and no other computer | Runs in the PowerShell process or reads the local computer only. | in-process |
| `DotNet:[System.Diagnostics.Stopwatch]::StartNew` | In-process helper | Default | n/a: reaches no DC and no other computer | Runs in the PowerShell process or reads the local computer only. | in-process |
| `DotNet:[System.IO.Path]::GetFileName` | In-process helper | Default | n/a: reaches no DC and no other computer | Runs in the PowerShell process or reads the local computer only. | in-process |
| `DotNet:[System.Net.IPAddress]::TryParse` | In-process helper | Default | n/a: reaches no DC and no other computer | Runs in the PowerShell process or reads the local computer only. | in-process |
| `DotNet:[System.Net.WebUtility]::HtmlEncode` | In-process helper | Default | n/a: reaches no DC and no other computer | Runs in the PowerShell process or reads the local computer only. | in-process |
| `DotNet:[System.Security.AccessControl.RawSecurityDescriptor]::new` | In-process helper | Default | n/a: reaches no DC and no other computer | Runs in the PowerShell process or reads the local computer only. | in-process |
| `DotNet:[System.Security.Cryptography.X509Certificates.X509Certificate2]::GetCertContentType` | In-process helper | Default | n/a: reaches no DC and no other computer | Runs in the PowerShell process or reads the local computer only. | in-process |
| `DotNet:[System.Security.Principal.SecurityIdentifier]::new` | In-process helper | Default | n/a: reaches no DC and no other computer | Runs in the PowerShell process or reads the local computer only. | in-process |
| `DotNet:[System.Text.Encoding]::GetEncoding` | In-process helper | Default | n/a: reaches no DC and no other computer | Runs in the PowerShell process or reads the local computer only. | in-process |
| `DotNet:[timespan]::TryParse` | In-process helper | Default | n/a: reaches no DC and no other computer | Runs in the PowerShell process or reads the local computer only. | in-process |
| `DotNet:[uint32]::TryParse` | In-process helper | Default | n/a: reaches no DC and no other computer | Runs in the PowerShell process or reads the local computer only. | in-process |
| `DotNet:[uint64]::TryParse` | In-process helper | Default | n/a: reaches no DC and no other computer | Runs in the PowerShell process or reads the local computer only. | in-process |
| `NewObject:byte[]` | In-process helper | Default | n/a: reaches no DC and no other computer | Runs in the PowerShell process or reads the local computer only. | in-process |
| `NewObject:datetime` | In-process helper | Default | n/a: reaches no DC and no other computer | Runs in the PowerShell process or reads the local computer only. | in-process |
| `NewObject:string[]` | In-process helper | Default | n/a: reaches no DC and no other computer | Runs in the PowerShell process or reads the local computer only. | in-process |
| `NewObject:System.Collections.ArrayList` | In-process helper | Default | n/a: reaches no DC and no other computer | Runs in the PowerShell process or reads the local computer only. | in-process |
| `NewObject:System.Collections.Generic.HashSet[string]` | In-process helper | Default | n/a: reaches no DC and no other computer | Runs in the PowerShell process or reads the local computer only. | in-process |
| `NewObject:System.Collections.Generic.List[object]` | In-process helper | Default | n/a: reaches no DC and no other computer | Runs in the PowerShell process or reads the local computer only. | in-process |
| `NewObject:System.Collections.Generic.List[string]` | In-process helper | Default | n/a: reaches no DC and no other computer | Runs in the PowerShell process or reads the local computer only. | in-process |
| `NewObject:System.Collections.Generic.List[uint32]` | In-process helper | Default | n/a: reaches no DC and no other computer | Runs in the PowerShell process or reads the local computer only. | in-process |
| `NewObject:System.Collections.Queue` | In-process helper | Default | n/a: reaches no DC and no other computer | Runs in the PowerShell process or reads the local computer only. | in-process |
| `NewObject:System.Security.Cryptography.X509Certificates.X509Certificate2` | In-process helper | Default | n/a: reaches no DC and no other computer | Runs in the PowerShell process or reads the local computer only. | in-process |
| `NewObject:System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension` | In-process helper | Default | n/a: reaches no DC and no other computer | Runs in the PowerShell process or reads the local computer only. | in-process |
| `NewObject:System.Security.Principal.SecurityIdentifier` | In-process helper | Default | n/a: reaches no DC and no other computer | Runs in the PowerShell process or reads the local computer only. | in-process |
| `NewObject:System.Text.StringBuilder` | In-process helper | Default | n/a: reaches no DC and no other computer | Runs in the PowerShell process or reads the local computer only. | in-process |
| `NewObject:System.Threading.ManualResetEvent` | In-process helper | Default | n/a: reaches no DC and no other computer | Runs in the PowerShell process or reads the local computer only. | in-process |

## Effects that cross every row

| Key | Where | Run | Learn source (read 2026-11-18 unless stated) | What Learn documents | Verdict |
| --- | --- | --- | --- | --- | --- |
| `Effect:logon-audit` | Every authenticated connection to a DC: LDAP, ADWS, RPC, SMB, WinRM, DCOM | Default | No Learn page read in this session for this effect | Whether the DC's audit policy logs these logons (for example in its Security log) depends on that policy. Not documented by the pages read. For the operator to decide. | not documented |
| `Effect:remote-registry-service` | OpenRemoteBaseKey (RestoreIntegrity) | Default | https://learn.microsoft.com/dotnet/api/microsoft.win32.registrykey.openremotebasekey and https://learn.microsoft.com/troubleshoot/windows-client/performance/memory-leak-remote-registry-service | Both machines must be running the remote registry service; the Remote Registry service is designed to stop running after the connection has been idle for 10 minutes. No page read says whether a connection starts a stopped service. For the operator to decide. | not documented |
| `Effect:dns-client-cache` | Resolve-DnsName, nslookup, nltest /dsgetdc, Dns.BeginGetHostAddresses on the host running the assessment | Default | https://learn.microsoft.com/powershell/module/dnsclient/resolve-dnsname and https://learn.microsoft.com/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc731935(v=ws.11) | Learn documents that a DC locator cache is consulted without /FORCE; whether these queries add entries to the runner's DNS client cache is not stated. | not documented |
| `Effect:schannel` | The LDAPS handshake | Opt-in: -IncludeLdapsHandshake | No Learn page read in this session for this effect (the README row was read 2026-11-16) | A DC that cannot complete the handshake may log a Schannel error event in its System log. | not documented |

