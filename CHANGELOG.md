# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

The tool's own changelog from before the extraction is kept at
[docs/CHANGELOG-ADForestAssessment.md](docs/CHANGELOG-ADForestAssessment.md).

## [Unreleased]

### Changed - 2026-11-18 (Side-effect audit: every Learn page read, instance methods keyed by receiver type, tool v1.39.0)

**PORT-PLAN H20c and H20d.** No new `-Sections` value, no section key, no finding Item text or
status changed, and nothing the script runs changed: the script's help and version moved, the rest
is docs/SIDE-EFFECT-AUDIT.md, the README and the tests. **Run against stubs only** - nothing in this
entry has been run against a real directory or DC. What was not verified: what a DC records of any
call these rows describe (logon auditing, the Remote Registry service, the DNS client cache and
Schannel stay the `Effect:` rows of H20b); how `SecurityIdentifier.Translate` looks a name up (its
page does not say); whether closing a TCP connection, a remote registry key or a file over SMB
leaves anything on the DC (the pages describe the operation only); the archived
`Gpo.GenerateReport` page has no remarks on where it reads.

- **Every Learn page read (H20c).** The 38 default rows H20a left on a page not read, and the four
  opt-in rows of the LDAPS handshake, now cite the page, the read date and what it says. 0 default
  rows rest on a page that was not read; 3 rest on no Learn page and say why (`dcdiag
  /test:FsmoCheck`, `repadmin /showbackup` in two forms). `documented read`: the 17 ActiveDirectory
  Get cmdlets, `Directory.GetDirectories`, the `FileStream` constructor as called (`FileMode.Open`,
  `FileAccess.Read`), `FileStream.Read`, `Dns.BeginGetHostAddresses`/`EndGetHostAddresses`,
  `RegistryKey.GetValue`/`GetValueNames`, `Gpo.GenerateReport`. `not documented`, page read:
  `Remove-CimSession` (it removes the session "from the local PowerShell session"; nothing about the
  remote end), `TcpClient.BeginConnect`/`EndConnect`/`Close`, `RegistryKey.Close` (it "flushes it to
  disk if its contents have been modified"; the key is opened read-only), `FileStream.Seek`/`Dispose`,
  `SslStream.AuthenticateAsClient`/`Dispose`, `SecurityIdentifier.Translate`. `in-process`:
  `Process.Start`, `Kill` and `WaitForExit` act on the console tool `Invoke-ExternalCommand` started
  on the host running the assessment (Learn: "You cannot cause processes on remote computers to
  exit"; Learn also warns that a killed process can lose data it was editing, and what a killed tool
  leaves half done on a DC is not documented), and the `TcpClient`, `SslStream`, `Process`,
  `ProcessStartInfo`, `[powershell]::Create` and `IPGlobalProperties` constructors and `GetStream`.
  No page documents a change of state on a DC or any other computer for a default row, so no row
  moved behind a switch. The verdict meanings were narrowed accordingly (`not documented`: the page
  was read and says nothing either way, or there is no page). Counts: documented read 81, documented
  change opt-in 7, not documented 22, local output 7, in-process 181.
- **Guards for verdicts that rest on how an API is called (H20c).** The population test fails on a
  `FileStream` opened other than with `FileMode.Open`, `FileAccess.Read` and only `FileShare`
  members as exactly four arguments, a `TcpClient` built with any value but one `$x.AddressFamily`
  (the overload Learn documents as connecting), and `-ForceDiscover` or `-Discover` in any form
  PowerShell binds (Learn: it "clears any cached domain controller information").
- **Instance methods keyed by receiver type (H20d).** `Method:[<type>].<name>` where the same
  function shows the type (`New-Object`, `[<type>]::new`, a cast, or a member whose return type
  Learn documents); `Untyped:<function>:<receiver>.<name>` for any other receiver, except 24 generic
  names keyed by name alone; a variable given two types fails. Every property set on the
  `ProcessStartInfo` or `Process` the script builds is keyed with its value, both may be built only
  in `Invoke-ExternalCommand`, and a method on one of their properties is never keyed by name alone:
  `$psi.FileName = 'sc.exe'` passed v1.38.0 and fails now. Shown red in-test on one planted source
  (13 plantings). The existing H20a registry-write mutation now expects
  `Method:[Microsoft.Win32.RegistryKey].SetValue` instead of `Method:SetValue`, and the unread-count
  test expects 0 instead of 38. Left open: H20e.
- **Found by an independent review of the diff before commit, and fixed in it.** Fifteen
  confirmed findings, each reproduced by the reviewer on a copy of the script under Windows
  PowerShell 5.1 and each surviving the first form of the test (no new key, no failure); all are
  test or documentation defects, and nothing the script runs changed. (1, 7, 14) The `TcpClient`
  guard counted `-ArgumentList @('dc1.contoso.com', 389)` and an array held in a variable as one
  value, so the host-and-port overload that connects passed; it now accepts no value or one
  `$x.AddressFamily` and refuses anything else. (2, 5, 11) A `Process` or `ProcessStartInfo` built
  by a hashtable cast (`[System.Diagnostics.Process]@{ StartInfo = ... FileName = 'sc.exe' }`)
  passed both the "only in `Invoke-ExternalCommand`" guard and the property keys; a cast to either
  type now fails, and `New-Object` of either must have no value and no `-Property` and go straight
  into a variable the test types as that type. (3, 6, 11, 13) A property set through a second name
  (`$s = $p.StartInfo; $s.FileName = 'sc.exe'`, `$alias = @($psi)[0]`,
  `$ev = $psi.EnvironmentVariables; $ev.Add(...)`) or through `New-Object -Property` was not keyed;
  every use of a variable typed as either is now one the test keys (a method call, a property set,
  the value of `$p.StartInfo = $psi`, or a read of `ExitCode`), `-Property` fails on any type, and
  `New-Object` parameters are matched by prefix. (4, 8, 10) The discovery guard matched only the
  exact names as a parameter or a literal hashtable key; PowerShell binds a unique prefix on the
  command line and from a splat (checked here on a local function: `@{ ForceDisc = $true }` and
  `-Fo` bind `-ForceDiscover`, `-F` is refused as ambiguous), and the script builds its splats by
  member assignment. The test now refuses any prefix on `Get-ADDomainController`, either exact name
  anywhere, any string of two or more letters that is a prefix of either (key, member, index, `Add`
  argument), and `@args`/`@PSBoundParameters` splatted into it. (9) The `FileStream` guard read only
  arguments 2 and 3, so a sixth argument `FileOptions.DeleteOnClose` (which Learn documents as
  deleting the file when it is no longer in use, and the reviewer showed deleting a scratch file)
  passed; the test now requires exactly four arguments, the fourth only `FileShare` members.
  (12) `Add` was a generic name keyed alone; Learn's ADSI "Adding Users to a Group" adds a member
  with `grp.Add(...)` alone, so the inventory's claim that a .NET directory write needs
  `CommitChanges`, `SetValue` or `Put` was wrong. `Add` is no longer generic; the four untyped `Add`
  calls are `Untyped:` rows (Method keys 83 to 82, generic names 25 to 24, Untyped rows 12 to 16,
  in-process rows 178 to 181), and the claim is gone. (15) A variable bound by `-OutVariable` (or
  `Set-Variable`) kept the type of its visible assignment; a common parameter that binds a variable,
  any prefix or alias of it, and `Set-Variable`/`New-Variable` are now untyped bindings. Each
  mutation is shown red in a new Context of the population test, on one planted source, and the
  script file's hash is checked unchanged after it. Left open and recorded as PORT-PLAN H20e: the
  arguments of an unguarded listed command (an `Out-File` pointed outside the run folder keeps its
  key), and a name built at run time from parts the parser does not hold.
- **Version** 1.39.0 in the script and the manifest; every version pin of the tests and the
  validation harness moved.
- **Sources** (all read 2026-11-18, whole page, on Microsoft Learn):
  https://learn.microsoft.com/powershell/module/activedirectory/get-adcomputer,
  get-addefaultdomainpasswordpolicy, get-addomain, get-addomaincontroller,
  get-adfinegrainedpasswordpolicy, get-adforest, get-adoptionalfeature, get-adreplicationconnection,
  get-adreplicationfailure, get-adreplicationpartnermetadata, get-adreplicationqueueoperation,
  get-adreplicationsite, get-adreplicationsitelink, get-adreplicationsubnet, get-adrootdse,
  get-adtrust, get-aduser (same path);
  https://learn.microsoft.com/powershell/module/cimcmdlets/remove-cimsession;
  https://learn.microsoft.com/dotnet/api/system.io.directory.getdirectories,
  system.io.filestream.-ctor, system.io.filestream.read, system.io.filestream.seek,
  system.io.stream.dispose, system.io.filemode, system.io.fileaccess, system.io.fileshare,
  system.io.file.open, system.net.dns.begingethostaddresses, system.net.dns.endgethostaddresses,
  system.net.sockets.tcpclient.-ctor, system.net.sockets.tcpclient.beginconnect,
  system.net.sockets.tcpclient.endconnect, system.net.sockets.tcpclient.getstream,
  system.net.sockets.tcpclient.close, system.net.security.sslstream.-ctor,
  system.net.security.sslstream.authenticateasclient, system.net.security.sslstream.dispose,
  system.net.networkinformation.ipglobalproperties.getipglobalproperties,
  microsoft.win32.registrykey.getvalue, microsoft.win32.registrykey.getvaluenames,
  microsoft.win32.registrykey.opensubkey, microsoft.win32.registrykey.close,
  microsoft.win32.registrykey.openremotebasekey, system.diagnostics.process,
  system.diagnostics.process.start, system.diagnostics.process.kill,
  system.diagnostics.process.waitforexit, system.diagnostics.processstartinfo,
  system.diagnostics.stopwatch.startnew, system.security.principal.securityidentifier.translate,
  system.security.cryptography.x509certificates.x509certificate.reset,
  system.threading.eventwaithandle.set, system.threading.waithandle.dispose (same path,
  view netframework-4.8.1); system.management.automation.powershell.create, .addscript and
  .addargument (view powershellsdk-7.4.0);
  https://learn.microsoft.com/previous-versions/windows/desktop/wmi_v2/class-library/gpo-generatereport-method-reporttype-microsoft-grouppolicy;
  https://learn.microsoft.com/powershell/module/grouppolicy/get-gporeport (adjacent).
  Read 2026-11-18 for the review fix: https://learn.microsoft.com/dotnet/api/system.io.fileoptions,
  https://learn.microsoft.com/dotnet/api/system.io.fileshare (re-read),
  https://learn.microsoft.com/dotnet/api/system.diagnostics.process.exitcode,
  https://learn.microsoft.com/powershell/module/activedirectory/get-addomaincontroller (re-read: the
  parameter list, -Discover, -DomainName, -Filter, -ForceDiscover),
  https://learn.microsoft.com/windows/win32/adsi/adding-users-to-a-group.

### Changed - 2026-11-18 (House rules: one output folder per run, closing log lines, exit codes 0/1/2, help of every function, tool v1.38.0)

**PORT-PLAN H21, closing GAP-P7. BREAKING: the default output folder moves, the log and transcript
file names change, and a run now sets a process exit code.** No new `-Sections` value, no section
key, no finding Item text or status changed. **Run against stubs only** - nothing in this entry has
been run against a real directory or DC. What was not verified: where a real run lands and that
nothing is written on a DC; the exit code `powershell.exe -File` returns on a real host for each of
0, 1 and 2; how often a real default run ends with 1 only because a whole section is Not Assessed
(on the single-domain stub forest 17 sections are; 15 before the review fix stopped counting an Info row as assessed); the transcript encoding under Windows PowerShell 5.1 (not
read); a Ctrl+C typed at a real console (the pipeline stop it raises was reproduced with a
`PipelineStoppedException` in a child `-File` run, which now ends with 2 and a closed log; the key
press itself was not tried); two runs racing for one folder in two real processes (the race was
reproduced in one process, with the other run's folder and log created between the check and the
claim). First real run: H21-R.

- **Output folder (BREAKING).** By operator decision this repository's `CLAUDE.md` convention wins
  inside this repository: one new folder per run,
  `C:\Scripts\Securnet\Reports\ADForestAssessment-yyyyMMdd-HHmmss\`, on the computer running the
  assessment only, overridable by `-OutputPath`. It was `%USERPROFILE%\Documents\AdAssessment\yyyy-MM-dd_HH-mm-ss\`.
  The operator's general default `C:\Scripts\Cannes` was considered; the repository rule is the one
  written for this repository. The log is now `ADForestAssessment-<stamp>.log` and the transcript
  `ADForestAssessment-<stamp>-transcript.log` (they were `assessment_<stamp>.log` and
  `transcript_<stamp>.log`). The folder holds the detailed log, the raw CSV, the raw JSON
  (`Assessment.json`, unchanged; no second JSON file) and the HTML report, as before. A run claims
  its folder by creating the folder's log with .NET `FileMode.CreateNew`; a second run in the same
  second, also one started at the same moment, gets `-2`, `-3`, up to 99 (tool default), then stops
  rather than write into a folder another run claimed. A
  root that does not exist is created and the screen and the log say so. An `-OutputPath` that is
  not on the file system is refused before anything is created. The folder is computed by three new
  functions that create nothing, from a new `Output` config table, and claimed by a fourth,
  `New-AdfaRunFolder`.
- **Exit codes (new).** `0` completed with at least one finding, no Fail finding, no section left
  Not Assessed, no finding with an empty or unknown status and every report written; `1` completed
  with a Fail, Broken or Failed finding, a section left Not Assessed (a Not Assessed finding and no
  graded one - an Info row is not graded), a finding with an empty or unknown status, no finding at
  all, uninterpretable rows or a report not written; `2` could not run or was stopped once started.
  PowerShell itself gives `1` for a run that never started (a parameter binding error): then there
  is no run folder and no log, and the README tells a wrapper to check for them. A caller that relied
  on 0 now gets 1 when the run has findings to act on. Set only by the script's one `exit`, in the
  `finally` of its tail, only when the script is run, never when dot-sourced. The returned object
  carries `ExitCode` and `ExitReason`. A tool convention, not a Microsoft value.
- **Log.** Everything after the log opens runs in one try/catch/finally. An error that stops the
  run is logged with the step, message, exception type, position and script stack trace, and the
  log always ends with `Run finished <time>; duration hh:mm:ss (n s)`, `Totals: ...` per status (or
  `not counted`, never zeros), `Exit code: n (reason)` and the log path. The first lines now carry
  the version, the start time, every parameter (a credential as `<redacted>`) and the log path,
  which is also shown on screen. The line format and levels are unchanged (H21a).
- **Help.** The script's `.NOTES` carries `Owner: Carlos Annes (TakeItToCloud)`, `Version`,
  `Created: 2026-07-22`, `Last updated` and `Requires` (with why it targets 5.1); the first
  `.EXAMPLE` is the safe run, and the example that is not read-only says so. Every one of the 449
  functions now documents each of its 1670 parameters with a `.PARAMETER` entry, and the 17 that
  had no help block have one. Most of the 1664 entries added were generated from the param block
  (type, mandatory, default, allowed values) with a sentence from the author's syntax comment, a
  vocabulary of parameter names, or the name itself; H21b replaces the generic ones.
- **Side-effect audit.** `[Environment]::GetFolderPath` is gone (the Documents default); the
  instance method `GetUnresolvedProviderPathFromPSPath`, used to refuse a non-file-system output
  path, is a new in-process row. In-process stays 127; the instance-method population is 58.
  `[System.IO.File]::Open`, the claim of the run folder, is a new local-output row (local output 6
  to 7); the `Method:Stop` row now says the run's stopwatch is stopped on every default run, and
  `Method:Dispose` names the claim's file stream.
- **Tests.** A new Pester Describe (folder computed and never created, the `-OutputPath` override
  and the paths it refuses, folder collision, every exit-code case, the closing lines, the wiring
  of the one `exit` and of the try/catch/finally read from the AST, a child `-File` run that exits
  2 and still closes its log, and the help of every function read from the tokens), new pure
  assertions in Run-Validation, and checks of the folder, the closing lines and the exit code in
  the single-domain, three-domain, failing-collector, refused-override and unreadable-forest smoke
  passes. Existing tests changed: the version pins (1.37.0 to 1.38.0), and the H20a population
  count of instance method names (57 to 58).
- Sources, read on Microsoft Learn 2026-11-18:
  https://learn.microsoft.com/powershell/module/microsoft.powershell.core/about/about_language_keywords
  (exit sets $LASTEXITCODE; with no exit, an unhandled exception gives 1; finally runs on Ctrl+C and exit),
  https://learn.microsoft.com/powershell/module/microsoft.powershell.core/about/about_powershell_exe
  (under -Command a code other than 0 or 1 becomes 1; Ctrl+C under -File gives 0),
  https://learn.microsoft.com/powershell/module/microsoft.powershell.core/about/about_scripts
  ("a nonzero exit code typically signals a failure"),
  https://learn.microsoft.com/powershell/module/microsoft.powershell.core/about/about_comment_based_help
  (one .PARAMETER per parameter; .NOTES is free text, so the five lines are a house convention),
  https://learn.microsoft.com/powershell/module/microsoft.powershell.management/new-item
  (-Force returns an existing folder intact; on a registry key it overwrites the key),
  https://learn.microsoft.com/dotnet/api/system.management.automation.pathintrinsics.getunresolvedproviderpathfrompspath
  (converts a path to a provider path; DriveNotFoundException for an unknown drive),
  https://learn.microsoft.com/dotnet/standard/base-types/custom-date-and-time-format-strings
  ("HH" is the hour from 00 to 23),
  https://learn.microsoft.com/dotnet/api/system.io.filemode
  (CreateNew: "If the file already exists, an IOException exception is thrown"),
  https://learn.microsoft.com/powershell/module/microsoft.powershell.core/about/about_powershell_exe?view=powershell-5.1
  (re-read for the review fix: under -File a script-terminating error gives 1, and an interrupted
  run gives 0).

Found by an independent review of the diff before commit, and fixed in it:

- A fatal error whose message ends in a line break (Windows PowerShell 5.1's ConvertFrom-Json
  message does) split the `Fatal error in Invoke-Main` record and the `Exit code:` line over two log
  lines, so the log no longer ended with its three closing lines. The message, the fatal reason and
  the `Exit code:` reason are now flattened (`" / "`), and so is the `Config override refused` line.
- An Info row beside Not Assessed rows hid a section in which nothing was assessed (the Exchange SE
  scope row, the Port Reachability population row), so such a run exited 0. A section is now left
  Not Assessed when it has a Not Assessed finding and no graded one.
- A finding with an empty, missing or unknown status, and a dictionary row, were counted as clean,
  so the run exited 0 beside `Unclassified=1`. Such a status now gives 1 and is named in the reason.
- Two runs started at the same moment with the same `-OutputPath` could both choose one folder (a
  check, then `New-Item -Force`), and the second truncated the first run's log. The folder is now
  claimed atomically by creating its log with `FileMode.CreateNew` (`New-AdfaRunFolder`); a run
  that loses moves on to `-2` and leaves the other run's files untouched.
- A run stopped by a pipeline stop (Ctrl+C) skips every catch: the script tail's `exit` was after
  the try, so such a `-File` run ended with PowerShell's 0. The `exit` is now in the tail's
  `finally` (measured: 0 before, 2 after).
- The README said 2 means "could not run" for every run that did not run; a parameter binding error
  never reaches the script and gives PowerShell's 1. The README and the help now say so, and a test
  shows it.
- docs/SIDE-EFFECT-AUDIT.md still called `Method:Stop` opt-in; every run now stops the run's stopwatch.
- Tests that could not fail, rewritten so the reviewer's mutation fails them: the script tail is a
  pure `Get-AdfaScriptExitCode` with its own tests, an AST test of its three assignments, and a child
  run that ends with 1 through the real tail (M1); the same child run checks `Credential=<redacted>`
  (M3) and the "did not exist" warning (M4); a smoke pass with both report writers failing and a
  collector returning a dictionary checks the wiring of `-ReportsNotWritten` and `-UnreadableRows`
  (M2, M7), as does an AST test; a child run stopped by a `PipelineStoppedException` checks the
  exit code set before the try (M6); and a test under the th-TH culture checks the stamp (M5).
  Existing tests changed because behaviour changed: the AST test that Invoke-Main calls
  Select-AdfaRunFolder now asserts New-AdfaRunFolder (which calls it), the help population is 449
  functions and 1670 parameters (was 447 and 1666), and the list of new H21 functions is eight.
- Found by CI: CI runs on Linux, where the `C:\` default root, the `\` separator and the Registry
  provider do not exist. Five H21 tests (the default folder, the 24-hour stamp, the th-TH stamp,
  the no-create check and the registry-key refusal) now skip off Windows, by the same platform test
  the ACL tests use. They run, and pass, under both local Windows gates; CI does not cover them.

### Changed - 2026-11-18 (Functional level wording, side-effect audit of every command, update build revision, tool v1.37.0)

**PORT-PLAN H18, H20a and C1a, in one change. No new `-Sections` value and no new section key.**
**Run against stubs only** - nothing in this entry has been run against a real directory or DC.
What was not verified: what `UBR` holds on a real domain controller and its registry type (C17);
every `not documented` row of the side-effect inventory, and the four effects no Learn page read
covers (H20b); the Learn pages of the ActiveDirectory Get cmdlets other than `Get-ADObject`,
`Remove-CimSession`, most of the .NET entry points and the instance methods with reach, which were
not read (38 default rows, H20c); the type of the object each instance method is called on (H20d).

- **H18, functional level wording.** The advice for a forest below the Exchange SE levels said
  raising the level "is a one-way change and cannot be reverted without a forest recovery". It
  now says what Learn says: raising is no longer permanent; the forest can be lowered with
  `Set-ADForestMode` (no lower than Windows Server 2016 while any Windows Server 2025 DC is in the
  forest, otherwise Windows Server 2008) unless a feature tied to the new level has been enabled,
  and lowering needs Enterprise Admins and the schema master. The URL and read date are in the
  text, the help of `-ExchangeSeConfigPath` and the README. The Recycle Bin is not named: the
  lowering page does not name it. KB 322692 (Windows Server 2003) still says a raised level can
  only be changed back by a forest recovery; the newer, specific page was taken.
- **H20a, side-effect audit.** New docs/SIDE-EFFECT-AUDIT.md: every command, console tool form,
  CIM class, StdRegProv method, static .NET member, `New-Object` type and instance method name the
  script holds, each with where it runs, default or opt-in, its Learn source and what Learn
  documents, and one of five verdicts - documented read 56, documented change and opt-in 7, not
  documented 54, local output 6, in-process 127 - plus four `Effect:` rows. Not every page was
  read: 38 default rows rest on a page not read on 2026-11-18 and say `not documented`. Of the
  pages read, none documents a change for anything a default run invokes, and nothing had to
  move behind a new switch; nothing is claimed for the pages not read. A Pester test parses
  the script and fails on any command the inventory does not hold, on a stale row, on a tool name
  or argument it cannot read, on a dynamic call outside four named ones, on a default row with a
  documented change and on an opt-in row naming a switch the script lacks. The smoke harness
  records every console tool a default pass starts. The README claim ("the other commands a
  default run invokes have not each been audited") is replaced by the claim the audit supports,
  with the counts.
- **C1a, update build revision.** The `DcSystem` OS build row shows the full build, for example
  `Build 17763.6532`: the fourth part is the registry value `UBR`, read with the existing
  `StdRegProv` `GetDWORDValue` seam in the CIM session the row already opens (the
  `Invoke-CimMethod` call sites stay three). Display only, never graded. A revision that was not
  read is "Update build revision not read" with its cause, never `.0`; a UBR failure never fails
  the OS read. The key and value name are in the `DcSystem` table and cannot be set from
  `-DcSystemConfigPath`. `DcSystem` now makes one CIM method call per DC; the help and the README
  name the four sections that do (DcDisk, DcHardening, TimeHierarchy, DcSystem).

**Found by an independent review of the diff before commit, and fixed in it.** (1, 2) The help
and the README still said only `DcDisk` and `DcHardening` make CIM method calls; C1a adds
`DcSystem`, and `TimeHierarchy` (C15) was already missing. Both now name the four, and a test
derives the callers of the two StdRegProv seams from the parsed script and checks each is named.
(3) The population test keyed a direct `& nltest.exe $a` (the script block run over WinRM) by its
bare name, `Command:nltest.exe`, so an `ArgumentList` of `/sc_reset:contoso.com` or a planted
`& nltest.exe /sc_reset:...` passed. A direct start is now keyed by its tool form, its argument
traced to the literal or the `Get-AdfaNltestScArgument` call behind the `ArgumentList` beside its
script block (anything else is a failure), the `Command:nltest.exe` row is gone, and both
mutations are shown red in-test. The smoke harness now also records the WinRM script blocks (a
stub `Invoke-Command`, which throws as an unanswered endpoint did) and any tool started directly,
in the single-domain, three-domain and failing-collector passes. (4, 5) The README, the plan row
and the inventory said every default command had been read on Learn; 38 default rows rest on pages
not read. The text now says what was read and what was not, a test pins the count, and the
inventory's result is "of the pages read, none documents a change". (6) The catch around the UBR
seam was reached by no test; a seam that throws is now tested (Ok kept, Error empty, revision not
read with the thrown text, never 0), which fails under the reviewer's mutations M5 and M6. (7) The
population test could not see instance methods, so `OpenSubKey(path, $true)` plus `SetValue` in
RestoreIntegrity passed. Every instance method name is now keyed and audited (57 names), and
`OpenSubKey` is allowed only with one argument, which Learn documents as "Retrieves a subkey as
read-only"; the mutation is shown red in-test. The receiver's type is still not known (H20d). (8)
The inventory's dcdiag DNS row cited the dcdiag reference for the test record; that page says only
that `/DnsDynamicUpdate` "determines if dynamic update is enabled". The row now cites the verify-DNS
page that documents the `_dcdiag_test_record` registration. (9) The help and the README credited
"the revision number of windows" to the Intune page; it is on the OEM deployment page, and both
now say so. (10) The type-mismatch wording ("its registry type is not published") is pinned by a
test. (11) The population test's comment gave wrong counts and asserted none; it now asserts 66
commands, 46 tool forms and 57 method names counted from the script, and the default dcdiag tests
from `DcdiagActiveTests`, not from the inventory's own Run column.

Tests: a new Pester Describe (62 tests, seven of them added by the review fixes); two harness checks changed - the Run-Validation assertion
that the advice "warns the change is irreversible" now asserts the opposite (H18), and the version
pins moved to 1.37.0. New Run-Validation and smoke assertions for C1a and H20a.

Sources, all read 2026-11-18 unless stated:

- https://learn.microsoft.com/windows-server/identity/ad-ds/plan/lower-domain-forest-functional-levels (in full)
- https://learn.microsoft.com/troubleshoot/windows-server/active-directory/raise-active-directory-domain-forest-functional-levels (the conflicting KB 322692, from the research brief)
- https://learn.microsoft.com/intune/app-management/deployment/deploy-win32-update-package (in full)
- https://learn.microsoft.com/windows-hardware/manufacture/desktop/oem-deployment-of-windows-desktop-editions and https://learn.microsoft.com/windows-hardware/manufacture/desktop/add-update-to-winre (search excerpts)
- https://learn.microsoft.com/windows/win32/cimwin32prov/win32-operatingsystem and https://learn.microsoft.com/previous-versions/windows/desktop/regprov/getdwordvalue-method-in-class-stdregprov
- https://learn.microsoft.com/windows-server/administration/windows-commands/dcdiag (in full)
- https://learn.microsoft.com/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc731935(v=ws.11) (nltest, in full)
- https://learn.microsoft.com/windows-server/administration/windows-commands/netdom-trust
- https://learn.microsoft.com/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc770963(v=ws.11), cc835092(v=ws.11) and cc742066(v=ws.11) (repadmin)
- https://learn.microsoft.com/troubleshoot/windows-server/active-directory/active-directory-replication-event-id-1388-1988 (`/advisory_mode`)
- https://learn.microsoft.com/windows-server/networking/windows-time-service/windows-time-service-tools-and-settings (w32tm)
- https://learn.microsoft.com/windows-server/administration/windows-commands/dfsrmig and https://learn.microsoft.com/windows-server/administration/windows-commands/nslookup
- https://learn.microsoft.com/powershell/module/dnsclient/resolve-dnsname, cimcmdlets/get-ciminstance, cimcmdlets/new-cimsession, cimcmdlets/invoke-cimmethod, smbshare/get-smbserverconfiguration, microsoft.powershell.diagnostics/get-winevent, microsoft.powershell.core/invoke-command, dnsserver/get-dnsserverzone, dnsserver/get-dnsserverforwarder, dnsserver/get-dnsserverresourcerecord, grouppolicy/get-gpo, dfsr/get-dfsrbacklog, activedirectory/get-adobject
- https://learn.microsoft.com/windows-server/networking/dns/configure-aging-scavenging
- https://learn.microsoft.com/dotnet/api/microsoft.win32.registrykey.openremotebasekey and https://learn.microsoft.com/troubleshoot/windows-client/performance/memory-leak-remote-registry-service
- https://learn.microsoft.com/dotnet/api/microsoft.win32.registrykey.opensubkey (in full; review fix)
- https://learn.microsoft.com/windows-server/identity/ad-ds/manage/troubleshoot/verify-dns-functionality-to-support-directory-replication (in full, re-read; review fix)

### Fixed - 2026-11-18 (Promise triage: the README and help promises the code did not keep, GAP-P1..P30, tool v1.36.0)

**PORT-PLAN C16. No new `-Sections` value and no new section key.** **Run against stubs only** - nothing in
this entry has been run against a real directory, DC or trust (C16c, with C17). The only real processes run
were `cmd.exe` loops on the build workstation, for the stream test below. The 30 items of
docs/GAP-ANALYSIS.md "Promises the code does not keep" (written at v1.15.0) are called GAP-P1..GAP-P30 here,
because PORT-PLAN already has rows P1-P6. Each was re-measured against v1.35.0 and classified; the full
outcome table, with receipts and the tests that pin each item, is the new "C16 triage (2026-11-18)" section
of docs/GAP-ANALYSIS.md (the original table is kept).

| Item | Outcome |
| --- | --- |
| GAP-P1 SYSVOL subscription | **FixCode**: read by the SYSVOL engine read from each scoped domain's own DCs (`msDFSR-Enabled`, `msDFSR-options` asked on the same `CN=SYSVOL Subscription` read, `-Server <domain>`); `ConvertTo-AdfaDfsrSubscriptionList` replaces `Get-AdfaDfsrSubscription`, which read a `ComputerObjectDN` no inventory row carries, so no subscription was ever read; the Pass row needs a DC read. Graded with `-Sections Sysvol` alone. Closes C2i(5), C14b(5) |
| GAP-P2 `/sc_verify` | **AlreadyFixed** (H19 v1.17.0, H20 v1.18.0); re-read on Learn 2026-11-18 |
| GAP-P3 trust directions | (1) **FixCode**: outbound asked of the PDC emulator of the domain assessed, `nltest /server:<pdc> /sc_query:<partner>`; Not Assessed with the cause when no DC is resolved or it is classified Unreachable. (2)-(4) **AlreadyFixed** (H19). (5)-(6) **Accept + FixWording** (C16a(1)) |
| GAP-P4 dcdiag | **AlreadyFixed** (C11 v1.28.0); README now says `Ping` is a TCP 135 probe |
| GAP-P5 replication | **FixCode**: Pass needs both reads; a failed read is `$null`, never a count of 1 or 0; synopsis corrected |
| GAP-P6 sites | Subnets without a site **AlreadyFixed** (C14); **FixCode**: exact site match on the first RDN; runs without the inventory, with one Not Assessed "Empty sites" row |
| GAP-P7 output folder | **Deferred to H21** |
| GAP-P8 DC hardening | **AlreadyFixed** (C3 v1.20.0, C3f v1.35.0) |
| GAP-P9 GPO / central store | WMI filters **AlreadyFixed** (C15); central store **FixCode** (Not Assessed with its class when SYSVOL could not be listed); wording |
| GAP-P10 security posture | AdminSDHolder **AlreadyFixed** (C9); **FixWording** (no RC4 evaluation, C16b); **FixCode** found while measuring: tombstone lifetime and machine account quota not returned are Not Assessed, not Warning |
| GAP-P11 privilege | **AlreadyFixed** (C10 v1.27.0) |
| GAP-P12 ESC1 | **FixWording** (a configuration heuristic over every template object); published templates and enrolment ACL: C16b |
| GAP-P13 dangerous ACLs | **AlreadyFixed** (C9 v1.26.0) |
| GAP-P14 Exchange markers | **FixWording** (one marker, no verdict); objectVersion: C16b |
| GAP-P15 delegation | **AlreadyFixed** (C10) |
| GAP-P16 DNS | Scavenging, secure update **AlreadyFixed** (C13); **FixCode**: an SRV lookup that failed is Not Assessed unless "no such record"; a measured "no open zone transfer" row; wording (root hints C13c, `-Credential` unused) |
| GAP-P17 dfsrmig | **FixWording** with a Scope fix: the row carries the host's domain and says it was read there |
| GAP-P18 redundancy | **FixWording** (no FSMO concentration, C16b); **FixCode**: the DC count uses `-Credential` |
| GAP-P19 time sync | **FixCode**: Not Assessed when w32tm failed or printed nothing; the row names the host; wording |
| GAP-P20 Exchange SE DC gate | **FixCode**: Pass only over every domain of the forest with no DC unread (`-ForestComplete`); README commands name `DomainControllers` |
| GAP-P21 `-SkipVerification` | **AlreadyFixed** (H19); README parameter guard added |
| GAP-P22 `-AllDomains` help | **FixWording** |
| GAP-P23 `-Server` / `-Credential` help | **FixWording**; `-Credential` for DNS reads: C16b |
| GAP-P24 Invoke-ExternalCommand | **FixCode**: asynchronous reads of both streams started before the wait; retries kept (C16a(5)) |
| GAP-P25 event cap | **FixCode**: `EventScanMaxEvents` (500, tool default); a scan at its cap marks every count a minimum |
| GAP-P26 lingering objects | **FixCode**: no readable count is Not Assessed, not Pass; domain NC only, said in every row; wording |
| GAP-P27 lockout policy | **FixWording**; the rest: C16b |
| GAP-P28 stale objects | **AlreadyFixed** (C14 v1.31.0) |
| GAP-P29 `$sectionStatus` | **FixCode**: removed; a failed forest summary is a Not Assessed row; `.OUTPUTS` corrected |
| GAP-P30 `-Sections` help | **FixWording**; `.PARAMETER EventLookbackDays` and `.PARAMETER ExchangeSeConfigPath` added |

- **Fail closed, by item.** No new row passes on a value not read: the subscription Pass needs a DC read;
  replication Pass needs both queries; the central store, the time source, an SRV lookup, a lingering scan
  and two security posture values are Not Assessed with the cause where they were graded before; the Exchange
  SE DC gate is Not Assessed over part of the forest. Unreachable, access denied and not found are told
  apart by the classes the script already has (`Get-AdfaDirectoryReadErrorClass`, the file classes of the Gpo
  section, the C14 reachability class).
- **Read-only.** No new command. `nltest /server:<dc>` is the query form of the same `/sc_query`; the
  central store is listed with the Gpo section's read-only folder seam (`[System.IO.Directory]::GetDirectories`);
  `Invoke-ExternalCommand` only changes how output is read. The H19 AST guards (the one `/sc_verify`
  builder, the remote script blocks, the `-LiveVerify` wiring) are unchanged and green.
- **Item texts.** Every existing Item is kept. New Items: `<server>: zone transfer` as Pass and Not Assessed
  (it was Warning only), `Empty sites`, `Forest summary`, and `DFSR SYSVOL subscription state` with a new
  cause (no DFSR subscription). Changed Detail texts: the "has no subnets" and "has no domain controllers"
  rows, the site topology Pass, the central store rows, the time source row, the dfsrmig row, the lingering
  scan rows, the Exchange SE DC gate Pass and its no-DC row.
- **Existing tests changed, because the behaviour changed on purpose:** Pester `passes it from the trust
  collector to both directions` (H19) now gives `Get-AdfaTrustHealth` a `-SourceDc`, without which the
  outbound check is no longer run; Run-Validation section 6 likewise (two calls); Pester `treats an unreadable
  OS as absent, not unsupported` and Run-Validation `SE DC OS: a readable DC ...` now expect the DC gate Not
  Assessed (it was Pass beside a row saying no forest-wide verdict could be given); the C4 and C4b non-vacuity
  counts of `-Properties` arguments go from 37 to 38 (the subscription list) and the C4 count of Properties
  key assignments from 23 to 22 (the deleted reader's); and every "carries version"
  test moves to 1.36.0. No test was deleted or weakened.
- **New tests.** Pester `Promise triage: ... (C16, GAP-P1..P30)`, 41 tests, 39 of them red against v1.35.0
  (the two that were green are the README parameter guard - GAP-P21 was already fixed; it is shown able to
  fail on the v1.16.0 example - and the time-out test of `Invoke-ExternalCommand`, which keeps a behaviour);
  Run-Validation `C16` (15 assertions); smoke harness C16 checks in the single-domain, unreachable-DC,
  three-domain, sections-alone and failing-collector passes.
- **Not verified.** Everything against a real forest (C16c): `nltest /server:<dc> /sc_query` from a member
  server and from a DC and the rights it needs; its output for a broken channel (Learn shows only the success
  line); large `repadmin` and `dcdiag` output through the new reader; the advisory-mode output of
  `repadmin /removelingeringobjects` with no lingering object; whether an unset `msDFSR-Enabled` is returned
  and in what type; the exception a refused or unreachable SYSVOL Policies listing raises; what
  `Get-ADReplicationFailure` returns for a DC with no failure. Nothing was run under a localised Windows.
- **Vendor sources, read 2026-11-18:**
  https://learn.microsoft.com/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc731935(v=ws.11)
  (nltest: `/sc_verify`, `/sc_query`, `/server`, Example 3; archived - the current windows-commands/nltest
  address could not be retrieved);
  https://learn.microsoft.com/dotnet/api/system.diagnostics.process.standarderror and
  https://learn.microsoft.com/dotnet/api/system.diagnostics.process.waitforexit (the redirected-stream
  deadlock; WaitForExit() after WaitForExit(timeout));
  https://learn.microsoft.com/windows-server/networking/windows-time-service/windows-time-service-tools-and-settings
  (w32tm /query reads the local computer unless /computer is given);
  https://learn.microsoft.com/windows-server/administration/windows-commands/dfsrmig (/getglobalstate: run it
  on the PDC emulator);
  https://learn.microsoft.com/troubleshoot/windows-client/group-policy/create-and-manage-central-store (the
  central store; no severity published).

**Found by an independent review of the diff before commit, and fixed in it.** Each fix has a test in the new
Pester context `Independent review of the C16 diff: defects found before commit` (12 tests), and each was shown
red by a mutation on a scratch copy of the repository restoring the old behaviour (or the reviewer's own
mutation), the script then restored byte-for-byte and verified by hash.

| Review finding | Fix |
| --- | --- |
| 1, 7 DnsDepth SRV | Only answers of type SRV count. A name with no SRV data (NODATA) answers with its zone's SOA from the Authority section and no error; that was a Pass reading "1 record(s)" and is now a Fail naming the types returned. An Additional-section A record no longer inflates the count |
| 2 zone transfer | The Pass row is judged over the graded zone types (`GradedZoneTypes`, Primary) only: Learn documents `SecureSecondaries` on `Set-DnsServerPrimaryZone`, and `Set-DnsServerSecondaryZone` and the conditional forwarder cmdlets expose no such setting, so a forwarder or stub zone returning no value no longer makes the row Not Assessed for ever. A `TransferAnyServer` on any zone is still the Warning |
| 14 zone transfer, no zone | A server read with no primary zone is Not Assessed; pinned by a test with zero zones (the reviewer's `if ($false)` mutant now fails) |
| 3, 9 empty sites | Asserted only when the DC inventory covers every domain of the forest and no domain's read failed (new pure `Get-AdfaSiteInventoryGap`, the condition the Exchange SE gate already used); otherwise one "Empty sites" Not Assessed row naming the gap (`-AllDomains`, or the failed domains). Before, a site holding only DCs of an unscoped or failed domain was "has no domain controllers" |
| 4 subscription causes | The "not readable" row names each DC with its own cause (access denied, unreachable, not returned, malformed) |
| 5 replication | Partner metadata read but empty, or with no `LastReplicationSuccess` on any partner, is Not Assessed with that cause (PartnerCount 0 is then measured), never Pass; also for the only DC of a domain, since the configuration and schema partitions replicate between domains |
| 6, 10 `msDFSR-Enabled` not returned | Unknown with its cause, so Not Assessed - no longer TRUE (C16a(3) reversed). Re-read on Learn 2026-11-18: KB 2218556 gives only the procedure (set FALSE, then TRUE); it does not say the attribute is normally unset, so the citation is removed from the help and PORT-PLAN |
| 8 central store advice | The Warning Detail no longer quotes `\\<domain>\...` with the domain filled in, so a domain label holding "replication" or "clock" cannot take an earlier unscoped recommendation; the domain is the row's Scope |
| 11 TimeSync | Pinned: a w32tm query that exited non-zero with error text is Not Assessed, never Info "Source: <error>" (the reviewer's mutant now fails) |
| 12 `-NotDfsrCount` wiring | Pinned by the AST argument text `([int]$subscriptionList.NotDfsrCount)` (the reviewer's `-NotDfsrCount 0` mutant now fails) |
| 13 drain bound | Output not complete within `ExternalToolDrainMs` is returned as a failure with the exit code and is **not retried** (the help says a retry follows only a start failure or a time-out), and `.Result` is never read while another process holds the pipe; pinned on a real `cmd.exe /c start /b ping` (`sh -c "sleep 3 &"` elsewhere) |
| 15 dfsrmig output | The state is read from the "Current DFSR global state:" line in the unquoted form Learn publishes, and in the quoted form matched before; any other text stays Not Assessed. Which form each Windows release prints is not verified (C16c) |

Existing assertions changed by these fixes, because the behaviour changed on purpose: Run-Validation
`C16 GAP-P1: FALSE kept, ...` now expects the subscription whose `msDFSR-Enabled` was not returned to be
unknown with its cause (it expected TRUE); the smoke stub of the SYSVOL subscription now returns
`msDFSR-Enabled` TRUE when asked for it, the shape Get-ADObject gives for a set attribute (it returned none and
relied on the TRUE rule). New: Run-Validation 6 assertions; smoke checks in the single-domain pass (replication
Pass on a measured partner), the three-domain pass (empty sites judged with the forest scoped, Not Assessed
naming `-AllDomains` with one domain of three) and the failing-collector pass (no replication Pass). Not
verified, added to C16c: Resolve-DnsName's NODATA shape against an AD zone (seen on this workstation for a
public name only), the properties `Get-DnsServerZone` returns for forwarder, stub and secondary zones, the
dfsrmig output form per release, the partner metadata of the only DC of a forest, and a real helper process
holding stdout open. Left out: C16d. Vendor sources read 2026-11-18 for these fixes:
https://learn.microsoft.com/powershell/module/dnsserver/set-dnsserverprimaryzone (`-SecureSecondaries`);
https://learn.microsoft.com/powershell/module/dnsserver/set-dnsserversecondaryzone (no such parameter);
https://learn.microsoft.com/windows-server/networking/dns/manage-dns-zones (zone transfer settings, for a primary
zone); https://learn.microsoft.com/windows-server/administration/windows-commands/dfsrmig (the published
`/getglobalstate` output); https://learn.microsoft.com/troubleshoot/windows-server/group-policy/force-authoritative-non-authoritative-synchronization
(KB 2218556, re-read for finding 10).

### Changed - 2026-11-17 (SMB server configuration read with Get-SmbServerConfiguration: the SMBv1 row and the second instrument of SMB server signing, tool v1.35.0)

**PORT-PLAN C3f, decision (a). No new `-Sections` value; `-Sections DcHardening`, the section key
`DC Hardening` and the row families are unchanged.** **Run against stubs only** - nothing in this entry
has been run against a real directory or a real DC (C17a). The cmdlet itself was run, read-only, on one
Windows 11 workstation (not a DC), as recorded below.

- **What was wrong.** The `SMBv1` row and the second instrument of `SMB server signing` read
  `MSFT_SmbServerConfiguration` by instance query (`Get-CimInstance`). Measured on 2026-11-15 on one
  Windows 11 workstation, that query returns no instance and no error, so wherever a DC answers the same
  way SMBv1 was never graded and SMB server signing had no second instrument.
- **The decision.** The section now runs `Get-SmbServerConfiguration -CimSession $session -WhatIf:$false
  -Confirm:$false -ErrorAction Stop` in the CIM session it already opens to each DC
  (`Get-AdfaDcHardeningRaw`), and no longer queries the class as instances. It is the read Microsoft
  documents - "Retrieves the SMB server configuration", with `-CimSession` "Runs the cmdlet in a remote
  session or on a remote computer" - and Microsoft's own detection command for both properties read. It
  adds no name to the `Invoke-CimMethod` allow-list, which stays at the three `StdRegProv` `Get*` reads.
  Not taken: invoking `GetConfiguration` (a fourth method name) and the `LanmanServer\Parameters\SMB1`
  registry value (Microsoft documents its absence as the default, Enabled, only under its Windows 7 /
  Windows Server 2008 R2 / Windows Vista / Windows Server 2008 heading, and publishes no meaning of an
  absent value for later builds, so it could not grade an unset value). Learn does not say that the cmdlet calls `GetConfiguration`; that is not claimed. The cmdlet has
  no timeout parameter and is bounded by the session's `OperationTimeoutSec`. `-WhatIf:$false
  -Confirm:$false` are forced because `SmbShare` declares this Get cmdlet with `ConfirmImpact="Medium"`
  (read in `SmbServerConfiguration.cdxml` on the workstation).
- **Fail closed.** One pure resolver, `Resolve-AdfaSmbServerRead`, turns the read into one kind - `Read`,
  `CmdletMissing` (no `SmbShare` module on the computer running the assessment; the DC is not asked),
  `NoInstance` (nothing returned, no error), `AccessDenied` (CIM code, then text), `ClassMissing`
  (`InvalidNamespace`/`InvalidClass`, or those words where no code came back) and `ReadFailed` (anything
  else, quoted; also two or more objects for one DC) - and feeds both rows, so they always describe the
  same answer. A flag that says nothing was read wins over any stray value. The SMBv1 row is its own pure
  verdict, `Get-AdfaSmb1Verdict`: `EnableSMB1Protocol` True is `Fail`, False is `Pass`, and every other
  result - including a property not returned as true or false - is `Not Assessed` with its cause. The OS
  build is never used to infer a pass. Unreachable DCs still go through the C14 gate
  (`Get-AdfaDcProbeGate`) and get the section's `DC hardening: <dc>` row; no SMBv1 row is made for them.
  The CIM error code is now read from the exception or the one it wraps (`Get-AdfaExceptionErrorCode`):
  a CDXML cmdlet's error was measured to reach the catch block as a `CimJobException` with no
  `NativeErrorCode` of its own.
- **SMB server signing.** The C3 rules are unchanged: the second instrument can veto a registry verdict,
  and grades the row when the registry value is not set. The row now names the instrument
  `Get-SmbServerConfiguration RequireSecuritySignature` (was `MSFT_SmbServerConfiguration.RequireSecuritySignature`),
  says the cmdlet "is what was run here" (it used to say the cmdlet was not run), and says why the second
  instrument is missing where it is.
- **Config and override.** `$script:Config.DcHardening.SmbServer` records the cmdlet, its module, the two
  properties and the sources (read 2026-11-17). It is provenance only and cannot be overridden: a
  `SmbServer` key in a `DcHardening` override is refused with its reason.
- **Read-only guard.** A new AST guard in the tests allows `Get-SmbServerConfiguration` only - exactly once,
  inside `Get-AdfaDcHardeningRaw`, with `-CimSession $session`, `-WhatIf:$false`, `-Confirm:$false` and
  `-ErrorAction Stop` - and fails on `Set-SmbServerConfiguration`, `Reset-SmbServerConfiguration`, the
  CDXML aliases `ssmbsc`, `rsmbsc` and `gsmbsc`, any other `Set-Smb*`/`Reset-Smb*` or `*-Smb*` command, any
  `Reset-*` command that is not one of this script's Adfa functions, and an `Invoke-CimMethod` naming
  `GetConfiguration`, `SetConfiguration` or `ResetConfiguration`. It reads command names, not free strings,
  so the recommendation map's advice text is not a hit. It cannot see a command name built at run time.
- **Tests.** A new Describe (C3f, 71 tests): config and override (valid, a `SmbServer` key, and six
  malformed shapes), the wrapped error code (and its five-deep bound), the resolver (thirteen inputs,
  contradictory flags, and who wrote the cause), the
  SMBv1 verdict (pass, fail, eight Not Assessed causes), both rows from one read, the seam against stubs in
  the measured shape (one call, `-WhatIf`/`-Confirm` off, empty/null/two objects, wrapped access denied
  and missing class, cmdlet missing), the collector over five DCs in two domains (one classified
  Unreachable first, one refused, one with SMBv1 on, one off, one silent on every port), and the AST
  wiring and guard with sixteen red cases and two green ones. `Run-SmokeTest.ps1` gained a
  `Get-SmbServerConfiguration` stub in the measured shape (refusing a call without a session or without
  both switches off) and a `Test-CommandAvailable` answer for it; the single-domain pass, the three-domain
  pass (one call per domain's DC) and the failing-collector pass (no call, no SMBv1 row) assert the new
  read, and four modes (missing, empty, denied, SMBv1 on) run end to end. `Run-Validation.ps1` gained the
  pure-logic assertions.
- **Existing tests changed, because the behaviour they pinned changed (none deleted):** the C2 count of
  `Get-CimInstance` calls in the script (7 to 6) and the C3 count of bounded seam operations (4 to 3, classes
  `Win32_OperatingSystem,Win32_Service`), because the instance query is gone; the C3 verdict test's
  instrument name and "the cmdlet was not run" (now "which is what was run here"); the C3 "no instance"
  finding test, now the cmdlet returning no object; the C3 seam context, whose stubs gained
  `Get-SmbServerConfiguration` answering in the measured shape (one instance, SMBv1 False, signing True)
  where the instance query used to answer nothing - so its first test now counts two queries plus one
  cmdlet call, its seam-to-rows test expects SMBv1 `Pass` and an agreeing second instrument, and its
  mixed-result test no longer lists SMBv1 among the Not Assessed rows; the smoke harness checks of the
  same rows (four passes per DC became five); and every version pin, 1.34.0 to 1.35.0.
- **Mutations.** Eighteen single mutations, each applied to a scratch copy of `src`, `tests` and the README
  and restored byte-for-byte after its run (SHA-256 of the scratch script checked equal to the working
  tree's, `8D14EB07...`, after each; the working-tree script unchanged throughout), run against the new
  Describe (65 tests) - **all eighteen killed**: M1 verdict direction swapped (3 tests); M2 no object
  returned made a Pass (2); M3 an unreachable DC read as reachable, WinRM taken as open (1); M4 access
  denied reported as read failed (7); M5 the `SmbServer` override refusal removed (1); M6 the cmdlet call
  dropped (6); M7 the SMBv1 row no longer from its verdict (9); M8 two objects accepted as a read, a
  threshold off by one (1); M9 the per-DC loop stopping after the first DC (1); M10 `-WhatIf:$false`
  dropped (2); M11 the class-missing classification removed (7); M12 the cmdlet-missing check removed (2);
  M13 the wrapped CIM error code not read (3); M14 the no-object flag ignored (4); M15 the second
  instrument fed a value that was not read (8); and three guard reds on the whole script, G1
  `Set-SmbServerConfiguration`, G2 the `rsmbsc` alias, G3 an `Invoke-CimMethod ... ResetConfiguration`
  (2 each).
- **Found by an independent review of the diff before commit, and fixed in it.** (1) The SMBv1
  access-denied row said "Local Administrators rights on the DC are needed for this read", while the
  same change records those rights as not published; the row now says the rights are not published and
  not measured (C17a) and names none. (2) The SMBv1 row said "Reported by the DC -" before sentences
  this tool wrote itself (two configuration objects for one DC; nothing recorded), and a quoted cause
  with no closing period ran into "Read over ...". The raw read now marks this tool's own sentences
  (`SmbErrorByTool`: two or more objects, and an error raised with no message), the resolver says who
  wrote each cause (`CauseSource` `Error` or `Tool`) and reads a tool sentence's words neither as a
  refusal nor as a missing class (a CIM code the exception carried still counts), and the row says
  "Written by this tool, not an error from the DC -" for those; every quoted cause now ends its sentence.
  (3) The `SMB1` registry default was attributed without its scope: Microsoft states "The default
  configuration is Enabled" only under its Windows 7 / Windows Server 2008 R2 / Windows Vista / Windows
  Server 2008 heading (re-read 2026-11-18); the script help, README, PORT-PLAN and this entry now say so.
  (4) The `Get-AdfaDcHardeningRaw` help listed neither `SmbInstrument` nor `SmbCmdletMissing`; it now
  lists them and `SmbErrorByTool`. (5) Tests that could not fail, now red under the reviewer's mutation
  on a scratch copy (restored by hash): `NotFound` added to the missing-class codes (2 tests), the
  "invalid namespace" text fallback cut (1), the five-deep bound cut to two (1), and the empty-message
  default of the SMB catch deleted (1). Not changed: the reviewer's mutation that deletes the SMB catch's
  feed of the section error survives because it is unobservable - the build query runs before it and
  either answers (so the section error is not used) or always sets that error first. Existing test
  changed: the C3f Not Assessed case "access denied" and the smoke harness's `Denied` SMB mode expected
  "Local Administrators" and now expect the not-published sentence.
- **Not verified.** Everything against a real DC: that `Get-SmbServerConfiguration -CimSession` returns one
  object over WSMan and over DCOM, under Windows PowerShell 5.1 and PowerShell 7, with the rights the tool
  runs under; the exception shape and `NativeErrorCode` of a refusal, a missing class or namespace and a
  timeout on a remote DC (so `ClassMissing` and `AccessDenied` by code are unmeasured); which rights the
  read needs on a DC; whether an error raised on the assessing host (a WinRM client failure) is quoted
  as "Reported by the DC", as in the other per-DC sections; that the session's
  `OperationTimeoutSec` bounds the CDXML cmdlet in practice; whether the instance query is also empty on a
  DC; and how an `SMB1` registry value relates to `EnableSMB1Protocol`. All of it is PORT-PLAN C17a.
  WSMan to the workstation itself could not be measured (WinRM not running there).
- **Measured on one Windows 11 build 26100 workstation, not a DC, not elevated, 2026-11-17:** under
  PowerShell 7.6.9 and Windows PowerShell 5.1.26100.9711, `Get-SmbServerConfiguration` is a function of
  `SmbShare` 2.0.0.0 with `-CimSession`, `-ThrottleLimit`, `-AsJob`, `-WhatIf` and `-Confirm`; over a DCOM
  session to localhost it returned one `MSFT_SmbServerConfiguration` instance (namespace
  `ROOT/Microsoft/Windows/Smb`) with `EnableSMB1Protocol` False and `RequireSecuritySignature` True, both
  `CimType Boolean`; an error from a CDXML cmdlet (`Get-SmbShare` for a share that does not exist) reached
  the catch block as `Microsoft.PowerShell.Cmdletization.Cim.CimJobException` with no `NativeErrorCode`;
  `Get-CimInstance` for a missing class and a missing namespace gave `CimException` with `InvalidClass` and
  `InvalidNamespace`. `SmbServerConfiguration.cdxml` declares Get `ConfirmImpact="Medium"` alias `gsmbsc`,
  Reset `ConfirmImpact="High"` alias `rsmbsc`, Set `ConfirmImpact="High"` alias `ssmbsc`.
- **Vendor sources, read 2026-11-17:**
  https://learn.microsoft.com/powershell/module/smbshare/get-smbserverconfiguration ("Retrieves the SMB
  server configuration", the syntax with `-CimSession`, output `MSFT_SmbServerConfiguration`),
  https://learn.microsoft.com/windows-server/storage/file-server/troubleshoot/detect-enable-and-disable-smbv1-v2-v3
  (detection `Get-SmbServerConfiguration | Select EnableSMB1Protocol`; the `SMB1` registry value, its
  default Enabled with no named value - stated under the heading for Windows 7, Windows Server 2008 R2,
  Windows Vista and Windows Server 2008 only, re-read 2026-11-18; "Be careful when you disable SMBv1 on
  domain controllers"),
  https://learn.microsoft.com/windows-server/storage/file-server/troubleshoot/smbv1-not-installed-by-default-in-windows
  (not installed by default from Windows Server 2019; "We strongly recommend that you don't reinstall
  SMBv1"), https://learn.microsoft.com/windows-server/storage/file-server/smb-signing (the
  `RequireSecuritySignature` check), https://learn.microsoft.com/previous-versions/windows/desktop/smb/msft-smbserverconfiguration
  (archived: `EnableSMB1Protocol`, `RequireSecuritySignature`, boolean; methods `GetConfiguration` and
  `SetConfiguration`),
  https://learn.microsoft.com/dotnet/api/microsoft.management.infrastructure.cimcmdlets.newcimsessioncommand.operationtimeoutsec?view=powershellsdk-7.6.0
  ("Specifies the operation timeout for all operations in session") and
  https://learn.microsoft.com/dotnet/api/microsoft.management.infrastructure.nativeerrorcode?view=powershellsdk-7.6.0
  (the code names `AccessDenied`, `InvalidNamespace`, `InvalidClass`). The smbv1-not-installed, smb-signing
  and archived class pages were read by the research step of this session, not re-opened while writing the
  code; the others were re-read.

### Changed - 2026-11-17 (Per-domain DC targets for every per-DC section, one probe per port, the reachability class in every section, CIM ports refused, tool v1.34.0)

**PORT-PLAN C2e, C1b, C3g and the reachability part of C14c, in one change. No new `-Sections` value.
A BREAKING change for an override file that names `WsmanPort` or `RpcPort` under `DcDisk`, or in
`-DcSystemConfigPath`.** **Run against stubs only** - nothing in this entry has been run against a real
directory or a real DC (C17).

- **C2e - what was wrong.** The per-DC sections other than `DcDisk`, `DcHardening`, `DcCertificates`,
  `RidPool`, `Dns`, `DcDiagnostics` and `DnsRecordExport` took their DC list from `$dcNames`. When
  `DomainControllers` is not among `-Sections`, that is one `Get-ADDomainController -Filter *` against the
  default server, which Microsoft documents as the domain "of the computer running Windows PowerShell": on
  `-AllDomains` every other domain was missing from `Replication`, the SYSVOL shares and DFS Replication
  events, the patch-level half of `DcSystem`, `Backup`, `TimeHierarchy`, `PortMatrix`, `DsEvents` and
  `RestoreIntegrity`, with no row to say so; the DNS server set of `DnsAdConsistency`, `DsaCname`,
  `GcConsistency` and `MsdcsDelegation`, the SYSVOL backlog fallback, the raw `repadmin`/`dcdiag`
  captures and the run's DC count had the same gap.
- **C2e - what it does now.** One per-domain list, `$perDcTargets`: the C14/C15 list where the run
  already holds one per domain, otherwise one `Get-AdfaDcTargetsByDomain` (one `Get-ADDomainController
  -Filter * -Server <domain>` per scoped domain) shared by every section, and the unscoped names only when
  no domain gave a DC. Each of those sections takes it, each row carries its domain in `Scope`, and a
  scoped domain whose DCs could not be enumerated - or that returned none - gets one `Not Assessed`
  `<label> (population): <domain>` row with the cause (`Get-AdfaDcPopulationRow`, the C2 gap logic):
  `Replication health`, `SYSVOL / NETLOGON shares`, `DFS Replication events`, `Patch level`,
  `Directory backup`, `USN rollback marker`, `Directory Service events` and `Time hierarchy`; the port
  matrix uses the `DC reachability (population)` rows it already had. A DC with no host name is its own
  `Not Assessed` row, never probed and never dropped. `DcSecureChannel`, which already read each domain,
  words a failed enumeration with the same text and no longer returns nothing for a domain that returned no
  DC. The DNS server set is the per-domain host names, each once; `DcCount` counts them. **A test reads
  the parsed `Invoke-Main` and fails if any command takes `$dcNames` again**: every reference must be its
  definition, its emptiness check, or the last-resort fallback of a declared list of sections.
- **C1b and C14c - what was wrong.** The reachability classification (C14) measures 5985 and 135 only on
  a DC whose LDAP answered, so for a DC classified `Unreachable` the cache held nothing for them, and every
  section that probed 5985, 135, 445 or 636 probed it again and reported a silent port instead of the
  class. Nine sections bypassed the cache altogether with `Test-TcpPort` (`Replication` on 135 and 9389,
  `Backup`, `PortMatrix` on all seven ports plus its own unbounded `Dns.GetHostAddresses`,
  `DcSecureChannel`, the SYSVOL shares, the backlog, the DFS Replication and Directory Service events,
  `RestoreIntegrity`, the lingering-object scan and the raw captures).
- **C1b and C14c - what it does now.** One gate, `Get-AdfaDcProbeGate`: the C14 class first - a DC
  classified `Unreachable` is probed on **no** port and the gate returns the class as the cause - then
  `Test-AdfaDcPort`, the per-run cache. Every per-DC section probes through it; `Test-TcpPort` remains in
  the cache and the trust checks only - the trusted domain's own name (135, 389; not a DC host name) and
  the partner DC, which `Get-AdfaTrustHealth` and `Test-AdfaRemoteSecureChannel` probe only after
  `Get-AdfaDcReachCause` finds no class for it - and `Test-AdfaDcPort` in the gate only, all pinned by a
  test. Every row of an unreachable DC in `Replication`, `DcSecureChannel` (secure channel), `DsEvents`,
  `RestoreIntegrity`, `Backup`, `DcDisk`, `DcHardening`, `DcSystem` (patch level), `Dns` (server read, DC
  DNS client, locator CNAMEs, record export), `DcDiagnostics`, `DcCertificates` (LDAPS handshake), the
  DFS Replication events, the SYSVOL shares, the backlog, the lingering scan, the GPO SYSVOL read of a
  PDC (`GPO folder listing` and each `GPO version` row) and the inbound check of a trust partner DC is
  `Not Assessed` with the class, worded once (`Get-AdfaDcGateText`: the class, then what was not read).
  The dcdiag grid row keeps `Status` and `Ping` `Fail` (C11g(1)) and names the class in `Failures`. The
  port matrix row of such a DC is `Not Assessed` (its `DC reachability` row carries the `Fail`), and the
  port matrix of any other DC takes the classification's name resolution, or the bounded seam, instead of
  resolving again. The DC DNS client adapters, which used to be read before the classification, are read
  after it (their section keeps its place in the report). `RestoreIntegrity` reads the registry through
  a new seam, `Get-AdfaUsnRollbackRaw` (the same `OpenRemoteBaseKey` read, keys now closed), and an
  access-denied read now says `Access denied:`, apart from a key that does not exist and from an
  unreachable DC. **Measured on stubs: with one DC whose name does not resolve, a whole `All` run makes
  one name resolution and no TCP probe of it; with one that refuses LDAP, one resolution and one probe of
  389** (the smoke harness, both passes, and a Pester test across all fourteen per-DC collectors).
  The `DC reachability` row of an unreachable DC no longer says the other sections probe on their own.
- **C3g.** `WsmanPort` and `RpcPort` under `DcDisk` in `-ConfigOverridePath`, and in
  `-DcSystemConfigPath`, are refused with the `DcHardening` wording, whatever they hold. They changed the
  port that was probed and not the port the CIM session connects to: `New-CimSession` is opened without
  `-Port` (pinned by a test on both seams). Honouring them was not chosen: Microsoft documents that "Before
  using an alternate port, you must configure the WinRM listener on the remote computer to listen at that
  port", which only a change on the DC does, says "Do not use the Port parameter unless you must", and
  `New-CimSessionOption` has no port option for DCOM, which always starts at the RPC endpoint mapper on 135.
  The keys stay in the built-in tables, which the code reads.
- **Behaviour kept.** Item texts and statuses of a reachable DC are unchanged; rows of the moved sections
  gained a `Scope` value (and the replication rows a `Scope` column). The classification runs only when
  `PortMatrix` is selected (it is the `PortMatrix` branch of `Invoke-Main` that calls it; `Topology` alone
  enumerates per domain but classifies nothing); without it the gate shares the cache only (C2h(1)).
- **Tests.** A new Describe (`Per-domain DC targets, one probe per port, ...`): the gate (unreachable,
  not classified, reachable with measured ports reused, NotManageable); every one of fourteen per-DC
  collectors with an unreachable DC first and a live DC second (Not Assessed with the class, the second
  DC still handled, the first never probed, resolved once), all fourteen together (one resolution, no
  probe) and a refused DC (one probe of 389); population rows for eight sections (a failed domain, an
  empty domain, the DC rows' scope), the unnamed DC, the empty run; `RestoreIntegrity` unreachable, access
  denied, absent key and a mixed three-DC result; the C3g refusals (each key, values 5985, 5986, 135 and
  1, through the override file and `-DcSystemConfigPath`, the seams opened without a port, the help and
  README); and the wiring by the parsed script (`$dcNames` population, the shared list, nine collectors and
  four DNS sections, the probe allow-lists, the classification before the DC DNS client, `DcCount`). The
  smoke harness gains a counting `Test-TcpPort`, a `Get-AdfaUsnRollbackRaw` stub (so no pass opens a real
  remote registry any more), a read-only `repadmin /showbackup` answer, a nine-section multi-domain pass
  without `DomainControllers`, an unresolved and a refused pass over the whole run, and the failing-
  collector checks of seven sections; `Run-Validation.ps1` gains the pure-logic assertions.
- **Existing tests changed, because the behaviour they pinned changed (none deleted):** C1 "goes on
  citing Microsoft when the override changes a port" (now: the port is refused, the dates keep their
  source); C2 "uses only the transport whose port answered, and the ports the config names" (now: the
  default ports), "shares the per-run probe cache" (now: through the gate) and "goes on calling the
  thresholds tool defaults when the override changes only a port" (now: refused); C3 "reads each DC through
  the shared transport loop and the shared probe cache" (one gate call instead of two cache calls) and the
  `DcDisk` line of "refuses the two port keys" (now refused); C5 "probes port 636 through the shared cache
  only" (through the gate); C8 "reads through its seams only" (the probe and the command whitelist name the
  gate); C11 "probes through the per-run cache" (the gate); C13 "gives the Dns, DnsAdConsistency and
  DomainControllers branches..." (the DNS server set and the DC DNS client's own branch); C14 "says which
  sections reuse an Unreachable class" (reworded) and "no longer probes the time hierarchy with the
  uncached Test-TcpPort" (the gate); the eleven version pins (1.34.0). In `Run-Validation.ps1`: the
  `DcDisk` port line and the C14 reachability wording. After the review: C8 "reads through its seams only"
  (the command whitelist gains the pure `Get-AdfaDcGateText`, 30 commands); the C2e `$dcNames` population
  (`fallback:domainDcNames` removed, because that consumer is gone); the C2e `Test-TcpPort` pin (comment
  corrected, and it now also asserts that the class is consulted before each partner-DC probe); the C2e
  RestoreIntegrity access-denied stub (`ErrorCode` `AccessDenied`, the shape the seam returns, instead of
  `5`); the smoke unreachable pass excludes `Directory certificate:` rows, read from the directory, from
  "no row passes", as it does the OS lifecycle and password rows.
- **Mutations.** Fourteen single mutations of the new code, each on a scratch copy of the repository and run against the new Describe, the script restored byte-for-byte after each and checked by SHA-256 - **all fourteen killed**: M1 the gate ignores the class (15 tests fail); M2 a population row `Pass` instead of `Not Assessed` (7); M3 access denied worded as unreachable (1); M4 the `DcDisk` port refusal removed (3); M5 the `-DcSystemConfigPath` port refusal removed (3); M6 `Backup` wired back to `$dcNames` (2); M7 the empty check of `DsEvents` off by one (1); M8 the DFS Replication loop over the first DC only (3); M9 the port matrix gate inverted (2); M10 the scoped domains dropped from the population (8); M11 the DC DNS client read before the classification (1); M12 `Replication` probing a DC after its class (4); M13 the per-domain list replaced by the unscoped names (2); M14 the dcdiag grid row without the class (2).
- **Found by an independent review of the diff before commit, and fixed in it.** Fourteen defects.
  (1, 2) The GPO SYSVOL read went through the gate but kept only `Open[445]`, so the `GPO folder listing`
  row and every `GPO version` row of a PDC classified `Unreachable` said "port 445 (SMB) ... did not
  answer" for a probe that was never made, and did not name the class (on any run with `PortMatrix` and
  `Gpo`, `All` included): `Get-AdfaGpoSysvolRaw` now returns the gate's cause as `ReachCause`, and
  `Get-AdfaGpoDomainFinding` words those rows with it. (3) The SYSVOL backlog took the unscoped current-domain
  names for any domain with no per-domain DC, so on `-AllDomains` another domain's DCs were measured under
  the failed domain's scope with no row naming the failure: `Get-AdfaDomainDcHostName` (pure) now gives a
  domain its own DCs only, the unscoped names only on a single-domain run, and otherwise a `SYSVOL backlog
  (population): <domain>` row with the cause; the last consumer of `$dcNames` outside the declared fallbacks
  is gone from `Invoke-Main`. (4) `MsdcsDelegation` graded an NS host missing from an incomplete DC list as
  the `Warning` "not a known DC" (with advice to remove a decommissioned DC's record): it is now told which
  scoped domains' DCs are missing (`-IncompleteDomains`) and such a host is `Not Assessed` naming them. (5,
  14) The help said `Topology` triggers the classification (only `PortMatrix` does) and that every per-DC
  section takes every scoped domain's DCs (the `Sysvol` subscription verdict does not, C2i(5)); both
  corrected, here, in PORT-PLAN C2h(1) and in the README. (6) The trust checks probed the partner DC that
  `nltest /dsgetdc` names with `Test-TcpPort` (135, and 5985 for the inbound check) even when it was a DC
  of a scoped domain classified `Unreachable`: both now consult `Get-AdfaDcReachCause` first, do not probe
  it, and name the class in `VerifyDetail` and the inbound result; the trusted domain's own name is still
  probed (C2h(10)). (7, 8, 13) The gate branches of the LDAPS handshake, the SYSVOL backlog, the lingering
  scan, the locator CNAME read, the record export and the DC DNS client, and the `Secure channel: (unnamed)`
  branch, had no test that could fail; each now has one, with an unreachable DC first and a live DC after
  it (the smoke unreachable pass now also runs with `-IncludeLdapsHandshake` and checks the GPO rows). (9,
  12) The hand-kept `$perDcSections` list and the single shared enumeration were unpinned: a test now reads
  the list, derives from the parsed `Invoke-Main` every section branch and switch that uses the per-domain
  targets and fails if one is not covered, and pins `$c15PerDomain = $true`; the smoke harness runs `Backup`
  alone and `DsEvents` with `Backup` on the three-domain forest and counts one `Get-ADDomainController` per
  domain. (10) The access-denied test of the registry seam stubbed an `ErrorCode` the seam never returns:
  the type check is now a pure function, `Get-AdfaRegistryReadErrorCode`, tested with
  `UnauthorizedAccessException`, `SecurityException` and a wrapped `MethodInvocationException`, with
  Portuguese and German messages, the seam's one assignment from it is pinned, and the stub returns
  `AccessDenied`. (11) De-duplication of the DC host set is now a pure function, `Get-AdfaDcHostSet`, tested
  with one DC listed under three domains and in another case. The behaviour fixes (1-4, 6, 10, 11) were run
  red first against the script as it was before them (6 of the 15 new tests failed); each test gap was
  closed by a mutation on a scratch copy that the new tests now kill - see the next item.
- **Mutations for the review fixes.** Eighteen single mutations, each on its own scratch copy of `src`,
  `tests` and the README (the working-tree script's SHA-256 checked equal before and after), run against the
  new Describe (78 tests) and, where named, the harnesses - **all eighteen killed**: R1 the LDAPS
  `ReachCause` branch off (1 test); R2 the backlog peer gate off (1); R3 the lingering-scan gate off (1); R4
  the locator CNAME gate off (1); R5 the record-export gate off (1); R6 the DC DNS client gate off (1); R7
  `Backup` dropped from `$perDcSections` (1, and 7 smoke checks); R8 the raw-capture switches dropped from
  the enumeration guard (1); R9 the registry seam no longer assigns the error code (1); R10 the type check of
  `Get-AdfaRegistryReadErrorCode` off (1, and 1 validation assertion); R11 the host-set de-duplication
  removed (1, and 1 validation); R12 `$c15PerDomain = $false` (1, and 3 smoke checks: each domain enumerated
  twice); R13 the `(unnamed)` branch of `DcSecureChannel` off (1); R14 the GPO class branches off (1, 2
  smoke checks, 1 validation); R15 the trust check probes the partner DC again (1); R16 the inbound check
  probes it again (1); R17 the incomplete-list branch of the `_msdcs` verdict off (1, and 1 validation);
  R18 the unscoped fallback taken for any domain (1, and 1 validation).
- **Not verified.** Everything against a real DC: that a DC classified `Unreachable` is in fact
  unreachable on 445, 636 and 9389 as well (Microsoft publishes no rule that a DC silent on 389 is silent
  elsewhere; the class is the tool's design, REACH-001); the number of `Get-ADDomainController` calls a
  real run makes; `RegistryKey.OpenRemoteBaseKey` access-denied exception types on a real DC (read as
  `UnauthorizedAccessException` or `SecurityException`, by type, then by text); Windows PowerShell 5.1 and
  PowerShell 7 against a real forest. `New-CimSessionOption` was read in the PowerShell 7.5 view; Learn
  does not say what `New-CimSession -Port` does to a DCOM session.
- **Vendor sources, read 2026-11-17:**
  https://learn.microsoft.com/powershell/module/cimcmdlets/new-cimsession (the Windows PowerShell 5.1
  view, read for this entry: `-Port`, the WinRM listener sentence, "Do not use the Port parameter unless
  you must", WSMan by default with `-ComputerName`, DCOM through `New-CimSessionOption`),
  https://learn.microsoft.com/powershell/module/cimcmdlets/new-cimsessionoption (`-Protocol` Dcom, Default
  or Wsman; no port option in either parameter set),
  https://learn.microsoft.com/windows/win32/winrm/installation-and-configuration-for-windows-remote-management
  (default listener ports 5985/5986; "WinRM listeners can be configured on any arbitrary port"),
  https://learn.microsoft.com/powershell/module/activedirectory/get-addomaincontroller (`-Server` default is
  the domain of the computer running PowerShell; `HostName` not set when `DNSHostName` is null),
  https://learn.microsoft.com/troubleshoot/windows-server/active-directory/config-firewall-for-ad-domains-and-trusts
  (the DC port list the port matrix probes). The last four were read by the research step of this
  session, not re-opened while writing the code. For the review fixes:
  https://learn.microsoft.com/dotnet/api/microsoft.win32.registrykey.openremotebasekey (exceptions:
  `SecurityException`, "The user does not have the proper permissions to perform this operation";
  `UnauthorizedAccessException`, "The user does not have the necessary registry rights"; `IOException`
  when the machine is not found) and
  https://learn.microsoft.com/dotnet/api/microsoft.win32.registrykey.opensubkey (`SecurityException`; a key
  that does not exist returns null), both read 2026-11-17.

### Changed - 2026-11-17 (Declared property lists: no read of every attribute, no secret attribute in any list, tool v1.33.0)

**PORT-PLAN C4b. A security fix, and a BREAKING change of the `AllUsers_<domain>.csv` and
`AllComputers_<domain>.csv` exports and of the `Replication Connections` section.** No new
`-Sections` value: the reads stay in `Identity`, `Trusts` and `Topology`. **Run against stubs only** -
nothing in this entry has been run against a real directory (PORT-PLAN C4b2, with C17).

- **What was wrong.** Five reads asked the directory for every attribute (`-Properties *`): the user and
  computer export (`Get-ADUser`, `Get-ADComputer`), the trust health rows (`Get-ADTrust`), the site links
  (`Get-ADReplicationSiteLink`) and the connection objects (`Get-ADReplicationConnection`). Microsoft
  documents `*` as "all of the attributes that are set on the object". For an account with the rights -
  a Domain Admin, the usual way this tool is run - that includes confidential attributes ("only
  Administrators can read confidential attributes"), among them the LAPS passwords, the legacy one in
  clear text; C4 (v1.21.0) stopped writing those to the CSV but they were still requested and held in
  memory. A Windows Server 2025 DC logs Directory Service event 3079 for a search of confidential
  attributes over an unencrypted LDAP session and silently leaves them out ("User error: None"), so the
  old column set also changed with the DC that answered.
- **What it does now.** Every one of those reads names its attributes in a new versioned table,
  `DirectoryRead` (read date 2026-11-17), which no override file can change: `UserExportProperties` (21
  attributes), `ComputerExportProperties` (18), `TrustHealthProperties` (the 14 the trust rows read),
  `SiteLinkProperties` (5) and `ConnectionProperties` (5, LDAP names). A new pure guard,
  `Get-AdfaRefusedPropertyName`, refuses a list with a wildcard (`*` or `?`), a blank name, no name at all,
  a name that is not a plain name (a letter, then letters, digits and hyphens only - a tool rule, so that
  an attribute option such as `;binary`, a range or an OID cannot carry a secret name past the compare),
  or a name of the secret set (`Get-AdfaSecretAttributeName`: the seven LAPS names of `Laps.NeverRead` and
  the seventeen of `DirectoryRead.SecretNames` - password hashes and history, `supplementalCredentials`,
  the gMSA password, the TPM owner information, the BitLocker recovery password and key package, the
  trust secrets, the secret object values, `userPassword` and `unixUserPassword`), compared without
  regard to case; with no secret list it refuses everything. It runs in every seam before anything is
  sent, and a refused read is `Not Assessed` naming the names, with nothing sent. The list is
  name-based, not the confidential bit: `msDS-ManagedPassword`, `unicodePwd`, `supplementalCredentials`
  and `trustAuthIncoming` all carry searchFlags 0.
- **The export.** Each domain's users and computers are read through the C15 seam
  (`Get-AdfaIdentityExportRaw` -> `Get-AdfaInventoryDirectoryRaw`, `Get-ADObject -Server <domain>`,
  `-ResultSetSize MaxObjects + 1`), with the filter `(&(objectCategory=person)(objectClass=user))` or
  `(objectClass=computer)` (which, as `Get-ADComputer -Filter *` did, keeps managed service accounts: a
  gMSA is a "Subclass of Computer"). `ConvertTo-AdfaIdentityExport` (pure) writes the declared columns in
  order, then `Enabled` (from ACCOUNTDISABLE in `userAccountControl`; empty when it was not returned) and
  `ListComplete`. A capped read writes at most `MaxObjects` rows, each "No: ..."; a refused, failed
  (unreachable, access denied and timed out worded apart), capped or empty read makes the
  `Identity Inventory` row `Not Assessed` with its cause, never 0. The summary now counts Enabled and
  Disabled each from a value that was read; an object with no readable `userAccountControl` was counted
  disabled and is now counted in neither, and the row says how many.
- **BREAKING - the export's columns.** They were the union of every attribute any object had, with the
  module's names (`Enabled`, `PasswordLastSet`, `LastLogonDate`, ...); they are now the declared list
  with raw LDAP names and values (`objectSid`, `pwdLastSet`, `lastLogonTimestamp`, `accountExpires` as the
  directory stores them; multi-valued joined with `;`), then `Enabled` and `ListComplete`. The two LAPS
  expiry attributes are no longer export columns (the `Laps` section reads them; an attribute the schema
  lacks would make the read fail). A script that reads these files by column name must be changed.
- **Trusts.** `Get-AdfaTrustHealth` asks for `TrustHealthProperties` and stops the pipeline after
  `MaxObjects + 1` trusts (Learn shows no `-ResultSetSize` for `Get-ADTrust`): a refused read is
  `(enumeration refused)`, more than the cap `(enumeration capped)`, and a failed read
  `(enumeration failed)` now names unreachable or access denied - each one `Not Assessed` row. `Created`
  and `Modified` are read through `Get-AdfaConfigValue`, so an object without them no longer stops the
  section under StrictMode. Verdicts and advice are unchanged.
- **Site links and connections.** One never-throwing seam, `Get-AdfaTopologyObjectRaw`, per cmdlet, with
  the declared list and the same post-read cap, and `ConvertTo-AdfaTopologyListRow` (pure). A failed,
  refused or capped read is ONE `Not Assessed` row (Item `Site links` / `Replication connections`, with the
  cause; "not an empty list") and no longer takes the sites and subnets down with it - before, one throw
  lost the whole topology. **BREAKING - `Replication Connections` columns:** the old ones (FromServer,
  ToServer, Enabled, AutoGenerated) are property names Microsoft does not publish; the connection is now
  read by the NTDS-Connection class's own LDAP names and shows Name, FromServer (`fromServer`, "The
  distinguished name of the replication source server"), DistinguishedName (its parent is the NTDS
  Settings object of the DC holding it), Enabled (`enabledConnection`) and Options (`options`, raw: "the
  meaning of the bits varies from objectClass to objectClass"). ToServer and AutoGenerated are gone
  (PORT-PLAN C4b3).
- **Override.** `MaxObjects` of the `Inventory` key of `-ConfigOverridePath` now also caps these reads; the
  key's `AlsoUsedBy` gained `Topology`. Every list and the secret set are refused from a file as unknown
  keys, and `DirectoryRead` is not a section of the file.
- **Tests.** A new Describe (C4b): an AST guard over the whole script that fails on any argument of
  `-Properties`, of its documented alias `-Property` or of an abbreviation of either down to two letters
  (also `-Name:<x>`), on any command, any `.Properties`/`.Property`/`['Properties']`/`['Property']`
  assignment and any hashtable key named `Property`, `Properties` or ending in `Properties` that holds a
  `*` or a whole name of a secret set declared in the test (24 names, so a name taken out of the script's
  table is still caught), shown red on twenty-two injected cases; a check that every one of the 87
  ActiveDirectory module calls spells `-Properties` in full, so the argument count is the whole population; a check that every non-LAPS secret name appears in the script only inside `DirectoryRead`; a
  walk of every `*Properties` list of the loaded config; the guard; each read with stub cmdlets (exact
  list sent, per domain, refusal sends nothing, a secret the stub hands back reaches no row); normal,
  empty, unreachable, access denied, capped, refused and mixed results; the override; and the wiring by
  AST. Smoke and validation harnesses extended; the stubs now throw on a wildcard, a secret name or a
  list other than the declared one. **Existing tests changed because behaviour changed:** the C4
  `-Properties` argument count 38 -> 37; the C4 context that tested the export mitigation (it stubbed
  `-Properties *` and called the removed `Get-AdfaComputerInventory`) now asserts the declared list sent
  and the declared columns kept; the C15 pin of the `Inventory` key's `AlsoUsedBy` gained `Topology`; the
  version pins; the validation harness's two mitigation asserts and the smoke test's
  "kept the non-secret expiry time" check were rewritten the same way.
- **Not verified** (PORT-PLAN C4b2, owner operator, with C17): that `Get-ADTrust` accepts the 14 ADTrust
  names in `-Properties` (Learn publishes none of them; a name it refuses makes every trust row
  `Not Assessed`), that `Get-ADReplicationConnection` returns `fromServer`, `enabledConnection` and
  `options` under those names when asked by them, that `Select-Object -First` stops a real ADWS search,
  the default property sets of any of these cmdlets, that `-ResultSetSize` caps a `Get-ADObject` search as
  it caps `Get-ADUser`, and the cost of the export on a domain near the 100000 cap. The column lists
  themselves are this tool's choice, for the operator to confirm (PORT-PLAN C4b1). Also not measured:
  whether the ActiveDirectory module would accept a name with an attribute option (`;binary`) in
  `-Properties` - the guard refuses such a name without sending it.
- **Found by an independent review of the diff before commit, and fixed in it.** (1) A capped trust,
  site link, connection or export read said its cap was "Inventory.MaxObjects, a tool default" even when
  the `-ConfigOverridePath` file had set it; a new pure `Get-AdfaCapSource` reads the provenance
  `Merge-AdfaSpecConfig` records and the row now says "set in the -ConfigOverridePath file" when it was.
  The same wording in the C15 inventory rows is not changed here (PORT-PLAN C4b4). (2) The guard compared
  whole names only, so `ms-Mcs-AdmPwd;binary` passed it (no declared list held such a name); it now
  refuses any name that is not a plain name. (3) The AST guard read only a parameter named exactly
  `Properties`, so `Get-ADUser -Filter * -Property *` (Learn: `-Properties` "Aliases: Property") passed
  every test; it now reads the alias and every abbreviation, and a new test pins that the 87
  ActiveDirectory calls spell `-Properties` in full. (4) No test pinned that the trust, site link and
  connection reads stop after `MaxObjects + 1` objects: the stubs now count what they emit and a read of 50
  with a cap of 2 must take 3. (5) Classing a failed topology read by exception type was untested: a
  `TimeoutException` must read "timed out" and the seam must keep `ErrorType`. (6) A refused topology read
  must read "was refused", not "failed". (7) The Pester wiring test now checks each export conversion's
  `-Columns` (its own kind's list), `-AccountDisableBit` (a key the `Inventory` table holds) and
  `-CapSource`, not only the smoke harness. Each fix has a test shown to fail on the reviewer's mutation.
  Existing test changed: the title of "lets the ordinary ... names through" now says the guard has no rule
  on the *beginning* of a name, because it now has a rule on its shape.
- **Vendor sources, all read 2026-11-17:**
  https://learn.microsoft.com/powershell/module/activedirectory/get-adreplicationconnection (`-Properties`,
  "Aliases: Property"),
  https://learn.microsoft.com/powershell/module/activedirectory/get-aduser,
  https://learn.microsoft.com/powershell/module/activedirectory/get-adcomputer,
  https://learn.microsoft.com/powershell/module/activedirectory/get-adtrust,
  https://learn.microsoft.com/powershell/module/activedirectory/get-adreplicationsitelink,
  https://learn.microsoft.com/powershell/module/activedirectory/new-adreplicationsitelink,
  https://learn.microsoft.com/powershell/module/activedirectory/set-adreplicationconnection,
  https://learn.microsoft.com/windows/win32/adschema/a-searchflags,
  https://learn.microsoft.com/troubleshoot/windows-server/windows-security/mark-attribute-as-confidential,
  https://learn.microsoft.com/troubleshoot/windows-server/windows-security/confidential-attributes-unexpected-behavior-using-windows-server-2025-dc,
  https://learn.microsoft.com/windows-server/get-started/whats-new-windows-server-2025,
  https://learn.microsoft.com/windows-server/identity/laps/laps-technical-reference,
  https://learn.microsoft.com/windows/win32/adschema/a-msds-managedpassword,
  https://learn.microsoft.com/windows-server/security/kerberos/passwords-technical-overview,
  https://learn.microsoft.com/windows/win32/adschema/a-dbcspwd,
  https://learn.microsoft.com/windows/win32/adschema/a-mstpm-ownerinformation,
  https://learn.microsoft.com/windows/win32/adschema/a-msfve-recoverypassword,
  https://learn.microsoft.com/windows/win32/adschema/a-trustauthincoming,
  https://learn.microsoft.com/windows/win32/adschema/a-trustauthoutgoing,
  https://learn.microsoft.com/windows/win32/adschema/a-initialauthoutgoing,
  https://learn.microsoft.com/windows/win32/adschema/c-ntdsconnection,
  https://learn.microsoft.com/windows/win32/adschema/a-fromserver,
  https://learn.microsoft.com/windows/win32/adschema/a-options,
  https://learn.microsoft.com/windows/win32/adschema/c-msds-groupmanagedserviceaccount.
  `initialAuthIncoming`, `msFVE-KeyPackage`, `userPassword` and `unixUserPassword` are in the secret set
  by analogy and were not read this session; refusing them is harmless.

### Added - 2026-11-17 (Inventory depth: topology, trusts, suffixes, object counts, stale disabled objects, groups, GPOs, events, w32tm configuration, tool v1.32.0)

**PORT-PLAN C15.** The AdAssessment26 catalogue rows INV-001, INV-006..INV-012 and INV-015, built into the
existing `Forest` (`Topology Inventory`), `Trusts` (`Trust Inventory`), `Identity` (`Object Counts`,
`Group Inventory`), `StaleObjects` (`Stale Objects`), `Gpo` (`GPO Directory Inventory`), `DsEvents`
(`Event Inventory`) and `TimeHierarchy` (`Time Configuration`) sections. No new `-Sections` value. The
catalogue grades none of these rows (Kind Inventory, decision D7): every row is `Info` when it was read
and `Not Assessed` with its cause when it was not, never `Pass`, `Warning` or `Fail`, so none carries a
recommendation and no recommendation entry was added. The reference repository has code for the
topology and trust reads only; the other rules come from its catalogue, PORT-PLAN and SPEC text.

**This has run only against stubs.** No directory object, event log or registry value was read by this
code from a real forest: every answer it was tested on is a stub in the shape the cmdlet or the CIM
method returns. Not verified (PORT-PLAN C15a, with the first real run, C17): the error texts
`Get-WinEvent` raises for "no events" and for a missing log (tool patterns; anything else is `Not
Assessed`); whether ADWS returns more than 1500 `member` values; the property names `Get-ADObject`
returns for the trust, gPLink and WMI filter attributes; the `gPCWQLFilter` format and the `cn` of an
`msWMI-Som` object; the registry type of W32Time `Type` and `NtpServer`; the cost of the count reads on
a large domain; `-ResultSetSize` on `Get-ADObject`; how `Get-WinEvent -ComputerName` answers an
account outside Event Log Readers on a DC, for the filtered read and for the one-event access check
(C15d).

- **One directory seam, one config table.** Every read goes through `Get-AdfaInventoryDirectoryRaw`:
  `Get-ADObject -Server <domain>`, listed properties only (a wildcard is refused before anything is sent),
  `-ResultSetSize MaxObjects+1` so a capped read is `Capped`, a read that throws part-way is not used,
  and a counted property (`member`) keeps only its number of values. The versioned `Inventory` table
  holds the caps, the MS-ADTS names, the filters, the logs and levels, and the W32Time keys; the
  `-ConfigOverridePath` key `Inventory` sets `MaxObjects` (1-1000000), `NameListCap` (0-1000),
  `EventMaxEvents` (1-100000) and `EventGroupCap` (1-1000) only, through `Merge-AdfaSpecConfig`.
  "Seventeen sections can be named."
- **Topology Inventory (INV-001, INV-007).** Forest and domain functional levels from
  `msDS-Behavior-Version` (CN=Partitions and each domain head), named as MS-ADTS names them; 8, 9, a value
  that is not a whole number, or one not returned is `Not Assessed` (MS-ADTS says an absent value is 0,
  but a read that cannot see the attribute looks the same). The five FSMO holders from `fSMORoleOwner`
  on the five role objects, the holder in a column; a value naming a deleted NTDS Settings object
  (`DEL:`) is `Not Assessed`. The UPN suffixes of CN=Partitions, each domain's
  `msDS-AllowedDNSSuffixes`, each DC's DNS suffix against its domain (Disjoint Yes, No or Unknown, never
  graded) with a population row per scoped domain, and the runner DC from the rootDSE `dnsHostName`.
- **Trust Inventory (INV-006).** The `trustedDomain` objects one level under CN=System of every scoped
  domain, read from that domain with six listed attributes. `trustAttributes` by the 13 names of
  MS-ADTS 6.1.6.7.9 (read unsigned; an unnamed bit kept as "unknown 0x.."); direction and type by name
  (0 Disabled, 5 AAD, others "(no published name)"); transitivity as NON_TRANSITIVE set or clear;
  QUARANTINED_DOMAIN, TREAT_AS_EXTERNAL and PIM_TRUST as the SID filtering flags; CROSS_ORGANIZATION by
  its raw name (Learn does not call it selective authentication); TGT delegation from the MS-KILE rule.
  A failed or capped read is `Not Assessed`, never "0 trusts". The trust health rows are unchanged and
  still read `Get-ADTrust -Properties *` (C4b).
- **Object Counts and Group Inventory (INV-008, INV-010).** Thirteen counts per domain from seven capped
  reads that are not the full export: users and computers split enabled/disabled on ACCOUNTDISABLE,
  groups split security/distribution on 0x80000000, contacts, OUs, gMSA, sMSA (computers exclude both
  managed account classes). A failed or capped read, or a split with any unreadable flag, is `Not
  Assessed`. Groups by scope and type, empty groups (names in a column; primaryGroupID members are not
  counted, and the row says so), direct member counts (1500 values or more, the MaxValRange default, is
  "not counted exactly"), and one row per group in `csv\Groups_<domain>.csv`, each with `ListComplete`
  ("No: ..." on every row of a read that reached its cap, which writes at most MaxObjects rows). **Fixed:** a failed user
  or computer export was summarised in `Identity Inventory` as 0 objects with status `Info`; it is now
  `Not Assessed` with the cause. The export itself is unchanged (C4b).
- **Stale disabled objects (INV-009).** `Stale disabled users` and `Stale disabled computers` per domain in
  `Stale Objects`: ACCOUNTDISABLE set, `lastLogonTimestamp` at or before `-StaleDays` or none and created
  before it, from the same listed, capped read as the C14 rows, against the disabled accounts counted
  first as the declared population; the sync interval is stated. `Info`, names in a column only.
- **GPO Directory Inventory (INV-011).** From the directory, without the GroupPolicy module: each GPO's
  status flags (labels from the Gpo table, "unknown" otherwise), WMI filter (the GUID in `gPCWQLFilter`
  matched to an `msWMI-Som` object under CN=System) and links; the `gPLink` entries of the domain head,
  its OUs, every site, and the domain head and OUs of every other scoped domain that link one of the
  domain's GPOs (options 0x1 disabled and 0x2 enforced counted, an entry that cannot be parsed kept,
  `gPOptions` raw); a link is credited to a GPO by its GUID and the domain named in its GPC DN. Linked and
  unlinked GPOs per domain, counting as linking only a SOM with a link that was read. A GPO whose links
  could not be read is never called unlinked, and a GPO is called unlinked only when the SOMs of every
  domain of the forest were read; otherwise it is "no link found" and the summary is `Not Assessed`.
  The GroupPolicy-module rows are unchanged.
- **Event Inventory (INV-012).** On every DC of every scoped domain, the System, Directory Service, DFS
  Replication, DNS Server and File Replication Service logs read with `Get-WinEvent -FilterHashtable`
  (Level 1, 2, 3; StartTime `-EventLookbackDays`) and `-MaxEvents 2000` (a tool default), grouped by
  event ID, worst level first, at most 50 groups per log (a tool default). A missing log is `Info` "log
  absent"; a count at the bound or over a log that does not reach back is a floor, on the log row and on
  every group row; none found over such a log is `Not Assessed`; none found is taken only after a
  one-event `-LogName -MaxEvents 1` read of the log succeeds; a refusal, a DC classified unreachable or
  silent on RPC 135, and any other error are each their own `Not Assessed` cause. No event is graded.
- **Time Configuration (INV-015).** Each DC's W32Time `Type` and `NtpServer` (`W32Time\Parameters`) and
  `AnnounceFlags` (`W32Time\Config`) through the shared CIM transport loop, whose allow-list gains
  `Get-AdfaDcW32TimeRaw`, using the StdRegProv `GetStringValue` and `GetDWORDValue` methods already on the
  CIM allow-list - no new CIM method. Not set, refused, another type and not answered are each named.
  The Group Policy area that overrides these values is not read, and each row says so. Not graded.
- **Read-only guard.** A new AST guard in the tests fails on an event log write or clear
  (`Clear-/Limit-/Remove-/Write-/New-EventLog`, `wevtutil cl/sl/im`), a GroupPolicy write
  (`New-/Set-/Remove-/Copy-/Import-/Restore-/Backup-GP*`, `Rename-GPO`), a `.SaveChanges()` call, an
  StdRegProv method outside the Get ones, and, in the C15 functions, any `Set-/New-/Remove-` command,
  `Invoke-CimMethod`, a w32tm string and a `*` property list; 17 injected cases each make it fail.
- **Tests.** A new Describe (160 tests with the review fixes): normal, empty, unreachable, access denied, timed out, capped and
  mixed data per family, the config override (valid and every malformed shape), the seams, two DCs in
  every per-DC loop, and the wiring read from the parsed script. The smoke harness asserts every new
  section in the single-domain, three-domain, failing-collector and unreadable-forest passes, with stubs
  for `Get-WinEvent`, the inventory directory reads, the disabled-account reads, the rootDSE and the
  W32Time registry values in the shapes the cmdlets return.
- **Pins moved** because behaviour legitimately changed: the version (1.31.0 to 1.32.0) in every
  Describe and the validation harness; the override key order and "Sixteen" to "Seventeen" sections; the
  shared transport loop's allow-list (adds `Get-AdfaDcW32TimeRaw`); the CIM session count (4 to 5: the
  W32Time seam opens and closes one); the `-Properties` argument count (27 to 38) and assignment count
  (22 to 23), each new one a non-secret list; the smoke harness's stale-read counts are unchanged
  because the disabled reads are recorded apart.

Mutations (each a single change to the new code on a scratch copy of the repository, the C15 tests run,
the file restored and checked by SHA-256; every one killed):

| Id | Kind | Mutation | Tests failed | Restored (SHA-256) |
| --- | --- | --- | --- | --- |
| M1 | wrong verdict direction | Disjoint Yes/No swapped in Get-AdfaDnsSuffixRows | 1 | yes |
| M2 | Not Assessed turned into Info | failed trust read population row Info instead of Not Assessed | 4 | yes |
| M3 | unreachable DC read as reachable | W32Time: no transport answered, read attempted anyway | 1 | yes |
| M4 | unreachable DC read as reachable | Events: RPC 135 silent, logs read anyway | 1 | yes |
| M5 | access denied reported as unreachable | W32Time refusal worded Unreachable | 2 | yes |
| M6 | access denied reported as read failed | Event log refusal not told apart | 1 | yes |
| M7 | override validation removed | EventMaxEvents lower bound 1 -> 0 | 1 | yes |
| M8 | override validation removed | Inventory key unregistered from ConfigOverrideSections | 2 | yes |
| M9 | wiring dropped | Event Inventory not put in sectionData | 1 | yes |
| M10 | wiring dropped | Topology inventory given the built-in table, not the override | 1 | yes |
| M11 | threshold off by one | member ceiling -ge -> -gt | 1 | yes |
| M12 | threshold off by one | stale disabled cutoff -le -> -lt | 1 | yes |
| M13 | per-DC loop handles only the first DC | Get-AdfaEventInventory | 2 | yes |
| M14 | per-DC loop handles only the first DC | Get-AdfaW32TimeInventory | 2 | yes |
| M15 | Not Assessed turned into Info | a failed count read reported Info | 2 | yes |
| M16 | Not Assessed turned into a count | a capped read treated as complete | 2 | yes |
| M17 | value dropped | unknown trustAttributes bits dropped | 1 | yes |
| M18 | read-only guard removed | wildcard property list no longer refused in the seam | 1 | yes |
| M19 | bound removed | Get-WinEvent without -MaxEvents | 2 | yes |
| M20 | Not Assessed turned into a value | msDS-Behavior-Version not returned read as level 0 | 1 | yes |
| M21 | Not Assessed turned into a value | GPO links unknown treated as known (unlinked) | 1 | yes |
| M22 | Not Assessed turned into Info | no events over a log that does not reach back reported Info 0 | 1 | yes |
| M23 | wrong verdict direction | TGT delegation: disable conditions ignored | 1 | yes |

**Found by an independent review of the diff before commit, and fixed in it.** Each behaviour fix has a
test that failed against the tree as the review found it (run on a scratch copy: 24 of the C15 tests
red there) and passes now; each test that could not fail was rewritten until the reviewer's mutation
fails it (table below).
1. A `gPLink` options field too large for Int64 (`;99999999999999999999`) or written with a non-ASCII
   digit (U+0663, which .NET's `\d` matches) made `[int64]` throw out of the Gpo section, and nothing
   on the way up caught it: the run ended with no report. The options are now matched as `[0-9]+` and
   parsed with `[int64]::TryParse` (invariant culture); an entry that does not parse is kept as unparsed,
   as other bad entries already were. An entry whose DN names no domain is unparsed too.
2. A GPO linked only from an OU or domain head of another domain was reported `Info` "with no link", in
   a run scoped to one domain and with `-AllDomains` alike. Learn: a GPO "is a per-domain object that can
   be linked anywhere in the forest". Every scoped domain is now read before any is matched, so a link
   from another scoped domain's SOM is credited to the GPO its DN names (by GUID and the domain in the
   GPC DN, since the two default GPOs have the same GUID in every domain), and "unlinked" is stated only
   when the SOMs of every domain in `Get-ADForest`'s `Domains` were read. Otherwise a GPO with none found
   has Links '' and is counted in `NoLinkFound`, the summary is `Not Assessed` and names the cause (out of
   scope, a failed read, or the domain list unknown), and link counts are a floor. Reading the domains
   outside the scope is left out (C15d). The review raised this three times (its findings 2, 5 and 15).
3. A SOM whose `gPLink` held no link that could be read (a blank value) was counted among the "linking"
   SOMs. `Soms` now counts only SOMs with a link read; the others are `SomsWithNoLink`, and their row says
   so.
4. `Get-WinEvent -FilterHashtable` answers an account that may not read a log with `NoMatchingEventsFound`
   (measured by the review under Windows PowerShell 5.1 on a local Security log; not published), so a
   refusal was read as "no events" and the row blamed the log's reach back. A filtered read that finds
   nothing is now followed by one `-LogName <log> -MaxEvents 1` read (a read, bounded): a refusal there is
   `Access denied`, another error is kept and quoted, and only an event or a second "no events" sets
   `NoEvents`. Not measured remotely against a DC (C15d).
5. The `Event group` rows of a read cut at `EventMaxEvents`, or of a log that does not reach back, showed
   Count and First as exact. Each now has `PartialRead` "Yes", Count "at least n", and a Detail that says
   First is the earliest event read.
6. `csv\Groups_<domain>.csv` was written from a capped read (MaxObjects+1 records) with nothing saying
   the list was cut. It now holds at most MaxObjects rows, and every row carries `ListComplete` ("Yes", or
   "No: the read reached its cap ...").
7. Tests that could not fail, now able to: a failed site `gPLink` read with a GPO linked only at a site
   (mutation V); TGT delegation from QUARANTINED_DOMAIN alone, trustAttributes 0x24 (A, MS-KILE 3.3.5.7.5);
   disabled and enabled link counts (S); a site that links only another domain's GPO left out (D); a
   mixed-case DC host name against its domain (I); a W32Time key absent, StdRegProv 2, as "(not set)" (R);
   a refusal wrapped as an InnerException (M).

Tests changed because behaviour legitimately changed: the INV-011 "normal data" test passes
`-ForestDomains` (a one-domain forest), since without the forest's domain list no GPO is called
unlinked; the event seam test's `Get-WinEvent` stub takes `-LogName` and answers the one-event access
check, since "no events" now needs it; the AST test "bounds every event read" now finds two
`Get-WinEvent` calls and checks that each is splatted from a hashtable holding `MaxEvents`; the smoke
harness's event read count leaves out the access checks and asserts them apart, and its directory stub
gives each domain its own DNs.

Review mutations (single changes to the fixed code on a scratch copy, the C15 tests run, the file
restored byte for byte and its SHA-256 checked):

| Id | Finding | Mutation | Tests failed | Restored (SHA-256) |
| --- | --- | --- | --- | --- |
| V | 8 | `$linksKnown` ignores the site read | 1 | yes |
| A | 9 | QUARANTINED_DOMAIN dropped from the TGT delegation disable list | 1 | yes |
| S | 10 | every link counted as enabled | 1 | yes |
| D | 11 | a site that links none of the domain's GPOs no longer left out | 1 | yes |
| I | 12 | DNS suffix compared with `-ceq` | 1 | yes |
| R | 13 | W32Time KeyAbsent written "(empty)" | 1 | yes |
| M | 14 | the InnerException walk stops after the outer exception | 1 | yes |
| X1 | 1 | options cast with `[int64]` instead of TryParse | 1 | yes |
| X1b | 1 | options matched with `\d` instead of `[0-9]` | 0 - equivalent: TryParse with `NumberStyles.None` refuses U+0663 too; `[0-9]` kept as the first guard | yes |
| X2 | 2 | other forest domains treated as read | 3 | yes |
| X3 | 3 | every SOM counted as linking | 1 | yes |
| X4 | 4 | a refused access check not marked AccessDenied | 2 | yes |
| X5 | 6 | group rows never marked partial | 2 | yes |
| X6 | 7 | a capped group read not marked or trimmed | 1 | yes |
| X7 | 2 | a link credited by GUID alone | 2 | yes |
| X8 | 2 | the collector passes no other domain's SOM read | 1 | yes |
| X9 | 2 | the GPOs' domain not taken from their own DNs | 1 | yes |

The smoke harness's three-domain pass also caught that the domain DN must come from the GPOs' own DNs:
its `Get-ADDomain` stub answers `DC=contoso,DC=com` for every domain, so matching on that DN credited
contoso's links to north's GPOs. The domain a GPO lives in is now taken from its `groupPolicyContainer`
DN when every container names the same one (else `Get-ADDomain`'s DN, else the DNS name).

Sources, each read on Learn on 2026-11-17:
- MS-ADTS msDS-Behavior-Version, forest and domain:
  https://learn.microsoft.com/openspecs/windows_protocols/ms-adts/564dc969-6db3-49b3-891a-f2f8d0a68a7f and
  https://learn.microsoft.com/openspecs/windows_protocols/ms-adts/d7422d35-448a-451a-8846-6a7def0044df
- FSMO role objects and invalid `fSMORoleOwner`:
  https://learn.microsoft.com/troubleshoot/windows-server/active-directory/fsmo-transfer-seizure-process and
  https://learn.microsoft.com/troubleshoot/windows-server/active-directory/error-seize-rid-master-role-with-ntdsutil
- trustAttributes, trustType, trustDirection, TGT delegation:
  https://learn.microsoft.com/openspecs/windows_protocols/ms-adts/e9a2d23c-c31e-4a6f-88a0-6646fdb51a3c,
  https://learn.microsoft.com/openspecs/windows_protocols/ms-adts/36565693-b5e4-4f37-b0a8-c1b12138e18e,
  https://learn.microsoft.com/openspecs/windows_protocols/ms-lsad/f28f42b7-173c-4cda-9809-3fe4a5213ab3,
  https://learn.microsoft.com/openspecs/windows_protocols/ms-kile/bac4dc69-352d-416c-a9f4-730b81ababb3;
  Get-ADTrust (lists no output property names):
  https://learn.microsoft.com/powershell/module/activedirectory/get-adtrust?view=windowsserver2025-ps
- Suffixes and disjoint namespace: https://learn.microsoft.com/windows/win32/adschema/a-upnsuffixes,
  https://learn.microsoft.com/windows/win32/adschema/a-msds-alloweddnssuffixes,
  https://learn.microsoft.com/windows-server/identity/ad-ds/plan/disjoint-namespace,
  https://learn.microsoft.com/troubleshoot/windows-server/active-directory/event-ids-5788-5789
- Counts and groups:
  https://learn.microsoft.com/troubleshoot/windows-server/active-directory/useraccountcontrol-manipulate-account-properties,
  https://learn.microsoft.com/windows/win32/adschema/a-grouptype,
  https://learn.microsoft.com/troubleshoot/windows-server/active-directory/view-set-ldap-policy-using-ntdsutil
- Stale: https://learn.microsoft.com/windows/win32/adschema/a-lastlogontimestamp and
  https://learn.microsoft.com/windows/win32/adschema/a-msds-logontimesyncinterval (no default published)
- GPOs: https://learn.microsoft.com/windows-server/identity/ad-ds/manage/group-policy/group-policy-scope,
  https://learn.microsoft.com/windows-server/identity/ad-ds/manage/group-policy/group-policy-management-console
  ("A GPO is a per-domain object that can be linked anywhere in the forest"; added by the review fix),
  https://learn.microsoft.com/windows/win32/adschema/a-gpcwqlfilter,
  https://learn.microsoft.com/windows/win32/adschema/c-mswmi-som
- Events: https://learn.microsoft.com/powershell/module/microsoft.powershell.diagnostics/get-winevent?view=powershell-5.1,
  https://learn.microsoft.com/powershell/scripting/samples/creating-get-winevent-queries-with-filterhashtable,
  https://learn.microsoft.com/troubleshoot/windows-server/application-management/move-event-viewer-log-files
- W32Time: https://learn.microsoft.com/windows-server/networking/windows-time-service/windows-time-service-tools-and-settings and
  https://learn.microsoft.com/troubleshoot/windows-server/active-directory/configure-authoritative-time-server

### Added — 2026-11-17 (Reachability classes, subnets and clients without a site, clock offset against the forest root PDC, stale enabled objects, SYSVOL replication engine, tool v1.31.0)

**PORT-PLAN C14.** The AdAssessment26 catalogue rows REACH-001..002, SITE-001, TIME-001,
STALE-001..002 and SYSVOL-004, built into the existing `PortMatrix` (`Port Reachability`), `Topology`
(`Site Health`), `TimeHierarchy`, `StaleObjects` and `Sysvol` (`SYSVOL / DFSR`) sections. No new
`-Sections` value. The reference repository has code for the reachability probe only; the other rules
come from its catalogue, PORT-PLAN and SPEC text. The `NO_CLIENT_SITE` read and the old-password row are
additions of the C14 brief beyond the catalogue.

**This has run only against stubs.** No name was resolved, no port probed, no `netlogon.log` read, no
`w32tm` run and no directory object read by this code against a real forest: every answer it was tested
on is a stub in the shape the cmdlet, the .NET method or the documented output has. Not verified (PORT-PLAN
C14a, with the first real run, C17): the text and time stamp of a real `NO_CLIENT_SITE:` line, whether it is
written without debug logging and how long it stays; the rights a read over `ADMIN$` needs; the exception
`Get-ADObject` throws for an object that does not exist; that `Get-ADReplicationSubnet` carries the site in
`Site`; a real `/rdtsc` CSV; `-ResultSetSize` on a large domain; `msDFSR-Flags` in a domain born at Windows
Server 2008 level; the SocketError a real host gives for a filtered, a refused and an unrouted DC.

**What it reads, and nothing else.** `Dns.BeginGetHostAddresses` (bounded) and one TCP connect per port
that sends nothing and is closed at once (LDAP 389 per address, then WinRM 5985 and RPC 135 at the address
that answered); a read-only open (FileShare ReadWrite/Delete) of the last 4 MB of
`\\<dc>\ADMIN$\debug\netlogon.log` after an SMB 445 probe through the shared cache; `w32tm /stripchart
/computer:<dc> /dataonly /samples:<n> /rdtsc` (the same call the section already made, now through one
helper, plus one for the forest root PDC when it is not among the DCs asked); `Get-ADUser` /
`Get-ADComputer -LDAPFilter` with `-Server <domain>`, a listed property set (never every property; the
population count asks for no property and takes the default set) and `-ResultSetSize`; `Get-ADDomain` and `Get-ADObject -Identity <DN> -Server <domain>` for
`msDS-LogonTimeSyncInterval`, `CN=DFSR-GlobalSettings,CN=System` (`msDFSR-Flags`) and each DC's
`CN=SYSVOL Subscription` and NTFRS subscriber; `Get-ADDomainController -Filter * -Server <domain>`. No
`dfsrmig /setglobalstate`, no `w32tm /resync`, `/config`, `/register`, `/unregister` or `/debug`, no `Set-AD*`,
`Disable-ADAccount` or `Remove-*`, no registry write. A test parses the script and fails on any of those
outside the recommendation map and the finding rows (whose advice names commands for the operator); a
switch assembled at run time is not seen by it.

| Section | Rows |
| --- | --- |
| Port Reachability (`-Sections PortMatrix`) | `DC reachability: <dc>` per DC of every scoped domain (REACH-001/002), `DC reachability (population): <domain>` per domain (Info, or `Not Assessed` for a domain with no DC row); the port matrix rows follow, unchanged |
| Site Health (`-Sections Topology`) | `Subnets without a site: <forest>` (SITE-001), outside the DC inventory gate; `Clients without a site: <dc>` per DC, with the clients in the `Clients` column; `Clients without a site (population): <domain>` for a domain with no DC row |
| Time Hierarchy | `Clock offset vs forest root PDC: <dc>` per DC (TIME-001), with `OffsetSeconds`, `ErrorBoundSeconds` and `Reference` columns; the `Clock offset on <dc>` rows are kept |
| Stale Objects | `Inactive enabled users` and `Inactive enabled computers` (STALE-001/002; Items kept), with `Accounts`, `NeverLoggedOn`, `Population` and `SyncIntervalDays` columns; new `Enabled users with an old password` (with `MustChangeAtNextLogon`, `AgeNotKnown` and `Population`) |
| SYSVOL / DFSR | `SYSVOL engine: <dc>` (Info) per DC and `SYSVOL replication engine: <domain>` per scoped domain (SYSVOL-004) |

**The grades.** Unreachable `Fail`, not remotely manageable on the default ports `Warning`, reachable
`Pass`; a subnet with no site `Warning`; clients without a site `Warning`, none found `Info`; offset against
the forest root PDC at 300 s `Fail` (Microsoft) and at 60 s `Warning` (tool default); stale accounts and old
passwords `Warning`; a writable DC on FRS or migrating `Warning`. Every grade that is a tool default says so
in its row, and five config tables can be overridden from `-ConfigOverridePath` (`Reach`, `SiteCoverage`,
`ClockSkew` - `WarnSeconds` and `Samples` only -, `Stale`, `SysvolEngine`) through one validator that refuses
every key a table does not declare. Unreachable, access denied, timed out, not found, not configured and a
tool that is missing are each their own `Not Assessed` cause; a stale count that is not complete is
`Not Assessed`, never zero.

**Changed.** The time hierarchy now probes RPC through the shared port cache instead of `Test-TcpPort`.
The `Inactive enabled users/computers` rows used a `-Filter` that dropped every account that never logged
on and stated no logon-sync caveat; they now count those accounts and state it. Site Health is produced
whenever `Topology` runs, not only when the DC inventory was collected. Seven section-scoped
recommendation entries anchored on the new Items precede the unscoped entries; the existing
`Clock offset on <dc>` rows, whose detail mentions replication metadata and so drew the unscoped AD
replication advice, now get the time advice. Existing tests changed because behaviour legitimately
changed: the version assertions (1.30.0 to 1.31.0), the `$script:ConfigOverrideSections` population
assertions (five new keys) and the "Eleven sections can be named" help assertions (now sixteen).

**Sources, read on Microsoft Learn on 2026-11-17:**

- https://learn.microsoft.com/dotnet/api/system.net.sockets.socketerror (SocketError names and codes)
- https://learn.microsoft.com/troubleshoot/windows-server/active-directory/config-firewall-for-ad-domains-and-trusts (DC ports)
- https://learn.microsoft.com/windows/win32/winrm/installation-and-configuration-for-windows-remote-management (WinRM 5985; listeners on any port)
- https://learn.microsoft.com/windows-server/identity/ad-ds/deploy/ad-ds-metadata-cleanup (metadata cleanup, advice)
- https://learn.microsoft.com/windows/win32/adschema/a-siteobject and https://learn.microsoft.com/windows/win32/ad/directory-service-functions (siteObject; a client's site)
- https://learn.microsoft.com/troubleshoot/windows-server/active-directory/dc-delayed-response-to-ldap-kerberos-request (Netlogon event 5807, `NO_CLIENT_SITE:`, netlogon.log, LogFileMaxSize)
- https://learn.microsoft.com/troubleshoot/windows-client/windows-security/enable-debug-logging-netlogon-service (netlogon.log path)
- https://learn.microsoft.com/troubleshoot/windows-server/windows-security/kerberos-protocol-registry-kdc-configuration-keys (SkewTime default 5 minutes)
- https://learn.microsoft.com/troubleshoot/windows-server/active-directory/replications-fail-with-error-5 (relative skew between KDC and target)
- https://learn.microsoft.com/troubleshoot/windows-server/active-directory/configure-w32ime-against-huge-time-offset (forest root PDC as the authoritative time server)
- https://learn.microsoft.com/windows-server/networking/windows-time-service/windows-time-service-tools-and-settings (`/stripchart`, `/samples`, `/rdtsc`; the writing verbs)
- https://learn.microsoft.com/windows/win32/adschema/a-lastlogontimestamp, https://learn.microsoft.com/windows/win32/adschema/a-msds-logontimesyncinterval, https://learn.microsoft.com/troubleshoot/mem/configmgr/discovery/lastlogontimestamp-not-accurate and https://learn.microsoft.com/archive/blogs/askds/the-lastlogontimestamp-attribute-what-it-was-designed-for-and-how-it-works (update rule, 9 to 14 days, default 14, 0 disables)
- https://learn.microsoft.com/windows/win32/adschema/a-pwdlastset (pwdLastSet 0)
- https://learn.microsoft.com/powershell/module/activedirectory/get-aduser (`-LDAPFilter`, `-ResultSetSize`)
- https://learn.microsoft.com/defender-for-identity/security-posture-assessments/accounts (90 days, Defender's own rule, cited as adjacent only)
- https://learn.microsoft.com/troubleshoot/windows-server/networking/sysvol-dfsr-migration-fails-after-in-place-upgrade (Windows Server 2019 promotion requires DFSR)
- https://learn.microsoft.com/troubleshoot/windows-server/networking/troubleshoot-missing-sysvol-and-netlogon-shares (the NTFRS subscriber DN)
- https://learn.microsoft.com/windows/win32/adschema/a-msdfsr-flags (msDFSR-Flags schema; values from https://learn.microsoft.com/previous-versions/windows/it-pro/windows-server-2008-r2-and-2008/dd639789(v=ws.10), provisional: that page was read by the research brief, not re-read for this entry)
- https://learn.microsoft.com/windows-server/administration/windows-commands/dfsrmig and https://learn.microsoft.com/windows-server/storage/dfs-replication/migrate-sysvol-to-dfsr (advice)

**Not published by Microsoft, and so tool defaults or tool reasoning, labelled in the rows:** the
reachability classes and the 3000 ms time-out; "an empty siteObject means no site"; the 60 s warning
level; the PDC difference method and its error bound; the 90-day stale age (`-StaleDays`), the 365-day
password age, the 100000-object cap; the FRS grade.

**Found by an independent review of the diff before commit, and fixed in it.** (1) The `DC reachability`
row of an unreachable DC said every check of the run that needs it is `Not Assessed`, while the port matrix
rows of the same section re-resolve the DC and grade it `Fail`: the Detail now names the sections that reuse
the class (Time Hierarchy, Site Health) and says the port matrix and the other per-DC sections probe on
their own (moving them onto the class stays C14c). (2) An empty stale or old-password read was `Pass` with
no declared population, so a read that saw nothing read as "none stale": each domain's enabled users and
computers are now counted first (`Get-AdfaStalePopulationRaw`, the same filter without its time term, the
default property set, capped), shown in a `Population` column, and an empty result passes only when that
count is at least one; uncounted, refused or empty is `Not Assessed`. (3) `pwdLastSet` 0 was always read as
"must change at next logon"; Learn says so only where `UF_DONT_EXPIRE_PASSWD` (0x10000, KB 305144) is clear.
The record now keeps `userAccountControl`; with the flag set the password's age is not known
(`AgeNotKnown`/`AgeNotKnownAccounts` columns, and the row cannot pass), and with it unread the row is
`Not Assessed`. (4) Time Hierarchy probed a DC already classified Unreachable and reported a name that does
not resolve as "RPC (135) was not reachable"; it now reuses the class for the `Time source` and
`Clock offset on` rows too. (8) The lag of `lastLogonTimestamp` was stated as the interval "plus up to 5"
days and the guard made `-StaleDays` 15 to 19 `Not Assessed`; KB 2679653 says "9 to 14 days" under the
default, so the random part shortens the wait: the lag is at most the interval, and the guard is now
`-StaleDays` not longer than the interval (help, README, advice and row text corrected). (9) The SYSVOL
advice said "The migration is one-way"; dfsrmig on Learn says only Eliminated is irreversible and shows
`dfsrmig /setglobalstate 0` to roll back, which the advice now says. Tests that could not fail were
rewritten or added so the reviewer's mutations now fail them: an unclassifiable stale record (5), a
password record with no `pwdLastSet` (6), the password read's property list (7), an unreadable read-only
flag counted as writable (10), LDAP probed address by address until one answers (11), a silent WinRM seeded
closed (12), exactly `MaxObjects` records not capped and a password set exactly at the cutoff counted (13),
and the stated error bound (14). Existing tests changed for it: the threshold-inside-the-sync-window case
now uses `-StaleDays` 14, not 19 (Pester and Run-Validation), because 19 is now graded; the stale and
password Pass cases now pass a declared population, and the password records carry `userAccountControl`;
the C14 function population is 29, not 27. Still run against stubs only; the population count against a
real domain of more than 1000 accounts (paging) is part of C14a.

Added source, read on Microsoft Learn on 2026-11-17:
https://learn.microsoft.com/troubleshoot/windows-server/active-directory/useraccountcontrol-manipulate-account-properties
(KB 305144: DONT_EXPIRE_PASSWORD is 0x10000). Re-read on 2026-11-17 for the corrections:
https://learn.microsoft.com/troubleshoot/mem/configmgr/discovery/lastlogontimestamp-not-accurate ("9 to 14
days"), https://learn.microsoft.com/windows/win32/adschema/a-pwdlastset (the UF_DONT_EXPIRE_PASSWD
condition) and https://learn.microsoft.com/windows-server/administration/windows-commands/dfsrmig
("Migration to the Eliminated state is irreversible"; `/setglobalstate 0` rolls back to Start).

### Added — 2026-11-17 (DNS: zone dynamic update, aging and scavenging, DC locator SRV and A records, records naming no DC, zone inventory, DC DNS client, opt-in record export, tool v1.30.0)

**PORT-PLAN C13.** The AdAssessment26 catalogue rows ADA-DNS-001 to -005, ADA-INV-013, -014 and -016,
built into the existing `Dns` (`DNS Health`), `DnsAdConsistency` (`DNS vs AD Consistency`) and
`DomainControllers` sections, plus one new opt-in `-Sections` value, `DnsRecordExport`. The reference
repository has no code for any of these rows; the rules come from its catalogue, PORT-PLAN and SPEC
text. The differences from the catalogue rules are listed below.

**This has run only against stubs.** No DnsServer cmdlet, no `Resolve-DnsName` query and no
`Win32_NetworkAdapterConfiguration` read has been made by it against a real DNS server or domain
controller: every answer it was tested on is a stub in the shape the config table names, and Learn
does not publish the output property names of `Get-DnsServerZone`, `Get-DnsServerScavenging` or
`Get-DnsServerZoneAging`. The first run against a real forest is PORT-PLAN C17, owned by the operator,
and PORT-PLAN C13a lists what that run must confirm for this row.

**What it reads, and nothing else.** `Get-DnsServerZone`, `Get-DnsServerScavenging`,
`Get-DnsServerZoneAging` (primary zones only), `Get-DnsServerForwarder` and
`Get-DnsServerResourceRecord`, with `-ComputerName`, from the DnsServer module of the host running the
assessment, after an RPC (135) probe through the shared port cache; `Resolve-DnsName -DnsOnly -Server`
(nslookup where the DnsClient module is absent) as the second instrument; and
`Win32_NetworkAdapterConfiguration` where `IPEnabled = TRUE`, five properties, through the shared CIM
transport loop (WinRM, then DCOM; `Get-AdfaDcNetworkRaw` added to its allow-list). No `Set-`, `Add-`,
`Remove-`, `Start-` or `Clear-DnsServer*` cmdlet, no CIM method (the adapter class's
`SetDNSServerSearchOrder` and the like are never called), no `ipconfig`, no `nltest /dsregdns`, no
`dnscmd`. A test parses the script and fails on a DnsServer or DnsClient cmdlet that writes, on
`dnscmd` or `ipconfig` named as a command or as a string argument of any command (the script starts
console tools through `Invoke-ExternalCommand -FilePath '<tool>.exe'`), and on a registration or
cache switch (`/registerdns`, `/dsregdns`, `/dsderegdns`, `/flushdns`, `/release`, `/renew`) in any
string literal outside the recommendation map; a switch assembled at run time from pieces is not
seen by it.

| Section | Rows |
| --- | --- |
| DNS Health (`-Sections Dns`) | `DNS server: <dc>` per DC (Info when read, otherwise `Not Assessed` with the cause); `Zone configuration: <zone> on <dc>` per zone not auto-created (Info: type, replication scope, AD-integrated, dynamic update, aging - ADA-INV-013); per domain and primary zone over every DNS server of the domain, `Zone dynamic update: <zone>` (ADA-DNS-001) and `Zone scavenging: <zone>` (ADA-DNS-002); `DNS zones (population): <domain>`; a `DNS server - <domain>` row for a scoped domain with no DC row. The `<dc>: forwarders` and `<dc>: zone transfer` rows are kept as they were |
| DNS vs AD Consistency | after the per-server SRV rows, which are unchanged: `DC locator records: <dc>` (ADA-DNS-003), `DC A record: <dc>` (ADA-DNS-004), one `Stale DC record: <target or CNAME>` per record that names no DC and `Stale DC records (population): <domain>` (ADA-DNS-005) |
| DC DNS Client (`-Sections DomainControllers`, its own report section) | `DNS client: <dc>` per DC, with its DNS server list and IPv4 addresses in their own columns; `DNS client (population): <domain>`; `DNS client - <domain>` for a scoped domain with no DC row (ADA-INV-016) |
| DNS Record Export (`-Sections DnsRecordExport`, opt-in) | one `csv\DnsRecords_<server>_<zone>.csv` per zone that holds a record; `Record export: <zone> on <server>` ("Exported N of M record(s); cap C per zone; cap reached: yes/no"), `Record export (population): <server>` and `Record export: total` (ADA-INV-014) |

**The grades.** Each is a status in the new versioned `Dns` config table. Each graded row ends with
"Graded <status>: <source>": the built-in source says tool defaults, not Microsoft values; a status
set by `-ConfigOverridePath` names the file and the keys it supplied.

- Zone dynamic update: `NonsecureAndSecure` on an AD-integrated zone on any hosting server is a `Fail`
  (`NonsecureStatus`; Learn: "Secure only is recommended for AD-integrated zones"); that measured
  finding stands when another server was not read. Every hosting server read and none nonsecure:
  `Pass`. A zone that is not AD-integrated: `Info` (Learn: secure update exists only for
  AD-integrated zones). A server not read, `IsDsIntegrated` not returned, or a value outside None,
  Secure, NonsecureAndSecure: `Not Assessed`.
- Zone scavenging: zone aging off on a read server is a `Warning` (`AgingOffStatus`; Learn:
  scavenging "skips any zone that has aging disabled"); every hosting server read and none with
  scavenging enabled (`ScavengingInterval` above zero, Learn: "0, which disables scavenging") is a
  `Warning` (`ScavengingOffStatus`), only when the hosting set is complete: a `Domain`-scope zone over
  the DNS servers of its domain; a `Forest` or `Custom` zone is graded once over every DNS server of
  the run, and that `Warning` needs a run that covered every domain of the forest; any other scope
  (`Legacy`, none, not returned) never gets it. A server or a value not read: `Not Assessed`.
- DC locator records: each graded record (`_ldap._tcp.dc._msdcs.<domain>`,
  `_kerberos._tcp.dc._msdcs.<domain>`; reference decision 61) on each DNS server, by two
  instruments. `Fail` only when both instruments agree the record does not name the DC; `Warning`
  (`OneInstrumentStatus`, `Not Assessed` by override) when one could say so and the other could not
  be read; `Not Assessed` when neither could; `Info` for a read-only DC (Learn: RODCs register
  site-specific records by default).
- DC A record: an A record for an address the DC's adapters do not hold, or none by both instruments,
  is a `Warning` (`ARecordStatus`); none by one instrument is `OneInstrumentStatus`; adapters not
  read, or a record whose address could not be read, is `Not Assessed`. IPv4 only.
- The server instrument reads only the zone that holds the name: a server that holds no zone for it,
  only a stub or forwarder zone, or a parent zone in which the name sits below a delegation (an NS
  record below the apex), or whose NS records could not be read, is an unread instrument, never an
  absence. Only Win32 9701 or 9714 ("DNS record does not exist.", "DNS name does not exist."), in
  the message or the error id, is read as no such record; anything else is a failed read.
- Stale DC record: an SRV target that matches no DC of the domain or of the NTDS Settings objects
  (RODCs included, so their records are never stale), or, in the forest root, a `<guid>._msdcs` CNAME
  whose GUID is no NTDS Settings object, is a `Warning` (`StaleRecordStatus`; Learn: "Remove
  references to stale domain controllers").
- DNS client: a list returned empty, or a single DNS server while more than one DC is known to the
  run, is a `Warning` (`SingleServerStatus`; KB 4013: a single DNS server, loopback included, is a
  single point of failure, tolerable only in a single-DC forest). A single server with one DC known
  is `Info` only when the run covered every domain of the forest with no inventory failure, otherwise
  `Not Assessed`. A list no adapter returned, and a read that listed no adapter, are `Not Assessed`. Itself or loopback first, no other DC in the
  list, and an address that is no known DC are `Info` notes: Learn allows a DC to use itself as
  preferred server and publishes no "loopback not first" rule, and an address alone cannot show an
  ISP resolver.

**Not Assessed, each with its own cause, never Pass.** No DC enumerated (the enumeration error
quoted); a DC with no host name; the DnsServer module not installed on the host running the
assessment; unreachable on RPC (DnsServer reads) or on WinRM and RPC (adapter read); access denied
(CIM error code first, then the text); the DNS provider missing (`InvalidNamespace`, `InvalidClass`);
timed out; any other failure, quoted; a property not returned; a value not recognised; one instrument
only; no query tool on the host; a server whose zone does not hold the name (no zone, a stub or
forwarder zone, a delegation, NS records not read); an adapter read that listed no adapter; a DNS
server list no adapter returned; a single DNS server on the only DC of a run that did not cover the
forest; a forest-wide zone no server of such a run scavenges; in the forest root, DSA GUIDs not read or an NTDS Settings search that
returned no object (no `<guid>._msdcs` CNAME is then judged, so none is called stale).

**Changed.** DNS Health's `<dc>: zones` and `<dc>: scavenging` rows are replaced by the zone rows:
the old scavenging row passed a zone whose aging property was not returned, and it never read server
scavenging. DNS Health now covers the DCs of every scoped domain, each row carrying its domain, from
the DC inventory or its own enumeration, as DcDisk does (it used to take the unscoped host list).
DNS Depth's `Secure dynamic updates` row, which read the domain zone on the first DC only and warned
on anything but `Secure`, is retired: it is now one `Info` row saying the check moved to DNS Health,
so a zone is never graded twice by two rules. Existing tests pinned on the version (1.29.0), the
config override section list (ten sections), the transport loop's allow-list and the number of CIM
sessions and instance reads in the script were updated for the new values; no assertion was removed.

**Config.** A new `Dns` table with its sources and read date, and a `Dns` key for
`-ConfigOverridePath` (`Merge-AdfaDnsConfig`): `NonsecureStatus` (Fail or Warning),
`ScavengingOffStatus`, `AgingOffStatus`, `ARecordStatus`, `StaleRecordStatus`, `SingleServerStatus`
(Warning or Info), `OneInstrumentStatus` (Warning or Not Assessed) and `RecordExportCap` (1 to
1000000, default 50000 - the reference's `-DnsRecordCap`). The record names, zone types, patterns,
error codes and ports are refused, so a file can never make a status Pass or turn a failed read into
an absence.

**Recommendations.** Section-scoped entries anchored on the Item prefixes this tool writes, ahead of
the unscoped entries: zone dynamic update (Secure only), zone scavenging (aging and one scavenging
server per zone), DC locator records (Netlogon.dns, DnsAvoidRegisterRecords), DC A record, stale DC
record, DNS client (single point of failure, no ISP DNS); catch-alls give the inventory and population
rows no advice. The forwarder, zone transfer and per-server SRV rows keep the unscoped advice they had.

**Where this differs from the catalogue rules.**

- ADA-DNS-002 keeps zone aging as evidence only; here a measured "aging off" is its own `Warning`,
  because Learn says scavenging skips such a zone (C13b).
- ADA-DNS-003 has no two-instrument rule and grades a missing record `Fail`; here `Fail` needs both
  instruments, one instrument is a `Warning` (C13b).
- ADA-DNS-003's DsaCname part is not graded again: the existing DsaCname section grades it per DNS
  server. Its orphans (ADA-DNS-005) are graded here.
- ADA-INV-014 is JSON-only in the reference SPEC; here it is CSV, as the C13 brief asked (C13b).
- ADA-INV-016 is inventory only; here a single DNS server is graded, from KB 4013 (C13b).
- The catalogue's PROPOSED severity is not carried: the finding shape has no severity column.

**Guards shown able to fail.** 21 single mutations of the new code, each applied to a scratch copy of
the repository, the C13 tests run, and the file restored byte for byte and checked by SHA-256; every
one was killed: the nonsecure test inverted; a Not Assessed turned into Pass (dynamic update, stale
population) or into Warning (scavenging with a server unread); an unreachable DC read as reachable;
access denied reported as a plain failure (DNS read, adapter read); the status and cap validation
removed; the override, the DC DNS Client branch and the opt-in gate unwired; three thresholds off by
one (scavenging interval, export cap, single-server DC count); the per-DC loops cut to the first DC
(DNS Health, DC DNS Client, locator and A records); the two-instrument rule made one; RODCs dropped
from the known DCs; an empty NTDS Settings answer judged.

**Found by an independent review of the diff before commit, and fixed in it.** Each behaviour fix has a
test that fails without it; each was shown by reverting the fix on a scratch copy of the repository,
running the C13 tests and restoring the file byte for byte (SHA-256 checked) - 17 mutations, all
killed.

- The server instrument chose the longest zone suffix and ignored delegations, so a root DNS server
  asked about a child domain read the parent zone, got "no such name" and reported a measured
  absence (a Warning with a resolver time-out, a Fail with a resolver NXDOMAIN). It now reads a name
  only from a Primary or Secondary zone that holds it with no delegation (an NS record below the
  apex, read once per zone and server) above it; a parent zone, a stub or forwarder zone, no zone, a
  zone type not returned, or NS records that could not be read make that instrument unread. The
  forest-root CNAME scan uses the same rule.
- `NoRecordPattern` read bare "was not found" and "does not exist", so "The network path was not
  found." (Win32 53) and "The specified domain either does not exist ..." (1355) were measured
  absences, and a CIM `NotFound` code was too. Only Win32 9701 or 9714, by number in the message or
  the error id or by their exact text, is now "no such record".
- A read that listed no IP-enabled adapter was graded "No DNS server is configured" (Warning); it is
  now `Not Assessed` ("Read returned no adapter"), and the DC A record row agrees. A DNS server list
  that no adapter returned stays `$null` (the call site no longer wraps it in `@()`), so it is
  `Not Assessed` ("Not returned"), not an empty list.
- With no DC known, every SRV target was listed as a stale DC record before the "no DC known" guard
  ran; the guard now runs first. An empty DSA GUID list with a CNAME to judge is read as not known.
- An A record whose address could not be read passed with nothing compared; it is `Not Assessed`.
- A forest-wide zone was graded per domain, so a child DC that does not scavenge got "no hosting
  server scavenges" although the root DC scavenges it. `Forest` and `Custom` zones are graded once
  over every DNS server of the run, and that Warning needs a run that covered every domain of the
  forest (`-ForestComplete` from `Invoke-Main`); any other non-`Domain` scope never gets it.
- Every grade said "tool default" even when an override file set it. Every graded row now ends
  "Graded <status>: <ThresholdSource>", which names the file for the keys it supplied; those rows are
  all matched by Item-anchored section entries, so a path cannot choose advice (tested with a path
  that says backup, stale and replication).
- A single DNS server on the only DC known was `Info` ("tolerable in a forest with one DC") from the
  run's DC count; it is `Info` only when the run covered every domain of the forest with no inventory
  failure, otherwise `Not Assessed`.
- The read-only guard missed `Invoke-ExternalCommand -FilePath 'nltest.exe' -Arguments '/dsregdns'`,
  the way the script starts console tools; it now checks the string arguments of every command and
  every string literal outside the recommendation map, and a test injects the reviewer's three calls
  (and a switch held in a variable, the call operator, a DnsServer write cmdlet) to show it fails.
- Tests that could not fail now can: an A record absent on one instrument; a server with no zone, a
  stub zone, a forwarder zone, a zone type not returned or an NS read failure; aging off with another
  server unread; a failed zone read in the export's population row; the zone inventory columns.
- Text: the README no longer says Microsoft says not to use `ipconfig /registerdns` (the dynamic
  update page says so for DHCP clients; the DC DNS client page tells you to run it after a change),
  and PublishAddresses is credited to the dynamic registration page, not the DNS client page.

Existing tests changed because the behaviour changed, none removed: the error-class test now
expects `Error` for a CIM `NotFound` code (it expected `NotFound`); the single-DC `Info` case now
passes `-DcCountIsForest $true` (and a new case asserts `Not Assessed` without it), in Pester and
Run-Validation; the DNS vs AD collector mocks now return zone types and answer the NS read, the shape
the seams now read; the smoke stubs give each zone its apex NS record and the `_msdcs` zone `Forest`
scope, so the export counts are 6 of 6 and 8 records (were 5 and 7). Not built from the review:
PORT-PLAN C13d.

**Not verified.** The output property names of `Get-DnsServerZone` (`ZoneType`, `IsDsIntegrated`,
`IsAutoCreated`, `DynamicUpdate`, `ReplicationScope`, `SecureSecondaries`), `Get-DnsServerScavenging`
(`ScavengingInterval`) and `Get-DnsServerZoneAging` (`AgingEnabled`, `NoRefreshInterval`,
`RefreshInterval`, `ScavengeServers`); the property names inside `RecordData` (`DomainName`,
`IPv4Address`, `HostNameAlias` - Add-DnsServerResourceRecord parameter names); the error a missing
record raises (read as Win32 9701 or 9714 only, by number in the message or the error id, or by
their exact text); that `Get-DnsServerResourceRecord -ZoneName <zone> -RRType Ns` with no `-Name`
returns the delegation NS records below the apex as well as the apex ones; the transport
`-ComputerName` uses and whether RPC 135 is the right probe; the rights a read needs (Learn documents
DnsAdmins or local Administrators for configuring only); that a DC which is not a DNS server answers
with an error the tool reports, which keeps every zone of its domain `Not Assessed`; how
`DNSServerSearchOrder` lists IPv6 servers; whether `Resolve-DnsName` fills the local cache; that the
DnsServer cmdlets have no time bound of their own (C13a).

**Vendor sources, all read 2026-11-17.**

- Troubleshooting DNS dynamic update (Secure only recommended; the three options):
  https://learn.microsoft.com/troubleshoot/windows-client/networking/troubleshooting-dns-dynamic-update-issues
- Dynamic update (AD-integrated default; any computer can modify an A record without secure update;
  for DHCP clients, ipconfig /renew rather than /registerdns):
  https://learn.microsoft.com/windows-server/networking/dns/dynamic-update
- Set-DnsServerPrimaryZone (DynamicUpdate and ReplicationScope values):
  https://learn.microsoft.com/powershell/module/dnsserver/set-dnsserverprimaryzone
- Get-DnsServerZone (outputs not published): https://learn.microsoft.com/powershell/module/dnsserver/get-dnsserverzone
- MicrosoftDNS_Zone (AllowUpdate values not published; not used):
  https://learn.microsoft.com/windows/win32/dns/microsoftdns-zone
- Aging and scavenging (both needed; scavenging skips a zone with aging off; one scavenging server per
  zone; static records): https://learn.microsoft.com/windows-server/networking/dns/aging-scavenging
- Configure aging and scavenging (defaults; DHCP lease; primary zones only):
  https://learn.microsoft.com/windows-server/networking/dns/configure-aging-scavenging
- Set-DnsServerScavenging (ScavengingInterval 0 disables; ScavengingState is the default for new
  zones): https://learn.microsoft.com/powershell/module/dnsserver/set-dnsserverscavenging
- Set-DnsServerZoneAging and Get-DnsServerZoneAging (Aging alias AgingEnabled; primary zones only):
  https://learn.microsoft.com/powershell/module/dnsserver/set-dnsserverzoneaging and
  https://learn.microsoft.com/powershell/module/dnsserver/get-dnsserverzoneaging
- DNS scavenging setup (dnscmd /ageallrecords stamps static records):
  https://learn.microsoft.com/troubleshoot/windows-server/networking/dns-scavenging-setup
- Get-DnsServerResourceRecord (fields; whole-zone read; -RRType values; -CimSession and -ComputerName):
  https://learn.microsoft.com/powershell/module/dnsserver/get-dnsserverresourcerecord
- Add-DnsServerResourceRecord (IPv4Address, HostNameAlias parameters):
  https://learn.microsoft.com/powershell/module/dnsserver/add-dnsserverresourcerecord
- Problems with DCs and AD-integrated zones (the Netlogon mnemonic table; DnsAvoidRegisterRecords;
  RODCs register site-specific records):
  https://learn.microsoft.com/troubleshoot/windows-server/active-directory/problems-with-dc-ad-integrated-dns-zones
- Enable or disable DNS dynamic registration (Netlogon re-registers hourly; Netlogon.dns; the DNS
  Server service registers A records for the adapters it listens on; PublishAddresses):
  https://learn.microsoft.com/troubleshoot/windows-server/networking/enable-disable-dns-dynamic-registration
- Best practices for DNS client settings on DCs (self as preferred allowed; no ISP DNS; host record;
  ipconfig /registerdns after changing the settings):
  https://learn.microsoft.com/troubleshoot/windows-server/networking/best-practices-for-dns-client-settings
- Troubleshoot DNS event ID 4013 (single server, loopback included, a single point of failure;
  hub-and-branch order; remove references to stale DCs):
  https://learn.microsoft.com/troubleshoot/windows-server/networking/troubleshoot-dns-event-id-4013
- Win32_NetworkAdapterConfiguration (IPEnabled, IPAddress, DNSServerSearchOrder; the class's methods):
  https://learn.microsoft.com/windows/win32/cimwin32prov/win32-networkadapterconfiguration
- Resolve-DnsName (-Server, -Type, -DnsOnly): https://learn.microsoft.com/powershell/module/dnsclient/resolve-dnsname
- NativeErrorCode (AccessDenied, InvalidNamespace, InvalidClass, NotFound; no time-out value):
  https://learn.microsoft.com/dotnet/api/microsoft.management.infrastructure.nativeerrorcode
- System error codes 9000-11999 (DNS_ERROR_RECORD_DOES_NOT_EXIST 9701 "DNS record does not exist.",
  DNS_ERROR_NAME_DOES_NOT_EXIST 9714 "DNS name does not exist."):
  https://learn.microsoft.com/windows/win32/debug/system-error-codes--9000-11999-
- DNS zones (primary, secondary, stub; "A stub zone only contains information about the
  authoritative name servers for the zone"): https://learn.microsoft.com/windows-server/networking/dns/zone-types
- Add-DnsServerPrimaryZone (ReplicationScope: Domain "The domain directory partition", Forest "The
  ForestDnsZone directory partition", Legacy "A legacy directory partition", Custom):
  https://learn.microsoft.com/powershell/module/dnsserver/add-dnsserverprimaryzone
- Get-DnsServerResourceRecord -RRType accepted values include Ns; Example 6 reads a zone's apex NS
  records: https://learn.microsoft.com/powershell/module/dnsserver/get-dnsserverresourcerecord

### Added — 2026-11-16 (dcdiag DNS summary per test group: Auth, Basc, Forw, Del, Dyn, RReg, Ext, per DC and per domain, tool v1.29.0)

**PORT-PLAN C12, and H15 closed.** In the existing `DcDiagnostics` section (report section `DC
Diagnostics`, no new `-Sections` value), the summary table of dcdiag's DNS test is graded per test
group instead of one overall verdict. It addresses the AdAssessment26 catalogue rows DNSDIAG-001 to
-007; the differences from the catalogue rules are listed below.

**This has run only against stubs.** No dcdiag process has been started by it against a real domain
controller: every table it was tested on is a fixture written from the one sample Microsoft shows on
Learn. The first run against a real forest is PORT-PLAN C17, owned by the operator, and PORT-PLAN
C12a lists what that run must confirm for this row.

**What it runs: nothing new.** The table is read from the output of the one
`dcdiag /test:DNS /DnsAll /s:<DC>` invocation C11 already makes per DC. No new invocation and no new
switch: no `/v`, no `/e`, no `/fix`, no `/DnsResolveExtName`, and never `/x`. The DNS test stays
opt-in behind `-IncludeDcdiagActiveTests`, because its dynamic update test registers and deletes a
test record (H20); a test asserts the argument string is unchanged.

| Scope | Rows |
| --- | --- |
| Per DC, with `-IncludeDcdiagActiveTests` | `dcdiag DNS <group>: <host>` for each of Auth, Basc, Forw, Del, Dyn, RReg, Ext (seven per DC), Scope = the DC's domain, Target = the host, Evidence = the header line and the DC's row |
| Per domain, with the switch | `dcdiag DNS <group>: domain <domain>` for each group, over every DC of the domain in the section's list (Fail, then Warning, then Not Assessed - which includes a DC whose status the roll-up does not read - then Pass, then Info), with the counts and the DCs that failed, warned or were not assessed |
| Per domain, without the switch | `dcdiag DNS not run: <domain>`, `Not Assessed`, the reason in `NotRun` (the C11 Intersite wording) |

**How the table is read.** Learn shows it once (KB 2102154): a header "Auth Basc Forw Del  Dyn  RReg
Ext" with uneven spacing, "Domain: <fqdn>" lines, rows "DC1 PASS PASS FAIL PASS PASS PASS n/a", then
"Enterprise DNS infrastructure test results:" and the overall verdict. The header is the last line
whose whitespace-separated tokens are all column tokens, none twice, at least four of them - a tool
default, not a Microsoft value - never a fixed column position. Rows run to the enterprise block, a
verdict line or a block header; cells are split on runs of whitespace and mapped to the columns by
order; CRLF and LF are both read.

**The grades.** PASS `Pass`; FAIL `Fail`; WARN `Warning` - provisional, because no Learn sample shows
a WARN cell and two Learn pages say only, in prose, to note the DCs that report "Warn" or "Fail";
`n/a` `Not Assessed`, "Microsoft does not publish what n/a means", under Auth, Basc, Forw, Del, Dyn
and RReg; `n/a` under **Ext** `Info`, "not requested": `/DnsAll` "performs all tests, except for the
/DnsResolveExtName test", and `/DnsAll` is what this tool runs. Ext's PASS/WARN/FAIL are graded as
the other columns, with Microsoft's caveat that the external name resolution test cannot resolve
internet names where a proxy server is used.

**Not Assessed, each with its own cause, never Pass.** The DC was unreachable on RPC/135; dcdiag.exe
is not available; the DNS test was not started after Connectivity failed; access denied, did not
complete or timed out (with the time-out and its source), no output, or output not recognised
(possibly localised) - C11's own causes when no table was printed; no summary table although an
overall verdict was printed (quoted); no row for the DC (host name, first label, 15-character NetBIOS
form); two rows for it; no column for the group; a row whose cell count is not the header's ("row
not recognised"); a cell value outside PASS, FAIL, WARN, n/a.

**Config.** A `DnsSummary` sub-table of the `DcDiag` table, now versioned 1.29.0, with its source
and read date: the seven column tokens with Learn's names and descriptions (Ext flagged as not named
on Learn), the cell map, the n/a grade per column, the header threshold with its "tool default"
label, the Domain-line, end and separator patterns. The `DcDiag` key of `-ConfigOverridePath` is not
widened: `DnsSummary` and every key in it are refused as unknown, so a file can never turn a group's
result into a Pass.

**Recommendations.** Seven section-scoped entries, one per test group, anchored on the Item prefix
"dcdiag DNS <group>: " and placed ahead of the unscoped entries; each restates what Microsoft
documents the group checks and dcdiag's own advice to use `/v` when the summary table reports errors
or warnings. `DNS` joins the section's catch-all, so the not-run rows get no advice instead of the
unscoped delegation or dcdiag advice.

**/x stays out (H15).** The dcdiag reference documents `/x:<XMLLog.xml>` only as "Redirects all
output to xmllog.xml"; no Learn page publishes its schema. The request for a real `/x:` sample moves
to C12a.

**Where this differs from the catalogue rules.**

- "missing row -> Assessment Error" and "unrecognised table": `Not Assessed` with the cause; this
  repo has no Assessment Error status (C12b).
- DNSDIAG-007 "n/a -> Not Applicable": `Info` "not requested"; this repo has no Not Applicable status
  (C12b).
- The catalogue's PROPOSED severity (Fail Medium, Warning Low) is not carried: the finding shape has
  no severity column (C12b).
- The C12 brief said n/a -> Info "not applicable" for every column; the catalogue's fail-closed rule
  was followed instead, and the reversal is a one-line config edit (C12b).

**Not verified.** Whether a `/s:<DC>` run prints the table at all, only that DC's row, the "Domain:"
lines and the "Summary of DNS test results:" line; the WARN token; what n/a means; the DC-name form in
a row; that Ext is external name resolution; spacing and separator lines; localised output; that
Enterprise Admins is needed and what dcdiag prints without it (C12a).

**Vendor sources, all read 2026-11-16.**

- dcdiag command reference (the DNS sub-tests, /DnsAll excluding /DnsResolveExtName, /v, /x, the DNS
  test not run by default): https://learn.microsoft.com/windows-server/administration/windows-commands/dcdiag
- KB 2102154, Active Directory replication error 1722 (the only summary-table sample, the test-group
  names and abbreviations): https://learn.microsoft.com/troubleshoot/windows-server/active-directory/replication-error-1722-rpc-server-unavailable
- Active Directory replication event ID 2087 (Enterprise Admins minimum for the DNS tests; "Warn" in
  prose): https://learn.microsoft.com/troubleshoot/windows-server/active-directory/active-directory-replication-event-id-2087
- Verify DNS functionality to support directory replication (the dynamic update test record; "Warn"
  in prose; the host (AAAA) portion of the dynamic update test expected to fail when IPv6 is not
  enabled - given for /DnsDynamicUpdate and for reruns of the whole DNS test, never for
  /DnsRecordRegistration, whose record list is CNAME, A, LDAP SRV, GC SRV and PDC SRV; re-read
  2026-11-16): https://learn.microsoft.com/windows-server/identity/ad-ds/manage/troubleshoot/verify-dns-functionality-to-support-directory-replication
- Archived dcdiag page, labelled Windows Server 2003 SP1 (warnings for functional configurations,
  the proxy caveat of the external name test, secure dynamic updates recommended, the failed-delete
  warning of the test record, DNSAvoidRegisterRecord): https://learn.microsoft.com/previous-versions/windows/it-pro/windows-server-2003/cc776854(v=ws.10)

**The guards were shown able to fail.** An earlier run of this claim was stopped after six of its
twenty mutations and left the seventh in the script (see the review paragraph below), so the run was
redone. This time it ran on four scratch copies of the repository, and the working-tree script was
never written: its SHA-256 was the same before and after. There were 32 single mutations, each run
against the C12 `Describe` under PowerShell 7, with that copy restored byte for byte after each and
its SHA-256 checked. All 32 were killed: 20 of the original set (M5 now anchored on the
`dcdiag config override` message, which is unique), the ten the review showed surviving (R1-R10),
and one for each of the two code fixes below. No mutation was skipped.

**Found by an independent review of the diff before commit, and fixed in it.**

- The working tree still held one mutation, `HeaderMinTokens = 3`, left by a mutation run that was
  stopped part way. It is restored to 4. The script's SHA-256 then matched the intended version,
  F03186B6...5EF9C4, before any of the fixes below were made.
- `Resolve-AdfaDcdiagDnsRollup` failed open. A DC whose status was empty, null or not one of the
  five it counts fell through to `Info`, with counts that did not add up to the population. Such a
  DC is now counted and named, and makes the roll-up `Not Assessed`, unless another DC failed or
  warned. The collector never passed such a status, but the pure function now fails closed by itself.
- The RReg advice credited Microsoft with the AAAA caveat. The "Verify DNS functionality" page,
  re-read 2026-11-16, gives that caveat for /DnsDynamicUpdate and for reruns of the whole DNS test,
  never for /DnsRecordRegistration. The caveat now sits in the Dyn advice. The RReg advice lists the
  records Microsoft says that test verifies.
- New tests pin behaviour that the review showed was stated but never tested: Ext PASS, WARN and
  FAIL; the proxy and functional-warnings notes; an overall Fail with no table; the last header
  being read; server, partition and enterprise block headers ending the table; the
  "(domain not known)" roll-up; the unnamed-DC cause; and the status allow-list. Run-Validation
  gained the matching pure-logic checks. No existing test was changed or removed.

**Existing tests changed, because behaviour legitimately changed.** The eight version tests now
expect 1.29.0, and the C11 config test expects the `DcDiag` table at 1.29.0. The C11 recommendation
test that counts the section's scoped entries now declares twelve (four families, seven DNS groups,
the catch-all; it was five). The smoke harness's count of unusable override files went from 16 to
17 (a `DnsSummary` override is refused).

### Changed — 2026-11-16 (dcdiag per DC, per partition and per scope: Topology, CheckSDRefDom, CrossRefValidation, Intersite per site, SystemLog held back, tool v1.28.0)

**PORT-PLAN C11, and C6e closed.** The existing `DcDiagnostics` section (report section `DC
Diagnostics`, no new `-Sections` value) is rebuilt on a parser that attributes every dcdiag verdict
to the block dcdiag prints it in. It addresses the AdAssessment26 catalogue rows DCDIAG-001, -008
and -009, REPL-001, -004 and -006 to -010, and SYSVOL-002 and -003; the differences from the
catalogue rules are listed below.

**This has run only against stubs.** No dcdiag process has been started by it against a real
domain controller: every verdict line it was tested on is a fixture written from the shapes on
Microsoft Learn. The first run against a real forest is PORT-PLAN C17, owned by the operator, and
PORT-PLAN C11b lists what that run must confirm for this row.

**What it runs, and nothing else.** `dcdiag /test:<test> /s:<server>` from the host running the
assessment, one test per invocation, through one seam (`Invoke-AdfaDcdiagTest`) whose argument
comes only from `Get-AdfaDcdiagArgument`. No `/fix`, `/c`, `/e`, `/u`, `/p`, `/skip`,
`/ReplSource`, `/RecreateMachineAccount` or `/FixMachineAccount`, and none of CutoffServers
(Microsoft: it "triggers replication on the DCs"), DcPromo, RegisterInDNS or
OutboundSecureChannels. A test asserts that no configured test builds any of those switches.

| Scope | Tests | Rows |
| --- | --- | --- |
| Per DC (grid) | Connectivity (first), Replications, Advertising, Services, Netlogons, SysVolCheck, DFSREvent, FrsEvent, KccEvent, RidManager, KnowsOfRoleHolders, MachineAccount, ObjectsReplicated, NCSecDesc, VerifyReferences, VerifyReplicas, FsmoCheck, CheckSecurityError, VerifyEnterpriseReferences; **opt-in** SystemLog and DNS | One row per DC: `DomainController`, **`Scope`** (new), `Status`, `Ping`, one `DCDIAG_<test>` column per test (21), `Failures`, `NotRun` |
| Per scoped domain | Topology, against a usable writable DC of the domain | `dcdiag Topology: <domain>`; `dcdiag coverage: <domain>` (Info with the counts of its DCs' grid rows, or Not Assessed when no DC row accounts for the domain) |
| Per forest | CheckSDRefDom, CrossRefValidation, once each, against a DC of the forest root | `dcdiag <test>: <partition>` per part dcdiag printed, and `dcdiag <test>: forest <root>` |
| Per site | **opt-in** Intersite with `/a`, once per site that holds a DC | `dcdiag Intersite: <site>`; without the switch one `dcdiag Intersite: not run` row; `site unknown` for DCs with no site |
| Not run | LocatorCheck | `dcdiag LocatorCheck: not run` (Not Assessed, NotRun says why) |

**The verdict rule.** A verdict is `<subject> passed|failed test <Test>`; the match spans the line
break Learn's own sample shows between "passed test" and the test name. A grid cell counts the DC's
own verdicts - a subject that is the DC's host name, its first label, or the 15-character NetBIOS
form of a longer label (Learn's sample writes "MAPLEWAFFLE-WS2" for home server "MapleWaffle-WS22";
NetBIOS names are at most 15 characters) - and, for Replications and VerifyReplicas only, the
verdicts in partition blocks, which are about the asked server's replicas, and for FsmoCheck and
the opt-in DNS only, the verdicts in the enterprise block, which in a `/s:<DC>` invocation without
`/e` is the enterprise test run from that DC. Other enterprise verdicts,
another DC's verdicts and other tests' partition verdicts are never counted for a DC; a cell with
only those is `Not Assessed`, saying what was printed and that it was not counted. Any counted part
failed -> `Fail`; otherwise any passed -> `Pass`; otherwise `Not Assessed`. "failed" is read before
"passed" everywhere: `Get-AdfaDcdiagTestOutcome` read "passed" first, so output holding both read
`Pass` (the reference's R2 false pass); it now reads `Fail`.

**Not Assessed, each with its own cause, never Pass.** No verdict and "Access is denied" in the
output (access denied); no verdict and a provisional unreachable pattern (could not reach the
server); no verdict after the invocation's own Connectivity failed; a verdict only for something
other than this DC; dcdiag did not complete (with the time-out and where it came from, never the
override file's path); no output; output not recognised - no banner, block or verdict line in a
form this build reads - "possibly a localised, non-English Windows". An event-log test (DFSREvent,
FrsEvent, KccEvent, SystemLog) that failed while its log "could not be queried" is `Not Assessed`:
Microsoft calls that an expected error of the DC's firewall rules (KB 2512643). A failed verdict
that also says "Access is denied" stays `Fail`, with a note: Microsoft documents error 5 "Access is
denied" between DCs with causes on the DCs themselves (KB 3073945). A DC closed on RPC/135 keeps its `Fail` row
with every cell `Not Assessed`, as before. A grid row whose attempted cells were all unreadable is
now `Not Assessed` (it was `Warning`).

**Connectivity first.** Microsoft documents that the connectivity test "can't be skipped", so it
runs in every invocation; it is now also its own cell (DCDIAG-001), run first. When it fails, no
further test is started on that DC, every remaining cell is `Not Assessed` and the row's `NotRun`
column names them and Connectivity, and the cell carries Microsoft's caveat that "Blocking ICMP prevents DCDiag from functioning as intended".

**SystemLog is held back.** Learn describes it as validating the System log "by reading and writing
entries". It does not say what is written, and the wording may be a documentation error, but by the
H20 rule it joins DNS and Intersite in `DcdiagActiveTests` and runs only with
`-IncludeDcdiagActiveTests` (PORT-PLAN C11a). **Intersite now runs once per site** that holds a DC
(it used to run per DC), which triggers fewer replications when the switch is given.

**C6e closed: RidManager stays in the default list.** Learn describes it as checks only - the RID
master "is accessible", "contains the proper information", "can be located and contacted through a
DsBind", "has valid RID pool values" - over LDAP and RPC, and describes no write and no pool
request. It does not say in so many words that the test never requests a pool; the README says so.

**Config.** A new `DcDiag` table, versioned 1.28.0 with its source and read date: the per-DC,
per-domain, per-forest and per-site test lists (each test with Learn's description), the tests not
run and why, the parser's anchors, and the evidence patterns - the unreachable ones marked
`Provisional`, because Learn publishes no text for a DC dcdiag cannot reach. A new `DcDiag` key of
`-ConfigOverridePath` accepts `TestTimeoutSeconds` (5-600) and `Retries` (1-10) only, both tool
defaults; every other key is refused, so a file can never add a test. The section's targets are the
DCs of every scoped domain (the inventory, else `Get-AdfaDcTargetsByDomain`), probed through the
per-run cache (`Test-AdfaDcPort`).

**Recommendations.** Four section-scoped entries, anchored on the Item prefixes this tool writes
(`dcdiag Topology: `, `dcdiag CheckSDRefDom: `, `dcdiag CrossRefValidation: `, `dcdiag Intersite: `
other than the not-run and site-unknown rows) and a prefix catch-all with no advice, placed ahead of
the unscoped entries. Each restates what Microsoft documents the test checks and names dcdiag's `/v`
switch. The grid rows (Item = host name) keep reaching the unscoped `sysvol|dfsr`, `replication` and
`dcdiag` entries, as the H20 tests pin.

**Where this differs from the catalogue rules.**

- DCDIAG-008 SystemLog: "Parsed verdict" in the catalogue; not run by default here (C11a).
- DCDIAG-009 LocatorCheck: not run at all (C11d).
- SYSVOL-002 / -003: "Not Applicable where SYSVOL uses FRS / DFSR" is not built, because no per-DC
  SYSVOL engine is collected (SYSVOL-004 is C14); both are graded from their own output (C11e).
- REPL-010: "site without DC -> Not Applicable" is not built; sites are those that hold a DC (C11f).
- REPL-004 NCSecDesc is per DC, as in the catalogue; REPL-001 and REPL-006 take partition parts.
- The reference's 2-consecutive-time-outs circuit breaker and its 180 s per-test time-out are not
  adopted; the time-out stays the tool's 90 s default, overridable (C11f).

**The guards were shown able to fail.** Eighteen single mutations of the new code, each run against
the new `Describe` and the H20 `Describe`, with the script restored byte for byte after each
(SHA-256 checked); the table is in the C11 hand-off.

**Existing tests changed, because behaviour legitimately changed.** H20: the opt-in list holds three
tests (SystemLog added); the per-DC invocation counts are 19, 57 and 21 (were 16, 48 and 18), counted
without the once-per-scope tests; the `DCDIAG_Intersite` assertions became `DCDIAG_SystemLog` and an
Intersite site row; the helper hands the DC over as an inventory row with a site; each test starts
with an empty port cache (`Clear-AdfaDcPortCache`), because the section now probes through it. The
"DNS test in the array the collector iterates" test now reads the `PerDcTests` config list and
proves, from the parsed script, that the collector reads it. The seven version tests now expect
1.28.0; the eight section-list tests and the validation harness's expect `DcDiag` as the tenth
section; five help tests expect "Ten sections can be named". In the validation harness the grid
assertions count grid rows and per-DC invocations (19/21). The smoke harness now has dcdiag.exe
"available" and a dcdiag stub, and its count of unusable override files went from 14 to 16.

**Found by an independent review of the diff before commit, and fixed in it.**

- **A false Pass for opt-in DNS, and FsmoCheck never Pass.** An enterprise-block verdict counted for
  no DC. `dcdiag /test:DNS /DnsAll /s:<DC>` prints "DC passed test DNS" in the server block and its
  summary of these "enterprise-wide DNS health checks" (Learn) under "Running enterprise tests on :
  <forest>", so a failed summary read `Pass` (v1.27.0 read the same output as `Pass` too, by
  matching "passed" first for this test). FsmoCheck, one of dcdiag's enterprise tests, prints only
  there, so every DC's FsmoCheck cell read `Not Assessed` and every healthy DC's row `Warning`. A new
  `EnterpriseParts` flag on the per-DC entries (FsmoCheck and DNS only) counts the enterprise verdict
  of the invocation against that DC; "failed" wins, and the Fail detail names the enterprise block
  and says that a fault of the forest shows on every DC asked. The FsmoCheck output shape is from
  field captures, not Microsoft (Learn's sample prints LocatorCheck and Intersite in that block and
  does not show FsmoCheck); C11b now asks a real capture to confirm it, and C11g(11) records the
  decision. The test fixtures and the smoke stub now answer FsmoCheck in the enterprise block.
- **Three notes this tool writes chose the wrong advice for a grid row** (whose advice comes from
  the unscoped entries, matched on the whole text, first match wins): the "Access is denied" note on
  a failed verdict said "replication" and gave a NetLogons share failure the `repadmin /replicate`
  advice; the unrecognised-output cause said "not a pass" and gave the event-log coverage advice; the
  "Not run after Connectivity failed: Replications, ..." list gave a Connectivity failure the
  replication advice. The first two are reworded; the list moved to the row's `NotRun` column, which
  is added after the advice is chosen. Tests assert the dcdiag advice for each. dcdiag's own quoted
  lines can still choose other advice: new Planned row C11h.
- **Guards no test could fail, now covered:** the 15-character NetBIOS rule against a shorter prefix;
  a DC whose Connectivity failed never chosen for Topology; the fallback to a DC whose Connectivity
  was not assessed; the KB 3073945 note itself (the old test matched words the fixture already
  held); the partition named in a DC's failed Replications detail; English banner-only output read
  as "no verdict line", not "possibly localised"; a bare verdict in another DC's server block, and
  another DC's failed Connectivity, not counted for this DC; Topology run for a domain known only
  from a DC's Scope. Each was shown to fail under the reviewer's mutation, with the script restored
  byte for byte (SHA-256 checked).
- **Existing test changed:** the Connectivity-failure test asserted the not-run list in `Failures`;
  it now asserts it in `NotRun`, and that `Failures` does not name the tests not run.

**Sources, all read on Microsoft Learn 2026-11-16.**

- [dcdiag command reference](https://learn.microsoft.com/windows-server/administration/windows-commands/dcdiag) -
  the known-tests table and each test's description (Connectivity, NCSecDesc, VerifyReplicas,
  CheckSDRefDom, CrossRefValidation, Topology and DS_REPSYNCALL_DO_NOT_SYNC, Intersite and `/a`,
  RidManager, SystemLog "reading and writing", DFSREvent, FrsEvent, KccEvent, CutoffServers
  "triggers replication"), `/fix` and the MachineAccount repair options, "The connectivity test can't
  be skipped", the ICMP note, administrative rights and an elevated prompt, and the sample output
  (block headers, the wrapped verdict, LocatorCheck and Intersite under the enterprise block with
  the forest as subject), DNS as "enterprise-wide DNS health checks", and that FsmoCheck is not in
  the known-tests table (re-read for the review fixes).
- [DCDIAG.EXE /E or /A or /C expected errors (KB 2512643)](https://learn.microsoft.com/troubleshoot/windows-server/identity/dcdiag-commands-running-errors) -
  "could not be queried" and the "failed test" form for FrsEvent, DFSREvent, KccEvent and SystemLog,
  and the Remote Event Log Management firewall rules.
- [Replication error 5: Access is denied (KB 3073945)](https://learn.microsoft.com/troubleshoot/windows-server/active-directory/replication-error-5) -
  dcdiag's Replications test reporting error 5, and its causes on the DCs (an invalid secure
  channel, time skew, user rights, SMB signing and others).
- [System Error Codes (0-499)](https://learn.microsoft.com/windows/win32/debug/system-error-codes--0-499-) -
  ERROR_ACCESS_DENIED, "Access is denied."
- [Naming conventions in Active Directory (KB 909264)](https://learn.microsoft.com/troubleshoot/windows-server/active-directory/naming-conventions-for-computer-domain-site-ou) -
  NetBIOS computer names are at most 15 characters.
- Not published on Learn (searched 2026-11-16): the text dcdiag prints for a DC it cannot reach, and
  for tests skipped after Connectivity failed; per-test scope; localised output; a dcdiag time-out.

**Not verified.** Everything in PORT-PLAN C11b: the provisional unreachable patterns, the output
shape of a single-test invocation for the partition tests, Topology and VerifyReplicas, the block
FsmoCheck and the DNS summary print their verdicts in, the enterprise block's name, the failed-verdict form on current builds, exit codes, run times, and the
rights the forest tests need. That a real dcdiag run is read the same way on Windows PowerShell 5.1
and PowerShell 7 (the stubs are). That SystemLog writes anything.

### Changed — 2026-11-16 (Privileged groups and delegation: Schema and Enterprise Admins, privileged group counts, adminCount orphans, SPNs and delegation, read by SID, tool v1.27.0)

**PORT-PLAN C10.** The existing `PrivilegedAccounts`, `PrivilegedHygiene` and `Kerberos` sections
(report sections `Privileged Accounts`, `Privileged Hygiene` and `Kerberos Exposure`, no new
`-Sections` value) are rebuilt on one set of directory reads made once per run. They address the
AdAssessment26 catalogue rows ADA-PRIV-001 and -002, ADA-INV-005, ADA-OBJ-001, -002, -003, -004 and
-006, and ADA-INV-017, and add one row the catalogue does not have (privileged accounts that can be
delegated).

**This has run only against stubs.** No read in it has met a real domain controller: the Pester
tests answer the seams from a fake two-domain directory in the shape the module returns, and the
harnesses from small stub directories. The first run against a real forest is PORT-PLAN C17, owned by
the operator, and PORT-PLAN C10a lists what that run must confirm - first of all whether
`Get-ADObject -Properties member` does range retrieval past MaxValRange, and what the module returns
for `msDS-AllowedToActOnBehalfOfOtherIdentity`, neither of which Microsoft publishes.

**What was wrong with the old checks.** `Get-AdfaPrivilegedAccount` read `Get-ADDomain` outside any
`try`, expanded groups with `Get-ADGroupMember -Recursive` (Learn: it fails for a whole group with a
member in another forest without ADWS; Learn does not say whether it returns members through
`primaryGroupID`, and this was not measured, so whether the old count included them is unknown), built its group list
in an unordered hashtable, put member names in a column and graded any group over 10 members a
Warning, a threshold no source gives; Schema Admins and Enterprise Admins had no verdict at all.
`Get-AdfaKerberosExposure` excluded DCs from unconstrained delegation by **name**, with a
`Get-ADDomainController` call that dropped `-Credential`, filtered nothing (`-or $true`), never read
constrained delegation or protocol transition, and counted RBCD without grading it.
`Get-AdfaPrivilegedHygiene` computed no orphan (it counted adminCount=1 users), lost its SPN row when
the read failed, read Protected Users without `-Credential` and graded it `Pass` at one member - with
a Detail ("should be enrolled") that the unscoped ESC1 entry of the advice map answered with
certificate-template advice. Names were in Detail throughout, where they can change the advice. All
three are rebuilt; the dead `PrivilegedGroupRids` and `BuiltinAdministrators` config keys are gone.

**Grades and Items that changed for a report reader.** Two client-facing grades went **down**:
v1.26.0's `Unconstrained delegation (non-DC)` (`Fail`) is now `Unconstrained delegation: <domain>`
at `Warning`, and `Privileged accounts with SPNs (Kerberoast risk)` (`Fail`) is now
`Privileged accounts with SPN: <domain>` at `Warning` - the catalogue rule (ADA-OBJ-002 and
ADA-OBJ-006), a tool default; `UnconstrainedStatus` and `PrivilegedSpnStatus` set to `Fail` in the
override file restore the old grade. The old Item strings `Unconstrained delegation (non-DC)`,
`Privileged accounts with SPNs (Kerberoast risk)`, `Protected Users group members` and
`adminCount=1 users` are retired: a v1.26.0 report and a v1.27.0 report do not share those rows.
Their replacements are listed under "What it reports".

**What it reads, and nothing else** (named attributes only; a list with a wildcard or a blank is
refused before any call; nothing is written - no `Set-AD*`, no `Add-ADGroupMember`, no
`Set-ADAccountControl`, and never the rootDSE `RunProtectAdminGroupsTask` modify Appendix C documents):

- `Get-ADDomain -Identity <d> -Server <d>` for every domain of the forest (through the C9 seam), for
  its DN and SID, so that a member DN is read from the domain that holds it, and its `DomainMode`.
- Per scoped domain, each group of the new `Privileged` table with `Get-ADObject -LDAPFilter
  '(objectSid=<SID as escaped bytes>)'` - by SID, never by name; every member DN with
  `Get-ADObject -Identity <DN>` from its own domain, nested groups followed security and distribution
  alike; `(primaryGroupID=<RID>)` for every group with a domain SID, because primary-group membership
  is not in `member`, with `-ResultSetSize` one more than what is left of `MaxExpandedObjects`. Each
  object is read once per run.
- Per scoped domain, `(adminCount=1)` and one delegation search for `TRUSTED_FOR_DELEGATION`,
  `TRUSTED_TO_AUTH_FOR_DELEGATION`, `msDS-AllowedToDelegateTo` and
  `msDS-AllowedToActOnBehalfOfOtherIdentity`, with the bits as decimals. The Kerberoast and AS-REP
  reads are unchanged.
- Once per run, whichever of the three sections runs, under `CN=Sites` of the configuration
  partition, every `nTDSDSA` and `server` object (`serverReference`), and `dSHeuristics` on
  `CN=Directory Service,CN=Windows NT,CN=Services`.

**The rules.** Schema Admins and Enterprise Admins (forest root only, once per run): `Warning` at
one transitive member - users, computers, others and foreign security principals by SID, nested
groups followed but not counted - the catalogue rule; the forest root's built-in Administrator, which
Learn names as the default member and a possible Enterprise Admins exception, is counted and quoted,
and `EnterpriseAdminsExemptRootAdministrator` exempts it. Every privileged group is counted (Info, no
threshold: the reference sets none). adminCount orphans: an adminCount=1 object - user, computer or
group, enabled or not - that no protected group of the domain or the forest root reaches and that is
not Administrator or krbtgt; Learn says "formerly protected", and "orphan" is labelled this tool's
inference; an object protected only through Account, Server, Print or Backup Operators is undecided
when `dwAdminSDExMask` (dSHeuristics character 16) is not 0 or was not read, because Learn does not
publish its bit mapping. SPN on a privileged account: enabled users only, computers and krbtgt left
out. Privileged accounts delegable (a C10 addition): enabled accounts with neither `NOT_DELEGATED`
nor a transitive Protected Users membership that blocks delegation - which Learn says it does only at
domain functional level Windows Server 2012 R2 or later, so below it a member is graded and with the
level unread it is undecided. Unconstrained delegation and protocol transition
exclude DCs and RODCs by the DN of their computer account from `serverReference` - never by name,
never by primaryGroupID 516/521, which is reported when an account carries it without being a
registered DC - because Learn shows a writable DC carries `TRUSTED_FOR_DELEGATION` and an RODC
`TRUSTED_TO_AUTH_FOR_DELEGATION` by default; with the DC population unread or incomplete both rows
are Not Assessed. Constrained delegation (Kerberos-only) is inventory with its targets. RBCD is graded
and its descriptor is read in memory by the C9 converter, listing the SIDs it allows and denies.
Nothing is passed on an empty answer: the DC population must be complete, each domain's registered
DCs must be found in its DC groups and returned by its delegation search (a tool rule on Learn's
defaults), and the adminCount search and the privileged-account population must hold the domain's
Administrator (RID 500). Every grade is a **tool default** (`Warning`, `Fail` by override); Microsoft
publishes none.

**What it reports.** `Schema Admins members: <root>`, `Enterprise Admins members: <root>`,
`Privileged group: <name>: <domain>` (17 groups in the forest root, 13 in a child domain) and
`Privileged group population: <domain>`; `adminCount orphans`, `Privileged accounts with SPN`,
`Privileged accounts delegable`, `Protected Users members` (each `: <domain>`); the Kerberoast and
AS-REP rows, then `Unconstrained delegation`, `Protocol transition delegation`, `Constrained
delegation` and `Resource-based delegation` (each `: <domain>`). Names, SIDs, DNs and SPNs are in
`Principals`, `PrincipalSids`, `ForeignSids`, `Unresolved`, `Targets` and `AllowedSids`, never in
Detail. `Not Assessed`, each in its own words: `Unreachable:`, `Access denied:`, `Timed out:`, `Read
failed:`, `Not found:`, and for a member reference out of scope (a forest domain the run did not
scope - the reference rule, AdAssessment26 decision 56), domain not decided, not found, the read cap
(`MaxExpandedObjects`, 5000, a tool default) or a member list of exactly 1500 or 5000 values, which
may be cut at MaxValRange; such a group's count is left empty - never a lower number - while a member
found still grades Schema and Enterprise Admins.

**Config.** New versioned table `Config.Privileged` with every source and its read date; override key
`Privileged` in `-ConfigOverridePath`: the eight grades (Warning or Fail),
`EnterpriseAdminsExemptRootAdministrator` (a JSON boolean), `NameListCap` (0 to 1000) and
`MaxExpandedObjects` (1 to 100000); the groups, bits, filters and property lists are refused. The
override registry gains `AlsoUsedBy`, so the "validated but not used" log is right whichever of the
three sections a run selects. **Advice**: section-scoped entries for each graded family, ahead of the
unscoped entries, with a catch-all for the new rows; the Kerberoast and AS-REP rows still reach the
advice they had.

**Tests.** A new Pester Describe (74 tests): wiring by AST, the config table, the SID filter value
against Learn's own example, routing, the membership walk, every verdict, two domains through the
seams with unreachable, access-denied and timed-out domains, the override (valid and twelve malformed
shapes) and the advice. Twelve single mutations of the new code were each caught and the file
restored byte for byte (SHA-256). Existing tests changed because behaviour changed: the override
registry list and its declared population (seven places, and Run-Validation), "Eight sections can be
named" to "Nine" (four places), the version 1.26.0 to 1.27.0 (six places), and the counts of
`-Properties` arguments (23 to 28) and splatted property lists (17 to 19) in the C4 Describe - C10
removed three literal lists and added eight arguments and two lists to its own seams. The smoke
harness retires its `Get-ADGroupMember` stub (it now throws) and asserts the three sections in the
single-domain, three-domain, failing-collector and unreadable-forest passes.

**Not verified.** Anything against a real directory (C17, C10a): range retrieval of `member`; the
shape of an attribute with no value; the type of the RBCD attribute; the exception types of a real
not-found, refused, unreachable and timed-out read; that `(objectClass=nTDSDSA)` matches an RODC;
that `serverReference` equals each DC's computer DN; run time on a large forest. Left out, PORT-PLAN
C10b: DnsAdmins, the dwAdminSDExMask mapping (KB 817433, off Learn), the ACL of each adminCount=1
object, the SDProp interval. Decisions for the operator, PORT-PLAN C10c. Left open by the review,
PORT-PLAN C10d: the DC-defaults rule behind the delegation population check, a second non-vacuity
check on `member`, a domain where SDProp has not yet run, whether the module honours `-ResultSetSize`
with its paging, and `DomainMode` values of later releases.

**Found by an independent review of the diff before commit, and fixed in it.** Twenty confirmed
findings, each with a test that fails without the fix (or, for a test that could not fail, a test the
reviewer's mutation now fails):

1. A DC population read incompletely - no `nTDSDSA` object returned, a DC server object without
   `serverReference`, an `nTDSDSA` object with no server object - was used as complete, so a DC's own
   computer account could be graded as a non-DC with unconstrained delegation. `DsaCount` and
   `NoReference` were computed and never read. `Get-AdfaPrivDcPopulationState` now checks all three,
   and the two bit rows are `Not Assessed` when any fails.
2. The delegation rows passed on a search that returned none of the domain's registered DCs, which
   carry the delegation bits by default. The search now has a declared population - every DC
   registered for the domain, told apart from a child domain's by its naming context - and no row
   passes without it; the Constrained count is not given.
3. The orphan, SPN and delegable rows passed on an empty population. The domain's Administrator (RID
   500) is a protected account and Learn says a protected account has adminCount 1, so the adminCount
   search and the account population must hold it; an empty population is `Not Assessed`.
4. `Targets` and `AllowedSids` were taken from the unsorted hits while `Principals` lists the first
   `NameListCap` in ordinal order, so past the cap they named other accounts. Both now come from the
   records `Principals` lists.
5. A search failing with the identity-not-found exception (adminCount, delegation, roast) was worded
   as "no group with the SID of ...". Searches now say the search was answered "not found".
6. A SID lookup answered with two objects was worded as a read failure that might be a missing right.
   It is now class `Duplicate`, "ambiguous", not a refusal.
7. With every group answering without members and every search answering empty (an account without
   read rights), the hygiene rows, the population row and an empty Schema or Enterprise Admins passed.
   The group reads of each domain must now find its registered DCs in its DC groups (Microsoft's
   default primary groups 516 and 521); otherwise the population row is `Not Assessed` and an empty
   Schema or Enterprise Admins is not passed. A "blind" stub domain proves no graded row passes.
8. As 2, for the protocol-transition and RBCD rows.
9. As 1, for a DC listed only in `NoReference`.
10. A member in a scoped domain whose own `Get-ADDomain` read failed was "out of scope". It now
    carries that domain's cause: unreachable, access denied, timed out or read failed.
11. Primary-group searches were not counted against `MaxExpandedObjects`: `Domain Users` nested in a
    protected group read every user. They now count, and ask `-ResultSetSize` one more than is left; a
    larger answer is "read cap", its members not counted.
12. No test pinned that a protected group's nested groups and foreign members count as protected
    (mutations M4 and M5 survived). A pure test now fails on each.
13. No test pinned that a disabled privileged account is left out of the delegable row (M8 survived).
14. Protected Users membership counted as delegation protection at any functional level. Learn says
    the DC-side restriction needs domain functional level Windows Server 2012 R2; `DomainMode` is now
    read and a member below it is graded, with it unread undecided. The README no longer says "either
    counts as protection".
15. Enterprise Key Admins (-527) was looked up in every domain. Learn's domain-wide updates page
    (Operation 85) names it a root-domain group, so it is now `ForestRoot`: not looked up in a child
    domain (whose row said "documented only from a later level") and counted as a protected source for
    every child. 13 group rows per child domain, not 14.
16. No test pinned the 5000-value member limit (M1 survived).
17. No test exercised `NameListCap` (M10 survived).
18. No test pinned that a Kerberoastable account with no `Enabled` value is counted (M6 survived).
19. This entry did not say that two rows went from `Fail` to `Warning` and that four Item strings are
    retired - see "Grades and Items that changed".
20. This entry stated as fact that the old collector "did not read the primary-group members", which
    was never measured; it now says so.

Existing tests changed because behaviour changed, each named: the protected-group list and the
child-domain group count (Enterprise Key Admins is forest-root: 14 to 13, and the north row counts 15
to 14 and 25 to 24); the orphan, SPN and delegable `Pass` cases now include the domain's
Administrator; the delegation `Pass` cases now include the registered DCs in the search answer, and
an empty answer is `Not Assessed`; RBCD with the DC population unread is `Not Assessed`, not `Pass`;
`Get-AdfaPrivilegedState -Parts Groups` now reads the forest configuration; the smoke three-domain
count 50 to 48. The test stubs gained `DomainMode` and `-ResultSetSize`, as the real cmdlets have.

**Sources**, all read on Microsoft Learn on 2026-11-16:

- https://learn.microsoft.com/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory
- https://learn.microsoft.com/windows-server/identity/ad-ds/plan/security-best-practices/reducing-the-active-directory-attack-surface
- https://learn.microsoft.com/windows-server/identity/ad-ds/plan/security-best-practices/appendix-e--securing-enterprise-admins-groups-in-active-directory
- https://learn.microsoft.com/windows-server/identity/ad-ds/manage/understand-security-groups
- https://learn.microsoft.com/windows-server/identity/ad-ds/manage/understand-security-identifiers
- https://learn.microsoft.com/windows-server/identity/ad-ds/manage/understand-default-user-accounts
- https://learn.microsoft.com/windows-server/identity/ad-ds/manage/how-to-configure-protected-accounts
- https://learn.microsoft.com/windows-server/security/credentials-protection-and-management/protected-users-security-group
- https://learn.microsoft.com/windows-server/security/kerberos/kerberos-constrained-delegation-overview
- https://learn.microsoft.com/windows-server/identity/ad-ds/manage/group-managed-service-accounts/group-managed-service-accounts/configure-kerberos-delegation-group-managed-service-accounts
- https://learn.microsoft.com/defender-for-identity/security-posture-assessments/accounts
- https://learn.microsoft.com/windows/win32/adschema/a-useraccountcontrol
- https://learn.microsoft.com/troubleshoot/windows-server/active-directory/useraccountcontrol-manipulate-account-properties
- https://learn.microsoft.com/troubleshoot/windows-server/active-directory/replication-error-8453
- https://learn.microsoft.com/windows/win32/adschema/a-msds-allowedtodelegateto
- https://learn.microsoft.com/windows/win32/adschema/a-msds-allowedtoactonbehalfofotheridentity
- https://learn.microsoft.com/windows/win32/adschema/a-serverreference
- https://learn.microsoft.com/windows/win32/adschema/c-ntdsdsaro
- https://learn.microsoft.com/openspecs/windows_protocols/ms-adts/e5899be4-862e-496f-9a38-33950617d2c5
- https://learn.microsoft.com/windows/win32/ad/how-to-specify-comparison-values
- https://learn.microsoft.com/windows/win32/adsi/search-filter-syntax
- https://learn.microsoft.com/troubleshoot/windows-server/active-directory/domain-controller-returns-500-values-ldap-response
- https://learn.microsoft.com/powershell/module/activedirectory/get-adgroupmember
- https://learn.microsoft.com/windows-server/identity/ad-ds/deploy/domain-wide-updates (Enterprise Key Admins is "rootdomain\Enterprise Key Admins"; both key-admin groups are created once a Windows Server 2016 DC holds the PDC emulator role)
- https://learn.microsoft.com/windows-server/identity/ad-ds/active-directory-functional-levels (Protected Users DC-side protections, delegation among them, at the 2012 R2 domain functional level)
- https://learn.microsoft.com/powershell/module/activedirectory/set-addomainmode (the `DomainMode` values)
- https://learn.microsoft.com/powershell/module/activedirectory/get-adobject (`-ResultSetSize`)
- https://learn.microsoft.com/powershell/module/activedirectory/about/about_activedirectory_filter ("ResultSetSize controls the maximum number of returned objects")

### Changed — 2026-11-16 (Dangerous rights: replication and control rights on the domain head, AdminSDHolder and every GPO, matched by SID, tool v1.26.0)

**PORT-PLAN C9.** The existing `Acl` section (report section `Dangerous ACLs (DCSync)`, no new
`-Sections` value) is rebuilt. It addresses the AdAssessment26 catalogue rows ADA-ACL-001 (dangerous
rights on the domain root), ADA-ACL-002 (on AdminSDHolder) and ADA-ACL-003 (on GPOs).

**This has run only against stubs.** No `Get-ADObject` call in it has met a real domain controller,
and no descriptor it has read came from a directory: the Pester tests build real descriptors from
SDDL on Windows, the harnesses use records in the converter's shape. The first run against a real
forest is PORT-PLAN C17, owned by the operator, and PORT-PLAN C9a lists what that run must confirm -
first of all which .NET type `Get-ADObject` returns for `nTSecurityDescriptor` and which descriptor
parts the module asks for, neither of which Microsoft publishes.

**What was wrong with the old check.** `Get-AdfaDangerousAcl` decided "default" by matching the
`IdentityReference` NAME against `DcSyncAllowedPatterns` with `-match` on an escaped substring, so
any group whose name contains an allowed name passed (`Not Domain Controllers`, `Fake
Administrators`) and a localised name failed; it read the descriptor with `Get-Acl -Path AD:\<dn>`,
which takes neither the run's `-Server` nor its `-Credential` and needs the AD: drive; it matched
rights as text (`-match 'ExtendedRight|GenericAll'`), ignored WriteDacl, WriteOwner, GenericWrite,
an extended right with no object type and inherit-only ACEs; and one `catch` turned any failure
into a single `Not Assessed` row holding the raw exception. `Test-AdfaDcSyncAce`, `DcSyncRightGuids`
(whose third key was a truncated name) and `DcSyncAllowedPatterns` are retired; nothing else read
them.

**What it reads, and nothing else.** Per scoped domain, each read sent to that domain
(`-Server <domain>`, with `-Credential` when the run has one), asking for `nTSecurityDescriptor`
alone - a property list that is anything else is refused before any call:

- `Get-ADDomain -Identity <domain>` for the DN and SID, and once for the forest root domain's SID
  (Enterprise Admins and Enterprise Read-only Domain Controllers are SIDs of the root domain).
- `Get-ADObject -Identity <domain DN>` and `Get-ADObject -Identity CN=AdminSDHolder,CN=System,<DN>`.
- One `Get-ADObject -SearchBase CN=Policies,CN=System,<DN> -SearchScope OneLevel -LDAPFilter
  '(objectClass=groupPolicyContainer)'` - **every** GPO, as the catalogue's ADA-ACL-003 says, not only
  those linked at the domain root and the Domain Controllers OU as the plan row said (PORT-PLAN C9c).

The descriptor - an `ActiveDirectorySecurity` or a byte array; anything else is `Not Assessed` - is
turned into its binary form and read in memory with `RawSecurityDescriptor`: the owner SID, whether
a DACL is present, and every ACE in order, each principal as its SID. Not with `GetAccessRules`:
**measured in this session** (Windows PowerShell 5.1 and PowerShell 7.6, descriptors built from
SDDL), `GetAccessRules` reports a descriptor that carries no DACL as one "Everyone, full control"
rule, which would turn "the DACL was not returned" into a finding about Everyone. Also measured: an
`ActiveDirectorySecurity` hands a canonical DACL back with its explicit allow ACEs regrouped, denies
still first, which does not change which deny precedes which allow. Nothing is written: no
`Set-Acl`, no `Set-ADObject`, `Persist` is never called (Learn documents `Persist` as the method that
writes an in-memory descriptor to storage). A test pins the three AD reads by function and refuses
any write cmdlet, write parameter, external tool, `Get-Acl` and any descriptor-changing method.

**The rule** (catalogue, operator-approved 2026-09-24): an allow ACE that applies to the object and
grants full control, `WriteDacl`, `WriteOwner`, write of all properties, all extended rights or one
of the three replication rights, to a SID outside the allowlist. Decided by **access mask bits**,
never by a rights name: full control is every bit of 983551 or the GENERIC_ALL bit; write of all
properties is `WriteProperty` (0x20) with no object type, or GENERIC_WRITE - not `GenericWrite`'s
`ReadControl` bit, so a read ACE is never flagged; all extended rights is `ExtendedRight` (0x100) with
no object type, which Learn documents as every extended right and so includes the three replication
rights; a replication right is `ExtendedRight` with its GUID. A write scoped to one property, and
any other extended right (Apply-Group-Policy on a GPO), is not graded. An object ACE scoped to the
object's own class, or a class above it (domainDNS, domain, top; groupPolicyContainer, container,
top; container, top for AdminSDHolder), is graded as unscoped; one scoped to any other GUID grants
only that node - never `WriteDacl`, `WriteOwner` or full control on the object, and only the
replication right whose GUID it names. An **inherit-only** ACE is
skipped (Learn: it "does not control access to the object to which it is attached"). An ACE scoped
to a child class through `InheritedObjectType` but **not** inherit-only is graded: Learn documents
that such an ACE is also effective on the container - the plan row's "an ACE scoped to a child class
does not grant on the domain object" holds only with the inherit-only flag. A **deny** ACE cancels a
grant only when it names the same SID, comes earlier, applies to the object and covers every graded
bit; otherwise the grant is flagged and the deny is named in `Evidence`. The **owner** is graded as
holding `WriteDacl`, which Learn says an owner holds implicitly.

**The allowlist, by SID only**, per object and per right (`Config.Acl.Allowlist`): from Microsoft -
the Domain-DNS default descriptor (Domain Admins, Administrators, SYSTEM and Enterprise Admins hold
`WriteDacl`, `WriteOwner`, write of all properties and every extended right; Enterprise Domain
Controllers `Get-Changes` and `In-Filtered-Set`; Domain Controllers `Get-Changes-All`), the RODC
article (Enterprise Domain Controllers, "only writeable DCs", `Get-Changes-All` - which the
Domain-DNS descriptor does not list; the two pages disagree and the row says so), the 8453 and RODC
articles (the forest root's Enterprise Read-only DCs: `Get-Changes` only - holding
`Get-Changes-All` is the misconfiguration Microsoft says to change back, and is flagged), AdminSDHolder
appendix C (Enterprise Admins, Domain Admins, Administrators) and the groupPolicyContainer default
descriptor (Domain Admins, Enterprise Admins, SYSTEM, Creator Owner: write of all properties,
`WriteDacl` and `WriteOwner` only - that descriptor grants them no control access); and **tool
defaults**, labelled as such - SYSTEM on AdminSDHolder and Administrators on GPOs (AdAssessment26
decision D14), and all extended rights and the replication rights on GPOs for Domain Admins,
Enterprise Admins, SYSTEM and Creator Owner (C9).
Every graded row says the allowlist is **provisional** until it is captured from a clean lab forest
(catalogue P44/P45). A test shows a SID that resolves to "Fake Administrators", or even to
"BUILTIN\Administrators", is still flagged: no decision reads a name.

**What it reports.**

| Row | Results |
| --- | --- |
| `DCSync rights: <domain>` | ADA-ACL-001, High. The flagged grade (`Warning`, a **tool default**, the catalogue rule; `Fail` by override) naming each SID outside the allowlist that holds a replication right and which; `Pass` otherwise |
| `Domain root control rights: <domain>` | ADA-ACL-001, High. The same for `WriteDacl`, `WriteOwner`, write of all properties, full control and ownership. ADA-ACL-001 is two rows because the advice differs |
| `AdminSDHolder rights: <domain>` | ADA-ACL-002, High. Every graded right and ownership |
| `GPO rights: {GUID}` | ADA-ACL-003, Medium. One per GPO the search returned ("one part per GPO") |
| `GPO rights summary: <domain>` | `Population`, `ReadCount`, `FlaggedCount`, `NotAssessedCount`; `Not Assessed` as a defect in the tool unless there is exactly one GPO row per container returned. The flagged grade when any GPO is flagged; `Not Assessed` when any could not be read, when none is visible (a domain holds its two default GPOs) or when the search failed; `Pass` only when every GPO was read and none is flagged |
| `Dangerous ACLs (no domain scoped)`, `Dangerous ACLs` | `Not Assessed`: no domain scoped; the forest unreadable |

`Not Assessed`, each in its own words: `Unreachable:`, `Access denied:`, `Timed out:`, `Read
failed:` (from the exception type first), `Not returned:` (the answer held no `nTSecurityDescriptor`;
Learn: a read can succeed without the attributes the caller may not see), `No DACL returned:` (which
cannot be told from an object with no DACL), `Not read:` (not a descriptor), an ACE of a type the tool
does not interpret, and an account SID that could not be decided because the scoped domain's or the
forest root's SID was not read (with the root's SID unread, the scoped domain's own -519 and -498
too) - each only when no SID is flagged: a flagged SID takes the grade and the Detail names the rest.
A NULL DACL (`NULL DACL:`, the present flag set and no ACL), which Microsoft documents as granting
full access to any user, is graded as Everyone (`S-1-1-0`) holding every right of the row. A domain
whose DN was not read gets its four rows, never a gap; an
exception while one domain is handled makes its four rows `Not Assessed` and the next domain is still
graded. Detail names SIDs only; display names are resolved for the `Principals` column only, a SID
that cannot be named stays a SID marked `unresolved`, and no decision reads that column. Other
columns: `CatalogueId`, `Severity`, `ObjectKind`, `ObjectDn`, `ReadFrom`, `OwnerSid`, `AceCount`,
`FlaggedSids`, `RightsHeld`, `Undecided`, `AllowlistNote`, `NotRun`.

**Config.** A new versioned table `Acl`, overridable under a new `Acl` key of `-ConfigOverridePath`:
`FlaggedStatus` (`Warning` or `Fail`) and `AdditionalAllowed`, a list of `{ Sid, Objects, Rights,
Reason }` for the operator's legitimate non-default holders (Microsoft documents both replication
rights for the Entra Connect AD DS connector account). A name in place of a SID is refused, and so
are Everyone, Anonymous Logon, Authenticated Users, Users, Guests and RIDs 513, 514 and 515 of any
domain; `*` is not a right. The built-in allowlist, masks, GUIDs, filter and property list are
refused. A finding cites the file for exactly the keys it supplied; the reason of an override entry
that allowed a grant is in `Evidence`.

**Advice.** Section-scoped entries anchored on the Item prefixes the tool writes - DCSync, domain
root control, AdminSDHolder, GPO (and its summary) - and a prefix catch-all with no advice, all ahead
of the unscoped entries: every graded row says "replication", which the unscoped `replication` entry
would otherwise answer with DNS and `repadmin` advice. Each text is Microsoft's own facts, cited in
the map's comment.

**Changed tests, because behaviour legitimately changed.** The two Pester tests and four
Run-Validation asserts that pinned `Test-AdfaDcSyncAce` and `DcSyncRightGuids` now make the same four
claims on the new functions (a Get-Changes-All grant is detected, a deny and a plain read are not,
full control is); the pinned list of `-ConfigOverridePath` sections gains `Acl` (Pester, six places,
and Run-Validation); the five version pins move to 1.26.0; the three help tests expecting "Seven
sections can be named" now expect "Eight"; the count of splatted `Properties` assignments in the
script, which the Laps section pins, goes from 15 to 17 (the lists of `Get-AdfaAclObjectRaw` and
`Get-AdfaAclGpoRaw`). No test was deleted or weakened. The smoke harness's `Get-ADObject` stub gains
a branch for descriptor reads, chosen by `nTSecurityDescriptor` in the property list, ahead of the
C8 `groupPolicyContainer` branch, which is unchanged; `ConvertTo-AdfaAclDescriptor` and
`Resolve-AdfaAclSidName` are stubbed there because `SecurityIdentifier` and
`ActiveDirectorySecurity` do not exist off Windows and the harness must run anywhere.

**Guards shown able to fail.** Nineteen single mutations of the new code, each applied alone to the script, run against the new and migrated Pester tests (the C9 Describe and "Deep security pure logic", PowerShell 7 on Windows) and then reverted byte for byte, SHA-256 checked after each: a right the SID may not hold read as allowed; a failed read turned into `Pass`; an unreachable domain read as reachable; access denied worded as unreachable; `FlaggedStatus` `Pass` accepted by the validator; the collector's wiring dropped from Invoke-Main; the full-control mask off by one; the per-domain loop and the per-GPO loop each cut to the first item; a deny after the allow honoured; inherit-only ACEs graded; the owner not graded; an undecidable account SID passed; the unsigned mask off by one; an empty GPO population passed; the DCSync advice unscoped; Enterprise Read-only DCs allowed every replication right; and the no-DACL guard removed (caught). Eighteen were caught. The one that survived was removing only the `ControlFlags` half of the no-DACL test. The reason first given for it - that `RawSecurityDescriptor.DiscretionaryAcl` is null exactly when `DiscretionaryAclPresent` is clear - is false: a NULL DACL (SDDL `D:NO_ACCESS_CONTROL`) has the flag set and a null `DiscretionaryAcl` (measured on 5.1). The two halves are now separate classes (`DaclAbsent`, `NullDacl`), and the same mutation is caught (see the review paragraph below).

**Found by an independent review of the diff before commit, and fixed in it.** Seventeen findings.
For each defect in behaviour a test was added that fails against the defect, and the fix makes it
pass; each was shown by applying the defect back alone to a scratch copy of the script and running
the C9 and "Deep security" Pester tests (PowerShell 7, 66 tests), restored byte for byte and
checked by SHA-256 after each - all fourteen were caught.

- An object ACE whose object type was the object's own class GUID (for example
  `(OA;;CRWP;19195a5b-...;;<SID>)` on the domain head) was not graded at all, so a real DCSync or
  write-all grant came out `Pass` (two findings). It is now graded as unscoped, for the class and
  every class above it (MS-DTYP 2.5.3.2 and OBJECT_TYPE_LIST: the object itself is level zero and
  a grant there applies to every node below; which class GUID the directory puts at level zero is in
  MS-ADTS, not read in this session, so the whole chain is read as the object - may over-report,
  never under-reports; PORT-PLAN C9d).
- `WriteDacl`, `WriteOwner` and full control inside an object ACE scoped to a property, another class
  or a right were graded as object-wide rights, so a scoped grant was reported as every replication
  right. A scoped ACE now grants only the replication right whose GUID it names.
- A flagged principal was hidden behind `Not Assessed` when the same DACL held one ACE of a type the
  tool does not interpret (two findings). The flagged SID now takes the grade and the Detail names the
  uninterpreted ACEs; with none flagged the row is still `Not Assessed`.
- With the forest root's SID unread, the scoped domain's own Enterprise Admins (-519) and Enterprise
  Read-only DCs (-498) were flagged; they are now undecided (`Not Assessed`).
- `Get-ADDomain` was sent to the run's `-Server`, not to the domain it is about, although the docs said
  every read is; and the test claiming to check it recorded only `-Identity`. It now sends
  `-Server <domain>` (Learn: `-Server` takes a fully qualified domain name) and the stub records it.
- A NULL DACL (present flag set, no ACL) was reported as "no DACL returned". It is its own class and is
  graded as Everyone holding every right, which is what Microsoft documents a null DACL to grant. The
  earlier entry's claim that `DiscretionaryAcl` is null "exactly when" the flag is clear was false and
  is corrected above.
- The groupPolicyContainer default descriptor grants DA, EA, SYSTEM and Creator Owner no control
  access, but the allowlist gave them every right on GPOs as a Learn fact. The Learn rows now hold
  `WriteDacl`, `WriteOwner` and write of all properties; all extended rights and the replication
  rights on GPOs are a separate row per principal, labelled a tool default.
- The RODC article cited by the config says Enterprise Domain Controllers hold `Get-Changes-All` by
  default; the Domain-DNS descriptor does not. ED is now allowed it, in its own row whose origin
  records the disagreement (PORT-PLAN C9d).
- Tests that could not fail: the GPO summary under a `Fail` override; an undecidable owner on a row
  that grades the owner; a deny carrying GENERIC_ALL; the callback-ACE exclusion in the converter.
  Each now has a test, and the reviewer's mutation fails it. The summary's "counts add up" guard could
  never fire as written; it now checks one GPO row per container returned, and a test that makes the
  verdict return no row shows it firing.
- Documentation: the C8 entry's "Twenty single mutations" had been changed to "Nineteen" by this
  change and is restored; the help no longer states that Authenticated Users hold READ_CONTROL on
  AdminSDHolder by default (not published), and now names the SACL caveat of C9a.

Tests changed because behaviour legitimately changed: `Get-AdfaAclAceRight` takes a mandatory
`-ObjectKind`, so its existing callers (two "Deep security" tests, two C9 tests, four Run-Validation
asserts) now pass `-ObjectKind 'DomainRoot'`, with the same expectations; the allowlist test now
declares eighteen rows, not ten, and accepts the `tool default (C9)` origin; the collector test's
`Get-ADDomain` stub records `-Server` and the two `Get-ADDomain` assertions expect it.

**Not verified.** Everything listed in PORT-PLAN C9a and C9d: the .NET type `Get-ADObject` returns for
`nTSecurityDescriptor` and the descriptor parts the module asks for (if the module asks for the SACL
without SeSecurityPrivilege, an ordinary account may get `Not returned:` on every object, and the
documented fallback `DirectorySearcher.SecurityMasks = Dacl | Owner` would be needed); the exception
types of a real refused, unreachable or timed-out read; the real default DACL of the domain head on a
Windows Server 2016 or later schema and of AdminSDHolder (Learn's adschema pages stop at Windows
Server 2012); whether a GPO whose permissions deny this account read is absent from the search; the
time the name lookups of flagged SIDs take. The converter's tests run on Windows only and are skipped
on the Linux CI runner. Not built (PORT-PLAN C9b): the permissions of GPO folders in SYSVOL, group
membership of flagged principals, the SACL. Decisions for the operator to confirm are in PORT-PLAN
C9c, among them every GPO rather than the linked ones, `Warning` rather than the old `Fail`, and a
delegated GPO creator being flagged.

**Vendor sources, all read on Microsoft Learn on 2026-11-16:**

- DS-Replication-Get-Changes - https://learn.microsoft.com/windows/win32/adschema/r-ds-replication-get-changes
- DS-Replication-Get-Changes-All - https://learn.microsoft.com/windows/win32/adschema/r-ds-replication-get-changes-all
- DS-Replication-Get-Changes-In-Filtered-Set - https://learn.microsoft.com/windows/win32/adschema/r-ds-replication-get-changes-in-filtered-set
- Domain-DNS class (default security descriptor, schemaIDGUID) - https://learn.microsoft.com/windows/win32/adschema/c-domaindns
- Group-Policy-Container class (default security descriptor) - https://learn.microsoft.com/windows/win32/adschema/c-grouppolicycontainer
- Container class (schemaIDGUID, subclass of top; not stated to be AdminSDHolder's descriptor) - https://learn.microsoft.com/windows/win32/adschema/c-container
- Domain class (schemaIDGUID, the superclass of domainDNS) - https://learn.microsoft.com/windows/win32/adschema/c-domain
- Top class (schemaIDGUID) - https://learn.microsoft.com/windows/win32/adschema/c-top
- OBJECT_TYPE_LIST ("Level zero indicates the object itself") - https://learn.microsoft.com/windows/win32/api/winnt/ns-winnt-object_type_list
- ACEs to control access to an object's properties (rights granted at a higher level apply to the lower levels) - https://learn.microsoft.com/windows/win32/secauthz/aces-to-control-access-to-an-object-s-properties
- Null DACLs and empty DACLs ("A null DACL grants full access to any user that requests it") - https://learn.microsoft.com/windows/win32/secauthz/null-dacls-and-empty-dacls
- Get-ADDomain (-Server takes a fully qualified domain name) - https://learn.microsoft.com/powershell/module/activedirectory/get-addomain
- Defender for Identity posture assessments ("the CN=AdminSDHolder container") - https://learn.microsoft.com/defender-for-identity/security-posture-assessments/accounts
- Replication error 8453 (default holders, Enterprise Read-only DCs and RODCPREP) - https://learn.microsoft.com/troubleshoot/windows-server/active-directory/replication-error-8453
- RODC replicates passwords because of incorrect permissions - https://learn.microsoft.com/troubleshoot/windows-server/active-directory/rodc-replicates-passwords-grant-incorrect-permissions
- Appendix C: protected accounts and groups (AdminSDHolder, its owner and writers, SDProp) - https://learn.microsoft.com/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory
- Security identifiers - https://learn.microsoft.com/windows-server/identity/ad-ds/manage/understand-security-identifiers
- Security groups (Enterprise Read-only Domain Controllers, RID 498) - https://learn.microsoft.com/windows-server/identity/ad-ds/manage/understand-security-groups
- SID strings (SDDL abbreviations) - https://learn.microsoft.com/windows/win32/secauthz/sid-strings
- nTSecurityDescriptor attribute - https://learn.microsoft.com/windows/win32/adschema/a-ntsecuritydescriptor
- LDAP_SERVER_SD_FLAGS_OID - https://learn.microsoft.com/openspecs/windows_protocols/ms-adts/3888c2b7-35b9-45b7-afeb-b772aa932dd0
- Reading an object's security descriptor (READ_CONTROL, SE_SECURITY_NAME) - https://learn.microsoft.com/windows/win32/ad/reading-an-objectampaposs-security-descriptor
- Access control and read operations (a search succeeds without unreadable properties) - https://learn.microsoft.com/windows/win32/ad/access-control-and-read-operations
- Get-ADObject - https://learn.microsoft.com/powershell/module/activedirectory/get-adobject
- DirectorySearcher.SecurityMasks (documented alternative, not used) - https://learn.microsoft.com/dotnet/api/system.directoryservices.directorysearcher.securitymasks
- ActiveDirectorySecurity (Persist writes to storage) - https://learn.microsoft.com/dotnet/api/system.directoryservices.activedirectorysecurity
- DirectoryObjectSecurity.GetAccessRules - https://learn.microsoft.com/dotnet/api/system.security.accesscontrol.directoryobjectsecurity.getaccessrules
- ActiveDirectoryRights (GenericAll 983551, GenericWrite 131112) - https://learn.microsoft.com/dotnet/api/system.directoryservices.activedirectoryrights
- ActiveDirectoryAccessRule - https://learn.microsoft.com/dotnet/api/system.directoryservices.activedirectoryaccessrule
- ADS_RIGHTS_ENUM (access mask bits; no object type = all properties, all extended rights) - https://learn.microsoft.com/windows/win32/api/iads/ne-iads-ads_rights_enum
- ACE_HEADER (inherit-only) - https://learn.microsoft.com/windows/win32/api/winnt/ns-winnt-ace_header
- Setting rights to specific types of objects (InheritedObjectType without inherit-only is effective on the container) - https://learn.microsoft.com/windows/win32/ad/setting-rights-to-specific-types-of-objects
- MS-DTYP access check (order, deny, owner's implicit rights, null and empty DACL) - https://learn.microsoft.com/openspecs/windows_protocols/ms-dtyp/4f1bbcbb-814a-4c70-a11e-2a5b8779a6f9
- Owner of a new object (implicit WRITE_DAC) - https://learn.microsoft.com/windows/win32/secauthz/owner-of-a-new-object
- ControlFlags (DiscretionaryAclPresent) - https://learn.microsoft.com/dotnet/api/system.security.accesscontrol.controlflags
- AceFlags (InheritOnly, Inherited) - https://learn.microsoft.com/dotnet/api/system.security.accesscontrol.aceflags
- ObjectAce - https://learn.microsoft.com/dotnet/api/system.security.accesscontrol.objectace
- ObjectAceFlags - https://learn.microsoft.com/dotnet/api/system.security.accesscontrol.objectaceflags
- RawSecurityDescriptor constructors - https://learn.microsoft.com/dotnet/api/system.security.accesscontrol.rawsecuritydescriptor.-ctor
- SecurityIdentifier.Translate (IdentityNotMappedException) - https://learn.microsoft.com/dotnet/api/system.security.principal.securityidentifier.translate
- Password writeback access rights (Entra Connect connector account holds both replication rights) - https://learn.microsoft.com/troubleshoot/entra/entra-id/user-prov-sync/password-writeback-access-rights-permissions
- Default GPO GUIDs - https://learn.microsoft.com/troubleshoot/windows-server/group-policy/rebuild-sysvol-tree-and-content-in-a-domain

Not published on Learn, and handled as such: the .NET type and descriptor parts of
`Get-ADObject -Properties nTSecurityDescriptor`; the full default DACL of the domain head on later
schemas and of AdminSDHolder; the numeric OID of the SD flags control (not cited); AdminSDHolder's
object class; which class GUID the directory places at level zero of the object type list (MS-ADTS,
not retrieved in this session).

### Added — 2026-11-16 (GPO version consistency: directory versionNumber against GPT.INI in SYSVOL, read from the PDC emulator, tool v1.25.0)

**PORT-PLAN C8.** New rows in the existing `Gpo` section (report section `GPO Inventory`), so no
new `-Sections` value: the inventory rows (linked / unlinked GPOs, through the GroupPolicy module)
are unchanged and the version rows follow them. It addresses ADA-GPO-001 (GPO AD version differs
from SYSVOL GPT.INI), for which the tool had nothing.

**This has run only against stubs.** No `Get-ADObject` call, SMB probe, folder listing or file
read in it has met a real domain controller. The first run against a real forest is PORT-PLAN C17,
owned by the operator, and PORT-PLAN C8a lists what that run must confirm for this row - among
them the exception types a real SYSVOL read throws (on which the `Not found:` / `Access denied:` /
`Unreachable:` wording rests), and the type `Get-ADObject` returns for `versionNumber`.

**Instrument.** The brief preferred the GroupPolicy module's Gpo object (`Computer.DSVersion`,
`Computer.SysvolVersion` and the user pair) with a directory-plus-SYSVOL read as the fallback.
Microsoft Learn documents only `Get-GPO`'s formatted output ("AD Version: n, SysVol Version: n"),
not those members, and does not say which DC's SYSVOL it reads; MS-GPOL on Learn specifies the
directory attribute, the file and their layout completely. So the version check does not use the
module at all - it runs the same way with or without RSAT GPMC - and the module's properties are
left to C17 as a second instrument (PORT-PLAN C8b).

**What it reads, and nothing else.** Per scoped domain, all from the domain's **PDC emulator**
(Learn: `Get-GPO` contacts it by default, and the Group Policy Object Editor uses it unless
configured otherwise), so that a difference is a difference on one DC, not between two:

- `Get-ADDomain -Identity <domain>` for the PDC and the domain's DN.
- `Get-ADObject -Server <PDC> -SearchBase CN=Policies,CN=System,<DN> -SearchScope OneLevel
  -LDAPFilter '(objectClass=groupPolicyContainer)'`, asking for `versionNumber`, `gPCFileSysPath`,
  `displayName` and `flags` only. A wildcard or blank in the list is refused before any call.
- `Test-AdfaDcPort <PDC> 445` (the per-run probe cache). With no answer nothing in SYSVOL is read,
  so a UNC "not found" is never taken from a host that did not answer.
- `[System.IO.Directory]::GetDirectories('\\<PDC>\SYSVOL\<domain>\Policies')`, and each GPO's
  `GPT.INI` through `[System.IO.FileStream]::new(path, Open, FileAccess.Read, FileShare.ReadWrite
  -bor FileShare.Delete)`: read access only, and no other open of the file - for reading, writing
  or delete - refused while it is held, so a GPMC save or a DFSR install of that file on the PDC
  is never made to fail by this read. At most 64 KB (a tool default; a larger file is not taken).
  A GPO whose folder the listing does not hold is not read. When the listing fails, the files are
  read one by one only after an access-denied listing (a folder can refuse a listing and still let
  its files be read; a tool rule, `ReadFilesAfterListingClass`); after an unreachable, timed-out,
  not-found or uninterpreted failure no file is read, because each read would go to the path that
  just failed with no timeout of its own, and every GPO is `Not Assessed` with the listing's class.
  File reads run as the account running the script: `-Credential` is not passed to them.

The `GPT.INI` path is built from the PDC's name and the container's GUID. **The host written in
`gPCFileSysPath` is never contacted**: it is a directory string, and reading a path it names would
send this account's credentials to whatever host was written there. A `gPCFileSysPath` that is not
`\\<domain>\sysvol\<domain>\policies\<GUID>` for this domain and GPO (case-insensitive) makes the
GPO `Not Assessed`. Nothing is written: no `Set-GP*`, no `Backup-GPO`, no `Import-GPO`, no
`gpupdate`, and `GPT.INI` is never opened for writing (the MS-GPOL editing sequence opens it
read/write; this does not). A test reads the parsed script and pins, as a whitelist, every command
(29), every static .NET call with its type and calling function (13), every instance method (11),
every `New-Object` type (2) and every `System.IO` type literal the row's 18 functions use, and the
four arguments of the one file open; any addition fails it, whatever its name. It also pins the two
AD reads and the one probe by function, and still refuses by name any write parameter, external
tool, `Get-GPO` or direct `Test-TcpPort`.

**What it reports.**

| Row | Results |
| --- | --- |
| `GPO version: {GUID}` | Only when there is something to say. `Warning` when the whole 32-bit numbers differ (a **tool default**, the catalogue rule ADA-GPO-001; `Fail` by override), naming the half that differs - user (upper 16 bits) or computer (lower 16 bits) - and both numbers with their halves, and saying it can be replication still in flight. `Not Assessed`, each cause in its own words: `Unreachable:` (SMB did not answer, or the network path), `Access denied:`, `Timed out:`, `Not found:` (the GPO's folder is not on this DC although the folder was listed - an orphaned container or a folder not yet replicated; or the folder holds no `GPT.INI`; or not found with the listing unread, said), `Not parsed:` (no `[General]` section, no or two `Version` keys, not a whole number, not 32 bits), `Not returned:` (`versionNumber`), `Not read:` (above the size bound), `Not assessed:` (`gPCFileSysPath` not the GPO's folder, or a container name that is not a GUID). The numbers that were read are in their columns even then |
| `GPO folder without container: {GUID}` | `Warning` (tool default; `Info` by override): a folder under `Policies` named by a GPO GUID with no container visible to this account - Microsoft's "orphaned GPO" in the file system - worded so, because a container this account cannot read looks the same. Folders not named by a GUID (`PolicyDefinitions`) are counted in the summary and not graded |
| `GPO folder listing: <domain>` | `Not Assessed` when the `Policies` folder was not listed, with the cause |
| `GPO version summary: <domain>` | One per scoped domain, always. The declared population (containers returned), `Compared`, `Mismatched`, `NotAssessedCount` and `FoldersWithoutContainer` in their own columns. `Pass` only when at least one container was read, every one was compared and none differs; the mismatch status when any differs; otherwise `Not Assessed`. No container at all is `Not Assessed` (a domain holds at least the Default Domain Policy). A failed PDC lookup or container query gives this row only, worded by class from the exception type: `Unreachable:`, `Access denied:`, `Timed out:` or `Read failed:` |
| `GPO version (no domain scoped)`, `GPO version` | `Not Assessed`: no domain scoped; the forest unreadable |

A number that was not measured is empty, never 0. Every row's `Evidence` names what was measured:
`none`, `directory`, `SYSVOL` or `directory and SYSVOL`; the summary names SYSVOL only when the
`Policies` folder was listed or a `GPT.INI` version read. The GPO's display name (free text anyone allowed
to edit the GPO can set) and its `gPCFileSysPath` are in their own columns (`GPOName`,
`FileSysPath`), never in `Item` or `Detail`, which the recommendation is chosen from.

**Vendor facts and where Microsoft is silent.** From MS-GPOL on Learn: the user version is the upper
16 bits and the machine version the lower 16 bits of a GPO version, for `versionNumber` and for the
`GPT.INI` `Version` alike (this supersedes the AdAssessment26 reference's N30, which recorded the
split as not published); `GPT.INI` is ANSI and its `[General]` section is required; both versions
are updated together on every edit; the four `flags` values. `versionNumber` has the Enumeration
syntax, a signed Int32, so a user half of 32768 or more reads as a negative number and is taken as
its 32-bit pattern - an **inference** from the type, tested at -2147418111 (user 32769). A UTF-16 or
UTF-8 `GPT.INI` is tolerated and named in the `Encoding` column. Microsoft publishes **no grade** for
a difference and **no time** after which one stops being transient: the `Warning` and the advice
("run again once replication has converged") are this tool's, labelled in the row and the config.

**Config.** A new versioned table `Gpo`, overridable under a new `Gpo` key of `-ConfigOverridePath`
(`MismatchStatus` Warning or Fail, `OrphanFolderStatus` Warning or Info). The filter, the property
list, the share, the folder and file names, the port, the size bound and the sources are refused, so
a file cannot make the tool read another path or ask for every attribute. A finding cites the file
for exactly the keys it supplied.

**Advice.** Section-scoped recommendation entries anchored on the Item prefixes the tool writes -
the mismatch family (`GPO version: {` and `GPO version summary: `) and the folder family - and a
`GPO version|folder` prefix catch-all with no advice, all ahead of the unscoped entries: every
version row says SYSVOL and replication, which the unscoped `sysvol|dfsr` and `replication`
entries would otherwise answer with restore advice (`dfsrmig`, D2/D4, `repadmin /replicate`). No
section-wide catch-all, so the inventory's older rows, whose Item is the section name, keep exactly
the advice they had (a test compares with the map before C8).

**The old inventory.** `Get-AdfaGpoInventory` is unchanged except its catch-all: the `(enumeration
failed)` row keeps its four columns (`Scope`, `GPOName`, `Status`, `Detail`) and its Detail now
leads with the class (`Access denied:`, `Unreachable:`, ...), counts the rows written before the
failure and says it is not a clean result. Its help no longer claims WMI filters, which no code read.
One defect on main is fixed: an unlinked GPO's report has no `LinksTo` element, and reading
`$rep.GPO.LinksTo` under StrictMode threw `PropertyNotFoundException`, so every domain holding one
unlinked GPO lost its inventory to the catch-all. The element is now read through
`PSObject.Properties`; the linked and unlinked rows are unchanged in shape and text, and a new test
pins them from a stubbed `Get-GPO` (it failed before the fix).

**Changed tests, because behaviour legitimately changed.** The pinned list of `-ConfigOverridePath`
sections gains `Gpo` (Pester, five places, and Run-Validation); the four version pins move to
1.25.0; the two help tests expecting "Six sections can be named" now expect "Seven"; the count of
splatted `Properties` assignments in the script, which the Laps section pins, goes from 14 to 15
(the list of `Get-AdfaGpoContainerRaw`). The smoke harness's `Get-ADDomain` stub now remembers the
`-Identity` it was last asked for, so the new `groupPolicyContainer` stub can answer per domain;
everything it returns is unchanged. No test was deleted or weakened. One C8 test named "keeps the
module-missing row and the inventory rows as they were" asserted only the module-missing row; it is
renamed to say so, and a new test asserts the inventory rows.

**Guards shown able to fail.** Twenty single mutations of the new code, each applied alone, run
against the 49 new Pester tests and then reverted byte for byte (SHA-256 checked after each): an
equal pair read as a mismatch, a GPO not compared turned into a domain `Pass`, the SMB probe ignored
(in the seam and in the verdict), access denied reported as unreachable, the override validation
removed, the collector's wiring dropped, the 32-bit bound and the empty-population bound each off
by one, the per-domain loop and the per-GPO loop each cut to the first item, the negative-Int32
mask removed, orphan-folder detection off, the `gPCFileSysPath` host trusted, the size bound off by
one, an unlisted folder still read, the recommendation entries unscoped, the halves swapped, keys
read outside `[General]`, a mismatch not counted. All twenty were caught. One test helper returned
a single row that Windows PowerShell 5.1 unrolled to a scalar; its call sites are wrapped in `@()`.

**Found by an independent review of the diff before commit, and fixed in it.**

- The summary row claimed `Evidence` "directory and SYSVOL" even when nothing in SYSVOL was read
  (SMB silent, every read failed, no container). It is now derived from what was read, as on the
  GPO rows; no test had read `Evidence` on any C8 row, and now the normal, empty, unreachable,
  access-denied, mixed and failed-query tests do.
- A JSON list such as `["Fail"]` for `MismatchStatus` was refused with a message saying `'Fail'`
  was refused. A value that is not one text value is now refused by its type.
- After a listing that failed as unreachable or timed out, every `GPT.INI` was still read, each
  with no timeout of its own. Files are now read after a failed listing only when it was refused
  as access denied (PORT-PLAN C8d keeps the time bound that is still missing).
- `File.OpenRead` shares the file for reading only, so a GPMC save or DFSR install of the same
  `GPT.INI` on the PDC would have been refused while the tool held it. It is now opened with
  `FileShare.ReadWrite | FileShare.Delete`; a test holds the file open for writing and reads it.
- The no-write AST test was a blacklist with gaps (`Set-Acl`, `[IO.File]::ReadAllBytes`,
  `[IO.Directory]::EnumerateFiles` passed it), and this entry overclaimed it. It is now a whitelist.
- `SecurityException` was read as access denied; Learn says .NET Framework throws it only in
  limited trust, not for a refused file, so it is now an uninterpreted error.
- Guards not shown able to fail now have tests: error codes 2 and 1232, `DriveNotFoundException`,
  the UTF-16BE byte-order mark, a domain name that is not a DNS name, a `Get-ADDomain` answer with
  a PDC and no DN, a `UInt64` version at and above 32 bits and at its maximum, and `flags` values
  above 3. The `';'` comment rule of the `GPT.INI` parser was dead code (a commented key reads as
  `;Version`, never `Version`) and is removed; a test shows a commented `Version` beside the real
  one is neither taken nor counted twice.
- A code comment quoted the MS-GPOL GPO path form from 3.1.1, which does not hold it; it is in the
  glossary, and the comment now cites each quotation to its page.
- The test for the inventory claimed to cover its rows and did not; see "The old inventory".

Twenty-one mutations were run for these, each alone on a scratch copy against the 53 C8 tests
under Windows PowerShell 5.1 and restored byte for byte (SHA-256 checked): each fix reverted, and
each mutation the review reported as surviving. Twenty were caught. The one that survives - the
`UInt64` bound raised from 4294967295 to 4294967296 - is equivalent: the general 32-bit range check
after it refuses 4294967296 either way. The bound exists to stop a larger `UInt64` overflowing the
cast to `Int64`, and removing it is caught (`[UInt64]::MaxValue`).

**Not verified.** Everything listed in PORT-PLAN C8a: the exception types and HResults of a real
SYSVOL read (missing folder, missing file, refused, share absent, dropped session); the type of
`versionNumber` from `Get-ADObject`; whether a read can hang past the bounded SMB probe; the
`gPCFileSysPath` values of a real domain; the encodings GPMC writes; that the shared open leaves a
real GPMC save and DFSR install unaffected (PORT-PLAN C8d). No time bound on the reads once the
listing succeeded (C8d). Not built: the other DCs'
SYSVOL copies, the `User` / `Machine` subfolders and the ACL comparison (PORT-PLAN C8c). Decisions
for the operator to confirm are in PORT-PLAN C8b, among them `Warning` rather than the brief's
`Fail` and the module not being used.

**Vendor sources, all read on Microsoft Learn on 2026-11-16:**

- MS-GPOL glossary (user and machine GPO version, container and file system version, GPO path) -
  https://learn.microsoft.com/openspecs/windows_protocols/ms-gpol/2f362c13-9a2d-469b-8c4b-7b4045258995
- MS-GPOL GPO search: groupPolicyContainer attributes, versionNumber, gpt.ini format and encoding,
  flags, cn and displayName - https://learn.microsoft.com/openspecs/windows_protocols/ms-gpol/b0e5c9e8-e858-4a7a-a94a-4a3d0a9d87a2
- MS-GPOL sample gpt.ini - https://learn.microsoft.com/openspecs/windows_protocols/ms-gpol/ab105255-75e9-44d9-aa8f-22f61c270bfa
- MS-GPOL version update on edit - https://learn.microsoft.com/openspecs/windows_protocols/ms-gpol/70fd86b1-926a-4dcf-9ce7-6f9d2149c20d
- MS-GPOL admin-tool increment of each half - https://learn.microsoft.com/openspecs/windows_protocols/ms-gpol/59bb540a-64f4-4c52-9c55-5ca2fd2c0270
- MS-GPOL client version comparison - https://learn.microsoft.com/openspecs/windows_protocols/ms-gpol/bc953fef-0ca0-495f-8097-20772b3f6a6e
- MS-GPOL client gpt.ini read - https://learn.microsoft.com/openspecs/windows_protocols/ms-gpol/5c7ecdad-469f-4b30-94b3-450b7fff868f
- MS-GPOL 3.1.1 Server Abstract Data Model (a GPO path MUST be available; the GUID in the GPO DN
  and the GPO path MUST be the same; the path's UNC form is in the glossary above) -
  https://learn.microsoft.com/openspecs/windows_protocols/ms-gpol/34f68012-77c5-4487-837f-84a23829273b
- versionNumber schema (2.5.5.9) - https://learn.microsoft.com/openspecs/windows_protocols/ms-ada3/5e517dde-c710-45fa-b694-2704e17b5612
  and Enumeration syntax - https://learn.microsoft.com/windows/win32/adschema/s-enumeration
- gPCFileSysPath schema (single-valued, not in the GC; its Learn description text is a defect and is
  not quoted) - https://learn.microsoft.com/windows/win32/adschema/a-gpcfilesyspath
- groupPolicyContainer class (default security descriptor) - https://learn.microsoft.com/windows/win32/adschema/c-grouppolicycontainer
- Get-GPO (-Server, PDC emulator by default, formatted version output) - https://learn.microsoft.com/powershell/module/grouppolicy/get-gpo
- Group Policy CSP, GPDCOptions (PDC Operations Master by default) - https://learn.microsoft.com/windows/client-management/mdm/policy-csp-admx-grouppolicy
- Group Policy processing (AD and SYSVOL replicate independently; DFSR every 15 minutes within a
  site) - https://learn.microsoft.com/windows-server/identity/ad-ds/manage/group-policy/group-policy-processing
- Rebuild the SYSVOL tree (orphaned GPO in the file system; container with no folder on any DC) -
  https://learn.microsoft.com/troubleshoot/windows-server/group-policy/rebuild-sysvol-tree-and-content-in-a-domain
- Service overview and network port requirements (SMB TCP 445) -
  https://learn.microsoft.com/troubleshoot/windows-server/networking/service-overview-and-network-port-requirements
- System error codes 2, 3, 5, 51, 53, 64, 65, 67 - https://learn.microsoft.com/windows/win32/debug/system-error-codes--0-499-
  and 1231, 1232 - https://learn.microsoft.com/windows/win32/debug/system-error-codes--1000-1299-
- Handling I/O errors in .NET (error code to exception mapping; HResult low 16 bits;
  SecurityException only in limited trust on .NET Framework) -
  https://learn.microsoft.com/dotnet/standard/io/handling-io-errors
- DriveNotFoundException (a drive or share not available; COR_E_DIRECTORYNOTFOUND, thrown on
  ERROR_PATH_NOT_FOUND) - https://learn.microsoft.com/dotnet/api/system.io.drivenotfoundexception
- FileStream(String, FileMode, FileAccess, FileShare) - https://learn.microsoft.com/dotnet/api/system.io.filestream.-ctor
  and FileShare (Read, Write, ReadWrite, Delete; without Write "any request to open the file for
  writing ... will fail until the file is closed") - https://learn.microsoft.com/dotnet/api/system.io.fileshare
- File.OpenRead (FileAccess.Read, FileShare.Read; the open this row no longer uses) -
  https://learn.microsoft.com/dotnet/api/system.io.file.openread
  and File.ReadAllBytes exceptions - https://learn.microsoft.com/dotnet/api/system.io.file.readallbytes
- Get-Credential notes (the Credential parameter is not supported by every provider) -
  https://learn.microsoft.com/powershell/module/microsoft.powershell.security/get-credential

### Added — 2026-11-16 (SID history: principals with sIDHistory, same-domain and privileged historic SIDs, their source domains, tool v1.24.0)

**PORT-PLAN C7.** Four new rows per scoped domain in the existing `SecurityPosture` section
(report section `Security Posture`), so no new `-Sections` value: the section already runs per
domain, and its older rows (krbtgt password age, AD Recycle Bin, tombstone lifetime, machine
account quota, DES/reversible-encryption accounts) are unchanged. It addresses ADA-OBJ-009
(SIDHistory populated), for which the tool had nothing; the reference rule is "Warning when count >
0", and the same-domain, privileged and source-domain rows are this tool's additions.

**This has run only against stubs.** No `Get-ADDomain` or `Get-ADObject` call in it has met a
real domain controller. The first run against a real forest is PORT-PLAN C17, owned by the
operator, and PORT-PLAN C7a lists what that run must confirm for this row - among them what the
ActiveDirectory module actually returns for `sIDHistory` (bytes, `SecurityIdentifier` objects or a
collection of either: Learn does not say, so all three are read), and the exception types behind
the `Unreachable:` / `Access denied:` / `Timed out:` wording.

**What it reads, and nothing else.** Directory reads only, with domain read access:

- **Per scoped domain** (`Get-AdfaSidHistoryRaw`): `Get-ADDomain -Identity <domain>` for the
  domain's DN and SID; `Get-ADObject -LDAPFilter '(sIDHistory=*)' -Server <domain>` asking for
  `sIDHistory`, `objectSid`, `objectClass`, `sAMAccountName`, `distinguishedName` and
  `userAccountControl` only, paged by the module; and `Get-ADObject -LDAPFilter
  '(objectClass=trustedDomain)' -SearchBase CN=System,<domain DN>` asking for `securityIdentifier`,
  `trustPartner` and `flatName`. A property list holding a wildcard or a blank is refused before
  any call. The three reads are independent: a domain SID or a trust read that fails leaves the
  principals.
- **Once per run** (`Get-AdfaSidHistoryForestMap`): `Get-ADDomain` for the SID of every domain of
  the forest, to name the domain a historic SID came from.

Nothing is written. `sIDHistory` is never removed or changed: Microsoft's own remediation
(`Set-ADUser -Remove @{SIDHistory=...}`) is quoted in the advice and never run, and `netdom` and
`Forest.SetSidFilteringStatus` are not used. A test reads the parsed script and fails on any
state-changing cmdlet, any write parameter (`-Remove`, `-Replace`, `-Add`, `-Clear`), any ADSI
write, any external tool, and on any directory call in the row other than the four declared.

**What it reports.**

| Row | Results |
| --- | --- |
| `SID history: <domain>` | `Warning` when any principal carries SID history (a **tool default**, the catalogue rule; `Info` by override), with counts by class (user, computer - managed service accounts included, group, other) and enabled state (from `userAccountControl`, never for a group), and the names up to `NameListCap` (25, a tool default) with the number not listed; `Pass` when the query succeeded and returned none, worded "None visible: ... visible to this account" |
| `SID history same-domain: <domain>` | `Fail` when a historic SID's domain part equals the domain's own SID; `Pass`, also when no principal was returned; `Not Assessed` when the domain SID was not read, or when a value could not be parsed or a returned principal had no `sIDHistory` value read and none failed (a Fail found stands) |
| `SID history privileged: <domain>` | `Fail` when a historic SID is a privileged RID (500, 502, 512, 516, 517, 518, 519, 520, 526, 527 - on an account-domain SID `S-1-5-21-x-y-z-RID` only) or SID (`S-1-5-32-544`, `-548`, `-549`, `-550`, `-551`, `S-1-5-9`), naming each by name and count in Detail ("Domain Admins (RID 512) x1", "Administrators (well-known SID) x1") and the SIDs in `HistoricSids`; `Pass`; `Not Assessed` as above |
| `SID history sources: <domain>` | `Info`: each distinct domain part with its count, labelled as a domain of this forest, a trust partner of this domain, builtin or well-known, not an account-domain SID, or "unresolved" - never "foreign" or "deleted" - and saying when the forest's SIDs or the trusts were read only in part, or a principal had no value read; `Not Assessed` when principals were returned and no value was read on any of them |
| `SID history (no domain scoped)`, `SID history` | `Not Assessed`: no domain scoped; the forest unreadable |

A principal query that failed makes all four rows of that domain `Not Assessed` with the cause,
worded by class from the exception type first: `Unreachable:`, `Access denied:`, `Timed out:` or
`Read failed:`. A count that was not measured is empty, never 0. Account names, historic SIDs, the
domain SID and the source domains are in their own columns (`Principals`, `HistoricSids`,
`DomainSid`, `SourceDomains`), never in `Detail`, which the recommendation is chosen from.

**Grades where Microsoft is silent.** Microsoft publishes no grade for SID history that is
present; Defender for Identity publishes no severity for "Unsecure SID History attributes". The
`Warning` is the operator-approved catalogue rule, labelled in the row and the config as a tool
default and overridable to `Info`, never to `Pass`. The same-domain `Fail` is an **inference**,
said in the row: Microsoft documents that DsAddSidHistory requires the source and destination in
different forests "so that duplicate SIDs ... are not created in the same forest", and a move
between domains keeps the SID of the domain left; no Learn page calls a same-domain value an abuse
indicator. The privileged list is this tool's, from Microsoft's well-known SID tables; Microsoft
gives only the Enterprise Admins example. Learn writes Key Admins as `S-1-5-root domain-526` and
Enterprise Key Admins as `S-1-5-domain-527`, the reverse of their names; matching on the RID
alone, the check is not affected (said in the config comment).

**SID parsing, 5.1-safe.** `ConvertFrom-AdfaSidValue` reads bytes, text and objects carrying the
text in `Value`, as `SecurityIdentifier` does. Bytes are checked against the SID layout first
(revision 1, at most 15 sub-authorities, exactly 8 + 4 x count bytes - so trailing bytes, which
.NET would ignore, are refused on every platform alike), the 6-byte authority read big-endian and
each sub-authority as an unsigned 32-bit little-endian number by `[uint64]` arithmetic, never
`[int]`. Where the platform has `SecurityIdentifier(byte[], 0)` it reads the same bytes; a value it
refuses is not read, and a value it reads differently from the fallback is not read either, so the
two parsers are cross-checked on every Windows run (measured: Windows PowerShell 5.1.26100 and
PowerShell 7.6.9 both read `S-1-5-21-1-2-3-4294967295` and a 48-bit authority as the fallback does,
and both throw an `ArgumentException` for a short value or revision 2). No real value reaches the
refusal or the disagreement branch - the layout check refuses first, and the two parsers agree on
every value that passes it - so those two branches are tested through a test-only `-PlatformReader`
seam that no caller in the script uses: a reading that differs, an `ArgumentException` (also
wrapped in a `MethodInvocationException`, as a .NET constructor throws it) and a
`PlatformNotSupportedException` (the fallback's reading stands). Tested on `S-1-5-21-...`
with a RID of 4294967295, every sub-authority at 4294967295, `S-1-5-32-544`, `S-1-5-9`, a 48-bit
authority and 15 sub-authorities, and on eleven malformed values (empty, 3 bytes, revision 2, 16
sub-authorities, one byte short, trailing bytes, non-SID text, a RID above UInt32, a text-form
authority above 2^48 - 1, a number, null): each is "not parsed" with a reason, never an exception. A single byte array is one value and is
never unrolled into its bytes (a test found a test helper doing exactly that).

**Config.** A new versioned table `SidHistory`, overridable under a new `SidHistory` key of
`-ConfigOverridePath` (`PresentStatus` Warning or Info, `NameListCap` a whole number from 0 to
1000). The privileged RIDs and SIDs, the filters, the property lists and the class buckets are
refused, so a file cannot make the tool ask for every attribute or stop a privileged SID from
failing. A finding cites the file for exactly the keys it supplied.

**Advice.** Section-scoped recommendation entries for the three graded families, anchored on the
Item prefix the tool writes (`SID history: `, `SID history same-domain: `, `SID history
privileged: `), plus a `SID history` prefix catch-all with no advice - and no section-wide
catch-all, because the older Security Posture rows rely on the unscoped `krbtgt`, `recycle bin` and
`machine account quota` entries. All four sit ahead of the unscoped entries, so a group name in a
Detail ("KRBTGT", "Backup Operators") cannot reach the `krbtgt` or `backup` advice.

**Changed tests, because behaviour legitimately changed.** The pinned list of
`-ConfigOverridePath` sections gains `SidHistory` (Pester, four places, and Run-Validation); the
three version pins move to 1.24.0; the RidPool help test now expects "Six sections can be named";
the count of splatted `Properties` assignments in the script, which the Laps section pins so that
no new property list goes unreviewed, goes from 12 to 14 (the two lists of
`Get-AdfaSidHistoryRaw`). The smoke harness's `Get-ADDomain` stub now gives each domain its own
SID (keyed by `-Identity`; a call naming no domain gets contoso.com's, as before).

**Found by an independent review of the diff before commit, and fixed in it.**

- **Principals returned with no `sIDHistory` value made the same-domain and privileged rows
  `Pass`.** An object returned for `(sIDHistory=*)` whose value was missing, `$null` or an empty
  collection became a record with no history; the count row said `Warning`, and the same-domain and
  privileged rows passed with "None visible", because they tested only the number of values. Those
  rows now pass only when no principal was returned. Principals returned with no value read on any
  of them make the same-domain, privileged and sources rows `Not Assessed`. When some values were
  read, the principals with none are counted in the rows (`Not Assessed` unless a Fail is found,
  which stands), and the count row says how many came back with no value. On a live domain controller
  this is unlikely, because the same access governs the filter and the value, but the guard was
  missing in the code. It was reproduced with a stub.
- **A `|` in a distinguished name corrupted the `Principals` and `HistoricSids` columns** of the
  same-domain and privileged rows (`CN=x|y,...` with sAMAccountName `alice` read as
  `y,...|alice`). The name was recovered by splitting the grouping key at the first `|`, and RFC 4514
  needs no escaping for `|` in a DN. The name is now kept on its own, and the grouping key starts
  with the DN's length, so two principals cannot share one key.
- **The privileged row put fixed SIDs in Detail** ("Administrators (S-1-5-32-544)"), while the help,
  README, PORT-PLAN and this entry say SIDs never go there. Detail now reads "Administrators
  (well-known SID)" or "Domain Admins (RID 512)", and the SIDs are only in `HistoricSids`. The
  Pester guard that checked only `S-1-5-21-` now refuses any `S-1-` in the Detail of every row.
- **Guards no test could fail**, each now killed by a test:
  - The platform/fallback cross-check and the platform-refusal branch of `ConvertFrom-AdfaSidValue`
    could not be reached, because no real value gets through the layout check to either. They are
    now tested through the `-PlatformReader` seam described above.
  - The "builtin or well-known" label for `S-1-5-9` (one sub-authority), and "not an account-domain
    SID" for `S-1-16-12288` and a service SID.
  - `NameListCap` on the same-domain and privileged rows, where only the count row was tested.
  - The most specific `objectClass` taken from the whole chain (`top,person,organizationalPerson,user`)
    as an array and as a list.
  - No enabled state for a group or another class that returns `userAccountControl`.
  - A text-form authority above 2^48 - 1 refused (`S-1-281474976710656-5`), and one at the limit read.

  Existing tests strengthened by the review:
  - The Pester malformed-values test, from ten values to eleven.
  - Run-Validation's malformed values, from eight to nine.
  - Run-Validation's verdict table, from seven reads to eight (adding "no value read").
  - The Detail guard of the "present" test, from `S-1-5-21-` to `S-1-`.

  No test was deleted or weakened.

**Not verified.** Everything listed in PORT-PLAN C7a; whether a trust filters SID history is left to
the Trusts section (cross-referenced in the rows' NotRun note); the trusted domain objects of other
forest domains, and the Security-log "Add Sid History" events, are not read (PORT-PLAN C7c).
Decisions for the operator to confirm are in PORT-PLAN C7b.

**Vendor sources, all read on Microsoft Learn on 2026-11-16:**

- sIDHistory attribute (syntax, multi-valued, GC, search flags, Security-Principal) -
  https://learn.microsoft.com/windows/win32/adschema/a-sidhistory
- String(Sid) syntax (octet string, System.Byte[]) - https://learn.microsoft.com/windows/win32/adschema/s-string-sid
- user and group classes (Security-Principal auxiliary class; default security descriptors) -
  https://learn.microsoft.com/windows/win32/adschema/c-user and https://learn.microsoft.com/windows/win32/adschema/c-group
- General-Information property set (SID-History, Object-Sid) - https://learn.microsoft.com/windows/win32/adschema/r-general-information
- trustedDomain class and securityIdentifier - https://learn.microsoft.com/windows/win32/adschema/c-trusteddomain and
  https://learn.microsoft.com/windows/win32/adschema/a-securityidentifier
- objectSid - https://learn.microsoft.com/windows/win32/adschema/a-objectsid
- Access control and read operations - https://learn.microsoft.com/windows/win32/ad/access-control-and-read-operations
- Security identifiers (SIDHistory multi-valued and in the token; domain identifier and RID;
  well-known SID table) - https://learn.microsoft.com/windows-server/identity/ad-ds/manage/understand-security-identifiers
- Well-known SIDs (aliases 0x220.., Key Admins 0x20E, Enterprise Key Admins 0x20F) -
  https://learn.microsoft.com/windows/win32/secauthz/well-known-sids
- SID structure (MS-DTYP 2.4.2.2) - https://learn.microsoft.com/openspecs/windows_protocols/ms-dtyp/f992ad60-0fe4-4b87-9fed-beb478836861
- SecurityIdentifier(Byte[], Int32) - https://learn.microsoft.com/dotnet/api/system.security.principal.securityidentifier.-ctor
- Defender for Identity, Unsecure SID History attributes (no severity published) -
  https://learn.microsoft.com/defender-for-identity/security-posture-assessments/accounts
- Defender for Identity alert "Suspected SID-History injection" (external ID 1106) -
  https://learn.microsoft.com/defender-for-identity/alerts-mdi-classic
- Using DsAddSidHistory - https://learn.microsoft.com/windows/win32/ad/using-dsaddsidhistory
- Planning for compromise ("eliminating SID history") -
  https://learn.microsoft.com/windows-server/identity/ad-ds/plan/security-best-practices/planning-for-compromise
- netdom trust /quarantine - https://learn.microsoft.com/windows-server/administration/windows-commands/netdom-trust
- Get-ADObject (paging defaults) - https://learn.microsoft.com/powershell/module/activedirectory/get-adobject
- userAccountControl ACCOUNTDISABLE - https://learn.microsoft.com/troubleshoot/windows-server/active-directory/useraccountcontrol-manipulate-account-properties

### Added — 2026-11-16 (RID pool: allocation enabled, global RID space issued, each DC's RID pool, tool v1.23.0)

**PORT-PLAN C6.** New `-Sections RidPool` (report section `RID Pool`), included in the default
`All` run. It addresses three rows of the gap analysis for which the tool had nothing:
ADA-RID-001 (RID pool allocation disabled), ADA-RID-002 (global RID space consumption) and
ADA-INV-004 (per-DC RID pool). The differences from the catalogue rules are listed below.

**This has run only against stubs.** No part of it has been executed against a real directory:
no `Get-ADDomain`, `Get-ADObject` or `Get-ADComputer` call in it has met a real domain
controller. The first run against a real forest is PORT-PLAN C17, owned by the operator, and
PORT-PLAN C6a lists what that run must confirm for this row.

**What it reads, and nothing else.** Directory reads only, with domain read access:

- **Per scoped domain** (`Get-AdfaRidManagerRaw`): `Get-ADDomain -Identity <domain>` for the
  domain's DN and its RID master (`RIDMaster`, the same property the Domains and Fsmo sections
  read, read again here so this section does not depend on either having run); then
  `Get-ADObject` on `CN=RID Manager$,CN=System,<domain DN>` with `-Server` set to the domain,
  twice: once for `rIDAvailablePool` and once for `msDS-RIDPoolAllocationEnabled`, so that a
  schema without the second attribute cannot take the first away.
- **Once per run**: the forest schema, through the same seam the Laps section uses
  (`Get-AdfaLapsSchemaRaw`), asked whether it defines `msDS-RIDPoolAllocationEnabled`, with
  `rIDAvailablePool` as the control - so "not set", "not in the schema" and "the schema could not
  be read" are three different results.
- **Per DC** (`Get-AdfaDcRidSetRaw`): the DC's computer object by `dNSHostName`, asked for
  `rIDSetReferences` only; the RID Set object it names, asked for `rIDPreviousAllocationPool`,
  `rIDAllocationPool`, `rIDNextRID` and `rIDUsedPool`; and, as a **second instrument** before the
  word "absent" is ever used, a one-level search for `objectClass=rIDSet` under the computer
  object, run when the reference is empty or does not resolve (but not after a refused,
  unreachable or timed-out read, which says nothing about existence).

Nothing is written. No `Set-*` cmdlet, no `-Replace`, no ADSI write path; neither
`msDS-RIDPoolAllocationEnabled` nor `SidCompatibilityVersion` is ever touched (both are documented
writes: the first removes the RID ceiling, the second irreversibly unlocks the 31st bit). No
dcdiag test is run by this section: Microsoft does not say whether `/test:RidManager` requests a
pool (the DC Diagnostics section runs it, unchanged). A test reads the parsed script and fails on
any state-changing cmdlet, any write parameter, any ADSI `Put`/`SetInfo`/`CommitChanges`, any
`DirectoryEntry`, and on any property list in the section other than the five named attributes.

**What it reports.**

| Row | Results |
| --- | --- |
| `RID pool allocation: <domain>` | FALSE `Fail`; TRUE `Pass`; `Not Assessed` when the attribute is not returned (Microsoft documents NOT SET as its default, but also that a read succeeds without the properties the caller may not read, so the two look the same), where the schema does not define it, the schema could not be read, the value is neither TRUE nor FALSE, or the read failed |
| `Global RID space: <domain>` | `Pass` / `Warning` / `Fail` against the size of the space read from the upper half of `rIDAvailablePool`; `Not Assessed` for a size that is neither documented value, a size of 0, more issued than the size, a value not returned, or a value that is not an integer |
| `RID pool: <dc>` | `Info` with the current pool, the next RID, the RIDs remaining in the pool and the prefetched pool; otherwise `Not Assessed`, worded `RID Set object absent`, `Access denied`, `Unreachable`, `Timed out`, `Read failed`, `Not found`, `Ambiguous`, `Multiple references`, `RID Set empty`, `Unreadable value` or `Inconsistent` |
| `RID pool - <domain>`, `RID pools`, `RID pool (no domain scoped)`, `RID pool` | `Not Assessed` population rows: a domain whose DCs were not enumerated, no DC enumerated at all, no domain scoped, the forest unreadable |

**The 64-bit values.** `rIDAvailablePool` and the two pools are Interval values, whose halves
Microsoft documents as unsigned. `ConvertFrom-AdfaLargeInteger` splits a value with explicit
32-bit arithmetic that gives the same answer on Windows PowerShell 5.1 and PowerShell 7 (the
Int64 with the same bits; low = value AND 4294967295; high = (value shifted right 32) AND
4294967295, so a negative Int64 - a high half of 0x80000000 or more - cannot carry its sign into
the result). It accepts any integer type, a UInt64 above Int64.MaxValue, and invariant-culture
text, and refuses everything else without throwing. Tested at 0, Microsoft's sample
4611686014132422708 (low 2100, high 1073741823) and the sample plus 100,000, high 0x7FFFFFFF,
Int64.MaxValue and MinValue, -1, high 0xFFFFFFFE, 2^32, UInt64.MaxValue, and their text forms.

**Thresholds: Microsoft's own points.** `Warning` from 10 % of the global RID space issued:
Microsoft's event 16658 fires at the first 10 % and Microsoft calls reaching it "not expected".
`Fail` from 90 %: the hard-coded RID ceiling, at which the RID master writes event 16657, sets
`msDS-RIDPoolAllocationEnabled` to FALSE and issues no further pool. The comparison is on
integers (issued * 100 against size * percent), "at or past". On the 31-bit space the Warning
point is 214,748,365, Microsoft's figure; on the 30-bit space it is 107,374,183 and the Fail
points are 966,367,641 and 1,932,735,283, one RID past the figures Microsoft gives, because the
low half is where the next pool begins. Both points are in a versioned table and can be changed
under a new `RidPool` key of `-ConfigOverridePath` (`WarnAtPercentUsed`, `FailAtPercentUsed`,
whole numbers from 1 to 99, Fail above Warning once merged); a finding then cites the file for the
key it supplied. The known sizes, the location of `CN=RID Manager$` and every attribute and class
name are refused.

**The size of the space is read, never assumed.** 1,073,741,823 is graded as the default 30-bit
space and 2,147,483,647 as the 31-bit space after the unlock. That the attribute holds the second
value after the unlock is an **inference** from Microsoft's dcdiag example, and every row graded
against it says so: Microsoft gives the unlocked size as 2,147,483,648 in one sentence and as
2,147,483,647 (what dcdiag shows) in the next, and the unlock itself, `SidCompatibilityVersion`,
"isn't readable using ADSIEdit, LDP, or other tools". Any other size is `Not Assessed` with the
values quoted, never a percentage against a guessed size.

**Per DC.** `rIDPreviousAllocationPool` is the current pool, start in the lower four bytes and
end in the upper, as Microsoft documents. `rIDAllocationPool` is the prefetched next pool; its
page does not restate the layout, so reading its halves the same way is an **inference**, said in
the row. "Remaining in pool" is end - next + 1, **a tool derivation**: Microsoft does not say
whether the end of a pool is inclusive. `rIDUsedPool` is read but not interpreted. No threshold
is applied to a DC's pool: Microsoft publishes none. `rIDSetReferences` is multi-valued in the
schema; more than one value is reported and none is chosen. A RID Set that is absent after both
instruments is worded as the known DC defect Microsoft names ("a RID pool leak when missing
rIDSetReferences attribute", KB 2618669) - except on a DC the inventory marks read-only, for
which no Microsoft page read says whether a RID Set exists, and the row says that instead.

**Population.** Domains: every scoped domain gets exactly its two rows. DCs: as DcCertificates,
the DCs of every scoped domain, from the DC inventory where `DomainControllers` is also selected
and otherwise from the section's own enumeration of each scoped domain
(`Get-AdfaDcTargetsByDomain`), with a `RID pool - <domain>` row for a domain no DC row accounts
for (`Get-AdfaDcPopulationGap`). An exception while one domain or one DC is handled makes its rows
`Not Assessed` and never ends the section. With the forest unreadable the section is one
`Not Assessed` row naming the cause.

**Recommendations.** Two section-scoped entries, anchored on the Item prefixes the tool writes
(`RID pool allocation: `, `Global RID space: `), and a catch-all that gives every other row of the
section no advice, all placed before the unscoped entries: a RID pool row can contain "event
16658", "restored", "dcdiag" or a file path, which the unscoped `event \d+ on`, `backup`,
`dcdiag` and `aging` entries would otherwise answer. The text the tool cannot control - the RID
master's name, the DNs, the raw values - is in columns the matcher never reads, and what was not
read is in `NotRun`, added after the advice is chosen. Both texts come from Managing RID Issuance:
the causes of RID consumption Microsoft lists, investigating before re-enabling, how the block is
removed, and that the 31-bit unlock is irreversible.

**Where this differs from the catalogue rules.**

- ADA-RID-002 is Warning-only in the catalogue. This build adds a `Fail` at 90 % used, Microsoft's
  hard-coded ceiling: after an administrator lifts the block, `msDS-RIDPoolAllocationEnabled`
  returns to NOT SET and RID-001 is no longer a `Fail`, while the space stays above 90 % with no further
  ceiling, so RID-002 is then the only row that says so. Recorded as a decision for the operator
  (PORT-PLAN C6b).
- ADA-RID-001 says "else Pass". This build gives `Pass` for TRUE only. An attribute that is not
  returned is `Not Assessed`: NOT SET is Microsoft's documented default, but Microsoft also documents
  that a read succeeds without the properties the caller may not read, so an unset value and a
  FALSE one hidden by a changed ACL look the same (the gap analysis already asked for "attribute not
  returned" to be `Not Assessed`). Not in the schema is `Not Assessed` too, because Microsoft
  publishes no meaning for it. Telling "not set" from "not readable" needs the object's ACL to be
  evaluated: PORT-PLAN C6d.
- The reference lists read-only DCs as Excluded. This build does not exclude them: it reads what
  is there and, where the inventory marks a DC read-only, does not call a missing RID Set a defect.

**The guards were shown able to fail.** Nineteen single mutations of the new code, each run
against the new `Describe` and the file then restored byte for byte (SHA-256 checked): FALSE read
as allowed, an unconfirmed "not set" turned into `Pass`, an unreachable DC's failed read not
reported, access denied worded as unreachable, the override's range check removed, the Invoke-Main
branch never taken, the issued count off by one, the per-DC loop limited to the first DC, the high
half shifted by 31, the sign not masked after the shift, the second instrument dropped, "remaining"
off by one, the read-only flag ignored, the recommendation catch-all removed, the domain loop
limited to the first domain, the Warning and the Fail comparison each turned from "at or past" into
"past", a refused reference read followed by the search anyway, and an unknown size graded against
the 30-bit size. Seventeen were caught at once. The two comparison mutants survived: the two
documented sizes are odd and end in 3 and 7, so no whole count of RIDs is ever exactly 10 % or 90 %
of them. A test was added that gives the pure verdict a size divisible by ten, and kills both.

**Found by an independent review of the diff before commit, and fixed in it.**

- **The percentage contradicted the grade at Microsoft's own boundary RIDs.** `PercentUsed` was
  rounded to four decimals while the grade compared integers, so 107,374,182 of 1,073,741,823 was a
  `Pass` that read "(10 % used). Below the Warning point of 10 % used", and 966,367,640 (Microsoft's
  30-bit trigger RID) a `Warning` showing 90 %; the same on the 31-bit space. The figure is now
  computed in decimal and **truncated** to four decimals, never rounded up: those rows show 9.9999
  and 89.9999. As a consequence Microsoft's sample value (2,100 issued) now shows 0.0001 %, not
  0.0002 %. A test at nine boundary points checks the figure, the text and that the figure agrees
  with the grade.
- **"Not set" was a `Pass`, and the README promised a changed ACL never shows as a pass.** Microsoft
  documents ([Access Control and Read Operations](https://learn.microsoft.com/windows/win32/ad/access-control-and-read-operations),
  read 2026-11-16) that "a search operation can succeed, but the search results don't include
  objects or properties to which the caller doesn't have access", so a FALSE
  `msDS-RIDPoolAllocationEnabled` hidden by an attribute-level deny arrived exactly like an unset
  one and passed. Behaviour changed to the safe result: an allocation attribute that is not returned
  is now `Not Assessed` (`Not returned: ...`), whatever the schema says, and the README says only
  what the tool can see. Telling the two apart needs the object's ACL evaluated, which is new work:
  PORT-PLAN C6d.
- **Guards no test could fail.** `Get-AdfaRidSchemaState` had no test at all (turning "not in the
  schema" into "in the schema", or removing the `rIDAvailablePool` control check, left every test
  green); it now has seven pinned answers in Pester and five in the validation harness. Also
  pinned now: the `rIDNextRID` width rule (a negative Int32 is decoded; a value with a non-zero
  upper half is `Unreadable value`), the seam reading nothing more when `rIDSetReferences` holds two
  values, a one-item collection holding FALSE or TRUE, the allocation row's `RawValue` column, and
  "ends before it starts" told apart from "next RID outside the pool" by its own wording.
- **A config comment misstated how the tool relates to Microsoft's trigger point** ("graded one pool
  late"). The integer rule turns on the same allocation that includes Microsoft's RID; the comment
  now says so.

Ten mutations covering the findings (the eight a test could not catch, the rounding and the "not
set" `Pass` brought back) were each run under Windows PowerShell
5.1 against the C6 `Describe` and the validation harness, on a copy of the tree restored byte for
byte (SHA-256 checked) after each; every one now fails at least one test.

**Existing tests changed, because behaviour legitimately changed.** In this row's own tests, after
the review: the allocation verdict for "not set, attribute in schema", the allocation row of the
domain-rows test, the collector's contoso.com allocation row and the smoke harness's single-domain
and RID-Set-absent checks now expect `Not Assessed` instead of `Pass`; the four `0.0002`
assertions (three in Pester, one in the smoke harness) now expect `0.0001`; two per-DC leads
("next RID outside pool", "end before start") were narrowed from `^Inconsistent: ` to their own
wording. Before the review: the three Pester assertions and
the validation-harness assertion that pin the `-ConfigOverridePath` section list now include
`RidPool`. The C4 and C5 version tests now expect 1.23.0. The C4 count of assignments to a
`Properties` key in the script went from 7 to 12: the five property lists of this section, each a
named attribute from the config table. The smoke harness's count of declared unusable override
files went from 12 to 14 (two `RidPool` files added). The smoke stubs gained, each selected only by
what this section sends: a `Get-ADComputer` branch for `rIDSetReferences` on the DC lookup the
DcCertificates stub already answered, and `Get-ADObject` branches for `CN=RID Manager$` (keyed by
`-Server`, because the `Get-ADDomain` stub gives every domain the same DN), for the RID Set and for
the one-level search; the two RID attribute names were added to the stub schema.

**Sources, all read on Microsoft Learn 2026-11-16.**

- [Managing RID Issuance](https://learn.microsoft.com/windows-server/identity/ad-ds/manage/managing-rid-issuance) - event 16658 at 10 % used and "not expected"; the RID ceiling at 90 % used, its trigger points, event 16657 and `msDS-RIDPoolAllocationEnabled` set to FALSE; TRUE to remove the block and the return to "its default NOT SET value"; the global space sizes and the unlock, `SidCompatibilityVersion` not readable, irreversible, and its DC caveats (KB 2642658); RID Block Size (500 by default, 15,000 at most); the RID pool leak with a missing `rIDSetReferences` (KB 2618669); the causes of RID consumption.
- [Raise the value of available RID pools](https://learn.microsoft.com/windows-server/identity/ad-ds/manage/forest-recovery-guide/ad-forest-recovery-raise-rid-pool) - `CN=RID Manager$,CN=System`, the halves of `rIDAvailablePool`, the sample value.
- [Interval syntax](https://learn.microsoft.com/windows/win32/adschema/s-interval) - the halves are unsigned.
- [RID-Previous-Allocation-Pool](https://learn.microsoft.com/windows/win32/adschema/a-ridpreviousallocationpool), [RID-Allocation-Pool](https://learn.microsoft.com/windows/win32/adschema/a-ridallocationpool), [RID-Next-RID](https://learn.microsoft.com/windows/win32/adschema/a-ridnextrid), [RID-Used-Pool](https://learn.microsoft.com/windows/win32/adschema/a-ridusedpool), [RID-Set-References](https://learn.microsoft.com/windows/win32/adschema/a-ridsetreferences) - the per-DC attributes, their layout where published, `rIDSetReferences` multi-valued.
- [RID-Set class](https://learn.microsoft.com/windows/win32/adschema/c-ridset) and [RID-Manager class](https://learn.microsoft.com/windows/win32/adschema/c-ridmanager) - one RID Set per DC, its mandatory attributes, `rIDSet` as the class name, and the default security descriptors (Authenticated Users read).
- [Access Control and Read Operations](https://learn.microsoft.com/windows/win32/ad/access-control-and-read-operations) - a read can succeed without the properties the caller may not read; why an attribute that is not returned is never a pass.
- [ms-DS-RID-Pool-Allocation-Enabled](https://learn.microsoft.com/windows/win32/adschema/a-msds-ridpoolallocationenabled) - **not found** (the page could not be retrieved, 2026-11-16): the attribute's schema version and what its absence means are not published.

**Not verified.** That the upper half of `rIDAvailablePool` holds 2,147,483,647 after the 31-bit
unlock; the types the ActiveDirectory module returns for these attributes (the stubs return an
Int64 for the Interval values, a Boolean for `msDS-RIDPoolAllocationEnabled`, an Int32 for
`rIDNextRID`, and leave an unset attribute out of the answer); whether `rIDNextRID` and the pool
end bound "remaining" as end - next + 1 on a real DC; whether a read-only DC has a RID Set; the
exception the module throws for a reference that does not resolve (every error that is not a
refusal, an unreachable server or a time-out is followed by the search); who can read these
objects beyond the default security descriptors. All are PORT-PLAN C6a, with C17.

### Added — 2026-11-16 (DC certificates: the LDAPS certificate each DC presents, and those published for it, tool v1.22.0)

**PORT-PLAN C5.** New `-Sections DcCertificates` (report section `DC Certificates`), included in
the default `All` run, and a new opt-in switch `-IncludeLdapsHandshake`. It addresses two rows of
the gap analysis, ADA-CERT-001 (DC certificate expiry) and ADA-INV-020 (DC certificate
inventory), for which the tool had nothing. It covers ADA-INV-020 only partly; the differences
from the catalogue rules are listed below.

**This has run only against stubs.** No part of it has been executed against a real directory or
a real domain controller: no `Get-ADComputer` call in it has met a real directory, and no
handshake has been made to a real DC's port 636. The first run against a real forest is
PORT-PLAN C17, owned by the operator. What was measured, on this workstation only (not a DC),
is listed under "Measured" below.

**The instrument, and why.** The reference rule (AdAssessment26 decision D12) reads the DC's
`LocalMachine\My` store, "the store the DC presents from". Microsoft Learn says otherwise: AD DS
"preferentially checks the NTDS store first", and "if a Windows Server 2008 or a later version
domain controller finds multiple certificates in its store, it will random chose one". A store
read therefore cannot say which certificate clients receive. This build uses two instruments,
each named in every row's `Evidence` column:

- **LDAPS handshake** (`Get-AdfaDcTlsCertificateRaw`), only with `-IncludeLdapsHandshake`. One
  TCP connection to port 636 after the port answered the shared probe (`Test-AdfaDcPort`), then
  `SslStream.AuthenticateAsClient(<DC host name>)` - the overload that uses no client certificate
  and does not check revocation - called synchronously. The connection is bounded by
  `ConnectTimeoutMs`, and the whole handshake by `HandshakeTimeoutMs`: the call has no timeout
  of its own, and the socket's receive timeout restarts on every read, so a deadline (a second
  runspace of this process that waits on an event) shuts down and closes the connection when
  the bound runs out. If the deadline cannot be armed, no handshake is made. The
  validation callback copies the certificate, the platform's `SslPolicyErrors` and the chain
  status, and returns *true*: the tool neither trusts nor rejects the certificate, and does not
  abort the handshake. The stream and the connection are closed at once; no application data is
  written, so no LDAP request, no bind and no credential is sent ("SSL/TLS is negotiated before
  any LDAP traffic is exchanged"). It needs no right on the DC.
- **Directory** (`Get-AdfaDcCertificateDirectoryRaw`), always. One
  `Get-ADComputer -LDAPFilter (&(objectClass=computer)(dNSHostName=<dc>)) -Properties
  userCertificate` per DC, against the DC's own domain (or, for a DC from the unscoped fallback
  enumeration, the DC itself, which the row says). `-Identity` does not take a DNS host name.
  Labelled **directory evidence**: a value shows a CA published that certificate, not that the
  DC holds or presents it, nor that it is a DC certificate. A value is opened only when
  `X509Certificate2.GetCertContentType` says it is one certificate (`Cert`); a PKCS12 (PFX) or
  PKCS7 value is `Not Assessed` (`Read failed:`) and never opened.
- The certificate store over WinRM was **rejected** (PORT-PLAN C5a): the script has no
  read-only remoting seam for it, it needs local Administrators, the Certificate provider can
  also delete certificates and keys, and it would still miss the NTDS service store.

**Why the handshake is opt-in.** No Microsoft page read states that a TLS handshake leaves no
trace on the server, and Learn documents Schannel event logging as on by default ("error
messages are logged") and a System-log Schannel event for a fatal alert received. A DC that
cannot complete the handshake may therefore log an error event. That is the kind of side effect
this tool puts behind a switch (`-IncludeLingeringObjectScan`, PORT-PLAN C4d), so the decision -
taken by this build under the operator's standing authorization, and open to revision in
PORT-PLAN C5b - is opt-in. Without the switch every DC's `LDAPS certificate` row is
`Not Assessed`, starts `Not run:` and names the switch, and port 636 is not touched. The README's
"What a run can change" table has a row for it, and a run with the switch says so in its log.

**What it reports.**

| Row | Status |
| --- | --- |
| `LDAPS certificate: <dc>` (exactly one per DC) | `Pass` / `Warning` / `Fail` on the presented certificate's expiry; `Not Assessed` for: not run, port 636 did not answer the probe, refused, connect timed out, unresolved, connection failed, handshake timed out, handshake failed, no certificate, certificate unreadable, a defect in the tool - each with its own wording, the error quoted |
| `Directory certificate: <dc> [<thumbprint>]` (one per published value) | `Pass` / `Warning` / `Fail` on expiry, saying whether it is the presented certificate; `Not Assessed` for a value that is not a certificate (`[value N]`) |
| `Directory certificates: <dc>` | `Info` no value visible; `Not Assessed` `Unreachable:` / `Access denied:` / `Timed out:` / `Read failed:`, no computer object with that DNS host name, or more than one |
| `DC certificates - <domain>`, `DC certificates`, `LDAPS certificate: (unnamed)` | `Not Assessed`: a scoped domain whose DCs were not enumerated, no DC at all, a DC with no host name |

None of the failed-handshake results is read as "the DC has no certificate": Learn does not
document what a DC without a usable certificate does on 636. **No published value is `Info`,
never "no certificate"**: of the DC templates in Learn's default template table, *Domain
Controller* (version 1) is published to AD DS, while *Domain Controller Authentication* and
*Kerberos Authentication* are not, and publication is a separate operation from issuance. A
value the account cannot read also looks like none. The same table publishes *Directory E-mail
Replication* (a computer template, version 2) and several user templates to AD DS, so a
published value is not said to be a DC certificate: the row says so, and its EKUs are reported.

**Grading: expiry only, in UTC, against an injected clock** (`Get-AdfaCertificateExpiryVerdict`,
pure). Learn documents `X509Certificate2.NotBefore` and `.NotAfter` as local time; both are
converted once. NotAfter at or before now is `Fail` (expired; the reference named the boundary
without its side, and a certificate with no validity left is expired); at most `WarnWithinDays`
whole days left is `Warning` (30, so exactly 30 days is a Warning, as the reference's "at most 30
days" says); `FailWithinDays` exists and is 0, off; a start date in the future is `Warning`,
**this tool's rule** (the reference has none); unreadable or reversed dates are `Not Assessed`.
**The two windows are tool defaults, not Microsoft values**: Microsoft publishes no warning
window for a DC certificate; 30 days is the catalogue's operator-set value (S24). Every graded
row names its window and its source.

**Not graded, reported in their own columns:** subject, issuer, subject alternative names, the
EKUs (Server Authentication, Client Authentication, KDC Authentication and Smart Card Logon
named), `SslPolicyErrors` and `ChainStatus` as the platform of the host running the assessment
reported them. A certificate's subject is chosen by whoever requested it, so none of these
columns is in the text the recommendation is chosen from; a test feeds a hostile subject and a
hostile chain status through and checks the advice. Grading trust, name or EKU is PORT-PLAN C5b.

**Population.** The DCs of every scoped domain, from the DC inventory where `DomainControllers`
ran, otherwise the section's own enumeration (`Get-AdfaDcTargetsByDomain`), with a
`Not Assessed` row for every scoped domain none of whose DCs is in the section
(`Get-AdfaDcPopulationGap`). RODCs are included. An exception while one DC is handled makes that
DC's two rows `Not Assessed` and never ends the section.

**Config.** `$script:Config.DcCertificates` holds the windows, the two timeouts, the port (636)
and the EKU names, with sources and read date. `-ConfigOverridePath` takes a new `DcCertificates`
key with four settable values: `WarnWithinDays`, `FailWithinDays` (whole days, 0 to 3650),
`HandshakeTimeoutMs` and `ConnectTimeoutMs` (100 to 60000; 5000 each by default, tool
defaults). `LdapsPort` and `EkuNames` are refused as unknown. Also
refused: a file that is not one object, an empty object, a null, a quoted number, a fraction, a
Fail window above the Warning window once merged. Provenance is rewritten for the windows the
file supplied only.

**Recommendations.** Two section-scoped entries, anchored on the Item the tool writes
(`LDAPS certificate: `, `Directory certificate: `), and a catch-all, all ahead of every unscoped
entry, so that `certificate template|enrol` (the ESC1 advice), `port.*not reachable`,
`does not resolve`, `time sync|clock`, `replication`, `backup` and `NOT a pass` cannot answer a
certificate row. The advice is Microsoft's: request a new DC certificate rather than renew an
expired one; the LDAPS requirements; the NTDS store first; restart or `renewServerCertificate`
(named as Microsoft's documented step, never run by this tool); third-party CAs do not renew
automatically; publication is separate from issuance.

**Where this differs from the catalogue rules.**

- ADA-CERT-001 grades every certificate in `LocalMachine\My`. This build grades the presented
  certificate and the published ones; the store is PORT-PLAN C5a.
- ADA-INV-020 inventories every certificate in that store. Covered **partly**.
- The catalogue has no rule for a certificate not yet valid; this build reports it as a
  `Warning`, its own rule.
- The catalogue's DCOM case ("certificate store needs WinRM") does not arise: neither instrument
  uses WinRM or DCOM.

**Measured** on this workstation (Windows 11, not a DC), PowerShell 7.6.9 and Windows
PowerShell 5.1, 2026-11-16, with the seam itself: against a public HTTPS endpoint (port 443,
not a DC) the script-block callback ran on the calling thread and returned the certificate,
its EKU and UTC dates on both editions; a loopback port with no listener came back
`ConnectRefused` - **only with a connection bound above about 2 s**: Windows reported the
refusal after 2.1 to 2.4 s, so at 1200 ms (the shared probe's bound, which the first draft used)
it came back `ConnectTimedOut`; a `.invalid` name `Unresolved`; 192.0.2.1 `ConnectTimedOut`; a
loopback listener that never answers `HandshakeTimedOut` within the bound; and one that answers
with non-TLS bytes `HandshakeFailed`. Test certificates are made in memory with an ephemeral
ECDSA key (an RSA key for the PFX test); nothing is written to a certificate store.

**Found by an independent review of the diff before commit, and fixed in it.**

- *A PFX in `userCertificate` had its private key imported on the assessment host.* The record
  builder passed the bytes to the `X509Certificate2(byte[])` constructor, which also takes a
  PKCS12 blob and imports its private key into a key container (the reviewer saw a key file
  created and deleted under `%APPDATA%\Microsoft\Crypto\Keys`), and a PKCS7 blob, of which it
  keeps the signer. Whoever can write the attribute chooses the bytes. The content type is now
  checked first with `GetCertContentType`, which only identifies the content, and anything but
  `Cert` is refused unopened. A test exports an in-memory PFX and PKCS7 and fails if either is
  read; a `FileSystemWatcher` on `%APPDATA%\Microsoft\Crypto` recorded no event while the fixed
  function was given the PFX, on either edition (that the watcher catches the key file with the
  old code is the reviewer's measurement; it was not repeated here, so as to write no key to
  this profile - a watcher on a scratch folder showed the event mechanism working).
- *`HandshakeTimeoutMs` bounded each read, not the handshake.* A peer that sent one byte every
  1.5 s held one call for 12 to 20 s against a 2.5 s bound, and could hold the per-DC loop for
  hours. The whole handshake now has a deadline (above). A loopback peer that sends one byte
  every 250 ms for 10 s is now cut off at the 1000 ms bound (1.1 to 1.3 s measured).
- *A refused connection was reported as a time-out at the bound the collector used* (1200 ms,
  the shared probe's), so the `Refused` row could not be produced on a Windows assessor and
  this entry's "came back `ConnectRefused`" held only at a longer bound. The handshake's
  connection now has its own `ConnectTimeoutMs`, 5000 ms (tool default), and the `Timed out`
  row says a refusal is told apart only within that bound. The shared probe still cannot tell
  a refused port from a filtered one (PORT-PLAN C5d).
- *The directory text misquoted Learn's template table* ("publish to AD DS only for *Domain
  Controller*"): *Directory E-mail Replication* is published too. Text, docstring, README, this
  entry and the directory advice corrected; the advice now says to check the certificate's
  purposes and template before treating it as a DC certificate.
- *Tests that could not fail, now made to:* the UTC test used `ToLocalTime()` at an instant
  where this host's offset is 0, so removing either UTC conversion survived - the tests now pick
  an instant where the local offset is not zero, prove their inputs tell the two readings apart,
  and are skipped (saying why) on a host that is UTC all year, such as the Linux CI runner;
  "rounded down" is pinned with 30.75 days; the handshake seam itself is now run against
  loopback listeners (refused, connect timed out on Windows, silent peer, trickling peer,
  non-TLS peer), and its classification moved into a pure function (`Get-AdfaTlsProbeClass`)
  whose test keeps a certificate received before an error; the timeout upper bound (60000), a
  Fail window equal to the Warning window, the NUL escape and the `NotBeforeUtc` column are each
  asserted; and the test titled "no other new parameter" now compares the whole parameter list
  with v1.21.0's. Each reviewer mutation was re-applied to a copy and now fails the C5 tests.

**The guards were shown able to fail.** Eighteen single mutations of the new code, each run
against the new `Describe` and the file then restored byte for byte (SHA-256 checked): verdict
direction, a `Not Assessed` turned into `Pass`, a DC whose port did not answer read as
reachable, access denied worded as unreachable, the override's unknown-key refusal and its
Fail-above-Warning check removed, the `ValidateSet` entry dropped, the Warning window off by one,
the per-DC loop limited to the first DC, not-yet-valid turned into `Pass`, refused read as timed
out, the Fail window ignored, no published value graded `Fail`, the callback returning *false*,
the subject put into `Detail`, the recommendation catch-all removed, the handshake made without
the switch, and a lone byte array split into bytes. Seventeen were caught at once; the last
survived the Pester suite (only the validation harness had a case for it), and a test was added
that kills it.

**Existing tests changed, because behaviour legitimately changed.** The two assertions that pin
the `-ConfigOverridePath` section list (C3 and C4 Describes, and the validation harness) now
include `DcCertificates`. The C4 version test now expects 1.22.0. The C4 count of assignments to
a `Properties` key in the script went from 6 to 7: `Get-AdfaDcCertificateDirectoryRaw` assigns
`@('userCertificate')`. The smoke harness's count of declared unusable override files went from
10 to 12 (two `DcCertificates` files added). Within this row's own new tests, after the review:
the UTC test was replaced (it could not fail); the collector test now records the connection
bound as well (`dc1.contoso.com:636:2500:5000`, from a config with `ConnectTimeoutMs` 2500),
because the handshake's connection no longer takes `-PortTimeoutMs`; the override refusal table
grew from 11 to 15 shapes and names the key in its expected message; the section's function
population grew from 14 to 15 (`Get-AdfaTlsProbeClass`).

**Sources, all read on Microsoft Learn 2026-11-16.**

- [Enable LDAP over SSL with a third-party CA (KB 321051)](https://learn.microsoft.com/troubleshoot/windows-server/active-directory/enable-ldap-over-ssl-3rd-certification-authority) - NTDS store precedence, the random choice among several, TLS before LDAP traffic on 636 and 3269, `renewServerCertificate`, the Server Authentication OID.
- [Configure LDAP signing certificates](https://learn.microsoft.com/windows-server/identity/ad-ds/configure-ldap-signing-certificates) - "checks the NTDS store first", FQDN in the CN or a SAN DNS entry.
- [LDAP over SSL connection issues](https://learn.microsoft.com/troubleshoot/windows-server/active-directory/ldap-over-ssl-connection-issues) - Schannel picks the first valid certificate.
- [Requirements for DC certificates from a third-party CA](https://learn.microsoft.com/troubleshoot/windows-server/active-directory/requirements-domain-controller) - Client and Server Authentication OIDs; no automatic enrolment or renewal.
- [Windows Hello for Business on-premises certificate trust](https://learn.microsoft.com/windows/security/identity-protection/hello-for-business/deploy/on-premises-cert-trust) - KDC Authentication OID, and that the Domain Controller templates lack it.
- [Smart card logon with third-party CAs](https://learn.microsoft.com/troubleshoot/windows-server/certificates-and-public-key-infrastructure-pki/enabling-smart-card-logon-third-party-certification-authorities) - Smart Card Logon OID; an expired DC certificate as a cause of failure, and request rather than renew.
- [X509-Cert (userCertificate)](https://learn.microsoft.com/windows/win32/adschema/a-usercertificate), [Certificate template concepts](https://learn.microsoft.com/windows-server/identity/ad-cs/certificate-template-concepts), [Manage certificate templates](https://learn.microsoft.com/windows-server/identity/ad-cs/manage-certificate-templates) - the attribute, which templates publish to AD DS, publication separate from issuance.
- [Get-ADComputer](https://learn.microsoft.com/powershell/module/activedirectory/get-adcomputer) - the forms `-Identity` accepts; [Search filter syntax](https://learn.microsoft.com/windows/win32/adsi/search-filter-syntax) - the escapes.
- [SslStream.AuthenticateAsClient](https://learn.microsoft.com/dotnet/api/system.net.security.sslstream.authenticateasclient?view=netframework-4.8), [RemoteCertificateValidationCallback](https://learn.microsoft.com/dotnet/api/system.net.security.remotecertificatevalidationcallback), [SslPolicyErrors](https://learn.microsoft.com/dotnet/api/system.net.security.sslpolicyerrors), [X509ChainStatusFlags](https://learn.microsoft.com/dotnet/api/system.security.cryptography.x509certificates.x509chainstatusflags), [X509Certificate2.NotAfter](https://learn.microsoft.com/dotnet/api/system.security.cryptography.x509certificates.x509certificate2.notafter) and [.NotBefore](https://learn.microsoft.com/dotnet/api/system.security.cryptography.x509certificates.x509certificate2.notbefore), [X509EnhancedKeyUsageExtension.EnhancedKeyUsages](https://learn.microsoft.com/dotnet/api/system.security.cryptography.x509certificates.x509enhancedkeyusageextension.enhancedkeyusages), [SocketError](https://learn.microsoft.com/dotnet/api/system.net.sockets.socketerror?view=netframework-4.8), [TcpClient.ReceiveTimeout](https://learn.microsoft.com/dotnet/api/system.net.sockets.tcpclient.receivetimeout), [X509ChainPolicy.DisableCertificateDownloads](https://learn.microsoft.com/dotnet/api/system.security.cryptography.x509certificates.x509chainpolicy.disablecertificatedownloads).
- [Enable Schannel event logging](https://learn.microsoft.com/troubleshoot/developer/webapps/iis/health-diagnostic-performance/enable-schannel-event-logging) and [SSL/TLS problems after KB931125](https://learn.microsoft.com/troubleshoot/windows-server/windows-security/ssltls-communication-problems-after-install-kb931125) - logging on by default; event 36887.
- [Certificate renewals and autoenrollment](https://learn.microsoft.com/troubleshoot/windows-server/certificates-and-public-key-infrastructure-pki/approval-required-certificate-renewals-autoenrollment) - the six-week renewal example the 30-day default sits after.
- [about_Certificate_Provider](https://learn.microsoft.com/powershell/module/microsoft.powershell.security/about/about_certificate_provider?view=powershell-5.1) - the provider can delete; an empty EKU list means all purposes.
- [X509Certificate2 constructors](https://learn.microsoft.com/dotnet/api/system.security.cryptography.x509certificates.x509certificate2.-ctor) - the byte-array constructor takes DER, PEM or a PKCS7 signed file ("the signer certificate is used"), and the PKCS12 constructors import the private key into a key container; [X509Certificate2.GetCertContentType](https://learn.microsoft.com/dotnet/api/system.security.cryptography.x509certificates.x509certificate2.getcertcontenttype) - "Indicates the type of certificate contained in a byte array", and throws for content it cannot identify.

**Not verified.** Whether the handshake writes any event on a DC that has a usable certificate,
and what a DC without one does on 636 and logs; whether building the chain fetches issuer
certificates from AIA addresses on either edition; whether `SslStream.Dispose` sends a
close_notify; who can read `userCertificate` by default; the shape the ActiveDirectory module
returns for `userCertificate` (the stub returns a collection of byte arrays); the exception types
a real refused or unreachable directory read throws. All are PORT-PLAN C5c, with C17. Also not
verified (PORT-PLAN C5d): that the handshake deadline wakes the blocked read on Linux (measured
on Windows only; the loopback seam tests also run on the Linux CI runner, where they are the
first measurement), how long a remote host takes to report a refused connection, and telling a
refused port from a filtered one at the shared probe. No "no
state change" statement for a TLS handshake was found on Learn; the decision to make the
handshake opt-in rests on that absence.

### Added — 2026-11-15 (Windows LAPS: schema, DSRM password backup, computers with no LAPS expiry time, tool v1.21.0)

**PORT-PLAN C4.** New `-Sections Laps` (report section `Windows LAPS`), included in the default
`All` run. It addresses two rows of the gap analysis, ADA-LAPS-001 and ADA-LAPS-002, for which
the tool had nothing. It does not implement either catalogue rule as written; the differences
are listed below.

**This has run only against stubs.** No part of it has been executed against a real directory.
No `Get-ADComputer`, `Get-ADObject`, `Get-ADDomain` or `Get-ADRootDSE` call in it has met a real
domain controller. The first run against a real forest is PORT-PLAN C17, owned by the operator.

**The section never reads a password.** It reads attribute definitions in the schema partition,
`msDS-Behavior-Version` on each domain head, and a fixed list of attributes on computer objects
(`operatingSystem`, `operatingSystemVersion`, `userAccountControl`, `lastLogonTimestamp`,
`dNSHostName`, `objectClass`) plus the two expiry time attributes where the schema defines
them. Seven attributes are never requested and never used in a filter on a computer object:
`msLAPS-Password`, `msLAPS-EncryptedPassword`, `msLAPS-EncryptedPasswordHistory`,
`msLAPS-EncryptedDSRMPassword`, `msLAPS-EncryptedDSRMPasswordHistory`,
`msLAPS-CurrentPasswordVersion` and `ms-Mcs-AdmPwd`. Four things enforce it:

- the property list is built by one function, which throws if the result holds a never-read
  name, a wildcard, a blank, or any name containing "password" or "pwd" that does not end in
  `ExpirationTime`;
- the function that sends the query checks the list again and refuses it before any call;
- a test fails if one of the seven names is in any `-Properties` argument, or in any value
  assigned to a `Properties` key, anywhere in the script;
- a test fails if one of the seven names appears in the script at all outside the `Laps`
  config table.

No cmdlet of the LAPS module is called. `Get-LapsADPassword` returns the password.

**What it reports.**

| Row | Evidence | Status |
| --- | --- | --- |
| `Windows LAPS schema` (one, forest) | Attribute definitions, searched by `lDAPDisplayName`, with `operatingSystemVersion` in the same query as a control | `Pass` the six attributes `Update-LapsADSchema` adds; `Warning` some of them; `Info` none of them; `Not Assessed` the query failed, or answered without the control |
| `DSRM password backup: <dc>` (one per DC computer object) | `msLAPS-PasswordExpirationTime` on the DC's computer object; its `operatingSystemVersion`; the domain's `msDS-Behavior-Version` | `Pass` a time not more than 7 days past; `Warning` a time further past, or none visible while another object of the domain returned one, or no such attribute in the schema; `Info` not applicable; `Not Assessed` otherwise |
| `DSRM password backup - <domain>` | - | `Not Assessed`: the read of the domain failed, or returned no DC object, or returned an object without `userAccountControl` that may be a DC |
| `LAPS coverage: <domain>` (one per scoped domain) | Either expiry attribute on each computer in population | `Pass` all have one visible; `Warning` any has none; `Fail` only under a config file; `Info` nothing in population; `Not Assessed` see below |

`msLAPS-CurrentPasswordVersion` is reported in the schema row and never required: Microsoft
states it "is only available when using the Windows Server 2025 forest schema" and is "not
installed by running the `Update-LapsADSchema` cmdlet".

**Three results for the schema, three for a read.** Attributes absent, attributes present and
"the query failed" are different rows. An answer that lacks the control attribute is
`Not Assessed`, never "absent". A domain whose query threw is `Not Assessed` and begins
`Unreachable:`, `Access denied:`, `Timed out:` or `Read failed:`, decided by the type of the
exception and then by its text. The row quotes the error and names the exception type it was
decided from.

**Not set and not readable look the same.** A directory leaves out an attribute the account
may not read; it does not say so. A computer with no expiry time in the answer is therefore
"no LAPS expiry time visible to this account", never "unmanaged". Following decision D13 of
the AdAssessment26 plan: with **neither** expiry attribute in the schema the absence is
measured and graded; with one in the schema and **at least one** value returned in the
domain, absences are counted; with one in the schema and **no** value returned anywhere in
the domain, the rows are `Not Assessed`. A device that backs its password up to Microsoft
Entra ID has no value here either, and every graded row says this read cannot see that.

**The population of the coverage row**, stated in the row: enabled computer accounts that are
not domain controllers and not managed service accounts, whose `operatingSystem` begins with
`Windows`, whose OS build can run Windows LAPS (17763, or 19041 and later), and whose
`lastLogonTimestamp` is within `-StaleDays` - the threshold the `StaleObjects` section already
uses; no second one was added. Each class left out has its own count in the row: domain
controllers, managed service accounts, disabled accounts, objects with no `operatingSystem`,
non-Windows computers, Windows with an unreadable build, Windows releases that cannot run
Windows LAPS (with how many of those show a legacy expiry time), no logon recorded, stale, and
`userAccountControl` not returned. Names are listed for the in-population computers only, up
to `SampleLimit`, and the row says "showing 25 of N" when it cut the list. The last class, and
Windows with an unreadable build, are not measured: while there is one the row is never `Pass`
or `Info` but `Not Assessed`, and names them.

**Thresholds are tool defaults, not Microsoft values**, labelled so in the config table and in
every row that uses one: Warning above 0 % (any computer, the catalogue's rule), Fail above
100 % (which no share can exceed, so the row never fails unless a file lowers it), 25 names,
and 7 days of grace on a DC's expiry time. Microsoft publishes none of them.

**Where this differs from the catalogue rules.**

- ADA-LAPS-001 tests for the presence of the confidential DSRM password attribute. This row
  does not touch it. It uses the expiry time on the DC's computer object, which is an
  **inference**: Microsoft's `Get-LapsADPassword` example shows an expiration time for a DC
  whose source is the DSRM password, and no page states it in prose. Every DSRM row says so.
- A read-only domain controller with nothing visible is `Not Assessed`: Microsoft does not
  say, on the pages read, whether the feature is supported there.
- ADA-LAPS-002 counts every enabled non-DC computer. This row also leaves out non-Windows
  computers, objects with no operating system, Windows releases that cannot run Windows LAPS,
  and stale accounts (PORT-PLAN C4c for the third).
- The catalogue gives one status. This row has a `Fail` threshold, off by default.

**Config.** `$script:Config.Laps` holds the thresholds, the vendor values and their sources.
`-ConfigOverridePath` takes a new `Laps` key with four settable values: `WarnAbovePercent`,
`FailAbovePercent`, `SampleLimit`, `ExpiredGraceDays`. Every other key is refused as unknown,
so no attribute name and not the never-read list can be set from a file. Also refused: a file
that is not one object, an empty object, a null, a value that is not a JSON number, a
percentage outside 0 to 100, a Warning threshold of 100 (nothing could exceed it), Fail below
Warning once merged, a sample limit outside 0 to 1000, a grace period outside 0 to 365.

**Recommendations.** Three section-scoped entries, anchored on the Item the tool writes
(`Windows LAPS schema`, `LAPS coverage: `, `DSRM password backup: `), and a catch-all that gives
every other row of the section no advice. Without them the wording of these rows would have
attracted unrelated advice from the unscoped entries: `backup`, `scavenging|aging` ("managing"
contains "aging"), `stale|inactive`, `password policy|lockout`. The DSRM advice says that
Microsoft documents the feature as off by default, not as a requirement.

### Changed — 2026-11-15 (the Identity export no longer writes LAPS passwords to CSV, tool v1.21.0)

Found while building C4, in code C4 did not write. `Get-AdfaComputerInventory`, which the
`Identity` section runs and which is part of `All`, asks for every attribute of every computer
(`Get-ADComputer -Filter * -Properties *`). For an account with the rights to read them - a
Domain Admin, for instance - that includes the attributes that hold LAPS passwords, the legacy
one in clear text, and **before this version they were written to `AllComputers_<domain>.csv`
with everything else**.

The seven never-read attribute names are now removed from what the function returns, by name
compared without regard to case, so they are not written to the CSV. The two expiry time attributes, and ordinary
attributes such as `pwdLastSet`, stay.

**This is a mitigation, not the fix.** The attributes are still requested by the wildcard and
are held in memory for the length of the call. Replacing the wildcard with a list is PORT-PLAN
C4b, and changes what the export contains. **A CSV produced by v1.20.0 or earlier under a
privileged account should be treated as holding passwords.**

**Two existing tests were changed**, both in the C3 `Describe`: the pin of the sections the
override file can carry, from `DcDisk,DcHardening` to `DcDisk,DcHardening,Laps`; and the test
that pinned the version to 1.20.0, which now asserts that the script and the manifest agree,
the number itself being pinned to 1.21.0 by the C4 `Describe`. The same pin in
`Run-Validation.ps1` moved with it.

**Proven able to fail.** Fifty single mutations were applied to the new code one at a time - a verdict reversed, a Not Assessed turned into a Pass, a failed read graded as an answer, access denied reported as unreachable, two validations of the override removed, the section unwired three ways, seven thresholds off by one, the per-DC and the per-domain loop cut to their first item, and nine attempts on the hard rule (a secret attribute in the config list, in a literal property list inside and outside the section, and each guard removed in turn). The C4 tests failed on all fifty, and the script was restored after each and verified by SHA-256. Two of them would have survived the first draft of the tests - the never-read list not refusing a listed name, because every listed name is also caught by the password-like-name guard, and proof of read for a DC row taken from the legacy attribute - and a test was added for each before the run.

**Found by an independent review of the diff before commit, and fixed in it.**

- **A DC whose expiry time is at the end of the calendar ended the whole run.** The DSRM
  verdict added the grace period to the expiry time; for a value within 7 days (up to 365 by
  override) of the last date .NET holds - which is what an administrator gets by setting the
  expiry to "never" - that threw, and nothing above it caught it, so the run ended with no
  report. The grace period is now taken off "now" instead (the same comparison), such a DC is
  `Pass`, and the collector now catches any exception while grading one domain and reports
  that domain's two rows `Not Assessed` with the error, so no value in one domain can end the
  section or the run. A Pester test, a `Run-Validation.ps1` assertion and a smoke pass (three
  domains, run end to end) each fail on the old code.
- **A timeout was reported as "Unreachable: no directory server answered".** A
  `TimeoutException` or `ServerTooBusyException` can come from a server that accepted the query
  and then took too long. It is now its own class, worded `Timed out:` and saying it is not
  evidence that no server answered. **One existing test changed for this**: the classifier
  table in the C4 `Describe` expected `Unreachable` for `System.TimeoutException`; it now
  expects `TimedOut`, and the table grew from ten cases to fifteen so that every pattern of the
  classifier has a case of its own.
- **The coverage row could be `Pass` or `Info` while objects were not measured.** Objects
  whose `userAccountControl` was not returned, or Windows computers whose build could not be
  read, were counted with the measured-out classes. They now keep a would-be `Pass` or `Info`
  at `Not Assessed`, and are named; a `Warning` or `Fail` stands and says over what it was
  counted. A DC whose `userAccountControl` was not returned got no DSRM row and no
  `Not Assessed` row while another DC was recognised; the domain now gets a
  `DSRM password backup - <domain>` `Not Assessed` row naming such objects.
- **Behaviours no test pinned**, each now pinned by a test that fails under the reviewer's
  mutation: a computer with both expiry times counted as Windows LAPS; the "with a legacy
  expiry time" count of releases that cannot run Windows LAPS; no names listed in a
  `Not Assessed` row with no proof of read; a grace period over 365 days refused; the "never
  fails unless a config file lowers it" wording; the `ServerTooBusyException`,
  `SecurityAccessDeniedException` and "server is unavailable" patterns of the classifier; the
  DSRM rows in name order; and the Identity export filter ignoring case.
- **Text that said more than the code or the page.** The help of the directory seam said every
  call carried `-Server` for the domain; `Get-ADDomain` does not - it takes the caller's AD
  parameters, as the script's older calls do - and the help and the test name now say so (the
  behaviour is unchanged). "Microsoft does not publish who can read the expiry attributes"
  overstated it: the general default is published, a LAPS-specific statement is not. The
  domain functional level values were cited from the forest-level page without a caveat in the
  code. The recommendation source comment gave laps-concepts-overview for the legacy migration
  advice, whose sentence is on laps-overview.

Seventeen mutations - the reviewer's ten, six that each undo one part of the three behaviour
fixes, and the old help sentence restored - were applied one at a time to a copy of the
script outside the working tree; the C4 tests failed on every one, and the copy was restored
byte for byte and verified by SHA-256 after each.

**Not done, and recorded as plan rows.** The Windows LAPS policy in each DC's registry, which
is what would say whether DSRM backup is configured, not only visible (C4a). The wildcard in
the Identity export (C4b). Grading older Windows on the legacy attribute (C4c). A presence
test of the confidential DSRM attribute, as an opt-in (C4d). What only a real directory can
show (C4e).

**Not verified.**

- Nothing against a real directory: see the first paragraph.
- That a DC with DSRM password backup on carries `msLAPS-PasswordExpirationTime` on its
  computer object. Microsoft does not state it; the rows call it an inference.
- Who can read the two expiry attributes by default, in a real forest. Microsoft publishes it
  only in general terms - "Default security in Active Directory is set so that authenticated
  users have read access to all attributes", in a KB that applies to Windows Server 2003 - and
  gives `SearchFlags: 0` (not confidential) for the Windows one and nothing for the legacy one.
  There is no LAPS-specific statement, and permissions can differ per organizational unit.
- The exception types of an unreachable server and of a refused read from the ActiveDirectory
  cmdlets. Microsoft Learn does not list them, the module is not installed on the build
  machine, and the three-way wording rests on type names that no test has seen a real
  directory produce.
- What `Get-ADComputer` returns for `objectClass` when asked, and whether it returns managed
  service accounts at all. The code accepts a string or a collection and excludes by class
  either way.
- How cluster and other virtual computer objects can be recognised. No marker was found on
  Microsoft Learn; they are left out by having no `operatingSystem`, which is a heuristic.
- Whether the April 11, 2023 update is installed on a computer. The directory holds the build,
  not the revision, so "can run Windows LAPS" means the release.
- Time and memory of the computer query on a large domain. No page size or result limit is
  set, here or anywhere else in the script.
- The domain functional level numbers 7 and 10 were read on the MS-ADTS page for the forest
  level (6.1.4.4); the page for the domain level was searched for on Learn and not found, so
  that it holds the same values is an assumption, now said in the config comment and in the
  row that reports an unknown level (PORT-PLAN C4f).
- Which exception a query that times out raises. A `TimeoutException` or
  `ServerTooBusyException` is reported `Timed out:`; that a real slow query raises one of them
  is not verified (PORT-PLAN C4e).

**Vendor sources**, all on Microsoft Learn, read 2026-11-15:

- Attribute names, their `SearchFlags`, the legacy mapping, `Update-LapsADSchema` and
  `msLAPS-CurrentPasswordVersion`:
  https://learn.microsoft.com/windows-server/identity/laps/laps-technical-reference
- DSRM requirements (domain functional level 2016, Windows Server 2019 or later DC), the
  schema extension as "a one-time operation for the entire forest",
  `Set-LapsADComputerSelfPermission`, `BackupDirectory` = 2, and that a forest backing up to
  Microsoft Entra ID only needs none of it:
  https://learn.microsoft.com/windows-server/identity/laps/laps-scenarios-windows-server-active-directory
- Policy settings, their defaults, and that the CSP does not support `ADBackupDSRMPassword`:
  https://learn.microsoft.com/windows-server/identity/laps/laps-management-policy-settings
- The OS builds that can run Windows LAPS ("Applicable OS" of each policy):
  https://learn.microsoft.com/windows/client-management/mdm/laps-csp
- `msLAPS-PasswordExpirationTime` as the sign of a successful move to Windows LAPS:
  https://learn.microsoft.com/windows-server/identity/laps/laps-scenarios-migration
- Password encryption as Microsoft's recommendation; DSRM passwords backed up only to Active
  Directory and only encrypted:
  https://learn.microsoft.com/windows-server/identity/laps/laps-concepts-overview
- Supported platforms, Active Directory or Microsoft Entra ID but not both, and migration from
  legacy Microsoft LAPS as Microsoft's recommendation ("We strongly recommend that you begin
  planning now to migrate", support statement section; re-read 2026-11-16):
  https://learn.microsoft.com/windows-server/identity/laps/laps-overview
- Legacy Microsoft LAPS on a domain controller is always ignored:
  https://learn.microsoft.com/windows-server/identity/laps/laps-scenarios-legacy
- The `Get-LapsADPassword` example with source `EncryptedDSRMPassword`, and that the cmdlet
  returns the password:
  https://learn.microsoft.com/powershell/module/laps/get-lapsadpassword
- Confidential attributes, the read access check on a search filter, and that authenticated
  users read every attribute by default (re-read 2026-11-16):
  https://learn.microsoft.com/troubleshoot/windows-server/windows-security/mark-attribute-as-confidential
- Windows Server 2025 DCs and confidential attributes on an unencrypted session (event 3079):
  https://learn.microsoft.com/troubleshoot/windows-server/windows-security/confidential-attributes-unexpected-behavior-using-windows-server-2025-dc
- `msDS-Behavior-Version` 7 and 10, on the page for the FOREST functional level (re-read
  2026-11-16):
  https://learn.microsoft.com/openspecs/windows_protocols/ms-adts/564dc969-6db3-49b3-891a-f2f8d0a68a7f
- Windows Server 2019 = build 17763:
  https://learn.microsoft.com/windows-server/get-started/windows-server-release-info
- `userAccountControl` flags:
  https://learn.microsoft.com/troubleshoot/windows-server/active-directory/useraccountcontrol-manipulate-account-properties
- A group managed service account is a subclass of computer:
  https://learn.microsoft.com/windows/win32/adschema/c-msds-groupmanagedserviceaccount

The Active Directory scenarios page was fetched in full in the session that wrote the code, and
passages of the technical reference, the policy settings page, the CSP page and the migration
page were re-read there through a documentation search. The others were read the same day by
the research step that preceded it, and its quotations were used as given.

### Added — 2026-11-13 (DC hardening: LDAP signing and channel binding, SMB signing, LAN Manager level, tool v1.20.0)

**PORT-PLAN C3.** `-Sections DcHardening`, already part of the default `All` run, now reads six
registry values per domain controller and grades each one. It closes or narrows seven rows of
the gap analysis (ADA-LDAP-001, -002, -003, ADA-SMB-001, -002, ADA-NTLM-001, ADA-INV-019). Before
this change the section read one of the six, `LDAPServerIntegrity`, and called anything other
than 2 a `Warning`, an absent value included, with no reason.

**This has run only against stubs.** No part of it has been executed against a real directory
or a real domain controller. No `Invoke-CimMethod`, `Get-CimInstance` or registry read in it has
met a real DC. The first run against a real forest is PORT-PLAN C17, owned by the operator.

**These rows show configured policy, not what is negotiated on the wire.** Every value is read
from the registry of the DC. No LDAP bind and no SMB session is attempted, and each of the six
setting rows says so in its `NotRun` column. Microsoft's own live check of LDAP signing is a
simple bind on port 389 that "sends simple-bind credentials without TLS. Run it only in an
isolated lab"; this tool does not make one (PORT-PLAN C3e).

**What it reads, per DC**, in one CIM session (WinRM first, DCOM second, no retry after a
refusal):

| Row | Value | Passes at |
| --- | --- | --- |
| `LDAP server signing: <dc>` | `NTDS\Parameters`, `LDAPServerIntegrity` | 2 |
| `LDAP server signing enforcement: <dc>` | `NTDS\Parameters`, `LDAPServerEnforceIntegrity` | 1, from Windows Server 2025; `Info`, not applicable, below it |
| `LDAP channel binding: <dc>` | `NTDS\Parameters`, `LdapEnforceChannelBinding` | 2 |
| `SMB server signing: <dc>` | `LanManServer\Parameters`, `RequireSecuritySignature` | 1 |
| `SMB client signing: <dc>` | `LanManWorkstation\Parameters`, `RequireSecuritySignature` | 1 |
| `LAN Manager authentication level: <dc>` | `Control\Lsa`, `LmCompatibilityLevel` | 5 |
| `Print Spooler: <dc>` | `Win32_Service` (State, StartMode) | Stopped |
| `SMBv1: <dc>` | `MSFT_SmbServerConfiguration.EnableSMB1Protocol`, by instance query - which returned no instance on the one host measured; see "Found by an independent review" below | False |

Plus `Win32_OperatingSystem.BuildNumber`, the DC's own statement of its build. A value below the
expectation is a `Warning`, the rule the AdAssessment26 catalogue gives for these rows; a number
Microsoft publishes no meaning for is `Not Assessed`. `EnableSecuritySignature` is not read:
Microsoft documents it as ignored for SMB2 and later.

**The expected value is Microsoft's; the status is not.** Each expectation is the value a
Microsoft page gives for a domain controller, cited in the row. What a DC is called for missing
it - `Warning`, or `Fail` where a config file says so - is **a tool default, not a Microsoft
value**, and every row graded that way says so.

**A value that is not set.** It is not a failure by itself and not a pass by itself. Where
Microsoft documents the default for the DC's OS build, the row is graded on that default and
says so ("graded on that documented default, not on a configured value", with the source).
Where it does not, the row is `Not Assessed` with the reason. The only boundary Microsoft
publishes for these defaults is "Windows Server 2022 or earlier" against "Windows Server 2025 or
later", so the table is keyed on build 20348 and below, and 26100 and above; a build between
the two, or one that was not read, has no documented default.

| Setting, not set | Build 20348 and below | Build 26100 and above |
| --- | --- | --- |
| LDAP server signing | default None: `Warning` | decided with the enforcement value, below |
| LDAP channel binding | default Never: `Warning` | `Not Assessed` - "When supported" is published for new deployments only |
| SMB server signing | `Not Assessed` unless the second instrument was read | the same |
| SMB client signing | default Disabled: `Warning` | default required: `Pass`, named as a default |
| LAN Manager level | default 3, from Windows Server 2008 R2 (every build above 7100): `Warning` | `Not Assessed` - NTLMv1 is removed and the default is not restated |

**LDAP signing on Windows Server 2025.** With `LDAPServerEnforceIntegrity` = 1 the signing row
passes whatever `LDAPServerIntegrity` holds, because Microsoft documents that the enforcement
policy takes precedence. With it = 0 the older value decides. With neither set, both rows pass
on the documented default. With the enforcement value not set and a signing value below 2
present, both rows are `Not Assessed`: Microsoft documents both that an upgrade "maintains your
current settings" and that Not Configured "has the same effect as Enabled", and the registry
does not show which applies. `LDAPServerIntegrity` = 2 passes on every build. A number
Microsoft publishes no meaning for decides nothing in either row: a signing value of 3 is not
"at least 2", and an enforcement value of 2 is neither Enabled nor Disabled.

**SMB server signing has a second instrument, where the DC returns one.**
`MSFT_SmbServerConfiguration.RequireSecuritySignature` is asked for in the same session, by
instance query. Microsoft's own verification is the cmdlet `Get-SmbServerConfiguration`, which
returns an object of that class; this tool does not run the cmdlet. Where the instance was
returned and the registry value is set, the row is graded on the registry and says whether the
second instrument agrees; where the two disagree the row is `Not Assessed`. Where the registry
value is not set, the row is graded on the second instrument, which is a measurement and not a
default. **On the one host measured the query returns no instance**, and then there is no
second instrument: a registry value that is set is graded alone, with that said, and one that
is not set is `Not Assessed`.

**Results that are kept apart.** Unreachable (no port answered, no read attempted); access
denied for the DC, or for one value (return 5, 0x80041003, or a thrown refusal); not set
(return 1); key absent (return 2); present with another type (0x80041005); any other failure,
with the code quoted and not interpreted. The reading of 1 and 2 is **measured on one Windows 11
workstation, not published by Microsoft**, and each row that relies on it says so. A value that
was not read is never turned into a number: for four of the six settings 0 means "disabled".

**Not published on Microsoft Learn**, and labelled so in the config table and in the findings
that rely on it: the registry path of `LDAPServerIntegrity` for AD DS (Learn gives it for AD LDS
only; PORT-PLAN C3a), so every `LDAP server signing` row, passing or not, says the path is
inferred; what its value 1 means, so 1 is reported as "not 2"; a value table for
`LDAPServerEnforceIntegrity`, so 0 is reported as "Disabled, inferred"; what an absent
`RequireSecuritySignature` means on a domain controller; the default `LmCompatibilityLevel` on
Windows Server 2025; the default channel binding on an upgraded 2025 DC; and which return code
`GetDWORDValue` gives for which condition.

**Every scoped domain is in the section.** DcHardening now takes its DCs as DcDisk does - from
the DC inventory, or from its own enumeration of each scoped domain when `DomainControllers` was
not selected - and gives a scoped domain with no DC row a `Not Assessed` row of its own. This is
PORT-PLAN C2e, done for this section only. It probes through the shared port cache, which is
C1b, done for this section only.

**The expectation can be changed from a file.** `-ConfigOverridePath` accepts a second section,
`DcHardening`: under `Settings`, per setting id, `ExpectedMinimum` (only to a value the tool can
grade against) and `OtherStatus` (`Warning` or `Fail`). The registry value a setting reads, the
meanings of its numbers, its defaults and its sources cannot be set from a file, and neither can
a status of `Pass` or `Info` for a weak value. Nor can the two ports: `WsmanPort` and `RpcPort`
are refused for this section, because its CIM session does not use them (PORT-PLAN C3g). A
finding cites the file for exactly what the file supplied.

**Read-only.** `GetDWORDValue` is the script's third CIM method, beside the two C2 added.
Microsoft documents it as returning "the data value for a named value whose data type is
REG_DWORD" and lists the `Set*` methods separately as the ones that create or change. As for
the other two, no page says in so many words that it has no side effect; the decision rests on
its documented purpose and signature. The test that reads every `Invoke-CimMethod` from the
parsed script now allows exactly three literal names and still fails on any other.

### Changed — 2026-11-13 (DC hardening rows and transports, tool v1.20.0)

- **Row names.** Rows are named family first: `Print Spooler: <dc>` (was `<dc>: Print Spooler`),
  `SMBv1: <dc>` (was `<dc>: SMBv1`), `LDAP server signing: <dc>` (was `<dc>: LDAP signing
  required`), and `DC hardening: <dc>` for a DC that could not be read (was the bare `<dc>`).
  Anything that matched the old `Item` strings in the CSV or JSON needs updating. Every row of
  the section now has a `NotRun` column.
- **One transport.** Print Spooler was read with `Get-Service -ComputerName`, which PowerShell 7
  does not have, so under PowerShell 7 the row was always `Not Assessed`; SMBv1 opened its own
  CIM connection; `LDAPServerIntegrity` used the .NET remote registry and ignored `-Credential`,
  as did the Spooler read. All three now go through the section's one CIM session.
- **Two false passes closed.** A missing `EnableSMB1Protocol` property read as "not enabled" and
  passed; it is now `Not Assessed`. A Spooler service in a state that is empty or `Unknown`, or
  not returned at all, is `Not Assessed` where it used to pass. `Stopped` is still a `Pass`
  and `Running` still a `Warning`; the start mode is now stated, not graded (PORT-PLAN C3b).
- **An absent `LDAPServerIntegrity`** was a `Warning` reading "LDAPServerIntegrity =  (2 =
  required)". It is now graded as described above.
- **Advice.** The section's `Warning` and `Fail` rows took their advice from three unscoped
  entries matched anywhere in the text, so a host name or an error containing "backup" or
  "replication" could pick another fault's advice. Each row family now has its own
  section-scoped entry, anchored on the family name the tool writes, and no other text of a
  DC Hardening row can reach an unscoped entry.
- **Shared helpers.** `Get-AdfaStdRegReturnClass`, `Get-AdfaDcPopulationGap`,
  `Get-AdfaDcPopulationGapText`, `ConvertTo-AdfaDcTarget` and `Invoke-AdfaDcRemoteRead` were
  taken out of the DcDisk code and are used by both sections. DcDisk's output is unchanged.

**Tests.** 89 new Pester tests in a new `Describe` (78 before the review below, 11 added by
it), and assertions in both harnesses. Four
existing C2 tests were changed, because they are declared-population counts over the whole
script and this change adds to those populations: the `Invoke-CimMethod` count and allow-list
(2 calls and two names, now 3 and three, twice), the `New-CimSession` / `Remove-CimSession`
count (2, now 3), and the `Get-CimInstance` count (4, now 6). The smoke harness's count of
unusable override files went from six to eight with the two cases this change adds. No other
existing test was changed.

**The guards were shown able to fail.** The tests of this row were written with the code, so
they could not all be shown red first. Instead 143 single mutations were applied one at a time
across every new function, the config table, the recommendation map and the wiring - a verdict
turned round, a `Not Assessed` turned into `Pass`, an unreachable DC read as reachable, access
denied reported as a read failure, a validation removed, a boundary moved by one, a loop cut to
its first item. Each was applied to an isolated copy of the tree, run against the C2 and C3
`Describe`s, and the copy restored and verified by SHA-256; the working tree was never the
thing mutated. Eleven survived at first, which is eleven tests that were missing. Each now has
a test that fails on it: one DC without a domain in a population row; a second instrument
marked as not read; a build reported as 0; a `uValue` handed back beside a nonzero return code;
a result with no return code; a config that differs from the built-in table reaching the seam,
and reaching the rows; ports 0 and 65536; the last build before Windows Server 2025; and DCOM
tried although the RPC port did not answer. On the final pass all 143 are caught. That pass,
the gate under Windows PowerShell 5.1 and the changes they led to were made on 2026-11-15.
The last of the eleven has a twin in code this change did not write: the same line in the
`DcDisk` collector is held by no C2 test either. That is PORT-PLAN C2g, not fixed here.

**Found by an independent review of the diff before commit, and fixed in it.** The review
confirmed fifteen findings against the uncommitted change. All fifteen are fixed here, on
2026-11-15; none was judged wrong. Each behaviour finding has a test that fails without the fix.

1. *A false Pass.* With `LDAPServerEnforceIntegrity` not set on a Windows Server 2025 DC, the
   enforcement row passed beside any `LDAPServerIntegrity` number of 2 or more - 3 and
   4294967295 included - and said that number "requires signing", while the signing row of the
   same DC said Microsoft publishes no meaning for it. The test was "at least 2", not "a
   documented value". The enforcement row is now `Not Assessed` beside a number with no
   published meaning, and with the signing setting's meanings not supplied it takes no number
   as documented.
2. *A cause that was lost.* When the OS build was not read, the enforcement row said only that
   the build was unread: access denied, an absent key, a wrong type and a failed read all
   disappeared from it, while the DC's other five rows said "Access denied". The cause of the
   read now comes first in that row, and the `Info` row below Windows Server 2025 states it too.
3. *A false cause.* The signing row said the enforcement value "was not read" when it had been
   read and held a number that is neither 0 nor 1. It now says the value was read, what it
   holds, and that the number settles nothing.
4. *A sentence that contradicted itself.* A LAN Manager level not set on build 7100 or below was
   told that Microsoft documents no default for its build, because the pages cover "build 20348
   and below". The reason is now built from the ranges of that setting's own rows.
5. and 8. *An instrument that returns nothing* (reported twice, by two reviewers). The `SMBv1`
   row and the second instrument of SMB server signing read `MSFT_SmbServerConfiguration` by
   instance query. Measured during the review and again for the fix - one Windows 11 build 26100
   workstation, not a domain controller, not elevated, PowerShell 7 and Windows PowerShell 5.1 -
   that query returns **no instance and no error**, plain, with `-Property` and as WQL, while
   `Get-SmbServerConfiguration` in the same process returns `EnableSMB1Protocol` False and
   `RequireSecuritySignature` True. The cmdlet calls the class's static method
   `GetConfiguration`. The Pester stub and the smoke stub handed back an instance, so the green
   tests proved the stubs; and the README, this entry and a config comment said the property
   read "is what Microsoft's own verification reads", which is true of the cmdlet and not of
   the query. The code did fail closed - `Not Assessed`, never a false pass - but as a read
   failure, with nothing to say it was the normal answer. **What changed:** `GetConfiguration`
   is *not* invoked - it is not one of the three registry `Get*` methods the script is held to,
   Microsoft Learn documents the cmdlet and not the class or its methods, and widening the
   allow-list is the operator's decision (PORT-PLAN C3f). A class that returns no instance is
   now its own result, "Not read", `Not Assessed`, saying what was measured, naming the method
   that is not invoked and giving Microsoft's cmdlet as the check to run on the DC; it is told
   apart from access denied and from a query that failed. Both stubs now return the measured
   shape by default, and the tests that hand back an instance say that shape is unmeasured. The
   three texts say only what the page says. **What this means for a run:** wherever a DC answers
   as the workstation did, SMBv1 is not graded and SMB server signing has no second instrument.
   The same instance query was in the section before this change, so SMBv1 may never have been
   graded by this tool; that has not been measured on a DC.
6. *An override that did not do what its name says.* `WsmanPort` and `RpcPort` under
   `DcHardening` changed the port probed and the port named in the `Unreachable` row, but the
   CIM session is opened without a port: with 5986 in the file, a DC listening on 5985 was
   reported unreachable without a read being attempted. Both keys are now refused for this
   section, with the reason, and a test reads the parsed seam to show the session is given no
   port. `DcDisk` and `DcSystem` accept the same two keys and have the same gap; they are
   unchanged, the README now says so for both, and it is PORT-PLAN C3g.
7. *Two targets in one row.* With `ExpectedMinimum` lowered from a file, the finding said "below
   the expected minimum of 3" and its recommendation said to set level 5. The advice for the
   two settings whose expectation can be moved - channel binding and the LAN Manager level -
   now says to raise the setting to at least the minimum the finding names, and gives
   Microsoft's baseline value as Microsoft's.
9. to 13. *Five tests that could not fail*, each shown by a mutation that survived all 188 C2
   and C3 tests: an empty SMB result fabricated into SMBv1 False and signing True; any
   enforcement number other than 0 making the signing row pass; 0 (Never) added to the
   channel-binding `ExpectedChoices`, which would have let a file make every channel-binding
   value pass; the collector probing with a fixed 1200 ms instead of `-PortTimeoutMs`; and the
   source of an unknown default dropped from the rows that are `Not Assessed` for it. Each now
   has a test, and so does the one the reviewer called near-equivalent (the build query's error
   kept as the first error when nothing answered).
14. *A README sentence the code did not keep.* "A value that is set is graded whatever the
    build" is true of four settings, not of the two LDAP signing rows. The README now says which.
15. *A quotation the page does not carry.* "NTLMv1 is removed starting in Windows 11, version
    24H2 and Windows Server 2025." was in quotation marks beside the Windows Server page, which
    says "NTLMv1 is removed. LANMAN and NTLMv2 are no longer under active feature development
    and are deprecated." The fact was right; the config comment now quotes the page it cites.

Tests changed because behaviour changed, all of them tests this same change had added: the
validator test that merged `WsmanPort` and the six "port that is not a port" cases now assert
the refusal; the collector test that set the two ports through the validator sets them on a
copy of the table; the seam's default stub and its expectations follow the measured SMB shape;
and one seam test now names its four `Not Assessed` rows where it counted three; the port
assertions and the stubs in the two harnesses were changed the same way, and the smoke harness
now counts four passing rows per DC where it counted five, SMBv1 no longer being one of them.
No test from before this change was touched, and the 110 C2 tests are unchanged and green.

**The review's guards were shown able to fail.** 23 single mutations, one or more per finding
and the reviewers' own five among them, were applied one at a time to a copy of the tree under
Windows PowerShell 5.1 with Pester 5.9.1: a green baseline on the copy first (199 run, 0
failed - the 110 C2 tests and the 89 C3 tests), each mutation run against the C2 and C3
`Describe`s, the copy restored after each, a green baseline on the restored copy at the end, and
the working tree's script verified unchanged by SHA-256. The working tree was never the thing
mutated. All 23 are caught; before the fixes the reviewers' five survived all 188 tests then
present. The first attempt at this pass copied only the script and the test file, so two tests
that read `README.md` failed on the copy before any mutation was applied; it was stopped and
discarded for that reason, and the pass was repeated on a copy of the whole tree.

**Found by reading the rows that pass, not by a test.** A default that fell short read "it
below the expected minimum"; it now reads "it is below". The row for the Windows Server 2025
enforcement policy, where it is `Info` and not applicable, carried the sentence about return
code 1 although it rests on no reading of one; it no longer does. Both are pinned by tests.

**Not verified.** Everything a real DC would answer: the return codes of `GetDWORDValue` on a
domain controller, over WinRM, over DCOM and under Windows PowerShell 5.1 (measured only on a
Windows 11 workstation, local session, PowerShell 7); that `Win32_Service` returns the
properties read, in the types assumed; **whether `MSFT_SmbServerConfiguration` returns any
instance to an instance query on a domain controller, remotely, or elevated** - on the one
workstation measured, locally and not elevated, it returns none, so the `SMBv1` row and the SMB
signing second instrument may be `Not Assessed` on every DC (PORT-PLAN C3f); whether the
unadapted CIM store differs from the adapted members for these classes; the rights the
registry reads need beyond local Administrators; and which of the six values a real DC has set
or absent. The `MSFT_SmbServerConfiguration` class schema is not published on Learn, only the
cmdlet pages; its three methods were read from the class on the workstation.
The Azure baseline pages are machine-configuration renderings of the baselines, not the
Security Compliance Toolkit download.

**Vendor sources**, read 2026-11-13 except where a line gives another date:

- LDAP signing defaults, Windows Server 2025 behaviour, events 2887 and 2889:
  <https://learn.microsoft.com/windows-server/identity/ad-ds/ldap-signing>
- `LDAPServerIntegrity` values (AD LDS), the enforcement policy and its precedence, the lab-only
  warning: <https://learn.microsoft.com/windows-server/identity/manage-ldap-signing-group-policy>
- `LDAPServerIntegrity` path for AD LDS:
  <https://learn.microsoft.com/troubleshoot/windows-server/active-directory/enable-ldap-signing-in-windows-server>
- `LDAPServerIntegrity`=2 on domain controllers:
  <https://learn.microsoft.com/troubleshoot/windows-server/active-directory/ldap-session-security-settings-requirements-adv190023>
- LDAP signing policy defaults and recommendation:
  <https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/domain-controller-ldap-server-signing-requirements>
- Channel binding values, defaults and events:
  <https://learn.microsoft.com/windows-server/identity/ad-ds/ldap-channel-binding>
- Baseline rows (`LDAPServerEnforceIntegrity`, `LdapEnforceChannelBinding`, both
  `RequireSecuritySignature`, `LmCompatibilityLevel`):
  <https://learn.microsoft.com/azure/governance/policy/samples/guest-configuration-baseline-windows-server-2025>
- SMB signing registry values, `EnableSecuritySignature` ignored, DC default:
  <https://learn.microsoft.com/windows-server/storage/file-server/smb-signing-overview>
- SMB signing on Windows Server 2025, verification (by the cmdlet `Get-SmbServerConfiguration
  | FL RequireSecuritySignature`; re-read 2026-11-15) and remediation:
  <https://learn.microsoft.com/windows-server/storage/file-server/smb-signing> and
  <https://learn.microsoft.com/windows-server/storage/file-server/smb-security-hardening>
- SMB signing policy defaults:
  <https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/microsoft-network-server-digitally-sign-communications-always>
  and
  <https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/microsoft-network-client-digitally-sign-communications-always>
- `LmCompatibilityLevel` location, levels and default:
  <https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/network-security-lan-manager-authentication-level>
- `LmCompatibilityLevel` 5 on a DC, NTLMv1 audit:
  <https://learn.microsoft.com/troubleshoot/windows-server/windows-security/audit-domain-controller-ntlmv1>
- NTLMv1 removed in Windows Server 2025 (re-read 2026-11-15; the page's words are "NTLMv1 is
  removed. LANMAN and NTLMv2 are no longer under active feature development and are
  deprecated", and it lists NTLMv1 under "Features removed"):
  <https://learn.microsoft.com/windows-server/get-started/removed-deprecated-features-windows-server>
- `Get-SmbServerConfiguration`, "Retrieves the SMB server configuration", output "The
  MSFT_SmbServerConfiguration object" (read 2026-11-15):
  <https://learn.microsoft.com/powershell/module/smbshare/get-smbserverconfiguration>
- `GetDWORDValue`:
  <https://learn.microsoft.com/previous-versions/windows/desktop/regprov/getdwordvalue-method-in-class-stdregprov>
  and <https://learn.microsoft.com/windows/win32/wmisdk/obtaining-registry-data>
- `Win32_Service` State and StartMode:
  <https://learn.microsoft.com/windows/win32/cimwin32prov/win32-service>
- Print Spooler on domain controllers:
  <https://learn.microsoft.com/defender-for-identity/security-posture-assessments/identity-infrastructure>
- SMBv1 detection (by the cmdlet `Get-SmbServerConfiguration | Select EnableSMB1Protocol`, and
  the `SMB1` registry value with its "no registry named value is created" default; re-read
  2026-11-15), removal and audit:
  <https://learn.microsoft.com/windows-server/storage/file-server/troubleshoot/detect-enable-and-disable-smbv1-v2-v3>
- Remote WMI rights:
  <https://learn.microsoft.com/troubleshoot/windows-server/system-management-components/scenario-guide-troubleshoot-wmi-connectivity-access-issues>
- Windows Server 2008 R2 as every build above 7100, the lower bound of the LAN Manager default
  (read 2026-11-15): <https://learn.microsoft.com/windows/win32/msi/operating-system-property-values>

### Added — 2026-11-13 (DC disk space, and one override file for section config, tool v1.19.0)

**PORT-PLAN C2.** New `-Sections DcDisk`, included in the default `All` run, and a new
parameter `-ConfigOverridePath`. It closes one row of the gap analysis (ADA-DISK-001): the tool
read nothing about the disks a domain controller's database, logs and SYSVOL sit on.

**This has run only against stubs.** No part of it has been executed against a real directory
or a real domain controller. No `Invoke-CimMethod`, `Get-CimInstance` or registry read in it has
met a real DC. The first run against a real forest is PORT-PLAN C17, owned by the operator.

**What it reads, per DC.** Three registry values, then the volume list, in one CIM session
(WinRM first, DCOM second):

| Role | Value under `HKLM\SYSTEM\CurrentControlSet\Services` |
| --- | --- |
| NTDS database | `NTDS\Parameters`, `DSA Database File` (a file path) |
| NTDS logs | `NTDS\Parameters`, `Database Log Files Path` |
| SYSVOL | `Netlogon\Parameters`, `SysVol` |

Each path is matched to the `Win32_Volume` whose mount path is its longest prefix, so a
database under a mounted folder is judged on the right volume. One row per distinct volume,
listing the roles it holds; a DC with everything on `C:` gives one row, not three.

**Thresholds: tool defaults, not Microsoft values.**

| Result | Free space, share of the volume | Or free space, absolute |
| --- | --- | --- |
| `Fail` | below 10 % | below 2 GB |
| `Warning` | below 20 % | below 5 GB |

Either test is enough and the finding says which fired; "below" is strict. Microsoft publishes
no free-space threshold for these volumes. The three figures it does publish are relative to
the database, not the volume: "make sure the free space you have available is 110% of the
`NTDS.dit` size", for offline defragmentation; "allocating enough free space to equal 300% of
the DIT size is a safe way to accommodate growth and defragging"; and, for a fixed VHD, "at
least 210% the size of the DIT". This section does not read the database file size, so none of
them is **evaluated**, and the row for the database volume says so in its `NotRun` column
(PORT-PLAN C2a). Figures in a finding are cut off after two decimals, never rounded. 20 % and 10 % are the pair the AdAssessment26 catalogue lists for this check
as operator-set. The absolute floor is this tool's addition, because 25 % of an 8 GB volume is
2 GB; it is kept low so a correctly sized 10 to 20 GB dedicated volume is not flagged. Every
finding prints the thresholds in force and "tool default, not a Microsoft value".

**Results that are kept apart.** Every role is accounted for by exactly one row. Where it could
not be judged the row is `Not Assessed` and says which of these happened:

| Situation | Row |
| --- | --- |
| Neither port answered | `Unreachable`, no read attempted |
| The DC refused the session or the read, or the provider returned 5 or `0x80041003` | `Access denied`: local Administrators rights needed |
| The provider returned 1 | `Not found`, read as the value not being set. **No default path is assumed** |
| The provider returned 2 | `Not found`, read as the registry key not existing |
| The provider returned `0x80041005` | The value is present but is not a string |
| Any other error or return code | `Read failed`, quoted, not interpreted |
| Value empty, or still holding `%VARIABLE%` | Says so, with the value |
| Path under no volume the DC returned | Names the path and the volumes |
| Volume list could not be read | Every role `Not Assessed`, with the cause |
| Volume returned no capacity | `Not Assessed` for that volume, with the values returned |

No row is `Info`. No row is `Pass` unless both the capacity and the free space were read.

5, `0x80041003` and `0x80041005` are read by the names WinError.h and WbemErrorEnum give them.
**1 and 2 are read on a measurement, not on a Microsoft statement**: on one Windows 11
workstation (not a domain controller), with the same two methods, the provider returned 1 for a
value that does not exist under a key that does and 2 for a key that does not exist. Each
`Not found` row says so.

**Every scoped domain is in the section.** With `DomainControllers` selected the DCs come from
the inventory; without it the section enumerates each scoped domain itself, so `-Sections
DcDisk -AllDomains` covers every domain and every row carries its domain. A domain whose DCs
could not be enumerated, or that returned none, gets its own `Not Assessed` row.

**The registry is read with a CIM method call - the first, and the only, in this script.** The
house rule is "no CIM method invocation". `StdRegProv` exposes no instances, so a value can be
read through it only by calling a method, and it rides the same session as the volume query,
so one transport, one timeout and one WinRM-to-DCOM fallback cover both; the older
`OpenRemoteBaseKey` route used elsewhere in the script is a separate connection with no
fallback of its own. Decision: `GetStringValue` and `GetExpandedStringValue` are
accepted as reads. Microsoft describes them as "Gets the string data value of a named value" and
"Gets the expanded string data value of a named value", with the value as their only output.
It lists the class's 20 methods in one table and does not sort them into reading and writing
methods; that sorting is this tool's, made from each method's own description, and the ones
described as creating, deleting or setting (`CreateKey`, `DeleteKey`, `DeleteValue`, the `Set*`
methods) are never called. **Microsoft does not state that the `Get*` methods have no
side effect**; the decision rests on their documented purpose and signature, and the script
says so. Only `Get*` methods are used: `EnumValues`, which the reference tool calls first, is
not. Each call names its class and method literally, and a test reads every `Invoke-CimMethod`
from the parsed script and fails on any other method, a computed method name, or another class;
a second test fails on `Set-CimInstance`, `New-CimInstance`, `Remove-CimInstance` or any WMI
write cmdlet. `Win32_Volume` has methods that change a volume (`Format`, `Dismount`, `Chkdsk`,
`Defrag`); none is called, only instances are read.

`Invoke-CimMethod` honours `-WhatIf`, and under it "The cmdlet is not run". A `WhatIf`
preference in the caller's session would have skipped the read and left nothing to judge, so
`-WhatIf` and `-Confirm` are forced off on these two calls, which is safe only because both are
reads. They are forced off on `Remove-CimSession` as well, so a preference cannot leave a
session open on each DC.

The registry type of the three values is not published. `GetStringValue` is documented for
`REG_SZ`, so where it returns nothing usable the value is read again with
`GetExpandedStringValue`; that second read is not made after a refusal (5 or `0x80041003`).

**`-ConfigOverridePath`: one file, one key per section.** A JSON object whose top-level keys
are section names; each value goes to that section's own validator. `DcDisk` is the only
section so far:

```json
{ "DcDisk": { "WarnBelowPercent": 25, "FailBelowPercent": 15, "WarnBelowFreeGB": 10, "FailBelowFreeGB": 5 } }
```

It is built so a later check adds one line to `$script:ConfigOverrideSections` and writes its
own `Merge-*` function; the two loader functions do not change, and a test proves that with a
second, made-up section. The file is read once, **before the directory is contacted**, and
anything wrong with it stops the run before anything is collected: a missing or empty file,
text that is not JSON, JSON `null`, an array or a string, an empty object, a key or a section
written twice, an unknown section, a section set to `null`, an unknown key, or a value its
section cannot use. An array is refused even when it holds one valid object, and a repeated
key is found in the file's text, because the parser hides both: PowerShell 7 unwraps a
one-element array, and both editions keep the last of two equal keys without an error. For
`DcDisk` that
means a value that is not a JSON number (a number in quotes is refused, not parsed), a
percentage outside 0 to 100, a negative floor, `Fail` above `Warning` once the file is merged
with the built-in values, a table left with no threshold at all, or a port that is not a port.
`Paths`, `SourceUrl` and `ReadDate` cannot be set from the file: a file that redirected the
registry reads would make every finding describe something else. The file is validated in full
even when `-Sections` leaves out the section it names, and the log then says so.

Provenance moves key by key. A file that supplies only `WarnBelowPercent` produces findings
that cite the file for that key and go on calling the other three "tool default, not a
Microsoft value". A file that changes only a port leaves the label alone.

`-ExchangeSeConfigPath` and `-DcSystemConfigPath` are unchanged and keep their own files.
`"DcSystem"` or `"ExchangeSe"` as a top-level key of the new file is refused as an unknown
section; folding them in is PORT-PLAN C2d, because it has to decide what happens when both
sources name the same section.

**Advice.** One section-scoped entry answers every `Warning` and `Fail` row, placed ahead of
the unscoped entries. A row of this section names SYSVOL, and without that entry the unscoped
`sysvol|dfsr` entry would have advised an authoritative DFSR restore for a full disk. The text
is Microsoft's own order of steps for a database volume short of space: move unrelated files to
another volume, take a system state backup, defragment offline. A test pins that neither the
row's wording nor an override file path full of other entries' keywords can replace it. The
note about the 110 % figure is in `NotRun`, so it is added to the finding after the advice has
been chosen.

**Found while building, and fixed: `Get-Help` could not read this script's help at all.** The
licence banner sat directly above the help block with no blank line between them, which makes
the two one comment. `Get-Help .\Invoke-ADForestAssessment.ps1` showed only the auto-generated
syntax line, for every parameter. The same was true at v1.18.0, the only earlier version
checked. One blank line fixes it. A test now reads the help the way `Get-Help` does and fails if it comes back empty.

**The guards were shown able to fail.** Against a green baseline, 32 single changes were made
to the new code one at a time, the new tests run after each, and the script restored and
verified by SHA-256 after each. All 32 turned at least one test red: a reversed verdict; an
unusable figure or an unread registry value reported as `Pass`; an unreachable DC treated as
reachable; a refusal reported as a read failure, at the DC and at the value; an absent value
no longer told apart; six validation checks removed, one at a time; the section branch, the
file load and the hand-over of the file's table each dropped; both thresholds off by one; a
loop that handled only the first DC; `SetStringValue` planted in place of a read, and a
computed method name; `-WhatIf` no longer forced off; first-match in place of longest-prefix;
non-local volumes admitted; file thresholds still labelled tool defaults; the advice entry
detached; and the not-measured note moved into the detail. Two of them, the file never being
loaded and its table never reaching the section, would have passed the first draft of the
Pester wiring tests, which matched text; those tests were rewritten to read the parsed script
before the run, and the smoke harness also catches both.

**Found by an independent review of the diff before commit, and fixed in it.** Twenty-two
findings, several of them the same defect seen by more than one reviewer.

- *A registry value that is not set was never reported as `Not found`.* The code and every stub
  took the provider's return for an absent value to be 2. Measured on a workstation, it is 1;
  2 is an absent key. So the not-configured case fell into "Read failed: StdRegProv returned
  1 ... not interpreted", and the tests were green over a shape the provider does not produce.
  1 is now `Not found` (value not set) and 2 `Not found` (key does not exist), each labelled
  as measured and not published; the stubs answer as the provider was measured to.
- *`-Sections DcDisk -AllDomains` without `DomainControllers` read one domain's DCs and said
  nothing about the others.* The section now enumerates every scoped domain itself when there
  is no inventory, and gives each scoped domain with no DC row a `Not Assessed` row. The other
  per-DC sections still use the unscoped fallback: PORT-PLAN C2e.
- *A domain row said "none of their volumes was read" directly above a `Pass` row* when the
  inventory failed and the fallback enumeration still returned DCs. It now says that those DCs
  carry no domain and that the domain is not shown as read.
- *A figure could print as the threshold it was said to be below* ("10.00 % free ... Below the
  Fail threshold of 10 % free"), because 0.0000001 was added before truncating. Figures are now
  truncated in decimal arithmetic with nothing added. Plain rounding passed every earlier test.
- *PowerShell 7 accepted a top-level array holding one object* as an override file, and Windows
  PowerShell 5.1 refused it. Both refuse it now.
- *A key or a section written twice in the override file was applied with its last value.* The
  "more than once" checks could not fire for a file. It is now found in the text and refused.
- *A `WhatIf` preference left a CIM session open per DC per transport,* in this section and in
  the `DcSystem` seam added by C1. Both now force `-WhatIf` and `-Confirm` off when closing.
- *Tests that could not fail.* Each of these was applied to the script and left every test
  green; each now turns at least one test red: the credential dropped from the CIM session, or
  from the collector's call to the seam; `-Confirm:$false` removed from the method calls; the
  operation timeout removed from the method calls, or from the volume query; the event 1393
  consequence limited to the database, dropping the logs; an empty value no longer triggering
  the expanded read; a DC whose registry reads all threw reported as a whole-DC failure
  although its volume list was read; the collector handed the unscoped DC names in place of
  its targets; the enumeration error replaced by an empty string; and the `throw` removed
  where a refused override file stops the run.
- *Three statements attributed to Microsoft were the tool's own.* "Microsoft lists its methods
  in two groups": it lists them in one table. The return value "only" as a WinError.h code: the
  same pages send script callers to WbemErrorEnum, and the provider does return such codes.
  "Its one published figure" of 110 %: the page gives three. All three are corrected in the
  script, this file, the README and the plan.

After the fixes, 23 single changes were applied one at a time to a copy of the script - the
eleven above, plain rounding and the old addend in the figure formatting, and ten that undo a
fix - and the DcDisk Pester block run against each copy. Every one turned at least one test
red, against a baseline of 110 passed and none failed. The repository's script was never the
file changed, and its SHA-256 was the same before and after.

Existing tests that changed, each because the behaviour or the stub did. None was removed or
weakened.

- `quotes any other return code without interpreting it` used return code 1 as its example of
  an uninterpreted code. 1 now has a meaning, so the test uses 87.
- The two tests of an absent registry value (one on the pure layer, one on the CIM seam) used
  2. They now use 1, the return the provider gives for a value that is not set, and a new
  test beside each covers 2 for a key that does not exist. The Pester stub and the smoke stub
  answer 1 for a value they do not hold and 2 only for a key they do not hold.
- Four wiring and guard tests were tightened: the branch test asserts what each of the
  collector's eight parameters is given, not only that it is given; the inventory test asserts
  the three sources of the section's targets and their order; the load test asserts the
  rethrow; and the `-WhatIf` test asserts `-Confirm` as well.

**Vendor sources, all read on Microsoft Learn 2026-11-13.**

- Registry values for the database and log locations, and the `SysVol` value:
  [Microsoft Defender Antivirus exclusions on Windows Server](https://learn.microsoft.com/defender-endpoint/microsoft-defender-antivirus-exclusions-windows-server).
  That page prints the `SysVol` value under `ControlSet001`.
- The `SysVol` value under `CurrentControlSet\Services\NetLogon\Parameters`, and that after a
  migration to DFSR it points at the `SYSVOL_DFSR` copy:
  [Backing up and restoring an FRS-replicated SYSVOL folder](https://learn.microsoft.com/windows/win32/vss/backing-up-and-restoring-an-frs-replicated-sysvol-folder).
- `StdRegProv`, its namespaces, its single table of 20 methods and "Read, write, and delete
  data values":
  [StdRegProv class](https://learn.microsoft.com/previous-versions/windows/desktop/regprov/stdregprov).
- `GetStringValue`: signature, `HKEY_LOCAL_MACHINE` = 2147483650, and the return value: 0 if
  successful; for C++ "a nonzero error code that is defined in WinError.h ... You can also
  look up return values under the WMI Error Constants"; for scripting "a nonzero error code
  that you can look up in WbemErrorEnum":
  [GetStringValue method](https://learn.microsoft.com/previous-versions/windows/desktop/regprov/getstringvalue-method-in-class-stdregprov).
- `GetExpandedStringValue`, with the same return value text:
  [GetExpandedStringValue method](https://learn.microsoft.com/previous-versions/windows/desktop/regprov/getexpandedstringvalue-method-in-class-stdregprov).
- 1 is `ERROR_INVALID_FUNCTION`, 2 is `ERROR_FILE_NOT_FOUND` and 5 is `ERROR_ACCESS_DENIED`:
  [System Error Codes (0-499)](https://learn.microsoft.com/windows/win32/debug/system-error-codes--0-499-).
- `0x80041003` is `wbemErrAccessDenied` and `0x80041005` is `wbemErrTypeMismatch`:
  [WbemErrorEnum](https://learn.microsoft.com/windows/win32/api/wbemdisp/ne-wbemdisp-wbemerrorenum).
- `Remove-CimSession` and `-WhatIf` ("The cmdlet is not run"):
  [Remove-CimSession](https://learn.microsoft.com/powershell/module/cimcmdlets/remove-cimsession?view=powershell-5.1).
- `Win32_Volume`: `Capacity` and `FreeSpace` in bytes, `DriveType` 3 = Local Disk, `DeviceID`,
  and that the class returns unformatted and offline volumes:
  [Win32_Volume class](https://learn.microsoft.com/previous-versions/windows/desktop/legacy/aa394515(v=vs.85)).
- Longest prefix as the rule for mapping a path to its volume:
  [GetVolumePathNameW](https://learn.microsoft.com/windows/win32/api/fileapi/nf-fileapi-getvolumepathnamew).
- `Invoke-CimMethod` and `-WhatIf`:
  [Invoke-CimMethod](https://learn.microsoft.com/powershell/module/cimcmdlets/invoke-cimmethod?view=powershell-5.1).
- "By default, only members of the Administrators group can access the WMI namespace remotely":
  [Troubleshoot WMI connectivity and access issues](https://learn.microsoft.com/troubleshoot/windows-server/system-management-components/scenario-guide-troubleshoot-wmi-connectivity-access-issues).
- The 110 %, 300 % and 210 % of `NTDS.dit` figures, and no volume threshold:
  [Capacity planning for Active Directory Domain Services](https://learn.microsoft.com/windows-server/administration/performance-tuning/role/active-directory-server/capacity-planning-for-active-directory-domain-services).
- NTDS General event 1393 (updates fail with error 112, Net Logon is paused), quoted on a
  failing database or log volume:
  [Replication error 8456 or 8457](https://learn.microsoft.com/troubleshoot/windows-server/active-directory/replication-error-8456-8457).
- The remediation steps and their order:
  [Replication event IDs 2108 and 1084](https://learn.microsoft.com/troubleshoot/windows-server/active-directory/replication-event-id-2108-1084).

The `GetStringValue` and replication-event pages were read in full in the session that wrote
the code; the system error code list was read from a Learn search excerpt of the page; the
other facts were read on Learn earlier the same day by the research step of this row and are
used as that step recorded them. In the session that fixed the review findings, the
`StdRegProv`, `GetStringValue`, `GetExpandedStringValue`, `WbemErrorEnum` and
`Remove-CimSession` pages were read in full, and the capacity planning figures and the error
code names 1, 2 and 5 from Learn search excerpts of their pages.

**Measured, not published.** On 2026-11-13, on one Windows 11 (build 26100) workstation that
is not a domain controller, over a local CIM session and a DCOM session to itself, under
Windows PowerShell 5.1 and PowerShell 7.6, `GetStringValue` and `GetExpandedStringValue` each returned: 0 for a string
value that exists; 1 for a value that does not exist under a key that does; 2 for a key that
does not exist; 5 for a key the account may not read; 2147749893 (`0x80041005`) for a value
that is a `REG_DWORD`. Nothing was written, and no domain controller was contacted. On the
same two editions `ConvertFrom-Json` returned the last value for a key written twice, and
refused keys that differ only by case. The seam function was also run once against that
workstation itself, before and after the fix, with a `WhatIf` preference set: one CIM session
was left open before, none after, and the three values came back 2, 2 and 1 (the workstation
has no `NTDS\Parameters` key, and a `Netlogon\Parameters` key with no `SysVol` value). That is
the only time any part of this section has met a real provider, and it was not a DC.

**Not verified. Each of these is something Microsoft does not publish, or that only a real DC
can show.**

- That `Win32_Volume.Name` holds the mount path (`C:\`, `D:\Mount\NTDS\`). Learn describes it
  only as "Label by which the object is known". The mapping rests on it. If a real DC returns
  something else, the affected roles report `Not Assessed` naming the volumes returned.
- The registry type of the three values, and what `GetStringValue` returns for a
  `REG_EXPAND_SZ` value.
- Which return code the provider gives for an absent value, an absent key or a refusal **on a
  domain controller**. 1 and 2 are read as measured on one workstation, 5 by its WinError.h
  name; Microsoft publishes none of it. Not measured: Windows Server, a DC, a remote session
  over WinRM or DCOM. Any other code is quoted, not interpreted.
- That the section's own per-domain enumeration (`Get-ADDomainController -Filter * -Server
  <domain>`) returns every DC of a domain on a real forest. It is the call the DC inventory
  already makes; it has run only against a stub here.
- The rights needed. "Administrators" for remote WMI is Microsoft's default; the registry
  permission `StdRegProv` needs on the two keys is not published.
- Whether Windows PowerShell 5.1 applies a type adapter to `Win32_Volume` properties. The raw
  value is read first in case it does.
- Whether `Win32_Volume.FreeSpace` is affected by disk quotas for the account that asks.
- How a CIM operation behaves under the timeout over DCOM. One DC involves up to seven
  operations per transport.
- SYSVOL is judged on the volume of the path the `SysVol` value names. Whether DFSR staging or
  a junction target sits on another volume is not examined (PORT-PLAN C2c).

**Not done, and recorded as plan rows.** Free space against the 110 % of `ntds.dit` figure
(C2a). Telling an absent value from an absent key, and reading the value's type, which needs
`EnumValues` - not a `Get*` method (C2b). `DSA Working Directory` and the other SYSVOL
locations (C2c). Moving the Exchange SE and DC system tables into the new file (C2d).

### Fixed — 2026-11-13 (two dcdiag tests in every default run changed state, tool v1.18.0)

**PORT-PLAN H20. This changes what a default run tests. Read this before comparing a v1.18.0
report with an earlier one.**

The review of H19 found that a default run was still not read-only. `DcDiagnostics`, part of
the default `All`, ran two `dcdiag` tests on every DC that Microsoft documents as doing more
than reading (both read on Learn 2026-11-13):

- `dcdiag /test:DNS /DnsAll`. Its dynamic update test is described as: "perform registration of
  a test record (_dcdiag_test_record)... The test record is deleted automatically after the
  test."
  ([Verify DNS functionality](https://learn.microsoft.com/windows-server/identity/ad-ds/manage/troubleshoot/verify-dns-functionality-to-support-directory-replication))
- `dcdiag /test:Intersite /a`. Listed as working by "Reporting back any replication failures
  after triggering a replication."
  ([dcdiag](https://learn.microsoft.com/windows-server/administration/windows-commands/dcdiag))

H12 (v1.13.0) added the DNS test, choosing `/DnsAll` specifically to cover dynamic update; the
only way `dcdiag` can test dynamic update is to perform one. Intersite was already in the grid,
but before H12 it ran without `/a` or `/e`, which Microsoft says "skips actual testing"; H12
gave it `/a`, and with that it began doing the testing that triggers a replication.

**Both now run only with `-IncludeDcdiagActiveTests`**, by operator decision. With the switch
the run log warns that the run is not read-only.

**What a default run reports instead.** The **DNS** and **Intersite** cells of the DC
Diagnostics grid read `Not Assessed`. Each DC's row says they were not run, why, and which
switch runs them, in a new `NotRun` column. `dcdiag` is not invoked for those two tests at all.

**The note has its own column, and does not choose the advice.** A first draft put the note in
the `Failures` column. The recommendation map matches on a finding's whole text, first match
wins; the note says the Intersite test "triggers a replication", and an unscoped entry matches
the word "replication". Every failing `dcdiag` row in a default run would have been given
replication advice, whatever had failed. The review caught it. The note is now in `NotRun`, and
the step that turns a row into a finding - extracted from `Invoke-Main` as
`ConvertTo-AdfaConsolidatedFinding` so it can be tested - chooses the recommendation first and
appends the note to the detail afterwards.

**The row's status ignores the two held-back cells.** A DC whose 16 attempted tests all passed
is `Pass`, not `Warning`. A held-back test is a decision, not a failed measurement, and a
`Warning` on every DC in every default run would bury the DCs with a test that really could not
be read. A test that was attempted and could not be read still makes the row `Warning`, and a
test asserts that.

**What a default run no longer covers.** Through `dcdiag`: DNS dynamic update, DNS delegation,
forwarders and record registration, and intersite replication. The `Dns`, `DnsDepth`,
`DnsAdConsistency` and `MsdcsDelegation` sections still read DNS without `dcdiag`.

**Config.** The two tests are listed in `$script:Config.DcdiagActiveTests`, each with the
vendor's sentence, its URL and the date read, so adding a test to the list carries its evidence
with it.

**The claim the documentation now makes** is that every state-changing command *this project
knows of* is opt-in. It does not say a default run changes nothing: the other commands a
default run invokes are used as queries but have not each been audited. That audit is
PORT-PLAN H20a. The README's "What a run can change" table and the script's help list all four
opt-in switches.

**`-IncludeDcdiag` is now described as not read-only, and it logs a warning.** It captures raw
`dcdiag /c /v`. Microsoft documents `/c` as "Comprehensive. Runs all tests except DCPromo and
RegisterInDNS, including non-default tests". By that description the capture includes
`CutoffServers`, which "triggers replication on the DCs", and the DNS test - independently of
`-IncludeDcdiagActiveTests`. So a run with `-IncludeDcdiag` alone shows DNS as not run in the
grid while the raw capture ran it; the README says so. No `dcdiag` was executed to confirm what
`/c` runs on a given build; this rests on Microsoft's sentence.

**Found by an independent review of the diff before commit, and fixed in it:** the note
choosing the advice; the raw capture's DNS test; three stale README statements (a coverage row
still describing 18 tests in a default run, a test list of 17 that omitted DNS, and a heading
naming "the one switch" where there are four); a test that failed under Windows PowerShell 5.1
and passed only under PowerShell 7; and five tests that could not fail, each shown with a
mutation that survived - holding the tests back for the first DC only, dropping the note from
later rows or from rows with a real finding, never reporting `Fail` in a default run, and
making the function default to running the tests.

**This has run only against stubs.** No `dcdiag` was executed. That a default run leaves no
test record behind on a real DNS server is asserted from the fact that `dcdiag` is not invoked
for the DNS test, not from observation. The first real run is PORT-PLAN H20-R, owned by the
operator.

### Fixed — 2026-11-13 (the tool was not read-only: it ran nltest /sc_verify by default, tool v1.17.0)

**PORT-PLAN H19. This changes what an existing result means. Read this before comparing a
v1.17.0 report with an earlier one.**

The README said the tool was "strictly read-only" and the script's help said "The script is
read-only"; both listed `/sc_verify` among its "read-only modes". Microsoft's `nltest`
reference says otherwise:

> `/sc_verify` - Checks the status of the secure channel that the NetLogon service established.
> If the secure channel does not work, this parameter removes the existing channel, and then
> builds a new one.

([nltest](https://learn.microsoft.com/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc731935(v=ws.11)),
read 2026-11-13. This is an archived page; no current `nltest` reference was found on Learn.)

The tool ran that command by default in three places: the outbound direction of every trust,
on the host running the assessment; the inbound direction, on a domain controller of the trust
partner over WinRM; and `-Sections DcSecureChannel`, on every DC of the scoped domains. On a
healthy channel it changed nothing. On a broken one - the case a post-incident assessment is
run for - it rebuilt the channel, and then reported it healthy.

**The default is now `nltest /sc_query`**, which the same page describes as reporting "on the
state of the secure channel the last time that you used it". It changes nothing.

**The live test is opt-in.** `-IncludeSecureChannelVerify` runs `/sc_verify` at the same three
places. The run log carries a warning that the run is not read-only, and each result says that
a channel broken before the run may have been rebuilt by it.

**What a default result now means.** `Verified` for a trust direction, and `Pass` for a DC's
secure channel, mean that the *last recorded* status was `NERR_Success`. It is not a live test,
and a channel that has broken since it was last used can still read that way. Every default
row says this and names the switch. This is weaker than the old result and is the price of
being read-only; the operator chose it.

**How the default output is read.** One line, in the form Microsoft's reference shows:
`Trusted DC Connection Status Status = 0 0x0 NERR_Success`. A zero status passes; any other
status fails and is quoted. The closing "The command completed successfully" line is ignored on
purpose: it reports on the command, not on the channel, and the status line is where the
channel's state is printed. Whether that closing line appears beside a non-zero status was not
observed - only Microsoft's one published sample, the success case, was available - so the
parser is written not to depend on it either way. Output without the status line is
`Not Assessed` with an excerpt, which is also what a host with a non-English display language
will get.

One place builds the `nltest` argument, `Get-AdfaNltestScArgument`. Tests read the parsed
script to assert that it is the only place a string that could become an `/sc_verify` argument
exists, that the two script blocks sent to a DC run exactly the argument they are given, and
that every call passes `-LiveVerify` the switch's value and never a bare or constant one.

**`netdom trust /Verify` is no longer run by default either.** It is a live test, and what it
does beyond "verifies the secure channel secrets for a specific trust relationship"
([netdom trust](https://learn.microsoft.com/windows-server/administration/windows-commands/netdom-trust),
read 2026-11-13) is not established. It remains the fallback for the outbound direction only
with `-IncludeSecureChannelVerify`. In that mode it no longer reads "The command failed to
complete successfully" as success because it contains the word "successfully".

**The live test is stricter too.** With the switch, `/sc_verify` output was accepted as healthy
if it contained "The command completed successfully" or the word `NERR_Success` anywhere, so an
error status printed beside either was reported `Verified`. It now needs a zero code on every
status line.

**Also corrected.** The README's example `-SkipVerification` named a parameter that does not
exist; it is `-SkipTrustVerification`. The help text listed `/sc_query` and `getmigrationstate`
as modes the tool used; before this change it invoked neither.

**A default run is still not read-only, and the documentation now says so.** The review of this
change found that `DcDiagnostics`, part of the default run, executes `dcdiag /test:DNS /DnsAll`
- whose dynamic update test Microsoft documents as registering and then deleting a test record -
and `dcdiag /test:Intersite /a`, which Microsoft documents as triggering a replication. Neither
is changed here; both are PORT-PLAN H20, for the operator to decide per test. The README has a
new section, "What a run can change", listing every known case with Microsoft's wording, and it
no longer claims that a default run changes nothing. A first draft of this entry made exactly
that claim.

**Found by an independent review of the diff before commit, and fixed in it:** the netdom
fall-through and its lax success rule; the live-mode rule above; a parser pattern that read past
the end of the status line; two function synopses and two one-line "read-only" statements left
describing the old behaviour; and three tests that could not fail, which matched text where
they now read the parsed script.

**This has run only against stubs.** No `nltest` was executed against a real secure channel.
What `/sc_query` prints on a real domain controller, and on a member server for a trusted
domain, has not been observed - only Microsoft's published sample. The first real run is
PORT-PLAN H19-R, owned by the operator.

**Not verified.** What `netdom trust /Verify` does beyond what Learn states, which is why it
is now opt-in. The layout of `/sc_verify` status lines, for which no sample is published.
That `/sc_query` is accepted on a host that is not a domain controller; the reference says
`/sc_verify` is valid only on domain controllers and says nothing either way about `/sc_query`.

### Added — 2026-11-13 (DC operating system lifecycle, and patch-level inventory, tool v1.16.0)

**PORT-PLAN C1.** New `-Sections DcSystem`, included in the default `All` run. It closes two
rows of the gap analysis: the tool collected each DC's operating system and judged it only
against the Exchange SE compatibility table, and it read nothing about uptime or updates.

**This has run only against stubs.** No part of it has been executed against a real directory
or a real domain controller. The first run against a real forest is PORT-PLAN C17, owned by the
operator.

**OS lifecycle, one row per DC.** The verdict is taken from the `OperatingSystem` and
`OperatingSystemVersion` the `DomainControllers` section already reads from the directory, so
it needs no rights on any DC.

| Situation | Result |
| --- | --- |
| On or before the extended support end date | `Pass`, with the date stated |
| Past it, ESU programme still running | `Fail`: programme end date stated, **enrolment not assessed** |
| Past it, ESU programme also ended | `Fail`, saying so |
| Past it, no ESU date published | `Fail`: "ESU end date not published" |
| OS not in the table (for example Windows Server 2008 R2) | `Not Assessed`, raw name and version shown |
| OS could not be read | `Not Assessed`, with the cause the inventory recorded |

A release is identified only when its name and its build number agree. A first draft matched
on the build alone; a review pointed out that the Semi-Annual Channel release "Windows Server,
version 1809" shares build 17763 with Windows Server 2019, so that draft would have passed it on
2019's dates. A DC whose name and build disagree, or whose name is not recognised, is now
`Not Assessed` with both raw values. Windows Server 2012 and 2012 R2, which the table lists
without a build, are kept apart by name.

**Dates, read on Microsoft Learn 2026-11-13.** Extended support end: 2025 `2034-11-14`, 2022
`2031-10-14`, 2019 `2029-01-09`, 2016 `2027-01-12`
([release information](https://learn.microsoft.com/windows-server/get-started/windows-server-release-info));
2012 and 2012 R2 `2023-10-10`, and ESU Year 3 end dates 2016 `2030-01-08`, 2012/R2 `2026-10-13`
([ESU FAQ](https://learn.microsoft.com/lifecycle/faq/extended-security-updates)). No ESU
programme is published for 2019, 2022 or 2025, so the table holds `$null` for them and the
finding says the date is not published.

Two things about those sources that the table's comments record:

- The product lifecycle pages print the same instants as Pacific Time timestamps on the *next*
  calendar day (`1/13/2027 6:59:59 AM` for 2027-01-12). The table uses the calendar dates of the
  two pages above and does not mix conventions. The end date itself counts as supported.
- The ESU FAQ contradicts itself for Windows Server 2016: its table says extended support ends
  January 12, 2027 and one prose answer says January 12, 2026. The table agrees with the two
  other pages, so 2027 is used.

The AdAssessment26 plan recorded no ESU date for Windows Server 2016 when it was written
(2026-09-24). Learn publishes one now, which is why this table differs from that record.

**Patch level, two rows per DC, inventory only.** `Win32_OperatingSystem` for build and last
boot time, `Win32_QuickFixEngineering` for the latest install date, in one bounded CIM session:
WinRM first, DCOM second. Every row is `Info` or `Not Assessed`, never `Pass`. Microsoft
publishes no maximum uptime and no maximum update age for a domain controller, and the operator
chose not to set one, so none is applied.

Three results are kept apart: **unreachable** (neither port answered, no read attempted),
**access denied** (the row says local Administrators rights are needed), and **any other read
failure**, quoted as the DC reported it. A failure of the update query alone keeps the build and
uptime row.

Install dates need care. Learn types `InstalledOn` as a string with no stated culture, and says
it may be a hexadecimal FILETIME. `11/10/2026` is 10 November or 11 October depending on the
host, so it is read only when another record from the same DC proves the order (a day above 12).
Where nothing proves it, the row reports how many records could not be read and gives no date.
Zero records is `Not Assessed`, not "no updates installed". The row also states Learn's own
limit: the class lists only updates supplied by Component Based Servicing.

**Config.** `$script:Config.DcSystem` holds the table with its sources; `-DcSystemConfigPath`
replaces it from JSON on the same contract as `-ExchangeSeConfigPath`. A missing or malformed
file is a terminating error, and so is an empty table, a date not in `yyyy-MM-dd` form, a row
with neither a build nor a pattern, or a pattern that is not a valid regular expression.

**A DC is probed once per port.** New `Test-AdfaDcPort` caches each answer for the run. Only
`DcSystem` uses it so far; moving the older per-DC sections onto it is PORT-PLAN C1b.

**Not done, and recorded as plan rows.** The update revision within the build is not read
(C1a). No warning is raised ahead of an end date: by operator decision a DC is `Pass` until the
date and `Fail` after it.

**Found by an independent review of the diff before commit, and fixed in it.** Twenty findings
were confirmed. The ones that would have produced a wrong report:

- **A wrongly shaped override file was accepted in silence.** A top-level JSON array, a string,
  `null`, or a misspelt key left the built-in dates in force while every finding cited the
  operator's file for them. The override must now be one object whose keys are known; anything
  else stops the run, and provenance is rewritten only when the file supplied the dates.
- **Windows PowerShell 5.1 converts `InstalledOn` before the script sees it.** Its type data
  replaces the member with `[DateTime]::Parse`, which guesses month-first and returns nothing
  for a day-first date or a hexadecimal FILETIME. Measured on a real `Get-CimInstance` result on
  the build machine: the member is a `DateTime`, the raw property a `String` shaped
  `99/99/9999`. The raw value is now read from `CimInstanceProperties`. The stubs had hidden
  this by returning plain objects.
- **A refusal was recognised only in English.** The message is in the UI language of the host
  running the assessment. The CIM error code is now carried alongside it and checked first.
- **A domain whose DC inventory failed produced no row at all**, so the section looked complete.
  It now gets its own `Not Assessed` row naming the domain and the cause.
- **Findings cited one page for dates that are on another.** Both source pages are now cited.
- **A build-and-uptime row was `Info` when the class returned neither value.** It is
  `Not Assessed`.

Tests the review showed could not fail were replaced: the section's presence in the
`ValidateSet` is now read from the parsed parameter instead of matched as text; the transport
order, the DCOM fallback, the DCOM session option and the plain "read failed" result each have a
test; and "never graded" is asserted as "only `Info` or `Not Assessed`" over a five-DC population,
not as "no `Pass`".

**Not verified.** The `InstalledOn` shape was measured on the local machine, not on a domain
controller, and not over a remote session. The CIM error code of a real refusal was not
observed: only that the exception type carries one. The layout of `operatingSystemVersion` (`10.0 (17763)`) is not documented on Learn;
the build is taken from the parentheses and anything else falls back to the name. DCOM
connection behaviour under the timeout was not measured.

### Docs — 2026-11-13 (gap analysis against the AdAssessment26 finding catalogue; no code change)

[docs/GAP-ANALYSIS.md](docs/GAP-ANALYSIS.md) maps all 89 rows of the AdAssessment26 finding
catalogue to this tool at v1.15.0: 15 Covered, 44 Partly, 30 Missing, each with its evidence,
what is needed, the data source and transport, the rights needed and a proposed `-Sections`
name. It also lists 30 things the README or help text promise that the code does not do, or
does only in part. PORT-PLAN gains a Coverage track, C1 to C17, proposed and awaiting approval.

Limits, stated in the document itself: the rows were produced by reading code and were not
individually re-verified; nothing was run against a directory; and the vendor facts quoted come
from the reference repository's records and were not re-read on Microsoft Learn.

### Fixed — 2026-11-12 (a forest above the supported functional levels was told to raise its level, tool v1.15.1)

**PORT-PLAN H17.** The Exchange SE section judged the forest functional level by asking whether
the `ForestMode` *name* was in a list:

```powershell
elseif ($supportedModes -contains $ForestMode) { ... Pass ... }
else { ... "Setup will not proceed until the forest functional level is raised." }
```

A list can only answer "listed" or "not listed". Everything not listed was treated as too low,
and the recommendation map matched on the item name alone, so a Windows Server 2025 level forest
was reported as:

```
Windows2025Forest is NOT supported for Exchange Server SE. ... Setup will not proceed until the
forest functional level is raised.
FIX: ... "Set-ADForestMode -Identity <forest> -ForestMode Windows2016Forest" ...
```

That advice points the wrong way. The config table's comment had the same error in words: it
said Windows Server 2016 is the highest forest functional level Microsoft has ever shipped.

**What Microsoft Learn says, read 2026-11-12:**

- A Windows Server 2025 forest and domain functional level exists; Windows Server 2019 and 2022
  "use Windows Server 2016 as the most recent functional level"
  ([functional levels](https://learn.microsoft.com/windows-server/identity/ad-ds/active-directory-functional-levels)).
- The Exchange Server SE row lists forest functional levels Windows Server 2016 and Windows
  Server 2012 R2, and no other
  ([supportability matrix](https://learn.microsoft.com/exchange/plan-and-deploy/supportability-matrix#supported-active-directory-environments)).
- The 2025 level "maps to the value of `DomainLevel 10` and `ForestLevel 10`"
  ([what's new in Windows Server 2025](https://learn.microsoft.com/windows-server/get-started/whats-new-windows-server-2025)).
- 6 is Windows Server 2012 R2 and 7 is Windows Server 2016
  ([Install-ADDSForest](https://learn.microsoft.com/powershell/module/addsdeployment/install-addsforest)).
- The forest level is `msDS-Behavior-Version` on `CN=Partitions,CN=Configuration`
  ([raise functional levels](https://learn.microsoft.com/troubleshoot/windows-server/active-directory/raise-active-directory-domain-forest-functional-levels)).
- `Windows2025Forest` is a published `ADForestMode` name
  ([Set-ADForestMode](https://learn.microsoft.com/powershell/module/activedirectory/set-adforestmode)).

**The fix.** The verdict is now taken from the number, read by the new
`Get-AdfaForestBehaviorVersion` (one read-only `Get-ADObject` of the Partitions container, whose
DN comes from `Get-ADForest`'s own `PartitionsContainer`). A new pure
`Get-AdfaForestLevelClass` places it relative to the supported levels:

| Level | Result |
| --- | --- |
| Supported (6, 7) | `Pass` |
| Below | `Fail`, with the existing "raise" wording and advice |
| Above (10) | `Fail`: not listed in the supportability matrix, with the matrix URL and **no remediation command** |
| Not a known level (8, 9, `abc`) | `Not Assessed`, raw value shown |
| Not read | `Not Assessed`, with the directory's own error |

The `ForestMode` name is still shown, labelled as information only. It never decides anything:
what an older ActiveDirectory module prints for a level-10 forest is not published, so it is not
relied on. A test passes level 10 with the names `UnknownForest`, `Windows2016Forest` and an
empty string and requires the same result each time.

An attribute that is **not returned** is reported as not read. Learn says "0 or not set" means
the Windows 2000 level, but an unset attribute and an unreadable one look the same from this
read, so no level is assumed.

An explicit **empty** recommendation entry, scoped to this section and placed first, is what
keeps the *above* finding free of advice. It blocks the raise entry, and it blocks every later
unscoped entry: under a config override the finding cites the override file's path, and a path
containing a word such as `Backup` would otherwise attract the backup advice. The raise advice
itself no longer names `Windows2016Forest` as the target, because the supported set can be
overridden; it refers to the supported modes the finding lists.

**Found by an independent review of the diff before commit, and fixed in it:**

- The raise advice named `Windows2016Forest` even when an override made that the level the
  forest was already at.
- The *above* wording said "the supportability matrix" when the list had come from an override
  file, attributing the operator's table to Microsoft. It now says "the supplied config table"
  unless the source is Microsoft Learn.
- A comment claimed the vendor publishes no step for a forest above the matrix. Learn publishes
  a procedure for lowering a functional level; the comment now says so and points at H18.
- Overriding only `ForestFunctionalLevels` replaces the whole table, and the resulting error
  blamed a mode name the override had not mentioned. The message now says the table is replaced
  whole, the README says the same, and an empty table is refused like any other empty gate.
- The JSON form of the level table and the "no supported mode resolves to a level" guard had no
  test. Both have one now.

**Guards shown able to fail** (each mutation applied alone, then the file restored and verified
by SHA-256) are listed in the pull request evidence with the test counts that went red.

**Config.** `ExchangeSe` gains a `ForestFunctionalLevels` table (level, mode name, label) with
its sources. `SupportedForestModes` keeps its shape, so existing override files still load. An
override naming a mode that table does not know is now a terminating error, because that name
would otherwise drop out of the supported set and fail a supported forest. A test confirms that
adding `Windows2025Forest` to an override turns a level-10 forest into a `Pass` with no code
change.

**Other uses of `ForestMode` / `DomainMode` checked.** The forest summary, the domain summary and
the SE section's per-domain `Info` rows print the name and compare nothing. No other comparison
exists in the script.

**Not verified.** This has run **only against stubs**. The real `Get-ADObject` read, on Windows
PowerShell 5.1, against a real Partitions container has not been exercised; that is PORT-PLAN
H17-R, owned by the operator. Learn documents values 0-4 as values of the attribute and
5, 6, 7 and 10 as `ForestMode` / `ForestLevel` integers; treating them as one number line is an
inference, not a quoted statement.

**Found and not changed (PORT-PLAN H18).** The raise advice still says the change "cannot be
reverted without a forest recovery". Learn now has a page on lowering functional levels. Only
its search excerpt was read, so the wording was left alone and given its own plan row.

### Fixed — 2026-09-26 (the DC inventory asked the wrong domain controller, so every child-domain DC lost its OS, tool v1.15.0)

**Found by the first run against a live multi-domain forest** — four domains — which is the
exact path R5 named as the highest-risk untested one. It failed on first contact.

`Get-AdfaDomainControllerInventory` makes two calls per domain. The first targeted the right
server; the second did not:

```powershell
$p = @{} + $AdParams; $p.Server = $DomainName       # Get-ADDomainController -> correct DC
$cp = @{} + $AdParams; $cp.Identity = $id           # Get-ADComputer -> NO -Server
```

`$id` is the DC's `ComputerObjectDN`, a DN in the domain being enumerated. With no `-Server`,
`Get-ADComputer` asked whatever DC the tool was running against — in the forest root. That DC
does not hold a child domain's naming context, so LDAP answered with a **referral**, and
`Get-ADComputer` does not chase referrals.

Every domain controller outside the tool's own domain came back as:

```
WARNING: DC enrichment failed for <dc>: A referral was returned from the server
```

and lost `OperatingSystem`, `OperatingSystemVersion` and `Enabled`.

**What that cost.** The Exchange SE check reads exactly that field and treats the literal
`Not Assessed` as unreadable, so it reported those DCs *"unverified, not compatible"*. On a
four-domain forest that made the SE readiness verdict — the single thing that section exists to
answer — wrong for three domains out of four. A single-domain run never showed it, because
there the default server and the target domain are the same host.

Not affected: `SiteGc`, `Topology` and everything else reading `Site`, `IsGlobalCatalog` or
`IsReadOnly`, because those come from `Get-ADDomainController`, which did set `-Server`.

The fix is to splat the per-domain `$p`, which already carries the right `-Server`.

**Two further defects fixed alongside it, both of the same family.**

The cause went to `Write-Warning` and nowhere else. A reader of `Assessment.html` saw
`Not Assessed` with no explanation anywhere in the report — the same defect H10 fixed for
dcdiag and this collector was missed. The inventory row now carries an `EnrichmentError`
column.

And the "OS not readable" finding gave one fixed line whatever had gone wrong: *"Re-run with
credentials that can read the DC computer objects."* For a referral that is simply **wrong** —
credentials had nothing to do with it, and the advice sent an operator somewhere there was
nothing to find. New pure `Get-AdfaEnrichmentFailureAdvice` matches the advice to the cause:
a referral is named as a referral, an access failure keeps the credentials advice, both are
given when both occur, and an error the tool does not recognise is **quoted verbatim rather
than interpreted**. A wrong cause is worse than no cause.

The regression guard is the field failure itself: `Run-SmokeTest`'s `Get-ADComputer` stub now
throws `A referral was returned from the server` when called without `-Server`, exactly as the
directory did. Reverting the fix turns three smoke assertions and two harness assertions red.

**Separately, a client domain label was removed from the test fixtures.** A leak check run
before committing this change found one of the third-level domain labels from the forest this
tool was being run against, used as a "fictional" domain in `Run-SmokeTest.ps1` and
`Invoke-ADForestAssessment.Tests.ps1`, where it had been since v1.6.0. `CLAUDE.md` is
unambiguous - *no client ever appears in this repository, not in code, not in tests* - and *if
a value could plausibly be a real client's, it is the wrong value*. Replaced with `south`,
mirroring the existing `north`. The label itself is deliberately not repeated here, for the
same reason it had to leave the fixtures. Note this does not remove it from git history, which
would need a rewrite of published commits.

### Added — 2026-09-22 (a runtime event-lookback window, and the clock offset H8 admitted it was not measuring, tool v1.14.0)

**H13 — `-EventLookbackDays`.** The Directory Service and DFS Replication event scans looked
back 14 days, from two constants in `$script:Config` with **no runtime override at all**. On the
tool built for assessing a forest *after a restore*, a restore older than two weeks could not be
reached without editing the script. It is now a validated parameter (1–365, default 14) feeding
both windows.

Widening it is safe rather than a licence to lie, because the H2 coverage guard already compares
the oldest retained record against the requested window: ask for 180 days over a 30-day log and
it reports `Truncated` naming where coverage actually begins, not a clean scan of a period the
log never held. A test asserts exactly that.

**H14 — the clock offset.** H8 reported where each DC takes time *from*, and said in its own
finding text that it *"does not verify that the source is accurate"*. That was honest and it was
a hole: a DC can have a perfect source and still be minutes out, and **Kerberos fails on the
skew, not on the configuration**.

Every DC now gets a measured offset, via:

```
w32tm /stripchart /computer:<dc> /dataonly /samples:3 /rdtsc
```

`/rdtsc` is chosen deliberately over `w32tm /monitor`. Learn documents `/monitor`'s *parameter*
but never its *output*, whereas `/rdtsc` carries a published contract — *"prints comma-separated
values along with the headers RdtscStart, RdtscEnd, FileTime, RoundtripDelay, and NtpOffset"*,
with `NtpOffset` defined as the offset in seconds
([Learn](https://learn.microsoft.com/windows-server/networking/windows-time-service/windows-time-service-tools-and-settings),
read 2026-09-22). **This is the only external-tool output in this entire tool whose format the
vendor publishes**, and that is the whole reason it was chosen: every other parser here matches
undocumented console text and has to degrade on a wording or locale change.

Three decisions the findings state rather than imply:

- **Whose threshold is whose.** 300 seconds is Microsoft's documented Kerberos maximum, verified
  in two independent places. The 60-second warning bar is **ours**, and the `Warning` text says
  so outright — 300s is the cliff where authentication stops, not a level to run at.
- **The worst sample, not the mean.** Averaging a `+400s` and a `-400s` sample would report a
  wildly swinging clock as perfect. A mutation to the mean turns that assertion red.
- **What it does not prove.** The offset is measured *from the host running the assessment*, so
  it reports divergence between that host and each DC — not that the forest's time is correct.
  If the measuring host is wrong, every DC agreeing with it still reads clean. Every finding
  names the reference host rather than leaving that implied.

A sample that will not parse as a number is **dropped, never coerced**: `Request timed out.`
appears in this stream for an unreachable target, and reading it as an offset of zero would
report a dead DC as perfectly synchronised. Zero usable samples is `Not Assessed` with the cause
named — timed out, unparsed rows, no output, or no CSV header, each distinguished.

### Fixed — 2026-09-22 (the Intersite dcdiag column was a false Pass; the DNS test was never run, tool v1.13.0)

**`Intersite` reported `Pass` without testing anything.** The grid invoked
`dcdiag /test:Intersite /s:<dc>` with neither `/a` nor `/e`. Microsoft is explicit:

> *"The `/a` or `/e` parameter must be used as not providing a site would allow the test to run
> but **skips actual testing**."*
> — [dcdiag](https://learn.microsoft.com/windows-server/administration/windows-commands/dcdiag), read 2026-09-22

So dcdiag ran, tested nothing, printed `passed test Intersite`, and the column has read `Pass`
on every DC of every run since the R2 15-test grid. **A false Pass is the one outcome this tool
exists to make impossible**, and this one has been shipping the whole time. Intersite now carries
`/a` — this site, rather than `/e` for the whole enterprise, because Learn warns enterprise run
times are significant and offline DCs make them worse, and the grid already iterates every DC.

**This deliberately changes statuses.** A forest with genuine intersite replication problems will
now show `Fail` where it showed `Pass`. That is the fix working.

**The DNS test was never run.** The grid's 17 tests contained no `DNS` entry, on a tool built for
a post-recovery engagement whose stated problem is DNS. `DNS` is not run by default and must be
requested explicitly. It is now the 18th test, invoked as `/test:DNS /DnsAll` — `/DnsAll` spelled
out rather than relied on as the default, so a change to that default cannot silently narrow what
this tool checks. It covers basic connectivity and service checks, forwarders, **delegations**,
dynamic update and **record registration** — the exact failure classes a restored DC produces.
`/DnsResolveExtName` is deliberately excluded: it needs internet egress and is not a directory
question.

Both changes go through a new pure `Get-AdfaDcdiagArgument`, so the per-test argument is asserted
rather than assumed — a test proves exactly two of the eighteen deviate from the plain form, and
spraying `/a` across all of them turns three assertions red.

Two caveats recorded rather than glossed: the DNS test needs **Enterprise Admins** minimum and
uses WMI as well as DNS and RPC, so it will report `Not Assessed` with a named cause (via v1.12.0's
H10 work) where rights or WMI are missing. And `dcdiag /test:DNS` supports `/x:<XMLLog.xml>` for
structured output, which would remove the localisation fragility every console parser here
carries — but **the XML schema is not published on Learn**, so it is not parsed. That is a plan
row, not a silent omission.

### Fixed — 2026-09-22 (two defects found by the first run against a real forest, tool v1.12.0)

v1.11.0 was run against a live four-DC forest — the first time any of this code touched a real
directory. Two defects surfaced that no fixture had caught.

**A `Not Assessed` dcdiag cell recorded no cause.** `VerifyEnterpriseReferences` came back
unassessed on every DC, `KnowsOfRoleHolders` and `CheckSecurityError` on the PDC, and the report
said nothing about why. The collector was:

```powershell
else { $row["DCDIAG_$t"] = $script:Status.NotAssessed }
```

No exit code, no output, no error — and `Failures` was only populated for a `Fail`, so nothing
reached the consolidated findings either. That breaks this repository's own rule: *a value not
measured is reported as not measured **with a named cause***. An empty `Not Assessed` is not
that, and it left the one question a reader has — *did dcdiag fail, or did it say something we
could not read?* — unanswerable from the report.

New pure `Get-AdfaDcdiagTestOutcome` separates `Pass | Fail | Unparsed | ToolFailed`, and
`Get-AdfaDcdiagUnassessedCause` builds the cause that now lands in `Failures` for every
unassessed cell: the exit code, the error text, and an excerpt of what dcdiag actually printed.
Two details that matter:

- The **verdict is read before `Success`**. dcdiag exits non-zero for a *failed* test, so
  checking the exit code first would have thrown away a real measurement and called the DC
  unassessed.
- The excerpt prefers lines naming the test or carrying a verdict/error word, and otherwise
  takes the **last** lines, not the first. The first lines are dcdiag's banner
  (`Directory Server Diagnosis`, `Performing initial setup`) and say nothing; the summary — and
  therefore a localised verdict line — is at the bottom. The first cut of this function
  excerpted the head and was caught by its own test.

The cause names non-English Windows as a candidate explicitly, because the verdict match is the
literal English `passed test <name>` and cannot survive localisation. That remains a real
limitation; it is now a *stated* one.

**A DNS server with no forwarders was reported as unreadable.** The live run produced
`forwarders — Not Assessed: You cannot call a method on a null-valued expression`. Root cause:

```powershell
-Detail (($fwd.IPAddress | ForEach-Object { $_.ToString() }) -join ', ')
```

With no forwarders configured, `IPAddress` is `$null`. Piping `$null` into `ForEach-Object`
still runs the block once with `$_ = $null`, and `$null.ToString()` throws under
`Set-StrictMode -Version Latest`. The exception was caught upstream and became `Not Assessed`.

So a **measured absence was reported as a failed measurement** — the exact conflation this tool
exists to prevent, running backwards. A reader could not tell "this DC has no forwarders" from
"we could not ask", and the first is a real finding on a recovered forest.

New pure `Get-AdfaForwarderAddress` returns an empty list for that case, and the collector now
says so plainly as `Info`. **This changes a status**: a DC with no forwarders moves from
`Not Assessed` to `Info`. That is the point of the fix — it was never unassessed, it was
measured as zero.

Two null guards were **removed** rather than added while fixing this. Neither could be
demonstrated able to fail, because a third check already covered them: `@($null)` is a
one-element array holding `$null`, and `[string]$null` is `''`, so the emptiness test catches
both. An unreachable guard implies a coverage the function does not have. The one guard that is
load-bearing — the property-existence check — was measured, not assumed: reading `.Value` off an
absent property throws *"The property 'Value' cannot be found on this object"* under StrictMode,
and removing it turns three assertions red.

### Added — 2026-09-22 (`_msdcs` delegation, the time hierarchy, and per-site writeable-GC coverage, tool v1.11.0)

Three checks a post-recovery forest needs and this tool did not have. Each is a pure classifier
plus a thin collector, so all of the decision logic is unit-tested without a directory.

**`_msdcs` zone delegation** — new section `MsdcsDelegation`, `-Sections MsdcsDelegation`.

The forest-wide locator records live in their own AD-integrated zone, replicated to every DNS
server in the forest through the forest-wide DNS application directory partition
([Learn](https://learn.microsoft.com/windows-server/identity/ad-ds/plan/integrating-ad-ds-into-an-existing-dns-infrastructure),
read 2026-09-22). After a hand-rebuilt DNS server that is easy to get wrong, and nothing in the
report would have shown it. Four separable properties, each its own finding because each has a
different fix:

| Property | Verdict |
| --- | --- |
| `_msdcs.<forest>` answers its own SOA | `Pass`; the **parent** answering is `Fail` (a plain subdomain, not a delegated zone) |
| The parent zone holds delegation NS records | `Pass` / `Fail` |
| Each NS target has a resolvable glue (A) record | `Pass` / `Fail`; a glue query that got no answer is `Not Assessed`, never `Fail` |
| Each NS host is a DC this run inventoried | `Pass` / `Warning` — a non-DC DNS server can legitimately be authoritative |

The forest recovery guide is explicit on two of these: *"Ensure that the parent DNS zone contains
delegation resource records (name server (NS) and glue host (A) resource records) for the child
zone"*, and *"In the `_msdcs` and domain DNS zones, delete NS records of DCs that no longer exist
after metadata cleanup"*. Every property is measured **per DNS server** rather than merged — the
zone is AD-integrated, so with replication broken the answer genuinely differs between servers.

**Time hierarchy** — new section `TimeHierarchy`, `-Sections TimeHierarchy`. The existing
`TimeSync` section reads the **local** host's `w32tm /query /source` and is unchanged. This one
reads every DC's source with the documented remote form `w32tm /query /computer:<target> /source`,
and applies the two role-specific rules the vendor publishes:

- A DC whose source is `VM IC Time Synchronization Provider` is taking time from its
  virtualisation host. Per KB 976924 a DC with two time sources can jump, which *"can cause
  lingering objects to be left in caches, and may cause replication to stop"* — both of which
  this report checks for elsewhere. `Warning`, naming the Integration Services fix.
- The forest root PDC emulator must not synchronise from the domain hierarchy it is the top of;
  W32Time logs **event ID 12** for exactly that. So a root PDC whose source is one of this
  forest's own DCs is a `Warning`, and its configured client `Type` gets its own row — `NT5DS`
  or `NoSync` is a `Warning`, `NTP`/`AllSync` **with a peer list actually read** is a `Pass`.

Where Microsoft's own guidance diverges — the Windows Server 2016 timekeeping guidance says *"For
the PDC, you don't want to disable the entry because the Hyper-V host delivers the most stable
time source"*, against KB 976924 — the finding names **both** positions and says the operator must
decide. It does not pick a side silently.

**Per-site writeable global catalog** — new section `SiteGc`, `-Sections SiteGc`. Joins `Site`,
`IsGlobalCatalog` and `IsReadOnly`, which the DC inventory already collected and never correlated.
A site holding DCs but no DC that is **both** writeable and a GC is a `Warning` naming what is
actually there (read-only GC / writeable non-GC), because Microsoft requires the AD site hosting
an Exchange server to contain at least one writeable domain controller that is also a global
catalog server, and states that an Exchange server cannot be deployed in a site containing only
read-only directory servers. A `Warning` rather than a `Fail` because a site with no GC-dependent
application is a design choice, and this tool does not know what is deployed there. This closes
the gap the v1.7.0 Exchange SE section explicitly disclaimed.

**Resolver**: `Resolve-AdfaDnsRecord` and `Get-AdfaDnsRecordView` now accept `NS`, `A` and `SOA`
alongside `SRV` and `CNAME`. For an `SOA` query `Targets` holds the **zone apex that answered**,
not the primary server — that is the only thing an SOA query is asked for here, and it is how a
delegated child zone is told apart from a subdomain of its parent. `SOA` is deliberately **not**
attempted through the `nslookup` fallback: its output does not label the answering zone in any
documented way, and a guessed apex would turn a healthy delegation into a confident `Fail`, so it
returns `NoTool`. The `nslookup` `A` parser skips the header `Address:` line, which is the DNS
server's own address and not the record's glue.

Fixed in passing, found by the new tests rather than reported: nothing. Every existing finding
keeps its status — the three sections are new `ValidateSet` entries writing new `$sectionData`
keys, and no existing collector's logic was touched.

### Fixed — 2026-09-22 (a replication link with no failures and a weeks-old last success reported Pass, tool v1.10.0)

The `repadmin /showrepl * /csv` cross-check judged links on **failure count alone**:

```powershell
if ($failing -eq 0) { ... -Status Pass -Detail "all with zero failures." }
```

`Last Success Time` was already parsed for every link but only read on links that were failing.
So a link that had simply **stopped being attempted** — a disabled connection object, a KCC fault,
a site-link schedule that never fires, a partner no longer in the topology — reported clean. That
is the silent case, and the one a post-restore forest produces: nothing errors because nothing is
being tried. `repadmin /showrepl` shows two-way replication "occurring without error", which
Microsoft itself notes makes the inconsistency *"difficult to detect"*.

Lag is now evaluated on **every** link. A last success past 24h is a `Warning`, past 7 days a
`Fail` naming the likely causes, and an unreadable or absent timestamp is `Not Assessed` — never
treated as recent, because a link that has never succeeded reports zero failures too. A
last-success timestamp **in the future** is reported as clock skew, not convergence, since every
other replication timestamp in the report is unreliable until time is fixed.

### Added — 2026-09-22 (repadmin /replsummary parsed into findings, tool v1.10.0)

`/replsummary` was written to `raw\repadmin_replsummary.txt` under `-IncludeRepadmin` and never
read. It is the only place the tool sees a per-DSA convergence delta rolled up across every
partition, in both directions, so it is now parsed into findings.

Layout per the vendor's own sample output
([error 8418](https://learn.microsoft.com/troubleshoot/windows-server/active-directory/replication-error-8418),
read 2026-09-22): two tables keyed by source and by destination DSA, each row carrying the largest
delta, fails/total, a percentage and an optional error code.

Two things the parser is careful about:

- **An unreadable delta is `$null`, never `0`.** `(unknown)` means that DSA has no successful
  replication to measure from, which is *worse* than a large number. Zero failures plus an unknown
  delta is therefore `Not Assessed`, not `Pass`.
- **A parse miss is `Not Assessed`, never "no problems found."** This is localised,
  version-dependent console text with no CSV option, so the parser will eventually meet output it
  cannot read, and that must not read as health. The caller says so and points at the raw capture.

Thresholds are **this tool's, not Microsoft's, and the findings say so** — intra-site replication
is notification-driven and the default inter-site schedule is 180 minutes, so a day is outside any
normal schedule and a week means it has stopped. The hard cliff is tombstone lifetime, which the
detail names rather than letting the thresholds imply.

Remediation distinguishes a stall from a failure, because a stall has no error to chase: it points
at the connection object, the site-link schedule and KCC health rather than at DNS and the network,
and warns against reconnecting a link older than tombstone lifetime without running the
lingering-object scan first.

**`/showutdvec` was considered and not used.** Its output format is not documented on Microsoft
Learn, and the `/showrepl * /csv` output already carries `Last Success Time` per link per naming
context in a stable, parseable format. Building verdicts on undocumented console text when a
documented source of the same signal was already being collected would have been the worse
engineering choice — recorded on the plan row rather than left as an unexplained omission.


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
