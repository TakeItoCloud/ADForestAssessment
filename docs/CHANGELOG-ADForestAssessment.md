# Changelog — AD Forest Assessment

## 1.3.0 — 2026-07-23

Deep security & reliability coverage - the items needed to move from "healthy" toward a
full security bill of health. All read-only; each degrades to Not Assessed when the required
tool/module/permission is absent. New `-Sections` values, all included in `All`.

### Added - security / attack-path
- **PKI / AD CS** (`Get-AdfaPkiHealth`, `Test-AdfaEsc1Template`) - enterprise CA discovery and
  ESC1-susceptible certificate templates (enrollee-supplies-subject + auth EKU + no manager
  approval + no enrolment-agent signature).
- **Dangerous ACLs / DCSync** (`Get-AdfaDangerousAcl`, `Test-AdfaDcSyncAce`) - non-default
  principals holding Replicating-Directory-Changes(-All) or GenericAll on the domain head.
- **Kerberos exposure** (`Get-AdfaKerberosExposure`) - Kerberoastable (SPN) users, AS-REP
  roastable (no-preauth) accounts, unconstrained delegation (non-DC), and RBCD.
- **Privileged hygiene** (`Get-AdfaPrivilegedHygiene`) - adminCount=1 accounts, SPNs on
  privileged accounts (Kerberoast risk), Protected Users adoption.
- **DC hardening** (`Get-AdfaDcHardening`) - Print Spooler running, SMBv1 enabled, LDAP
  server-signing requirement (remote CIM / registry).

### Added - reliability / operational
- **Directory backup status** (`Get-AdfaBackupStatus`) - last partition backups via
  `repadmin /showbackup`.
- **Time sync** (`Get-AdfaTimeSync`) - w32time source (flags Local CMOS / free-running).
- **DNS depth** (`Get-AdfaDnsDepth`) - critical SRV records resolvable, secure dynamic updates.
- **Redundancy / availability** (`Get-AdfaRedundancy`, `Find-AdfaDuplicateSpn`) - DC count,
  GPO central store, duplicate SPNs.

### Tests
- Unit gate 44 checks (adds ESC1 / DCSync-ACE / duplicate-SPN logic); Pester file extended.

## 1.2.0 — 2026-07-23

Feedback from the first live run against a real forest.

### Added
- **Detailed run log** (`assessment_<stamp>.log`) — the previous `transcript_*.log` only held
  PowerShell's module-load noise. The new log records runtime/parameters, every stage, and an
  **itemised, worst-first list of every finding** (status + exact detail text) plus a summary
  tally. `Write-Log` is the single sink; the transcript is still captured for raw host/verbose.
- **Consolidated findings** (`csv\Findings-Consolidated.csv`) — one severity-sorted row per
  status-bearing check across all sections (Section / Scope / Item / Status / Detail): the single
  actionable list.
- HTML report now **leads with a "Findings (worst first)"** table (warnings/failures/Not-Assessed)
  before the detail sections.
- Run summary object gains `LogFile` and `FindingsFile`.

### Fixed
- Replaced Unicode em-dashes in output strings with ASCII `-` (they rendered as `â€"` mojibake
  when CSVs were opened as ANSI).
- Privileged group membership is now de-duplicated by SID (`-Recursive` could list the same
  principal — e.g. `Administrator` — more than once).

## 1.1.0 — 2026-07-22

### Added
- **Exact failure detail for replication** — `Get-AdfaReplicationHealth` now emits a
  `FailureDetail` column naming each failing partner with its partition, `LastReplicationResult`,
  consecutive-failure count, and (from `Get-ADReplicationFailure`) `FailureType`, count, first
  failure time and `LastError`. No longer just a count.
- **Exact failure detail for dcdiag** — `Get-AdfaDcDiagnostic` now adds an overall `Status`
  column (RAG-coloured) and a `Failures` column carrying the specific failing test names and the
  error/warning lines dcdiag emitted, alongside the per-test PASS/FAIL matrix.
- **Full user & computer export (all attributes)** — new `Identity` section
  (`Get-AdfaUserInventory`, `Get-AdfaComputerInventory`, `ConvertTo-AdfaFlatObject`,
  `Get-AdfaObjectPropertyUnion`) exports every user and computer with the union of all populated
  attributes (`-Properties *`), multi-valued attributes joined with `;`, to
  `csv\AllUsers_<domain>.csv` / `csv\AllComputers_<domain>.csv`. The HTML report shows an
  `Identity Inventory` summary (totals / enabled / disabled) rather than dumping every row.
- Cross-forest guidance documented: `-AllDomains` covers domains within the target forest only;
  another forest requires a separate run with `-Server` / `-Credential` aimed at a DC in it.

### Tests
- Unit gate now 34 checks (adds identity flatten/union/summary); smoke gate now 14 checks
  (adds AllUsers/AllComputers export + new dcdiag/replication columns). Pester file extended.

## 1.0.0 — 2026-07-22

Initial release of `Invoke-ADForestAssessment.ps1`, an enhanced successor to
`Invoke-CoreInfraAssessment.ps1`.

### Kept from the base engine
- Per-DC reachability gating (TCP 135 / 9389) before remote calls.
- External-tool wrapper with hard timeout + retries (`Invoke-ExternalCommand`).
- `Set-StrictMode -Version Latest`; honest `Not Assessed` (no false "Healthy"/0).
- CSV-per-topic bundle + single HTML report + transcript.

### Added
- **Verified two-way trust health** (`Get-AdfaTrustHealth`, `Test-AdfaSecureChannel`,
  `Resolve-AdfaTrustHealth`, `Get-AdfaTrustSecurityWarning`): per-direction secure-channel
  verification (`nltest /sc_verify`, `netdom /Verify`), SID filtering / quarantine, selective
  authentication, TGT delegation, RC4 posture, and a fail-closed
  `Healthy/Degraded/Broken/Not Assessed` verdict — the headline gap in both prior scripts.
- Parsed DC diagnostics to PASS/FAIL columns (`Get-AdfaDcDiagnostic`).
- DNS health (zones, scavenging, forwarders, zone transfer) — `Get-AdfaDnsHealth`.
- SYSVOL / DFSR migration state — `Get-AdfaSysvolHealth`.
- GPO inventory incl. unlinked GPOs and links — `Get-AdfaGpoInventory`.
- Password & lockout policy incl. FGPP — `Get-AdfaPasswordPolicy`.
- Privileged group membership — `Get-AdfaPrivilegedAccount`.
- Security posture: krbtgt age, AD Recycle Bin, tombstone lifetime, machine account quota,
  DES/reversible-encryption accounts — `Get-AdfaSecurityPosture`.
- Stale objects (inactive users/computers, PasswordNeverExpires) — `Get-AdfaStaleObject`.
- Site/subnet topology findings (sites without subnets/DCs) — `Get-AdfaSiteHealthFinding`.
- Multi-domain forest traversal via `-AllDomains`; section selection via `-Sections`.
- RAG-coloured HTML with roll-up badges; portable HTML encoding
  (`System.Net.WebUtility`, no `System.Web` dependency).

### Output location
- Default output moved to the logged-on user's Documents:
  `%USERPROFILE%\Documents\AdAssessment\yyyy-MM-dd_HH-mm-ss\`
  (falls back to `$HOME/Documents` off-Windows).

### Tests
- `Tests/Run-Validation.ps1` — dependency-free unit gate (AST parse + stubbed logic), 29 checks.
- `Tests/Run-SmokeTest.ps1` — full stubbed end-to-end pipeline, 9 checks.
- `Tests/Invoke-ADForestAssessment.Tests.ps1` — Pester v5 + PSScriptAnalyzer gate for DC/CI.

### Notes
- The original `Invoke-CoreInfraAssessment.ps1` is left untouched for reference.
