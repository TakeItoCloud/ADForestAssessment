# Invoke-ADForestAssessment.ps1

Near-enterprise-grade Active Directory **forest** assessment with **verified two-way trust
health**. Built on the engine of `Invoke-CoreInfraAssessment.ps1` (reachability gating,
external-tool timeout/retry, `Set-StrictMode`, honest *Not Assessed* status, CSV-per-topic +
HTML) and extended to full-forest coverage.

## What it reports

| Domain | Forest | Item |
|---|---|---|
| Forest/domain functional levels, FSMO roles | ✔ | Config |
| Domain controller inventory (OS / GC / site / IP) | ✔ | Inventory |
| Replication health (partner metadata, failures, queue depth) + topology (sites, subnets, site links, connections) | ✔ | Health |
| **Trusts + two-way trust health** — secure-channel verification per direction (`nltest /sc_verify`, `netdom … /Verify`), SID filtering / quarantine, selective authentication, TGT delegation, RC4 posture, `Healthy / Degraded / Broken / Not Assessed` verdict | ✔ | **Health** |
| DC diagnostics parsed to PASS/FAIL (`dcdiag` netlogons/services/replications/fsmocheck/advertising/sysvolcheck) | ✔ | Health |
| DNS health (zones, aging/scavenging, forwarders, zone transfer) — *DnsServer module* | ✔ | Health |
| SYSVOL / DFSR migration state (`dfsrmig /getglobalstate`) — *DFSR* | ✔ | Health |
| GPO inventory (linked / unlinked / WMI filters) — *GroupPolicy module* | ✔ | Inventory |
| Password & lockout policy (default + fine-grained) | ✔ | Config |
| Privileged group membership (DA / EA / SA / Administrators) | ✔ | Security |
| Security posture (krbtgt age, AD Recycle Bin, tombstone lifetime, machine account quota, DES/reversible-encryption accounts) | ✔ | Security |
| Stale objects (inactive users/computers, PasswordNeverExpires) | ✔ | Hygiene |
| **Full user & computer export — all populated attributes** (`Identity` section → `csv\AllUsers_<domain>.csv`, `csv\AllComputers_<domain>.csv`; HTML shows a summary) | ✔ | Inventory |
| **PKI / AD CS** — enterprise CAs + ESC1-susceptible templates | ✔ | Security |
| **Dangerous ACLs** — non-default principals with DCSync rights on the domain head | ✔ | Security |
| **Kerberos exposure** — Kerberoastable (SPN) users, AS-REP roastable, unconstrained delegation, RBCD | ✔ | Security |
| **Privileged hygiene** — adminCount orphans, SPNs on privileged accounts, Protected Users | ✔ | Security |
| **DC hardening** — Print Spooler, SMBv1, LDAP signing (remote CIM/registry) | ✔ | Security |
| **Backup status** (`repadmin /showbackup`), **time sync** (`w32tm`) | ✔ | Reliability |
| **DNS depth** — critical SRV records, secure dynamic updates | ✔ | Reliability |
| **Redundancy** — DC count, GPO central store, duplicate SPNs | ✔ | Reliability |
| Exchange schema markers | ✔ | Config |

> **Exact failure detail:** replication findings include a `FailureDetail` column (failing
> partner + `FailureType` + `LastError` + first failure time); dcdiag findings include an overall
> `Status` plus a `Failures` column with the specific failing test(s) and the error lines dcdiag
> emitted. Trust findings already carry per-direction results and `VerifyDetail`.

> **Cross-forest:** `-AllDomains` covers domains **within the target forest only**. A trust does
> not let your ADWS enumerate another forest, so assess each forest separately — run again with
> `-Server <DC-in-other-forest> -Credential <creds-valid-there>` (needs network + rights to that
> forest's ADWS/LDAP).

## Output

Written to the **logged-on user's Documents** by default:

```
%USERPROFILE%\Documents\AdAssessment\yyyy-MM-dd_HH-mm-ss\
    Assessment.html               # RAG report; leads with "Findings (worst first)"
    assessment_<stamp>.log        # detailed itemised run log (every finding + summary)
    csv\Findings-Consolidated.csv # all findings, severity-sorted, in one file
    csv\*.csv                     # one CSV per section (incl. AllUsers_*/AllComputers_*)
    raw\*.txt                     # optional repadmin / dcdiag captures
    transcript_<stamp>.log        # raw PowerShell transcript (host/verbose)
```

Override with `-OutputPath`. Off-Windows it falls back to `$HOME/Documents`.

## Usage

```powershell
# Full forest, all domains, with raw diagnostics
.\Invoke-ADForestAssessment.ps1 -AllDomains -IncludeDcdiag -IncludeRepadmin -Verbose

# Current domain only
.\Invoke-ADForestAssessment.ps1

# Only trusts + replication, skip external trust verification
.\Invoke-ADForestAssessment.ps1 -Sections Trusts,Replication -SkipTrustVerification

# Target a specific DC / credential
.\Invoke-ADForestAssessment.ps1 -Server dc1.contoso.com -Credential (Get-Credential)
```

Key parameters: `-Sections`, `-AllDomains`, `-IncludeDcdiag`, `-IncludeRepadmin`,
`-SkipTrustVerification`, `-Server`, `-Credential`, `-StaleDays`, `-KrbtgtMaxAgeDays`,
`-RpcPortTimeoutMs`, `-ExternalToolTimeoutSeconds`, `-Retries`, `-RetryDelaySeconds`.
See `Get-Help .\Invoke-ADForestAssessment.ps1 -Full`.

## How two-way trust health is determined

For each trust the script records the full configuration, then (unless
`-SkipTrustVerification`):

1. Resolves and **reachability-probes** the partner (via `nltest /dsgetdc` + TCP 135/389) so a
   dead partner can never hang the run.
2. For each **expected direction** (Outbound / Inbound / both, from the trust's `Direction`),
   verifies the secure channel with `nltest /sc_verify` and cross-checks with
   `netdom trust … /Verify`.
3. Rolls up a verdict, **fail-closed**:
   - `Broken` — partner unreachable, or a tested expected direction failed.
   - `Healthy` — every tested expected direction verified (coverage caveats noted when a
     direction can't be validated from the local side; a direction that wasn't tested is
     **never** reported as verified).
   - `Degraded` — verified but a security weakness is present (e.g. SID filtering disabled on
     an external trust, RC4).
   - `Not Assessed` — verification skipped or tools unavailable.

## Requirements

- RSAT **ActiveDirectory** module (required). **DnsServer**, **GroupPolicy**, **DFSR**
  modules and `nltest.exe` / `netdom.exe` / `dcdiag.exe` / `repadmin.exe` / `dfsrmig.exe` are
  optional — anything absent degrades that section to *Not Assessed* rather than failing.
- Windows PowerShell 5.1 or PowerShell 7+. Run elevated, ideally as Enterprise Admin, for
  complete data. **Read-only** — no directory changes.

## Tests

```powershell
# Dependency-free (no PSGallery/Pester needed) — pure logic + full stubbed pipeline
pwsh -File Tests\Run-Validation.ps1
pwsh -File Tests\Run-SmokeTest.ps1

# Pester v5 (on a DC / CI runner) + PSScriptAnalyzer gate
Invoke-Pester Tests\Invoke-ADForestAssessment.Tests.ps1
```
