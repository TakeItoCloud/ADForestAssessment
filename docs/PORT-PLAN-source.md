# AD Forest Assessment — Build Plan

Enhancement of the "runner-up" `Invoke-CoreInfraAssessment.ps1` engine into a full,
near-enterprise-grade forest assessment: **`Invoke-ADForestAssessment.ps1`**.

Base engine kept from the runner-up (reachability gating, timeout/retry external-command
wrapper, StrictMode, honest `Not Assessed` status, CSV-per-topic + HTML). Everything the
winner (`Start-ADAssessment.ps1`) had — and several items neither had — is added.

Output bundle now lands in the **logged-in user's Documents**:
`%USERPROFILE%\Documents\AdAssessment\yyyy-MM-dd_HH-mm-ss\` (falls back to `$HOME/Documents`
off-Windows), with `csv\`, `raw\`, `Assessment.html`, and a run transcript.

## Section coverage checklist

| # | Section | Collector | Status |
|---|---------|-----------|--------|
| 1 | Forest / domain functional levels | `Get-AdfaForestSummary` / `Get-AdfaDomainSummary` | Done |
| 2 | FSMO roles | `Get-AdfaFsmoRole` | Done |
| 3 | DC inventory (OS/GC/site/IP, via Get-ADComputer enrichment) | `Get-AdfaDomainControllerInventory` | Done |
| 4 | Replication health (partner metadata, failures, queue) | `Get-AdfaReplicationHealth` | Done |
| 5 | Replication topology (sites/subnets/links/connections) | `Get-AdfaReplicationTopology` | Done |
| 6 | **Forest trusts + two-way trust HEALTH** (nltest sc_verify, netdom /verify, SID filtering, selective auth, TGT delegation, encryption) | `Get-AdfaTrustHealth` + `Resolve-AdfaTrustHealth` | Done |
| 7 | DC diagnostics parsed to PASS/FAIL (dcdiag key tests + service state) | `Get-AdfaDcDiagnostic` | Done |
| 8 | DNS health (zones, scavenging, forwarders, zone transfer) | `Get-AdfaDnsHealth` | Done |
| 9 | SYSVOL / DFSR replication state (dfsrmig, sysvol check) | `Get-AdfaSysvolHealth` | Done |
| 10 | GPO inventory (linked/unlinked, WMI filters) | `Get-AdfaGpoInventory` | Done |
| 11 | Password & lockout policy (default + fine-grained) | `Get-AdfaPasswordPolicy` | Done |
| 12 | Privileged group membership (DA/EA/SA/Administrators/…) | `Get-AdfaPrivilegedAccount` | Done |
| 13 | Security posture (krbtgt age, recycle bin, tombstone, machine quota, AdminSDHolder, stale/never-expire, RC4/DES) | `Get-AdfaSecurityPosture` | Done |
| 14 | Stale objects (inactive users/computers) | `Get-AdfaStaleObject` | Done |
| 15 | Exchange schema markers | `Get-AdfaExchangeSchemaMarker` | Done |
| 16 | Multi-domain forest traversal (`-AllDomains`) | main loop | Done |
| 17 | Raw diagnostics (repadmin / dcdiag) with gating | main | Done |

## Verdict model (fail-closed, coverage-aware)

`Pass | Warning | Fail | Not Assessed`. Anything that could not be collected is
`Not Assessed` — never silently `Pass`/`0`. Trust directions are reported per-direction
(`Verified | Failed | Not Assessed`); an untested direction is never reported as verified.

## Quality gate

- AST parse: 0 errors (authoritative syntax gate; enforced by `Tests/Run-Validation.ps1`).
- `Resolve-AdfaTrustHealth` + status roll-up covered by dependency-free unit tests
  (stubbed `nltest`/`netdom`/AD cmdlets) — runnable without PSGallery/Pester.
- Pester v5 + PSScriptAnalyzer run automatically **when available**; PSGallery is blocked in
  the build sandbox (proxy 403), so the dependency-free harness is the enforced gate here and
  the Pester file is provided for the DC/CI run.

## Notes

- Kept 5.1-safe idioms (no `??`/`?:`/ternary) so it runs on a stock DC's Windows PowerShell
  5.1 *and* on pwsh 7. RSAT ActiveDirectory module required; DnsServer/GroupPolicy/DFSR
  optional (degrade to `Not Assessed`).
- Read-only. No directory writes. External verify tools are invoked read-only
  (`/verify`, `/sc_verify`, `/sc_query`, `getmigrationstate`).
