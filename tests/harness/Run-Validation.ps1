#Requires -Version 5.1
<#
.SYNOPSIS
    Dependency-free validation for Invoke-ADForestAssessment.ps1.

.DESCRIPTION
    Runs without PSGallery / Pester (both are unavailable in the sealed build sandbox). It:
      1. AST-parses the target script (authoritative syntax gate).
      2. Dot-sources it (auto-run suppressed) to load every function without needing RSAT.
      3. Exercises the pure decision logic (trust verdict, security warnings, secure-channel
         output parsing, HTML RAG rendering, coverage-aware findings) with stubbed cmdlets.
    Exits non-zero on the first failure so it can gate CI.

.NOTES
    Complements Invoke-ADForestAssessment.Tests.ps1 (Pester v5), which runs on a DC/CI host
    where Pester is present.
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$script:Failures = 0
$script:Passed = 0

function Assert-True {
    param([Parameter(Mandatory)][bool]$Condition, [Parameter(Mandatory)][string]$Name)
    if ($Condition) { $script:Passed++; Write-Host ("  [PASS] {0}" -f $Name) -ForegroundColor Green }
    else { $script:Failures++; Write-Host ("  [FAIL] {0}" -f $Name) -ForegroundColor Red }
}

function Assert-Equal {
    param($Expected, $Actual, [Parameter(Mandatory)][string]$Name)
    if ($Expected -eq $Actual) { $script:Passed++; Write-Host ("  [PASS] {0}" -f $Name) -ForegroundColor Green }
    else { $script:Failures++; Write-Host ("  [FAIL] {0} (expected '{1}', got '{2}')" -f $Name, $Expected, $Actual) -ForegroundColor Red }
}

$target = Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) 'src/ADForestAssessment/Invoke-ADForestAssessment.ps1'
Write-Host "== 1. AST parse ==" -ForegroundColor Cyan
$tokens = $null; $errors = $null
[System.Management.Automation.Language.Parser]::ParseFile($target, [ref]$tokens, [ref]$errors) | Out-Null
Assert-Equal 0 $errors.Count 'Script parses with zero syntax errors'
if ($errors.Count -gt 0) { $errors | ForEach-Object { Write-Host ("    L{0}: {1}" -f $_.Extent.StartLineNumber, $_.Message) } }

Write-Host "== 2. Load functions (auto-run suppressed) ==" -ForegroundColor Cyan
$env:ADFA_NO_AUTORUN = '1'
. $target
Assert-True ([bool](Get-Command Resolve-AdfaTrustHealth -ErrorAction SilentlyContinue)) 'Resolve-AdfaTrustHealth loaded'
Assert-True ([bool](Get-Command Get-AdfaTrustHealth -ErrorAction SilentlyContinue)) 'Get-AdfaTrustHealth loaded'

Write-Host "== 3. Resolve-AdfaTrustHealth verdict logic ==" -ForegroundColor Cyan
$r = Resolve-AdfaTrustHealth -Direction Bidirectional -OutboundResult Verified -InboundResult Verified -TargetReachable $true
Assert-Equal 'Healthy' $r.Health 'Bidirectional, both verified => Healthy'

$r = Resolve-AdfaTrustHealth -Direction Bidirectional -OutboundResult Failed -InboundResult Verified -TargetReachable $true
Assert-Equal 'Broken' $r.Health 'Any expected direction Failed => Broken'

$r = Resolve-AdfaTrustHealth -Direction Outbound -OutboundResult Verified -InboundResult 'Not Assessed' -TargetReachable $false
Assert-Equal 'Broken' $r.Health 'Unreachable partner => Broken'

$r = Resolve-AdfaTrustHealth -Direction Bidirectional -OutboundResult 'Not Assessed' -InboundResult 'Not Assessed' -TargetReachable $true -VerificationSkipped $true
Assert-Equal 'Not Assessed' $r.Health 'Verification skipped => Not Assessed'

$r = Resolve-AdfaTrustHealth -Direction Bidirectional -OutboundResult Verified -InboundResult 'Not Assessed' -TargetReachable $true
Assert-Equal 'Healthy' $r.Health 'Outbound verified, inbound not testable => Healthy (with coverage note)'
Assert-True ($r.Reasons -join ' ' -match 'Inbound') 'Coverage note mentions inbound gap'

$r = Resolve-AdfaTrustHealth -Direction Outbound -OutboundResult Verified -InboundResult 'Not Assessed' -TargetReachable $true -SecurityWarnings @('SID filtering disabled')
Assert-Equal 'Degraded' $r.Health 'Verified but security warning => Degraded'

$r = Resolve-AdfaTrustHealth -Direction Bidirectional -OutboundResult 'Not Assessed' -InboundResult 'Not Assessed' -TargetReachable $true
Assert-Equal 'Not Assessed' $r.Health 'Reachable but nothing verified => Not Assessed (never false Pass)'

Write-Host "== 4. Get-AdfaTrustSecurityWarning ==" -ForegroundColor Cyan
$extTrust = [pscustomobject]@{ TrustType = 'External'; SIDFilteringQuarantined = $false; SelectiveAuthentication = $false; TGTDelegation = $false; UsesRC4Encryption = $false }
$w = Get-AdfaTrustSecurityWarning -Trust $extTrust
Assert-True (@($w).Count -ge 2) 'External trust w/ SID filtering off + selective auth off => >=2 warnings'
Assert-True (($w -join ' ') -match 'SID filtering') 'Warning mentions SID filtering'

$forestTrust = [pscustomobject]@{ TrustType = 'Forest'; SIDFilteringForestAware = $false; TGTDelegation = $true; UsesRC4Encryption = $true }
$w = Get-AdfaTrustSecurityWarning -Trust $forestTrust
Assert-True (($w -join ' ') -match 'TGT delegation') 'Forest trust w/ TGT delegation => warning'
Assert-True (($w -join ' ') -match 'RC4') 'RC4 encryption => warning'

$cleanTrust = [pscustomobject]@{ TrustType = 'Forest'; SIDFilteringForestAware = $true; SelectiveAuthentication = $true; TGTDelegation = $false; UsesRC4Encryption = $false }
$w = Get-AdfaTrustSecurityWarning -Trust $cleanTrust
Assert-Equal 0 (@($w).Count) 'Clean forest trust => no warnings'

Write-Host "== 5. Test-AdfaSecureChannel output parsing (stubbed tools) ==" -ForegroundColor Cyan
function Test-CommandAvailable { param([string]$Name) return $true }   # pretend nltest exists
function Invoke-ExternalCommand {
    param([string]$FilePath, [string]$Arguments, [string]$OutFile, [int]$TimeoutSeconds, [int]$Retries, [int]$RetryDelaySeconds)
    [pscustomobject]@{ Success = $true; ExitCode = 0; Attempt = 1; Error = $null; OutFile = $OutFile
        StdOut = "Flags: 0`nTrusted DC Name \\dc1`nTrust Verification Status = 0x0 NERR_Success`nThe command completed successfully" }
}
$sc = Test-AdfaSecureChannel -SourceDomain 'a.local' -TargetDomain 'b.local'
Assert-Equal 'Verified' $sc.Result 'nltest success output => Verified'

function Invoke-ExternalCommand {
    param([string]$FilePath, [string]$Arguments, [string]$OutFile, [int]$TimeoutSeconds, [int]$Retries, [int]$RetryDelaySeconds)
    [pscustomobject]@{ Success = $false; ExitCode = 1; Attempt = 1; Error = $null; OutFile = $OutFile
        StdOut = "Trust Verification Status = 0x35 ERROR_NO_LOGON_SERVERS`nThe command failed" }
}
$sc = Test-AdfaSecureChannel -SourceDomain 'a.local' -TargetDomain 'b.local'
Assert-Equal 'Failed' $sc.Result 'nltest error status => Failed'

function Test-CommandAvailable { param([string]$Name) return $false }  # no tools
$sc = Test-AdfaSecureChannel -SourceDomain 'a.local' -TargetDomain 'b.local'
Assert-Equal 'Not Assessed' $sc.Result 'No verification tools => Not Assessed'

Write-Host "== 6. Get-AdfaTrustHealth end-to-end (stubbed) ==" -ForegroundColor Cyan
function Get-ADTrust {
    param([string]$Filter, $Properties, [string]$Server, $Credential, $ErrorAction)
    [pscustomobject]@{ Name = 'b.local'; Source = 'a.local'; Target = 'b.local'; Direction = 'Bidirectional'
        TrustType = 'Forest'; IntraForest = $false; ForestTransitive = $true
        SelectiveAuthentication = $true; SIDFilteringForestAware = $true; SIDFilteringQuarantined = $true
        TGTDelegation = $false; UsesRC4Encryption = $false; Created = (Get-Date); Modified = (Get-Date) }
}
function Test-TcpPort { param([string]$ComputerName, [int]$Port, [int]$TimeoutMs) return $true }
function Test-CommandAvailable { param([string]$Name) return $false }  # skip dsgetdc probe
function Test-AdfaSecureChannel {
    param([string]$SourceDomain, [string]$TargetDomain, [int]$TimeoutSeconds, [int]$Retries, [int]$RetryDelaySeconds)
    [pscustomobject]@{ Result = 'Verified'; Tool = 'stub'; Detail = 'stub' }
}
# Inbound is verified ON the partner DC (Test-AdfaRemoteSecureChannel) - the old local
# nltest against our own domain was a false Verified. Stub the remote path succeeding:
function Test-AdfaRemoteSecureChannel {
    param([string]$PartnerDomain, [string]$VerifyDomain, [string]$PartnerDc, [pscredential]$Credential, [int]$RpcPortTimeoutMs)
    [pscustomobject]@{ Result = 'Verified'; Tool = 'stub'; Detail = 'stub remote verify' }
}
$rows = Get-AdfaTrustHealth -DomainName 'a.local' -AdParams @{}
Assert-Equal 1 (@($rows).Count) 'One trust row returned'
Assert-Equal 'Healthy' $rows[0].Health 'Healthy forest trust, both directions verified'
Assert-Equal 'Verified' $rows[0].OutboundSecureChannel 'Outbound recorded Verified'
Assert-Equal 'Verified' $rows[0].InboundSecureChannel 'Inbound recorded Verified (via stubbed partner-side verification)'

# And when the partner side cannot be remoted to, inbound must be Not Assessed - never
# inferred from a local check that would succeed on any healthy DC.
function Test-AdfaRemoteSecureChannel {
    param([string]$PartnerDomain, [string]$VerifyDomain, [string]$PartnerDc, [pscredential]$Credential, [int]$RpcPortTimeoutMs)
    [pscustomobject]@{ Result = 'Not Assessed'; Tool = 'winrm'; Detail = "WinRM not reachable. Run 'nltest /sc_verify:$VerifyDomain' on a DC in $PartnerDomain." }
}
$rows = Get-AdfaTrustHealth -DomainName 'a.local' -AdParams @{}
Assert-Equal 'Not Assessed' $rows[0].InboundSecureChannel 'Inbound honestly Not Assessed when the partner side is unreachable'
Assert-Equal 'Healthy' $rows[0].Health 'Outbound-verified trust stays Healthy with the inbound coverage gap noted'
Assert-True ($rows[0].Reasons -match 'Inbound') 'Coverage gap for inbound is stated in Reasons'

# Skip-verification path must never fabricate a result.
$rows = Get-AdfaTrustHealth -DomainName 'a.local' -AdParams @{} -SkipVerification
Assert-Equal 'Not Assessed' $rows[0].Health 'SkipVerification => Not Assessed'
Assert-Equal 'Not Assessed' $rows[0].OutboundSecureChannel 'SkipVerification => outbound Not Assessed'

Write-Host "== 7. Findings + HTML rendering ==" -ForegroundColor Cyan
$f = New-Finding -Area 'Security' -Item 'krbtgt' -Status 'Warning' -Detail 'old'
Assert-Equal 'Warning' $f.Status 'New-Finding sets status'
$html = ConvertTo-AdfaHtmlSection -Title 'T' -Data @(
    [pscustomobject]@{ Item = 'x'; Health = 'Broken' },
    [pscustomobject]@{ Item = 'y'; Health = 'Healthy' }
)
Assert-True ($html -match "tr class='bad'") 'Broken row renders bad RAG class'
Assert-True ($html -match "tr class='ok'") 'Healthy row renders ok RAG class'
$htmlEmpty = ConvertTo-AdfaHtmlSection -Title 'Empty' -Data @()
Assert-True ($htmlEmpty -match 'No data collected') 'Empty section renders placeholder'

Write-Host "== 8. Identity export flattening ==" -ForegroundColor Cyan
$obj1 = [pscustomobject]@{ SamAccountName = 'jdoe'; Enabled = $true; MemberOf = @('CN=A', 'CN=B') }
$obj2 = [pscustomobject]@{ SamAccountName = 'asmith'; Description = 'svc' }
$props = Get-AdfaObjectPropertyUnion -Objects @($obj1, $obj2)
Assert-True (($props -contains 'MemberOf') -and ($props -contains 'Description')) 'Property union spans differing objects'
$flat = ConvertTo-AdfaFlatObject -InputObject $obj1 -Property $props
Assert-Equal 'CN=A;CN=B' $flat.MemberOf 'Multi-valued attribute flattened with ;'
Assert-Equal '' $flat.Description 'Missing property flattens to empty string (no StrictMode throw)'
$sum = Get-AdfaIdentitySummary -DomainName 'contoso.com' -Users @($obj1, $obj2) -Computers @()
Assert-Equal 2 ($sum | Where-Object Object -eq 'Users' | Select-Object -Expand Total) 'Identity summary counts users'
Assert-Equal 1 ($sum | Where-Object Object -eq 'Users' | Select-Object -Expand Enabled) 'Identity summary counts enabled users'

Write-Host "== 9. Deep security pure logic ==" -ForegroundColor Cyan
# ESC1 heuristic
$vulnT = [pscustomobject]@{ 'msPKI-Certificate-Name-Flag' = 1; 'msPKI-Enrollment-Flag' = 0; 'msPKI-RA-Signature' = 0; 'pKIExtendedKeyUsage' = @('1.3.6.1.5.5.7.3.2') }
Assert-True (Test-AdfaEsc1Template -Template $vulnT).Vulnerable 'ESC1: supplies-subject + auth EKU + no approval => vulnerable'
$safeT = [pscustomobject]@{ 'msPKI-Certificate-Name-Flag' = 0; 'msPKI-Enrollment-Flag' = 2; 'msPKI-RA-Signature' = 1; 'pKIExtendedKeyUsage' = @('1.3.6.1.5.5.7.3.2') }
Assert-True (-not (Test-AdfaEsc1Template -Template $safeT).Vulnerable) 'ESC1: approval required + no supplies-subject => not vulnerable'
$approvalT = [pscustomobject]@{ 'msPKI-Certificate-Name-Flag' = 1; 'msPKI-Enrollment-Flag' = 2; 'msPKI-RA-Signature' = 0; 'pKIExtendedKeyUsage' = @('1.3.6.1.5.5.7.3.2') }
Assert-True (-not (Test-AdfaEsc1Template -Template $approvalT).Vulnerable) 'ESC1: manager approval required => not vulnerable'

# DCSync ACE detection
$getChanges = $script:Config.DcSyncRightGuids['DS-Replication-Get-Changes-All']
$syncAce = [pscustomobject]@{ AccessControlType = 'Allow'; ActiveDirectoryRights = 'ExtendedRight'; ObjectType = $getChanges; IdentityReference = 'CONTOSO\eviluser' }
Assert-True (Test-AdfaDcSyncAce -Ace $syncAce) 'DCSync ACE: Get-Changes-All extended right => detected'
$denyAce = [pscustomobject]@{ AccessControlType = 'Deny'; ActiveDirectoryRights = 'ExtendedRight'; ObjectType = $getChanges; IdentityReference = 'x' }
Assert-True (-not (Test-AdfaDcSyncAce -Ace $denyAce)) 'DCSync ACE: Deny ACE => not flagged'
$readAce = [pscustomobject]@{ AccessControlType = 'Allow'; ActiveDirectoryRights = 'ReadProperty'; ObjectType = '00000000-0000-0000-0000-000000000000'; IdentityReference = 'x' }
Assert-True (-not (Test-AdfaDcSyncAce -Ace $readAce)) 'DCSync ACE: ordinary read => not flagged'
$genericAll = [pscustomobject]@{ AccessControlType = 'Allow'; ActiveDirectoryRights = 'GenericAll'; ObjectType = '00000000-0000-0000-0000-000000000000'; IdentityReference = 'x' }
Assert-True (Test-AdfaDcSyncAce -Ace $genericAll) 'DCSync ACE: GenericAll => detected'

# Duplicate SPN detection
$objs = @(
    [pscustomobject]@{ SamAccountName = 'svc1'; ServicePrincipalName = @('MSSQLSvc/db1:1433', 'HOST/svc1') },
    [pscustomobject]@{ SamAccountName = 'svc2'; ServicePrincipalName = @('MSSQLSvc/db1:1433') },
    [pscustomobject]@{ SamAccountName = 'svc3'; ServicePrincipalName = @('HOST/svc3') }
)
$dupes = Find-AdfaDuplicateSpn -Objects $objs
Assert-Equal 1 (@($dupes).Count) 'Duplicate SPN: one collision found'
Assert-True (($dupes[0].Spn -eq 'mssqlsvc/db1:1433') -and ($dupes[0].Holders -match 'svc1' -and $dupes[0].Holders -match 'svc2')) 'Duplicate SPN: names the SPN and both holders'
$emptyDupes = Find-AdfaDuplicateSpn -Objects @()   # assign-then-count (how collectors use it)
Assert-Equal 0 (@($emptyDupes).Count) 'Duplicate SPN: empty input => none'

Write-Host "== 10. Recovery & consistency pure logic ==" -ForegroundColor Cyan
# DNS vs AD divergence
$cmp = Compare-AdfaDnsAdvertisement -AdHosts @('dc1.corp.local', 'dc2.corp.local') -DnsTargets @('dc2.corp.local', 'dc3.corp.local')
Assert-Equal 'dc3.corp.local' (@($cmp.StaleInDns) -join ',') 'DNS vs AD: stale entry detected'
Assert-Equal 'dc1.corp.local' (@($cmp.MissingFromDns) -join ',') 'DNS vs AD: missing advertisement detected'
Assert-Equal 'dc2.corp.local' (@($cmp.Matched) -join ',') 'DNS vs AD: agreement detected'
$cmp = Compare-AdfaDnsAdvertisement -AdHosts @('DC1.Corp.Local') -DnsTargets @('dc1.corp.local.')
Assert-Equal 0 (@($cmp.StaleInDns).Count + @($cmp.MissingFromDns).Count) 'DNS vs AD: case and trailing dot normalised'

# DC machine-account password verdict
Assert-Equal 'Pass' (Resolve-AdfaDcPasswordVerdict -AgeDays 10) 'DC password: fresh => Pass'
Assert-Equal 'Warning' (Resolve-AdfaDcPasswordVerdict -AgeDays 45) 'DC password: warn threshold => Warning'
Assert-Equal 'Fail' (Resolve-AdfaDcPasswordVerdict -AgeDays 90) 'DC password: fail threshold => Fail'
Assert-Equal 'Not Assessed' (Resolve-AdfaDcPasswordVerdict -AgeDays $null) 'DC password: unknown age => Not Assessed, never a verdict'

# Recommendation mapping
Assert-True ((Get-AdfaRecommendation -Section 'Trusts & Two-Way Health' -Item 't' -Detail 'Trust partner is not reachable.') -match 'netdom trust') 'Recommendation: broken trust => netdom trust reset'
Assert-True ((Get-AdfaRecommendation -Section 'Directory Service Events' -Item 'Event 1988 on DC1' -Detail 'Lingering object detected') -match 'removelingeringobjects') 'Recommendation: lingering object => removelingeringobjects'
Assert-True ((Get-AdfaRecommendation -Section 'DSA GUID CNAMEs' -Item 'DSA GUID CNAME for dc1' -Detail 'missing') -match 'dsregdns') 'Recommendation: missing DSA CNAME => dsregdns'
Assert-Equal '' (Get-AdfaRecommendation -Section 'Forest Summary' -Item 'xyzzy' -Detail 'nothing matches') 'Recommendation: no match => empty, never invented'
$trustRec = Get-AdfaRecommendation -Section 'Trusts & Two-Way Health' -Item 'corp-partner' -Detail 'Outbound secure channel verification FAILED.'
Assert-True ($trustRec -match 'netdom trust' -and $trustRec -notmatch 'resetpwd') 'Recommendation: trust failure mentioning secure channel routes to the TRUST fix'

Write-Host "== 11. R1/R2 pure logic ==" -ForegroundColor Cyan
# DNS query outcome classification
Assert-Equal 'NoTool' (Get-AdfaDnsQueryOutcome -Available $false) 'DNS outcome: no resolver tool'
Assert-Equal 'Resolved' (Get-AdfaDnsQueryOutcome -Available $true -TargetCount 2) 'DNS outcome: targets => Resolved'
Assert-Equal 'NoRecord' (Get-AdfaDnsQueryOutcome -Available $true -TargetCount 0 -ErrorText 'DNS name does not exist') 'DNS outcome: NXDOMAIN => NoRecord'
Assert-Equal 'NoAnswer' (Get-AdfaDnsQueryOutcome -Available $true -TargetCount 0 -ErrorText 'request timed out') 'DNS outcome: timeout => NoAnswer, never NoRecord'

# Per-server divergence
$views = @{ 'dns1' = @('dc1.x', 'dc2.x'); 'dns2' = @('dc2.x', 'dc3.x') }
$sv = Compare-AdfaDnsServerView -AdHosts @('dc1.x', 'dc2.x') -ServerTargets $views
Assert-Equal 'dns2' (@($sv.DivergentServers) -join ',') 'Server view: divergent server named'
Assert-Equal 'dns1' (@($sv.AgreeingServers) -join ',') 'Server view: agreeing server named'

# repadmin /showrepl CSV parse
$showrepl = "Repadmin banner line`nshowrepl_COLUMNS,Destination DSA Site,Destination DSA,Naming Context,Source DSA Site,Source DSA,Transport Type,Number of Failures,Last Failure Time,Last Success Time,Last Failure Status`nshowrepl_INFO,S1,DC1,""DC=x"",S1,DC2,RPC,0,0,2026-08-30 10:00:00,0`nshowrepl_INFO,S1,DC1,""DC=x"",S1,DC3,RPC,7,t,t,1722"
$links = @(ConvertFrom-AdfaShowreplCsv -Text $showrepl)
Assert-Equal 2 (@($links).Count) 'showrepl CSV: two links parsed past the banner'
Assert-Equal '7' ([string](@($links | Where-Object { $_.'Source DSA' -eq 'DC3' })[0].'Number of Failures')) 'showrepl CSV: failure count preserved'
Assert-Equal 0 (@(ConvertFrom-AdfaShowreplCsv -Text 'garbage').Count) 'showrepl CSV: unparsable => empty, not a crash'

# Backup date extraction
$bd = Get-AdfaLatestBackupDate -Text "DC=x : 2026-07-01 10:00:00`nCN=Configuration : 2026-08-15 09:30:00"
Assert-Equal ([datetime]'2026-08-15 09:30:00') $bd 'Backup date: most recent of several'
Assert-True ($null -eq (Get-AdfaLatestBackupDate -Text 'no dates')) 'Backup date: none parsable => null, never fabricated'

Write-Host "== 12. Heterogeneous row shapes (regression: live run 2026-08-30) ==" -ForegroundColor Cyan
# A reachable DC yields FailureDetail; an unreachable one did not. Reading row 0's columns
# off a shorter row threw PropertyNotFoundStrict and lost the entire HTML report.
$mixed = @(
    [pscustomobject]@{ DomainController = 'dc1'; Status = 'Fail'; FailureDetail = 'partner=dc9 lastError=1722' },
    [pscustomobject]@{ DomainController = 'dc2'; Status = 'Not Assessed'; Detail = 'SKIPPED: RPC135=False' }
)
$norm = @(ConvertTo-AdfaRowSet -Rows $mixed)
Assert-Equal 2 (@($norm).Count) 'RowSet: both rows survive normalisation'
Assert-Equal 'DomainController,Status,FailureDetail,Detail' (@($norm[0].PSObject.Properties.Name) -join ',') 'RowSet: column union in first-seen order'
Assert-Equal '' ([string]$norm[1].FailureDetail) 'RowSet: missing column filled with empty string'
Assert-Equal 'partner=dc9 lastError=1722' ([string]$norm[0].FailureDetail) 'RowSet: present values preserved'
Assert-Equal 0 (@(ConvertTo-AdfaRowSet -Rows @()).Count) 'RowSet: empty input => empty, not one empty array'

$renderOk = $true
try { $html = ConvertTo-AdfaHtmlSection -Title 'Replication Health' -Data $mixed }
catch { $renderOk = $false; $html = '' }
Assert-True $renderOk 'HTML: mixed-shape section renders instead of throwing PropertyNotFoundStrict'
Assert-True ($html -match 'FailureDetail' -and $html -match 'dc2') 'HTML: union column and short row both present'

# Short row first: columns must come from the union, not from row 0.
$mixedRev = @($mixed[1], $mixed[0])
$htmlRev = ConvertTo-AdfaHtmlSection -Title 'Replication Health' -Data $mixedRev
Assert-True ($htmlRev -match 'partner=dc9') 'HTML: short row first still renders the longer row''s data'

Write-Host ""
Write-Host "== 13. JSON report document (machine-readable output) ==" -ForegroundColor Cyan

# --- Summary roll-up: every finding lands in exactly one bucket -----------------
# The four counters Invoke-Main keeps for the log line and the HTML badges match
# Pass/Healthy, Warning/Degraded, Fail/Broken and Not Assessed - but NOT 'Info', which is a
# valid New-Finding status. Measured on the three-domain fixture: 123 findings, 106 counted,
# 17 Info counted nowhere. The document adds 'info' plus an 'unclassified' catch-all so a
# consumer can assert the buckets sum to the total.
$legacy = [pscustomobject]@{ Pass = 1; Warning = 1; Fail = 1; NotAssessed = 1 }
$mixedFindings = @(
    (New-Finding -Area 'A' -Item 'i1' -Status 'Pass'         -Detail 'd'),
    (New-Finding -Area 'A' -Item 'i2' -Status 'Warning'      -Detail 'd'),
    (New-Finding -Area 'A' -Item 'i3' -Status 'Fail'         -Detail 'd'),
    (New-Finding -Area 'A' -Item 'i4' -Status 'Not Assessed' -Detail 'd'),
    (New-Finding -Area 'A' -Item 'i5' -Status 'Info'         -Detail 'd'),
    (New-Finding -Area 'A' -Item 'i6' -Status 'Info'         -Detail 'd')
)
$sum = New-AdfaReportSummary -Summary $legacy -Findings $mixedFindings
Assert-Equal 6 ([int]$sum.total) 'Summary: total counts every finding'
Assert-Equal 2 ([int]$sum.info) 'Summary: Info findings are counted, not invisible'
Assert-Equal 0 ([int]$sum.unclassified) 'Summary: nothing escapes every bucket'
$bucketSum = [int]$sum.pass + [int]$sum.warning + [int]$sum.fail + [int]$sum.notAssessed +
    [int]$sum.info + [int]$sum.unclassified
Assert-Equal 6 $bucketSum 'Summary: buckets reconcile with the total'

# A status none of the filters know must surface in 'unclassified', never vanish.
$oddFindings = @([pscustomobject]@{ Area = 'A'; Item = 'i'; Status = 'Verified'; Detail = 'd' })
$oddSum = New-AdfaReportSummary -Summary $legacy -Findings $oddFindings
Assert-Equal 1 ([int]$oddSum.unclassified) 'Summary: an unknown status is reported, not dropped'
Assert-Equal 1 ([int]$oddSum.total) 'Summary: unknown status still counted in the total'

# A row with no Status column at all must not throw under StrictMode.
$noStatusOk = $true
try { $nsSum = New-AdfaReportSummary -Summary $legacy -Findings @([pscustomobject]@{ Area = 'A' }) }
catch { $noStatusOk = $false }
Assert-True $noStatusOk 'Summary: a row without Status does not throw (StrictMode-safe)'
Assert-Equal 0 ([int]$nsSum.info) 'Summary: a row without Status is not counted as Info'

Assert-Equal 0 ([int](New-AdfaReportSummary -Summary $legacy -Findings @()).total) 'Summary: empty findings => total 0'

# --- Document shape -------------------------------------------------------------
$meta = [pscustomobject]@{
    Forest = 'contoso.com'; Generated = '2026-01-01 00:00:00Z'; RunBy = 'CONTOSO\tester'
    Version = '9.9.9'; DomainsScoped = @('contoso.com', 'north.contoso.com'); DcCount = 2
    Badges = "<span class='b-ok'>Pass 1</span>"
}
# NOTE: not $sections - the script under test declares a [ValidateSet] $Sections parameter and
# PowerShell variable names are case-insensitive, so that name is taken in this scope.
$docSections = [ordered]@{}
$docSections['One Row'] = @([pscustomobject]@{ Name = 'dc1'; Site = 'HQ' })
$docSections['Empty']   = @()
$doc = New-AdfaReportDocument -Meta $meta -Findings $mixedFindings -Coverage @() -Sections $docSections -Summary $legacy

Assert-Equal 1 ([int]$doc.schemaVersion) 'Document: schemaVersion emitted'
Assert-Equal 'ADForestAssessment' ([string]$doc.tool.name) 'Document: tool name'
Assert-Equal '9.9.9' ([string]$doc.tool.version) 'Document: tool version from config'
Assert-Equal 'contoso.com' ([string]$doc.run.forest) 'Document: forest recorded'
Assert-Equal 2 (@($doc.run.domainsScoped).Count) 'Document: every scoped domain recorded'
Assert-Equal 6 (@($doc.findings).Count) 'Document: findings carried'
# $doc is an OrderedDictionary, so PSObject.Properties enumerates .NET members, not keys -
# testing it that way would pass whatever the document contained. Assert on the keys, and on
# the serialised text, so the claim is about real content.
Assert-True (@($doc.Keys) -notcontains 'Badges') 'Document: no Badges key in the data document'
Assert-True (@($doc.Keys) -contains 'summary') 'Document: expected keys really are inspectable this way (non-vacuity)'
Assert-True (@($doc.sections.Keys) -contains 'Empty') 'Document: a section that collected nothing is still present'
Assert-Equal 0 (@($doc.sections['Empty']).Count) 'Document: empty section is empty, not one empty array'

# --- Serialisation round trip ---------------------------------------------------
# This is the assertion that has to travel to Windows PowerShell 5.1: ConvertTo-Json there is
# a different implementation, and a single-element array collapsing to an object - or an empty
# one rendering as "" - would break any consumer indexing the result. Verified on pwsh 7.4 in
# CI; this harness is what carries the check onto a 5.1 host.
$json = $doc | ConvertTo-Json -Depth 12
$back = $json | ConvertFrom-Json
Assert-True ($null -ne $back) 'Round trip: document parses back'
Assert-Equal 'dc1' ([string]@($back.sections.'One Row')[0].Name) 'Round trip: single-element section keeps its row addressable'
Assert-True (@($back.findings).Count -eq 6) 'Round trip: findings survive as an array'
Assert-True ($json -notmatch '"@\{') 'Round trip: no row collapsed to a hashtable string at depth 12'
Assert-True ($json -notmatch 'b-ok' -and $json -notmatch '<span') 'Round trip: no HTML markup leaked into the JSON'

# Depth 2 is the ConvertTo-Json default and MUST be shown to lose data, otherwise the explicit
# -Depth on Export-AdfaJsonReport is cargo cult. Truncation stringifies the row rather than
# emitting a type name, so that is what is asserted.
$shallow = $doc | ConvertTo-Json -Depth 2
Assert-True ($shallow -match '"@\{') 'Depth: the default depth of 2 demonstrably collapses section rows'

Write-Host ""
Write-Host "== 14. Directory Service log coverage (a cleared log must not read as healthy) ==" -ForegroundColor Cyan

# The defect this closes: finding no events reported Pass, so a DC whose Directory Service log
# was wiped during a ransomware recovery looked exactly like a healthy one on the checks that
# matter most - USN rollback (2095), unsupported restore (2103), lingering objects (1988).
$wStart = (Get-Date).AddDays(-14)

Assert-Equal 'Covered' (Get-AdfaEventLogCoverage -Inspected $true -RecordCount 500 -OldestRecord $wStart.AddDays(-30) -WindowStart $wStart) 'Coverage: log older than the window => Covered'
Assert-Equal 'Covered' (Get-AdfaEventLogCoverage -Inspected $true -RecordCount 500 -OldestRecord $wStart -WindowStart $wStart) 'Coverage: oldest record exactly at the window start => Covered (boundary)'
Assert-Equal 'Truncated' (Get-AdfaEventLogCoverage -Inspected $true -RecordCount 500 -OldestRecord $wStart.AddDays(1) -WindowStart $wStart) 'Coverage: log starts inside the window => Truncated'
Assert-Equal 'Truncated' (Get-AdfaEventLogCoverage -Inspected $true -RecordCount 3 -OldestRecord (Get-Date) -WindowStart $wStart) 'Coverage: log cleared moments ago => Truncated, never Covered'
Assert-Equal 'Empty' (Get-AdfaEventLogCoverage -Inspected $true -RecordCount 0 -OldestRecord $null -WindowStart $wStart) 'Coverage: zero records => Empty'
Assert-Equal 'Unknown' (Get-AdfaEventLogCoverage -Inspected $false -RecordCount $null -OldestRecord $null -WindowStart $wStart) 'Coverage: log not inspectable => Unknown'
Assert-Equal 'Unknown' (Get-AdfaEventLogCoverage -Inspected $true -RecordCount 500 -OldestRecord $null -WindowStart $wStart) 'Coverage: oldest record unknown => Unknown, not Covered'
Assert-Equal 'Unknown' (Get-AdfaEventLogCoverage -Inspected $true -RecordCount 500 -OldestRecord $wStart.AddDays(-1) -WindowStart $null) 'Coverage: no window bound => Unknown, not Covered'

# Fail-closed in the round: NOTHING may classify as Covered without both bounds present and
# the log demonstrably reaching back. Enumerate the non-covered inputs and assert the whole set.
$notCovered = @(
    (Get-AdfaEventLogCoverage -Inspected $false -RecordCount 10   -OldestRecord $wStart.AddDays(-5) -WindowStart $wStart),
    (Get-AdfaEventLogCoverage -Inspected $true  -RecordCount 0    -OldestRecord $null               -WindowStart $wStart),
    (Get-AdfaEventLogCoverage -Inspected $true  -RecordCount 10   -OldestRecord $null               -WindowStart $wStart),
    (Get-AdfaEventLogCoverage -Inspected $true  -RecordCount 10   -OldestRecord $wStart.AddDays(2)  -WindowStart $wStart)
)
Assert-Equal 4 (@($notCovered).Count) 'Coverage: non-vacuity - four degraded inputs were actually evaluated'
Assert-Equal 0 (@($notCovered | Where-Object { $_ -eq 'Covered' }).Count) 'Coverage: no degraded input is ever reported as Covered'

# The caveat sentence must name what limits the claim, not just say "unknown".
Assert-Equal '' (Get-AdfaEventCoverageDetail -Coverage 'Covered' -OldestRecord $wStart -LookbackDays 14) 'Detail: Covered carries no caveat'
$trunc = Get-AdfaEventCoverageDetail -Coverage 'Truncated' -OldestRecord ([datetime]'2026-09-15 08:30') -LookbackDays 14
Assert-True ($trunc -match '2026-09-15 08:30') 'Detail: Truncated names where coverage actually begins'
Assert-True ($trunc -match 'cleared or has wrapped') 'Detail: Truncated names the likely cause'
$empty = Get-AdfaEventCoverageDetail -Coverage 'Empty' -OldestRecord $null -LookbackDays 14
Assert-True ($empty -match 'proves nothing') 'Detail: Empty says absence proves nothing'
$unk = Get-AdfaEventCoverageDetail -Coverage 'Unknown' -OldestRecord $null -LookbackDays 14 -Reason 'Access is denied'
Assert-True ($unk -match 'Access is denied') 'Detail: Unknown carries the underlying cause'

# The finding must carry guidance, and it must be the RIGHT guidance: recovering the evidence,
# not resetting a secure channel. The map is first-match-wins, so ordering is behaviour.
$covRec = Get-AdfaRecommendation -Section 'Directory Service Events' -Item 'Log coverage on dc1.contoso.com' `
    -Detail (Get-AdfaEventCoverageDetail -Coverage 'Truncated' -OldestRecord (Get-Date) -LookbackDays 14)
Assert-True (-not [string]::IsNullOrWhiteSpace($covRec)) 'Recommendation: a coverage finding carries guidance'
Assert-True ($covRec -match 'UNASSESSED') 'Recommendation: says to treat the DC as unassessed, not healthy'
Assert-True ($covRec -match 'evtx|SIEM') 'Recommendation: points at recovering the archived evidence'
Assert-True ($covRec -notmatch 'netdom trust') 'Recommendation: not hijacked by the trust guidance'

# A real event found in the window must still route to its own event guidance, not to the
# coverage text - the new entry sits ahead of the event entries, so this is worth pinning.
$rollbackRec = Get-AdfaRecommendation -Section 'Directory Service Events' -Item 'Event 2095 on dc1.contoso.com' `
    -Detail '1 occurrence(s) in 14 day(s), last 2026-09-20 10:00. USN rollback detected - the directory is silently diverging.'
Assert-True ($rollbackRec -notmatch 'UNASSESSED') 'Recommendation: a real USN rollback still gets rollback guidance, not coverage guidance'
Assert-True (-not [string]::IsNullOrWhiteSpace($rollbackRec)) 'Recommendation: USN rollback guidance is present'

Write-Host ""
Write-Host "== 15. Exchange Server SE compatibility (forest level + DC operating systems) ==" -ForegroundColor Cyan

$seCfg = $script:Config.ExchangeSe
Assert-True ($seCfg.SourceUrl -match 'learn\.microsoft\.com') 'SE config: carries its vendor source URL'
Assert-True ($seCfg.ReadDate -match '^\d{4}-\d{2}-\d{2}$') 'SE config: carries the date the source was read'

# --- OS pattern matching. The 2012 R2 / 2012 split is the trap: 2012 R2 is supported and
# plain 2012 is not, so a loosened pattern would silently pass an unsupported DC.
Assert-Equal 'Windows Server 2025' (Test-AdfaOsSupported -OperatingSystem 'Windows Server 2025 Datacenter' -SupportedOs $seCfg.SupportedDomainControllerOs) 'SE OS: 2025 supported'
Assert-Equal 'Windows Server 2022' (Test-AdfaOsSupported -OperatingSystem 'Windows Server 2022 Standard' -SupportedOs $seCfg.SupportedDomainControllerOs) 'SE OS: 2022 supported'
Assert-Equal 'Windows Server 2019' (Test-AdfaOsSupported -OperatingSystem 'Windows Server 2019 Datacenter' -SupportedOs $seCfg.SupportedDomainControllerOs) 'SE OS: 2019 supported'
Assert-Equal 'Windows Server 2016' (Test-AdfaOsSupported -OperatingSystem 'Windows Server 2016 Standard' -SupportedOs $seCfg.SupportedDomainControllerOs) 'SE OS: 2016 supported'
Assert-Equal 'Windows Server 2012 R2' (Test-AdfaOsSupported -OperatingSystem 'Windows Server 2012 R2 Datacenter' -SupportedOs $seCfg.SupportedDomainControllerOs) 'SE OS: 2012 R2 supported'
Assert-Equal '' (Test-AdfaOsSupported -OperatingSystem 'Windows Server 2012 Standard' -SupportedOs $seCfg.SupportedDomainControllerOs) 'SE OS: plain 2012 NOT supported (not confused with 2012 R2)'
Assert-Equal '' (Test-AdfaOsSupported -OperatingSystem 'Windows Server 2008 R2 Enterprise' -SupportedOs $seCfg.SupportedDomainControllerOs) 'SE OS: 2008 R2 NOT supported'
Assert-Equal '' (Test-AdfaOsSupported -OperatingSystem '' -SupportedOs $seCfg.SupportedDomainControllerOs) 'SE OS: empty string is not supported'
Assert-Equal '' (Test-AdfaOsSupported -OperatingSystem 'Windows Server 2019' -SupportedOs @()) 'SE OS: an empty table supports nothing (never vacuously true)'

# --- Verdict: forest functional level
$dcOk = @([pscustomobject]@{ HostName = 'dc1.contoso.com'; OperatingSystem = 'Windows Server 2019 Datacenter'; IsReadOnly = $false })
function Get-SeRow {
    # Returns $null rather than indexing [0] into an empty array, which throws under StrictMode.
    param($Rows, [string]$Item)
    $m = @($Rows | Where-Object { [string]$_.Item -eq $Item })
    if ($m.Count -eq 0) { return $null }
    return $m[0]
}

$rFfl = Get-AdfaExchangeSeCompatibility -ForestMode 'Windows2016Forest' -DomainSummaries @() -DomainControllers $dcOk -SeConfig $seCfg
Assert-Equal 'Pass' ([string](Get-SeRow $rFfl 'Forest functional level').Status) 'SE FFL: Windows2016Forest => Pass'
$rFfl2 = Get-AdfaExchangeSeCompatibility -ForestMode 'Windows2012R2Forest' -DomainSummaries @() -DomainControllers $dcOk -SeConfig $seCfg
Assert-Equal 'Pass' ([string](Get-SeRow $rFfl2 'Forest functional level').Status) 'SE FFL: Windows2012R2Forest => Pass'
$rFflBad = Get-AdfaExchangeSeCompatibility -ForestMode 'Windows2008R2Forest' -DomainSummaries @() -DomainControllers $dcOk -SeConfig $seCfg
Assert-Equal 'Fail' ([string](Get-SeRow $rFflBad 'Forest functional level').Status) 'SE FFL: Windows2008R2Forest => Fail'
Assert-True ((Get-SeRow $rFflBad 'Forest functional level').Detail -match 'Windows2016Forest') 'SE FFL: the failure names what IS supported'
$rFflNone = Get-AdfaExchangeSeCompatibility -ForestMode '' -DomainSummaries @() -DomainControllers $dcOk -SeConfig $seCfg
Assert-Equal 'Not Assessed' ([string](Get-SeRow $rFflNone 'Forest functional level').Status) 'SE FFL: unreadable => Not Assessed, never Pass'

# --- Verdict: DC operating systems. One bad DC anywhere in the forest is a blocker.
$dcMixed = @(
    [pscustomobject]@{ HostName = 'dc1.contoso.com'; OperatingSystem = 'Windows Server 2019 Datacenter'; IsReadOnly = $false },
    [pscustomobject]@{ HostName = 'dc2.contoso.com'; OperatingSystem = 'Windows Server 2012 Standard';   IsReadOnly = $false }
)
$rOs = Get-AdfaExchangeSeCompatibility -ForestMode 'Windows2016Forest' -DomainSummaries @() -DomainControllers $dcMixed -SeConfig $seCfg
$osRow = Get-SeRow $rOs 'Domain controller operating systems'
Assert-Equal 'Fail' ([string]$osRow.Status) 'SE DC OS: one unsupported DC => Fail for the forest'
Assert-True ($osRow.Detail -match 'dc2\.contoso\.com') 'SE DC OS: the failure names the offending DC'
Assert-True ($osRow.Detail -notmatch 'dc1\.contoso\.com') 'SE DC OS: a compliant DC is not named as a problem'

# An unreadable OS is an absent measurement, NOT an unsupported one - they are different claims.
$dcUnknown = @(
    [pscustomobject]@{ HostName = 'dc1.contoso.com'; OperatingSystem = 'Windows Server 2019'; IsReadOnly = $false },
    [pscustomobject]@{ HostName = 'dc2.contoso.com'; OperatingSystem = 'Not Assessed';        IsReadOnly = $false }
)
$rUnk = Get-AdfaExchangeSeCompatibility -ForestMode 'Windows2016Forest' -DomainSummaries @() -DomainControllers $dcUnknown -SeConfig $seCfg
Assert-Equal 'Pass' ([string](Get-SeRow $rUnk 'Domain controller operating systems').Status) 'SE DC OS: a readable DC still passes on its own merits'
$unkRow = Get-SeRow $rUnk 'Domain controller OS - not readable'
Assert-True ($null -ne $unkRow) 'SE DC OS: an unreadable OS gets its own row, so a partial pass cannot hide it'
# Guarded: if the row is missing the assertion above has already failed, and dereferencing
# $null here would abort the whole harness instead of reporting a clean FAIL.
if ($null -ne $unkRow) {
    Assert-Equal 'Not Assessed' ([string]$unkRow.Status) 'SE DC OS: unreadable => Not Assessed, not Fail'
    Assert-True ($unkRow.Detail -match 'unverified, not compatible') 'SE DC OS: unreadable row refuses to imply compatibility'
}

$rAllUnk = Get-AdfaExchangeSeCompatibility -ForestMode 'Windows2016Forest' -DomainSummaries @() `
    -DomainControllers @([pscustomobject]@{ HostName = 'dc1'; OperatingSystem = 'Not Assessed'; IsReadOnly = $false }) -SeConfig $seCfg
Assert-Equal 'Not Assessed' ([string](Get-SeRow $rAllUnk 'Domain controller operating systems').Status) 'SE DC OS: nothing readable => Not Assessed, never Pass'

$rNoDc = Get-AdfaExchangeSeCompatibility -ForestMode 'Windows2016Forest' -DomainSummaries @() -DomainControllers @() -SeConfig $seCfg
Assert-Equal 'Not Assessed' ([string](Get-SeRow $rNoDc 'Domain controller operating systems').Status) 'SE DC OS: no DCs enumerated => Not Assessed'

# --- RODC caveat
$dcRodc = @(
    [pscustomobject]@{ HostName = 'dc1.contoso.com'; OperatingSystem = 'Windows Server 2019'; IsReadOnly = $false },
    [pscustomobject]@{ HostName = 'rodc1.contoso.com'; OperatingSystem = 'Windows Server 2019'; IsReadOnly = $true }
)
$rRodc = Get-AdfaExchangeSeCompatibility -ForestMode 'Windows2016Forest' -DomainSummaries @() -DomainControllers $dcRodc -SeConfig $seCfg
$rodcRow = Get-SeRow $rRodc 'Read-only domain controllers'
Assert-True ($null -ne $rodcRow) 'SE RODC: a read-only DC is reported'
if ($null -ne $rodcRow) {
    Assert-Equal 'Warning' ([string]$rodcRow.Status) 'SE RODC: reported as a Warning, not a false blocker'
    Assert-True ($rodcRow.Detail -match 'rodc1\.contoso\.com') 'SE RODC: names the read-only DC'
}
# Non-vacuity for the "no row" assertions below: prove the lookup can actually return nothing,
# so an absent row is evidence rather than an artefact of how it is queried.
Assert-True ($null -eq (Get-SeRow $rRodc 'No Such Item Exists')) 'SE RODC: non-vacuity - the row lookup returns null for an absent item'
$rNoRodc = Get-AdfaExchangeSeCompatibility -ForestMode 'Windows2016Forest' -DomainSummaries @() -DomainControllers $dcOk -SeConfig $seCfg
Assert-True ($null -eq (Get-SeRow $rNoRodc 'Read-only domain controllers')) 'SE RODC: no row when there are no read-only DCs'

# --- Scope statement: the section must not be mistaken for full SE readiness.
$scopeRow = Get-SeRow $rFfl 'Scope of this check'
Assert-True ($null -ne $scopeRow) 'SE scope: the section states its own limits'
if ($null -ne $scopeRow) {
    Assert-True ($scopeRow.Detail -match 'does NOT cover') 'SE scope: names what it does not cover'
}

# --- Config override merge
$merged = Merge-AdfaExchangeSeConfig -BaseConfig $seCfg -Override @{ SupportedForestModes = @('Windows2025Forest') } -OverrideSource 'C:\cfg\se.json'
Assert-Equal 1 (@($merged.SupportedForestModes).Count) 'SE config: override replaces the forest mode list'
Assert-Equal 5 (@($merged.SupportedDomainControllerOs).Count) 'SE config: keys absent from the override keep their built-in value'
Assert-Equal 'C:\cfg\se.json' ([string]$merged.SourceUrl) 'SE config: provenance rewritten so findings do not cite Learn for overridden values'
$unmerged = Merge-AdfaExchangeSeConfig -BaseConfig $seCfg -Override $null
Assert-Equal 2 (@($unmerged.SupportedForestModes).Count) 'SE config: a null override changes nothing'

# An override must not be able to empty a gate.
$emptied = $false
try { Merge-AdfaExchangeSeConfig -BaseConfig $seCfg -Override @{ SupportedForestModes = @() } | Out-Null }
catch { $emptied = $true }
Assert-True $emptied 'SE config: an empty forest-mode list is rejected, not honoured'
$emptiedOs = $false
try { Merge-AdfaExchangeSeConfig -BaseConfig $seCfg -Override @{ SupportedDomainControllerOs = @() } | Out-Null }
catch { $emptiedOs = $true }
Assert-True $emptiedOs 'SE config: an empty OS list is rejected, not honoured'

# The override must actually change the verdict, or it is decoration.
$strict = Merge-AdfaExchangeSeConfig -BaseConfig $seCfg -Override @{ SupportedForestModes = @('Windows2016Forest') }
$rStrict = Get-AdfaExchangeSeCompatibility -ForestMode 'Windows2012R2Forest' -DomainSummaries @() -DomainControllers $dcOk -SeConfig $strict
Assert-Equal 'Fail' ([string](Get-SeRow $rStrict 'Forest functional level').Status) 'SE config: a narrowed override really does change the verdict'

# Remediation must reach the SE findings and must be SE-specific, not generic replication advice.
$fflRec = Get-AdfaRecommendation -Section 'Exchange SE Compatibility' -Item 'Forest functional level' `
    -Detail 'Windows2008R2Forest is NOT supported for Exchange Server SE.'
Assert-True ($fflRec -match 'Set-ADForestMode') 'SE remediation: forest level fix names the cmdlet'
Assert-True ($fflRec -match 'one-way|cannot be reverted') 'SE remediation: warns the change is irreversible'
$osRec = Get-AdfaRecommendation -Section 'Exchange SE Compatibility' -Item 'Domain controller operating systems' `
    -Detail '1 of 2 DC(s) run an OS not supported for Exchange Server SE: dc2 (Windows Server 2012 Standard).'
Assert-True ($osRec -match 'Every domain controller in the forest') 'SE remediation: OS fix states the forest-wide scope'
Assert-True ($osRec -notmatch 'nltest /dsregdns') 'SE remediation: not hijacked by the DNS guidance'
$rodcRec = Get-AdfaRecommendation -Section 'Exchange SE Compatibility' -Item 'Read-only domain controllers' `
    -Detail '1 read-only DC(s): rodc1.contoso.com.'
Assert-True ($rodcRec -match 'writeable global catalog') 'SE remediation: RODC advice names the real constraint'

Write-Host ""
Write-Host "== 16. SYSVOL / DFSR depth (shares, subscription state, log coverage) ==" -ForegroundColor Cyan

# --- Share presence. The distinction that matters: "not shared" vs "could not look".
Assert-Equal 'Shared'          (Get-AdfaSysvolShareOutcome -SmbReachable $true  -SysvolPresent $true  -NetlogonPresent $true)  'Shares: both present => Shared'
Assert-Equal 'MissingBoth'     (Get-AdfaSysvolShareOutcome -SmbReachable $true  -SysvolPresent $false -NetlogonPresent $false) 'Shares: neither present => MissingBoth'
Assert-Equal 'MissingSysvol'   (Get-AdfaSysvolShareOutcome -SmbReachable $true  -SysvolPresent $false -NetlogonPresent $true)  'Shares: SYSVOL absent => MissingSysvol'
Assert-Equal 'MissingNetlogon' (Get-AdfaSysvolShareOutcome -SmbReachable $true  -SysvolPresent $true  -NetlogonPresent $false) 'Shares: NETLOGON absent => MissingNetlogon'
Assert-Equal 'Unknown'         (Get-AdfaSysvolShareOutcome -SmbReachable $false -SysvolPresent $null  -NetlogonPresent $null)  'Shares: SMB unreachable => Unknown, never a missing share'
Assert-Equal 'Unknown'         (Get-AdfaSysvolShareOutcome -SmbReachable $true  -SysvolPresent $null  -NetlogonPresent $true)  'Shares: unprobed SYSVOL => Unknown, not Shared'
# An unreachable DC must never be reported as healthy just because nothing was measured.
Assert-Equal 'Unknown'         (Get-AdfaSysvolShareOutcome -SmbReachable $false -SysvolPresent $true  -NetlogonPresent $true)  'Shares: unreachable wins over stale true values'

# --- DFSR subscription state (KB 2218556). The cross-DC rule is the point of this verdict.
function Get-SvRow {
    param($Rows, [string]$Item)
    $m = @($Rows | Where-Object { [string]$_.Item -eq $Item })
    if ($m.Count -eq 0) { return $null }
    return $m[0]
}
$subsHealthy = @(
    [pscustomobject]@{ DcName = 'dc1.contoso.com'; Enabled = $true; Options = $null },
    [pscustomobject]@{ DcName = 'dc2.contoso.com'; Enabled = $true; Options = $null }
)
$vH = Get-AdfaDfsrSubscriptionVerdict -DomainName 'contoso.com' -Subscriptions $subsHealthy
Assert-Equal 'Pass' ([string](Get-SvRow $vH 'DFSR SYSVOL replication enabled').Status) 'Subscription: all enabled, none authoritative => Pass'
Assert-True ($null -eq (Get-SvRow $vH 'Authoritative SYSVOL member set')) 'Subscription: no authoritative row when msDFSR-options is unset'
Assert-True ($null -eq (Get-SvRow $vH 'No Such Item')) 'Subscription: non-vacuity - the lookup returns null for an absent item'

# msDFSR-Enabled=FALSE is only ever set by hand, so it means a rebuild was started.
$subsDisabled = @(
    [pscustomobject]@{ DcName = 'dc1.contoso.com'; Enabled = $true;  Options = $null },
    [pscustomobject]@{ DcName = 'dc2.contoso.com'; Enabled = $false; Options = $null }
)
$vD = Get-AdfaDfsrSubscriptionVerdict -DomainName 'contoso.com' -Subscriptions $subsDisabled
$dRow = Get-SvRow $vD 'DFSR SYSVOL replication disabled'
Assert-True ($null -ne $dRow) 'Subscription: a disabled DC is reported'
if ($null -ne $dRow) {
    Assert-Equal 'Fail' ([string]$dRow.Status) 'Subscription: msDFSR-Enabled=FALSE => Fail'
    Assert-True ($dRow.Detail -match 'dc2\.contoso\.com') 'Subscription: the disabled DC is named'
    Assert-True ($dRow.Detail -notmatch 'dc1\.contoso\.com') 'Subscription: a healthy DC is not named as disabled'
}

# Exactly one authoritative member is the documented procedure; two is a conflict no single
# DC could reveal, which is why this verdict is computed across the whole domain.
$subsOneAuth = @(
    [pscustomobject]@{ DcName = 'dc1.contoso.com'; Enabled = $true; Options = 1 },
    [pscustomobject]@{ DcName = 'dc2.contoso.com'; Enabled = $true; Options = 0 }
)
$v1 = Get-AdfaDfsrSubscriptionVerdict -DomainName 'contoso.com' -Subscriptions $subsOneAuth
Assert-Equal 'Warning' ([string](Get-SvRow $v1 'Authoritative SYSVOL member set').Status) 'Subscription: one authoritative member => Warning, not Fail'
Assert-True ((Get-SvRow $v1 'Authoritative SYSVOL member set').Detail -match 'dc1\.contoso\.com') 'Subscription: the authoritative DC is named'

$subsTwoAuth = @(
    [pscustomobject]@{ DcName = 'dc1.contoso.com'; Enabled = $true; Options = 1 },
    [pscustomobject]@{ DcName = 'dc2.contoso.com'; Enabled = $true; Options = 1 }
)
$v2 = Get-AdfaDfsrSubscriptionVerdict -DomainName 'contoso.com' -Subscriptions $subsTwoAuth
$cRow = Get-SvRow $v2 'Conflicting authoritative SYSVOL members'
Assert-True ($null -ne $cRow) 'Subscription: two authoritative members are reported'
if ($null -ne $cRow) {
    Assert-Equal 'Fail' ([string]$cRow.Status) 'Subscription: more than one authoritative member => Fail'
    Assert-True ($cRow.Detail -match 'dc1' -and $cRow.Detail -match 'dc2') 'Subscription: both conflicting DCs are named'
}
Assert-True ($null -eq (Get-SvRow $v2 'Authoritative SYSVOL member set')) 'Subscription: the conflict replaces the single-member row rather than both appearing'

# An unreadable subscription object is unverified, never healthy.
$subsUnknown = @([pscustomobject]@{ DcName = 'dc1.contoso.com'; Enabled = $null; Options = $null })
$vU = Get-AdfaDfsrSubscriptionVerdict -DomainName 'contoso.com' -Subscriptions $subsUnknown
Assert-Equal 'Not Assessed' ([string](Get-SvRow $vU 'DFSR SYSVOL subscription - not readable').Status) 'Subscription: unreadable => Not Assessed'
Assert-Equal 'Not Assessed' ([string](Get-SvRow (Get-AdfaDfsrSubscriptionVerdict -DomainName 'contoso.com' -Subscriptions @()) 'DFSR SYSVOL subscription state').Status) 'Subscription: nothing read at all => Not Assessed'

# --- The coverage guard is now log-agnostic and must name the log it is talking about.
$dfsrTrunc = Get-AdfaEventCoverageDetail -Coverage 'Truncated' -OldestRecord ([datetime]'2026-09-15 08:30') -LookbackDays 14 -LogName 'DFS Replication'
Assert-True ($dfsrTrunc -match 'DFS Replication log only goes back') 'Coverage detail: names the DFS Replication log'
Assert-True ($dfsrTrunc -match '2026-09-15 08:30') 'Coverage detail: still names where coverage begins'
Assert-True ((Get-AdfaEventCoverageDetail -Coverage 'Empty' -OldestRecord $null -LookbackDays 14) -match 'Directory Service log holds no records') 'Coverage detail: defaults to the Directory Service log'

# Remediation must be specific to each SYSVOL failure, not "perform a D4" for all of them -
# the vendor's guidance is that reinitialising is a last resort that can lose data.
$shareRec = Get-AdfaRecommendation -Section 'SYSVOL / DFSR' -Item 'Shares on dc1.contoso.com' `
    -Detail 'Neither SYSVOL nor NETLOGON is shared. Group Policy and logon scripts are not being served by this DC.'
Assert-True ($shareRec -match 'Do NOT jump to a D4') 'SYSVOL remediation: missing shares steers away from a blind rebuild'
Assert-True ($shareRec -match '2213' -and $shareRec -match '4012') 'SYSVOL remediation: missing shares names the events to read first'

$disRec = Get-AdfaRecommendation -Section 'SYSVOL / DFSR' -Item 'DFSR SYSVOL replication disabled' `
    -Detail 'msDFSR-Enabled=FALSE on 1 of 2 DC(s): dc2.contoso.com.'
Assert-True ($disRec -match 'dfsrdiag pollad') 'SYSVOL remediation: disabled membership names the completion step'
Assert-True ($disRec -match '4604') 'SYSVOL remediation: disabled membership names the event that proves success'

$confRec = Get-AdfaRecommendation -Section 'SYSVOL / DFSR' -Item 'Conflicting authoritative SYSVOL members' `
    -Detail 'msDFSR-options=1 on 2 DCs: dc1.contoso.com, dc2.contoso.com.'
Assert-True ($confRec -match 'Only ONE member may be authoritative') 'SYSVOL remediation: the conflict gets conflict-specific advice'

$freshRec = Get-AdfaRecommendation -Section 'DFS Replication Events' -Item 'Event 4012 on dc1.contoso.com' `
    -Detail '1 occurrence(s). Content freshness protection stopped replication - the folder has not replicated for longer than MaxOfflineTimeInDays.'
Assert-True ($freshRec -match 'MaxOfflineTimeInDays') 'SYSVOL remediation: content freshness gets its own guidance'
Assert-True ($freshRec -match 'EVERY DC has logged 4012') 'SYSVOL remediation: names the one case where authoritative is correct'

$dirtyRec = Get-AdfaRecommendation -Section 'DFS Replication Events' -Item 'Event 2213 on dc1.contoso.com' `
    -Detail '1 occurrence(s). Dirty shutdown detected - DFSR replication is PAUSED on this volume.'
Assert-True ($dirtyRec -match 'ResumeReplication') 'SYSVOL remediation: a dirty shutdown routes to ResumeReplication, not a rebuild'
Assert-True ($dirtyRec -notmatch 'Do NOT jump') 'SYSVOL remediation: entries do not bleed into each other'

Write-Host ""
Write-Host "== 17. SYSVOL backlog (the 100-record cap is the trap) ==" -ForegroundColor Cyan

# Get-DfsrBacklog returns at most 100 records and the true total is only in its verbose stream,
# so counting objects reports a FLOOR as a total once the backlog reaches the cap. The vendor's
# documented message format is:
#   The replicated folder has a backlog of files. Replicated folder: "RF01". Count: 2400
$vmsg = 'The replicated folder has a backlog of files. Replicated folder: "SYSVOL Share". Count: 2400'
$r1 = Get-AdfaDfsrBacklogCount -VerboseMessage $vmsg -ObjectCount 100 -DisplayCap 100
Assert-Equal 2400 ([int]$r1.Count) 'Backlog: the verbose count beats the capped object count'
Assert-True ([bool]$r1.Exact) 'Backlog: a verbose count is exact'
Assert-Equal 'Verbose' ([string]$r1.Source) 'Backlog: source recorded as Verbose'

# Without a verbose count, an at-cap result is a floor and must say so.
$r2 = Get-AdfaDfsrBacklogCount -VerboseMessage '' -ObjectCount 100 -DisplayCap 100
Assert-Equal 100 ([int]$r2.Count) 'Backlog: at the cap, the count is the cap'
Assert-True (-not [bool]$r2.Exact) 'Backlog: at the cap WITHOUT a verbose count, the figure is NOT exact'

# Below the cap the object count is the real answer.
$r3 = Get-AdfaDfsrBacklogCount -VerboseMessage '' -ObjectCount 7 -DisplayCap 100
Assert-Equal 7 ([int]$r3.Count) 'Backlog: below the cap the object count is used'
Assert-True ([bool]$r3.Exact) 'Backlog: below the cap the figure is exact'
Assert-Equal 0 ([int](Get-AdfaDfsrBacklogCount -VerboseMessage '' -ObjectCount 0 -DisplayCap 100).Count) 'Backlog: no objects and no verbose => 0'

# A failed call is unmeasured, not zero - the distinction the whole tool turns on.
$r4 = Get-AdfaDfsrBacklogCount -VerboseMessage '' -ObjectCount 0 -DisplayCap 100 -Succeeded $false
Assert-Equal (-1) ([int]$r4.Count) 'Backlog: a failed call is -1 (unmeasured), never 0'

# The parser must not read any trailing number as a backlog size.
Assert-Equal 3 ([int](Get-AdfaDfsrBacklogCount -VerboseMessage 'Connected to partner over port 135. Count: 99' -ObjectCount 3 -DisplayCap 100).Count) 'Backlog: an unrelated verbose line is not mistaken for a count'

# --- Verdicts
Assert-Equal 'Pass' ([string](Get-AdfaSysvolBacklogVerdict -SourceDc 'dc1' -DestinationDc 'dc2' -Count 0 -Exact $true -WarnAt 1 -FailAt 100).Status) 'Backlog verdict: zero => Pass'
Assert-Equal 'Warning' ([string](Get-AdfaSysvolBacklogVerdict -SourceDc 'dc1' -DestinationDc 'dc2' -Count 5 -Exact $true -WarnAt 1 -FailAt 100).Status) 'Backlog verdict: a small standing backlog => Warning'
Assert-Equal 'Fail' ([string](Get-AdfaSysvolBacklogVerdict -SourceDc 'dc1' -DestinationDc 'dc2' -Count 100 -Exact $false -WarnAt 1 -FailAt 100).Status) 'Backlog verdict: at or above FailAt => Fail'
Assert-Equal 'Not Assessed' ([string](Get-AdfaSysvolBacklogVerdict -SourceDc 'dc1' -DestinationDc 'dc2' -Count (-1) -Exact $true -Reason 'RPC failed').Status) 'Backlog verdict: unmeasured => Not Assessed, never Pass'

# An inexact figure must never be presented as a total.
$floorDetail = (Get-AdfaSysvolBacklogVerdict -SourceDc 'dc1' -DestinationDc 'dc2' -Count 100 -Exact $false -WarnAt 1 -FailAt 100).Detail
Assert-True ($floorDetail -match 'at least 100') 'Backlog verdict: a floor is reported as "at least"'
Assert-True ($floorDetail -match 'floor, not a total') 'Backlog verdict: the caveat names the cap explicitly'
$exactDetail = (Get-AdfaSysvolBacklogVerdict -SourceDc 'dc1' -DestinationDc 'dc2' -Count 100 -Exact $true -WarnAt 1 -FailAt 100).Detail
Assert-True ($exactDetail -notmatch 'at least') 'Backlog verdict: an exact figure carries no floor caveat'
Assert-True ($exactDetail -notmatch 'floor, not a total') 'Backlog verdict: non-vacuity - the caveat really is conditional'
# The finding must not overstate the vendor position.
Assert-True ($exactDetail -match 'indicates latency rather than a fault') 'Backlog verdict: states that a backlog alone is latency, not a fault'
Assert-True ((Get-AdfaSysvolBacklogVerdict -SourceDc 'dcA' -DestinationDc 'dcB' -Count 5 -Exact $true).Detail -match 'dcA -> dcB') 'Backlog verdict: the direction is named'

Write-Host ""
Write-Host "== 18. Restore integrity (USN rollback forensics, database instantiation) ==" -ForegroundColor Cyan

# The registry marker is the only restore-integrity signal that survives the event log being
# cleared, which Microsoft names explicitly as the fallback when event 2095 has been overwritten.
Assert-Equal 'Rollback'   (Get-AdfaUsnRollbackVerdict -Readable $true  -Present $true  -Value 4)     'Rollback: "Dsa Not Writable"=4 => Rollback'
Assert-Equal 'Rollback'   (Get-AdfaUsnRollbackVerdict -Readable $true  -Present $true  -Value '4')   'Rollback: the documented value matches as a string too'
Assert-Equal 'OtherValue' (Get-AdfaUsnRollbackVerdict -Readable $true  -Present $true  -Value 1)     'Rollback: an undocumented value is reported as found, not interpreted'
Assert-Equal 'NoEvidence' (Get-AdfaUsnRollbackVerdict -Readable $true  -Present $false -Value $null) 'Rollback: absent marker => NoEvidence'
Assert-Equal 'Unknown'    (Get-AdfaUsnRollbackVerdict -Readable $false -Present $null  -Value $null) 'Rollback: unreadable registry => Unknown'
Assert-Equal 'Unknown'    (Get-AdfaUsnRollbackVerdict -Readable $true  -Present $null  -Value $null) 'Rollback: readable but presence unknown => Unknown, never NoEvidence'
# Fail-closed: an unreachable DC must never be reported as having no evidence of a rollback.
$rbDegraded = @(
    (Get-AdfaUsnRollbackVerdict -Readable $false -Present $true  -Value 4),
    (Get-AdfaUsnRollbackVerdict -Readable $false -Present $false -Value $null),
    (Get-AdfaUsnRollbackVerdict -Readable $true  -Present $null  -Value 4)
)
Assert-Equal 3 (@($rbDegraded).Count) 'Rollback: non-vacuity - three degraded inputs evaluated'
Assert-Equal 0 (@($rbDegraded | Where-Object { $_ -eq 'NoEvidence' }).Count) 'Rollback: no degraded input is ever reported as NoEvidence'

# The wording has to carry the quarantine consequence and the do-not-touch warning.
$rbDetail = Get-AdfaUsnRollbackDetail -Verdict 'Rollback' -Value 4
Assert-True ($rbDetail -match 'USN ROLLBACK') 'Rollback detail: names the condition'
Assert-True ($rbDetail -match 'Net Logon is paused') 'Rollback detail: states the quarantine effect'
Assert-True ($rbDetail -match 'Do NOT delete or edit') 'Rollback detail: warns against clearing the marker'
Assert-True ($rbDetail -match 'overwritten') 'Rollback detail: explains why this beats the event log'
# Absence must be honest about what it does not prove.
$rbNone = Get-AdfaUsnRollbackDetail -Verdict 'NoEvidence' -Value $null
Assert-True ($rbNone -match 'operating-system installation only') 'Rollback detail: absence states its own limit'
Assert-True ($rbNone -notmatch 'healthy') 'Rollback detail: absence does not claim health'
Assert-True ((Get-AdfaUsnRollbackDetail -Verdict 'Unknown' -Value $null -Reason 'Access is denied') -match 'Access is denied') 'Rollback detail: unknown carries the cause'
Assert-True ((Get-AdfaUsnRollbackDetail -Verdict 'OtherValue' -Value 9) -match '9') 'Rollback detail: an undocumented value is quoted back'

# --- invocationId: exactly one conclusion is safe from a single read - a cloned database.
function Get-RiRow {
    param($Rows, [string]$Item)
    $m = @($Rows | Where-Object { [string]$_.Item -eq $Item })
    if ($m.Count -eq 0) { return $null }
    return $m[0]
}
$invDistinct = @(
    [pscustomobject]@{ DnsHostName = 'dc1.contoso.com'; ServerDn = 'CN=DC1'; InvocationId = '11111111-1111-1111-1111-111111111111' },
    [pscustomobject]@{ DnsHostName = 'dc2.contoso.com'; ServerDn = 'CN=DC2'; InvocationId = '22222222-2222-2222-2222-222222222222' }
)
$vD = Get-AdfaInvocationIdVerdict -DsaInventory $invDistinct
Assert-Equal 'Pass' ([string](Get-RiRow $vD 'Database instantiation (invocationId)').Status) 'invocationId: distinct values => Pass'
Assert-True ((Get-RiRow $vD 'Database instantiation (invocationId)').Detail -match 'cannot detect a rollback on its own') 'invocationId: the pass states what it cannot conclude'
Assert-True ($null -ne (Get-RiRow $vD 'invocationId of dc1.contoso.com')) 'invocationId: per-DC baseline is emitted for later comparison'
Assert-True ($null -eq (Get-RiRow $vD 'No Such Item')) 'invocationId: non-vacuity - the lookup returns null for an absent item'

$invCloned = @(
    [pscustomobject]@{ DnsHostName = 'dc1.contoso.com'; ServerDn = 'CN=DC1'; InvocationId = '11111111-1111-1111-1111-111111111111' },
    [pscustomobject]@{ DnsHostName = 'dc2.contoso.com'; ServerDn = 'CN=DC2'; InvocationId = '11111111-1111-1111-1111-111111111111' }
)
$vC = Get-AdfaInvocationIdVerdict -DsaInventory $invCloned
$cRow = Get-RiRow $vC 'Duplicate database instantiation (invocationId)'
Assert-True ($null -ne $cRow) 'invocationId: a shared value is reported'
if ($null -ne $cRow) {
    Assert-Equal 'Fail' ([string]$cRow.Status) 'invocationId: a cloned database => Fail'
    Assert-True ($cRow.Detail -match 'dc1' -and $cRow.Detail -match 'dc2') 'invocationId: both DCs are named'
    Assert-True ($cRow.Detail -match 'CLONED') 'invocationId: names what a shared value means'
}
Assert-True ($null -eq (Get-RiRow $vC 'Database instantiation (invocationId)')) 'invocationId: the clone finding replaces the clean row'

# A DSA with no readable invocationId is excluded and said to be excluded.
$invPartial = @(
    [pscustomobject]@{ DnsHostName = 'dc1.contoso.com'; ServerDn = 'CN=DC1'; InvocationId = '11111111-1111-1111-1111-111111111111' },
    [pscustomobject]@{ DnsHostName = 'dc2.contoso.com'; ServerDn = 'CN=DC2'; InvocationId = '' }
)
$vP = Get-AdfaInvocationIdVerdict -DsaInventory $invPartial
$pRow = Get-RiRow $vP 'invocationId - not readable'
Assert-True ($null -ne $pRow) 'invocationId: an unreadable value gets its own row'
if ($null -ne $pRow) {
    Assert-Equal 'Not Assessed' ([string]$pRow.Status) 'invocationId: unreadable => Not Assessed'
    Assert-True ($pRow.Detail -match 'partial result, not a clean one') 'invocationId: says the clone check is partial'
}
Assert-Equal 'Not Assessed' ([string](Get-RiRow (Get-AdfaInvocationIdVerdict -DsaInventory @()) 'Database instantiation (invocationId)').Status) 'invocationId: nothing read => Not Assessed'

# --- The two post-restore dcdiag tests must actually be in the grid.
$dcdiagSrc = Get-Content (Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) 'src/ADForestAssessment/Invoke-ADForestAssessment.ps1') -Raw
Assert-True ($dcdiagSrc -match "'CheckSecurityError'") 'dcdiag: CheckSecurityError added to the grid'
Assert-True ($dcdiagSrc -match "'VerifyEnterpriseReferences'") 'dcdiag: VerifyEnterpriseReferences added to the grid'

# --- The VM-revert events must be in the Directory Service table with vendor meanings.
$dsIds = @($script:Config.DsEventsOfInterest | ForEach-Object { [int]$_.Id })
Assert-True ($dsIds -contains 2170) 'DS events: 2170 (VM Generation ID change) present'
Assert-True ($dsIds -contains 2181) 'DS events: 2181 (VM reverted) present'
$e2170 = @($script:Config.DsEventsOfInterest | Where-Object { [int]$_.Id -eq 2170 })[0]
Assert-True ($e2170.Meaning -match 'snapshot') 'DS events: 2170 meaning names the snapshot cause'
Assert-True ($e2170.Meaning -match 'not a supported procedure') 'DS events: 2170 says a snapshot restore is unsupported'

# Remediation for the new findings, and a correctness fix to an existing one.
$dnwRec = Get-AdfaRecommendation -Section 'Restore Integrity' -Item 'USN rollback marker on dc1.contoso.com' `
    -Detail (Get-AdfaUsnRollbackDetail -Verdict 'Rollback' -Value 4)
Assert-True ($dnwRec -match 'Do NOT delete or change') 'Restore remediation: leads with not touching the marker'
Assert-True ($dnwRec -match 'Uninstall-ADDSDomainController') 'Restore remediation: uses the current demotion cmdlet'
Assert-True ($dnwRec -match 'metadata cleanup') 'Restore remediation: names metadata cleanup'
Assert-True ($dnwRec -match 'loses every change') 'Restore remediation: warns forced demotion loses unreplicated changes'

# The old text recommended dcpromo /forceremoval, which is Windows 2000 / Server 2003 era - not
# valid on any OS this tool supports. It must be gone from every entry, not just the new one.
# Asserted against the recommendation TEXT, not the whole file: a comment recording why the
# advice changed is worth keeping, and banning the word everywhere would forbid that.
$adviceWithDcpromo = @($script:RecommendationMap | Where-Object { [string]$_.Text -match 'dcpromo\s*/forceremoval' })
Assert-Equal 0 (@($adviceWithDcpromo).Count) 'Restore remediation: no recommendation advises the retired dcpromo command'
# Non-vacuity: the map really is inspectable this way and really does contain advice.
Assert-True (@($script:RecommendationMap).Count -gt 10) ("Restore remediation: non-vacuity - {0} recommendation entries were inspected" -f @($script:RecommendationMap).Count)
Assert-True (@($script:RecommendationMap | Where-Object { [string]$_.Text -match 'Uninstall-ADDSDomainController' }).Count -ge 2) 'Restore remediation: the current cmdlet is what the map now advises'
$usnRec = Get-AdfaRecommendation -Section 'Directory Service Events' -Item 'Event 2095 on dc1' `
    -Detail 'USN rollback detected - the directory is silently diverging.'
Assert-True ($usnRec -match 'Uninstall-ADDSDomainController') 'Restore remediation: the 2095 entry uses the current cmdlet too'

$cloneRec = Get-AdfaRecommendation -Section 'Restore Integrity' -Item 'Duplicate database instantiation (invocationId)' `
    -Detail '2 DCs share invocationId 1111: dc1, dc2. ... database was CLONED from the other'
Assert-True ($cloneRec -match 'Do not leave both in service') 'Restore remediation: a clone gets clone-specific advice'
Assert-True ($cloneRec -notmatch 'Dsa Not Writable') 'Restore remediation: entries do not bleed into each other'

$genRec = Get-AdfaRecommendation -Section 'Directory Service Events' -Item 'Event 2170 on dc1' `
    -Detail 'VM Generation ID change detected - a snapshot, import or live migration was applied to this DC.'
Assert-True ($genRec -match 'RID pool') 'Restore remediation: 2170 names what AD reset for you'
Assert-True ($genRec -match 'not supported') 'Restore remediation: 2170 still says snapshots are not a restore method'

Write-Host ""
Write-Host "== 19. Replication convergence (/replsummary parse, silent-stall lag) ==" -ForegroundColor Cyan

# --- Delta token parsing. An unreadable delta must be $null, never 0: "(unknown)" means the DSA
# has NO successful replication to measure from, which is worse than a large number.
Assert-Equal 242  (ConvertFrom-AdfaRepadminDelta -Delta '04h:02m:16s') 'Delta: h:m:s parsed to minutes'
Assert-Equal 15   (ConvertFrom-AdfaRepadminDelta -Delta '15m:30s')     'Delta: m:s parsed to minutes'
Assert-Equal 4562 (ConvertFrom-AdfaRepadminDelta -Delta '3d.04h:02m:16s') 'Delta: days included'
Assert-Equal 86400 (ConvertFrom-AdfaRepadminDelta -Delta '>60 days')   'Delta: ">60 days" handled'
Assert-True ($null -eq (ConvertFrom-AdfaRepadminDelta -Delta '(unknown)')) 'Delta: (unknown) => null, never 0'
Assert-True ($null -eq (ConvertFrom-AdfaRepadminDelta -Delta ''))          'Delta: empty => null'
Assert-True ($null -eq (ConvertFrom-AdfaRepadminDelta -Delta 'garbage'))   'Delta: unparseable => null, never 0'
Assert-Equal 0 (ConvertFrom-AdfaRepadminDelta -Delta '45s') 'Delta: sub-minute parses to 0 rather than null'

# --- /replsummary parse against the documented layout.
$replsum = @"
Replication Summary Start Time: 2026-09-22 00:00:00

Beginning data collection for replication summary, this may take a while:
  .....

Source DSA          largest delta    fails/total %%   error
 DC1                      15m:30s     0 /  10    0
 DC2                    (unknown)     5 /   5  100  (8524) The DSA operation is unable to proceed because of a DNS lookup failure.
 DC3                  04h:02m:16s     4 /   5   80  (8418) The replication operation failed because of a schema mismatch.

Destination DSA     largest delta    fails/total %%   error
 DC1                      15m:30s     0 /  10    0
 DC3                  04h:02m:16s     4 /   5   80  (8418) The replication operation failed because of a schema mismatch.
"@
$parsed = @(ConvertFrom-AdfaReplsummary -Text $replsum)
Assert-Equal 5 ($parsed.Count) 'replsummary: all five rows across both tables parsed'
Assert-Equal 3 (@($parsed | Where-Object { $_.Direction -eq 'Source' }).Count) 'replsummary: source rows attributed to the source table'
Assert-Equal 2 (@($parsed | Where-Object { $_.Direction -eq 'Destination' }).Count) 'replsummary: destination rows attributed to the destination table'
$dc2 = @($parsed | Where-Object { $_.Dsa -eq 'DC2' -and $_.Direction -eq 'Source' })[0]
Assert-Equal 5 ([int]$dc2.Fails) 'replsummary: fails parsed'
Assert-Equal 5 ([int]$dc2.Total) 'replsummary: total parsed'
Assert-True ($null -eq $dc2.DeltaMinutes) 'replsummary: (unknown) delta stays null'
Assert-True ($dc2.ErrorText -match '8524') 'replsummary: the error code is carried'
$dc1 = @($parsed | Where-Object { $_.Dsa -eq 'DC1' -and $_.Direction -eq 'Source' })[0]
Assert-Equal 0 ([int]$dc1.Fails) 'replsummary: a clean row parses with zero fails'
Assert-Equal 15 ([int]$dc1.DeltaMinutes) 'replsummary: a clean row carries its delta'
Assert-Equal '' ([string]$dc1.ErrorText) 'replsummary: a clean row has no error text'
# Banner and blank lines must not become rows.
Assert-Equal 0 (@($parsed | Where-Object { $_.Dsa -match 'Replication|Beginning|^\.+$' }).Count) 'replsummary: banner lines are not parsed as DSAs'
# Fail-closed: unparseable input yields nothing, and the caller turns that into Not Assessed.
Assert-Equal 0 (@(ConvertFrom-AdfaReplsummary -Text 'not the output of anything').Count) 'replsummary: unrecognised text => no rows'
Assert-Equal 0 (@(ConvertFrom-AdfaReplsummary -Text '').Count) 'replsummary: empty input => no rows'

# --- Verdicts. Zero failures is not the same as converged.
Assert-Equal 'Pass' ([string](Get-AdfaReplsummaryVerdict -Direction 'Source' -Dsa 'DC1' -Delta '15m:30s' -DeltaMinutes 15 -Fails 0 -Total 10).Status) 'replsummary verdict: no failures, small delta => Pass'
Assert-Equal 'Fail' ([string](Get-AdfaReplsummaryVerdict -Direction 'Source' -Dsa 'DC2' -Delta '(unknown)' -DeltaMinutes $null -Fails 5 -Total 5).Status) 'replsummary verdict: failing every attempt => Fail'
Assert-True ((Get-AdfaReplsummaryVerdict -Direction 'Source' -Dsa 'DC2' -Delta '(unknown)' -DeltaMinutes $null -Fails 5 -Total 5).Detail -match 'EVERY replication attempt') 'replsummary verdict: total failure is called out as such'
Assert-Equal 'Fail' ([string](Get-AdfaReplsummaryVerdict -Direction 'Source' -Dsa 'DC3' -Delta '04h' -DeltaMinutes 240 -Fails 4 -Total 5).Status) 'replsummary verdict: partial failures => Fail'
# The key case: no failures but no measurable convergence.
$unk = Get-AdfaReplsummaryVerdict -Direction 'Source' -Dsa 'DC4' -Delta '(unknown)' -DeltaMinutes $null -Fails 0 -Total 3
Assert-Equal 'Not Assessed' ([string]$unk.Status) 'replsummary verdict: no failures + unknown delta => Not Assessed, never Pass'
Assert-True ($unk.Detail -match 'NOT a clean result') 'replsummary verdict: says an unknown delta is not clean'
Assert-Equal 'Warning' ([string](Get-AdfaReplsummaryVerdict -Direction 'Source' -Dsa 'DC5' -Delta '30h' -DeltaMinutes 1800 -Fails 0 -Total 3 -WarnHours 24 -FailHours 168).Status) 'replsummary verdict: lag past the warn threshold => Warning'
$stalled = Get-AdfaReplsummaryVerdict -Direction 'Source' -Dsa 'DC6' -Delta '10d' -DeltaMinutes 14400 -Fails 0 -Total 3 -WarnHours 24 -FailHours 168
Assert-Equal 'Fail' ([string]$stalled.Status) 'replsummary verdict: lag past the fail threshold => Fail'
Assert-True ($stalled.Detail -match 'stopped converging rather than lagged') 'replsummary verdict: names the silent-stall case'
Assert-True ($stalled.Detail -match "tool's, not Microsoft's") 'replsummary verdict: does not pass our thresholds off as vendor limits'
Assert-True ($stalled.Detail -match 'tombstone lifetime') 'replsummary verdict: names the real cliff'

# --- Link lag: the gap this closes is a link with ZERO failures and an old last success.
$now = [datetime]'2026-09-22 00:00:00'
Assert-Equal 'Pass' ([string](Get-AdfaReplicationLagVerdict -Destination 'DC1' -Source 'DC2' -LastSuccess '2026-09-21 23:00:00' -Now $now).Status) 'Lag: an hour ago => Pass'
Assert-Equal 'Warning' ([string](Get-AdfaReplicationLagVerdict -Destination 'DC1' -Source 'DC2' -LastSuccess '2026-09-20 12:00:00' -Now $now -WarnHours 24 -FailHours 168).Status) 'Lag: 36h ago => Warning'
$stall = Get-AdfaReplicationLagVerdict -Destination 'DC1' -Source 'DC2' -NamingContext 'DC=contoso,DC=com' -LastSuccess '2026-09-01 00:00:00' -Now $now -WarnHours 24 -FailHours 168
Assert-Equal 'Fail' ([string]$stall.Status) 'Lag: three weeks ago => Fail even with zero failures'
Assert-True ($stall.Detail -match 'nothing is being attempted') 'Lag: names why nothing errored'
Assert-True ($stall.Detail -match 'DC=contoso,DC=com') 'Lag: names the naming context'
# An unreadable timestamp must not be treated as recent.
$noTime = Get-AdfaReplicationLagVerdict -Destination 'DC1' -Source 'DC2' -LastSuccess '' -Now $now
Assert-Equal 'Not Assessed' ([string]$noTime.Status) 'Lag: no last-success time => Not Assessed, never Pass'
Assert-True ($noTime.Detail -match 'never succeeded reports zero failures too') 'Lag: explains why a blank is not clean'
Assert-Equal 'Not Assessed' ([string](Get-AdfaReplicationLagVerdict -Destination 'DC1' -Source 'DC2' -LastSuccess 'not a date' -Now $now).Status) 'Lag: unparseable time => Not Assessed'
# Clock skew: a future timestamp is a time problem, not a converged link.
$future = Get-AdfaReplicationLagVerdict -Destination 'DC1' -Source 'DC2' -LastSuccess '2026-09-23 00:00:00' -Now $now
Assert-Equal 'Not Assessed' ([string]$future.Status) 'Lag: a future last-success => Not Assessed, not Pass'
Assert-True ($future.Detail -match 'clock skew') 'Lag: names clock skew as the cause'

# Fail-closed in the round over every degraded lag input.
$lagDegraded = @(
    (Get-AdfaReplicationLagVerdict -Destination 'a' -Source 'b' -LastSuccess ''           -Now $now),
    (Get-AdfaReplicationLagVerdict -Destination 'a' -Source 'b' -LastSuccess 'garbage'    -Now $now),
    (Get-AdfaReplicationLagVerdict -Destination 'a' -Source 'b' -LastSuccess '2026-09-23 00:00:00' -Now $now)
)
Assert-Equal 3 (@($lagDegraded).Count) 'Lag: non-vacuity - three degraded inputs evaluated'
Assert-Equal 0 (@($lagDegraded | Where-Object { $_.Status -eq 'Pass' }).Count) 'Lag: no degraded input is ever reported as Pass'

# A silent stall needs different advice from a failing link: there is no error to chase.
$stallRec = Get-AdfaRecommendation -Section 'Replication Cross-Check (repadmin)' -Item 'repadmin lag: DC1 <- DC2' `
    -Detail 'last successful replication 2026-09-01 00:00 - 504h ago - with no failures reported. Nothing is erroring because nothing is being attempted.'
Assert-True ($stallRec -match 'topology rather than the network') 'Lag remediation: points at topology, not the network'
Assert-True ($stallRec -match 'repadmin /showconn|connection object') 'Lag remediation: names the connection object check'
Assert-True ($stallRec -match 'lingering objects') 'Lag remediation: warns against blindly reconnecting a stale link'
Assert-True ($stallRec -notmatch 'Fix the DNS findings first') 'Lag remediation: not hijacked by the generic replication entry'

$skewRec = Get-AdfaRecommendation -Section 'Replication Cross-Check (repadmin)' -Item 'repadmin lag: DC1 <- DC2' `
    -Detail 'last success is timestamped in the future, which means clock skew between the DCs.'
Assert-True ($skewRec -match 'Fix time first') 'Skew remediation: time before replication'
Assert-True ($skewRec -match 'five-minute skew') 'Skew remediation: names the Kerberos limit'

# A genuinely failing link must still get the replication guidance, not the stall guidance.
$failRec = Get-AdfaRecommendation -Section 'Replication Cross-Check (repadmin)' -Item 'repadmin: DC1 <- DC2' `
    -Detail '5 consecutive failure(s) on DC=contoso,DC=com; last failure status 1722; last success unknown.'
Assert-True ($failRec -match 'Fix the DNS findings first') 'Lag remediation: a real failure still routes to replication guidance'

Write-Host ""
Write-Host "== 20. _msdcs delegation, time hierarchy, per-site GC coverage ==" -ForegroundColor Cyan

function Get-H8Row {
    param($Rows, [string]$Pattern)
    $m = @($Rows | Where-Object { [string]$_.Item -match $Pattern })
    if ($m.Count -eq 0) { return $null }
    return $m[0]
}

# --- Name normalisation. Every comparison below rests on it, and a mismatch here would read
#     as a missing record rather than as a bug.
Assert-Equal 'dc1.contoso.com' (Get-AdfaDnsNameNormalised -Name 'DC1.Contoso.COM.') 'Normalise: case folded and root dot stripped'
Assert-Equal '' (Get-AdfaDnsNameNormalised -Name $null) 'Normalise: null becomes empty, not the string "null"'
Assert-Equal '' (Get-AdfaDnsNameNormalised -Name '   ') 'Normalise: whitespace becomes empty'

# --- Zone verdict: which zone answers the SOA is the discriminator between a delegated
#     _msdcs zone and a plain subdomain of the parent.
Assert-Equal 'DelegatedZone' (Get-AdfaMsdcsZoneVerdict -ZoneName '_msdcs.contoso.com' -ParentZone 'contoso.com' -SoaApex @('_msdcs.contoso.com')) 'Zone verdict: own apex => DelegatedZone'
Assert-Equal 'DelegatedZone' (Get-AdfaMsdcsZoneVerdict -ZoneName '_msdcs.contoso.com' -ParentZone 'contoso.com' -SoaApex @('_MSDCS.CONTOSO.COM.')) 'Zone verdict: spelling differences do not change it'
Assert-Equal 'NotDelegated' (Get-AdfaMsdcsZoneVerdict -ZoneName '_msdcs.contoso.com' -ParentZone 'contoso.com' -SoaApex @('contoso.com')) 'Zone verdict: parent apex => NotDelegated'
Assert-Equal 'OtherApex' (Get-AdfaMsdcsZoneVerdict -ZoneName '_msdcs.contoso.com' -ParentZone 'contoso.com' -SoaApex @('fabrikam.com')) 'Zone verdict: a third zone => OtherApex'
Assert-Equal 'NoAnswer' (Get-AdfaMsdcsZoneVerdict -ZoneName '_msdcs.contoso.com' -ParentZone 'contoso.com' -SoaApex @()) 'Zone verdict: no answer is never DelegatedZone'
Assert-Equal 'NoAnswer' (Get-AdfaMsdcsZoneVerdict -ZoneName '_msdcs.contoso.com' -ParentZone 'contoso.com' -SoaApex @('', '  ')) 'Zone verdict: blank answers are no answer'
$zoneVerdicts = @('_msdcs.contoso.com', 'contoso.com', 'fabrikam.com') | ForEach-Object {
    Get-AdfaMsdcsZoneVerdict -ZoneName '_msdcs.contoso.com' -ParentZone 'contoso.com' -SoaApex @($_)
}
Assert-Equal 3 (@($zoneVerdicts).Count) 'Zone verdict: non-vacuity - three declared apex cases evaluated'
Assert-Equal 3 (@($zoneVerdicts | Sort-Object -Unique).Count) 'Zone verdict: the three cases are genuinely distinguished'

# --- Delegation verdict. Healthy first, so the failure cases are measured against a known green.
$h8Dcs = @('dc1.contoso.com', 'dc2.contoso.com')
$h8Healthy = @(
    [pscustomobject]@{ Server = 'dc1.contoso.com'; SoaApex = @('_msdcs.contoso.com'); NsTargets = @('dc1.contoso.com', 'dc2.contoso.com'); GlueMissing = @(); GlueUnknown = @() }
    [pscustomobject]@{ Server = 'dc2.contoso.com'; SoaApex = @('_msdcs.contoso.com'); NsTargets = @('dc1.contoso.com'); GlueMissing = @(); GlueUnknown = @() }
)
$delOk = @(Get-AdfaMsdcsDelegationVerdict -ForestRoot 'contoso.com' -Observations $h8Healthy -AdDcHosts $h8Dcs)
Assert-Equal 4 (@($delOk).Count) 'Delegation: a healthy view produces one row per checked property (4)'
Assert-Equal 0 (@($delOk | Where-Object { $_.Status -ne 'Pass' }).Count) 'Delegation: a healthy view produces no non-Pass row'
Assert-True (@($delOk | Where-Object { $_.Item -match 'is a delegated zone' }).Count -eq 1) 'Delegation: names the zone as delegated'

# Not a zone of its own - the state a hand-rebuilt DNS server is left in after a recovery.
$delNot = @(Get-AdfaMsdcsDelegationVerdict -ForestRoot 'contoso.com' -AdDcHosts $h8Dcs -Observations @(
        [pscustomobject]@{ Server = 'dc1.contoso.com'; SoaApex = @('contoso.com'); NsTargets = @('dc1.contoso.com'); GlueMissing = @(); GlueUnknown = @() }
    ))
$rowNot = Get-H8Row -Rows $delNot -Pattern 'is not a delegated zone'
Assert-True ($null -ne $rowNot) 'Delegation: a non-delegated subdomain produces its own row'
if ($null -ne $rowNot) {
    Assert-Equal 'Fail' ([string]$rowNot.Status) 'Delegation: a non-delegated _msdcs is a Fail'
    Assert-True ($rowNot.Detail -match 'PARENT zone contoso\.com') 'Delegation: names the parent zone that answered'
}
Assert-Equal 0 (@($delNot | Where-Object { $_.Item -match 'is a delegated zone' }).Count) 'Delegation: the Pass row is withheld when any server disagrees'

# No NS records: no referral to the locator zone at all.
$delNoNs = @(Get-AdfaMsdcsDelegationVerdict -ForestRoot 'contoso.com' -AdDcHosts $h8Dcs -Observations @(
        [pscustomobject]@{ Server = 'dc1.contoso.com'; SoaApex = @('_msdcs.contoso.com'); NsTargets = @(); GlueMissing = @(); GlueUnknown = @() }
    ))
$rowNoNs = Get-H8Row -Rows $delNoNs -Pattern 'no NS records'
Assert-True ($null -ne $rowNoNs) 'Delegation: missing NS records produce a row'
if ($null -ne $rowNoNs) { Assert-Equal 'Fail' ([string]$rowNoNs.Status) 'Delegation: no NS record for the locator zone is a Fail' }

# Missing glue: an NS record naming a host that cannot be resolved to an address.
$delGlue = @(Get-AdfaMsdcsDelegationVerdict -ForestRoot 'contoso.com' -AdDcHosts $h8Dcs -Observations @(
        [pscustomobject]@{ Server = 'dc1.contoso.com'; SoaApex = @('_msdcs.contoso.com'); NsTargets = @('dc2.contoso.com'); GlueMissing = @('dc2.contoso.com'); GlueUnknown = @() }
    ))
$rowGlue = Get-H8Row -Rows $delGlue -Pattern 'missing glue'
Assert-True ($null -ne $rowGlue) 'Delegation: missing glue produces a row'
if ($null -ne $rowGlue) {
    Assert-Equal 'Fail' ([string]$rowGlue.Status) 'Delegation: an NS record with no glue is a Fail'
    Assert-True ($rowGlue.Detail -match 'dc2\.contoso\.com') 'Delegation: names the NS target with no glue'
}
Assert-Equal 0 (@($delGlue | Where-Object { $_.Item -match 'glue records resolvable' }).Count) 'Delegation: the glue Pass row is withheld when glue is missing'

# Glue that could not be queried is UNKNOWN, not missing - the distinction the whole tool rests on.
$delGlueNa = @(Get-AdfaMsdcsDelegationVerdict -ForestRoot 'contoso.com' -AdDcHosts $h8Dcs -Observations @(
        [pscustomobject]@{ Server = 'dc1.contoso.com'; SoaApex = @('_msdcs.contoso.com'); NsTargets = @('dc2.contoso.com'); GlueMissing = @(); GlueUnknown = @('dc2.contoso.com') }
    ))
$rowGlueNa = Get-H8Row -Rows $delGlueNa -Pattern 'glue not readable'
Assert-True ($null -ne $rowGlueNa) 'Delegation: unqueryable glue produces its own row'
if ($null -ne $rowGlueNa) { Assert-Equal 'Not Assessed' ([string]$rowGlueNa.Status) 'Delegation: unqueryable glue is Not Assessed, never Fail' }
Assert-Equal 0 (@($delGlueNa | Where-Object { $_.Item -match 'glue records resolvable' }).Count) 'Delegation: no glue Pass row while any glue is unverified'

# Stale NS after metadata cleanup: a Warning, because a non-DC DNS server can be legitimate.
$delStale = @(Get-AdfaMsdcsDelegationVerdict -ForestRoot 'contoso.com' -AdDcHosts $h8Dcs -Observations @(
        [pscustomobject]@{ Server = 'dc1.contoso.com'; SoaApex = @('_msdcs.contoso.com'); NsTargets = @('dc1.contoso.com', 'oldDC.contoso.com'); GlueMissing = @(); GlueUnknown = @() }
    ))
$rowStale = Get-H8Row -Rows $delStale -Pattern 'not a known DC'
Assert-True ($null -ne $rowStale) 'Delegation: an NS host that is not a known DC produces a row'
if ($null -ne $rowStale) {
    Assert-Equal 'Warning' ([string]$rowStale.Status) 'Delegation: an unknown NS host is a Warning, not a Fail'
    Assert-True ($rowStale.Detail -match 'oldDC\.contoso\.com') 'Delegation: names the host that is not a known DC'
    Assert-True ($rowStale.Detail -notmatch 'dc1\.contoso\.com,|dc1\.contoso\.com$') 'Delegation: a legitimate DC is not listed as stale'
}

# With no inventory the cross-check is not silently skipped.
$delNoInv = @(Get-AdfaMsdcsDelegationVerdict -ForestRoot 'contoso.com' -AdDcHosts @() -Observations $h8Healthy)
$rowNoInv = Get-H8Row -Rows $delNoInv -Pattern 'not cross-checked'
Assert-True ($null -ne $rowNoInv) 'Delegation: no DC inventory produces an explicit not-cross-checked row'
if ($null -ne $rowNoInv) { Assert-Equal 'Not Assessed' ([string]$rowNoInv.Status) 'Delegation: an unperformed cross-check is Not Assessed' }

# No server answered at all.
$delNone = @(Get-AdfaMsdcsDelegationVerdict -ForestRoot 'contoso.com' -Observations @() -AdDcHosts $h8Dcs -Unanswered @('dc1.contoso.com'))
Assert-Equal 1 (@($delNone).Count) 'Delegation: no observations produces exactly one row'
Assert-Equal 'Not Assessed' ([string]@($delNone)[0].Status) 'Delegation: no observations is Not Assessed, never Pass'
Assert-True (@($delNone)[0].Detail -match 'dc1\.contoso\.com') 'Delegation: names the servers that did not answer'

# Fail-closed in the round. Note what is NOT asserted here: that a degraded view contains no
# Pass row at all. It legitimately does - a view with a broken delegation still has healthy
# glue, and reporting that honestly is the point. The property that must hold is that every
# degraded view carries at least one non-Pass row, so none of them can read as clean. The
# withholding of each specific Pass row is asserted case by case above.
$delDegraded = @($delNot, $delNoNs, $delGlue, $delGlueNa, $delNone)
Assert-Equal 5 (@($delDegraded).Count) 'Delegation: non-vacuity - five degraded delegation views evaluated'
Assert-Equal 5 (@($delDegraded | Where-Object { @($_ | Where-Object { $_.Status -ne 'Pass' }).Count -gt 0 }).Count) 'Delegation: every degraded view carries at least one non-Pass row'
Assert-Equal 0 (@($delDegraded | Where-Object { @($_ | Where-Object { $_.Status -ne 'Pass' }).Count -eq 0 }).Count) 'Delegation: no degraded view is silently all-Pass'

# --- w32tm /query /configuration parse. The KEY names are published; the line format is not,
#     so an unmatched key must come back empty rather than assumed.
$cfgOk = ConvertFrom-AdfaW32tmConfiguration -Text @"
[TimeProviders]

NtpClient (Local)
Enabled: 1 (Local)
Type: NTP (Local)
NtpServer: ntp.example.test,0x8 (Local)
"@
Assert-Equal 'NTP' $cfgOk.Type 'w32tm config: Type parsed with the (Local) annotation stripped'
Assert-Equal 'ntp.example.test,0x8' $cfgOk.NtpServer 'w32tm config: NtpServer parsed with the annotation stripped'
$cfgHier = ConvertFrom-AdfaW32tmConfiguration -Text "  Type: NT5DS (Policy)"
Assert-Equal 'NT5DS' $cfgHier.Type 'w32tm config: leading whitespace and a (Policy) annotation are tolerated'
$cfgNone = ConvertFrom-AdfaW32tmConfiguration -Text 'The following error occurred: Access is denied.'
Assert-Equal '' $cfgNone.Type 'w32tm config: an error page yields no Type, not a guessed one'
Assert-Equal '' (ConvertFrom-AdfaW32tmConfiguration -Text $null).Type 'w32tm config: null input yields no Type'

# --- Time source verdict. The two documented rules, and nothing beyond them.
$tsUnread = Get-AdfaTimeSourceVerdict -DomainController 'dc1.contoso.com' -Queried $false -ErrorText 'RPC (135) was not reachable' -DomainControllerHosts $h8Dcs
Assert-Equal 'Not Assessed' ([string]$tsUnread.Status) 'Time: a source that could not be read is Not Assessed'
Assert-True ($tsUnread.Detail -match 'Domain Admins') 'Time: says the remote query needs Domain Admins, so a denial is not read as a clock fault'
Assert-Equal 'Not Assessed' ([string](Get-AdfaTimeSourceVerdict -DomainController 'dc1.contoso.com' -Source '   ' -DomainControllerHosts $h8Dcs).Status) 'Time: a blank source line is Not Assessed'

$tsVmMember = Get-AdfaTimeSourceVerdict -DomainController 'dc2.contoso.com' -Source 'VM IC Time Synchronization Provider' -DomainControllerHosts $h8Dcs
Assert-Equal 'Warning' ([string]$tsVmMember.Status) 'Time: host time sync on a non-PDC DC is a Warning'
Assert-True ($tsVmMember.Detail -match 'lingering objects') 'Time: names the vendor-documented consequence'
Assert-True ($tsVmMember.Detail -match 'Integration Services') 'Time: names the published fix'

$tsVmRoot = Get-AdfaTimeSourceVerdict -DomainController 'dc1.contoso.com' -IsPdcEmulator $true -IsForestRootPdc $true -Source 'VM IC Time Synchronization Provider' -DomainControllerHosts $h8Dcs
Assert-Equal 'Warning' ([string]$tsVmRoot.Status) 'Time: host time sync on the root PDC is a Warning'
Assert-True ($tsVmRoot.Detail -match 'guidance is split') 'Time: states that the vendor guidance diverges for this role rather than picking a side silently'
Assert-True ($tsVmRoot.Detail -match 'KB 976924' -and $tsVmRoot.Detail -match 'Windows Server 2016') 'Time: cites both positions'

$tsCmosRoot = Get-AdfaTimeSourceVerdict -DomainController 'dc1.contoso.com' -IsPdcEmulator $true -IsForestRootPdc $true -Source 'Local CMOS Clock' -DomainControllerHosts $h8Dcs
Assert-Equal 'Warning' ([string]$tsCmosRoot.Status) 'Time: the root PDC on its own clock is a Warning'
Assert-True ($tsCmosRoot.Detail -match 'NO authoritative upstream') 'Time: says the forest has no upstream time at all'
Assert-Equal 'Warning' ([string](Get-AdfaTimeSourceVerdict -DomainController 'dc2.contoso.com' -Source 'Free-running System Clock' -DomainControllerHosts $h8Dcs).Status) 'Time: a member DC free-running is a Warning'

$tsRootFromDc = Get-AdfaTimeSourceVerdict -DomainController 'dc1.contoso.com' -IsPdcEmulator $true -IsForestRootPdc $true -Source 'dc2.contoso.com' -DomainControllerHosts $h8Dcs
Assert-Equal 'Warning' ([string]$tsRootFromDc.Status) 'Time: the root PDC syncing from one of its own DCs is a Warning'
Assert-True ($tsRootFromDc.Detail -match 'event ID 12') 'Time: cites the event the vendor logs for this exact condition'

$tsRootExternal = Get-AdfaTimeSourceVerdict -DomainController 'dc1.contoso.com' -IsPdcEmulator $true -IsForestRootPdc $true -Source 'ntp.example.test' -DomainControllerHosts $h8Dcs
Assert-Equal 'Pass' ([string]$tsRootExternal.Status) 'Time: the root PDC on an external source is a Pass'
Assert-True ($tsRootExternal.Detail -match 'does not verify') 'Time: the Pass states what it did NOT check'
Assert-Equal 'Not Assessed' ([string](Get-AdfaTimeSourceVerdict -DomainController 'dc1.contoso.com' -IsForestRootPdc $true -Source 'ntp.example.test' -DomainControllerHosts @()).Status) 'Time: with no DC inventory, external-vs-internal is unverified, not a Pass'

Assert-Equal 'Pass' ([string](Get-AdfaTimeSourceVerdict -DomainController 'dc2.contoso.com' -Source 'DC1.CONTOSO.COM' -DomainControllerHosts $h8Dcs).Status) 'Time: a member DC on the domain hierarchy is a Pass, matched case-insensitively'
Assert-Equal 'Info' ([string](Get-AdfaTimeSourceVerdict -DomainController 'dc2.contoso.com' -Source 'ntp.example.test' -DomainControllerHosts $h8Dcs).Status) 'Time: a member DC on an external source is Info - a deviation, not a fault'

$tsDegraded = @($tsUnread, $tsVmMember, $tsVmRoot, $tsCmosRoot, $tsRootFromDc)
Assert-Equal 5 (@($tsDegraded).Count) 'Time: non-vacuity - five declared degraded source cases evaluated'
Assert-Equal 0 (@($tsDegraded | Where-Object { $_.Status -eq 'Pass' }).Count) 'Time: no degraded source is ever reported as Pass'

# --- Root PDC client type. Configured intent, separate from the source in effect.
Assert-Equal 'Warning' ([string](Get-AdfaRootPdcClientTypeVerdict -DomainController 'dc1.contoso.com' -ClientType 'NT5DS').Status) 'Client type: NT5DS on the root PDC is a Warning'
Assert-True ((Get-AdfaRootPdcClientTypeVerdict -DomainController 'dc1.contoso.com' -ClientType 'NT5DS').Detail -match 'event ID 12') 'Client type: cites the documented event'
Assert-Equal 'Warning' ([string](Get-AdfaRootPdcClientTypeVerdict -DomainController 'dc1.contoso.com' -ClientType 'NoSync').Status) 'Client type: NoSync is a Warning'
Assert-Equal 'Pass' ([string](Get-AdfaRootPdcClientTypeVerdict -DomainController 'dc1.contoso.com' -ClientType 'NTP' -NtpServer 'ntp.example.test,0x8').Status) 'Client type: NTP with a peer list is a Pass'
Assert-Equal 'Pass' ([string](Get-AdfaRootPdcClientTypeVerdict -DomainController 'dc1.contoso.com' -ClientType 'AllSync' -NtpServer 'ntp.example.test,0x8').Status) 'Client type: AllSync with a peer list is a Pass'
Assert-Equal 'Not Assessed' ([string](Get-AdfaRootPdcClientTypeVerdict -DomainController 'dc1.contoso.com' -ClientType 'NTP').Status) 'Client type: NTP with no peer list read is unverified, not a Pass'
Assert-Equal 'Not Assessed' ([string](Get-AdfaRootPdcClientTypeVerdict -DomainController 'dc1.contoso.com' -ClientType '').Status) 'Client type: an unread Type is Not Assessed'
Assert-Equal 'Not Assessed' ([string](Get-AdfaRootPdcClientTypeVerdict -DomainController 'dc1.contoso.com' -ClientType 'Something').Status) 'Client type: an undocumented value is not interpreted'
$ctAll = @('NT5DS', 'NoSync', '', 'Something') | ForEach-Object { Get-AdfaRootPdcClientTypeVerdict -DomainController 'dc1.contoso.com' -ClientType $_ }
Assert-Equal 4 (@($ctAll).Count) 'Client type: non-vacuity - four declared non-compliant type cases evaluated'
Assert-Equal 0 (@($ctAll | Where-Object { $_.Status -eq 'Pass' }).Count) 'Client type: none of the non-compliant cases reports Pass'

# --- Per-site writeable GC coverage. Joins Site, IsGlobalCatalog and IsReadOnly, which the
#     inventory already collects and never correlated.
function New-H8Dc {
    param([string]$Name, [string]$Site, $Gc, $Ro)
    return [pscustomobject]@{ HostName = $Name; Site = $Site; IsGlobalCatalog = $Gc; IsReadOnly = $Ro }
}
$gcHealthy = @(Get-AdfaSiteGcCoverage -DomainControllers @((New-H8Dc 'dc1.contoso.com' 'HQ' $true $false)))
Assert-Equal 1 (@($gcHealthy).Count) 'Site GC: a covered site produces exactly one row'
Assert-Equal 'Pass' ([string]@($gcHealthy)[0].Status) 'Site GC: a writeable GC in the site is a Pass'
Assert-True (@($gcHealthy)[0].Detail -match '1 of 1 site') 'Site GC: the Pass names its declared population'

$gcRodcOnly = @(Get-AdfaSiteGcCoverage -DomainControllers @((New-H8Dc 'rodc1.contoso.com' 'Branch' $true $true)))
$rowRodc = Get-H8Row -Rows $gcRodcOnly -Pattern "Site 'Branch'"
Assert-True ($null -ne $rowRodc) 'Site GC: a site with only a read-only GC produces a row'
if ($null -ne $rowRodc) {
    Assert-Equal 'Warning' ([string]$rowRodc.Status) 'Site GC: a read-only GC does not satisfy the writeable-GC requirement'
    Assert-True ($rowRodc.Detail -match 'read-only GC: rodc1\.contoso\.com') 'Site GC: names what is actually in the site'
    Assert-True ($rowRodc.Detail -match 'read-only directory servers') 'Site GC: names the documented Exchange consequence'
}
Assert-Equal 0 (@($gcRodcOnly | Where-Object { $_.Status -eq 'Pass' }).Count) 'Site GC: no Pass row when no site is covered'

$rowNonGc = Get-H8Row -Rows @(Get-AdfaSiteGcCoverage -DomainControllers @((New-H8Dc 'dc9.contoso.com' 'Branch' $false $false))) -Pattern "Site 'Branch'"
Assert-True ($null -ne $rowNonGc) 'Site GC: a writeable non-GC does not cover the site'
if ($null -ne $rowNonGc) { Assert-True ($rowNonGc.Detail -match 'writeable but not a GC') 'Site GC: distinguishes writeable-not-GC from read-only' }

# A mixed forest: one covered site, one not - both must be visible in the same run.
$gcMixed = @(Get-AdfaSiteGcCoverage -DomainControllers @(
        (New-H8Dc 'dc1.contoso.com' 'HQ' $true $false),
        (New-H8Dc 'rodc1.contoso.com' 'Branch' $true $true)
    ))
Assert-Equal 1 (@($gcMixed | Where-Object { $_.Status -eq 'Warning' }).Count) 'Site GC: the uncovered site is reported'
Assert-Equal 1 (@($gcMixed | Where-Object { $_.Status -eq 'Pass' }).Count) 'Site GC: the covered site is still reported as covered'
Assert-True (@($gcMixed | Where-Object { $_.Status -eq 'Pass' })[0].Detail -match '1 of 2 site') 'Site GC: the Pass row states the population it does NOT cover'

# Unreadable flags must make the site unknown, not uncovered.
$gcUnknown = @(Get-AdfaSiteGcCoverage -DomainControllers @((New-H8Dc 'dc5.contoso.com' 'Branch' $null $null)))
$rowUnknown = Get-H8Row -Rows $gcUnknown -Pattern 'not readable'
Assert-True ($null -ne $rowUnknown) 'Site GC: a site whose flags are unreadable produces a row'
if ($null -ne $rowUnknown) { Assert-Equal 'Not Assessed' ([string]$rowUnknown.Status) 'Site GC: unreadable flags are Not Assessed, not a missing GC' }
$gcNotBool = @(Get-AdfaSiteGcCoverage -DomainControllers @((New-H8Dc 'dc6.contoso.com' 'Branch' 'Not Assessed' $false)))
# Guarded: Get-H8Row returns $null when no row matches, and reading .Status off $null under
# StrictMode aborts the whole harness - which would hide every assertion after this one rather
# than report this one. Assert on presence first, then on the value.
$rowNotBool = Get-H8Row -Rows $gcNotBool -Pattern 'not readable'
Assert-True ($null -ne $rowNotBool) 'Site GC: a non-boolean flag produces a not-readable row rather than being coerced'
if ($null -ne $rowNotBool) { Assert-Equal 'Not Assessed' ([string]$rowNotBool.Status) 'Site GC: a non-boolean flag is not coerced to false' }

$gcNoSite = @(Get-AdfaSiteGcCoverage -DomainControllers @((New-H8Dc 'dc7.contoso.com' '' $true $false)))
$rowNoSite = Get-H8Row -Rows $gcNoSite -Pattern 'no site'
Assert-True ($null -ne $rowNoSite) 'Site GC: a DC with no site is reported rather than dropped'
if ($null -ne $rowNoSite) { Assert-Equal 'Not Assessed' ([string]$rowNoSite.Status) 'Site GC: a siteless DC is Not Assessed' }

$gcEmpty = @(Get-AdfaSiteGcCoverage -DomainControllers @())
Assert-Equal 1 (@($gcEmpty).Count) 'Site GC: an empty inventory produces exactly one row'
Assert-Equal 'Not Assessed' ([string]@($gcEmpty)[0].Status) 'Site GC: an empty inventory is Not Assessed, never Pass'
$gcDegraded = @($gcRodcOnly, $gcUnknown, $gcNoSite, $gcEmpty)
Assert-Equal 4 (@($gcDegraded).Count) 'Site GC: non-vacuity - four declared degraded inventories evaluated'
Assert-Equal 0 (@($gcDegraded | ForEach-Object { $_ } | Where-Object { $_.Status -eq 'Pass' }).Count) 'Site GC: no degraded inventory reports Pass'

# --- Config: the volatile vendor strings are data, with their source recorded.
Assert-Equal '_msdcs' ([string]$script:Config.MsdcsZoneLabel) 'Config: the locator zone label is held as data'
Assert-Equal 'NT5DS' ([string]$script:Config.Time.DomainHierarchyType) 'Config: the domain-hierarchy client type is the published value'
Assert-True (@($script:Config.Time.ExternalTypes) -contains 'NTP' -and @($script:Config.Time.ExternalTypes) -contains 'AllSync') 'Config: both published external client types are listed'
Assert-True ('VM IC Time Synchronization Provider' -match $script:Config.Time.HypervisorPattern) 'Config: the hypervisor pattern matches the published provider name'
Assert-True ('Local CMOS Clock' -match $script:Config.Time.LocalClockPattern) 'Config: the local-clock pattern matches the published source name'
Assert-True ('dc1.contoso.com' -notmatch $script:Config.Time.LocalClockPattern) 'Config: the local-clock pattern does not match an ordinary host name'
Assert-True ($script:Config.Time.RootPdcUrl -match '^https://learn\.microsoft\.com/') 'Config: the root-PDC rule records its source URL'
Assert-True ($script:Config.Time.HypervisorUrl -match '^https://learn\.microsoft\.com/') 'Config: the host-time-sync rule records its source URL'
Assert-Equal '2026-09-22' ([string]$script:Config.Time.ReadDate) 'Config: the read date is recorded next to the values'

# --- Remediation routing for the three new sections.
$recMsdcs = Get-AdfaRecommendation -Section '_msdcs Zone Delegation' -Item '_msdcs.contoso.com is not a delegated zone' -Detail 'answered by the PARENT zone contoso.com'
Assert-True ($recMsdcs -match 'New Delegation') 'Remediation: a non-delegated locator zone routes to delegation guidance'
Assert-True ($recMsdcs -notmatch 'scavenging') 'Remediation: not hijacked by the generic DNS scavenging entry'
$recGlue = Get-AdfaRecommendation -Section '_msdcs Zone Delegation' -Item '_msdcs.contoso.com delegation - missing glue records' -Detail 'no resolvable glue (A) record'
Assert-True ($recGlue -match 'glue host') 'Remediation: missing glue routes to the glue-record fix'
$recStale = Get-AdfaRecommendation -Section '_msdcs Zone Delegation' -Item '_msdcs.contoso.com delegation - NS host not a known DC' -Detail 'not domain controllers in this forest'
Assert-True ($recStale -match 'dsderegdns') 'Remediation: a stale NS host routes to the deregistration command'
$recTimeVm = Get-AdfaRecommendation -Section 'Time Hierarchy' -Item 'Time source on dc2.contoso.com (domain controller)' -Detail "Source is the virtualisation host's time provider"
Assert-True ($recTimeVm -match 'VMICTimeProvider') 'Remediation: host time sync routes to the provider fix'
$recTimeRoot = Get-AdfaRecommendation -Section 'Time Hierarchy' -Item 'Time source on dc1.contoso.com (FOREST ROOT PDC emulator)' -Detail 'so the forest has NO authoritative upstream time'
Assert-True ($recTimeRoot -match 'manualpeerlist') 'Remediation: a root PDC with no upstream routes to the w32tm config command'
Assert-True ($recTimeRoot -match 'five minutes') 'Remediation: names the Kerberos skew limit'
$recSiteGc = Get-AdfaRecommendation -Section 'Site Global Catalog Coverage' -Item "Site 'Branch' has no writeable global catalog" -Detail 'read-only GC: rodc1.contoso.com'
Assert-True ($recSiteGc -match '\+IS_GC') 'Remediation: an uncovered site routes to the GC-flag fix'
$h8Recs = @($recMsdcs, $recGlue, $recStale, $recTimeVm, $recTimeRoot, $recSiteGc)
Assert-Equal 6 (@($h8Recs).Count) 'Remediation: non-vacuity - six declared H8 findings routed'
Assert-Equal 0 (@($h8Recs | Where-Object { [string]::IsNullOrWhiteSpace($_) }).Count) 'Remediation: every declared H8 finding has guidance'

# --- The resolver must be able to ask for the record types these checks need.
$resolveParam = (Get-Command Resolve-AdfaDnsRecord).Parameters['Type']
$resolveSet = @($resolveParam.Attributes | Where-Object { $_ -is [System.Management.Automation.ValidateSetAttribute] } | Select-Object -First 1).ValidValues
foreach ($t in @('SRV', 'CNAME', 'NS', 'A', 'SOA')) {
    Assert-True (@($resolveSet) -contains $t) ("Resolver: accepts record type {0}" -f $t)
}

# The nslookup fallback paths for the two new record types, and the SOA refusal. This must be
# exercised with nslookup PRESENT and Resolve-DnsName ABSENT, or the assertions are vacuous:
# with no tool at all every type returns NoTool and the SOA guard is never reached. These stubs
# are last in the file on purpose - they change Test-CommandAvailable for everything after them.
function Test-CommandAvailable { param([string]$Name) return ($Name -eq 'nslookup.exe') }
function Invoke-ExternalCommand {
    param([string]$FilePath, [string]$Arguments, [string]$OutFile, [int]$TimeoutSeconds, [int]$Retries, [int]$RetryDelaySeconds)
    $out = ''
    if ($Arguments -match 'type=NS') {
        # nslookup prints its own server in a header before the answer.
        $out = "Server:  ns1.contoso.com`r`nAddress:  192.0.2.10`r`n`r`n_msdcs.contoso.com`tnameserver = dc1.contoso.com`r`n_msdcs.contoso.com`tnameserver = dc2.contoso.com`r`n"
    }
    elseif ($Arguments -match 'type=A') {
        $out = "Server:  ns1.contoso.com`r`nAddress:  192.0.2.10`r`n`r`nName:    dc1.contoso.com`r`nAddress:  192.0.2.11`r`n"
    }
    [pscustomobject]@{ Success = $true; ExitCode = 0; Attempt = 1; Error = $null; OutFile = $OutFile; StdOut = $out }
}
$nsFallback = Resolve-AdfaDnsRecord -Name '_msdcs.contoso.com' -Type NS
Assert-Equal 'Resolved' ([string]$nsFallback.Outcome) 'Resolver: NS records are parsed from the nslookup fallback'
Assert-Equal 2 (@($nsFallback.Targets).Count) 'Resolver: both nameserver lines are read'
Assert-True (@($nsFallback.Targets) -contains 'dc1.contoso.com') 'Resolver: the NS target name is captured'
$aFallback = Resolve-AdfaDnsRecord -Name 'dc1.contoso.com' -Type A
Assert-Equal 1 (@($aFallback.Targets).Count) 'Resolver: exactly one address is read from an A answer'
Assert-Equal '192.0.2.11' ([string]@($aFallback.Targets)[0]) 'Resolver: the ANSWER address is read, not the DNS server''s own address from the header'
Assert-True (@($aFallback.Targets) -notcontains '192.0.2.10') 'Resolver: the header address is never returned as glue'
Assert-Equal 'NoTool' ([string](Resolve-AdfaDnsRecord -Name '_msdcs.contoso.com' -Type SOA).Outcome) 'Resolver: an SOA query is refused rather than guessed from nslookup output'

Write-Host ""
Write-Host "== 21. Live-run defects: dcdiag unassessed cause, DNS forwarders null ==" -ForegroundColor Cyan

# --- dcdiag outcome classification. The live run produced cells that were Not Assessed with
#     NOTHING recorded about why, on a tool whose own rule is that an unmeasured value carries
#     a named cause. These four outcomes are what that cell can actually mean.
Assert-Equal 'Pass' (Get-AdfaDcdiagTestOutcome -TestName 'Advertising' -StdOut '......................... DC1 passed test Advertising') 'dcdiag outcome: a passed verdict is read'
Assert-Equal 'Fail' (Get-AdfaDcdiagTestOutcome -TestName 'Advertising' -StdOut '......................... DC1 failed test Advertising') 'dcdiag outcome: a failed verdict is read'
Assert-Equal 'Unparsed' (Get-AdfaDcdiagTestOutcome -TestName 'VerifyEnterpriseReferences' -StdOut 'Doing initial required tests') 'dcdiag outcome: output with no verdict is Unparsed, not Pass'
Assert-Equal 'Unparsed' (Get-AdfaDcdiagTestOutcome -TestName 'Advertising' -StdOut '') 'dcdiag outcome: empty output is Unparsed, not Pass'
Assert-Equal 'ToolFailed' (Get-AdfaDcdiagTestOutcome -TestName 'Advertising' -Success $false -StdOut '') 'dcdiag outcome: a tool that did not run is ToolFailed'
# A FAILED test makes dcdiag exit non-zero. Reading Success first would throw that measurement
# away and report the DC as unassessed when dcdiag actually told us something.
Assert-Equal 'Fail' (Get-AdfaDcdiagTestOutcome -TestName 'Advertising' -Success $false -StdOut '......................... DC1 failed test Advertising') 'dcdiag outcome: a real failure is kept even though dcdiag exits non-zero'
# The verdict must belong to the test that was asked for.
Assert-Equal 'Unparsed' (Get-AdfaDcdiagTestOutcome -TestName 'VerifyReferences' -StdOut '......................... DC1 passed test VerifyEnterpriseReferences') 'dcdiag outcome: a longer test name does not satisfy a shorter one'
# The word boundary: a verdict for a test whose name merely STARTS with the one asked for must
# not be claimed. Without \b, 'passed test Netlogons' would be satisfied by 'NetlogonsExtra'.
Assert-Equal 'Unparsed' (Get-AdfaDcdiagTestOutcome -TestName 'Netlogons' -StdOut '..... DC1 passed test NetlogonsExtra') 'dcdiag outcome: a verdict for a longer-named test does not satisfy a prefix'
Assert-Equal 'Unparsed' (Get-AdfaDcdiagTestOutcome -TestName 'Netlogons' -StdOut '..... DC1 failed test NetlogonsExtra') 'dcdiag outcome: the same boundary applies to a failed verdict'
Assert-Equal 'Pass' (Get-AdfaDcdiagTestOutcome -TestName 'VerifyEnterpriseReferences' -StdOut '... DC1 PASSED TEST VerifyEnterpriseReferences') 'dcdiag outcome: the verdict match is case-insensitive'
$dcdiagOutcomes = @(
    (Get-AdfaDcdiagTestOutcome -TestName 'T' -StdOut 'passed test T'),
    (Get-AdfaDcdiagTestOutcome -TestName 'T' -StdOut 'failed test T'),
    (Get-AdfaDcdiagTestOutcome -TestName 'T' -StdOut 'nothing'),
    (Get-AdfaDcdiagTestOutcome -TestName 'T' -Success $false -StdOut '')
)
Assert-Equal 4 (@($dcdiagOutcomes).Count) 'dcdiag outcome: non-vacuity - four declared outcomes evaluated'
Assert-Equal 4 (@($dcdiagOutcomes | Sort-Object -Unique).Count) 'dcdiag outcome: all four are genuinely distinguished'

# --- The cause text. This is the whole point of the fix: no unassessed cell may be silent.
# The excerpt must carry the DIAGNOSTIC line, not dcdiag's banner. This fixture is the shape
# the live run would have produced: banner first, the interesting line last. Excerpting the
# first lines - as the first cut of this function did - would have returned pure boilerplate
# and left the report no better off than the silent Not Assessed it replaced.
$causeUnparsed = Get-AdfaDcdiagUnassessedCause -TestName 'VerifyEnterpriseReferences' -Outcome 'Unparsed' `
    -StdOut "Directory Server Diagnosis`n`nPerforming initial setup:`n   Trying to find home server...`n   Home Server = DC1`n   * Identified AD Forest.`n   Ldap search capability attribute search failed on server DC1, return value = 81" -ExitCode 0
Assert-True ($causeUnparsed -match 'VerifyEnterpriseReferences') 'dcdiag cause: names the test'
Assert-True ($causeUnparsed -match 'NOT ASSESSED') 'dcdiag cause: says plainly that nothing was measured'
Assert-True ($causeUnparsed -match 'neither') 'dcdiag cause: explains that no verdict line was found'
Assert-True ($causeUnparsed -match 'non-English') 'dcdiag cause: names localisation as a candidate, which the verdict match cannot survive'
Assert-True ($causeUnparsed -match 'return value = 81') 'dcdiag cause: carries the DIAGNOSTIC line from the output'
Assert-True ($causeUnparsed -notmatch 'Directory Server Diagnosis') 'dcdiag cause: does not waste the excerpt on the banner'

# With nothing diagnostic in the output, the END is taken - dcdiag prints its summary there.
$causeTail = Get-AdfaDcdiagUnassessedCause -TestName 'T' -Outcome 'Unparsed' -ExitCode 0 `
    -StdOut "Directory Server Diagnosis`nbanner two`nbanner three`nlast meaningful line"
Assert-True ($causeTail -match 'last meaningful line') 'dcdiag cause: with no diagnostic line, the tail is excerpted, not the banner'

$causeFailed = Get-AdfaDcdiagUnassessedCause -TestName 'CheckSecurityError' -Outcome 'ToolFailed' -StdOut '' -ErrorText 'timed out' -ExitCode 258
Assert-True ($causeFailed -match 'did not complete') 'dcdiag cause: a tool failure is described as the tool not running'
Assert-True ($causeFailed -match '258') 'dcdiag cause: carries the exit code'
Assert-True ($causeFailed -match 'timed out') 'dcdiag cause: carries the error text'
Assert-True ($causeFailed -notmatch 'non-English') 'dcdiag cause: does not blame localisation for a tool that never ran'

$causeSilent = Get-AdfaDcdiagUnassessedCause -TestName 'KnowsOfRoleHolders' -Outcome 'Unparsed' -StdOut '' -ExitCode 0
Assert-True ($causeSilent -match 'NO output') 'dcdiag cause: distinguishes no output from unrecognised output'
Assert-True ($causeSilent -match 'dcdiag /test:KnowsOfRoleHolders') 'dcdiag cause: names the command to run by hand'

# The excerpt must be bounded - a CSV cell is not a log file. Each line here is long enough
# that four of them exceed the cap, so truncation is genuinely exercised.
$longOut = (1..80 | ForEach-Object { "error line $_ with a great deal of padding text to make it comfortably long" }) -join "`n"
$causeLong = Get-AdfaDcdiagUnassessedCause -TestName 'T' -Outcome 'Unparsed' -StdOut $longOut -ExitCode 0
Assert-True ($causeLong.Length -lt 600) ("dcdiag cause: the excerpt is bounded (got {0} chars)" -f $causeLong.Length)
Assert-True ($causeLong -match '\.\.\.') 'dcdiag cause: a truncated excerpt says it was truncated'

$dcdiagCauses = @($causeUnparsed, $causeTail, $causeFailed, $causeSilent, $causeLong)
Assert-Equal 5 (@($dcdiagCauses).Count) 'dcdiag cause: non-vacuity - five declared unassessed cases evaluated'
Assert-Equal 0 (@($dcdiagCauses | Where-Object { [string]::IsNullOrWhiteSpace($_) }).Count) 'dcdiag cause: not one unassessed case produces an empty cause'

# --- DNS forwarders. The live-run defect: a DC with NO forwarders threw
#     "You cannot call a method on a null-valued expression" and was reported as unreadable.
Assert-Equal 0 (@(Get-AdfaForwarderAddress -Forwarder ([pscustomobject]@{ IPAddress = $null })).Count) 'Forwarders: a null IPAddress yields none configured, and does NOT throw'
Assert-Equal 0 (@(Get-AdfaForwarderAddress -Forwarder $null).Count) 'Forwarders: a null result yields none configured'
Assert-Equal 0 (@(Get-AdfaForwarderAddress -Forwarder ([pscustomobject]@{ IPAddress = @() })).Count) 'Forwarders: an empty collection yields none configured'
# Guarded, because the failure mode here is a THROW, not a wrong value: reading .Value off an
# absent property raises "The property 'Value' cannot be found on this object" under StrictMode.
# Asserting the count directly would abort the whole harness and hide every later assertion.
$fwdNoProp = $null
$fwdNoPropThrew = ''
try { $fwdNoProp = @(Get-AdfaForwarderAddress -Forwarder ([pscustomobject]@{ Other = 'x' })) }
catch { $fwdNoPropThrew = $_.Exception.Message }
Assert-Equal '' $fwdNoPropThrew 'Forwarders: an object with no IPAddress property does not throw'
Assert-Equal 0 (@($fwdNoProp).Count) 'Forwarders: an object with no IPAddress property yields none configured'
$fwdTwo = @(Get-AdfaForwarderAddress -Forwarder ([pscustomobject]@{ IPAddress = @('192.0.2.53', '192.0.2.54') }))
Assert-Equal 2 (@($fwdTwo).Count) 'Forwarders: both configured addresses are returned'
Assert-Equal '192.0.2.53' ([string]@($fwdTwo)[0]) 'Forwarders: the address text is preserved'
Assert-Equal 1 (@(Get-AdfaForwarderAddress -Forwarder ([pscustomobject]@{ IPAddress = @('192.0.2.53', $null, '192.0.2.53') })).Count) 'Forwarders: null elements are dropped and duplicates collapsed'
# Non-vacuity over the degraded shapes: every one of them must be survivable.
$fwdShapes = @(
    ([pscustomobject]@{ IPAddress = $null }),
    ([pscustomobject]@{ IPAddress = @() }),
    ([pscustomobject]@{ Other = 'x' }),
    $null
)
Assert-Equal 4 (@($fwdShapes).Count) 'Forwarders: non-vacuity - four declared degraded shapes evaluated'
$fwdSurvived = 0
foreach ($shape in $fwdShapes) {
    try { Get-AdfaForwarderAddress -Forwarder $shape | Out-Null; $fwdSurvived++ } catch { }
}
Assert-Equal 4 $fwdSurvived 'Forwarders: not one degraded shape throws'

# --- End to end through Get-AdfaDcDiagnostic. The classifier being correct is worth nothing if
#     the cause does not reach Failures, which is the column the consolidated findings read -
#     so this asserts the PLUMBING, not the logic. Stubs are local to this block and are the
#     last thing in the file.
function Test-CommandAvailable { param([string]$Name) return $true }
function Test-TcpPort { param([string]$ComputerName, [int]$Port, [int]$TimeoutMs) return $true }
function Invoke-ExternalCommand {
    param([string]$FilePath, [string]$Arguments, [string]$OutFile, [int]$TimeoutSeconds, [int]$Retries, [int]$RetryDelaySeconds)
    # 'Advertising' passes; everything else returns output with no verdict at all - the shape
    # the live run hit on VerifyEnterpriseReferences, CheckSecurityError and KnowsOfRoleHolders.
    if ($Arguments -match '/test:Advertising\b') {
        return [pscustomobject]@{ Success = $true; ExitCode = 0; Attempt = 1; Error = $null; OutFile = $OutFile
            StdOut = "Directory Server Diagnosis`n......................... DC1 passed test Advertising" }
    }
    return [pscustomobject]@{ Success = $true; ExitCode = 0; Attempt = 1; Error = $null; OutFile = $OutFile
        StdOut = "Directory Server Diagnosis`nPerforming initial setup:`nLdap search capability attribute search failed on server DC1, return value = 81" }
}
$gridRows = @(Get-AdfaDcDiagnostic -DomainControllers @('dc1.contoso.com') -TimeoutSeconds 5 -Retries 1 -RetryDelaySeconds 0)
Assert-Equal 1 (@($gridRows).Count) 'dcdiag grid: one row per DC'
$gridRow = @($gridRows)[0]
Assert-Equal 'Pass' ([string]$gridRow.DCDIAG_Advertising) 'dcdiag grid: a parseable verdict is still read correctly'
Assert-Equal 'Not Assessed' ([string]$gridRow.DCDIAG_VerifyEnterpriseReferences) 'dcdiag grid: an unreadable verdict is Not Assessed, never Pass'
Assert-True ([string]$gridRow.Failures -match 'VerifyEnterpriseReferences: NOT ASSESSED') 'dcdiag grid: the unassessed cause REACHES the Failures column'
Assert-True ([string]$gridRow.Failures -match 'return value = 81') 'dcdiag grid: the cause carries what dcdiag actually printed'
Assert-True ([string]$gridRow.Failures -match 'CheckSecurityError') 'dcdiag grid: every unassessed test is named, not just the first'
Assert-Equal 'Warning' ([string]$gridRow.Status) 'dcdiag grid: a row with unassessed cells is Warning, not Pass'
# The regression this whole fix exists to prevent: an unassessed cell with nothing recorded.
$unassessedCells = @('VerifyEnterpriseReferences', 'CheckSecurityError', 'KnowsOfRoleHolders', 'Netlogons', 'Services')
Assert-Equal 5 (@($unassessedCells).Count) 'dcdiag grid: non-vacuity - five declared unassessed tests checked'
$namedInFailures = @($unassessedCells | Where-Object { [string]$gridRow.Failures -match [regex]::Escape($_) })
Assert-Equal 5 (@($namedInFailures).Count) 'dcdiag grid: not one unassessed cell is left without a recorded cause'

Write-Host ""
Write-Host ("RESULT: {0} passed, {1} failed" -f $script:Passed, $script:Failures) -ForegroundColor $(if ($script:Failures -eq 0) { 'Green' } else { 'Red' })
Remove-Item Env:\ADFA_NO_AUTORUN -ErrorAction SilentlyContinue
if ($script:Failures -gt 0) { exit 1 }
exit 0
