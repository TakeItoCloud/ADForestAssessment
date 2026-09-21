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
Write-Host ("RESULT: {0} passed, {1} failed" -f $script:Passed, $script:Failures) -ForegroundColor $(if ($script:Failures -eq 0) { 'Green' } else { 'Red' })
Remove-Item Env:\ADFA_NO_AUTORUN -ErrorAction SilentlyContinue
if ($script:Failures -gt 0) { exit 1 }
exit 0
