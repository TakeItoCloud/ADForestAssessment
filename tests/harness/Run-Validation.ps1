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
Write-Host ("RESULT: {0} passed, {1} failed" -f $script:Passed, $script:Failures) -ForegroundColor $(if ($script:Failures -eq 0) { 'Green' } else { 'Red' })
Remove-Item Env:\ADFA_NO_AUTORUN -ErrorAction SilentlyContinue
if ($script:Failures -gt 0) { exit 1 }
exit 0
