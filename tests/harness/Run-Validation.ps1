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
$rows = Get-AdfaTrustHealth -DomainName 'a.local' -AdParams @{}
Assert-Equal 1 (@($rows).Count) 'One trust row returned'
Assert-Equal 'Healthy' $rows[0].Health 'Healthy forest trust, both directions verified'
Assert-Equal 'Verified' $rows[0].OutboundSecureChannel 'Outbound recorded Verified'
Assert-Equal 'Verified' $rows[0].InboundSecureChannel 'Inbound recorded Verified'

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

Write-Host ""
Write-Host ("RESULT: {0} passed, {1} failed" -f $script:Passed, $script:Failures) -ForegroundColor $(if ($script:Failures -eq 0) { 'Green' } else { 'Red' })
Remove-Item Env:\ADFA_NO_AUTORUN -ErrorAction SilentlyContinue
if ($script:Failures -gt 0) { exit 1 }
exit 0
