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
$sc = Test-AdfaSecureChannel -SourceDomain 'a.local' -TargetDomain 'b.local' -LiveVerify
Assert-Equal 'Verified' $sc.Result 'nltest /sc_verify success output => Verified (opt-in live test)'

function Invoke-ExternalCommand {
    param([string]$FilePath, [string]$Arguments, [string]$OutFile, [int]$TimeoutSeconds, [int]$Retries, [int]$RetryDelaySeconds)
    [pscustomobject]@{ Success = $false; ExitCode = 1; Attempt = 1; Error = $null; OutFile = $OutFile
        StdOut = "Trust Verification Status = 0x35 ERROR_NO_LOGON_SERVERS`nThe command failed" }
}
$sc = Test-AdfaSecureChannel -SourceDomain 'a.local' -TargetDomain 'b.local' -LiveVerify
Assert-Equal 'Failed' $sc.Result 'nltest /sc_verify error status => Failed (opt-in live test)'

# H19: the DEFAULT must be read-only. nltest /sc_verify resets a channel that is not working,
# so without the opt-in the tool runs /sc_query and reads the connection status line - not the
# "command completed successfully" line, which is printed for a broken channel too.
Assert-Equal '/sc_query:b.local' (Get-AdfaNltestScArgument -Domain 'b.local') 'H19: the default nltest argument is /sc_query'
Assert-Equal '/sc_verify:b.local' (Get-AdfaNltestScArgument -Domain 'b.local' -LiveVerify) 'H19: /sc_verify only with the opt-in'
$script:h19Args = @()
function Invoke-ExternalCommand {
    param([string]$FilePath, [string]$Arguments, [string]$OutFile, [int]$TimeoutSeconds, [int]$Retries, [int]$RetryDelaySeconds)
    $script:h19Args += ("{0} {1}" -f $FilePath, $Arguments)
    [pscustomobject]@{ Success = $true; ExitCode = 0; Attempt = 1; Error = $null; OutFile = $OutFile
        StdOut = "Flags: 30 HAS_IP  HAS_TIMESERV`nTrusted DC Name \\dc1.b.local`nTrusted DC Connection Status Status = 0 0x0 NERR_Success`nThe command completed successfully" }
}
$sc = Test-AdfaSecureChannel -SourceDomain 'a.local' -TargetDomain 'b.local'
Assert-Equal 'Verified' $sc.Result 'H19: /sc_query with status 0 => Verified'
Assert-Equal 0 (@($script:h19Args | Where-Object { $_ -match 'sc_verify' }).Count) 'H19: a default run never invokes /sc_verify'
Assert-True (@($script:h19Args | Where-Object { $_ -match 'nltest\.exe /sc_query:b\.local' }).Count -eq 1) 'H19: a default run invokes /sc_query once'
Assert-True ($sc.Detail -match 'not a live test') 'H19: the default result says it is not a live test'
function Invoke-ExternalCommand {
    param([string]$FilePath, [string]$Arguments, [string]$OutFile, [int]$TimeoutSeconds, [int]$Retries, [int]$RetryDelaySeconds)
    [pscustomobject]@{ Success = $true; ExitCode = 0; Attempt = 1; Error = $null; OutFile = $OutFile
        StdOut = "Trusted DC Connection Status Status = 1311 0x51f ERROR_NO_LOGON_SERVERS`nThe command completed successfully" }
}
$sc = Test-AdfaSecureChannel -SourceDomain 'a.local' -TargetDomain 'b.local'
Assert-Equal 'Failed' $sc.Result 'H19: a non-zero status is Failed even though the command "completed successfully"'
Assert-Equal 'Unparsed' ([string](Get-AdfaScQueryOutcome -Output 'The command completed successfully').Outcome) 'H19: output with no status line is Unparsed, never Ok'

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
# PORT-PLAN C16 (GAP-P3): the outbound direction is asked of a DC of the domain, which the caller names.
$rows = Get-AdfaTrustHealth -DomainName 'a.local' -AdParams @{} -SourceDc 'dc1.a.local'
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
$rows = Get-AdfaTrustHealth -DomainName 'a.local' -AdParams @{} -SourceDc 'dc1.a.local'
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

# DCSync ACE detection. Migrated by PORT-PLAN C9 from the retired Test-AdfaDcSyncAce (rights matched as
# text, principals by name) to the access mask and the SID; the same four claims.
$aclCfg = $script:Config.Acl
$getChanges = @($aclCfg['ReplicationRights'] | Where-Object { $_['Name'] -eq 'DS-Replication-Get-Changes-All' })[0]['Guid']
function New-ValAce { param([string]$Sid, [int64]$Mask, [string]$ObjectType = '', [bool]$Allow = $true, [bool]$InheritOnly = $false, [string]$Kind = '')
    if ($Kind -eq '') { if ($ObjectType -ne '') { $Kind = 'Object' } else { $Kind = 'Common' } }
    [pscustomobject]@{ Index = 0; Sid = $Sid; Allow = $Allow; Deny = (-not $Allow); Kind = $Kind; Mask = $Mask; InheritOnly = $InheritOnly; Inherited = $false; ObjectType = $ObjectType; InheritedObjectType = '' } }
function New-ValDescriptor { param($Aces = @(), [string]$Owner = 'S-1-5-32-544')
    $list = @($Aces); for ($i = 0; $i -lt $list.Count; $i++) { $list[$i].Index = $i }
    [pscustomobject]@{ Ok = $true; Class = 'Read'; Error = ''; OwnerSid = $Owner; Aces = $list; AceCount = $list.Count } }
Assert-True (@((Get-AdfaAclAceRight -Ace (New-ValAce -Sid 'S-1-5-21-1-2-3-1105' -Mask 0x100 -ObjectType $getChanges) -ObjectKind 'DomainRoot' -Config $aclCfg).Atoms) -contains 'DS-Replication-Get-Changes-All') 'DCSync ACE: Get-Changes-All extended right => detected'
$denyOnly = Get-AdfaAclAnalysis -Descriptor (New-ValDescriptor -Aces @(New-ValAce -Sid 'S-1-5-21-1-2-3-1105' -Mask 0x100 -ObjectType $getChanges -Allow $false)) -ObjectKind 'DomainRoot' -RowKey 'DCSync' -DomainSid 'S-1-5-21-1-2-3' -RootDomainSid 'S-1-5-21-1-2-3' -Config $aclCfg
Assert-Equal 0 @($denyOnly.Flagged).Count 'DCSync ACE: Deny ACE => not flagged'
Assert-Equal 0 @((Get-AdfaAclAceRight -Ace (New-ValAce -Sid 'x' -Mask 0x10) -ObjectKind 'DomainRoot' -Config $aclCfg).Atoms).Count 'DCSync ACE: ordinary read => not flagged'
$gaRight = Get-AdfaAclAceRight -Ace (New-ValAce -Sid 'x' -Mask 983551) -ObjectKind 'DomainRoot' -Config $aclCfg
Assert-True ($gaRight.GenericAll -and @($gaRight.Atoms) -contains 'DS-Replication-Get-Changes-All') 'DCSync ACE: GenericAll => detected'

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

$rFfl = Get-AdfaExchangeSeCompatibility -ForestMode 'Windows2016Forest' -ForestLevel '7' -DomainSummaries @() -DomainControllers $dcOk -SeConfig $seCfg
Assert-Equal 'Pass' ([string](Get-SeRow $rFfl 'Forest functional level').Status) 'SE FFL: Windows2016Forest => Pass'
$rFfl2 = Get-AdfaExchangeSeCompatibility -ForestMode 'Windows2012R2Forest' -ForestLevel '6' -DomainSummaries @() -DomainControllers $dcOk -SeConfig $seCfg
Assert-Equal 'Pass' ([string](Get-SeRow $rFfl2 'Forest functional level').Status) 'SE FFL: Windows2012R2Forest => Pass'
$rFflBad = Get-AdfaExchangeSeCompatibility -ForestMode 'Windows2008R2Forest' -ForestLevel '4' -DomainSummaries @() -DomainControllers $dcOk -SeConfig $seCfg
Assert-Equal 'Fail' ([string](Get-SeRow $rFflBad 'Forest functional level').Status) 'SE FFL: Windows2008R2Forest => Fail'
Assert-True ((Get-SeRow $rFflBad 'Forest functional level').Detail -match 'Windows2016Forest') 'SE FFL: the failure names what IS supported'
$rFflNone = Get-AdfaExchangeSeCompatibility -ForestMode '' -DomainSummaries @() -DomainControllers $dcOk -SeConfig $seCfg
Assert-Equal 'Not Assessed' ([string](Get-SeRow $rFflNone 'Forest functional level').Status) 'SE FFL: unreadable => Not Assessed, never Pass'

# H17: the direction comes from msDS-Behavior-Version, not the mode name. A Windows Server 2025
# level forest (10) is ABOVE the supported levels and must not be told to raise anything.
$rFfl2025 = Get-AdfaExchangeSeCompatibility -ForestMode 'Windows2025Forest' -ForestLevel '10' -DomainSummaries @() -DomainControllers $dcOk -SeConfig $seCfg
$row2025 = Get-SeRow $rFfl2025 'Forest functional level'
Assert-Equal 'Fail' ([string]$row2025.Status) 'SE FFL: level 10 (Windows Server 2025) => Fail'
Assert-True ($row2025.Detail -match 'not listed in the supportability matrix') 'SE FFL: level 10 is reported as not listed, with the matrix cited'
Assert-True ($row2025.Detail -notmatch '(?i)is raised|Set-ADForestMode') 'SE FFL: level 10 is never told to raise the level'
Assert-Equal '' ([string](Get-AdfaRecommendation -Section 'Exchange SE Compatibility' -Item 'Forest functional level' -Detail ([string]$row2025.Detail))) 'SE FFL: level 10 carries no remediation command'
$rFflNameLies = Get-AdfaExchangeSeCompatibility -ForestMode 'Windows2016Forest' -ForestLevel '4' -DomainSummaries @() -DomainControllers $dcOk -SeConfig $seCfg
Assert-Equal 'Fail' ([string](Get-SeRow $rFflNameLies 'Forest functional level').Status) 'SE FFL: the number decides even when the mode name says supported'
$rFflNameOnly = Get-AdfaExchangeSeCompatibility -ForestMode 'Windows2016Forest' -ForestLevel '' -ForestLevelError 'Access is denied' -DomainSummaries @() -DomainControllers $dcOk -SeConfig $seCfg
$rowNameOnly = Get-SeRow $rFflNameOnly 'Forest functional level'
Assert-Equal 'Not Assessed' ([string]$rowNameOnly.Status) 'SE FFL: a mode name with no readable level => Not Assessed, never Pass'
Assert-True ($rowNameOnly.Detail -match 'Access is denied') 'SE FFL: the unreadable row carries its cause'
$rFflOdd = Get-AdfaExchangeSeCompatibility -ForestMode '' -ForestLevel '9' -DomainSummaries @() -DomainControllers $dcOk -SeConfig $seCfg
$rowOdd = Get-SeRow $rFflOdd 'Forest functional level'
Assert-Equal 'Not Assessed' ([string]$rowOdd.Status) 'SE FFL: an unrecognised level => Not Assessed'
Assert-True ($rowOdd.Detail -match "'9'") 'SE FFL: the unrecognised raw value is shown'

# --- Verdict: DC operating systems. One bad DC anywhere in the forest is a blocker.
$dcMixed = @(
    [pscustomobject]@{ HostName = 'dc1.contoso.com'; OperatingSystem = 'Windows Server 2019 Datacenter'; IsReadOnly = $false },
    [pscustomobject]@{ HostName = 'dc2.contoso.com'; OperatingSystem = 'Windows Server 2012 Standard';   IsReadOnly = $false }
)
$rOs = Get-AdfaExchangeSeCompatibility -ForestMode 'Windows2016Forest' -ForestLevel '7' -DomainSummaries @() -DomainControllers $dcMixed -SeConfig $seCfg
$osRow = Get-SeRow $rOs 'Domain controller operating systems'
Assert-Equal 'Fail' ([string]$osRow.Status) 'SE DC OS: one unsupported DC => Fail for the forest'
Assert-True ($osRow.Detail -match 'dc2\.contoso\.com') 'SE DC OS: the failure names the offending DC'
Assert-True ($osRow.Detail -notmatch 'dc1\.contoso\.com') 'SE DC OS: a compliant DC is not named as a problem'

# An unreadable OS is an absent measurement, NOT an unsupported one - they are different claims.
$dcUnknown = @(
    [pscustomobject]@{ HostName = 'dc1.contoso.com'; OperatingSystem = 'Windows Server 2019'; IsReadOnly = $false },
    [pscustomobject]@{ HostName = 'dc2.contoso.com'; OperatingSystem = 'Not Assessed';        IsReadOnly = $false }
)
$rUnk = Get-AdfaExchangeSeCompatibility -ForestMode 'Windows2016Forest' -ForestLevel '7' -DomainSummaries @() -DomainControllers $dcUnknown -SeConfig $seCfg
# PORT-PLAN C16 (GAP-P20): changed from Pass. Every DC in the forest must run a supported version, so the
# gate is not given while one is unread; before v1.36.0 this was a Pass beside the row below that said so.
Assert-Equal 'Not Assessed' ([string](Get-SeRow $rUnk 'Domain controller operating systems').Status) 'SE DC OS: a readable DC does not make the gate pass while another DC is unread (C16)'
$unkRow = Get-SeRow $rUnk 'Domain controller OS - not readable'
Assert-True ($null -ne $unkRow) 'SE DC OS: an unreadable OS gets its own row, so a partial pass cannot hide it'
# Guarded: if the row is missing the assertion above has already failed, and dereferencing
# $null here would abort the whole harness instead of reporting a clean FAIL.
if ($null -ne $unkRow) {
    Assert-Equal 'Not Assessed' ([string]$unkRow.Status) 'SE DC OS: unreadable => Not Assessed, not Fail'
    Assert-True ($unkRow.Detail -match 'unverified, not compatible') 'SE DC OS: unreadable row refuses to imply compatibility'
}

$rAllUnk = Get-AdfaExchangeSeCompatibility -ForestMode 'Windows2016Forest' -ForestLevel '7' -DomainSummaries @() `
    -DomainControllers @([pscustomobject]@{ HostName = 'dc1'; OperatingSystem = 'Not Assessed'; IsReadOnly = $false }) -SeConfig $seCfg
Assert-Equal 'Not Assessed' ([string](Get-SeRow $rAllUnk 'Domain controller operating systems').Status) 'SE DC OS: nothing readable => Not Assessed, never Pass'

$rNoDc = Get-AdfaExchangeSeCompatibility -ForestMode 'Windows2016Forest' -ForestLevel '7' -DomainSummaries @() -DomainControllers @() -SeConfig $seCfg
Assert-Equal 'Not Assessed' ([string](Get-SeRow $rNoDc 'Domain controller operating systems').Status) 'SE DC OS: no DCs enumerated => Not Assessed'

# --- RODC caveat
$dcRodc = @(
    [pscustomobject]@{ HostName = 'dc1.contoso.com'; OperatingSystem = 'Windows Server 2019'; IsReadOnly = $false },
    [pscustomobject]@{ HostName = 'rodc1.contoso.com'; OperatingSystem = 'Windows Server 2019'; IsReadOnly = $true }
)
$rRodc = Get-AdfaExchangeSeCompatibility -ForestMode 'Windows2016Forest' -ForestLevel '7' -DomainSummaries @() -DomainControllers $dcRodc -SeConfig $seCfg
$rodcRow = Get-SeRow $rRodc 'Read-only domain controllers'
Assert-True ($null -ne $rodcRow) 'SE RODC: a read-only DC is reported'
if ($null -ne $rodcRow) {
    Assert-Equal 'Warning' ([string]$rodcRow.Status) 'SE RODC: reported as a Warning, not a false blocker'
    Assert-True ($rodcRow.Detail -match 'rodc1\.contoso\.com') 'SE RODC: names the read-only DC'
}
# Non-vacuity for the "no row" assertions below: prove the lookup can actually return nothing,
# so an absent row is evidence rather than an artefact of how it is queried.
Assert-True ($null -eq (Get-SeRow $rRodc 'No Such Item Exists')) 'SE RODC: non-vacuity - the row lookup returns null for an absent item'
$rNoRodc = Get-AdfaExchangeSeCompatibility -ForestMode 'Windows2016Forest' -ForestLevel '7' -DomainSummaries @() -DomainControllers $dcOk -SeConfig $seCfg
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
$rStrict = Get-AdfaExchangeSeCompatibility -ForestMode 'Windows2012R2Forest' -ForestLevel '6' -DomainSummaries @() -DomainControllers $dcOk -SeConfig $strict
Assert-Equal 'Fail' ([string](Get-SeRow $rStrict 'Forest functional level').Status) 'SE config: a narrowed override really does change the verdict'

# Remediation must reach the SE findings and must be SE-specific, not generic replication advice.
$fflRec = Get-AdfaRecommendation -Section 'Exchange SE Compatibility' -Item 'Forest functional level' `
    -Detail ([string](Get-SeRow $rFflBad 'Forest functional level').Detail)
Assert-True ($fflRec -match 'Set-ADForestMode') 'SE remediation: forest level fix names the cmdlet'
# PORT-PLAN H18: until v1.37.0 this asserted the advice called the raise irreversible (KB 322692, Windows Server 2003).
# Learn's 'Lower domain and forest functional levels' page (read 2026-11-18) says it no longer is.
Assert-True ($fflRec -match 'no longer treats raising a level as permanent' -and $fflRec -match 'cannot roll back') 'SE remediation (H18): says the raise can be lowered again unless a level-tied feature was enabled'
Assert-True ($fflRec -notmatch '(?i)one-way|forest recovery|cannot be reverted') 'SE remediation (H18): no longer calls the raise irreversible'
Assert-True ($fflRec -match 'lower-domain-forest-functional-levels' -and $fflRec -match 'read 2026-11-18') 'SE remediation (H18): cites the Learn page with its read date'
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
# Since v1.28.0 (PORT-PLAN C11) the section also returns its once-per-domain, -forest and -site rows;
# the grid rows are the ones with a DomainController column, and the per-DC invocations are the ones
# that are not Topology, CheckSDRefDom, CrossRefValidation or Intersite.
function Get-ValGrid { param($Rows) @($Rows | Where-Object { $null -ne $_.PSObject.Properties['DomainController'] }) }
Clear-AdfaDcPortCache
$gridRows = @(Get-ValGrid @(Get-AdfaDcDiagnostic -DomainControllers @('dc1.contoso.com') -TimeoutSeconds 5 -Retries 1 -RetryDelaySeconds 0))
Assert-Equal 1 (@($gridRows).Count) 'dcdiag grid: one row per DC'

# H20: the DNS and Intersite tests change state (a DNS test record is registered and deleted; a
# replication is triggered), so a default run must not invoke dcdiag for them at all.
$script:h20Args = @()
function Invoke-ExternalCommand {
    param([string]$FilePath, [string]$Arguments, [string]$OutFile, [int]$TimeoutSeconds, [int]$Retries, [int]$RetryDelaySeconds)
    $script:h20Args += $Arguments
    $name = ([regex]::Match($Arguments, '/test:(\S+)')).Groups[1].Value
    [pscustomobject]@{ Success = $true; ExitCode = 0; Attempt = 1; Error = $null; OutFile = $OutFile; StdOut = ("......................... DC1 passed test {0}" -f $name) }
}
Clear-AdfaDcPortCache
$h20Rows = @(Get-AdfaDcDiagnostic -DomainControllers @('dc1.contoso.com') -TimeoutSeconds 5 -Retries 1 -RetryDelaySeconds 0)
$h20Default = @(Get-ValGrid $h20Rows)[0]
$h20PerDc = @($script:h20Args | Where-Object { $_ -notmatch '/test:(Topology|CheckSDRefDom|CrossRefValidation|Intersite)\b' })
Assert-Equal 19 (@($h20PerDc).Count) 'H20/C11: a default run invokes dcdiag for 19 per-DC tests, not 21'
Assert-Equal 0 (@($script:h20Args | Where-Object { $_ -match '/test:(DNS|Intersite|SystemLog)\b' }).Count) 'H20/C11: a default run never invokes the DNS, SystemLog or Intersite test'
Assert-Equal 'Not Assessed' ([string]$h20Default.DCDIAG_DNS) 'H20: the DNS cell is Not Assessed by default'
Assert-Equal 'Not Assessed' ([string]$h20Default.DCDIAG_SystemLog) 'C11: the SystemLog cell is Not Assessed by default'
$h20Inter = @($h20Rows | Where-Object { $null -ne $_.PSObject.Properties['Item'] -and $_.Item -eq 'dcdiag Intersite: not run' })
Assert-True (@($h20Inter).Count -eq 1 -and [string]$h20Inter[0].Status -eq 'Not Assessed' -and [string]$h20Inter[0].NotRun -match 'IncludeDcdiagActiveTests') 'C11: Intersite is not run by default, and one row says so with the switch'
Assert-True ([string]$h20Default.NotRun -match 'IncludeDcdiagActiveTests') 'H20: the row names the switch that runs them, in its NotRun column'
Assert-Equal '' ([string]$h20Default.Failures) 'H20: nothing failed, so the Failures column - which the advice is chosen from - is empty'
$h20Finding = ConvertTo-AdfaConsolidatedFinding -Section 'DC Diagnostics' -Row ([pscustomobject]@{ DomainController = 'dc1.contoso.com'; Status = 'Fail'; Failures = 'SysVolCheck: no diagnostic lines captured'; NotRun = [string]$h20Default.NotRun }) -StatusColumn 'Status'
$h20Clean = Get-AdfaRecommendation -Section 'DC Diagnostics' -Item 'dc1.contoso.com' -Detail 'SysVolCheck: no diagnostic lines captured'
Assert-Equal $h20Clean ([string]$h20Finding.Recommendation) 'H20: the not-run note does not choose the advice for a failing row'
Assert-True ([string]$h20Finding.Detail -match 'IncludeDcdiagActiveTests') 'H20: the note still reaches the consolidated finding detail'
Assert-Equal 'Pass' ([string]$h20Default.Status) 'H20: a DC whose 19 attempted tests passed is Pass, not Warning'
$script:h20Args = @()
Clear-AdfaDcPortCache
$h20ActiveTarget = [pscustomobject]@{ HostName = 'dc1.contoso.com'; Scope = 'contoso.com'; Site = 'Default-First-Site-Name'; IsReadOnly = $false }
$h20ActiveRows = @(Get-AdfaDcDiagnostic -DomainControllers @($h20ActiveTarget) -TimeoutSeconds 5 -Retries 1 -RetryDelaySeconds 0 -IncludeActiveTests)
$h20Active = @(Get-ValGrid $h20ActiveRows)[0]
Assert-Equal 21 (@($script:h20Args | Where-Object { $_ -notmatch '/test:(Topology|CheckSDRefDom|CrossRefValidation|Intersite)\b' }).Count) 'H20/C11: with the opt-in all 21 per-DC tests are invoked'
Assert-Equal 1 (@($script:h20Args | Where-Object { $_ -match '^/test:Intersite /s:dc1\.contoso\.com /a$' }).Count) 'C11: with the opt-in Intersite runs once for the DC''s site, with /a'
Assert-Equal 'Pass' ([string]$h20Active.DCDIAG_DNS) 'H20: with the opt-in the DNS cell is read'
# C12: this stub prints a bare verdict and no summary table, so every DNS test group of the DC is Not
# Assessed - an overall passed verdict is never a Pass for a group it does not report.
$h20DnsGroups = @($h20ActiveRows | Where-Object { $null -ne $_.PSObject.Properties['Item'] -and $_.Item -match '^dcdiag DNS (Auth|Basc|Forw|Del|Dyn|RReg|Ext): dc1\.contoso\.com$' })
Assert-True (@($h20DnsGroups).Count -eq 7 -and @($h20DnsGroups | Where-Object { $_.Status -ne 'Not Assessed' -or $_.Detail -notmatch 'overall verdict' }).Count -eq 0) 'C12: with no summary table each of the seven DNS test groups is Not Assessed, quoting the overall verdict (declared population: seven groups of one DC)'
Assert-Equal 0 (@($h20Rows | Where-Object { $null -ne $_.PSObject.Properties['Item'] -and $_.Item -match '^dcdiag DNS (Auth|Basc|Forw|Del|Dyn|RReg|Ext): ' }).Count) 'C12: a default run has no DNS test-group rows'
# Restore the stub the assertions below were written against.
function Invoke-ExternalCommand {
    param([string]$FilePath, [string]$Arguments, [string]$OutFile, [int]$TimeoutSeconds, [int]$Retries, [int]$RetryDelaySeconds)
    if ($Arguments -match '/test:Advertising\b') {
        return [pscustomobject]@{ Success = $true; ExitCode = 0; Attempt = 1; Error = $null; OutFile = $OutFile
            StdOut = "Directory Server Diagnosis`n......................... DC1 passed test Advertising" }
    }
    return [pscustomobject]@{ Success = $true; ExitCode = 0; Attempt = 1; Error = $null; OutFile = $OutFile
        StdOut = "Directory Server Diagnosis`nPerforming initial setup:`nLdap search capability attribute search failed on server DC1, return value = 81" }
}
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
Write-Host "== 22. dcdiag arguments: the Intersite false Pass, and the DNS test ==" -ForegroundColor Cyan

# Intersite without /a or /e "would allow the test to run but SKIPS ACTUAL TESTING" - so every
# run before v1.13.0 reported Pass on a test that had checked nothing. A false Pass is the one
# outcome this tool exists to make impossible, so the argument is asserted, not assumed.
#   https://learn.microsoft.com/windows-server/administration/windows-commands/dcdiag (2026-09-22)
$argIntersite = Get-AdfaDcdiagArgument -TestName 'Intersite' -DomainController 'dc1.contoso.com'
Assert-True ($argIntersite -match '(?i)(^|\s)/a(\s|$)') 'dcdiag args: Intersite carries /a, without which dcdiag skips the actual testing'
Assert-True ($argIntersite -match '/test:Intersite') 'dcdiag args: Intersite still names its test'
Assert-True ($argIntersite -match '/s:dc1\.contoso\.com') 'dcdiag args: Intersite still targets the DC'

$argDns = Get-AdfaDcdiagArgument -TestName 'DNS' -DomainController 'dc1.contoso.com'
Assert-True ($argDns -match '/test:DNS') 'dcdiag args: the DNS test is requested explicitly - it does not run by default'
Assert-True ($argDns -match '/DnsAll') 'dcdiag args: /DnsAll is spelled out so a change to the default cannot silently narrow coverage'
Assert-True ($argDns -notmatch 'DnsResolveExtName') 'dcdiag args: external-name resolution is not requested - it needs internet egress and is not a directory question'

# Every other test keeps the plain form: a builder that quietly added flags everywhere would
# change what 15 existing columns measure.
$argPlain = Get-AdfaDcdiagArgument -TestName 'Advertising' -DomainController 'dc1.contoso.com'
Assert-Equal '/test:Advertising /s:dc1.contoso.com' $argPlain 'dcdiag args: an ordinary test is unchanged'
Assert-True ($argPlain -notmatch '/a\b') 'dcdiag args: /a is not sprayed onto tests that do not need it'

# Non-vacuity over the declared population: every test in the grid must build an argument that
# names itself and its DC, and only the two special cases may differ from the plain form.
$gridTests = @('Netlogons', 'Services', 'Replications', 'FsmoCheck', 'Advertising', 'SysVolCheck',
    'MachineAccount', 'ObjectsReplicated', 'RidManager', 'KccEvent', 'VerifyReferences',
    'CrossRefValidation', 'KnowsOfRoleHolders', 'Intersite', 'DFSREvent',
    'CheckSecurityError', 'VerifyEnterpriseReferences', 'DNS')
Assert-Equal 18 (@($gridTests).Count) 'dcdiag args: non-vacuity - the declared grid is 18 tests'
$argRows = @($gridTests | ForEach-Object { Get-AdfaDcdiagArgument -TestName $_ -DomainController 'dc1.contoso.com' })
Assert-Equal 18 (@($argRows | Where-Object { $_ -match '/s:dc1\.contoso\.com' }).Count) 'dcdiag args: every test targets the DC'
Assert-Equal 2 (@($argRows | Where-Object { $_ -notmatch ("^/test:\S+ /s:dc1\.contoso\.com$") }).Count) 'dcdiag args: exactly two tests deviate from the plain form'

# The grid itself must actually contain the DNS test - a builder that handles 'DNS' is worth
# nothing if nothing ever asks for it. Since v1.28.0 (PORT-PLAN C11) the list is the PerDcTests of
# the DcDiag config table, which the collector reads.
$gridNames = @($script:Config.DcDiag['PerDcTests'] | ForEach-Object { [string]$_['Test'] })
Assert-True ($gridNames -contains 'DNS') 'dcdiag grid: the DNS test is in the list the collector iterates'
$gridSrc = Get-Content -LiteralPath $target -Raw
Assert-True ($gridSrc -match "Get-AdfaConfigValue -Entry \`$Config -Name 'PerDcTests'") 'dcdiag grid: the collector reads PerDcTests from its config table'

Write-Host ""
Write-Host "== 23. Event lookback parameter, and measured clock offset ==" -ForegroundColor Cyan

# --- H13. The lookback was a pair of constants with no runtime override, on the tool built for
#     assessing a forest after a restore - so a restore older than 14 days was unreachable
#     without editing the script.
$lookParam = (Get-Command $target).Parameters['EventLookbackDays']
Assert-True ($null -ne $lookParam) 'Lookback: -EventLookbackDays exists as a runtime parameter'
if ($null -ne $lookParam) {
    $range = @($lookParam.Attributes | Where-Object { $_ -is [System.Management.Automation.ValidateRangeAttribute] } | Select-Object -First 1)
    Assert-True (@($range).Count -eq 1) 'Lookback: the parameter is range-validated'
    if (@($range).Count -eq 1) {
        Assert-Equal 1 ([int]$range[0].MinRange) 'Lookback: minimum is 1 day'
        Assert-Equal 365 ([int]$range[0].MaxRange) 'Lookback: maximum is a year - enough to reach a restore months back'
    }
}
$cfgSrc = Get-Content -LiteralPath $target -Raw
Assert-True ($cfgSrc -match 'DsEventLookbackDays\s*=\s*\$EventLookbackDays') 'Lookback: the Directory Service window reads the parameter, not a constant'
Assert-True ($cfgSrc -match 'DfsrEventLookbackDays\s*=\s*\$EventLookbackDays') 'Lookback: the DFS Replication window reads the parameter, not a constant'
# The guard that makes a long lookback honest rather than a lie: a 180-day request over a
# 30-day log must report Truncated, not a clean scan of a period the log never covered.
Assert-Equal 'Truncated' (Get-AdfaEventLogCoverage -Inspected $true -RecordCount 500 -OldestRecord (Get-Date).AddDays(-30) -WindowStart (Get-Date).AddDays(-180)) 'Lookback: a window longer than the log reports Truncated, so widening it cannot fabricate coverage'
Assert-Equal 'Covered' (Get-AdfaEventLogCoverage -Inspected $true -RecordCount 500 -OldestRecord (Get-Date).AddDays(-200) -WindowStart (Get-Date).AddDays(-180)) 'Lookback: a log that does reach back reports Covered'

# --- H14. w32tm /stripchart /rdtsc is the only external-tool output Microsoft publishes a
#     schema for, which is exactly why it is used.
$scCsv = @"
Tracking dc1.contoso.com [192.0.2.11:123].
RdtscStart, RdtscEnd, FileTime, RoundtripDelay, NtpOffset
123, 456, 133000000000000000, 0.0021234, +0.0012218
124, 457, 133000000000000001, 0.0022000, -0.0009000
"@
$scParsed = ConvertFrom-AdfaStripchartCsv -Text $scCsv
Assert-Equal 2 (@($scParsed.Offsets).Count) 'Stripchart: both sample rows are parsed'
Assert-Equal 2 ([int]$scParsed.RowsParsed) 'Stripchart: the parsed count matches'
Assert-True ([Math]::Abs(([double]@($scParsed.Offsets)[0]) - 0.0012218) -lt 0.0000001) 'Stripchart: a signed offset is read as a number'
Assert-Equal 2 (@($scParsed.Delays).Count) 'Stripchart: the round-trip delays are read too'
# The header is not assumed to be the first line - w32tm prints a Tracking line before it.
Assert-True (@(ConvertFrom-AdfaStripchartCsv -Text $scCsv).Offsets.Count -gt 0) 'Stripchart: a preamble line before the header does not defeat the parse'
# A timed-out sample must be DROPPED, never coerced: zero would mean perfectly synchronised.
$scTimeout = "Tracking dc9.contoso.com.`nRdtscStart, RdtscEnd, FileTime, RoundtripDelay, NtpOffset`nRequest timed out.`n"
$scTo = ConvertFrom-AdfaStripchartCsv -Text $scTimeout
Assert-Equal 0 (@($scTo.Offsets).Count) 'Stripchart: a timed-out sample yields no offset, rather than an offset of zero'
# A row with the RIGHT number of columns but a non-numeric offset. The short-row above is
# rejected by the column count before the number parse is reached, so without this fixture the
# TryParse guard is never exercised - and it is the one that stops a junk value being read as an
# offset of zero, i.e. as "perfectly synchronised".
$scBadNum = ConvertFrom-AdfaStripchartCsv -Text @"
RdtscStart, RdtscEnd, FileTime, RoundtripDelay, NtpOffset
123, 456, 133000000000000000, 0.002, error
124, 457, 133000000000000001, 0.002, +0.5
"@
Assert-Equal 1 (@($scBadNum.Offsets).Count) 'Stripchart: a full-width row with a non-numeric offset is dropped, not read as zero'
Assert-Equal 2 ([int]$scBadNum.RowsSeen) 'Stripchart: the dropped row is still counted as seen, so the loss is visible'
Assert-True ([Math]::Abs(([double]@($scBadNum.Offsets)[0]) - 0.5) -lt 0.0000001) 'Stripchart: the good row in the same output is still read'

$scNoHeader = ConvertFrom-AdfaStripchartCsv -Text 'no csv here at all'
Assert-Equal 0 (@($scNoHeader.Offsets).Count) 'Stripchart: output with no header yields nothing'
$scNull = ConvertFrom-AdfaStripchartCsv -Text $null
Assert-Equal 0 (@($scNull.Offsets).Count) 'Stripchart: null input yields nothing'

# --- The verdict. Two thresholds, and the finding must say which is whose.
$skFail = Get-AdfaClockOffsetVerdict -DomainController 'dc1.contoso.com' -Offsets @(400.0) -WarnSeconds 60 -FailSeconds 300
Assert-Equal 'Fail' ([string]$skFail.Status) 'Offset: past the Kerberos maximum is a Fail'
Assert-True ($skFail.Detail -match '300s Kerberos maximum') 'Offset: the Fail cites the vendor limit'
$skWarn = Get-AdfaClockOffsetVerdict -DomainController 'dc1.contoso.com' -Offsets @(90.0) -WarnSeconds 60 -FailSeconds 300
Assert-Equal 'Warning' ([string]$skWarn.Status) 'Offset: past our bar but inside the vendor limit is a Warning'
Assert-True ($skWarn.Detail -match 'OURS and not a vendor threshold') 'Offset: the Warning says plainly whose threshold it is'
$skPass = Get-AdfaClockOffsetVerdict -DomainController 'dc1.contoso.com' -Offsets @(0.4, -0.2) -WarnSeconds 60 -FailSeconds 300
Assert-Equal 'Pass' ([string]$skPass.Status) 'Offset: a small offset passes'
Assert-True ($skPass.Detail -match 'not proof the forest''s time is correct') 'Offset: the Pass states what it does NOT prove'
# A negative offset is just as bad as a positive one.
Assert-Equal 'Fail' ([string](Get-AdfaClockOffsetVerdict -DomainController 'a' -Offsets @(-400.0) -WarnSeconds 60 -FailSeconds 300).Status) 'Offset: a DC behind by 400s fails exactly as one ahead by 400s'
# The WORST sample, not the mean - averaging +4 and -4 would report a swinging clock as perfect.
$skSwing = Get-AdfaClockOffsetVerdict -DomainController 'a' -Offsets @(400.0, -400.0) -WarnSeconds 60 -FailSeconds 300
Assert-Equal 'Fail' ([string]$skSwing.Status) 'Offset: a clock swinging either side is judged on its worst sample, not the mean'

$skNone = Get-AdfaClockOffsetVerdict -DomainController 'a' -Offsets @() -ErrorText 'every NTP sample timed out'
Assert-Equal 'Not Assessed' ([string]$skNone.Status) 'Offset: no usable sample is Not Assessed, never Pass'
Assert-True ($skNone.Detail -match 'timed out') 'Offset: the cause is carried into the finding'
Assert-True ($skNone.Detail -match 'zero would mean') 'Offset: says why a bad sample is discarded rather than read as zero'
Assert-Equal 'Not Assessed' ([string](Get-AdfaClockOffsetVerdict -DomainController 'a' -Queried $false -ErrorText 'RPC (135) was not reachable').Status) 'Offset: an unreachable DC is Not Assessed'
Assert-True ((Get-AdfaClockOffsetVerdict -DomainController 'a' -Queried $false).Detail -match 'unmeasured offset is not a small one') 'Offset: refuses to imply an unmeasured clock is fine'

$skDegraded = @($skNone,
    (Get-AdfaClockOffsetVerdict -DomainController 'a' -Queried $false),
    (Get-AdfaClockOffsetVerdict -DomainController 'a' -Offsets @('not a number')),
    $skWarn, $skFail)
Assert-Equal 5 (@($skDegraded).Count) 'Offset: non-vacuity - five declared degraded or failing cases evaluated'
Assert-Equal 0 (@($skDegraded | Where-Object { $_.Status -eq 'Pass' }).Count) 'Offset: not one of them reports Pass'

# --- Config: the vendor number and ours, kept apart and sourced.
Assert-Equal 300 ([int]$script:Config.ClockSkew.KerberosMaxSeconds) 'Config: the Kerberos maximum is the vendor 300s'
Assert-True ([double]$script:Config.ClockSkew.WarnSeconds -lt 300) 'Config: our warning bar sits below the vendor cliff'
Assert-True ($script:Config.ClockSkew.KerberosUrl -match '^https://learn\.microsoft\.com/') 'Config: the Kerberos limit records its source'
Assert-True ($script:Config.ClockSkew.StripchartUrl -match '^https://learn\.microsoft\.com/') 'Config: the stripchart contract records its source'
Assert-Equal '2026-09-22' ([string]$script:Config.ClockSkew.ReadDate) 'Config: the read date is recorded'

Write-Host ""
Write-Host "== 24. Cross-domain DC enrichment: the referral, and advice that matches the cause ==" -ForegroundColor Cyan

# Found on a live four-domain forest: the inventory enriched via Get-ADComputer without -Server,
# so a child-domain DN was asked of a forest-root DC, which answers with an LDAP referral.
# Every child-domain DC lost its OperatingSystem and the SE verdict called them "unverified,
# not compatible". The collector fix is guarded end-to-end by Run-SmokeTest, whose Get-ADComputer
# stub refuses a call with no -Server exactly as the directory did. These are the pure parts.
$srcEnrich = Get-Content -LiteralPath $target -Raw
Assert-True ($srcEnrich -match '\$cp = @\{\} \+ \$p') 'Enrichment: the Get-ADComputer splat inherits $p, which carries -Server for the domain being enumerated'
Assert-True ($srcEnrich -notmatch '\$cp = @\{\} \+ \$AdParams') 'Enrichment: it no longer copies $AdParams, which had no -Server'

# The advice must match what actually happened. A referral is NOT a credentials problem, and
# telling an operator to re-run with other credentials sends them where there is nothing to find.
$advRef = Get-AdfaEnrichmentFailureAdvice -Causes @('A referral was returned from the server')
Assert-True ($advRef -match 'LDAP referral') 'Advice: a referral is named as a referral'
Assert-True ($advRef -match "does not hold that domain's naming context") 'Advice: explains what a referral actually means'
Assert-True ($advRef -match 'not a credentials problem') 'Advice: rules out the wrong cause explicitly'
Assert-True ($advRef -notmatch 're-run with credentials') 'Advice: a referral does NOT get the credentials advice'

$advDenied = Get-AdfaEnrichmentFailureAdvice -Causes @('Access is denied')
Assert-True ($advDenied -match 're-run with credentials') 'Advice: an access failure DOES get the credentials advice'
Assert-True ($advDenied -notmatch 'LDAP referral') 'Advice: an access failure is not described as a referral'

# Both at once - a forest can produce both, and neither may be dropped.
$advBoth = Get-AdfaEnrichmentFailureAdvice -Causes @('A referral was returned from the server', 'Access is denied')
Assert-True ($advBoth -match 'LDAP referral') 'Advice: with both causes, the referral is still named'
Assert-True ($advBoth -match 're-run with credentials') 'Advice: with both causes, the credentials advice is still given'

# An error the tool does not recognise is QUOTED, never interpreted.
$advOther = Get-AdfaEnrichmentFailureAdvice -Causes @('The server is not operational')
Assert-True ($advOther -match 'Reported by the directory') 'Advice: an unrecognised error is attributed to the directory'
Assert-True ($advOther -match 'The server is not operational') 'Advice: an unrecognised error is quoted verbatim, not guessed at'
Assert-True ($advOther -notmatch 'LDAP referral' -and $advOther -notmatch 're-run with credentials') 'Advice: an unrecognised error attracts neither canned explanation'

Assert-Equal '' (Get-AdfaEnrichmentFailureAdvice -Causes @()) 'Advice: no cause yields no advice, rather than an empty sentence'
Assert-Equal '' (Get-AdfaEnrichmentFailureAdvice -Causes @('', '   ')) 'Advice: blank causes yield no advice'
Assert-Equal '' (Get-AdfaEnrichmentFailureAdvice -Causes $null) 'Advice: a null cause list is survivable'
# Repeated identical errors across many DCs must not repeat in the text.
$advDupe = Get-AdfaEnrichmentFailureAdvice -Causes @('A referral was returned from the server', 'A referral was returned from the server')
Assert-Equal 1 ([regex]::Matches($advDupe, 'A referral was returned from the server').Count) 'Advice: an identical cause on many DCs is reported once, not once per DC'

$advCases = @($advRef, $advDenied, $advBoth, $advOther)
Assert-Equal 4 (@($advCases).Count) 'Advice: non-vacuity - four declared cause shapes evaluated'
Assert-Equal 0 (@($advCases | Where-Object { [string]::IsNullOrWhiteSpace($_) }).Count) 'Advice: every declared cause shape produces advice'

# --- The FAILURE path through the collector. Run-SmokeTest proves the success path, where
#     EnrichmentError is empty either way - so without this the "carry the cause" fix is
#     untested and a mutation removing it survives. These stubs are last in the file.
function Get-ADDomainController {
    param([Parameter(ValueFromRemainingArguments)]$a)
    [pscustomobject]@{ HostName = 'dc9.contoso.com'; Name = 'DC9'; Site = 'HQ'; IPv4Address = '192.0.2.9'
        IsGlobalCatalog = $true; IsReadOnly = $false; ComputerObjectDN = 'CN=DC9,OU=Domain Controllers,DC=child,DC=contoso,DC=com' }
}
function Get-ADComputer { param([Parameter(ValueFromRemainingArguments)]$a) throw 'A referral was returned from the server' }
$invFail = @(Get-AdfaDomainControllerInventory -DomainName 'child.contoso.com' -AdParams @{} -WarningAction SilentlyContinue)
Assert-Equal 1 (@($invFail).Count) 'Enrichment failure: the DC is still inventoried, not dropped'
if (@($invFail).Count -eq 1) {
    $rowFail = @($invFail)[0]
    Assert-Equal 'Not Assessed' ([string]$rowFail.OperatingSystem) 'Enrichment failure: the OS is Not Assessed, never invented'
    Assert-True ($rowFail.PSObject.Properties.Name -contains 'EnrichmentError') 'Enrichment failure: the row exposes EnrichmentError'
    Assert-True ([string]$rowFail.EnrichmentError -match 'referral') 'Enrichment failure: the CAUSE is carried into the row, not left in the warning stream'
    # The facts that come from Get-ADDomainController must survive an enrichment failure -
    # they are what SiteGc reads, and it kept working on the live forest for this reason.
    Assert-Equal $true ([bool]$rowFail.IsGlobalCatalog) 'Enrichment failure: IsGlobalCatalog still populated, so per-site GC coverage is unaffected'
    Assert-Equal 'HQ' ([string]$rowFail.Site) 'Enrichment failure: Site still populated'
}

Write-Host ""
Write-Host "== 25. DC disk space (verdict, path-to-volume, rows, config override) ==" -ForegroundColor Cyan

# PORT-PLAN C2. Pure logic only: nothing here opens a session, and the AD stubs defined just
# above are not used. The collector and the CIM seam are covered by the Pester suite and by
# Run-SmokeTest, which runs them through Invoke-Main.
function Assert-Throws {
    param([Parameter(Mandatory)][scriptblock]$Script, [Parameter(Mandatory)][string]$Pattern, [Parameter(Mandatory)][string]$Name)
    $message = $null
    try { & $Script | Out-Null } catch { $message = [string]$_.Exception.Message }
    if ($null -eq $message) { $script:Failures++; Write-Host ("  [FAIL] {0} (nothing was thrown)" -f $Name) -ForegroundColor Red; return }
    if ($message -match $Pattern) { $script:Passed++; Write-Host ("  [PASS] {0}" -f $Name) -ForegroundColor Green }
    else { $script:Failures++; Write-Host ("  [FAIL] {0} (threw '{1}', expected to match '{2}')" -f $Name, $message, $Pattern) -ForegroundColor Red }
}

$diskCfg = $script:Config.DcDisk
$gb = [double]1073741824
function Get-DiskVerdict {
    param([double]$CapacityGB, [double]$FreeGB, [double]$WarnGB = 0, [double]$FailGB = 0)
    Get-AdfaDiskSpaceVerdict -CapacityBytes ([uint64]($CapacityGB * $gb)) -FreeBytes ([uint64]($FreeGB * $gb)) `
        -WarnBelowPercent 20 -FailBelowPercent 10 -WarnBelowFreeGB $WarnGB -FailBelowFreeGB $FailGB
}

# --- Config table: the thresholds are labelled for what they are.
Assert-Equal 'tool default, not a Microsoft value' ([string]$diskCfg.ThresholdSource) 'Disk config: thresholds are labelled as tool defaults, not Microsoft values'
Assert-Equal 3 (@($diskCfg.Paths).Count) 'Disk config: declared population - three registry values, one per role'
Assert-Equal 'NTDS database|NTDS logs|SYSVOL' (@($diskCfg.Paths | ForEach-Object { [string]$_.Role }) -join '|') 'Disk config: the three roles are the database, the logs and SYSVOL'
Assert-Equal 'DSA Database File|Database Log Files Path|SysVol' (@($diskCfg.Paths | ForEach-Object { [string]$_.ValueName }) -join '|') 'Disk config: the three value names are the ones Microsoft documents'

# --- Verdict boundaries. "Below" is strict.
Assert-Equal 'Fail' ([string](Get-DiskVerdict 1000 99.9).Status) 'Disk verdict: 9.99 % free is Fail'
Assert-Equal 'Warning' ([string](Get-DiskVerdict 1000 100).Status) 'Disk verdict: exactly 10 % free is Warning, not Fail'
Assert-Equal 'Warning' ([string](Get-DiskVerdict 1000 199.9).Status) 'Disk verdict: 19.99 % free is Warning'
Assert-Equal 'Pass' ([string](Get-DiskVerdict 1000 200).Status) 'Disk verdict: exactly 20 % free is Pass'
Assert-Equal 'Warning' ([string](Get-DiskVerdict 20 4.9 5 2).Status) 'Disk verdict: 24.5 % free but under the 5 GB floor is Warning'
Assert-Equal 'Floor' ([string](Get-DiskVerdict 20 4.9 5 2).Trigger) 'Disk verdict: the floor is named as what fired'
Assert-Equal 'Pass' ([string](Get-DiskVerdict 20 5 5 2).Status) 'Disk verdict: exactly on the floor is not below it'
Assert-Equal 'Fail' ([string](Get-DiskVerdict 8 1.9 5 2).Status) 'Disk verdict: under the 2 GB floor is Fail whatever the percentage'
Assert-Equal 'Pass' ([string](Get-DiskVerdict 20 4.9 0 0).Status) 'Disk verdict: a floor of 0 is not applied'
Assert-Equal 'Both' ([string](Get-DiskVerdict 30 1 5 2).Trigger) 'Disk verdict: both tests failing is reported as both'
Assert-True ([string](Get-DiskVerdict 120 60).Detail -match '50\.00 % free: 60\.00 GB free of 120\.00 GB') 'Disk verdict: the figures are stated, with a point as the decimal separator on any host'

# --- Fail closed: nothing unusable is ever a Pass.
$diskBad = @(
    (Get-AdfaDiskSpaceVerdict -CapacityBytes $null -FreeBytes 100 -WarnBelowPercent 20 -FailBelowPercent 10),
    (Get-AdfaDiskSpaceVerdict -CapacityBytes 0 -FreeBytes 0 -WarnBelowPercent 20 -FailBelowPercent 10),
    (Get-AdfaDiskSpaceVerdict -CapacityBytes 'abc' -FreeBytes 100 -WarnBelowPercent 20 -FailBelowPercent 10),
    (Get-AdfaDiskSpaceVerdict -CapacityBytes 1000 -FreeBytes $null -WarnBelowPercent 20 -FailBelowPercent 10),
    (Get-AdfaDiskSpaceVerdict -CapacityBytes 1000 -FreeBytes 2000 -WarnBelowPercent 20 -FailBelowPercent 10)
)
Assert-Equal 5 (@($diskBad).Count) 'Disk verdict: non-vacuity - five declared unusable shapes evaluated'
Assert-Equal 5 (@($diskBad | Where-Object { [string]$_.Status -eq 'Not Assessed' }).Count) 'Disk verdict: a missing, zero, non-numeric or inconsistent figure is Not Assessed, never Pass'
Assert-Equal 'Fail' ([string](Get-AdfaDiskSpaceVerdict -CapacityBytes '536870912000' -FreeBytes '42949672960' -WarnBelowPercent 20 -FailBelowPercent 10).Status) 'Disk verdict: a deserialized string value is read like a number (8 % free)'

# --- Path to volume: longest mount path wins.
$diskVols = @(
    [pscustomobject]@{ Name = 'C:\'; DeviceID = '\\?\Volume{c}\'; DriveType = [uint32]3; Capacity = [uint64](120 * $gb); FreeSpace = [uint64](60 * $gb) }
    [pscustomobject]@{ Name = 'D:\'; DeviceID = '\\?\Volume{d}\'; DriveType = [uint32]3; Capacity = [uint64](100 * $gb); FreeSpace = [uint64](15 * $gb) }
    [pscustomobject]@{ Name = 'D:\Mount\NTDS\'; DeviceID = '\\?\Volume{m}\'; DriveType = [uint32]3; Capacity = [uint64](100 * $gb); FreeSpace = [uint64](5 * $gb) }
    [pscustomobject]@{ Name = '\\?\Volume{r}\'; DeviceID = '\\?\Volume{r}\'; DriveType = [uint32]3; Capacity = [uint64](1 * $gb); FreeSpace = [uint64](0) }
    [pscustomobject]@{ Name = 'E:\'; DeviceID = '\\?\Volume{e}\'; DriveType = [uint32]5; Capacity = $null; FreeSpace = $null }
)
Assert-Equal 'C:\' ([string](Resolve-AdfaVolumeForPath -Path 'c:\windows\ntds\ntds.dit' -Volumes $diskVols).Volume.Name) 'Disk volume: a path maps to its drive, ignoring case'
Assert-Equal 'D:\Mount\NTDS\' ([string](Resolve-AdfaVolumeForPath -Path 'D:\Mount\NTDS\ntds.dit' -Volumes $diskVols).Volume.Name) 'Disk volume: a mounted folder beats the drive it is mounted on'
Assert-Equal 'D:\' ([string](Resolve-AdfaVolumeForPath -Path 'D:\Mount\NTDSX\ntds.dit' -Volumes $diskVols).Volume.Name) 'Disk volume: a folder that only starts with the same letters is not under the mounted folder'
Assert-True (-not (Resolve-AdfaVolumeForPath -Path 'E:\NTDS' -Volumes $diskVols).Resolved) 'Disk volume: a volume that is not a local disk is never matched'
Assert-True (-not (Resolve-AdfaVolumeForPath -Path 'C:\Windows\NTDS' -Volumes @()).Resolved) 'Disk volume: with no volumes nothing is matched'

# --- One DC, mixed result: three volumes, three verdicts, and each role exactly once.
function New-DiskPath {
    param([string]$Role, [string]$Value, $ReturnValue = 0)
    [pscustomobject]@{ Role = $Role; Key = 'k'; ValueName = 'v'; Read = ($ReturnValue -eq 0 -and $Value -ne ''); ReturnValue = $ReturnValue; Value = $Value
        Method = 'GetStringValue'; Error = ''; ErrorCode = ''; ExpandedReturnValue = $null }
}
$diskRaw = [pscustomobject]@{ Ok = $true; Protocol = 'Wsman'; Error = ''; ErrorCode = ''; VolumesOk = $true; Volumes = $diskVols; VolumeError = ''; VolumeErrorCode = ''
    Paths = @((New-DiskPath 'NTDS database' 'D:\Mount\NTDS\ntds.dit'), (New-DiskPath 'NTDS logs' 'D:\Logs'), (New-DiskPath 'SYSVOL' 'C:\Windows\SYSVOL\sysvol')) }
$diskRows = @(Get-AdfaDcDiskFinding -DomainController 'dc1.contoso.com' -Scope 'contoso.com' -Raw $diskRaw -Config $diskCfg)
Assert-Equal 3 (@($diskRows).Count) 'Disk rows: one row per distinct volume (declared population: three volumes)'
Assert-Equal 'Fail,Pass,Warning' ((@($diskRows | ForEach-Object { [string]$_.Status }) | Sort-Object) -join ',') 'Disk rows: a mixed result is reported as mixed'
foreach ($role in @('NTDS database', 'NTDS logs', 'SYSVOL')) {
    Assert-Equal 1 (@($diskRows | Where-Object { [string]$_.Item -match [regex]::Escape($role) }).Count) ("Disk rows: role '{0}' is accounted for by exactly one row" -f $role)
}
$diskDb = @($diskRows | Where-Object { [string]$_.Item -match 'NTDS database' })[0]
Assert-Equal 'Fail' ([string]$diskDb.Status) 'Disk rows: the database volume at 5 % free is Fail'
Assert-True ([string]$diskDb.Detail -match 'tool default, not a Microsoft value') 'Disk rows: the finding text labels the thresholds as tool defaults'
Assert-True ([string]$diskDb.Detail -match 'event 1393') 'Disk rows: a failing database volume states the documented consequence'
Assert-True ([string]$diskDb.NotRun -match '110 %' -and [string]$diskDb.Detail -notmatch '110 %') 'Disk rows: the not-measured note is in NotRun, never in the text the advice is chosen from'
Assert-Equal 'contoso.com' ([string]$diskDb.Scope) 'Disk rows: the row carries its domain'

# --- An absent value, a refusal and an unreadable volume list are three different results.
$diskGap = [pscustomobject]@{ Ok = $true; Protocol = 'Wsman'; Error = ''; ErrorCode = ''; VolumesOk = $true; Volumes = $diskVols; VolumeError = ''; VolumeErrorCode = ''
    Paths = @((New-DiskPath 'NTDS database' 'C:\Windows\NTDS\ntds.dit'), (New-DiskPath 'NTDS logs' '' 5), (New-DiskPath 'SYSVOL' '' 2)) }
$gapRows = @(Get-AdfaDcDiskFinding -DomainController 'dc1.contoso.com' -Scope 'contoso.com' -Raw $diskGap -Config $diskCfg)
$gapLogs = @($gapRows | Where-Object { [string]$_.Item -match 'NTDS logs path' })[0]
$gapSysvol = @($gapRows | Where-Object { [string]$_.Item -match 'SYSVOL path' })[0]
Assert-True ([string]$gapLogs.Status -eq 'Not Assessed' -and [string]$gapLogs.Detail -match '^Access denied') 'Disk rows: a refused registry read (5) is Not Assessed as access denied'
Assert-True ([string]$gapSysvol.Status -eq 'Not Assessed' -and [string]$gapSysvol.Detail -match '^Not found: StdRegProv returned 2,' -and [string]$gapSysvol.Detail -match 'the registry key not existing') 'Disk rows: an absent registry KEY (2) is Not Assessed as not found, not as access denied'
Assert-True ([string]$gapSysvol.Detail -match 'No default location is assumed') 'Disk rows: an absent value is not replaced by a default path'
# The provider was measured to return 1, not 2, for a value that does not exist under a key that
# does - the case a DC with an unset value produces. It must be named, not left as a bare code.
$diskUnset = [pscustomobject]@{ Ok = $true; Protocol = 'Wsman'; Error = ''; ErrorCode = ''; VolumesOk = $true; Volumes = $diskVols; VolumeError = ''; VolumeErrorCode = ''
    Paths = @((New-DiskPath 'NTDS database' 'C:\Windows\NTDS\ntds.dit'), (New-DiskPath 'NTDS logs' '' 1), (New-DiskPath 'SYSVOL' '' ([uint32]2147749893))) }
$unsetRows = @(Get-AdfaDcDiskFinding -DomainController 'dc1.contoso.com' -Scope 'contoso.com' -Raw $diskUnset -Config $diskCfg)
$unsetLogs = @($unsetRows | Where-Object { [string]$_.Item -match 'NTDS logs path' })[0]
$unsetSysvol = @($unsetRows | Where-Object { [string]$_.Item -match 'SYSVOL path' })[0]
Assert-True ([string]$unsetLogs.Status -eq 'Not Assessed' -and [string]$unsetLogs.Detail -match '^Not found: StdRegProv returned 1,' -and [string]$unsetLogs.Detail -match 'the value not being set') 'Disk rows: a registry value that is not set (1) is Not Assessed as not found, not as an uninterpreted read failure'
Assert-True ([string]$unsetLogs.Detail -match 'measured, not published by Microsoft') 'Disk rows: the reading of 1 and 2 is labelled as measured, not as a Microsoft statement'
Assert-True ([string]$unsetLogs.Detail -match 'No default location is assumed') 'Disk rows: a value that is not set is not replaced by a default path'
Assert-True ([string]$unsetSysvol.Status -eq 'Not Assessed' -and [string]$unsetSysvol.Detail -match '^The value is present but is not a string' -and [string]$unsetSysvol.Detail -match 'wbemErrTypeMismatch') 'Disk rows: a WbemErrorEnum type mismatch is named as a value that is not a string'
$otherCode = Resolve-AdfaDcDiskPathRead -Entry (New-DiskPath 'SYSVOL' '' 87)
Assert-True (-not $otherCode.Usable -and [string]$otherCode.Cause -match '^Read failed: StdRegProv returned 87 \(0x00000057\)\.' -and [string]$otherCode.Cause -match 'not interpreted') 'Disk rows: any other return code is quoted, decimal and hex, and not interpreted'
$wbemDenied = Resolve-AdfaDcDiskPathRead -Entry (New-DiskPath 'SYSVOL' '' ([uint32]2147749891))
Assert-True (-not $wbemDenied.Usable -and [string]$wbemDenied.Cause -match '^Access denied: StdRegProv returned 2147749891 \(0x80041003\)') 'Disk rows: the WbemErrorEnum refusal code is access denied, as 5 is'
Assert-Equal 1 (@($gapRows | Where-Object { [string]$_.Status -eq 'Pass' }).Count) 'Disk rows: only the role that was read is judged'
# --- A failing volume that holds ONLY the logs carries the documented consequence too.
$diskLogsOnly = [pscustomobject]@{ Ok = $true; Protocol = 'Wsman'; Error = ''; ErrorCode = ''; VolumesOk = $true; VolumeError = ''; VolumeErrorCode = ''
    Volumes = @(
        [pscustomobject]@{ Name = 'C:\'; DeviceID = 'vc'; DriveType = [uint32]3; Capacity = [uint64](100 * $gb); FreeSpace = [uint64](50 * $gb) }
        [pscustomobject]@{ Name = 'L:\'; DeviceID = 'vl'; DriveType = [uint32]3; Capacity = [uint64](100 * $gb); FreeSpace = [uint64](3 * $gb) }
        [pscustomobject]@{ Name = 'S:\'; DeviceID = 'vs'; DriveType = [uint32]3; Capacity = [uint64](100 * $gb); FreeSpace = [uint64](3 * $gb) }
    )
    Paths = @((New-DiskPath 'NTDS database' 'C:\Windows\NTDS\ntds.dit'), (New-DiskPath 'NTDS logs' 'L:\Logs'), (New-DiskPath 'SYSVOL' 'S:\SYSVOL\sysvol')) }
$logsOnlyRows = @(Get-AdfaDcDiskFinding -DomainController 'dc1.contoso.com' -Scope 'contoso.com' -Raw $diskLogsOnly -Config $diskCfg)
$logsOnly = @($logsOnlyRows | Where-Object { [string]$_.Item -match 'L:\\ \(NTDS logs\)' })
$sysvolOnly = @($logsOnlyRows | Where-Object { [string]$_.Item -match 'S:\\ \(SYSVOL\)' })
Assert-True (@($logsOnly).Count -eq 1 -and [string]$logsOnly[0].Status -eq 'Fail' -and [string]$logsOnly[0].Detail -match 'event 1393') 'Disk rows: a failing volume that holds only the logs states the documented consequence'
Assert-True (@($sysvolOnly).Count -eq 1 -and [string]$sysvolOnly[0].Status -eq 'Fail' -and [string]$sysvolOnly[0].Detail -notmatch '1393') 'Disk rows: a failing volume that holds only SYSVOL does not claim it'

$diskNoVol = [pscustomobject]@{ Ok = $true; Protocol = 'Wsman'; Error = ''; ErrorCode = ''; VolumesOk = $false; Volumes = @(); VolumeError = 'The operation has timed out.'; VolumeErrorCode = ''
    Paths = $diskRaw.Paths }
$noVolRows = @(Get-AdfaDcDiskFinding -DomainController 'dc1.contoso.com' -Scope 'contoso.com' -Raw $diskNoVol -Config $diskCfg)
Assert-Equal 3 (@($noVolRows | Where-Object { [string]$_.Status -eq 'Not Assessed' }).Count) 'Disk rows: with no volume list every role is Not Assessed, none is Pass'

# --- Advice: the section's own entry answers, whatever words the row or a file path contains.
$diskRec = Get-AdfaRecommendation -Section 'DC Disk Space' -Item 'Disk space: dc1.contoso.com C:\ (NTDS database, NTDS logs, SYSVOL)' -Detail 'Threshold source: C:\Backup\replication\sysvol-dfsr.json'
Assert-True ($diskRec -match 'Move unrelated files') 'Disk advice: a low-space row gets the steps Microsoft gives for a database volume short of space'
Assert-True ($diskRec -notmatch 'D4|dfsrmig|repadmin|wbadmin') 'Disk advice: a row naming SYSVOL is not answered with the DFSR restore advice'

# --- The DcDisk validator.
$diskMerged = Merge-AdfaDcDiskConfig -BaseConfig $diskCfg -Override @{ WarnBelowPercent = 25 } -OverrideSource 'C:\cfg\disk.json'
Assert-Equal 25 ([double]$diskMerged.WarnBelowPercent) 'Disk override: a supplied threshold replaces the built-in one'
Assert-Equal 10 ([double]$diskMerged.FailBelowPercent) 'Disk override: a threshold the file omits keeps its built-in value'
Assert-True ([string]$diskMerged.ThresholdSource -match 'C:\\cfg\\disk\.json.* for WarnBelowPercent; tool default, not a Microsoft value, for FailBelowPercent') 'Disk override: the file is cited for the key it supplied and the rest stay labelled tool defaults'
Assert-Equal 20 ([double]$diskCfg.WarnBelowPercent) 'Disk override: the built-in table is not modified by a merge'
Assert-Throws { Merge-AdfaDcDiskConfig -BaseConfig $diskCfg -Override @{ RpcPort = 1135 } -OverrideSource 'C:\cfg\disk.json' } "names 'RpcPort'. The ports of this section cannot be set from a file" 'Disk override: a port is refused since v1.34.0 - the CIM session always uses the default ports (PORT-PLAN C3g)'
Assert-Throws { Merge-AdfaDcDiskConfig -BaseConfig $diskCfg -Override 'abc' } 'single object' 'Disk override: a string is refused'
Assert-Throws { Merge-AdfaDcDiskConfig -BaseConfig $diskCfg -Override @(1, 2) } 'single object' 'Disk override: an array is refused'
Assert-Throws { Merge-AdfaDcDiskConfig -BaseConfig $diskCfg -Override ('{}' | ConvertFrom-Json) } 'empty object' 'Disk override: an empty object is refused'
Assert-Throws { Merge-AdfaDcDiskConfig -BaseConfig $diskCfg -Override @{ Typo = 1 } } "unknown key 'Typo'" 'Disk override: an unknown key is refused'
Assert-Throws { Merge-AdfaDcDiskConfig -BaseConfig $diskCfg -Override @{ Paths = @() } } "unknown key 'Paths'" 'Disk override: the registry values the tool reads cannot be redirected from a file'
Assert-Throws { Merge-AdfaDcDiskConfig -BaseConfig $diskCfg -Override ('{ "WarnBelowPercent": null }' | ConvertFrom-Json) } 'null' 'Disk override: a null is refused'
Assert-Throws { Merge-AdfaDcDiskConfig -BaseConfig $diskCfg -Override @{ WarnBelowPercent = '25' } } 'JSON number' 'Disk override: a number written as a string is refused'
Assert-Throws { Merge-AdfaDcDiskConfig -BaseConfig $diskCfg -Override @{ WarnBelowPercent = 101 } } '0 to 100' 'Disk override: a percentage above 100 is refused'
Assert-Throws { Merge-AdfaDcDiskConfig -BaseConfig $diskCfg -Override @{ FailBelowPercent = 25 } } 'FailBelowPercent.*WarnBelowPercent' 'Disk override: Fail above the built-in Warning threshold is refused on the merged table'
Assert-Throws { Merge-AdfaDcDiskConfig -BaseConfig $diskCfg -Override @{ FailBelowFreeGB = 6 } } 'FailBelowFreeGB.*WarnBelowFreeGB' 'Disk override: a Fail floor above the Warning floor is refused'
Assert-Throws { Merge-AdfaDcDiskConfig -BaseConfig $diskCfg -Override @{ WarnBelowPercent = 0; FailBelowPercent = 0; WarnBelowFreeGB = 0; FailBelowFreeGB = 0 } } 'no threshold' 'Disk override: a table with no threshold left is refused'
Assert-Throws { Merge-AdfaDcDiskConfig -BaseConfig $diskCfg -Override @{ RpcPort = 70000 } } 'RpcPort' 'Disk override: a port that is not a port is refused'

# --- The generic file: one top-level key per section, each to its own validator.
$ovr = Resolve-AdfaConfigOverride -Override ('{ "DcDisk": { "FailBelowPercent": 5 } }' | ConvertFrom-Json) -BaseConfig $script:Config -Sections $script:ConfigOverrideSections -OverrideSource 'C:\cfg\all.json'
Assert-Equal 'DcDisk' (@($ovr.Keys) -join ',') 'Config override: only the section the file names is returned'
Assert-Equal 5 ([double]$ovr['DcDisk'].FailBelowPercent) 'Config override: the section value went through the DcDisk validator'
Assert-Throws { Resolve-AdfaConfigOverride -Override $null -BaseConfig $script:Config -Sections $script:ConfigOverrideSections } 'null' 'Config override: null is refused'
Assert-Throws { Resolve-AdfaConfigOverride -Override @(1, 2) -BaseConfig $script:Config -Sections $script:ConfigOverrideSections } 'single object' 'Config override: an array is refused'
Assert-Throws { Resolve-AdfaConfigOverride -Override ('{}' | ConvertFrom-Json) -BaseConfig $script:Config -Sections $script:ConfigOverrideSections } 'empty object' 'Config override: an empty object is refused'
Assert-Throws { Resolve-AdfaConfigOverride -Override ('{ "Nope": {} }' | ConvertFrom-Json) -BaseConfig $script:Config -Sections $script:ConfigOverrideSections } "unknown section 'Nope'" 'Config override: an unknown section is refused'
Assert-Throws { Resolve-AdfaConfigOverride -Override ('{ "DcDisk": null }' | ConvertFrom-Json) -BaseConfig $script:Config -Sections $script:ConfigOverrideSections } "'DcDisk' to null" 'Config override: a section set to null is refused'
Assert-Throws { Resolve-AdfaConfigOverride -Override ('{ "DcDisk": { "WarnBelowPercent": "high" } }' | ConvertFrom-Json) -BaseConfig $script:Config -Sections $script:ConfigOverrideSections } "section 'DcDisk'.*WarnBelowPercent" 'Config override: a malformed value is refused, naming its section'
Assert-Throws { Resolve-AdfaConfigOverride -Override ('{ "DcSystem": { "WsmanPort": 5986 } }' | ConvertFrom-Json) -BaseConfig $script:Config -Sections $script:ConfigOverrideSections } "unknown section 'DcSystem'" 'Config override: the DC system table keeps its own parameter and cannot be set here'
Assert-Throws { Import-AdfaConfigOverride -Path (Join-Path ([IO.Path]::GetTempPath()) 'adfa-no-such-override.json') -BaseConfig $script:Config -Sections $script:ConfigOverrideSections } 'not found' 'Config override: a missing file stops the run'

# --- Figures are truncated, never rounded up across the threshold they are printed beside.
Assert-Equal '9.99' (ConvertTo-AdfaFixedText -Value 9.99999999906868) 'Fixed text: a value just under 10 prints as 9.99, not 10.00'
Assert-Equal '9.99' (ConvertTo-AdfaFixedText -Value 9.99) 'Fixed text: an exact 9.99 is not shaved to 9.98 by binary error'
Assert-Equal '19.99' (ConvertTo-AdfaFixedText -Value 19.999) 'Fixed text: 19.999 truncates to 19.99'
Assert-Equal '10.00' (ConvertTo-AdfaFixedText -Value 10) 'Fixed text: an exact 10 prints as 10.00'
Assert-Equal '0.00' (ConvertTo-AdfaFixedText -Value 0.005) 'Fixed text: 0.005 truncates to 0.00'
$oneByteShort = Get-AdfaDiskSpaceVerdict -CapacityBytes ([uint64]107374182400) -FreeBytes ([uint64]10737418239) -WarnBelowPercent 20 -FailBelowPercent 10 -WarnBelowFreeGB 5 -FailBelowFreeGB 2
Assert-Equal 'Fail' ([string]$oneByteShort.Status) 'Disk verdict: one byte short of 10 % is Fail'
Assert-Equal '9.99 % free: 9.99 GB free of 100.00 GB. Below the Fail threshold of 10 % free.' ([string]$oneByteShort.Detail) 'Disk verdict: the figure printed beside "below 10 %" is 9.99, not 10.00'
$floorShort = Get-AdfaDiskSpaceVerdict -CapacityBytes ([uint64]10737418240) -FreeBytes ([uint64]5368709119) -WarnBelowPercent 20 -FailBelowPercent 10 -WarnBelowFreeGB 5 -FailBelowFreeGB 2
Assert-Equal '49.99 % free: 4.99 GB free of 10.00 GB. Below the Warning floor of 5 GB free.' ([string]$floorShort.Detail) 'Disk verdict: one byte short of the 5 GB floor prints 4.99 GB, not 5.00'

# --- The section accounts for every scoped domain, and does not contradict itself.
# No DC is given here, so nothing is probed or read: only the population rows are produced.
$scopedDomains = @('contoso.com', 'north.contoso.com', 'south.contoso.com')
$popRows = @(Get-AdfaDcDiskSpace -DomainControllers @() -Config $diskCfg -ScopedDomains $scopedDomains `
        -InventoryFailures @([pscustomobject]@{ Domain = 'north.contoso.com'; Error = 'The server is not operational' }))
Assert-Equal 4 (@($popRows).Count) 'Disk population: with no DC, each of the three scoped domains has a row, plus the section row (declared population: three domains)'
Assert-Equal 0 (@($popRows | Where-Object { [string]$_.Status -ne 'Not Assessed' }).Count) 'Disk population: with no DC read, nothing is anything but Not Assessed'
foreach ($d in $scopedDomains) {
    Assert-Equal 1 (@($popRows | Where-Object { [string]$_.Item -eq ("Disk space - {0}" -f $d) -and [string]$_.Scope -eq $d }).Count) ("Disk population: scoped domain '{0}' has its own row" -f $d)
}
$popNorth = @($popRows | Where-Object { [string]$_.Scope -eq 'north.contoso.com' })[0]
$popSouth = @($popRows | Where-Object { [string]$_.Scope -eq 'south.contoso.com' })[0]
Assert-True ([string]$popNorth.Detail -match 'could not be enumerated\. Cause: The server is not operational') 'Disk population: a domain whose enumeration threw carries the cause'
Assert-True ([string]$popSouth.Detail -match 'returned no domain controller for this domain') 'Disk population: a domain that returned no DC says so, and is not confused with one that threw'

# --- The override file: faults that only the text shows.
Assert-Equal 'Array' (Get-AdfaJsonTopLevelKind -Text '[{"DcDisk":{"WarnBelowPercent":25}}]') 'Override text: an array holding one object is an array, whatever the parser makes of it'
Assert-Equal 'Object' (Get-AdfaJsonTopLevelKind -Text '  {"DcDisk":{"WarnBelowPercent":25}}') 'Override text: an object is an object'
Assert-Equal 'DcDisk.WarnBelowPercent' (@(Get-AdfaJsonDuplicateKey -Text '{"DcDisk":{"WarnBelowPercent":25,"WarnBelowPercent":90}}') -join '|') 'Override text: a key written twice in a section is found, with its path'
Assert-Equal 'DcDisk' (@(Get-AdfaJsonDuplicateKey -Text '{"DcDisk":{"WarnBelowPercent":25},"DcDisk":{"WarnBelowPercent":90}}') -join '|') 'Override text: a section written twice is found'
Assert-Equal '' (@(Get-AdfaJsonDuplicateKey -Text '{"DcDisk":{"WsmanPort":5986},"Later":{"WsmanPort":1},"s":"{\"a\":1,\"a\":2}"}') -join '|') 'Override text: the same key in two sections, or inside a string, is not a repeat'
$overrideProbe = Join-Path ([IO.Path]::GetTempPath()) ("adfa_validation_override_{0}.json" -f [guid]::NewGuid().ToString('N'))
try {
    '[{"DcDisk":{"WarnBelowPercent":25}}]' | Out-File -LiteralPath $overrideProbe -Encoding UTF8
    Assert-Throws { Import-AdfaConfigOverride -Path $overrideProbe -BaseConfig $script:Config -Sections $script:ConfigOverrideSections } 'not a JSON array' 'Override file: an array holding one valid object is refused on this PowerShell edition too'
    '{"DcDisk":{"WarnBelowPercent":25,"WarnBelowPercent":90}}' | Out-File -LiteralPath $overrideProbe -Encoding UTF8
    Assert-Throws { Import-AdfaConfigOverride -Path $overrideProbe -BaseConfig $script:Config -Sections $script:ConfigOverrideSections } "'DcDisk.WarnBelowPercent' more than once" 'Override file: a key written twice is refused, not reduced to its last value'
    '{"DcDisk":{"WarnBelowPercent":25}}' | Out-File -LiteralPath $overrideProbe -Encoding UTF8
    Assert-Equal 25 ([double](Import-AdfaConfigOverride -Path $overrideProbe -BaseConfig $script:Config -Sections $script:ConfigOverrideSections)['DcDisk'].WarnBelowPercent) 'Override file: non-vacuity - the same content as one object, written once, is accepted'
}
finally { Remove-Item -LiteralPath $overrideProbe -Force -ErrorAction SilentlyContinue }

# =============================================================================
# PORT-PLAN C3. DC hardening: pure logic only - nothing here opens a session. The collector and
# the CIM seam are covered by the Pester suite and by Run-SmokeTest.
# =============================================================================
Write-Host ""
Write-Host "== DC hardening (C3): pure logic ==" -ForegroundColor Cyan
$hardCfg = $script:Config.DcHardening
$hardIds = @('LdapServerIntegrity', 'LdapServerEnforceIntegrity', 'LdapEnforceChannelBinding', 'SmbServerSigning', 'SmbClientSigning', 'LmCompatibilityLevel')
function Get-HardSetting { param([string]$Id, $Config = $hardCfg) @($Config['Settings'] | Where-Object { [string]$_['Id'] -eq $Id })[0] }
# One registry read in the seam's shape. No -Number means the value is not set: return code 1, no number.
function New-HardValue {
    param([string]$Id, $Number = $null, $ReturnValue = 0, [string]$Err = '', [string]$Code = '')
    $setting = Get-HardSetting -Id $Id
    if ($Err -ne '') { $ReturnValue = $null; $Number = $null }
    elseif ($null -eq $Number -and [int64]$ReturnValue -eq 0) { $ReturnValue = 1 }
    [pscustomobject]@{ Id = $Id; Key = [string]$setting['Key']; ValueName = [string]$setting['ValueName']; Answered = ($Err -eq '')
        ReturnValue = $ReturnValue; Value = $Number; Method = 'GetDWORDValue'; Error = $Err; ErrorCode = $Code }
}
function Get-HardState { param([string]$Id, $Number = $null, $ReturnValue = 0, [string]$Err = '') Resolve-AdfaHardeningRead -Entry (New-HardValue -Id $Id -Number $Number -ReturnValue $ReturnValue -Err $Err) }
function Get-HardVerdict {
    param([string]$Id, $Number = $null, $Build = 17763, [hashtable]$Related = @{}, $Second = $null, $Config = $hardCfg, $ReturnValue = 0, [switch]$NoRelatedSettings)
    # The config rows by setting id, as the row builder hands them to the verdict.
    $byId = @{}
    if (-not $NoRelatedSettings) { foreach ($s in @($Config['Settings'])) { $byId[[string]$s['Id']] = $s } }
    Get-AdfaHardeningVerdict -Setting (Get-HardSetting -Id $Id -Config $Config) -State (Get-HardState -Id $Id -Number $Number -ReturnValue $ReturnValue) -Build $Build -Related $Related -SecondInstrument $Second -RelatedSettings $byId
}
# The SMB part, as Get-SmbServerConfiguration returns it since PORT-PLAN C3f. The default (one object,
# both properties booleans) is the shape measured on one Windows 11 workstation (not a DC) on
# 2026-11-17. -SmbNoInstance is the cmdlet returning nothing and raising no error.
function New-HardRaw {
    param([hashtable]$Numbers = @{}, [string]$Build = '17763', $Smb1 = $false, $SmbSigning = $true, [string]$SpoolerState = 'Stopped', [string]$SpoolerStartMode = 'Disabled', [switch]$SmbNoInstance)
    $values = @()
    foreach ($id in $hardIds) { $n = $null; if ($Numbers.ContainsKey($id)) { $n = $Numbers[$id] }; $values += New-HardValue -Id $id -Number $n }
    $smbOk = $true
    if ($SmbNoInstance) { $smbOk = $false; $Smb1 = $null; $SmbSigning = $null }
    [pscustomobject]@{ Ok = $true; Protocol = 'Wsman'; Error = ''; ErrorCode = ''; BuildNumber = $Build; BuildError = ''; BuildErrorCode = ''; Values = @($values)
        SmbOk = $smbOk; SmbNoInstance = [bool]$SmbNoInstance; SmbEnableSmb1 = $Smb1; SmbRequireSigning = $SmbSigning; SmbError = ''; SmbErrorCode = ''
        SpoolerOk = $true; SpoolerFound = $true; SpoolerState = $SpoolerState; SpoolerStartMode = $SpoolerStartMode; SpoolerError = ''; SpoolerErrorCode = '' }
}

# --- Config table.
Assert-Equal 6 (@($hardCfg['Settings']).Count) 'Hardening config: declared population - six registry settings'
Assert-Equal ($hardIds -join ',') (@($hardCfg['Settings'] | ForEach-Object { [string]$_['Id'] }) -join ',') 'Hardening config: the six settings, in table order'
Assert-Equal 'LDAPServerIntegrity|LDAPServerEnforceIntegrity|LdapEnforceChannelBinding|RequireSecuritySignature|RequireSecuritySignature|LmCompatibilityLevel' (@($hardCfg['Settings'] | ForEach-Object { [string]$_['ValueName'] }) -join '|') 'Hardening config: the six value names'
Assert-Equal '2,1,2,1,1,5' (@($hardCfg['Settings'] | ForEach-Object { [string]$_['ExpectedMinimum'] }) -join ',') 'Hardening config: each setting expects the value the Microsoft baseline gives for a domain controller'
Assert-Equal 6 (@($hardCfg['Settings'] | Where-Object { [string]$_['SourceUrl'] -match '^https://learn\.microsoft\.com/' -and [string]$_['ReadDate'] -eq '2026-11-13' }).Count) 'Hardening config: every setting records where it was read on Microsoft Learn, and when'

# --- The shared return-code reading.
Assert-Equal 'Success,ValueNotSet,KeyAbsent,AccessDenied,AccessDenied,TypeMismatch,ReadFailed' (@(@(0, 1, 2, 5, [uint32]2147749891, [uint32]2147749893, 87) | ForEach-Object { [string](Get-AdfaStdRegReturnClass -ReturnValue $_).Class }) -join ',') 'Registry return codes: 0, 1, 2, 5, 0x80041003, 0x80041005 and any other code are seven declared answers, read one way for every section'
Assert-Equal 'NoReturnCode' ([string](Get-AdfaStdRegReturnClass -ReturnValue $null).Class) 'Registry return codes: no return code is not a read'
Assert-Equal 'AccessDenied' ([string](Get-AdfaStdRegReturnClass -ReturnValue $null -ErrorText 'Acesso negado.' -ErrorCode 'AccessDenied').Class) 'Registry return codes: a refusal that threw is access denied by its CIM error code, whatever the language of the text'

# --- A value that was not read is never a number.
$hardNotSet = Get-HardState -Id 'SmbServerSigning'
Assert-True ([string]$hardNotSet.Kind -eq 'NotSet' -and $null -eq $hardNotSet.Number) 'Hardening read: a value that is not set (return 1) has no number - it is not 0, which would read as disabled'
Assert-True ([string](Get-HardState -Id 'SmbServerSigning' -Number 0).Kind -eq 'Value' -and (Get-HardState -Id 'SmbServerSigning' -Number 0).Number -eq 0) 'Hardening read: a value that IS 0 is kept as 0'
Assert-Equal 'KeyAbsent,AccessDenied,TypeMismatch,ReadFailed,AccessDenied' ((@(
        (Get-HardState -Id 'LmCompatibilityLevel' -ReturnValue 2), (Get-HardState -Id 'LmCompatibilityLevel' -ReturnValue 5),
        (Get-HardState -Id 'LmCompatibilityLevel' -ReturnValue ([uint32]2147749893)), (Get-HardState -Id 'LmCompatibilityLevel' -ReturnValue 87),
        (Get-HardState -Id 'LmCompatibilityLevel' -Err 'Access is denied.')) | ForEach-Object { [string]$_.Kind }) -join ',') 'Hardening read: key absent, refused, wrong type, any other code and a thrown refusal are five different results'

# --- Defaults by OS build, with the boundaries.
$hardCb = Get-HardSetting -Id 'LdapEnforceChannelBinding'
Assert-True ((Resolve-AdfaHardeningDefault -Setting $hardCb -Build 20348).Known -and (Resolve-AdfaHardeningDefault -Setting $hardCb -Build 20348).Value -eq 0) 'Hardening default: channel binding on build 20348 is the documented Never (0)'
Assert-True (-not (Resolve-AdfaHardeningDefault -Setting $hardCb -Build 20349).Known) 'Hardening default: one build above Windows Server 2022 there is no documented default'
Assert-True (-not (Resolve-AdfaHardeningDefault -Setting $hardCb -Build 26100).Known) 'Hardening default: channel binding on Windows Server 2025 is not known - published for new deployments only'
Assert-True (-not (Resolve-AdfaHardeningDefault -Setting $hardCb -Build $null).Known) 'Hardening default: with the build not read, no default is known'
$hardClient = Get-HardSetting -Id 'SmbClientSigning'
Assert-Equal '0,1' ((@(20348, 26100) | ForEach-Object { [string](Resolve-AdfaHardeningDefault -Setting $hardClient -Build $_).Value }) -join ',') 'Hardening default: SMB client signing is disabled by default up to 2022 and required from 2025'
Assert-True (-not (Resolve-AdfaHardeningDefault -Setting $hardClient -Build 26099).Known) 'Hardening default: one build below Windows Server 2025 there is no documented default'

# --- Verdict direction and boundaries.
Assert-Equal 'Warning,Warning,Pass' ((@(0, 1, 2) | ForEach-Object { [string](Get-HardVerdict -Id 'LdapEnforceChannelBinding' -Number $_).Status }) -join ',') 'Hardening verdict: channel binding 0 and 1 warn, 2 passes'
Assert-Equal 'Warning,Warning,Warning,Warning,Warning,Pass' ((@(0, 1, 2, 3, 4, 5) | ForEach-Object { [string](Get-HardVerdict -Id 'LmCompatibilityLevel' -Number $_).Status }) -join ',') 'Hardening verdict: LmCompatibilityLevel passes at 5 only (declared population: the six levels)'
Assert-Equal 'Not Assessed' ([string](Get-HardVerdict -Id 'LmCompatibilityLevel' -Number 6).Status) 'Hardening verdict: a number Microsoft publishes no meaning for is Not Assessed, not graded'
Assert-Equal 'Warning' ([string](Get-HardVerdict -Id 'LdapEnforceChannelBinding' -Build 17763).Status) 'Hardening verdict: channel binding not set on a 2019 DC is graded as the documented default, Never'
Assert-True ([string](Get-HardVerdict -Id 'LdapEnforceChannelBinding' -Build 17763).Detail -match 'documented default' -and [string](Get-HardVerdict -Id 'LdapEnforceChannelBinding' -Build 17763).Detail -match 'not on a configured value') 'Hardening verdict: a row graded on a default says so'
Assert-Equal 'Not Assessed' ([string](Get-HardVerdict -Id 'LdapEnforceChannelBinding' -Build 26100).Status) 'Hardening verdict: channel binding not set on a 2025 DC is Not Assessed, not a guess'
Assert-Equal 'Not Assessed' ([string](Get-HardVerdict -Id 'LdapEnforceChannelBinding' -Build $null).Status) 'Hardening verdict: a value that is not set, on a DC whose build was not read, is Not Assessed'
Assert-Equal 'Pass' ([string](Get-HardVerdict -Id 'SmbClientSigning' -Build 26100).Status) 'Hardening verdict: SMB client signing not set on a 2025 DC passes on the documented default'
Assert-Equal 'Info,Info,Pass' ((@(17763, 26099, 26100) | ForEach-Object { [string](Get-HardVerdict -Id 'LdapServerEnforceIntegrity' -Number 1 -Build $_).Status }) -join ',') 'Hardening verdict: the enforcement policy is not applicable below build 26100 and graded from it'
Assert-Equal 'Not Assessed' ([string](Get-HardVerdict -Id 'LdapServerEnforceIntegrity' -Number 1 -Build $null).Status) 'Hardening verdict: with the build not read, the enforcement row is Not Assessed, not Info'
$hardDenied = @($hardIds | ForEach-Object { Get-HardVerdict -Id $_ -ReturnValue 5 -Build 26100 })
Assert-Equal 6 (@($hardDenied | Where-Object { [string]$_.Status -eq 'Not Assessed' -and [string]$_.Detail -match '^Access denied' }).Count) 'Hardening verdict: a refused read is Not Assessed as access denied on every one of the six settings'
$hardAbsentKey = @($hardIds | ForEach-Object { Get-HardVerdict -Id $_ -ReturnValue 2 -Build 26100 })
Assert-Equal 6 (@($hardAbsentKey | Where-Object { [string]$_.Status -eq 'Not Assessed' -and [string]$_.Detail -match '^Not found' }).Count) 'Hardening verdict: an absent key is Not Assessed as not found, and is not confused with a refusal'

# --- LDAP signing on Windows Server 2025: the enforcement value decides with it.
$enfOn = @{ LdapServerEnforceIntegrity = (Get-HardState -Id 'LdapServerEnforceIntegrity' -Number 1) }
$enfOff = @{ LdapServerEnforceIntegrity = (Get-HardState -Id 'LdapServerEnforceIntegrity' -Number 0) }
$enfUnset = @{ LdapServerEnforceIntegrity = (Get-HardState -Id 'LdapServerEnforceIntegrity') }
Assert-Equal 'Warning' ([string](Get-HardVerdict -Id 'LdapServerIntegrity' -Number 1 -Build 17763 -Related $enfOn).Status) 'LDAP signing: on a 2019 DC a value of 1 is a Warning whatever the enforcement value holds'
Assert-Equal 'Pass' ([string](Get-HardVerdict -Id 'LdapServerIntegrity' -Number 1 -Build 26100 -Related $enfOn).Status) 'LDAP signing: on a 2025 DC enforcement = 1 requires signing whatever this value holds'
Assert-Equal 'Warning' ([string](Get-HardVerdict -Id 'LdapServerIntegrity' -Number 1 -Build 26100 -Related $enfOff).Status) 'LDAP signing: on a 2025 DC with enforcement = 0 this value decides'
Assert-Equal 'Pass' ([string](Get-HardVerdict -Id 'LdapServerIntegrity' -Build 26100 -Related $enfUnset).Status) 'LDAP signing: neither value set on a 2025 DC is the documented default, signing required'
Assert-Equal 'Not Assessed' ([string](Get-HardVerdict -Id 'LdapServerIntegrity' -Number 1 -Build 26100 -Related $enfUnset).Status) 'LDAP signing: a legacy value with no enforcement value on a 2025 DC is Not Assessed - Microsoft documents both outcomes'
Assert-Equal 'Not Assessed' ([string](Get-HardVerdict -Id 'LdapServerIntegrity' -Number 1 -Build 26100).Status) 'LDAP signing: with the enforcement value unread on a 2025 DC, a value below 2 is Not Assessed'
Assert-Equal 'Pass' ([string](Get-HardVerdict -Id 'LdapServerIntegrity' -Number 2 -Build $null).Status) 'LDAP signing: 2 requires signing on every build, so it passes even with the build unread'
Assert-Equal 'Not Assessed' ([string](Get-HardVerdict -Id 'LdapServerIntegrity' -Number 1 -Build $null).Status) 'LDAP signing: below 2 with the build unread is Not Assessed'

# --- SMB server signing: the second instrument can veto, and stands in when the value is not set.
function New-HardSecond { param($Value, [bool]$Read = $true) [pscustomobject]@{ Read = $Read; Value = $Value; Error = '' } }
Assert-Equal 'Pass' ([string](Get-HardVerdict -Id 'SmbServerSigning' -Number 1 -Second (New-HardSecond $true)).Status) 'SMB server signing: registry 1 and the SMB server configuration True agree - Pass'
Assert-Equal 'Not Assessed' ([string](Get-HardVerdict -Id 'SmbServerSigning' -Number 1 -Second (New-HardSecond $false)).Status) 'SMB server signing: registry 1 against the SMB server configuration False is Not Assessed, never Pass'
Assert-Equal 'Pass,Warning' ((@($true, $false) | ForEach-Object { [string](Get-HardVerdict -Id 'SmbServerSigning' -Second (New-HardSecond $_)).Status }) -join ',') 'SMB server signing: not set in the registry, the row is graded on the measured SMB server configuration'
Assert-Equal 'Not Assessed' ([string](Get-HardVerdict -Id 'SmbServerSigning' -Second (New-HardSecond $null $false)).Status) 'SMB server signing: not set and nothing else read is Not Assessed on any build'

# --- One DC to rows.
$hardRows = @(Get-AdfaDcHardeningFinding -DomainController 'dc1.contoso.com' -Scope 'contoso.com' -Config $hardCfg -Raw (New-HardRaw -Numbers @{ LdapServerIntegrity = 2; SmbServerSigning = 1; LmCompatibilityLevel = 3 } -Smb1 $true -SpoolerState 'Running' -SpoolerStartMode 'Auto'))
Assert-Equal 8 (@($hardRows).Count) 'Hardening rows: one row per setting, then Print Spooler and SMBv1 (declared population: eight)'
Assert-Equal 'Pass,Info,Warning,Pass,Warning,Warning,Warning,Fail' (@($hardRows | ForEach-Object { [string]$_.Status }) -join ',') 'Hardening rows: a mixed result is reported as mixed, in table order'
Assert-Equal 8 (@($hardRows | Where-Object { [string]$_.Item -match ': dc1\.contoso\.com$' -and [string]$_.Scope -eq 'contoso.com' }).Count) 'Hardening rows: every row is named family first and carries its domain'
Assert-Equal 6 (@($hardRows | Where-Object { [string]$_.NotRun -match 'not necessarily what a client and this DC negotiate on the wire' -and [string]$_.Detail -notmatch 'negotiate' }).Count) 'Hardening rows: the not-on-the-wire note is in NotRun on the six setting rows, never in the text the advice is chosen from'
$hardEmpty = @(Get-AdfaDcHardeningFinding -DomainController 'dc1.contoso.com' -Scope '' -Config $hardCfg -Raw (New-HardRaw -Build '' -SmbSigning $null))
Assert-Equal 0 (@($hardEmpty | Where-Object { [string]$_.Status -eq 'Pass' -and [string]$_.Item -notmatch '^(Print Spooler|SMBv1)' }).Count) 'Hardening rows: with no value set and the build unread, no setting passes'
Assert-Equal 6 (@($hardEmpty | Where-Object { [string]$_.Status -eq 'Not Assessed' }).Count) 'Hardening rows: with no value set and the build unread, all six settings are Not Assessed'
# What is not Microsoft's is said in the row that relies on it: the inferred registry path of
# LDAPServerIntegrity, and the status a value below the expectation is given.
Assert-Equal 1 (@($hardRows | Where-Object { [string]$_.Detail -match 'registry path of this value is inferred, not published by Microsoft for AD DS' }).Count) 'Hardening rows: one row says its registry path is inferred'
Assert-True ([string]$hardRows[0].Item -eq 'LDAP server signing: dc1.contoso.com' -and [string]$hardRows[0].Status -eq 'Pass' -and [string]$hardRows[0].Detail -match 'path of this value is inferred') 'Hardening rows: it is the LDAP server signing row, and it says so even when it passes'
Assert-Equal 'LDAP channel binding|SMB client signing|LAN Manager authentication level' ((@($hardRows | Where-Object { [string]$_.Detail -match 'below the expectation \(Warning\) is a tool default or your own override, not a Microsoft value' } | ForEach-Object { [string]$_.Item -replace ': .*$', '' }) -join '|')) 'Hardening rows: each setting graded below its expectation says the status is a tool default, not a Microsoft value (declared population: three)'
Assert-Equal 0 (@($hardEmpty | Where-Object { [string]$_.Detail -match 'tool default' }).Count) 'Hardening rows: a row that is not graded below the expectation does not carry that sentence'
$hardLm = Get-HardSetting -Id 'LmCompatibilityLevel'
Assert-Equal '3,3' ((@(7600, 7601) | ForEach-Object { [string](Resolve-AdfaHardeningDefault -Setting $hardLm -Build $_).Value }) -join ',') 'Hardening default: the LAN Manager default of 3 applies to both Windows Server 2008 R2 builds'
Assert-Equal 'True,False,False' ((@(7101, 7100, 6002) | ForEach-Object { [string](Resolve-AdfaHardeningDefault -Setting $hardLm -Build $_).Known }) -join ',') 'Hardening default: it applies from every build above 7100, as Microsoft publishes Windows Server 2008 R2, and not below (off by one)'

# --- Population: every scoped domain is accounted for.
$hardPop = @(Get-AdfaDcHardening -DomainControllers @() -Config $hardCfg -ScopedDomains $scopedDomains `
        -InventoryFailures @([pscustomobject]@{ Domain = 'north.contoso.com'; Error = 'The server is not operational' }))
Assert-Equal 4 (@($hardPop).Count) 'Hardening population: with no DC, each of the three scoped domains has a row, plus the section row'
Assert-Equal 0 (@($hardPop | Where-Object { [string]$_.Status -ne 'Not Assessed' }).Count) 'Hardening population: with no DC read, nothing is anything but Not Assessed'
foreach ($d in $scopedDomains) {
    Assert-Equal 1 (@($hardPop | Where-Object { [string]$_.Item -eq ("DC hardening - {0}" -f $d) -and [string]$_.Scope -eq $d }).Count) ("Hardening population: scoped domain '{0}' has its own row" -f $d)
}

# --- Advice: each family's own entry answers, whatever words the row or a file path contains.
$hardAdvice = [ordered]@{
    'LDAP server signing'              = '2887 and 2889'
    'LDAP server signing enforcement'  = 'LDAP server signing requirements enforcement'
    'LDAP channel binding'             = 'channel binding token requirements'
    'SMB server signing'               = 'Set-SmbServerConfiguration -RequireSecuritySignature'
    'SMB client signing'               = 'Set-SmbClientConfiguration -RequireSecuritySignature'
    'LAN Manager authentication level' = 'Refuse LM & NTLM'
    'Print Spooler'                    = 'print pruning'
    'SMBv1'                            = 'EnableSMB1Protocol \$false'
}
foreach ($family in @($hardAdvice.Keys)) {
    $rec = Get-AdfaRecommendation -Section 'DC Hardening' -Item ("{0}: dc1-backup.contoso.com" -f $family) -Detail 'Expectation source: C:\Backup\replication\sysvol-dfsr.json ldap signing smbv1 spooler'
    Assert-True ($rec -match $hardAdvice[$family] -and $rec -notmatch 'repadmin|wbadmin|dfsrmig') ("Hardening advice: '{0}' gets its own Microsoft-supported advice, not an unrelated one" -f $family)
}
Assert-Equal '' (Get-AdfaRecommendation -Section 'DC Hardening' -Item 'DC hardening: dc1.contoso.com' -Detail 'replication backup sysvol ldap signing') 'Hardening advice: a row of the section with no advice of its own gets none'

# --- The DcHardening validator.
$hardMerged = Merge-AdfaDcHardeningConfig -BaseConfig $hardCfg -OverrideSource 'C:\cfg\hard.json' -Override @{ Settings = @{ LmCompatibilityLevel = @{ ExpectedMinimum = 3; OtherStatus = 'Fail' } } }
Assert-Equal 'Fail,Pass,Pass' ((@(2, 3, 5) | ForEach-Object { [string](Get-HardVerdict -Id 'LmCompatibilityLevel' -Number $_ -Config $hardMerged).Status }) -join ',') 'Hardening override: the expectation and the status below it come from the file (off by one below the minimum fails)'
Assert-True ([string](Get-HardSetting -Id 'LmCompatibilityLevel' -Config $hardMerged)['ExpectedSource'] -match 'C:\\cfg\\hard\.json') 'Hardening override: the file is cited for the setting it changed'
Assert-Equal 5 ([int](Get-HardSetting -Id 'LmCompatibilityLevel')['ExpectedMinimum']) 'Hardening override: the built-in table is not modified by a merge'
Assert-Throws { Merge-AdfaDcHardeningConfig -BaseConfig $hardCfg -Override 'abc' } 'single object' 'Hardening override: a string is refused'
Assert-Throws { Merge-AdfaDcHardeningConfig -BaseConfig $hardCfg -Override ('{}' | ConvertFrom-Json) } 'empty object' 'Hardening override: an empty object is refused'
Assert-Throws { Merge-AdfaDcHardeningConfig -BaseConfig $hardCfg -Override @{ Typo = 1 } } "unknown key 'Typo'" 'Hardening override: an unknown key is refused'
Assert-Throws { Merge-AdfaDcHardeningConfig -BaseConfig $hardCfg -Override ('{ "Settings": null }' | ConvertFrom-Json) } 'null' 'Hardening override: a null is refused'
Assert-Throws { Merge-AdfaDcHardeningConfig -BaseConfig $hardCfg -Override ('{ "Settings": [] }' | ConvertFrom-Json) } 'object keyed by setting id' 'Hardening override: an empty list of settings is refused'
Assert-Throws { Merge-AdfaDcHardeningConfig -BaseConfig $hardCfg -Override @{ Settings = @{ Nope = @{ OtherStatus = 'Fail' } } } } "unknown setting 'Nope'" 'Hardening override: an unknown setting is refused'
Assert-Throws { Merge-AdfaDcHardeningConfig -BaseConfig $hardCfg -Override @{ Settings = @{ LmCompatibilityLevel = @{ Key = 'x' } } } } "unknown key 'Key'" 'Hardening override: the registry value a setting reads cannot be redirected from a file'
Assert-Throws { Merge-AdfaDcHardeningConfig -BaseConfig $hardCfg -Override @{ Settings = @{ LmCompatibilityLevel = @{ ExpectedMinimum = 2 } } } } 'one of 3, 4, 5' 'Hardening override: an expectation Microsoft documents no support for is refused'
Assert-Throws { Merge-AdfaDcHardeningConfig -BaseConfig $hardCfg -Override @{ Settings = @{ LmCompatibilityLevel = @{ ExpectedMinimum = '3' } } } } 'JSON number' 'Hardening override: a number written as a string is refused'
Assert-Throws { Merge-AdfaDcHardeningConfig -BaseConfig $hardCfg -Override @{ Settings = @{ SmbServerSigning = @{ OtherStatus = 'Pass' } } } } 'Warning or Fail' 'Hardening override: a weak value can never be configured to read as a pass'
# The two ports cannot be set from a file: the section's CIM session does not use them, so a port
# set there would change the probe and not the connection. Refused whatever the value.
Assert-Throws { Merge-AdfaDcHardeningConfig -BaseConfig $hardCfg -Override @{ WsmanPort = 5986 } } "names 'WsmanPort'. The ports of this section cannot be set from a file" 'Hardening override: WsmanPort is refused - the CIM session always uses the default WinRM port'
Assert-Throws { Merge-AdfaDcHardeningConfig -BaseConfig $hardCfg -Override @{ RpcPort = 1135 } } "names 'RpcPort'. The ports of this section cannot be set from a file" 'Hardening override: RpcPort is refused - DCOM always goes through the RPC endpoint mapper'
Assert-Throws { Merge-AdfaDcHardeningConfig -BaseConfig $hardCfg -Override @{ WsmanPort = 5985 } } 'cannot be set from a file' 'Hardening override: the port key is refused even with the built-in value'
Assert-Equal '5985,135' ((@('WsmanPort', 'RpcPort') | ForEach-Object { [string](Merge-AdfaDcHardeningConfig -BaseConfig $hardCfg -Override @{ Settings = @{ SmbServerSigning = @{ OtherStatus = 'Fail' } } })[$_] }) -join ',') 'Hardening override: a merge leaves the two built-in ports as they are'
# Found by the review of the diff: the choices a file may set an expectation to, exactly.
Assert-Equal '2|1|1,2|1|1|3,4,5' ((@($hardCfg['Settings'] | ForEach-Object { (@($_['ExpectedChoices']) -join ',') }) -join '|')) 'Hardening config: the expectations a file may choose, per setting (declared population: six) - none of them a value that means off or never'
Assert-Throws { Merge-AdfaDcHardeningConfig -BaseConfig $hardCfg -Override @{ Settings = @{ LdapEnforceChannelBinding = @{ ExpectedMinimum = 0 } } } } 'It must be one of 1, 2' 'Hardening override: channel binding Never (0) can never be made the expectation'
# Found by mutation: the last build before Windows Server 2025, a second instrument that is
# marked as not read, and a build that is not a build.
Assert-Equal 'Warning,Pass' ((@(26099, 26100) | ForEach-Object { [string](Get-HardVerdict -Id 'LdapServerIntegrity' -Number 1 -Build $_ -Related $enfOn).Status }) -join ',') 'LDAP signing: the enforcement value decides from build 26100, not one build earlier (off by one)'
Assert-Equal 'Not Assessed' ([string](Get-HardVerdict -Id 'SmbServerSigning' -Second (New-HardSecond $true $false)).Status) 'SMB server signing: a second instrument marked as not read is not used, whatever value it carries'
Assert-Equal 'Warning' ([string](Get-HardVerdict -Id 'SmbServerSigning' -Number 0 -Second (New-HardSecond $true $false)).Status) 'SMB server signing: with the second instrument not read, a value that is set is graded on the registry alone'
$hardZero = @(Get-AdfaDcHardeningFinding -DomainController 'dc1.contoso.com' -Scope '' -Config $hardCfg -Raw (New-HardRaw -Build '0' -SmbSigning $null))
Assert-Equal 6 (@($hardZero | Where-Object { [string]$_.Status -eq 'Not Assessed' }).Count) 'Hardening rows: a build of 0 is not a build - no default is applied and all six settings are Not Assessed'
# --- Found by the independent review of the diff before commit.
# 1. A signing value with no published meaning beside an unset enforcement value: the enforcement
#    row does not take "3 is at least 2" for "signing is required".
$sigOdd = @(3, [int64]4294967295) | ForEach-Object { Get-HardVerdict -Id 'LdapServerEnforceIntegrity' -Build 26100 -Related @{ LdapServerIntegrity = (Get-HardState -Id 'LdapServerIntegrity' -Number $_) } }
Assert-Equal 2 (@($sigOdd | Where-Object { [string]$_.Status -eq 'Not Assessed' -and [string]$_.Detail -match 'a number Microsoft publishes no meaning for \(documented values: 0, 1, 2; see that row\)' -and [string]$_.Detail -notmatch 'requires signing whichever' }).Count) 'LDAP enforcement: beside a signing value with no published meaning (3, 4294967295) the default is not applied and the row is Not Assessed, never Pass'
Assert-Equal 'Pass' ([string](Get-HardVerdict -Id 'LdapServerEnforceIntegrity' -Build 26100 -Related @{ LdapServerIntegrity = (Get-HardState -Id 'LdapServerIntegrity' -Number 2) }).Status) 'LDAP enforcement: non-vacuity - beside the documented value 2 the default still applies and passes'
Assert-Equal 'Not Assessed' ([string](Get-HardVerdict -Id 'LdapServerEnforceIntegrity' -Build 26100 -NoRelatedSettings -Related @{ LdapServerIntegrity = (Get-HardState -Id 'LdapServerIntegrity' -Number 2) }).Status) 'LDAP enforcement: with the signing setting''s published meanings not supplied, no number is taken as documented (fail closed)'
# 2. Build not read: the cause of the failed read stays in the enforcement row.
$enfNoBuild = Get-HardVerdict -Id 'LdapServerEnforceIntegrity' -ReturnValue 5 -Build $null
Assert-True ([string]$enfNoBuild.Status -eq 'Not Assessed' -and [string]$enfNoBuild.Detail -match '^Access denied: StdRegProv returned 5' -and [string]$enfNoBuild.Detail -match 'also depends on the OS build, which was not read') 'LDAP enforcement: with the build unread, a refused read is still reported as access denied, and the build as a second cause'
Assert-True ([string](Get-HardVerdict -Id 'LdapServerEnforceIntegrity' -ReturnValue 2 -Build $null).Detail -match '^Not found: StdRegProv returned 2') 'LDAP enforcement: with the build unread, an absent key is still reported as not found'
Assert-True ([string](Get-HardVerdict -Id 'LdapServerEnforceIntegrity' -ReturnValue 5 -Build 17763).Status -eq 'Info' -and [string](Get-HardVerdict -Id 'LdapServerEnforceIntegrity' -ReturnValue 5 -Build 17763).Detail -match 'The value itself was not read on this DC - Access denied') 'LDAP enforcement: below Windows Server 2025 the row is still Info, and still says the read was refused'
# 3. An enforcement value that was read and is neither 0 nor 1: the signing row says it was read.
$enfTwo = @{ LdapServerEnforceIntegrity = (Get-HardState -Id 'LdapServerEnforceIntegrity' -Number 2) }
$sigBesideTwo = @(@($null, 0, 1) | ForEach-Object { Get-HardVerdict -Id 'LdapServerIntegrity' -Number $_ -Build 26100 -Related $enfTwo })
Assert-Equal 3 (@($sigBesideTwo | Where-Object { [string]$_.Status -eq 'Not Assessed' -and [string]$_.Detail -match 'LDAPServerEnforceIntegrity, which holds 2 on this DC' -and [string]$_.Detail -notmatch 'was not read' }).Count) 'LDAP signing: beside an enforcement value that was read as 2, the row is Not Assessed and says the value was read (declared population: signing not set, 0 and 1)'
# 4. A build below the LAN Manager default's lower bound is not told it is "20348 and below".
$lmLow = [string](Resolve-AdfaHardeningDefault -Setting (Get-HardSetting -Id 'LmCompatibilityLevel') -Build 6003).Reason
Assert-True ($lmLow -match 'no default for OS build 6003' -and $lmLow -match 'builds 7101 to 20348, and for build 26100 and later only' -and $lmLow -notmatch '20348 and below') 'Hardening default: a build below the LAN Manager lower bound is given that setting''s own ranges, not a sentence that contradicts itself'
# 5. The SMB read returned no object and no error (Get-SmbServerConfiguration, PORT-PLAN C3f).
$hardNoInst = @(Get-AdfaDcHardeningFinding -DomainController 'dc1.contoso.com' -Scope 'contoso.com' -Config $hardCfg -Raw (New-HardRaw -Numbers @{ LdapServerIntegrity = 2; LdapEnforceChannelBinding = 2; SmbServerSigning = 1; SmbClientSigning = 1; LmCompatibilityLevel = 5 } -SmbNoInstance))
$hardNoInstSmb1 = @($hardNoInst | Where-Object { [string]$_.Item -eq 'SMBv1: dc1.contoso.com' })[0]
Assert-True ([string]$hardNoInstSmb1.Status -eq 'Not Assessed' -and [string]$hardNoInstSmb1.Detail -match '^Not read: Get-SmbServerConfiguration returned no configuration object for this DC, and no error' -and [string]$hardNoInstSmb1.Detail -match 'This is not a pass') 'Hardening rows: an SMB read that returned no object leaves SMBv1 Not Assessed, never Pass, and the row says why'
$hardNoInstSrv = @($hardNoInst | Where-Object { [string]$_.Item -eq 'SMB server signing: dc1.contoso.com' })[0]
Assert-True ([string]$hardNoInstSrv.Status -eq 'Pass' -and [string]$hardNoInstSrv.Detail -match 'was not read \(Get-SmbServerConfiguration returned no configuration object' -and [string]$hardNoInstSrv.Detail -notmatch 'agrees') 'Hardening rows: SMB server signing is then graded on the registry alone and claims no second instrument'
$hardNoInstUnset = @(Get-AdfaDcHardeningFinding -DomainController 'dc1.contoso.com' -Scope '' -Config $hardCfg -Raw (New-HardRaw -SmbNoInstance))
Assert-Equal 'Not Assessed,Not Assessed' ((@('SMB server signing', 'SMBv1') | ForEach-Object { $f = $_; [string]@($hardNoInstUnset | Where-Object { [string]$_.Item -eq ("{0}: dc1.contoso.com" -f $f) })[0].Status }) -join ',') 'Hardening rows: with the registry value not set and no object, SMB server signing and SMBv1 are both Not Assessed'
# 6. C3f: the SMB server configuration read resolved once, and the SMBv1 verdict on it. Pure, no directory.
function New-C3fValRaw {
    param($Smb1 = $false, $Signing = $true, [switch]$NoInstance, [switch]$CmdletMissing, [string]$Err = '', [string]$Code = '')
    $r = New-HardRaw -Numbers @{ LdapServerIntegrity = 2; LdapEnforceChannelBinding = 2; SmbServerSigning = 1; SmbClientSigning = 1; LmCompatibilityLevel = 5 } -Smb1 $Smb1 -SmbSigning $Signing -SmbNoInstance:$NoInstance
    $r | Add-Member -NotePropertyName SmbInstrument -NotePropertyValue 'Get-SmbServerConfiguration'
    $r | Add-Member -NotePropertyName SmbCmdletMissing -NotePropertyValue ([bool]$CmdletMissing)
    if ($CmdletMissing -or $Err -ne '') { $r.SmbOk = $false; $r.SmbEnableSmb1 = $null; $r.SmbRequireSigning = $null }
    $r.SmbError = $Err; $r.SmbErrorCode = $Code
    return $r
}
# Declared population: the six kinds the resolver gives, each reached once.
$c3fKinds = [ordered]@{
    Read          = (New-C3fValRaw)
    NoInstance    = (New-C3fValRaw -NoInstance)
    CmdletMissing = (New-C3fValRaw -CmdletMissing)
    AccessDenied  = (New-C3fValRaw -Err 'Acesso negado.' -Code 'AccessDenied')
    ClassMissing  = (New-C3fValRaw -Err 'x' -Code 'InvalidNamespace')
    ReadFailed    = (New-C3fValRaw -Err 'The operation has timed out.' -Code 'Failed')
}
Assert-Equal 6 (@($c3fKinds.Keys).Count) 'C3f: six kinds of SMB read (declared population)'
foreach ($k in @($c3fKinds.Keys)) { Assert-Equal $k ([string](Resolve-AdfaSmbServerRead -Raw $c3fKinds[$k]).Kind) ("C3f: the resolver tells the {0} read apart" -f $k) }
Assert-Equal 'Pass,Fail' ((@($false, $true) | ForEach-Object { [string](Get-AdfaSmb1Verdict -Read (Resolve-AdfaSmbServerRead -Raw (New-C3fValRaw -Smb1 $_)) -Protocol 'Wsman').Status }) -join ',') 'C3f: SMBv1 passes on a returned False and fails on True'
$c3fNa = @(@('NoInstance', 'CmdletMissing', 'AccessDenied', 'ClassMissing', 'ReadFailed') | ForEach-Object { [string](Get-AdfaSmb1Verdict -Read (Resolve-AdfaSmbServerRead -Raw $c3fKinds[$_]) -Protocol 'Wsman').Status })
Assert-Equal 'Not Assessed,Not Assessed,Not Assessed,Not Assessed,Not Assessed' ($c3fNa -join ',') 'C3f: each result that is not a read is Not Assessed, never Pass (declared population: five)'
Assert-Equal 'Not Assessed' ([string](Get-AdfaSmb1Verdict -Read (Resolve-AdfaSmbServerRead -Raw (New-C3fValRaw -Smb1 $null)) -Protocol 'Wsman').Status) 'C3f: an EnableSMB1Protocol that was not returned is Not Assessed, not False'
Assert-Equal 'Not Assessed' ([string](Get-AdfaSmb1Verdict -Read (Resolve-AdfaSmbServerRead -Raw (New-C3fValRaw -Smb1 0)) -Protocol 'Wsman').Status) 'C3f: a number is not a boolean'
$c3fStray = New-C3fValRaw
$c3fStray.SmbNoInstance = $true
Assert-Equal 'NoInstance' ([string](Resolve-AdfaSmbServerRead -Raw $c3fStray).Kind) 'C3f: a flag that says nothing was read wins over stray values'
Assert-Equal 'ReadFailed' ([string](Resolve-AdfaSmbServerRead -Raw (New-C3fValRaw -Err 'Invalid namespace' -Code 'Failed')).Kind) 'C3f: a code that says something else wins over the words of the text'
$c3fWrapInner = New-Object System.Exception 'Acesso negado.'
$c3fWrapInner | Add-Member -NotePropertyName NativeErrorCode -NotePropertyValue 'AccessDenied'
Assert-Equal 'AccessDenied' (Get-AdfaExceptionErrorCode -Exception (New-Object System.Exception -ArgumentList 'dc: Acesso negado.', $c3fWrapInner)) 'C3f: the CIM code is read from the exception a CDXML error wraps'
Assert-Equal '' (Get-AdfaExceptionErrorCode -Exception (New-Object System.Exception 'x')) 'C3f: no code, no invented code'
# Up to five exceptions deep, the code on the innermost (declared population: chains of 1 to 6).
$c3fDepth = @(1, 2, 3, 4, 5, 6 | ForEach-Object {
        $e = New-Object System.Exception 'level 1'
        $e | Add-Member -NotePropertyName NativeErrorCode -NotePropertyValue 'AccessDenied'
        for ($i = 2; $i -le $_; $i++) { $e = New-Object System.Exception -ArgumentList ("level {0}" -f $i), $e }
        [string](Get-AdfaExceptionErrorCode -Exception $e)
    })
Assert-Equal 'AccessDenied,AccessDenied,AccessDenied,AccessDenied,AccessDenied,' ($c3fDepth -join ',') 'C3f: the CIM code is read up to five exceptions deep, and no deeper'
Assert-Equal 'ReadFailed' ([string](Resolve-AdfaSmbServerRead -Raw (New-C3fValRaw -Err 'x' -Code 'NotFound')).Kind) 'C3f: the code NotFound is a failed read, not a missing class'
Assert-Equal 'ClassMissing' ([string](Resolve-AdfaSmbServerRead -Raw (New-C3fValRaw -Err 'Invalid namespace ')).Kind) 'C3f: with no code, the words "invalid namespace" are a missing class'
$c3fToolRaw = New-C3fValRaw -Err 'Access is denied. Invalid class'
$c3fToolRaw | Add-Member -NotePropertyName SmbErrorByTool -NotePropertyValue $true
$c3fTool = Resolve-AdfaSmbServerRead -Raw $c3fToolRaw
Assert-True ([string]$c3fTool.Kind -eq 'ReadFailed' -and [string]$c3fTool.CauseSource -eq 'Tool') 'C3f: a sentence this tool wrote is never read as a refusal or a missing class'
$c3fToolDetail = [string](Get-AdfaSmb1Verdict -Read $c3fTool -Protocol 'Wsman').Detail
Assert-True ($c3fToolDetail -notmatch 'Reported by the DC' -and $c3fToolDetail -match 'Written by this tool, not an error from the DC - ') 'C3f: the SMBv1 row never says the DC reported this tool''s own sentence'
$c3fDcDetail = [string](Get-AdfaSmb1Verdict -Read (Resolve-AdfaSmbServerRead -Raw (New-C3fValRaw -Err 'Invalid class ')) -Protocol 'Wsman').Detail
Assert-True ($c3fDcDetail -match 'Reported by the DC - Invalid class\. Read over Wsman\.$') 'C3f: an error the DC raised is quoted as its own and ends its sentence before the transport'
$c3fDeniedDetail = [string](Get-AdfaSmb1Verdict -Read (Resolve-AdfaSmbServerRead -Raw $c3fKinds['AccessDenied']) -Protocol 'Wsman').Detail
Assert-True ($c3fDeniedDetail -match '^Access denied: ' -and $c3fDeniedDetail -notmatch 'Local Administrators' -and $c3fDeniedDetail -match 'not published') 'C3f: the access-denied row names no rights, which are not published'
$c3fRows = @(Get-AdfaDcHardeningFinding -DomainController 'dc1.contoso.com' -Scope '' -Config $hardCfg -Raw (New-C3fValRaw -Err 'Acesso negado.' -Code 'AccessDenied'))
$c3fSign = @($c3fRows | Where-Object { [string]$_.Item -eq 'SMB server signing: dc1.contoso.com' })[0]
Assert-True ([string]$c3fSign.Status -eq 'Pass' -and [string]$c3fSign.Detail -match 'second instrument, Get-SmbServerConfiguration RequireSecuritySignature, was not read \(access denied - Acesso negado') 'C3f: a refused SMB read leaves SMB server signing on the registry, with the cause of the missing second instrument'
Assert-Throws { Merge-AdfaDcHardeningConfig -BaseConfig $hardCfg -Override @{ SmbServer = @{ Instrument = 'x' } } } "names 'SmbServer'" 'C3f: the SMB server read cannot be set from a file'
# 7. Advice and finding name one target when a file moved the expectation.
$hardMoved = Merge-AdfaDcHardeningConfig -BaseConfig $hardCfg -OverrideSource 'C:\cfg\hard.json' -Override @{ Settings = @{ LmCompatibilityLevel = @{ ExpectedMinimum = 3 }; LdapEnforceChannelBinding = @{ ExpectedMinimum = 1 } } }
$hardMovedRows = @(Get-AdfaDcHardeningFinding -DomainController 'dc1.contoso.com' -Scope '' -Config $hardMoved -Raw (New-HardRaw -Build '20348' -Numbers @{ LdapServerIntegrity = 2; LdapEnforceChannelBinding = 0; SmbServerSigning = 1; SmbClientSigning = 1; LmCompatibilityLevel = 0 }) |
        ForEach-Object { ConvertTo-AdfaConsolidatedFinding -Section 'DC Hardening' -Row $_ -StatusColumn 'Status' })
$hardMovedTwo = @($hardMovedRows | Where-Object { [string]$_.Item -match '^(LDAP channel binding|LAN Manager authentication level): ' })
Assert-Equal 2 (@($hardMovedTwo | Where-Object { [string]$_.Status -eq 'Warning' -and [string]$_.Recommendation -match 'to at least the expected minimum this finding names' -and [string]$_.Recommendation -notmatch '^Set the Group Policy setting' }).Count) 'Hardening advice: for the two settings a file can move, the advice points at the minimum the finding names and sets no fixed value of its own'
Assert-True ([string]@($hardMovedTwo | Where-Object { [string]$_.Item -match '^LAN Manager' })[0].Detail -match 'Below the expected minimum of 3 ' -and [string]@($hardMovedTwo | Where-Object { [string]$_.Item -match '^LDAP channel' })[0].Detail -match 'Below the expected minimum of 1 ') 'Hardening advice: non-vacuity - both findings do name the moved expectation'
# 13. A default that is not known cites its page in the row.
Assert-Equal 3 (@(@(@{ Id = 'LdapEnforceChannelBinding'; B = 26100 }, @{ Id = 'LmCompatibilityLevel'; B = 26100 }, @{ Id = 'SmbServerSigning'; B = 17763 }) | Where-Object { $v = Get-HardVerdict -Id $_.Id -Build $_.B; [string]$v.Status -eq 'Not Assessed' -and [string]$v.Detail -match 'default in force is not known' -and [string]$v.Detail -match 'Source: https://learn\.microsoft\.com/' }).Count) 'Hardening verdict: a row that is Not Assessed because no default is known cites the Microsoft page beside the claim (declared population: three settings)'
$hardOvr = Resolve-AdfaConfigOverride -Override ('{ "DcHardening": { "Settings": { "SmbClientSigning": { "OtherStatus": "Fail" } } } }' | ConvertFrom-Json) -BaseConfig $script:Config -Sections $script:ConfigOverrideSections -OverrideSource 'C:\cfg\all.json'
Assert-Equal 'DcHardening' (@($hardOvr.Keys) -join ',') 'Config override: the DcHardening section goes through its own validator'
Assert-Equal 'DcDisk,DcHardening,Laps,DcCertificates,RidPool,SidHistory,Gpo,Acl,Privileged,DcDiag,Dns,Reach,SiteCoverage,ClockSkew,Stale,SysvolEngine,Inventory' (@($script:ConfigOverrideSections.Keys) -join ',') 'Config override: declared population - the seventeen sections the file can carry (Inventory since v1.32.0, Reach, SiteCoverage, ClockSkew, Stale and SysvolEngine since v1.31.0, Dns since v1.30.0, DcDiag since v1.28.0, Privileged since v1.27.0, Acl since v1.26.0, Gpo since v1.25.0, SidHistory since v1.24.0)'

Write-Host "== Windows LAPS (C4): pure logic ==" -ForegroundColor Cyan
$lapsCfg = $script:Config.Laps
$lapsNow = [datetime]::SpecifyKind(([datetime]'2026-11-15T12:00:00'), [System.DateTimeKind]::Utc)
$lapsWin = 'msLAPS-PasswordExpirationTime'
$lapsLegacy = 'ms-Mcs-AdmPwdExpirationTime'
# Declared population: the seven attributes that are never requested.
$lapsSecret = @('msLAPS-Password', 'msLAPS-EncryptedPassword', 'msLAPS-EncryptedPasswordHistory', 'msLAPS-EncryptedDSRMPassword',
    'msLAPS-EncryptedDSRMPasswordHistory', 'msLAPS-CurrentPasswordVersion', 'ms-Mcs-AdmPwd')
$lapsFullSchema = @('operatingSystemVersion', 'msLAPS-PasswordExpirationTime', 'msLAPS-Password', 'msLAPS-EncryptedPassword', 'msLAPS-EncryptedPasswordHistory',
    'msLAPS-EncryptedDSRMPassword', 'msLAPS-EncryptedDSRMPasswordHistory')
function New-LapsSchema { param([string[]]$Names = $lapsFullSchema, [bool]$Ok = $true, [string]$Err = '', [string]$Type = '')
    [pscustomobject]@{ Ok = $Ok; Error = $Err; ErrorType = $Type; SchemaNamingContext = 'CN=Schema,CN=Configuration,DC=contoso,DC=com'; Names = @($Names) } }
function Get-LapsState { param([string[]]$Names = $lapsFullSchema) Get-AdfaLapsSchemaState -Raw (New-LapsSchema -Names $Names) -Config $lapsCfg }
function New-LapsRecord {
    param([string]$Name, [string]$Os = 'Windows 11 Enterprise', [string]$OsVersion = '10.0 (22631)', $Uac = 4096, $LogonDaysAgo = 1, $WinExpiryDays = $null, $LegacyExpiryDays = $null, [string[]]$Classes = @('computer'))
    $logon = $null; if ($null -ne $LogonDaysAgo) { $logon = $lapsNow.AddDays(-1 * [double]$LogonDaysAgo).ToFileTimeUtc() }
    $win = $null; if ($null -ne $WinExpiryDays) { $win = $lapsNow.AddDays([double]$WinExpiryDays).ToFileTimeUtc() }
    $legacy = $null; if ($null -ne $LegacyExpiryDays) { $legacy = $lapsNow.AddDays([double]$LegacyExpiryDays).ToFileTimeUtc() }
    [pscustomobject]@{ Name = $Name; OperatingSystem = $Os; OperatingSystemVersion = $OsVersion; UserAccountControl = $Uac
        LastLogonTimestamp = $logon; ObjectClasses = @($Classes); WindowsExpiry = $win; LegacyExpiry = $legacy }
}
function New-LapsRaw { param($Computers = @(), [string]$Level = '7', [bool]$Ok = $true, [string]$Err = '', [string]$Type = '')
    [pscustomobject]@{ Ok = $Ok; Refused = $false; Error = $Err; ErrorType = $Type; DomainLevel = $Level; DomainLevelError = ''; Computers = @($Computers); PropertyNames = @() } }
function Get-LapsRows { param($Computers = @(), [string[]]$SchemaNames = $lapsFullSchema, $Config = $lapsCfg, [int]$StaleDays = 90)
    @(Get-AdfaLapsDomainFinding -DomainName 'contoso.com' -Raw (New-LapsRaw -Computers $Computers) -SchemaState (Get-LapsState -Names $SchemaNames) -Config $Config -StaleDays $StaleDays -Now $lapsNow) }
function Get-LapsRow { param($Rows, [string]$Item) @($Rows | Where-Object { [string]$_.Item -eq $Item })[0] }
function Get-LapsDsrm { param($Build = 17763, [string]$Level = '7', $ExpiryDays = $null, [bool]$Proof = $true, [bool]$HasWindowsExpiry = $true, [bool]$ReadOnly = $false, [bool]$SchemaRead = $true)
    $expiry = $null; $present = $false
    if ($null -ne $ExpiryDays) { $expiry = $lapsNow.AddDays([double]$ExpiryDays); $present = $true }
    Get-AdfaLapsDsrmVerdict -Build $Build -DomainLevel $Level -ExpiryPresent $present -ExpiryUtc $expiry -Now $lapsNow -ProofOfRead $Proof -SchemaRead $SchemaRead -HasWindowsExpiry $HasWindowsExpiry -IsReadOnly $ReadOnly -Config $lapsCfg }
function Get-LapsCoverage { param([int]$In, [int]$None, [int]$Total = -1, [bool]$Proof = $true, [bool]$HasExpiry = $true, $Config = $lapsCfg)
    if ($Total -lt 0) { $Total = $In }
    Get-AdfaLapsCoverageVerdict -TotalReturned $Total -InPopulation $In -NoneVisible $None -ProofOfRead $Proof -SchemaHasExpiry $HasExpiry -Config $Config }

# The hard rule: no password attribute is ever requested.
Assert-Equal ($lapsSecret -join ',') (@($lapsCfg['NeverRead']) -join ',') 'LAPS config: the never-read list is the seven confidential attributes, in order (declared population: seven)'
Assert-Equal 0 (@(Get-AdfaLapsRefusedProperty -PropertyNames @($lapsCfg['ComputerProperties']) -NeverRead @($lapsCfg['NeverRead'])).Count) 'LAPS guard: the fixed property list holds nothing that is refused'
Assert-Equal 7 (@($lapsSecret | Where-Object { @(Get-AdfaLapsRefusedProperty -PropertyNames @('operatingSystem', $_) -NeverRead $lapsSecret).Count -eq 1 }).Count) 'LAPS guard: each of the seven secret names is refused (declared population: seven)'
Assert-Equal 0 (@(Get-AdfaLapsRefusedProperty -PropertyNames @($lapsWin, $lapsLegacy) -NeverRead $lapsSecret).Count) 'LAPS guard: the two expiry attributes are not refused, although their names hold "Password" and "Pwd"'
Assert-Equal 3 (@(Get-AdfaLapsRefusedProperty -PropertyNames @('*', 'unicodePwd', ' ') -NeverRead $lapsSecret).Count) 'LAPS guard: a wildcard, a password-like name on no list and a blank are refused'
Assert-Equal 1 (@(Get-AdfaLapsRefusedProperty -PropertyNames @('operatingSystem') -NeverRead @()).Count) 'LAPS guard: with no never-read list everything is refused (fail closed)'
$lapsAllSchema = @($lapsFullSchema + @('msLAPS-CurrentPasswordVersion', $lapsLegacy, 'ms-Mcs-AdmPwd'))
Assert-Equal ("operatingSystem,operatingSystemVersion,userAccountControl,lastLogonTimestamp,dNSHostName,objectClass,{0},{1}" -f $lapsWin, $lapsLegacy) (@(Get-AdfaLapsPropertyList -SchemaState (Get-LapsState -Names $lapsAllSchema) -Config $lapsCfg) -join ',') 'LAPS property list: the fixed names plus the two expiry attributes, and nothing else, when the schema holds all nine'
$lapsBadCfg = @{} + $lapsCfg; $lapsBadCfg['WindowsExpiry'] = 'msLAPS-Password'
Assert-Throws { Get-AdfaLapsPropertyList -SchemaState (Get-AdfaLapsSchemaState -Raw (New-LapsSchema) -Config $lapsBadCfg) -Config $lapsBadCfg } 'never read' 'LAPS property list: a config that pointed the expiry name at a password attribute is a terminating error'
$lapsSeamCalls = 0
function Get-ADDomain { param([Parameter(ValueFromRemainingArguments)]$a) $script:lapsSeamCalls++; [pscustomobject]@{ DistinguishedName = 'DC=contoso,DC=com' } }
function Get-ADObject { param([Parameter(ValueFromRemainingArguments)]$a) $script:lapsSeamCalls++; [pscustomobject]@{ 'msDS-Behavior-Version' = 7 } }
function Get-ADComputer { param([Parameter(ValueFromRemainingArguments)]$a) $script:lapsSeamCalls++; @() }
$script:lapsSeamCalls = 0
$lapsRefused = Get-AdfaLapsDirectoryRaw -DomainName 'contoso.com' -PropertyNames @('operatingSystem', 'ms-Mcs-AdmPwd') -NeverRead $lapsSecret
Assert-True ($lapsRefused.Refused -and -not $lapsRefused.Ok -and $script:lapsSeamCalls -eq 0) 'LAPS seam: a list holding a secret attribute is refused before any directory call'
$lapsClean = Get-AdfaLapsDirectoryRaw -DomainName 'contoso.com' -PropertyNames @('operatingSystem') -NeverRead $lapsSecret
Assert-True (-not $lapsClean.Refused -and $lapsClean.Ok -and $script:lapsSeamCalls -eq 3) 'LAPS seam: non-vacuity - a clean list does reach the directory, in three calls'

# FILETIME, the same on both editions.
$lapsWhen = [datetime]::SpecifyKind(([datetime]'2026-12-01T08:30:00'), [System.DateTimeKind]::Utc)
Assert-Equal $lapsWhen.ToString('o') (ConvertTo-AdfaFileTimeUtc -Value $lapsWhen.ToFileTimeUtc()).ToString('o') 'FILETIME: a 64-bit count is read as the UTC instant it denotes'
Assert-Equal $lapsWhen.ToString('o') (ConvertTo-AdfaFileTimeUtc -Value ([string]$lapsWhen.ToFileTimeUtc())).ToString('o') 'FILETIME: the same count as text gives the same instant'
Assert-True ($null -eq (ConvertTo-AdfaFileTimeUtc -Value ([int64]::MaxValue)) -and $null -eq (ConvertTo-AdfaFileTimeUtc -Value ([int64]-1)) -and $null -eq (ConvertTo-AdfaFileTimeUtc -Value 'x') -and $null -eq (ConvertTo-AdfaFileTimeUtc -Value $null)) 'FILETIME: the directory''s "never", a negative count, text and null are not a time, and nothing throws'

# Schema: absent, present and "the query failed" are three results.
Assert-Equal 'Complete,Partial,LegacyOnly,Absent,ControlMissing,NotRead' ((@(
            (Get-LapsState).State
            (Get-LapsState -Names @('operatingSystemVersion', $lapsWin)).State
            (Get-LapsState -Names @('operatingSystemVersion', $lapsLegacy)).State
            (Get-LapsState -Names @('operatingSystemVersion')).State
            (Get-LapsState -Names @($lapsWin)).State
            (Get-AdfaLapsSchemaState -Raw (New-LapsSchema -Ok $false -Err 'boom' -Names @()) -Config $lapsCfg).State) -join ',')) 'LAPS schema: the six states (declared population: six)'
Assert-Equal 'Pass,Warning,Info,Info,Not Assessed,Not Assessed' ((@(
            (Get-LapsState)
            (Get-LapsState -Names @('operatingSystemVersion', $lapsWin))
            (Get-LapsState -Names @('operatingSystemVersion', $lapsLegacy))
            (Get-LapsState -Names @('operatingSystemVersion'))
            (Get-LapsState -Names @($lapsWin))
            (Get-AdfaLapsSchemaState -Raw (New-LapsSchema -Ok $false -Err 'boom' -Names @()) -Config $lapsCfg)) | ForEach-Object { [string](Get-AdfaLapsSchemaFinding -SchemaState $_ -Config $lapsCfg).Status }) -join ',') 'LAPS schema row: complete passes, partial warns, legacy-only and absent are Info, an answer without the control attribute and a failed query are Not Assessed'
Assert-Equal 'Unreachable,AccessDenied,Error' ((@(
            (Get-AdfaDirectoryReadErrorClass -TypeName 'Microsoft.ActiveDirectory.Management.ADServerDownException' -Message 'x')
            (Get-AdfaDirectoryReadErrorClass -TypeName 'System.UnauthorizedAccessException' -Message 'Unable to contact the server')
            (Get-AdfaDirectoryReadErrorClass -TypeName 'System.Exception' -Message 'A referral was returned from the server')) -join ',')) 'Directory read failure: unreachable, access denied and anything else are three classes, the exception type deciding before the text'

# Population: who is graded.
$lapsCutoff = $lapsNow.AddDays(-90)
Assert-Equal 'InPopulation,ServiceAccount,DomainController,DomainController,AccountControlNotRead,Disabled,NoOperatingSystem,NonWindows,BuildNotRead,NotCapable,NoLogonRecorded,Stale' ((@(
            (New-LapsRecord -Name 'ws1')
            (New-LapsRecord -Name 'gmsa1$' -Classes @('msDS-GroupManagedServiceAccount'))
            (New-LapsRecord -Name 'dc1' -Uac 532480)
            (New-LapsRecord -Name 'rodc1' -Uac 83890176)
            (New-LapsRecord -Name 'ws2' -Uac $null)
            (New-LapsRecord -Name 'ws3' -Uac 4098)
            (New-LapsRecord -Name 'cluster1' -Os '' -OsVersion '')
            (New-LapsRecord -Name 'linux1' -Os 'Ubuntu' -OsVersion '22.04')
            (New-LapsRecord -Name 'ws4' -OsVersion '')
            (New-LapsRecord -Name 'old1' -Os 'Windows Server 2016 Standard' -OsVersion '10.0 (14393)')
            (New-LapsRecord -Name 'ws5' -LogonDaysAgo $null)
            (New-LapsRecord -Name 'ws6' -LogonDaysAgo 91)) | ForEach-Object { Get-AdfaLapsComputerClass -Computer $_ -Config $lapsCfg -StaleCutoffUtc $lapsCutoff }) -join ',') 'LAPS population: each kind of computer object falls in its own class (declared population: twelve objects, eleven classes)'
Assert-Equal 'NotCapable,InPopulation,NotCapable,NotCapable,InPopulation,InPopulation' ((@(17762, 17763, 17764, 19040, 19041, 26100) | ForEach-Object {
            Get-AdfaLapsComputerClass -Computer (New-LapsRecord -Name 'x' -OsVersion ("10.0 ({0})" -f $_)) -Config $lapsCfg -StaleCutoffUtc $lapsCutoff }) -join ',') 'LAPS population: capable is build 17763, and 19041 and later - both edges of both ranges'
$lapsEdge = New-LapsRecord -Name 'edge'
$lapsEdge.LastLogonTimestamp = $lapsCutoff.ToFileTimeUtc()
$lapsAtCutoff = Get-AdfaLapsComputerClass -Computer $lapsEdge -Config $lapsCfg -StaleCutoffUtc $lapsCutoff
$lapsEdge.LastLogonTimestamp = $lapsCutoff.ToFileTimeUtc() - 1
Assert-Equal 'InPopulation,Stale' ("{0},{1}" -f $lapsAtCutoff, (Get-AdfaLapsComputerClass -Computer $lapsEdge -Config $lapsCfg -StaleCutoffUtc $lapsCutoff)) 'LAPS population: an account at the stale cutoff is in, one tick older is out (off by one)'

# Coverage verdict.
Assert-Equal 'Not Assessed/NoObjects,Info/EmptyPopulation,Warning/SchemaAbsent,Not Assessed/NoProofOfRead,Pass/AllVisible,Warning/AboveWarn' ((@(
            (Get-LapsCoverage -In 0 -None 0 -Total 0)
            (Get-LapsCoverage -In 0 -None 0 -Total 5)
            (Get-LapsCoverage -In 4 -None 4 -HasExpiry $false -Proof $false)
            (Get-LapsCoverage -In 4 -None 4 -Proof $false)
            (Get-LapsCoverage -In 4 -None 0)
            (Get-LapsCoverage -In 4 -None 1)) | ForEach-Object { "{0}/{1}" -f $_.Status, $_.State }) -join ',') 'LAPS coverage verdict: the six outcomes of the built-in thresholds - nothing readable is never a Pass and never a Warning'
$lapsMoved = Merge-AdfaLapsConfig -BaseConfig $lapsCfg -Override @{ WarnAbovePercent = 10; FailAbovePercent = 50 }
Assert-Equal 'Pass,Warning,Warning,Fail' ((@(1, 2, 5, 6) | ForEach-Object { [string](Get-LapsCoverage -In 10 -None $_ -Config $lapsMoved).Status }) -join ',') 'LAPS coverage verdict: a share equal to a threshold is not above it (10 % and 50 % of ten computers)'

# DSRM verdict.
Assert-Equal 'Pass/Current,Warning/Expired,Warning/NoneVisible,Not Assessed/NoProofOfRead,Warning/SchemaAbsent,Not Assessed/SchemaNotRead,Info/NotApplicableLevel,Info/NotApplicableBuild,Not Assessed/LevelNotRead,Not Assessed/LevelUnknown,Not Assessed/BuildNotRead,Not Assessed/RodcNotPublished' ((@(
            (Get-LapsDsrm -ExpiryDays 20)
            (Get-LapsDsrm -ExpiryDays -30)
            (Get-LapsDsrm)
            (Get-LapsDsrm -Proof $false)
            (Get-LapsDsrm -HasWindowsExpiry $false)
            (Get-LapsDsrm -SchemaRead $false)
            (Get-LapsDsrm -Level '6' -ExpiryDays 20)
            (Get-LapsDsrm -Build 14393)
            (Get-LapsDsrm -Level '' -ExpiryDays 20)
            (Get-LapsDsrm -Level '8')
            (Get-LapsDsrm -Build $null -ExpiryDays 20)
            (Get-LapsDsrm -ReadOnly $true)) | ForEach-Object { "{0}/{1}" -f $_.Status, $_.State }) -join ',') 'LAPS DSRM verdict: twelve states (declared population: twelve) - an ineligible DC is Info, an unread level or build is Not Assessed'
Assert-Equal 'NotApplicableBuild,NoneVisible,NotApplicableLevel,NoneVisible' ("{0},{1},{2},{3}" -f (Get-LapsDsrm -Build 17762).State, (Get-LapsDsrm -Build 17763).State, (Get-LapsDsrm -Level '6').State, (Get-LapsDsrm -Level '7').State) 'LAPS DSRM verdict: the eligibility lines are build 17763 and domain level 7, not one below (off by one)'
$lapsGrace = [int]$lapsCfg['ExpiredGraceDays']
Assert-Equal 'Current,Expired' ("{0},{1}" -f (Get-AdfaLapsDsrmVerdict -Build 17763 -DomainLevel '7' -ExpiryPresent $true -ExpiryUtc $lapsNow.AddDays(-1 * $lapsGrace) -Now $lapsNow -ProofOfRead $true -SchemaRead $true -HasWindowsExpiry $true -IsReadOnly $false -Config $lapsCfg).State,
    (Get-AdfaLapsDsrmVerdict -Build 17763 -DomainLevel '7' -ExpiryPresent $true -ExpiryUtc $lapsNow.AddDays(-1 * $lapsGrace).AddSeconds(-1) -Now $lapsNow -ProofOfRead $true -SchemaRead $true -HasWindowsExpiry $true -IsReadOnly $false -Config $lapsCfg).State) 'LAPS DSRM verdict: exactly the grace period after the expiry time is still current, one second more is expired'

# Rows.
$lapsMixed = @(
    (New-LapsRecord -Name 'dc1.contoso.com' -Os 'Windows Server 2019 Standard' -OsVersion '10.0 (17763)' -Uac 532480 -WinExpiryDays 20)
    (New-LapsRecord -Name 'dc2.contoso.com' -Os 'Windows Server 2019 Standard' -OsVersion '10.0 (17763)' -Uac 532480)
    (New-LapsRecord -Name 'ws1.contoso.com' -WinExpiryDays 3)
    (New-LapsRecord -Name 'ws2.contoso.com')
    (New-LapsRecord -Name 'linux1.contoso.com' -Os 'Ubuntu' -OsVersion '22.04')
    (New-LapsRecord -Name 'cluster1.contoso.com' -Os '' -OsVersion '')
    (New-LapsRecord -Name 'ws-off.contoso.com' -Uac 4098))
$lapsRows = Get-LapsRows -Computers $lapsMixed
Assert-Equal 3 $lapsRows.Count 'LAPS rows: one coverage row and one DSRM row per domain controller (declared population: one domain, two DCs)'
$lapsCovRow = Get-LapsRow $lapsRows 'LAPS coverage: contoso.com'
Assert-True ([string]$lapsCovRow.Status -eq 'Warning' -and [string]$lapsCovRow.Detail -match '^1 of 2 computer account\(s\) in population \(50 %\) have no LAPS expiry time visible to this account' -and [string]$lapsCovRow.Detail -match 'No LAPS expiry time visible: ws2\.contoso\.com\.') 'LAPS coverage row: the share is over the population, and only an in-population computer is named'
Assert-True ([string]$lapsCovRow.Detail -notmatch 'visible: .*(linux1|cluster1|ws-off)' -and [string]$lapsCovRow.Detail -match 'disabled 1; no operatingSystem recorded 1; operatingSystem not Windows 1') 'LAPS coverage row: a non-Windows host, a cluster object and a disabled account are counted out of the population, never named as missing LAPS'
Assert-True ([string]$lapsCovRow.Detail -match 'tool default, not a Microsoft value' -and [string]$lapsCovRow.Detail -match 'not set and not readable look the same' -and [string]$lapsCovRow.Detail -match 'Microsoft Entra ID') 'LAPS coverage row: the thresholds are labelled tool defaults, and the row says what it cannot tell apart or see'
Assert-Equal 'Pass,Warning' ("{0},{1}" -f (Get-LapsRow $lapsRows 'DSRM password backup: dc1.contoso.com').Status, (Get-LapsRow $lapsRows 'DSRM password backup: dc2.contoso.com').Status) 'LAPS DSRM rows: every DC gets its own row and its own verdict, not only the first'
Assert-Equal 0 (@($lapsRows | Where-Object { $null -eq $_.PSObject.Properties['NotRun'] }).Count) 'LAPS rows: every row carries the NotRun column'
$lapsQuiet = Get-LapsRows -Computers @((New-LapsRecord -Name 'dc1.contoso.com' -Os 'Windows Server 2019 Standard' -OsVersion '10.0 (17763)' -Uac 532480), (New-LapsRecord -Name 'ws1'), (New-LapsRecord -Name 'ws2'))
Assert-Equal 2 (@($lapsQuiet | Where-Object { [string]$_.Status -eq 'Not Assessed' }).Count) 'LAPS rows: with the attribute in the schema and no value visible anywhere, the coverage row and the DC row are both Not Assessed - never Warning, never Pass'
$lapsNoSchema = Get-LapsRows -Computers @((New-LapsRecord -Name 'ws1'), (New-LapsRecord -Name 'ws2')) -SchemaNames @('operatingSystemVersion')
Assert-True ([string](Get-LapsRow $lapsNoSchema 'LAPS coverage: contoso.com').Status -eq 'Warning' -and [string](Get-LapsRow $lapsNoSchema 'LAPS coverage: contoso.com').Detail -match '^The forest schema carries neither ') 'LAPS rows: a schema with neither expiry attribute is a measured absence - a Warning that names the schema as the cause'
$lapsFailed = @(@(
        (New-LapsRaw -Ok $false -Err 'Unable to contact the server.' -Type 'Microsoft.ActiveDirectory.Management.ADServerDownException')
        (New-LapsRaw -Ok $false -Err 'Access is denied' -Type 'System.UnauthorizedAccessException')
        (New-LapsRaw -Ok $false -Err 'A referral was returned from the server' -Type 'Microsoft.ActiveDirectory.Management.ADException')) | ForEach-Object {
        $r = @(Get-AdfaLapsDomainFinding -DomainName 'contoso.com' -Raw $_ -SchemaState (Get-LapsState) -Config $lapsCfg -StaleDays 90 -Now $lapsNow)
        "{0}:{1}:{2}" -f $r.Count, (@($r | Where-Object { [string]$_.Status -eq 'Not Assessed' }).Count), (([string]$r[0].Detail -split ':')[0]) })
Assert-Equal '2:2:Unreachable,2:2:Access denied,2:2:Read failed' ($lapsFailed -join ',') 'LAPS rows: a failed read gives the domain two Not Assessed rows, and unreachable, access denied and another failure are worded apart'
$lapsMany = @(New-LapsRecord -Name 'ws-ok' -WinExpiryDays 5)
foreach ($i in 1..30) { $lapsMany += New-LapsRecord -Name ("ws{0:d2}.contoso.com" -f $i) }
$lapsManyRow = Get-LapsRow (Get-LapsRows -Computers $lapsMany) 'LAPS coverage: contoso.com'
Assert-True ([string]$lapsManyRow.Detail -match 'showing 25 of 30, in name order' -and [string]$lapsManyRow.Detail -match 'ws25\.contoso\.com\.' -and [string]$lapsManyRow.Detail -notmatch 'ws26\.contoso\.com') 'LAPS coverage row: the names are capped at SampleLimit, and the row says it cut the list'
Assert-True ([string](Get-LapsRow (Get-LapsRows -Computers $lapsMany -Config (Merge-AdfaLapsConfig -BaseConfig $lapsCfg -Override @{ SampleLimit = 30 })) 'LAPS coverage: contoso.com').Detail -notmatch 'showing') 'LAPS coverage row: at the limit exactly nothing is cut (off by one)'

# Config override.
$lapsMerged = Merge-AdfaLapsConfig -BaseConfig $lapsCfg -Override ('{ "WarnAbovePercent": 5, "SampleLimit": 10 }' | ConvertFrom-Json) -OverrideSource 'C:\cfg\laps.json'
Assert-True ([double]$lapsMerged['WarnAbovePercent'] -eq 5 -and [int]$lapsMerged['SampleLimit'] -eq 10 -and [double]$lapsMerged['FailAbovePercent'] -eq 100 -and [string]$lapsMerged['ThresholdSource'] -match 'for WarnAbovePercent, SampleLimit; tool default, not a Microsoft value, for FailAbovePercent, ExpiredGraceDays') 'LAPS override: only the named keys change, and the source is cited for exactly those'
Assert-Equal 'tool default, not a Microsoft value' ([string]$lapsCfg['ThresholdSource']) 'LAPS override: the built-in table is not changed by a merge'
Assert-Throws { Merge-AdfaLapsConfig -BaseConfig $lapsCfg -Override @(1, 2) } 'single object' 'LAPS override: an array is refused'
Assert-Throws { Merge-AdfaLapsConfig -BaseConfig $lapsCfg -Override ('{}' | ConvertFrom-Json) } 'empty object' 'LAPS override: an empty object is refused'
Assert-Throws { Merge-AdfaLapsConfig -BaseConfig $lapsCfg -Override @{ Typo = 1 } } "unknown key 'Typo'" 'LAPS override: an unknown key is refused'
Assert-Throws { Merge-AdfaLapsConfig -BaseConfig $lapsCfg -Override @{ NeverRead = @() } } "unknown key 'NeverRead'" 'LAPS override: the never-read list cannot be set from a file'
Assert-Throws { Merge-AdfaLapsConfig -BaseConfig $lapsCfg -Override @{ WindowsExpiry = 'ms-Mcs-AdmPwd' } } "unknown key 'WindowsExpiry'" 'LAPS override: an attribute name cannot be set from a file'
Assert-Throws { Merge-AdfaLapsConfig -BaseConfig $lapsCfg -Override ('{ "SampleLimit": null }' | ConvertFrom-Json) } 'to null' 'LAPS override: a null is refused'
Assert-Throws { Merge-AdfaLapsConfig -BaseConfig $lapsCfg -Override ('{ "SampleLimit": [] }' | ConvertFrom-Json) } 'JSON number' 'LAPS override: an empty list is refused'
Assert-Throws { Merge-AdfaLapsConfig -BaseConfig $lapsCfg -Override @{ WarnAbovePercent = '5' } } 'JSON number' 'LAPS override: a number written as a string is refused'
Assert-Throws { Merge-AdfaLapsConfig -BaseConfig $lapsCfg -Override @{ FailAbovePercent = 101 } } 'range 0 to 100' 'LAPS override: a percentage above 100 is refused'
Assert-Throws { Merge-AdfaLapsConfig -BaseConfig $lapsCfg -Override @{ WarnAbovePercent = 100 } } 'would ever be reported' 'LAPS override: a Warning threshold nothing can exceed is refused - it would switch the check off'
Assert-Throws { Merge-AdfaLapsConfig -BaseConfig $lapsCfg -Override @{ WarnAbovePercent = 30; FailAbovePercent = 20 } } 'is below WarnAbovePercent' 'LAPS override: Fail below Warning is refused'
Assert-Throws { Merge-AdfaLapsConfig -BaseConfig $lapsCfg -Override @{ SampleLimit = 1001 } } 'whole number from 0 to 1000' 'LAPS override: a sample of thousands is refused'
Assert-Throws { Merge-AdfaLapsConfig -BaseConfig $lapsCfg -Override @{ ExpiredGraceDays = -1 } } 'whole number of days from 0 to 365' 'LAPS override: a negative grace period is refused'
$lapsOvr = Resolve-AdfaConfigOverride -Override ('{ "Laps": { "FailAbovePercent": 50 } }' | ConvertFrom-Json) -BaseConfig $script:Config -Sections $script:ConfigOverrideSections -OverrideSource 'C:\cfg\all.json'
Assert-True ((@($lapsOvr.Keys) -join ',') -eq 'Laps' -and [double]$lapsOvr['Laps']['FailAbovePercent'] -eq 50) 'Config override: the Laps section goes through its own validator'

# Recommendations: section-scoped, anchored on the Item the tool writes.
$lapsHostile = 'Threshold source: C:\Backup\replication\sysvol-dfsr\stale.json. managing aging scavenging password policy lockout global catalog tombstone lifetime krbtgt'
Assert-True ((Get-AdfaRecommendation -Section 'Windows LAPS' -Item 'LAPS coverage: backup.contoso.com' -Detail $lapsHostile) -match 'Set-LapsADComputerSelfPermission' -and (Get-AdfaRecommendation -Section 'Windows LAPS' -Item 'DSRM password backup: dc1.contoso.com' -Detail $lapsHostile) -match 'ADBackupDSRMPassword' -and (Get-AdfaRecommendation -Section 'Windows LAPS' -Item 'Windows LAPS schema' -Detail $lapsHostile) -match 'Update-LapsADSchema') 'LAPS advice: each row family gets its own advice whatever the detail, the host name or a file path contains (declared population: three families)'
Assert-Equal '' (Get-AdfaRecommendation -Section 'Windows LAPS' -Item 'DSRM password backup - contoso.com' -Detail $lapsHostile) 'LAPS advice: a row of the section with no advice of its own gets none, not an unrelated one'
Assert-True ((Get-AdfaRecommendation -Section 'Somewhere Else' -Item 'x' -Detail $lapsHostile) -ne '') 'LAPS advice: non-vacuity - the same text outside the section does attract advice'

# Found by the independent review of the C4 diff, and fixed in it.
Assert-Equal 'TimedOut,TimedOut,Unreachable,AccessDenied' ((@(
            (Get-AdfaDirectoryReadErrorClass -TypeName 'System.TimeoutException' -Message 'x')
            (Get-AdfaDirectoryReadErrorClass -TypeName 'System.ServiceModel.ServerTooBusyException' -Message 'x')
            (Get-AdfaDirectoryReadErrorClass -TypeName 'System.Exception' -Message 'The server is unavailable')
            (Get-AdfaDirectoryReadErrorClass -TypeName 'System.ServiceModel.Security.SecurityAccessDeniedException' -Message 'x'))) -join ',') 'Directory read failure: a timeout or a busy server is its own class, not "unreachable" (declared population: four patterns)'
$lapsTimeoutLead = Get-AdfaLapsReadFailureLead -Message 'Tempo limite excedido' -TypeName 'System.TimeoutException' -What 'the computer objects of contoso.com'
Assert-True ($lapsTimeoutLead -match '^Timed out: ' -and $lapsTimeoutLead -notmatch 'no directory server answered') 'LAPS rows: a timed-out query does not say that no directory server answered'
$lapsEndOfTime = [datetime]::SpecifyKind([datetime]::MaxValue, [System.DateTimeKind]::Utc)
$lapsEndStates = @()
foreach ($lapsGraceCfg in @($lapsCfg, (Merge-AdfaLapsConfig -BaseConfig $lapsCfg -Override @{ ExpiredGraceDays = 365 }))) {
    foreach ($lapsEnd in @($lapsEndOfTime, $lapsEndOfTime.AddDays(-3))) {
        $lapsEndStates += [string](Get-AdfaLapsDsrmVerdict -Build 20348 -DomainLevel '7' -ExpiryPresent $true -ExpiryUtc $lapsEnd -Now $lapsNow -ProofOfRead $true -SchemaRead $true -HasWindowsExpiry $true -IsReadOnly $false -Config $lapsGraceCfg).State
    }
}
Assert-Equal 'Current,Current,Current,Current' ($lapsEndStates -join ',') 'LAPS DSRM verdict: an expiry time at the end of the calendar is current and does not throw, with 7 or 365 days of grace (declared population: four)'
$lapsUnc = Get-LapsRows -Computers @(
    (New-LapsRecord -Name 'dc1.contoso.com' -Os 'Windows Server 2019 Standard' -OsVersion '10.0 (17763)' -Uac 532480 -WinExpiryDays 5)
    (New-LapsRecord -Name 'ws1.contoso.com' -WinExpiryDays 5)
    (New-LapsRecord -Name 'ws-nobuild.contoso.com' -OsVersion '')
    (New-LapsRecord -Name 'dc2.contoso.com' -Uac $null))
Assert-Equal 'Not Assessed' ([string](Get-LapsRow $lapsUnc 'LAPS coverage: contoso.com').Status) 'LAPS coverage row: objects that could not be classified keep a would-be Pass at Not Assessed'
Assert-True ([string](Get-LapsRow $lapsUnc 'DSRM password backup - contoso.com').Status -eq 'Not Assessed' -and [string](Get-LapsRow $lapsUnc 'DSRM password backup - contoso.com').Detail -match 'Without account control flags: dc2\.contoso\.com\.') 'LAPS DSRM rows: an object without account control flags, which may be a DC, is named in a Not Assessed row'
$lapsBoth = Get-LapsRow (Get-LapsRows -Computers @((New-LapsRecord -Name 'ws-both' -WinExpiryDays 5 -LegacyExpiryDays 5), (New-LapsRecord -Name 'ws-legacy' -LegacyExpiryDays 5)) -SchemaNames @($lapsFullSchema + @($lapsLegacy))) 'LAPS coverage: contoso.com'
Assert-True ([string]$lapsBoth.Detail -match 'Windows LAPS expiry time visible 1; legacy Microsoft LAPS expiry time only 1;') 'LAPS coverage row: a computer with both expiry times counts as Windows LAPS, once'
Assert-Throws { Merge-AdfaLapsConfig -BaseConfig $lapsCfg -Override @{ ExpiredGraceDays = 366 } } 'whole number of days from 0 to 365' 'LAPS override: a grace period over a year is refused'

# PORT-PLAN C4b (v1.33.0) replaced the C4 mitigation: the Identity export asks for a declared list and
# keeps only those columns, so nothing the directory hands back beyond the list reaches the CSV. Pure
# logic only; the read itself is exercised by the Pester tests and the smoke test.
$c4bOdd = [pscustomobject]@{ DistinguishedName = 'CN=WS2,CN=Computers,DC=contoso,DC=com'; Name = 'WS2'; operatingSystem = 'Windows 11 Enterprise'; userAccountControl = 4096 }
$c4bOdd | Add-Member -NotePropertyName 'MS-MCS-ADMPWD' -NotePropertyValue 'STUB-ODD-CASE'
$c4bOdd | Add-Member -NotePropertyName 'mslaps-encryptedpassword' -NotePropertyValue 'STUB-ODD-CASE'
$c4bRaw = [pscustomobject]@{ Ok = $true; Error = ''; ErrorType = ''; NotFound = $false; Records = @($c4bOdd); Count = 1; Capped = $false; Filter = '(objectClass=computer)'; Identity = ''; Refused = $false }
$c4bExport = ConvertTo-AdfaIdentityExport -Kind Computer -Raw $c4bRaw -Columns @($script:Config.DirectoryRead['ComputerExportProperties'])
$c4bColumns = @($c4bExport.Rows[0].PSObject.Properties | ForEach-Object { $_.Name })
Assert-True ((($c4bExport.Rows | ConvertTo-Csv -NoTypeInformation) -join ' ') -notmatch 'STUB-ODD-CASE' -and $c4bColumns -notcontains 'ms-Mcs-AdmPwd' -and $c4bColumns -contains 'operatingSystem') 'C4b: the computer export keeps the declared columns only; a LAPS password the answer carried, in any case, is in no row'
Assert-Equal ((@($script:Config.DirectoryRead['ComputerExportProperties']) + @('Enabled', 'ListComplete')) -join ',') ($c4bColumns -join ',') 'C4b: the export columns are the declared list, in order, then Enabled and ListComplete'
Assert-Equal $true $c4bExport.Rows[0].Enabled 'C4b: Enabled from userAccountControl 4096 (ACCOUNTDISABLE clear) is True'
$c4bSecret = @(Get-AdfaSecretAttributeName)
Assert-Equal 24 $c4bSecret.Count 'C4b: the secret list is the seven LAPS names and the seventeen of DirectoryRead.SecretNames (declared population: 24)'
foreach ($c4bName in @('ms-Mcs-AdmPwd', 'msLAPS-Password', 'unicodePwd', 'supplementalCredentials', 'msDS-ManagedPassword', 'trustAuthIncoming', 'trustAuthOutgoing', 'msTPM-OwnerInformation', 'msFVE-RecoveryPassword')) {
    Assert-Equal $c4bName.ToUpperInvariant() (@(Get-AdfaRefusedPropertyName -PropertyNames @('name', $c4bName.ToUpperInvariant()) -SecretNames $c4bSecret) -join ',') ("C4b: the guard refuses {0}, whatever its case, and only it" -f $c4bName)
}
Assert-Equal 1 @(Get-AdfaRefusedPropertyName -PropertyNames @('name', '*') -SecretNames $c4bSecret).Count 'C4b: the guard refuses a wildcard'
Assert-Equal 1 @(Get-AdfaRefusedPropertyName -PropertyNames @('name', 'msLAPS-*') -SecretNames $c4bSecret).Count 'C4b: the guard refuses a partial wildcard'
Assert-Equal 1 @(Get-AdfaRefusedPropertyName -PropertyNames @() -SecretNames $c4bSecret).Count 'C4b: the guard refuses an empty list'
Assert-Equal 2 @(Get-AdfaRefusedPropertyName -PropertyNames @('name', 'cn') -SecretNames @()).Count 'C4b: with no secret list to check against, every name is refused'
Assert-Equal 0 @(Get-AdfaRefusedPropertyName -PropertyNames @('pwdLastSet', 'lastLogonTimestamp', 'msLAPS-PasswordExpirationTime') -SecretNames $c4bSecret).Count 'C4b: the guard has no shape rule - pwdLastSet and the LAPS expiry time are allowed'
foreach ($c4bList in @('UserExportProperties', 'ComputerExportProperties', 'TrustHealthProperties', 'SiteLinkProperties', 'ConnectionProperties')) {
    Assert-Equal 0 @(Get-AdfaRefusedPropertyName -PropertyNames @($script:Config.DirectoryRead[$c4bList]) -SecretNames $c4bSecret).Count ("C4b: DirectoryRead.{0} passes the guard" -f $c4bList)
}
$c4bBad = @{} + $script:Config.DirectoryRead
$c4bBad['UserExportProperties'] = @('name', 'unicodePwd')
$c4bRefused = Get-AdfaIdentityExportRaw -DomainName 'contoso.com' -Kind User -Config $c4bBad
Assert-True ($c4bRefused.Refused -and -not $c4bRefused.Ok -and [string]$c4bRefused.Error -match 'unicodePwd') 'C4b: an export list naming unicodePwd is refused before anything is sent'
$c4bRefusedCause = (ConvertTo-AdfaIdentityExport -Kind User -Raw $c4bRefused -Columns @('name')).Cause
$c4bSum = @(Get-AdfaIdentitySummary -DomainName 'contoso.com' -Users @() -Computers @() -UsersError $c4bRefusedCause -ComputersError 'x')
Assert-True (@($c4bSum | Where-Object { $_.Object -eq 'Users' -and $_.Status -eq 'Not Assessed' -and [string]$_.Total -eq '' -and $_.Detail -match 'refused' }).Count -eq 1) 'C4b: a refused export is Not Assessed in the summary, never 0'
$c4bEmpty = ConvertTo-AdfaIdentityExport -Kind User -Raw ([pscustomobject]@{ Ok = $true; Error = ''; ErrorType = ''; NotFound = $false; Records = @(); Count = 0; Capped = $false; Refused = $false }) -Columns @('name')
Assert-True ($c4bEmpty.Cause -match 'returned no object' -and @($c4bEmpty.Rows).Count -eq 0) 'C4b: an export that returned nothing is a cause, never 0'
$c4bDenied = ConvertTo-AdfaIdentityExport -Kind User -Raw ([pscustomobject]@{ Ok = $false; Error = 'Access is denied'; ErrorType = 'System.UnauthorizedAccessException'; NotFound = $false; Records = @(); Count = 0; Capped = $false; Refused = $false }) -Columns @('name')
Assert-True ($c4bDenied.Cause -match '\(access denied\)' -and $c4bDenied.Cause -notmatch 'unreachable') 'C4b: access denied is worded as access denied'
$c4bDown = ConvertTo-AdfaIdentityExport -Kind User -Raw ([pscustomobject]@{ Ok = $false; Error = 'Unable to contact the server.'; ErrorType = 'Microsoft.ActiveDirectory.Management.ADServerDownException'; NotFound = $false; Records = @(); Count = 0; Capped = $false; Refused = $false }) -Columns @('name')
Assert-True ($c4bDown.Cause -match '\(unreachable\)' -and $c4bDown.Cause -notmatch 'access denied') 'C4b: an unreachable domain is worded as unreachable'
$c4bCapped = ConvertTo-AdfaIdentityExport -Kind User -Raw ([pscustomobject]@{ Ok = $true; Error = ''; ErrorType = ''; NotFound = $false; Records = @($c4bOdd, $c4bOdd, $c4bOdd); Count = 3; Capped = $true; Refused = $false }) -Columns @('name') -MaxObjects 2
Assert-True (@($c4bCapped.Rows).Count -eq 2 -and @($c4bCapped.Rows | Where-Object { $_.ListComplete -like 'No:*' }).Count -eq 2 -and $c4bCapped.Cause -match 'cap of 2') 'C4b: a capped export keeps at most MaxObjects rows, each ListComplete No, with the cap as its cause'
$c4bLinks = @(ConvertTo-AdfaTopologyListRow -Kind SiteLink -Raw ([pscustomobject]@{ Ok = $false; Error = 'Access is denied'; ErrorType = 'System.UnauthorizedAccessException'; NotFound = $false; Refused = $false; Records = @(); Count = 0; Capped = $false }))
Assert-True ($c4bLinks.Count -eq 1 -and $c4bLinks[0].Status -eq 'Not Assessed' -and $c4bLinks[0].Detail -match '\(access denied\)') 'C4b: a site link read refused by the directory is one Not Assessed row, not an empty list'
$c4bConn = @(ConvertTo-AdfaTopologyListRow -Kind Connection -Raw ([pscustomobject]@{ Ok = $true; Error = ''; ErrorType = ''; NotFound = $false; Refused = $false; Records = @([pscustomobject]@{ name = 'c1'; distinguishedName = 'CN=c1,CN=NTDS Settings,CN=DC1'; fromServer = 'CN=NTDS Settings,CN=DC2'; enabledConnection = $true; options = 1 }); Count = 1; Capped = $false }))
Assert-True ($c4bConn.Count -eq 1 -and $c4bConn[0].FromServer -eq 'CN=NTDS Settings,CN=DC2' -and $c4bConn[0].Enabled -eq $true -and $c4bConn[0].Options -eq 1) 'C4b: a connection row carries fromServer, enabledConnection and options raw'
# Found by the independent review of C4b, before commit.
foreach ($c4bName in $c4bSecret) {
    Assert-Equal ("{0};binary" -f $c4bName) (@(Get-AdfaRefusedPropertyName -PropertyNames @('name', ("{0};binary" -f $c4bName)) -SecretNames $c4bSecret) -join ',') ("C4b: the guard refuses {0} with an attribute option" -f $c4bName)
}
Assert-Equal 1 @(Get-AdfaRefusedPropertyName -PropertyNames @('name', 'member;range=0-1') -SecretNames $c4bSecret).Count 'C4b: the guard refuses a name that is not a plain name (a range)'
Assert-Equal 1 @(Get-AdfaRefusedPropertyName -PropertyNames @('name', '1.2.3.4') -SecretNames $c4bSecret).Count 'C4b: the guard refuses a name that is not a plain name (an OID shape)'
$c4bInv = $script:Config.Inventory
Assert-Equal 'Inventory.MaxObjects, a tool default' (Get-AdfaCapSource -Config $c4bInv -BaseConfig $c4bInv -Key 'MaxObjects' -Label 'Inventory') 'C4b: the built-in cap is called a tool default'
$c4bFileInv = Merge-AdfaSpecConfig -BaseConfig $c4bInv -Override @{ MaxObjects = 2 } -OverrideSource 'C:\cfg\c4b.json'
$c4bCapSource = Get-AdfaCapSource -Config $c4bFileInv -BaseConfig $c4bInv -Key 'MaxObjects' -Label 'Inventory'
Assert-Equal 'Inventory.MaxObjects, set in the -ConfigOverridePath file' $c4bCapSource 'C4b: a cap the file set is said to come from the file'
Assert-Equal 'Inventory.MaxObjects, a tool default' (Get-AdfaCapSource -Config (Merge-AdfaSpecConfig -BaseConfig $c4bInv -Override @{ NameListCap = 5 } -OverrideSource 'C:\cfg\c4b.json') -BaseConfig $c4bInv -Key 'MaxObjects' -Label 'Inventory') 'C4b: a file that sets another key leaves the cap a tool default'
$c4bFileCapped = ConvertTo-AdfaIdentityExport -Kind User -Raw ([pscustomobject]@{ Ok = $true; Error = ''; ErrorType = ''; NotFound = $false; Records = @($c4bOdd, $c4bOdd, $c4bOdd); Count = 3; Capped = $true; Refused = $false }) -Columns @('name') -MaxObjects 2 -CapSource $c4bCapSource
Assert-True (@($c4bFileCapped.Rows | Where-Object { $_.ListComplete -match 'set in the -ConfigOverridePath file' -and $_.ListComplete -notmatch 'a tool default' }).Count -eq 2 -and $c4bFileCapped.Cause -match 'set in the -ConfigOverridePath file') 'C4b: an export capped by the file says so, not "a tool default"'
$c4bTimed = @(ConvertTo-AdfaTopologyListRow -Kind SiteLink -Raw ([pscustomobject]@{ Ok = $false; Error = 'The operation took longer than allowed.'; ErrorType = 'System.TimeoutException'; NotFound = $false; Refused = $false; Records = @(); Count = 0; Capped = $false }))
Assert-True ($c4bTimed.Count -eq 1 -and $c4bTimed[0].Detail -match '\(timed out\)') 'C4b: a timed-out topology read is classed from its exception type'
$c4bRefusedRow = @(ConvertTo-AdfaTopologyListRow -Kind Connection -Raw ([pscustomobject]@{ Ok = $false; Error = 'the property list was refused before anything was sent, because it names *'; ErrorType = ''; NotFound = $false; Refused = $true; Records = @(); Count = 0; Capped = $false }))
Assert-True ($c4bRefusedRow[0].Detail -match '^Reading the replication connection objects was refused:' -and $c4bRefusedRow[0].Detail -notmatch 'failed \(') 'C4b: a refused topology read is worded as refused, not as a failed read'

Write-Host "== DC certificates (C5): pure logic ==" -ForegroundColor Cyan
$certCfg = $script:Config.DcCertificates
$certNow = [datetime]::SpecifyKind(([datetime]'2026-11-16T12:00:00'), [System.DateTimeKind]::Utc)
$certDc = 'dc1.contoso.com'
function Get-CertVerdict { param($To, $From = -300, [int]$Warn = 30, [int]$Fail = 0)
    $nb = $null; $na = $null
    if ($null -ne $From) { $nb = $certNow.AddDays([double]$From) }
    if ($null -ne $To) { $na = $certNow.AddDays([double]$To) }
    Get-AdfaCertificateExpiryVerdict -NotBeforeUtc $nb -NotAfterUtc $na -NowUtc $certNow -WarnWithinDays $Warn -FailWithinDays $Fail -ThresholdSource 'tool default, not a Microsoft value' }
# Declared population: nine points on the expiry scale and their statuses.
$certScale = [ordered]@{ '65' = 'Pass'; '31' = 'Pass'; '30' = 'Warning'; '0.01' = 'Warning'; '0' = 'Fail'; '-1' = 'Fail'; 'notyet' = 'Warning'; 'missing' = 'Not Assessed'; 'reversed' = 'Not Assessed' }
$certGot = @()
foreach ($point in @($certScale.Keys)) {
    switch ($point) {
        'notyet' { $certGot += [string](Get-CertVerdict -To 400 -From 2).Status }
        'missing' { $certGot += [string](Get-CertVerdict -To $null).Status }
        'reversed' { $certGot += [string](Get-CertVerdict -To 5 -From 10).Status }
        default { $certGot += [string](Get-CertVerdict -To ([double]$point)).Status }
    }
}
Assert-Equal (@($certScale.Values) -join ',') ($certGot -join ',') 'Certificate expiry: 30 days left is a Warning, 31 a Pass, NotAfter equal to now and before it a Fail, not yet valid a Warning, unreadable or reversed dates Not Assessed (declared population: nine points)'
Assert-Equal 'FailWindow,ExpiringSoon' ((@((Get-CertVerdict -To 7 -Fail 7).State, (Get-CertVerdict -To 8 -Fail 7).State)) -join ',') 'Certificate expiry: a Fail window of 7 days fails at 7 days left and warns at 8'
Assert-True ([string](Get-CertVerdict -To 2 -From 2).Reason -match "this tool's rule, not a Microsoft value") 'Certificate expiry: a certificate not yet valid is labelled as this tool''s rule'
Assert-Equal 'ConnectRefused,ConnectTimedOut,Unresolved,Unresolved,Unresolved,ConnectFailed' ((@('ConnectionRefused', 'TimedOut', 'HostNotFound', 'TryAgain', 'NoData', 'ConnectionReset') | ForEach-Object { Get-AdfaSocketErrorClass -SocketError $_ }) -join ',') 'Certificate handshake: refused, timed out and unresolved are kept apart (declared population: six socket errors)'
Assert-Equal 'HandshakeTimedOut,HandshakeFailed' ((@((Get-AdfaTlsHandshakeErrorClass -SocketErrors @('TimedOut')), (Get-AdfaTlsHandshakeErrorClass -SocketErrors @()))) -join ',') 'Certificate handshake: a handshake that timed out is not a failed one'
Assert-Equal 'a\2ab\28c\29d\5ce\2ff' (ConvertTo-AdfaLdapFilterValue -Value 'a*b(c)d\e/f') 'Certificate directory read: the LDAP filter value is escaped as Microsoft documents'
Assert-True ((Get-AdfaCertificateEkuText -Ekus @() -HasEkuExtension $false -EkuNames $certCfg['EkuNames']) -match 'no EKU extension') 'Certificate EKUs: no EKU extension is said as such, not as a missing purpose'
$certKey = [System.Security.Cryptography.ECDsa]::Create([System.Security.Cryptography.ECCurve+NamedCurves]::nistP256)
$certRequest = New-Object System.Security.Cryptography.X509Certificates.CertificateRequest -ArgumentList 'CN=dc1.contoso.com', $certKey, ([System.Security.Cryptography.HashAlgorithmName]::SHA256)
$certMade = $certRequest.CreateSelfSigned((New-Object System.DateTimeOffset -ArgumentList $certNow.AddDays(-10)), (New-Object System.DateTimeOffset -ArgumentList $certNow.AddDays(-2)))
$certKey.Dispose()
$certRecord = ConvertTo-AdfaCertificateRecord -Certificate $certMade.RawData
Assert-True ($certRecord.Read -and $certRecord.NotAfterUtc.Kind -eq 'Utc' -and -not $certRecord.HasEkuExtension -and $certRecord.Thumbprint -eq $certMade.Thumbprint.ToUpperInvariant()) 'Certificate record: DER bytes are read in memory, with UTC dates and no EKU extension reported as such'
Assert-True (-not (ConvertTo-AdfaCertificateRecord -Certificate ([byte[]](1, 2, 3))).Read) 'Certificate record: bytes that are not a certificate are Read = false, not an exception'
$certNotRun = Get-AdfaDcLdapsFinding -DomainController $certDc -HandshakeRun $false -PortAnswered $false -Config $certCfg -NowUtc $certNow
Assert-True ($certNotRun.Status -eq 'Not Assessed' -and $certNotRun.Detail -match '^Not run: ' -and $certNotRun.Detail -match '-IncludeLdapsHandshake') 'LDAPS row: not run is Not Assessed and names the switch'
$certClasses = @('ConnectRefused', 'ConnectTimedOut', 'Unresolved', 'ConnectFailed', 'HandshakeTimedOut', 'HandshakeFailed', 'NoCertificate', 'Error')
$certNa = @($certClasses | ForEach-Object { (Get-AdfaDcLdapsFinding -DomainController $certDc -HandshakeRun $true -PortAnswered $true -Config $certCfg -NowUtc $certNow `
            -Raw ([pscustomobject]@{ Ok = $false; Class = $_; Error = 'x'; ErrorType = ''; SocketError = ''; Certificate = $null; SslPolicyErrors = ''; ChainStatus = @(); CallbackRan = $false; ElapsedMs = 1 })) })
Assert-True (@($certNa | Where-Object { $_.Status -ne 'Not Assessed' }).Count -eq 0 -and @($certNa | ForEach-Object { $_.Detail } | Select-Object -Unique).Count -eq 8) 'LDAPS row: each of the eight failure classes is Not Assessed with its own cause (declared population: eight classes)'
$certPresented = Get-AdfaDcLdapsFinding -DomainController $certDc -HandshakeRun $true -PortAnswered $true -Config $certCfg -NowUtc $certNow `
    -Raw ([pscustomobject]@{ Ok = $true; Class = 'Presented'; Error = ''; ErrorType = ''; SocketError = ''; Certificate = $certRecord; SslPolicyErrors = 'RemoteCertificateChainErrors'; ChainStatus = @('UntrustedRoot: x'); CallbackRan = $true; ElapsedMs = 1 })
Assert-True ($certPresented.Status -eq 'Fail' -and $certPresented.Detail -notmatch 'UntrustedRoot' -and $certPresented.ChainStatus -match 'UntrustedRoot') 'LDAPS row: an expired presented certificate is a Fail, and the chain status stays in its own column'
$certEmpty = @(Get-AdfaDcDirectoryCertificateFinding -DomainController $certDc -Scope 'contoso.com' -Config $certCfg -NowUtc $certNow `
        -Raw ([pscustomobject]@{ Ok = $true; Error = ''; ErrorType = ''; Server = 'contoso.com'; ObjectCount = 1; AttributeReturned = $true; Values = @() }))
Assert-True ($certEmpty.Count -eq 1 -and $certEmpty[0].Status -eq 'Info' -and $certEmpty[0].Detail -match 'not evidence that the DC holds no certificate') 'Directory rows: no published value is Info, never "no certificate"'
$certLone = @(Get-AdfaDcDirectoryCertificateFinding -DomainController $certDc -Scope 'contoso.com' -Config $certCfg -NowUtc $certNow `
        -Raw ([pscustomobject]@{ Ok = $true; Error = ''; ErrorType = ''; Server = 'contoso.com'; ObjectCount = 1; AttributeReturned = $true; Values = $certMade.RawData }))
Assert-True ($certLone.Count -eq 1 -and $certLone[0].Status -eq 'Fail') 'Directory rows: a lone byte array is one certificate, not one value per byte'
$certDenied = @(Get-AdfaDcDirectoryCertificateFinding -DomainController $certDc -Scope 'contoso.com' -Config $certCfg -NowUtc $certNow `
        -Raw ([pscustomobject]@{ Ok = $false; Error = 'Access is denied.'; ErrorType = 'System.UnauthorizedAccessException'; Server = 'contoso.com'; ObjectCount = 0; AttributeReturned = $false; Values = @() }))
Assert-True ($certDenied[0].Status -eq 'Not Assessed' -and $certDenied[0].Detail -match '^Access denied: ') 'Directory rows: a refused read is Access denied, not unreachable'
Assert-Throws { Merge-AdfaDcCertificatesConfig -BaseConfig $certCfg -Override @{ LdapsPort = 3269 } } "unknown key 'LdapsPort'" 'DC certificates override: the port cannot be set from a file'
Assert-Throws { Merge-AdfaDcCertificatesConfig -BaseConfig $certCfg -Override @{ FailWithinDays = 31 } } 'is above WarnWithinDays' 'DC certificates override: a Fail window above the built-in Warning window is refused'
Assert-Throws { Merge-AdfaDcCertificatesConfig -BaseConfig $certCfg -Override @{ WarnWithinDays = '30' } } 'JSON number' 'DC certificates override: a quoted number is refused'
Assert-Equal 45 ([int](Merge-AdfaDcCertificatesConfig -BaseConfig $certCfg -Override @{ WarnWithinDays = 45 })['WarnWithinDays']) 'DC certificates override: a valid window is merged'
$certRecLdaps = Get-AdfaRecommendation -Section 'DC Certificates' -Item 'LDAPS certificate: backup-dc.contoso.com' -Detail 'replication backup time sync certificate template enrol krbtgt'
$certRecOther = Get-AdfaRecommendation -Section 'DC Certificates' -Item 'Directory certificates: dc1.contoso.com' -Detail 'replication backup time sync certificate template enrol krbtgt'
Assert-True ($certRecLdaps -match 'NTDS service store' -and $certRecOther -eq '') 'DC certificates advice: the LDAPS family gets its own advice and a row without advice gets none, whatever the text holds'
# Found by an independent review of the C5 diff before commit, and fixed in it.
Assert-Equal 30 ([int](Get-CertVerdict -To 30.75).DaysLeft) 'Certificate expiry: days left are rounded down - 30 days and 18 hours is 30, not 31'
Assert-Equal 'Warning' ([string](Get-CertVerdict -To 30.75).Status) 'Certificate expiry: 30 days and 18 hours left is inside a 30-day Warning window'
Assert-Equal 'a\00b' (ConvertTo-AdfaLdapFilterValue -Value ('a{0}b' -f [char]0)) 'Certificate directory read: NUL is escaped as \00, as Microsoft documents'
$certProbeCases = [ordered]@{
    ConnectRefused    = @{ Connected = $false; ConnectThrew = $true; ConnectSocketError = 'ConnectionRefused' }
    ConnectTimedOut   = @{ Connected = $false; ConnectThrew = $false }
    Presented         = @{ Connected = $true; CertificateSeen = $true; HandshakeThrew = $true }
    HandshakeTimedOut = @{ Connected = $true; HandshakeThrew = $true; DeadlineExpired = $true }
    HandshakeFailed   = @{ Connected = $true; HandshakeThrew = $true }
    NoCertificate     = @{ Connected = $true }
}
$certProbeGot = @(foreach ($k in @($certProbeCases.Keys)) { $a = $certProbeCases[$k]; Get-AdfaTlsProbeClass @a })
Assert-Equal (@($certProbeCases.Keys) -join ',') ($certProbeGot -join ',') 'Certificate handshake: one attempt is classified from what happened, and a certificate received before an error is kept (declared population: six attempts)'
$certRsa = [System.Security.Cryptography.RSA]::Create(2048)
$certRsaRequest = New-Object System.Security.Cryptography.X509Certificates.CertificateRequest -ArgumentList 'CN=dc1.contoso.com', $certRsa, ([System.Security.Cryptography.HashAlgorithmName]::SHA256), ([System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
$certWithKey = $certRsaRequest.CreateSelfSigned((New-Object System.DateTimeOffset -ArgumentList $certNow.AddDays(-10)), (New-Object System.DateTimeOffset -ArgumentList $certNow.AddDays(90)))
$certPfx = $certWithKey.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pfx)
$certRsa.Dispose()
$certFromPfx = ConvertTo-AdfaCertificateRecord -Certificate ([byte[]]$certPfx)
Assert-True ([string][System.Security.Cryptography.X509Certificates.X509Certificate2]::GetCertContentType([byte[]]$certPfx) -eq 'Pfx' -and -not $certFromPfx.Read -and $certFromPfx.ReadError -match 'Pfx blob' -and $certFromPfx.Subject -eq '') 'Certificate record: a PKCS12 (PFX) value is refused before it is opened, so no private key is imported'
Assert-True ((ConvertTo-AdfaCertificateRecord -Certificate ([byte[]]$certWithKey.RawData)).Read) 'Certificate record: non-vacuity - the DER form of the same certificate is read'
Assert-Equal 5000 ([int]$certCfg['ConnectTimeoutMs']) 'DC certificates config: the handshake''s connection has its own bound, 5000 ms, above the ~2 s Windows took to report a refusal'
Assert-Throws { Merge-AdfaDcCertificatesConfig -BaseConfig $certCfg -Override @{ HandshakeTimeoutMs = 60001 } } 'from 100 to 60000' 'DC certificates override: a handshake bound above 60000 ms is refused'
Assert-Throws { Merge-AdfaDcCertificatesConfig -BaseConfig $certCfg -Override @{ ConnectTimeoutMs = 99 } } "'ConnectTimeoutMs' to 99" 'DC certificates override: a connection bound below 100 ms is refused'
Assert-Equal 30 ([int](Merge-AdfaDcCertificatesConfig -BaseConfig $certCfg -Override @{ WarnWithinDays = 30; FailWithinDays = 30 })['FailWithinDays']) 'DC certificates override: a Fail window equal to the Warning window is allowed'
$certInv = [System.Globalization.CultureInfo]::InvariantCulture
Assert-Equal ($certNow.AddDays(-10).ToString('yyyy-MM-dd HH:mm:ss', $certInv)) ([string]$certPresented.NotBeforeUtc) 'LDAPS row: NotBeforeUtc carries the start of validity, in UTC'
$certDirText = [string]$certLone[0].Detail
Assert-True ($certDirText -match "Directory E-mail Replication" -and $certEmpty[0].Detail -notmatch '(?i)only for .Domain Controller') 'Directory rows: a published value is not said to be a DC certificate, and the Info row does not claim only one template is published'

Write-Host "== RID pool (C6): pure logic ==" -ForegroundColor Cyan
$ridCfg = $script:Config.RidPool
function New-RidInterval { param([int64]$Low, [int64]$High) return ([int64]$High * [int64]4294967296) + [int64]$Low }
# The large-integer split, at its edges, on whichever edition runs this harness.
$ridVectors = [ordered]@{
    'Learn sample 4611686014132422708' = @{ Value = [int64]4611686014132422708; Expect = '2100/1073741823' }
    'zero'                             = @{ Value = [int64]0; Expect = '0/0' }
    'high 0x7FFFFFFF'                  = @{ Value = (New-RidInterval -Low 9 -High 2147483647); Expect = '9/2147483647' }
    'Int64 min (high 0x80000000)'      = @{ Value = [int64]::MinValue; Expect = '0/2147483648' }
    'minus one'                        = @{ Value = [int64]-1; Expect = '4294967295/4294967295' }
    'UInt64 max'                       = @{ Value = [uint64]::MaxValue; Expect = '4294967295/4294967295' }
    'text'                             = @{ Value = '4611686014132522708'; Expect = '102100/1073741823' }
}
$ridGot = @(foreach ($k in @($ridVectors.Keys)) { $d = ConvertFrom-AdfaLargeInteger -Value $ridVectors[$k]['Value']; ("{0}/{1}" -f $d.Low, $d.High) })
Assert-Equal (@($ridVectors.Values | ForEach-Object { $_['Expect'] }) -join ',') ($ridGot -join ',') 'RID pool: a 64-bit value splits into its unsigned halves, Learn''s sample and the sign edges included (declared population: seven values)'
Assert-True (-not (ConvertFrom-AdfaLargeInteger -Value '1.5').Read -and -not (ConvertFrom-AdfaLargeInteger -Value $null).Read -and -not (ConvertFrom-AdfaLargeInteger -Value ([double]2)).Read) 'RID pool: a fraction, a null or a double is not read as a large integer'
# The global space verdict at its boundaries, on both documented sizes.
$ridScale = [ordered]@{ '107374182/1073741823' = 'Pass'; '107374183/1073741823' = 'Warning'; '966367640/1073741823' = 'Warning'; '966367641/1073741823' = 'Fail'
    '214748364/2147483647' = 'Pass'; '214748365/2147483647' = 'Warning'; '1932735283/2147483647' = 'Fail'; '2100/500000000' = 'Not Assessed'; '10/5' = 'Not Assessed'; '0/0' = 'Not Assessed' }
$ridScaleGot = @(foreach ($k in @($ridScale.Keys)) { $p = $k -split '/'; [string](Get-AdfaRidSpaceVerdict -Low ([int64]$p[0]) -High ([int64]$p[1]) -Config $ridCfg).Status })
Assert-Equal (@($ridScale.Values) -join ',') ($ridScaleGot -join ',') 'RID pool: Warning from 10 % used and Fail from 90 % used by integer comparison; an unknown size, more issued than the size, or a size of 0 is Not Assessed (declared population: ten points)'
# The allocation verdict.
function New-RidManagerRaw { param([bool]$Read = $true, [bool]$Returned = $false, $Value = $null)
    [pscustomobject]@{ Ok = $true; AllocationRead = $Read; AllocationReturned = $Returned; AllocationValue = $Value } }
$ridAllocCases = [ordered]@{
    'FALSE'                     = @{ Raw = (New-RidManagerRaw -Returned $true -Value $false); In = 'Yes'; Expect = 'Fail' }
    'TRUE'                      = @{ Raw = (New-RidManagerRaw -Returned $true -Value $true); In = 'Unknown'; Expect = 'Pass' }
    'not set, in schema'        = @{ Raw = (New-RidManagerRaw); In = 'Yes'; Expect = 'Not Assessed' }
    'not set, schema unknown'   = @{ Raw = (New-RidManagerRaw); In = 'Unknown'; Expect = 'Not Assessed' }
    'not in schema'             = @{ Raw = (New-RidManagerRaw -Read $false); In = 'No'; Expect = 'Not Assessed' }
    'FALSE, one-item list'      = @{ Raw = (New-RidManagerRaw -Returned $true -Value ([System.Collections.ArrayList]@($false))); In = 'Yes'; Expect = 'Fail' }
}
$ridAllocGot = @(foreach ($k in @($ridAllocCases.Keys)) { [string](Get-AdfaRidAllocationVerdict -Raw $ridAllocCases[$k]['Raw'] -InSchema $ridAllocCases[$k]['In']).Status })
Assert-Equal (@($ridAllocCases.Values | ForEach-Object { $_['Expect'] }) -join ',') ($ridAllocGot -join ',') 'RID pool: FALSE fails (also in a one-item collection), TRUE passes, and a value not returned is Not Assessed whatever the schema says - an unset value and an unreadable one look the same (declared population: six inputs)'
# The figure shown never reaches a point the row is graded below: truncated, not rounded.
$ridPct = [ordered]@{ '107374182/1073741823' = 'Pass 9.9999'; '107374183/1073741823' = 'Warning 10'; '966367640/1073741823' = 'Warning 89.9999'; '966367641/1073741823' = 'Fail 90'
    '214748364/2147483647' = 'Pass 9.9999'; '1932735282/2147483647' = 'Warning 89.9999'; '1932735283/2147483647' = 'Fail 90' }
$ridPctGot = @(foreach ($k in @($ridPct.Keys)) { $p = $k -split '/'; $v = Get-AdfaRidSpaceVerdict -Low ([int64]$p[0]) -High ([int64]$p[1]) -Config $ridCfg; ("{0} {1}" -f $v.Status, $v.PercentUsed) })
Assert-Equal (@($ridPct.Values) -join ',') ($ridPctGot -join ',') 'RID pool: PercentUsed at Microsoft''s boundary RIDs agrees with the grade - 9.9999 on a Pass, 89.9999 on a Warning (declared population: seven points)'
# The schema seam: No only with the control attribute in the answer.
$ridCtl = [string]$ridCfg['AvailablePoolAttribute']
$ridAtt = [string]$ridCfg['AllocationAttribute']
$ridSchemaCases = [ordered]@{
    'both'          = @{ Raw = [pscustomobject]@{ Ok = $true; Error = ''; ErrorType = ''; Names = @($ridCtl, $ridAtt) }; Expect = 'Yes' }
    'control only'  = @{ Raw = [pscustomobject]@{ Ok = $true; Error = ''; ErrorType = ''; Names = @($ridCtl) }; Expect = 'No' }
    'empty answer'  = @{ Raw = [pscustomobject]@{ Ok = $true; Error = ''; ErrorType = ''; Names = @() }; Expect = 'Unknown' }
    'no control'    = @{ Raw = [pscustomobject]@{ Ok = $true; Error = ''; ErrorType = ''; Names = @($ridAtt) }; Expect = 'Unknown' }
    'query failed'  = @{ Raw = [pscustomobject]@{ Ok = $false; Error = 'x'; ErrorType = ''; Names = @() }; Expect = 'Unknown' }
}
$ridSchemaGot = @(foreach ($k in @($ridSchemaCases.Keys)) { [string](Get-AdfaRidSchemaState -Raw $ridSchemaCases[$k]['Raw'] -Config $ridCfg).InSchema })
Assert-Equal (@($ridSchemaCases.Values | ForEach-Object { $_['Expect'] }) -join ',') ($ridSchemaGot -join ',') 'RID pool schema: "not in the schema" only when the same answer carried rIDAvailablePool; an empty or partial answer proves nothing (declared population: five answers)'
# The per-DC row: the three causes that must not be confused.
function New-RidSetRaw { param([bool]$Ok = $true, [string]$Err = '', [string]$Type = '', [string[]]$Refs = @(), [bool]$SearchRun = $true, [int]$SearchCount = 0, $Set = $null)
    [pscustomobject]@{ Ok = $Ok; Stage = ''; Error = $Err; ErrorType = $Type; Server = 'contoso.com'; ObjectCount = 1; ComputerDn = 'CN=DC1,OU=Domain Controllers,DC=contoso,DC=com'; References = @($Refs)
        ReferenceRead = 'NotTried'; ReferenceError = ''; ReferenceErrorType = ''; SearchRun = $SearchRun; SearchOk = $true; SearchError = ''; SearchErrorType = ''; SearchCount = $SearchCount; RidSet = $Set } }
$ridDcName = 'dc1.contoso.com'
$ridAbsent = Get-AdfaDcRidPoolFinding -DomainController $ridDcName -Scope 'contoso.com' -Raw (New-RidSetRaw) -Config $ridCfg
$ridDenied = Get-AdfaDcRidPoolFinding -DomainController $ridDcName -Scope 'contoso.com' -Raw (New-RidSetRaw -Ok $false -Err 'Access is denied.' -Type 'System.UnauthorizedAccessException') -Config $ridCfg
$ridDown = Get-AdfaDcRidPoolFinding -DomainController $ridDcName -Scope 'contoso.com' -Raw (New-RidSetRaw -Ok $false -Err 'x' -Type 'Microsoft.ActiveDirectory.Management.ADServerDownException') -Config $ridCfg
Assert-True ($ridAbsent.Detail -match '^RID Set object absent: ' -and $ridDenied.Detail -match '^Access denied: ' -and $ridDown.Detail -match '^Unreachable: ' -and @($ridAbsent, $ridDenied, $ridDown | Where-Object { $_.Status -ne 'Not Assessed' }).Count -eq 0) 'RID pool: RID Set absent, access denied and unreachable are three different Not Assessed results'
$ridSet = [pscustomobject]@{ Dn = 'CN=RID Set,CN=DC1,DC=contoso,DC=com'; FromSearch = $false; PreviousAllocationPool = (New-RidInterval -Low 2100 -High 2599); AllocationPool = (New-RidInterval -Low 3100 -High 3599); NextRid = 2150; UsedPool = $null; Returned = @() }
$ridInfo = Get-AdfaDcRidPoolFinding -DomainController $ridDcName -Scope 'contoso.com' -Raw (New-RidSetRaw -Refs @('CN=RID Set,CN=DC1,DC=contoso,DC=com') -SearchRun $false -Set $ridSet) -Config $ridCfg
Assert-True ($ridInfo.Status -eq 'Info' -and $ridInfo.PoolStart -eq '2100' -and $ridInfo.PoolEnd -eq '2599' -and $ridInfo.RemainingInPool -eq '450' -and $ridInfo.NextPoolEnd -eq '3599') 'RID pool: a DC''s pool is Info, with start, end, remaining (end - next + 1) and the prefetched pool in their columns'
# rIDNextRID is 4 bytes: a negative Int32 is decoded (and here falls outside the pool), a wider value is unreadable.
$ridSetWith = { param($Prev, $Next) [pscustomobject]@{ Dn = 'CN=RID Set,CN=DC1,DC=contoso,DC=com'; FromSearch = $false; PreviousAllocationPool = $Prev; AllocationPool = $null; NextRid = $Next; UsedPool = $null; Returned = @() } }
$ridDcWith = { param($Set) Get-AdfaDcRidPoolFinding -DomainController $ridDcName -Scope 'contoso.com' -Raw (New-RidSetRaw -Refs @('CN=RID Set,CN=DC1,DC=contoso,DC=com') -SearchRun $false -Set $Set) -Config $ridCfg }
$ridNeg = & $ridDcWith (& $ridSetWith (New-RidInterval -Low 2100 -High 2599) ([int32]-5))
$ridWide = & $ridDcWith (& $ridSetWith (New-RidInterval -Low 2100 -High 2599) ([int64]4294969396))
$ridBack = & $ridDcWith (& $ridSetWith (New-RidInterval -Low 2599 -High 2100) 2150)
Assert-True ($ridNeg.Detail -match '^Inconsistent: rIDNextRID of .* \(4294967291\) is outside' -and $ridWide.Detail -match '^Unreadable value: .*not a 32-bit integer' -and $ridBack.Detail -match 'ends \(2100\) before it starts \(2599\)' -and @($ridNeg, $ridWide, $ridBack | Where-Object { $_.Status -ne 'Not Assessed' }).Count -eq 0) 'RID pool: a negative Int32 rIDNextRID is decoded, a wider one is Unreadable value, and a pool that ends before it starts is its own Inconsistent cause'
# The validator and the advice.
Assert-Throws { Merge-AdfaRidPoolConfig -BaseConfig $ridCfg -Override @{ KnownCeilings = @() } } "unknown key 'KnownCeilings'" 'RID pool override: the ceilings cannot be set from a file'
Assert-Throws { Merge-AdfaRidPoolConfig -BaseConfig $ridCfg -Override @{ WarnAtPercentUsed = 95 } } 'must be above WarnAtPercentUsed' 'RID pool override: a Warning point above the built-in Fail point is refused'
Assert-Throws { Merge-AdfaRidPoolConfig -BaseConfig $ridCfg -Override @{ FailAtPercentUsed = 100 } } 'whole number from 1 to 99' 'RID pool override: a point of 100 % is refused'
Assert-Equal 5 ([int](Merge-AdfaRidPoolConfig -BaseConfig $ridCfg -Override @{ WarnAtPercentUsed = 5 })['WarnAtPercentUsed']) 'RID pool override: a valid point is merged'
$ridHostile = 'event 16658 on dc1 restored from backup dcdiag /test:RidManager aging replication C:\Backup\stale.json'
$ridRecSpace = Get-AdfaRecommendation -Section 'RID Pool' -Item 'Global RID space: contoso.com' -Detail $ridHostile
$ridRecDc = Get-AdfaRecommendation -Section 'RID Pool' -Item 'RID pool: dc1.contoso.com' -Detail $ridHostile
Assert-True ($ridRecSpace -match '16658' -and $ridRecSpace -notmatch 'wbadmin|scavenging|repadmin' -and $ridRecDc -eq '') 'RID pool advice: the global space row gets its own advice and a per-DC row none, whatever the text holds'

Write-Host "== SID history (C7): pure logic ==" -ForegroundColor Cyan
$shCfg = $script:Config.SidHistory
# A SID's bytes, built here without the script: revision, count, authority big-endian, sub-authorities little-endian.
function New-ShBytes { param([string]$Sid)
    $parts = $Sid.Split('-'); $subs = @($parts | Select-Object -Skip 3); $list = New-Object System.Collections.Generic.List[byte]
    $list.Add([byte]1); $list.Add([byte]$subs.Count); $auth = [uint64]$parts[2]
    for ($i = 5; $i -ge 0; $i--) { $list.Add([byte](($auth -shr (8 * $i)) -band 255)) }
    foreach ($s in $subs) { $v = [uint64]$s; for ($i = 0; $i -lt 4; $i++) { $list.Add([byte](($v -shr (8 * $i)) -band 255)) } }
    return , $list.ToArray() }
# The byte parser at its edges, by the fallback alone and as a caller gets it, on whichever edition runs this harness.
$shVectors = @('S-1-5-21-1000-2000-3000-4294967295', 'S-1-5-21-4294967295-4294967295-4294967295-500', 'S-1-5-32-544', 'S-1-5-9', 'S-1-20015998343868-5', 'S-1-5-1-2-3-4-5-6-7-8-9-10-11-12-13-14-15')
$shGot = @(foreach ($v in $shVectors) { $b = New-ShBytes -Sid $v; ("{0}|{1}" -f (ConvertFrom-AdfaSidValue -Value $b -NoPlatform).Text, (ConvertFrom-AdfaSidValue -Value $b).Text) })
Assert-Equal (@($shVectors | ForEach-Object { "{0}|{0}" -f $_ }) -join ',') ($shGot -join ',') 'SID history: a SID read from its bytes round-trips by the fallback and as a caller gets it, RID 4294967295, a 48-bit authority and 15 sub-authorities included (declared population: six SIDs)'
$shMax = ConvertFrom-AdfaSidValue -Value (New-ShBytes -Sid 'S-1-5-21-1000-2000-3000-4294967295') -NoPlatform
Assert-True ($shMax.Rid -is [uint32] -and $shMax.Rid -eq [uint32]4294967295 -and $shMax.DomainPart -eq 'S-1-5-21-1000-2000-3000' -and $shMax.IsAccountDomain) 'SID history: a RID at UInt32 max stays unsigned, and the domain part is everything before it'
$shGood = New-ShBytes -Sid 'S-1-5-32-544'
$shBadRev = [byte[]]$shGood.Clone(); $shBadRev[0] = 2
$shMalformed = [ordered]@{ 'empty' = [byte[]]@(); 'three bytes' = [byte[]](1, 1, 0); 'revision 2' = $shBadRev; 'count 16' = [byte[]](@(1, 16, 0, 0, 0, 0, 0, 5) + @(0) * 64); 'short by one' = [byte[]]($shGood[0..($shGood.Length - 2)]); 'trailing bytes' = [byte[]](@($shGood) + @(9)); 'text' = 'contoso\admin'; 'RID above UInt32' = 'S-1-5-21-1-2-3-4294967296'; 'authority above 2^48 - 1' = 'S-1-281474976710656-5' }
$shMalGot = @(foreach ($k in @($shMalformed.Keys)) { $r = ConvertFrom-AdfaSidValue -Value $shMalformed[$k]; ("{0}:{1}" -f $k, ($r.Ok -or $r.Error -eq '')) })
Assert-Equal (@($shMalformed.Keys | ForEach-Object { "{0}:False" -f $_ }) -join ',') ($shMalGot -join ',') 'SID history: a malformed value is not read and carries a reason, without throwing (declared population: nine values)'
# The platform's reading, replaced through its test seam: a disagreement and a refusal are not read; a platform that cannot run leaves the fallback.
$shReaders = [ordered]@{ 'disagrees' = @{ Reader = { param($b) 'S-1-5-32-545' }; Expect = 'False' }; 'refuses' = @{ Reader = { param($b) throw [System.ArgumentException]'STUB' }; Expect = 'False' }; 'cannot run' = @{ Reader = { param($b) throw [System.PlatformNotSupportedException]'STUB' }; Expect = 'True:Fallback' }; 'agrees' = @{ Reader = { param($b) 'S-1-5-32-544' }; Expect = 'True:Platform' } }
$shReaderGot = @(foreach ($k in @($shReaders.Keys)) { $r = ConvertFrom-AdfaSidValue -Value $shGood -PlatformReader $shReaders[$k]['Reader']; if ($r.Ok) { "{0}:{1}" -f $r.Ok, $r.Parser } else { [string]$r.Ok } })
Assert-Equal (@($shReaders.Values | ForEach-Object { $_['Expect'] }) -join ',') ($shReaderGot -join ',') 'SID history: a value the platform reads differently or refuses is not read; a platform that cannot run leaves the fallback (declared population: four readers)'
Assert-Equal 1 @(Get-AdfaSidValueList -Value $shGood).Count 'SID history: one byte array is one value, never unrolled into its bytes'
# The verdicts, from a raw read built here.
function New-ShRec { param([string]$Sam, [object[]]$History, [string]$Class = 'user', $Enabled = $true) [pscustomobject]@{ Dn = "CN=$Sam,DC=contoso,DC=com"; Sam = $Sam; Name = $Sam; Class = $Class; Enabled = $Enabled; ObjectSid = $null; History = @($History) } }
function New-ShRaw { param($Records = @(), [bool]$Ok = $true, [string]$Err = '', [string]$Type = '', [string]$DomainSid = 'S-1-5-21-1-2-3')
    [pscustomobject]@{ Ok = $Ok; Refused = $false; Error = $Err; ErrorType = $Type; Server = 'contoso.com'; DomainDn = 'DC=contoso,DC=com'; DomainSid = $DomainSid; DomainSidError = 'x'; Records = @($Records); TrustOk = $true; TrustError = ''; TrustErrorType = ''; Trusts = @() } }
$shMap = [pscustomobject]@{ Map = @{ 'S-1-5-21-1-2-3' = 'contoso.com' }; Failures = @() }
$shStatus = { param($Raw) @(Get-AdfaSidHistoryDomainFinding -Domain 'contoso.com' -Raw $Raw -ForestMap $shMap -Config $shCfg | ForEach-Object { $_.Status }) -join ',' }
$shCases = [ordered]@{
    'none returned'          = @{ Raw = (New-ShRaw); Expect = 'Pass,Pass,Pass,Info' }
    'benign'                 = @{ Raw = (New-ShRaw -Records @(New-ShRec -Sam 'a' -History @('S-1-5-21-7-8-9-1105'))); Expect = 'Warning,Pass,Pass,Info' }
    'same-domain'            = @{ Raw = (New-ShRaw -Records @(New-ShRec -Sam 'a' -History @('S-1-5-21-1-2-3-1500'))); Expect = 'Warning,Fail,Pass,Info' }
    'privileged'             = @{ Raw = (New-ShRaw -Records @(New-ShRec -Sam 'a' -History @(, (New-ShBytes -Sid 'S-1-5-21-7-8-9-519')))); Expect = 'Warning,Pass,Fail,Info' }
    'domain SID not read'    = @{ Raw = (New-ShRaw -DomainSid '' -Records @(New-ShRec -Sam 'a' -History @('S-1-5-21-7-8-9-1105'))); Expect = 'Warning,Not Assessed,Pass,Info' }
    'unparsed only'          = @{ Raw = (New-ShRaw -Records @(New-ShRec -Sam 'a' -History @(, [byte[]](1, 2, 0)))); Expect = 'Warning,Not Assessed,Not Assessed,Info' }
    'query failed'           = @{ Raw = (New-ShRaw -Ok $false -Err 'STUB' -Type 'System.UnauthorizedAccessException'); Expect = 'Not Assessed,Not Assessed,Not Assessed,Not Assessed' }
    'no value read'          = @{ Raw = (New-ShRaw -Records @(New-ShRec -Sam 'a' -History @())); Expect = 'Warning,Not Assessed,Not Assessed,Not Assessed' }
}
$shCaseGot = @(foreach ($k in @($shCases.Keys)) { & $shStatus $shCases[$k]['Raw'] })
Assert-Equal (@($shCases.Values | ForEach-Object { $_['Expect'] }) -join ' / ') ($shCaseGot -join ' / ') 'SID history: four rows per domain - present is the tool-default Warning, same-domain and privileged fail, an unknown domain SID, an unparsed value or a principal with no value read is Not Assessed, a failed query fails closed (declared population: eight reads)'
# The Principals and HistoricSids columns of the privileged row: a '|' in a DN, no SID in Detail, and the cap.
$shPipe = [pscustomobject]@{ Dn = 'CN=x|y,DC=contoso,DC=com'; Sam = 'alice'; Name = 'alice'; Class = 'user'; Enabled = $true; ObjectSid = $null; History = @('S-1-5-32-544', 'S-1-5-9') }
$shPipeRow = @(Get-AdfaSidHistoryDomainFinding -Domain 'contoso.com' -Raw (New-ShRaw -Records @($shPipe)) -ForestMap $shMap -Config $shCfg)[2]
Assert-True ($shPipeRow.Status -eq 'Fail' -and $shPipeRow.Principals -eq 'alice' -and $shPipeRow.HistoricSids -eq 'alice=S-1-5-32-544 (Administrators),S-1-5-9 (Enterprise Domain Controllers)' -and $shPipeRow.Detail -notmatch 'S-1-') 'SID history: a privileged row names the principal whose DN holds a ''|'' by its own name, and keeps the fixed SIDs out of Detail'
$shPrivThree = New-ShRaw -Records @(1..3 | ForEach-Object { New-ShRec -Sam "p$_" -History @("S-1-5-21-1-2-3-150$_", 'S-1-5-21-7-8-9-519') })
$shCap2 = Merge-AdfaSidHistoryConfig -BaseConfig $shCfg -Override @{ NameListCap = 2 }
$shCapRows = @(Get-AdfaSidHistoryDomainFinding -Domain 'contoso.com' -Raw $shPrivThree -ForestMap $shMap -Config $shCap2)
Assert-Equal '2/1,2/1' (@($shCapRows[1], $shCapRows[2] | ForEach-Object { "{0}/{1}" -f $_.Listed, $_.NotListed }) -join ',') 'SID history: the name cap applies to the same-domain and privileged rows (declared population: two rows, three principals, cap 2)'
$shLeads = [ordered]@{ 'Microsoft.ActiveDirectory.Management.ADServerDownException' = '^Unreachable: '; 'System.UnauthorizedAccessException' = '^Access denied: '; 'System.TimeoutException' = '^Timed out: ' }
$shLeadGot = @(foreach ($t in @($shLeads.Keys)) { $d = @(Get-AdfaSidHistoryDomainFinding -Domain 'contoso.com' -Raw (New-ShRaw -Ok $false -Err 'STUB' -Type $t) -ForestMap $shMap -Config $shCfg)[0].Detail; [bool]($d -match $shLeads[$t]) })
Assert-Equal 'True,True,True' ($shLeadGot -join ',') 'SID history: unreachable, access denied and timed out are three different Not Assessed results (declared population: three exception types)'
# The cap, around three principals.
$shThree = New-ShRaw -Records @(1..3 | ForEach-Object { New-ShRec -Sam "u$_" -History @("S-1-5-21-7-8-9-11$_") })
$shCapGot = @(foreach ($cap in @(0, 2, 3, 4)) { $c = Merge-AdfaSidHistoryConfig -BaseConfig $shCfg -Override @{ NameListCap = $cap }; $r = @(Get-AdfaSidHistoryDomainFinding -Domain 'contoso.com' -Raw $shThree -ForestMap $shMap -Config $c)[0]; "{0}/{1}" -f $r.Listed, $r.NotListed })
Assert-Equal '0/3,2/1,3/0,3/0' ($shCapGot -join ',') 'SID history: names listed up to the cap, the rest counted (declared population: four caps)'
# The validator and the advice.
Assert-Throws { Merge-AdfaSidHistoryConfig -BaseConfig $shCfg -Override @{ PresentStatus = 'Pass' } } 'Warning or Info' 'SID history override: present SID history can never be configured to pass'
Assert-Throws { Merge-AdfaSidHistoryConfig -BaseConfig $shCfg -Override @{ PrivilegedSids = @() } } "unknown key 'PrivilegedSids'" 'SID history override: the privileged list cannot be set from a file'
Assert-Throws { Merge-AdfaSidHistoryConfig -BaseConfig $shCfg -Override @{ NameListCap = 1001 } } 'whole number from 0 to 1000' 'SID history override: a cap above 1000 is refused'
$shHostile = 'KRBTGT Backup Operators replication global catalog stale NOT a pass event 1106 on dc1 C:\Backup\stale.json'
$shRecPriv = Get-AdfaRecommendation -Section 'Security Posture' -Item 'SID history privileged: contoso.com' -Detail $shHostile
$shRecSrc = Get-AdfaRecommendation -Section 'Security Posture' -Item 'SID history sources: contoso.com' -Detail $shHostile
$shRecKrb = Get-AdfaRecommendation -Section 'Security Posture' -Item 'krbtgt password age' -Detail '400 days'
Assert-True ($shRecPriv -match 'Enterprise Admins' -and $shRecPriv -notmatch 'New-KrbtgtKeys|wbadmin|Disable first' -and $shRecSrc -eq '' -and $shRecKrb -match 'krbtgt') 'SID history advice: the privileged row gets its own advice, the sources row none, and the older krbtgt row still gets its own'

Write-Host ""
Write-Host "== GPO version consistency (C8): pure logic ==" -ForegroundColor Cyan
$gpCfg = $script:Config.Gpo
$gpG1 = '{31B2F340-016D-11D2-945F-00C04FB984F9}'
$gpG2 = '{6AC1786C-016F-11D2-945F-00C04FB984F9}'
$gpG3 = '{A1B2C3D4-0000-4000-8000-000000000003}'
$gpOrphan = '{A1B2C3D4-0000-4000-8000-0000000000FF}'
function New-GpIni { param($Version) [pscustomobject]@{ Ok = $true; Class = 'Read'; Bytes = [byte[]][System.Text.Encoding]::ASCII.GetBytes(("[General]`r`nVersion={0}`r`n" -f $Version)); Error = ''; ErrorType = ''; HResult = 0; Path = '' } }
function New-GpFail { param([string]$Class) [pscustomobject]@{ Ok = $false; Class = $Class; Bytes = $null; Error = 'STUB'; ErrorType = 'System.IO.IOException'; HResult = 0; Path = '' } }
function New-GpContainer { param([string]$Guid, $Version = 65537) [pscustomobject]@{ Guid = $Guid; DisplayName = 'x'; Version = $Version; FileSysPath = ("\\contoso.com\sysvol\contoso.com\Policies\{0}" -f $Guid); Flags = 0; Dn = '' } }
function New-GpRaw { param($Containers = @(), [bool]$Ok = $true, [string]$Type = '') [pscustomobject]@{ Ok = $Ok; Refused = $false; Error = 'STUB'; ErrorType = $Type; Pdc = 'dc1.contoso.com'; PdcError = ''; PdcErrorType = ''; DomainDn = 'DC=contoso,DC=com'; Containers = @($Containers) } }
function New-GpSysvol { param([bool]$PortOk = $true, $Names = @(), [hashtable]$Reads = @{})
    $listing = $null
    if ($PortOk) { $listing = [pscustomobject]@{ Ok = ($null -ne $Names); Class = $(if ($null -ne $Names) { 'Read' } else { 'AccessDenied' }); Names = @($Names); Error = 'STUB'; ErrorType = 'System.UnauthorizedAccessException'; HResult = 0; Path = '' } }
    [pscustomobject]@{ PortOk = $PortOk; Port = 445; Pdc = 'dc1.contoso.com'; PoliciesPath = '\\dc1.contoso.com\SYSVOL\contoso.com\Policies'; Listing = $listing; Reads = $Reads } }
# The version layout MS-GPOL publishes, and the 32-bit reading of a negative Int32.
$gpSplit = Split-AdfaGpoVersion -Version 9437184
Assert-Equal '144/0' ("{0}/{1}" -f $gpSplit.User, $gpSplit.Computer) 'GPO version: Microsoft''s sample GPT.INI value 9437184 is user 144, computer 0'
$gpNumbers = @(foreach ($v in @([int]-2147418111, [int64]4294967295, [int64]4294967296, [int64]-2147483649, 'abc', $null)) { $n = ConvertTo-AdfaGpoVersionNumber -Value $v; if ($n.Ok) { [string]$n.Version } else { [string]$n.Cause } })
Assert-Equal '2147549185,4294967295,OutOfRange,OutOfRange,NotANumber,NotReturned' ($gpNumbers -join ',') 'GPO version: versionNumber read as 32 bits - a negative Int32 masked, the edges held, the rest refused (declared population: six values)'
$gpIni = @(foreach ($text in @("[General]`r`nVersion=65537", "[general]`r`n version = 131073 ", "[Other]`r`nVersion=1", "[General]`r`nVersion=1`r`nVersion=2", "[General]`r`nVersion=4294967296")) { $r = ConvertFrom-AdfaGptIniVersion -Bytes ([System.Text.Encoding]::ASCII.GetBytes($text)) -Config $gpCfg; if ($r.Ok) { [string]$r.Version } else { [string]$r.Cause } })
Assert-Equal '65537,131073,NoGeneralSection,DuplicateVersionKey,OutOfRange' ($gpIni -join ',') 'GPO version: GPT.INI read from [General] only, case-insensitively; a file without it, with two versions or out of range is refused (declared population: five files)'
$gpUtf16 = ConvertFrom-AdfaGptIniVersion -Bytes ([byte[]](@(0xFF, 0xFE) + @([System.Text.Encoding]::Unicode.GetBytes("[General]`r`nVersion=7")))) -Config $gpCfg
Assert-True ($gpUtf16.Ok -and $gpUtf16.Version -eq 7 -and $gpUtf16.Encoding -eq 'UTF-16LE (BOM)') 'GPO version: a UTF-16 GPT.INI with a byte-order mark is read and named'
# The verdicts: equal, the half that differs, the domain summary.
$gpHalves = @(foreach ($pair in @(@(65537, 65537), @(131073, 65537), @(65538, 65537), @(131074, 65537))) { (Get-AdfaGpoVersionVerdict -DsVersion $pair[0] -SysvolVersion $pair[1] -ReadFrom 'dc1.contoso.com' -Config $gpCfg).Half })
Assert-Equal 'None,User,Computer,Both' ($gpHalves -join ',') 'GPO version: equal, user half, computer half, both halves (declared population: four pairs)'
$gpDomain = @(foreach ($c in @(@(2, 2, 0, 0), @(0, 0, 0, 0), @(2, 1, 0, 1), @(2, 2, 1, 0), @(2, 1, 0, 0))) { (Get-AdfaGpoDomainVerdict -Domain 'contoso.com' -ReadFrom 'dc1.contoso.com' -Population $c[0] -Compared $c[1] -Mismatched $c[2] -NotAssessed $c[3] -Config $gpCfg).Status })
Assert-Equal 'Pass,Not Assessed,Not Assessed,Warning,Not Assessed' ($gpDomain -join ',') 'GPO version: a domain passes only when every GPO was compared and none differs; none visible, one not compared and counts that do not add up are Not Assessed (declared population: five count sets)'
# One domain's reads to rows: normal, unreachable, access denied, mixed.
$gpStatus = { param($Raw, $Sysvol) @(Get-AdfaGpoDomainFinding -Domain 'contoso.com' -Raw $Raw -Sysvol $Sysvol -Config $gpCfg | ForEach-Object { "{0}={1}" -f ($_.Item -replace ': .*$', ''), $_.Status }) -join ',' }
$gpCases = [ordered]@{
    'agree'          = @{ Raw = (New-GpRaw -Containers @((New-GpContainer $gpG1), (New-GpContainer $gpG2))); Sysvol = (New-GpSysvol -Names @($gpG1, $gpG2) -Reads @{ $gpG1 = (New-GpIni 65537); $gpG2 = (New-GpIni 65537) }); Expect = 'GPO version summary=Pass' }
    'one differs'    = @{ Raw = (New-GpRaw -Containers @((New-GpContainer $gpG1), (New-GpContainer $gpG2 -Version 131073))); Sysvol = (New-GpSysvol -Names @($gpG1, $gpG2) -Reads @{ $gpG1 = (New-GpIni 65537); $gpG2 = (New-GpIni 65537) }); Expect = 'GPO version=Warning,GPO version summary=Warning' }
    'unreachable'    = @{ Raw = (New-GpRaw -Containers @((New-GpContainer $gpG1))); Sysvol = (New-GpSysvol -PortOk $false); Expect = 'GPO version=Not Assessed,GPO folder listing=Not Assessed,GPO version summary=Not Assessed' }
    'access denied'  = @{ Raw = (New-GpRaw -Containers @((New-GpContainer $gpG1))); Sysvol = (New-GpSysvol -Names $null -Reads @{ $gpG1 = (New-GpFail 'AccessDenied') }); Expect = 'GPO version=Not Assessed,GPO folder listing=Not Assessed,GPO version summary=Not Assessed' }
    'mixed'          = @{ Raw = (New-GpRaw -Containers @((New-GpContainer $gpG1), (New-GpContainer $gpG2), (New-GpContainer $gpG3))); Sysvol = (New-GpSysvol -Names @($gpG1, $gpG2, $gpOrphan) -Reads @{ $gpG1 = (New-GpIni 65537); $gpG2 = (New-GpFail 'NotFound') }); Expect = 'GPO version=Not Assessed,GPO version=Not Assessed,GPO folder without container=Warning,GPO version summary=Not Assessed' }
    'no container'   = @{ Raw = (New-GpRaw -Containers @()); Sysvol = (New-GpSysvol -Names @('PolicyDefinitions')); Expect = 'GPO version summary=Not Assessed' }
    'query failed'   = @{ Raw = (New-GpRaw -Ok $false -Type 'System.UnauthorizedAccessException'); Sysvol = $null; Expect = 'GPO version summary=Not Assessed' }
}
$gpGot = @(foreach ($k in @($gpCases.Keys)) { & $gpStatus $gpCases[$k]['Raw'] $gpCases[$k]['Sysvol'] })
Assert-Equal (@($gpCases.Values | ForEach-Object { $_['Expect'] }) -join ' / ') ($gpGot -join ' / ') 'GPO version: rows per domain - a difference is the tool-default Warning, unreachable, access denied, absent files and an empty population fail closed, a GUID folder with no container is a Warning (declared population: seven reads)'
$gpLeads = @(foreach ($k in @('unreachable', 'access denied')) { @(Get-AdfaGpoDomainFinding -Domain 'contoso.com' -Raw $gpCases[$k]['Raw'] -Sysvol $gpCases[$k]['Sysvol'] -Config $gpCfg)[0].Detail -replace ':.*$', '' })
Assert-Equal 'Unreachable,Access denied' ($gpLeads -join ',') 'GPO version: an unreachable PDC and a refused read are two different Not Assessed results'
$gpClasses = @(foreach ($t in @(@('System.IO.FileNotFoundException', 0), @('System.UnauthorizedAccessException', 0), @('System.IO.IOException', [int]0x80070035), @('System.IO.IOException', [int]0x80070020))) { Get-AdfaGpoFileReadErrorClass -TypeName $t[0] -HResult $t[1] -Message '' })
Assert-Equal 'NotFound,AccessDenied,Unreachable,Error' ($gpClasses -join ',') 'GPO version: file read failures - not found, access denied, network path not found (53), anything else quoted (declared population: four)'
$gpPath = Get-AdfaGpoSysvolPath -Pdc 'dc1.contoso.com' -Domain 'contoso.com' -Guid $gpG1 -FileSysPath ("\\fileserver.fabrikam.com\sysvol\contoso.com\Policies\{0}" -f $gpG1) -Config $gpCfg
Assert-True (-not $gpPath.Ok -and $gpPath.IniPath -eq '') 'GPO version: a gPCFileSysPath naming another host is never read'
# The validator and the advice.
Assert-Throws { Merge-AdfaGpoConfig -BaseConfig $gpCfg -Override @{ MismatchStatus = 'Pass' } } 'Warning or Fail' 'GPO override: a version mismatch can never be configured to pass'
Assert-Throws { Merge-AdfaGpoConfig -BaseConfig $gpCfg -Override @{ OrphanFolderStatus = 'Pass' } } 'Warning or Info' 'GPO override: an orphan folder can never be configured to pass'
Assert-Throws { Merge-AdfaGpoConfig -BaseConfig $gpCfg -Override @{ ContainerProperties = @('*') } } "unknown key 'ContainerProperties'" 'GPO override: the property list cannot be set from a file'
$gpListMsg = ''
try { Merge-AdfaGpoConfig -BaseConfig $gpCfg -Override ('{ "MismatchStatus": ["Fail"] }' | ConvertFrom-Json) | Out-Null } catch { $gpListMsg = [string]$_.Exception.Message }
Assert-True ($gpListMsg -match 'not a single text value' -and $gpListMsg -notmatch "to 'Fail'") 'GPO override: a JSON list holding Fail is refused by its type, not as if Fail had been refused'
# Evidence: the summary says SYSVOL only when SYSVOL was read (declared population: three reads).
$gpEvidence = @(foreach ($k in @('agree', 'unreachable', 'access denied')) { @(Get-AdfaGpoDomainFinding -Domain 'contoso.com' -Raw $gpCases[$k]['Raw'] -Sysvol $gpCases[$k]['Sysvol'] -Config $gpCfg | Where-Object { $_.Item -eq 'GPO version summary: contoso.com' })[0].Evidence })
Assert-Equal 'directory and SYSVOL,directory,directory' ($gpEvidence -join ',') 'GPO version: the summary''s Evidence names SYSVOL only when the folder was listed or a GPT.INI version read'
# A listing that failed as unreachable: no file was read, and each GPO says so with that class - never as a defect in the tool.
$gpUnreachList = New-GpSysvol -Names $null
$gpUnreachList.Listing.Class = 'Unreachable'
$gpUnreachRows = @(Get-AdfaGpoDomainFinding -Domain 'contoso.com' -Raw (New-GpRaw -Containers @((New-GpContainer $gpG1), (New-GpContainer $gpG2))) -Sysvol $gpUnreachList -Config $gpCfg | Where-Object { $_.Item -like 'GPO version: *' })
Assert-True (@($gpUnreachRows).Count -eq 2 -and @($gpUnreachRows | Where-Object { $_.Status -eq 'Not Assessed' -and $_.Detail -match '^Unreachable: .*could not be listed' -and $_.Detail -notmatch 'defect in the tool' }).Count -eq 2) 'GPO version: after an unreachable listing every GPO is Not Assessed as unreachable (declared population: two GPOs)'
Assert-Equal 'AccessDenied' (@($gpCfg['ReadFilesAfterListingClass']) -join ',') 'GPO version: files are read one by one after a failed listing only when it was refused as access denied'
$gpMore = @(foreach ($t in @(@('System.IO.IOException', [int]0x800704D0), @('System.IO.IOException', [int]0x80070002), @('System.Security.SecurityException', 0), @('System.IO.DriveNotFoundException', 0))) { Get-AdfaGpoFileReadErrorClass -TypeName $t[0] -HResult $t[1] -Message '' })
Assert-Equal 'Unreachable,NotFound,Error,NotFound' ($gpMore -join ',') 'GPO version: 1232 unreachable, 2 not found, SecurityException not read as access denied, DriveNotFoundException not found (declared population: four)'
$gpHostile = 'sysvol dfsr replication backup stale krbtgt C:\Backup\stale.json'
$gpRecMis = Get-AdfaRecommendation -Section 'GPO Inventory' -Item ("GPO version: {0}" -f $gpG1) -Detail $gpHostile
$gpRecOrphan = Get-AdfaRecommendation -Section 'GPO Inventory' -Item ("GPO folder without container: {0}" -f $gpOrphan) -Detail $gpHostile
$gpRecList = Get-AdfaRecommendation -Section 'GPO Inventory' -Item 'GPO folder listing: contoso.com' -Detail $gpHostile
Assert-True ($gpRecMis -match 'converged' -and $gpRecMis -notmatch 'dfsrmig|wbadmin|krbtgt' -and $gpRecOrphan -match 'orphaned' -and $gpRecList -eq '') 'GPO version advice: a mismatch and an orphan folder get their own advice, whatever the Detail holds, and the listing row none'
Write-Host "== C9. Dangerous rights: replication and control rights, matched by SID ==" -ForegroundColor Cyan
$aclRoot = 'S-1-5-21-1000-2000-3000'
$aclRep = @{}; foreach ($r in @($aclCfg['ReplicationRights'])) { $aclRep[[string]$r['Name']] = [string]$r['Guid'] }
$aclHead = @(
    (New-ValAce -Sid 'S-1-5-11' -Mask 0x20094)
    (New-ValAce -Sid ('{0}-512' -f $aclRoot) -Mask 0xE01BD)
    (New-ValAce -Sid 'S-1-5-32-544' -Mask 0xF01BD)
    (New-ValAce -Sid 'S-1-5-18' -Mask 0xF01FF)
    (New-ValAce -Sid ('{0}-519' -f $aclRoot) -Mask 0xF01FF)
    (New-ValAce -Sid 'S-1-5-9' -Mask 0x100 -ObjectType $aclRep['DS-Replication-Get-Changes'])
    (New-ValAce -Sid ('{0}-516' -f $aclRoot) -Mask 0x100 -ObjectType $aclRep['DS-Replication-Get-Changes-All'])
    (New-ValAce -Sid ('{0}-498' -f $aclRoot) -Mask 0x100 -ObjectType $aclRep['DS-Replication-Get-Changes'])
)
$aclVerdict = { param($Aces, [string]$RowKey = 'DCSync', [string]$Owner = ('{0}-512' -f $aclRoot), [string]$DomainSid = $aclRoot, $Read = $null, [scriptblock]$Resolver = $null)
    if ($null -eq $Read) { $Read = [pscustomobject]@{ Ok = $true; Class = 'Read'; Error = ''; ErrorType = ''; Dn = 'DC=contoso,DC=com'; Server = 'contoso.com'; Descriptor = (New-ValDescriptor -Aces $Aces -Owner $Owner) } }
    Get-AdfaAclObjectVerdict -Domain 'contoso.com' -Item ('{0}: contoso.com' -f $RowKey) -ObjectKind 'DomainRoot' -RowKey $RowKey -What 'the domain head of contoso.com' -Read $Read -DomainSid $DomainSid -RootDomainSid $aclRoot -Config $aclCfg -NameResolver $Resolver }
# Rights by mask (declared population: eight masks).
$aclMasks = @(@(0xF01FF, ''), @(0x10000000, ''), @(0x40000000, ''), @(131112, ''), @(131220, ''), @(0x20, 'bf967a68-0de6-11d0-a285-00aa003049e2'), @(0x100, 'edacfd8f-ffb3-11d1-b41d-00a0c968f939'), @(0x80000, ''))
$aclGot = @(foreach ($m in $aclMasks) { @((Get-AdfaAclAceRight -Ace (New-ValAce -Sid 'x' -Mask $m[0] -ObjectType $m[1]) -ObjectKind 'DomainRoot' -Config $aclCfg).Atoms).Count })
Assert-Equal '7,7,1,1,0,0,0,1' ($aclGot -join ',') 'Dangerous rights: full control and GENERIC_ALL grant every graded right, GENERIC_WRITE and GenericWrite only write-all-properties, a read, a one-property write and Apply-Group-Policy nothing, WriteOwner itself (declared population: eight masks)'
# The verdicts: the default holders pass; a SID outside the allowlist is flagged whatever its name.
Assert-Equal 'Pass,Pass' (@((& $aclVerdict $aclHead).Status, (& $aclVerdict $aclHead 'DomainRootControl').Status) -join ',') 'Dangerous rights: Microsoft''s default holders of the domain head pass both head rows'
$aclFake = ('{0}-1105' -f $aclRoot)
$aclFakeRow = & $aclVerdict (@($aclHead) + @(New-ValAce -Sid $aclFake -Mask 0x100 -ObjectType $aclRep['DS-Replication-Get-Changes-All'])) 'DCSync' ('{0}-512' -f $aclRoot) $aclRoot $null { param($Sid) 'BUILTIN\Administrators' }
Assert-True ($aclFakeRow.Status -eq 'Warning' -and $aclFakeRow.FlaggedSids -eq $aclFake -and $aclFakeRow.Detail -notmatch 'Administrators\b.*=' -and $aclFakeRow.Principals -eq ('{0} = BUILTIN\Administrators' -f $aclFake)) 'Dangerous rights: a SID outside the allowlist is flagged even when it resolves to the name of a default group - the name is never read'
$aclErodc = & $aclVerdict (@($aclHead) + @(New-ValAce -Sid ('{0}-498' -f $aclRoot) -Mask 0x100 -ObjectType $aclRep['DS-Replication-Get-Changes-All']))
Assert-True ($aclErodc.Status -eq 'Warning' -and $aclErodc.RightsHeld -eq ('{0}-498: DS-Replication-Get-Changes-All' -f $aclRoot)) 'Dangerous rights: Enterprise Read-only DCs holding Replicating Directory Changes All are flagged'
# Deny ordering, inherit-only, owner (declared population: five cases).
$x = ('{0}-1300' -f $aclRoot)
$aclCases = @(
    (& $aclVerdict (@($aclHead) + @((New-ValAce -Sid $x -Mask 0x100 -Allow $false), (New-ValAce -Sid $x -Mask 0x100)))).Status
    (& $aclVerdict (@($aclHead) + @((New-ValAce -Sid $x -Mask 0x100), (New-ValAce -Sid $x -Mask 0x100 -Allow $false)))).Status
    (& $aclVerdict (@($aclHead) + @(New-ValAce -Sid $x -Mask 0xF01FF -InheritOnly $true))).Status
    (& $aclVerdict $aclHead 'DomainRootControl' $x).Status
    (& $aclVerdict $aclHead 'DCSync' ('{0}-512' -f $aclRoot) '').Status
)
Assert-Equal 'Pass,Warning,Pass,Warning,Not Assessed' ($aclCases -join ',') 'Dangerous rights: a deny before the allow cancels it, after it does not; an inherit-only ACE is skipped; a non-default owner is flagged; an account SID that cannot be decided fails closed (declared population: five cases)'
# Failed reads: each its own Not Assessed lead (declared population: six classes).
$aclLeads = @(foreach ($c in @(@('Unreachable', 'Unable to contact the server.', 'Microsoft.ActiveDirectory.Management.ADServerDownException'), @('AccessDenied', 'Access is denied.', 'System.UnauthorizedAccessException'), @('TimedOut', 'timed out', 'System.TimeoutException'), @('NotReturned', 'x', ''), @('DaclAbsent', 'x', ''), @('Unparseable', 'x', ''))) {
        $r = & $aclVerdict @() 'DCSync' '' $aclRoot ([pscustomobject]@{ Ok = $false; Class = $c[0]; Error = $c[1]; ErrorType = $c[2]; Dn = 'DC=contoso,DC=com'; Server = 'contoso.com'; Descriptor = $null })
        '{0}:{1}' -f $r.Status, ($r.Detail -replace ':.*$', '')
    })
Assert-Equal 'Not Assessed:Unreachable,Not Assessed:Access denied,Not Assessed:Timed out,Not Assessed:Not returned,Not Assessed:No DACL returned,Not Assessed:Not read' ($aclLeads -join ',') 'Dangerous rights: unreachable, access denied, timed out, not returned, no DACL and unreadable are six different Not Assessed results, never Pass'
# A domain: rows in order, and the GPO population counted.
$aclGpoRead = [pscustomobject]@{ Ok = $true; Class = 'Read'; Error = ''; ErrorType = ''; Dn = 'CN={G},CN=Policies'; Server = 'contoso.com'; Descriptor = (New-ValDescriptor -Owner ('{0}-512' -f $aclRoot) -Aces @((New-ValAce -Sid ('{0}-512' -f $aclRoot) -Mask 0xF00FF), (New-ValAce -Sid 'S-1-3-0' -Mask 0xF00FF -InheritOnly $true))) }
$aclHeadRead = [pscustomobject]@{ Ok = $true; Class = 'Read'; Error = ''; ErrorType = ''; Dn = 'DC=contoso,DC=com'; Server = 'contoso.com'; Descriptor = (New-ValDescriptor -Aces $aclHead -Owner ('{0}-512' -f $aclRoot)) }
$aclAdminRead = [pscustomobject]@{ Ok = $true; Class = 'Read'; Error = ''; ErrorType = ''; Dn = 'CN=AdminSDHolder,CN=System,DC=contoso,DC=com'; Server = 'contoso.com'; Descriptor = (New-ValDescriptor -Owner ('{0}-512' -f $aclRoot) -Aces @((New-ValAce -Sid ('{0}-512' -f $aclRoot) -Mask 0xE01BD), (New-ValAce -Sid 'S-1-5-18' -Mask 0xF01FF))) }
$aclDenied = [pscustomobject]@{ Ok = $false; Class = 'AccessDenied'; Error = 'Access is denied.'; ErrorType = 'System.UnauthorizedAccessException'; Dn = 'CN={H},CN=Policies'; Server = 'contoso.com'; Descriptor = $null }
$aclGpoRaw = [pscustomobject]@{ Ok = $true; Class = 'Read'; Error = ''; ErrorType = ''; SearchBase = 'CN=Policies,CN=System,DC=contoso,DC=com'; Items = @([pscustomobject]@{ Guid = '{G}'; Dn = 'x'; Read = $aclGpoRead }, [pscustomobject]@{ Guid = '{H}'; Dn = 'y'; Read = $aclDenied }) }
$aclDomainRows = @(Get-AdfaAclDomainFinding -Domain 'contoso.com' -DomainRaw ([pscustomobject]@{ Ok = $true; Error = ''; ErrorType = ''; DomainDn = 'DC=contoso,DC=com'; DomainSid = $aclRoot; DomainSidError = '' }) -RootRaw ([pscustomobject]@{ Sid = $aclRoot; Error = '' }) -HeadRead $aclHeadRead -AdminRead $aclAdminRead -GpoRaw $aclGpoRaw -Config $aclCfg)
Assert-Equal 'DCSync rights=Pass,Domain root control rights=Pass,AdminSDHolder rights=Pass,GPO rights=Pass,GPO rights=Not Assessed,GPO rights summary=Not Assessed' (@($aclDomainRows | ForEach-Object { '{0}={1}' -f ($_.Item -replace ': .*$', ''), $_.Status }) -join ',') 'Dangerous rights: a domain gives its three object rows, one row per GPO and a summary that is Not Assessed when one GPO could not be read (declared population: six rows)'
$aclSum = @($aclDomainRows | Where-Object { $_.Item -eq 'GPO rights summary: contoso.com' })[0]
Assert-Equal '2/1/0/1' ('{0}/{1}/{2}/{3}' -f $aclSum.Population, $aclSum.ReadCount, $aclSum.FlaggedCount, $aclSum.NotAssessedCount) 'Dangerous rights: the GPO summary''s counts add up to the population'
# The validator and the advice.
Assert-Throws { Merge-AdfaAclConfig -BaseConfig $aclCfg -Override @{ FlaggedStatus = 'Pass' } } 'Warning or Fail' 'Acl override: a flagged principal can never be configured to pass'
Assert-Throws { Merge-AdfaAclConfig -BaseConfig $aclCfg -Override @{ AdditionalAllowed = @(@{ Sid = 'CONTOSO\svc'; Objects = @('DomainRoot'); Rights = @('DS-Replication-Get-Changes'); Reason = 'r' }) } } 'names are refused' 'Acl override: a name is refused, the allowlist is matched by SID only'
Assert-Throws { Merge-AdfaAclConfig -BaseConfig $aclCfg -Override @{ AdditionalAllowed = @(@{ Sid = 'S-1-1-0'; Objects = @('DomainRoot'); Rights = @('DS-Replication-Get-Changes'); Reason = 'r' }) } } 'never be allowlisted' 'Acl override: Everyone can never be allowlisted'
Assert-Throws { Merge-AdfaAclConfig -BaseConfig $aclCfg -Override @{ Allowlist = @() } } "unknown key 'Allowlist'" 'Acl override: the built-in allowlist cannot be replaced from a file'
$aclHostile = 'replication backup stale sysvol dfsr pdc emulator delegation dcsync C:\Backup\stale.json'
$aclRecs = @(foreach ($i in @('DCSync rights: contoso.com', 'Domain root control rights: contoso.com', 'AdminSDHolder rights: contoso.com', 'GPO rights: {G}', 'GPO rights summary: contoso.com', 'Dangerous ACLs (no domain scoped)')) { Get-AdfaRecommendation -Section 'Dangerous ACLs (DCSync)' -Item $i -Detail $aclHostile })
Assert-True ($aclRecs[0] -match 'Entra Connect' -and $aclRecs[1] -match 'WriteDacl' -and $aclRecs[2] -match 'SDProp' -and $aclRecs[3] -match 'Group Policy' -and $aclRecs[4] -eq $aclRecs[3] -and $aclRecs[5] -eq '' -and @($aclRecs | Where-Object { $_ -match 'dfsrmig|wbadmin|repadmin' }).Count -eq 0) 'Dangerous rights advice: each family gets its own advice whatever the Detail holds, and no unscoped entry reaches the section (declared population: six items)'
# The Windows seam, where SecurityIdentifier exists: a descriptor with no DACL is never "Everyone, full control".
if ([System.Environment]::OSVersion.Platform -eq [System.PlatformID]::Win32NT) {
    $aclNoDacl = New-Object System.Security.AccessControl.RawSecurityDescriptor -ArgumentList ('O:{0}-512G:{0}-512' -f $aclRoot)
    $aclBytes = New-Object byte[] $aclNoDacl.BinaryLength
    $aclNoDacl.GetBinaryForm($aclBytes, 0)
    $aclConv = ConvertTo-AdfaAclDescriptor -Value $aclBytes
    Assert-True ($aclConv.Class -eq 'DaclAbsent' -and -not $aclConv.Ok -and @($aclConv.Aces).Count -eq 0) 'Dangerous rights: a descriptor without a DACL is DaclAbsent, never read as Everyone with full control'
}
Assert-Equal 'NotReturned' (ConvertTo-AdfaAclDescriptor -Value $null).Class 'Dangerous rights: no value is NotReturned'
# Found by the review before commit (C9).
$aclDomainDns = '19195a5b-6da0-11d0-afd3-00c04fd930c9'
$aclClassRow = & $aclVerdict (@($aclHead) + @(New-ValAce -Sid $aclFake -Mask 0x120 -ObjectType $aclDomainDns))
Assert-True ($aclClassRow.Status -eq 'Warning' -and $aclClassRow.FlaggedSids -eq $aclFake) 'Dangerous rights: control access granted through an ACE scoped to the domainDNS class is graded as unscoped (DCSync), never passed'
$aclNodeRights = @((Get-AdfaAclAceRight -Ace (New-ValAce -Sid 'S-1-1-0' -Mask 0xF01FF -ObjectType 'bf967a86-0de6-11d0-a285-00aa003049e2') -ObjectKind 'DomainRoot' -Config $aclCfg).Atoms)
Assert-Equal 0 $aclNodeRights.Count 'Dangerous rights: full control scoped to another class (computer) grants no right on the domain head'
$aclMixed = & $aclVerdict (@($aclHead) + @((New-ValAce -Sid 'S-1-1-0' -Mask 0x10000000), (New-ValAce -Sid 'S-1-1-0' -Mask 0x100 -Kind 'Other')))
Assert-True ($aclMixed.Status -eq 'Warning' -and $aclMixed.FlaggedSids -eq 'S-1-1-0' -and $aclMixed.Detail -match 'not interpreted') 'Dangerous rights: a flagged SID is reported even when another ACE is not interpreted, and the Detail names that ACE'
$aclNoRoot = Get-AdfaAclObjectVerdict -Domain 'contoso.com' -Item 'DCSync: contoso.com' -ObjectKind 'DomainRoot' -RowKey 'DCSync' -What 'the domain head of contoso.com' -Read ([pscustomobject]@{ Ok = $true; Class = 'Read'; Error = ''; ErrorType = ''; Dn = 'DC=contoso,DC=com'; Server = 'contoso.com'; Descriptor = (New-ValDescriptor -Aces @(New-ValAce -Sid ('{0}-519' -f $aclRoot) -Mask 0xF01FF)) }) -DomainSid $aclRoot -RootDomainSid '' -Config $aclCfg
Assert-True ($aclNoRoot.Status -eq 'Not Assessed' -and $aclNoRoot.FlaggedSids -eq '' -and $aclNoRoot.Undecided -eq ('{0}-519' -f $aclRoot)) 'Dangerous rights: with the forest root SID unread, the scoped domain''s own -519 is undecided, never flagged'
$aclFailCfg = Merge-AdfaAclConfig -BaseConfig $aclCfg -Override @{ FlaggedStatus = 'Fail' }
$aclBadGpo = [pscustomobject]@{ Ok = $true; Class = 'Read'; Error = ''; ErrorType = ''; Dn = 'CN={G},CN=Policies'; Server = 'contoso.com'; Descriptor = (New-ValDescriptor -Owner ('{0}-512' -f $aclRoot) -Aces @(New-ValAce -Sid 'S-1-5-11' -Mask 0x40000)) }
$aclFailRows = @(Get-AdfaAclDomainFinding -Domain 'contoso.com' -DomainRaw ([pscustomobject]@{ Ok = $true; Error = ''; ErrorType = ''; DomainDn = 'DC=contoso,DC=com'; DomainSid = $aclRoot; DomainSidError = '' }) -RootRaw ([pscustomobject]@{ Sid = $aclRoot; Error = '' }) -HeadRead $aclHeadRead -AdminRead $aclAdminRead -GpoRaw ([pscustomobject]@{ Ok = $true; Class = 'Read'; Error = ''; ErrorType = ''; SearchBase = 'CN=Policies,CN=System,DC=contoso,DC=com'; Items = @([pscustomobject]@{ Guid = '{G}'; Dn = 'x'; Read = $aclBadGpo }) }) -Config $aclFailCfg)
$aclFailSum = @($aclFailRows | Where-Object { $_.Item -eq 'GPO rights summary: contoso.com' })[0]
Assert-Equal 'Fail|1/1/1/0' ('{0}|{1}/{2}/{3}/{4}' -f $aclFailSum.Status, $aclFailSum.Population, $aclFailSum.ReadCount, $aclFailSum.FlaggedCount, $aclFailSum.NotAssessedCount) 'Dangerous rights: under a Fail override a flagged GPO makes the summary Fail and is counted as flagged'

Write-Host "== C10. Privileged groups and delegation (pure logic) ==" -ForegroundColor Cyan
$pv = $script:Config.Privileged
$pvRoot = 'S-1-5-21-1000-2000-3000'
function New-ValPrivRecord {
    param([string]$Name, [string]$Kind = 'User', [string]$Sid = '', $Uac = 512, [string[]]$Spns = @(), [string[]]$Members = @(), $PrimaryGroupId = $null, [string[]]$DelegateTo = @(), [string]$Dn = '')
    if ($Dn -eq '') { $Dn = ("CN={0},CN=Users,DC=contoso,DC=com" -f $Name) }
    $p = $null; if ($Sid -ne '') { $p = ConvertFrom-AdfaSidValue -Value $Sid }
    $enabled = $null; if (($Kind -eq 'User' -or $Kind -eq 'Computer') -and $null -ne $Uac) { $enabled = (([int64]$Uac -band 2) -eq 0) }
    $uacValue = $null; if ($null -ne $Uac) { $uacValue = [int64]$Uac }
    [pscustomobject]@{ Dn = $Dn; Sam = $Name; Name = $Name; Class = $Kind.ToLowerInvariant(); Kind = $Kind; Sid = $Sid; DomainPart = $(if ($null -ne $p) { $p.DomainPart } else { '' }); Rid = $(if ($null -ne $p) { $p.Rid } else { $null })
        IsAccountDomainSid = $(if ($null -ne $p) { $p.IsAccountDomain } else { $false }); Uac = $uacValue; Enabled = $enabled; AdminCount = $null; Spns = @($Spns); PrimaryGroupId = $PrimaryGroupId; Members = @($Members); DelegateTo = @($DelegateTo); HasRbcd = $false; Rbcd = $null }
}
# The SID filter value, against Learn's own example (how-to-specify-comparison-values).
Assert-Equal '\01\04\00\00\00\00\00\05\15\00\00\00\11\c3\5f\73\19\52\5f\12\75\b9\75\54' (ConvertTo-AdfaLdapSidFilterValue -Sid 'S-1-5-21-1935655697-308236825-1417001333') 'Privileged: a SID in an objectSid filter is the encoded byte string of Learn''s example'
Assert-Equal '' (ConvertTo-AdfaLdapSidFilterValue -Sid 'Domain Admins') 'Privileged: a name is never turned into a filter value - groups are located by SID only'
# The protected list: Appendix C (13 groups + Administrator and krbtgt) plus Enterprise RODCs.
$pvProtected = @(@($pv['Groups']) | Where-Object { [bool]$_['Protected'] })
Assert-Equal 14 $pvProtected.Count 'Privileged: declared population - 13 Appendix C groups and Enterprise Read-only Domain Controllers are protected'
Assert-Equal '500,502' (@($pv['ProtectedAccountRids']) -join ',') 'Privileged: Administrator and krbtgt are protected as themselves'
Assert-Equal '524288|16777216|1048576' ('{0}|{1}|{2}' -f $pv['Uac']['TrustedForDelegation'], $pv['Uac']['TrustedToAuthForDelegation'], $pv['Uac']['NotDelegated']) 'Privileged: the delegation bits are Learn''s decimals'
# Routing: the longest suffix wins, an unscoped forest domain is out of scope, a shared DN is never guessed.
$pvMap = @{ 'contoso.com' = [pscustomobject]@{ Ok = $true; DomainDn = 'DC=contoso,DC=com' }; 'north.contoso.com' = [pscustomobject]@{ Ok = $true; DomainDn = 'DC=north,DC=contoso,DC=com' } }
Assert-Equal 'Routed:north.contoso.com|OutOfScope|Ambiguous' ('{0}:{1}|{2}|{3}' -f (Resolve-AdfaPrivDnDomain -Dn 'CN=a,DC=north,DC=contoso,DC=com' -DomainMap $pvMap -Scoped @('contoso.com', 'north.contoso.com')).Class, (Resolve-AdfaPrivDnDomain -Dn 'CN=a,DC=north,DC=contoso,DC=com' -DomainMap $pvMap -Scoped @('contoso.com', 'north.contoso.com')).Domain, (Resolve-AdfaPrivDnDomain -Dn 'CN=a,DC=north,DC=contoso,DC=com' -DomainMap $pvMap -Scoped @('contoso.com')).Class, (Resolve-AdfaPrivDnDomain -Dn 'CN=a,DC=contoso,DC=com' -DomainMap @{ a = $pvMap['contoso.com']; b = $pvMap['contoso.com'] } -Scoped @('a', 'b')).Class) 'Privileged: a member DN is routed to the domain that holds it, an unscoped domain is out of scope, a shared DN is ambiguous'
# The closure: nested, primary group, foreign principal, unresolved, cycle.
$pvCtx = New-AdfaPrivContext -DomainMap @{} -Config $pv -Offline
$pvG1 = New-ValPrivRecord -Name 'G1' -Kind 'Group' -Sid "$pvRoot-512" -Uac $null -Members @('CN=G2,CN=Users,DC=contoso,DC=com', 'CN=u1,CN=Users,DC=contoso,DC=com', 'CN=gone,DC=fabrikam,DC=com', 'CN=S-1-5-11,CN=ForeignSecurityPrincipals,DC=contoso,DC=com')
$pvG2 = New-ValPrivRecord -Name 'G2' -Kind 'Group' -Sid "$pvRoot-1500" -Uac $null -Members @('CN=G1,CN=Users,DC=contoso,DC=com', 'CN=u2,CN=Users,DC=contoso,DC=com')
foreach ($r in @($pvG2, (New-ValPrivRecord -Name 'u1' -Sid "$pvRoot-1601"), (New-ValPrivRecord -Name 'u2' -Sid "$pvRoot-1602"), (New-ValPrivRecord -Name 'S-1-5-11' -Kind 'Foreign' -Sid 'S-1-5-11' -Uac $null -Dn 'CN=S-1-5-11,CN=ForeignSecurityPrincipals,DC=contoso,DC=com'))) {
    $pvCtx['Objects'][$r.Dn.ToLowerInvariant()] = [pscustomobject]@{ Ok = $true; Class = 'Read'; Error = ''; ErrorType = ''; Record = $r }
}
$pvCtx['Objects']['cn=gone,dc=fabrikam,dc=com'] = [pscustomobject]@{ Ok = $false; Class = 'OutOfScope'; Error = 'not in this forest'; ErrorType = ''; Record = $null }
$pvCtx['Primary']['cn=g1,cn=users,dc=contoso,dc=com|512'] = [pscustomobject]@{ Ok = $true; Class = 'Read'; Error = ''; ErrorType = ''; Records = @(New-ValPrivRecord -Name 'u3' -Sid "$pvRoot-1603" -PrimaryGroupId 512) }
$pvClosure = Resolve-AdfaPrivGroupClosure -Group $pvG1 -Context $pvCtx -Config $pv
Assert-Equal 'u1=direct,u2=nested,u3=primary|F1|U1|False' ('{0}|F{1}|U{2}|{3}' -f (@($pvClosure.Principals | ForEach-Object { '{0}={1}' -f $_.Record.Name, $_.Via } | Sort-Object) -join ','), @($pvClosure.Foreign).Count, @($pvClosure.Unresolved).Count, $pvClosure.Complete) 'Privileged: membership is followed through nested groups and primary groups, a cycle ends, a foreign principal is kept by SID and an unresolved DN makes it incomplete'
# Schema Admins: 0 members Pass, 1 member Warning, not read Not Assessed (never Pass).
$pvSaGroup = New-ValPrivRecord -Name 'Schema Admins' -Kind 'Group' -Sid "$pvRoot-518" -Uac $null
$pvSpec = [pscustomobject]@{ Key = 'SchemaAdmins'; Name = 'Schema Admins'; Rid = 518; Scope = 'ForestRoot'; Protected = $true; Always = $true; Sid = "$pvRoot-518" }
$pvLocate = [pscustomobject]@{ Ok = $true; Class = 'Read'; Error = ''; ErrorType = ''; Filter = '(objectSid=x)'; Record = $pvSaGroup }
$pvEmpty = [pscustomobject]@{ Spec = $pvSpec; Locate = $pvLocate; Closure = [pscustomobject]@{ Group = $pvSaGroup; Complete = $true; Principals = @(); Groups = @(); Foreign = @(); Unresolved = @() } }
$pvOne = [pscustomobject]@{ Spec = $pvSpec; Locate = $pvLocate; Closure = [pscustomobject]@{ Group = $pvSaGroup; Complete = $true; Principals = @([pscustomobject]@{ Record = (New-ValPrivRecord -Name 'x' -Sid "$pvRoot-1900"); Via = 'direct' }); Groups = @(); Foreign = @(); Unresolved = @() } }
$pvDenied = [pscustomobject]@{ Spec = $pvSpec; Locate = [pscustomobject]@{ Ok = $false; Class = 'AccessDenied'; Error = 'Access is denied.'; ErrorType = 'System.UnauthorizedAccessException'; Filter = '(objectSid=x)'; Record = $null }; Closure = $null }
Assert-Equal 'Pass|Warning|Not Assessed' (@($pvEmpty, $pvOne, $pvDenied | ForEach-Object { (Get-AdfaPrivEmptyGroupVerdict -Domain 'contoso.com' -Key 'SchemaAdmins' -Entry $_ -DomainSid $pvRoot -Config $pv).Status }) -join '|') 'Privileged: Schema Admins passes empty, warns at one member, and is Not Assessed when it could not be read'
# Delegation: a registered DC is excluded by DN, a non-DC with the bit is a Warning, an unread DC population is Not Assessed.
$pvDc = New-ValPrivRecord -Name 'DC1$' -Kind 'Computer' -Uac 532480 -Dn 'CN=DC1,OU=Domain Controllers,DC=contoso,DC=com'
$pvSvc = New-ValPrivRecord -Name 'svc.web' -Uac (512 + 524288)
$pvSearch = [pscustomobject]@{ Ok = $true; Class = 'Read'; Error = ''; ErrorType = ''; Filter = ''; Records = @($pvDc, $pvSvc) }
$pvForest = [pscustomobject]@{ DcOk = $true; DcClass = 'Read'; DcError = ''; DcDns = @('cn=dc1,ou=domain controllers,dc=contoso,dc=com'); DsaCount = 1; NoReference = @() }
$pvUnc = @(Get-AdfaPrivDelegationVerdict -Domain 'contoso.com' -Delegation $pvSearch -Forest $pvForest -Config $pv -DomainDn 'DC=contoso,DC=com')[0]
Assert-True ($pvUnc.Status -eq 'Warning' -and $pvUnc.Principals -eq 'svc.web' -and $pvUnc.ExcludedCount -eq '1') 'Privileged: unconstrained delegation on a non-DC is a Warning; the registered DC is excluded by DN'
$pvNoDc = @(Get-AdfaPrivDelegationVerdict -Domain 'contoso.com' -Delegation $pvSearch -Forest ([pscustomobject]@{ DcOk = $false; DcClass = 'Unreachable'; DcError = 'down'; DcDns = @() }) -Config $pv -DomainDn 'DC=contoso,DC=com')[0]
Assert-Equal 'Not Assessed' $pvNoDc.Status 'Privileged: with the DC population unread, unconstrained delegation is Not Assessed, never judged by name'
# Review fixes: a DC population read incompletely never lets a DC be graded as a non-DC; a search that
# did not return the domain's registered DC never passes; a population without the domain's
# Administrator never passes.
$pvNoDsa = [pscustomobject]@{ DcOk = $true; DcClass = 'Read'; DcError = ''; DcDns = @(); DsaCount = 0; NoReference = @() }
$pvDcOnly = [pscustomobject]@{ Ok = $true; Class = 'Read'; Error = ''; ErrorType = ''; Filter = ''; Records = @($pvDc) }
$pvNoDsaRow = @(Get-AdfaPrivDelegationVerdict -Domain 'contoso.com' -Delegation $pvDcOnly -Forest $pvNoDsa -Config $pv -DomainDn 'DC=contoso,DC=com')[0]
Assert-True ($pvNoDsaRow.Status -eq 'Not Assessed' -and $pvNoDsaRow.Principals -eq '') 'Privileged: with no nTDSDSA object read, a DC carrying TRUSTED_FOR_DELEGATION is never graded as a non-DC'
$pvEmptySearch = [pscustomobject]@{ Ok = $true; Class = 'Read'; Error = ''; ErrorType = ''; Filter = ''; Records = @() }
$pvEmptyRows = @(Get-AdfaPrivDelegationVerdict -Domain 'contoso.com' -Delegation $pvEmptySearch -Forest $pvForest -Config $pv -DomainDn 'DC=contoso,DC=com')
Assert-Equal 'Not Assessed|Not Assessed|Not Assessed|Not Assessed' (@($pvEmptyRows | ForEach-Object { $_.Status }) -join '|') 'Privileged: a delegation search that did not return the registered DC passes none of its four rows (declared population: four rows)'
Assert-Equal 'Pass|Pass|Info|Pass' (@(Get-AdfaPrivDelegationVerdict -Domain 'contoso.com' -Delegation $pvDcOnly -Forest $pvForest -Config $pv -DomainDn 'DC=contoso,DC=com' | ForEach-Object { $_.Status }) -join '|') 'Privileged: the registered DC alone coming back is a measured "none"'
$pvComplete = [pscustomobject]@{ Complete = $true; Missing = @(); BySid = @{}; ByDn = @{}; Members = @(); DomainSid = $pvRoot }
$pvHeur = [pscustomobject]@{ Known = $true; MaskZero = $true; Character = '0'; Text = 'x' }
Assert-Equal 'Not Assessed' (Get-AdfaPrivOrphanVerdict -Domain 'contoso.com' -AdminCount ([pscustomobject]@{ Ok = $true; Class = 'Read'; Error = ''; ErrorType = ''; Filter = ''; Records = @() }) -Protected $pvComplete -Heuristics $pvHeur -Config $pv).Status 'Privileged: an adminCount search without the domain''s Administrator (RID 500) is not a clean result'
Assert-Equal 'Not Assessed' (Get-AdfaPrivSpnVerdict -Domain 'contoso.com' -Population ([pscustomobject]@{ Records = @(); Complete = $true; Gaps = @() }) -Config $pv).Status 'Privileged: an empty privileged-account population is not passed'
# Search failures are worded as searches; a scoped domain that could not be read keeps its own cause.
Assert-True ((Get-AdfaPrivLocateLead -Locate ([pscustomobject]@{ Class = 'NotFound'; Error = 'x'; ErrorType = '' }) -What 'the objects with adminCount=1' -Search) -notmatch 'no group with the SID') 'Privileged: a search answered "not found" is not worded as a missing group'
$pvUnreadMap = @{ 'contoso.local' = [pscustomobject]@{ Ok = $true; DomainDn = 'DC=contoso,DC=local'; Error = ''; ErrorType = '' }; 'fabrikam.local' = [pscustomobject]@{ Ok = $false; DomainDn = ''; Error = 'STUB: access is denied'; ErrorType = 'System.UnauthorizedAccessException' } }
Assert-Equal 'AccessDenied' (Resolve-AdfaPrivDnDomain -Dn 'CN=u,DC=fabrikam,DC=local' -DomainMap $pvUnreadMap -Scoped @('contoso.local', 'fabrikam.local')).Class 'Privileged: a member in a scoped domain that refused its own read is access denied, not out of scope'
# Enterprise Key Admins is a forest-root group; Protected Users counts only at DFL 2012 R2 or later.
Assert-Equal 'ForestRoot' ([string]@(@($pv['Groups']) | Where-Object { $_['Key'] -eq 'EnterpriseKeyAdmins' })[0]['Scope']) 'Privileged: Enterprise Key Admins (-527) is read from the forest root (Learn, domain-wide updates, Operation 85)'
$pvAlice = New-ValPrivRecord -Name 'adm.alice' -Sid "$pvRoot-1101"
$pvAdmin = New-ValPrivRecord -Name 'Administrator' -Sid "$pvRoot-500" -Uac (512 + 1048576)
$pvPop = [pscustomobject]@{ Records = @($pvAlice, $pvAdmin); Complete = $true; Gaps = @() }
$pvPu = { param($E) [pscustomobject]@{ Known = $true; Dns = @{ ($pvAlice.Dn.ToLowerInvariant()) = $true }; Why = ''; DelegationEnforced = $E; ModeText = 'x' } }
Assert-Equal 'Pass|Warning|Not Assessed' ((@($true, $false, $null) | ForEach-Object { (Get-AdfaPrivDelegableVerdict -Domain 'contoso.com' -Population $pvPop -ProtectedUsers (& $pvPu $_) -Config $pv).Status }) -join '|') 'Privileged: a Protected Users member is protected from delegation at DFL 2012 R2 or later, delegable below it, undecided when the level is unknown'
# The validator.
Assert-Throws { Merge-AdfaPrivilegedConfig -BaseConfig $pv -Override @{ OrphanStatus = 'Pass' } } 'Warning or Fail' 'Privileged override: a finding can never be configured to pass'
Assert-Throws { Merge-AdfaPrivilegedConfig -BaseConfig $pv -Override @{ Groups = @() } } "unknown key 'Groups'" 'Privileged override: the group table cannot be replaced from a file'
Assert-Throws { Merge-AdfaPrivilegedConfig -BaseConfig $pv -Override @{ NameListCap = 1001 } } 'whole number from 0 to 1000' 'Privileged override: NameListCap is bounded'
Assert-Throws { Merge-AdfaPrivilegedConfig -BaseConfig $pv -Override @{ EnterpriseAdminsExemptRootAdministrator = 'yes' } } 'JSON true or false' 'Privileged override: the exemption switch is a boolean'
# The advice: each graded family gets its own, whatever the Detail holds.
$pvHostile = 'replication backup stale sysvol krbtgt pdc emulator delegation dcsync enrol C:\Backup\stale.json'
$pvRecs = @(foreach ($pair in @(@('Privileged Accounts', 'Schema Admins members: contoso.com'), @('Privileged Hygiene', 'adminCount orphans: contoso.com'), @('Kerberos Exposure', 'Resource-based delegation: contoso.com'), @('Privileged Accounts', 'Privileged group: Backup Operators: contoso.com'))) { Get-AdfaRecommendation -Section $pair[0] -Item $pair[1] -Detail $pvHostile })
Assert-True ($pvRecs[0] -match 'temporarily' -and $pvRecs[1] -match 'inheritance' -and $pvRecs[2] -match 'PrincipalsAllowedToDelegateToAccount' -and $pvRecs[3] -eq '' -and @($pvRecs | Where-Object { $_ -match 'wbadmin|repadmin|New-KrbtgtKeys|replace with resource-based' }).Count -eq 0) 'Privileged advice: each family gets its own advice and no unscoped entry reaches the three sections (declared population: four items)'

Write-Host ""
Write-Host "== C11. dcdiag per DC, per partition and per scope (pure logic) ==" -ForegroundColor Cyan
# The dcdiag command reference (read 2026-11-16) prints per-DC verdicts under "Testing server:",
# partition verdicts under "Running partition tests on :" and wraps a verdict line before the test
# name. Each verdict is graded for the block it is in, never for an unrelated DC.
$dd = $script:Config.DcDiag
$ddOut = "Doing initial required tests`r`n   Testing server: Default-First-Site-Name\DC1`r`n      Starting test: Connectivity`r`n         ......................... DC1 passed test Connectivity`r`n" +
"   Running partition tests on : Schema`r`n      Starting test: CrossRefValidation`r`n         ......................... Schema passed test CrossRefValidation`r`n" +
"   Running partition tests on : Configuration`r`n      Starting test: CrossRefValidation`r`n         ......................... Configuration failed test `r`n         CrossRefValidation"
$ddParsed = ConvertFrom-AdfaDcdiagOutput -StdOut $ddOut -Config $dd
$ddParts = @($ddParsed.Parts | Where-Object { $_.Test -eq 'CrossRefValidation' })
Assert-Equal 2 (@($ddParts).Count) 'C11 parser: one part per partition block (declared population: two partitions), the wrapped verdict included'
Assert-Equal 'Partition:Schema:Pass|Partition:Configuration:Fail' ((@($ddParts | ForEach-Object { "{0}:{1}:{2}" -f $_.ScopeKind, $_.ScopeName, $_.Verdict })) -join '|') 'C11 parser: each verdict is attributed to its partition'
Assert-Equal 'Fail' ([string](Resolve-AdfaDcdiagVerdict -Parsed $ddParsed -TestName 'CrossRefValidation' -Mode 'Scope' -HostName 'dc1.contoso.com').Status) 'C11 verdict: in scope mode one failed partition fails the test'
Assert-Equal 'Not Assessed' ([string](Resolve-AdfaDcdiagVerdict -Parsed $ddParsed -TestName 'CrossRefValidation' -Mode 'Dc' -HostName 'dc1.contoso.com').Status) 'C11 verdict: a partition result is never counted as a DC''s, for a test without partition parts'
Assert-Equal 'Fail' ([string](Resolve-AdfaDcdiagVerdict -Parsed $ddParsed -TestName 'CrossRefValidation' -Mode 'Dc' -HostName 'dc1.contoso.com' -PartitionParts $true).Status) 'C11 verdict: with partition parts a failed partition fails the DC'
$ddMixed = ConvertFrom-AdfaDcdiagOutput -StdOut "......................... DC1 passed test Replications`n......................... DC1 failed test Replications" -Config $dd
Assert-Equal 'Fail' ([string](Resolve-AdfaDcdiagVerdict -Parsed $ddMixed -TestName 'Replications' -HostName 'dc1.contoso.com').Status) 'C11 verdict: passed and failed for the same DC is Fail, never Pass (the R2 false pass)'
Assert-Equal 'Fail' (Get-AdfaDcdiagTestOutcome -TestName 'Replications' -StdOut "......................... DC1 passed test Replications`n......................... DC1 failed test Replications") 'C11: the old classifier reads failed before passed too'
$ddOther = ConvertFrom-AdfaDcdiagOutput -StdOut '......................... DC2 failed test Services' -Config $dd
Assert-Equal 'Not Assessed|Fail' (((Resolve-AdfaDcdiagVerdict -Parsed $ddOther -TestName 'Services' -HostName 'dc1.contoso.com').Status, (Resolve-AdfaDcdiagVerdict -Parsed $ddOther -TestName 'Services' -HostName 'dc2.contoso.com').Status) -join '|') 'C11 verdict: another DC''s failure is not counted for this DC, and is for that DC'
Assert-True ((Test-AdfaDcdiagSubject -Subject 'MAPLEWAFFLE-WS2' -HostName 'maplewaffle-ws22.contoso.com') -and -not (Test-AdfaDcdiagSubject -Subject 'DC1' -HostName 'dc10.contoso.com')) 'C11 subject: the 15-character NetBIOS form matches a longer host name; a prefix does not'
$ddUnreach = Resolve-AdfaDcdiagVerdict -Parsed (ConvertFrom-AdfaDcdiagOutput -StdOut "Directory Server Diagnosis`nLdap search capability attribute search failed on server DC1, return value = 81" -Config $dd) -TestName 'Advertising' -HostName 'dc1.contoso.com'
$ddDenied = Resolve-AdfaDcdiagVerdict -Parsed (ConvertFrom-AdfaDcdiagOutput -StdOut "Directory Server Diagnosis`n[DC1] LDAP bind failed with error 5, Access is denied." -Config $dd) -TestName 'Advertising' -HostName 'dc1.contoso.com'
Assert-True ($ddUnreach.Status -eq 'Not Assessed' -and $ddUnreach.Detail -match 'could not reach' -and $ddUnreach.Detail -match 'provisional' -and $ddUnreach.Detail -notmatch '(?i)access denied') 'C11 verdict: an unreachable server is Not Assessed with a provisional cause, not access denied'
Assert-True ($ddDenied.Status -eq 'Not Assessed' -and $ddDenied.Detail -match 'access denied' -and $ddDenied.Detail -notmatch 'could not reach') 'C11 verdict: access denied is its own cause, not unreachable'
$ddEvent = ConvertFrom-AdfaDcdiagOutput -StdOut "The event log System on server dc1.contoso.com could not be queried, error 0x6ba`n......................... DC1 failed test SystemLog" -Config $dd
Assert-Equal 'Not Assessed' ([string](Resolve-AdfaDcdiagVerdict -Parsed $ddEvent -TestName 'SystemLog' -HostName 'dc1.contoso.com' -EventLog $true).Status) 'C11 verdict: an event log that could not be queried is Not Assessed, not Fail (KB 2512643)'
$ddLocal = Resolve-AdfaDcdiagVerdict -Parsed (ConvertFrom-AdfaDcdiagOutput -StdOut 'Diagnostico do Servidor de Diretorio' -Config $dd) -TestName 'Advertising' -HostName 'dc1.contoso.com'
Assert-True ($ddLocal.Status -eq 'Not Assessed' -and $ddLocal.Detail -match 'not recognised' -and $ddLocal.Detail -match 'localised') 'C11 verdict: unrecognised output is Not Assessed and says it may be localised'
# The target of a once-per-domain, -forest or -site test: usable and writable, never a read-only DC.
$ddStates = @(
    [pscustomobject]@{ HostName = 'rodc1.contoso.com'; IsReadOnly = $true; Usable = $true; Connectivity = 'Pass' }
    [pscustomobject]@{ HostName = 'dc2.contoso.com'; IsReadOnly = $false; Usable = $false; Connectivity = 'Fail' }
    [pscustomobject]@{ HostName = 'dc3.contoso.com'; IsReadOnly = $null; Usable = $true; Connectivity = 'Pass' }
    [pscustomobject]@{ HostName = 'dc4.contoso.com'; IsReadOnly = $false; Usable = $true; Connectivity = 'Pass' }
)
Assert-Equal 'dc4.contoso.com' ([string](Select-AdfaDcdiagTarget -States $ddStates).HostName) 'C11 target: a usable DC known to be writable is chosen first'
Assert-Equal 'dc3.contoso.com' ([string](Select-AdfaDcdiagTarget -States @($ddStates[0], $ddStates[1], $ddStates[2])).HostName) 'C11 target: then one whose writability is not known'
Assert-True ($null -eq (Select-AdfaDcdiagTarget -States @($ddStates[0], $ddStates[1]))) 'C11 target: a read-only DC and a DC whose Connectivity failed are never chosen'
# The validator: the time-out and retries only, never a test list.
Assert-Equal 180 ([int](Merge-AdfaDcDiagConfig -BaseConfig $dd -Override @{ TestTimeoutSeconds = 180 } -OverrideSource 'C:\cfg\o.json')['TestTimeoutSeconds']) 'DcDiag override: the time-out is accepted'
Assert-Throws { Merge-AdfaDcDiagConfig -BaseConfig $dd -Override @{ PerDcTests = @('CutoffServers') } } "unknown key 'PerDcTests'" 'DcDiag override: a test list can never be set from a file'
Assert-Throws { Merge-AdfaDcDiagConfig -BaseConfig $dd -Override @{ TestTimeoutSeconds = 601 } } 'whole number from 5 to 600' 'DcDiag override: the time-out is bounded'
Assert-Throws { Merge-AdfaDcDiagConfig -BaseConfig $dd -Override @{ Retries = '2' } } 'JSON number' 'DcDiag override: a quoted number is refused'
Assert-Equal 'DNS,Intersite,SystemLog' ((@($script:Config.DcdiagActiveTests) | ForEach-Object { [string]$_.Test }) -join ',') 'C11: SystemLog is held back with DNS and Intersite (Learn: "reading and writing entries")'
# The advice: the scoped families get their own; since C11h the grid rows get one entry per failing test.
$ddHostile = 'replication sysvol dfsr backup global catalog delegation C:\Backup\stale.json'
$ddRecs = @(foreach ($item in @('dcdiag Topology: contoso.com', 'dcdiag CheckSDRefDom: Schema', 'dcdiag CrossRefValidation: forest contoso.com', 'dcdiag Intersite: HQ', 'dcdiag coverage: contoso.com')) { Get-AdfaRecommendation -Section 'DC Diagnostics' -Item $item -Detail $ddHostile })
Assert-True ($ddRecs[0] -match 'topology generation' -and $ddRecs[1] -match 'msDS-SDReferenceDomain' -and $ddRecs[2] -match 'nETBIOSName' -and $ddRecs[3] -match 'Intersite Topology Generator' -and $ddRecs[4] -eq '' -and @($ddRecs | Where-Object { $_ -match 'dfsrmig|wbadmin|repadmin /replsummary' }).Count -eq 0) 'C11 advice: each scoped family gets its own advice, whatever the Detail says (declared population: five items)'
Assert-True ((Get-AdfaRecommendation -Section 'DC Diagnostics' -Item 'dc1.contoso.com' -Detail 'SysVolCheck: x') -match "^dcdiag's SysVolCheck test failed") 'C11h advice: a grid row gets its failing test''s own section-scoped advice (was the unscoped dfsrmig advice before v1.40.0)'
# Found by the independent review of the C11 diff, before commit.
$ddLong = 'maplewaffle-ws22.corp.contoso.com'
Assert-True (-not (Test-AdfaDcdiagSubject -Subject 'MAPLEWAFFLE' -HostName $ddLong) -and -not (Test-AdfaDcdiagSubject -Subject 'MAPLEWAFFLE-WS' -HostName $ddLong) -and (Test-AdfaDcdiagSubject -Subject 'MAPLEWAFFLE-WS2' -HostName $ddLong)) 'C11 subject: an 11- or 14-character prefix of a long label is not its NetBIOS form; the 15-character form is'
$ddDnsOut = "   Testing server: Default-First-Site-Name\DC1`r`n      Starting test: DNS`r`n         ......................... DC1 passed test DNS`r`n   Running enterprise tests on : contoso.com`r`n      Starting test: DNS`r`n         ......................... contoso.com failed test DNS"
$ddDns = ConvertFrom-AdfaDcdiagOutput -StdOut $ddDnsOut -Config $dd
Assert-Equal 'Fail' ([string](Resolve-AdfaDcdiagVerdict -Parsed $ddDns -TestName 'DNS' -HostName 'dc1.contoso.com' -EnterpriseParts $true -StdOut $ddDnsOut).Status) 'C11 verdict: a failed enterprise DNS summary fails the DC''s DNS cell, although the server block passed'
Assert-Equal 'FsmoCheck,DNS' ((@($dd['PerDcTests']) | Where-Object { $_['EnterpriseParts'] } | ForEach-Object { [string]$_['Test'] }) -join ',') 'C11 config: FsmoCheck and DNS are the per-DC tests whose enterprise verdict counts for the DC asked'
$ddFsmo = ConvertFrom-AdfaDcdiagOutput -StdOut "   Running enterprise tests on : contoso.com`r`n      Starting test: FsmoCheck`r`n         ......................... contoso.com passed test `r`n         FsmoCheck" -Config $dd
Assert-Equal 'Pass' ([string](Resolve-AdfaDcdiagVerdict -Parsed $ddFsmo -TestName 'FsmoCheck' -HostName 'dc1.contoso.com' -EnterpriseParts $true).Status) 'C11 verdict: FsmoCheck passed in the enterprise block reads Pass for the DC asked'
$ddNlOut = "   Testing server: Default-First-Site-Name\DC1`r`n      Starting test: NetLogons`r`n         Unable to connect to the NETLOGON share! (\\DC1\netlogon)`r`n         Access is denied.`r`n         ......................... DC1 failed test NetLogons"
$ddNl = Resolve-AdfaDcdiagVerdict -Parsed (ConvertFrom-AdfaDcdiagOutput -StdOut $ddNlOut -Config $dd) -TestName 'Netlogons' -HostName 'dc1.contoso.com' -StdOut $ddNlOut
Assert-True ($ddNl.Status -eq 'Fail' -and $ddNl.Detail -match 'KB 3073945' -and $ddNl.Detail -notmatch '(?i)replication') 'C11 verdict: the Access is denied note on a failed verdict is there, and does not say replication'
$ddAdvice = [string]@($script:RecommendationMap | Where-Object { -not $_.ContainsKey('Section') -and [string]$_.Match -eq '(?i)dcdiag|advertising|netlogons|sysvolcheck|fsmocheck|kccevent' })[0].Text
$ddNlRec = Get-AdfaRecommendation -Section 'DC Diagnostics' -Item 'dc1.contoso.com' -Detail $ddNl.Detail
Assert-True ($ddNlRec -match "^dcdiag's NetLogons test failed" -and $ddNlRec -ne $ddAdvice) 'C11h advice: a failed NetLogons with Access is denied gets the NetLogons advice, not the replication or the generic dcdiag advice'
$ddKcc = Resolve-AdfaDcdiagVerdict -Parsed (ConvertFrom-AdfaDcdiagOutput -StdOut "Diagnostic du serveur d'annuaire`r`nDC1 a reussi le test KccEvent" -Config $dd) -TestName 'KccEvent' -HostName 'dc1.contoso.com' -StdOut "Diagnostic du serveur d'annuaire`r`nDC1 a reussi le test KccEvent"
$ddKccRec = Get-AdfaRecommendation -Section 'DC Diagnostics' -Item 'dc1.contoso.com' -Detail $ddKcc.Detail
Assert-True ($ddKccRec -match 'gave no verdict this tool could read' -and $ddKccRec -notmatch 'cleared or wrapped') 'C11h advice: an unrecognised cell gets the Not Assessed grid advice, not the event-log coverage advice'
$ddBanner = Resolve-AdfaDcdiagVerdict -Parsed (ConvertFrom-AdfaDcdiagOutput -StdOut "Directory Server Diagnosis`r`nPerforming initial setup:" -Config $dd) -TestName 'Advertising' -HostName 'dc1.contoso.com' -StdOut "Directory Server Diagnosis`r`nPerforming initial setup:"
Assert-True ($ddBanner.Status -eq 'Not Assessed' -and $ddBanner.Detail -match 'neither' -and $ddBanner.Detail -notmatch 'localised') 'C11 verdict: English banner-only output is "no verdict line", not "possibly localised"'
$ddBare = ConvertFrom-AdfaDcdiagOutput -StdOut "   Testing server: Default-First-Site-Name\DC2`r`n      Starting test: Advertising`r`n         ......................... passed test Advertising" -Config $dd
Assert-Equal 'Not Assessed|Pass' (((Resolve-AdfaDcdiagVerdict -Parsed $ddBare -TestName 'Advertising' -HostName 'dc1.contoso.com').Status, (Resolve-AdfaDcdiagVerdict -Parsed $ddBare -TestName 'Advertising' -HostName 'dc2.contoso.com').Status) -join '|') 'C11 verdict: a bare verdict in DC2''s server block is DC2''s, not dc1''s'
$ddNaStates = @(
    [pscustomobject]@{ HostName = 'rodc8.contoso.com'; IsReadOnly = $true; Usable = $true; Connectivity = 'Not Assessed' }
    [pscustomobject]@{ HostName = 'dc6.contoso.com'; IsReadOnly = $null; Usable = $true; Connectivity = 'Not Assessed' }
    [pscustomobject]@{ HostName = 'dc7.contoso.com'; IsReadOnly = $false; Usable = $true; Connectivity = 'Not Assessed' }
)
Assert-Equal 'dc7.contoso.com|dc6.contoso.com' (([string](Select-AdfaDcdiagTarget -States $ddNaStates).HostName, [string](Select-AdfaDcdiagTarget -States @($ddNaStates[0], $ddNaStates[1])).HostName) -join '|') 'C11 target: with no Connectivity passed, a usable DC whose Connectivity was not assessed is tried, writable first'

Write-Host ""
Write-Host "== C12. dcdiag DNS summary per test group (pure logic) ==" -ForegroundColor Cyan
# Learn shows the DNS test's summary table once (KB 2102154, read 2026-11-16): a header
# "Auth Basc Forw Del  Dyn  RReg Ext", "Domain:" lines, one row per DC, then the enterprise block.
# The header is found by its tokens, the cells mapped by order, each group graded on its own.
$dnsSample = "Auth Basc Forw Del  Dyn  RReg Ext`r`n`r`nDomain: contoso.com`r`nDC1 PASS PASS FAIL PASS PASS PASS n/a  `r`nDomain: child.contoso.com  `r`nDC2 PASS PASS n/a  n/a  n/a  PASS n/a  `r`n`r`nEnterprise DNS infrastructure test results:  `r`nDC9 FAIL FAIL FAIL FAIL FAIL FAIL FAIL`r`n......................... contoso.com failed test DNS"
$dnsSum = ConvertFrom-AdfaDcdiagDnsSummary -StdOut $dnsSample -Config $dd
Assert-Equal 'Auth,Basc,Forw,Del,Dyn,RReg,Ext' (@($dnsSum.Columns) -join ',') 'C12 parser: the header is found by its tokens, in Learn''s column order (declared population: seven columns)'
Assert-Equal 'DC1@contoso.com|DC2@child.contoso.com' ((@($dnsSum.Rows) | ForEach-Object { "{0}@{1}" -f $_.Name, $_.Domain }) -join '|') 'C12 parser: two rows under their Domain lines, nothing read after the enterprise block (declared population: two DCs)'
Assert-Equal 'PASS,PASS,n/a,n/a,n/a,PASS,n/a' (@(@($dnsSum.Rows)[1].Cells) -join ',') 'C12 parser: cells split on runs of whitespace and kept in order'
Assert-Equal 2 (@((ConvertFrom-AdfaDcdiagDnsSummary -StdOut ($dnsSample -replace "`r`n", "`n") -Config $dd).Rows).Count) 'C12 parser: LF output reads the same as CRLF'
Assert-True (-not (ConvertFrom-AdfaDcdiagDnsSummary -StdOut "Auth Basc Forw`r`nDC1 PASS PASS PASS" -Config $dd).HeaderFound -and (ConvertFrom-AdfaDcdiagDnsSummary -StdOut "Auth Basc Forw Del`r`nDC1 PASS PASS PASS PASS" -Config $dd).HeaderFound) 'C12 parser: four header tokens make a header, three do not (tool default, not a Microsoft value)'
$dnsGrades = @(foreach ($t in @('Auth', 'Basc', 'Forw', 'Del', 'Dyn', 'RReg', 'Ext')) { [string](Resolve-AdfaDcdiagDnsCategory -Summary $dnsSum -HostName 'dc1.contoso.com' -Token $t -Config $dd).Status })
Assert-Equal 'Pass,Pass,Fail,Pass,Pass,Pass,Info' ($dnsGrades -join ',') 'C12 verdict: DC1 of Learn''s sample - FAIL under Forw is Fail, n/a under Ext is Info (declared population: seven groups)'
$dnsGrades2 = @(foreach ($t in @('Forw', 'Del', 'Dyn')) { [string](Resolve-AdfaDcdiagDnsCategory -Summary $dnsSum -HostName 'dc2.child.contoso.com' -Token $t -Config $dd).Status })
Assert-Equal 'Not Assessed,Not Assessed,Not Assessed' ($dnsGrades2 -join ',') 'C12 verdict: n/a under Forw, Del and Dyn is Not Assessed, never Not Applicable or Pass (catalogue DNSDIAG-003..005)'
$dnsWarn = ConvertFrom-AdfaDcdiagDnsSummary -StdOut "Auth Basc Forw Del Dyn RReg Ext`r`nDC1 PASS WARN PASS PASS PASS PASS n/a" -Config $dd
Assert-Equal 'Warning' ([string](Resolve-AdfaDcdiagDnsCategory -Summary $dnsWarn -HostName 'dc1.contoso.com' -Token 'Basc' -Config $dd).Status) 'C12 verdict: WARN is Warning'
$dnsMissing = Resolve-AdfaDcdiagDnsCategory -Summary $dnsSum -HostName 'dc3.contoso.com' -Token 'Auth' -Config $dd
Assert-True ($dnsMissing.Status -eq 'Not Assessed' -and $dnsMissing.Detail -match 'no row for this domain controller') 'C12 verdict: a DC with no row is Not Assessed, never Pass'
$dnsShort = ConvertFrom-AdfaDcdiagDnsSummary -StdOut "Auth Basc Forw Del Dyn RReg Ext`r`nDC1 PASS PASS PASS PASS PASS PASS" -Config $dd
Assert-True ((Resolve-AdfaDcdiagDnsCategory -Summary $dnsShort -HostName 'dc1.contoso.com' -Token 'Auth' -Config $dd).Detail -match 'row not recognised') 'C12 verdict: a row whose cell count is not the header''s is not recognised, not graded'
$dnsUnreach = Resolve-AdfaDcdiagDnsCategory -Summary $dnsSum -HostName 'dc1.contoso.com' -Token 'Auth' -Config $dd -NotRunCause 'unreachable: the domain controller did not answer on RPC/135'
Assert-True ($dnsUnreach.Status -eq 'Not Assessed' -and $dnsUnreach.Detail -match 'RPC/135') 'C12 verdict: a cause that stopped the test wins over any table'
$dnsDenied = Resolve-AdfaDcdiagDnsCategory -Summary (ConvertFrom-AdfaDcdiagDnsSummary -StdOut 'Access is denied.' -Config $dd) -HostName 'dc1.contoso.com' -Token 'Dyn' -Config $dd -RunCause 'DNS: NOT ASSESSED - access denied: dcdiag printed no verdict'
Assert-True ($dnsDenied.Status -eq 'Not Assessed' -and $dnsDenied.Detail -match 'access denied' -and $dnsDenied.Detail -notmatch 'RPC/135') 'C12 verdict: with no table, the run''s own cause (access denied) is carried, not unreachable'
$dnsOverall = Resolve-AdfaDcdiagDnsCategory -Summary (ConvertFrom-AdfaDcdiagDnsSummary -StdOut '......................... DC1 passed test DNS' -Config $dd) -HostName 'dc1.contoso.com' -Token 'Del' -Config $dd -OverallStatus 'Pass' -OverallEvidence 'DC1 passed test DNS'
Assert-True ($dnsOverall.Status -eq 'Not Assessed' -and $dnsOverall.Detail -match 'overall verdict') 'C12 verdict: an overall Pass with no summary table grades no test group as Pass'
$dnsCellsFor = { param([string[]]$S) @(for ($k = 0; $k -lt $S.Count; $k++) { [pscustomobject]@{ HostName = ("dc{0}.contoso.com" -f ($k + 1)); Status = $S[$k] } }) }
$dnsRolls = @(
    [string](Resolve-AdfaDcdiagDnsRollup -Cells (& $dnsCellsFor @('Pass', 'Fail', 'Not Assessed')) -Token 'Del').Status
    [string](Resolve-AdfaDcdiagDnsRollup -Cells (& $dnsCellsFor @('Pass', 'Warning')) -Token 'Del').Status
    [string](Resolve-AdfaDcdiagDnsRollup -Cells (& $dnsCellsFor @('Pass', 'Not Assessed')) -Token 'Del').Status
    [string](Resolve-AdfaDcdiagDnsRollup -Cells (& $dnsCellsFor @('Pass', 'Pass')) -Token 'Del').Status
    [string](Resolve-AdfaDcdiagDnsRollup -Cells (& $dnsCellsFor @('Info', 'Info')) -Token 'Ext').Status
    [string](Resolve-AdfaDcdiagDnsRollup -Cells @() -Token 'Del').Status
)
Assert-Equal 'Fail,Warning,Not Assessed,Pass,Info,Not Assessed' ($dnsRolls -join ',') 'C12 roll-up: Fail, then Warning, then Not Assessed, then Pass, then Info; no DC is Not Assessed (declared population: six cases)'
Assert-Throws { Merge-AdfaDcDiagConfig -BaseConfig $dd -Override @{ DnsSummary = @{} } } "unknown key 'DnsSummary'" 'C12 override: the DNS summary table can never be set from a file'
Assert-Throws { Merge-AdfaDcDiagConfig -BaseConfig $dd -Override @{ HeaderMinTokens = 1 } } "unknown key 'HeaderMinTokens'" 'C12 override: the header threshold can never be set from a file'
$dnsRecs = @(foreach ($t in @('Auth', 'Basc', 'Forw', 'Del', 'Dyn', 'RReg', 'Ext')) { Get-AdfaRecommendation -Section 'DC Diagnostics' -Item ("dcdiag DNS {0}: dc1.contoso.com" -f $t) -Detail $ddHostile })
Assert-True ($dnsRecs[0] -match 'Enterprise Admins' -and $dnsRecs[1] -match 'zone existence' -and $dnsRecs[2] -match 'configuration of forwarders' -and $dnsRecs[3] -match 'proper delegations' -and $dnsRecs[4] -match 'secure dynamic updates' -and $dnsRecs[5] -match '\(SRV\)' -and $dnsRecs[6] -match 'proxy server') 'C12 advice: each DNS test group gets its own advice, whatever the Detail says (declared population: seven groups)'
Assert-Equal '' (Get-AdfaRecommendation -Section 'DC Diagnostics' -Item 'dcdiag DNS not run: contoso.com' -Detail $ddHostile) 'C12 advice: the not-run row gets no advice, not the unscoped delegation or dcdiag advice'
# Found by an independent review of the C12 diff, before commit.
$dnsOdd = @(foreach ($v in @('Bogus', '', $null)) { [string](Resolve-AdfaDcdiagDnsRollup -Cells @([pscustomobject]@{ HostName = 'dc8.contoso.com'; Status = $v }) -Token 'Auth').Status })
Assert-Equal 'Not Assessed,Not Assessed,Not Assessed' ($dnsOdd -join ',') 'C12 roll-up: a status it does not read (unknown, empty, null) is Not Assessed, never Info (declared population: three cases)'
$dnsExtFail = Resolve-AdfaDcdiagDnsCategory -Summary (ConvertFrom-AdfaDcdiagDnsSummary -StdOut "Auth Basc Forw Del Dyn RReg Ext`r`nDC1 PASS PASS PASS PASS PASS PASS FAIL" -Config $dd) -HostName 'dc1.contoso.com' -Token 'Ext' -Config $dd
Assert-True ($dnsExtFail.Status -eq 'Fail' -and $dnsExtFail.Detail -match 'proxy server') 'C12 verdict: FAIL under Ext is Fail with Microsoft''s proxy caveat (catalogue DNSDIAG-007), not Info'
$dnsOverallFail = Resolve-AdfaDcdiagDnsCategory -Summary (ConvertFrom-AdfaDcdiagDnsSummary -StdOut '......................... contoso.com failed test DNS' -Config $dd) -HostName 'dc1.contoso.com' -Token 'Auth' -Config $dd -OverallStatus 'Fail' -OverallEvidence 'contoso.com failed test DNS'
Assert-Equal 'Not Assessed' ([string]$dnsOverallFail.Status) 'C12 verdict: an overall Fail with no summary table grades no test group as Fail'
$dnsTwo = ConvertFrom-AdfaDcdiagDnsSummary -StdOut "Auth Basc Forw Del Dyn RReg Ext`r`nDC1 FAIL FAIL FAIL FAIL FAIL FAIL FAIL`r`nEnterprise DNS infrastructure test results:`r`nAuth Basc Forw Del Dyn RReg Ext`r`nDC1 PASS PASS PASS PASS PASS PASS n/a" -Config $dd
Assert-Equal '2|PASS' (("{0}|{1}" -f $dnsTwo.HeaderCount, @(@($dnsTwo.Rows)[0].Cells)[0])) 'C12 parser: the last header in the output is the one read'
$dnsBlock = ConvertFrom-AdfaDcdiagDnsSummary -StdOut "Auth Basc Forw Del Dyn RReg Ext`r`nDC1 PASS PASS PASS PASS PASS PASS n/a`r`n   Testing server: Default-First-Site-Name\DC2`r`nDC2 FAIL FAIL FAIL FAIL FAIL FAIL FAIL" -Config $dd
Assert-Equal 'DC1' ((@($dnsBlock.Rows) | ForEach-Object { $_.Name }) -join ',') 'C12 parser: a server block header ends the table (declared population: one row above it)'
$dnsRecDyn = Get-AdfaRecommendation -Section 'DC Diagnostics' -Item 'dcdiag DNS Dyn: dc1.contoso.com' -Detail 'x'
$dnsRecRReg = Get-AdfaRecommendation -Section 'DC Diagnostics' -Item 'dcdiag DNS RReg: dc1.contoso.com' -Detail 'x'
Assert-True ($dnsRecDyn -match 'AAAA' -and $dnsRecRReg -notmatch 'AAAA') 'C12 advice: the AAAA caveat is under Dyn, where Learn gives it, not under RReg'
Write-Host "== C13. DNS: dynamic update, aging and scavenging, locator records, A records, records naming no DC, DNS client ==" -ForegroundColor Cyan
$dnsCfg = $script:Config.Dns
$dnsObs = { param([string]$Server, [bool]$Read = $true, $Ds = $true, [string]$Dyn = 'Secure', $Scav = $true, $Aging = $true)
    [pscustomobject]@{ Server = $Server; Read = $Read; Cause = 'not read'; IsDsIntegrated = $Ds; DynamicUpdate = $Dyn; ServerScavenging = $Scav; AgingEnabled = $Aging } }
$dnsDyn = @(
    [string](Get-AdfaDnsDynamicUpdateVerdict -Observations @((& $dnsObs 'dc1.contoso.com'), (& $dnsObs 'dc2.contoso.com' -Dyn 'NonsecureAndSecure')) -Config $dnsCfg).Status
    [string](Get-AdfaDnsDynamicUpdateVerdict -Observations @((& $dnsObs 'dc1.contoso.com'), (& $dnsObs 'dc2.contoso.com' -Dyn 'None')) -Config $dnsCfg).Status
    [string](Get-AdfaDnsDynamicUpdateVerdict -Observations @((& $dnsObs 'dc1.contoso.com'), (& $dnsObs 'dc2.contoso.com' -Read $false)) -Config $dnsCfg).Status
    [string](Get-AdfaDnsDynamicUpdateVerdict -Observations @((& $dnsObs 'dc1.contoso.com' -Dyn 'Bogus')) -Config $dnsCfg).Status
    [string](Get-AdfaDnsDynamicUpdateVerdict -Observations @((& $dnsObs 'dc1.contoso.com' -Ds $null)) -Config $dnsCfg).Status
    [string](Get-AdfaDnsDynamicUpdateVerdict -Observations @((& $dnsObs 'dc1.contoso.com' -Ds $false -Dyn 'NonsecureAndSecure')) -Config $dnsCfg).Status
    [string](Get-AdfaDnsDynamicUpdateVerdict -Observations @() -Config $dnsCfg).Status
)
Assert-Equal 'Fail,Pass,Not Assessed,Not Assessed,Not Assessed,Info,Not Assessed' ($dnsDyn -join ',') 'C13 DNS-001: nonsecure on an AD-integrated zone fails; Secure/None pass; an unread server, an unknown value or an absent property is Not Assessed; a file-backed zone is Info (declared population: seven cases)'
$dnsScav = @(
    [string](Get-AdfaDnsScavengingVerdict -Observations @((& $dnsObs 'dc1.contoso.com' -Scav $false), (& $dnsObs 'dc2.contoso.com' -Scav $false)) -Config $dnsCfg).Status
    [string](Get-AdfaDnsScavengingVerdict -Observations @((& $dnsObs 'dc1.contoso.com' -Scav $false), (& $dnsObs 'dc2.contoso.com' -Scav $true)) -Config $dnsCfg).Status
    [string](Get-AdfaDnsScavengingVerdict -Observations @((& $dnsObs 'dc1.contoso.com' -Aging $false)) -Config $dnsCfg).Status
    [string](Get-AdfaDnsScavengingVerdict -Observations @((& $dnsObs 'dc1.contoso.com' -Scav $false), (& $dnsObs 'dc2.contoso.com' -Read $false)) -Config $dnsCfg).Status
    [string](Get-AdfaDnsScavengingVerdict -Observations @((& $dnsObs 'dc1.contoso.com' -Scav $null)) -Config $dnsCfg).Status
)
Assert-Equal 'Warning,Pass,Warning,Not Assessed,Not Assessed' ($dnsScav -join ',') 'C13 DNS-002: no scavenging server or aging off is a Warning, one scavenging server passes, an unread server or value is Not Assessed (declared population: five cases)'
$dnsSpan = @((Test-AdfaDnsServerScavenges -Interval ([timespan]::Zero)), (Test-AdfaDnsServerScavenges -Interval ([timespan]::FromSeconds(1))), ($null -eq (Test-AdfaDnsServerScavenges -Interval 168)))
Assert-Equal 'False,True,True' ($dnsSpan -join ',') 'C13 DNS-002: a scavenging interval of zero is off, one second is on, a bare number is not read'
$dnsStates = @(foreach ($pair in @(@('Present', 'Absent'), @('Absent', 'Absent'), @('Absent', 'Unread'), @('Unread', 'Absent'), @('Unread', 'Unread'))) { Get-AdfaDnsEvidenceState -ServerOutcome $pair[0] -ResolverOutcome $pair[1] })
Assert-Equal 'Present,AbsentBoth,AbsentOne,AbsentOne,Unread' ($dnsStates -join ',') 'C13 two instruments: only both saying absent is a confirmed absence (declared population: five pairs)'
$dnsCheck = { param([string]$State) [pscustomobject]@{ Record = 'Dc'; Server = 'dc1.contoso.com'; State = $State; Cause = '' } }
$dnsLoc = @(
    [string](Get-AdfaDcLocatorVerdict -IsReadOnly $false -Checks @((& $dnsCheck 'Present')) -Config $dnsCfg).Status
    [string](Get-AdfaDcLocatorVerdict -IsReadOnly $false -Checks @((& $dnsCheck 'AbsentBoth')) -Config $dnsCfg).Status
    [string](Get-AdfaDcLocatorVerdict -IsReadOnly $false -Checks @((& $dnsCheck 'AbsentOne')) -Config $dnsCfg).Status
    [string](Get-AdfaDcLocatorVerdict -IsReadOnly $false -Checks @((& $dnsCheck 'Unread')) -Config $dnsCfg).Status
    [string](Get-AdfaDcLocatorVerdict -IsReadOnly $true -Checks @((& $dnsCheck 'AbsentBoth')) -Config $dnsCfg).Status
    [string](Get-AdfaDcLocatorVerdict -IsReadOnly $false -Checks @() -Config $dnsCfg).Status
)
Assert-Equal 'Pass,Fail,Warning,Not Assessed,Info,Not Assessed' ($dnsLoc -join ',') 'C13 DNS-003: Fail only on two instruments, one instrument a Warning, unread Not Assessed, an RODC Info (declared population: six cases)'
$dnsA = @(
    [string](Get-AdfaDcARecordVerdict -ConfiguredIPv4 @('192.0.2.11') -Answers @([pscustomobject]@{ Server = 'dc1.contoso.com'; State = 'Present'; Addresses = @('192.0.2.11') }) -Config $dnsCfg).Status
    [string](Get-AdfaDcARecordVerdict -ConfiguredIPv4 @('192.0.2.11') -Answers @([pscustomobject]@{ Server = 'dc1.contoso.com'; State = 'Present'; Addresses = @('192.0.2.99') }) -Config $dnsCfg).Status
    [string](Get-AdfaDcARecordVerdict -ConfiguredIPv4 $null -Answers @([pscustomobject]@{ Server = 'dc1.contoso.com'; State = 'Present'; Addresses = @('192.0.2.11') }) -Config $dnsCfg).Status
)
Assert-Equal 'Pass,Warning,Not Assessed' ($dnsA -join ',') 'C13 DNS-004: an A record not on the adapters is a Warning; adapters not read is Not Assessed (declared population: three cases)'
$dnsStale = Get-AdfaStaleDnsRecordVerdict -Candidates @([pscustomobject]@{ Name = '_ldap._tcp.dc._msdcs.contoso.com'; Type = 'SRV'; Target = 'old-dc.contoso.com.'; Server = 'dc1.contoso.com' },
    [pscustomobject]@{ Name = '_ldap._tcp.dc._msdcs.contoso.com'; Type = 'SRV'; Target = 'rodc1.contoso.com'; Server = 'dc1.contoso.com' }) -KnownDcHosts @('dc1.contoso.com', 'rodc1.contoso.com') -KnownDsaGuids @() -Config $dnsCfg
Assert-True ($dnsStale.Status -eq 'Warning' -and @($dnsStale.Stale).Count -eq 1 -and [string]@($dnsStale.Stale)[0].Target -eq 'old-dc.contoso.com' -and $dnsStale.Detail -notmatch 'old-dc') 'C13 DNS-005: the target that is no DC is listed (RODC known), and its name is not in Detail'
$dnsClient = @(
    [string](Get-AdfaDcDnsClientVerdict -DnsServers @('127.0.0.1') -SelfAddresses @('192.0.2.11') -KnownDcAddresses @('192.0.2.11', '192.0.2.12') -DcCount 2 -Config $dnsCfg).Status
    [string](Get-AdfaDcDnsClientVerdict -DnsServers @('127.0.0.1') -SelfAddresses @('192.0.2.11') -KnownDcAddresses @('192.0.2.11') -DcCount 1 -DcCountIsForest $true -Config $dnsCfg).Status
    [string](Get-AdfaDcDnsClientVerdict -DnsServers @('192.0.2.12', '127.0.0.1') -SelfAddresses @('192.0.2.11') -KnownDcAddresses @('192.0.2.11', '192.0.2.12') -DcCount 2 -Config $dnsCfg).Status
    [string](Get-AdfaDcDnsClientVerdict -DnsServers $null -Cause 'Unreachable' -SelfAddresses @() -KnownDcAddresses @() -DcCount 2 -Config $dnsCfg).Status
    [string](Get-AdfaDcDnsClientVerdict -DnsServers @('127.0.0.1') -SelfAddresses @('192.0.2.11') -KnownDcAddresses @('192.0.2.11') -DcCount 1 -Config $dnsCfg).Status
)
Assert-Equal 'Warning,Info,Info,Not Assessed,Not Assessed' ($dnsClient -join ',') 'C13 INV-016: one DNS server with more than one DC is a Warning (KB 4013), in a one-DC forest Info, two servers Info, not read Not Assessed, one DC known in a run that did not cover the forest Not Assessed (declared population: five cases)'
$dnsMerged = Merge-AdfaDnsConfig -BaseConfig $dnsCfg -Override @{ NonsecureStatus = 'Warning'; RecordExportCap = 10 } -OverrideSource 'C:\cfg\dns.json'
Assert-True ($dnsMerged['NonsecureStatus'] -eq 'Warning' -and $dnsMerged['RecordExportCap'] -eq 10 -and $dnsCfg['NonsecureStatus'] -eq 'Fail') 'C13 override: the statuses and the cap merge, the built-in table is unchanged'
Assert-Throws { Merge-AdfaDnsConfig -BaseConfig $dnsCfg -Override @{ LocatorRecords = @() } } "unknown key 'LocatorRecords'" 'C13 override: the record names can never be set from a file'
Assert-Throws { Merge-AdfaDnsConfig -BaseConfig $dnsCfg -Override @{ NonsecureStatus = 'Pass' } } 'Fail, Warning' 'C13 override: a status outside its set is refused'
Assert-Throws { Merge-AdfaDnsConfig -BaseConfig $dnsCfg -Override @{ RecordExportCap = 0 } } '1 to 1000000' 'C13 override: a cap of zero is refused'
Assert-Throws { Merge-AdfaDnsConfig -BaseConfig $dnsCfg -Override @{ } } 'empty object' 'C13 override: an empty object is refused'
Assert-Throws { Merge-AdfaDnsConfig -BaseConfig $dnsCfg -Override @{ OneInstrumentStatus = $null } } 'null' 'C13 override: a null is refused'
$dnsHostile = 'replication stale delegation secure dynamic zone transfer scavenging aging backup global catalog dcdiag NOT a pass'
$dnsRecs = @(
    Get-AdfaRecommendation -Section 'DNS Health' -Item 'Zone dynamic update: replication.contoso.com' -Detail $dnsHostile
    Get-AdfaRecommendation -Section 'DNS Health' -Item 'Zone scavenging: contoso.com' -Detail $dnsHostile
    Get-AdfaRecommendation -Section 'DNS vs AD Consistency' -Item 'DC locator records: dc1.contoso.com' -Detail $dnsHostile
    Get-AdfaRecommendation -Section 'DNS vs AD Consistency' -Item 'Stale DC record: backup-dc.contoso.com' -Detail $dnsHostile
    Get-AdfaRecommendation -Section 'DC DNS Client' -Item 'DNS client: dc1.contoso.com' -Detail $dnsHostile
)
Assert-True ($dnsRecs[0] -match 'Secure only' -and $dnsRecs[1] -match 'only one DNS server per zone' -and $dnsRecs[2] -match 'Netlogon\.dns' -and $dnsRecs[3] -match 'stale domain controllers' -and $dnsRecs[4] -match 'single point of failure' -and @($dnsRecs | Where-Object { $_ -notmatch 'changes nothing' }).Count -eq 0) 'C13 advice: each graded family gets its own advice whatever the Item and Detail say (declared population: five families)'
Assert-Equal '' (Get-AdfaRecommendation -Section 'DNS Record Export' -Item 'Record export: total' -Detail $dnsHostile) 'C13 advice: the record export rows get no advice'
# C13 independent review: the fixes, as pure logic.
Assert-Equal 'Error,Error,Error,NotFound,NotFound' ((@('The network path was not found.', 'The specified domain either does not exist or could not be contacted.', 'x', 'Failed to get dc9 record. WIN32 9714', 'DNS record does not exist.') | ForEach-Object { $code = ''; if ($_ -eq 'x') { $code = 'NotFound' }; Get-AdfaDnsReadErrorClass -Message $_ -ErrorCode $code -Config $dnsCfg }) -join ',') 'C13 review: only Win32 9701/9714 is no such record; a transport failure, a domain failure and a bare CIM NotFound are failed reads (declared population: five messages)'
Assert-Equal 'north,,' ((@((Get-AdfaDnsDelegationPoint -Relative '_ldap._tcp.dc._msdcs.north' -Delegations @('north')), (Get-AdfaDnsDelegationPoint -Relative 'dc1' -Delegations @('north')), (Get-AdfaDnsDelegationPoint -Relative 'dc1.xnorth' -Delegations @('north')))) -join ',') 'C13 review: a name below a delegation is found on a label boundary only (declared population: three names)'
$dnsNoDc = Get-AdfaStaleDnsRecordVerdict -Candidates @([pscustomobject]@{ Name = '_ldap._tcp.dc._msdcs.contoso.com'; Type = 'SRV'; Target = 'dc1.contoso.com'; Server = 'dc1.contoso.com' }) -KnownDcHosts @() -Config $dnsCfg
Assert-True ($dnsNoDc.Status -eq 'Not Assessed' -and @($dnsNoDc.Stale).Count -eq 0) 'C13 review: with no DC known, no SRV target is listed as stale'
$dnsA2 = @(
    [string](Get-AdfaDcARecordVerdict -ConfiguredIPv4 @('192.0.2.11') -Answers @([pscustomobject]@{ Server = 'dc1.contoso.com'; State = 'Present'; Addresses = @() }) -Config $dnsCfg).Status
    [string](Get-AdfaDcARecordVerdict -ConfiguredIPv4 @('192.0.2.11') -Answers @([pscustomobject]@{ Server = 'dc1.contoso.com'; State = 'AbsentOne'; Addresses = @() }) -Config $dnsCfg).Status
)
Assert-Equal 'Not Assessed,Warning' ($dnsA2 -join ',') 'C13 review: an A record with no readable address is Not Assessed, one absent on one instrument is OneInstrumentStatus, never Pass (declared population: two cases)'
$dnsScav2 = @(
    [string](Get-AdfaDnsScavengingVerdict -Observations @((& $dnsObs 'dc1.contoso.com' -Aging $false), (& $dnsObs 'dc2.contoso.com' -Read $false)) -Config $dnsCfg).Status
    [string](Get-AdfaDnsScavengingVerdict -Observations @((& $dnsObs 'dc1.contoso.com' -Scav $false)) -Config $dnsCfg -HostSetComplete $false).Status
)
Assert-Equal 'Warning,Not Assessed' ($dnsScav2 -join ',') 'C13 review: measured aging off stands with a server unread; no scavenging server on an incomplete hosting set is Not Assessed (declared population: two cases)'
$dnsProv = Get-AdfaDnsDynamicUpdateVerdict -Observations @((& $dnsObs 'dc1.contoso.com' -Dyn 'NonsecureAndSecure')) -Config (Merge-AdfaDnsConfig -BaseConfig $dnsCfg -Override @{ NonsecureStatus = 'Warning' } -OverrideSource 'C:\cfg\dns.json')
Assert-True ($dnsProv.Status -eq 'Warning' -and $dnsProv.Detail -match 'Graded Warning: C:\\cfg\\dns\.json \(loaded' -and $dnsProv.Detail -notmatch 'The grade is a tool default') 'C13 review: a grade a file set names the file, not a tool default'

Write-Host "== C14: reachability classes, site coverage, clock offset against the forest root PDC, stale objects, SYSVOL engine ==" -ForegroundColor Cyan
Assert-Equal '1.43.0' ([string]$script:Config.Version) 'C14: version 1.43.0 in the script (bumped by PORT-PLAN C15c)'
$c14Reach = $script:Config.Reach
$c14Res = { param([bool]$Ok = $true, [string[]]$A = @('192.0.2.21'), [string]$Se = '', [bool]$To = $false) [pscustomobject]@{ Ok = $Ok; Addresses = @($A); SocketError = $Se; TimedOut = $To; Error = '' } }
$c14Probe = { param([string]$O = 'Open', [string]$Se = '', [bool]$To = $false) [pscustomobject]@{ Outcome = $O; SocketError = $Se; TimedOut = $To; Error = '' } }
$c14Classes = @(
    (Resolve-AdfaDcReachClass -Resolve (& $c14Res $false @() 'HostNotFound') -LdapProbes @() -Config $c14Reach)
    (Resolve-AdfaDcReachClass -Resolve (& $c14Res $false @() '' $true) -LdapProbes @() -Config $c14Reach)
    (Resolve-AdfaDcReachClass -Resolve (& $c14Res) -LdapProbes @((& $c14Probe 'Failed' 'ConnectionRefused')) -Config $c14Reach)
    (Resolve-AdfaDcReachClass -Resolve (& $c14Res) -LdapProbes @((& $c14Probe 'Failed' 'ConnectionRefused'), (& $c14Probe 'Failed' '' $true)) -Config $c14Reach)
    (Resolve-AdfaDcReachClass -Resolve (& $c14Res) -LdapProbes @((& $c14Probe 'Failed' 'HostUnreachable')) -Config $c14Reach)
    (Resolve-AdfaDcReachClass -Resolve (& $c14Res) -LdapProbes @((& $c14Probe)) -WinRm (& $c14Probe) -Rpc (& $c14Probe 'Failed' 'TimedOut') -Config $c14Reach)
    (Resolve-AdfaDcReachClass -Resolve (& $c14Res) -LdapProbes @((& $c14Probe)) -WinRm (& $c14Probe 'Failed' 'TimedOut') -Rpc (& $c14Probe) -Config $c14Reach)
    (Resolve-AdfaDcReachClass -Resolve (& $c14Res) -LdapProbes @((& $c14Probe)) -WinRm (& $c14Probe 'Failed' 'TimedOut') -Rpc (& $c14Probe 'Failed' 'ConnectionRefused') -Config $c14Reach)
    (Resolve-AdfaDcReachClass -Resolve (& $c14Res) -LdapProbes @((& $c14Probe)) -Config $c14Reach)
)
Assert-Equal 'Unreachable/Unresolved,Unreachable/ResolveTimedOut,Unreachable/Refused,Unreachable/TimedOut,Unreachable/NetworkUnreachable,Reachable/,WinRmUnavailable/,NotManageable/ManagementPortsSilent,NotAssessed/NotProbed' (@($c14Classes | ForEach-Object { "{0}/{1}" -f $_.Class, $_.Cause }) -join ',') 'C14 REACH: the classifier tells name resolution, refused, timed out, no route, WinRM, DCOM, management ports silent and not probed apart (declared population: nine cases)'
$c14Verdicts = @(foreach ($cl in @('Unreachable', 'NotManageable', 'Reachable', 'WinRmUnavailable', 'NotAssessed')) { [string](Get-AdfaDcReachVerdict -HostName 'dc1.contoso.com' -Record ([pscustomobject]@{ Class = $cl; Cause = 'Refused'; Addresses = @('192.0.2.21'); PortText = ''; TimeoutMs = 3000; Error = ''; SocketError = '' }) -Config $c14Reach).Status })
Assert-Equal 'Fail,Warning,Pass,Pass,Not Assessed' ($c14Verdicts -join ',') 'C14 REACH: Unreachable Fail, not manageable Warning, LDAP with WinRM or with RPC Pass, not classified Not Assessed (declared population: five classes)'
$c14Sub = @(
    [string](Get-AdfaSubnetSiteVerdict -Subnets @([pscustomobject]@{ Name = '192.0.2.0/24'; Site = $null }) -ForestName 'contoso.com').Status
    [string](Get-AdfaSubnetSiteVerdict -Subnets @([pscustomobject]@{ Name = '192.0.2.0/24'; Site = 'CN=HQ' }) -ForestName 'contoso.com').Status
    [string](Get-AdfaSubnetSiteVerdict -Subnets @() -ForestName 'contoso.com').Status
    [string](Get-AdfaSubnetSiteVerdict -Subnets @() -ReadError 'STUB: refused' -ForestName 'contoso.com').Status
)
Assert-Equal 'Warning,Pass,Not Assessed,Not Assessed' ($c14Sub -join ',') 'C14 SITE: a subnet with no site Warning, all assigned Pass, none read or a failed read Not Assessed (declared population: four cases)'
$c14Parsed = ConvertFrom-AdfaNetlogonNoClientSite -Text "a NO_CLIENT_SITE: WS01 198.51.100.77`r`nb NO_CLIENT_SITE: WS01 198.51.100.77`r`nc NO_CLIENT_SITE: WS02 not-an-address`r`nd other"
Assert-True ($c14Parsed.Lines -eq 3 -and $c14Parsed.Unparsed -eq 1 -and @($c14Parsed.Entries).Count -eq 1 -and $c14Parsed.Entries[0].Address -eq '198.51.100.77') 'C14 SITE: NO_CLIENT_SITE lines read as name then address, a repeat counted once, a line without an address unparsed'
$c14Raw = [pscustomobject]@{ Ok = $true; Class = 'Read'; Text = 'nothing here'; Error = ''; Path = 'x'; Partial = $false; BytesRead = 12 }
Assert-Equal 'Info' ([string](Get-AdfaNoClientSiteVerdict -HostName 'dc1.contoso.com' -Raw $c14Raw).Status) 'C14 SITE: a log with no NO_CLIENT_SITE line is Info, never Pass'
$c14Denied = Get-AdfaNoClientSiteVerdict -HostName 'dc1.contoso.com' -Raw ([pscustomobject]@{ Ok = $false; Class = 'AccessDenied'; Text = ''; Error = 'x'; Path = 'x'; Partial = $false; BytesRead = 0 })
Assert-True ($c14Denied.Status -eq 'Not Assessed' -and $c14Denied.Detail -match 'access denied' -and $c14Denied.Detail -notmatch 'unreachable') 'C14 SITE: a refused log read says access denied, not unreachable'
$c14S = { param([double[]]$O, [bool]$Q = $true) [pscustomobject]@{ Queried = $Q; Offsets = @($O); Delays = @(0.02); Error = 'x' } }
$c14Time = @(foreach ($pair in @(@(59.9, 0.0), @(60.0, 0.0), @(-200.0, 100.0), @(500.0, 500.0))) { [string](Get-AdfaPdcClockOffsetVerdict -DomainController 'dc2.contoso.com' -ReferencePdc 'dc1.contoso.com' -Sample (& $c14S @($pair[0])) -ReferenceSample (& $c14S @($pair[1]))).Status })
Assert-Equal 'Pass,Warning,Fail,Pass' ($c14Time -join ',') 'C14 TIME: graded on the difference to the forest root PDC: 59.9 s Pass, 60 s Warning, -300 s Fail, both 500 s off Pass (declared population: four pairs)'
Assert-Equal 'Not Assessed' ([string](Get-AdfaPdcClockOffsetVerdict -DomainController 'dc2.contoso.com' -ReferencePdc 'dc1.contoso.com' -Sample (& $c14S @(1.0)) -ReferenceSample (& $c14S @() $false)).Status) 'C14 TIME: an unmeasured reference is Not Assessed, never Pass'
$c14Now = [datetime]::SpecifyKind([datetime]'2026-11-17 12:00:00', [System.DateTimeKind]::Utc)
$c14Acc = { param([string]$N, $L, $C) [pscustomobject]@{ Name = $N; HasLastLogon = ($null -ne $L); LastLogonUtc = $L; WhenCreatedUtc = $C; PwdLastSetRaw = $null } }
$c14StaleRaw = [pscustomobject]@{ Ok = $true; Error = ''; ErrorType = ''; Capped = $false; Records = @((& $c14Acc 'at.cutoff' $c14Now.AddDays(-90) $c14Now.AddDays(-900)), (& $c14Acc 'inside' $c14Now.AddDays(-89) $c14Now.AddDays(-900)), (& $c14Acc 'never.old' $null $c14Now.AddDays(-91)), (& $c14Acc 'never.new' $null $c14Now.AddDays(-10))) }
$c14Int = [pscustomobject]@{ Ok = $true; Present = $false; Value = $null; Error = '' }
$c14StaleRow = Get-AdfaStaleCountVerdict -DomainName 'contoso.com' -Kind 'User' -Raw $c14StaleRaw -Interval $c14Int -StaleDays 90 -Now $c14Now
Assert-True ($c14StaleRow.Status -eq 'Warning' -and $c14StaleRow.Detail -match '^2 enabled user' -and $c14StaleRow.Detail -match '1 of them never logged on' -and $c14StaleRow.Detail -match 'msDS-LogonTimeSyncInterval') 'C14 STALE: at the cutoff counts, a day inside does not, never-logged-on counts once older than the cutoff, and the sync caveat is stated'
$c14Na = @(
    [string](Get-AdfaStaleCountVerdict -DomainName 'contoso.com' -Kind 'User' -Raw ([pscustomobject]@{ Ok = $false; Error = 'Insufficient access rights'; ErrorType = ''; Capped = $false; Records = @() }) -Interval $c14Int -StaleDays 90 -Now $c14Now).Status
    [string](Get-AdfaStaleCountVerdict -DomainName 'contoso.com' -Kind 'User' -Raw ([pscustomobject]@{ Ok = $true; Error = ''; ErrorType = ''; Capped = $true; Records = @() }) -Interval $c14Int -StaleDays 90 -Now $c14Now).Status
    [string](Get-AdfaStaleCountVerdict -DomainName 'contoso.com' -Kind 'User' -Raw $c14StaleRaw -Interval ([pscustomobject]@{ Ok = $true; Present = $true; Value = 0; Error = '' }) -StaleDays 90 -Now $c14Now).Status
    [string](Get-AdfaStaleCountVerdict -DomainName 'contoso.com' -Kind 'User' -Raw $c14StaleRaw -Interval $c14Int -StaleDays 14 -Now $c14Now).Status
)
Assert-Equal 'Not Assessed,Not Assessed,Not Assessed,Not Assessed' ($c14Na -join ',') 'C14 STALE: a failed read, a capped read, updates disabled and a threshold inside the sync window are Not Assessed, never zero (declared population: four cases)'
# Review of C14 before commit: the declared population, the lag of at most the interval, pwdLastSet 0
# with UF_DONT_EXPIRE_PASSWD, and an unclassifiable record.
$c14Pop = { param([bool]$Ok = $true, [int]$N = 50) [pscustomobject]@{ Ok = $Ok; Count = $N; Capped = $false; Error = 'Insufficient access rights'; ErrorType = 'System.UnauthorizedAccessException'; Filter = '(x)' } }
$c14Empty = [pscustomobject]@{ Ok = $true; Error = ''; ErrorType = ''; Capped = $false; Records = @() }
$c14PopStatus = @(
    [string](Get-AdfaStaleCountVerdict -DomainName 'contoso.com' -Kind 'User' -Raw $c14Empty -Interval $c14Int -StaleDays 90 -Now $c14Now -Population (& $c14Pop)).Status
    [string](Get-AdfaStaleCountVerdict -DomainName 'contoso.com' -Kind 'User' -Raw $c14Empty -Interval $c14Int -StaleDays 90 -Now $c14Now).Status
    [string](Get-AdfaStaleCountVerdict -DomainName 'contoso.com' -Kind 'Computer' -Raw $c14Empty -Interval $c14Int -StaleDays 90 -Now $c14Now -Population (& $c14Pop $true 0)).Status
    [string](Get-AdfaPasswordAgeVerdict -DomainName 'contoso.com' -Raw $c14Empty -Now $c14Now -Population (& $c14Pop $false)).Status
)
Assert-Equal 'Pass,Not Assessed,Not Assessed,Not Assessed' ($c14PopStatus -join ',') 'C14 review: an empty stale read passes only against a counted, non-empty population; uncounted, empty or refused is Not Assessed (declared population: four cases)'
Assert-Equal 'Warning' ([string](Get-AdfaStaleCountVerdict -DomainName 'contoso.com' -Kind 'User' -Raw $c14StaleRaw -Interval $c14Int -StaleDays 15 -Now $c14Now -Population (& $c14Pop)).Status) 'C14 review: lastLogonTimestamp trails by at most the interval, so StaleDays 15 against 14 is graded'
$c14Pwd = { param([string]$N, $Raw, $Uac) [pscustomobject]@{ Name = $N; HasLastLogon = $false; LastLogonUtc = $null; WhenCreatedUtc = $null; PwdLastSetRaw = $Raw; UserAccountControl = $Uac } }
$c14PwdStatus = @(foreach ($uac in @(512, 66048, $null)) { [string](Get-AdfaPasswordAgeVerdict -DomainName 'contoso.com' -Raw ([pscustomobject]@{ Ok = $true; Error = ''; ErrorType = ''; Capped = $false; Records = @((& $c14Pwd 'zero' ([int64]0) $uac)) }) -Now $c14Now -Population (& $c14Pop)).Status })
Assert-Equal 'Pass,Not Assessed,Not Assessed' ($c14PwdStatus -join ',') 'C14 review: pwdLastSet 0 is must-change only with UF_DONT_EXPIRE_PASSWD clear; set, or userAccountControl unread, never passes (declared population: three flags)'
Assert-Equal 'Not Assessed' ([string](Get-AdfaPasswordAgeVerdict -DomainName 'contoso.com' -Raw ([pscustomobject]@{ Ok = $true; Error = ''; ErrorType = ''; Capped = $false; Records = @((& $c14Pwd 'none' $null 512)) }) -Now $c14Now -Population (& $c14Pop)).Status) 'C14 review: a record with no pwdLastSet is Not Assessed, never skipped'
Assert-Equal 'Not Assessed' ([string](Get-AdfaStaleCountVerdict -DomainName 'contoso.com' -Kind 'User' -Raw ([pscustomobject]@{ Ok = $true; Error = ''; ErrorType = ''; Capped = $false; Records = @([pscustomobject]@{ Name = 'odd'; HasLastLogon = $true; LastLogonUtc = 'x'; WhenCreatedUtc = $null; PwdLastSetRaw = $null }) }) -Interval $c14Int -StaleDays 90 -Now $c14Now -Population (& $c14Pop)).Status) 'C14 review: a returned account with an unreadable lastLogonTimestamp is Not Assessed, never skipped'
$c14UnreachRow = Get-AdfaDcReachVerdict -HostName 'dc1.contoso.com' -Record ([pscustomobject]@{ Class = 'Unreachable'; Cause = 'Unresolved'; Addresses = @(); PortText = ''; TimeoutMs = 3000; Error = ''; SocketError = 'HostNotFound' }) -Config $c14Reach
Assert-True ($c14UnreachRow.Detail -notmatch '(?i)every check' -and $c14UnreachRow.Detail -match 'The sections that connect to this domain controller reuse this result' -and $c14UnreachRow.Detail -match 'Rows read from the directory about it .* are still graded') 'C14 review (reworded by C14c): the Unreachable row says the sections that connect to the DC reuse it, and that the directory rows are still graded'
Assert-Equal 'DFSR,FRS,Transitional,Unknown,Unknown' ((@(@('Present', 'Absent'), @('Absent', 'Present'), @('Present', 'Present'), @('Absent', 'Absent'), @('Present', 'Unread')) | ForEach-Object { Resolve-AdfaSysvolEngineDc -Dfsr $_[0] -Frs $_[1] }) -join ',') 'C14 SYSVOL: the engine of a DC from its two objects (declared population: five pairs)'
$c14Dc = { param([string]$H, [string]$D, [string]$F, $Ro = $false) [pscustomobject]@{ HostName = $H; IsReadOnly = $Ro; ComputerDn = 'CN=X'; Dfsr = $D; DfsrError = 'x'; Frs = $F; FrsError = 'x' } }
$c14Eng = { param($Dcs) @(Get-AdfaSysvolEngineVerdict -DomainName 'contoso.com' -Raw ([pscustomobject]@{ Ok = $true; Error = ''; ErrorType = ''; DomainDn = 'DC=contoso,DC=com'; GlobalState = 'Present'; GlobalFlags = 48; GlobalError = ''; Dcs = @($Dcs) }) | Where-Object { $_.Item -eq 'SYSVOL replication engine: contoso.com' })[0].Status }
$c14EngStatus = @(
    [string](& $c14Eng @((& $c14Dc 'dc1' 'Present' 'Absent'), (& $c14Dc 'dc2' 'Present' 'Absent')))
    [string](& $c14Eng @((& $c14Dc 'dc1' 'Present' 'Absent'), (& $c14Dc 'dc2' 'Absent' 'Present')))
    [string](& $c14Eng @((& $c14Dc 'dc1' 'Present' 'Absent'), (& $c14Dc 'dc2' 'Present' 'Unread')))
    [string](& $c14Eng @((& $c14Dc 'rodc1' 'Absent' 'Present' $true)))
)
Assert-Equal 'Pass,Warning,Not Assessed,Not Assessed' ($c14EngStatus -join ',') 'C14 SYSVOL: every writable DC on DFSR Pass, one on FRS Warning, one unread Not Assessed, no writable DC Not Assessed (declared population: four domains)'
Assert-Throws { Merge-AdfaSpecConfig -BaseConfig $script:Config.ClockSkew -Override @{ KerberosMaxSeconds = 600 } } "unknown key 'KerberosMaxSeconds'" 'C14 override: the Kerberos maximum can never be set from a file'
Assert-Throws { Merge-AdfaSpecConfig -BaseConfig $script:Config.Reach -Override @{ ProbeTimeoutMs = 99 } } '100 to 60000' 'C14 override: a probe time-out below its range is refused'
Assert-Throws { Merge-AdfaSpecConfig -BaseConfig $script:Config.SysvolEngine -Override @{ FrsStatus = 'Pass' } } 'Warning, Fail' 'C14 override: a status outside its set is refused'
Assert-Throws { Merge-AdfaSpecConfig -BaseConfig $script:Config.Stale -Override @{ } } 'empty object' 'C14 override: an empty object is refused'
$c14Merged = Merge-AdfaSpecConfig -BaseConfig $script:Config.Stale -Override @{ PasswordAgeDays = 180 } -OverrideSource 'C:\cfg\c14.json'
Assert-True ($c14Merged['PasswordAgeDays'] -eq 180 -and $script:Config.Stale['PasswordAgeDays'] -eq 365 -and [string]$c14Merged['ThresholdSource'] -match 'c14\.json') 'C14 override: a valid value merges, cites the file, and leaves the built-in table unchanged'
$c14Hostile = 'replication stale delegation does not resolve port not reachable time sync clock skew w32tm sysvol dfsr inactive'
$c14Advice = @(
    Get-AdfaRecommendation -Section 'Port Reachability' -Item 'DC reachability: dc2.contoso.com' -Detail $c14Hostile
    Get-AdfaRecommendation -Section 'Site Health' -Item 'Clients without a site: dc1.contoso.com' -Detail $c14Hostile
    Get-AdfaRecommendation -Section 'Time Hierarchy' -Item 'Clock offset vs forest root PDC: dc2.contoso.com' -Detail $c14Hostile
    Get-AdfaRecommendation -Section 'Stale Objects' -Item 'Inactive enabled users' -Detail $c14Hostile
    Get-AdfaRecommendation -Section 'SYSVOL / DFSR' -Item 'SYSVOL replication engine: contoso.com' -Detail $c14Hostile
)
Assert-True ($c14Advice[0] -match 'metadata cleanup' -and $c14Advice[1] -match 'subnet object' -and $c14Advice[2] -match 'forest root PDC emulator' -and $c14Advice[3] -match 'lastLogonTimestamp' -and $c14Advice[4] -match 'dfsrmig') 'C14 advice: each family gets its own advice whatever the Detail says (declared population: five families)'
Write-Host "== C15: inventory depth - topology, trusts, suffixes, object counts, stale disabled objects, groups, GPOs, events, w32tm configuration ==" -ForegroundColor Cyan
Assert-Equal '1.43.0' ([string]$script:Config.Version) 'C15: version 1.43.0 in the script (bumped by PORT-PLAN C15c)'
$c15Cfg = $script:Config.Inventory
$c15Dc = 'dc1.contoso.com'
$c15Read = { param($Records = @(), [bool]$Ok = $true, [string]$E = '', [string]$T = '', [bool]$Cap = $false) [pscustomobject]@{ Ok = $Ok; Error = $E; ErrorType = $T; NotFound = $false; Records = @($Records); Count = @($Records).Count; Capped = $Cap; Filter = '(x)'; Identity = '' } }
$c15Levels = @(foreach ($v in @(7, 10, 8, 'x')) { $lr = Get-AdfaLevelRow -Kind 'Forest' -Scope 'contoso.com' -Raw (& $c15Read @([pscustomobject]@{ 'msDS-Behavior-Version' = $v })) -Config $c15Cfg; "{0}/{1}" -f $lr.Status, $lr.LevelName })
Assert-Equal 'Info/DS_BEHAVIOR_WIN2016,Info/DS_BEHAVIOR_WIN2025,Not Assessed/,Not Assessed/' ($c15Levels -join ',') 'C15 INV-001: levels 7 and 10 named, 8 and text Not Assessed (declared population: four values)'
Assert-Equal 'Not Assessed' ([string](Get-AdfaLevelRow -Kind 'Domain' -Scope 'contoso.com' -Raw (& $c15Read @([pscustomobject]@{ Name = 'x' })) -Config $c15Cfg).Status) 'C15 INV-001: an msDS-Behavior-Version not returned is not level 0'
$c15Fsmo = @(foreach ($v in @('CN=NTDS Settings,CN=DC1,CN=Servers,CN=HQ,CN=Sites,CN=Configuration,DC=contoso,DC=com', 'CN=NTDS Settings\0ADEL:1,CN=DC9,CN=Servers', 'CN=DC1,OU=Domain Controllers,DC=contoso,DC=com')) { $h = Get-AdfaFsmoHolderName -Value $v; "{0}/{1}" -f $h.Valid, $h.Server })
Assert-Equal 'True/DC1,False/,False/' ($c15Fsmo -join ',') 'C15 INV-001: the FSMO holder from an NTDS Settings DN; a deleted or malformed value is not a holder (declared population: three values)'
$c15Upn = @(
    [string](Get-AdfaUpnSuffixRow -ForestName 'contoso.com' -Raw (& $c15Read @([pscustomobject]@{ uPNSuffixes = @('contoso.net') })) -Config $c15Cfg).Count
    [string](Get-AdfaUpnSuffixRow -ForestName 'contoso.com' -Raw (& $c15Read @([pscustomobject]@{ Name = 'Partitions' })) -Config $c15Cfg).Count
    [string](Get-AdfaUpnSuffixRow -ForestName 'contoso.com' -Raw (& $c15Read @() $false 'Access is denied') -Config $c15Cfg).Count
)
Assert-Equal '1,0,' ($c15Upn -join ',') 'C15 INV-007: one suffix, an absent attribute 0, a failed read no count (declared population: three reads)'
$c15Dns = @(Get-AdfaDnsSuffixRows -DomainControllers @([pscustomobject]@{ HostName = 'dc1.contoso.com'; Scope = 'contoso.com' }, [pscustomobject]@{ HostName = 'dc4.corp.fabrikam.com'; Scope = 'contoso.com' }) -ScopedDomains @('contoso.com', 'north.contoso.com') -Config $c15Cfg)
Assert-Equal 'No,Yes,Unknown' ((@($c15Dns | Where-Object { $_.Item -like 'DNS suffix: *' }) + @($c15Dns | Where-Object { $_.Item -like 'DNS suffix (population)*' }) | ForEach-Object { $_.Disjoint }) -join ',') 'C15 INV-007: a matching DC, a disjoint DC, and a population row for the domain with no DC (declared population: three rows)'
$c15Dec = @(foreach ($v in @(0x24, '-2147483640', $null, 'forest')) { $d = Get-AdfaTrustAttributeDecode -Value $v -Config $c15Cfg; "{0}:{1}" -f $d.Measured, (@(@($d.Flags) + @($d.Unknown)) -join '+') })
Assert-Equal 'True:QUARANTINED_DOMAIN+WITHIN_FOREST,True:FOREST_TRANSITIVE+unknown 0x80000000,False:,False:' ($c15Dec -join ',') 'C15 INV-006: trustAttributes decoded by name, the high bit unsigned and kept, a missing or text value not measured (declared population: four values)'
$c15Trust = @(Get-AdfaTrustInventoryRows -DomainName 'contoso.com' -Raw (& $c15Read @([pscustomobject]@{ trustPartner = 'fabrikam.com'; trustAttributes = 0x205; trustDirection = 2; trustType = 1 })) -Config $c15Cfg)
$c15T = @($c15Trust | Where-Object { $_.Item -eq 'Trust: contoso.com -> fabrikam.com' })[0]
Assert-True ($c15T.Status -eq 'Info' -and $c15T.Transitive -eq 'No (NON_TRANSITIVE set)' -and $c15T.TgtDelegation -match '^Disabled' -and $c15T.TrustDirection -eq '2 Outbound' -and $c15T.TrustType -eq '1 DOWNLEVEL') 'C15 INV-006: a trust row carries transitivity, TGT delegation, direction and type by name'
$c15TrustFail = @(Get-AdfaTrustInventoryRows -DomainName 'contoso.com' -Raw (& $c15Read @() $false 'Unable to contact the server.') -Config $c15Cfg)
Assert-True ($c15TrustFail.Count -eq 1 -and $c15TrustFail[0].Status -eq 'Not Assessed' -and [string]$c15TrustFail[0].Count -eq '' -and $c15TrustFail[0].Detail -match 'unreachable') 'C15 INV-006: a failed trust read is Not Assessed, never 0 trusts'
$c15Reads = @{ Users = (& $c15Read @([pscustomobject]@{ userAccountControl = 512 }, [pscustomobject]@{ userAccountControl = 514 })); Computers = (& $c15Read @() $false 'Access is denied' 'System.UnauthorizedAccessException'); Groups = (& $c15Read @() $true '' '' $true); Contacts = (& $c15Read @()); OUs = (& $c15Read @([pscustomobject]@{ Name = 'o' })); gMSA = (& $c15Read @()); sMSA = $null }
$c15Counts = @(Get-AdfaObjectCountRows -DomainName 'contoso.com' -Reads $c15Reads -Config $c15Cfg)
Assert-Equal 13 $c15Counts.Count 'C15 INV-008: thirteen count rows per domain (declared population)'
Assert-Equal '2,1,1,,,,,0,1,' ((@('Users', 'Enabled users', 'Disabled users', 'Computers', 'Disabled computers', 'Groups', 'Security groups', 'Contacts', 'OUs', 'sMSA') | ForEach-Object { $k = $_; [string](@($c15Counts | Where-Object { $_.Item -eq ("Object count: {0} contoso.com" -f $k) })[0].Count) }) -join ',') 'C15 INV-008: counts read, a refused, capped or unread read never 0 (declared population: ten kinds)'
$c15Groups = @(Get-AdfaGroupInventoryRows -DomainName 'contoso.com' -Raw (& $c15Read @([pscustomobject]@{ sAMAccountName = 'Empty1'; groupType = -2147483646; memberCount = 0 }, [pscustomobject]@{ sAMAccountName = 'Big'; groupType = 8; memberCount = 1500 })) -Config $c15Cfg)
$c15Empty = @($c15Groups | Where-Object { $_.Item -eq 'Empty groups: contoso.com' })[0]
$c15Member = @($c15Groups | Where-Object { $_.Item -eq 'Group member counts: contoso.com' })[0]
Assert-True ($c15Empty.Groups -eq 'Empty1' -and $c15Empty.Detail -notmatch 'Empty1' -and [string]$c15Member.NotCountedExactly -eq '1') 'C15 INV-010: an empty group named in its column only; 1500 member values not counted exactly'
$c15Now = [datetime]::SpecifyKind([datetime]'2026-11-17 12:00:00', [System.DateTimeKind]::Utc)
$c15Acc = { param([string]$N, $L, $C) [pscustomobject]@{ Name = $N; HasLastLogon = ($null -ne $L); LastLogonUtc = $L; WhenCreatedUtc = $C; PwdLastSetRaw = $null } }
$c15Int = [pscustomobject]@{ Ok = $true; Present = $false; Value = $null; Error = '' }
$c15Pop = { param([bool]$Ok = $true, [int]$N = 5) [pscustomobject]@{ Ok = $Ok; Count = $N; Capped = $false; Error = 'Insufficient access rights'; ErrorType = ''; Filter = '(x)' } }
$c15StaleRaw = [pscustomobject]@{ Ok = $true; Error = ''; ErrorType = ''; Capped = $false; Records = @((& $c15Acc 'at.cutoff' $c15Now.AddDays(-90) $null), (& $c15Acc 'inside' $c15Now.AddDays(-89) $null)) }
$c15EmptyRaw = [pscustomobject]@{ Ok = $true; Error = ''; ErrorType = ''; Capped = $false; Records = @() }
$c15Dis = @(
    (Get-AdfaStaleDisabledVerdict -DomainName 'contoso.com' -Kind 'User' -Raw $c15StaleRaw -Interval $c15Int -StaleDays 90 -Now $c15Now -Population (& $c15Pop))
    (Get-AdfaStaleDisabledVerdict -DomainName 'contoso.com' -Kind 'User' -Raw $c15EmptyRaw -Interval $c15Int -StaleDays 90 -Now $c15Now -Population (& $c15Pop))
    (Get-AdfaStaleDisabledVerdict -DomainName 'contoso.com' -Kind 'User' -Raw $c15EmptyRaw -Interval $c15Int -StaleDays 90 -Now $c15Now -Population (& $c15Pop $false))
    (Get-AdfaStaleDisabledVerdict -DomainName 'contoso.com' -Kind 'Computer' -Raw ([pscustomobject]@{ Ok = $false; Error = 'Insufficient access rights'; ErrorType = ''; Capped = $false; Records = @() }) -Interval $c15Int -StaleDays 90 -Now $c15Now -Population (& $c15Pop))
)
Assert-Equal 'Info/1,Info/0,Not Assessed/,Not Assessed/' ((@($c15Dis | ForEach-Object { "{0}/{1}" -f $_.Status, $_.Count })) -join ',') 'C15 INV-009: stale disabled counted at the cutoff only; none found Info 0 against a counted population, Not Assessed against an uncounted one or a failed read (declared population: four cases)'
$c15Links = @(ConvertFrom-AdfaGpLink -Value '[LDAP://cn={31B2F340-016D-11D2-945F-00C04FB984F9},cn=policies,cn=system,DC=contoso,DC=com;2][cn={6AC1786C-016F-11D2-945F-00C04FB984F9},cn=policies,cn=system,DC=contoso,DC=com;1][junk]' -Config $c15Cfg)
Assert-Equal 'True/False/True,True/True/False,False/False/False' (@($c15Links | ForEach-Object { "{0}/{1}/{2}" -f $_.Parsed, $_.Disabled, $_.Enforced }) -join ',') 'C15 INV-011: gPLink parsed with options 0x1 disabled and 0x2 enforced, an unparsed entry kept (declared population: three entries)'
$c15Gpo = @(Get-AdfaGpoDirectoryRows -DomainName 'contoso.com' -Gpc (& $c15Read @([pscustomobject]@{ Name = '{31B2F340-016D-11D2-945F-00C04FB984F9}'; displayName = 'Default Domain Policy'; flags = 0 })) -Som (& $c15Read @() $false 'Access is denied' 'System.UnauthorizedAccessException') -Site (& $c15Read @()) -Wmi (& $c15Read @()) -Config $c15Cfg -GpoConfig $script:Config.Gpo)
$c15GpoSum = @($c15Gpo | Where-Object { $_.Item -eq 'GPO directory inventory: contoso.com' })[0]
Assert-True ($c15GpoSum.Status -eq 'Not Assessed' -and [string]$c15GpoSum.Unlinked -eq '' -and [string](@($c15Gpo | Where-Object { $_.Item -like 'GPO: *' })[0].Links) -eq '') 'C15 INV-011: links not read - no GPO is called unlinked and no link count is 0'
$c15Ev = { param([int]$Id, [int]$L) [pscustomobject]@{ Id = $Id; Level = $L; ProviderName = 'p'; TimeCreated = $c15Now } }
$c15EvRaw = { param($E = @(), [bool]$Ok = $true, [bool]$None = $false, [bool]$Absent = $false, [string]$Err = '', [string]$Code = '') [pscustomobject]@{ Ok = $Ok; NoEvents = $None; LogAbsent = $Absent; Events = @($E); Truncated = $false; Error = $Err; ErrorId = ''; ErrorCode = $Code } }
$c15Cov = { param([string]$C) [pscustomobject]@{ Coverage = $C; OldestRecord = $c15Now; RecordCount = 5; Reason = '' } }
$c15EvRows = @(
    @(Get-AdfaEventInventoryRows -ComputerName $c15Dc -LogName 'System' -Raw (& $c15EvRaw @((& $c15Ev 7 2), (& $c15Ev 41 1))) -Coverage (& $c15Cov 'Covered') -Config $c15Cfg)[0]
    @(Get-AdfaEventInventoryRows -ComputerName $c15Dc -LogName 'System' -Raw (& $c15EvRaw @() $true $true) -Coverage (& $c15Cov 'Covered') -Config $c15Cfg)[0]
    @(Get-AdfaEventInventoryRows -ComputerName $c15Dc -LogName 'System' -Raw (& $c15EvRaw @() $true $true) -Coverage (& $c15Cov 'Truncated') -Config $c15Cfg)[0]
    @(Get-AdfaEventInventoryRows -ComputerName $c15Dc -LogName 'DNS Server' -Raw (& $c15EvRaw @() $false $false $true) -Coverage $null -Config $c15Cfg)[0]
    @(Get-AdfaEventInventoryRows -ComputerName $c15Dc -LogName 'System' -Raw (& $c15EvRaw @() $false $false $false 'denied' 'AccessDenied') -Coverage $null -Config $c15Cfg)[0]
)
Assert-Equal 'Info/2,Info/0,Not Assessed/,Info/,Not Assessed/' (@($c15EvRows | ForEach-Object { "{0}/{1}" -f $_.Status, $_.Events }) -join ',') 'C15 INV-012: events counted, none over a covered log 0, none over a short log not a measurement, a log absent Info, a refusal Not Assessed (declared population: five reads)'
$c15Groups2 = @(Get-AdfaEventInventoryRows -ComputerName $c15Dc -LogName 'System' -Raw (& $c15EvRaw @((& $c15Ev 7 2), (& $c15Ev 41 1))) -Coverage (& $c15Cov 'Covered') -Config $c15Cfg | Where-Object { $_.Item -like 'Event group: *' })
Assert-Equal 'Event group: System 41 on dc1.contoso.com' ([string]$c15Groups2[0].Item) 'C15 INV-012: the Critical group is listed first'
$c15Reg = { param([string]$Id, $Rv, $V) [pscustomobject]@{ Id = $Id; Key = 'k'; ValueName = $Id; Answered = $true; ReturnValue = $Rv; Value = $V; Method = 'm'; Error = ''; ErrorCode = '' } }
$c15TimeRead = { param($Values, [bool]$Ok = $true, [bool]$Denied = $false) [pscustomobject]@{ Raw = [pscustomobject]@{ Ok = $Ok; Protocol = 'Wsman'; Error = 'x'; ErrorCode = ''; Values = @($Values) }; Denied = $Denied; Attempts = @() } }
$c15Time = @(
    (Get-AdfaW32TimeConfigRow -ComputerName $c15Dc -Read (& $c15TimeRead @((& $c15Reg 'Type' 0 'NT5DS'), (& $c15Reg 'NtpServer' 1 ''), (& $c15Reg 'AnnounceFlags' 0 10))) -Config $c15Cfg)
    (Get-AdfaW32TimeConfigRow -ComputerName $c15Dc -Read (& $c15TimeRead @() $false $true) -Config $c15Cfg)
    (Get-AdfaW32TimeConfigRow -ComputerName $c15Dc -Read $null -Unreachable 'Unreachable: no port answered.' -Config $c15Cfg)
    (Get-AdfaW32TimeConfigRow -ComputerName $c15Dc -Read (& $c15TimeRead @((& $c15Reg 'Type' 2147749893 $null), (& $c15Reg 'NtpServer' 1 ''), (& $c15Reg 'AnnounceFlags' 0 10))) -Config $c15Cfg)
)
Assert-Equal 'Info/(not set),Not Assessed/,Not Assessed/,Not Assessed/(not set)' (@($c15Time | ForEach-Object { "{0}/{1}" -f $_.Status, $_.NtpServer }) -join ',') 'C15 INV-015: values read Info (NtpServer not set is the documented default); access denied, unreachable and a value of another type Not Assessed, the values that were read kept in their columns (declared population: four reads)'
Assert-True ($c15Time[1].Detail -match 'Access denied' -and $c15Time[2].Detail -match 'Unreachable' -and $c15Time[1].Detail -notmatch 'Unreachable') 'C15 INV-015: access denied and unreachable are worded apart'
Assert-Throws { Merge-AdfaSpecConfig -BaseConfig $c15Cfg -Override @{ EventLogs = @('Security') } } "unknown key 'EventLogs'" 'C15 override: the logs can never be set from a file'
Assert-Throws { Merge-AdfaSpecConfig -BaseConfig $c15Cfg -Override @{ EventMaxEvents = 0 } } '1 to 100000' 'C15 override: zero events per log is refused'
Assert-Throws { Merge-AdfaSpecConfig -BaseConfig $c15Cfg -Override @{ MaxObjects = '5' } } 'JSON number' 'C15 override: a number written as text is refused'
$c15Merged = Merge-AdfaSpecConfig -BaseConfig $c15Cfg -Override @{ EventGroupCap = 10 } -OverrideSource 'C:\cfg\c15.json'
Assert-True ($c15Merged['EventGroupCap'] -eq 10 -and $script:Config.Inventory['EventGroupCap'] -eq 50 -and [string]$c15Merged['ThresholdSource'] -match 'c15\.json') 'C15 override: a valid value merges, cites the file, and leaves the built-in table unchanged'
# C15 review (found by an independent review before commit).
$c15Quar = @(Get-AdfaTrustInventoryRows -DomainName 'contoso.com' -Raw (& $c15Read @([pscustomobject]@{ trustPartner = 'q.fabrikam.com'; trustAttributes = 0x24; trustDirection = 3; trustType = 2 })) -Config $c15Cfg | Where-Object { $_.Item -eq 'Trust: contoso.com -> q.fabrikam.com' })[0]
Assert-Equal 'Disabled by trustAttributes (QUARANTINED_DOMAIN)' ([string]$c15Quar.TgtDelegation) 'C15 review INV-006: QUARANTINED_DOMAIN alone disables TGT delegation (MS-KILE 3.3.5.7.5)'
Assert-Equal 'No' ([string]@(Get-AdfaDnsSuffixRows -DomainControllers @([pscustomobject]@{ HostName = 'DC1.Contoso.com'; Scope = 'contoso.com' }) -ScopedDomains @('contoso.com') -Config $c15Cfg | Where-Object { $_.Item -like 'DNS suffix: *' })[0].Disjoint) 'C15 review INV-007: the DNS suffix is compared without regard to case'
$c15BadLinks = @(ConvertFrom-AdfaGpLink -Value ('[LDAP://cn={{AAAAAAAA-0000-0000-0000-000000000001}},cn=policies,cn=system,DC=fabrikam,DC=local;99999999999999999999][LDAP://cn={{AAAAAAAA-0000-0000-0000-000000000001}},cn=policies,cn=system,DC=fabrikam,DC=local;{0}][LDAP://cn={{AAAAAAAA-0000-0000-0000-000000000001}},cn=policies,cn=system;0]' -f [string][char]0x0663) -Config $c15Cfg)
Assert-Equal 'False,False,False' (@($c15BadLinks | ForEach-Object { [string]$_.Parsed }) -join ',') 'C15 review INV-011: options beyond Int64, a non-ASCII digit and a DN with no domain are kept unparsed, never thrown (declared population: three entries)'
$c15GpcX = & $c15Read @([pscustomobject]@{ Name = '{AAAAAAAA-0000-4000-8000-000000000001}'; displayName = 'Branch Policy'; flags = 0 })
$c15NorthSom = & $c15Read @([pscustomobject]@{ DistinguishedName = 'OU=Branch,DC=north,DC=contoso,DC=com'; objectClass = @('top', 'organizationalUnit'); gPLink = '[LDAP://cn={AAAAAAAA-0000-4000-8000-000000000001},cn=policies,cn=system,DC=contoso,DC=com;1]' })
$c15Cross = @(
    @(Get-AdfaGpoDirectoryRows -DomainName 'contoso.com' -Gpc $c15GpcX -Som (& $c15Read @()) -Site (& $c15Read @()) -Wmi (& $c15Read @()) -ForestDomains @('contoso.com', 'north.contoso.com') -Config $c15Cfg -GpoConfig $script:Config.Gpo | Where-Object { $_.Item -eq 'GPO directory inventory: contoso.com' })[0]
    @(Get-AdfaGpoDirectoryRows -DomainName 'contoso.com' -Gpc $c15GpcX -Som (& $c15Read @()) -Site (& $c15Read @()) -Wmi (& $c15Read @()) -ForestDomains @('contoso.com', 'north.contoso.com') -OtherSom @([pscustomobject]@{ Domain = 'north.contoso.com'; Raw = $c15NorthSom }) -Config $c15Cfg -GpoConfig $script:Config.Gpo | Where-Object { $_.Item -eq 'GPO directory inventory: contoso.com' })[0]
    @(Get-AdfaGpoDirectoryRows -DomainName 'contoso.com' -Gpc $c15GpcX -Som (& $c15Read @()) -Site (& $c15Read @() $false 'Access is denied' 'System.UnauthorizedAccessException') -Wmi (& $c15Read @()) -ForestDomains @('contoso.com') -Config $c15Cfg -GpoConfig $script:Config.Gpo | Where-Object { $_.Item -eq 'GPO directory inventory: contoso.com' })[0]
)
Assert-Equal 'Not Assessed//1,Info/0/0,Not Assessed//' (@($c15Cross | ForEach-Object { "{0}/{1}/{2}" -f $_.Status, $_.Unlinked, $_.NoLinkFound }) -join ',') 'C15 review INV-011: no link found with another forest domain unread is not "unlinked"; a link from that domain''s OU, once read, counts; a failed site read leaves links unknown (declared population: three cases)'
$c15GroupCap = @(ConvertTo-AdfaGroupExportRow -DomainName 'contoso.com' -Raw (& $c15Read @([pscustomobject]@{ sAMAccountName = 'G1'; groupType = 2 }, [pscustomobject]@{ sAMAccountName = 'G2'; groupType = 2 }) $true '' '' $true) -Config (Merge-AdfaSpecConfig -BaseConfig $c15Cfg -Override @{ MaxObjects = 1 }))
Assert-True ($c15GroupCap.Count -eq 1 -and [string]$c15GroupCap[0].ListComplete -match '^No') 'C15 review INV-010: a capped group read gives MaxObjects CSV rows, each marked incomplete'
$c15Partial = @(Get-AdfaEventInventoryRows -ComputerName $c15Dc -LogName 'System' -Raw ([pscustomobject]@{ Ok = $true; NoEvents = $false; LogAbsent = $false; Events = @((& $c15Ev 7 2), (& $c15Ev 7 2)); Truncated = $true; Error = ''; ErrorId = ''; ErrorCode = '' }) -Coverage (& $c15Cov 'Covered') -Config $c15Cfg | Where-Object { $_.Item -like 'Event group: *' })
Assert-True ($c15Partial.Count -eq 1 -and $c15Partial[0].Count -eq 'at least 2' -and $c15Partial[0].PartialRead -eq 'Yes') 'C15 review INV-012: a group from a read cut at MaxEvents says its count is a floor'
Assert-Equal '(not set)' ([string](Get-AdfaW32TimeConfigRow -ComputerName $c15Dc -Read (& $c15TimeRead @((& $c15Reg 'Type' 0 'NT5DS'), (& $c15Reg 'NtpServer' 1 ''), (& $c15Reg 'AnnounceFlags' 2 $null))) -Config $c15Cfg).AnnounceFlags) 'C15 review INV-015: a value whose key is absent (StdRegProv 2) is not set'
$c15AllRows = @($c15Trust) + @($c15Counts) + @($c15Groups) + @($c15Dis) + @($c15Gpo) + @($c15EvRows) + @($c15Time) + @($c15Cross)
Assert-Equal 0 @($c15AllRows | Where-Object { $null -ne $_ -and $null -ne $_.PSObject.Properties['Status'] -and @('Info', 'Not Assessed') -notcontains [string]$_.Status }).Count 'C15: no inventory row is Pass, Warning or Fail'
# --- PORT-PLAN C2e, C1b, C14c, C3g: the probe gate, the population rows, the refused CIM ports.
$c2eDead = 'dc9.contoso.com'
$c2eLive = 'dc1.contoso.com'
Assert-Equal 'Unreachable, classified once for this run by the reachability probe: x, so nothing was read.' (Get-AdfaDcGateText -Cause 'Unreachable, classified once for this run by the reachability probe: x.' -NotRead 'nothing was read.') 'C14c: the gate text is the class, then what was not read'
$c2eGate = & {
    $script:C2eValProbes = @()
    function Test-TcpPort { param([string]$ComputerName, [int]$Port, [int]$TimeoutMs) $script:C2eValProbes += ('{0}:{1}' -f $ComputerName, $Port); return $true }
    function Resolve-AdfaHostAddress { param([string]$HostName, [int]$TimeoutMs) [pscustomobject]@{ Ok = $false; Addresses = @(); SocketError = 'HostNotFound'; TimedOut = $false; Error = 'No such host is known.' } }
    Clear-AdfaDcPortCache
    Get-AdfaDcReachability -HostName $c2eDead | Out-Null
    $dead = Get-AdfaDcProbeGate -ComputerName $c2eDead -Ports @(135, 445, 5985) -TimeoutMs 100
    $live = Get-AdfaDcProbeGate -ComputerName $c2eLive -Ports @(135, 445) -TimeoutMs 100
    $again = Get-AdfaDcProbeGate -ComputerName $c2eLive -Ports @(445) -TimeoutMs 100
    Clear-AdfaDcPortCache
    [pscustomobject]@{ Dead = $dead; Live = $live; Again = $again; Probes = @($script:C2eValProbes) }
}
Assert-True ([string]$c2eGate.Dead.Cause -match '^Unreachable, classified once for this run by the reachability probe: the host name does not resolve') 'C14c gate: a DC classified Unreachable returns the class as the cause'
Assert-Equal 0 @($c2eGate.Dead.Open.Values | Where-Object { $_ }).Count 'C14c gate: every port of an unreachable DC is closed (declared population: 135, 445, 5985)'
Assert-Equal '' ([string]$c2eGate.Live.Cause) 'C1b gate: a DC not classified has no cause'
Assert-True ([bool]$c2eGate.Live.Open[135] -and [bool]$c2eGate.Live.Open[445] -and [bool]$c2eGate.Again.Open[445]) 'C1b gate: a DC not classified is probed and answers'
Assert-Equal 'dc1.contoso.com:135,dc1.contoso.com:445' (@($c2eGate.Probes) -join ',') 'C1b/C14c gate: the unreachable DC is probed on no port, the other once per port in the run'
$c2eTargets = @([pscustomobject]@{ HostName = $c2eLive; Scope = 'contoso.com' })
$c2ePop = @(Get-AdfaDcPopulationRow -Targets $c2eTargets -InventoryFailures @([pscustomobject]@{ Domain = 'fabrikam.com'; Error = 'Access is denied.' }) -ScopedDomains @('contoso.com', 'fabrikam.com', 'north.contoso.com') -Area 'Backup' -Label 'Directory backup' -NothingRead 'Nothing was read.')
Assert-Equal 'Directory backup (population): fabrikam.com|Not Assessed,Directory backup (population): north.contoso.com|Not Assessed' (@($c2ePop | ForEach-Object { "{0}|{1}" -f $_.Item, $_.Status }) -join ',') 'C2e: a population row for each scoped domain no target carries (declared population: fabrikam.com, north.contoso.com), none for contoso.com'
Assert-True ([string]$c2ePop[0].Detail -match 'could not be enumerated\. Cause: Access is denied\.' -and [string]$c2ePop[1].Detail -match 'returned no domain controller') 'C2e: the failed enumeration and the empty one are told apart'
$c2eRep = @(Get-AdfaDcPopulationRow -Targets @() -ScopedDomains @('contoso.com') -Area 'Replication' -Label 'Replication health' -NothingRead 'Nothing.' -Shape 'DomainController')
Assert-True ($c2eRep.Count -eq 1 -and [string]$c2eRep[0].DomainController -eq 'Replication health (population): contoso.com' -and [string]$c2eRep[0].Scope -eq 'contoso.com' -and $null -ne $c2eRep[0].PSObject.Properties['PartnerCount']) 'C2e: the replication population row has the replication row shape'
Assert-Equal 0 @(Get-AdfaDcPopulationRow -Targets $c2eTargets -ScopedDomains @('contoso.com') -Area 'Backup' -Label 'Directory backup' -NothingRead 'x').Count 'C2e: a domain a target carries needs no population row'
foreach ($c3gKey in @('WsmanPort', 'RpcPort')) {
    Assert-Throws { Merge-AdfaDcDiskConfig -BaseConfig $script:Config.DcDisk -Override @{ $c3gKey = 5985 } } ("names '{0}'. The ports of this section cannot be set from a file" -f $c3gKey) ("C3g: DcDisk refuses {0}, whatever it holds" -f $c3gKey)
    Assert-Throws { Merge-AdfaDcSystemConfig -BaseConfig $script:Config.DcSystem -Override @{ $c3gKey = 135 } } ("names '{0}'. The ports of this section cannot be set from a file" -f $c3gKey) ("C3g: DcSystem refuses {0}, whatever it holds" -f $c3gKey)
}
Assert-Equal 25 ([double](Merge-AdfaDcDiskConfig -BaseConfig $script:Config.DcDisk -Override @{ WarnBelowPercent = 25 }).WarnBelowPercent) 'C3g: DcDisk still takes its thresholds'
# --- Found by the independent review of the diff before commit (C2e, C14c).
$c2eSet = @(Get-AdfaDcHostSet -Targets @([pscustomobject]@{ HostName = $c2eLive; Scope = 'contoso.com' }, [pscustomobject]@{ HostName = $c2eLive; Scope = 'north.contoso.com' }, 'DC1.CONTOSO.COM.', [pscustomobject]@{ HostName = ''; Scope = 'contoso.com' }, 'dc1.fabrikam.com'))
Assert-Equal 'dc1.contoso.com,dc1.fabrikam.com' ($c2eSet -join ',') 'C2e review: the DC host set holds each DC once, whatever domain lists it and in whatever case (declared population: two DCs among five targets)'
$c2eTwo = @([pscustomobject]@{ HostName = $c2eLive; Scope = 'contoso.com' }, [pscustomobject]@{ HostName = 'dc1.fabrikam.com'; Scope = 'fabrikam.com' })
$c2ePeersFailed = Get-AdfaDomainDcHostName -Domain 'north.contoso.com' -Targets $c2eTwo -InventoryFailures @([pscustomobject]@{ Domain = 'north.contoso.com'; Error = 'ADWS unreachable' }) -ScopedDomains @('contoso.com', 'fabrikam.com', 'north.contoso.com')
Assert-True (@($c2ePeersFailed.HostNames).Count -eq 0 -and [bool]$c2ePeersFailed.Gap.Failed -and [string]$c2ePeersFailed.Gap.Error -eq 'ADWS unreachable') 'C2e review: a domain whose DC list failed gets no other domain''s DCs, and its gap names the cause'
Assert-Equal 'dc1.fabrikam.com' ((Get-AdfaDomainDcHostName -Domain 'fabrikam.com' -Targets $c2eTwo -ScopedDomains @('contoso.com', 'fabrikam.com')).HostNames -join ',') 'C2e review: a domain''s own DCs only'
Assert-Equal 'dc1.contoso.com,dc2.contoso.com' ((Get-AdfaDomainDcHostName -Domain 'contoso.com' -Targets @($c2eLive, 'dc2.contoso.com') -ScopedDomains @('contoso.com')).HostNames -join ',') 'C2e review: on a single-domain run the unscoped names are that domain''s, as before'
Assert-Equal 0 @((Get-AdfaDomainDcHostName -Domain 'fabrikam.com' -Targets @($c2eLive, 'dc2.contoso.com') -ScopedDomains @('contoso.com', 'fabrikam.com')).HostNames).Count 'C2e review: on a multi-domain run the unscoped names stand in for no domain'
$c2eObs = @([pscustomobject]@{ Server = $c2eLive; SoaApex = @('_msdcs.contoso.com'); NsTargets = @($c2eLive, 'dc1.fabrikam.com'); GlueMissing = @(); GlueUnknown = @() })
$c2eMsdcs = @(Get-AdfaMsdcsDelegationVerdict -ForestRoot 'contoso.com' -Observations $c2eObs -AdDcHosts @($c2eLive) -IncompleteDomains @('fabrikam.com'))
Assert-True (@($c2eMsdcs | Where-Object { $_.Item -like '*NS hosts not cross-checked' -and $_.Status -eq 'Not Assessed' -and $_.Detail -match 'fabrikam\.com could not be listed' }).Count -eq 1 -and @($c2eMsdcs | Where-Object { $_.Status -eq 'Warning' }).Count -eq 0) 'C2e review: an NS host missing from an incomplete DC list is Not Assessed naming the domain left out, never a Warning'
Assert-Equal 'Warning' ([string]@(@(Get-AdfaMsdcsDelegationVerdict -ForestRoot 'contoso.com' -Observations $c2eObs -AdDcHosts @($c2eLive)) | Where-Object { $_.Item -like '*NS host not a known DC' })[0].Status) 'C2e review: with a complete DC list the same NS host is the Warning it was'
Assert-Equal 'AccessDenied' (Get-AdfaRegistryReadErrorCode -Exception (New-Object System.Management.Automation.MethodInvocationException -ArgumentList 'Acesso negado.', (New-Object System.UnauthorizedAccessException -ArgumentList 'Acesso negado.'))) 'C14c review: a refused remote registry read is access denied by its exception type, in any language'
Assert-Equal '' (Get-AdfaRegistryReadErrorCode -Exception (New-Object System.IO.IOException -ArgumentList 'Access is denied.')) 'C14c review: an exception of another type is not access denied, whatever its text'
$c2eGpo = & {
    function Resolve-AdfaHostAddress { param([string]$HostName, [int]$TimeoutMs) [pscustomobject]@{ Ok = $false; Addresses = @(); SocketError = 'HostNotFound'; TimedOut = $false; Error = 'No such host is known.' } }
    function Test-TcpPort { param([string]$ComputerName, [int]$Port, [int]$TimeoutMs) throw 'STUB: no probe' }
    Clear-AdfaDcPortCache
    Get-AdfaDcReachability -HostName $c2eDead | Out-Null
    $sysvol = Get-AdfaGpoSysvolRaw -Pdc $c2eDead -Domain 'contoso.com' -Targets @() -Config $script:Config.Gpo
    $raw = [pscustomobject]@{ Ok = $true; Refused = $false; Error = ''; ErrorType = ''; Pdc = $c2eDead; PdcError = ''; PdcErrorType = ''; DomainDn = 'DC=contoso,DC=com'; Containers = @() }
    $rows = @(Get-AdfaGpoDomainFinding -Domain 'contoso.com' -Raw $raw -Sysvol $sysvol -Config $script:Config.Gpo)
    Clear-AdfaDcPortCache
    @($rows | Where-Object { $_.Item -eq 'GPO folder listing: contoso.com' })[0]
}
Assert-True ([string]$c2eGpo.Detail -match '^Unreachable, classified once for this run by the reachability probe: the host name does not resolve' -and [string]$c2eGpo.Detail -notmatch 'did not answer') 'C14c review: the GPO folder listing of a PDC classified Unreachable names the class, never a probe that was not made'

Write-Host "== C16. Promise triage (GAP-P1..P30), pure logic ==" -ForegroundColor Cyan
$c16Dom = 'contoso.com'
# GAP-P3: the outbound direction is asked of a DC of the domain assessed (Learn Example 3 form).
Assert-Equal '/server:dc1.contoso.com /sc_query:fabrikam.com' (Get-AdfaNltestScArgument -Domain 'fabrikam.com' -Server 'dc1.contoso.com') 'C16 GAP-P3: /server:<dc> /sc_query:<partner>'
Assert-Equal '/sc_query:fabrikam.com' (Get-AdfaNltestScArgument -Domain 'fabrikam.com') 'C16 GAP-P3: with no server the argument is unchanged'
Assert-Equal '/server:dc1.contoso.com /sc_verify:fabrikam.com' (Get-AdfaNltestScArgument -Domain 'fabrikam.com' -Server 'dc1.contoso.com' -LiveVerify) 'C16 GAP-P2: /sc_verify only with the opt-in'
# GAP-P1: no Pass row when no subscription was read; one read gives a Pass counted on it alone.
$c16Unknown = @([pscustomobject]@{ DcName = 'dc1.contoso.com'; Enabled = $null; Options = $null; Error = 'x' }, [pscustomobject]@{ DcName = 'dc2.contoso.com'; Enabled = $null; Options = $null; Error = 'y' })
$c16Rows = @(Get-AdfaDfsrSubscriptionVerdict -DomainName $c16Dom -Subscriptions $c16Unknown)
Assert-True (@($c16Rows | Where-Object { $_.Status -eq 'Pass' }).Count -eq 0 -and @($c16Rows | Where-Object { $_.Item -eq 'DFSR SYSVOL subscription - not readable' -and $_.Status -eq 'Not Assessed' }).Count -eq 1) 'C16 GAP-P1: two DCs unread give no Pass row, one Not Assessed row'
$c16Raw = [pscustomobject]@{ Ok = $true; Error = ''; ErrorType = ''; DomainDn = 'DC=contoso,DC=com'; GlobalState = 'Present'; GlobalFlags = 48; GlobalError = ''; Dcs = @(
        [pscustomobject]@{ HostName = 'dc1.contoso.com'; IsReadOnly = $false; ComputerDn = 'CN=DC1'; Dfsr = 'Present'; DfsrError = ''; Frs = 'Absent'; FrsError = ''; DfsrEnabled = $false; DfsrOptions = 1 },
        [pscustomobject]@{ HostName = 'dc2.contoso.com'; IsReadOnly = $false; ComputerDn = 'CN=DC2'; Dfsr = 'Present'; DfsrError = ''; Frs = 'Absent'; FrsError = ''; DfsrEnabled = $null; DfsrOptions = $null },
        [pscustomobject]@{ HostName = 'dc3.contoso.com'; IsReadOnly = $false; ComputerDn = 'CN=DC3'; Dfsr = 'Unread'; DfsrError = 'access denied: STUB'; Frs = 'Unread'; FrsError = ''; DfsrEnabled = $null; DfsrOptions = $null },
        [pscustomobject]@{ HostName = 'dc4.contoso.com'; IsReadOnly = $false; ComputerDn = 'CN=DC4'; Dfsr = 'Absent'; DfsrError = ''; Frs = 'Present'; FrsError = ''; DfsrEnabled = $null; DfsrOptions = $null }) }
$c16List = ConvertTo-AdfaDfsrSubscriptionList -Raw $c16Raw
Assert-True (@($c16List.Subscriptions).Count -eq 3 -and $c16List.NotDfsrCount -eq 1) 'C16 GAP-P1: four DCs give three subscriptions and one DC without DFSR (declared population: dc1..dc4)'
$c16By = @{}; foreach ($s in @($c16List.Subscriptions)) { $c16By[$s.DcName] = $s }
# Changed by the independent review of the C16 diff (findings 6, 10): msDFSR-Enabled not returned is
# unknown with its cause, no longer taken as TRUE.
Assert-True ($c16By['dc1.contoso.com'].Enabled -eq $false -and $c16By['dc1.contoso.com'].Options -eq 1 -and $null -eq $c16By['dc2.contoso.com'].Enabled -and $c16By['dc2.contoso.com'].Error -match 'not returned' -and $null -eq $c16By['dc3.contoso.com'].Enabled -and $c16By['dc3.contoso.com'].Error -match 'access denied') 'C16 GAP-P1: FALSE kept, not returned unknown with its cause (review 6/10), unread kept unknown with its class'
$c16ListRows = @(Get-AdfaDfsrSubscriptionVerdict -DomainName $c16Dom -Subscriptions $c16List.Subscriptions -NotDfsrCount $c16List.NotDfsrCount)
$c16NotRead = @($c16ListRows | Where-Object { $_.Item -eq 'DFSR SYSVOL subscription - not readable' })
Assert-True ($c16NotRead.Count -eq 1 -and $c16NotRead[0].Detail -match 'dc2\.contoso\.com \(msDFSR-Enabled was not returned' -and $c16NotRead[0].Detail -match 'dc3\.contoso\.com \(access denied: STUB\)' -and @($c16ListRows | Where-Object { $_.Status -eq 'Pass' }).Count -eq 0) 'C16 review 4: the not-readable row names each DC with its own cause, and nothing passes'
Assert-Equal 0 @((ConvertTo-AdfaDfsrSubscriptionList -Raw ([pscustomobject]@{ Ok = $false; Dcs = @() })).Subscriptions).Count 'C16 GAP-P1: an unread DC list gives no subscription'
# GAP-P6: the site name is the first RDN of the subnet's site DN, compared whole.
$c16Topo = [pscustomobject]@{ Sites = @([pscustomobject]@{ Name = 'HQ' }, [pscustomobject]@{ Name = 'HQ-Branch' }); Subnets = @([pscustomobject]@{ Name = '192.0.2.0/24'; Site = 'CN=HQ-Branch,CN=Sites,CN=Configuration,DC=contoso,DC=com' }) }
$c16Site = @(Get-AdfaSiteHealthFinding -Topology $c16Topo -DomainControllers @([pscustomobject]@{ HostName = 'dc1.contoso.com'; Site = 'HQ' }, [pscustomobject]@{ HostName = 'dc2.contoso.com'; Site = 'HQ-Branch' }))
Assert-True (@($c16Site | Where-Object { $_.Item -eq "Site 'HQ' has no subnets" -and $_.Status -eq 'Warning' }).Count -eq 1 -and @($c16Site | Where-Object { $_.Item -eq "Site 'HQ-Branch' has no subnets" }).Count -eq 0) 'C16 GAP-P6: a subnet of HQ-Branch does not give HQ a subnet'
$c16NoInv = @(Get-AdfaSiteHealthFinding -Topology $c16Topo -DomainControllers @() -InventoryCollected $false)
Assert-True (@($c16NoInv | Where-Object { $_.Item -eq 'Empty sites' -and $_.Status -eq 'Not Assessed' }).Count -eq 1 -and @($c16NoInv | Where-Object { $_.Status -eq 'Pass' -or $_.Item -like '*has no domain controllers' }).Count -eq 0) 'C16 GAP-P6: without the inventory, empty sites are Not Assessed and nothing passes'
# Review 3/9: the inventory must cover every domain of the forest, with no domain's read failed.
Assert-Equal '' (Get-AdfaSiteInventoryGap -Collected $true -DcCount 2 -ScopeCoversForest $true -Failures @()) 'C16 review 3: a forest-wide inventory with no failure has no gap'
Assert-True ((Get-AdfaSiteInventoryGap -Collected $true -DcCount 2 -ScopeCoversForest $false) -match 'AllDomains') 'C16 review 3: a run that did not scope the forest has a gap naming -AllDomains'
Assert-True ((Get-AdfaSiteInventoryGap -Collected $true -DcCount 2 -ScopeCoversForest $true -Failures @([pscustomobject]@{ Domain = 'child.contoso.com'; Error = 'x' })) -match 'child\.contoso\.com') 'C16 review 9: a failed domain inventory is a gap naming the domain'
$c16Gap = Get-AdfaSiteInventoryGap -Collected $true -DcCount 1 -ScopeCoversForest $false
$c16Partial = @(Get-AdfaSiteHealthFinding -Topology $c16Topo -DomainControllers @([pscustomobject]@{ HostName = 'dc2.contoso.com'; Site = 'HQ-Branch' }) -InventoryCollected ($c16Gap -eq '') -InventoryGap $c16Gap)
Assert-True (@($c16Partial | Where-Object { $_.Item -like '*has no domain controllers' }).Count -eq 0 -and @($c16Partial | Where-Object { $_.Item -eq 'Empty sites' -and $_.Detail -match 'AllDomains' }).Count -eq 1) 'C16 review 3: a partial inventory calls no site empty, and the Not Assessed row names the gap'
# Review 1/7: only answers of type SRV count; a NODATA answer (the zone SOA) is a Fail.
$c16Srv = & {
    function Test-CommandAvailable { param([string]$Name) $true }
    function Resolve-DnsName { param([string]$Name, [string]$Type, $ErrorAction) [pscustomobject]@{ Name = 'contoso.com'; Type = 'SOA'; Section = 'Authority' } }
    @(Get-AdfaDnsDepth -DomainName 'contoso.com')
}
Assert-Equal 2 @($c16Srv | Where-Object { $_.Item -like 'SRV *' -and $_.Status -eq 'Fail' }).Count 'C16 review 1/7: both SRV names answered with the SOA only are a Fail (declared population: the _ldap and _kerberos names)'
# GAP-P25: the cap sentence only at the cap.
Assert-True ((Get-AdfaEventCapText -Count 500 -Cap 500) -match 'MINIMUM' -and (Get-AdfaEventCapText -Count 499 -Cap 500) -eq '' -and (Get-AdfaEventCapText -Count 0 -Cap 500) -eq '') 'C16 GAP-P25: a scan that returned its cap says its counts are a minimum, one below it does not'
# GAP-P20: the DC gate passes only over a complete forest.
$c16SeDcs = @([pscustomobject]@{ HostName = 'dc1.contoso.com'; OperatingSystem = 'Windows Server 2019 Datacenter'; IsReadOnly = $false })
$c16SePart = @(Get-AdfaExchangeSeCompatibility -ForestMode 'Windows2016Forest' -ForestLevel '7' -DomainSummaries @() -DomainControllers $c16SeDcs -SeConfig $script:Config.ExchangeSe)
$c16SeFull = @(Get-AdfaExchangeSeCompatibility -ForestMode 'Windows2016Forest' -ForestLevel '7' -DomainSummaries @() -DomainControllers $c16SeDcs -SeConfig $script:Config.ExchangeSe -ForestComplete $true)
Assert-Equal 'Not Assessed' ([string]@($c16SePart | Where-Object { $_.Item -eq 'Domain controller operating systems' })[0].Status) 'C16 GAP-P20: part of the forest is Not Assessed'
Assert-Equal 'Pass' ([string]@($c16SeFull | Where-Object { $_.Item -eq 'Domain controller operating systems' })[0].Status) 'C16 GAP-P20: the whole forest passes'
# GAP-P3: the source DC is the PDC emulator; a failed read names its class.
$c16Src = & {
    function Get-ADDomain { param([string]$Identity, [string]$Server, $Credential, $ErrorAction) throw [System.UnauthorizedAccessException]'STUB: refused' }
    Resolve-AdfaTrustSourceDc -DomainName 'contoso.com' -AdParams @{}
}
Assert-True ($c16Src.HostName -eq '' -and $c16Src.Error -match 'access denied') 'C16 GAP-P3: a refused PDC lookup gives no DC and names access denied'
$c16Src2 = & {
    function Get-ADDomain { param([string]$Identity, [string]$Server, $Credential, $ErrorAction) [pscustomobject]@{ PDCEmulator = 'dc1.contoso.com' } }
    Resolve-AdfaTrustSourceDc -DomainName 'contoso.com' -AdParams @{}
}
Assert-Equal 'dc1.contoso.com' ([string]$c16Src2.HostName) 'C16 GAP-P3: the PDC emulator is the source DC'
Assert-Equal '1.43.0' ([string]$script:Config.Version) 'C16: version 1.43.0 in the script (bumped by PORT-PLAN C15c)'

# ---- PORT-PLAN C1a: the update build revision (pure) -----------------------------------------
$c1aKey = [string]$script:Config.DcSystem['UbrKey']
Assert-Equal 'SOFTWARE\Microsoft\Windows NT\CurrentVersion' $c1aKey 'C1a: the UBR key is the one Learn documents'
Assert-Equal 'UBR' ([string]$script:Config.DcSystem['UbrValueName']) 'C1a: the value name is UBR'
$c1aRead = Resolve-AdfaBuildRevision -BuildNumber '20348' -UbrRead ([pscustomobject]@{ Answered = $true; ReturnValue = 0; Value = 4405; Error = ''; ErrorCode = '' }) -Key $c1aKey -ValueName 'UBR'
Assert-True ($c1aRead.Kind -eq 'Value' -and $c1aRead.FullBuild -eq '20348.4405' -and $c1aRead.Text -match 'not graded') 'C1a: a read revision is the fourth part of the build, display only'
$c1aZero = Resolve-AdfaBuildRevision -BuildNumber '20348' -UbrRead ([pscustomobject]@{ Answered = $true; ReturnValue = 0; Value = 0; Error = ''; ErrorCode = '' }) -Key $c1aKey -ValueName 'UBR'
Assert-Equal '20348.0' ([string]$c1aZero.FullBuild) 'C1a: a revision of 0 that was read is shown as read'
# Declared population: the six ways a read can fail to give a number (NotSet, KeyAbsent, AccessDenied, TypeMismatch, ReadFailed, NotAttempted).
$c1aFail = @(
    @{ Kind = 'NotSet'; Read = [pscustomobject]@{ Answered = $true; ReturnValue = 1; Value = $null; Error = ''; ErrorCode = '' } }
    @{ Kind = 'KeyAbsent'; Read = [pscustomobject]@{ Answered = $true; ReturnValue = 2; Value = $null; Error = ''; ErrorCode = '' } }
    @{ Kind = 'AccessDenied'; Read = [pscustomobject]@{ Answered = $true; ReturnValue = 5; Value = $null; Error = ''; ErrorCode = '' } }
    @{ Kind = 'TypeMismatch'; Read = [pscustomobject]@{ Answered = $true; ReturnValue = 2147749893; Value = $null; Error = ''; ErrorCode = '' } }
    @{ Kind = 'ReadFailed'; Read = [pscustomobject]@{ Answered = $false; ReturnValue = $null; Value = $null; Error = 'The RPC server is unavailable.'; ErrorCode = 'Failed' } }
    @{ Kind = 'NotAttempted'; Read = $null })
Assert-Equal 6 @($c1aFail).Count 'C1a: declared population of unread kinds is six'
foreach ($c in $c1aFail) {
    $r = Resolve-AdfaBuildRevision -BuildNumber '20348' -UbrRead $c.Read -Key $c1aKey -ValueName 'UBR'
    Assert-True ($r.Kind -eq $c.Kind -and $null -eq $r.Number -and $r.FullBuild -eq '' -and $r.Text -match '^Update build revision not read' -and $r.Text -notmatch '20348\.\d') ("C1a: {0} is not read, never a number" -f $c.Kind)
}
# Review fix: the type-mismatch text says the registry type is not published, and only that kind says so.
$c1aType = Resolve-AdfaBuildRevision -BuildNumber '20348' -UbrRead $c1aFail[3].Read -Key $c1aKey -ValueName 'UBR'
Assert-True ($c1aType.Text -match 'its registry type is not published' -and $c1aType.Text -match 'compared as an integer') 'C1a: a type mismatch says Microsoft does not publish the registry type'
Assert-True (@($c1aFail | Where-Object { $_.Kind -ne 'TypeMismatch' } | Where-Object { (Resolve-AdfaBuildRevision -BuildNumber '20348' -UbrRead $_.Read -Key $c1aKey -ValueName 'UBR').Text -match 'registry type is not published' }).Count -eq 0) 'C1a: no other unread kind claims anything about the registry type'
$c1aMerged = Merge-AdfaDcSystemConfig -BaseConfig $script:Config.DcSystem -Override $null
Assert-Equal $c1aKey ([string]$c1aMerged['UbrKey']) 'C1a: the merged table keeps the UBR key'
Assert-Throws { Merge-AdfaDcSystemConfig -BaseConfig $script:Config.DcSystem -Override @{ UbrValueName = 'CurrentBuildNumber' } | Out-Null } 'unknown key' 'C1a: a file cannot rename the UBR value'
# PORT-PLAN H20a: the inventory exists and states its read date.
$h20aDoc = Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) 'docs\SIDE-EFFECT-AUDIT.md'
Assert-True ((Test-Path -LiteralPath $h20aDoc) -and ([System.IO.File]::ReadAllText($h20aDoc) -match 'Read 2026-11-18')) 'H20a: docs/SIDE-EFFECT-AUDIT.md exists with its read date'
Assert-True ([System.IO.File]::ReadAllText($h20aDoc) -notmatch '(?i)\bno side[- ]effects?\b') 'H20a: the inventory never says "no side effect"'
# PORT-PLAN H20c: every row's Learn page was read; a row on no page names why. Declared population:
# the inventory rows (each a markdown table line whose first cell is a backticked key).
$h20cRows = @([regex]::Matches([System.IO.File]::ReadAllText($h20aDoc), '(?m)^\|\s*`([^`]+)`\s*\|([^\r\n]*)\|\s*$') | ForEach-Object {
        $cells = @($_.Groups[2].Value -split '\s\|\s' | ForEach-Object { $_.Trim() })
        [pscustomobject]@{ Key = $_.Groups[1].Value; Run = $cells[1]; Source = $cells[2] }
    })
Assert-True ($h20cRows.Count -gt 250) ('H20c: the inventory rows were read (declared population: every keyed row; got {0})' -f $h20cRows.Count)
Assert-True (@($h20cRows | Where-Object { $_.Source -match '(?i)not read in this session|API reference not read' }).Count -eq 0) 'H20c: no inventory row rests on a page that was not read'
Assert-True (@($h20cRows | Where-Object { $_.Source -match 'No Learn page' -and $_.Source -notmatch 'No Learn page: \S' }).Count -eq 0) 'H20c: every row on no Learn page names why'
$h20cNoPage = @($h20cRows | Where-Object { $_.Run -eq 'Default' -and $_.Key -notlike 'Effect:*' -and $_.Source -match 'No Learn page' } | ForEach-Object { $_.Key } | Sort-Object)
Assert-Equal 'Tool:dcdiag.exe /test:FsmoCheck /s:<dc>|Tool:repadmin.exe /showbackup|Tool:repadmin.exe /showbackup {0}' ($h20cNoPage -join '|') 'H20c: the three default rows on no Learn page are FsmoCheck and the two forms of repadmin /showbackup'
# PORT-PLAN H20d: the instance-method rows are keyed by receiver type; no reach name is keyed by name alone.
Assert-True (@($h20cRows | Where-Object { $_.Key -match '^Method:(Close|Dispose|Read|Seek|Start|Kill|Stop|Translate|GenerateReport|BeginConnect|EndConnect|GetValue|OpenSubKey)$' }).Count -eq 0) 'H20d: no reach method is keyed by name alone'
Assert-True (@($h20cRows | Where-Object { $_.Key -like 'Method:`[System.Net.Sockets.TcpClient`].Close' }).Count -eq 1 -and @($h20cRows | Where-Object { $_.Key -like 'Property:*' }).Count -eq 7) 'H20d: TcpClient.Close is keyed by type, and the 7 properties of the started process are rows'

# ---- PORT-PLAN H21: run folder, exit code and closing log lines (pure) ------------------------
$h21Out = $script:Config.Output
$h21Now = Get-Date -Year 2026 -Month 11 -Day 18 -Hour 9 -Minute 30 -Second 0
$h21Root = Resolve-AdfaOutputRoot -OutputPath '' -Config $h21Out
Assert-True ($h21Root.Root -eq 'C:\Scripts\Securnet\Reports' -and $h21Root.FromDefault) 'H21: with no -OutputPath the root is C:\Scripts\Securnet\Reports (the repository convention)'
$h21Path = Get-AdfaRunFolderPath -Root $h21Root.Root -Now $h21Now -Config $h21Out
Assert-Equal 'C:\Scripts\Securnet\Reports\ADForestAssessment-20261118-093000' ([string]$h21Path.RunRoot) 'H21: the default run folder is computed, not created'
Assert-True (-not (Test-Path -LiteralPath $h21Path.RunRoot)) 'H21: computing the default run folder created nothing (it does not exist after the call)'
Assert-Equal 'ADForestAssessment-20261118-093000.log' ([string](Split-Path -Leaf $h21Path.LogFile)) 'H21: the log is named after the run folder'
Assert-Equal 'ADForestAssessment-20261118-093000-2' ([string](Get-AdfaRunFolderPath -Root $h21Root.Root -Now $h21Now -Config $h21Out -Attempt 2).RunFolderName) 'H21: a second attempt in the same second adds -2'
Assert-Equal '20261118-213000' ([string](Get-AdfaRunFolderPath -Root $h21Root.Root -Now $h21Now.AddHours(12) -Config $h21Out).Stamp) 'H21: the hour is on the 24-hour clock'
Assert-Throws { Resolve-AdfaOutputRoot -OutputPath 'HKCU:\Software\AdfaH21NeverCreated' -Config $h21Out | Out-Null } 'Registry provider' 'H21: an -OutputPath on the registry is refused before anything is created'
function New-H21ValidationFinding { param([string]$Section, [string]$Status) ConvertTo-AdfaConsolidatedFinding -Section $Section -Row (New-Finding -Area 'H21' -Item 'item' -Status $Status) -StatusColumn 'Status' }
Assert-Equal 0 ([int](Get-AdfaRunExitCode -Findings @((New-H21ValidationFinding 'A' 'Pass'), (New-H21ValidationFinding 'A' 'Warning'), (New-H21ValidationFinding 'B' 'Info'))).ExitCode) 'H21: Pass, Warning and Info only is exit code 0'
Assert-Equal 1 ([int](Get-AdfaRunExitCode -Findings @((New-H21ValidationFinding 'A' 'Pass'), (New-H21ValidationFinding 'A' 'Fail'))).ExitCode) 'H21: a Fail finding is exit code 1'
Assert-Equal 1 ([int](Get-AdfaRunExitCode -Findings @((New-H21ValidationFinding 'A' 'Pass'), (New-H21ValidationFinding 'B' 'Not Assessed'), (New-H21ValidationFinding 'B' 'Not Assessed'))).ExitCode) 'H21: a section whose every finding is Not Assessed is exit code 1'
Assert-Equal 0 ([int](Get-AdfaRunExitCode -Findings @((New-H21ValidationFinding 'B' 'Pass'), (New-H21ValidationFinding 'B' 'Not Assessed'))).ExitCode) 'H21: a section assessed in part is not a Not Assessed section'
Assert-Equal 1 ([int](Get-AdfaRunExitCode -Findings @()).ExitCode) 'H21: no finding at all is exit code 1, never 0'
Assert-Equal 2 ([int](Get-AdfaRunExitCode -Findings @(New-H21ValidationFinding 'A' 'Pass') -Fatal -FatalReason 'stub').ExitCode) 'H21: a fatal run is exit code 2'
$h21Lines = @(Get-AdfaRunClosingLine -End $h21Now -Elapsed (New-TimeSpan -Seconds 3723) -Totals $null -ExitInfo ([pscustomobject]@{ ExitCode = 2; Reason = 'stub' }))
Assert-True ($h21Lines.Count -eq 3 -and $h21Lines[0] -match 'duration 01:02:03 \(3723 s\)$' -and $h21Lines[1] -match '^Totals: not counted' -and $h21Lines[2] -eq 'Exit code: 2 (stub)') 'H21: the closing lines state the duration, that the totals were not counted (never zeros) and the exit code'
$h21Exits = @([System.Management.Automation.Language.Parser]::ParseFile($target, [ref]$null, [ref]$null).FindAll({ param($n) $n -is [System.Management.Automation.Language.ExitStatementAst] }, $true))
Assert-Equal 1 $h21Exits.Count 'H21: the script holds exactly one exit statement (the guarded tail)'
# Independent review fixes of H21 (pure).
Assert-Equal 1 ([int](Get-AdfaRunExitCode -Findings @((New-H21ValidationFinding 'A' 'Pass'), (New-H21ValidationFinding 'B' 'Not Assessed'), (New-H21ValidationFinding 'B' 'Info'))).ExitCode) 'H21 review fix: Not Assessed beside an Info row is a section left Not Assessed (exit 1)'
Assert-Equal 0 ([int](Get-AdfaRunExitCode -Findings @((New-H21ValidationFinding 'A' 'Pass'), (New-H21ValidationFinding 'B' 'Info'))).ExitCode) 'H21 review fix: an Info-only section is not a Not Assessed section (exit 0)'
Assert-Equal 1 ([int](Get-AdfaRunExitCode -Findings @((New-H21ValidationFinding 'A' 'Pass'), [pscustomobject]@{ Section = 'A'; Status = '' })).ExitCode) 'H21 review fix: an empty status is exit 1, never 0'
Assert-Equal 1 ([int](Get-AdfaRunExitCode -Findings @((New-H21ValidationFinding 'A' 'Pass'), [pscustomobject]@{ Section = 'A'; Status = 'Unknown' })).ExitCode) 'H21 review fix: an unknown status is exit 1, never 0'
Assert-Equal 1 ([int](Get-AdfaRunExitCode -Findings @((New-H21ValidationFinding 'A' 'Pass'), @{ Section = 'A'; Status = 'Fail' })).ExitCode) 'H21 review fix: a Fail in a dictionary row is exit 1'
Assert-True ([string](Get-AdfaRunExitCode -Fatal -FatalReason ("not valid JSON: { not json" + "`r`n")).Reason -notmatch "[`r`n]") 'H21 review fix: a fatal reason with a line break is flattened'
Assert-Equal 'Exit code: 2 (a / b)' ([string]@(Get-AdfaRunClosingLine -End $h21Now -Elapsed (New-TimeSpan -Seconds 1) -Totals $null -ExitInfo ([pscustomobject]@{ ExitCode = 2; Reason = "a`r`nb`n" }))[2]) 'H21 review fix: the Exit code line stays one line'
Assert-Equal 0 ([int](Get-AdfaScriptExitCode -RunOutput @([pscustomobject]@{ ExitCode = 0 }))) 'H21 review fix: the process exit code is the summary ExitCode 0'
Assert-Equal 1 ([int](Get-AdfaScriptExitCode -RunOutput @([pscustomobject]@{ ExitCode = 1 }))) 'H21 review fix: the process exit code is the summary ExitCode 1'
Assert-Equal 2 ([int](Get-AdfaScriptExitCode -RunOutput @())) 'H21 review fix: no summary is exit code 2'
Assert-Equal 2 ([int](Get-AdfaScriptExitCode -RunOutput @([pscustomobject]@{ ExitCode = 7 }))) 'H21 review fix: an ExitCode outside 0/1/2 is exit code 2'

# --- PORT-PLAN C4b3: the options bits and the destination of a connection object (MS-ADTS, read 2026-11-19) ---
$lhConn = $script:Config['ConnectionOptions']
Assert-Equal 7 @($lhConn['Bits']).Count 'C4b3: the ConnectionOptions table holds the seven MS-ADTS bits (declared population)'
Assert-Equal 'NTDSCONN_OPT_IS_GENERATED' ([string]@($lhConn['Bits'] | Where-Object { [int]$_['Value'] -eq 1 })[0]['Name']) 'C4b3: bit 0x1 is NTDSCONN_OPT_IS_GENERATED (MS-ADTS 6.1.1.2.2.1.2.1.2)'
Assert-Equal 'Yes' ([string](ConvertFrom-AdfaConnectionOptions -Value 1 -Config $lhConn).Generated) 'C4b3: options 1 is a generated connection (IG set)'
Assert-Equal 'No' ([string](ConvertFrom-AdfaConnectionOptions -Value 0 -Config $lhConn).Generated) 'C4b3: options 0, read, is a connection with IG clear'
foreach ($lhBad in @($null, '', 'abc', 1.5, $true, [int64]4294967296)) {
    $lhD = ConvertFrom-AdfaConnectionOptions -Value $lhBad -Config $lhConn
    Assert-True ($lhD.Generated -eq 'Not read' -and -not $lhD.Read -and [string]$lhD.Cause -ne '') ("C4b3: options '{0}' is Not read with a cause, never No" -f [string]$lhBad)
}
Assert-Equal '0x80' ((@((ConvertFrom-AdfaConnectionOptions -Value 0x81 -Config $lhConn).Unknown)) -join ',') 'C4b3: a bit outside the MS-ADTS table is kept raw'
Assert-True ((ConvertFrom-AdfaConnectionOptions -Value ([int32]-2147483647) -Config $lhConn).Generated -eq 'Yes') 'C4b3: a negative options value is read as unsigned 32 bits'
$lhMin = ConvertFrom-AdfaConnectionOptions -Value ([int32]::MinValue) -Config $lhConn
Assert-True ($lhMin.Read -and $lhMin.Generated -eq 'No' -and ((@($lhMin.Unknown)) -join ',') -eq '0x80000000') 'C4b3: [int32]::MinValue, the lower edge, decodes as 0x80000000 with IG clear'
$lhMax = ConvertFrom-AdfaConnectionOptions -Value ([int64]4294967295) -Config $lhConn
Assert-True ($lhMax.Read -and $lhMax.Generated -eq 'Yes' -and @($lhMax.Unknown).Count -eq 25) 'C4b3: 0xFFFFFFFF, the upper edge, decodes: seven named bits and 25 raw (declared population: 32 bits)'
Assert-True ((ConvertFrom-AdfaConnectionOptions -Value ([int64]-2147483649) -Config $lhConn).Generated -eq 'Not read') 'C4b3: one below [int32]::MinValue is Not read'
Assert-True ([string](ConvertFrom-AdfaConnectionOptions -Value $null -Config $lhConn).Cause -notmatch 'KCC') 'C4b3: a Not read cause names the bit, not the KCC (MS-ADTS defines IG differently on an RODC NTFRS connection)'
$lhCnf = Get-AdfaConnectionDestination -DistinguishedName 'CN=x,CN=NTDS Settings\0ACNF:0f0e0d0c-0000-0000-0000-000000000001,CN=DC01,CN=Servers,CN=S1,CN=Sites,CN=Configuration,DC=contoso,DC=local' -Config $lhConn
Assert-True (-not $lhCnf.Ok -and [string]$lhCnf.Cause -match 'parent RDN of this connection is not CN=NTDS Settings' -and [string]$lhCnf.Cause -notmatch 'is not an nTDSDSA') 'C4b3: a CNF-mangled NTDS Settings parent is not derived, and the cause names the RDN, not a class never read'
$lhNoBit = @{} + $lhConn; $lhNoBit.Remove('GeneratedBit')
Assert-Equal 'Not read' ([string](ConvertFrom-AdfaConnectionOptions -Value 1 -Config $lhNoBit).Generated) 'C4b3: no GeneratedBit in the table is Not read, never No'
$lhDsa = 'CN=NTDS Settings,CN=DC1,CN=Servers,CN=HQ,CN=Sites,CN=Configuration,DC=contoso,DC=com'
$lhDest = Get-AdfaConnectionDestination -DistinguishedName ('CN=c1,{0}' -f $lhDsa) -Config $lhConn
Assert-True ($lhDest.Ok -and $lhDest.DsaDn -eq $lhDsa) 'C4b3: the destination is the parent of the connection DN, an NTDS Settings object in CN=Servers'
Assert-True ((Get-AdfaConnectionDestination -DistinguishedName ('CN=c\,1,{0}' -f $lhDsa) -Config $lhConn).DsaDn -eq $lhDsa) 'C4b3: an escaped comma does not split the DN'
foreach ($lhDn in @('', 'CN=lonely', 'CN=c1,CN=DC1,CN=Domain System Volume (SYSVOL share),CN=File Replication Service,CN=System,DC=contoso,DC=com', 'CN=c1,CN=NTDS Settings,CN=DC1,CN=Elsewhere,DC=contoso,DC=com')) {
    $lhX = Get-AdfaConnectionDestination -DistinguishedName $lhDn -Config $lhConn
    Assert-True (-not $lhX.Ok -and $lhX.DsaDn -eq '' -and [string]$lhX.Cause -match 'not derived') ("C4b3: '{0}' gives no destination, with the cause" -f $lhDn)
}
$lhRows = @(ConvertTo-AdfaTopologyListRow -Kind Connection -Raw ([pscustomobject]@{ Ok = $true; Error = ''; ErrorType = ''; NotFound = $false; Refused = $false; Count = 2; Capped = $false
            Records = @([pscustomobject]@{ name = 'c1'; distinguishedName = ('CN=c1,{0}' -f $lhDsa); fromServer = 'CN=NTDS Settings,CN=DC2,CN=Servers,CN=HQ,CN=Sites,CN=Configuration,DC=contoso,DC=com'; enabledConnection = $true; options = 1 },
                [pscustomobject]@{ name = 'c2'; distinguishedName = ('CN=c2,{0}' -f $lhDsa); fromServer = 'CN=NTDS Settings,CN=DC3,CN=Servers,CN=HQ,CN=Sites,CN=Configuration,DC=contoso,DC=com'; enabledConnection = $true }) }))
Assert-True ($lhRows.Count -eq 2 -and $lhRows[0].ToServer -eq $lhDsa -and $lhRows[0].AutoGenerated -eq 'Yes' -and $lhRows[0].OptionFlags -eq 'NTDSCONN_OPT_IS_GENERATED') 'C4b3: a connection row carries ToServer, AutoGenerated and OptionFlags'
Assert-True ($lhRows[1].AutoGenerated -eq 'Not read' -and $lhRows[1].Detail -match '^AutoGenerated: options was not returned') 'C4b3: a connection with no options value is Not read with its cause, never No'

# --- PORT-PLAN C4b4: a cap the file set is never called a tool default ---
$lhInvFile = Merge-AdfaSpecConfig -BaseConfig $script:Config.Inventory -Override @{ MaxObjects = 2 } -OverrideSource 'C:\cfg\c4b4.json'
$lhStaleFile = Merge-AdfaSpecConfig -BaseConfig $script:Config.Stale -Override @{ MaxObjects = 2 } -OverrideSource 'C:\cfg\c4b4.json'
$lhCapped = [pscustomobject]@{ Ok = $true; Error = ''; ErrorType = ''; NotFound = $false; Records = @([pscustomobject]@{ Name = 'g1'; sAMAccountName = 'g1'; groupType = 2; memberCount = 0 }); Count = 1; Capped = $true }
$lhNow = [datetime]::new(2026, 11, 19, 9, 0, 0, [System.DateTimeKind]::Utc)
$lhTexts = [ordered]@{
    'level'          = (Get-AdfaLevelRow -Kind Domain -Scope 'contoso.com' -Raw $lhCapped -Config $lhInvFile).Detail
    'FSMO'           = (Get-AdfaFsmoRow -Role 'RID master' -Scope 'contoso.com' -Raw $lhCapped -Config $lhInvFile).Detail
    'UPN suffix'     = (Get-AdfaUpnSuffixRow -ForestName 'contoso.com' -Raw $lhCapped -Config $lhInvFile).Detail
    'DNS suffix'     = (Get-AdfaAllowedDnsSuffixRow -DomainName 'contoso.com' -Raw $lhCapped -Config $lhInvFile).Detail
    'trusts'         = @(Get-AdfaTrustInventoryRows -DomainName 'contoso.com' -Raw $lhCapped -Config $lhInvFile)[0].Detail
    'object counts'  = @(Get-AdfaObjectCountRows -DomainName 'contoso.com' -Reads @{ Users = $lhCapped } -Config $lhInvFile)[0].Detail
    'groups'         = @(Get-AdfaGroupInventoryRows -DomainName 'contoso.com' -Raw $lhCapped -Config $lhInvFile)[0].Detail
    'group export'   = @(ConvertTo-AdfaGroupExportRow -DomainName 'contoso.com' -Raw $lhCapped -Config $lhInvFile)[0].ListComplete
    'GPO'            = @(Get-AdfaGpoDirectoryRows -DomainName 'contoso.com' -Gpc $lhCapped -Som $lhCapped -Site $lhCapped -Wmi $lhCapped -Config $lhInvFile -GpoConfig $script:Config.Gpo)[0].Detail
    'stale users'    = (Get-AdfaStaleCountVerdict -DomainName 'contoso.com' -Kind User -Raw $lhCapped -Interval $null -StaleDays 90 -Now $lhNow -Config $lhStaleFile).Detail
    'password age'   = (Get-AdfaPasswordAgeVerdict -DomainName 'contoso.com' -Raw $lhCapped -Now $lhNow -Config $lhStaleFile).Detail
    'stale disabled' = (Get-AdfaStaleDisabledVerdict -DomainName 'contoso.com' -Kind Computer -Raw $lhCapped -Interval $null -StaleDays 90 -Now $lhNow -Config $lhStaleFile).Detail
}
Assert-Equal 12 $lhTexts.Count 'C4b4: twelve row families checked (declared population)'
foreach ($lhK in @($lhTexts.Keys)) {
    Assert-True ([string]$lhTexts[$lhK] -match 'MaxObjects, set in the -ConfigOverridePath file' -and [string]$lhTexts[$lhK] -notmatch 'a tool default') ("C4b4: the {0} row names a file-set cap as the file's, not a tool default" -f $lhK)
}
Assert-True ((Get-AdfaLevelRow -Kind Domain -Scope 'contoso.com' -Raw $lhCapped -Config $script:Config.Inventory).Detail -match '\(Inventory\.MaxObjects, a tool default\)') 'C4b4: the built-in cap is still called a tool default'
Assert-Throws { Get-AdfaInventoryReadCause -Raw $lhCapped -What 'x' -CapSource '' } 'empty' 'C4b4: Get-AdfaInventoryReadCause refuses an empty cap source'
# Review fix: the GPO reads after the groupPolicyContainer read, each capped alone after a complete Gpc read
# (declared population: the SOM, site, WMI and other-domain reads).
$lhGpc = [pscustomobject]@{ Ok = $true; Error = ''; ErrorType = ''; NotFound = $false; Count = 1; Capped = $false
    Records = @([pscustomobject]@{ Name = '{31B2F340-016D-11D2-945F-00C04FB984F9}'; DistinguishedName = 'CN={31B2F340-016D-11D2-945F-00C04FB984F9},CN=Policies,CN=System,DC=contoso,DC=com'; displayName = 'Default Domain Policy'; flags = 0; versionNumber = 1; gPCWQLFilter = '' }) }
$lhDone = [pscustomobject]@{ Ok = $true; Error = ''; ErrorType = ''; NotFound = $false; Count = 0; Capped = $false; Records = @() }
$lhGpoCases = [ordered]@{ Som = 'the gPLink of the domain head and its OUs'; Site = 'the gPLink of the sites'; Wmi = 'the WMI filters (msWMI-Som)'; Other = "the gPLink of another forest domain's head and OUs" }
Assert-Equal 4 $lhGpoCases.Count 'C4b4: four GPO reads past the Gpc early return (declared population)'
foreach ($lhG in @($lhGpoCases.Keys)) {
    $lhR = @{ Som = $lhDone; Site = $lhDone; Wmi = $lhDone; Other = $lhDone }
    $lhR[$lhG] = $lhCapped
    $lhSum = @(@(Get-AdfaGpoDirectoryRows -DomainName 'contoso.com' -Gpc $lhGpc -Som $lhR.Som -Site $lhR.Site -Wmi $lhR.Wmi -ForestDomains @('contoso.com', 'north.contoso.com') -OtherSom @([pscustomobject]@{ Domain = 'north.contoso.com'; Raw = $lhR.Other }) -Config $lhInvFile -GpoConfig $script:Config.Gpo) | Where-Object { [string]$_.Item -eq 'GPO directory inventory: contoso.com' })
    $lhSumText = ''
    if ($lhSum.Count -eq 1) { $lhSumText = [string]$lhSum[0].Detail }
    Assert-True ($lhSum.Count -eq 1 -and $lhSumText.Contains($lhGpoCases[$lhG]) -and $lhSumText -match 'Inventory\.MaxObjects, set in the -ConfigOverridePath file' -and $lhSumText -notmatch 'a tool default') ("C4b4: the GPO {0} read, capped by the file, names the file's cap, not a tool default" -f $lhG)
}

# --- PORT-PLAN C11h: one advice entry per failing grid test; quoted dcdiag lines choose nothing ---
$lhUnscoped = @($script:RecommendationMap | Where-Object { -not $_.ContainsKey('Section') } | ForEach-Object { [string]$_.Text })
$lhPerDc = @($script:Config.DcDiag.PerDcTests | ForEach-Object { [string]$_.Test })
Assert-Equal 21 $lhPerDc.Count 'C11h: 21 per-DC grid tests (declared population)'
foreach ($lhT in $lhPerDc) {
    $lhRec = Get-AdfaRecommendation -Section 'DC Diagnostics' -Item 'dc1.contoso.com' -Detail ("{0}: replication access was denied; time skew; TRUSTED_FOR_DELEGATION; SYSVOL; backup" -f $lhT)
    Assert-True ($lhRec -match ("^dcdiag's {0} test failed" -f $lhT) -and $lhUnscoped -notcontains $lhRec) ("C11h: a failed {0} cell gets its own advice, whatever dcdiag quoted" -f $lhT)
}
Assert-Equal '' (Get-AdfaRecommendation -Section 'DC Diagnostics' -Item 'dc1.contoso.com' -Detail 'Unexpected: replication backup') 'C11h: any other grid text gets no advice, never an unscoped entry'
Assert-True ((Get-AdfaRecommendation -Section 'DC Diagnostics' -Item 'dc1.contoso.com' -Detail 'DC not reachable (RPC/135) - no dcdiag tests run.') -match 'did not answer on RPC/135') 'C11h: a DC not reachable gets the reachability advice'
# Review fix: a DC classified Unreachable by the reachability probe was never probed on 135.
$lhGated = ("DC not reachable - no dcdiag tests run. {0}" -f (Get-AdfaDcGateText -Cause 'Unreachable, classified once for this run by the reachability probe: the name does not resolve' -NotRead 'it was not probed again'))
$lhGatedRec = Get-AdfaRecommendation -Section 'DC Diagnostics' -Item 'dc1.contoso.com' -Detail $lhGated
Assert-True ($lhGatedRec -match 'classified this domain controller Unreachable' -and $lhGatedRec -notmatch 'did not answer on RPC/135' -and $lhUnscoped -notcontains $lhGatedRec) 'C11h: a DC classified Unreachable (never probed on 135) gets advice that states no RPC/135 result'

# --- PORT-PLAN C14c and C11e: the second SYSVOL instrument, the engine in the grid, netlogon.bak, dMSA, future timestamps ---
$ccSys = $script:Config.SysvolEngine
Assert-Equal 4 @($ccSys['RegistryValues']).Count 'C14c: four registry values are read - the three Learn spellings of Local State and the Netlogon SysVol path (declared population)'
function New-CcValRead { param($LocalState = 'absent', $Alt = 'absent', $NoSpace = 'nokey', $Path = 'C:\Windows\SYSVOL\sysvol', [bool]$Denied = $false, [bool]$Ok = $true)
    $one = { param([string]$Id, $Spec)
        $rv = 0; $v = $Spec
        if ($Spec -is [string]) { switch ($Spec) { 'absent' { $rv = 1; $v = $null } 'nokey' { $rv = 2; $v = $null } 'denied' { $rv = 5; $v = $null } } }
        [pscustomobject]@{ Id = $Id; Key = ''; ValueName = ''; Kind = ''; Answered = $true; ReturnValue = $rv; Value = $v; Method = ''; Error = ''; ErrorCode = '' } }
    $vals = @((& $one 'LocalState' $LocalState), (& $one 'LocalStateAlt' $Alt), (& $one 'LocalStateNoSpace' $NoSpace), (& $one 'SysVolPath' $Path))
    if (-not $Ok) { $vals = @() }
    [pscustomobject]@{ Raw = [pscustomobject]@{ Ok = $Ok; Protocol = 'Wsman'; Error = 'Access is denied.'; ErrorCode = ''; Values = $vals }; Denied = $Denied; Attempts = @() }
}
Assert-Equal 'DFSR' ([string](Resolve-AdfaSysvolRegistryEngine -Read (New-CcValRead -LocalState 3) -Config $ccSys).Engine) 'C14c: Local State 3 (Eliminated) is DFSR'
Assert-Equal 'FRS' ([string](Resolve-AdfaSysvolRegistryEngine -Read (New-CcValRead -Alt 0) -Config $ccSys).Engine) 'C14c: LocalState 0 (Start) under the VSS spelling is FRS'
Assert-Equal 'Transitional' ([string](Resolve-AdfaSysvolRegistryEngine -Read (New-CcValRead -LocalState 2) -Config $ccSys).Engine) 'C14c: Local State 2 (Redirected) is a migration in progress'
Assert-Equal 'Unknown' ([string](Resolve-AdfaSysvolRegistryEngine -Read (New-CcValRead -LocalState 42) -Config $ccSys).Engine) 'C14c: a number Learn does not map is Unknown'
$ccAbsent = Resolve-AdfaSysvolRegistryEngine -Read (New-CcValRead) -Config $ccSys
Assert-True ($ccAbsent.Engine -eq 'Absent' -and $ccAbsent.Detail -match 'FRS is being used' -and $ccAbsent.Detail -match 'not graded') 'C14c: every spelling absent is reported with Learn''s rule quoted and never graded FRS'
$ccDenied = Resolve-AdfaSysvolRegistryEngine -Read (New-CcValRead -Ok $false -Denied $true) -Config $ccSys
Assert-True ($ccDenied.Engine -eq 'Unread' -and $ccDenied.Class -eq 'AccessDenied' -and $ccDenied.Detail -notmatch '(?i)unreachable') 'C14c: a refused registry read is access denied, never unreachable'
$ccUnreach = Resolve-AdfaSysvolRegistryEngine -Read $null -Unreachable 'Unreachable: neither WinRM (5985) nor RPC (135) answered within 1200 ms, so the registry was not read.' -Config $ccSys
Assert-True ($ccUnreach.Engine -eq 'Unread' -and $ccUnreach.Class -eq 'Unreachable' -and $ccUnreach.Detail -notmatch '(?i)access denied') 'C14c: an unreachable DC is unreachable, never access denied'
Assert-Equal 'DFSR|registry' (@((Resolve-AdfaSysvolEngineCombined -DirectoryEngine 'Unknown' -RegistryEngine 'DFSR').PSObject.Properties.Value) -join '|') 'C14c: a DC whose directory objects could not tell is graded from the registry'
Assert-Equal 'Unknown|disagree' (@((Resolve-AdfaSysvolEngineCombined -DirectoryEngine 'DFSR' -RegistryEngine 'FRS').PSObject.Properties.Value) -join '|') 'C14c: two instruments that disagree are Unknown'
Assert-Equal 'FRS|directory' (@((Resolve-AdfaSysvolEngineCombined -DirectoryEngine 'FRS' -RegistryEngine 'Absent').PSObject.Properties.Value) -join '|') 'C14c: an absent registry value leaves the directory engine'
Assert-Equal 'Unknown|disagree' (@((Resolve-AdfaSysvolEngineCombined -DirectoryEngine 'Unknown' -RegistryEngine 'DFSR' -Dfsr 'Unread' -Frs 'Present').PSObject.Properties.Value) -join '|') 'C14c review: a measured NTFRS subscriber is never overruled by a registry DFSR'
Assert-Equal 'Unknown|disagree' (@((Resolve-AdfaSysvolEngineCombined -DirectoryEngine 'Unknown' -RegistryEngine 'DFSR' -Dfsr 'Absent' -Frs 'Absent').PSObject.Properties.Value) -join '|') 'C14c review: two objects measured absent are not graded from the registry'
Assert-Equal 'DFSR|registry' (@((Resolve-AdfaSysvolEngineCombined -DirectoryEngine 'Unknown' -RegistryEngine 'DFSR' -Dfsr 'Present' -Frs 'Unread').PSObject.Properties.Value) -join '|') 'C14c review: one object read and agreeing lets the registry grade'
Assert-True ($null -eq (ConvertTo-AdfaFileWriteTimeUtc -Written ([datetime]::new(1601, 1, 1))).Time) 'C14c review: GetLastWriteTimeUtc''s 1601-01-01 is read as not known'
Assert-Equal ([System.DateTimeKind]::Utc) ((ConvertTo-AdfaFileWriteTimeUtc -Written ([datetime]::new(2026, 11, 18))).Time.Kind) 'C14c review: a real last write time is returned as UTC'
$ccSrcCfg = Merge-AdfaSpecConfig -BaseConfig $script:Config.SiteCoverage -Override @{ NoClientSiteMaxAgeDays = 7 } -OverrideSource 'C:\Config for engagements\cc.json'
Assert-True ((Get-AdfaOverrideKeySource -Config $ccSrcCfg -Key 'NoClientSiteMaxAgeDays' -BuiltIn 'BUILTIN') -like 'set by C:\Config for engagements\cc.json (loaded *)') 'C14c review: an override path holding '' for '' is still named as the source of the key it set'
Assert-True (-not (Resolve-AdfaDcdiagApplicability -TestName 'FrsEvent' -Engine 'DFSR' -Source 'registry').Applicable) 'C11e: FrsEvent is not applicable on a DFSR DC (catalogue SYSVOL-003)'
Assert-True (-not (Resolve-AdfaDcdiagApplicability -TestName 'DFSREvent' -Engine 'FRS' -Source 'directory').Applicable) 'C11e: DFSREvent is not applicable on an FRS DC (catalogue SYSVOL-002)'
foreach ($ccE in @('Transitional', 'Unknown', '')) {
    Assert-True ((Resolve-AdfaDcdiagApplicability -TestName 'FrsEvent' -Engine $ccE).Applicable -and (Resolve-AdfaDcdiagApplicability -TestName 'DFSREvent' -Engine $ccE).Applicable) ("C11e: engine '{0}' keeps both tests graded from their own output" -f $ccE)
}
Assert-True ([string](Resolve-AdfaDcdiagApplicability -TestName 'FrsEvent' -Engine 'DFSR').Reason -match 'not a Microsoft rule') 'C11e: the reason says the rule is the catalogue''s, not Microsoft''s'
$ccNow = [datetime]::new(2026, 11, 19, 12, 0, 0, [System.DateTimeKind]::Utc)
$ccLine = '11/19 10:00:01 [MISC] [1234] CONTOSO: NO_CLIENT_SITE: WS01 198.51.100.77'
function New-CcFile { param([string]$Text, $Written, [bool]$Ok = $true, [string]$Class = 'Read')
    [pscustomobject]@{ Ok = $Ok; Class = $Class; Text = $Text; Error = ''; ErrorType = ''; HResult = 0; Path = 'x'; Partial = $false; BytesRead = $Text.Length; FileLength = [int64]0; LastWriteTimeUtc = $Written; LastWriteError = '' } }
$ccNoBak = New-CcFile -Text '' -Written $null -Ok $false -Class 'NotFound'
Assert-Equal 'Warning' ([string](Get-AdfaNoClientSiteVerdict -HostName 'dc1.contoso.com' -Raw (New-CcFile -Text $ccLine -Written $ccNow.AddDays(-30)) -BakRaw $ccNoBak -Now $ccNow -Config $script:Config.SiteCoverage).Status) 'C14c: a file last written at the edge of the 30-day window is current'
Assert-Equal 'Info' ([string](Get-AdfaNoClientSiteVerdict -HostName 'dc1.contoso.com' -Raw (New-CcFile -Text $ccLine -Written $ccNow.AddDays(-30).AddSeconds(-1)) -BakRaw $ccNoBak -Now $ccNow -Config $script:Config.SiteCoverage).Status) 'C14c: a file older than the window holds only old clients: Info, never current'
Assert-Equal 'Warning' ([string](Get-AdfaNoClientSiteVerdict -HostName 'dc1.contoso.com' -Raw (New-CcFile -Text 'x' -Written $ccNow) -BakRaw (New-CcFile -Text $ccLine -Written $ccNow.AddDays(-1)) -Now $ccNow -Config $script:Config.SiteCoverage).Status) 'C14c: clients named only in a recent netlogon.bak are current'
Assert-Equal 'Not Assessed' ([string](Get-AdfaNoClientSiteVerdict -HostName 'dc1.contoso.com' -Raw (New-CcFile -Text 'x' -Written $ccNow) -BakRaw (New-CcFile -Text '' -Written $null -Ok $false -Class 'AccessDenied') -Now $ccNow -Config $script:Config.SiteCoverage).Status) 'C14c: nothing current and netlogon.bak refused is Not Assessed'
Assert-Throws { Merge-AdfaSpecConfig -BaseConfig $script:Config.SiteCoverage -Override @{ NoClientSiteMaxAgeDays = 0 } -OverrideSource 'C:\cfg\cc.json' } 'whole number' 'C14c: an age window of 0 days is refused'
Assert-Equal 'Not Assessed' ([string](Get-AdfaNoClientSiteVerdict -HostName 'dc1.contoso.com' -Raw (New-CcFile -Text 'a NO_CLIENT_SITE: ' -Written $null) -BakRaw $ccNoBak -Now $ccNow -Config $script:Config.SiteCoverage).Status) 'C14c review: an unparsed marker line in a file of unknown age is Not Assessed, never Info'
foreach ($ccK in @('Computer', 'EnabledComputer', 'DisabledComputer', 'AllDisabledComputer', 'FutureComputer')) {
    Assert-True ((Get-AdfaStaleLdapFilter -Kind $ccK -CutoffUtc $ccNow) -match '\(!\(objectClass=msDS-DelegatedManagedServiceAccount\)\)') ("C14c: the {0} filter excludes delegated managed service accounts" -f $ccK)
}
$ccFuture = [pscustomobject]@{ Ok = $true; Error = ''; ErrorType = ''; Capped = $false; Filter = '(x)'; Properties = @()
    Records = @([pscustomobject]@{ Name = 'at'; HasLastLogon = $true; LastLogonUtc = $ccNow.AddSeconds(300); WhenCreatedUtc = $null }, [pscustomobject]@{ Name = 'before'; HasLastLogon = $true; LastLogonUtc = $ccNow.AddSeconds(299); WhenCreatedUtc = $null }) }
Assert-Equal 1 ([int](Get-AdfaFutureLogonCount -Raw $ccFuture -Now $ccNow -ToleranceSeconds 300).Count) 'C14c: a lastLogonTimestamp at the tolerance counts as future, one second before it does not'
$ccPop = [pscustomobject]@{ Ok = $true; Count = 10; Capped = $false; Error = ''; ErrorType = ''; Filter = '(x)' }
$ccNone = [pscustomobject]@{ Ok = $true; Error = ''; ErrorType = ''; Capped = $false; Filter = '(x)'; Properties = @(); Records = @() }
$ccInterval = [pscustomobject]@{ Ok = $true; Present = $false; Value = $null; Error = '' }
Assert-Equal 'Info' ([string](Get-AdfaFutureLogonVerdict -DomainName 'contoso.com' -Kind User -Raw $ccFuture -Now $ccNow -Population $ccPop).Status) 'C14c: accounts with a future lastLogonTimestamp are Info, never Pass'
Assert-Equal 'Not Assessed' ([string](Get-AdfaStaleCountVerdict -DomainName 'contoso.com' -Kind User -Raw $ccNone -Interval $ccInterval -StaleDays 90 -Now $ccNow -Population $ccPop -Future $ccFuture).Status) 'C14c: the inactive row cannot pass while an account carries a future lastLogonTimestamp'
Assert-Equal 'Pass' ([string](Get-AdfaStaleCountVerdict -DomainName 'contoso.com' -Kind User -Raw $ccNone -Interval $ccInterval -StaleDays 90 -Now $ccNow -Population $ccPop -Future $ccNone).Status) 'C14c: none stale and none in the future, in complete reads, passes'
# PORT-PLAN C11f + C2i + C15d(2) + C16d (v1.42.0): the pure logic of the dcdiag circuit breaker, the Intersite site
# states and the per-domain target selection. Fictional names only.
$lfPattern = [string]$script:Config.DcDiag['TimeoutErrorPattern']
Assert-True (Test-AdfaDcdiagTimedOut -Run ([pscustomobject]@{ Success = $false; Error = 'Timeout after 90s' }) -Pattern $lfPattern) 'C11f: the seam''s own time-out text is a time-out'
Assert-True (-not (Test-AdfaDcdiagTimedOut -Run ([pscustomobject]@{ Success = $false; Error = 'Access is denied.' }) -Pattern $lfPattern)) 'C11f: access denied is not a time-out'
Assert-True (-not (Test-AdfaDcdiagTimedOut -Run ([pscustomobject]@{ Success = $true; Error = 'Timeout after 90s' }) -Pattern $lfPattern)) 'C11f: a run that succeeded is a measurement, never a time-out'
$lfB = New-AdfaDcdiagBreaker -Threshold 2
$lfB = Register-AdfaDcdiagOutcome -Breaker $lfB -TimedOut $true
Assert-True (-not $lfB.Tripped) 'C11f: one time-out does not trip a breaker of two'
$lfB = Register-AdfaDcdiagOutcome -Breaker $lfB -TimedOut $true
Assert-True ([bool]$lfB.Tripped) 'C11f: two consecutive time-outs trip it'
$lfB = Register-AdfaDcdiagOutcome -Breaker $lfB -TimedOut $false
Assert-True ([bool]$lfB.Tripped -and [int]$lfB.ConsecutiveTimeouts -eq 0) 'C11f: a later completed test resets the count but never un-trips the breaker'
$lfA = New-AdfaDcdiagBreaker -Threshold 2
foreach ($lfI in 1..5) { $lfA = Register-AdfaDcdiagOutcome -Breaker $lfA -TimedOut $true; $lfA = Register-AdfaDcdiagOutcome -Breaker $lfA -TimedOut $false }
Assert-True (-not $lfA.Tripped) 'C11f: alternating time-outs never trip it'
Assert-Equal 2 ([int]$script:Config.DcDiag['CircuitBreakerTimeouts']) 'C11f: the threshold is 2, the operator''s value'
Assert-True ([string]$script:Config.DcDiag['CircuitBreakerSource'] -match 'not a Microsoft value') 'C11f: the threshold is labelled a tool default, not a Microsoft value'
Assert-Throws { Merge-AdfaDcDiagConfig -BaseConfig $script:Config.DcDiag -Override @{ CircuitBreakerTimeouts = 0 } } 'whole number from 1 to 10' 'C11f: a threshold of 0 is refused'
Assert-Throws { Merge-AdfaDcDiagConfig -BaseConfig $script:Config.DcDiag -Override @{ TimeoutErrorPattern = '.*' } } "unknown key 'TimeoutErrorPattern'" 'C11f: the time-out pattern cannot be set from a file'
Assert-Equal 'HQ' (ConvertTo-AdfaDsaSiteName -ServerDn 'CN=DC1,CN=Servers,CN=HQ,CN=Sites,CN=Configuration,DC=contoso,DC=com') 'C11f: the site of a server object is read from its DN'
Assert-Equal '' (ConvertTo-AdfaDsaSiteName -ServerDn 'CN=DC1,OU=Domain Controllers,DC=contoso,DC=com') 'C11f: no site is read from a DN of another shape'
$lfStates = @([pscustomobject]@{ HostName = 'dc1.contoso.com'; Site = 'HQ' })
$lfDsa = @([pscustomobject]@{ Site = 'HQ'; HostName = 'dc1.contoso.com'; ServerDn = 'x' }, [pscustomobject]@{ Site = 'Remote'; HostName = 'dc7.fabrikam.com'; ServerDn = 'y' })
Assert-Equal 'NoDc' ([string](Resolve-AdfaIntersiteSiteState -SiteName 'Warehouse' -SectionStates $lfStates -DsaRead $true -DsaServers $lfDsa).State) 'C11f: a site with no NTDS Settings object is not applicable'
Assert-Equal 'OutOfScope' ([string](Resolve-AdfaIntersiteSiteState -SiteName 'Remote' -SectionStates $lfStates -DsaRead $true -DsaServers $lfDsa).State) 'C11f: a site whose DCs are all outside the section is told apart'
Assert-Equal 'Unknown' ([string](Resolve-AdfaIntersiteSiteState -SiteName 'Warehouse' -SectionStates $lfStates -DsaRead $false -DsaServers @()).State) 'C11f: with the NTDS Settings objects not read, a site is never called empty'
Assert-Equal 'InSection' ([string](Resolve-AdfaIntersiteSiteState -SiteName 'hq' -SectionStates $lfStates -DsaRead $true -DsaServers $lfDsa).State) 'C11f: site names are not case sensitive'
$lfUnplaced = @($lfDsa) + @([pscustomobject]@{ Site = ''; HostName = 'dc9.contoso.com'; ServerDn = 'CN=NTDS Settings\0ACNF:1234,CN=DC9,CN=Servers,CN=Branch,CN=Sites,CN=Configuration,DC=contoso,DC=com' })
Assert-Equal 'Unknown' ([string](Resolve-AdfaIntersiteSiteState -SiteName 'Warehouse' -SectionStates $lfStates -DsaRead $true -DsaServers $lfUnplaced).State) 'C11f review: an NTDS Settings object read with no site blocks "no DC in site"'
Assert-Equal '' (ConvertTo-AdfaDsaSiteName -ServerDn 'CN=NTDS Settings\0ACNF:1234,CN=DC9,CN=Servers,CN=Branch,CN=Sites,CN=Configuration,DC=contoso,DC=com') 'C11f review: a conflict-mangled DN gives no site, never a guess'
$lfTargets = @([pscustomobject]@{ HostName = 'dc1.contoso.com'; Scope = 'contoso.com'; ComputerObjectDN = 'CN=DC1,DC=contoso,DC=com' }, [pscustomobject]@{ HostName = 'dc3.north.contoso.com'; Scope = 'north.contoso.com' })
Assert-Equal 'dc1.contoso.com' ((@((Select-AdfaDomainDcTarget -Domain 'contoso.com' -Targets $lfTargets -ScopedDomains @('contoso.com', 'north.contoso.com')).Targets) | ForEach-Object { $_.HostName }) -join ',') 'C2i(3): one domain''s targets only'
Assert-True ([bool](Select-AdfaDomainDcTarget -Domain 'south.contoso.com' -Targets $lfTargets -InventoryFailures @([pscustomobject]@{ Domain = 'south.contoso.com'; Error = 'STUB' }) -ScopedDomains @('south.contoso.com')).Gap.Failed) 'C2i(3): a domain whose DCs could not be listed has its gap, never another domain''s DCs'
Assert-Equal 'Primary' (@($script:Config.Dns['GradedZoneTypes']) -join ',') 'C16d(c): the zone transfer setting is graded on primary zones only (Learn documents SecureSecondaries on Set-DnsServerPrimaryZone alone)'
# PORT-PLAN C15c (v1.43.0): the pure logic of the leftovers batch - the W32Time effective source, the raw event
# occurrences, the ranged member count, the primary-group count, the gPOptions meaning, the runner role and the
# trust bit names. Fictional names only.
$lzInv = $script:Config.Inventory
$lzReg = { param([string]$Id, $Rv = 0, $Value = $null) [pscustomobject]@{ Id = $Id; Key = 'k'; ValueName = $Id; Answered = $true; ReturnValue = $Rv; Value = $Value; Method = 'GetStringValue'; Error = ''; ErrorCode = '' } }
$lzAbsent = @(@($lzInv['W32TimePolicyValues']) | ForEach-Object { & $lzReg ([string]$_.Id) 2 })
Assert-Equal 'Local' ([string](Resolve-AdfaW32TimeEffectiveSource -Id 'Type' -Values $lzAbsent -Config $lzInv).Source) 'C15c: a policy area holding no value leaves the local value in force'
$lzSet = @(@($lzInv['W32TimePolicyValues']) | ForEach-Object { if ($_.Id -eq 'Policy.Type.NtpClient') { & $lzReg ([string]$_.Id) 0 'NTP' } else { & $lzReg ([string]$_.Id) 2 } })
Assert-Equal 'Policy' ([string](Resolve-AdfaW32TimeEffectiveSource -Id 'Type' -Values $lzSet -Config $lzInv).Source) 'C15c: a policy value is the source in force'
$lzDenied = @(@($lzInv['W32TimePolicyValues']) | ForEach-Object { if ($_.Id -eq 'Policy.Type.Parameters') { & $lzReg ([string]$_.Id) 5 } else { & $lzReg ([string]$_.Id) 2 } })
Assert-True (-not (Resolve-AdfaW32TimeEffectiveSource -Id 'Type' -Values $lzDenied -Config $lzInv).Measured) 'C15c: a refused policy read leaves the source not measured, never local'
$lzEvents = @(1..25 | ForEach-Object { [pscustomobject]@{ Id = 7; Level = 2; ProviderName = 'p'; TimeCreated = [datetime]'2026-11-19 10:00:00'; RecordId = [long]$_ } })
$lzSel = Select-AdfaEventOccurrence -Events $lzEvents -Cap 20
Assert-Equal 20 ([int]$lzSel.Kept) 'C15c: at most RawEventCap raw occurrences are kept'
Assert-True (@($lzSel.Shown)[0] -match 'record 25') 'C15c: the newest occurrence comes first'
Assert-Equal 0 ([int](Select-AdfaEventOccurrence -Events $lzEvents -Cap 0).Kept) 'C15c: a cap of 0 keeps none'
$lzPage = { param($Low, [string]$High, [int]$Count, [bool]$Ok = $true) [pscustomobject]@{ Ok = $Ok; Error = 'The server is not operational'; ErrorType = ''; RangedMatches = 1; RangedLow = $Low; RangedHigh = $High; RangedCount = $Count } }
Assert-Equal 1234 ([int64](Measure-AdfaRangedMemberCount -Pages @((& $lzPage 0 '999' 1000), (& $lzPage 1000 '*' 234)) -MaxPages 100).Count) 'C15c: the pages add up to the exact count when the last ends with *'
$lzFailed = Measure-AdfaRangedMemberCount -Pages @((& $lzPage 0 '999' 1000), (& $lzPage 1000 '*' 0 $false)) -MaxPages 100
Assert-True ($lzFailed.State -eq 'Failed' -and $null -eq $lzFailed.Count) 'C15c: a failed page gives no count, never a partial number'
Assert-Equal 'Capped' ([string](Measure-AdfaRangedMemberCount -Pages @((& $lzPage 0 '999' 1000)) -MaxPages 1).State) 'C15c: the read stops at MemberRangeMaxPages and says so'
$lzPrimaryRaw = [pscustomobject]@{ Ok = $true; Error = ''; ErrorType = ''; NotFound = $false; Capped = $false; Count = 3; Records = @([pscustomobject]@{ primaryGroupID = 513 }, [pscustomobject]@{ primaryGroupID = 513 }, [pscustomobject]@{ primaryGroupID = 516 }) }
Assert-Equal 2 ([int](ConvertTo-AdfaPrimaryGroupCount -Raw $lzPrimaryRaw -Config $lzInv -CapSource 'x').Counts['513']) 'C15c: members are counted per primaryGroupID'
# C15c review (found by an independent review before commit): a read that holds neither RID every domain holds is not a count.
$lzPrimaryEmpty = [pscustomobject]@{ Ok = $true; Error = ''; ErrorType = ''; NotFound = $false; Capped = $false; Count = 0; Records = @() }
$lzPrimaryEmptyCount = ConvertTo-AdfaPrimaryGroupCount -Raw $lzPrimaryEmpty -Config $lzInv -CapSource 'x'
Assert-True (-not $lzPrimaryEmptyCount.Ok -and $lzPrimaryEmptyCount.Why -match '513 or 516') 'C15c review: an empty primary-group read is not a count (declared population: RIDs 513 and 516)'
$lzPrimaryNo516 = [pscustomobject]@{ Ok = $true; Error = ''; ErrorType = ''; NotFound = $false; Capped = $false; Count = 1; Records = @([pscustomobject]@{ primaryGroupID = 513 }) }
Assert-True (-not (ConvertTo-AdfaPrimaryGroupCount -Raw $lzPrimaryNo516 -Config $lzInv -CapSource 'x').Ok) 'C15c review: a primary-group read with no domain controller account (RID 516) is not a count'
$lzAadRow = @(Get-AdfaTrustInventoryRows -DomainName 'contoso.com' -Raw (& $c15Read @([pscustomobject]@{ trustPartner = 'fabrikam.com'; trustAttributes = $null; trustDirection = 3; trustType = 5 })) -Config $lzInv | Where-Object { $_.Item -eq 'Trust: contoso.com -> fabrikam.com' })[0]
Assert-True ($lzAadRow.Status -eq 'Not Assessed' -and $lzAadRow.Detail -match 'TRUST_TYPE_AAD') 'C15c review: a type 5 trust whose trustAttributes was not returned still names TRUST_TYPE_AAD'
$lzPrimaryCapped = [pscustomobject]@{ Ok = $true; Error = ''; ErrorType = ''; NotFound = $false; Capped = $true; Count = 2; Records = @() }
Assert-True (-not (ConvertTo-AdfaPrimaryGroupCount -Raw $lzPrimaryCapped -Config $lzInv -CapSource 'x').Ok) 'C15c: a capped primary-group read is not a count'
Assert-True ((Get-AdfaGpOptionsMeaning -Value 1 -Labels $lzInv['GpOptionsLabels']) -match '^1 block inheritance') 'C15c: gPOptions 1 blocks inheritance (MS-GPOL 2.2.2)'
Assert-True ((Get-AdfaGpOptionsMeaning -Value 2 -Labels $lzInv['GpOptionsLabels']) -match '^unknown 2') 'C15c: any other gPOptions value is unknown'
Assert-True ((Get-AdfaGpOptionsMeaning -Value $null -Labels $lzInv['GpOptionsLabels']) -match '^not returned') 'C15c: a gPOptions not returned is never a measured 0'
$lzRunner = { param($Role, $Product) [pscustomobject]@{ ComputerSystemOk = $true; DomainRole = $Role; ComputerName = 'ADMIN01'; ComputerSystemError = ''; OperatingSystemOk = ($null -ne $Product); ProductType = $Product; OperatingSystemError = 'not read' } }
Assert-Equal 'Yes' ([string](Resolve-AdfaRunnerRole -Raw (& $lzRunner 5 2) -Config $lzInv).IsDc) 'C15c: DomainRole 5 with ProductType 2 is a DC'
Assert-Equal 'No' ([string](Resolve-AdfaRunnerRole -Raw (& $lzRunner 3 3) -Config $lzInv).IsDc) 'C15c: a member server both instruments agree on is not a DC'
Assert-Equal 'Unknown' ([string](Resolve-AdfaRunnerRole -Raw (& $lzRunner 3 $null) -Config $lzInv).IsDc) 'C15c: a negative is never stated from one instrument'
Assert-Equal 'Unknown' ([string](Resolve-AdfaRunnerRole -Raw (& $lzRunner 4 3) -Config $lzInv).IsDc) 'C15c: two instruments that disagree give Unknown'
Assert-Equal 'OBSOLETE 0x400000' ((@((Get-AdfaTrustAttributeDecode -Value 0x400000 -Config $lzInv).Reserved)) -join ',') 'C15c: an obsolete trust bit is named by its MS-ADTS range'
Assert-Equal 0 (@((Get-AdfaTrustAttributeDecode -Value 4294967295 -Config $lzInv).Unknown).Count) 'C15c: no trustAttributes bit is unknown with the ranges of MS-ADTS 6.1.6.7.9'
Write-Host ""
Write-Host ("RESULT: {0} passed, {1} failed" -f $script:Passed, $script:Failures) -ForegroundColor $(if ($script:Failures -eq 0) { 'Green' } else { 'Red' })
Remove-Item Env:\ADFA_NO_AUTORUN -ErrorAction SilentlyContinue
if ($script:Failures -gt 0) { exit 1 }
exit 0
