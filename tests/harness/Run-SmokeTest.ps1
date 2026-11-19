#Requires -Version 5.1
<#
.SYNOPSIS
    End-to-end smoke test: runs the full Invoke-Main orchestration against a fully stubbed
    Active Directory, with no RSAT present, and asserts a report + CSV bundle is produced.
.DESCRIPTION
    Every AD cmdlet the orchestration touches is replaced with an in-memory stub, and
    Import-Module is shadowed with a no-op, so the real pipeline (collection -> CSV -> HTML)
    executes on any host. Verifies wiring, output paths, HTML/CSV emission and the roll-up.
#>
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$fail = 0
function Check($cond, $name) {
    if ($cond) { Write-Host "  [PASS] $name" -ForegroundColor Green }
    else { Write-Host "  [FAIL] $name" -ForegroundColor Red; $script:fail++ }
}

$target = Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) 'src/ADForestAssessment/Invoke-ADForestAssessment.ps1'
$env:ADFA_NO_AUTORUN = '1'
. $target

# ---- Stub RSAT + AD cmdlets -------------------------------------------------
function Import-Module { param([Parameter(ValueFromRemainingArguments)]$args) }
function Start-Transcript { param([Parameter(ValueFromRemainingArguments)]$args) }
function Stop-Transcript { param([Parameter(ValueFromRemainingArguments)]$args) }

$now = Get-Date

# Get-ADDomain returns DomainSID as a System.Security.Principal.SecurityIdentifier, whose
# ToString() is the SID string. The collector reads it two ways - [string]$d.DomainSID at
# Get-AdfaDomainSummary, and .DomainSID.Value elsewhere - so the stub must honour both.
# A bare [pscustomobject]@{Value=...} honours only .Value: its ToString() yields
# "@{Value=S-1-5-21-1-2-3}", which the JSON guard caught being written into the report.
# SecurityIdentifier itself cannot be constructed off Windows, and this harness must run
# anywhere, so ToString() is overridden instead.
function New-StubSid {
    param([string]$Sid)
    $o = [pscustomobject]@{ Value = $Sid }
    $o | Add-Member -MemberType ScriptMethod -Name ToString -Value { $this.Value } -Force
    return $o
}
function Get-ADForest { param([Parameter(ValueFromRemainingArguments)]$a)
    [pscustomobject]@{ Name='contoso.com'; RootDomain='contoso.com'; ForestMode='Windows2016Forest'
        PartitionsContainer='CN=Partitions,CN=Configuration,DC=contoso,DC=com'
        Domains=@('contoso.com'); Sites=@('Default-First-Site-Name'); GlobalCatalogs=@('dc1.contoso.com')
        SchemaMaster='dc1.contoso.com'; DomainNamingMaster='dc1.contoso.com'; UPNSuffixes=@() } }
# C7 (SID history) gives each domain of the stub forest its own SID, keyed by the -Identity the
# caller names, so a historic SID can be matched to the domain it came from and a same-domain value
# can be told from a value of another forest domain. A call that names no domain (the current
# domain) gets contoso.com's, as before. Everything else the stub returns is unchanged.
$script:SmokeDomainSids = @{ 'contoso.com' = 'S-1-5-21-1-2-3'; 'north.contoso.com' = 'S-1-5-21-1-2-4'; 'south.contoso.com' = 'S-1-5-21-1-2-5' }
function Get-ADDomain { param([Parameter(ValueFromRemainingArguments)]$a)
    $stubDomainNamed = ConvertTo-StubArgument -Given $a
    $stubDomainSid = 'S-1-5-21-1-2-3'
    if ($stubDomainNamed.ContainsKey('Identity') -and $script:SmokeDomainSids.ContainsKey([string]$stubDomainNamed['Identity'])) { $stubDomainSid = $script:SmokeDomainSids[[string]$stubDomainNamed['Identity']] }
    # C8: remembered so the groupPolicyContainer stub knows which domain it is answering for.
    if ($stubDomainNamed.ContainsKey('Identity')) { $script:SmokeGpoLastDomain = [string]$stubDomainNamed['Identity'] }
    [pscustomobject]@{ DNSRoot='contoso.com'; NetBIOSName='CONTOSO'; DomainMode='Windows2016Domain'
        PDCEmulator='dc1.contoso.com'; RIDMaster='dc1.contoso.com'; InfrastructureMaster='dc1.contoso.com'
        DomainSID=(New-StubSid $stubDomainSid); DistinguishedName='DC=contoso,DC=com' } }
function Get-ADDomainController { param([Parameter(ValueFromRemainingArguments)]$a)
    [pscustomobject]@{ HostName='dc1.contoso.com'; Name='DC1'; Site='Default-First-Site-Name'
        IPv4Address='10.0.0.1'; IsGlobalCatalog=$true; IsReadOnly=$false; ComputerObjectDN='CN=DC1,OU=DCs,DC=contoso,DC=com' } }
# Reproduces the failure a real multi-domain forest produced on 2026-09-26: the DC inventory
# enriched via Get-ADComputer WITHOUT -Server, so a child-domain DN was asked of a forest-root
# DC, which answers with an LDAP referral rather than the object. Every child-domain DC lost its
# OperatingSystem, and the Exchange SE verdict called them "unverified, not compatible".
# The stub refuses exactly as the directory did, so the bug cannot come back unnoticed.
#
# C4 (Laps) adds two behaviours, each selected by what the caller sends, so that the callers that
# existed before it receive exactly what they received before:
#   -LDAPFilter (only the Laps section sends one): the computer objects of the domain named by
#     -Server, in the shape the cmdlet returns - the default properties always, a requested
#     attribute only where the object has a value, the times as raw Int64 FILETIME. The stub
#     REFUSES a property list that holds a wildcard or one of the seven secret LAPS attributes:
#     a section that asked for a password would fail here, not appear to work.
#     Eight objects: one DC with a current Windows LAPS expiry time; three in the population
#     (two with an expiry time, one without); a disabled workstation, a Linux host, a cluster
#     object with no operatingSystem and a stale workstation, none of which may be graded.
#     $script:SmokeLapsFail makes this query, and the schema query, throw;
#     $script:SmokeLapsComputerFail makes this query alone throw.
#     $script:SmokeLapsDcExpiryFileTime, when set, is the raw expiry value of the DC instead of
#     "in 20 days" - the end-of-calendar value that once threw out of the section.
#   -Properties * : since v1.33.0 (PORT-PLAN C4b) no read sends it, and the stub THROWS on a
#     wildcard. The Identity export moved to Get-ADObject with a declared list; the Get-ADObject
#     stub hands each export object the seven secret LAPS attributes as well, each holding a
#     sentinel string, and the harness asserts the sentinel appears nowhere in the output bundle.
$script:SmokeLapsFail = $false
$script:SmokeLapsComputerFail = $false
$script:SmokeLapsDcExpiryFileTime = $null
$script:SmokeSecretSentinel = 'ADFA-SMOKE-SENTINEL-NOT-A-PASSWORD'
$script:SmokeLapsSecretNames = @('msLAPS-Password', 'msLAPS-EncryptedPassword', 'msLAPS-EncryptedPasswordHistory', 'msLAPS-EncryptedDSRMPassword',
    'msLAPS-EncryptedDSRMPasswordHistory', 'msLAPS-CurrentPasswordVersion', 'ms-Mcs-AdmPwd')
# What the stub forest's schema defines: the control attribute and the six attributes
# Update-LapsADSchema adds. No legacy attributes and no Windows Server 2025 attribute.
$script:SmokeLapsSchema = @('operatingSystemVersion', 'msLAPS-PasswordExpirationTime', 'msLAPS-Password', 'msLAPS-EncryptedPassword',
    'msLAPS-EncryptedPasswordHistory', 'msLAPS-EncryptedDSRMPassword', 'msLAPS-EncryptedDSRMPasswordHistory')
function New-StubLapsComputer {
    param([string]$Name, [string]$Domain, [string[]]$Asked, [string]$Os, [string]$OsVersion, [int]$Uac = 4096, $LogonDaysAgo = 1, $ExpiryDays = $null, $ExpiryFileTime = $null)
    $o = [pscustomobject]@{ DistinguishedName = ("CN={0},CN=Computers,DC={1}" -f $Name.ToUpperInvariant(), (($Domain -split '\.') -join ',DC='))
        DNSHostName = ("{0}.{1}" -f $Name, $Domain); Name = $Name.ToUpperInvariant(); ObjectClass = 'computer'; Enabled = (($Uac -band 2) -eq 0) }
    if ($Os -and ($Asked -contains 'operatingSystem')) { $o | Add-Member -NotePropertyName 'operatingSystem' -NotePropertyValue $Os }
    if ($OsVersion -and ($Asked -contains 'operatingSystemVersion')) { $o | Add-Member -NotePropertyName 'operatingSystemVersion' -NotePropertyValue $OsVersion }
    if ($Asked -contains 'userAccountControl') { $o | Add-Member -NotePropertyName 'userAccountControl' -NotePropertyValue $Uac }
    if ($null -ne $LogonDaysAgo -and ($Asked -contains 'lastLogonTimestamp')) { $o | Add-Member -NotePropertyName 'lastLogonTimestamp' -NotePropertyValue ([int64]$now.AddDays(-1 * $LogonDaysAgo).ToFileTimeUtc()) }
    if ($null -ne $ExpiryFileTime -and ($Asked -contains 'msLAPS-PasswordExpirationTime')) { $o | Add-Member -NotePropertyName 'msLAPS-PasswordExpirationTime' -NotePropertyValue ([int64]$ExpiryFileTime) }
    elseif ($null -ne $ExpiryDays -and ($Asked -contains 'msLAPS-PasswordExpirationTime')) { $o | Add-Member -NotePropertyName 'msLAPS-PasswordExpirationTime' -NotePropertyValue ([int64]$now.AddDays($ExpiryDays).ToFileTimeUtc()) }
    return $o
}
# C5 (DcCertificates): two certificates made in memory with an ephemeral ECDSA key - nothing is
# written to any certificate store or key container - one valid for 200 more days and one that
# expired 10 days ago, relative to the time of this run. The directory stub publishes both on the
# DC's computer object; the TLS seam stub presents the valid one.
function New-StubCertificate {
    param([string]$Subject, [double]$FromDays, [double]$ToDays)
    $key = [System.Security.Cryptography.ECDsa]::Create([System.Security.Cryptography.ECCurve+NamedCurves]::nistP256)
    $request = New-Object System.Security.Cryptography.X509Certificates.CertificateRequest -ArgumentList $Subject, $key, ([System.Security.Cryptography.HashAlgorithmName]::SHA256)
    $oids = New-Object System.Security.Cryptography.OidCollection
    [void]$oids.Add((New-Object System.Security.Cryptography.Oid -ArgumentList '1.3.6.1.5.5.7.3.1'))
    $request.CertificateExtensions.Add((New-Object System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension -ArgumentList $oids, $false))
    $cert = $request.CreateSelfSigned((New-Object System.DateTimeOffset -ArgumentList $now.AddDays($FromDays)), (New-Object System.DateTimeOffset -ArgumentList $now.AddDays($ToDays)))
    $key.Dispose()
    return $cert
}
$script:SmokeCertValid = New-StubCertificate -Subject 'CN=dc1.contoso.com' -FromDays -165 -ToDays 200
$script:SmokeCertExpired = New-StubCertificate -Subject 'CN=dc1.contoso.com' -FromDays -375 -ToDays -10
# $script:SmokeCertDirFail makes the userCertificate read throw, as a refused directory read would.
$script:SmokeCertDirFail = $false
# C6 (RidPool): CN=RID Manager$ of each domain, keyed by the -Server the section sends (the
# Get-ADDomain stub gives every domain the same DN, so the DN cannot tell the domains apart), in
# the shape the module returns: rIDAvailablePool an Int64, msDS-RIDPoolAllocationEnabled a Boolean
# and absent from the answer when it is not set. The values are built from their two 32-bit halves.
#   contoso.com        2,100 of the 30-bit space issued (Microsoft's own sample value), not set
#   north.contoso.com  150,000,000 of the 30-bit space (13.97 %), allocation FALSE
#   south.contoso.com  5,000 of the 31-bit space, allocation TRUE
# Each DC's computer object names its RID Set in rIDSetReferences (multi-valued, so a collection),
# and the RID Set holds the pool 2100-2599, next RID 2150, and the prefetched pool 3100-3599.
# $script:SmokeRidFail makes every read of CN=RID Manager$ throw; $script:SmokeRidSetAbsent takes
# rIDSetReferences away and makes the one-level search find nothing; $script:SmokeRidDcRefused
# makes the computer read throw an access-denied exception.
function New-StubInterval { param([int64]$Low, [int64]$High) return ([int64]$High * [int64]4294967296) + [int64]$Low }
$script:SmokeRidDomains = @{
    'contoso.com'       = @{ Pool = (New-StubInterval -Low 2100 -High 1073741823); Allocation = $null }
    'north.contoso.com' = @{ Pool = (New-StubInterval -Low 150000000 -High 1073741823); Allocation = $false }
    'south.contoso.com' = @{ Pool = (New-StubInterval -Low 5000 -High 2147483647); Allocation = $true }
}
$script:SmokeRidSchema = @('rIDAvailablePool', 'msDS-RIDPoolAllocationEnabled')
$script:SmokeRidFail = $false
$script:SmokeRidSetAbsent = $false
$script:SmokeRidDcRefused = $false
function New-StubRidSet { param([string]$Dn)
    [pscustomobject]@{ DistinguishedName = $Dn; ObjectClass = 'rIDSet'; rIDPreviousAllocationPool = (New-StubInterval -Low 2100 -High 2599)
        rIDAllocationPool = (New-StubInterval -Low 3100 -High 3599); rIDNextRID = [int32]2150; rIDUsedPool = (New-StubInterval -Low 1100 -High 1599) } }
# C7 (SID history): the principals of each domain that carry sIDHistory, keyed by the -Server the
# row sends, in the shape Get-ADObject returns - the default properties (DistinguishedName, Name,
# ObjectClass, ObjectGUID) always, a requested attribute only where the object has a value. What the
# module returns for a String(Sid) attribute is not published, so the two domains use two shapes:
# contoso.com hands back bytes (sIDHistory a collection of byte arrays, objectSid a byte array),
# north.contoso.com objects that carry the SID text in Value, as SecurityIdentifier does.
#   contoso.com        mig.user1 (enabled user): a SID of fabrikam.com, the trust partner;
#                      mig.group1 (group): a SID of north.contoso.com;
#                      ws-mig$ (disabled computer): a SID of a domain neither in the forest nor trusted
#   north.contoso.com  svc.north (enabled user): a SID of north.contoso.com itself (same-domain) and
#                      the Enterprise Admins SID of contoso.com (RID 519)
#   south.contoso.com  none
# The query REFUSES a wildcard or any attribute outside the six the row declares. contoso.com has one
# trusted domain object, fabrikam.com, under CN=System. $script:SmokeSidHistoryFail makes the
# principal query throw an access-denied exception.
$script:SmokeSidHistoryFail = $false
$script:SmokeSidHistoryAllowed = @('sIDHistory', 'objectSid', 'objectClass', 'sAMAccountName', 'distinguishedName', 'userAccountControl')
$script:SmokeFabrikamSid = 'S-1-5-21-7-8-9'
$script:SmokeLostSid = 'S-1-5-21-99-98-97'
# A SID in its binary form, built here without the script's parser: revision 1, the sub-authority
# count, the 6-byte authority big-endian, each sub-authority 4 bytes little-endian.
function New-StubSidBytes { param([string]$Sid)
    $stubSidParts = $Sid.Split('-')
    $stubSidSubs = @($stubSidParts | Select-Object -Skip 3)
    $stubSidList = New-Object System.Collections.Generic.List[byte]
    $stubSidList.Add([byte]1); $stubSidList.Add([byte]$stubSidSubs.Count)
    $stubSidAuthority = [uint64]$stubSidParts[2]
    for ($i = 5; $i -ge 0; $i--) { $stubSidList.Add([byte](($stubSidAuthority -shr (8 * $i)) -band 255)) }
    foreach ($s in $stubSidSubs) { $stubSidValue = [uint64]$s; for ($i = 0; $i -lt 4; $i++) { $stubSidList.Add([byte](($stubSidValue -shr (8 * $i)) -band 255)) } }
    return , $stubSidList.ToArray() }
function New-StubSidHistoryPrincipal {
    param([string]$Sam, [string]$Class, [string]$Domain, [string]$Rid, [object[]]$History, [string[]]$Asked, $Uac = $null, [switch]$AsText)
    $stubPrincipalDn = ("CN={0},OU=Migrated,DC={1}" -f $Sam, (($Domain -split '\.') -join ',DC='))
    $o = [pscustomobject]@{ DistinguishedName = $stubPrincipalDn; Name = $Sam; ObjectClass = $Class; ObjectGUID = [guid]::NewGuid() }
    $stubOwnSid = ("{0}-{1}" -f $script:SmokeDomainSids[$Domain], $Rid)
    $stubHistory = New-Object System.Collections.ArrayList
    foreach ($h in $History) { if ($AsText) { [void]$stubHistory.Add((New-StubSid $h)) } else { [void]$stubHistory.Add((New-StubSidBytes -Sid $h)) } }
    if ($Asked -contains 'sIDHistory') { $o | Add-Member -NotePropertyName 'sIDHistory' -NotePropertyValue $stubHistory }
    if ($Asked -contains 'objectSid') { if ($AsText) { $o | Add-Member -NotePropertyName 'objectSid' -NotePropertyValue (New-StubSid $stubOwnSid) } else { $o | Add-Member -NotePropertyName 'objectSid' -NotePropertyValue (New-StubSidBytes -Sid $stubOwnSid) } }
    if ($Asked -contains 'sAMAccountName') { $o | Add-Member -NotePropertyName 'sAMAccountName' -NotePropertyValue $Sam }
    if ($null -ne $Uac -and $Asked -contains 'userAccountControl') { $o | Add-Member -NotePropertyName 'userAccountControl' -NotePropertyValue ([int]$Uac) }
    return $o
}
# C8 (GPO version consistency): two groupPolicyContainer objects per domain, in the shape
# Get-ADObject returns - the default properties always (DistinguishedName, Name = the GUID in braces,
# ObjectClass, ObjectGUID), and of the four attributes the row declares only those asked for, with
# versionNumber as the Int32 the schema's Enumeration syntax gives. The Get-ADDomain stub answers
# every domain with the same PDC and DN, so the stub tells the domains apart by the -Identity of the
# Get-ADDomain call that comes just before (the seam's own order). Per domain:
#   contoso.com        both GPOs at 65537 in the directory and in GPT.INI: they agree
#   north.contoso.com  the second GPO at 131073 in the directory, 65537 in GPT.INI: user half differs
#   south.contoso.com  both agree, and SYSVOL holds a third GUID folder with no container
# Every Policies folder also holds PolicyDefinitions (the central store), which is not a GPO.
# SYSVOL is never touched: the two file seams are stubbed below, and record every path asked for.
# $script:SmokeGpoFail makes the container query throw an access-denied exception.
$script:SmokeGpoFail = $false
$script:SmokeGpoLastDomain = 'contoso.com'
$script:SmokeGpoAllowed = @('versionNumber', 'gPCFileSysPath', 'displayName', 'flags')
$script:SmokeGpoGuids = @('{31B2F340-016D-11D2-945F-00C04FB984F9}', '{6AC1786C-016F-11D2-945F-00C04FB984F9}')
$script:SmokeGpoOrphan = '{A1B2C3D4-0000-4000-8000-0000000000FF}'
$script:SmokeGptIniCalls = @()
$script:SmokeGpoListCalls = @()
function New-StubGpoContainer {
    param([string]$Guid, [string]$Domain, [string]$DisplayName, [int]$Version, [string[]]$Asked)
    $o = [pscustomobject]@{ DistinguishedName = ("CN={0},CN=Policies,CN=System,DC=contoso,DC=com" -f $Guid); Name = $Guid; ObjectClass = 'groupPolicyContainer'; ObjectGUID = [guid]::NewGuid() }
    if ($Asked -contains 'versionNumber') { $o | Add-Member -NotePropertyName 'versionNumber' -NotePropertyValue ([int]$Version) }
    if ($Asked -contains 'gPCFileSysPath') { $o | Add-Member -NotePropertyName 'gPCFileSysPath' -NotePropertyValue ("\\{0}\SysVol\{0}\Policies\{1}" -f $Domain, $Guid) }
    if ($Asked -contains 'displayName') { $o | Add-Member -NotePropertyName 'displayName' -NotePropertyValue $DisplayName }
    if ($Asked -contains 'flags') { $o | Add-Member -NotePropertyName 'flags' -NotePropertyValue ([int]0) }
    return $o
}
function Get-AdfaSysvolPolicyFolderRaw {
    param([string]$Path)
    $script:SmokeGpoListCalls += $Path
    $names = @($script:SmokeGpoGuids) + @('PolicyDefinitions')
    if ($Path -match '\\south\.contoso\.com\\Policies$') { $names += $script:SmokeGpoOrphan }
    [pscustomobject]@{ Ok = $true; Class = 'Read'; Names = @($names); Error = ''; ErrorType = ''; HResult = 0; Path = $Path }
}
function Get-AdfaGptIniRaw {
    param([string]$Path, [int]$MaxBytes)
    $script:SmokeGptIniCalls += $Path
    [pscustomobject]@{ Ok = $true; Class = 'Read'; Bytes = [byte[]][System.Text.Encoding]::ASCII.GetBytes("[General]`r`nVersion=65537`r`ndisplayName=New Group Policy Object`r`n"); Error = ''; ErrorType = ''; HResult = 0; Path = $Path }
}
# C9 (Acl): the security descriptors of the domain head, CN=AdminSDHolder,CN=System and every
# groupPolicyContainer. The Get-ADObject stub below answers a read only when it asks for
# nTSecurityDescriptor alone and names the domain itself as -Server (the Get-ADDomain stub gives every
# domain the same DN, so the domain comes from -Server); anything else throws. The value it hands back
# is a marker, and ConvertTo-AdfaAclDescriptor - the Windows seam that reads a real descriptor in
# memory - is stubbed to turn the marker into the records the real seam returns, because
# ActiveDirectorySecurity and SecurityIdentifier are not available off Windows and this harness must
# run anywhere. The real seam is tested on Windows by the Pester suite, from SDDL. Per domain:
#   contoso.com        the head holds Microsoft's default grants plus Get-Changes-All for
#                      S-1-5-21-1-2-3-1105, a group whose name resolves to "Fake Administrators"
#   north.contoso.com  the head holds only the defaults - Enterprise Admins and Enterprise Read-only
#                      DCs as SIDs of the forest root - and AdminSDHolder has a non-default writer
#   south.contoso.com  only the defaults
# Two GPOs per domain, with the groupPolicyContainer default grants. $script:SmokeAclFail makes every
# descriptor read throw an access-denied exception, $script:SmokeAclUnreachable an unreachable one,
# and $script:SmokeAclDaclAbsent makes every descriptor come back without a DACL.
$script:SmokeAclFail = $false
$script:SmokeAclUnreachable = $false
$script:SmokeAclDaclAbsent = $false
$script:SmokeAclCalls = @()
$script:SmokeAclFake = 'S-1-5-21-1-2-3-1105'
$script:SmokeAclRep = @{ Get = '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'; All = '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'; Filtered = '89e95b76-444d-4c62-991a-0facbeda640c' }
function New-StubAce {
    param([string]$Sid, [int64]$Mask, [string]$ObjectType = '', [bool]$Allow = $true, [bool]$InheritOnly = $false)
    $stubAceKind = 'Common'
    if ($ObjectType -ne '') { $stubAceKind = 'Object' }
    [pscustomobject]@{ Index = 0; Sid = $Sid; Allow = $Allow; Deny = (-not $Allow); Kind = $stubAceKind; Mask = $Mask; InheritOnly = $InheritOnly; Inherited = $false; ObjectType = $ObjectType; InheritedObjectType = '' }
}
function ConvertTo-AdfaAclDescriptor {
    param($Value)
    $stubAclDomain = [string]$Value.SmokeDomain
    $stubAclSid = $script:SmokeDomainSids[$stubAclDomain]
    $stubAclRoot = $script:SmokeDomainSids['contoso.com']
    if ($script:SmokeAclDaclAbsent) { return [pscustomobject]@{ Ok = $false; Class = 'DaclAbsent'; Error = 'the descriptor carries no DACL'; OwnerSid = ("{0}-512" -f $stubAclSid); Aces = @(); AceCount = 0 } }
    $stubAces = @()
    switch ([string]$Value.SmokeSdKind) {
        'Head' {
            $stubAces = @(
                (New-StubAce -Sid 'S-1-5-11' -Mask 0x20094)
                (New-StubAce -Sid ("{0}-512" -f $stubAclSid) -Mask 0xE01BD)
                (New-StubAce -Sid 'S-1-5-32-544' -Mask 0xF01BD)
                (New-StubAce -Sid 'S-1-5-18' -Mask 0xF01FF)
                (New-StubAce -Sid ("{0}-519" -f $stubAclRoot) -Mask 0xF01FF)
                (New-StubAce -Sid 'S-1-5-9' -Mask 0x100 -ObjectType $script:SmokeAclRep.Get)
                (New-StubAce -Sid 'S-1-5-9' -Mask 0x100 -ObjectType $script:SmokeAclRep.Filtered)
                (New-StubAce -Sid ("{0}-516" -f $stubAclSid) -Mask 0x100 -ObjectType $script:SmokeAclRep.All)
                (New-StubAce -Sid 'S-1-5-32-544' -Mask 0x100 -ObjectType $script:SmokeAclRep.All)
                (New-StubAce -Sid ("{0}-498" -f $stubAclRoot) -Mask 0x100 -ObjectType $script:SmokeAclRep.Get)
                (New-StubAce -Sid 'S-1-5-10' -Mask 0x20 -InheritOnly $true)
            )
            if ($stubAclDomain -eq 'contoso.com') { $stubAces += (New-StubAce -Sid $script:SmokeAclFake -Mask 0x100 -ObjectType $script:SmokeAclRep.All) }
        }
        'AdminSDHolder' {
            $stubAces = @(
                (New-StubAce -Sid ("{0}-512" -f $stubAclSid) -Mask 0xE01BD)
                (New-StubAce -Sid 'S-1-5-32-544' -Mask 0xF01BD)
                (New-StubAce -Sid 'S-1-5-18' -Mask 0xF01FF)
                (New-StubAce -Sid ("{0}-519" -f $stubAclRoot) -Mask 0xF01FF)
                (New-StubAce -Sid 'S-1-5-11' -Mask 0x20094)
            )
            if ($stubAclDomain -eq 'north.contoso.com') { $stubAces += (New-StubAce -Sid ("{0}-1500" -f $stubAclSid) -Mask 0x20) }
        }
        'Gpo' {
            $stubAces = @(
                (New-StubAce -Sid ("{0}-512" -f $stubAclSid) -Mask 0xF00FF)
                (New-StubAce -Sid ("{0}-519" -f $stubAclRoot) -Mask 0xF00FF)
                (New-StubAce -Sid 'S-1-3-0' -Mask 0xF00FF -InheritOnly $true)
                (New-StubAce -Sid 'S-1-5-18' -Mask 0xF00FF)
                (New-StubAce -Sid 'S-1-5-11' -Mask 0x20094)
                (New-StubAce -Sid 'S-1-5-11' -Mask 0x100 -ObjectType 'edacfd8f-ffb3-11d1-b41d-00a0c968f939')
                (New-StubAce -Sid 'S-1-5-9' -Mask 0x20094)
            )
        }
        default { throw ("STUB: no descriptor stubbed for '{0}'" -f [string]$Value.SmokeSdKind) }
    }
    for ($i = 0; $i -lt $stubAces.Count; $i++) { $stubAces[$i].Index = $i }
    [pscustomobject]@{ Ok = $true; Class = 'Read'; Error = ''; OwnerSid = ("{0}-512" -f $stubAclSid); Aces = $stubAces; AceCount = $stubAces.Count }
}
# Display names only: no LSA lookup is made from the harness.
function Resolve-AdfaAclSidName { param([string]$Sid) if ($Sid -eq $script:SmokeAclFake) { return 'CONTOSO\Fake Administrators' } return '' }
# The named arguments a remaining-arguments stub was called with: a splatted -Name value arrives as
# the string "-Name:" followed by the value.
function ConvertTo-StubArgument { param($Given)
    $named = @{}
    $list = @($Given)
    for ($i = 0; $i -lt $list.Count; $i++) {
        if ($list[$i] -is [string] -and $list[$i] -match '^-(\w+):?$' -and ($i + 1) -lt $list.Count) { $named[$Matches[1]] = $list[$i + 1]; $i++ }
    }
    return $named }
function Get-ADComputer {
    param([string]$Identity, [string]$Server, [string[]]$Properties, [string]$LDAPFilter, [Parameter(ValueFromRemainingArguments)]$a)
    if ([string]::IsNullOrWhiteSpace($Server)) { throw 'A referral was returned from the server' }
    # C5: the DC's computer object found by its DNS host name, asked for userCertificate only. The
    # attribute comes back as the module returns a multi-valued attribute - a collection whose
    # elements are the DER bytes of one certificate each.
    if ($LDAPFilter -match '^\(&\(objectClass=computer\)\(dNSHostName=([^()*\\]+)\)\)$') {
        $certHost = $Matches[1]
        # C6: the same lookup, asked for rIDSetReferences alone.
        if ((@($Properties) -join ',') -eq 'rIDSetReferences') {
            if ($script:SmokeRidDcRefused) { throw [System.UnauthorizedAccessException]'STUB: computer read refused' }
            $ridDn = ("CN=DC1,OU=Domain Controllers,DC={0}" -f (($Server -split '\.') -join ',DC='))
            $ridObject = [pscustomobject]@{ DistinguishedName = $ridDn; DNSHostName = $certHost; Name = 'DC1'; ObjectClass = 'computer'; Enabled = $true }
            if (-not $script:SmokeRidSetAbsent) { $ridObject | Add-Member -NotePropertyName 'rIDSetReferences' -NotePropertyValue @(("CN=RID Set,{0}" -f $ridDn)) }
            return $ridObject
        }
        if ($script:SmokeCertDirFail) { throw 'STUB: certificate read refused' }
        if ((@($Properties) -join ',') -ne 'userCertificate') { throw ("STUB: the certificate read asked for '{0}', not userCertificate alone" -f (@($Properties) -join ',')) }
        $certObject = [pscustomobject]@{ DistinguishedName = ("CN=DC1,OU=Domain Controllers,DC={0}" -f (($Server -split '\.') -join ',DC=')); DNSHostName = $certHost; Name = 'DC1'; ObjectClass = 'computer'; Enabled = $true }
        $certObject | Add-Member -NotePropertyName 'userCertificate' -NotePropertyValue @($script:SmokeCertValid.RawData, $script:SmokeCertExpired.RawData)
        return $certObject
    }
    # C15 (INV-009): the stale DISABLED computer read and its population, told apart by ACCOUNTDISABLE set.
    # One disabled computer, with no logon for 300 days.
    if ($LDAPFilter -match '\(userAccountControl:1\.2\.840\.113556\.1\.4\.803:=2\)' -and $LDAPFilter -notmatch '!\(userAccountControl') {
        $script:SmokeDisabledCalls += ("computer {0}" -f $Server)
        if ($script:SmokeStaleFail) { throw [System.UnauthorizedAccessException]'STUB: disabled read refused' }
        if ($LDAPFilter -notmatch '<=') {
            if ($PSBoundParameters.ContainsKey('Properties')) { throw 'STUB: the disabled population read asked for a property list' }
            return @([pscustomobject]@{ SamAccountName = 'WS-RETIRED$'; Name = 'WS-RETIRED'; Enabled = $false; ObjectClass = 'computer' })
        }
        if (@($Properties) -contains '*' -or @($Properties).Count -eq 0) { throw 'STUB: the disabled read asked for every property' }
        return [pscustomobject]@{ SamAccountName = 'WS-RETIRED$'; lastLogonTimestamp = [int64]$now.AddDays(-300).ToFileTimeUtc(); whenCreated = $now.AddDays(-900); userAccountControl = 4098 }
    }
    # C14c: the future lastLogonTimestamp read of the computers, told apart by '>='. Listed properties only,
    # sent to the domain; no computer carries a future value.
    if ($LDAPFilter -match 'lastLogonTimestamp>=') {
        if (@($Properties) -contains '*' -or @($Properties).Count -eq 0) { throw 'STUB: the future read asked for every property' }
        if ($LDAPFilter -notmatch 'msDS-DelegatedManagedServiceAccount') { throw 'STUB: the future computer read does not exclude delegated managed service accounts' }
        $script:SmokeFutureCalls += ("computer {0}" -f $Server)
        if ($script:SmokeStaleFail) { throw [System.UnauthorizedAccessException]'STUB: future read refused' }
        return @()
    }
    # C14 (STALE-001, review): the declared population, the enabled computers, told apart by the stale
    # filter without its time term. The default property set (no -Properties); three computers.
    if ($LDAPFilter -match '^\(&\(objectCategory=computer\)' -and $LDAPFilter -notmatch '<=') {
        if ($PSBoundParameters.ContainsKey('Properties')) { throw 'STUB: the population read asked for a property list' }
        $script:SmokePopulationCalls += ("computer {0}" -f $Server)
        if ($script:SmokeStaleFail) { throw [System.UnauthorizedAccessException]'STUB: population read refused' }
        return @(foreach ($n in @('DC1', 'WS-OLD', 'WS1')) { [pscustomobject]@{ SamAccountName = ("{0}$" -f $n); Name = $n; Enabled = $true; ObjectClass = 'computer' } })
    }
    # C14 (STALE-001): the stale computer read, told apart by its filter: one workstation with no logon
    # for 200 days. Listed properties only.
    if ($LDAPFilter -match 'lastLogonTimestamp<=') {
        if (@($Properties) -contains '*' -or @($Properties).Count -eq 0) { throw 'STUB: the stale read asked for every property' }
        $script:SmokeStaleCalls += ("computer {0}" -f $Server)
        if ($script:SmokeStaleFail) { throw [System.UnauthorizedAccessException]'STUB: stale read refused' }
        return [pscustomobject]@{ SamAccountName = 'WS-OLD$'; lastLogonTimestamp = [int64]$now.AddDays(-200).ToFileTimeUtc(); whenCreated = $now.AddDays(-900); userAccountControl = 4096 }
    }
    if (-not [string]::IsNullOrWhiteSpace($LDAPFilter)) {
        if ($script:SmokeLapsFail -or $script:SmokeLapsComputerFail) { throw 'STUB: computer query refused' }
        foreach ($p in @($Properties)) {
            if ($p -match '[*?]' -or $script:SmokeLapsSecretNames -contains $p) { throw ("STUB: the section asked for '{0}', which it must never request" -f $p) }
        }
        if ($LDAPFilter -ne '(objectClass=computer)') { throw ("STUB: unexpected LDAP filter '{0}'" -f $LDAPFilter) }
        return @(
            (New-StubLapsComputer -Name 'dc1' -Domain $Server -Asked $Properties -Os 'Windows Server 2019 Standard' -OsVersion '10.0 (17763)' -Uac 532480 -ExpiryDays 20 -ExpiryFileTime $script:SmokeLapsDcExpiryFileTime)
            (New-StubLapsComputer -Name 'srv1' -Domain $Server -Asked $Properties -Os 'Windows Server 2022 Standard' -OsVersion '10.0 (20348)' -ExpiryDays 10)
            (New-StubLapsComputer -Name 'ws1' -Domain $Server -Asked $Properties -Os 'Windows 11 Enterprise' -OsVersion '10.0 (22631)' -ExpiryDays 5)
            (New-StubLapsComputer -Name 'ws2' -Domain $Server -Asked $Properties -Os 'Windows 11 Enterprise' -OsVersion '10.0 (22631)')
            (New-StubLapsComputer -Name 'ws-off' -Domain $Server -Asked $Properties -Os 'Windows 10 Enterprise' -OsVersion '10.0 (19045)' -Uac 4098)
            (New-StubLapsComputer -Name 'linux1' -Domain $Server -Asked $Properties -Os 'Ubuntu' -OsVersion '22.04')
            (New-StubLapsComputer -Name 'cluster1' -Domain $Server -Asked $Properties -Os '' -OsVersion '')
            (New-StubLapsComputer -Name 'ws-stale' -Domain $Server -Asked $Properties -Os 'Windows 11 Enterprise' -OsVersion '10.0 (22631)' -LogonDaysAgo 200)
        )
    }
    # C4b: no read may ask for every attribute; one that does fails the run here.
    foreach ($p in @($Properties)) { if ([string]$p -match '[*?]') { throw 'STUB: Get-ADComputer was asked for every attribute (PORT-PLAN C4b)' } }
    $stubComputer = [pscustomobject]@{ OperatingSystem='Windows Server 2019'; OperatingSystemVersion='10.0 (17763)'; Enabled=$true; whenCreated=$now }
    $stubComputer }
# C1 (DcSystem): the CIM cmdlets, stubbed in the shape the real ones return for the classes the
# sections read. Any other class throws, so a section that asked for a class nobody stubbed
# degrades to Not Assessed instead of quietly "succeeding" against an object that has none of
# its properties. InstalledOn is given as the string Learn documents, in a form whose day/month
# order the set itself proves (23 > 12).
function New-CimSessionOption { param([string]$Protocol) [pscustomobject]@{ Protocol = $Protocol } }
function New-CimSession { param([string]$ComputerName, $SessionOption, [uint32]$OperationTimeoutSec, [pscredential]$Credential, $ErrorAction)
    [pscustomobject]@{ ComputerName = $ComputerName; Protocol = 'WSMAN' } }
function Remove-CimSession { param([Parameter(ValueFromRemainingArguments)]$a) }
function Get-CimInstance {
    param($CimSession, [string]$ComputerName, [string]$ClassName, [string]$Namespace, [string[]]$Property, [string]$Filter, [uint32]$OperationTimeoutSec, [pscredential]$Credential, $ErrorAction)
    if ($ClassName -eq 'Win32_OperatingSystem') {
        return [pscustomobject]@{ LastBootUpTime = $now.AddDays(-9); BuildNumber = '17763'; Version = '10.0.17763' }
    }
    # C3 (DcHardening): the Print Spooler service as Win32_Service returns it - State and StartMode
    # are strings. The service query is answered only for the filter the section sends, so a section
    # that asked for every service would get nothing rather than a Spooler it did not ask for.
    # MSFT_SmbServerConfiguration is NOT answered here: since PORT-PLAN C3f the SMB server
    # configuration is read with Get-SmbServerConfiguration (stubbed below), and an instance query of
    # the class falls through to the throw at the end, so a return to it would show.
    if ($ClassName -eq 'Win32_Service') {
        if ($Filter -ne "Name='Spooler'") { return @() }
        return [pscustomobject]@{ Name = 'Spooler'; State = 'Stopped'; StartMode = 'Disabled' }
    }
    if ($ClassName -eq 'Win32_QuickFixEngineering') {
        return @(
            [pscustomobject]@{ HotFixID = 'KB0000001'; InstalledOn = '10/23/2026' }
            [pscustomobject]@{ HotFixID = 'KB0000002'; InstalledOn = '11/10/2026' }
        )
    }
    # C2 (DcDisk): Win32_Volume in the shape the class returns - Name is the mount path, DeviceID
    # the volume GUID path, DriveType a uint32, Capacity and FreeSpace uint64 bytes. Four
    # volumes, so the path-to-volume mapping has something to get wrong: the system volume, a
    # second local volume for the logs, a recovery partition that has no mount path, and an
    # empty optical drive, which returns no capacity at all.
    if ($ClassName -eq 'Win32_Volume') {
        return @(
            [pscustomobject]@{ Name = 'C:\'; DeviceID = '\\?\Volume{00000000-0000-0000-0000-00000000000c}\'; DriveType = [uint32]3; Capacity = [uint64]128849018880; FreeSpace = [uint64]64424509440 }
            [pscustomobject]@{ Name = 'E:\'; DeviceID = '\\?\Volume{00000000-0000-0000-0000-00000000000e}\'; DriveType = [uint32]3; Capacity = [uint64]21474836480; FreeSpace = [uint64]12884901888 }
            [pscustomobject]@{ Name = '\\?\Volume{00000000-0000-0000-0000-00000000000f}\'; DeviceID = '\\?\Volume{00000000-0000-0000-0000-00000000000f}\'; DriveType = [uint32]3; Capacity = [uint64]554696704; FreeSpace = [uint64]83886080 }
            [pscustomobject]@{ Name = 'D:\'; DeviceID = '\\?\Volume{00000000-0000-0000-0000-00000000000d}\'; DriveType = [uint32]5; Capacity = $null; FreeSpace = $null }
        )
    }
    # C13 (DC DNS client, DC A records): Win32_NetworkAdapterConfiguration in the shape the class
    # returns - IPAddress and DNSServerSearchOrder are string arrays, IPEnabled a boolean - answered only
    # for the IPEnabled filter the section sends. One enabled adapter with an IPv4 and an IPv6 address;
    # $script:SmokeDnsClientServers is its DNS server list. The class's methods (SetDNSServerSearchOrder
    # and the like) are refused by the Invoke-CimMethod stub below, which answers StdRegProv only.
    if ($ClassName -eq 'Win32_NetworkAdapterConfiguration') {
        if ($Filter -ne 'IPEnabled = TRUE') { return @() }
        return [pscustomobject]@{ IPEnabled = $true; IPAddress = @('192.0.2.10', 'fe80::10'); DNSServerSearchOrder = @($script:SmokeDnsClientServers)
            Description = 'Stub adapter'; InterfaceIndex = [uint32]4 }
    }
    throw ("STUB: CIM class '{0}' is not stubbed" -f $ClassName)
}
$script:SmokeDnsClientServers = @('192.0.2.20', '127.0.0.1')
# C2 (DcDisk): the registry is read through StdRegProv, which has no instances - a value comes
# back from a METHOD call, as an object carrying ReturnValue (uint32, 0 for success) and the
# method's [out] parameter sValue. The stub answers GetStringValue for the three values the
# section reads. For anything else it answers what the REAL provider was measured to answer on
# 2026-11-13 (one Windows 11 workstation, not a DC): 1 for a value that does not exist under a
# key that does, 2 for a key that does not exist. An earlier version answered 2 for an absent
# value, a shape the provider does not produce. $script:SmokeAbsentValues names values to
# treat as not set, so a scenario can take one away. Any other class or
# method throws: nothing in this tool may call a method that is not a registry read, and a
# call that tried would fail here rather than appear to succeed. The database and SYSVOL are
# on C:, the logs on E:, so one DC yields two volume rows. -WhatIf and -Confirm are not declared:
# in a simple function the values the caller passes for them fall into $args and are ignored.
#
# C3 (DcHardening): GetDWORDValue, whose [out] parameter is uValue (uint32) and is absent on every
# nonzero return. The stub DC is a Windows Server 2019 DC (build 17763) on which three of the six
# values are set - LDAPServerIntegrity 2, the SMB server's RequireSecuritySignature 1 and
# LmCompatibilityLevel 5 - and three are not: LdapEnforceChannelBinding, LDAPServerEnforceIntegrity
# and the SMB client's RequireSecuritySignature, whose key exists. That is the shape a real DC
# has: a value Group Policy never set is simply not there. A value of the wrong type answers
# 2147749893 (0x80041005) to either kind of method, as measured.
$script:SmokeAbsentValues = @()
# C3f (DcHardening): the SMB server configuration, read with Get-SmbServerConfiguration -CimSession. By
# default the stub answers the shape MEASURED on 2026-11-17 on one Windows 11 workstation (not a DC,
# PowerShell 7 and Windows PowerShell 5.1): one MSFT_SmbServerConfiguration instance whose two
# properties are CimType Boolean, held in CimInstanceProperties - EnableSMB1Protocol False,
# RequireSecuritySignature True. $script:SmokeSmbMode selects the other answers: 'Empty' (no object,
# no error), 'Denied' (a refusal wrapped as a CDXML cmdlet raises it, the CIM code on the inner
# exception) and 'Smb1On'. -WhatIf and -Confirm are not declared, so the values the caller passes fall
# into $args; a call that does not pass both as $false is refused here, as is a call with no session.
$script:SmokeSmbMode = 'Instance'
# C3f: whether the cmdlet exists on the computer running the assessment (the Test-CommandAvailable stub).
$script:SmokeSmbCmdlet = $true
$script:SmokeSmbCalls = @()
function Get-SmbServerConfiguration {
    param($CimSession)
    if ($null -eq $CimSession) { throw 'STUB: Get-SmbServerConfiguration was called without -CimSession, so it would read the computer running the assessment' }
    $flags = (@($args) -join ' ')
    if ($flags -notmatch '-WhatIf: False' -or $flags -notmatch '-Confirm: False') { throw ("STUB: Get-SmbServerConfiguration was called without -WhatIf:`$false -Confirm:`$false ({0})" -f $flags) }
    $script:SmokeSmbCalls += [string]$CimSession.ComputerName
    if ($script:SmokeSmbMode -eq 'Empty') { return @() }
    if ($script:SmokeSmbMode -eq 'Denied') {
        $inner = New-Object System.Exception 'Acesso negado.'
        $inner | Add-Member -NotePropertyName NativeErrorCode -NotePropertyValue 'AccessDenied'
        throw (New-Object System.Exception -ArgumentList ('{0}: Acesso negado.' -f [string]$CimSession.ComputerName), $inner)
    }
    $smb1 = ($script:SmokeSmbMode -eq 'Smb1On')
    $store = @{ EnableSMB1Protocol = [pscustomobject]@{ Value = $smb1; CimType = 'Boolean' }; RequireSecuritySignature = [pscustomobject]@{ Value = $true; CimType = 'Boolean' } }
    return [pscustomobject]@{ CimClass = 'ROOT/Microsoft/Windows/Smb:MSFT_SmbServerConfiguration'; CimInstanceProperties = $store }
}
function Invoke-CimMethod {
    param($CimSession, [string]$Namespace, [string]$ClassName, [string]$MethodName, $Arguments, [uint32]$OperationTimeoutSec, $ErrorAction)
    if ($ClassName -ne 'StdRegProv' -or @('GetStringValue', 'GetExpandedStringValue', 'GetDWORDValue') -notcontains $MethodName) {
        throw ("STUB: CIM method '{0}.{1}' is not stubbed" -f $ClassName, $MethodName)
    }
    $stubRegistry = @{
        'SYSTEM\CurrentControlSet\Services\NTDS\Parameters|DSA Database File'       = 'C:\Windows\NTDS\ntds.dit'
        'SYSTEM\CurrentControlSet\Services\NTDS\Parameters|Database Log Files Path' = 'E:\NTDS-Logs'
        'SYSTEM\CurrentControlSet\Services\Netlogon\Parameters|SysVol'              = 'C:\Windows\SYSVOL\sysvol'
        # C15 (INV-015): W32Time Type, as a domain member has it; NtpServer is not set under the same key.
        'SYSTEM\CurrentControlSet\Services\W32Time\Parameters|Type'                 = 'NT5DS'
    }
    $stubDwords = @{
        'SYSTEM\CurrentControlSet\Services\NTDS\Parameters|LDAPServerIntegrity'              = [uint32]2
        'SYSTEM\CurrentControlSet\Services\LanManServer\Parameters|RequireSecuritySignature' = [uint32]1
        'SYSTEM\CurrentControlSet\Control\Lsa|LmCompatibilityLevel'                         = [uint32]5
        # C15 (INV-015): AnnounceFlags 10, the documented default for domain members.
        'SYSTEM\CurrentControlSet\Services\W32Time\Config|AnnounceFlags'                    = [uint32]10
        # C1a: the update build revision of the stub DC (build 17763), as GetDWORDValue returns it.
        'SOFTWARE\Microsoft\Windows NT\CurrentVersion|UBR'                                  = [uint32]6532
        # C14c: the DFSR migration Local State of a DC whose SYSVOL migration is Eliminated (3), under the
        # first Learn spelling only; 'LocalState' under the same key then answers 1 (key exists, value not
        # set) and 'Local State' under 'MigratingSysVols' answers 2 (no such key), as measured.
        'SYSTEM\CurrentControlSet\Services\DFSR\Parameters\SysVols\Migrating SysVols|Local State' = [uint32]3
    }
    # Keys that exist although the stub holds no value under them.
    $stubEmptyKeys = @('SYSTEM\CurrentControlSet\Services\LanManWorkstation\Parameters')
    $stubKey = ('{0}|{1}' -f [string]$Arguments['sSubKeyName'], [string]$Arguments['sValueName'])
    $stubAbsent = (@($script:SmokeAbsentValues) -contains [string]$Arguments['sValueName'])
    $stubIsString = ($stubRegistry.ContainsKey($stubKey) -and -not $stubAbsent)
    $stubIsDword = ($stubDwords.ContainsKey($stubKey) -and -not $stubAbsent)
    if ($MethodName -eq 'GetDWORDValue') {
        if ($stubIsDword) { return [pscustomobject]@{ ReturnValue = [uint32]0; uValue = $stubDwords[$stubKey]; PSComputerName = 'stub' } }
        if ($stubIsString) { return [pscustomobject]@{ ReturnValue = [uint32]2147749893; uValue = $null; PSComputerName = 'stub' } }
    }
    else {
        if ($stubIsString) { return [pscustomobject]@{ ReturnValue = [uint32]0; sValue = $stubRegistry[$stubKey]; PSComputerName = 'stub' } }
        if ($stubIsDword) { return [pscustomobject]@{ ReturnValue = [uint32]2147749893; sValue = $null; PSComputerName = 'stub' } }
    }
    $stubKeyPrefix = ([string]$Arguments['sSubKeyName'] + '|')
    $stubKeyExists = (@(@($stubRegistry.Keys) + @($stubDwords.Keys) | Where-Object { $_.StartsWith($stubKeyPrefix, [System.StringComparison]::OrdinalIgnoreCase) }).Count -gt 0)
    if (-not $stubKeyExists) { $stubKeyExists = (@($stubEmptyKeys | Where-Object { $_ -eq [string]$Arguments['sSubKeyName'] }).Count -gt 0) }
    if ($MethodName -eq 'GetDWORDValue') {
        if ($stubKeyExists) { return [pscustomobject]@{ ReturnValue = [uint32]1; uValue = $null; PSComputerName = 'stub' } }
        return [pscustomobject]@{ ReturnValue = [uint32]2; uValue = $null; PSComputerName = 'stub' }
    }
    if ($stubKeyExists) { return [pscustomobject]@{ ReturnValue = [uint32]1; sValue = $null; PSComputerName = 'stub' } }
    return [pscustomobject]@{ ReturnValue = [uint32]2; sValue = $null; PSComputerName = 'stub' }
}
function Get-ADReplicationPartnerMetadata { param([Parameter(ValueFromRemainingArguments)]$a)
    [pscustomobject]@{ Partner='dc2.contoso.com'; ConsecutiveReplicationFailures=0; LastReplicationSuccess=$now } }
function Get-ADReplicationFailure { param([Parameter(ValueFromRemainingArguments)]$a) @() }
function Get-ADReplicationQueueOperation { param([Parameter(ValueFromRemainingArguments)]$a) @() }
function Get-ADReplicationSite { param([Parameter(ValueFromRemainingArguments)]$a)
    [pscustomobject]@{ Name='Default-First-Site-Name'; Description=''; WhenCreated=$now; WhenChanged=$now } }
function Get-ADReplicationSubnet { param([Parameter(ValueFromRemainingArguments)]$a)
    [pscustomobject]@{ Name='10.0.0.0/24'; Site='Default-First-Site-Name'; Location=''; Description='' } }
# C4b: the site link, connection and trust reads must ask for exactly their declared list - never a
# wildcard, never a secret name, never a name outside the list - and each call is recorded with the
# list it sent and the server it named. $script:SmokeC4bFail refuses all three (access denied), and the
# Identity export read of the Get-ADObject stub with them. The connection object comes back by its LDAP
# names, as asked (fromServer, enabledConnection, options), with the default Name and DistinguishedName.
function Assert-StubC4bList { param($Named, [string]$Kind, [string]$ListKey)
    $asked = @(@($Named['Properties']) | Where-Object { $null -ne $_ } | ForEach-Object { [string]$_ })
    $script:SmokeC4bCalls += ("{0}:{1}@{2}" -f $Kind, ($asked -join ','), [string]$Named['Server'])
    foreach ($p in $asked) { if ($p -match '[*?]' -or $script:SmokeAllSecretNames -contains $p) { throw ("STUB: the {0} read asked for '{1}', which no read may request (PORT-PLAN C4b)" -f $Kind, $p) } }
    if (($asked -join ',') -ne (@($script:Config.DirectoryRead[$ListKey]) -join ',')) { throw ("STUB: the {0} read asked for '{1}', not its declared list" -f $Kind, ($asked -join ',')) }
    if ($script:SmokeC4bFail) { throw [System.UnauthorizedAccessException]('STUB: {0} read refused' -f $Kind) } }
function Get-ADReplicationSiteLink { param([Parameter(ValueFromRemainingArguments)]$a)
    Assert-StubC4bList -Named (ConvertTo-StubArgument -Given $a) -Kind 'SiteLink' -ListKey 'SiteLinkProperties'
    [pscustomobject]@{ Name='DEFAULTIPSITELINK'; Cost=100; ReplicationFrequencyInMinutes=180
        InterSiteTransportProtocol='IP'; SitesIncluded=@('CN=Default-First-Site-Name') } }
function Get-ADReplicationConnection { param([Parameter(ValueFromRemainingArguments)]$a)
    Assert-StubC4bList -Named (ConvertTo-StubArgument -Given $a) -Kind 'Connection' -ListKey 'ConnectionProperties'
    [pscustomobject]@{ Name='conn1'; DistinguishedName='CN=conn1,CN=NTDS Settings,CN=DC1,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=contoso,DC=com'
        ObjectClass='nTDSConnection'; fromServer='CN=NTDS Settings,CN=DC2,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=contoso,DC=com'
        enabledConnection=$true; options=1 } }
function Get-ADTrust { param([Parameter(ValueFromRemainingArguments)]$a)
    Assert-StubC4bList -Named (ConvertTo-StubArgument -Given $a) -Kind 'Trust' -ListKey 'TrustHealthProperties'
    [pscustomobject]@{ Name='fabrikam.com'; Source='contoso.com'; Target='fabrikam.com'; Direction='Bidirectional'
        TrustType='Forest'; IntraForest=$false; ForestTransitive=$true; SelectiveAuthentication=$false
        SIDFilteringForestAware=$false; SIDFilteringQuarantined=$true; TGTDelegation=$false
        UsesRC4Encryption=$false; Created=$now; Modified=$now } }
function Get-ADDefaultDomainPasswordPolicy { param([Parameter(ValueFromRemainingArguments)]$a)
    [pscustomobject]@{ MinPasswordLength=8; PasswordHistoryCount=24; MaxPasswordAge=[timespan]::FromDays(42)
        MinPasswordAge=[timespan]::FromDays(1); ComplexityEnabled=$true; LockoutThreshold=5; ReversibleEncryptionEnabled=$false } }
function Get-ADFineGrainedPasswordPolicy { param([Parameter(ValueFromRemainingArguments)]$a) @() }
# C10 retired Get-ADGroupMember: the privileged groups are read by SID through Get-ADObject. A call
# now fails the run here instead of quietly returning three made-up members.
function Get-ADGroupMember { param([Parameter(ValueFromRemainingArguments)]$a) throw 'STUB: Get-ADGroupMember is no longer used by this tool (PORT-PLAN C10)' }
# C10: the Kerberoast and AS-REP reads are refused when $script:SmokePrivFail is set; every other call
# receives the single object it always received.
function Get-ADUser { param([Parameter(ValueFromRemainingArguments)]$a)
    $stubUserNamed = ConvertTo-StubArgument -Given $a
    # C4b: no read may ask for every attribute or name a secret one.
    foreach ($p in @(@($stubUserNamed['Properties']) | Where-Object { $null -ne $_ })) { if ([string]$p -match '[*?]' -or $script:SmokeAllSecretNames -contains [string]$p) { throw ("STUB: Get-ADUser was asked for '{0}' (PORT-PLAN C4b)" -f $p) } }
    if ($script:SmokePrivFail -and [string]$stubUserNamed['LDAPFilter'] -match 'servicePrincipalName|4194304') { throw [System.UnauthorizedAccessException]'STUB: roast read refused' }
    # C15 (INV-009): the stale DISABLED user read and its declared population, told apart by ACCOUNTDISABLE
    # set (no '!' in front of it). Two disabled users in all; one with no logon for 400 days. Listed
    # properties for the stale read, the default set for the population; both must name the domain.
    if ([string]$stubUserNamed['LDAPFilter'] -match '\(userAccountControl:1\.2\.840\.113556\.1\.4\.803:=2\)' -and [string]$stubUserNamed['LDAPFilter'] -notmatch '!\(userAccountControl') {
        if ([string]::IsNullOrWhiteSpace([string]$stubUserNamed['Server'])) { throw 'STUB: a disabled read must name its domain' }
        $script:SmokeDisabledCalls += ("user {0}" -f [string]$stubUserNamed['Server'])
        if ($script:SmokeStaleFail) { throw [System.UnauthorizedAccessException]'STUB: disabled read refused' }
        if ([string]$stubUserNamed['LDAPFilter'] -notmatch '<=') {
            if ($stubUserNamed.ContainsKey('Properties')) { throw 'STUB: the disabled population read asked for a property list' }
            return @([pscustomobject]@{ SamAccountName = 'left.user'; Name = 'left.user'; Enabled = $false; ObjectClass = 'user' }, [pscustomobject]@{ SamAccountName = 'paused.user'; Name = 'paused.user'; Enabled = $false; ObjectClass = 'user' })
        }
        $disabledAsked = @(@($stubUserNamed['Properties']) | ForEach-Object { [string]$_ })
        if ($disabledAsked -contains '*' -or $disabledAsked.Count -eq 0) { throw 'STUB: the disabled read asked for every property' }
        return [pscustomobject]@{ SamAccountName = 'left.user'; lastLogonTimestamp = [int64]$now.AddDays(-400).ToFileTimeUtc(); whenCreated = $now.AddDays(-900); userAccountControl = 514 }
    }
    # C14c: the future lastLogonTimestamp read of the users, told apart by '>='. Listed properties only, sent
    # to the domain; one user carries a value 30 days in the future (a DC whose clock ran ahead).
    if ([string]$stubUserNamed['LDAPFilter'] -match 'lastLogonTimestamp>=') {
        $futureAsked = @(@($stubUserNamed['Properties']) | ForEach-Object { [string]$_ })
        if ($futureAsked -contains '*' -or $futureAsked.Count -eq 0) { throw 'STUB: the future read asked for every property' }
        if ([string]::IsNullOrWhiteSpace([string]$stubUserNamed['Server'])) { throw 'STUB: the future read must name its domain' }
        $script:SmokeFutureCalls += ("user {0}" -f [string]$stubUserNamed['Server'])
        if ($script:SmokeStaleFail) { throw [System.UnauthorizedAccessException]'STUB: future read refused' }
        return @([pscustomobject]@{ SamAccountName = 'clock.skewed'; lastLogonTimestamp = [int64]$now.AddDays(30).ToFileTimeUtc(); whenCreated = $now.AddDays(-900); userAccountControl = 512 })
    }
    # C14 (STALE-001/002, review): the declared population, the enabled users, told apart by the stale
    # filter without its time term. The default property set (no -Properties); five users.
    if ([string]$stubUserNamed['LDAPFilter'] -match '^\(&\(objectCategory=person\)' -and [string]$stubUserNamed['LDAPFilter'] -notmatch '<=') {
        if ($stubUserNamed.ContainsKey('Properties')) { throw 'STUB: the population read asked for a property list' }
        if ([string]::IsNullOrWhiteSpace([string]$stubUserNamed['Server'])) { throw 'STUB: the population read must name its domain' }
        $script:SmokePopulationCalls += ("user {0}" -f [string]$stubUserNamed['Server'])
        if ($script:SmokeStaleFail) { throw [System.UnauthorizedAccessException]'STUB: population read refused' }
        return @(foreach ($n in @('old.user', 'never.user', 'old.pwd', 'new.starter', 'recent.user')) { [pscustomobject]@{ SamAccountName = $n; Name = $n; Enabled = $true; ObjectClass = 'user' } })
    }
    # C14 (STALE-001/002): the stale reads, told apart by their filter. The property list must be the
    # listed one, never every property, and the read must name its domain. Two users without a logon
    # for a year (one never logged on, created two years ago) and, for the password read, one password
    # set two years ago and one pwdLastSet 0. Times are raw FILETIME Int64, whenCreated a DateTime.
    if ([string]$stubUserNamed['LDAPFilter'] -match 'lastLogonTimestamp<=|pwdLastSet<=') {
        $staleAsked = @(@($stubUserNamed['Properties']) | ForEach-Object { [string]$_ })
        if ($staleAsked -contains '*' -or $staleAsked.Count -eq 0) { throw 'STUB: the stale read asked for every property' }
        if ([string]::IsNullOrWhiteSpace([string]$stubUserNamed['Server'])) { throw 'STUB: the stale read must name its domain' }
        $script:SmokeStaleCalls += ("user {0}" -f [string]$stubUserNamed['Server'])
        if ($script:SmokeStaleFail) { throw [System.UnauthorizedAccessException]'STUB: stale read refused' }
        if ([string]$stubUserNamed['LDAPFilter'] -match 'pwdLastSet<=') {
            return @([pscustomobject]@{ SamAccountName = 'old.pwd'; pwdLastSet = [int64]$now.AddDays(-730).ToFileTimeUtc(); userAccountControl = 512 }
                [pscustomobject]@{ SamAccountName = 'new.starter'; pwdLastSet = [int64]0; userAccountControl = 512 })
        }
        return @([pscustomobject]@{ SamAccountName = 'old.user'; lastLogonTimestamp = [int64]$now.AddDays(-365).ToFileTimeUtc(); whenCreated = $now.AddDays(-900); userAccountControl = 512 }
            [pscustomobject]@{ SamAccountName = 'never.user'; whenCreated = $now.AddDays(-730); userAccountControl = 512 })
    }
    [pscustomobject]@{ PasswordLastSet=$now.AddDays(-30); SamAccountName='krbtgt' } }
# C10 (PrivilegedAccounts, PrivilegedHygiene, Kerberos): one small directory per domain, keyed by the
# -Server the read names. The Get-ADDomain stub gives every domain the same DN, so every object here
# sits under DC=contoso,DC=com; in the three-domain pass a member DN therefore cannot be routed to one
# domain, and the rows that depend on membership must say so (Not Assessed), never pass. Per domain:
#   Administrators (builtin)  Domain Admins, and - in the forest root - Enterprise Admins
#   Domain Admins (-512)      adm.smoke (enabled, an SPN, NOT_DELEGATED clear)
#   Enterprise Admins (-519)  Administrator (root only); Schema Admins (-518) empty (root only)
#   the other groups that always exist, empty; Domain Controllers holding DC1 by primaryGroupID 516
#   old.smoke                 adminCount=1 and in no group: an orphan
#   svc.deleg                 TRUSTED_FOR_DELEGATION; DC1 carries it too, and is a registered DC
# The configuration partition registers DC1 (an nTDSDSA object and serverReference) and holds no
# dSHeuristics. Answers carry the default properties and a requested attribute only where the object
# has a value; objectSid as bytes. $script:SmokePrivFail refuses every one of these reads.
$script:SmokePrivFail = $false
$script:SmokePrivCalls = @()
$script:SmokePrivCfg = 'CN=Configuration,DC=contoso,DC=com'
$script:SmokePrivDc = 'CN=DC1,OU=Domain Controllers,DC=contoso,DC=com'
function New-StubPrivDirectory {
    param([string]$Domain)
    $sid = $script:SmokeDomainSids[$Domain]
    $u = 'CN=Users,DC=contoso,DC=com'; $b = 'CN=Builtin,DC=contoso,DC=com'
    $isRoot = ($Domain -eq 'contoso.com')
    $adminMembers = @("CN=Domain Admins,$u")
    if ($isRoot) { $adminMembers += "CN=Enterprise Admins,$u" }
    $objects = @(
        @{ Dn = "CN=Administrators,$b"; Class = 'group'; Sid = 'S-1-5-32-544'; Sam = 'Administrators'; AdminCount = 1; Members = $adminMembers }
        @{ Dn = "CN=Domain Admins,$u"; Class = 'group'; Sid = "$sid-512"; Sam = 'Domain Admins'; AdminCount = 1; Members = @("CN=adm.smoke,$u") }
        @{ Dn = "CN=Account Operators,$b"; Class = 'group'; Sid = 'S-1-5-32-548'; Sam = 'Account Operators' }
        @{ Dn = "CN=Server Operators,$b"; Class = 'group'; Sid = 'S-1-5-32-549'; Sam = 'Server Operators' }
        @{ Dn = "CN=Print Operators,$b"; Class = 'group'; Sid = 'S-1-5-32-550'; Sam = 'Print Operators' }
        @{ Dn = "CN=Backup Operators,$b"; Class = 'group'; Sid = 'S-1-5-32-551'; Sam = 'Backup Operators' }
        @{ Dn = "CN=Replicator,$b"; Class = 'group'; Sid = 'S-1-5-32-552'; Sam = 'Replicator' }
        @{ Dn = "CN=Domain Controllers,$u"; Class = 'group'; Sid = "$sid-516"; Sam = 'Domain Controllers'; AdminCount = 1 }
        @{ Dn = "CN=Cert Publishers,$u"; Class = 'group'; Sid = "$sid-517"; Sam = 'Cert Publishers' }
        @{ Dn = "CN=Group Policy Creator Owners,$u"; Class = 'group'; Sid = "$sid-520"; Sam = 'Group Policy Creator Owners' }
        @{ Dn = "CN=Administrator,$u"; Class = 'user'; Sid = "$sid-500"; Sam = 'Administrator'; Uac = (512 + 1048576); AdminCount = 1; PrimaryGroupId = 513 }
        @{ Dn = "CN=adm.smoke,$u"; Class = 'user'; Sid = "$sid-1101"; Sam = 'adm.smoke'; Uac = 512; AdminCount = 1; PrimaryGroupId = 513; Spns = @('HTTP/app.contoso.com') }
        @{ Dn = "CN=old.smoke,$u"; Class = 'user'; Sid = "$sid-1102"; Sam = 'old.smoke'; Uac = 512; AdminCount = 1; PrimaryGroupId = 513 }
        @{ Dn = "CN=svc.deleg,$u"; Class = 'user'; Sid = "$sid-1103"; Sam = 'svc.deleg'; Uac = (512 + 524288); PrimaryGroupId = 513 }
        @{ Dn = $script:SmokePrivDc; Class = 'computer'; Sid = "$sid-1000"; Sam = 'DC1$'; Uac = 532480; PrimaryGroupId = 516 }
    )
    if ($isRoot) {
        $objects += @{ Dn = "CN=Enterprise Admins,$u"; Class = 'group'; Sid = "$sid-519"; Sam = 'Enterprise Admins'; AdminCount = 1; Members = @("CN=Administrator,$u") }
        $objects += @{ Dn = "CN=Schema Admins,$u"; Class = 'group'; Sid = "$sid-518"; Sam = 'Schema Admins'; AdminCount = 1 }
    }
    return $objects
}
function ConvertTo-StubPrivAnswer {
    param([hashtable]$O, [string[]]$Asked)
    $answer = [pscustomobject]@{ DistinguishedName = $O.Dn; Name = ($O.Dn -replace '^CN=([^,]+),.*$', '$1'); ObjectClass = $O.Class; ObjectGUID = [guid]::NewGuid() }
    foreach ($k in @('sAMAccountName', 'userAccountControl', 'adminCount', 'primaryGroupID')) {
        $v = @{ sAMAccountName = $O['Sam']; userAccountControl = $O['Uac']; adminCount = $O['AdminCount']; primaryGroupID = $O['PrimaryGroupId'] }[$k]
        if ($Asked -contains $k -and $null -ne $v) { $answer | Add-Member -NotePropertyName $k -NotePropertyValue $v }
    }
    if ($Asked -contains 'objectClass') { $answer | Add-Member -NotePropertyName 'objectClass' -NotePropertyValue @('top', $O.Class) -Force }
    if ($Asked -contains 'objectSid') { $answer | Add-Member -NotePropertyName 'objectSid' -NotePropertyValue (New-StubSidBytes -Sid $O.Sid) }
    if ($Asked -contains 'member' -and @($O['Members']).Count -gt 0 -and $null -ne $O['Members']) { $answer | Add-Member -NotePropertyName 'member' -NotePropertyValue @($O['Members']) }
    if ($Asked -contains 'servicePrincipalName' -and $null -ne $O['Spns']) { $answer | Add-Member -NotePropertyName 'servicePrincipalName' -NotePropertyValue @($O['Spns']) }
    return $answer
}
function Get-StubPrivAnswer {
    param([hashtable]$Named, [string[]]$Asked)
    foreach ($p in $Asked) { if ($p -match '[*?]') { throw 'STUB: a C10 read asked for every attribute' } }
    $server = [string]$Named['Server']
    $target = [string]$Named['Identity']
    if ($target -eq '') { $target = [string]$Named['LDAPFilter'] }
    $script:SmokePrivCalls += ("{0}@{1}" -f $target, $server)
    if ($script:SmokePrivFail) { throw [System.UnauthorizedAccessException]'STUB: privileged read refused' }
    if ([string]$Named['SearchBase'] -eq ("CN=Sites,{0}" -f $script:SmokePrivCfg)) {
        if ([string]$Named['LDAPFilter'] -eq '(objectClass=nTDSDSA)') { return [pscustomobject]@{ DistinguishedName = ("CN=NTDS Settings,CN=DC1,CN=Servers,CN=Default-First-Site-Name,CN=Sites,{0}" -f $script:SmokePrivCfg); ObjectClass = 'nTDSDSA' } }
        if ([string]$Named['LDAPFilter'] -eq '(objectClass=server)') { return [pscustomobject]@{ DistinguishedName = ("CN=DC1,CN=Servers,CN=Default-First-Site-Name,CN=Sites,{0}" -f $script:SmokePrivCfg); ObjectClass = 'server'; serverReference = $script:SmokePrivDc } }
        throw ("STUB: no configuration search '{0}'" -f [string]$Named['LDAPFilter'])
    }
    if ($target -like 'CN=Directory Service,*') { return [pscustomobject]@{ DistinguishedName = $target; ObjectClass = 'nTDSService' } }
    if (-not $script:SmokeDomainSids.ContainsKey($server)) { throw ("STUB: a C10 read must name its domain as -Server, not '{0}'" -f $server) }
    $objects = @(New-StubPrivDirectory -Domain $server)
    if ([string]$Named['Identity'] -ne '') {
        $hit = @($objects | Where-Object { $_.Dn -eq [string]$Named['Identity'] })
        if ($hit.Count -eq 0) { throw ("STUB: Cannot find an object with identity: '{0}'" -f [string]$Named['Identity']) }
        return (ConvertTo-StubPrivAnswer -O $hit[0] -Asked $Asked)
    }
    $filter = [string]$Named['LDAPFilter']
    if ($filter -match '^\(objectSid=(.+)\)$') {
        $wanted = $Matches[1]
        return @($objects | Where-Object { (ConvertTo-AdfaLdapSidFilterValue -Sid $_.Sid) -eq $wanted } | ForEach-Object { ConvertTo-StubPrivAnswer -O $_ -Asked $Asked })
    }
    if ($filter -match '^\(primaryGroupID=(\d+)\)$') {
        $rid = [int]$Matches[1]
        return @($objects | Where-Object { $null -ne $_['PrimaryGroupId'] -and [int]$_['PrimaryGroupId'] -eq $rid } | ForEach-Object { ConvertTo-StubPrivAnswer -O $_ -Asked $Asked })
    }
    if ($filter -eq '(adminCount=1)') { return @($objects | Where-Object { $_['AdminCount'] -eq 1 } | ForEach-Object { ConvertTo-StubPrivAnswer -O $_ -Asked $Asked }) }
    if ($filter -like '(|(userAccountControl:1.2.840.113556.1.4.803:=524288)*') {
        return @($objects | Where-Object { $null -ne $_['Uac'] -and ((([int64]$_['Uac']) -band 524288) -ne 0 -or (([int64]$_['Uac']) -band 16777216) -ne 0) } | ForEach-Object { ConvertTo-StubPrivAnswer -O $_ -Asked $Asked })
    }
    throw ("STUB: no C10 answer for '{0}'" -f $filter)
}
function Get-ADOptionalFeature { param([Parameter(ValueFromRemainingArguments)]$a)
    [pscustomobject]@{ Name='Recycle Bin Feature'; EnabledScopes=@('CN=Partitions') } }
function Get-ADRootDSE { param([Parameter(ValueFromRemainingArguments)]$a)
    [pscustomobject]@{ configurationNamingContext='CN=Configuration,DC=contoso,DC=com'; schemaNamingContext='CN=Schema,CN=Configuration,DC=contoso,DC=com'
        # C15 (INV-001): the DC that answered the run.
        dnsHostName='dc1.contoso.com' } }
# C4 (Laps): one more behaviour, selected by the filter. A search for attributeSchema objects by
# lDAPDisplayName - which only the Laps schema read sends - is answered with one object per name
# that is both asked for and in $script:SmokeLapsSchema, in the shape the cmdlet returns. Every
# other call receives the single object it always received.
function Get-ADObject { param([Parameter(ValueFromRemainingArguments)]$a)
    $stubAsked = (@($a | ForEach-Object { [string]$_ }) -join ' ')
    $stubNamed = ConvertTo-StubArgument -Given $a
    # C15 (INV-001, 006, 008, 010, 011): the inventory reads, told apart by what they ask for - fSMORoleOwner
    # (topology), trustAttributes (trusts), a count filter of the Inventory table, gPCWQLFilter (GPOs), a
    # gPLink search (domain, OUs and sites) and msWMI-Som (WMI filters). Each must name its domain and list
    # its properties; the answers carry what was asked for, in the shape the cmdlet returns (member as a
    # list of DNs, groupType as a signed Int32). $script:SmokeInventoryFail refuses them all (access denied).
    $stubInvAsked = @(@($stubNamed['Properties']) | ForEach-Object { [string]$_ })
    $stubInvFilter = [string]$stubNamed['LDAPFilter']
    $stubInvIdentity = [string]$stubNamed['Identity']
    # C4b: no directory read may ask for every attribute or name a secret one.
    foreach ($p in $stubInvAsked) { if ($p -match '[*?]' -or $script:SmokeAllSecretNames -contains $p) { throw ("STUB: a directory read asked for '{0}', which no read may request (PORT-PLAN C4b)" -f $p) } }
    # C4b: the Identity export, told apart by its declared filter AND its declared list (the user filter
    # is also the Inventory count filter). Users: an enabled one, a disabled one (514) and a service
    # account with two SPNs; computers: the DC, a workstation and a gMSA (a computer subclass). In the
    # shape the C15 seam receives: the default Name, DistinguishedName, ObjectClass and ObjectGUID, then
    # the requested LDAP names where set - objectSid a SecurityIdentifier, the times raw Int64 FILETIME,
    # whenCreated a DateTime. Each object also carries the seven secret LAPS attributes holding the
    # sentinel, as if the module had handed them back: none may reach a file.
    $stubExportKind = ''
    if ($stubInvFilter -eq [string]$script:Config.DirectoryRead['UserExportFilter'] -and ($stubInvAsked -join ',') -eq (@($script:Config.DirectoryRead['UserExportProperties']) -join ',')) { $stubExportKind = 'User' }
    if ($stubInvFilter -eq [string]$script:Config.DirectoryRead['ComputerExportFilter'] -and ($stubInvAsked -join ',') -eq (@($script:Config.DirectoryRead['ComputerExportProperties']) -join ',')) { $stubExportKind = 'Computer' }
    if ($stubExportKind -ne '') {
        $stubExportServer = [string]$stubNamed['Server']
        if ([string]::IsNullOrWhiteSpace($stubExportServer)) { throw 'STUB: the export read must name its domain' }
        $script:SmokeExportCalls += ("{0}@{1}#{2}" -f $stubExportKind, $stubExportServer, [string]$stubNamed['ResultSetSize'])
        if ($script:SmokeC4bFail) { throw [System.UnauthorizedAccessException]'STUB: export read refused' }
        $stubExportDn = 'DC=' + ($stubExportServer -replace '\.', ',DC=')
        $stubExportRows = @()
        if ($stubExportKind -eq 'User') {
            $stubExportRows = @(
                [pscustomobject]@{ DistinguishedName = ("CN=smoke.one,CN=Users,{0}" -f $stubExportDn); Name = 'smoke.one'; ObjectClass = 'user'; ObjectGUID = [guid]'11111111-0000-4000-8000-000000000001'; sAMAccountName = 'smoke.one'; userPrincipalName = ("smoke.one@{0}" -f $stubExportServer); userAccountControl = 512; objectSid = (New-Object System.Security.Principal.SecurityIdentifier 'S-1-5-21-1004336348-1177238915-682003330-1601'); whenCreated = $now.AddDays(-400); pwdLastSet = [int64]$now.AddDays(-30).ToFileTimeUtc() }
                [pscustomobject]@{ DistinguishedName = ("CN=smoke.two,CN=Users,{0}" -f $stubExportDn); Name = 'smoke.two'; ObjectClass = 'user'; ObjectGUID = [guid]'11111111-0000-4000-8000-000000000002'; sAMAccountName = 'smoke.two'; userAccountControl = 514; objectSid = (New-Object System.Security.Principal.SecurityIdentifier 'S-1-5-21-1004336348-1177238915-682003330-1602'); whenCreated = $now.AddDays(-900) }
                [pscustomobject]@{ DistinguishedName = ("CN=svc.smoke,CN=Users,{0}" -f $stubExportDn); Name = 'svc.smoke'; ObjectClass = 'user'; ObjectGUID = [guid]'11111111-0000-4000-8000-000000000003'; sAMAccountName = 'svc.smoke'; userAccountControl = 66048; servicePrincipalName = @('HTTP/app.contoso.com', 'HTTP/app'); whenCreated = $now.AddDays(-100) }
            )
        }
        else {
            $stubExportRows = @(
                [pscustomobject]@{ DistinguishedName = ("CN=DC1,OU=Domain Controllers,{0}" -f $stubExportDn); Name = 'DC1'; ObjectClass = 'computer'; ObjectGUID = [guid]'22222222-0000-4000-8000-000000000001'; sAMAccountName = 'DC1$'; dNSHostName = ("dc1.{0}" -f $stubExportServer); operatingSystem = 'Windows Server 2019 Standard'; operatingSystemVersion = '10.0 (17763)'; userAccountControl = 532480; primaryGroupID = 516 }
                [pscustomobject]@{ DistinguishedName = ("CN=WS1,CN=Computers,{0}" -f $stubExportDn); Name = 'WS1'; ObjectClass = 'computer'; ObjectGUID = [guid]'22222222-0000-4000-8000-000000000002'; sAMAccountName = 'WS1$'; dNSHostName = ("ws1.{0}" -f $stubExportServer); operatingSystem = 'Windows 11 Enterprise'; userAccountControl = 4096; primaryGroupID = 515 }
                [pscustomobject]@{ DistinguishedName = ("CN=gmsa1,CN=Managed Service Accounts,{0}" -f $stubExportDn); Name = 'gmsa1'; ObjectClass = 'msDS-GroupManagedServiceAccount'; ObjectGUID = [guid]'22222222-0000-4000-8000-000000000003'; sAMAccountName = 'gmsa1$'; userAccountControl = 4096; primaryGroupID = 515 }
            )
        }
        foreach ($stubExportRow in $stubExportRows) {
            foreach ($secretName in $script:SmokeLapsSecretNames) { $stubExportRow | Add-Member -NotePropertyName $secretName -NotePropertyValue $script:SmokeSecretSentinel }
        }
        return $stubExportRows
    }
    $stubInvCountKind = ''
    foreach ($k in @($script:Config.Inventory['CountFilters'].Keys)) { if ([string]$script:Config.Inventory['CountFilters'][$k] -eq $stubInvFilter) { $stubInvCountKind = [string]$k } }
    $stubInvTopology = ($stubInvAsked -contains 'fSMORoleOwner')
    $stubInvTrust = ($stubInvFilter -eq '(objectClass=trustedDomain)' -and $stubInvAsked -contains 'trustAttributes')
    $stubInvGpo = ($stubInvFilter -eq '(objectClass=groupPolicyContainer)' -and $stubInvAsked -contains 'gPCWQLFilter')
    $stubInvSom = ($stubInvFilter -eq '(gPLink=*)' -or $stubInvFilter -eq '(&(objectClass=site)(gPLink=*))')
    $stubInvWmi = ($stubInvFilter -eq '(objectClass=msWMI-Som)')
    if ($stubInvTopology -or $stubInvTrust -or $stubInvCountKind -ne '' -or $stubInvGpo -or $stubInvSom -or $stubInvWmi) {
        foreach ($p in $stubInvAsked) { if ($p -match '[*?]') { throw 'STUB: an inventory read asked for every attribute' } }
        if ([string]::IsNullOrWhiteSpace([string]$stubNamed['Server'])) { throw 'STUB: an inventory read must name its domain' }
        $stubInvWhat = $stubInvIdentity
        if ($stubInvWhat -eq '') { $stubInvWhat = $stubInvFilter }
        $script:SmokeInventoryCalls += ("{0}@{1}" -f $stubInvWhat, [string]$stubNamed['Server'])
        if ($script:SmokeInventoryFail) { throw [System.UnauthorizedAccessException]'STUB: inventory read refused' }
        $stubGpo0 = $script:SmokeGpoGuids[0]
        $stubGpo1 = $script:SmokeGpoGuids[1]
        if ($stubInvTopology) {
            $stubTopo = [pscustomobject]@{ DistinguishedName = $stubInvIdentity; Name = ($stubInvIdentity -replace '^(?:CN|DC)=([^,]+),?.*$', '$1'); ObjectClass = 'container'
                fSMORoleOwner = 'CN=NTDS Settings,CN=DC1,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=contoso,DC=com' }
            if ($stubInvAsked -contains 'msDS-Behavior-Version') { $stubTopo | Add-Member -NotePropertyName 'msDS-Behavior-Version' -NotePropertyValue 7 }
            if ($stubInvAsked -contains 'uPNSuffixes') { $stubTopo | Add-Member -NotePropertyName 'uPNSuffixes' -NotePropertyValue @('contoso.net') }
            return $stubTopo
        }
        if ($stubInvTrust) {
            if ([string]$stubNamed['Server'] -ne 'contoso.com') { return }
            return [pscustomobject]@{ DistinguishedName = 'CN=fabrikam.com,CN=System,DC=contoso,DC=com'; Name = 'fabrikam.com'; ObjectClass = 'trustedDomain'; cn = 'fabrikam.com'
                trustPartner = 'fabrikam.com'; flatName = 'FABRIKAM'; trustAttributes = 8; trustDirection = 3; trustType = 2 }
        }
        if ($stubInvCountKind -ne '') {
            switch ($stubInvCountKind) {
                'Users' { return @(foreach ($u in @(@('smoke.one', 512), @('smoke.two', 514), @('smoke.three', 66048))) { [pscustomobject]@{ DistinguishedName = ("CN={0},CN=Users,DC=contoso,DC=com" -f $u[0]); Name = $u[0]; ObjectClass = 'user'; userAccountControl = $u[1] } }) }
                'Computers' { return @(foreach ($c in @(@('DC1', 532480), @('WS-RETIRED', 4098))) { [pscustomobject]@{ DistinguishedName = ("CN={0},CN=Computers,DC=contoso,DC=com" -f $c[0]); Name = $c[0]; ObjectClass = 'computer'; userAccountControl = $c[1] } }) }
                'Groups' {
                    return @(
                        [pscustomobject]@{ DistinguishedName = 'CN=Smoke-Staff,CN=Users,DC=contoso,DC=com'; Name = 'Smoke-Staff'; ObjectClass = 'group'; sAMAccountName = 'Smoke-Staff'; groupType = -2147483646; member = @('CN=smoke.one,CN=Users,DC=contoso,DC=com', 'CN=smoke.two,CN=Users,DC=contoso,DC=com') }
                        [pscustomobject]@{ DistinguishedName = 'CN=Smoke-Empty,CN=Users,DC=contoso,DC=com'; Name = 'Smoke-Empty'; ObjectClass = 'group'; sAMAccountName = 'Smoke-Empty'; groupType = -2147483644 }
                        [pscustomobject]@{ DistinguishedName = 'CN=Smoke-List,CN=Users,DC=contoso,DC=com'; Name = 'Smoke-List'; ObjectClass = 'group'; sAMAccountName = 'Smoke-List'; groupType = 8; member = @('CN=smoke.one,CN=Users,DC=contoso,DC=com') }
                    )
                }
                'Contacts' { return [pscustomobject]@{ DistinguishedName = 'CN=Ext Contact,CN=Users,DC=contoso,DC=com'; Name = 'Ext Contact'; ObjectClass = 'contact' } }
                'OUs' { return @([pscustomobject]@{ DistinguishedName = 'OU=Domain Controllers,DC=contoso,DC=com'; Name = 'Domain Controllers'; ObjectClass = 'organizationalUnit' }, [pscustomobject]@{ DistinguishedName = 'OU=Staff,DC=contoso,DC=com'; Name = 'Staff'; ObjectClass = 'organizationalUnit' }) }
            }
            return
        }
        # C15 review: each domain's GPOs and SOMs carry that domain's DN, as the directory does; the two
        # default GPOs have the same GUID in every domain. In the three-domain pass north.contoso.com links
        # its Default Domain Controllers Policy from nowhere of its own: an OU of south.contoso.com links
        # it (disabled link), which only a read of the other domains' SOMs can see.
        $stubInvServer = [string]$stubNamed['Server']
        $stubInvDn = 'DC=' + ($stubInvServer -replace '\.', ',DC=')
        if ($stubInvGpo) {
            return @(
                [pscustomobject]@{ DistinguishedName = ("CN={0},CN=Policies,CN=System,{1}" -f $stubGpo0, $stubInvDn); Name = $stubGpo0; ObjectClass = 'groupPolicyContainer'; displayName = 'Default Domain Policy'; flags = 0; versionNumber = 65537 }
                [pscustomobject]@{ DistinguishedName = ("CN={0},CN=Policies,CN=System,{1}" -f $stubGpo1, $stubInvDn); Name = $stubGpo1; ObjectClass = 'groupPolicyContainer'; displayName = 'Default Domain Controllers Policy'; flags = 1; versionNumber = 65537; gPCWQLFilter = ('[{0};{{A1B2C3D4-0000-4000-8000-0000000000AA}};0]' -f $stubInvServer) }
            )
        }
        if ($stubInvFilter -eq '(gPLink=*)') {
            $stubSoms = @([pscustomobject]@{ DistinguishedName = $stubInvDn; Name = ($stubInvServer -split '\.')[0]; objectClass = @('top', 'domain', 'domainDNS'); gPLink = ("[LDAP://cn={0},cn=policies,cn=system,{1};0]" -f $stubGpo0, $stubInvDn); gPOptions = 0 })
            if ($stubInvServer -ne 'north.contoso.com') {
                $stubSoms += [pscustomobject]@{ DistinguishedName = ("OU=Domain Controllers,{0}" -f $stubInvDn); Name = 'Domain Controllers'; objectClass = @('top', 'organizationalUnit'); gPLink = ("[LDAP://cn={0},cn=policies,cn=system,{1};2]" -f $stubGpo1, $stubInvDn) }
            }
            if ($stubInvServer -eq 'south.contoso.com') {
                $stubSoms += [pscustomobject]@{ DistinguishedName = ("OU=Branch,{0}" -f $stubInvDn); Name = 'Branch'; objectClass = @('top', 'organizationalUnit'); gPLink = ("[LDAP://cn={0},cn=policies,cn=system,DC=north,DC=contoso,DC=com;1]" -f $stubGpo1) }
            }
            return $stubSoms
        }
        if ($stubInvWmi) { return [pscustomobject]@{ DistinguishedName = 'CN={A1B2C3D4-0000-4000-8000-0000000000AA},CN=SOM,CN=WMIPolicy,CN=System,DC=contoso,DC=com'; Name = '{A1B2C3D4-0000-4000-8000-0000000000AA}'; ObjectClass = 'msWMI-Som'; 'msWMI-Name' = 'Smoke servers only' } }
        # The sites: no site links a GPO.
        return
    }
    # C13 (the DNS scenario only, $script:SmokeDnsDsa): DC1's NTDS Settings object under the configuration
    # partition, as Get-AdfaDsaInventory searches for it, and its server object with dNSHostName. Every
    # other pass keeps the answer it had.
    if ($script:SmokeDnsDsa -and [string]$stubNamed['LDAPFilter'] -eq '(objectClass=nTDSDSA)' -and [string]$stubNamed['SearchBase'] -eq 'CN=Configuration,DC=contoso,DC=com') {
        return [pscustomobject]@{ DistinguishedName = 'CN=NTDS Settings,CN=DC1,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=contoso,DC=com'; ObjectClass = 'nTDSDSA'
            objectGUID = [guid]$script:SmokeDsaGuid; invocationId = [guid]'99999999-0000-4000-8000-000000000001' }
    }
    if ($script:SmokeDnsDsa -and [string]$stubNamed['Identity'] -eq 'CN=DC1,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=contoso,DC=com') {
        return [pscustomobject]@{ DistinguishedName = [string]$stubNamed['Identity']; ObjectClass = 'server'; dNSHostName = 'dc1.contoso.com' }
    }
    # C14 (SYSVOL-004): the DFSR global settings (msDFSR-Flags 48, Eliminated), each DC's DFSR SYSVOL
    # subscription (present) and its NTFRS subscriber (not found, thrown as the module's identity-not-
    # found type), each read from the domain named by -Server, never without one.
    $stubIdentity = [string]$stubNamed['Identity']
    if ($stubIdentity -like 'CN=DFSR-GlobalSettings,CN=System,*' -or $stubIdentity -like 'CN=SYSVOL Subscription,CN=Domain System Volume,CN=DFSR-LocalSettings,*' -or $stubIdentity -like 'CN=Domain System Volume (SYSVOL share),CN=NTFRS Subscriptions,*') {
        if ([string]::IsNullOrWhiteSpace([string]$stubNamed['Server'])) { throw 'STUB: a SYSVOL engine object must be read from its own domain' }
        # PORT-PLAN C16d(b): $script:SmokeFrsOnlyDomain names a domain whose SYSVOL is still replicated by FRS: its DC has
        # an NTFRS subscriber and no DFSR SYSVOL subscription, and no DFSR global settings object exists.
        if (-not [string]::IsNullOrWhiteSpace($script:SmokeFrsOnlyDomain) -and [string]$stubNamed['Server'] -eq $script:SmokeFrsOnlyDomain) {
            if ($stubIdentity -like 'CN=Domain System Volume (SYSVOL share),*') { return [pscustomobject]@{ DistinguishedName = $stubIdentity; ObjectClass = 'nTFRSSubscriber' } }
            throw (New-Object SmokeStub.ADIdentityNotFoundException ("Cannot find an object with identity: '{0}'" -f $stubIdentity))
        }
        if ($stubIdentity -like 'CN=Domain System Volume (SYSVOL share),*') { throw (New-Object SmokeStub.ADIdentityNotFoundException ("Cannot find an object with identity: '{0}'" -f $stubIdentity)) }
        if ($stubIdentity -like 'CN=DFSR-GlobalSettings,*') { return [pscustomobject]@{ DistinguishedName = $stubIdentity; ObjectClass = 'msDFSR-GlobalSettings'; 'msDFSR-Flags' = 48 } }
        # The subscription as Get-ADObject returns it when msDFSR-Enabled is asked for and set TRUE: since
        # the independent review of the C16 diff (findings 6/10) a value not returned is no longer taken
        # as TRUE, so the stub returns what it is asked for.
        $stubSub = [pscustomobject]@{ DistinguishedName = $stubIdentity; ObjectClass = 'msDFSR-Subscription' }
        if (@($stubNamed['Properties']) -contains 'msDFSR-Enabled') { $stubSub | Add-Member -NotePropertyName 'msDFSR-Enabled' -NotePropertyValue $true }
        return $stubSub
    }
    # C10: told apart by what they ask for - the member and delegation property lists hold
    # primaryGroupID, no other section's does - and by the configuration searches under CN=Sites and
    # the read of CN=Directory Service.
    $stubPrivAsked = @(@($stubNamed['Properties']) | ForEach-Object { [string]$_ })
    if ($stubPrivAsked -contains 'primaryGroupID' -or [string]$stubNamed['SearchBase'] -like 'CN=Sites,*' -or [string]$stubNamed['Identity'] -like 'CN=Directory Service,*') {
        return (Get-StubPrivAnswer -Named $stubNamed -Asked $stubPrivAsked)
    }
    # C7: the principals with sIDHistory of the domain named by -Server, and its trusted domains.
    if ([string]$stubNamed['LDAPFilter'] -eq '(sIDHistory=*)') {
        if ($script:SmokeSidHistoryFail) { throw [System.UnauthorizedAccessException]'STUB: sIDHistory query refused' }
        $shAsked = @($stubNamed['Properties'] | ForEach-Object { [string]$_ })
        foreach ($p in $shAsked) {
            if ($p -match '[*?]' -or $script:SmokeSidHistoryAllowed -notcontains $p) { throw ("STUB: the SID history query asked for '{0}', which it does not declare" -f $p) }
        }
        if (-not [string]::IsNullOrWhiteSpace([string]$stubNamed['SearchBase'])) { throw 'STUB: the SID history query must search the whole domain' }
        switch ([string]$stubNamed['Server']) {
            'contoso.com' {
                return @(
                    (New-StubSidHistoryPrincipal -Sam 'mig.user1' -Class 'user' -Domain 'contoso.com' -Rid '1601' -Uac 512 -Asked $shAsked -History @(("{0}-1105" -f $script:SmokeFabrikamSid)))
                    (New-StubSidHistoryPrincipal -Sam 'mig.group1' -Class 'group' -Domain 'contoso.com' -Rid '1602' -Asked $shAsked -History @(("{0}-1200" -f $script:SmokeDomainSids['north.contoso.com'])))
                    (New-StubSidHistoryPrincipal -Sam 'ws-mig$' -Class 'computer' -Domain 'contoso.com' -Rid '1603' -Uac 4098 -Asked $shAsked -History @(("{0}-1300" -f $script:SmokeLostSid)))
                )
            }
            'north.contoso.com' {
                return (New-StubSidHistoryPrincipal -Sam 'svc.north' -Class 'user' -Domain 'north.contoso.com' -Rid '1700' -Uac 512 -Asked $shAsked -AsText `
                        -History @(("{0}-1500" -f $script:SmokeDomainSids['north.contoso.com']), ("{0}-519" -f $script:SmokeDomainSids['contoso.com'])))
            }
        }
        return
    }
    if ([string]$stubNamed['LDAPFilter'] -eq '(objectClass=trustedDomain)') {
        foreach ($p in @($stubNamed['Properties'])) { if ([string]$p -match '[*?]') { throw 'STUB: the trust query asked for every attribute' } }
        if ([string]$stubNamed['SearchBase'] -ne 'CN=System,DC=contoso,DC=com') { throw ("STUB: trusted domain objects are under CN=System, not '{0}'" -f [string]$stubNamed['SearchBase']) }
        if ([string]$stubNamed['Server'] -eq 'contoso.com') {
            return [pscustomobject]@{ DistinguishedName = 'CN=fabrikam.com,CN=System,DC=contoso,DC=com'; Name = 'fabrikam.com'; ObjectClass = 'trustedDomain'; ObjectGUID = [guid]::NewGuid()
                trustPartner = 'fabrikam.com'; flatName = 'FABRIKAM'; securityIdentifier = (New-StubSidBytes -Sid $script:SmokeFabrikamSid) }
        }
        return
    }
    # C9: a security descriptor read - the domain head, AdminSDHolder, or the GPO search - told apart
    # from the C8 version read by what it asks for.
    if (@(@($stubNamed['Properties']) | ForEach-Object { [string]$_ }) -contains 'nTSecurityDescriptor') {
        $aclAsked = @(@($stubNamed['Properties']) | ForEach-Object { [string]$_ })
        if (($aclAsked -join ',') -ne 'nTSecurityDescriptor') { throw ("STUB: the security descriptor read asked for '{0}', not nTSecurityDescriptor alone" -f ($aclAsked -join ',')) }
        $aclServer = [string]$stubNamed['Server']
        if (-not $script:SmokeDomainSids.ContainsKey($aclServer)) { throw ("STUB: a security descriptor must be read from its own domain, not from '{0}'" -f $aclServer) }
        $aclTarget = [string]$stubNamed['Identity']
        if ([string]$stubNamed['LDAPFilter'] -ne '') { $aclTarget = ("search {0} {1}" -f [string]$stubNamed['SearchBase'], [string]$stubNamed['SearchScope']) }
        $script:SmokeAclCalls += ("{0}@{1}" -f $aclTarget, $aclServer)
        if ($script:SmokeAclUnreachable) { throw 'Unable to contact the server. This may be because this server does not exist, it is currently down, or it does not have the Active Directory Web Services running.' }
        if ($script:SmokeAclFail) { throw [System.UnauthorizedAccessException]'STUB: security descriptor read refused' }
        if ([string]$stubNamed['LDAPFilter'] -eq '(objectClass=groupPolicyContainer)') {
            if ([string]$stubNamed['SearchBase'] -ne 'CN=Policies,CN=System,DC=contoso,DC=com' -or [string]$stubNamed['SearchScope'] -ne 'OneLevel') { throw 'STUB: the GPO descriptors are one level under CN=Policies,CN=System' }
            return @(foreach ($aclGuid in $script:SmokeGpoGuids) {
                    [pscustomobject]@{ DistinguishedName = ("CN={0},CN=Policies,CN=System,DC=contoso,DC=com" -f $aclGuid); Name = $aclGuid; ObjectClass = 'groupPolicyContainer'; ObjectGUID = [guid]::NewGuid()
                        nTSecurityDescriptor = [pscustomobject]@{ SmokeSdKind = 'Gpo'; SmokeDomain = $aclServer } }
                })
        }
        $aclKind = ''
        if ($aclTarget -eq 'DC=contoso,DC=com') { $aclKind = 'Head' }
        elseif ($aclTarget -eq 'CN=AdminSDHolder,CN=System,DC=contoso,DC=com') { $aclKind = 'AdminSDHolder' }
        else { throw ("STUB: no security descriptor stubbed for '{0}'" -f $aclTarget) }
        return [pscustomobject]@{ DistinguishedName = $aclTarget; Name = $aclKind; ObjectClass = 'container'; ObjectGUID = [guid]::NewGuid()
            nTSecurityDescriptor = [pscustomobject]@{ SmokeSdKind = $aclKind; SmokeDomain = $aclServer } }
    }
    # C8: the groupPolicyContainer objects, one level under CN=Policies,CN=System, read from the PDC.
    if ([string]$stubNamed['LDAPFilter'] -eq '(objectClass=groupPolicyContainer)') {
        if ($script:SmokeGpoFail) { throw [System.UnauthorizedAccessException]'STUB: groupPolicyContainer query refused' }
        $gpoAsked = @($stubNamed['Properties'] | ForEach-Object { [string]$_ })
        foreach ($p in $gpoAsked) {
            if ($p -match '[*?]' -or $script:SmokeGpoAllowed -notcontains $p) { throw ("STUB: the GPO query asked for '{0}', which it does not declare" -f $p) }
        }
        if ([string]$stubNamed['SearchBase'] -ne 'CN=Policies,CN=System,DC=contoso,DC=com') { throw ("STUB: GPO containers are under CN=Policies,CN=System, not '{0}'" -f [string]$stubNamed['SearchBase']) }
        if ([string]$stubNamed['SearchScope'] -ne 'OneLevel') { throw 'STUB: the GPO container search must be one level' }
        if ([string]$stubNamed['Server'] -ne 'dc1.contoso.com') { throw ("STUB: the GPO containers must be read from the PDC emulator, not '{0}'" -f [string]$stubNamed['Server']) }
        $gpoDomain = $script:SmokeGpoLastDomain
        $secondVersion = 65537
        if ($gpoDomain -eq 'north.contoso.com') { $secondVersion = 131073 }
        return @(
            (New-StubGpoContainer -Guid $script:SmokeGpoGuids[0] -Domain $gpoDomain -DisplayName 'Default Domain Policy' -Version 65537 -Asked $gpoAsked)
            (New-StubGpoContainer -Guid $script:SmokeGpoGuids[1] -Domain $gpoDomain -DisplayName 'Default Domain Controllers Policy' -Version $secondVersion -Asked $gpoAsked)
        )
    }
    # C6: CN=RID Manager$ of the domain named by -Server, with the one attribute asked for.
    if ($stubNamed.ContainsKey('Identity') -and [string]$stubNamed['Identity'] -match '^CN=RID Manager\$,CN=System,') {
        if ($script:SmokeRidFail) { throw 'STUB: RID Manager read refused' }
        $ridState = $script:SmokeRidDomains[[string]$stubNamed['Server']]
        if ($null -eq $ridState) { throw ("STUB: no RID Manager stubbed for server '{0}'" -f [string]$stubNamed['Server']) }
        $ridManager = [pscustomobject]@{ DistinguishedName = [string]$stubNamed['Identity']; ObjectClass = 'rIDManager' }
        $ridAsked = @($stubNamed['Properties'])
        if ($ridAsked -contains 'rIDAvailablePool') { $ridManager | Add-Member -NotePropertyName 'rIDAvailablePool' -NotePropertyValue ([int64]$ridState['Pool']) }
        if ($ridAsked -contains 'msDS-RIDPoolAllocationEnabled' -and $null -ne $ridState['Allocation']) { $ridManager | Add-Member -NotePropertyName 'msDS-RIDPoolAllocationEnabled' -NotePropertyValue ([bool]$ridState['Allocation']) }
        return $ridManager
    }
    # C6: the RID Set by the DN rIDSetReferences named, and the one-level search under the computer.
    if ($stubNamed.ContainsKey('Identity') -and [string]$stubNamed['Identity'] -match '^CN=RID Set,') { return (New-StubRidSet -Dn ([string]$stubNamed['Identity'])) }
    if ([string]$stubNamed['LDAPFilter'] -eq '(objectClass=rIDSet)') {
        if ([string]$stubNamed['SearchScope'] -ne 'OneLevel') { throw 'STUB: the RID Set search must be one level' }
        if ($script:SmokeRidSetAbsent) { return }
        return (New-StubRidSet -Dn ("CN=RID Set,{0}" -f [string]$stubNamed['SearchBase']))
    }
    if ($stubAsked -match 'lDAPDisplayName=') {
        if ($script:SmokeLapsFail) { throw 'STUB: schema query refused' }
        foreach ($schemaName in @(@($script:SmokeLapsSchema) + @($script:SmokeRidSchema))) {
            if ($stubAsked -match ("\(lDAPDisplayName={0}\)" -f [regex]::Escape($schemaName))) {
                [pscustomobject]@{ DistinguishedName = ("CN={0},CN=Schema,CN=Configuration,DC=contoso,DC=com" -f $schemaName); ObjectClass = 'attributeSchema'; lDAPDisplayName = $schemaName }
            }
        }
        return
    }
    [pscustomobject]@{ tombstoneLifetime=180; 'ms-DS-MachineAccountQuota'=0; rangeUpper=15334; whenChanged=$now
        'msDS-Behavior-Version'=7 } }
# No verification tools on this host -> trust health should degrade to Not Assessed honestly.
# C11: dcdiag.exe is the one exception, so the DC Diagnostics section is exercised end to end
# through the dcdiag stub below; every other tool stays absent.
# C13: Resolve-DnsName is present only in the DNS scenario ($script:SmokeDnsResolver), so every other pass
# keeps the shape it had: no DNS query tool on this host.
$script:SmokeDnsResolver = $false
# PORT-PLAN C16d(b): no domain is FRS-only except in the FRS pass.
$script:SmokeFrsOnlyDomain = ''
# PORT-PLAN C2e: repadmin.exe is present only in the per-domain pass ($script:SmokeRepadmin), where it answers /showbackup.
$script:SmokeRepadmin = $false
$script:SmokeRepadminCalls = @()
function Test-CommandAvailable { param([string]$Name) return ($Name -eq 'dcdiag.exe' -or ($script:SmokeDnsResolver -and $Name -eq 'Resolve-DnsName') -or ($script:SmokeW32tm -and $Name -eq 'w32tm.exe') -or ($script:SmokeRepadmin -and $Name -eq 'repadmin.exe') -or ($script:SmokeSmbCmdlet -and $Name -eq 'Get-SmbServerConfiguration')) }
# C11 (DcDiagnostics): dcdiag, answered in the shape the dcdiag command reference prints (Learn,
# read 2026-11-16): a banner, the initial Connectivity block under "Testing server: <site>\<DC>",
# then the test's own block. CheckSDRefDom and CrossRefValidation answer one verdict per partition
# under "Running partition tests on : <NC>" (Configuration wrapped onto two lines, as in Learn's
# sample); Intersite answers under "Running enterprise tests on : contoso.com". Every argument string
# is recorded with its time-out. Any call that is not dcdiag is refused, so a section that started
# another tool through this seam would fail here rather than appear to work.
# $script:SmokeDcdiagMode: 'Pass' (every verdict passed); 'Localised' (output in a form this build
# does not read); 'PartitionFail' (CrossRefValidation fails the Configuration partition only).
$script:SmokeDcdiagMode = 'Pass'
$script:SmokeDcdiagCalls = @()
function New-StubDcdiagOutput { param([string]$Dc, [string]$Test, [string]$Mode)
    if ($Mode -eq 'Localised') { return ("Diagnostico do Servidor de Diretorio`r`n......................... {0} passou no teste {1}" -f $Dc, $Test) }
    $b = New-Object System.Collections.Generic.List[string]
    foreach ($l in @('Directory Server Diagnosis', '', 'Performing initial setup:', ("   Home Server = {0}" -f $Dc), '', 'Doing initial required tests', '',
            ("   Testing server: Default-First-Site-Name\{0}" -f $Dc), '      Starting test: Connectivity', ("         ......................... {0} passed test Connectivity" -f $Dc), '', 'Doing primary tests', '')) { $b.Add($l) }
    if (@('CheckSDRefDom', 'CrossRefValidation') -contains $Test) {
        foreach ($p in @('ForestDnsZones', 'DomainDnsZones', 'Schema', 'Configuration', 'contoso')) {
            $v = 'passed'
            if ($Mode -eq 'PartitionFail' -and $Test -eq 'CrossRefValidation' -and $p -eq 'Configuration') { $v = 'failed' }
            $b.Add(("   Running partition tests on : {0}" -f $p)); $b.Add(("      Starting test: {0}" -f $Test))
            if ($p -eq 'Configuration') { $b.Add(("         ......................... {0} {1} test " -f $p, $v)); $b.Add(("         {0}" -f $Test)) }
            else { $b.Add(("         ......................... {0} {1} test {2}" -f $p, $v, $Test)) }
        }
    }
    elseif (@('Intersite', 'FsmoCheck') -contains $Test) {
        # FsmoCheck is one of dcdiag's enterprise tests: its verdict is printed under the
        # enterprise block with the forest as subject (field captures; Learn's sample shows the
        # same for LocatorCheck and Intersite), and it counts for the DC asked.
        $b.Add('   Running enterprise tests on : contoso.com'); $b.Add(("      Starting test: {0}" -f $Test)); $b.Add('         ......................... contoso.com passed test '); $b.Add(("         {0}" -f $Test))
    }
    elseif ($Test -eq 'DNS') {
        # C12: the DNS test answers in the server block and then the enterprise block, with the
        # summary table in the layout of Learn's only sample (KB 2102154, read 2026-11-16): the
        # header "Auth Basc Forw Del  Dyn  RReg Ext", a "Domain:" line, the DC's row of
        # $script:SmokeDnsCells, then "Enterprise DNS infrastructure test results:" and the verdict.
        $dnsVerdict = 'passed'
        if ($script:SmokeDnsCells -match 'FAIL') { $dnsVerdict = 'failed' }
        foreach ($l in @(("   Testing server: Default-First-Site-Name\{0}" -f $Dc), '      Starting test: DNS', '         DNS Tests are running and not hung. Please wait a few minutes...',
                ("         ......................... {0} passed test DNS" -f $Dc), '', '   Running enterprise tests on : contoso.com', '      Starting test: DNS',
                '         Test results for domain controllers:', ("            DC: {0}" -f $Dc), '', '         Summary of DNS test results:', '',
                '                                            Auth Basc Forw Del  Dyn  RReg Ext', '', '            Domain: contoso.com',
                ("               {0,-25} {1}  " -f $Dc, $script:SmokeDnsCells), '', '         Enterprise DNS infrastructure test results:',
                ("         ......................... contoso.com {0} test DNS" -f $dnsVerdict))) { $b.Add($l) }
    }
    elseif ($Test -ne 'Connectivity') {
        $b.Add(("   Testing server: Default-First-Site-Name\{0}" -f $Dc)); $b.Add(("      Starting test: {0}" -f $Test))
        # C11h: 'GridFail' fails MachineAccount with the lines of Microsoft's 8453 sample, whose words
        # ("delegation", "replicate") used to choose the unscoped delegation advice.
        if ($Mode -eq 'GridFail' -and $Test -eq 'MachineAccount') {
            $b.Add(("         The account {0} is not trusted for delegation . It cannot replicate." -f $Dc)); $b.Add(("         ......................... {0} failed test {1}" -f $Dc, $Test))
        }
        else { $b.Add(("         ......................... {0} passed test {1}" -f $Dc, $Test)) }
    }
    return ($b -join "`r`n")
}
# C12: the cells of the stub DC's row in the DNS summary table, in the column order of Learn's sample.
$script:SmokeDnsCells = 'PASS PASS PASS PASS PASS PASS n/a'
# PORT-PLAN H20a (review fix): the script also starts nltest.exe directly, inside the script block it
# runs on a DC over WinRM, and that path never reaches the Invoke-ExternalCommand stub. Invoke-Command is
# stubbed to record the script block and its ArgumentList, then to throw as an unanswered WinRM endpoint
# does - which is what the real cmdlet did against these fictional names before this stub existed, so no
# row changes. Each console tool is also stubbed as a function, so a tool started directly in this
# process is recorded instead of run.
$script:SmokeRemoteCalls = @()
function Invoke-Command {
    param([string]$ComputerName, [scriptblock]$ScriptBlock, [object[]]$ArgumentList, [pscredential]$Credential, $ErrorAction)
    $script:SmokeRemoteCalls += [pscustomobject]@{ ComputerName = $ComputerName; ScriptBlock = ([string]$ScriptBlock).Trim(); Arguments = (@($ArgumentList) -join ' ') }
    throw ("STUB: WinRM on {0} is not answered by this harness" -f $ComputerName)
}
$script:SmokeDirectToolCalls = @()
function nltest.exe { $script:SmokeDirectToolCalls += ('nltest.exe {0}' -f ($args -join ' ')) }
function dcdiag.exe { $script:SmokeDirectToolCalls += ('dcdiag.exe {0}' -f ($args -join ' ')) }
function repadmin.exe { $script:SmokeDirectToolCalls += ('repadmin.exe {0}' -f ($args -join ' ')) }
function w32tm.exe { $script:SmokeDirectToolCalls += ('w32tm.exe {0}' -f ($args -join ' ')) }
function dfsrmig.exe { $script:SmokeDirectToolCalls += ('dfsrmig.exe {0}' -f ($args -join ' ')) }
function nslookup.exe { $script:SmokeDirectToolCalls += ('nslookup.exe {0}' -f ($args -join ' ')) }
function netdom.exe { $script:SmokeDirectToolCalls += ('netdom.exe {0}' -f ($args -join ' ')) }
$script:SmokeExternalCalls = @()
function Invoke-ExternalCommand {
    param([string]$FilePath, [string]$Arguments, [string]$OutFile, [int]$TimeoutSeconds, [int]$Retries, [int]$RetryDelaySeconds)
    # H20a: every external tool a pass asks for, answered or not, recorded before anything else.
    $script:SmokeExternalCalls += ('{0} {1}' -f $FilePath, $Arguments)
    if ($script:SmokeW32tm -and $FilePath -eq 'w32tm.exe') {
        # C14: read-only w32tm forms only; any other switch fails the run here.
        # PORT-PLAN C14c: the local read-only queries of the TimeSync section are answered too, and not
        # recorded as a call to a DC.
        if ($Arguments -match '^/query /(source|status|configuration)\s*$') { return [pscustomobject]@{ Success = $true; ExitCode = 0; Attempt = 1; Error = $null; OutFile = $OutFile; StdOut = 'dc1.contoso.com' } }
        if ($Arguments -notmatch '^/(stripchart|query) /computer:\S+') { throw ("STUB: w32tm asked for '{0}', which this harness does not answer" -f $Arguments) }
        $script:SmokeW32tmCalls += $Arguments
        $w32Out = 'time.contoso.com,0x8'
        if ($Arguments -match '^/stripchart /computer:(\S+)') {
            $w32Offset = '0.500'
            if ($Matches[1] -like 'dc2.*') { $w32Offset = '400.500' }
            $w32Out = ("Tracking {0} [192.0.2.10:123].`r`nRdtscStart,RdtscEnd,FileTime,RoundtripDelay,NtpOffset`r`n1,2,3,0.020,{1}`r`n1,2,3,0.020,{1}`r`n1,2,3,0.020,{1}" -f $Matches[1], $w32Offset)
        }
        elseif ($Arguments -match '/configuration') { $w32Out = "Type: NTP (Local)`r`nNtpServer: time.contoso.com,0x8 (Local)" }
        return [pscustomobject]@{ Success = $true; ExitCode = 0; Attempt = 1; Error = $null; OutFile = $OutFile; StdOut = $w32Out }
    }
    if ($script:SmokeRepadmin -and $FilePath -eq 'repadmin.exe') {
        # PORT-PLAN C2e: /showbackup answered; the other read-only forms the Replication section asks for
        # (/showrepl, /replsummary) are answered as a failed run, and any form that writes fails the run here.
        if ($Arguments -match '(?i)/(removelingeringobjects|replicate|syncall|kcc|options|add|del|mod)\b') { throw ("STUB: repadmin asked for '{0}', which is not a read" -f $Arguments) }
        if ($Arguments -notmatch '^/showbackup \S+$') { return [pscustomobject]@{ Success = $false; ExitCode = 1; Attempt = 1; Error = 'STUB: not answered by this harness'; OutFile = $OutFile; StdOut = '' } }
        $script:SmokeRepadminCalls += $Arguments
        return [pscustomobject]@{ Success = $true; ExitCode = 0; Attempt = 1; Error = $null; OutFile = $OutFile; StdOut = ("CN=Configuration,DC=contoso,DC=com
  Last backup: {0:yyyy-MM-dd HH:mm:ss}" -f $now.AddDays(-2)) }
    }
    if ($FilePath -ne 'dcdiag.exe') { throw ("STUB: only dcdiag.exe is answered by this harness, not {0}" -f $FilePath) }
    $script:SmokeDcdiagCalls += [pscustomobject]@{ Arguments = $Arguments; Timeout = $TimeoutSeconds; Retries = $Retries }
    $test = ([regex]::Match($Arguments, '/test:(\S+)')).Groups[1].Value
    $server = ([regex]::Match($Arguments, '/s:(\S+)')).Groups[1].Value
    $dc = $server.Split('.')[0].ToUpperInvariant()
    # PORT-PLAN C11f: 'Timeout' answers Replications and Advertising as the real seam does after its last attempt
    # at an invocation that did not exit in time (Success $false, no exit code, "Timeout after <n>s", no output).
    if ($script:SmokeDcdiagMode -eq 'Timeout' -and @('Replications', 'Advertising') -contains $test) {
        return [pscustomobject]@{ Success = $false; ExitCode = $null; Attempt = $Retries; Error = ("Timeout after {0}s" -f $TimeoutSeconds); OutFile = $OutFile; StdOut = '' }
    }
    $exit = 0
    if ($script:SmokeDcdiagMode -eq 'PartitionFail' -and $test -eq 'CrossRefValidation') { $exit = 1 }
    [pscustomobject]@{ Success = ($exit -eq 0); ExitCode = $exit; Attempt = 1; Error = $null; OutFile = $OutFile
        StdOut = (New-StubDcdiagOutput -Dc $dc -Test $test -Mode $script:SmokeDcdiagMode) }
}
# C13: the DnsServer module is present only in the DNS scenario ($script:SmokeDnsModule); every other pass
# keeps "no optional module", so DNS Health says the module is missing.
$script:SmokeDnsModule = $false
function Test-ModuleAvailable { param([string]$Name) return ($script:SmokeDnsModule -and $Name -eq 'DnsServer') }
# C13: the DnsServer cmdlets, in the shape the CIM classes return (property names as the config table
# lists them; Learn does not publish the output properties). One DNS server, dc1.contoso.com: the forest
# zone with NONSECURE dynamic update, the _msdcs zone Secure, an auto-created reverse zone, a conditional
# forwarder zone. Scavenging every 7 days, aging on. The _msdcs zone holds the two locator SRV records
# (the _ldap one also naming a removed DC), dc1's DSA CNAME and one CNAME of a DSA that no longer exists;
# the forest zone holds dc1's A record. Each zone carries its apex NS record and no delegation, which the
# server read checks before it reads a name (C13 review: a name below a delegation is never read). A -Name with no such record throws the WIN32 9714 text this tool
# reads as "no such record" (provisional: the real error is not published). Every call is recorded.
$script:SmokeDnsCalls = @()
$script:SmokeDnsDsa = $false
$script:SmokeDsaGuid = '0f0e0d0c-0b0a-4909-8807-060504030201'
$script:SmokeOrphanGuid = '1a2b3c4d-0000-4000-8000-00000000abcd'
function New-StubDnsZone { param([string]$Name, [string]$Dyn, [bool]$Ds = $true, [string]$Type = 'Primary', [bool]$Auto = $false, [string]$Scope = 'Domain')
    [pscustomobject]@{ ZoneName = $Name; ZoneType = $Type; IsAutoCreated = $Auto; IsDsIntegrated = $Ds; IsReverseLookupZone = ($Name -like '*.arpa')
        DynamicUpdate = $Dyn; ReplicationScope = $Scope; SecureSecondaries = 'NoTransfer' } }
function New-StubDnsRecord { param([string]$HostName, [string]$Type, [hashtable]$Data)
    [pscustomobject]@{ HostName = $HostName; RecordType = $Type; RecordClass = 'IN'; TimeToLive = [timespan]::FromMinutes(10); Timestamp = $null; RecordData = [pscustomobject]$Data } }
$script:SmokeDnsRecords = @{
    'contoso.com'        = @((New-StubDnsRecord 'dc1' 'A' @{ IPv4Address = '192.0.2.10' }), (New-StubDnsRecord '@' 'NS' @{ NameServer = 'dc1.contoso.com.' }))
    '_msdcs.contoso.com' = @((New-StubDnsRecord '_ldap._tcp.dc' 'SRV' @{ DomainName = 'dc1.contoso.com.'; Port = [uint16]389; Priority = [uint16]0; Weight = [uint16]100 }),
        (New-StubDnsRecord '_ldap._tcp.dc' 'SRV' @{ DomainName = 'old-dc.contoso.com.'; Port = [uint16]389; Priority = [uint16]0; Weight = [uint16]100 }),
        (New-StubDnsRecord '_kerberos._tcp.dc' 'SRV' @{ DomainName = 'dc1.contoso.com.'; Port = [uint16]88; Priority = [uint16]0; Weight = [uint16]100 }),
        (New-StubDnsRecord $script:SmokeDsaGuid 'CNAME' @{ HostNameAlias = 'dc1.contoso.com.' }),
        (New-StubDnsRecord $script:SmokeOrphanGuid 'CNAME' @{ HostNameAlias = 'old-dc.contoso.com.' }),
        (New-StubDnsRecord '@' 'NS' @{ NameServer = 'dc1.contoso.com.' }))
}
function Get-DnsServerZone { param([string]$ComputerName, [string]$Name, $ErrorAction)
    $script:SmokeDnsCalls += ("Get-DnsServerZone {0}" -f $ComputerName)
    if ($ComputerName -ne 'dc1.contoso.com') { throw ("STUB: {0} is not a DNS server" -f $ComputerName) }
    @((New-StubDnsZone 'contoso.com' 'NonsecureAndSecure'), (New-StubDnsZone '_msdcs.contoso.com' 'Secure' -Scope 'Forest'), (New-StubDnsZone '0.in-addr.arpa' 'None' -Ds $false -Auto $true),
        (New-StubDnsZone 'fabrikam.com' 'None' -Ds $false -Type 'Forwarder')) }
function Get-DnsServerScavenging { param([string]$ComputerName, $ErrorAction) $script:SmokeDnsCalls += ("Get-DnsServerScavenging {0}" -f $ComputerName)
    [pscustomobject]@{ ScavengingInterval = [timespan]::FromDays(7); ScavengingState = $true; NoRefreshInterval = [timespan]::FromDays(7); RefreshInterval = [timespan]::FromDays(7) } }
function Get-DnsServerZoneAging { param([string]$Name, [string]$ComputerName, $ErrorAction) $script:SmokeDnsCalls += ("Get-DnsServerZoneAging {0} {1}" -f $ComputerName, $Name)
    [pscustomobject]@{ ZoneName = $Name; AgingEnabled = $true; NoRefreshInterval = [timespan]::FromDays(7); RefreshInterval = [timespan]::FromDays(7); ScavengeServers = $null } }
function Get-DnsServerForwarder { param([string]$ComputerName, $ErrorAction) $script:SmokeDnsCalls += ("Get-DnsServerForwarder {0}" -f $ComputerName)
    [pscustomobject]@{ IPAddress = @('192.0.2.53'); UseRootHint = $true } }
function Get-DnsServerResourceRecord { param([string]$ComputerName, [string]$ZoneName, [string]$Name, [string]$RRType, $ErrorAction)
    $script:SmokeDnsCalls += ("Get-DnsServerResourceRecord {0} {1} {2} {3}" -f $ComputerName, $ZoneName, $Name, $RRType)
    $all = @($script:SmokeDnsRecords[$ZoneName.ToLowerInvariant()])
    if ($Name -ne '') { $all = @($all | Where-Object { $_.HostName -eq $Name }) }
    if ($RRType -ne '') { $all = @($all | Where-Object { $_.RecordType -eq $RRType }) }
    if ($Name -ne '' -and $all.Count -eq 0) { throw ("Failed to get {0} record in {1} zone on {2} server. WIN32 9714" -f $Name, $ZoneName, $ComputerName) }
    return $all }
# Resolve-DnsName -DnsOnly -Server, in the shape of Microsoft.DnsClient.Commands.DnsRecord: an SRV
# answer carries NameTarget, an A answer IPAddress. It answers from the same records as the zone.
# PORT-PLAN C16d(a): $script:SmokeDnsDepthMixed makes an SRV answer carry an A record of its Additional section
# too, and answers the domain's _kerberos._tcp name with the zone's SOA alone (a name with no SRV data, NODATA),
# as Resolve-DnsName returns every record from the wire (Learn resolve-dnsname, read 2026-11-19).
$script:SmokeDnsDepthMixed = $false
function Resolve-DnsName { param([string]$Name, [string]$Type, [string]$Server, [switch]$DnsOnly, $ErrorAction)
    $script:SmokeDnsCalls += ("Resolve-DnsName {0} {1} {2}" -f $Name, $Type, $Server)
    if ($Type -eq 'SRV') {
        if ($script:SmokeDnsDepthMixed -and $Name -eq '_kerberos._tcp.contoso.com') { return @([pscustomobject]@{ Name = 'contoso.com'; Type = 'SOA'; PrimaryServer = 'dc1.contoso.com' }) }
        $rel = ($Name -replace '\._msdcs\.contoso\.com$', '')
        $hits = @($script:SmokeDnsRecords['_msdcs.contoso.com'] | Where-Object { $_.RecordType -eq 'SRV' -and $_.HostName -eq $rel })
        if ($hits.Count -gt 0) {
            $srvAnswer = @($hits | ForEach-Object { [pscustomobject]@{ Name = $Name; Type = 'SRV'; NameTarget = $_.RecordData.DomainName.TrimEnd('.') } })
            if ($script:SmokeDnsDepthMixed) { $srvAnswer += [pscustomobject]@{ Name = 'dc1.contoso.com'; Type = 'A'; IPAddress = '192.0.2.10' } }
            return $srvAnswer
        }
    }
    if ($Type -eq 'A' -and $Name -eq 'dc1.contoso.com') { return [pscustomobject]@{ Name = $Name; Type = 'A'; IPAddress = '192.0.2.10' } }
    throw ("{0} : DNS name does not exist" -f $Name) }
# PORT-PLAN C1b/C14c: every probe is recorded, so a pass can show that a DC classified Unreachable is
# probed on no port by any section.
$script:SmokeTcpCalls = @()
function Test-TcpPort { param([string]$ComputerName, [int]$Port, [int]$TimeoutMs) $script:SmokeTcpCalls += ('{0}:{1}' -f $ComputerName.ToLowerInvariant(), $Port); return $true }
# PORT-PLAN C14c: the USN-rollback registry seam, so no pass opens a real remote registry. It answers as
# a DC with no "Dsa Not Writable" value does. Every call is recorded.
$script:SmokeUsnCalls = @()
function Get-AdfaUsnRollbackRaw { param([string]$ComputerName) $script:SmokeUsnCalls += $ComputerName; [pscustomobject]@{ Readable = $true; Present = $false; Value = $null; Reason = ''; ErrorCode = '' } }
# C14 (REACH-001/002): the two probe seams, so no pass makes a real DNS lookup or TCP connection. Every
# DC resolves to 192.0.2.10 and answers every port ('Open'); 'Unresolved' answers HostNotFound, as the
# resolver does for a name with no record; 'Refused' resolves and refuses every port. Every call is
# recorded, so the harness can show each DC is classified once per run.
$script:SmokeReachMode = 'Open'
$script:SmokeReachCalls = @()
function Resolve-AdfaHostAddress { param([string]$HostName, [int]$TimeoutMs)
    $script:SmokeReachCalls += ("resolve {0}" -f $HostName)
    if ($script:SmokeReachMode -eq 'Unresolved') { return [pscustomobject]@{ Ok = $false; Addresses = @(); SocketError = 'HostNotFound'; TimedOut = $false; Error = 'No such host is known.' } }
    [pscustomobject]@{ Ok = $true; Addresses = @('192.0.2.10'); SocketError = ''; TimedOut = $false; Error = '' } }
function Test-AdfaTcpAddress { param([string]$Address, [int]$Port, [int]$TimeoutMs)
    $script:SmokeReachCalls += ("tcp {0}:{1}" -f $Address, $Port)
    if ($script:SmokeReachMode -eq 'Refused') { return [pscustomobject]@{ Outcome = 'Failed'; SocketError = 'ConnectionRefused'; TimedOut = $false; Error = 'No connection could be made because the target machine actively refused it.' } }
    [pscustomobject]@{ Outcome = 'Open'; SocketError = ''; TimedOut = $false; Error = '' } }
# C14 (SITE-001): the netlogon.log file seam, in the shape Get-AdfaNetlogonLogRaw returns: the end of a
# log holding one NO_CLIENT_SITE line, for a fictional client in 198.51.100.0/24, and one unrelated line.
# $script:SmokeNetlogonDenied makes it refuse the read as access denied. Every path asked is recorded.
# C14c: each read carries the file's last write time (UTC), as Get-AdfaNetlogonLogRaw now returns it. The
# log was last written an hour ago; netlogon.bak, its rollover file, 60 days ago (older than the 30-day age
# window), and it names another fictional client, WS78, which must be reported as old, never current.
$script:SmokeNetlogonDenied = $false
$script:SmokeNetlogonCalls = @()
function Get-AdfaNetlogonLogRaw { param([string]$Path, [int]$MaxBytes)
    $script:SmokeNetlogonCalls += $Path
    if ($script:SmokeNetlogonDenied) { return [pscustomobject]@{ Ok = $false; Class = 'AccessDenied'; Text = ''; Error = 'Access to the path is denied.'; ErrorType = 'System.UnauthorizedAccessException'; HResult = -2147024891; Path = $Path; Partial = $false; BytesRead = 0; FileLength = [int64]0; LastWriteTimeUtc = $null; LastWriteError = '' } }
    if ($Path -like '*\netlogon.bak') {
        $bakText = "09/20 08:00:01 [MISC] [1234] CONTOSO: NO_CLIENT_SITE: WS78 198.51.100.78`r`n"
        return [pscustomobject]@{ Ok = $true; Class = 'Read'; Text = $bakText; Error = ''; ErrorType = ''; HResult = 0; Path = $Path; Partial = $false; BytesRead = $bakText.Length; FileLength = [int64]$bakText.Length; LastWriteTimeUtc = [datetime]::UtcNow.AddDays(-60); LastWriteError = '' }
    }
    $text = "11/17 09:00:01 [SESSION] [1234] CONTOSO: NlSessionSetup: Try Session setup`r`n11/17 09:05:02 [MISC] [1234] CONTOSO: NO_CLIENT_SITE: WS77 198.51.100.77`r`n"
    [pscustomobject]@{ Ok = $true; Class = 'Read'; Text = $text; Error = ''; ErrorType = ''; HResult = 0; Path = $Path; Partial = $true; BytesRead = $text.Length; FileLength = [int64]20000000; LastWriteTimeUtc = [datetime]::UtcNow.AddHours(-1); LastWriteError = '' } }
# C14 (SYSVOL-004): the module's "identity not found" exception, by type name, for the NTFRS subscriber
# that a DFSR-only DC does not have.
if ($null -eq ('SmokeStub.ADIdentityNotFoundException' -as [type])) {
    Add-Type -TypeDefinition 'namespace SmokeStub { public class ADIdentityNotFoundException : System.Exception { public ADIdentityNotFoundException(string m) : base(m) { } } }' -WarningAction SilentlyContinue
}
# C15: the inventory directory reads, the disabled-account reads and the event reads, each recorded; the
# failing-collectors pass refuses them.
$script:SmokeInventoryFail = $false
$script:SmokeInventoryCalls = @()
$script:SmokeDisabledCalls = @()
# C4b: the export, trust, site link and connection reads, each recorded with what it sent; the
# failing-collectors pass refuses them. The declared secret set is the harness's own copy, so a name
# taken out of the script's tables is still refused here.
$script:SmokeC4bFail = $false
$script:SmokeExportCalls = @()
$script:SmokeC4bCalls = @()
$script:SmokeAllSecretNames = @($script:SmokeLapsSecretNames + @('unicodePwd', 'dBCSPwd', 'ntPwdHistory', 'lmPwdHistory', 'supplementalCredentials', 'msDS-ManagedPassword',
    'msTPM-OwnerInformation', 'msFVE-RecoveryPassword', 'msFVE-KeyPackage', 'trustAuthIncoming', 'trustAuthOutgoing', 'initialAuthIncoming', 'initialAuthOutgoing',
    'currentValue', 'priorValue', 'userPassword', 'unixUserPassword'))
$script:SmokeEventsFail = $false
$script:SmokeEventCalls = @()
# C15 (INV-012): Get-WinEvent, so no pass reaches a real host. The event inventory read - a FilterHashtable
# with a Level key, a StartTime and -MaxEvents - is answered per log in the shape the cmdlet returns
# (EventLogRecord: Id, Level, ProviderName, TimeCreated): two System events, none in the other logs (the
# text this script reads as "no events"), and no DNS Server log (the text it reads as "log absent").
# $script:SmokeEventsFail refuses it as the cmdlet does (UnauthorizedAccessException). Every other call -
# the DsEvents and DFSR scans and the coverage reads - throws the message the real cmdlet gave against
# the stub host name before this stub existed, "The RPC server is unavailable.", so those sections keep
# the results they had.
function Get-WinEvent {
    param([string]$ComputerName, $FilterHashtable, [long]$MaxEvents, [string]$ListLog, [string]$LogName, [switch]$Oldest, [pscredential]$Credential, $ErrorAction)
    if ($null -ne $FilterHashtable -and $FilterHashtable -is [System.Collections.IDictionary] -and $FilterHashtable.Contains('Level')) {
        if (-not $PSBoundParameters.ContainsKey('MaxEvents') -or $MaxEvents -lt 1) { throw 'STUB: an event read without -MaxEvents' }
        if (-not $FilterHashtable.Contains('StartTime')) { throw 'STUB: an event read without a StartTime' }
        $stubLog = [string]$FilterHashtable['LogName']
        $script:SmokeEventCalls += ("{0}|{1}" -f $ComputerName, $stubLog)
        if ($script:SmokeEventsFail) { throw [System.UnauthorizedAccessException]'Attempted to perform an unauthorized operation.' }
        if ($stubLog -eq 'System') {
            return @([pscustomobject]@{ Id = 7; Level = [byte]2; ProviderName = 'Disk'; TimeCreated = $now.AddDays(-2) }, [pscustomobject]@{ Id = 41; Level = [byte]1; ProviderName = 'Microsoft-Windows-Kernel-Power'; TimeCreated = $now.AddDays(-1) })
        }
        if ($stubLog -eq 'DNS Server') { throw ('There is not an event log on the {0} computer that matches "DNS Server".' -f $ComputerName) }
        throw 'No events were found that match the specified selection criteria.'
    }
    # C15 review: the one-event access check that follows a filtered read which found nothing
    # (-LogName -MaxEvents 1, no -Oldest). It returns one Information event, as a readable log does;
    # in the failing pass the log refuses it as the cmdlet does.
    if ($PSBoundParameters.ContainsKey('LogName') -and -not $Oldest -and $null -eq $FilterHashtable -and $MaxEvents -eq 1) {
        $script:SmokeEventCalls += ("{0}|{1}|access check" -f $ComputerName, $LogName)
        if ($script:SmokeEventsFail) { throw [System.UnauthorizedAccessException]'Attempted to perform an unauthorized operation.' }
        return @([pscustomobject]@{ Id = 1000; Level = [byte]4; ProviderName = 'Smoke'; TimeCreated = $now.AddDays(-30) })
    }
    throw 'The RPC server is unavailable.'
}
# C14 (STALE-001/002): the stale reads refused, for the failing-collectors pass.
$script:SmokeStaleFail = $false
$script:SmokeStaleCalls = @()
# C14 review: the declared-population reads, kept apart from the stale reads.
$script:SmokePopulationCalls = @()
# C14c: the future lastLogonTimestamp reads, kept apart from both.
$script:SmokeFutureCalls = @()
# C14 (TIME-001): w32tm answered only in the time pass ($script:SmokeW32tm), in the shape the /rdtsc CSV
# documents: dc1 0.5 s and dc2 400.5 s from the host running the assessment.
$script:SmokeW32tm = $false
$script:SmokeW32tmCalls = @()
# C5: the TLS handshake seam. Test-TcpPort above says every port answers, so without this stub a
# run with -IncludeLdapsHandshake would make a real DNS lookup and a real TCP connection to
# dc1.contoso.com:636. It answers in the shape the real seam returns: the valid certificate, as
# presented, with the chain status a host that does not trust the stub's self-signed certificate
# would report. Every call is recorded.
$script:SmokeTlsCalls = @()
# The bounds each call was given, "<connect ms>/<handshake ms>".
$script:SmokeTlsBounds = @()
function Get-AdfaDcTlsCertificateRaw {
    param([string]$ComputerName, [int]$Port, [int]$ConnectTimeoutMs, [int]$HandshakeTimeoutMs)
    $script:SmokeTlsCalls += ("{0}:{1}" -f $ComputerName, $Port)
    $script:SmokeTlsBounds += ("{0}/{1}" -f $ConnectTimeoutMs, $HandshakeTimeoutMs)
    [pscustomobject]@{ Ok = $true; Class = 'Presented'; Error = ''; ErrorType = ''; SocketError = ''
        Certificate = (ConvertTo-AdfaCertificateRecord -Certificate $script:SmokeCertValid)
        SslPolicyErrors = 'RemoteCertificateChainErrors'; ChainStatus = @('UntrustedRoot: stub chain')
        CallbackRan = $true; DeadlineExpired = $false; ElapsedMs = 5 }
}

$out = Join-Path ([IO.Path]::GetTempPath()) ("adfa_smoke_" + [guid]::NewGuid().ToString('N'))
$script:OutputPath = $out
$script:Sections = @('All')
$script:AllDomains = $false
$script:IncludeDcdiag = $false
$script:IncludeRepadmin = $false
$script:SkipTrustVerification = $false
$script:IncludeLdapsHandshake = $false
# PORT-PLAN C15d(2): off unless a pass turns it on.
$script:IncludeUnscopedGpoLinks = $false
$script:Server = $null
$script:Credential = $null

Write-Host "== Running Invoke-Main against stubbed AD ==" -ForegroundColor Cyan
$script:SmokeExternalCalls = @()
$script:SmokeRemoteCalls = @()
$script:SmokeDirectToolCalls = @()
$result = Invoke-Main
$smokeDefaultCalls = @($script:SmokeExternalCalls)
$smokeDefaultRemote = @($script:SmokeRemoteCalls)
$smokeDefaultDirect = @($script:SmokeDirectToolCalls)

Check ($null -ne $result) 'Invoke-Main returned a summary object'
Check (Test-Path $result.ReportPath) 'HTML report written'
Check (Test-Path $result.CsvPath) 'CSV folder created'
$csvs = @(Get-ChildItem -Path $result.CsvPath -Filter *.csv)
Check ($csvs.Count -ge 8) ("CSV bundle populated ({0} files)" -f $csvs.Count)
$html = Get-Content $result.ReportPath -Raw
Check ($html -match 'Active Directory Forest Assessment') 'Report has title'
Check ($html -match 'Trusts &amp; Two-Way Health' -or $html -match 'Trusts') 'Report includes trust section'
Check ($html -match "class='b-ok'") 'Report renders roll-up badges'
$trustCsv = Join-Path $result.CsvPath 'Trusts & Two-Way Health.csv'
if (Test-Path $trustCsv) {
    $trow = Import-Csv $trustCsv | Select-Object -First 1
    Check ($trow.Health -eq 'Not Assessed') 'Trust health honestly Not Assessed when no verify tools present'
} else {
    Check $false 'Trust CSV exists'
}
Check ($result.Summary.Pass -ge 1) 'Roll-up counted at least one Pass'

# Detailed log + consolidated findings.
Check (Test-Path $result.LogFile) 'Detailed assessment log written'
if (Test-Path $result.LogFile) {
    $log = Get-Content $result.LogFile -Raw
    Check ($log -match '\[RESULT\]' -and $log -match 'Summary: Pass=') 'Log contains itemised results and summary line'
    Check ($log -match '\[STAGE') 'Log contains stage entries'
}
# PORT-PLAN H21: one ADForestAssessment-yyyyMMdd-HHmmss folder under -OutputPath, the log named after
# it, the closing lines at the end of the log, and the exit code in the return object.
function Test-SmokeH21Run {
    param($Result, [string]$Root, [string]$Name, [int]$ExpectedCode, [string]$ReasonPattern)
    $leaf = Split-Path -Leaf $Result.OutputRoot
    Check ($leaf -match '^ADForestAssessment-\d{8}-\d{6}(-\d+)?$') ("H21 {0}: the run folder is ADForestAssessment-yyyyMMdd-HHmmss ({1})" -f $Name, $leaf)
    Check ((Split-Path -Parent $Result.OutputRoot).TrimEnd('\', '/') -eq $Root.TrimEnd('\', '/')) ("H21 {0}: the run folder is directly under -OutputPath" -f $Name)
    Check ((Split-Path -Leaf $Result.LogFile) -eq ($leaf + '.log') -and (Split-Path -Parent $Result.LogFile) -eq $Result.OutputRoot) ("H21 {0}: the log is <run folder>\<run folder name>.log" -f $Name)
    $lines = @(Get-Content -LiteralPath $Result.LogFile)
    Check ($lines.Count -ge 4) ("H21 {0}: the log has its closing lines ({1} lines)" -f $Name, $lines.Count)
    if ($lines.Count -ge 4) {
        Check ($lines[$lines.Count - 4] -match '\[RESULT\] Run finished \d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}.*; duration \d{2,}:\d{2}:\d{2} \(\d+ s\)$') ("H21 {0}: closing line 1 states the end time and the duration" -f $Name)
        Check ($lines[$lines.Count - 3] -match '\[RESULT\] Totals: Pass=\d+ Warning=\d+ Fail=\d+ NotAssessed=\d+ Info=\d+ Unclassified=\d+ Total=\d+$') ("H21 {0}: closing line 2 states the totals per status" -f $Name)
        Check ($lines[$lines.Count - 2] -match ('\[RESULT\] Exit code: {0} \(' -f $ExpectedCode)) ("H21 {0}: closing line 3 states exit code {1} ({2})" -f $Name, $ExpectedCode, $lines[$lines.Count - 2])
        Check ($lines[$lines.Count - 1] -match ('Detailed log: ' + [regex]::Escape($Result.LogFile) + '$')) ("H21 {0}: the last line is the log path" -f $Name)
        # The Total of the closing line is the number of consolidated findings, never zeros by default.
        $fnd = @(Import-Csv -LiteralPath $Result.FindingsFile)
        Check ($lines[$lines.Count - 3] -match ('Total={0}$' -f $fnd.Count)) ("H21 {0}: the closing Total is the {1} consolidated findings" -f $Name, $fnd.Count)
    }
    Check ($Result.ExitCode -eq $ExpectedCode) ("H21 {0}: ExitCode {1} (got {2}: {3})" -f $Name, $ExpectedCode, $Result.ExitCode, $Result.ExitReason)
    Check ([string]$Result.ExitReason -match $ReasonPattern) ("H21 {0}: the exit reason names the cause ({1})" -f $Name, $Result.ExitReason)
    Check ($Result.ExitCode -ne 0) ("H21 {0}: a run with Fail findings or Not Assessed sections is never exit code 0" -f $Name)
}
Write-Host ("    H21 single-domain exit: {0} - {1}" -f $result.ExitCode, $result.ExitReason) -ForegroundColor DarkGray
Test-SmokeH21Run -Result $result -Root $out -Name 'single-domain' -ExpectedCode 1 -ReasonPattern 'Fail finding'
Check (Test-Path $result.FindingsFile) 'Consolidated findings CSV written'
if (Test-Path $result.FindingsFile) {
    $fnd = Import-Csv $result.FindingsFile
    Check ((@($fnd)[0].PSObject.Properties.Name -contains 'Section') -and (@($fnd)[0].PSObject.Properties.Name -contains 'Status')) 'Findings CSV has Section+Status columns'
}

# Full identity export produced per-domain CSVs with flattened attributes.
$usersCsv = Get-ChildItem -Path $result.CsvPath -Filter 'AllUsers_*.csv' -ErrorAction SilentlyContinue
$compCsv = Get-ChildItem -Path $result.CsvPath -Filter 'AllComputers_*.csv' -ErrorAction SilentlyContinue
Check (@($usersCsv).Count -ge 1) 'Full user export CSV written (AllUsers_*.csv)'
Check (@($compCsv).Count -ge 1) 'Full computer export CSV written (AllComputers_*.csv)'

# DC diagnostics now carry an overall Status + Failures column.
$dcCsv = Join-Path $result.CsvPath 'DC Diagnostics.csv'
if (Test-Path $dcCsv) {
    $dcRow = Import-Csv $dcCsv | Select-Object -First 1
    Check ($dcRow.PSObject.Properties.Name -contains 'Status') 'DC Diagnostics has overall Status column'
    Check ($dcRow.PSObject.Properties.Name -contains 'Failures') 'DC Diagnostics has Failures detail column'
    # C11: the grid row keeps its columns, with one per per-DC test and the DC's domain.
    $dcCsvRows = @(Import-Csv $dcCsv)
    $dcCsvGrid = @($dcCsvRows | Where-Object { $_.DomainController -eq 'dc1.contoso.com' })
    Check (@($dcCsvGrid).Count -eq 1 -and $dcCsvGrid[0].Scope -eq 'contoso.com' -and $dcCsvGrid[0].DCDIAG_Connectivity -eq 'Pass' -and $dcCsvGrid[0].DCDIAG_NCSecDesc -eq 'Pass' -and $dcCsvGrid[0].DCDIAG_SystemLog -eq 'Not Assessed') 'C11: the DC Diagnostics CSV has one grid row for the stub DC, with its domain, the new per-DC tests, and SystemLog held back'
    Check (@($dcCsvRows[0].PSObject.Properties.Name | Where-Object { $_ -like 'DCDIAG_*' }).Count -eq 21) 'C11: the grid has one column per per-DC test (declared population: 21)'
    Check (@($dcCsvGrid).Count -eq 1 -and $dcCsvGrid[0].DCDIAG_FsmoCheck -eq 'Pass' -and $dcCsvGrid[0].Status -eq 'Pass') 'C11 review: FsmoCheck, answered in the enterprise block, reads Pass for the DC asked, and the grid row stays Pass'
    # C11e: the stub DC's SYSVOL engine is DFSR (directory objects and registry Local State 3), so FrsEvent is
    # not applicable there; DFSREvent still runs, and the row's status is unchanged.
    Check (@($dcCsvGrid).Count -eq 1 -and $dcCsvGrid[0].DCDIAG_FrsEvent -eq 'Not Applicable' -and $dcCsvGrid[0].DCDIAG_DFSREvent -eq 'Pass' -and $dcCsvGrid[0].NotRun -match 'FrsEvent not applicable' -and $dcCsvGrid[0].Failures -notmatch 'not applicable') 'C11e: FrsEvent is Not Applicable on the DFSR stub DC, DFSREvent runs, and the reason is in NotRun, not Failures'
}
else { Check $false 'DC Diagnostics CSV exists' }

# Replication now carries a FailureDetail column for the exact failing partner/error.
$repCsv = Join-Path $result.CsvPath 'Replication Health.csv'
if (Test-Path $repCsv) {
    $repRow = Import-Csv $repCsv | Select-Object -First 1
    Check ($repRow.PSObject.Properties.Name -contains 'FailureDetail') 'Replication Health has FailureDetail column'
}
else { Check $false 'Replication Health CSV exists' }

# The DC inventory must actually be ENRICHED. The stub refuses a Get-ADComputer call that
# carries no -Server, exactly as a real forest-root DC refuses a child-domain DN with an LDAP
# referral. If the enrichment regresses, OperatingSystem goes to 'Not Assessed' here and the
# Exchange SE verdict silently downgrades every affected DC to "unverified, not compatible".
$dcInvCsv = Join-Path $result.CsvPath 'Domain Controllers.csv'
if (Test-Path $dcInvCsv) {
    $dcInv = @(Import-Csv $dcInvCsv)
    Check (@($dcInv).Count -ge 1) ("DC inventory has rows ({0})" -f @($dcInv).Count)
    $enriched = @($dcInv | Where-Object { $_.OperatingSystem -and $_.OperatingSystem -ne 'Not Assessed' })
    Check (@($enriched).Count -eq @($dcInv).Count) ("DC inventory enrichment succeeded for every DC ({0}/{1} carry a real OperatingSystem)" -f @($enriched).Count, @($dcInv).Count)
    $withErr = @($dcInv | Where-Object { $_.EnrichmentError })
    Check (@($withErr).Count -eq 0) ("No DC row carries an EnrichmentError ({0})" -f @($withErr).Count)
    Check ($dcInv[0].PSObject.Properties.Name -contains 'EnrichmentError') 'DC inventory exposes EnrichmentError so an unreadable OS carries its cause into the report'
}
else { Check $false 'Domain Controllers CSV exists' }


# The three sections added in v1.11.0 must be wired, not merely present as functions: a
# ValidateSet entry with no branch in Invoke-Main produces no section at all, and nothing else
# in this harness would notice.
$smokeFindings = @(Import-Csv $result.FindingsFile)

# The Exchange SE verdict must not be degraded by a failed enrichment: an unreadable OS makes
# this tool call a DC "unverified, not compatible", which is the wrong answer to the one
# question the SE section exists to answer.
$seRows = @($smokeFindings | Where-Object { $_.Section -eq 'Exchange SE Compatibility' })
Check (@($seRows).Count -gt 0) ("Exchange SE section produced findings ({0})" -f @($seRows).Count)
Check (@($seRows | Where-Object { $_.Item -match 'not readable' }).Count -eq 0) 'Exchange SE: no DC is reported as having an unreadable OS'
# H17: the forest functional level verdict is read from msDS-Behavior-Version on the Partitions
# container. If the collector is not wired, or the stub forest loses PartitionsContainer, this
# row degrades to Not Assessed instead of Pass.
$fflSmoke = @($seRows | Where-Object { $_.Item -eq 'Forest functional level' })
Check (@($fflSmoke).Count -eq 1) ("Exchange SE: exactly one forest functional level row ({0})" -f @($fflSmoke).Count)
Check (@($fflSmoke | Where-Object { $_.Status -eq 'Pass' -and $_.Detail -match 'msDS-Behavior-Version 7' }).Count -eq 1) 'Exchange SE: forest functional level passes on the numeric level read from the Partitions container'
foreach ($sec in @('_msdcs Zone Delegation', 'Time Hierarchy', 'Site Global Catalog Coverage')) {
    $n = @($smokeFindings | Where-Object { $_.Section -eq $sec }).Count
    Check ($n -gt 0) ("Section '{0}' is wired into Invoke-Main and reached the findings ({1} rows)" -f $sec, $n)
}
# With no DNS or time tools on this host, those two must degrade honestly rather than pass.
foreach ($sec in @('_msdcs Zone Delegation', 'Time Hierarchy')) {
    $rows = @($smokeFindings | Where-Object { $_.Section -eq $sec })
    Check (@($rows | Where-Object { $_.Status -eq 'Pass' }).Count -eq 0) ("Section '{0}' reports no Pass when the query tools are absent" -f $sec)
    Check (@($rows | Where-Object { $_.Status -eq 'Not Assessed' }).Count -gt 0) ("Section '{0}' reports Not Assessed with a named cause" -f $sec)
}
# C11: DcDiagnostics is wired, runs dcdiag through the stub once per per-DC test, Topology once for
# the stub domain and the two forest tests once each, and reports each scope in its own rows.
$ddRows = @($smokeFindings | Where-Object { $_.Section -eq 'DC Diagnostics' })
$ddCalls = @($script:SmokeDcdiagCalls)
$ddPerDc = @($ddCalls | Where-Object { $_.Arguments -notmatch '/test:(Topology|CheckSDRefDom|CrossRefValidation|Intersite)\b' })
# C11e: 18 since v1.41.0 - FrsEvent is not run on the stub DC, whose SYSVOL engine is DFSR.
Check (@($ddPerDc).Count -eq 18 -and $ddPerDc[0].Arguments -eq '/test:Connectivity /s:dc1.contoso.com' -and @($ddPerDc | Where-Object { $_.Arguments -match '^/test:FrsEvent ' }).Count -eq 0 -and @($ddPerDc | Where-Object { $_.Arguments -match '^/test:DFSREvent ' }).Count -eq 1) ("DC Diagnostics: the stub DC is asked 18 per-DC tests, Connectivity first, FrsEvent not applicable to its DFSR engine ({0})" -f @($ddPerDc).Count)
Check (@($ddCalls | Where-Object { $_.Arguments -match '^/test:Topology /s:dc1\.contoso\.com$' }).Count -eq 1) 'DC Diagnostics: Topology runs once for the one scoped domain'
Check (@($ddCalls | Where-Object { $_.Arguments -match '^/test:(CheckSDRefDom|CrossRefValidation) /s:dc1\.contoso\.com$' }).Count -eq 2) 'DC Diagnostics: CheckSDRefDom and CrossRefValidation run once each, for the forest'
Check (@($ddCalls | Where-Object { $_.Arguments -match '(?i)/test:(DNS|SystemLog|Intersite|LocatorCheck|CutoffServers)\b|(\s|^)/(fix|c|e)(\s|$)' }).Count -eq 0) 'DC Diagnostics: a default run starts no test that changes state, no LocatorCheck and no /fix, /c or /e'
Check (@($ddCalls | Where-Object { $_.Timeout -ne 90 -or $_.Retries -ne 2 }).Count -eq 0) 'DC Diagnostics: without an override each invocation gets -ExternalToolTimeoutSeconds and -Retries'
$ddGrid = @($ddRows | Where-Object { $_.Item -eq 'dc1.contoso.com' })
Check (@($ddGrid).Count -eq 1 -and $ddGrid[0].Status -eq 'Pass' -and $ddGrid[0].Scope -eq 'contoso.com' -and $ddGrid[0].Detail -match 'SystemLog') 'DC Diagnostics: the stub DC''s grid row passes, carries its domain, and says SystemLog was held back'
Check (@($ddRows | Where-Object { $_.Item -eq 'dcdiag Topology: contoso.com' -and $_.Status -eq 'Pass' -and $_.Scope -eq 'contoso.com' }).Count -eq 1) 'DC Diagnostics: one Topology row for the stub domain, Pass'
foreach ($ddTest in @('CheckSDRefDom', 'CrossRefValidation')) {
    $ddPart = @($ddRows | Where-Object { $_.Item -like ("dcdiag {0}: *" -f $ddTest) -and $_.Item -notlike '*: forest *' })
    Check (@($ddPart).Count -eq 5 -and @($ddPart | Where-Object { $_.Status -ne 'Pass' }).Count -eq 0) ("DC Diagnostics: {0} has one Pass row per partition the stub printed (declared population: five, the wrapped Configuration included; got {1})" -f $ddTest, @($ddPart).Count)
    Check (@($ddRows | Where-Object { $_.Item -eq ("dcdiag {0}: forest contoso.com" -f $ddTest) -and $_.Status -eq 'Pass' }).Count -eq 1) ("DC Diagnostics: {0} has a forest roll-up row, Pass" -f $ddTest)
}
Check (@($ddRows | Where-Object { $_.Item -eq 'dcdiag Intersite: not run' -and $_.Status -eq 'Not Assessed' -and $_.Detail -match 'IncludeDcdiagActiveTests' }).Count -eq 1) 'DC Diagnostics: Intersite not run by default, one Not Assessed row naming the switch'
Check (@($ddRows | Where-Object { $_.Item -eq 'dcdiag LocatorCheck: not run' -and $_.Status -eq 'Not Assessed' }).Count -eq 1) 'DC Diagnostics: LocatorCheck is not run, and a row says so'
Check (@($ddRows | Where-Object { $_.Item -eq 'dcdiag coverage: contoso.com' -and $_.Status -eq 'Info' -and $_.Detail -match '^1 domain controller\(s\) of this domain have a grid row: 1 Pass' }).Count -eq 1) 'DC Diagnostics: a coverage row counts the stub domain''s DC'
Check (@($ddRows | Where-Object { $_.Recommendation }).Count -eq 0) 'DC Diagnostics: no row that is not a Warning or a Fail carries advice'
# C12: without -IncludeDcdiagActiveTests the DNS summary is not read; one Not Assessed row for the
# stub domain says why, and no test-group row exists.
$ddDnsNotRun = @($ddRows | Where-Object { $_.Item -like 'dcdiag DNS not run: *' })
Check (@($ddDnsNotRun).Count -eq 1 -and $ddDnsNotRun[0].Item -eq 'dcdiag DNS not run: contoso.com' -and $ddDnsNotRun[0].Scope -eq 'contoso.com' -and $ddDnsNotRun[0].Status -eq 'Not Assessed' -and $ddDnsNotRun[0].Detail -match 'IncludeDcdiagActiveTests') 'C12: a default run reports one "dcdiag DNS not run" row for the stub domain, Not Assessed, naming the switch'
Check (@($ddRows | Where-Object { $_.Item -match '^dcdiag DNS (Auth|Basc|Forw|Del|Dyn|RReg|Ext): ' }).Count -eq 0) 'C12: a default run has no DNS test-group row'
# C13: with no DnsServer module and no DNS query tool on this host, every graded DNS row is Not Assessed
# with its cause and none is Pass; the DC DNS Client rows are read through the CIM stub; the opt-in
# record export is not part of All.
$c13Health = @($smokeFindings | Where-Object { $_.Section -eq 'DNS Health' })
Check (@($c13Health | Where-Object { $_.Item -eq 'DNS server: dc1.contoso.com' -and $_.Status -eq 'Not Assessed' -and $_.Scope -eq 'contoso.com' -and $_.Detail -match 'DnsServer PowerShell module' }).Count -eq 1) 'C13: DNS Health is wired, scoped to the stub domain, and names the missing DnsServer module for the stub DC'
Check (@($c13Health | Where-Object { $_.Item -eq 'DNS zones (population): contoso.com' -and $_.Status -eq 'Not Assessed' }).Count -eq 1) 'C13: the zone population row of the stub domain is Not Assessed when no DNS server was read'
Check (@($c13Health | Where-Object { $_.Status -eq 'Pass' }).Count -eq 0 -and @($c13Health | Where-Object { $_.Item -match '^Zone (dynamic update|scavenging): ' }).Count -eq 0) 'C13: DNS Health grades no zone, and passes nothing, when nothing could be read'
$c13Dac = @($smokeFindings | Where-Object { $_.Section -eq 'DNS vs AD Consistency' -and $_.Item -match '^(DC locator records|DC A record|Stale DC records \(population\)): ' })
Check (@($c13Dac).Count -eq 3 -and @($c13Dac | Where-Object { $_.Status -ne 'Not Assessed' -or $_.Scope -ne 'contoso.com' }).Count -eq 0) ("C13: DNS vs AD gives the stub DC its locator and A record rows and the domain its stale-record row, all Not Assessed with no instrument (declared population: three; got {0})" -f @($c13Dac).Count)
$c13Client = @($smokeFindings | Where-Object { $_.Section -eq 'DC DNS Client' })
Check (@($c13Client | Where-Object { $_.Item -eq 'DNS client: dc1.contoso.com' -and $_.Status -eq 'Info' -and $_.Scope -eq 'contoso.com' }).Count -eq 1) 'C13: DC DNS Client is wired into the DomainControllers section and reads the stub DC''s adapter (two DNS servers, one DC: Info)'
$c13ClientCsv = Join-Path $result.CsvPath 'DC DNS Client.csv'
Check ((Test-Path $c13ClientCsv) -and @(@(Import-Csv $c13ClientCsv) | Where-Object { $_.DnsServers -eq '192.0.2.20, 127.0.0.1' -and $_.ConfiguredIPv4 -eq '192.0.2.10' }).Count -eq 1) 'C13: the DNS server list and the IPv4 address are in their own columns of the DC DNS Client CSV'
Check (@($smokeFindings | Where-Object { $_.Section -eq 'DNS Record Export' }).Count -eq 0 -and @(Get-ChildItem -LiteralPath $result.CsvPath -Filter 'DnsRecords_*').Count -eq 0) 'C13: the DNS record export is opt-in - the All run writes no record and no export row'
Check (@($smokeFindings | Where-Object { $_.Section -eq 'DNS Depth' -and $_.Item -eq 'Secure dynamic updates' -and $_.Status -eq 'Info' -and $_.Detail -match 'Zone dynamic update' }).Count -eq 1) 'C13: DNS Depth no longer grades dynamic update and says where it went'
# C1: the DcSystem section must be wired, must judge the stub DC's OS from the inventory, and
# must report the patch-level inventory read through the CIM stubs - as Info, never as Pass.
$dcsRows = @($smokeFindings | Where-Object { $_.Section -eq 'DC System' })
Check (@($dcsRows).Count -gt 0) ("Section 'DC System' is wired into Invoke-Main and reached the findings ({0} rows)" -f @($dcsRows).Count)
$lifeRows = @($dcsRows | Where-Object { $_.Item -like 'OS lifecycle:*' })
Check (@($lifeRows).Count -eq 1 -and $lifeRows[0].Status -eq 'Pass' -and $lifeRows[0].Detail -match 'Windows Server 2019' -and $lifeRows[0].Detail -match '2029-01-09') 'DC System: the stub DC (build 17763) is judged in support, with the end date stated'
Check ([string]$lifeRows[0].Scope -eq 'contoso.com') 'DC System: the lifecycle row carries its domain as Scope'
$osRow = @($dcsRows | Where-Object { $_.Item -like 'OS build and uptime:*' })
Check (@($osRow).Count -eq 1 -and $osRow[0].Status -eq 'Info' -and $osRow[0].Detail -match 'Build 17763' -and $osRow[0].Detail -match 'up 9 day') 'DC System: build and uptime are read through the CIM stub and reported as Info'
# C1a: the update build revision is read through the StdRegProv stub in the same session and shown as the fourth part.
Check (@($osRow).Count -eq 1 -and $osRow[0].Detail -match 'Build 17763\.6532 \(version' -and $osRow[0].Detail -match 'Update build revision 6532 from the registry value UBR' -and $osRow[0].Detail -match 'not graded') 'C1a: the OS build row shows the full build 17763.6532, display only'
# H20a: the default run asked for no console tool form Microsoft documents as changing state, and only for forms the inventory
# lists as Default (declared population: the tools this harness answers or refuses - dcdiag, repadmin, w32tm, nltest, dfsrmig, nslookup).
$h20aChange = @($smokeDefaultCalls | Where-Object { $_ -match '(?i)/sc_verify|^netdom|/removelingeringobjects|/test:(DNS|SystemLog|Intersite|CutoffServers)\b|\s/c\s|/resync|/config\b|/register|/unregister|/setglobalstate|/createglobalobjects|/delete|/replicate|/syncall|/kcc|/fix\b' })
Check (@($h20aChange).Count -eq 0) ("H20a: the default run invoked no command Microsoft documents as changing state (found: {0})" -f ($h20aChange -join '; '))
$h20aTools = @($smokeDefaultCalls | ForEach-Object { ($_ -split ' ')[0] } | Sort-Object -Unique)
Check (@($smokeDefaultCalls | Where-Object { $_ -like 'dcdiag.exe /test:*' }).Count -gt 0 -and @($h20aTools | Where-Object { @('dcdiag.exe', 'repadmin.exe', 'w32tm.exe', 'nltest.exe', 'dfsrmig.exe', 'nslookup.exe') -notcontains $_ }).Count -eq 0) ("H20a: the default run started only audited console tools, dcdiag among them (tools: {0})" -f ($h20aTools -join ', '))
$h20aDcdiag = @($smokeDefaultCalls | Where-Object { $_ -like 'dcdiag.exe /test:*' } | ForEach-Object { ([regex]::Match($_, '/test:(\S+)')).Groups[1].Value } | Sort-Object -Unique)
Check (@($h20aDcdiag).Count -eq 22) ("H20a: the default run ran the 22 default dcdiag tests and no other (declared population: 19 per-DC, Topology, CheckSDRefDom, CrossRefValidation; got {0}: {1})" -f @($h20aDcdiag).Count, ($h20aDcdiag -join ', '))
# H20a (review fix): the direct start of nltest.exe in the WinRM script block. Declared population: the
# DcSecureChannel read of the stub DC (dc1.contoso.com), at least; every one runs the audited script block
# with /sc_query only, and no console tool is started directly in this process.
$h20aRemoteBad = @($smokeDefaultRemote | Where-Object { $_.ScriptBlock -notmatch '^param\(\$a\) & nltest\.exe \$a\b' -or $_.Arguments -notmatch '^/sc_query:\S+$' } | ForEach-Object { '{0}: {1} [{2}]' -f $_.ComputerName, $_.ScriptBlock, $_.Arguments })
Check (@($smokeDefaultRemote | Where-Object { $_.ComputerName -eq 'dc1.contoso.com' }).Count -ge 1 -and @($h20aRemoteBad).Count -eq 0) ("H20a: every WinRM script block of the default run starts nltest.exe with /sc_query only, the stub DC's among them ({0} calls; not so: {1})" -f @($smokeDefaultRemote).Count, ($h20aRemoteBad -join '; '))
Check (@($smokeDefaultDirect).Count -eq 0) ("H20a: the default run started no console tool directly in this process ({0})" -f (@($smokeDefaultDirect) -join '; '))
# PORT-PLAN C2i(4): DcSecureChannel's WinRM read is answered by the Invoke-Command stub above (added by the H20a
# review), so no real WinRM attempt is made against the fictional host. Declared population: exactly one remote
# /sc_query of the stub domain for the stub DC, from the shared DC list (C2i(3)); its row reports the stub's
# refusal, Not Assessed and scoped to its domain, never Pass.
$c2iRemote = @($smokeDefaultRemote | Where-Object { $_.ComputerName -eq 'dc1.contoso.com' -and $_.Arguments -eq '/sc_query:contoso.com' })
$c2iSc = @($smokeFindings | Where-Object { $_.Section -eq 'DC Secure Channel & Machine Passwords' -and $_.Item -eq 'Secure channel: dc1.contoso.com' })
Check ($c2iRemote.Count -eq 1 -and $c2iSc.Count -eq 1 -and $c2iSc[0].Status -eq 'Not Assessed' -and $c2iSc[0].Detail -match 'STUB: WinRM' -and $c2iSc[0].Scope -eq 'contoso.com') ("C2i(4): the DcSecureChannel WinRM read reaches the stub, not a real endpoint - one /sc_query for dc1, its row Not Assessed with the stub's refusal ({0} calls, {1} rows)" -f $c2iRemote.Count, $c2iSc.Count)
Check (@($smokeFindings | Where-Object { $_.Section -eq 'DC Secure Channel & Machine Passwords' -and $_.Item -eq 'DC enumeration' }).Count -eq 0) 'C2i(3): DcSecureChannel takes the stub domain''s DC from the shared list, with no enumeration row of its own'
$hfRow = @($dcsRows | Where-Object { $_.Item -like 'Last update installed:*' })
Check (@($hfRow).Count -eq 1 -and $hfRow[0].Status -eq 'Info' -and $hfRow[0].Detail -match '2026-11-10') 'DC System: the latest update date is the later of the two stub records, with the day/month order proven by the set'
Check (@($dcsRows | Where-Object { $_.Status -eq 'Pass' -and $_.Item -notlike 'OS lifecycle:*' }).Count -eq 0) 'DC System: no patch-level row is ever a Pass - it is inventory'
# C2: the DcDisk section must be wired, must read the three paths through the StdRegProv stub
# and the volumes through the Win32_Volume stub, and must judge each distinct volume once.
$diskRows = @($smokeFindings | Where-Object { $_.Section -eq 'DC Disk Space' })
Check (@($diskRows).Count -eq 2) ("Section 'DC Disk Space' is wired into Invoke-Main and gives one row per distinct volume of the stub DC ({0} rows, expected 2)" -f @($diskRows).Count)
$diskC = @($diskRows | Where-Object { $_.Item -eq 'Disk space: dc1.contoso.com C:\ (NTDS database, SYSVOL)' })
Check (@($diskC).Count -eq 1 -and $diskC[0].Status -eq 'Pass' -and $diskC[0].Detail -match '50\.00 % free: 60\.00 GB free of 120\.00 GB') 'DC Disk Space: the system volume holds the database and SYSVOL, and passes on the figures the stub returned'
$diskE = @($diskRows | Where-Object { $_.Item -eq 'Disk space: dc1.contoso.com E:\ (NTDS logs)' })
Check (@($diskE).Count -eq 1 -and $diskE[0].Status -eq 'Pass' -and $diskE[0].Detail -match 'E:\\NTDS-Logs') 'DC Disk Space: the logs are judged on their own volume, found from the path the registry stub returned'
# Declared population: the three roles. Each is accounted for by exactly one row.
foreach ($role in @('NTDS database', 'NTDS logs', 'SYSVOL')) {
    Check (@($diskRows | Where-Object { $_.Item -match [regex]::Escape($role) }).Count -eq 1) ("DC Disk Space: role '{0}' is accounted for by exactly one row" -f $role)
}
Check (@($diskRows | Where-Object { $_.Scope -eq 'contoso.com' }).Count -eq 2) 'DC Disk Space: every row carries its domain as Scope'
Check (@($diskRows | Where-Object { $_.Detail -match 'tool default, not a Microsoft value' }).Count -eq 2) 'DC Disk Space: every verdict labels its thresholds as tool defaults, not Microsoft values'
Check (@($diskRows | Where-Object { $_.Detail -match 'Read over Wsman' }).Count -eq 2) 'DC Disk Space: the transport that answered is stated'
Check ($diskC[0].Detail -match '110 %' -and $diskE[0].Detail -notmatch '110 %') 'DC Disk Space: the database volume, and only it, says the 110 % of ntds.dit figure was not measured'
Check (@($diskRows | Where-Object { @('Pass', 'Warning', 'Fail', 'Not Assessed') -notcontains $_.Status }).Count -eq 0) 'DC Disk Space: no row is Info - a row is a verdict or it is Not Assessed'
Check (@($diskRows | Where-Object { $_.Recommendation }).Count -eq 0) 'DC Disk Space: a passing row carries no advice'
# C3: the DcHardening section must be wired, must read the six values through the GetDWORDValue
# stub, the two classes through the Get-CimInstance stub and the SMB server configuration through the
# Get-SmbServerConfiguration stub (PORT-PLAN C3f) in ONE session per DC, and must
# report every setting exactly once, family first.
$hardFamilies = @('LDAP server signing', 'LDAP server signing enforcement', 'LDAP channel binding', 'SMB server signing', 'SMB client signing', 'LAN Manager authentication level', 'Print Spooler', 'SMBv1')
$hardRows = @($smokeFindings | Where-Object { $_.Section -eq 'DC Hardening' })
Check (@($hardRows).Count -eq 8) ("Section 'DC Hardening' is wired into Invoke-Main and gives one row per setting of the stub DC ({0} rows, expected 8)" -f @($hardRows).Count)
# Declared population: the six registry settings, Print Spooler and SMBv1.
foreach ($family in $hardFamilies) {
    Check (@($hardRows | Where-Object { $_.Item -eq ("{0}: dc1.contoso.com" -f $family) }).Count -eq 1) ("DC Hardening: '{0}' is accounted for by exactly one row" -f $family)
}
function Get-HardRow { param($Rows, [string]$Family) @($Rows | Where-Object { $_.Item -eq ("{0}: dc1.contoso.com" -f $Family) })[0] }
Check ((Get-HardRow $hardRows 'LDAP server signing').Status -eq 'Pass' -and (Get-HardRow $hardRows 'LDAP server signing').Detail -match 'LDAPServerIntegrity = 2') 'DC Hardening: LDAP server signing passes on the value the registry stub returned'
Check ((Get-HardRow $hardRows 'LDAP server signing enforcement').Status -eq 'Info' -and (Get-HardRow $hardRows 'LDAP server signing enforcement').Detail -match '^Not applicable') 'DC Hardening: the Windows Server 2025 enforcement policy is not applicable on the stub DC (build 17763), as Info'
$hardCb = Get-HardRow $hardRows 'LDAP channel binding'
Check ($hardCb.Status -eq 'Warning' -and $hardCb.Detail -match 'is not set in the registry of this DC' -and $hardCb.Detail -match "documented default" -and $hardCb.Detail -match "'Never'") 'DC Hardening: channel binding is not set, and is graded on the documented default for the build, named as a default'
Check ($hardCb.Detail -match 'measured, not published by Microsoft') 'DC Hardening: the reading of return code 1 as "not set" is labelled as measured'
Check ((Get-HardRow $hardRows 'SMB server signing').Status -eq 'Pass' -and (Get-HardRow $hardRows 'SMB server signing').Detail -match 'RequireSecuritySignature = 1') 'DC Hardening: SMB server signing passes on the registry value'
Check ((Get-HardRow $hardRows 'SMB server signing').Detail -match 'The second instrument agrees: Get-SmbServerConfiguration RequireSecuritySignature = True') 'DC Hardening: the second instrument, read with Get-SmbServerConfiguration in the measured shape, agrees with the registry value (PORT-PLAN C3f)'
$hardClient = Get-HardRow $hardRows 'SMB client signing'
Check ($hardClient.Status -eq 'Warning' -and $hardClient.Detail -match 'documented default' -and $hardClient.Detail -match 'Disabled') 'DC Hardening: SMB client signing is not set, and the documented pre-2025 default (Disabled) is a Warning'
Check ((Get-HardRow $hardRows 'LAN Manager authentication level').Status -eq 'Pass' -and (Get-HardRow $hardRows 'LAN Manager authentication level').Detail -match 'LmCompatibilityLevel = 5') 'DC Hardening: the LAN Manager level passes at 5'
Check ((Get-HardRow $hardRows 'Print Spooler').Status -eq 'Pass' -and (Get-HardRow $hardRows 'Print Spooler').Detail -match 'Stopped') 'DC Hardening: Print Spooler is read from Win32_Service and passes when Stopped'
Check ((Get-HardRow $hardRows 'SMBv1').Status -eq 'Pass' -and (Get-HardRow $hardRows 'SMBv1').Detail -match '^EnableSMB1Protocol = False: the SMBv1 server is not enabled on this DC, as Get-SmbServerConfiguration reports it') 'DC Hardening: SMBv1 is graded on EnableSMB1Protocol as Get-SmbServerConfiguration returned it (PORT-PLAN C3f)'
Check ((Get-HardRow $hardRows 'SMBv1').Detail -match 'detect-enable-and-disable-smbv1-v2-v3 \(read 2026-11-17\)' -and -not (Get-HardRow $hardRows 'SMBv1').Recommendation) 'DC Hardening: the SMBv1 row names the Microsoft detection source, and a Pass carries no advice'
Check ((@($script:SmokeSmbCalls) -join ',') -eq 'dc1.contoso.com') ("DC Hardening: Get-SmbServerConfiguration ran once, in the session opened to the stub DC, with -WhatIf and -Confirm off ({0})" -f (@($script:SmokeSmbCalls) -join ','))
Check (@($hardRows | Where-Object { $_.Status -eq 'Pass' }).Count -eq 5) ("DC Hardening: five rows pass on the stub DC - LDAP signing, SMB server signing, LAN Manager level, Print Spooler, SMBv1 ({0})" -f @($hardRows | Where-Object { $_.Status -eq 'Pass' }).Count)
Check (@($hardRows | Where-Object { $_.Scope -eq 'contoso.com' }).Count -eq 8) 'DC Hardening: every row carries its domain as Scope'
Check (@($hardRows | Where-Object { $_.Detail -match 'Read over Wsman' }).Count -eq 8) 'DC Hardening: the transport that answered is stated on every row'
Check (@($hardRows | Where-Object { $_.Detail -match 'OS build 17763' }).Count -eq 6) 'DC Hardening: each of the six setting rows states the OS build the default was chosen for'
Check (@($hardRows | Where-Object { $_.Detail -match 'not necessarily what a client and this DC negotiate on the wire' }).Count -eq 6) 'DC Hardening: each of the six setting rows says it is configured policy, not what is on the wire'
Check (@($hardRows | Where-Object { $_.Detail -match 'registry path of this value is inferred, not published by Microsoft for AD DS' }).Count -eq 1 -and (Get-HardRow $hardRows 'LDAP server signing').Detail -match 'path of this value is inferred') 'DC Hardening: the LDAP server signing row, and no other, says its registry path is inferred and not published'
Check (@($hardRows | Where-Object { $_.Status -eq 'Warning' }).Count -eq 2 -and @($hardRows | Where-Object { $_.Status -eq 'Warning' -and $_.Detail -match 'below the expectation \(Warning\) is a tool default or your own override, not a Microsoft value' }).Count -eq 2 -and @($hardRows | Where-Object { $_.Status -ne 'Warning' -and $_.Detail -match 'tool default' }).Count -eq 0) 'DC Hardening: each Warning row, and no other, says its status is a tool default and not a Microsoft value'
Check (@($hardRows | Where-Object { $_.Status -eq 'Pass' -and $_.Recommendation }).Count -eq 0 -and @($hardRows | Where-Object { $_.Status -eq 'Info' -and $_.Recommendation }).Count -eq 0) 'DC Hardening: a Pass or Info row carries no advice'
Check ($hardCb.Recommendation -match 'LDAP server channel binding token requirements' -and $hardClient.Recommendation -match 'Microsoft network client: Digitally sign communications') 'DC Hardening: each Warning row carries the advice of its own family'
Check (@($hardRows | Where-Object { $_.Item -like '*: Print Spooler' -or $_.Item -like '*: SMBv1' -or $_.Item -like '*: LDAP signing required' }).Count -eq 0) 'DC Hardening: the pre-1.20.0 row names are gone, so nothing is reported twice'
# C4: the Laps section must be wired, must read the schema and the computers through the AD
# stubs, and must grade only what is in its population. The stub domain holds eight computer
# objects: one DC, three in population (one of them with no expiry time), four left out.
$lapsRows = @($smokeFindings | Where-Object { $_.Section -eq 'Windows LAPS' })
Check (@($lapsRows).Count -eq 3) ("Section 'Windows LAPS' is wired into Invoke-Main and gives the schema row, one coverage row and one DSRM row for the stub domain ({0} rows, expected 3)" -f @($lapsRows).Count)
$lapsSchema = @($lapsRows | Where-Object { $_.Item -eq 'Windows LAPS schema' })
Check (@($lapsSchema).Count -eq 1 -and $lapsSchema[0].Status -eq 'Pass' -and $lapsSchema[0].Detail -match 'six attributes' -and $lapsSchema[0].Scope -eq 'contoso.com') 'Windows LAPS: the schema row passes on the six attributes the schema stub defines, and carries the forest as Scope'
Check (@($lapsSchema).Count -eq 1 -and $lapsSchema[0].Detail -match 'msLAPS-CurrentPasswordVersion: absent' -and $lapsSchema[0].Detail -match 'Legacy Microsoft LAPS attributes: absent') 'Windows LAPS: the schema row reports the 2025 attribute and the legacy attributes as absent, without requiring either'
$lapsCov = @($lapsRows | Where-Object { $_.Item -eq 'LAPS coverage: contoso.com' })
Check (@($lapsCov).Count -eq 1 -and $lapsCov[0].Status -eq 'Warning' -and $lapsCov[0].Scope -eq 'contoso.com') 'Windows LAPS: the coverage row is a Warning for a domain with one in-population computer without an expiry time, and carries its domain'
Check (@($lapsCov).Count -eq 1 -and $lapsCov[0].Detail -match '^1 of 3 computer account\(s\) in population \(33\.33 %\) have no LAPS expiry time visible to this account') 'Windows LAPS: the share is counted over the population - three computers, not the eight objects read'
Check (@($lapsCov).Count -eq 1 -and $lapsCov[0].Detail -match 'Read 8 computer object\(s\)' -and $lapsCov[0].Detail -match 'In population 3: Windows LAPS expiry time visible 2; legacy Microsoft LAPS expiry time only 0; no LAPS expiry time visible to this account 1\.') 'Windows LAPS: the counts reconcile - 8 read, 3 in population, 2 with and 1 without'
Check (@($lapsCov).Count -eq 1 -and $lapsCov[0].Detail -match 'Out of population 5: domain controllers 1 .*; managed service accounts 0; disabled 1; no operatingSystem recorded 1; operatingSystem not Windows 1; .* stale 1;') 'Windows LAPS: the disabled, non-Windows, cluster and stale objects and the DC are each counted out of the population, by name of class'
Check (@($lapsCov).Count -eq 1 -and $lapsCov[0].Detail -match 'No LAPS expiry time visible: ws2\.contoso\.com\.' -and $lapsCov[0].Detail -notmatch 'visible: .*(linux1|cluster1|ws-off|ws-stale)') 'Windows LAPS: only the in-population computer is named as having no expiry time visible - not the Linux host, the cluster object, the disabled or the stale one'
Check (@($lapsCov).Count -eq 1 -and $lapsCov[0].Detail -match 'tool default, not a Microsoft value' -and $lapsCov[0].Detail -match 'Microsoft Entra ID' -and $lapsCov[0].Detail -match 'not set and not readable look the same') 'Windows LAPS: the coverage row labels its thresholds as tool defaults and says what the read cannot tell apart or see'
Check (@($lapsCov).Count -eq 1 -and $lapsCov[0].Recommendation -match 'Set-LapsADComputerSelfPermission' -and $lapsCov[0].Recommendation -notmatch 'wbadmin|scavenging|Disable first, delete later|repadmin') 'Windows LAPS: the Warning carries the LAPS advice, not the backup, scavenging, stale-account or replication advice its wording would otherwise attract'
$lapsDsrm = @($lapsRows | Where-Object { $_.Item -eq 'DSRM password backup: dc1.contoso.com' })
Check (@($lapsDsrm).Count -eq 1 -and $lapsDsrm[0].Status -eq 'Pass' -and $lapsDsrm[0].Scope -eq 'contoso.com' -and $lapsDsrm[0].Detail -match 'A Windows LAPS expiry time is visible' -and $lapsDsrm[0].Detail -match 'inference') 'Windows LAPS: the stub DC (build 17763, domain level 7) has a current expiry time, so its DSRM row passes and says the evidence is an inference'
Check (@($lapsDsrm).Count -eq 1 -and $lapsDsrm[0].Detail -match 'PORT-PLAN C4a' -and -not $lapsDsrm[0].Recommendation) 'Windows LAPS: the DSRM row says the registry policy was not read, and a passing row carries no advice'
# The hard rule, end to end. The Identity export of this same run was handed the seven secret
# attributes by the stub, each holding a sentinel string. It must be in no file of the bundle.
$sentinelHits = @(Get-ChildItem -Path $result.OutputRoot -Recurse -File | Where-Object { (Get-Content -LiteralPath $_.FullName -Raw) -match [regex]::Escape($script:SmokeSecretSentinel) })
Check ($sentinelHits.Count -eq 0) ("Hard rule: no file of the output bundle holds a value of a LAPS password attribute ({0} file(s) do)" -f $sentinelHits.Count)
$allComputersCsv = @(Get-ChildItem -Path $result.CsvPath -Filter 'AllComputers_*.csv')
$allComputersColumns = @((Import-Csv $allComputersCsv[0].FullName | Select-Object -First 1).PSObject.Properties.Name)
Check (@($script:SmokeLapsSecretNames | Where-Object { $allComputersColumns -contains $_ }).Count -eq 0) 'Hard rule: the computer export has no column for any of the seven secret LAPS attributes'
# C4b (v1.33.0): the export asks for a declared list, and its columns are that list, in order, then
# Enabled and ListComplete. Non-vacuity of the sentinel check above: the stub DID hand every export
# object the seven secret attributes (the sentinel), and the export kept none of them.
Check ((@($allComputersColumns) -join ',') -eq ((@($script:Config.DirectoryRead['ComputerExportProperties']) + @('Enabled', 'ListComplete')) -join ',')) 'C4b: the computer export columns are the declared list, in order, then Enabled and ListComplete'
$allUsersCsv = @(Get-ChildItem -Path $result.CsvPath -Filter 'AllUsers_*.csv')
$allUsersRows = @(Import-Csv $allUsersCsv[0].FullName)
Check ((@($allUsersRows[0].PSObject.Properties.Name) -join ',') -eq ((@($script:Config.DirectoryRead['UserExportProperties']) + @('Enabled', 'ListComplete')) -join ',')) 'C4b: the user export columns are the declared list, in order, then Enabled and ListComplete'
Check ($allUsersRows.Count -eq 3 -and @($allUsersRows | Where-Object { $_.Enabled -eq 'False' -and $_.sAMAccountName -eq 'smoke.two' }).Count -eq 1 -and @($allUsersRows | Where-Object { $_.servicePrincipalName -eq 'HTTP/app.contoso.com;HTTP/app' }).Count -eq 1 -and @($allUsersRows | Where-Object { $_.ListComplete -ne 'Yes' }).Count -eq 0) 'C4b: three users exported, the disabled one Enabled False, two SPNs joined, every row ListComplete Yes (declared population: three users)'
$allComputersRows = @(Import-Csv $allComputersCsv[0].FullName)
Check ($allComputersRows.Count -eq 3 -and @($allComputersRows | Where-Object { $_.sAMAccountName -eq 'gmsa1$' }).Count -eq 1) 'C4b: three computer objects exported, the gMSA among them (a computer subclass), as Get-ADComputer -Filter * did (declared population: three)'
Check ((@($script:SmokeExportCalls) -join ',') -eq ('User@contoso.com#{0},Computer@contoso.com#{0}' -f ([int]$script:Config.Inventory['MaxObjects'] + 1))) ("C4b: one user and one computer export read, each naming the domain and asking for MaxObjects + 1 ({0})" -f (@($script:SmokeExportCalls) -join ', '))
$c4bIdentityCsv = Join-Path $result.CsvPath 'Identity Inventory.csv'
if (Test-Path $c4bIdentityCsv) {
    $c4bIdentity = @(Import-Csv $c4bIdentityCsv)
    Check (@($c4bIdentity | Where-Object { $_.Object -eq 'Users' -and $_.Status -eq 'Info' -and $_.Total -eq '3' -and $_.Enabled -eq '2' -and $_.Disabled -eq '1' -and $_.Scope -eq 'contoso.com' }).Count -eq 1 -and @($c4bIdentity | Where-Object { $_.Object -eq 'Computers' -and $_.Status -eq 'Info' -and $_.Total -eq '3' }).Count -eq 1) 'C4b: the Identity Inventory summary counts what the declared read returned, per domain'
    Check (@($c4bIdentity | Where-Object { $_.Detail -match 'Declared attribute list \(DirectoryRead\.' }).Count -eq 2) 'C4b: the summary says the export is the declared list, not every attribute'
}
else { Check $false 'C4b: Identity Inventory CSV exists' }
Check (@($script:SmokeC4bCalls | Where-Object { $_ -like 'Trust:*' }).Count -eq 1 -and @($script:SmokeC4bCalls | Where-Object { $_ -like 'SiteLink:*' }).Count -eq 1 -and @($script:SmokeC4bCalls | Where-Object { $_ -like 'Connection:*' }).Count -eq 1) ("C4b: one trust read, one site link read and one connection read, each with its declared list ({0} reads)" -f @($script:SmokeC4bCalls).Count)
Check (@($script:SmokeC4bCalls | Where-Object { $_ -like 'Trust:*' -and $_ -like '*@contoso.com' }).Count -eq 1) 'C4b: the trust read names its domain'
$c4bLinksCsv = Join-Path $result.CsvPath 'Site Links.csv'
$c4bConnCsv = Join-Path $result.CsvPath 'Replication Connections.csv'
if ((Test-Path $c4bLinksCsv) -and (Test-Path $c4bConnCsv)) {
    Check (@(Import-Csv $c4bLinksCsv | Where-Object { $_.Name -eq 'DEFAULTIPSITELINK' -and $_.Cost -eq '100' -and $_.SitesIncluded -eq 'CN=Default-First-Site-Name' }).Count -eq 1) 'C4b: the site link row is mapped from the declared list'
    $c4bConn = @(Import-Csv $c4bConnCsv)
    Check ($c4bConn.Count -eq 1 -and (@($c4bConn[0].PSObject.Properties.Name) -join ',') -eq 'Name,FromServer,ToServer,DistinguishedName,Enabled,Options,AutoGenerated,OptionFlags,Detail' -and $c4bConn[0].FromServer -match '^CN=NTDS Settings,CN=DC2,' -and $c4bConn[0].Enabled -eq 'True' -and $c4bConn[0].Options -eq '1') 'C4b: the connection row carries fromServer, the DN, enabledConnection and options'
    # PORT-PLAN C4b3: options decoded by the MS-ADTS table, the destination from the parent of the DN.
    Check ($c4bConn[0].ToServer -eq 'CN=NTDS Settings,CN=DC1,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=contoso,DC=com' -and $c4bConn[0].AutoGenerated -eq 'Yes' -and $c4bConn[0].OptionFlags -eq 'NTDSCONN_OPT_IS_GENERATED' -and $c4bConn[0].Detail -eq '') 'C4b3: the connection row names its destination NTDS Settings object and is read as generated (IG, options 0x1)'
}
else { Check $false 'C4b: Site Links and Replication Connections CSVs exist' }
# PORT-PLAN C4b4: with no override file every C15 row names the built-in cap as a tool default, by its table.
$c4b4Counts = @(@(Import-Csv $result.FindingsFile) | Where-Object { $_.Section -eq 'Object Counts' -and $_.Scope -eq 'contoso.com' })
Check ($c4b4Counts.Count -gt 0) ("C4b4: the Object Counts section reached the findings ({0} rows)" -f $c4b4Counts.Count)
$c4b4CountsCsv = @(Import-Csv (Join-Path $result.CsvPath 'Object Counts.csv') | Where-Object { $_.Scope -eq 'contoso.com' })
Check ($c4b4CountsCsv.Count -gt 0 -and @($c4b4CountsCsv | Where-Object { $_.Evidence -notmatch '\(Inventory\.MaxObjects, a tool default\)' }).Count -eq 0) ("C4b4: every Object Counts row names its cap as Inventory.MaxObjects, a tool default ({0} rows)" -f $c4b4CountsCsv.Count)
# PORT-PLAN C11h: a grid row that passed carries no advice; none reaches an unscoped entry.
$c11hUnscoped = @($script:RecommendationMap | Where-Object { -not $_.ContainsKey('Section') } | ForEach-Object { [string]$_.Text })
$c11hDd = @(@(Import-Csv $result.FindingsFile) | Where-Object { $_.Section -eq 'DC Diagnostics' -and $_.Item -eq 'dc1.contoso.com' })
Check ($c11hDd.Count -eq 1 -and $c11hDd[0].Status -eq 'Pass' -and $c11hDd[0].Recommendation -eq '') 'C11h: the grid row of dc1 passes and carries no advice'
Check (@(@(Import-Csv $result.FindingsFile) | Where-Object { $_.Section -eq 'DC Diagnostics' -and $_.Recommendation -ne '' -and $c11hUnscoped -contains $_.Recommendation }).Count -eq 0) 'C11h: no DC Diagnostics row reaches an unscoped advice entry'
$c4bTrustCsv = @(Import-Csv (Join-Path $result.CsvPath 'Trusts & Two-Way Health.csv'))
Check (@($c4bTrustCsv | Where-Object { $_.TrustName -eq 'fabrikam.com' -and $_.Created -ne '' }).Count -eq 1) 'C4b: the trust health row is built from the declared list and carries Created'
# C5: the DcCertificates section must be wired, must read the directory through the AD stub,
# and in a default run must NOT make the handshake. Declared population: one DC, so one LDAPS
# row (Not Assessed, not run) and one row per published certificate (two).
$certRows = @($smokeFindings | Where-Object { $_.Section -eq 'DC Certificates' })
Check (@($certRows).Count -eq 3) ("Section 'DC Certificates' is wired into Invoke-Main and gives one LDAPS row and one row per published certificate for the stub DC ({0} rows, expected 3)" -f @($certRows).Count)
Check (@($script:SmokeTlsCalls).Count -eq 0) ("DC Certificates: a default run makes no handshake ({0} calls)" -f @($script:SmokeTlsCalls).Count)
$certLdaps = @($certRows | Where-Object { $_.Item -eq 'LDAPS certificate: dc1.contoso.com' })
Check (@($certLdaps).Count -eq 1 -and $certLdaps[0].Status -eq 'Not Assessed' -and $certLdaps[0].Detail -match '^Not run: ' -and $certLdaps[0].Detail -match '-IncludeLdapsHandshake') 'DC Certificates: without the switch the LDAPS row is Not Assessed and names the switch, never Pass'
$certValid = @($certRows | Where-Object { $_.Item -eq ("Directory certificate: dc1.contoso.com [{0}]" -f $script:SmokeCertValid.Thumbprint.ToUpperInvariant()) })
$certExpired = @($certRows | Where-Object { $_.Item -eq ("Directory certificate: dc1.contoso.com [{0}]" -f $script:SmokeCertExpired.Thumbprint.ToUpperInvariant()) })
Check (@($certValid).Count -eq 1 -and $certValid[0].Status -eq 'Pass' -and $certValid[0].Detail -match 'Directory evidence') 'DC Certificates: the published valid certificate passes, labelled directory evidence'
Check (@($certExpired).Count -eq 1 -and $certExpired[0].Status -eq 'Fail' -and $certExpired[0].Detail -match '^Published in the directory: expired on') 'DC Certificates: the published expired certificate is a Fail'
Check (@($certExpired).Count -eq 1 -and $certExpired[0].Recommendation -match 'userCertificate' -and $certExpired[0].Recommendation -notmatch 'ENROLLEE_SUPPLIES_SUBJECT|wbadmin|repadmin') 'DC Certificates: the Fail carries the directory certificate advice, not the template or backup advice'
Check (@($certRows | Where-Object { $_.Scope -eq 'contoso.com' }).Count -eq 3) 'DC Certificates: every row carries its domain as Scope'
Check (@($certRows | Where-Object { $_.Status -ne 'Fail' -and $_.Recommendation }).Count -eq 0) 'DC Certificates: a row that is not a Fail or a Warning carries no advice'
$certCsv = Join-Path $result.CsvPath 'DC Certificates.csv'
if (Test-Path $certCsv) {
    $certColumns = @((Import-Csv $certCsv | Select-Object -First 1).PSObject.Properties.Name)
    Check (@('Evidence', 'Thumbprint', 'NotAfterUtc', 'DaysLeft', 'CertSubject', 'CertIssuer', 'Ekus', 'SslPolicyErrors', 'ChainStatus', 'NotRun' | Where-Object { $certColumns -notcontains $_ }).Count -eq 0) 'DC Certificates: the section CSV carries the evidence columns'
    Check (@(Import-Csv $certCsv | Where-Object { $_.Ekus -match 'Server Authentication \(1\.3\.6\.1\.5\.5\.7\.3\.1\)' }).Count -eq 2) 'DC Certificates: the EKUs of both published certificates are named in their column'
}
else { Check $false 'DC Certificates CSV exists' }
# C6: the RidPool section must be wired, must read CN=RID Manager$ and the DC's RID Set through the
# AD stubs, and must report the stub domain's two rows and the stub DC's pool. Declared population:
# one domain (two rows) and one DC (one row).
$ridRows = @($smokeFindings | Where-Object { $_.Section -eq 'RID Pool' })
Check (@($ridRows).Count -eq 3) ("Section 'RID Pool' is wired into Invoke-Main and gives two rows for the stub domain and one for its DC ({0} rows, expected 3)" -f @($ridRows).Count)
$ridAlloc = @($ridRows | Where-Object { $_.Item -eq 'RID pool allocation: contoso.com' })
Check (@($ridAlloc).Count -eq 1 -and $ridAlloc[0].Status -eq 'Not Assessed' -and $ridAlloc[0].Detail -match '^Not returned: ' -and $ridAlloc[0].Detail -match 'NOT SET' -and $ridAlloc[0].Detail -match "cannot be told from 'not readable'") 'RID Pool: an allocation attribute that is not returned, on a schema that defines it, is Not Assessed - never a pass, because an unset value and one this account cannot read look the same - and says why'
$ridSpace = @($ridRows | Where-Object { $_.Item -eq 'Global RID space: contoso.com' })
Check (@($ridSpace).Count -eq 1 -and $ridSpace[0].Status -eq 'Pass' -and $ridSpace[0].Detail -match '^2,100 of 1,073,741,823 RIDs issued \(0\.0001 % used\)') 'RID Pool: the global space is decoded from Microsoft''s sample value - 2,100 issued of 1,073,741,823 - and passes'
$ridDc = @($ridRows | Where-Object { $_.Item -eq 'RID pool: dc1.contoso.com' })
Check (@($ridDc).Count -eq 1 -and $ridDc[0].Status -eq 'Info' -and $ridDc[0].Detail -match 'Current pool \(rIDPreviousAllocationPool\): 2100-2599, 500 RIDs\. Next RID \(rIDNextRID\): 2150\. Remaining in this pool: 450') 'RID Pool: the DC''s pool is read through rIDSetReferences and reported as Info, never Pass'
Check (@($ridRows | Where-Object { $_.Scope -eq 'contoso.com' }).Count -eq 3) 'RID Pool: every row carries its domain as Scope'
Check (@($ridRows | Where-Object { $_.Recommendation }).Count -eq 0) 'RID Pool: a row that is not a Warning or a Fail carries no advice'
Check (@($ridRows | Where-Object { $_.Detail -match 'SidCompatibilityVersion' }).Count -eq 2) 'RID Pool: both domain rows say, in their NotRun note, that SidCompatibilityVersion was not read'
$ridCsv = Join-Path $result.CsvPath 'RID Pool.csv'
if (Test-Path $ridCsv) {
    $ridCsvRows = @(Import-Csv $ridCsv)
    $ridCsvSpace = @($ridCsvRows | Where-Object { $_.Item -eq 'Global RID space: contoso.com' })
    Check (@($ridCsvSpace).Count -eq 1 -and $ridCsvSpace[0].Ceiling -eq '1073741823' -and $ridCsvSpace[0].Issued -eq '2100' -and $ridCsvSpace[0].CeilingSource -eq '30-bit (default)' -and $ridCsvSpace[0].RidMaster -eq 'dc1.contoso.com') 'RID Pool: the section CSV carries the ceiling, the RIDs issued, the ceiling''s label and the RID master in their own columns'
    $ridCsvDc = @($ridCsvRows | Where-Object { $_.Item -eq 'RID pool: dc1.contoso.com' })
    Check (@($ridCsvDc).Count -eq 1 -and $ridCsvDc[0].PoolStart -eq '2100' -and $ridCsvDc[0].PoolEnd -eq '2599' -and $ridCsvDc[0].NextPoolStart -eq '3100' -and $ridCsvDc[0].ObjectDn -eq 'CN=RID Set,CN=DC1,OU=Domain Controllers,DC=contoso,DC=com') 'RID Pool: the DC row carries its pool bounds, the prefetched pool and the RID Set DN in their own columns'
}
else { Check $false 'RID Pool CSV exists' }
# C7: the SID history rows must be wired into Security Posture, must read the principals of the
# scoped domain through the stubbed query (bytes), and must keep names and SIDs out of Detail.
$shRows = @($smokeFindings | Where-Object { $_.Section -eq 'Security Posture' -and $_.Item -like 'SID history*' })
Check (@($shRows).Count -eq 4) ("SID history: wired into Security Posture with four rows for the stub domain ({0} rows, expected 4)" -f @($shRows).Count)
Check (@($shRows | Where-Object { $_.Scope -eq 'contoso.com' }).Count -eq 4) 'SID history: every row carries its domain as Scope'
Check (@($smokeFindings | Where-Object { $_.Section -eq 'Security Posture' -and $_.Item -eq 'krbtgt password age' }).Count -eq 1) 'SID history: non-vacuity - the older Security Posture rows are still there'
$shCount = @($shRows | Where-Object { $_.Item -eq 'SID history: contoso.com' })
Check (@($shCount).Count -eq 1 -and $shCount[0].Status -eq 'Warning' -and $shCount[0].Detail -match '^3 security principal\(s\) with sIDHistory visible to this account in contoso\.com: 1 user, 1 computer .*, 1 group, 0 other; 1 enabled, 1 disabled, 1 with no enabled state' -and $shCount[0].Detail -match 'tool default, not a Microsoft value') 'SID history: three principals read from bytes - a user, a computer and a group, enabled state from userAccountControl - graded Warning as a labelled tool default'
Check (@($shCount).Count -eq 1 -and $shCount[0].Recommendation -match 'Set-ADUser' -and $shCount[0].Recommendation -notmatch 'krbtgt|wbadmin|repadmin') 'SID history: the count row carries its own advice'
Check (@($shRows | Where-Object { $_.Item -eq 'SID history same-domain: contoso.com' -and $_.Status -eq 'Pass' }).Count -eq 1 -and @($shRows | Where-Object { $_.Item -eq 'SID history privileged: contoso.com' -and $_.Status -eq 'Pass' }).Count -eq 1) 'SID history: no same-domain and no privileged value in contoso.com, so both pass'
$shSources = @($shRows | Where-Object { $_.Item -eq 'SID history sources: contoso.com' })
Check (@($shSources).Count -eq 1 -and $shSources[0].Status -eq 'Info' -and $shSources[0].Detail -match '3 distinct domain part\(s\) - 0 in this forest, 1 trust partner\(s\) of this domain, 0 builtin or well-known, 2 unresolved' -and $shSources[0].Detail -match 'Trusts section') 'SID history: one source resolved through the trusted domain object, two unresolved (north.contoso.com is not in this single-domain forest), and the Trusts section named for SID filtering'
Check (@($shRows | Where-Object { $_.Detail -match 'mig\.user1|ws-mig|S-1-5-21-7-8-9' }).Count -eq 0) 'SID history: no account name and no SID in any Detail'
$spCsv = Join-Path $result.CsvPath 'Security Posture.csv'
if (Test-Path $spCsv) {
    $spCsvRows = @(Import-Csv $spCsv)
    $spCsvCount = @($spCsvRows | Where-Object { $_.Item -eq 'SID history: contoso.com' })
    Check (@($spCsvCount).Count -eq 1 -and $spCsvCount[0].PrincipalCount -eq '3' -and $spCsvCount[0].Principals -eq 'mig.user1; mig.group1; ws-mig$' -and $spCsvCount[0].DomainSid -eq 'S-1-5-21-1-2-3') 'SID history: the section CSV carries the count, the names and the domain SID in their own columns'
    $spCsvSources = @($spCsvRows | Where-Object { $_.Item -eq 'SID history sources: contoso.com' })
    Check (@($spCsvSources).Count -eq 1 -and $spCsvSources[0].SourceDomains -match 'S-1-5-21-7-8-9 \(fabrikam\.com, trust partner\) x1' -and $spCsvSources[0].SourceDomains -match 'S-1-5-21-99-98-97 \(unresolved\) x1') 'SID history: the source domains column names the trust partner and the unresolved domain'
    Check (@($spCsvRows | Where-Object { $_.Item -eq 'krbtgt password age' }).Count -eq 1) 'SID history: non-vacuity - the CSV holds the older rows too'
}
else { Check $false 'Security Posture CSV exists' }
# C8: the GPO version rows must be wired into GPO Inventory after the unchanged inventory rows, must
# read the containers through the stubbed query and GPT.INI through the stubbed file seam, on the PDC.
$gpoRows = @($smokeFindings | Where-Object { $_.Section -eq 'GPO Inventory' })
$gpoVer = @($gpoRows | Where-Object { $_.Item -like 'GPO version*' -or $_.Item -like 'GPO folder*' })
Check (@($gpoVer).Count -eq 1) ("GPO version: wired into GPO Inventory with one summary row for the stub domain, and no row for two GPOs that agree ({0} rows, expected 1)" -f @($gpoVer).Count)
Check (@($gpoRows | Where-Object { $_.Item -eq 'GroupPolicy module' -and $_.Status -eq 'Not Assessed' }).Count -eq 1) 'GPO version: non-vacuity - the inventory''s own row (no GroupPolicy module on this host) is still there'
$gpoSum = @($gpoVer | Where-Object { $_.Item -eq 'GPO version summary: contoso.com' })
Check (@($gpoSum).Count -eq 1 -and $gpoSum[0].Status -eq 'Pass' -and $gpoSum[0].Scope -eq 'contoso.com' -and $gpoSum[0].Detail -match '^All 2 GPO\(s\) of contoso\.com visible to this account were compared on dc1\.contoso\.com' -and -not $gpoSum[0].Recommendation) 'GPO version: two GPOs whose directory and GPT.INI versions agree pass on the PDC, without the GroupPolicy module, and carry no advice'
Check (@($script:SmokeGptIniCalls).Count -eq 2 -and @($script:SmokeGptIniCalls | Where-Object { $_ -notmatch '^\\\\dc1\.contoso\.com\\SYSVOL\\contoso\.com\\Policies\\\{[0-9A-F-]{36}\}\\GPT\.INI$' }).Count -eq 0) ("GPO version: each GPT.INI is read from the PDC's own SYSVOL share, never from the host gPCFileSysPath names ({0})" -f ($script:SmokeGptIniCalls -join ', '))
$gpoCsv = Join-Path $result.CsvPath 'GPO Inventory.csv'
if (Test-Path $gpoCsv) {
    $gpoCsvSum = @(Import-Csv $gpoCsv | Where-Object { $_.Item -eq 'GPO version summary: contoso.com' })
    Check (@($gpoCsvSum).Count -eq 1 -and $gpoCsvSum[0].Population -eq '2' -and $gpoCsvSum[0].Compared -eq '2' -and $gpoCsvSum[0].Mismatched -eq '0' -and $gpoCsvSum[0].ReadFrom -eq 'dc1.contoso.com' -and $gpoCsvSum[0].FoldersWithoutContainer -eq '0') 'GPO version: the section CSV carries the declared population and the counts in their own columns'
    Check (@($gpoCsvSum).Count -eq 1 -and $gpoCsvSum[0].Evidence -eq 'directory and SYSVOL') 'GPO version: the summary''s Evidence names SYSVOL, which was listed and read'
}
else { Check $false 'GPO Inventory CSV exists' }
# C9: the Dangerous ACLs rows must be wired, must read each descriptor from the scoped domain with
# nTSecurityDescriptor alone (the stub throws otherwise), and must flag the non-default SID by SID.
$aclRows = @($smokeFindings | Where-Object { $_.Section -eq 'Dangerous ACLs (DCSync)' })
Check (@($aclRows).Count -eq 6) ("Dangerous ACLs: wired, with three object rows, one row per GPO (two) and a GPO summary for the stub domain ({0} rows, expected 6)" -f @($aclRows).Count)
Check (@($aclRows | Where-Object { $_.Scope -ne 'contoso.com' }).Count -eq 0) 'Dangerous ACLs: every row carries its domain as Scope'
$aclDcsync = @($aclRows | Where-Object { $_.Item -eq 'DCSync rights: contoso.com' })
Check (@($aclDcsync).Count -eq 1 -and $aclDcsync[0].Status -eq 'Warning' -and $aclDcsync[0].Detail -match ("{0} \(DS-Replication-Get-Changes-All\)" -f [regex]::Escape($script:SmokeAclFake)) -and $aclDcsync[0].Detail -match 'matched by SID only, never by name' -and $aclDcsync[0].Detail -match 'allowlist provisional') 'Dangerous ACLs: the non-default SID holding Get-Changes-All is a Warning, named by SID, matched by SID only, allowlist provisional'
Check (@($aclDcsync).Count -eq 1 -and $aclDcsync[0].Recommendation -match 'Entra Connect' -and $aclDcsync[0].Recommendation -notmatch 'repadmin|dfsrmig|wbadmin|New-KrbtgtKeys') 'Dangerous ACLs: the DCSync row carries its own advice, not the replication or backup advice its Detail words would attract'
Check (@($aclRows | Where-Object { $_.Item -ne 'DCSync rights: contoso.com' -and $_.Status -eq 'Pass' }).Count -eq 5) 'Dangerous ACLs: the control row, AdminSDHolder, both GPOs and the GPO summary pass on Microsoft''s default holders'
Check (@($aclRows | Where-Object { $_.Detail -match 'Fake Administrators' }).Count -eq 0) 'Dangerous ACLs: no display name in any Detail'
Check (@($script:SmokeAclCalls).Count -eq 3 -and @($script:SmokeAclCalls | Where-Object { $_ -notmatch '@contoso\.com$' }).Count -eq 0) ("Dangerous ACLs: three descriptor reads - the head, AdminSDHolder and the GPO search - each from the domain itself ({0})" -f ($script:SmokeAclCalls -join ', '))
$aclCsv = Join-Path $result.CsvPath 'Dangerous ACLs (DCSync).csv'
if (Test-Path $aclCsv) {
    $aclCsvRows = @(Import-Csv $aclCsv)
    $aclCsvSync = @($aclCsvRows | Where-Object { $_.Item -eq 'DCSync rights: contoso.com' })
    Check (@($aclCsvSync).Count -eq 1 -and $aclCsvSync[0].FlaggedSids -eq $script:SmokeAclFake -and $aclCsvSync[0].Principals -eq ("{0} = CONTOSO\Fake Administrators" -f $script:SmokeAclFake) -and $aclCsvSync[0].CatalogueId -eq 'ADA-ACL-001' -and $aclCsvSync[0].AceCount -eq '12') 'Dangerous ACLs: the CSV carries the flagged SID, its display name in its own column, the catalogue id and the ACE count'
    $aclCsvSum = @($aclCsvRows | Where-Object { $_.Item -eq 'GPO rights summary: contoso.com' })
    Check (@($aclCsvSum).Count -eq 1 -and $aclCsvSum[0].Population -eq '2' -and $aclCsvSum[0].ReadCount -eq '2' -and $aclCsvSum[0].FlaggedCount -eq '0' -and $aclCsvSum[0].NotAssessedCount -eq '0') 'Dangerous ACLs: the GPO summary carries the declared population and the counts in their own columns'
}
else { Check $false 'Dangerous ACLs CSV exists' }
# C10: the three sections must be wired, must read every object from the scoped domain by SID (the
# stub refuses a read that names no domain), and must grade the stub's members, orphan, SPN and
# delegation. Names stay out of Detail.
$paRows = @($smokeFindings | Where-Object { $_.Section -eq 'Privileged Accounts' })
$phRows = @($smokeFindings | Where-Object { $_.Section -eq 'Privileged Hygiene' })
$krRows = @($smokeFindings | Where-Object { $_.Section -eq 'Kerberos Exposure' })
Check (@($paRows).Count -eq 20) ("Privileged Accounts: wired, with the two forest-root rows, 17 group rows and the population row for the stub domain ({0} rows, expected 20)" -f @($paRows).Count)
Check (@($phRows).Count -eq 4 -and @($krRows).Count -eq 6) ("Privileged Hygiene and Kerberos Exposure: four and six rows for the stub domain ({0} and {1})" -f @($phRows).Count, @($krRows).Count)
Check (@(@($paRows) + @($phRows) + @($krRows) | Where-Object { $_.Scope -ne 'contoso.com' }).Count -eq 0) 'C10: every row carries its domain as Scope'
Check (@($paRows | Where-Object { $_.Item -eq 'Schema Admins members: contoso.com' -and $_.Status -eq 'Pass' }).Count -eq 1) 'Privileged Accounts: the empty Schema Admins passes'
$smokeEa = @($paRows | Where-Object { $_.Item -eq 'Enterprise Admins members: contoso.com' })
Check (@($smokeEa).Count -eq 1 -and $smokeEa[0].Status -eq 'Warning' -and $smokeEa[0].Detail -match 'default member' -and $smokeEa[0].Recommendation -match 'day-to-day' -and $smokeEa[0].Recommendation -notmatch 'wbadmin|repadmin|New-KrbtgtKeys') 'Privileged Accounts: Enterprise Admins holding the root Administrator is a Warning that quotes Learn, with its own advice'
Check (@($paRows | Where-Object { $_.Item -eq 'Privileged group population: contoso.com' -and $_.Status -eq 'Pass' }).Count -eq 1) 'Privileged Accounts: every declared group was located by SID and expanded completely'
Check (@($paRows | Where-Object { $_.Item -eq 'Privileged group: Backup Operators: contoso.com' -and $_.Status -eq 'Info' -and -not $_.Recommendation }).Count -eq 1) 'Privileged Accounts: a group named Backup Operators is inventory and attracts no backup advice'
Check (@($phRows | Where-Object { $_.Item -eq 'adminCount orphans: contoso.com' -and $_.Status -eq 'Warning' -and $_.Recommendation -match 'inheritance' }).Count -eq 1) 'Privileged Hygiene: the adminCount=1 user in no protected group is an orphan Warning with its own advice'
Check (@($phRows | Where-Object { $_.Item -eq 'Privileged accounts with SPN: contoso.com' -and $_.Status -eq 'Warning' }).Count -eq 1) 'Privileged Hygiene: the Domain Admins member with an SPN is a Warning'
Check (@($phRows | Where-Object { $_.Item -eq 'Privileged accounts delegable: contoso.com' -and $_.Status -eq 'Warning' -and $_.Recommendation -match 'sensitive and cannot be delegated' }).Count -eq 1) 'Privileged Hygiene: the privileged account without NOT_DELEGATED or Protected Users is a Warning'
Check (@($phRows | Where-Object { $_.Item -eq 'Protected Users members: contoso.com' -and $_.Status -eq 'Info' -and $_.Detail -match '^Not present: ' }).Count -eq 1) 'Privileged Hygiene: the absent Protected Users group is Info "Not present"'
$smokeUnc = @($krRows | Where-Object { $_.Item -eq 'Unconstrained delegation: contoso.com' })
Check (@($smokeUnc).Count -eq 1 -and $smokeUnc[0].Status -eq 'Warning' -and $smokeUnc[0].Detail -match '1 DC account' -and $smokeUnc[0].Recommendation -match 'impersonate') 'Kerberos Exposure: unconstrained delegation outside the DCs is a Warning; the registered DC is excluded by DN'
Check (@($krRows | Where-Object { $_.Item -match '^(Protocol transition|Resource-based) delegation: contoso\.com$' -and $_.Status -eq 'Pass' }).Count -eq 2) 'Kerberos Exposure: no protocol transition and no RBCD pass - the search returned the registered DC, so "none" is measured'
Check (@($krRows | Where-Object { $_.Item -eq 'Constrained delegation: contoso.com' -and $_.Status -eq 'Info' -and $_.Detail -match '^0 account\(s\) of contoso\.com use Kerberos-only' }).Count -eq 1) 'Kerberos Exposure: the constrained-delegation count is given (0) because the search returned the domain''s registered DC'Check (@(@($paRows) + @($phRows) + @($krRows) | Where-Object { $_.Detail -match 'adm\.smoke|old\.smoke|svc\.deleg|HTTP/app' }).Count -eq 0) 'C10: no account name or SPN in any Detail'
Check (@($script:SmokePrivCalls).Count -gt 0 -and @($script:SmokePrivCalls | Where-Object { $_ -notmatch '@(contoso\.com)?$' }).Count -eq 0) ("C10: every directory read went to contoso.com or to the configuration partition ({0} reads)" -f @($script:SmokePrivCalls).Count)
$phCsv = Join-Path $result.CsvPath 'Privileged Hygiene.csv'
if (Test-Path $phCsv) {
    $phCsvRows = @(Import-Csv $phCsv)
    Check (@($phCsvRows | Where-Object { $_.Item -eq 'adminCount orphans: contoso.com' -and $_.Principals -eq 'old.smoke' -and $_.Count -eq '1' -and $_.CatalogueId -eq 'ADA-OBJ-001' }).Count -eq 1) 'Privileged Hygiene: the CSV names the orphan in its own column, with the count and the catalogue id'
    Check (@($phCsvRows | Where-Object { $_.Item -eq 'Privileged accounts with SPN: contoso.com' -and $_.Principals -eq 'adm.smoke' -and $_.Targets -eq 'adm.smoke: HTTP/app.contoso.com' }).Count -eq 1) 'Privileged Hygiene: the CSV carries the SPN in Targets, not in Detail'
    # Declared population: the three rows whose population always holds the domain's Administrator.
    $phPopRows = @($phCsvRows | Where-Object { $_.Item -match '^(adminCount orphans|Privileged accounts with SPN|Privileged accounts delegable): contoso\.com$' })
    Check ($phPopRows.Count -eq 3 -and @($phPopRows | Where-Object { $_.Unresolved -match 'RID 500' -or $_.Detail -match 'RID 500' }).Count -eq 0) 'Privileged Hygiene: the domain''s Administrator (RID 500) was in every population read, so no row reports it missing'
}
else { Check $false 'Privileged Hygiene CSV exists' }
# Site GC coverage is derived from the inventory alone, so it must produce a real verdict here.
$gcRows = @($smokeFindings | Where-Object { $_.Section -eq 'Site Global Catalog Coverage' })
Check (@($gcRows | Where-Object { $_.Status -eq 'Pass' }).Count -eq 1) 'Site GC coverage passes for a stub DC that is a writeable GC in its site'
# C14: reachability classes, subnets and clients without a site, stale enabled objects, SYSVOL engine -
# each wired into its existing section and graded from the stubs. The DC is classified once for the whole
# run: one name resolution and three TCP probes (389, 5985, 135), although three sections read the class.
$c14Reach = @($smokeFindings | Where-Object { $_.Section -eq 'Port Reachability' -and $_.Item -like 'DC reachability*' })
Check (@($c14Reach | Where-Object { $_.Item -eq 'DC reachability: dc1.contoso.com' -and $_.Status -eq 'Pass' -and $_.Scope -eq 'contoso.com' }).Count -eq 1) 'C14 REACH: the stub DC is classified Reachable and reported in Port Reachability, scoped to its domain'
Check (@($script:SmokeReachCalls | Where-Object { $_ -eq 'resolve dc1.contoso.com' }).Count -eq 1 -and @($script:SmokeReachCalls | Where-Object { $_ -like 'tcp *' }).Count -eq 3) ("C14 REACH: the DC is resolved once and probed on 389, 5985 and 135 once each for the whole run ({0})" -f ($script:SmokeReachCalls -join ', '))
Check (@($smokeFindings | Where-Object { $_.Section -eq 'Port Reachability' -and $_.Item -eq 'dc1.contoso.com' }).Count -eq 1) 'C14 REACH: the port matrix row is kept next to the reachability rows'
$c14Site = @($smokeFindings | Where-Object { $_.Section -eq 'Site Health' })
Check (@($c14Site | Where-Object { $_.Item -eq 'Subnets without a site: contoso.com' -and $_.Status -eq 'Pass' }).Count -eq 1) 'C14 SITE: the stub subnet carries a site, so Subnets without a site passes'
Check (@($c14Site | Where-Object { $_.Item -eq 'Clients without a site: dc1.contoso.com' -and $_.Status -eq 'Warning' -and $_.Scope -eq 'contoso.com' -and $_.Detail -notmatch '198\.51\.100' }).Count -eq 1) 'C14 SITE: the NO_CLIENT_SITE line of the stub log is a Warning, with the address kept out of the text'
Check ((@($script:SmokeNetlogonCalls) -join ',') -eq '\\dc1.contoso.com\ADMIN$\debug\netlogon.log,\\dc1.contoso.com\ADMIN$\debug\netlogon.bak') ("C14 SITE, C14c: netlogon.log and then netlogon.bak are read once each, over ADMIN$ of the DC ({0})" -f (@($script:SmokeNetlogonCalls) -join ','))
Check (@($c14Site | Where-Object { $_.Item -eq 'Clients without a site: dc1.contoso.com' -and $_.Detail -match '^1 distinct client' -and $_.Detail -match 'older than the age window' -and $_.Detail -match 'tool default, not a Microsoft value' -and $_.Detail -notmatch '198\.51\.100\.78' }).Count -eq 1) 'C14c SITE: the client in netlogon.bak, last written 60 days ago, is reported as old, not current, under the 30-day tool default'
$c14SiteCsv = Join-Path $result.CsvPath 'Site Health.csv'
if (Test-Path $c14SiteCsv) {
    Check (@(Import-Csv $c14SiteCsv | Where-Object { $_.Item -eq 'Clients without a site: dc1.contoso.com' -and $_.Clients -eq 'WS77 198.51.100.77' }).Count -eq 1) 'C14 SITE: the client name and address are in the Clients column'
    Check (@(Import-Csv $c14SiteCsv | Where-Object { $_.Item -eq 'Clients without a site: dc1.contoso.com' -and $_.ClientCount -eq '1' -and $_.OldClientCount -eq '1' -and $_.BakPath -eq '\\dc1.contoso.com\ADMIN$\debug\netlogon.bak' }).Count -eq 1) 'C14c SITE: one current client, one old client, and the netlogon.bak path in their columns'
}
else { Check $false 'C14 SITE: Site Health CSV exists' }
$c14Stale = @($smokeFindings | Where-Object { $_.Section -eq 'Stale Objects' })
Check (@($c14Stale | Where-Object { $_.Item -eq 'Inactive enabled users' -and $_.Status -eq 'Warning' -and $_.Detail -match '^2 enabled user' -and $_.Detail -match '1 of them never logged on' -and $_.Detail -match 'msDS-LogonTimeSyncInterval is not set' }).Count -eq 1) 'C14 STALE: two stale users, one never logged on, with the logon-sync caveat'
Check (@($c14Stale | Where-Object { $_.Item -eq 'Inactive enabled computers' -and $_.Status -eq 'Warning' -and $_.Detail -match '^1 enabled computer' }).Count -eq 1) 'C14 STALE: one stale computer'
Check (@($c14Stale | Where-Object { $_.Item -eq 'Enabled users with an old password' -and $_.Status -eq 'Warning' -and $_.Detail -match '^1 enabled user' -and $_.Detail -match '1 more must change' }).Count -eq 1) 'C14 STALE: one old password, and pwdLastSet 0 counted as must-change, not graded'
Check (@($c14Stale | Where-Object { $_.Detail -match 'old\.user|never\.user|old\.pwd' }).Count -eq 0) 'C14 STALE: no account name in any Detail'
Check (@($script:SmokeStaleCalls | Where-Object { $_ -match ' contoso\.com$' }).Count -eq 3) ("C14 STALE: three stale reads, each sent to the domain ({0})" -f ($script:SmokeStaleCalls -join ', '))
Check ((@($script:SmokePopulationCalls) -join ',') -eq 'user contoso.com,computer contoso.com') ("C14 STALE review: the enabled user and computer populations counted once each, from the domain ({0})" -f (@($script:SmokePopulationCalls) -join ', '))
Check (@($c14Stale | Where-Object { $_.Item -eq 'Inactive enabled users' -and $_.Detail -match 'The read saw 5 enabled user account' }).Count -eq 1) 'C14 STALE review: the inactive users row states its declared population (five enabled users)'
# The Population and AgeNotKnown columns are in the section CSV, not in the consolidated one.
$c14StaleCsv = Join-Path $result.CsvPath 'Stale Objects.csv'
if (Test-Path $c14StaleCsv) {
    $c14StaleCols = @(Import-Csv $c14StaleCsv)
    Check (@($c14StaleCols | Where-Object { $_.Item -eq 'Inactive enabled users' -and $_.Population -eq '5' }).Count -eq 1) 'C14 STALE review: the inactive users row carries its population (five enabled users) in the Population column'
    Check (@($c14StaleCols | Where-Object { $_.Item -eq 'Inactive enabled computers' -and $_.Population -eq '3' }).Count -eq 1) 'C14 STALE review: the inactive computers row carries its population (three enabled computers)'
    Check (@($c14StaleCols | Where-Object { $_.Item -eq 'Enabled users with an old password' -and $_.Population -eq '5' -and $_.AgeNotKnown -eq '0' -and $_.MustChangeAtNextLogon -eq '1' }).Count -eq 1) 'C14 STALE review: the password row carries its population, one must-change and no password of unknown age'
}
else { Check $false 'C14 STALE review: Stale Objects CSV exists' }
$c14Sysvol = @($smokeFindings | Where-Object { $_.Section -eq 'SYSVOL / DFSR' })
Check (@($c14Sysvol | Where-Object { $_.Item -eq 'SYSVOL replication engine: contoso.com' -and $_.Status -eq 'Pass' -and $_.Detail -match 'Eliminated' }).Count -eq 1) 'C14 SYSVOL: the stub domain replicates SYSVOL with DFSR, corroborated by msDFSR-Flags 48'
Check (@($c14Sysvol | Where-Object { $_.Item -eq 'SYSVOL engine: dc1.contoso.com' -and $_.Status -eq 'Info' }).Count -eq 1) 'C14 SYSVOL: the stub DC has its engine row'
Check (@($c14Sysvol | Where-Object { $_.Item -eq 'SYSVOL engine: dc1.contoso.com' -and $_.Detail -match 'The registry agrees' -and $_.Detail -match 'Local State' -and $_.Detail -match 'Eliminated' }).Count -eq 1) 'C14c SYSVOL: the second instrument, the registry Local State (3, Eliminated), agrees with the directory objects'
$c14cFuture = @($c14Stale | Where-Object { $_.Item -like 'Future logon timestamps: *' })
Check (@($c14cFuture).Count -eq 2 -and @($c14cFuture | Where-Object { $_.Status -ne 'Info' -or $_.Scope -ne 'contoso.com' }).Count -eq 0) ("C14c STALE: one future-timestamp row for users and one for computers, Info and scoped to the domain ({0} rows)" -f @($c14cFuture).Count)
Check (@($c14cFuture | Where-Object { $_.Item -eq 'Future logon timestamps: users' -and $_.Detail -match '^1 enabled user' -and $_.Detail -notmatch 'clock\.skewed' }).Count -eq 1) 'C14c STALE: the user with a lastLogonTimestamp 30 days ahead is counted, its name kept out of the text'
Check (@($c14Stale | Where-Object { $_.Item -eq 'Inactive enabled users' -and $_.Detail -match 'carry a lastLogonTimestamp in the future' }).Count -eq 1) 'C14c STALE: the inactive users row says the future account is neither stale nor recent'
Check ((@($script:SmokeFutureCalls) -join ',') -eq 'user contoso.com,computer contoso.com') ("C14c STALE: the future reads of users and computers, once each, from the domain ({0})" -f (@($script:SmokeFutureCalls) -join ', '))

# C15: the inventory families, each in its own report section of an existing -Sections value, every row
# Info or Not Assessed (the catalogue grades none), scoped to the domain, read from it.
$c15Sections = @('Topology Inventory', 'Trust Inventory', 'Object Counts', 'Group Inventory', 'GPO Directory Inventory', 'Event Inventory', 'Time Configuration')
foreach ($c15s in $c15Sections) { Check (@($smokeFindings | Where-Object { $_.Section -eq $c15s }).Count -gt 0) ("C15: the '{0}' section is wired and reported" -f $c15s) }
Check (@($smokeFindings | Where-Object { ($c15Sections -contains $_.Section -or $_.Item -like 'Stale disabled *') -and @('Info', 'Not Assessed') -notcontains $_.Status }).Count -eq 0) 'C15: no inventory row is Pass, Warning or Fail'
$c15Topo = @($smokeFindings | Where-Object { $_.Section -eq 'Topology Inventory' })
Check (@($c15Topo | Where-Object { $_.Item -eq 'Forest functional level: contoso.com' -and $_.Status -eq 'Info' }).Count -eq 1 -and @($c15Topo | Where-Object { $_.Item -eq 'Domain functional level: contoso.com' -and $_.Status -eq 'Info' -and $_.Scope -eq 'contoso.com' }).Count -eq 1) 'C15 INV-001: the forest and domain levels are read and named'
Check (@($c15Topo | Where-Object { $_.Item -like 'FSMO role holder: *' -and $_.Status -eq 'Info' }).Count -eq 5) 'C15 INV-001: the five FSMO holders are read from fSMORoleOwner (declared population: five roles)'
Check (@($c15Topo | Where-Object { $_.Item -eq 'Runner DC: contoso.com' -and $_.Status -eq 'Info' }).Count -eq 1 -and @($c15Topo | Where-Object { $_.Item -eq 'UPN suffixes: contoso.com' -and $_.Status -eq 'Info' }).Count -eq 1) 'C15 INV-001/007: the runner DC and the UPN suffixes'
Check (@($c15Topo | Where-Object { $_.Item -eq 'DNS suffix: dc1.contoso.com' -and $_.Status -eq 'Info' -and $_.Scope -eq 'contoso.com' }).Count -eq 1) 'C15 INV-007: the DC DNS suffix row carries its domain'
$c15TopoCsv = Join-Path $result.CsvPath 'Topology Inventory.csv'
if (Test-Path $c15TopoCsv) { Check (@(Import-Csv $c15TopoCsv | Where-Object { $_.Item -eq 'FSMO role holder: PDC emulator contoso.com' -and $_.Holder -eq 'DC1' }).Count -eq 1 -and @(Import-Csv $c15TopoCsv | Where-Object { $_.Item -eq 'DNS suffix: dc1.contoso.com' -and $_.Disjoint -eq 'No' }).Count -eq 1) 'C15 INV-001/007: the holder and the disjoint flag are in their columns' }
else { Check $false 'C15: Topology Inventory CSV exists' }
Check (@($smokeFindings | Where-Object { $_.Section -eq 'Trust Inventory' -and $_.Item -eq 'Trust: contoso.com -> fabrikam.com' -and $_.Status -eq 'Info' }).Count -eq 1 -and @($smokeFindings | Where-Object { $_.Section -eq 'Trust Inventory' -and $_.Item -eq 'Trusts (population): contoso.com' -and $_.Status -eq 'Info' }).Count -eq 1) 'C15 INV-006: the trust is read from the trustedDomain object, with its population row'
$c15TrustCsv = Join-Path $result.CsvPath 'Trust Inventory.csv'
if (Test-Path $c15TrustCsv) { Check (@(Import-Csv $c15TrustCsv | Where-Object { $_.TrustAttributeFlags -eq 'FOREST_TRANSITIVE' -and $_.TrustDirection -eq '3 Bidirectional' -and $_.TrustType -eq '2 UPLEVEL' }).Count -eq 1) 'C15 INV-006: trustAttributes, direction and type decoded by name' }
else { Check $false 'C15: Trust Inventory CSV exists' }
$c15Counts = @($smokeFindings | Where-Object { $_.Section -eq 'Object Counts' -and $_.Scope -eq 'contoso.com' })
Check ($c15Counts.Count -eq 13) ("C15 INV-008: thirteen object counts for the domain (declared population; {0})" -f $c15Counts.Count)
$c15CountCsv = Join-Path $result.CsvPath 'Object Counts.csv'
if (Test-Path $c15CountCsv) {
    $c15CountRows = @(Import-Csv $c15CountCsv)
    $c15Got = (@('Users', 'Disabled users', 'Computers', 'Disabled computers', 'Groups', 'Security groups', 'Contacts', 'OUs', 'gMSA') | ForEach-Object { $k = $_; [string](@($c15CountRows | Where-Object { $_.Item -eq ("Object count: {0} contoso.com" -f $k) })[0].Count) }) -join ','
    Check ($c15Got -eq '3,1,2,1,3,2,1,2,0') ("C15 INV-008: the counts are taken from the capped reads ({0})" -f $c15Got)
}
else { Check $false 'C15: Object Counts CSV exists' }
Check (@($smokeFindings | Where-Object { $_.Section -eq 'Group Inventory' -and $_.Item -eq 'Empty groups: contoso.com' -and $_.Status -eq 'Info' -and $_.Detail -notmatch 'Smoke-Empty' }).Count -eq 1) 'C15 INV-010: the empty groups row names no group in its Detail'
$c15GroupCsv = Join-Path $result.CsvPath 'Groups_contoso_com.csv'
Check ((Test-Path $c15GroupCsv) -and @(Import-Csv $c15GroupCsv).Count -eq 3 -and @(Import-Csv $c15GroupCsv | Where-Object { $_.Name -eq 'Smoke-Staff' -and $_.DirectMembers -eq '2' -and $_.Scope -eq 'Global' -and $_.Type -eq 'Security' }).Count -eq 1) 'C15 INV-010: one row per group in csv\Groups_<domain>.csv, with its direct member count'
$c15Disabled = @($smokeFindings | Where-Object { $_.Section -eq 'Stale Objects' -and $_.Item -like 'Stale disabled *' })
Check (@($c15Disabled | Where-Object { $_.Item -eq 'Stale disabled users' -and $_.Status -eq 'Info' -and $_.Scope -eq 'contoso.com' -and $_.Detail -match '^1 disabled user' -and $_.Detail -notmatch 'left\.user' }).Count -eq 1 -and @($c15Disabled | Where-Object { $_.Item -eq 'Stale disabled computers' -and $_.Status -eq 'Info' }).Count -eq 1) 'C15 INV-009: one stale disabled user and the computer row, Info, no name in Detail'
Check ((@($script:SmokeDisabledCalls) -join ',') -eq 'user contoso.com,user contoso.com,computer contoso.com,computer contoso.com') ("C15 INV-009: the disabled population and the stale disabled read, users then computers, each from the domain ({0})" -f (@($script:SmokeDisabledCalls) -join ', '))
$c15Gpo = @($smokeFindings | Where-Object { $_.Section -eq 'GPO Directory Inventory' })
Check (@($c15Gpo | Where-Object { $_.Item -eq 'GPO directory inventory: contoso.com' -and $_.Status -eq 'Info' }).Count -eq 1 -and @($c15Gpo | Where-Object { $_.Item -like 'GPO: *' }).Count -eq 2 -and @($c15Gpo | Where-Object { $_.Item -like 'GPO links on a SOM: *' }).Count -eq 2) 'C15 INV-011: two GPOs and two linking SOMs, with the summary row'
$c15GpoCsv = Join-Path $result.CsvPath 'GPO Directory Inventory.csv'
if (Test-Path $c15GpoCsv) { Check (@(Import-Csv $c15GpoCsv | Where-Object { $_.WmiFilterName -eq 'Smoke servers only' -and $_.EnforcedLinks -eq '1' -and $_.FlagsLabel -eq 'user settings disabled' }).Count -eq 1) 'C15 INV-011: the WMI filter is matched, the enforced link and the status flags are in their columns' }
else { Check $false 'C15: GPO Directory Inventory CSV exists' }
Check (@($script:SmokeInventoryCalls | Where-Object { $_ -notmatch '@contoso\.com$' }).Count -eq 0 -and @($script:SmokeInventoryCalls).Count -gt 0) ("C15: every inventory read names the domain ({0} reads)" -f @($script:SmokeInventoryCalls).Count)
$c15Ev = @($smokeFindings | Where-Object { $_.Section -eq 'Event Inventory' })
Check (@($c15Ev | Where-Object { $_.Item -like 'Event log: * on dc1.contoso.com' }).Count -eq 5) 'C15 INV-012: the five logs of the DC each have a row (declared population: five logs)'
Check (@($c15Ev | Where-Object { $_.Item -eq 'Event log: System on dc1.contoso.com' -and $_.Status -eq 'Info' }).Count -eq 1 -and @($c15Ev | Where-Object { $_.Item -eq 'Event log: DNS Server on dc1.contoso.com' -and $_.Status -eq 'Info' -and $_.Detail -match 'log absent' }).Count -eq 1) 'C15 INV-012: System events read, the DNS Server log absent'
Check (@($c15Ev | Where-Object { $_.Item -eq 'Event log: Directory Service on dc1.contoso.com' -and $_.Status -eq 'Not Assessed' }).Count -eq 1) 'C15 INV-012: none found over a log whose reach was not measured is Not Assessed, never 0'
Check (@($c15Ev | Where-Object { $_.Item -like 'Event group: System * on dc1.contoso.com' }).Count -eq 2) 'C15 INV-012: the two System event IDs are grouped'
Check (@($script:SmokeEventCalls | Where-Object { $_ -notmatch '\|access check$' }).Count -eq 5) ("C15 INV-012: one bounded read per log of the DC ({0})" -f (@($script:SmokeEventCalls) -join ', '))
# C15 review: a filtered read that found nothing is followed by one access check of that log - the three
# logs answered "no events" (Directory Service, DFS Replication, File Replication Service), not System
# (events found) nor DNS Server (log absent).
Check ((@($script:SmokeEventCalls | Where-Object { $_ -match '\|access check$' } | Sort-Object) -join ',') -eq 'dc1.contoso.com|DFS Replication|access check,dc1.contoso.com|Directory Service|access check,dc1.contoso.com|File Replication Service|access check') ("C15 review INV-012: one access check for each log the filtered read found empty ({0})" -f (@($script:SmokeEventCalls) -join ', '))
$c15EvCsv = Join-Path $result.CsvPath 'Event Inventory.csv'
if (Test-Path $c15EvCsv) {
    # The System log's reach back is not measured in this pass (the coverage read is not answered), so its
    # groups come from a partial read: every group row says so, and its Count is a floor.
    $c15EvGroups = @(Import-Csv $c15EvCsv | Where-Object { $_.Item -like 'Event group: System * on dc1.contoso.com' })
    Check ($c15EvGroups.Count -eq 2 -and @($c15EvGroups | Where-Object { $_.PartialRead -eq 'Yes' -and $_.Count -eq 'at least 1' -and $_.Detail -match 'floor' }).Count -eq 2) 'C15 review INV-012: group rows from a read whose reach back is not measured say the count is a floor (declared population: the two System groups)'
}
else { Check $false 'C15: Event Inventory CSV exists' }
if (Test-Path $c15GpoCsv) {
    $c15GpoSum = @(Import-Csv $c15GpoCsv | Where-Object { $_.Item -eq 'GPO directory inventory: contoso.com' })
    Check ($c15GpoSum.Count -eq 1 -and $c15GpoSum[0].OtherDomainSoms -eq 'All read' -and $c15GpoSum[0].Unlinked -eq '0' -and $c15GpoSum[0].Linked -eq '2' -and $c15GpoSum[0].Soms -eq '2' -and $c15GpoSum[0].SomsWithNoLink -eq '0') 'C15 review INV-011: a one-domain forest has every SOM read, so its summary states linked and unlinked'
}
Check ((Test-Path $c15GroupCsv) -and @(Import-Csv $c15GroupCsv | Where-Object { $_.ListComplete -ne 'Yes' }).Count -eq 0) 'C15 review INV-010: a group list from a read under its cap is marked complete on every row'
Check (@($smokeFindings | Where-Object { $_.Section -eq 'Time Configuration' -and $_.Item -eq 'W32Time configuration: dc1.contoso.com' -and $_.Status -eq 'Info' -and $_.Scope -eq 'contoso.com' }).Count -eq 1) 'C15 INV-015: the W32Time configuration of the DC is read'
$c15TimeCsv = Join-Path $result.CsvPath 'Time Configuration.csv'
if (Test-Path $c15TimeCsv) { Check (@(Import-Csv $c15TimeCsv | Where-Object { $_.Type -eq 'NT5DS' -and $_.NtpServer -eq '(not set)' -and $_.AnnounceFlags -eq '10' }).Count -eq 1) 'C15 INV-015: Type, NtpServer and AnnounceFlags are in their columns' }
else { Check $false 'C15: Time Configuration CSV exists' }

# PORT-PLAN C16 (GAP-P1..P30): the triaged sections in the single-domain run.
$c16Text = { param($Row) (@($Row.PSObject.Properties | ForEach-Object { [string]$_.Value }) -join ' ') }
$c16Sysvol = @($smokeFindings | Where-Object { $_.Section -eq 'SYSVOL / DFSR' })
Check (@($c16Sysvol | Where-Object { $_.Item -eq 'DFSR SYSVOL replication enabled' -and $_.Status -eq 'Pass' -and $_.Scope -eq 'contoso.com' -and $_.Detail -match 'on all 1 DC\(s\)' }).Count -eq 1) 'C16 GAP-P1: the stub DC''s SYSVOL subscription is read by the engine read from its own domain, and passes (declared population: 1 DC)'
Check (@($c16Sysvol | Where-Object { $_.Item -like 'DFSR SYSVOL subscription*' }).Count -eq 0) 'C16 GAP-P1: no "not readable" or "state" row when the one subscription was read'
Check (@($c16Sysvol | Where-Object { $_.Item -eq 'DFSR migration global state' -and $_.Status -eq 'Not Assessed' -and $_.Detail -match 'the computer running the assessment' }).Count -eq 1) 'C16 GAP-P17: the dfsrmig row says it reads the host''s own domain, and is Not Assessed with no dfsrmig on the host'
$c16Site = @($smokeFindings | Where-Object { $_.Section -eq 'Site Health' })
Check (@($c16Site | Where-Object { $_.Item -eq 'Site/subnet topology' -and $_.Status -eq 'Pass' }).Count -eq 1 -and @($c16Site | Where-Object { $_.Item -eq 'Empty sites' }).Count -eq 0) 'C16 GAP-P6: with the DC inventory, the stub site has its subnet and its DC, and the topology row passes'
$c16Cs = @($smokeFindings | Where-Object { $_.Section -eq 'Redundancy & Availability' -and $_.Item -eq 'GPO central store' })
Check ($c16Cs.Count -eq 1 -and $c16Cs[0].Status -eq 'Pass' -and $c16Cs[0].Detail -match [regex]::Escape('\\contoso.com\SYSVOL\contoso.com\Policies')) 'C16 GAP-P9: the central store is read by listing the domain''s Policies folder, and passes with PolicyDefinitions in it'
Check (@($script:SmokeGpoListCalls | Where-Object { $_ -eq '\\contoso.com\SYSVOL\contoso.com\Policies' }).Count -ge 1) 'C16 GAP-P9: the Policies listing went through the read-only folder seam'
$c16Se = @($smokeFindings | Where-Object { $_.Section -eq 'Exchange SE Compatibility' -and $_.Item -eq 'Domain controller operating systems' })
Check ($c16Se.Count -eq 1 -and $c16Se[0].Status -eq 'Pass' -and $c16Se[0].Detail -match 'every domain of the forest') 'C16 GAP-P20: a one-domain forest scoped whole, with its DC inventory, passes the Exchange SE DC gate'
# Independent review of the C16 diff: a replication Pass needs a measured partner (finding 5). The SRV
# rule (findings 1/7) is in Run-Validation and Pester: Resolve-DnsName is not available to these passes.
$c16RepCsv = Join-Path $result.CsvPath 'Replication Health.csv'
if (Test-Path $c16RepCsv) {
    $c16Rep = @(Import-Csv $c16RepCsv | Where-Object { $_.DomainController -eq 'dc1.contoso.com' })
    Check ($c16Rep.Count -eq 1 -and $c16Rep[0].Status -eq 'Pass' -and $c16Rep[0].PartnerCount -eq '1' -and $c16Rep[0].LastSuccessMinutesAgo -ne '') 'C16 review 5: the stub DC passes replication on one measured partner with a last-success time (declared population: dc1)'
}
else { Check $false 'C16 review 5: Replication Health CSV exists' }

Write-Host ""
Write-Host ("Output bundle: {0}" -f $result.OutputRoot)
Get-ChildItem -Recurse $result.OutputRoot | Select-Object -First 30 FullName | ForEach-Object { Write-Host ("   {0}" -f $_.FullName) }

# =============================================================================
# UNREACHABLE DC PASS (PORT-PLAN C1b, C14c)
# =============================================================================
# The whole run, every section, with the one DC classified Unreachable: first its name does not resolve,
# then it resolves and refuses LDAP. The classification is the only contact with it - one name
# resolution, and in the second pass one probe of 389 - and every per-DC section says so in its own
# rows: Not Assessed with the class (the dcdiag grid row stays Fail, C11g), never Pass, nothing read.
$smokeOutputSaved = $script:OutputPath
foreach ($c14cMode in @('Unresolved', 'Refused')) {
    $outU = Join-Path ([IO.Path]::GetTempPath()) ("adfa_smoke_unreach_" + [guid]::NewGuid().ToString('N'))
    $script:OutputPath = $outU
    $script:SmokeReachMode = $c14cMode
    $script:SmokeReachCalls = @()
    $script:SmokeTcpCalls = @()
    $script:SmokeUsnCalls = @()
    $script:SmokeEventCalls = @()
    $script:SmokeNetlogonCalls = @()
    $script:SmokeDcdiagCalls = @()
    $script:SmokeRepadmin = $true
    $script:SmokeRepadminCalls = @()
    $script:SmokeW32tm = $true
    $script:SmokeW32tmCalls = @()
    # Found by the independent review: the opt-in reads that consult the class too - the LDAPS handshake
    # (its TLS seam records every call) and the SYSVOL backlog (DFSR module absent here, so its own row).
    $script:IncludeLdapsHandshake = $true
    $script:SmokeTlsCalls = @()
    $resultU = Invoke-Main
    $script:IncludeLdapsHandshake = $false
    $script:SmokeRepadmin = $false
    $script:SmokeW32tm = $false
    $script:SmokeReachMode = 'Open'
    $findingsU = @(Import-Csv $resultU.FindingsFile)
    $expectReach = 'resolve dc1.contoso.com'
    $why = 'the host name does not resolve'
    if ($c14cMode -eq 'Refused') { $expectReach = 'resolve dc1.contoso.com,tcp 192.0.2.10:389'; $why = 'every address refused the connection on LDAP \(389\)' }
    Check ((@($script:SmokeReachCalls) -join ',') -eq $expectReach) ("C14c {0}: the classification is the only contact - {1} ({2})" -f $c14cMode, $expectReach, (@($script:SmokeReachCalls) -join ', '))
    Check (@($script:SmokeTcpCalls | Where-Object { $_ -like 'dc1.contoso.com:*' }).Count -eq 0) ("C14c {0}: no section probes the DC on any port afterwards ({1})" -f $c14cMode, (@($script:SmokeTcpCalls | Where-Object { $_ -like 'dc1.contoso.com:*' }) -join ', '))
    Check (@($script:SmokeUsnCalls).Count -eq 0 -and @($script:SmokeEventCalls).Count -eq 0 -and @($script:SmokeNetlogonCalls).Count -eq 0 -and @($script:SmokeRepadminCalls).Count -eq 0 -and @($script:SmokeW32tmCalls).Count -eq 0 -and @($script:SmokeDcdiagCalls | Where-Object { $_.Arguments -match 'dc1\.contoso\.com' }).Count -eq 0) ("C14c {0}: nothing is read from the DC - no registry, event log, netlogon.log, repadmin, w32tm or dcdiag" -f $c14cMode)
    # Declared population: the per-DC sections and the item each gives the DC.
    $c14cExpect = [ordered]@{
        'Replication Health'                    = '^dc1\.contoso\.com$'
        'SYSVOL / DFSR'                         = '^Shares on dc1\.contoso\.com$'
        'DFS Replication Events'                = '^dc1\.contoso\.com$'
        'DC System'                             = '^Patch level: dc1\.contoso\.com$'
        'Backup Status'                         = '^Directory backup: dc1\.contoso\.com$'
        'Port Reachability'                     = '^dc1\.contoso\.com$'
        'Restore Integrity'                     = '^USN rollback marker on dc1\.contoso\.com$'
        'Directory Service Events'              = '^dc1\.contoso\.com$'
        'Time Hierarchy'                        = '^Time source on dc1\.contoso\.com '
        'DC Disk Space'                         = '^Disk space: dc1\.contoso\.com$'
        'DC Hardening'                          = '^DC hardening: dc1\.contoso\.com$'
        'DC Secure Channel & Machine Passwords' = '^Secure channel: dc1\.contoso\.com$'
        'DNS Health'                            = '^DNS server: dc1\.contoso\.com$'
        'Time Configuration'                    = '^W32Time configuration: dc1\.contoso\.com$'
        'DC Certificates'                       = '^LDAPS certificate: dc1\.contoso\.com$'
    }
    foreach ($sec in @($c14cExpect.Keys)) {
        $hits = @($findingsU | Where-Object { $_.Section -eq $sec -and $_.Item -match $c14cExpect[$sec] })
        Check ($hits.Count -ge 1 -and @($hits | Where-Object { $_.Status -ne 'Not Assessed' }).Count -eq 0 -and @($hits | Where-Object { $_.Detail -notmatch 'classified once for this run' -or $_.Detail -notmatch $why }).Count -eq 0) ("C14c {0}: '{1}' has the DC Not Assessed with its class ({2} rows)" -f $c14cMode, $sec, $hits.Count)
    }
    $gridU = @($findingsU | Where-Object { $_.Section -eq 'DC Diagnostics' -and $_.Item -eq 'dc1.contoso.com' })
    Check ($gridU.Count -eq 1 -and $gridU[0].Status -eq 'Fail' -and $gridU[0].Detail -match 'classified once for this run' -and $gridU[0].Detail -match $why) ("C14c {0}: the dcdiag grid row stays Fail (C11g) and names the class" -f $c14cMode)
    Check (@($findingsU | Where-Object { $_.Section -eq 'Port Reachability' -and $_.Item -eq 'DC reachability: dc1.contoso.com' -and $_.Status -eq 'Fail' }).Count -eq 1) ("C14c {0}: non-vacuity - the DC is classified Unreachable (REACH-001 Fail)" -f $c14cMode)
    $passU = @($findingsU | Where-Object { $_.Item -match 'dc1\.contoso\.com' -and $_.Section -in @($c14cExpect.Keys) -and $_.Status -eq 'Pass' -and $_.Item -notmatch '^(Machine-account password|OS lifecycle|Directory certificates?): ' })
    # The three rows read from the directory about the DC (its OS lifecycle, machine-account password and
    # published certificates) need no connection.
    Check ($passU.Count -eq 0) ("C14c {0}: no per-DC row of the unreachable DC passes ({1})" -f $c14cMode, (@($passU | ForEach-Object { "{0} :: {1}" -f $_.Section, $_.Item }) -join '; '))
    Check (@($script:SmokeTlsCalls).Count -eq 0 -and @($findingsU | Where-Object { $_.Section -eq 'DC Certificates' -and $_.Item -eq 'LDAPS certificate: dc1.contoso.com' -and $_.Detail -match 'port 636 was not probed' }).Count -eq 1) ("C14c {0}: with -IncludeLdapsHandshake, no handshake is attempted with the DC and its row names the class" -f $c14cMode)
    # The SYSVOL read of Gpo on the PDC (the same DC): every row names the class, none says 445 did not answer.
    # PORT-PLAN C16 (GAP-P3): the outbound direction is asked of the domain's PDC emulator (the stub DC),
    # so a PDC classified Unreachable is not asked, and the trust row names its class.
    Check (@($findingsU | Where-Object { $_.Section -eq 'Trusts & Two-Way Health' -and (& $c16Text $_) -match 'Outbound direction not read on dc1\.contoso\.com: Unreachable, classified once for this run' }).Count -eq 1) ("C16 GAP-P3 {0}: the outbound direction is asked of the domain's own DC, which is not asked once classified Unreachable" -f $c14cMode)
    # PORT-PLAN C16 (GAP-P19): w32tm answers here, and the time source row names the host it read.
    $tsU = @($findingsU | Where-Object { $_.Section -eq 'Time Sync' -and $_.Item -eq 'Time source' })
    Check ($tsU.Count -eq 1 -and $tsU[0].Status -eq 'Info' -and $tsU[0].Detail -match 'the computer running the assessment' -and $tsU[0].Detail -match 'Time Hierarchy') ("C16 GAP-P19 {0}: the time source row says it is the host's, not a DC's" -f $c14cMode)
    $gpoU = @($findingsU | Where-Object { $_.Section -eq 'GPO Inventory' -and ($_.Item -like 'GPO folder listing: *' -or $_.Item -like 'GPO version: {*') })
    Check ($gpoU.Count -ge 1 -and @($gpoU | Where-Object { $_.Status -ne 'Not Assessed' -or $_.Detail -notmatch 'classified once for this run' -or $_.Detail -match 'did not answer' }).Count -eq 0) ("C14c {0}: the GPO SYSVOL rows of the PDC name its class, never a 445 probe that was not made ({1} rows)" -f $c14cMode, $gpoU.Count)
    Remove-Item -Recurse -Force $outU -ErrorAction SilentlyContinue
}
$script:OutputPath = $smokeOutputSaved
# =============================================================================
# MULTI-DOMAIN PASS (regression: live run 2026-08-31)
# =============================================================================
# The single-domain pass above cannot catch aggregation faults. Per-domain sections are
# built as `$rows = foreach ($d in $targetDomains) { Get-AdfaSomething -DomainName $d }`.
# While collectors ended in `return , @($rows)` each iteration emitted the array as ONE
# object, so with MORE THAN ONE domain the section became an array of arrays. Every
# consumer then looked for a Status property on an array, found none, and skipped it -
# twelve sections were collected and silently discarded, DNS-vs-AD consistency and DC
# secure channel among them. One domain hid it completely.
Write-Host ""
Write-Host "== Running Invoke-Main against a THREE-DOMAIN stubbed forest ==" -ForegroundColor Cyan

$multiDomains = @('contoso.com', 'north.contoso.com', 'south.contoso.com')
function Get-ADForest { param([Parameter(ValueFromRemainingArguments)]$a)
    [pscustomobject]@{ Name='contoso.com'; RootDomain='contoso.com'; ForestMode='Windows2016Forest'
        PartitionsContainer='CN=Partitions,CN=Configuration,DC=contoso,DC=com'
        Domains=@('contoso.com','north.contoso.com','south.contoso.com')
        Sites=@('Default-First-Site-Name'); GlobalCatalogs=@('dc1.contoso.com')
        SchemaMaster='dc1.contoso.com'; DomainNamingMaster='dc1.contoso.com'; UPNSuffixes=@() } }

$out2 = Join-Path ([IO.Path]::GetTempPath()) ("adfa_smoke_multi_" + [guid]::NewGuid().ToString('N'))
$script:OutputPath = $out2
$script:AllDomains = $true
$script:SmokeGptIniCalls = @()
$script:SmokeAclCalls = @()
$script:SmokePrivCalls = @()
# C11: one CrossRefValidation partition fails in this pass, to show it stays a partition's result.
$script:SmokeDcdiagCalls = @()
# C14c: the future lastLogonTimestamp reads of this pass alone.
$script:SmokeFutureCalls = @()
$script:SmokeDcdiagMode = 'PartitionFail'
# C4b: the export and trust reads of each of the three domains, recorded for this pass alone.
$script:SmokeExportCalls = @()
$script:SmokeC4bCalls = @()
# C3f: the Get-SmbServerConfiguration calls of this pass alone.
$script:SmokeSmbCalls = @()
$script:SmokeRemoteCalls = @()
$script:SmokeDirectToolCalls = @()
$result2 = Invoke-Main
$script:SmokeDcdiagMode = 'Pass'
# H20a (review fix): over three domains, every WinRM script block starts nltest.exe with /sc_query only,
# and no tool is started directly in this process. Declared population: the DcSecureChannel query of
# each of the three domains (the stub DC answers for all three, so the domains are told apart by the
# /sc_query argument, not by the host name).
$h20aRemote2 = @($script:SmokeRemoteCalls)
$h20aRemote2Bad = @($h20aRemote2 | Where-Object { $_.ScriptBlock -notmatch '^param\(\$a\) & nltest\.exe \$a\b' -or $_.Arguments -notmatch '^/sc_query:\S+$' })
$h20aRemote2Domains = @($h20aRemote2 | Where-Object { $_.Arguments -match '^/sc_query:(\S+)$' } | ForEach-Object { ([regex]::Match($_.Arguments, '^/sc_query:(\S+)$')).Groups[1].Value } | Sort-Object -Unique)
Check (@($multiDomains | Where-Object { $h20aRemote2Domains -notcontains $_ }).Count -eq 0 -and @($h20aRemote2Bad).Count -eq 0 -and @($script:SmokeDirectToolCalls).Count -eq 0) ("Multi-domain H20a: every WinRM nltest start is /sc_query, for each of the three domains, and none is direct ({0} calls; domains queried: {1})" -f @($h20aRemote2).Count, ($h20aRemote2Domains -join ', '))

Check ($null -ne $result2) 'Multi-domain: Invoke-Main returned a summary object'
# PORT-PLAN H21: the three-domain pass, one run folder, the closing lines and its exit code.
Write-Host ("    H21 three-domain exit: {0} - {1}" -f $result2.ExitCode, $result2.ExitReason) -ForegroundColor DarkGray
Test-SmokeH21Run -Result $result2 -Root $out2 -Name 'three-domain' -ExpectedCode 1 -ReasonPattern 'Fail finding'
Check (@($result2.DomainsScoped).Count -eq 3) ("Multi-domain: three domains scoped ({0})" -f @($result2.DomainsScoped).Count)

# The core assertion: per-domain sections must contribute findings, not vanish.
$findings2 = @(Import-Csv (Join-Path $result2.CsvPath 'Findings-Consolidated.csv'))
Check ($findings2.Count -gt 0) ("Multi-domain: consolidated findings are not empty ({0} rows)" -f $findings2.Count)

foreach ($sec in @('Password Policy', 'Security Posture', 'DNS vs AD Consistency', 'DC Secure Channel & Machine Passwords', 'DC System', 'DC Disk Space', 'DC Hardening', 'Windows LAPS', 'DC Certificates', 'RID Pool', 'GPO Inventory')) {
    $n = @($findings2 | Where-Object { $_.Section -eq $sec }).Count
    Check ($n -gt 0) ("Multi-domain: section '{0}' reached the consolidated findings ({1} rows)" -f $sec, $n)
}
# PORT-PLAN C2i(3): DcSecureChannel takes each domain's DCs from the shared per-domain list (the inventory here):
# one secure channel row per scoped domain, scoped to it, Not Assessed with the stub's WinRM refusal, never Pass.
foreach ($d in $multiDomains) {
    $c2iSc2 = @($findings2 | Where-Object { $_.Section -eq 'DC Secure Channel & Machine Passwords' -and $_.Item -eq 'Secure channel: dc1.contoso.com' -and $_.Scope -eq $d })
    Check ($c2iSc2.Count -eq 1 -and $c2iSc2[0].Status -eq 'Not Assessed' -and $c2iSc2[0].Detail -match 'STUB: WinRM') ("Multi-domain C2i(3): DcSecureChannel has the DC of '{0}', scoped to it, Not Assessed ({1} rows)" -f $d, $c2iSc2.Count)
}
Check (@($findings2 | Where-Object { $_.Section -eq 'DC Secure Channel & Machine Passwords' -and ($_.Item -eq 'DC enumeration' -or $_.Status -eq 'Pass') -and $_.Item -notlike 'Machine-account password: *' }).Count -eq 0) 'Multi-domain C2i(3): no DcSecureChannel enumeration row and no secure channel Pass'
# C11: one grid row, one Topology row and one coverage row per scoped domain, each carrying its own
# domain; the forest tests once for the forest; and the failed Configuration partition fails its
# own row and the forest roll-up, never a DC's grid row.
$dd2 = @($findings2 | Where-Object { $_.Section -eq 'DC Diagnostics' })
Check (@($dd2).Count -gt 0) ("Multi-domain: section 'DC Diagnostics' reached the consolidated findings ({0} rows)" -f @($dd2).Count)
foreach ($d in $multiDomains) {
    Check (@($dd2 | Where-Object { $_.Item -eq 'dc1.contoso.com' -and $_.Scope -eq $d -and $_.Status -eq 'Pass' }).Count -eq 1) ("Multi-domain: DC Diagnostics has the grid row of {0}'s DC, scoped to it, and it passes" -f $d)
    Check (@($dd2 | Where-Object { $_.Item -eq ("dcdiag Topology: {0}" -f $d) -and $_.Scope -eq $d -and $_.Status -eq 'Pass' }).Count -eq 1) ("Multi-domain: DC Diagnostics has one Topology row for {0}" -f $d)
    Check (@($dd2 | Where-Object { $_.Item -eq ("dcdiag coverage: {0}" -f $d) -and $_.Status -eq 'Info' }).Count -eq 1) ("Multi-domain: DC Diagnostics has one coverage row for {0}" -f $d)
}
$dd2Calls = @($script:SmokeDcdiagCalls)
Check (@($dd2Calls | Where-Object { $_.Arguments -match '^/test:Topology ' }).Count -eq 3) 'Multi-domain: DC Diagnostics runs Topology once per scoped domain (declared population: three)'
Check (@($dd2Calls | Where-Object { $_.Arguments -match '^/test:(CheckSDRefDom|CrossRefValidation) ' }).Count -eq 2) 'Multi-domain: DC Diagnostics runs the two forest tests once each, not once per domain'
Check (@($dd2Calls | Where-Object { $_.Arguments -notmatch '/test:(Topology|CheckSDRefDom|CrossRefValidation|Intersite)\b' }).Count -eq 54 -and @($dd2Calls | Where-Object { $_.Arguments -match '^/test:FrsEvent ' }).Count -eq 0) 'Multi-domain: DC Diagnostics asks 18 per-DC tests of each domain''s DC, FrsEvent not applicable to its DFSR engine (declared population: three DCs)'
Check (@($dd2 | Where-Object { $_.Item -eq 'dcdiag CrossRefValidation: Configuration' -and $_.Status -eq 'Fail' -and $_.Recommendation -match 'nETBIOSName' }).Count -eq 1) 'Multi-domain: the failed Configuration partition fails its own row, with the CrossRefValidation advice'
Check (@($dd2 | Where-Object { $_.Item -eq 'dcdiag CrossRefValidation: forest contoso.com' -and $_.Status -eq 'Fail' }).Count -eq 1) 'Multi-domain: the forest roll-up fails on that one partition'
# PORT-PLAN C11h: no DC Diagnostics row of the three domains carries an unscoped advice text.
$c11hUnscoped2 = @($script:RecommendationMap | Where-Object { -not $_.ContainsKey('Section') } | ForEach-Object { [string]$_.Text })
Check (@($dd2 | Where-Object { $_.Recommendation -ne '' -and $c11hUnscoped2 -contains $_.Recommendation }).Count -eq 0) 'Multi-domain C11h: no DC Diagnostics row reaches an unscoped advice entry'
# PORT-PLAN C4b4: each domain's Object Counts rows name the cap by its table (declared population: three domains).
$c4b4Counts2 = @(Import-Csv (Join-Path $result2.CsvPath 'Object Counts.csv'))
foreach ($d in $multiDomains) {
    $c4b4Mine = @($c4b4Counts2 | Where-Object { $_.Scope -eq $d })
    Check ($c4b4Mine.Count -gt 0 -and @($c4b4Mine | Where-Object { $_.Evidence -notmatch '\(Inventory\.MaxObjects, a tool default\)' }).Count -eq 0) ("Multi-domain C4b4: the Object Counts rows of {0} name the cap as Inventory.MaxObjects, a tool default ({1} rows)" -f $d, $c4b4Mine.Count)
}
# PORT-PLAN C4b3: the forest's connection object is decoded once, not per domain.
$c4b3Conn2 = @(Import-Csv (Join-Path $result2.CsvPath 'Replication Connections.csv'))
Check ($c4b3Conn2.Count -eq 1 -and $c4b3Conn2[0].AutoGenerated -eq 'Yes' -and $c4b3Conn2[0].ToServer -match '^CN=NTDS Settings,CN=DC1,CN=Servers,') 'Multi-domain C4b3: the forest''s one connection row carries its destination and AutoGenerated'
Check (@($dd2 | Where-Object { $_.Item -like 'dcdiag CrossRefValidation: *' -and $_.Item -ne 'dcdiag CrossRefValidation: Configuration' -and $_.Item -ne 'dcdiag CrossRefValidation: forest contoso.com' -and $_.Status -ne 'Pass' }).Count -eq 0) 'Multi-domain: the other four partitions still pass'
# C12: one "dcdiag DNS not run" row per scoped domain, each scoped to its own domain, never Pass.
$dd2DnsNotRun = @($dd2 | Where-Object { $_.Item -like 'dcdiag DNS not run: *' })
# C13: DNS Health, DC DNS Client and the per-DC DNS vs AD rows give each scoped domain its own rows, and
# with nothing readable none of them passes.
$c13H2 = @($findings2 | Where-Object { $_.Section -eq 'DNS Health' })
$c13C2 = @($findings2 | Where-Object { $_.Section -eq 'DC DNS Client' -and $_.Item -like 'DNS client: *' })
$c13D2 = @($findings2 | Where-Object { $_.Section -eq 'DNS vs AD Consistency' -and $_.Item -like 'DC locator records: *' })
foreach ($d in $multiDomains) {
    Check (@($c13H2 | Where-Object { $_.Item -eq 'DNS server: dc1.contoso.com' -and $_.Scope -eq $d -and $_.Status -eq 'Not Assessed' }).Count -eq 1) ("Multi-domain C13: DNS Health has the DNS server row of {0}'s DC, scoped to it, Not Assessed" -f $d)
    Check (@($c13H2 | Where-Object { $_.Item -eq ("DNS zones (population): {0}" -f $d) -and $_.Scope -eq $d }).Count -eq 1) ("Multi-domain C13: DNS Health has one zone population row for {0}" -f $d)
    Check (@($c13C2 | Where-Object { $_.Scope -eq $d }).Count -eq 1) ("Multi-domain C13: DC DNS Client has one row for {0}'s DC" -f $d)
    Check (@($c13D2 | Where-Object { $_.Scope -eq $d -and $_.Status -eq 'Not Assessed' }).Count -eq 1) ("Multi-domain C13: DNS vs AD has one locator row for {0}'s DC, Not Assessed" -f $d)
}
Check (@($c13H2).Count -gt 0 -and @($c13H2 | Where-Object { $_.Status -eq 'Pass' }).Count -eq 0) 'Multi-domain C13: DNS Health passes nothing when nothing could be read (declared population: three domains)'
Check (@($dd2DnsNotRun).Count -eq 3 -and @($dd2DnsNotRun | Where-Object { $_.Status -ne 'Not Assessed' -or $_.Item -ne ("dcdiag DNS not run: {0}" -f $_.Scope) -or $multiDomains -notcontains $_.Scope }).Count -eq 0) 'Multi-domain: one Not Assessed "dcdiag DNS not run" row per scoped domain, each scoped to it (declared population: three domains)'
# C1: one lifecycle row per DC per domain, each carrying its own domain - not three copies of
# the first domain, and not one row for the forest.
$life2 = @($findings2 | Where-Object { $_.Section -eq 'DC System' -and $_.Item -like 'OS lifecycle:*' })
# C1a: the OS build row of each domain's DC carries the full build and its own domain (declared population: three domains).
$os2 = @($findings2 | Where-Object { $_.Section -eq 'DC System' -and $_.Item -like 'OS build and uptime:*' })
Check (@($os2).Count -eq 3 -and @($os2 | Where-Object { $_.Status -ne 'Info' -or $_.Detail -notmatch 'Build 17763\.6532 \(version' }).Count -eq 0 -and @($os2 | ForEach-Object { $_.Scope } | Sort-Object -Unique).Count -eq 3) ("Multi-domain C1a: one OS build row per domain's DC, each with build 17763.6532 and its own scope ({0} rows)" -f @($os2).Count)
Check (@($life2).Count -eq 3) ("Multi-domain: DC System has one OS lifecycle row per domain's DC ({0})" -f @($life2).Count)
foreach ($d in $multiDomains) {
    Check (@($life2 | Where-Object { $_.Scope -eq $d }).Count -eq 1) ("Multi-domain: DC System lifecycle row carries scope '{0}'" -f $d)
}
# C2: two volume rows per domain's DC, each set carrying its own domain - not six rows for the
# first domain, and not two for the forest.
$disk2 = @($findings2 | Where-Object { $_.Section -eq 'DC Disk Space' })
Check (@($disk2).Count -eq 6) ("Multi-domain: DC Disk Space has two volume rows for each of the three domains' DC ({0}, expected 6)" -f @($disk2).Count)
foreach ($d in $multiDomains) {
    $forDomain = @($disk2 | Where-Object { $_.Scope -eq $d })
    Check (@($forDomain).Count -eq 2) ("Multi-domain: DC Disk Space has two rows scoped '{0}' ({1})" -f $d, @($forDomain).Count)
    Check (@($forDomain | Where-Object { $_.Status -eq 'Pass' }).Count -eq 2) ("Multi-domain: both DC Disk Space volumes of '{0}' are judged, not skipped" -f $d)
}
# C3: eight rows per domain's DC, each set carrying its own domain - not twenty-four rows for
# the first domain, and not eight for the forest.
$hard2 = @($findings2 | Where-Object { $_.Section -eq 'DC Hardening' })
Check (@($hard2).Count -eq 24) ("Multi-domain: DC Hardening has eight rows for each of the three domains' DC ({0}, expected 24)" -f @($hard2).Count)
foreach ($d in $multiDomains) {
    $forDomainH = @($hard2 | Where-Object { $_.Scope -eq $d })
    Check (@($forDomainH).Count -eq 8) ("Multi-domain: DC Hardening has eight rows scoped '{0}' ({1})" -f $d, @($forDomainH).Count)
    Check (@($forDomainH | Where-Object { $_.Status -eq 'Pass' }).Count -eq 5) ("Multi-domain: the DC Hardening settings of '{0}' are judged, not skipped" -f $d)
    Check (@($forDomainH | Where-Object { $_.Item -like 'SMBv1: *' -and $_.Status -eq 'Pass' -and $_.Detail -match 'Get-SmbServerConfiguration' }).Count -eq 1) ("Multi-domain: the SMBv1 row of '{0}' is graded on its own DC's Get-SmbServerConfiguration read (PORT-PLAN C3f)" -f $d)
}
# C3f: one Get-SmbServerConfiguration call per domain's DC, each in its own session - not one read
# shared by the three domains. (The stub names the DC of every domain dc1.contoso.com, so the calls
# are told apart by count and by the per-domain rows above, not by host.) Declared population: the
# three domains' DCs.
$smbHosts2 = @($script:SmokeSmbCalls)
Check (@($smbHosts2).Count -eq 3 -and @($hard2 | Where-Object { $_.Item -like 'SMBv1: *' }).Count -eq 3) ("Multi-domain: Get-SmbServerConfiguration ran once for each of the three domains' DCs, and each domain has its SMBv1 row ({0} calls)" -f @($smbHosts2).Count)

# C4: one schema row for the forest, and for EACH of the three domains its own coverage row and
# its own DSRM row, each carrying its domain and naming that domain's computers - not three
# copies of the first domain, and not one row for the forest.
$laps2 = @($findings2 | Where-Object { $_.Section -eq 'Windows LAPS' })
Check (@($laps2).Count -eq 7) ("Multi-domain: Windows LAPS has one schema row and two rows for each of the three domains ({0}, expected 7)" -f @($laps2).Count)
Check (@($laps2 | Where-Object { $_.Item -eq 'Windows LAPS schema' }).Count -eq 1) 'Multi-domain: the schema is read once for the forest, not once per domain'
foreach ($d in $multiDomains) {
    $forDomainL = @($laps2 | Where-Object { $_.Scope -eq $d -and $_.Item -ne 'Windows LAPS schema' })
    Check (@($forDomainL).Count -eq 2) ("Multi-domain: Windows LAPS has two rows scoped '{0}' ({1})" -f $d, @($forDomainL).Count)
    Check (@($forDomainL | Where-Object { $_.Item -eq ("LAPS coverage: {0}" -f $d) -and $_.Status -eq 'Warning' -and $_.Detail -match ("visible: ws2\.{0}\." -f [regex]::Escape($d)) }).Count -eq 1) ("Multi-domain: the coverage row of '{0}' is graded on that domain's own computers" -f $d)
    Check (@($forDomainL | Where-Object { $_.Item -eq ("DSRM password backup: dc1.{0}" -f $d) -and $_.Status -eq 'Pass' }).Count -eq 1) ("Multi-domain: the DC of '{0}' has its own DSRM row" -f $d)
}

# C5: three rows per domain's DC, each set carrying its own domain and read from that domain.
$cert2 = @($findings2 | Where-Object { $_.Section -eq 'DC Certificates' })
Check (@($cert2).Count -eq 9) ("Multi-domain: DC Certificates has three rows for each of the three domains' DC ({0}, expected 9)" -f @($cert2).Count)
foreach ($d in $multiDomains) {
    $forDomainC = @($cert2 | Where-Object { $_.Scope -eq $d })
    Check (@($forDomainC).Count -eq 3) ("Multi-domain: DC Certificates has three rows scoped '{0}' ({1})" -f $d, @($forDomainC).Count)
    Check (@($forDomainC | Where-Object { $_.Item -like 'Directory certificate: *' -and $_.Detail -match ("Read from {0}\." -f [regex]::Escape($d)) }).Count -eq 2) ("Multi-domain: the directory rows of '{0}' were read from that domain" -f $d)
}

# C6: two rows per domain and one per domain's DC, each set carrying its own domain and graded on
# that domain's own CN=RID Manager$ - not three copies of the first domain.
$rid2 = @($findings2 | Where-Object { $_.Section -eq 'RID Pool' })
Check (@($rid2).Count -eq 9) ("Multi-domain: RID Pool has two rows for each of the three domains and one for each domain's DC ({0}, expected 9)" -f @($rid2).Count)
foreach ($d in $multiDomains) {
    $forDomainR = @($rid2 | Where-Object { $_.Scope -eq $d })
    Check (@($forDomainR).Count -eq 3) ("Multi-domain: RID Pool has three rows scoped '{0}' ({1})" -f $d, @($forDomainR).Count)
    Check (@($forDomainR | Where-Object { $_.Item -eq 'RID pool: dc1.contoso.com' -and $_.Status -eq 'Info' -and $_.Detail -match ("Read from {0}\." -f [regex]::Escape($d)) }).Count -eq 1) ("Multi-domain: the DC of '{0}' has its RID pool read from that domain" -f $d)
}
$ridNorthAlloc = @($rid2 | Where-Object { $_.Item -eq 'RID pool allocation: north.contoso.com' })
Check (@($ridNorthAlloc).Count -eq 1 -and $ridNorthAlloc[0].Status -eq 'Fail' -and $ridNorthAlloc[0].Detail -match 'is FALSE' -and $ridNorthAlloc[0].Recommendation -match 'msDS-RIDPoolAllocationEnabled' -and $ridNorthAlloc[0].Recommendation -notmatch 'repadmin|wbadmin|scavenging') 'Multi-domain: north.contoso.com, whose allocation attribute is FALSE, is a Fail carrying the RID pool advice'
$ridNorthSpace = @($rid2 | Where-Object { $_.Item -eq 'Global RID space: north.contoso.com' })
Check (@($ridNorthSpace).Count -eq 1 -and $ridNorthSpace[0].Status -eq 'Warning' -and $ridNorthSpace[0].Detail -match '^150,000,000 of 1,073,741,823 RIDs issued \(13\.9698 % used\)' -and $ridNorthSpace[0].Recommendation -match '16658') 'Multi-domain: north.contoso.com, with 13.97 % of its space issued, is a Warning carrying the RID space advice'
$ridSouthSpace = @($rid2 | Where-Object { $_.Item -eq 'Global RID space: south.contoso.com' })
Check (@($ridSouthSpace).Count -eq 1 -and $ridSouthSpace[0].Status -eq 'Pass' -and $ridSouthSpace[0].Detail -match '^5,000 of 2,147,483,647 RIDs issued' -and $ridSouthSpace[0].Detail -match 'inferred') 'Multi-domain: south.contoso.com is judged against the 31-bit size it holds, and the row calls that size inferred'
Check (@($rid2 | Where-Object { $_.Item -eq 'RID pool allocation: south.contoso.com' -and $_.Status -eq 'Pass' -and $_.Detail -match 'is TRUE' }).Count -eq 1) 'Multi-domain: south.contoso.com, whose allocation attribute is TRUE, passes'
# C7: four SID history rows per scoped domain, each read from that domain's own principals - not
# three copies of the first domain - with the forest's domain SIDs resolving historic SIDs.
$sh2 = @($findings2 | Where-Object { $_.Section -eq 'Security Posture' -and $_.Item -like 'SID history*' })
Check (@($sh2).Count -eq 12) ("Multi-domain: SID history has four rows for each of the three domains ({0}, expected 12)" -f @($sh2).Count)
foreach ($d in $multiDomains) {
    Check (@($sh2 | Where-Object { $_.Scope -eq $d -and $_.Item -like ('*: {0}' -f $d) }).Count -eq 4) ("Multi-domain: SID history has four rows scoped '{0}'" -f $d)
}
Check (@($sh2 | Where-Object { $_.Item -eq 'SID history sources: contoso.com' -and $_.Detail -match '3 distinct domain part\(s\) - 1 in this forest, 1 trust partner\(s\) of this domain, 0 builtin or well-known, 1 unresolved' }).Count -eq 1) 'Multi-domain: contoso.com''s historic SID from north.contoso.com now resolves to a domain of this forest'
Check (@($sh2 | Where-Object { $_.Item -eq 'SID history same-domain: north.contoso.com' -and $_.Status -eq 'Fail' -and $_.Detail -match '^Same-domain SID history: 1 historic SID value\(s\) on 1 principal\(s\) belong to north\.contoso\.com itself' -and $_.Recommendation -match 'DsAddSidHistory' }).Count -eq 1) 'Multi-domain: north.contoso.com''s own SID in svc.north''s SID history (read as SecurityIdentifier-like objects) is a same-domain Fail carrying its advice'
Check (@($sh2 | Where-Object { $_.Item -eq 'SID history privileged: north.contoso.com' -and $_.Status -eq 'Fail' -and $_.Detail -match 'Enterprise Admins \(RID 519\) x1' -and $_.Recommendation -match 'Enterprise Admins' -and $_.Recommendation -notmatch 'New-KrbtgtKeys|wbadmin' }).Count -eq 1) 'Multi-domain: the Enterprise Admins SID of contoso.com in north.contoso.com is a privileged Fail, named, with its advice'
Check (@($sh2 | Where-Object { $_.Item -eq 'SID history same-domain: contoso.com' -and $_.Status -eq 'Pass' }).Count -eq 1) 'Multi-domain: the same-domain row is per domain - contoso.com, whose values come from other domains, passes'
Check (@($sh2 | Where-Object { $_.Scope -eq 'south.contoso.com' -and $_.Item -ne 'SID history sources: south.contoso.com' -and $_.Status -eq 'Pass' }).Count -eq 3 -and @($sh2 | Where-Object { $_.Item -eq 'SID history: south.contoso.com' -and $_.Detail -match '^None visible: ' }).Count -eq 1) 'Multi-domain: south.contoso.com, with no principal returned, passes worded "none visible to this account"'
# C8: one summary row per scoped domain, each graded on that domain's own containers and its own
# GPT.INI files - not three copies of the first domain. Declared population: three summaries, one
# mismatched GPO in north.contoso.com, one folder without a container in south.contoso.com.
$gpo2 = @($findings2 | Where-Object { $_.Section -eq 'GPO Inventory' -and ($_.Item -like 'GPO version*' -or $_.Item -like 'GPO folder*') })
Check (@($gpo2).Count -eq 5) ("Multi-domain: GPO version has a summary for each of the three domains, the mismatched GPO of north.contoso.com and the orphan folder of south.contoso.com ({0}, expected 5)" -f @($gpo2).Count)
foreach ($d in $multiDomains) {
    Check (@($gpo2 | Where-Object { $_.Scope -eq $d -and $_.Item -eq ("GPO version summary: {0}" -f $d) }).Count -eq 1) ("Multi-domain: GPO version has the summary of '{0}', scoped to it" -f $d)
    Check (@($script:SmokeGptIniCalls | Where-Object { $_ -match ("^\\\\dc1\.contoso\.com\\SYSVOL\\{0}\\Policies\\" -f [regex]::Escape($d)) }).Count -ge 2) ("Multi-domain: the GPT.INI files of '{0}' are read under that domain's own SYSVOL folder" -f $d)
}
Check (@($gpo2 | Where-Object { $_.Item -eq 'GPO version summary: contoso.com' -and $_.Status -eq 'Pass' }).Count -eq 1) 'Multi-domain: contoso.com, whose two GPOs agree, passes'
Check (@($gpo2 | Where-Object { $_.Item -eq ("GPO version: {0}" -f $script:SmokeGpoGuids[1]) -and $_.Scope -eq 'north.contoso.com' -and $_.Status -eq 'Warning' -and $_.Detail -match 'holds 131073 \(user 2, computer 1\) and GPT\.INI in SYSVOL holds 65537 \(user 1, computer 1\); the user half differs' -and $_.Detail -match 'replication still in flight' -and $_.Recommendation -match 'converged' -and $_.Recommendation -notmatch 'dfsrmig|wbadmin|repadmin /replicate' }).Count -eq 1) 'Multi-domain: the GPO of north.contoso.com whose directory version is ahead of GPT.INI is a Warning naming the user half, with its own advice and not the restore advice'
Check (@($gpo2 | Where-Object { $_.Item -eq 'GPO version summary: north.contoso.com' -and $_.Status -eq 'Warning' }).Count -eq 1) 'Multi-domain: north.contoso.com''s summary is a Warning'
Check (@($gpo2 | Where-Object { $_.Item -eq ("GPO folder without container: {0}" -f $script:SmokeGpoOrphan) -and $_.Scope -eq 'south.contoso.com' -and $_.Status -eq 'Warning' -and $_.Recommendation -match 'orphaned' }).Count -eq 1) 'Multi-domain: the GUID folder of south.contoso.com with no container is a Warning with its own advice'
Check (@($gpo2 | Where-Object { $_.Item -eq 'GPO version summary: south.contoso.com' -and $_.Status -eq 'Pass' }).Count -eq 1) 'Multi-domain: south.contoso.com''s versions agree, so its summary passes beside the orphan folder row'
# C9: six Dangerous ACLs rows per scoped domain, each read from that domain and graded on its own
# descriptors, with Enterprise Admins and ERODC recognised as SIDs of the forest root - not three
# copies of the first domain.
$acl2 = @($findings2 | Where-Object { $_.Section -eq 'Dangerous ACLs (DCSync)' })
Check (@($acl2).Count -eq 18) ("Multi-domain: Dangerous ACLs has six rows for each of the three domains ({0}, expected 18)" -f @($acl2).Count)
foreach ($d in $multiDomains) {
    Check (@($acl2 | Where-Object { $_.Scope -eq $d }).Count -eq 6) ("Multi-domain: Dangerous ACLs has six rows scoped '{0}'" -f $d)
    Check (@($script:SmokeAclCalls | Where-Object { $_ -match ("@{0}$" -f [regex]::Escape($d)) }).Count -eq 3) ("Multi-domain: the three descriptor reads of '{0}' went to that domain" -f $d)
}
Check (@($acl2 | Where-Object { $_.Item -eq 'DCSync rights: contoso.com' -and $_.Status -eq 'Warning' }).Count -eq 1) 'Multi-domain: contoso.com''s non-default replication grant is still flagged'
Check (@($acl2 | Where-Object { $_.Item -eq 'DCSync rights: north.contoso.com' -and $_.Status -eq 'Pass' }).Count -eq 1) 'Multi-domain: north.contoso.com''s head passes - the forest root''s Enterprise Admins and Enterprise Read-only DCs are recognised by the root domain SID'
Check (@($acl2 | Where-Object { $_.Item -eq 'AdminSDHolder rights: north.contoso.com' -and $_.Status -eq 'Warning' -and $_.Detail -match 'S-1-5-21-1-2-4-1500 \(WriteAllProperties\)' -and $_.Recommendation -match 'SDProp' }).Count -eq 1) 'Multi-domain: the non-default writer on north.contoso.com''s AdminSDHolder is a Warning with the AdminSDHolder advice'
Check (@($acl2 | Where-Object { $_.Scope -eq 'south.contoso.com' -and $_.Status -eq 'Pass' }).Count -eq 6) 'Multi-domain: south.contoso.com, with only default grants, passes on all six rows'
# C10: every scoped domain gets its own rows, read from that domain. The stub gives the three domains
# one DN, so a member DN cannot be routed to one of them: every count that depends on a member is Not
# Assessed with that cause - never a pass, never a lower number - while delegation, which reads no
# membership, is graded per domain.
$pa2 = @($findings2 | Where-Object { $_.Section -eq 'Privileged Accounts' })
$ph2 = @($findings2 | Where-Object { $_.Section -eq 'Privileged Hygiene' })
$kr2 = @($findings2 | Where-Object { $_.Section -eq 'Kerberos Exposure' })
Check (@($pa2).Count -eq 48) ("Multi-domain: Privileged Accounts has 2 root rows, 18 rows for the root and 14 for each child - Enterprise Key Admins is a forest-root group ({0}, expected 48)" -f @($pa2).Count)
Check (@($pa2 | Where-Object { $_.Item -match '^Privileged group: Enterprise Key Admins: ' } | ForEach-Object { $_.Scope }) -join ',') -eq 'contoso.com' 'Multi-domain: Enterprise Key Admins is read in the forest root only, never in a child domain'
foreach ($d in $multiDomains) {
    Check (@($ph2 | Where-Object { $_.Scope -eq $d }).Count -eq 4 -and @($kr2 | Where-Object { $_.Scope -eq $d }).Count -eq 6) ("Multi-domain: Privileged Hygiene has four and Kerberos Exposure six rows scoped '{0}'" -f $d)
    Check (@($pa2 | Where-Object { $_.Item -eq ("Privileged group: Administrators: {0}" -f $d) -and $_.Status -eq 'Not Assessed' -and $_.Detail -match 'could not be resolved' }).Count -eq 1) ("Multi-domain: the Administrators count of '{0}' is Not Assessed, its members not routable to one domain" -f $d)
    Check (@($ph2 | Where-Object { $_.Item -eq ("adminCount orphans: {0}" -f $d) -and $_.Status -eq 'Not Assessed' }).Count -eq 1) ("Multi-domain: the orphan row of '{0}' is Not Assessed, never Pass" -f $d)
    Check (@($kr2 | Where-Object { $_.Item -eq ("Unconstrained delegation: {0}" -f $d) -and $_.Status -eq 'Warning' }).Count -eq 1) ("Multi-domain: unconstrained delegation of '{0}' is graded from its own search" -f $d)
    Check (@($script:SmokePrivCalls | Where-Object { $_ -match '^\(adminCount=1\)@' -and $_ -match ("@{0}$" -f [regex]::Escape($d)) }).Count -eq 1) ("Multi-domain: the adminCount search of '{0}' went to that domain" -f $d)
}
Check (@($pa2 | Where-Object { $_.Item -match '^(Schema|Enterprise) Admins members: contoso\.com$' }).Count -eq 2) 'Multi-domain: the Schema Admins and Enterprise Admins rows appear once, for the forest root'
Check (@($pa2 | Where-Object { $_.Item -match '^Privileged group: (Schema Admins|Enterprise Admins): (north|south)\.' }).Count -eq 0) 'Multi-domain: no child domain is given a forest-root group'
Check (@($pa2 | Where-Object { $_.Item -match '^Privileged group: (Administrators|Domain Admins): ' }).Count -eq 6 -and @($pa2 | Where-Object { $_.Item -match '^Privileged group: (Administrators|Domain Admins): ' -and $_.Status -ne 'Not Assessed' }).Count -eq 0) 'Multi-domain: no count of a group with members is given on members it could not route (6 rows, all Not Assessed)'

# PORT-PLAN C16 (GAP-P1, P9, P20) in the three-domain run: one subscription verdict and one central
# store row per scoped domain, each read from that domain, and the DC gate over the whole forest.
foreach ($d in $multiDomains) {
    Check (@($findings2 | Where-Object { $_.Section -eq 'SYSVOL / DFSR' -and $_.Item -eq 'DFSR SYSVOL replication enabled' -and $_.Scope -eq $d -and $_.Status -eq 'Pass' }).Count -eq 1) ("C16 GAP-P1 multi-domain: the SYSVOL subscription of '{0}' is read from that domain and graded once" -f $d)
    Check (@($findings2 | Where-Object { $_.Section -eq 'Redundancy & Availability' -and $_.Item -eq 'GPO central store' -and $_.Scope -eq $d -and $_.Status -eq 'Pass' -and $_.Detail -match [regex]::Escape(('\\{0}\SYSVOL\{0}\Policies' -f $d)) }).Count -eq 1) ("C16 GAP-P9 multi-domain: the central store of '{0}' is read under that domain's own SYSVOL" -f $d)
}
Check (@($findings2 | Where-Object { $_.Section -eq 'Exchange SE Compatibility' -and $_.Item -eq 'Domain controller operating systems' -and $_.Status -eq 'Pass' }).Count -eq 1) 'C16 GAP-P20 multi-domain: every domain of the forest scoped, so the DC gate can pass'
# The same forest with each section alone: the SYSVOL subscription needs no DC inventory (GAP-P1), the
# site check runs without it and says empty sites were not assessed (GAP-P6), and the DC gate over one
# domain of three is not a Pass (GAP-P20).
# The multi-domain checks further down read what the stubs recorded in the run above; these two runs
# keep it as it was.
$c16Recorded = @{}
foreach ($name in @('SmokeC4bCalls', 'SmokeExportCalls', 'SmokeGptIniCalls', 'SmokeAclCalls', 'SmokePrivCalls', 'SmokeSmbCalls', 'SmokeDcdiagCalls', 'SmokeGpoListCalls', 'SmokeInventoryCalls', 'SmokeEventCalls', 'SmokeTcpCalls', 'SmokeReachCalls', 'SmokeNetlogonCalls', 'SmokeStaleCalls', 'SmokePopulationCalls', 'SmokeFutureCalls', 'SmokeDisabledCalls', 'SmokeUsnCalls', 'SmokeDnsCalls')) {
    $c16Var = Get-Variable -Scope Script -Name $name -ErrorAction SilentlyContinue
    if ($null -ne $c16Var) { $c16Recorded[$name] = @($c16Var.Value) }
}
$out16 = Join-Path ([IO.Path]::GetTempPath()) ("adfa_smoke_c16_" + [guid]::NewGuid().ToString('N'))
$script:OutputPath = $out16
$script:Sections = @('Sysvol', 'Topology')
$result16 = Invoke-Main
$findings16 = @(Import-Csv $result16.FindingsFile)
foreach ($d in $multiDomains) {
    Check (@($findings16 | Where-Object { $_.Section -eq 'SYSVOL / DFSR' -and $_.Item -eq 'DFSR SYSVOL replication enabled' -and $_.Scope -eq $d -and $_.Status -eq 'Pass' }).Count -eq 1) ("C16 GAP-P1 Sysvol alone: '{0}' has its subscription verdict without the DC inventory" -f $d)
}
$site16 = @($findings16 | Where-Object { $_.Section -eq 'Site Health' })
Check (@($site16 | Where-Object { $_.Item -eq 'Empty sites' -and $_.Status -eq 'Not Assessed' -and $_.Detail -match 'DomainControllers' }).Count -eq 1 -and @($site16 | Where-Object { $_.Item -eq 'Site/subnet topology' -or $_.Item -like '*has no domain controllers' }).Count -eq 0) 'C16 GAP-P6 Topology alone: empty sites are Not Assessed naming DomainControllers, and the topology row does not pass'
$script:Sections = @('Forest', 'Domains', 'DomainControllers', 'ExchangeSeReadiness', 'Topology')
$script:AllDomains = $false
$result16b = Invoke-Main
$findings16b = @(Import-Csv $result16b.FindingsFile)
$se16 = @($findings16b | Where-Object { $_.Section -eq 'Exchange SE Compatibility' -and $_.Item -eq 'Domain controller operating systems' })
Check ($se16.Count -eq 1 -and $se16[0].Status -eq 'Not Assessed' -and $se16[0].Detail -match 'AllDomains') 'C16 GAP-P20: one domain of a three-domain forest is not a forest-wide Pass of the DC gate; the row names -AllDomains'
# Independent review of the C16 diff (findings 3/9): the DC inventory of one domain of three does not
# say any site of the forest is empty, nor that the topology passes.
$site16b = @($findings16b | Where-Object { $_.Section -eq 'Site Health' })
Check (@($site16b | Where-Object { $_.Item -eq 'Empty sites' -and $_.Status -eq 'Not Assessed' -and $_.Detail -match 'AllDomains' }).Count -eq 1 -and @($site16b | Where-Object { $_.Item -eq 'Site/subnet topology' -or $_.Item -like '*has no domain controllers' }).Count -eq 0) 'C16 review 3: one domain of three scoped, so empty sites are Not Assessed naming -AllDomains and nothing passes'
# The whole forest scoped (the three-domain run above): the inventory covers it, so empty sites are judged.
Check (@($findings2 | Where-Object { $_.Section -eq 'Site Health' -and $_.Item -eq 'Empty sites' }).Count -eq 0) 'C16 review 3: every domain scoped and every inventory read, so empty sites are judged, not Not Assessed'
Remove-Item -Recurse -Force $out16 -ErrorAction SilentlyContinue
foreach ($name in @($c16Recorded.Keys)) { Set-Variable -Scope Script -Name $name -Value @($c16Recorded[$name]) }
$script:Sections = @('All')
$script:AllDomains = $true
$script:OutputPath = $out2

# C2: the same three domains with DcDisk selected WITHOUT DomainControllers. There is then no DC
# inventory, and the section used to fall back to one unscoped Get-ADDomainController call,
# which on a real forest returns the current domain's DCs only: two domains were missing from
# the section with no row to say so. The section now enumerates each scoped domain itself, so
# every domain is present and every row carries its domain.
$outD = Join-Path ([IO.Path]::GetTempPath()) ("adfa_smoke_diskonly_" + [guid]::NewGuid().ToString('N'))
$script:OutputPath = $outD
$script:Sections = @('DcDisk')
$resultD = Invoke-Main
$findingsD = @(Import-Csv $resultD.FindingsFile)
$diskD = @($findingsD | Where-Object { $_.Section -eq 'DC Disk Space' })
Check (@($resultD.DomainsScoped).Count -eq 3) ("Multi-domain, DcDisk alone: three domains scoped ({0})" -f @($resultD.DomainsScoped).Count)
Check (@($diskD).Count -eq 6) ("Multi-domain, DcDisk alone: two volume rows for each of the three domains' DC, with no DC inventory ({0}, expected 6)" -f @($diskD).Count)
foreach ($d in $multiDomains) {
    $forDomainD = @($diskD | Where-Object { $_.Scope -eq $d })
    Check (@($forDomainD).Count -eq 2 -and @($forDomainD | Where-Object { $_.Status -eq 'Pass' }).Count -eq 2) ("Multi-domain, DcDisk alone: domain '{0}' is in the section and judged ({1} rows)" -f $d, @($forDomainD).Count)
}
Check (@($diskD | Where-Object { -not $_.Scope }).Count -eq 0) 'Multi-domain, DcDisk alone: no row is without a domain'
Check (-not (Test-Path (Join-Path $resultD.CsvPath 'Domain Controllers.csv'))) 'Multi-domain, DcDisk alone: non-vacuity - the DomainControllers section itself was not run'
Remove-Item -Recurse -Force $outD -ErrorAction SilentlyContinue

# C3 / C2e: the same for DcHardening. Before v1.20.0 it took the unscoped host names, so on a
# real forest a run without DomainControllers covered the current domain only.
$outH = Join-Path ([IO.Path]::GetTempPath()) ("adfa_smoke_hardonly_" + [guid]::NewGuid().ToString('N'))
$script:OutputPath = $outH
$script:Sections = @('DcHardening')
$resultH = Invoke-Main
$hardH = @(@(Import-Csv $resultH.FindingsFile) | Where-Object { $_.Section -eq 'DC Hardening' })
Check (@($resultH.DomainsScoped).Count -eq 3) ("Multi-domain, DcHardening alone: three domains scoped ({0})" -f @($resultH.DomainsScoped).Count)
Check (@($hardH).Count -eq 24) ("Multi-domain, DcHardening alone: eight rows for each of the three domains' DC, with no DC inventory ({0}, expected 24)" -f @($hardH).Count)
foreach ($d in $multiDomains) {
    $forDomainHH = @($hardH | Where-Object { $_.Scope -eq $d })
    Check (@($forDomainHH).Count -eq 8 -and @($forDomainHH | Where-Object { $_.Status -eq 'Pass' }).Count -eq 5) ("Multi-domain, DcHardening alone: domain '{0}' is in the section and judged ({1} rows)" -f $d, @($forDomainHH).Count)
}
Check (@($hardH | Where-Object { -not $_.Scope }).Count -eq 0) 'Multi-domain, DcHardening alone: no row is without a domain'
Check (-not (Test-Path (Join-Path $resultH.CsvPath 'Domain Controllers.csv'))) 'Multi-domain, DcHardening alone: non-vacuity - the DomainControllers section itself was not run'
Remove-Item -Recurse -Force $outH -ErrorAction SilentlyContinue
# C4: Laps alone. It takes no DC list, so with no DC inventory it must still cover every domain.
$outL = Join-Path ([IO.Path]::GetTempPath()) ("adfa_smoke_lapsonly_" + [guid]::NewGuid().ToString('N'))
$script:OutputPath = $outL
$script:Sections = @('Laps')
$resultL = Invoke-Main
$lapsL = @(@(Import-Csv $resultL.FindingsFile) | Where-Object { $_.Section -eq 'Windows LAPS' })
Check (@($lapsL).Count -eq 7) ("Multi-domain, Laps alone: one schema row and two rows per domain, with no DC inventory ({0}, expected 7)" -f @($lapsL).Count)
foreach ($d in $multiDomains) {
    Check (@($lapsL | Where-Object { $_.Scope -eq $d }).Count -eq $(if ($d -eq 'contoso.com') { 3 } else { 2 })) ("Multi-domain, Laps alone: domain '{0}' is in the section" -f $d)
}
Check (-not (Test-Path (Join-Path $resultL.CsvPath 'Domain Controllers.csv'))) 'Multi-domain, Laps alone: non-vacuity - the DomainControllers section itself was not run'
Remove-Item -Recurse -Force $outL -ErrorAction SilentlyContinue
# C5: DcCertificates alone, WITH the handshake. No DC inventory, so the section enumerates each
# scoped domain itself; each DC is handshaken once, through the stub seam, and its LDAPS row is
# graded on the certificate presented.
$outC = Join-Path ([IO.Path]::GetTempPath()) ("adfa_smoke_certonly_" + [guid]::NewGuid().ToString('N'))
$script:OutputPath = $outC
$script:Sections = @('DcCertificates')
$script:IncludeLdapsHandshake = $true
$script:SmokeTlsCalls = @()
$script:SmokeTlsBounds = @()
$resultC = Invoke-Main
$script:IncludeLdapsHandshake = $false
$certC = @(@(Import-Csv $resultC.FindingsFile) | Where-Object { $_.Section -eq 'DC Certificates' })
Check (@($certC).Count -eq 9) ("Multi-domain, DcCertificates alone with the handshake: three rows for each domain's DC, with no DC inventory ({0}, expected 9)" -f @($certC).Count)
Check (@($script:SmokeTlsCalls).Count -eq 3 -and @($script:SmokeTlsCalls | Where-Object { $_ -ne 'dc1.contoso.com:636' }).Count -eq 0) ("Multi-domain, DcCertificates alone: one handshake per DC, to port 636 ({0})" -f ($script:SmokeTlsCalls -join ', '))
# Found by the independent review: the handshake's connection was bounded by the shared probe's
# 1200 ms, at which Windows reported a refusal as a time-out. It now takes ConnectTimeoutMs from
# the section's config, and the whole handshake HandshakeTimeoutMs.
Check (@($script:SmokeTlsBounds).Count -eq 3 -and @($script:SmokeTlsBounds | Where-Object { $_ -ne '5000/5000' }).Count -eq 0) ("Multi-domain, DcCertificates alone: each handshake is bounded by the section config (connect 5000 ms, handshake 5000 ms), not by the 1200 ms port probe ({0})" -f ($script:SmokeTlsBounds -join ', '))
foreach ($d in $multiDomains) {
    $forDomainCC = @($certC | Where-Object { $_.Scope -eq $d })
    Check (@($forDomainCC | Where-Object { $_.Item -eq 'LDAPS certificate: dc1.contoso.com' -and $_.Status -eq 'Pass' -and $_.Detail -match '^Presented on LDAPS port 636: ' }).Count -eq 1) ("Multi-domain, DcCertificates alone: the DC of '{0}' has its LDAPS row graded on the presented certificate" -f $d)
    Check (@($forDomainCC | Where-Object { $_.Status -eq 'Pass' -and $_.Detail -match 'It is the certificate this DC presented on LDAPS in this run' }).Count -eq 1) ("Multi-domain, DcCertificates alone: the published copy of the presented certificate of '{0}' says so" -f $d)
}
Check (@($certC | Where-Object { $_.Item -like 'LDAPS certificate: *' -and $_.Detail -match 'UntrustedRoot' }).Count -eq 0) 'Multi-domain, DcCertificates alone: the platform''s chain status is not in the finding text'
Check ((Get-Content $resultC.LogFile -Raw) -match 'IncludeLdapsHandshake is set') 'Multi-domain, DcCertificates alone: the log says the handshake switch was given'
Check (-not (Test-Path (Join-Path $resultC.CsvPath 'Domain Controllers.csv'))) 'Multi-domain, DcCertificates alone: non-vacuity - the DomainControllers section itself was not run'
Remove-Item -Recurse -Force $outC -ErrorAction SilentlyContinue
# C6: RidPool alone. No DC inventory, so the section enumerates each scoped domain itself; every
# domain gets its two rows and its DC row, and no row is without a domain.
$outR = Join-Path ([IO.Path]::GetTempPath()) ("adfa_smoke_ridonly_" + [guid]::NewGuid().ToString('N'))
$script:OutputPath = $outR
$script:Sections = @('RidPool')
$resultR = Invoke-Main
$ridR = @(@(Import-Csv $resultR.FindingsFile) | Where-Object { $_.Section -eq 'RID Pool' })
Check (@($ridR).Count -eq 9) ("Multi-domain, RidPool alone: two rows per domain and one per domain's DC, with no DC inventory ({0}, expected 9)" -f @($ridR).Count)
foreach ($d in $multiDomains) {
    $forDomainRR = @($ridR | Where-Object { $_.Scope -eq $d })
    Check (@($forDomainRR).Count -eq 3 -and @($forDomainRR | Where-Object { $_.Item -eq 'RID pool: dc1.contoso.com' -and $_.Status -eq 'Info' }).Count -eq 1) ("Multi-domain, RidPool alone: domain '{0}' is in the section, with its DC's pool read ({1} rows)" -f $d, @($forDomainRR).Count)
}
Check (@($ridR | Where-Object { -not $_.Scope }).Count -eq 0) 'Multi-domain, RidPool alone: no row is without a domain'
Check (-not (Test-Path (Join-Path $resultR.CsvPath 'Domain Controllers.csv'))) 'Multi-domain, RidPool alone: non-vacuity - the DomainControllers section itself was not run'
Remove-Item -Recurse -Force $outR -ErrorAction SilentlyContinue
# PORT-PLAN C2e: the nine sections that took the unscoped host names, selected together WITHOUT
# DomainControllers. Each now takes the DCs of every scoped domain, each row carrying its domain; the
# DNS server set of DNS vs AD is the per-domain host names, each once. repadmin and w32tm answer here.
$outC2e = Join-Path ([IO.Path]::GetTempPath()) ("adfa_smoke_c2e_" + [guid]::NewGuid().ToString('N'))
$script:OutputPath = $outC2e
$script:Sections = @('Replication', 'Sysvol', 'DcSystem', 'Backup', 'PortMatrix', 'RestoreIntegrity', 'DsEvents', 'TimeHierarchy', 'DnsAdConsistency')
$script:SmokeRepadmin = $true
$script:SmokeW32tm = $true
$script:SmokeRepadminCalls = @()
$script:SmokeUsnCalls = @()
$resultC2e = Invoke-Main
$script:SmokeRepadmin = $false
$script:SmokeW32tm = $false
$findingsC2e = @(Import-Csv $resultC2e.FindingsFile)
Check (@($resultC2e.DomainsScoped).Count -eq 3) ("Multi-domain C2e: three domains scoped ({0})" -f @($resultC2e.DomainsScoped).Count)
# Declared population: one row per section per domain, for the one DC each domain returns.
$c2eExpect = [ordered]@{
    'Replication Health'       = 'dc1.contoso.com'
    'SYSVOL / DFSR'            = 'Shares on dc1.contoso.com'
    'DFS Replication Events'   = 'Log coverage on dc1.contoso.com'
    'DC System'                = 'OS build and uptime: dc1.contoso.com'
    'Backup Status'            = 'Directory backup: dc1.contoso.com'
    'Port Reachability'        = 'dc1.contoso.com'
    'Restore Integrity'        = 'USN rollback marker on dc1.contoso.com'
    'Directory Service Events' = 'Log coverage on dc1.contoso.com'
    'Time Hierarchy'           = 'Time source on dc1.contoso.com (FOREST ROOT PDC emulator)'
}
foreach ($sec in @($c2eExpect.Keys)) {
    foreach ($d in $multiDomains) {
        $hits = @($findingsC2e | Where-Object { $_.Section -eq $sec -and $_.Item -eq $c2eExpect[$sec] -and $_.Scope -eq $d })
        Check ($hits.Count -eq 1) ("Multi-domain C2e: '{0}' has the DC of '{1}', scoped to it ({2} rows)" -f $sec, $d, $hits.Count)
    }
    # The reachability rows of Port Reachability carry an Info population row per domain (C14); no other population row.
    Check (@($findingsC2e | Where-Object { $_.Section -eq $sec -and $_.Item -like '*(population)*' -and $_.Item -notlike 'DC reachability (population): *' }).Count -eq 0) ("Multi-domain C2e: '{0}' needs no population row when every domain returned its DC" -f $sec)
}
Check (@($findingsC2e | Where-Object { $_.Section -eq 'Restore Integrity' -and $_.Item -like 'USN rollback marker on *' -and $_.Status -eq 'Pass' }).Count -eq 3 -and @($script:SmokeUsnCalls).Count -eq 3) ("Multi-domain C2e: the USN-rollback marker is read through the seam once per domain's DC ({0} reads)" -f @($script:SmokeUsnCalls).Count)
Check (@($script:SmokeRepadminCalls | Where-Object { $_ -eq '/showbackup dc1.contoso.com' }).Count -eq 3) ("Multi-domain C2e: repadmin /showbackup is asked once per domain's DC, read-only ({0})" -f (@($script:SmokeRepadminCalls) -join ', '))
Check (@($findingsC2e | Where-Object { $_.Section -eq 'DNS vs AD Consistency' } | Select-Object -ExpandProperty Scope -Unique | Where-Object { $_ }).Count -eq 3) 'Multi-domain C2e: DNS vs AD Consistency has rows for each of the three domains'
Check (-not (Test-Path (Join-Path $resultC2e.CsvPath 'Domain Controllers.csv'))) 'Multi-domain C2e: non-vacuity - the DomainControllers section itself was not run'
Remove-Item -Recurse -Force $outC2e -ErrorAction SilentlyContinue
# Found by the independent review of C2e: (1) each per-DC section ALONE must enumerate per domain - a
# section missing from the list that triggers the shared enumeration falls back to the current domain's
# DCs; Backup is the one that triggers nothing else. (2) Each domain is enumerated ONCE per run, also
# when DsEvents (which enumerates for its C15 inventory) is selected with another per-DC section.
$smokeDcEnumFunction = ${function:Get-ADDomainController}
$script:SmokeDcEnumCalls = @()
function Get-ADDomainController { param([Parameter(ValueFromRemainingArguments)]$a)
    $named = ConvertTo-StubArgument -Given $a
    $server = ''
    if ($named.ContainsKey('Server')) { $server = [string]$named['Server'] }
    $script:SmokeDcEnumCalls += $server
    & $smokeDcEnumFunction @a }
foreach ($c2eAlone in @(@('Backup'), @('DsEvents', 'Backup'))) {
    $outA = Join-Path ([IO.Path]::GetTempPath()) ("adfa_smoke_c2e_alone_" + [guid]::NewGuid().ToString('N'))
    $script:OutputPath = $outA
    $script:Sections = $c2eAlone
    $script:SmokeRepadmin = $true
    $script:SmokeRepadminCalls = @()
    $script:SmokeDcEnumCalls = @()
    $resultA = Invoke-Main
    $script:SmokeRepadmin = $false
    $findingsA = @(Import-Csv $resultA.FindingsFile)
    $label = $c2eAlone -join '+'
    foreach ($d in $multiDomains) {
        Check (@($findingsA | Where-Object { $_.Section -eq 'Backup Status' -and $_.Item -eq 'Directory backup: dc1.contoso.com' -and $_.Scope -eq $d }).Count -eq 1) ("Multi-domain C2e review, {0}: Backup has the DC of '{1}', scoped to it" -f $label, $d)
        Check (@($script:SmokeDcEnumCalls | Where-Object { $_ -eq $d }).Count -eq 1) ("Multi-domain C2e review, {0}: '{1}' is enumerated once in the run ({2} times)" -f $label, $d, @($script:SmokeDcEnumCalls | Where-Object { $_ -eq $d }).Count)
    }
    Check (@($findingsA | Where-Object { $_.Section -eq 'Backup Status' -and $_.Item -like '*(population)*' }).Count -eq 0) ("Multi-domain C2e review, {0}: Backup needs no population row" -f $label)
    Remove-Item -Recurse -Force $outA -ErrorAction SilentlyContinue
}
${function:Get-ADDomainController} = $smokeDcEnumFunction
# C4, found by the independent review: a DC whose expiry time is the last date .NET holds (the
# FILETIME of [datetime]::MaxValue, which an administrator gets by setting "never") threw out of
# the section and ended the run with no report. The run must finish, and every DC row must be graded.
$script:SmokeLapsDcExpiryFileTime = [int64]2650467743999999999
$outE = Join-Path ([IO.Path]::GetTempPath()) ("adfa_smoke_lapsend_" + [guid]::NewGuid().ToString('N'))
$script:OutputPath = $outE
$script:Sections = @('Laps')
$resultE = $null
try { $resultE = Invoke-Main } catch { Check $false ("End-of-calendar expiry: the run ended with an error - {0}" -f $_.Exception.Message) }
$script:SmokeLapsDcExpiryFileTime = $null
if ($null -ne $resultE) {
    $lapsE = @(@(Import-Csv $resultE.FindingsFile) | Where-Object { $_.Section -eq 'Windows LAPS' })
    Check (@($lapsE).Count -eq 7) ("End-of-calendar expiry: the run finished with the whole section, one schema row and two rows per domain ({0}, expected 7)" -f @($lapsE).Count)
    foreach ($d in $multiDomains) {
        Check (@($lapsE | Where-Object { $_.Item -eq ("DSRM password backup: dc1.{0}" -f $d) -and $_.Scope -eq $d -and $_.Status -eq 'Pass' -and $_.Detail -match '9999-12-31 23:59 UTC' }).Count -eq 1) ("End-of-calendar expiry: the DC of '{0}' is graded, as a time not past" -f $d)
    }
}
Remove-Item -Recurse -Force $outE -ErrorAction SilentlyContinue
$script:OutputPath = $out2
$script:Sections = @('All')

# Every scoped domain must actually appear - not just the first one.
$scopes = @($findings2 | Select-Object -ExpandProperty Scope -Unique | Where-Object { $_ })
foreach ($d in $multiDomains) {
    Check ($scopes -contains $d) ("Multi-domain: findings carry scope '{0}'" -f $d)
}

# A section CSV must hold real columns, never array metadata (Length/Rank/Count).
$ppCsv = Join-Path $result2.CsvPath 'Password Policy.csv'
if (Test-Path $ppCsv) {
    $cols = @((Import-Csv $ppCsv | Select-Object -First 1).PSObject.Properties.Name)
    Check (-not ($cols -contains 'Length' -and $cols -contains 'Rank')) ("Multi-domain: section CSV holds findings, not array metadata ({0})" -f ($cols -join ','))
}
else { Check $false 'Multi-domain: Password Policy CSV exists' }

# The reconciliation file must exist and show no unexplained empty status-bearing section.
$auditCsv = Join-Path $result2.CsvPath 'Section-Coverage.csv'
Check (Test-Path $auditCsv) 'Multi-domain: Section-Coverage.csv written'
if (Test-Path $auditCsv) {
    $audit = @(Import-Csv $auditCsv)
    Check ($audit.Count -gt 0) ("Multi-domain: reconciliation covers {0} sections" -f $audit.Count)
    $lost = @($audit | Where-Object { $_.Section -eq 'DNS vs AD Consistency' -and [int]$_.FindingsReported -eq 0 })
    Check ($lost.Count -eq 0) 'Multi-domain: DNS vs AD Consistency reported findings (reconciliation)'
}

# ---- JSON report (machine-readable twin of the HTML) -----------------------
# A phased rollout re-runs the assessment between phases and diffs the result, so the JSON
# must carry the findings and the section data in full. The depth check matters: ConvertTo-Json
# defaults to depth 2, which would render section rows as "System.Object[]" instead of values.
Check (-not [string]::IsNullOrWhiteSpace($result2.JsonPath)) 'Multi-domain: JsonPath returned'
Check (Test-Path $result2.JsonPath) 'Multi-domain: Assessment.json written'
if (Test-Path $result2.JsonPath) {
    $doc = Get-Content $result2.JsonPath -Raw | ConvertFrom-Json
    Check ($doc.schemaVersion -eq 1) 'JSON: schemaVersion present'
    Check ($doc.tool.name -eq 'ADForestAssessment') 'JSON: tool name present'
    Check (-not [string]::IsNullOrWhiteSpace([string]$doc.tool.version)) 'JSON: tool version present'
    Check ($doc.run.forest -eq 'contoso.com') 'JSON: run.forest recorded'
    Check (@($doc.run.domainsScoped).Count -eq 3) ("JSON: all three domains recorded ({0})" -f @($doc.run.domainsScoped).Count)

    # The JSON summary and the CSV findings must describe the same run.
    $jf = @($doc.findings)
    Check ($jf.Count -eq @($findings2).Count) ("JSON: findings match the consolidated CSV ({0} vs {1})" -f $jf.Count, @($findings2).Count)
    Check (@($doc.coverage).Count -eq $audit.Count) ("JSON: coverage matches Section-Coverage.csv ({0})" -f @($doc.coverage).Count)
    # Every finding must land in exactly one bucket. 'Info' is a valid New-Finding status that
    # the four legacy counters do not match, so the document adds it plus an 'unclassified'
    # catch-all; without them 17 of 123 rows were counted nowhere.
    $jsonTotal = [int]$doc.summary.pass + [int]$doc.summary.warning + [int]$doc.summary.fail +
        [int]$doc.summary.notAssessed + [int]$doc.summary.info + [int]$doc.summary.unclassified
    Check ($jsonTotal -eq $jf.Count) ("JSON: summary buckets reconcile with findings ({0} = {1})" -f $jsonTotal, $jf.Count)
    Check ([int]$doc.summary.total -eq $jf.Count) ("JSON: summary.total matches findings ({0})" -f [int]$doc.summary.total)
    Check ([int]$doc.summary.info -gt 0) ("JSON: Info findings are counted, not invisible ({0})" -f [int]$doc.summary.info)
    Check ([int]$doc.summary.unclassified -eq 0) ("JSON: no finding escaped every bucket ({0})" -f [int]$doc.summary.unclassified)

    # Findings must carry the remediation guidance, not just the verdict.
    $fnames = @(@($jf)[0].PSObject.Properties.Name)
    Check ($fnames -contains 'Status' -and $fnames -contains 'Recommendation') ("JSON: findings carry Status + Recommendation ({0})" -f ($fnames -join ','))

    # Depth: a section's rows must be objects with real values, never a type name.
    $secNames = @($doc.sections.PSObject.Properties.Name)
    Check ($secNames.Count -gt 0) ("JSON: {0} sections serialised" -f $secNames.Count)
    Check ($secNames -contains 'DNS vs AD Consistency') 'JSON: recovery section present in sections map'
    # Depth truncation does NOT show up as "System.Object[]" - ConvertTo-Json stringifies the
    # row to PowerShell's hashtable form instead, e.g. '@{Scope=contoso.com; PolicyName=...}'.
    # Measured: at the ConvertTo-Json default of -Depth 2, every section row collapses to one
    # such string while `findings` (one level shallower) still serialises correctly. So the
    # guard asserts the rows are objects with readable properties, not that a type name is
    # absent - and it targets `sections`, which is the deepest branch.
    $raw = Get-Content $result2.JsonPath -Raw
    Check ($raw -notmatch '"@\{') 'JSON: no row collapsed to a hashtable string (depth sufficient)'

    $pp = @($doc.sections.'Password Policy')
    Check ($pp.Count -eq 3) ("JSON: Password Policy carries 3 rows ({0})" -f $pp.Count)
    Check (-not ($pp[0] -is [string])) 'JSON: section row is an object, not a stringified hashtable'
    Check ($null -ne $pp[0].PSObject.Properties['MinPasswordLength']) 'JSON: section row properties are addressable'
    Check ([string]$pp[0].Scope -eq 'contoso.com') ("JSON: section row value readable (Scope={0})" -f [string]$pp[0].Scope)
}

# C14, per scoped domain: one reachability row and one clients-without-a-site row per DC of each domain
# (the stub gives every domain the same host name, so the DC is still probed only once), one stale row
# per kind and one SYSVOL engine row per domain, each carrying its own domain and read from it.
$c14Reach2 = @($findings2 | Where-Object { $_.Section -eq 'Port Reachability' -and $_.Item -eq 'DC reachability: dc1.contoso.com' })
$c14Site2 = @($findings2 | Where-Object { $_.Section -eq 'Site Health' -and $_.Item -eq 'Clients without a site: dc1.contoso.com' })
$c14Stale2 = @($findings2 | Where-Object { $_.Section -eq 'Stale Objects' -and $_.Item -eq 'Inactive enabled users' })
$c14Sys2 = @($findings2 | Where-Object { $_.Section -eq 'SYSVOL / DFSR' -and $_.Item -like 'SYSVOL replication engine: *' })
foreach ($d in $multiDomains) {
    Check (@($c14Reach2 | Where-Object { $_.Scope -eq $d -and $_.Status -eq 'Pass' }).Count -eq 1) ("Multi-domain C14: the DC of '{0}' has its reachability row" -f $d)
    Check (@($c14Site2 | Where-Object { $_.Scope -eq $d -and $_.Status -eq 'Warning' }).Count -eq 1) ("Multi-domain C14: the DC of '{0}' has its clients-without-a-site row" -f $d)
    Check (@($c14Stale2 | Where-Object { $_.Scope -eq $d -and $_.Status -eq 'Warning' }).Count -eq 1) ("Multi-domain C14: '{0}' has its own inactive users row" -f $d)
    Check (@($c14Sys2 | Where-Object { $_.Item -eq ("SYSVOL replication engine: {0}" -f $d) -and $_.Scope -eq $d -and $_.Status -eq 'Pass' }).Count -eq 1) ("Multi-domain C14: '{0}' has its own SYSVOL replication engine row" -f $d)
    Check (@($script:SmokeStaleCalls | Where-Object { $_ -eq ("user {0}" -f $d) }).Count -ge 2) ("Multi-domain C14: the stale user reads of '{0}' went to that domain" -f $d)
    Check (@($script:SmokePopulationCalls | Where-Object { $_ -eq ("user {0}" -f $d) }).Count -ge 1 -and @($script:SmokePopulationCalls | Where-Object { $_ -eq ("computer {0}" -f $d) }).Count -ge 1) ("Multi-domain C14 review: the enabled user and computer populations of '{0}' were counted from that domain" -f $d)
    Check (@($c14Stale2 | Where-Object { $_.Scope -eq $d -and $_.Detail -match 'The read saw 5 enabled user account' }).Count -eq 1) ("Multi-domain C14 review: the inactive users row of '{0}' states its own population" -f $d)
    Check (@($findings2 | Where-Object { $_.Section -eq 'Stale Objects' -and $_.Item -like 'Future logon timestamps: *' -and $_.Scope -eq $d -and $_.Status -eq 'Info' }).Count -eq 2) ("Multi-domain C14c: '{0}' has its own two future-timestamp rows" -f $d)
    Check (@($script:SmokeFutureCalls | Where-Object { $_ -eq ("user {0}" -f $d) -or $_ -eq ("computer {0}" -f $d) }).Count -eq 2) ("Multi-domain C14c: the two future reads of '{0}' went to that domain" -f $d)
    Check (@($findings2 | Where-Object { $_.Section -eq 'SYSVOL / DFSR' -and $_.Item -eq 'SYSVOL engine: dc1.contoso.com' -and $_.Scope -eq $d -and $_.Detail -match 'The registry agrees' }).Count -eq 1) ("Multi-domain C14c: the DC of '{0}' has its engine row with the registry instrument" -f $d)
}
Check (@($c14Reach2).Count -eq 3 -and @($c14Sys2).Count -eq 3) ("Multi-domain C14: three reachability rows and three domain SYSVOL rows ({0}, {1})" -f @($c14Reach2).Count, @($c14Sys2).Count)

# C15, per scoped domain: each family has its own rows for each of the three domains, read from that domain.
foreach ($d in $multiDomains) {
    Check (@($findings2 | Where-Object { $_.Section -eq 'Object Counts' -and $_.Scope -eq $d }).Count -eq 13) ("Multi-domain C15: '{0}' has its own thirteen object counts" -f $d)
    Check (@($findings2 | Where-Object { $_.Section -eq 'Topology Inventory' -and $_.Item -eq ("Domain functional level: {0}" -f $d) -and $_.Status -eq 'Info' }).Count -eq 1) ("Multi-domain C15: '{0}' has its own domain level" -f $d)
    Check (@($findings2 | Where-Object { $_.Section -eq 'Trust Inventory' -and $_.Item -eq ("Trusts (population): {0}" -f $d) -and $_.Status -eq 'Info' }).Count -eq 1) ("Multi-domain C15: '{0}' has its own trust population row" -f $d)
    Check (@($findings2 | Where-Object { $_.Section -eq 'Group Inventory' -and $_.Item -eq ("Empty groups: {0}" -f $d) }).Count -eq 1) ("Multi-domain C15: '{0}' has its own group inventory" -f $d)
    Check (@($findings2 | Where-Object { $_.Section -eq 'GPO Directory Inventory' -and $_.Item -eq ("GPO directory inventory: {0}" -f $d) -and $_.Status -eq 'Info' }).Count -eq 1) ("Multi-domain C15: '{0}' has its own GPO directory inventory, Info with every forest domain read" -f $d)
    Check (@($findings2 | Where-Object { $_.Section -eq 'Stale Objects' -and $_.Item -eq 'Stale disabled users' -and $_.Scope -eq $d -and $_.Status -eq 'Info' }).Count -eq 1) ("Multi-domain C15: '{0}' has its own stale disabled users row" -f $d)
    Check (@($findings2 | Where-Object { $_.Section -eq 'Time Configuration' -and $_.Item -like 'W32Time configuration: *' -and $_.Scope -eq $d }).Count -eq 1) ("Multi-domain C15: the DC of '{0}' has its W32Time row" -f $d)
    Check (@($findings2 | Where-Object { $_.Section -eq 'Event Inventory' -and $_.Item -like 'Event log: *' -and $_.Scope -eq $d }).Count -eq 5) ("Multi-domain C15: the DC of '{0}' has its five event log rows" -f $d)
    Check (@($script:SmokeInventoryCalls | Where-Object { $_ -match ("@{0}$" -f [regex]::Escape($d)) }).Count -gt 0) ("Multi-domain C15: the inventory reads of '{0}' went to that domain" -f $d)
    # C4b: each domain's own export and trust reads, with the declared lists, and its own summary rows.
    Check (@($script:SmokeExportCalls | Where-Object { $_ -like ("User@{0}#*" -f $d) }).Count -eq 1 -and @($script:SmokeExportCalls | Where-Object { $_ -like ("Computer@{0}#*" -f $d) }).Count -eq 1) ("Multi-domain C4b: one user and one computer export read went to '{0}'" -f $d)
    Check (@($script:SmokeC4bCalls | Where-Object { $_ -like ("Trust:*@{0}" -f $d) }).Count -eq 1) ("Multi-domain C4b: the trust read of '{0}' went to that domain with the declared list" -f $d)
    Check (@($findings2 | Where-Object { $_.Section -eq 'Identity Inventory' -and $_.Scope -eq $d -and $_.Status -eq 'Info' }).Count -eq 2) ("Multi-domain C4b: '{0}' has its own users and computers summary rows" -f $d)
    Check (Test-Path (Join-Path $result2.CsvPath ("AllUsers_{0}.csv" -f (New-SafeFileName $d)))) ("Multi-domain C4b: '{0}' has its own user export file" -f $d)
}
# Declared population: three domains x two kinds; one site link and one connection read for the forest.
Check (@($script:SmokeExportCalls).Count -eq 6) ("Multi-domain C4b: six export reads in all ({0})" -f @($script:SmokeExportCalls).Count)
Check (@($script:SmokeC4bCalls | Where-Object { $_ -like 'SiteLink:*' }).Count -eq 1 -and @($script:SmokeC4bCalls | Where-Object { $_ -like 'Connection:*' }).Count -eq 1) 'Multi-domain C4b: the site links and connections are read once for the forest'
Check (@($findings2 | Where-Object { $_.Section -eq 'Topology Inventory' -and $_.Item -like 'FSMO role holder: *' }).Count -eq 11) 'Multi-domain C15: two forest roles and three roles per domain (declared population: eleven rows)'
# C15 review (INV-011): north.contoso.com's Default Domain Controllers Policy is linked only from an OU of
# south.contoso.com (a disabled link). Read across every scoped domain, it is linked - never "unlinked" -
# and the link is credited to north's GPO by the domain in its DN, not to contoso's or south's GPO with the
# same GUID.
$c15GpoCsv2 = Join-Path $result2.CsvPath 'GPO Directory Inventory.csv'
if (Test-Path $c15GpoCsv2) {
    $c15Gpo2 = @(Import-Csv $c15GpoCsv2)
    $c15North = @($c15Gpo2 | Where-Object { $_.Item -eq 'GPO directory inventory: north.contoso.com' })
    Check ($c15North.Count -eq 1 -and $c15North[0].Status -eq 'Info' -and $c15North[0].Linked -eq '2' -and $c15North[0].Unlinked -eq '0' -and $c15North[0].OtherDomainSoms -eq 'All read') 'Multi-domain C15 review: a GPO linked only from another domain''s OU is counted as linked'
    $c15NorthDcp = @($c15Gpo2 | Where-Object { $_.Scope -eq 'north.contoso.com' -and $_.Item -eq ('GPO: {0}' -f $script:SmokeGpoGuids[1]) })
    Check ($c15NorthDcp.Count -eq 1 -and $c15NorthDcp[0].Links -eq '1' -and $c15NorthDcp[0].DisabledLinks -eq '1' -and $c15NorthDcp[0].EnabledLinks -eq '0') 'Multi-domain C15 review: the cross-domain link is credited to the GPO of the domain its DN names, with its disabled option'
    Check (@($c15Gpo2 | Where-Object { $_.Scope -eq 'north.contoso.com' -and $_.Item -eq 'GPO links on a SOM: north.contoso.com' -and $_.Som -eq 'OU=Branch,DC=south,DC=contoso,DC=com' -and $_.LinksToThisDomain -eq '1' }).Count -eq 1) 'Multi-domain C15 review: the other domain''s OU is listed under the domain whose GPO it links'
    $c15South = @($c15Gpo2 | Where-Object { $_.Item -eq 'GPO directory inventory: south.contoso.com' })
    Check ($c15South.Count -eq 1 -and $c15South[0].LinksToOtherGpos -eq '1' -and $c15South[0].Links -eq '2') 'Multi-domain C15 review: south counts the link to north''s GPO as a link to another domain''s GPO, not its own'
}
else { Check $false 'Multi-domain C15: GPO Directory Inventory CSV exists' }
Check (@($findings2 | Where-Object { ($_.Section -in @('Topology Inventory', 'Trust Inventory', 'Object Counts', 'Group Inventory', 'GPO Directory Inventory', 'Event Inventory', 'Time Configuration') -or $_.Item -like 'Stale disabled *') -and @('Info', 'Not Assessed') -notcontains $_.Status }).Count -eq 0) 'Multi-domain C15: no inventory row is Pass, Warning or Fail'
Check (@($findings2 | Where-Object { $_.Section -eq 'Site Health' -and $_.Item -eq 'Subnets without a site: contoso.com' }).Count -eq 1) 'Multi-domain C14: one subnet row for the forest'

# C14 (TIME-001): TimeHierarchy with w32tm answering, for two DCs of the forest root domain - dc1, the
# forest root PDC emulator, and dc2, 400 s away from it. Read-only w32tm forms only; the stub refuses any
# other. dc1 is the reference (Info) and dc2 fails against it; its runner-relative row is kept.
$smokeDcFunction = ${function:Get-ADDomainController}
function Get-ADDomainController { param([Parameter(ValueFromRemainingArguments)]$a)
    [pscustomobject]@{ HostName = 'dc1.contoso.com'; Name = 'DC1'; Site = 'Default-First-Site-Name'; IPv4Address = '192.0.2.10'; IsGlobalCatalog = $true; IsReadOnly = $false; ComputerObjectDN = 'CN=DC1,OU=Domain Controllers,DC=contoso,DC=com' }
    [pscustomobject]@{ HostName = 'dc2.contoso.com'; Name = 'DC2'; Site = 'Default-First-Site-Name'; IPv4Address = '192.0.2.11'; IsGlobalCatalog = $true; IsReadOnly = $false; ComputerObjectDN = 'CN=DC2,OU=Domain Controllers,DC=contoso,DC=com' } }
$outT = Join-Path ([IO.Path]::GetTempPath()) ("adfa_smoke_time_" + [guid]::NewGuid().ToString('N'))
$script:OutputPath = $outT
$script:AllDomains = $false
$script:Sections = @('PortMatrix', 'TimeHierarchy')
$script:SmokeW32tm = $true
$script:SmokeW32tmCalls = @()
$resultT = Invoke-Main
$script:SmokeW32tm = $false
${function:Get-ADDomainController} = $smokeDcFunction
$timeT = @(@(Import-Csv $resultT.FindingsFile) | Where-Object { $_.Section -eq 'Time Hierarchy' })
Check (@($timeT | Where-Object { $_.Item -eq 'Clock offset vs forest root PDC: dc1.contoso.com' -and $_.Status -eq 'Info' }).Count -eq 1) 'C14 TIME: the forest root PDC emulator is the reference, Info'
Check (@($timeT | Where-Object { $_.Item -eq 'Clock offset vs forest root PDC: dc2.contoso.com' -and $_.Status -eq 'Fail' -and $_.Detail -match 'is 400 s' }).Count -eq 1) 'C14 TIME: a DC 400 s from the forest root PDC fails against it'
Check (@($timeT | Where-Object { $_.Item -eq 'Clock offset on dc2.contoso.com' }).Count -eq 1) 'C14 TIME: the runner-relative row is kept'
Check (@($script:SmokeW32tmCalls | Where-Object { $_ -match '^/stripchart ' }).Count -eq 2) ("C14 TIME: one stripchart per DC, the reference reused, not read twice ({0})" -f (@($script:SmokeW32tmCalls) -join ' | '))
Remove-Item -Recurse -Force $outT -ErrorAction SilentlyContinue
$script:OutputPath = $out2
$script:AllDomains = $true
$script:Sections = @('All')

Write-Host ""
Write-Host ("Multi-domain bundle: {0}" -f $result2.OutputRoot)

# ---- Scenario 2b: -ConfigOverridePath through the whole run (C2) ------------
# The Pester suite proves the loader and the validator. This proves the wiring: that the file
# named on the command line reaches the section that uses it, that a finding then cites the
# file, and that a file that cannot be used stops the run before anything is collected.
Write-Host ""
Write-Host "== Running Invoke-Main with -ConfigOverridePath ==" -ForegroundColor Cyan

$overrideFile = Join-Path ([IO.Path]::GetTempPath()) ("adfa_smoke_override_" + [guid]::NewGuid().ToString('N') + ".json")
# The stub volumes are 50 % (C:) and 60 % (E:) free. These thresholds turn the first into a Fail
# and the second into a Warning; the built-in ones pass both.
'{ "DcDisk": { "WarnBelowPercent": 70, "FailBelowPercent": 55 } }' | Out-File -LiteralPath $overrideFile -Encoding UTF8
$outO = Join-Path ([IO.Path]::GetTempPath()) ("adfa_smoke_override_" + [guid]::NewGuid().ToString('N'))
$script:OutputPath = $outO
$script:AllDomains = $false
$script:Sections = @('DomainControllers', 'DcDisk')
$script:ConfigOverridePath = $overrideFile
$resultO = Invoke-Main
$findingsO = @(Import-Csv $resultO.FindingsFile)
$diskO = @($findingsO | Where-Object { $_.Section -eq 'DC Disk Space' })
Check (@($diskO).Count -eq 2) ("Override: DC Disk Space still gives one row per volume ({0}, expected 2)" -f @($diskO).Count)
$diskOC = @($diskO | Where-Object { $_.Item -like '*C:\ (NTDS database, SYSVOL)' })
$diskOE = @($diskO | Where-Object { $_.Item -like '*E:\ (NTDS logs)' })
Check (@($diskOC).Count -eq 1 -and $diskOC[0].Status -eq 'Fail') 'Override: the file''s thresholds reached the section - 50 % free is now a Fail (below 55 %)'
Check (@($diskOE).Count -eq 1 -and $diskOE[0].Status -eq 'Warning') 'Override: 60 % free is now a Warning (below 70 %)'
Check (@($diskO | Where-Object { $_.Detail -match [regex]::Escape($overrideFile) }).Count -eq 2) 'Override: each finding cites the file for the thresholds it supplied'
Check (@($diskO | Where-Object { $_.Detail -match 'for WarnBelowPercent, FailBelowPercent; tool default, not a Microsoft value, for WarnBelowFreeGB, FailBelowFreeGB' }).Count -eq 2) 'Override: the thresholds the file did not supply are still labelled tool defaults'
Check (@($diskO | Where-Object { $_.Recommendation -match 'Move unrelated files' }).Count -eq 2) 'Override: a Fail and a Warning row each carry the disk space advice'
Check (@($diskO | Where-Object { $_.Recommendation -match 'D4|dfsrmig|repadmin|wbadmin' }).Count -eq 0) 'Override: a row naming SYSVOL is not given the DFSR restore advice'
$logO = Get-Content $resultO.LogFile -Raw
Check ($logO -match 'Config override: section DcDisk taken from') 'Override: the log records which section was taken from the file'
Remove-Item -Recurse -Force $outO -ErrorAction SilentlyContinue

# C4: the same for the Laps key of the file. One of three in-population computers has no expiry
# time (33.33 %): a Warning by the built-in thresholds, a Fail once the file sets Fail above 20 %.
'{ "Laps": { "FailAbovePercent": 20, "SampleLimit": 0 } }' | Out-File -LiteralPath $overrideFile -Encoding UTF8
$outOL = Join-Path ([IO.Path]::GetTempPath()) ("adfa_smoke_override_" + [guid]::NewGuid().ToString('N'))
$script:OutputPath = $outOL
$script:Sections = @('Laps')
$resultOL = Invoke-Main
$lapsO = @(@(Import-Csv $resultOL.FindingsFile) | Where-Object { $_.Section -eq 'Windows LAPS' })
$lapsOCov = @($lapsO | Where-Object { $_.Item -eq 'LAPS coverage: contoso.com' })
Check (@($lapsOCov).Count -eq 1 -and $lapsOCov[0].Status -eq 'Fail' -and $lapsOCov[0].Detail -match 'above the Fail threshold of 20 %') 'Override: the file reached the Laps section - 33.33 % without an expiry time is now a Fail (above 20 %)'
Check (@($lapsOCov).Count -eq 1 -and $lapsOCov[0].Detail -match [regex]::Escape($overrideFile) -and $lapsOCov[0].Detail -match 'for FailAbovePercent, SampleLimit; tool default, not a Microsoft value, for WarnAbovePercent, ExpiredGraceDays') 'Override: the finding cites the file for the values it supplied, and still calls the rest tool defaults'
Check (@($lapsOCov).Count -eq 1 -and $lapsOCov[0].Detail -match 'names are not listed \(SampleLimit is 0\)' -and $lapsOCov[0].Detail -notmatch 'ws2\.contoso\.com') 'Override: a sample limit of 0 lists no computer name'
Check (@($lapsOCov).Count -eq 1 -and $lapsOCov[0].Recommendation -match 'Set-LapsADComputerSelfPermission' -and $lapsOCov[0].Recommendation -notmatch 'wbadmin|repadmin|dfsrmig') 'Override: a row that cites a file path still carries the advice of its own family'
Check ((Get-Content $resultOL.LogFile -Raw) -match 'Config override: section Laps taken from') 'Override: the log records that the Laps section was taken from the file'
Remove-Item -Recurse -Force $outOL -ErrorAction SilentlyContinue

# C5: the same for the DcCertificates key. The published valid certificate has 200 days left: a
# Pass by the built-in 30-day window, a Warning once the file widens it to 365 days.
'{ "DcCertificates": { "WarnWithinDays": 365 } }' | Out-File -LiteralPath $overrideFile -Encoding UTF8
$outOC = Join-Path ([IO.Path]::GetTempPath()) ("adfa_smoke_override_" + [guid]::NewGuid().ToString('N'))
$script:OutputPath = $outOC
$script:Sections = @('DomainControllers', 'DcCertificates')
$resultOC = Invoke-Main
$certO = @(@(Import-Csv $resultOC.FindingsFile) | Where-Object { $_.Section -eq 'DC Certificates' })
$certOValid = @($certO | Where-Object { $_.Item -eq ("Directory certificate: dc1.contoso.com [{0}]" -f $script:SmokeCertValid.Thumbprint.ToUpperInvariant()) })
Check (@($certOValid).Count -eq 1 -and $certOValid[0].Status -eq 'Warning' -and $certOValid[0].Detail -match 'within the Warning window of 365 day') 'Override: the file reached the DcCertificates section - 200 days left is now a Warning (window 365 days)'
Check (@($certOValid).Count -eq 1 -and $certOValid[0].Detail -match [regex]::Escape($overrideFile) -and $certOValid[0].Detail -match 'for WarnWithinDays; tool default, not a Microsoft value, for FailWithinDays') 'Override: the finding cites the file for the window it supplied, and still calls the other a tool default'
Check (@($certOValid).Count -eq 1 -and $certOValid[0].Recommendation -match 'userCertificate' -and $certOValid[0].Recommendation -notmatch 'wbadmin|repadmin|dfsrmig|ENROLLEE_SUPPLIES_SUBJECT') 'Override: a row that cites a file path still carries the advice of its own family'
Check ((Get-Content $resultOC.LogFile -Raw) -match 'Config override: section DcCertificates taken from') 'Override: the log records that the DcCertificates section was taken from the file'
Remove-Item -Recurse -Force $outOC -ErrorAction SilentlyContinue

# C3: the same for the DcHardening key of the file. The stub DC's SMB client signing value is not
# set, which is a Warning by the documented pre-2025 default; the file turns a value below the
# expectation into a Fail for that setting only, and the finding cites the file.
'{ "DcHardening": { "Settings": { "SmbClientSigning": { "OtherStatus": "Fail" } } } }' | Out-File -LiteralPath $overrideFile -Encoding UTF8
$outOH = Join-Path ([IO.Path]::GetTempPath()) ("adfa_smoke_override_" + [guid]::NewGuid().ToString('N'))
$script:OutputPath = $outOH
$script:Sections = @('DomainControllers', 'DcHardening')
$resultOH = Invoke-Main
$hardO = @(@(Import-Csv $resultOH.FindingsFile) | Where-Object { $_.Section -eq 'DC Hardening' })
Check (@($hardO).Count -eq 8) ("Override: DC Hardening still gives one row per setting ({0}, expected 8)" -f @($hardO).Count)
$hardOClient = @($hardO | Where-Object { $_.Item -eq 'SMB client signing: dc1.contoso.com' })
Check (@($hardOClient).Count -eq 1 -and $hardOClient[0].Status -eq 'Fail') 'Override: the file reached the section - SMB client signing below the expectation is now a Fail'
Check (@($hardOClient).Count -eq 1 -and $hardOClient[0].Detail -match [regex]::Escape($overrideFile) -and $hardOClient[0].Detail -match 'for OtherStatus') 'Override: the finding cites the file for the value it supplied'
Check (@($hardOClient).Count -eq 1 -and $hardOClient[0].Recommendation -match 'Microsoft network client: Digitally sign communications') 'Override: a row that cites a file path still carries the advice of its own family'
Check (@($hardO | Where-Object { $_.Item -eq 'LDAP channel binding: dc1.contoso.com' -and $_.Status -eq 'Warning' -and $_.Detail -notmatch [regex]::Escape($overrideFile) }).Count -eq 1) 'Override: a setting the file does not name keeps its built-in status and source'
Check ((Get-Content $resultOH.LogFile -Raw) -match 'Config override: section DcHardening taken from') 'Override: the log records that the DcHardening section was taken from the file'
Remove-Item -Recurse -Force $outOH -ErrorAction SilentlyContinue

# C3f: the other answers Get-SmbServerConfiguration can give, each run end to end through Invoke-Main
# so the SMBv1 row and the second instrument of SMB server signing are seen to move together. (The
# override file above is still in force; it touches SMB client signing only.) Declared population:
# the four modes - no object, a refusal, SMBv1 enabled, and the cmdlet missing on the assessing host.
$smbModes = @(
    @{ Mode = 'Missing'; Status = 'Not Assessed'; Smb1 = '^Not read: Get-SmbServerConfiguration \(module SmbShare\) is not available on the computer running the assessment'; Second = 'was not read \(Get-SmbServerConfiguration \(module SmbShare\) is not available' }
    @{ Mode = 'Empty'; Status = 'Not Assessed'; Smb1 = '^Not read: Get-SmbServerConfiguration returned no configuration object for this DC, and no error'; Second = 'was not read \(Get-SmbServerConfiguration returned no configuration object' }
    @{ Mode = 'Denied'; Status = 'Not Assessed'; Smb1 = '^Access denied: Get-SmbServerConfiguration could not read the SMB server configuration of this DC, so whether the SMBv1 server is enabled is not known\. This is not a pass\. Which rights this read needs on a DC is not published and has not been measured \(PORT-PLAN C17a\)\. Reported by the DC - dc1\.contoso\.com: Acesso negado'; Second = 'was not read \(access denied - dc1\.contoso\.com: Acesso negado' }
    @{ Mode = 'Smb1On'; Status = 'Fail'; Smb1 = '^EnableSMB1Protocol = True: the SMBv1 server is enabled on this DC'; Second = 'The second instrument agrees' }
)
Check (@($smbModes).Count -eq 4) 'SMB server configuration: four answers exercised (declared population)'
foreach ($m in $smbModes) {
    $script:SmokeSmbMode = $m.Mode
    $script:SmokeSmbCmdlet = ($m.Mode -ne 'Missing')
    $script:SmokeSmbCalls = @()
    $outSI = Join-Path ([IO.Path]::GetTempPath()) ("adfa_smoke_smb_" + [guid]::NewGuid().ToString('N'))
    $script:OutputPath = $outSI
    $script:Sections = @('DomainControllers', 'DcHardening')
    $resultSI = Invoke-Main
    $hardSI = @(@(Import-Csv $resultSI.FindingsFile) | Where-Object { $_.Section -eq 'DC Hardening' })
    Check (@($hardSI).Count -eq 8) ("SMB {0}: DC Hardening gives one row per setting ({1}, expected 8)" -f $m.Mode, @($hardSI).Count)
    $wantCalls = 1
    if ($m.Mode -eq 'Missing') { $wantCalls = 0 }
    Check (@($script:SmokeSmbCalls).Count -eq $wantCalls) ("SMB {0}: the cmdlet was asked {1} time(s), as expected ({2})" -f $m.Mode, @($script:SmokeSmbCalls).Count, $wantCalls)
    $smb1SI = @($hardSI | Where-Object { $_.Item -eq 'SMBv1: dc1.contoso.com' })
    Check (@($smb1SI).Count -eq 1 -and $smb1SI[0].Status -eq $m.Status -and $smb1SI[0].Detail -match $m.Smb1) ("SMB {0}: the SMBv1 row is {1} with its own cause" -f $m.Mode, $m.Status)
    $signSI = @($hardSI | Where-Object { $_.Item -eq 'SMB server signing: dc1.contoso.com' })
    Check (@($signSI).Count -eq 1 -and $signSI[0].Status -eq 'Pass' -and $signSI[0].Detail -match $m.Second) ("SMB {0}: SMB server signing is graded on the registry value and states its second instrument" -f $m.Mode)
    if ($m.Status -ne 'Fail') { Check (-not $smb1SI[0].Recommendation) ("SMB {0}: an SMBv1 row that read nothing carries no advice" -f $m.Mode) }
    else { Check ($smb1SI[0].Recommendation -match 'EnableSMB1Protocol \$false') 'SMB Smb1On: the SMBv1 Fail carries its own family''s advice' }
    Remove-Item -Recurse -Force $outSI -ErrorAction SilentlyContinue
}
$script:SmokeSmbMode = 'Instance'
$script:SmokeSmbCmdlet = $true
'{ "DcDisk": { "WarnBelowPercent": 70, "FailBelowPercent": 55 } }' | Out-File -LiteralPath $overrideFile -Encoding UTF8

# The same file with a section this run does not select: validated, logged as unused, no effect.
$outU = Join-Path ([IO.Path]::GetTempPath()) ("adfa_smoke_override_" + [guid]::NewGuid().ToString('N'))
$script:OutputPath = $outU
$script:Sections = @('DomainControllers', 'DcSystem')
$resultU = Invoke-Main
$logU = Get-Content $resultU.LogFile -Raw
Check ($logU -match 'section DcDisk was validated but is not used by this run') 'Override: a section the run does not select is validated and logged as unused'
$findingsU = @(Import-Csv $resultU.FindingsFile)
Check (@($findingsU | Where-Object { $_.Section -eq 'DC System' }).Count -gt 0) 'Override: non-vacuity - the run that did not select DcDisk did produce findings'
Check (@($findingsU | Where-Object { $_.Section -eq 'DC Disk Space' }).Count -eq 0) 'Override: an unselected section is still not run'
Remove-Item -Recurse -Force $outU -ErrorAction SilentlyContinue

# A registry value that is not set on the DC. The stub answers as the provider was measured to:
# 1 for a value that does not exist under a key that does. The role must come back Not Assessed
# and named Not found - not as an uninterpreted read failure - and the other two roles must
# still be judged. (The override file is still in force here; its thresholds fail and warn the
# two volumes, which does not matter to this check.)
$outA = Join-Path ([IO.Path]::GetTempPath()) ("adfa_smoke_absent_" + [guid]::NewGuid().ToString('N'))
$script:OutputPath = $outA
$script:Sections = @('DomainControllers', 'DcDisk')
$script:SmokeAbsentValues = @('SysVol')
$resultA = Invoke-Main
$script:SmokeAbsentValues = @()
# C1a: the same DC with no UBR value under a key that exists (the stub answers 1). The OS build row must say the revision
# was not read, show the build without it, and stay Info on the build and uptime it did read - never a revision of 0.
$outU1 = Join-Path ([IO.Path]::GetTempPath()) ("adfa_smoke_ubr_" + [guid]::NewGuid().ToString('N'))
$script:OutputPath = $outU1
$script:Sections = @('DomainControllers', 'DcSystem')
$script:SmokeAbsentValues = @('UBR')
$resultU1 = Invoke-Main
$script:SmokeAbsentValues = @()
$osU1 = @(@(Import-Csv $resultU1.FindingsFile) | Where-Object { $_.Section -eq 'DC System' -and $_.Item -like 'OS build and uptime:*' })
Check (@($osU1).Count -eq 1 -and $osU1[0].Status -eq 'Info' -and $osU1[0].Detail -match 'Build 17763 \(version' -and $osU1[0].Detail -match 'Update build revision not read: the registry value UBR' -and $osU1[0].Detail -match 'is not set on this DC' -and $osU1[0].Detail -notmatch '17763\.\d') 'Absent value C1a: a DC with no UBR value shows the build without a revision, says why, and is never given .0'
Remove-Item -Recurse -Force $outU1 -ErrorAction SilentlyContinue
$script:OutputPath = $outA
$script:Sections = @('DomainControllers', 'DcDisk')
$diskA = @(@(Import-Csv $resultA.FindingsFile) | Where-Object { $_.Section -eq 'DC Disk Space' })
Check (@($diskA).Count -eq 3) ("Absent value: one row for each volume and one for the role that could not be placed ({0}, expected 3)" -f @($diskA).Count)
$absentRow = @($diskA | Where-Object { $_.Item -eq 'Disk space: dc1.contoso.com - SYSVOL path' })
Check (@($absentRow).Count -eq 1 -and $absentRow[0].Status -eq 'Not Assessed') 'Absent value: the SYSVOL role is Not Assessed, never Pass'
Check (@($absentRow).Count -eq 1 -and $absentRow[0].Detail -match '^Not found: StdRegProv returned 1,' -and $absentRow[0].Detail -match 'measured, not published by Microsoft') 'Absent value: the cause is named Not found, with the return code, and the reading is labelled measured, not published'
Check (@($absentRow).Count -eq 1 -and $absentRow[0].Detail -match 'No default location is assumed') 'Absent value: no default path is put in its place'
Check (@($diskA | Where-Object { $_.Item -like '*C:\ (NTDS database)' -or $_.Item -like '*E:\ (NTDS logs)' }).Count -eq 2) 'Absent value: the database and log volumes are still judged, each on its own row'
Check (@($diskA | Where-Object { $_.Status -eq 'Pass' }).Count -eq 0) 'Absent value: nothing passes on the strength of the value that was not read'
Remove-Item -Recurse -Force $outA -ErrorAction SilentlyContinue

# C5: the userCertificate read refused, with the handshake on. The LDAPS row is still graded on
# the presented certificate; the directory row is Not Assessed with the cause, never Info and
# never "no certificate".
$outCF = Join-Path ([IO.Path]::GetTempPath()) ("adfa_smoke_certfail_" + [guid]::NewGuid().ToString('N'))
$script:OutputPath = $outCF
$script:Sections = @('DomainControllers', 'DcCertificates')
$script:IncludeLdapsHandshake = $true
$script:SmokeCertDirFail = $true
$resultCF = Invoke-Main
$script:SmokeCertDirFail = $false
$script:IncludeLdapsHandshake = $false
$certF = @(@(Import-Csv $resultCF.FindingsFile) | Where-Object { $_.Section -eq 'DC Certificates' })
Check (@($certF).Count -eq 2) ("Certificate read refused: one LDAPS row and one directory row ({0}, expected 2)" -f @($certF).Count)
Check (@($certF | Where-Object { $_.Item -eq 'Directory certificates: dc1.contoso.com' -and $_.Status -eq 'Not Assessed' -and $_.Detail -match '^Read failed: ' -and $_.Detail -match 'STUB: certificate read refused' }).Count -eq 1) 'Certificate read refused: the directory row is Not Assessed with the cause, never Info'
Check (@($certF | Where-Object { $_.Item -eq 'LDAPS certificate: dc1.contoso.com' -and $_.Status -eq 'Pass' }).Count -eq 1) 'Certificate read refused: non-vacuity - the presented certificate is still graded'
Remove-Item -Recurse -Force $outCF -ErrorAction SilentlyContinue

# C6: the DC's computer object has no rIDSetReferences and the one-level search finds no RID Set.
# The row says "RID Set object absent", names the known defect, and is never Info or Pass; the
# domain rows are still graded. Then the computer read refused: Access denied, not absent.
$outRA = Join-Path ([IO.Path]::GetTempPath()) ("adfa_smoke_ridabsent_" + [guid]::NewGuid().ToString('N'))
$script:OutputPath = $outRA
$script:Sections = @('DomainControllers', 'RidPool')
$script:SmokeRidSetAbsent = $true
$resultRA = Invoke-Main
$script:SmokeRidSetAbsent = $false
$ridA = @(@(Import-Csv $resultRA.FindingsFile) | Where-Object { $_.Section -eq 'RID Pool' })
Check (@($ridA).Count -eq 3) ("RID Set absent: two domain rows and one DC row ({0}, expected 3)" -f @($ridA).Count)
Check (@($ridA | Where-Object { $_.Item -eq 'RID pool: dc1.contoso.com' -and $_.Status -eq 'Not Assessed' -and $_.Detail -match '^RID Set object absent: rIDSetReferences of dc1\.contoso\.com has no value' -and $_.Detail -match 'KB 2618669' }).Count -eq 1) 'RID Set absent: the DC row says so, after both instruments, names the known defect, and is Not Assessed'
Check (@($ridA | Where-Object { $_.Item -eq 'Global RID space: contoso.com' -and $_.Status -eq 'Pass' }).Count -eq 1 -and @($ridA | Where-Object { $_.Item -eq 'RID pool allocation: contoso.com' -and $_.Status -eq 'Not Assessed' -and $_.Detail -match '^Not returned: ' }).Count -eq 1) 'RID Set absent: non-vacuity - the domain rows are still read (the space graded, the allocation attribute not returned)'
Remove-Item -Recurse -Force $outRA -ErrorAction SilentlyContinue
$outRD = Join-Path ([IO.Path]::GetTempPath()) ("adfa_smoke_riddenied_" + [guid]::NewGuid().ToString('N'))
$script:OutputPath = $outRD
$script:SmokeRidDcRefused = $true
$resultRD = Invoke-Main
$script:SmokeRidDcRefused = $false
$ridD = @(@(Import-Csv $resultRD.FindingsFile) | Where-Object { $_.Section -eq 'RID Pool' })
Check (@($ridD | Where-Object { $_.Item -eq 'RID pool: dc1.contoso.com' -and $_.Status -eq 'Not Assessed' -and $_.Detail -match '^Access denied: ' -and $_.Detail -notmatch 'absent' }).Count -eq 1) 'RID computer read refused: the DC row is Access denied, not absent and not unreachable'
Remove-Item -Recurse -Force $outRD -ErrorAction SilentlyContinue

# C11: the DcDiag key of the file sets the time-out and retries of each dcdiag invocation, and the
# section takes them; a localised dcdiag is never read as a pass.
'{ "DcDiag": { "TestTimeoutSeconds": 240, "Retries": 3 } }' | Out-File -LiteralPath $overrideFile -Encoding UTF8
$script:ConfigOverridePath = $overrideFile
$outDD = Join-Path ([IO.Path]::GetTempPath()) ("adfa_smoke_override_" + [guid]::NewGuid().ToString('N'))
$script:OutputPath = $outDD
$script:Sections = @('DomainControllers', 'DcDiagnostics')
$script:SmokeDcdiagCalls = @()
$script:SmokeDcdiagMode = 'Localised'
$resultDD = Invoke-Main
$script:SmokeDcdiagMode = 'Pass'
$ddO = @(@(Import-Csv $resultDD.FindingsFile) | Where-Object { $_.Section -eq 'DC Diagnostics' })
Check (@($script:SmokeDcdiagCalls).Count -gt 0 -and @($script:SmokeDcdiagCalls | Where-Object { $_.Timeout -ne 240 -or $_.Retries -ne 3 }).Count -eq 0) ("Override: every dcdiag invocation got the file's time-out and retries ({0} calls)" -f @($script:SmokeDcdiagCalls).Count)
Check (@($ddO | Where-Object { $_.Item -eq 'dc1.contoso.com' -and $_.Status -eq 'Not Assessed' -and $_.Detail -match 'not recognised' }).Count -eq 1) 'DC Diagnostics: localised output leaves the grid row Not Assessed, saying the output was not recognised'
Check (@($ddO | Where-Object { $_.Status -match '^(Pass|Fail|Warning)$' }).Count -eq 0) 'DC Diagnostics: with output it cannot read, no row is a Pass, a Fail or a Warning'
Check ((Get-Content $resultDD.LogFile -Raw) -match 'Config override: section DcDiag taken from') 'Override: the log records that the DcDiag section was taken from the file'
Remove-Item -Recurse -Force $outDD -ErrorAction SilentlyContinue
$script:Sections = @('All')

# PORT-PLAN C4b4 and C11h: the file sets the Inventory and Stale caps, and a grid cell fails with words
# that used to choose another section's advice. Every cap the C15 and Stale rows name is the file's, and
# the failing grid row gets the MachineAccount advice.
'{ "Inventory": { "MaxObjects": 1 }, "Stale": { "MaxObjects": 1 } }' | Out-File -LiteralPath $overrideFile -Encoding UTF8
$script:ConfigOverridePath = $overrideFile
$outCap = Join-Path ([IO.Path]::GetTempPath()) ("adfa_smoke_cap_" + [guid]::NewGuid().ToString('N'))
$script:OutputPath = $outCap
$script:SmokeDcdiagMode = 'GridFail'
$resultCap = Invoke-Main
$script:SmokeDcdiagMode = 'Pass'
$capFindings = @(Import-Csv $resultCap.FindingsFile)
$capCounts = @(Import-Csv (Join-Path $resultCap.CsvPath 'Object Counts.csv') | Where-Object { $_.Scope -eq 'contoso.com' })
Check ($capCounts.Count -gt 0 -and @($capCounts | Where-Object { $_.Evidence -notmatch '\(Inventory\.MaxObjects, set in the -ConfigOverridePath file\)' -or $_.Evidence -match 'a tool default' }).Count -eq 0) ("C4b4 override: every Object Counts row names the cap as set in the -ConfigOverridePath file ({0} rows)" -f $capCounts.Count)
$capRows = @($capFindings | Where-Object { $_.Detail -match 'reached its cap' })
Check ($capRows.Count -gt 0) ("C4b4 override: at least one row reached the file's cap of 1 ({0} rows)" -f $capRows.Count)
Check (@($capRows | Where-Object { $_.Detail -match 'MaxObjects, a tool default' }).Count -eq 0) 'C4b4 override: no capped row calls the file''s cap a tool default'
Check (@($capRows | Where-Object { $_.Detail -notmatch '(Inventory|Stale)\.MaxObjects, set in the -ConfigOverridePath file' -and $_.Section -notin @('Trusts & Two-Way Health', 'Site Links', 'Replication Connections', 'Identity Inventory') }).Count -eq 0) 'C4b4 override: every capped C15 and Stale row names its table and the file'
$capGrid = @($capFindings | Where-Object { $_.Section -eq 'DC Diagnostics' -and $_.Item -eq 'dc1.contoso.com' })
$capMachine = [string]@($script:RecommendationMap | Where-Object { $_.ContainsKey('Section') -and [string]$_.Match -eq '(?i)^DC Diagnostics :: [^\s:]+ :: MachineAccount: (?!NOT ASSESSED)' })[0].Text
Check ($capGrid.Count -eq 1 -and $capGrid[0].Status -eq 'Fail' -and $capGrid[0].Detail -match '^MachineAccount: ' -and $capGrid[0].Recommendation -eq $capMachine -and $capMachine -ne '') 'C11h: the grid row failing MachineAccount with "delegation" in its quoted line gets the MachineAccount advice'
Check ($capGrid.Count -eq 1 -and $capGrid[0].Recommendation -notmatch 'Remove unconstrained delegation') 'C11h: the quoted dcdiag line no longer chooses the unscoped delegation advice'
Remove-Item -Recurse -Force $outCap -ErrorAction SilentlyContinue
$script:ConfigOverridePath = $overrideFile

# A file that cannot be used: the run must stop, name the file, and collect nothing.
$badFiles = @(
    @{ Name = 'an unknown section'; Text = '{ "DcDisks": { "WarnBelowPercent": 70 } }'; Expect = "unknown section 'DcDisks'" }
    @{ Name = 'a malformed value'; Text = '{ "DcDisk": { "WarnBelowPercent": "high" } }'; Expect = 'WarnBelowPercent' }
    @{ Name = 'JSON null'; Text = 'null'; Expect = 'JSON null' }
    @{ Name = 'a file that is not JSON'; Text = 'not json {'; Expect = 'not valid JSON' }
    # PowerShell 7 unwraps a one-element array; the run must stop on it on both editions.
    @{ Name = 'an array holding one valid object'; Text = '[ { "DcDisk": { "WarnBelowPercent": 70 } } ]'; Expect = 'not a JSON array' }
    # Both editions keep the last of two equal keys without an error; the run must stop instead.
    @{ Name = 'a key written twice'; Text = '{ "DcDisk": { "WarnBelowPercent": 70, "WarnBelowPercent": 30 } }'; Expect = "'DcDisk.WarnBelowPercent' more than once" }
    # C3: a hardening expectation that would let a weak value read as a pass.
    @{ Name = 'a DcHardening status that is not Warning or Fail'; Text = '{ "DcHardening": { "Settings": { "SmbClientSigning": { "OtherStatus": "Pass" } } } }'; Expect = 'It must be Warning or Fail' }
    # C3: a port for DcHardening. The section's CIM session does not use it, so it is refused.
    @{ Name = 'a DcHardening port'; Text = '{ "DcHardening": { "WsmanPort": 5986 } }'; Expect = 'The ports of this section cannot be set from a file' }
    # C4: a file that tries to change which attributes the Laps section reads.
    @{ Name = 'a Laps attribute list'; Text = '{ "Laps": { "ComputerProperties": [ "ms-Mcs-AdmPwd" ] } }'; Expect = "unknown key 'ComputerProperties'" }
    # C4: a Warning threshold that nothing could exceed, which would switch the check off.
    @{ Name = 'a Laps Warning threshold of 100'; Text = '{ "Laps": { "WarnAbovePercent": 100 } }'; Expect = 'no domain would ever be reported' }
    # C5: a file that tries to move the handshake to another port.
    @{ Name = 'a DcCertificates port'; Text = '{ "DcCertificates": { "LdapsPort": 3269 } }'; Expect = "unknown key 'LdapsPort'" }
    # C5: a Fail window wider than the Warning window.
    @{ Name = 'a DcCertificates Fail window above the Warning window'; Text = '{ "DcCertificates": { "FailWithinDays": 60 } }'; Expect = 'is above WarnWithinDays' }
    # C6: a file that tries to grade against a ceiling the tool did not read.
    @{ Name = 'a RidPool ceiling list'; Text = '{ "RidPool": { "KnownCeilings": [] } }'; Expect = "unknown key 'KnownCeilings'" }
    # C6: a Warning point above the built-in Fail point, which would hide the Warning.
    @{ Name = 'a RidPool Warning point above the Fail point'; Text = '{ "RidPool": { "WarnAtPercentUsed": 95 } }'; Expect = 'must be above WarnAtPercentUsed' }
    # C11: a file that tries to add a dcdiag test, which could be one that changes state.
    @{ Name = 'a DcDiag test list'; Text = '{ "DcDiag": { "PerDcTests": [ { "Test": "CutoffServers" } ] } }'; Expect = "unknown key 'PerDcTests'" }
    # C11: a dcdiag time-out outside the range -ExternalToolTimeoutSeconds allows.
    @{ Name = 'a DcDiag time-out of 0'; Text = '{ "DcDiag": { "TestTimeoutSeconds": 0 } }'; Expect = 'whole number from 5 to 600' }
    # C12: a file that tries to change how the DNS summary table is graded (n/a or FAIL read as Pass).
    @{ Name = 'a DcDiag DNS summary table'; Text = '{ "DcDiag": { "DnsSummary": { "Cells": [ { "Token": "FAIL", "Status": "Pass" } ] } } }'; Expect = "unknown key 'DnsSummary'" }
)
$script:Sections = @('All')
foreach ($bad in $badFiles) {
    $bad.Text | Out-File -LiteralPath $overrideFile -Encoding UTF8
    $outB = Join-Path ([IO.Path]::GetTempPath()) ("adfa_smoke_override_" + [guid]::NewGuid().ToString('N'))
    $script:OutputPath = $outB
    $thrown = ''
    try { Invoke-Main | Out-Null } catch { $thrown = [string]$_.Exception.Message }
    Check ($thrown -match [regex]::Escape($bad.Expect)) ("Override: {0} stops the run ({1})" -f $bad.Name, $bad.Expect)
    Check ($thrown -match [regex]::Escape([IO.Path]::GetFileName($overrideFile))) ("Override: the refusal of {0} names the file" -f $bad.Name)
    # PORT-PLAN H21: the refused run still closes its log, with exit code 2 and totals not counted.
    $h21Logs = @(Get-ChildItem -Path $outB -Recurse -Filter 'ADForestAssessment-*.log' -ErrorAction SilentlyContinue | Where-Object { $_.Name -notlike '*-transcript.log' })
    $h21Text = ''
    if ($h21Logs.Count -eq 1) { $h21Text = [IO.File]::ReadAllText($h21Logs[0].FullName) }
    Check ($h21Logs.Count -eq 1 -and $h21Text -match 'Exit code: 2 \(' -and $h21Text -match 'Totals: not counted' -and $h21Text -match 'Fatal error in Invoke-Main: ') ("Override: with {0}, the log closes with exit code 2 and the fatal error ({1} log)" -f $bad.Name, $h21Logs.Count)
    # Review fix of H21: line by line, not over the whole text - the closing lines are the last
    # lines, and every line after the header is one whole record.
    if ($h21Logs.Count -eq 1) {
        $h21Lines = @(Get-Content -LiteralPath $h21Logs[0].FullName)
        Check ($h21Lines.Count -ge 4 -and $h21Lines[$h21Lines.Count - 2] -match '\[RESULT\] Exit code: 2 \(.*\)$' -and $h21Lines[$h21Lines.Count - 3] -match '\[RESULT\] Totals: not counted') ("Override: with {0}, the last lines are the closing lines" -f $bad.Name)
        Check (@($h21Lines | Select-Object -Skip 1 | Where-Object { $_ -notmatch '^\[\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\] \[(INFO|STAGE|RESULT|WARN|ERROR) *\] ' }).Count -eq 0) ("Override: with {0}, every log line is one whole record" -f $bad.Name)
    }
    $written = @(Get-ChildItem -Path $outB -Recurse -Filter *.csv -ErrorAction SilentlyContinue)
    Check ($written.Count -eq 0) ("Override: with {0}, nothing was collected before the run stopped ({1} CSV files)" -f $bad.Name, $written.Count)
    Remove-Item -Recurse -Force $outB -ErrorAction SilentlyContinue
}
Check (@($badFiles).Count -eq 17) 'Override: non-vacuity - seventeen declared unusable files were tried'
# Review fix of H21 (finding 1): a file that is not JSON at all. On Windows PowerShell 5.1 the
# ConvertFrom-Json message ends in a line break, which used to split the fatal-error record and the
# Exit code line in two. Every line must stay one record and the log must end with its closing lines.
'{ not json' | Out-File -LiteralPath $overrideFile -Encoding UTF8
$outJ = Join-Path ([IO.Path]::GetTempPath()) ("adfa_smoke_override_notjson_" + [guid]::NewGuid().ToString('N'))
$script:OutputPath = $outJ
$thrownJ = ''
try { Invoke-Main | Out-Null } catch { $thrownJ = [string]$_.Exception.Message }
Check ($thrownJ -match 'Config override file is not valid JSON') 'Override: a file that is not JSON stops the run'
$jLogs = @(Get-ChildItem -Path $outJ -Recurse -Filter 'ADForestAssessment-*.log' -ErrorAction SilentlyContinue | Where-Object { $_.Name -notlike '*-transcript.log' })
Check ($jLogs.Count -eq 1) ("Override: the run refused for a file that is not JSON has one log ({0})" -f $jLogs.Count)
if ($jLogs.Count -eq 1) {
    $jLines = @(Get-Content -LiteralPath $jLogs[0].FullName)
    Check (@($jLines | Select-Object -Skip 1 | Where-Object { $_ -notmatch '^\[\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\] \[(INFO|STAGE|RESULT|WARN|ERROR) *\] ' }).Count -eq 0) 'Override: not JSON - every log line is one whole record (no message split over two lines)'
    Check (@($jLines | Where-Object { $_ -match 'Fatal error in Invoke-Main: .*not valid JSON.* \| Type: ' }).Count -eq 1) 'Override: not JSON - one fatal-error record, message and type on the same line'
    Check ($jLines.Count -ge 4 -and $jLines[$jLines.Count - 2] -match '\[RESULT\] Exit code: 2 \(could not run or was stopped: .*not valid JSON.*\)$') 'Override: not JSON - the next-to-last line is the whole Exit code line'
}
Remove-Item -Recurse -Force $outJ -ErrorAction SilentlyContinue
Remove-Item -LiteralPath $overrideFile -Force -ErrorAction SilentlyContinue
# The parameter carries [ValidateNotNullOrEmpty()], and the attribute stays on the variable, so
# it cannot simply be set back to empty: the variable is removed and re-created without it.
Remove-Variable -Name ConfigOverridePath -Scope Script
$script:ConfigOverridePath = ''
$script:Sections = @('All')

# C12: with -IncludeDcdiagActiveTests the DNS test's summary table is graded per test group, from the
# one DNS invocation the grid makes, for the stub DC and for its domain.
Write-Host "== Running Invoke-Main with -IncludeDcdiagActiveTests (C12: DNS summary per test group) ==" -ForegroundColor Cyan
$outDns = Join-Path ([IO.Path]::GetTempPath()) ("adfa_smoke_dns_" + [guid]::NewGuid().ToString('N'))
$script:OutputPath = $outDns
$script:Sections = @('DomainControllers', 'DcDiagnostics')
$script:IncludeDcdiagActiveTests = $true
$script:SmokeDnsCells = 'PASS PASS PASS FAIL PASS PASS n/a'
$script:SmokeDcdiagCalls = @()
$resultDns = Invoke-Main
$script:SmokeDnsCells = 'PASS PASS PASS PASS PASS PASS n/a'
$script:IncludeDcdiagActiveTests = $false
$script:Sections = @('All')
$ddDns = @(@(Import-Csv $resultDns.FindingsFile) | Where-Object { $_.Section -eq 'DC Diagnostics' })
$ddDnsCalls = @($script:SmokeDcdiagCalls | Where-Object { $_.Arguments -match '/test:DNS' })
Check (@($ddDnsCalls).Count -eq 1 -and $ddDnsCalls[0].Arguments -eq '/test:DNS /DnsAll /s:dc1.contoso.com') ("C12: the DNS test is invoked once, for the stub DC, with the C11 arguments only ({0} calls)" -f @($ddDnsCalls).Count)
$ddDnsDc = @($ddDns | Where-Object { $_.Item -match '^dcdiag DNS (Auth|Basc|Forw|Del|Dyn|RReg|Ext): dc1\.contoso\.com$' })
Check (@($ddDnsDc).Count -eq 7 -and @($ddDnsDc | Where-Object { $_.Scope -ne 'contoso.com' }).Count -eq 0) ("C12: the stub DC has one row per DNS test group, scoped to its domain (declared population: seven; got {0})" -f @($ddDnsDc).Count)
Check (@($ddDnsDc | Where-Object { $_.Item -eq 'dcdiag DNS Del: dc1.contoso.com' -and $_.Status -eq 'Fail' -and $_.Recommendation -match 'proper delegations' }).Count -eq 1) 'C12: FAIL under Del fails the Del row, with the Delegations advice'
Check (@($ddDnsDc | Where-Object { $_.Item -eq 'dcdiag DNS Ext: dc1.contoso.com' -and $_.Status -eq 'Info' -and $_.Detail -match 'DnsResolveExtName' }).Count -eq 1) 'C12: n/a under Ext is Info, not requested by /DnsAll'
Check (@($ddDnsDc | Where-Object { $_.Item -match ': dc1\.contoso\.com$' -and $_.Item -notmatch '^dcdiag DNS (Del|Ext):' -and $_.Status -ne 'Pass' }).Count -eq 0) 'C12: the five PASS groups pass'
$ddDnsDom = @($ddDns | Where-Object { $_.Item -match '^dcdiag DNS (Auth|Basc|Forw|Del|Dyn|RReg|Ext): domain contoso\.com$' })
Check (@($ddDnsDom).Count -eq 7 -and @($ddDnsDom | Where-Object { $_.Scope -ne 'contoso.com' }).Count -eq 0 -and @($ddDnsDom | Where-Object { $_.Item -eq 'dcdiag DNS Del: domain contoso.com' -and $_.Status -eq 'Fail' }).Count -eq 1) 'C12: the stub domain has one roll-up per test group, and Del fails there too (declared population: seven)'
Check (@($ddDns | Where-Object { $_.Item -like 'dcdiag DNS not run: *' }).Count -eq 0) 'C12: with the opt-in no "not run" row is written'
Remove-Item -Recurse -Force $outDns -ErrorAction SilentlyContinue

# C13: the DNS sections with the DnsServer module and Resolve-DnsName present (stubs above), and the
# opt-in record export named. The stub zone allows nonsecure updates (Fail), the _msdcs zone is Secure
# (Pass), both age and the server scavenges (Pass); dc1 is named by both locator records on both
# instruments (Pass) and its A record is its adapter address (Pass); the _ldap record also names a removed
# DC and the _msdcs zone holds a CNAME of a DSA that no longer exists (two stale records).
Write-Host "== Running Invoke-Main with the DnsServer module and Resolve-DnsName (C13: DNS sections) ==" -ForegroundColor Cyan
$outC13 = Join-Path ([IO.Path]::GetTempPath()) ("adfa_smoke_c13_" + [guid]::NewGuid().ToString('N'))
$script:OutputPath = $outC13
$script:Sections = @('DomainControllers', 'Dns', 'DnsAdConsistency', 'DnsRecordExport')
$script:SmokeDnsModule = $true
$script:SmokeDnsResolver = $true
$script:SmokeDnsDsa = $true
$script:SmokeDnsCalls = @()
$resultC13 = Invoke-Main
$script:SmokeDnsModule = $false
$script:SmokeDnsResolver = $false
$script:SmokeDnsDsa = $false
$script:Sections = @('All')
$fC13 = @(Import-Csv $resultC13.FindingsFile)
$hC13 = @($fC13 | Where-Object { $_.Section -eq 'DNS Health' })
Check (@($hC13 | Where-Object { $_.Item -eq 'DNS server: dc1.contoso.com' -and $_.Status -eq 'Info' }).Count -eq 1) 'C13: the stub DNS server is read'
$dynC13 = @($hC13 | Where-Object { $_.Item -eq 'Zone dynamic update: contoso.com' })
Check (@($dynC13).Count -eq 1 -and $dynC13[0].Status -eq 'Fail' -and $dynC13[0].Scope -eq 'contoso.com' -and $dynC13[0].Recommendation -match 'Secure only') 'C13: nonsecure dynamic update on the AD-integrated zone fails, with the Secure only advice'
Check (@($hC13 | Where-Object { $_.Item -eq 'Zone dynamic update: _msdcs.contoso.com' -and $_.Status -eq 'Pass' }).Count -eq 1) 'C13: the Secure _msdcs zone passes'
Check (@($hC13 | Where-Object { $_.Item -like 'Zone scavenging: *' -and $_.Status -eq 'Pass' }).Count -eq 2) 'C13: both primary zones age and the server scavenges (declared population: two zones)'
Check (@($hC13 | Where-Object { $_.Item -match '^Zone (dynamic update|scavenging): (fabrikam\.com|0\.in-addr\.arpa)$' }).Count -eq 0) 'C13: the forwarder zone and the auto-created zone are not graded'
Check (@($hC13 | Where-Object { $_.Item -like 'Zone configuration: * on dc1.contoso.com' }).Count -eq 3) 'C13: one zone configuration row per zone not auto-created (declared population: three)'
$healthCsvC13 = @(Import-Csv (Join-Path $resultC13.CsvPath 'DNS Health.csv'))
Check (@($healthCsvC13 | Where-Object { $_.Item -eq 'Zone configuration: _msdcs.contoso.com on dc1.contoso.com' -and $_.ReplicationScope -eq 'Forest' -and $_.ZoneType -eq 'Primary' -and $_.DynamicUpdate -eq 'Secure' }).Count -eq 1) 'C13: the zone configuration row carries the replication scope, type and dynamic update the server reported (INV-013)'
Check (@($hC13 | Where-Object { $_.Item -eq 'Zone scavenging: _msdcs.contoso.com' }).Count -eq 1) 'C13: the forest-wide _msdcs zone is graded once (declared population: one forest-wide zone)'
Check (@($script:SmokeDnsCalls | Where-Object { $_ -match '^Get-DnsServerResourceRecord dc1\.contoso\.com \S+  Ns$' }).Count -ge 1) 'C13: the server read checks the zone''s delegations (its NS records) before it reads a name'
$dC13 = @($fC13 | Where-Object { $_.Section -eq 'DNS vs AD Consistency' })
Check (@($dC13 | Where-Object { $_.Item -eq 'DC locator records: dc1.contoso.com' -and $_.Status -eq 'Pass' }).Count -eq 1) 'C13: dc1 is named by both locator records on both instruments'
Check (@($dC13 | Where-Object { $_.Item -eq 'DC A record: dc1.contoso.com' -and $_.Status -eq 'Pass' }).Count -eq 1) 'C13: dc1''s A record is the address its adapter holds'
$staleC13 = @($dC13 | Where-Object { $_.Item -like 'Stale DC record: *' })
Check (@($staleC13).Count -eq 2 -and @($staleC13 | Where-Object { $_.Item -eq 'Stale DC record: old-dc.contoso.com' }).Count -eq 1 -and @($staleC13 | Where-Object { $_.Item -eq ("Stale DC record: {0}._msdcs.contoso.com" -f $script:SmokeOrphanGuid) }).Count -eq 1) ("C13: the removed DC's SRV target and the orphan DSA CNAME are listed, dc1's CNAME is not (declared population: two; got {0})" -f @($staleC13).Count)
Check (@($staleC13 | Where-Object { $_.Status -ne 'Warning' -or $_.Recommendation -notmatch 'stale domain controllers' }).Count -eq 0) 'C13: each stale record is a Warning with the stale DC advice'
Check (@($fC13 | Where-Object { $_.Section -eq 'DC DNS Client' -and $_.Item -eq 'DNS client: dc1.contoso.com' -and $_.Status -eq 'Info' }).Count -eq 1) 'C13: the DC DNS client row is read in the DNS scenario too'
$xC13 = @($fC13 | Where-Object { $_.Section -eq 'DNS Record Export' })
Check (@($xC13 | Where-Object { $_.Item -eq 'Record export: _msdcs.contoso.com on dc1.contoso.com' -and $_.Detail -match '^Exported 6 of 6' -and $_.Detail -match 'cap reached: no' }).Count -eq 1) 'C13: the opt-in export writes the _msdcs zone in full and says the cap was not reached'
Check (@(Get-ChildItem -LiteralPath $resultC13.CsvPath -Filter 'DnsRecords_*.csv').Count -eq 2) 'C13: one CSV per zone that holds a record (declared population: the two zones of the stub server with records; the auto-created and forwarder zones hold none)'
Check (@($xC13 | Where-Object { $_.Item -eq 'Record export: total' -and $_.Detail -match '^8 record\(s\) exported from 4 zone\(s\) on 1 DNS server' }).Count -eq 1) 'C13: the export total counts every record written'
Check (@($script:SmokeDnsCalls | Where-Object { $_ -match '^(Set|Add|Remove|Start|Clear|Register)-' }).Count -eq 0) 'C13: no DNS write was attempted'
Remove-Item -Recurse -Force $outC13 -ErrorAction SilentlyContinue

# ---- PORT-PLAN C11f + C2i + C15d(2) + C16d (v1.42.0) ---------------------------------------------------------
# Each pass below runs Invoke-Main on the stubs with the sections that row touches; every name is fictional.
$lfSavedAllDomains = $script:AllDomains
$lfSavedSections = @($script:Sections)
$lfSavedSite = ${function:Get-ADReplicationSite}

# C11f (REPL-010): with -IncludeDcdiagActiveTests, every site of the forest gets one Intersite row. The forest holds
# two sites; the stub DC's NTDS Settings object (C13's DSA stub) is under Default-First-Site-Name, none under Branch-Empty.
Write-Host "== Running Invoke-Main with -IncludeDcdiagActiveTests and a site with no DC (C11f) ==" -ForegroundColor Cyan
function Get-ADReplicationSite { param([Parameter(ValueFromRemainingArguments)]$a)
    [pscustomobject]@{ Name = 'Default-First-Site-Name'; Description = ''; WhenCreated = $now; WhenChanged = $now }
    [pscustomobject]@{ Name = 'Branch-Empty'; Description = ''; WhenCreated = $now; WhenChanged = $now } }
$outLf = Join-Path ([IO.Path]::GetTempPath()) ("adfa_smoke_c11f_" + [guid]::NewGuid().ToString('N'))
$script:OutputPath = $outLf
$script:AllDomains = $false
$script:Sections = @('DomainControllers', 'DcDiagnostics')
$script:IncludeDcdiagActiveTests = $true
$script:SmokeDnsDsa = $true
$script:SmokeDcdiagCalls = @()
$resultLf = Invoke-Main
$script:SmokeDnsDsa = $false
$script:IncludeDcdiagActiveTests = $false
${function:Get-ADReplicationSite} = $lfSavedSite
$ddLf = @(@(Import-Csv $resultLf.FindingsFile) | Where-Object { $_.Section -eq 'DC Diagnostics' })
$lfSiteRows = @($ddLf | Where-Object { $_.Item -like 'dcdiag Intersite: *' })
Check (@($lfSiteRows).Count -eq 2) ("C11f: one Intersite row per site of the forest (declared population: two sites; got {0}: {1})" -f @($lfSiteRows).Count, (@($lfSiteRows | ForEach-Object { $_.Item }) -join ', '))
Check (@($lfSiteRows | Where-Object { $_.Item -eq 'dcdiag Intersite: Default-First-Site-Name' -and $_.Status -eq 'Pass' }).Count -eq 1) 'C11f: the site of the stub DC is tested and passes'
Check (@($lfSiteRows | Where-Object { $_.Item -eq 'dcdiag Intersite: no DC in site Branch-Empty' -and $_.Status -eq 'Info' -and $_.Detail -match '^Not applicable: ' }).Count -eq 1) 'C11f: the site with no DC is not applicable (Info), never Pass'
Check (@($script:SmokeDcdiagCalls | Where-Object { $_.Arguments -match '^/test:Intersite ' }).Count -eq 1 -and @($script:SmokeDcdiagCalls | Where-Object { $_.Arguments -eq '/test:Intersite /s:dc1.contoso.com /a' }).Count -eq 1) 'C11f: Intersite runs once, against the stub DC, with /a'
Remove-Item -Recurse -Force $outLf -ErrorAction SilentlyContinue

# C11f: the circuit breaker. Replications and Advertising time out on the stub DC; after the second, no further
# dcdiag test is started on it, the rest read Not Assessed with the cause in NotRun, and the DC is not asked the
# once-per-domain or forest tests.
Write-Host "== Running Invoke-Main with two consecutive dcdiag time-outs (C11f circuit breaker) ==" -ForegroundColor Cyan
$outBk = Join-Path ([IO.Path]::GetTempPath()) ("adfa_smoke_breaker_" + [guid]::NewGuid().ToString('N'))
$script:OutputPath = $outBk
$script:Sections = @('DomainControllers', 'DcDiagnostics')
$script:SmokeDcdiagMode = 'Timeout'
$script:SmokeDcdiagCalls = @()
$resultBk = Invoke-Main
$script:SmokeDcdiagMode = 'Pass'
$ddBk = @(@(Import-Csv $resultBk.FindingsFile) | Where-Object { $_.Section -eq 'DC Diagnostics' })
$bkCalls = @($script:SmokeDcdiagCalls | ForEach-Object { ([regex]::Match($_.Arguments, '/test:(\S+)')).Groups[1].Value })
Check (($bkCalls -join ',') -eq 'Connectivity,Replications,Advertising') ("C11f: after two consecutive time-outs no further dcdiag test is started on the DC, and it is not asked Topology or the forest tests ({0})" -f ($bkCalls -join ','))
$bkGrid = @(Import-Csv (Join-Path $resultBk.CsvPath 'DC Diagnostics.csv') | Where-Object { $_.DomainController -eq 'dc1.contoso.com' })
Check ($bkGrid.Count -eq 1 -and $bkGrid[0].NotRun -match 'circuit breaker: two consecutive time-outs' -and $bkGrid[0].DCDIAG_Services -eq 'Not Assessed' -and $bkGrid[0].Status -eq 'Warning' -and $bkGrid[0].Failures -notmatch 'circuit breaker') 'C11f: the grid row names the breaker in NotRun, the stopped cells read Not Assessed, the row is a Warning, never Pass'
Check (@($ddBk | Where-Object { $_.Item -eq 'dcdiag Topology: contoso.com' -and $_.Status -eq 'Not Assessed' }).Count -eq 1) 'C11f: the domain''s Topology is Not Assessed when its only DC tripped the breaker'
Remove-Item -Recurse -Force $outBk -ErrorAction SilentlyContinue

# C16d(a): the DnsDepth SRV rule with Resolve-DnsName present: an SRV answer that also carries an A record counts its
# SRV records only, and a name answered with the zone's SOA alone fails as "no SRV record".
Write-Host "== Running Invoke-Main with Resolve-DnsName and mixed answers (C16d: DnsDepth SRV rule) ==" -ForegroundColor Cyan
$outDd = Join-Path ([IO.Path]::GetTempPath()) ("adfa_smoke_dnsdepth_" + [guid]::NewGuid().ToString('N'))
$script:OutputPath = $outDd
$script:Sections = @('DnsDepth')
$script:SmokeDnsResolver = $true
$script:SmokeDnsDepthMixed = $true
$resultDd = Invoke-Main
$script:SmokeDnsDepthMixed = $false
$script:SmokeDnsResolver = $false
$depthDd = @(@(Import-Csv $resultDd.FindingsFile) | Where-Object { $_.Section -eq 'DNS Depth' })
Check (@($depthDd | Where-Object { $_.Item -eq 'SRV _ldap._tcp.dc._msdcs.contoso.com' -and $_.Status -eq 'Pass' -and $_.Detail -match '^2 SRV record\(s\)' -and $_.Scope -eq 'contoso.com' }).Count -eq 1) 'C16d(a): the SRV answer with an A record beside it counts its two SRV records only'
Check (@($depthDd | Where-Object { $_.Item -eq 'SRV _kerberos._tcp.contoso.com' -and $_.Status -eq 'Fail' -and $_.Detail -match 'type SOA only' }).Count -eq 1) 'C16d(a): a name answered with the zone''s SOA alone is a Fail naming the type, never a Pass'
Remove-Item -Recurse -Force $outDd -ErrorAction SilentlyContinue

# C16d(b): one FRS-only domain among three: its DC has an NTFRS subscriber and no DFSR SYSVOL subscription, so the
# subscription verdict of that domain is given the -NotDfsrCount of the engine read, end to end.
Write-Host "== Running Invoke-Main with an FRS-only domain (C16d: -NotDfsrCount wiring) ==" -ForegroundColor Cyan
$outFrs = Join-Path ([IO.Path]::GetTempPath()) ("adfa_smoke_frs_" + [guid]::NewGuid().ToString('N'))
$script:OutputPath = $outFrs
$script:AllDomains = $true
$script:Sections = @('Sysvol')
$script:SmokeFrsOnlyDomain = 'south.contoso.com'
$resultFrs = Invoke-Main
$script:SmokeFrsOnlyDomain = ''
$svFrs = @(@(Import-Csv $resultFrs.FindingsFile) | Where-Object { $_.Section -eq 'SYSVOL / DFSR' })
Check (@($svFrs | Where-Object { $_.Scope -eq 'south.contoso.com' -and $_.Item -eq 'DFSR SYSVOL subscription state' -and $_.Status -eq 'Not Assessed' -and $_.Detail -match '^1 DC\(s\) of this domain have no DFSR SYSVOL subscription object' }).Count -eq 1) 'C16d(b): the FRS-only domain''s subscription row counts its DC with no DFSR subscription (-NotDfsrCount), Not Assessed'
Check (@($svFrs | Where-Object { $_.Scope -eq 'south.contoso.com' -and $_.Item -like 'DFSR SYSVOL replication*' -and $_.Status -eq 'Pass' }).Count -eq 0) 'C16d(b): the FRS-only domain has no DFSR Pass'
foreach ($d in @('contoso.com', 'north.contoso.com')) {
    Check (@($svFrs | Where-Object { $_.Scope -eq $d -and $_.Item -eq 'DFSR SYSVOL replication enabled' -and $_.Status -eq 'Pass' }).Count -eq 1) ("C16d(b): '{0}', DFSR, still passes beside the FRS-only domain" -f $d)
}
Remove-Item -Recurse -Force $outFrs -ErrorAction SilentlyContinue

# C15d(2): a single-domain run in the three-domain forest. Without -IncludeUnscopedGpoLinks no other domain is read
# and the summary names the switch; with it, the gPLink of each unscoped domain is read once, from that domain.
Write-Host "== Running Invoke-Main on one domain of three, with and without -IncludeUnscopedGpoLinks (C15d) ==" -ForegroundColor Cyan
foreach ($lfSwitch in @($false, $true)) {
    $outGp = Join-Path ([IO.Path]::GetTempPath()) ("adfa_smoke_gplink_" + [guid]::NewGuid().ToString('N'))
    $script:OutputPath = $outGp
    $script:AllDomains = $false
    $script:Sections = @('Gpo')
    $script:IncludeUnscopedGpoLinks = $lfSwitch
    $script:SmokeInventoryCalls = @()
    $resultGp = Invoke-Main
    $script:IncludeUnscopedGpoLinks = $false
    $gpSom = @($script:SmokeInventoryCalls | Where-Object { $_ -like '(gPLink=*)@*' } | ForEach-Object { ($_ -split '@')[-1] } | Sort-Object)
    $gpSum = @(Import-Csv (Join-Path $resultGp.CsvPath 'GPO Directory Inventory.csv') | Where-Object { $_.Item -eq 'GPO directory inventory: contoso.com' })
    if ($lfSwitch) {
        Check (($gpSom -join ',') -eq 'contoso.com,north.contoso.com,south.contoso.com') ("C15d(2): with the switch, the gPLink of each unscoped domain is read once, from that domain (declared population: the three forest domains; {0})" -f ($gpSom -join ','))
        Check ($gpSum.Count -eq 1 -and $gpSum[0].OtherDomainSoms -eq 'All read' -and $gpSum[0].Status -eq 'Info') 'C15d(2): with the switch, every forest domain''s SOMs are read and the summary says so'
        Check ((Get-Content $resultGp.LogFile -Raw) -match 'IncludeUnscopedGpoLinks=True') 'C15d(2): the log records the switch'
    }
    else {
        Check (($gpSom -join ',') -eq 'contoso.com') ("C15d(2): without the switch, only the scoped domain's gPLink is read ({0})" -f ($gpSom -join ','))
        Check ($gpSum.Count -eq 1 -and $gpSum[0].OtherDomainSoms -eq 'Not all read' -and $gpSum[0].Detail -match 'IncludeUnscopedGpoLinks' -and $gpSum[0].Detail -match 'AllDomains' -and $gpSum[0].Status -ne 'Pass') 'C15d(2): without the switch, the summary names -IncludeUnscopedGpoLinks and -AllDomains, never Pass'
    }
    Remove-Item -Recurse -Force $outGp -ErrorAction SilentlyContinue
}
$script:AllDomains = $lfSavedAllDomains
$script:Sections = @($lfSavedSections)
# ---- Scenario 3: collection failures must be reported, never swallowed -------
# Regression guard for the empty-catch fixes. The failure mode being pinned is the one this
# repo already shipped once (v1.6.0): a collector throws, its rows quietly do not appear, and
# the report looks complete. Here the DC enumeration and the per-domain lookups all fail, and
# the run must come back saying so rather than looking clean.
Write-Host ""
Write-Host "== Running Invoke-Main with failing collectors ==" -ForegroundColor Cyan

# Get-ADDomain is deliberately NOT broken here: Invoke-Main calls it unguarded while resolving
# which domains to scope, long before any section runs, so breaking it aborts the run instead of
# exercising a catch. That unguarded path is recorded as PORT-PLAN H9 rather than widened into
# this change. The two collectors below are stubbed at the seam this change actually touches.
function Get-ADDomainController { param([Parameter(ValueFromRemainingArguments)]$a) throw 'STUB: ADWS unreachable on the target DC' }
function Get-ADFineGrainedPasswordPolicy { param([Parameter(ValueFromRemainingArguments)]$a) throw 'STUB: FGPP query denied' }
function Get-AdfaDomainSummary { param([Parameter(ValueFromRemainingArguments)]$a) throw 'STUB: domain summary unavailable' }
function Get-AdfaFsmoRole { param([Parameter(ValueFromRemainingArguments)]$a) throw 'STUB: FSMO lookup denied' }
# C16 (GAP-P29): the forest summary fails too, and must become a Not Assessed row of its section.
function Get-AdfaForestSummary { param([Parameter(ValueFromRemainingArguments)]$a) throw 'STUB: forest summary unavailable' }
# C4: the Laps section does not use Get-ADDomainController, so breaking that leaves it working.
# Its own two reads are made to fail instead: the schema query and the computer query throw.
$script:SmokeLapsFail = $true
# C6: the RidPool section does not use Get-ADDomainController for its domain rows, so every read of
# CN=RID Manager$ is made to fail too.
$script:SmokeRidFail = $true
# C7: the SID history rows read the directory without Get-ADDomainController either, so their
# principal query is refused too (an access-denied exception).
$script:SmokeSidHistoryFail = $true
# C8: the GPO version check reads the directory without Get-ADDomainController too, so its container
# query is refused (an access-denied exception).
$script:SmokeGpoFail = $true
$script:SmokeGptIniCalls = @()
# C9: the descriptor reads do not use Get-ADDomainController either, so every one is refused (an
# access-denied exception).
$script:SmokeAclFail = $true
# C10: every privileged-group, adminCount, delegation and configuration read, and the two roast reads,
# are refused (an access-denied exception); Get-ADDomain still answers.
$script:SmokePrivFail = $true
# C14: the stale reads do not use Get-ADDomainController either, so they are refused (access denied).
$script:SmokeStaleFail = $true
# C15: the inventory directory reads and the event reads are refused (access denied); the disabled reads
# are refused with the stale reads above.
$script:SmokeInventoryFail = $true
$script:SmokeEventsFail = $true
$script:SmokeEventCalls = @()
$script:SmokePopulationCalls = @()
$script:SmokeFutureCalls = @()
# C4b: the export, trust, site link and connection reads are refused (access denied).
$script:SmokeC4bFail = $true
$script:SmokeExportCalls = @()
$script:SmokeC4bCalls = @()
$script:SmokeReachCalls = @()
$script:SmokeNetlogonCalls = @()
# C3f: the SMB server configuration read is refused too (access denied), and its calls recorded.
$script:SmokeSmbMode = 'Denied'
$script:SmokeSmbCalls = @()

$script:SmokeDcdiagCalls = @()
$out3 =Join-Path ([IO.Path]::GetTempPath()) ("adfa_smoke_fail_" + [guid]::NewGuid().ToString('N'))
$script:OutputPath = $out3
$script:AllDomains = $false
# PORT-PLAN C2e review: the SYSVOL backlog too, which must not measure DCs it cannot attribute to the domain.
$script:IncludeSysvolBacklog = $true
$script:SmokeRemoteCalls = @()
$script:SmokeDirectToolCalls = @()
$result3 = Invoke-Main
$script:IncludeSysvolBacklog = $false
# H20a (review fix): with failing collectors, no WinRM script block runs anything but /sc_query and no
# console tool is started directly in this process.
Check (@($script:SmokeRemoteCalls | Where-Object { $_.Arguments -notmatch '^/sc_query:\S+$' }).Count -eq 0 -and @($script:SmokeDirectToolCalls).Count -eq 0) ("Failure mode H20a: no WinRM nltest start other than /sc_query, none direct ({0} remote calls)" -f @($script:SmokeRemoteCalls).Count)

Check ($null -ne $result3) 'Failure mode: Invoke-Main still returns a summary rather than dying'
# PORT-PLAN H21: with failing collectors the run still completes (exit code 1, never 0) and names the
# sections left wholly Not Assessed.
Write-Host ("    H21 failing-collector exit: {0} - {1}" -f $result3.ExitCode, $result3.ExitReason) -ForegroundColor DarkGray
Test-SmokeH21Run -Result $result3 -Root $out3 -Name 'failing collectors' -ExpectedCode 1 -ReasonPattern 'section\(s\) Not Assessed: '
Check (Test-Path $result3.FindingsFile) 'Failure mode: consolidated findings still written'
$findings3 = @(Import-Csv $result3.FindingsFile)
Check ($findings3.Count -gt 0) ("Failure mode: findings are not empty ({0} rows)" -f $findings3.Count)

# Nothing may be reported as healthy on the strength of a collector that threw.
$dcEnum = @($findings3 | Where-Object { $_.Item -match 'Domain controller enumeration' })
Check ($dcEnum.Count -ge 1) 'Failure mode: DC enumeration failure is a first-class finding'
if ($dcEnum.Count -ge 1) {
    Check ($dcEnum[0].Status -eq 'Not Assessed') ("Failure mode: DC enumeration reported Not Assessed (got '{0}')" -f $dcEnum[0].Status)
    Check ($dcEnum[0].Detail -match 'ADWS unreachable') 'Failure mode: the underlying cause is carried into the report'
    Check ($dcEnum[0].Detail -match 'UNASSESSED, not clean') 'Failure mode: the finding refuses to imply the per-DC checks are clean'
}
# PORT-PLAN C16: the triaged rows with every DC list refused - Not Assessed with a cause, never Pass.
Check (@($findings3 | Where-Object { $_.Section -eq 'Forest Summary' -and $_.Item -eq 'Forest summary' -and $_.Status -eq 'Not Assessed' -and $_.Detail -match 'STUB: forest summary unavailable' }).Count -eq 1) 'Failure mode C16 GAP-P29: a forest summary that could not be read is a Not Assessed row with its cause, not a missing section'
$sv3 = @($findings3 | Where-Object { $_.Section -eq 'SYSVOL / DFSR' -and $_.Item -like 'DFSR SYSVOL*' })
Check (@($sv3 | Where-Object { $_.Item -eq 'DFSR SYSVOL subscription state' -and $_.Status -eq 'Not Assessed' -and $_.Scope -eq 'contoso.com' }).Count -eq 1 -and @($sv3 | Where-Object { $_.Status -eq 'Pass' }).Count -eq 0) 'Failure mode C16 GAP-P1: no DC list, so no subscription read and no Pass row'
Check (@($findings3 | Where-Object { $_.Section -eq 'Redundancy & Availability' -and $_.Item -eq 'Domain controller redundancy' -and $_.Status -eq 'Not Assessed' -and $_.Detail -match 'ADWS unreachable' }).Count -eq 1) 'Failure mode C16 GAP-P18: the DC count is Not Assessed with the cause'
$site3 = @($findings3 | Where-Object { $_.Section -eq 'Site Health' })
Check (@($site3 | Where-Object { $_.Item -eq 'Empty sites' -and $_.Status -eq 'Not Assessed' }).Count -eq 1 -and @($site3 | Where-Object { $_.Item -eq 'Site/subnet topology' }).Count -eq 0) 'Failure mode C16 GAP-P6: with the DC inventory failed, empty sites are Not Assessed and the topology row does not pass'
Check (@($findings3 | Where-Object { $_.Section -eq 'Replication Health' -and $_.Status -eq 'Pass' }).Count -eq 0) 'Failure mode C16 review 5: nothing read, so no replication row passes'
# PORT-PLAN C2i(3): DcSecureChannel takes the shared DC list, whose enumeration failed for the stub domain: one
# "DC enumeration" row for it, Not Assessed with the cause, nothing else read and nothing passing.
$sc3 = @($findings3 | Where-Object { $_.Section -eq 'DC Secure Channel & Machine Passwords' })
Check (@($sc3).Count -eq 1 -and $sc3[0].Item -eq 'DC enumeration' -and $sc3[0].Status -eq 'Not Assessed' -and $sc3[0].Scope -eq 'contoso.com' -and $sc3[0].Detail -match 'ADWS unreachable') ("Failure mode C2i(3): DcSecureChannel reports the stub domain's DC list as not read, with the cause ({0} rows)" -f @($sc3).Count)
# PORT-PLAN C11f: no DC enumerated, so no dcdiag test ran and no DC tripped a breaker; nothing in DC Diagnostics passes.
$dd3 = @($findings3 | Where-Object { $_.Section -eq 'DC Diagnostics' })
Check (@($dd3 | Where-Object { $_.Status -eq 'Pass' }).Count -eq 0 -and @($dd3 | Where-Object { $_.Item -eq 'dcdiag grid' -and $_.Status -eq 'Not Assessed' }).Count -eq 1 -and @($dd3 | Where-Object { $_.Detail -match 'circuit breaker: ' }).Count -eq 0) 'Failure mode C11f: DC Diagnostics passes nothing with no DC, and names no breaker'
Check (@($findings3 | Where-Object { $_.Section -eq 'Exchange SE Compatibility' -and $_.Item -eq 'Domain controller operating systems' -and $_.Status -eq 'Not Assessed' -and $_.Detail -match 'DomainControllers' }).Count -eq 1) 'Failure mode C16 GAP-P20: no DC enumerated, so the DC gate is Not Assessed and names DomainControllers'

$dsRow = @($findings3 | Where-Object { $_.Item -match 'Domain summary' })
Check ($dsRow.Count -ge 1) 'Failure mode: a domain whose summary failed appears as a row, not a gap'
if ($dsRow.Count -ge 1) { Check ($dsRow[0].Status -eq 'Not Assessed') 'Failure mode: failed domain summary is Not Assessed' }

$fsmoRow = @($findings3 | Where-Object { $_.Item -match 'FSMO roles' })
Check ($fsmoRow.Count -ge 1) 'Failure mode: a domain whose FSMO lookup failed appears as a row'
if ($fsmoRow.Count -ge 1) { Check ($fsmoRow[0].Status -eq 'Not Assessed') 'Failure mode: failed FSMO lookup is Not Assessed' }

$fgpp = @($findings3 | Where-Object { $_.Item -match 'Fine-grained password policies' })
Check ($fgpp.Count -ge 1) 'Failure mode: a failed FGPP query is reported, not indistinguishable from "none exist"'
if ($fgpp.Count -ge 1) {
    Check ($fgpp[0].Status -eq 'Not Assessed') 'Failure mode: failed FGPP query is Not Assessed'
    Check ($fgpp[0].Detail -match "NOT the same as") 'Failure mode: FGPP row states that absence was not measured'
}

# C1: with DC enumeration failing there is no inventory and no DC list. Both halves of the
# DcSystem section must say so as Not Assessed; neither may be silent and neither may pass.
$dcs3 = @($findings3 | Where-Object { $_.Section -eq 'DC System' })
Check (@($dcs3 | Where-Object { $_.Item -eq 'OS lifecycle' -and $_.Status -eq 'Not Assessed' }).Count -eq 1) 'Failure mode: DC System reports the OS lifecycle check as Not Assessed when there is no DC inventory'
Check (@($dcs3 | Where-Object { $_.Item -eq 'Patch level' -and $_.Status -eq 'Not Assessed' }).Count -eq 1) 'Failure mode: DC System reports patch level as Not Assessed when no DC was enumerated'
Check (@($dcs3 | Where-Object { $_.Status -ne 'Not Assessed' }).Count -eq 0) ("Failure mode: DC System reports nothing but Not Assessed ({0} rows)" -f @($dcs3).Count)
# C1a: with no DC enumerated no revision was read, and none is shown or invented: no OS build row, no build number.
Check (@($dcs3 | Where-Object { $_.Item -like 'OS build and uptime:*' -or $_.Detail -match '17763\.\d' }).Count -eq 0) 'Failure mode C1a: no OS build row and no update build revision when no DC was enumerated'
# C13: with DC enumeration failing, DNS Health and DC DNS Client say so, give the domain whose inventory
# failed its own row, and pass nothing; DNS vs AD gives no per-DC row a Pass.
$dns3 = @($findings3 | Where-Object { $_.Section -eq 'DNS Health' })
Check (@($dns3 | Where-Object { $_.Item -eq 'DNS health' -and $_.Status -eq 'Not Assessed' -and $_.Detail -match 'ADWS unreachable' }).Count -eq 1) 'Failure mode C13: DNS Health reports Not Assessed when no DC was enumerated, and carries the enumeration failure'
Check (@($dns3 | Where-Object { $_.Item -eq 'DNS server - contoso.com' -and $_.Status -eq 'Not Assessed' -and $_.Scope -eq 'contoso.com' }).Count -eq 1) 'Failure mode C13: DNS Health gives the domain whose inventory failed its own Not Assessed row'
Check (@($dns3).Count -eq 2 -and @($dns3 | Where-Object { $_.Status -ne 'Not Assessed' }).Count -eq 0) ("Failure mode C13: DNS Health reports nothing but Not Assessed ({0} rows, expected 2)" -f @($dns3).Count)
$cli3 = @($findings3 | Where-Object { $_.Section -eq 'DC DNS Client' })
Check (@($cli3 | Where-Object { $_.Item -eq 'DNS client - contoso.com' -and $_.Status -eq 'Not Assessed' -and $_.Detail -match 'ADWS unreachable' }).Count -eq 1 -and @($cli3 | Where-Object { $_.Status -ne 'Not Assessed' }).Count -eq 0) 'Failure mode C13: DC DNS Client gives the failed domain a Not Assessed row with the cause, and passes nothing'
Check (@($findings3 | Where-Object { $_.Section -eq 'DNS vs AD Consistency' -and $_.Status -eq 'Pass' }).Count -eq 0) 'Failure mode C13: DNS vs AD Consistency passes nothing when the DC list could not be read'
# PORT-PLAN C2e: with DC enumeration failing, each section that took the unscoped host names gives the
# domain whose DCs could not be enumerated its own population row with the cause, says no DC was
# enumerated, and passes nothing. Declared population: the seven per-DC sections and their labels.
$c2e3 = [ordered]@{
    'Replication Health'       = 'Replication health (population): contoso.com'
    'SYSVOL / DFSR'            = 'SYSVOL / NETLOGON shares (population): contoso.com'
    'DFS Replication Events'   = 'DFS Replication events (population): contoso.com'
    'DC System'                = 'Patch level (population): contoso.com'
    'Restore Integrity'        = 'USN rollback marker (population): contoso.com'
    'Directory Service Events' = 'Directory Service events (population): contoso.com'
    'Time Hierarchy'           = 'Time hierarchy (population): contoso.com'
}
foreach ($sec in @($c2e3.Keys)) {
    Check (@($findings3 | Where-Object { $_.Section -eq $sec -and $_.Item -eq $c2e3[$sec] -and $_.Status -eq 'Not Assessed' -and $_.Scope -eq 'contoso.com' -and $_.Detail -match 'could not be enumerated' -and $_.Detail -match 'ADWS unreachable' }).Count -eq 1) ("Failure mode C2e: '{0}' gives the domain its own Not Assessed row with the cause" -f $sec)
}
Check (@($findings3 | Where-Object { @($c2e3.Keys) -contains $_.Section -and $_.Status -eq 'Pass' }).Count -eq 0) 'Failure mode C2e: none of the seven sections passes anything when no DC was enumerated'
$backlog3 = @($findings3 | Where-Object { $_.Section -eq 'SYSVOL Backlog' })
Check ($backlog3.Count -eq 1 -and $backlog3[0].Item -eq 'SYSVOL backlog (population): contoso.com' -and $backlog3[0].Status -eq 'Not Assessed' -and $backlog3[0].Scope -eq 'contoso.com' -and $backlog3[0].Detail -match 'could not be enumerated' -and $backlog3[0].Detail -match 'ADWS unreachable') ("Failure mode C2e review: the SYSVOL backlog gives the domain whose DCs could not be listed one Not Assessed row with the cause, and measures nothing ({0} rows)" -f $backlog3.Count)
Check (@($findings3 | Where-Object { $_.Section -eq 'Backup Status' -and $_.Status -eq 'Pass' }).Count -eq 0 -and @($findings3 | Where-Object { $_.Section -eq 'Port Reachability' -and $_.Status -eq 'Pass' }).Count -eq 0) 'Failure mode C2e: Backup and the port matrix pass nothing'
# C2: the same for DcDisk. With no DC there is nothing to read; the section must say so, name
# the enumeration failure, give the domain whose inventory failed its own row, and pass nothing.
$disk3 = @($findings3 | Where-Object { $_.Section -eq 'DC Disk Space' })
Check (@($disk3 | Where-Object { $_.Item -eq 'Disk space' -and $_.Status -eq 'Not Assessed' }).Count -eq 1) 'Failure mode: DC Disk Space reports Not Assessed when no DC was enumerated'
Check (@($disk3 | Where-Object { $_.Item -eq 'Disk space' -and $_.Detail -match 'ADWS unreachable' }).Count -eq 1) 'Failure mode: DC Disk Space carries the enumeration failure into its row'
Check (@($disk3 | Where-Object { $_.Item -eq 'Disk space - contoso.com' -and $_.Status -eq 'Not Assessed' -and $_.Scope -eq 'contoso.com' }).Count -eq 1) 'Failure mode: DC Disk Space gives the domain whose inventory failed its own Not Assessed row'
Check (@($disk3).Count -eq 2 -and @($disk3 | Where-Object { $_.Status -ne 'Not Assessed' }).Count -eq 0) ("Failure mode: DC Disk Space reports nothing but Not Assessed, and never Pass ({0} rows, expected 2)" -f @($disk3).Count)

Check (@($disk3 | Where-Object { $_.Item -eq 'Disk space - contoso.com' -and $_.Detail -match 'could not be enumerated\. Cause: STUB: ADWS unreachable' -and $_.Detail -match 'None of its volumes was read' }).Count -eq 1) 'Failure mode: the domain row names the cause and, with no DC read at all, says none of its volumes was read'
# C3: the same for DcHardening. With no DC there is no setting to read; the section must say so,
# name the enumeration failure, give the domain whose inventory failed its own row, and pass
# nothing.
$hard3 = @($findings3 | Where-Object { $_.Section -eq 'DC Hardening' })
Check (@($hard3 | Where-Object { $_.Item -eq 'DC hardening' -and $_.Status -eq 'Not Assessed' -and $_.Detail -match 'ADWS unreachable' }).Count -eq 1) 'Failure mode: DC Hardening reports Not Assessed when no DC was enumerated, and carries the enumeration failure'
Check (@($hard3 | Where-Object { $_.Item -eq 'DC hardening - contoso.com' -and $_.Status -eq 'Not Assessed' -and $_.Scope -eq 'contoso.com' -and $_.Detail -match 'could not be enumerated\. Cause: STUB: ADWS unreachable' -and $_.Detail -match 'None of its hardening settings was read' }).Count -eq 1) 'Failure mode: DC Hardening gives the domain whose inventory failed its own Not Assessed row, with the cause'
Check (@($hard3).Count -eq 2 -and @($hard3 | Where-Object { $_.Status -ne 'Not Assessed' }).Count -eq 0) ("Failure mode: DC Hardening reports nothing but Not Assessed, and never Pass ({0} rows, expected 2)" -f @($hard3).Count)
Check (@($hard3 | Where-Object { $_.Recommendation }).Count -eq 0) 'Failure mode: a DC Hardening row that measured nothing carries no advice'
# C3f: with no DC there is nobody to ask - the SMB server configuration cmdlet is not called, and no
# SMBv1 row exists to pass or fail.
Check (@($script:SmokeSmbCalls).Count -eq 0) ("Failure mode: Get-SmbServerConfiguration is not called when no DC was enumerated ({0} calls)" -f @($script:SmokeSmbCalls).Count)
Check (@($hard3 | Where-Object { $_.Item -like 'SMBv1: *' }).Count -eq 0) 'Failure mode: no SMBv1 row is invented for a DC nobody enumerated'
# C4: the same for Laps. The schema could not be read, so no domain is queried; the forest row
# and both rows of the scoped domain are Not Assessed, name the cause, and nothing passes.
$laps3 = @($findings3 | Where-Object { $_.Section -eq 'Windows LAPS' })
Check (@($laps3).Count -eq 3 -and @($laps3 | Where-Object { $_.Status -ne 'Not Assessed' }).Count -eq 0) ("Failure mode: Windows LAPS reports nothing but Not Assessed, and never Pass ({0} rows, expected 3)" -f @($laps3).Count)
Check (@($laps3 | Where-Object { $_.Item -eq 'Windows LAPS schema' -and $_.Detail -match '^Read failed: ' -and $_.Detail -match 'STUB: schema query refused' -and $_.Detail -match 'it is not reported as absent' }).Count -eq 1) 'Failure mode: the schema row carries the cause, and does not report the attributes as absent'
Check (@($laps3 | Where-Object { $_.Item -eq 'LAPS coverage: contoso.com' -and $_.Scope -eq 'contoso.com' -and $_.Detail -match 'the forest schema could not be read' }).Count -eq 1) 'Failure mode: the scoped domain has its own coverage row, Not Assessed, pointing at the schema'
Check (@($laps3 | Where-Object { $_.Item -eq 'DSRM password backup - contoso.com' -and $_.Scope -eq 'contoso.com' }).Count -eq 1) 'Failure mode: the scoped domain has its own DSRM row, Not Assessed'
Check (@($laps3 | Where-Object { $_.Recommendation }).Count -eq 0) 'Failure mode: a Windows LAPS row that measured nothing carries no advice'
# C5: the same for DcCertificates. With no DC there is nothing to look up or connect to; the
# section must say so, name the enumeration failure, give the domain its own row, and pass nothing.
$cert3 = @($findings3 | Where-Object { $_.Section -eq 'DC Certificates' })
Check (@($cert3 | Where-Object { $_.Item -eq 'DC certificates' -and $_.Status -eq 'Not Assessed' -and $_.Detail -match 'ADWS unreachable' }).Count -eq 1) 'Failure mode: DC Certificates reports Not Assessed when no DC was enumerated, and carries the enumeration failure'
Check (@($cert3 | Where-Object { $_.Item -eq 'DC certificates - contoso.com' -and $_.Status -eq 'Not Assessed' -and $_.Scope -eq 'contoso.com' -and $_.Detail -match 'could not be enumerated\. Cause: STUB: ADWS unreachable' -and $_.Detail -match 'No certificate of its domain controllers was read' }).Count -eq 1) 'Failure mode: DC Certificates gives the domain whose inventory failed its own Not Assessed row, with the cause'
Check (@($cert3).Count -eq 2 -and @($cert3 | Where-Object { $_.Status -ne 'Not Assessed' }).Count -eq 0) ("Failure mode: DC Certificates reports nothing but Not Assessed, and never Pass ({0} rows, expected 2)" -f @($cert3).Count)
Check (@($cert3 | Where-Object { $_.Recommendation }).Count -eq 0) 'Failure mode: a DC Certificates row that measured nothing carries no advice'
# C6: CN=RID Manager$ refused and no DC enumerated. The domain's two rows are Not Assessed with the
# cause, the domain has its own population row, the section says no DC was enumerated, nothing passes.
$rid3 = @($findings3 | Where-Object { $_.Section -eq 'RID Pool' })
Check (@($rid3).Count -eq 4 -and @($rid3 | Where-Object { $_.Status -ne 'Not Assessed' }).Count -eq 0) ("Failure mode: RID Pool reports nothing but Not Assessed, and never Pass ({0} rows, expected 4)" -f @($rid3).Count)
Check (@($rid3 | Where-Object { $_.Scope -eq 'contoso.com' -and $_.Item -like '*: contoso.com' -and $_.Detail -match '^Read failed: ' -and $_.Detail -match 'STUB: RID Manager read refused' }).Count -eq 2) 'Failure mode: both domain rows of RID Pool carry the cause of the refused read'
Check (@($rid3 | Where-Object { $_.Item -eq 'RID pool - contoso.com' -and $_.Scope -eq 'contoso.com' -and $_.Detail -match 'could not be enumerated\. Cause: STUB: ADWS unreachable' -and $_.Detail -match 'No RID Set of its domain controllers was read' }).Count -eq 1) 'Failure mode: RID Pool gives the domain whose inventory failed its own population row, with the cause'
Check (@($rid3 | Where-Object { $_.Item -eq 'RID pools' -and $_.Detail -match 'ADWS unreachable' }).Count -eq 1) 'Failure mode: RID Pool says no DC was enumerated, and why'
Check (@($rid3 | Where-Object { $_.Recommendation }).Count -eq 0) 'Failure mode: a RID Pool row that measured nothing carries no advice'
# C11: with no DC enumerated, DC Diagnostics runs nothing and reports nothing but Not Assessed.
$dd3 = @($findings3 | Where-Object { $_.Section -eq 'DC Diagnostics' })
Check (@($dd3).Count -gt 0 -and @($dd3 | Where-Object { $_.Status -ne 'Not Assessed' }).Count -eq 0) ("Failure mode: DC Diagnostics reports nothing but Not Assessed, and never Pass ({0} rows)" -f @($dd3).Count)
Check (@($dd3 | Where-Object { $_.Item -eq 'dcdiag grid' -and $_.Detail -match 'ADWS unreachable' }).Count -eq 1) 'Failure mode: DC Diagnostics says no DC was enumerated, and why'
Check (@($dd3 | Where-Object { $_.Item -eq 'dcdiag coverage: contoso.com' -and $_.Scope -eq 'contoso.com' -and $_.Detail -match 'ADWS unreachable' }).Count -eq 1) 'Failure mode: DC Diagnostics names the scoped domain whose DCs could not be enumerated'
# C12: the DNS summary is not read; one Not Assessed row for the scoped domain, and no test-group row.
Check (@($dd3 | Where-Object { $_.Item -eq 'dcdiag DNS not run: contoso.com' -and $_.Scope -eq 'contoso.com' -and $_.Status -eq 'Not Assessed' }).Count -eq 1 -and @($dd3 | Where-Object { $_.Item -match '^dcdiag DNS (Auth|Basc|Forw|Del|Dyn|RReg|Ext): ' }).Count -eq 0) 'Failure mode: DC Diagnostics has one Not Assessed "dcdiag DNS not run" row for the scoped domain and no DNS test-group row'
Check (@($dd3 | Where-Object { $_.Item -eq 'dcdiag Topology: contoso.com' }).Count -eq 1) 'Failure mode: the scoped domain still has its Topology row, Not Assessed'
Check (@($script:SmokeDcdiagCalls).Count -eq 0) 'Failure mode: dcdiag was never invoked'
# C7: the principal query refused. All four SID history rows of the domain are Not Assessed, say
# "Access denied" with the cause, carry no count and no advice, and none passes.
$sh3 = @($findings3 | Where-Object { $_.Section -eq 'Security Posture' -and $_.Item -like 'SID history*' })
Check (@($sh3).Count -eq 4 -and @($sh3 | Where-Object { $_.Status -ne 'Not Assessed' }).Count -eq 0) ("Failure mode: SID history reports nothing but Not Assessed, and never Pass ({0} rows, expected 4)" -f @($sh3).Count)
Check (@($sh3 | Where-Object { $_.Scope -eq 'contoso.com' -and $_.Detail -match '^Access denied: ' -and $_.Detail -match 'STUB: sIDHistory query refused' -and $_.Detail -match 'not a clean result' }).Count -eq 4) 'Failure mode: every SID history row says Access denied, not unreachable, with the cause'
Check (@($sh3 | Where-Object { $_.Recommendation }).Count -eq 0) 'Failure mode: a SID history row that measured nothing carries no advice'
# C8: the container query refused. The domain's one version row is its summary, Not Assessed, saying
# "Access denied" with the cause; no SYSVOL file is read, nothing passes and nothing carries advice.
$gpo3 = @($findings3 | Where-Object { $_.Section -eq 'GPO Inventory' -and ($_.Item -like 'GPO version*' -or $_.Item -like 'GPO folder*') })
Check (@($gpo3).Count -eq 1 -and $gpo3[0].Item -eq 'GPO version summary: contoso.com' -and $gpo3[0].Status -eq 'Not Assessed' -and $gpo3[0].Scope -eq 'contoso.com') ("Failure mode: GPO version reports the scoped domain's summary as Not Assessed, and never Pass ({0} rows, expected 1)" -f @($gpo3).Count)
Check (@($gpo3 | Where-Object { $_.Detail -match '^Access denied: ' -and $_.Detail -match 'STUB: groupPolicyContainer query refused' -and $_.Detail -match 'not a clean result' }).Count -eq 1) 'Failure mode: the GPO version summary says Access denied, not unreachable, with the cause'
Check (@($script:SmokeGptIniCalls).Count -eq 0) 'Failure mode: no GPT.INI is read when the containers could not be'
$gpoCsv3 = Join-Path $result3.CsvPath 'GPO Inventory.csv'
if (Test-Path $gpoCsv3) {
    $gpoCsv3Sum = @(Import-Csv $gpoCsv3 | Where-Object { $_.Item -eq 'GPO version summary: contoso.com' })
    Check (@($gpoCsv3Sum).Count -eq 1 -and $gpoCsv3Sum[0].Evidence -eq 'none' -and $gpoCsv3Sum[0].Population -eq '') 'Failure mode: the GPO version summary claims no evidence and no population when the containers could not be read'
}
else { Check $false 'Failure mode: GPO Inventory CSV exists' }
Check (@($gpo3 | Where-Object { $_.Recommendation }).Count -eq 0) 'Failure mode: a GPO version row that measured nothing carries no advice'
# C9: every descriptor read refused. The domain's three object rows and its GPO summary are Not
# Assessed, say "Access denied" with the cause, and none passes or carries advice.
$acl3 = @($findings3 | Where-Object { $_.Section -eq 'Dangerous ACLs (DCSync)' })
Check (@($acl3).Count -eq 4 -and @($acl3 | Where-Object { $_.Status -ne 'Not Assessed' }).Count -eq 0) ("Failure mode: Dangerous ACLs reports nothing but Not Assessed, and never Pass ({0} rows, expected 4)" -f @($acl3).Count)
Check (@($acl3 | Where-Object { $_.Scope -eq 'contoso.com' -and $_.Detail -match '^Access denied: ' -and $_.Detail -match 'STUB: security descriptor read refused' -and $_.Detail -match 'not a clean result' }).Count -eq 4) 'Failure mode: every Dangerous ACLs row says Access denied, not unreachable, with the cause'
Check (@($acl3 | Where-Object { $_.Recommendation }).Count -eq 0) 'Failure mode: a Dangerous ACLs row that measured nothing carries no advice'
# C10: every read refused. Every row of the three sections is Not Assessed - none passes, none is Info
# (an optional group that could not be read is not "not present"), none carries advice - and the
# rows say Access denied, not unreachable.
$priv3 = @($findings3 | Where-Object { $_.Section -match '^(Privileged Accounts|Privileged Hygiene|Kerberos Exposure)$' })
Check (@($priv3).Count -eq 30) ("Failure mode: the three C10 sections keep their declared rows - 20, 4 and 6 ({0} rows, expected 30)" -f @($priv3).Count)
Check (@($priv3 | Where-Object { $_.Status -ne 'Not Assessed' }).Count -eq 0) ("Failure mode: every C10 row is Not Assessed, never Pass or Info ({0} not)" -f @($priv3 | Where-Object { $_.Status -ne 'Not Assessed' }).Count)
Check (@($priv3 | Where-Object { $_.Item -match '^(Schema Admins members|Privileged group: Domain Admins|adminCount orphans|Unconstrained delegation): ' -and $_.Detail -match '^Access denied: ' -and $_.Detail -match 'STUB: privileged read refused' }).Count -eq 4) 'Failure mode: the C10 rows say Access denied, with the cause'
Check (@($priv3 | Where-Object { $_.Item -eq 'Kerberoastable user accounts (SPN set)' -and $_.Detail -match '^Access denied: ' }).Count -eq 1) 'Failure mode: the Kerberoast row says Access denied too'
Check (@($priv3 | Where-Object { $_.Recommendation }).Count -eq 0) 'Failure mode: a C10 row that measured nothing carries no advice'
# C14: no DC enumerated and the stale reads refused. Reachability, clients without a site and the SYSVOL
# engine say why and probe or read nothing; the stale rows say access denied; nothing passes.
$reach3 = @($findings3 | Where-Object { $_.Section -eq 'Port Reachability' -and $_.Item -like 'DC reachability*' })
Check (@($reach3 | Where-Object { $_.Item -eq 'DC reachability' -and $_.Status -eq 'Not Assessed' -and $_.Detail -match 'ADWS unreachable' }).Count -eq 1) 'Failure mode C14: DC reachability says no DC was enumerated, and why'
Check (@($reach3 | Where-Object { $_.Item -eq 'DC reachability (population): contoso.com' -and $_.Status -eq 'Not Assessed' -and $_.Scope -eq 'contoso.com' }).Count -eq 1) 'Failure mode C14: the domain whose DCs could not be enumerated has its own reachability row'
Check (@($reach3 | Where-Object { $_.Status -ne 'Not Assessed' }).Count -eq 0 -and @($script:SmokeReachCalls).Count -eq 0) ("Failure mode C14: no reachability row passes and nothing is probed ({0} probes)" -f @($script:SmokeReachCalls).Count)
$site3 = @($findings3 | Where-Object { $_.Section -eq 'Site Health' -and $_.Item -like 'Clients without a site*' })
Check (@($site3).Count -eq 2 -and @($site3 | Where-Object { $_.Status -ne 'Not Assessed' }).Count -eq 0 -and @($script:SmokeNetlogonCalls).Count -eq 0) ("Failure mode C14: clients without a site is Not Assessed for the run and the domain, and no log is read ({0} rows)" -f @($site3).Count)
$stale3 = @($findings3 | Where-Object { $_.Section -eq 'Stale Objects' -and $_.Item -match '^(Inactive enabled (users|computers)|Enabled users with an old password)$' })
Check (@($stale3).Count -eq 3 -and @($stale3 | Where-Object { $_.Status -eq 'Not Assessed' -and $_.Detail -match '\(access denied\)' -and $_.Detail -match 'not zero' }).Count -eq 3) ("Failure mode C14: the three stale rows are Not Assessed, say access denied and never zero ({0} rows)" -f @($stale3).Count)
Check (@($script:SmokePopulationCalls).Count -eq 2 -and @($stale3 | Where-Object { $_.Status -eq 'Pass' -or $_.Detail -match 'The read saw' }).Count -eq 0) ("Failure mode C14 review: the two population counts were refused, no stale row passes and none states a population ({0} counts)" -f @($script:SmokePopulationCalls).Count)
# C14c: the two future-timestamp reads were refused too: Not Assessed, access denied, never Info 0 or Pass.
$future3 = @($findings3 | Where-Object { $_.Section -eq 'Stale Objects' -and $_.Item -like 'Future logon timestamps: *' })
Check (@($future3).Count -eq 2 -and @($future3 | Where-Object { $_.Status -eq 'Not Assessed' -and $_.Detail -match '\(access denied\)' }).Count -eq 2 -and @($script:SmokeFutureCalls).Count -eq 2) ("Failure mode C14c: the two future-timestamp rows are Not Assessed, access denied ({0} rows, {1} reads)" -f @($future3).Count, @($script:SmokeFutureCalls).Count)
# C14c: no DC was enumerated, so no SYSVOL engine row of a DC is graded and no grid cell is Not Applicable.
Check (@($findings3 | Where-Object { $_.Section -eq 'SYSVOL / DFSR' -and $_.Item -like 'SYSVOL engine: *' -and $_.Status -ne 'Not Assessed' }).Count -eq 0) 'Failure mode C14c: no per-DC SYSVOL engine row is graded when nothing could be read'
$sys3 = @($findings3 | Where-Object { $_.Section -eq 'SYSVOL / DFSR' -and $_.Item -like 'SYSVOL replication engine*' })
Check (@($sys3).Count -eq 1 -and $sys3[0].Status -eq 'Not Assessed' -and $sys3[0].Detail -match 'ADWS unreachable') ("Failure mode C14: the SYSVOL engine of the domain is Not Assessed with the cause ({0} rows)" -f @($sys3).Count)
# C15: no DC enumerated and every inventory read refused. Each family says so, per domain where it reads
# per domain, and nothing is Info 0 or Pass.
$c15Fail = @($findings3 | Where-Object { $_.Section -in @('Topology Inventory', 'Trust Inventory', 'Object Counts', 'Group Inventory', 'GPO Directory Inventory', 'Event Inventory', 'Time Configuration') })
Check (@($c15Fail | Where-Object { $_.Status -eq 'Pass' -or $_.Status -eq 'Warning' -or $_.Status -eq 'Fail' }).Count -eq 0 -and $c15Fail.Count -gt 0) ("Failure mode C15: no inventory row is graded ({0} rows)" -f $c15Fail.Count)
Check (@($c15Fail | Where-Object { $_.Section -eq 'Topology Inventory' -and ($_.Item -like '* functional level: *' -or $_.Item -like 'FSMO role holder: *') -and $_.Status -eq 'Not Assessed' -and $_.Detail -match '\(access denied\)' }).Count -eq 7) 'Failure mode C15: the two levels and five FSMO holders are Not Assessed, access denied'
Check (@($c15Fail | Where-Object { $_.Item -eq 'DNS suffix (population): contoso.com' -and $_.Status -eq 'Not Assessed' -and $_.Detail -match 'ADWS unreachable' }).Count -eq 1) 'Failure mode C15: the DNS suffix population row names why no DC was compared'
Check (@($c15Fail | Where-Object { $_.Section -eq 'Object Counts' -and $_.Status -eq 'Not Assessed' -and $_.Detail -match 'access denied' -and $_.Detail -match 'not zero' }).Count -eq 13) 'Failure mode C15: the thirteen object counts are Not Assessed, never 0'
Check (@($c15Fail | Where-Object { $_.Item -eq 'Trusts (population): contoso.com' -and $_.Status -eq 'Not Assessed' }).Count -eq 1) 'Failure mode C15: the trust population is Not Assessed, never 0 trusts'
Check (@($c15Fail | Where-Object { $_.Item -eq 'GPO directory inventory: contoso.com' -and $_.Status -eq 'Not Assessed' }).Count -eq 1) 'Failure mode C15: the GPO directory inventory is Not Assessed, never 0 GPOs'
Check (@($c15Fail | Where-Object { $_.Section -eq 'Event Inventory' -and $_.Status -eq 'Not Assessed' -and $_.Scope -eq 'contoso.com' -and $_.Item -eq 'Events (population): contoso.com' }).Count -eq 1 -and @($script:SmokeEventCalls).Count -eq 0) 'Failure mode C15: with no DC enumerated no event log is read, and the domain says why'
Check (@($c15Fail | Where-Object { $_.Section -eq 'Time Configuration' -and $_.Item -eq 'W32Time configuration (population): contoso.com' -and $_.Status -eq 'Not Assessed' }).Count -eq 1) 'Failure mode C15: with no DC enumerated no W32Time value is read, and the domain says why'
$c15Dis3 = @($findings3 | Where-Object { $_.Section -eq 'Stale Objects' -and $_.Item -like 'Stale disabled *' })
Check (@($c15Dis3).Count -eq 2 -and @($c15Dis3 | Where-Object { $_.Status -eq 'Not Assessed' -and $_.Detail -match '\(access denied\)' }).Count -eq 2) 'Failure mode C15: the stale disabled rows are Not Assessed, access denied'
# C4b: the export, trust, site link and connection reads were each refused. Each says so with its cause;
# nothing is Pass and nothing is 0; no export file is written; the sites and subnets survive.
$c4bId3 = @($findings3 | Where-Object { $_.Section -eq 'Identity Inventory' -and $_.Scope -eq 'contoso.com' })
Check ($c4bId3.Count -eq 2 -and @($c4bId3 | Where-Object { $_.Status -eq 'Not Assessed' -and $_.Detail -match '\(access denied\)' -and $_.Detail -match 'not zero' }).Count -eq 2) 'Failure mode C4b: the users and computers summary rows are Not Assessed, access denied, never 0'
Check ((@($script:SmokeExportCalls) -join ',') -like 'User@contoso.com#*,Computer@contoso.com#*') ("Failure mode C4b: the two export reads were made, to the domain ({0})" -f (@($script:SmokeExportCalls) -join ', '))
Check (@(Get-ChildItem -Path $result3.CsvPath -Filter 'All*_*.csv' -ErrorAction SilentlyContinue).Count -eq 0) 'Failure mode C4b: no export file is written from a refused read'
Check (@($findings3 | Where-Object { $_.Section -eq 'Trusts & Two-Way Health' -and $_.Item -eq '(enumeration failed)' -and $_.Status -eq 'Not Assessed' -and $_.Detail -match '\(access denied\)' }).Count -eq 1) 'Failure mode C4b: the trust health read is one Not Assessed row, access denied'
Check (@($findings3 | Where-Object { $_.Section -eq 'Site Links' -and $_.Item -eq 'Site links' -and $_.Status -eq 'Not Assessed' -and $_.Detail -match '\(access denied\)' }).Count -eq 1 -and @($findings3 | Where-Object { $_.Section -eq 'Replication Connections' -and $_.Item -eq 'Replication connections' -and $_.Status -eq 'Not Assessed' -and $_.Detail -match '\(access denied\)' }).Count -eq 1) 'Failure mode C4b: the site link and connection reads are each one Not Assessed row, access denied - not an empty list'
Check (@($findings3 | Where-Object { $_.Section -in @('Identity Inventory', 'Trusts & Two-Way Health', 'Site Links', 'Replication Connections') -and $_.Status -eq 'Pass' }).Count -eq 0) 'Failure mode C4b: nothing in the four sections is Pass'
Check (Test-Path (Join-Path $result3.CsvPath 'AD Sites.csv')) 'Failure mode C4b: the sites survive a failed site link read'
# PORT-PLAN C4b3: a refused connection read is one Not Assessed row with no decoded column - never "No".
$c4b3Conn3 = @(Import-Csv (Join-Path $result3.CsvPath 'Replication Connections.csv'))
Check ($c4b3Conn3.Count -eq 1 -and $c4b3Conn3[0].Status -eq 'Not Assessed' -and $null -eq $c4b3Conn3[0].PSObject.Properties['AutoGenerated']) 'Failure mode C4b3: the refused connection read has no AutoGenerated value, so none can read as No'
# PORT-PLAN C4b4: the Object Counts rows are Not Assessed, access denied, never 0 and never Pass.
$c4b4Counts3 = @($findings3 | Where-Object { $_.Section -eq 'Object Counts' -and $_.Scope -eq 'contoso.com' })
Check ($c4b4Counts3.Count -gt 0 -and @($c4b4Counts3 | Where-Object { $_.Status -ne 'Not Assessed' -or $_.Detail -notmatch '\(access denied\)' }).Count -eq 0) ("Failure mode C4b4: every Object Counts row is Not Assessed, access denied ({0} rows)" -f $c4b4Counts3.Count)
# PORT-PLAN C11h: no DC Diagnostics row is Pass, and none reaches an unscoped advice entry.
$c11hUnscoped3 = @($script:RecommendationMap | Where-Object { -not $_.ContainsKey('Section') } | ForEach-Object { [string]$_.Text })
$c11hDd3 = @($findings3 | Where-Object { $_.Section -eq 'DC Diagnostics' })
Check ($c11hDd3.Count -gt 0 -and @($c11hDd3 | Where-Object { $_.Status -eq 'Pass' -or ($_.Recommendation -ne '' -and $c11hUnscoped3 -contains $_.Recommendation) }).Count -eq 0) ("Failure mode C11h: no DC Diagnostics row is Pass or carries an unscoped advice ({0} rows)" -f $c11hDd3.Count)
$script:SmokeC4bFail = $false
$script:SmokeInventoryFail = $false
$script:SmokeEventsFail = $false
$script:SmokeStaleFail = $false
$script:SmokePrivFail = $false
# The same reads unreachable, and then answered without a DACL, with Acl selected alone: each is its
# own Not Assessed result, and nothing passes.
$out3a = Join-Path ([IO.Path]::GetTempPath()) ("adfa_smoke_fail_aclonly_" + [guid]::NewGuid().ToString('N'))
$script:OutputPath = $out3a
$script:Sections = @('Acl')
$script:SmokeAclFail = $false
$script:SmokeAclUnreachable = $true
$result3a = Invoke-Main
$acl3a = @(@(Import-Csv $result3a.FindingsFile) | Where-Object { $_.Section -eq 'Dangerous ACLs (DCSync)' })
Check (@($acl3a).Count -eq 4 -and @($acl3a | Where-Object { $_.Status -eq 'Not Assessed' -and $_.Detail -match '^Unreachable: ' }).Count -eq 4) ("Failure mode, Acl alone: an unreachable domain gives four Not Assessed rows that say Unreachable ({0} rows)" -f @($acl3a).Count)
Remove-Item -Recurse -Force $out3a -ErrorAction SilentlyContinue
$script:SmokeAclUnreachable = $false
$script:SmokeAclDaclAbsent = $true
$out3a = Join-Path ([IO.Path]::GetTempPath()) ("adfa_smoke_fail_acldacl_" + [guid]::NewGuid().ToString('N'))
$script:OutputPath = $out3a
$result3a = Invoke-Main
$acl3d = @(@(Import-Csv $result3a.FindingsFile) | Where-Object { $_.Section -eq 'Dangerous ACLs (DCSync)' })
# Declared population: three object rows, two GPO rows, one summary.
Check (@($acl3d).Count -eq 6 -and @($acl3d | Where-Object { $_.Status -ne 'Not Assessed' }).Count -eq 0) ("Failure mode, Acl alone: descriptors without a DACL give nothing but Not Assessed, and never Pass ({0} rows, expected 6)" -f @($acl3d).Count)
Check (@($acl3d | Where-Object { $_.Item -ne 'GPO rights summary: contoso.com' -and $_.Detail -match '^No DACL returned: ' }).Count -eq 5) 'Failure mode, Acl alone: each object without a DACL says so, and is never read as "no ACE" or as "Everyone, full control"'
Remove-Item -Recurse -Force $out3a -ErrorAction SilentlyContinue
$script:SmokeAclDaclAbsent = $false
$script:SmokeAclFail = $true
$script:OutputPath = $out3
$script:Sections = @('All')
# The schema readable and the computer query failing: the schema row stands, the domain rows
# are Not Assessed with the query's own error.
$out3l = Join-Path ([IO.Path]::GetTempPath()) ("adfa_smoke_fail_lapsonly_" + [guid]::NewGuid().ToString('N'))
$script:OutputPath = $out3l
$script:Sections = @('Laps')
$script:SmokeLapsFail = $false
$script:SmokeLapsComputerFail = $true
$result3l = Invoke-Main
$script:SmokeLapsComputerFail = $false
$laps3l = @(@(Import-Csv $result3l.FindingsFile) | Where-Object { $_.Section -eq 'Windows LAPS' })
Check (@($laps3l).Count -eq 3) ("Failure mode, Laps alone: the schema row and two rows for the domain ({0}, expected 3)" -f @($laps3l).Count)
Check (@($laps3l | Where-Object { $_.Item -eq 'Windows LAPS schema' -and $_.Status -eq 'Pass' }).Count -eq 1) 'Failure mode, Laps alone: non-vacuity - the schema was read, so only the computer query is failing'
Check (@($laps3l | Where-Object { $_.Scope -eq 'contoso.com' -and $_.Item -ne 'Windows LAPS schema' -and $_.Status -eq 'Not Assessed' -and $_.Detail -match '^Read failed: ' -and $_.Detail -match 'STUB: computer query refused' -and $_.Detail -match 'not a clean result' }).Count -eq 2) 'Failure mode, Laps alone: both domain rows are Not Assessed with the cause, and never Pass'
Check (@($laps3l | Where-Object { $_.Item -ne 'Windows LAPS schema' -and $_.Status -ne 'Not Assessed' }).Count -eq 0) 'Failure mode, Laps alone: no computer and no DC is graded on a query that threw'
Remove-Item -Recurse -Force $out3l -ErrorAction SilentlyContinue
$script:SmokeLapsFail = $true
$out3h = Join-Path ([IO.Path]::GetTempPath()) ("adfa_smoke_fail_hardonly_" + [guid]::NewGuid().ToString('N'))
$script:OutputPath = $out3h
$script:Sections = @('DcHardening')
$result3h = Invoke-Main
$hard3h = @(@(Import-Csv $result3h.FindingsFile) | Where-Object { $_.Section -eq 'DC Hardening' })
Check (@($hard3h).Count -eq 2 -and @($hard3h | Where-Object { $_.Status -ne 'Not Assessed' }).Count -eq 0) ("Failure mode, DcHardening alone: nothing but Not Assessed, and never Pass ({0} rows, expected 2)" -f @($hard3h).Count)
Check (@($hard3h | Where-Object { $_.Item -eq 'DC hardening - contoso.com' -and $_.Scope -eq 'contoso.com' -and $_.Detail -match 'ADWS unreachable' }).Count -eq 1) 'Failure mode, DcHardening alone: the scoped domain has its own row, with the cause'
Remove-Item -Recurse -Force $out3h -ErrorAction SilentlyContinue
$script:OutputPath = $out3
$script:Sections = @('All')

# The same failure with DcDisk selected alone: the section's own per-domain enumeration throws,
# and it must give the scoped domain its Not Assessed row rather than an empty section.
$out3d = Join-Path ([IO.Path]::GetTempPath()) ("adfa_smoke_fail_diskonly_" + [guid]::NewGuid().ToString('N'))
$script:OutputPath = $out3d
$script:Sections = @('DcDisk')
$result3d = Invoke-Main
$disk3d = @(@(Import-Csv $result3d.FindingsFile) | Where-Object { $_.Section -eq 'DC Disk Space' })
Check (@($disk3d).Count -eq 2 -and @($disk3d | Where-Object { $_.Status -ne 'Not Assessed' }).Count -eq 0) ("Failure mode, DcDisk alone: nothing but Not Assessed, and never Pass ({0} rows, expected 2)" -f @($disk3d).Count)
Check (@($disk3d | Where-Object { $_.Item -eq 'Disk space - contoso.com' -and $_.Scope -eq 'contoso.com' -and $_.Detail -match 'ADWS unreachable' }).Count -eq 1) 'Failure mode, DcDisk alone: the scoped domain has its own row, with the cause'
Remove-Item -Recurse -Force $out3d -ErrorAction SilentlyContinue
$script:OutputPath = $out3
$script:Sections = @('All')

# Non-vacuity: the run must not have passed simply because nothing was assessed at all.
$notAssessed3 = @($findings3 | Where-Object { $_.Status -eq 'Not Assessed' }).Count
Check ($notAssessed3 -ge 4) ("Failure mode: non-vacuity - {0} Not Assessed findings actually present" -f $notAssessed3)
# And crucially: no section may claim a Pass for something that could not be measured.
$falsePass = @($findings3 | Where-Object { $_.Status -eq 'Pass' -and $_.Detail -match 'could not|failed|unreachable' })
Check ($falsePass.Count -eq 0) ("Failure mode: nothing reports Pass off the back of a failure ({0})" -f $falsePass.Count)

# The JSON must reflect the same story, so a machine-readable consumer is not misled either.
if (Test-Path $result3.JsonPath) {
    $doc3 = Get-Content $result3.JsonPath -Raw | ConvertFrom-Json
    Check ([int]$doc3.summary.notAssessed -ge 4) ("Failure mode: JSON summary records the unassessed count ({0})" -f [int]$doc3.summary.notAssessed)
}
else { Check $false 'Failure mode: Assessment.json written' }

Remove-Item -Recurse -Force $out3 -ErrorAction SilentlyContinue

# ---- Scenario 4: the forest itself cannot be read (H9) ----------------------
# Before this, Get-ADForest was called unguarded during scope resolution, so a forest that
# could not be contacted killed the run with a raw exception and produced NO report. On a
# damaged or partly-recovered forest - the case this tool exists for - that is the worst
# possible outcome: the operator gets a stack trace instead of an artefact naming the cause.
Write-Host ""
Write-Host "== Running Invoke-Main with an unreadable forest ==" -ForegroundColor Cyan

function Get-ADForest { param([Parameter(ValueFromRemainingArguments)]$a) throw 'STUB: forest not contactable' }

$out4 = Join-Path ([IO.Path]::GetTempPath()) ("adfa_smoke_noforest_" + [guid]::NewGuid().ToString('N'))
$script:OutputPath = $out4
$script:AllDomains = $false
$noForestOk = $true
$result4 = $null
try { $result4 = Invoke-Main }
catch { $noForestOk = $false; Write-Host ("    unexpected throw: {0}" -f $_.Exception.Message) -ForegroundColor DarkYellow }

Check $noForestOk 'No forest: Invoke-Main completes instead of dying with a raw exception'
Check ($null -ne $result4) 'No forest: a summary object is still returned'
if ($null -ne $result4) {
    # PORT-PLAN H21: an unreadable forest completes with a bundle and its Fail headline finding: exit code 1.
    Write-Host ("    H21 no-forest exit: {0} - {1}" -f $result4.ExitCode, $result4.ExitReason) -ForegroundColor DarkGray
    Test-SmokeH21Run -Result $result4 -Root $out4 -Name 'no forest' -ExpectedCode 1 -ReasonPattern 'Fail finding'
}
if ($null -ne $result4) {
    Check (Test-Path $result4.FindingsFile) 'No forest: a findings bundle still lands on disk'
    Check (Test-Path $result4.ReportPath) 'No forest: the HTML report is still written'
    Check (Test-Path $result4.JsonPath) 'No forest: the JSON report is still written'
    $findings4 = @(Import-Csv $result4.FindingsFile)
    Check ($findings4.Count -gt 0) ("No forest: findings are not empty ({0} rows)" -f $findings4.Count)

    $scope = @($findings4 | Where-Object { $_.Item -eq 'Forest resolution' })
    Check ($scope.Count -eq 1) 'No forest: the failure is a single headline finding'
    if ($scope.Count -eq 1) {
        Check ($scope[0].Status -eq 'Fail') ("No forest: reported as Fail (got '{0}')" -f $scope[0].Status)
        Check ($scope[0].Detail -match 'not contactable') 'No forest: the underlying cause is carried into the report'
        Check ($scope[0].Detail -match 'NOTHING in this report was assessed') 'No forest: the finding refuses to imply anything was assessed'
    }

    # C15: with no forest each directory inventory family asks nothing and says so in one row.
    foreach ($c15Pair in @(@('Topology Inventory', 'Topology inventory: *'), @('Trust Inventory', 'Trusts (population): *'), @('Object Counts', 'Object count: *'), @('GPO Directory Inventory', 'GPO directory inventory: *'))) {
        $c15Rows4 = @($findings4 | Where-Object { $_.Section -eq $c15Pair[0] })
        Check (@($c15Rows4).Count -eq 1 -and $c15Rows4[0].Status -eq 'Not Assessed' -and $c15Rows4[0].Item -like $c15Pair[1] -and $c15Rows4[0].Detail -match 'not contactable') ("No forest: {0} is one Not Assessed row carrying the cause" -f $c15Pair[0])
    }
    # C4: with no forest the Laps section asks nothing and says so in one row.
    $laps4 = @($findings4 | Where-Object { $_.Section -eq 'Windows LAPS' })
    Check (@($laps4).Count -eq 1 -and $laps4[0].Status -eq 'Not Assessed' -and $laps4[0].Detail -match 'The forest could not be read' -and $laps4[0].Detail -match 'not contactable') 'No forest: Windows LAPS is one Not Assessed row carrying the cause'
    # C5: with no forest no domain is scoped and no DC enumerated; the section says so.
    $cert4 = @($findings4 | Where-Object { $_.Section -eq 'DC Certificates' })
    Check (@($cert4).Count -ge 1 -and @($cert4 | Where-Object { $_.Status -ne 'Not Assessed' }).Count -eq 0) ("No forest: DC Certificates is present and reports nothing but Not Assessed ({0} rows)" -f @($cert4).Count)
    # C6: with no forest no domain is scoped; the section asks nothing and says so in one row.
    $rid4 = @($findings4 | Where-Object { $_.Section -eq 'RID Pool' })
    Check (@($rid4).Count -eq 1 -and $rid4[0].Status -eq 'Not Assessed' -and $rid4[0].Detail -match 'The forest could not be read' -and $rid4[0].Detail -match 'not contactable') 'No forest: RID Pool is one Not Assessed row carrying the cause'
    # C7: with no forest no domain is scoped; the SID history rows ask nothing and say so in one row.
    $sh4 = @($findings4 | Where-Object { $_.Section -eq 'Security Posture' -and $_.Item -like 'SID history*' })
    Check (@($sh4).Count -eq 1 -and $sh4[0].Item -eq 'SID history' -and $sh4[0].Status -eq 'Not Assessed' -and $sh4[0].Detail -match 'The forest could not be read' -and $sh4[0].Detail -match 'not contactable') 'No forest: SID history is one Not Assessed row carrying the cause'
    # C8: with no forest no domain is scoped; the GPO version check asks nothing and says so in one row.
    $gpo4 = @($findings4 | Where-Object { $_.Section -eq 'GPO Inventory' })
    Check (@($gpo4).Count -eq 1 -and $gpo4[0].Item -eq 'GPO version' -and $gpo4[0].Status -eq 'Not Assessed' -and $gpo4[0].Detail -match 'The forest could not be read' -and $gpo4[0].Detail -match 'not contactable') 'No forest: GPO Inventory is one Not Assessed GPO version row carrying the cause'
    # C9: with no forest no domain is scoped and no root SID read; the section asks nothing and says so.
    $acl4 = @($findings4 | Where-Object { $_.Section -eq 'Dangerous ACLs (DCSync)' })
    Check (@($acl4).Count -eq 1 -and $acl4[0].Item -eq 'Dangerous ACLs' -and $acl4[0].Status -eq 'Not Assessed' -and $acl4[0].Detail -match 'The forest could not be read' -and $acl4[0].Detail -match 'not contactable') 'No forest: Dangerous ACLs is one Not Assessed row carrying the cause'
    # C10: with no forest no domain is scoped; each of the three sections asks nothing and says so in one row.
    foreach ($privSpec in @(@('Privileged Accounts', 'Privileged groups'), @('Privileged Hygiene', 'Privileged hygiene'), @('Kerberos Exposure', 'Kerberos exposure'))) {
        $priv4 = @($findings4 | Where-Object { $_.Section -eq $privSpec[0] })
        Check (@($priv4).Count -eq 1 -and $priv4[0].Item -eq $privSpec[1] -and $priv4[0].Status -eq 'Not Assessed' -and $priv4[0].Detail -match 'The forest could not be read' -and $priv4[0].Detail -match 'not contactable') ("No forest: {0} is one Not Assessed row carrying the cause" -f $privSpec[0])
    }

    # The critical property: with no forest, nothing may claim to have passed.
    $passes4 = @($findings4 | Where-Object { $_.Status -eq 'Pass' })
    Check ($passes4.Count -eq 0) ("No forest: nothing reports Pass when nothing could be read ({0})" -f $passes4.Count)
    # Non-vacuity: the run really did evaluate sections rather than producing a single row.
    Check ($findings4.Count -ge 5) ("No forest: non-vacuity - sections were evaluated and degraded ({0} rows)" -f $findings4.Count)
}
Remove-Item -Recurse -Force $out4 -ErrorAction SilentlyContinue

# ---- PORT-PLAN H21, independent review fix (M2, M7): reports not written and an uninterpretable row ----
# Both report writers fail and a collector returns a dictionary where a finding belongs. The run must
# still complete, and its exit code must be 1 naming each cause: the wiring of -ReportsNotWritten and
# -UnreadableRows from Invoke-Main into Get-AdfaRunExitCode, which the pure tests cannot see.
Write-Host ""
Write-Host "== Running Invoke-Main with failing report writers and an uninterpretable row (H21 review fix) ==" -ForegroundColor Cyan
$savedHtmlWriter = ${function:New-AdfaHtmlReport}
$savedJsonWriter = ${function:Export-AdfaJsonReport}
$savedForestSummary = ${function:Get-AdfaForestSummary}
function New-AdfaHtmlReport { param([Parameter(ValueFromRemainingArguments)]$a) throw 'STUB: HTML writer failed' }
function Export-AdfaJsonReport { param([Parameter(ValueFromRemainingArguments)]$a) throw 'STUB: JSON writer failed' }
function Get-AdfaForestSummary { param([Parameter(ValueFromRemainingArguments)]$a)
    New-Finding -Area 'Forest' -Item 'Forest name' -Status $script:Status.Pass -Detail 'stub'
    @{ Shape = 'a dictionary where a finding belongs' } }
$out5 = Join-Path ([IO.Path]::GetTempPath()) ("adfa_smoke_writers_" + [guid]::NewGuid().ToString('N'))
$script:OutputPath = $out5
$script:Sections = @('Forest')
$result5 = $null
try { $result5 = Invoke-Main }
catch { Write-Host ("    unexpected throw: {0}" -f $_.Exception.Message) -ForegroundColor DarkYellow }
finally {
    ${function:New-AdfaHtmlReport} = $savedHtmlWriter
    ${function:Export-AdfaJsonReport} = $savedJsonWriter
    ${function:Get-AdfaForestSummary} = $savedForestSummary
    $script:Sections = @('All')
}
Check ($null -ne $result5) 'H21 writers: the run completes although both report writers failed'
if ($null -ne $result5) {
    Write-Host ("    H21 writers exit: {0} - {1}" -f $result5.ExitCode, $result5.ExitReason) -ForegroundColor DarkGray
    Test-SmokeH21Run -Result $result5 -Root $out5 -Name 'report writers failed' -ExpectedCode 1 -ReasonPattern 'HTML report not written'
    Check ([string]$result5.ExitReason -match 'JSON report not written') 'H21 writers: the exit reason names the JSON report not written'
    Check ([string]$result5.ExitReason -match '1 collected row\(s\) could not be interpreted') ("H21 writers: the exit reason names the uninterpretable row ({0})" -f $result5.ExitReason)
    Check ([string]$result5.ReportPath -eq '' -and [string]$result5.JsonPath -eq '') 'H21 writers: the summary says neither report was written'
}
Remove-Item -Recurse -Force $out5 -ErrorAction SilentlyContinue

# cleanup
Remove-Item -Recurse -Force $out2 -ErrorAction SilentlyContinue
Remove-Item -Recurse -Force $out -ErrorAction SilentlyContinue
Remove-Item Env:\ADFA_NO_AUTORUN -ErrorAction SilentlyContinue
Write-Host ""
if ($fail -gt 0) { Write-Host "SMOKE TEST FAILED ($fail)" -ForegroundColor Red; exit 1 }
Write-Host "SMOKE TEST PASSED" -ForegroundColor Green
exit 0
