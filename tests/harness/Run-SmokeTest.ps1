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
function Get-ADDomain { param([Parameter(ValueFromRemainingArguments)]$a)
    [pscustomobject]@{ DNSRoot='contoso.com'; NetBIOSName='CONTOSO'; DomainMode='Windows2016Domain'
        PDCEmulator='dc1.contoso.com'; RIDMaster='dc1.contoso.com'; InfrastructureMaster='dc1.contoso.com'
        DomainSID=(New-StubSid 'S-1-5-21-1-2-3'); DistinguishedName='DC=contoso,DC=com' } }
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
#   -Properties * (only the Identity export sends it): the same single object as before, plus
#     the attributes a privileged account would be handed, the secret ones included. Their value
#     is a sentinel string, and the harness asserts it appears nowhere in the output bundle.
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
    $stubComputer = [pscustomobject]@{ OperatingSystem='Windows Server 2019'; OperatingSystemVersion='10.0 (17763)'; Enabled=$true; whenCreated=$now }
    if (@($Properties) -contains '*') {
        foreach ($secretName in $script:SmokeLapsSecretNames) { $stubComputer | Add-Member -NotePropertyName $secretName -NotePropertyValue $script:SmokeSecretSentinel }
        $stubComputer | Add-Member -NotePropertyName 'msLAPS-PasswordExpirationTime' -NotePropertyValue ([int64]$now.AddDays(20).ToFileTimeUtc())
    }
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
    # C3 (DcHardening): the SMB server configuration, and the Print Spooler service as
    # Win32_Service returns it - State and StartMode are strings. The service query is answered
    # only for the filter the section sends, so a section that asked for every service would get
    # nothing rather than a Spooler it did not ask for.
    #
    # MSFT_SmbServerConfiguration answers, BY DEFAULT, what the real class was MEASURED to answer
    # to an instance query on 2026-11-15 (one Windows 11 build 26100 workstation, not a DC, not
    # elevated, PowerShell 7 and Windows PowerShell 5.1): no instance and no error. The real
    # configuration comes from the class's static method GetConfiguration, which the tool does
    # not invoke and which the Invoke-CimMethod stub below refuses. An earlier version of this
    # stub handed back an instance, a shape nobody had measured, and so proved only itself.
    # $script:SmokeSmbInstance = $true selects that unmeasured shape for the one pass that
    # checks the code path a DC would take if it did return an instance; the two properties are
    # booleans there.
    if ($ClassName -eq 'MSFT_SmbServerConfiguration' -and $Namespace -eq 'root/Microsoft/Windows/SMB') {
        if ($script:SmokeSmbInstance) { return [pscustomobject]@{ EnableSMB1Protocol = $false; RequireSecuritySignature = $true } }
        return @()
    }
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
    throw ("STUB: CIM class '{0}' is not stubbed" -f $ClassName)
}
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
$script:SmokeSmbInstance = $false
function Invoke-CimMethod {
    param($CimSession, [string]$Namespace, [string]$ClassName, [string]$MethodName, $Arguments, [uint32]$OperationTimeoutSec, $ErrorAction)
    if ($ClassName -ne 'StdRegProv' -or @('GetStringValue', 'GetExpandedStringValue', 'GetDWORDValue') -notcontains $MethodName) {
        throw ("STUB: CIM method '{0}.{1}' is not stubbed" -f $ClassName, $MethodName)
    }
    $stubRegistry = @{
        'SYSTEM\CurrentControlSet\Services\NTDS\Parameters|DSA Database File'       = 'C:\Windows\NTDS\ntds.dit'
        'SYSTEM\CurrentControlSet\Services\NTDS\Parameters|Database Log Files Path' = 'E:\NTDS-Logs'
        'SYSTEM\CurrentControlSet\Services\Netlogon\Parameters|SysVol'              = 'C:\Windows\SYSVOL\sysvol'
    }
    $stubDwords = @{
        'SYSTEM\CurrentControlSet\Services\NTDS\Parameters|LDAPServerIntegrity'              = [uint32]2
        'SYSTEM\CurrentControlSet\Services\LanManServer\Parameters|RequireSecuritySignature' = [uint32]1
        'SYSTEM\CurrentControlSet\Control\Lsa|LmCompatibilityLevel'                         = [uint32]5
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
function Get-ADReplicationSiteLink { param([Parameter(ValueFromRemainingArguments)]$a)
    [pscustomobject]@{ Name='DEFAULTIPSITELINK'; Cost=100; ReplicationFrequencyInMinutes=180
        InterSiteTransportProtocol='IP'; SitesIncluded=@('CN=Default-First-Site-Name') } }
function Get-ADReplicationConnection { param([Parameter(ValueFromRemainingArguments)]$a)
    [pscustomobject]@{ Name='conn1'; FromServer='dc2'; ToServer='dc1'; Enabled=$true; AutoGenerated=$true } }
function Get-ADTrust { param([Parameter(ValueFromRemainingArguments)]$a)
    [pscustomobject]@{ Name='fabrikam.com'; Source='contoso.com'; Target='fabrikam.com'; Direction='Bidirectional'
        TrustType='Forest'; IntraForest=$false; ForestTransitive=$true; SelectiveAuthentication=$false
        SIDFilteringForestAware=$false; SIDFilteringQuarantined=$true; TGTDelegation=$false
        UsesRC4Encryption=$false; Created=$now; Modified=$now } }
function Get-ADDefaultDomainPasswordPolicy { param([Parameter(ValueFromRemainingArguments)]$a)
    [pscustomobject]@{ MinPasswordLength=8; PasswordHistoryCount=24; MaxPasswordAge=[timespan]::FromDays(42)
        MinPasswordAge=[timespan]::FromDays(1); ComplexityEnabled=$true; LockoutThreshold=5; ReversibleEncryptionEnabled=$false } }
function Get-ADFineGrainedPasswordPolicy { param([Parameter(ValueFromRemainingArguments)]$a) @() }
function Get-ADGroupMember { param([Parameter(ValueFromRemainingArguments)]$a)
    1..3 | ForEach-Object { [pscustomobject]@{ SamAccountName="admin$_" } } }
function Get-ADUser { param([Parameter(ValueFromRemainingArguments)]$a)
    [pscustomobject]@{ PasswordLastSet=$now.AddDays(-30); SamAccountName='krbtgt' } }
function Get-ADOptionalFeature { param([Parameter(ValueFromRemainingArguments)]$a)
    [pscustomobject]@{ Name='Recycle Bin Feature'; EnabledScopes=@('CN=Partitions') } }
function Get-ADRootDSE { param([Parameter(ValueFromRemainingArguments)]$a)
    [pscustomobject]@{ configurationNamingContext='CN=Configuration,DC=contoso,DC=com'; schemaNamingContext='CN=Schema,CN=Configuration,DC=contoso,DC=com' } }
# C4 (Laps): one more behaviour, selected by the filter. A search for attributeSchema objects by
# lDAPDisplayName - which only the Laps schema read sends - is answered with one object per name
# that is both asked for and in $script:SmokeLapsSchema, in the shape the cmdlet returns. Every
# other call receives the single object it always received.
function Get-ADObject { param([Parameter(ValueFromRemainingArguments)]$a)
    $stubAsked = (@($a | ForEach-Object { [string]$_ }) -join ' ')
    $stubNamed = ConvertTo-StubArgument -Given $a
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
function Test-CommandAvailable { param([string]$Name) return $false }
function Test-ModuleAvailable { param([string]$Name) return $false }
function Test-TcpPort { param([string]$ComputerName, [int]$Port, [int]$TimeoutMs) return $true }
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
$script:Server = $null
$script:Credential = $null

Write-Host "== Running Invoke-Main against stubbed AD ==" -ForegroundColor Cyan
$result = Invoke-Main

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
# C1: the DcSystem section must be wired, must judge the stub DC's OS from the inventory, and
# must report the patch-level inventory read through the CIM stubs - as Info, never as Pass.
$dcsRows = @($smokeFindings | Where-Object { $_.Section -eq 'DC System' })
Check (@($dcsRows).Count -gt 0) ("Section 'DC System' is wired into Invoke-Main and reached the findings ({0} rows)" -f @($dcsRows).Count)
$lifeRows = @($dcsRows | Where-Object { $_.Item -like 'OS lifecycle:*' })
Check (@($lifeRows).Count -eq 1 -and $lifeRows[0].Status -eq 'Pass' -and $lifeRows[0].Detail -match 'Windows Server 2019' -and $lifeRows[0].Detail -match '2029-01-09') 'DC System: the stub DC (build 17763) is judged in support, with the end date stated'
Check ([string]$lifeRows[0].Scope -eq 'contoso.com') 'DC System: the lifecycle row carries its domain as Scope'
$osRow = @($dcsRows | Where-Object { $_.Item -like 'OS build and uptime:*' })
Check (@($osRow).Count -eq 1 -and $osRow[0].Status -eq 'Info' -and $osRow[0].Detail -match 'Build 17763' -and $osRow[0].Detail -match 'up 9 day') 'DC System: build and uptime are read through the CIM stub and reported as Info'
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
# stub and the three classes through the Get-CimInstance stub in ONE session per DC, and must
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
Check ((Get-HardRow $hardRows 'SMB server signing').Detail -match 'second instrument, MSFT_SmbServerConfiguration\.RequireSecuritySignature, was not read \(MSFT_SmbServerConfiguration returned no instance' -and (Get-HardRow $hardRows 'SMB server signing').Detail -notmatch 'agrees') 'DC Hardening: the SMB class returned no instance, as measured, so the row says its second instrument was not read and claims no agreement'
$hardClient = Get-HardRow $hardRows 'SMB client signing'
Check ($hardClient.Status -eq 'Warning' -and $hardClient.Detail -match 'documented default' -and $hardClient.Detail -match 'Disabled') 'DC Hardening: SMB client signing is not set, and the documented pre-2025 default (Disabled) is a Warning'
Check ((Get-HardRow $hardRows 'LAN Manager authentication level').Status -eq 'Pass' -and (Get-HardRow $hardRows 'LAN Manager authentication level').Detail -match 'LmCompatibilityLevel = 5') 'DC Hardening: the LAN Manager level passes at 5'
Check ((Get-HardRow $hardRows 'Print Spooler').Status -eq 'Pass' -and (Get-HardRow $hardRows 'Print Spooler').Detail -match 'Stopped') 'DC Hardening: Print Spooler is read from Win32_Service and passes when Stopped'
Check ((Get-HardRow $hardRows 'SMBv1').Status -eq 'Not Assessed' -and (Get-HardRow $hardRows 'SMBv1').Detail -match '^Not read: MSFT_SmbServerConfiguration returned no instance to an instance query') 'DC Hardening: SMBv1 is Not Assessed, never Pass, when the SMB class returns no instance - the shape measured on a real host'
Check ((Get-HardRow $hardRows 'SMBv1').Detail -match 'GetConfiguration' -and (Get-HardRow $hardRows 'SMBv1').Detail -match 'PORT-PLAN C3f' -and -not (Get-HardRow $hardRows 'SMBv1').Recommendation) 'DC Hardening: the SMBv1 row names the method it does not invoke and the plan row, and carries no advice'
Check (@($hardRows | Where-Object { $_.Status -eq 'Pass' }).Count -eq 4) ("DC Hardening: four rows pass on the stub DC - LDAP signing, SMB server signing, LAN Manager level, Print Spooler ({0})" -f @($hardRows | Where-Object { $_.Status -eq 'Pass' }).Count)
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
Check ($allComputersColumns -contains 'msLAPS-PasswordExpirationTime' -and $allComputersColumns -contains 'OperatingSystem') 'Hard rule: non-vacuity - the export did receive the all-attributes object, and kept the non-secret expiry time'
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
# Site GC coverage is derived from the inventory alone, so it must produce a real verdict here.
$gcRows = @($smokeFindings | Where-Object { $_.Section -eq 'Site Global Catalog Coverage' })
Check (@($gcRows | Where-Object { $_.Status -eq 'Pass' }).Count -eq 1) 'Site GC coverage passes for a stub DC that is a writeable GC in its site'

Write-Host ""
Write-Host ("Output bundle: {0}" -f $result.OutputRoot)
Get-ChildItem -Recurse $result.OutputRoot | Select-Object -First 30 FullName | ForEach-Object { Write-Host ("   {0}" -f $_.FullName) }

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
$result2 = Invoke-Main

Check ($null -ne $result2) 'Multi-domain: Invoke-Main returned a summary object'
Check (@($result2.DomainsScoped).Count -eq 3) ("Multi-domain: three domains scoped ({0})" -f @($result2.DomainsScoped).Count)

# The core assertion: per-domain sections must contribute findings, not vanish.
$findings2 = @(Import-Csv (Join-Path $result2.CsvPath 'Findings-Consolidated.csv'))
Check ($findings2.Count -gt 0) ("Multi-domain: consolidated findings are not empty ({0} rows)" -f $findings2.Count)

foreach ($sec in @('Password Policy', 'Security Posture', 'DNS vs AD Consistency', 'DC Secure Channel & Machine Passwords', 'DC System', 'DC Disk Space', 'DC Hardening', 'Windows LAPS', 'DC Certificates', 'RID Pool')) {
    $n = @($findings2 | Where-Object { $_.Section -eq $sec }).Count
    Check ($n -gt 0) ("Multi-domain: section '{0}' reached the consolidated findings ({1} rows)" -f $sec, $n)
}
# C1: one lifecycle row per DC per domain, each carrying its own domain - not three copies of
# the first domain, and not one row for the forest.
$life2 = @($findings2 | Where-Object { $_.Section -eq 'DC System' -and $_.Item -like 'OS lifecycle:*' })
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
    Check (@($forDomainH | Where-Object { $_.Status -eq 'Pass' }).Count -eq 4) ("Multi-domain: the DC Hardening settings of '{0}' are judged, not skipped" -f $d)
    Check (@($forDomainH | Where-Object { $_.Item -like 'SMBv1: *' -and $_.Status -eq 'Not Assessed' }).Count -eq 1) ("Multi-domain: the SMBv1 row of '{0}' is Not Assessed, never Pass, on a class that returned no instance" -f $d)
}

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
    Check (@($forDomainHH).Count -eq 8 -and @($forDomainHH | Where-Object { $_.Status -eq 'Pass' }).Count -eq 4) ("Multi-domain, DcHardening alone: domain '{0}' is in the section and judged ({1} rows)" -f $d, @($forDomainHH).Count)
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

# C3: the other shape of the SMB class - an instance returned to the query. NOT MEASURED on any
# host; run once so the code a DC would take if it did return one is exercised end to end. (The
# override file above is still in force; it touches SMB client signing only.)
$script:SmokeSmbInstance = $true
$outSI = Join-Path ([IO.Path]::GetTempPath()) ("adfa_smoke_smbinstance_" + [guid]::NewGuid().ToString('N'))
$script:OutputPath = $outSI
$script:Sections = @('DomainControllers', 'DcHardening')
$resultSI = Invoke-Main
$hardSI = @(@(Import-Csv $resultSI.FindingsFile) | Where-Object { $_.Section -eq 'DC Hardening' })
Check (@($hardSI).Count -eq 8) ("SMB instance returned (unmeasured shape): DC Hardening gives one row per setting ({0}, expected 8)" -f @($hardSI).Count)
Check (@($hardSI | Where-Object { $_.Item -eq 'SMBv1: dc1.contoso.com' -and $_.Status -eq 'Pass' -and $_.Detail -match 'EnableSMB1Protocol = False' }).Count -eq 1) 'SMB instance returned (unmeasured shape): SMBv1 is graded on EnableSMB1Protocol'
Check (@($hardSI | Where-Object { $_.Item -eq 'SMB server signing: dc1.contoso.com' -and $_.Status -eq 'Pass' -and $_.Detail -match 'second instrument agrees' }).Count -eq 1) 'SMB instance returned (unmeasured shape): the second instrument agrees with the registry value'
$script:SmokeSmbInstance = $false
Remove-Item -Recurse -Force $outSI -ErrorAction SilentlyContinue
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
    $written = @(Get-ChildItem -Path $outB -Recurse -Filter *.csv -ErrorAction SilentlyContinue)
    Check ($written.Count -eq 0) ("Override: with {0}, nothing was collected before the run stopped ({1} CSV files)" -f $bad.Name, $written.Count)
    Remove-Item -Recurse -Force $outB -ErrorAction SilentlyContinue
}
Check (@($badFiles).Count -eq 14) 'Override: non-vacuity - fourteen declared unusable files were tried'
Remove-Item -LiteralPath $overrideFile -Force -ErrorAction SilentlyContinue
# The parameter carries [ValidateNotNullOrEmpty()], and the attribute stays on the variable, so
# it cannot simply be set back to empty: the variable is removed and re-created without it.
Remove-Variable -Name ConfigOverridePath -Scope Script
$script:ConfigOverridePath = ''
$script:Sections = @('All')

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
# C4: the Laps section does not use Get-ADDomainController, so breaking that leaves it working.
# Its own two reads are made to fail instead: the schema query and the computer query throw.
$script:SmokeLapsFail = $true
# C6: the RidPool section does not use Get-ADDomainController for its domain rows, so every read of
# CN=RID Manager$ is made to fail too.
$script:SmokeRidFail = $true

$out3 = Join-Path ([IO.Path]::GetTempPath()) ("adfa_smoke_fail_" + [guid]::NewGuid().ToString('N'))
$script:OutputPath = $out3
$script:AllDomains = $false
$result3 = Invoke-Main

Check ($null -ne $result3) 'Failure mode: Invoke-Main still returns a summary rather than dying'
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

    # C4: with no forest the Laps section asks nothing and says so in one row.
    $laps4 = @($findings4 | Where-Object { $_.Section -eq 'Windows LAPS' })
    Check (@($laps4).Count -eq 1 -and $laps4[0].Status -eq 'Not Assessed' -and $laps4[0].Detail -match 'The forest could not be read' -and $laps4[0].Detail -match 'not contactable') 'No forest: Windows LAPS is one Not Assessed row carrying the cause'
    # C5: with no forest no domain is scoped and no DC enumerated; the section says so.
    $cert4 = @($findings4 | Where-Object { $_.Section -eq 'DC Certificates' })
    Check (@($cert4).Count -ge 1 -and @($cert4 | Where-Object { $_.Status -ne 'Not Assessed' }).Count -eq 0) ("No forest: DC Certificates is present and reports nothing but Not Assessed ({0} rows)" -f @($cert4).Count)
    # C6: with no forest no domain is scoped; the section asks nothing and says so in one row.
    $rid4 = @($findings4 | Where-Object { $_.Section -eq 'RID Pool' })
    Check (@($rid4).Count -eq 1 -and $rid4[0].Status -eq 'Not Assessed' -and $rid4[0].Detail -match 'The forest could not be read' -and $rid4[0].Detail -match 'not contactable') 'No forest: RID Pool is one Not Assessed row carrying the cause'

    # The critical property: with no forest, nothing may claim to have passed.
    $passes4 = @($findings4 | Where-Object { $_.Status -eq 'Pass' })
    Check ($passes4.Count -eq 0) ("No forest: nothing reports Pass when nothing could be read ({0})" -f $passes4.Count)
    # Non-vacuity: the run really did evaluate sections rather than producing a single row.
    Check ($findings4.Count -ge 5) ("No forest: non-vacuity - sections were evaluated and degraded ({0} rows)" -f $findings4.Count)
}
Remove-Item -Recurse -Force $out4 -ErrorAction SilentlyContinue

# cleanup
Remove-Item -Recurse -Force $out2 -ErrorAction SilentlyContinue
Remove-Item -Recurse -Force $out -ErrorAction SilentlyContinue
Remove-Item Env:\ADFA_NO_AUTORUN -ErrorAction SilentlyContinue
Write-Host ""
if ($fail -gt 0) { Write-Host "SMOKE TEST FAILED ($fail)" -ForegroundColor Red; exit 1 }
Write-Host "SMOKE TEST PASSED" -ForegroundColor Green
exit 0
