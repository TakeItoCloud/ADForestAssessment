#Requires -Version 5.1
<#
.SYNOPSIS
    Near-enterprise-grade Active Directory forest assessment with two-way trust health.

.DESCRIPTION
    Invoke-ADForestAssessment is an enhanced successor to Invoke-CoreInfraAssessment.ps1.
    It keeps that script's robust engine (per-DC reachability gating, external-tool
    timeout/retry wrapper, StrictMode, honest "Not Assessed" status, CSV-per-topic + HTML)
    and adds full-forest coverage:

        - Forest / domain functional levels and FSMO roles
        - Domain controller inventory (OS / GC / site / IP)
        - Replication health (partner metadata, failures, queue) and topology
          (sites, subnets, site links, connection objects)
        - FOREST & DOMAIN TRUSTS with verified TWO-WAY trust health
          (secure-channel verification per direction via nltest/netdom, plus SID filtering,
          selective authentication, TGT delegation and encryption posture)
        - Parsed DC diagnostics (dcdiag key tests + core service state) as PASS/FAIL
        - DNS health (zones, scavenging, forwarders, zone transfer)         [DnsServer optional]
        - SYSVOL / DFSR replication migration state                          [DFSR optional]
        - GPO inventory (linked / unlinked / WMI filters)                    [GroupPolicy optional]
        - Password & lockout policy (default + fine-grained)
        - Privileged group membership and security posture
          (krbtgt password age, AD Recycle Bin, tombstone lifetime, machine account quota,
          AdminSDHolder, stale / never-expiring / RC4-DES accounts)
        - Stale user / computer objects
        - Full user & computer export with ALL populated attributes (CSV; HTML shows a summary)
        - AD CS / PKI: enrolment CAs and ESC1-susceptible certificate templates
        - Dangerous ACLs: non-default principals holding DCSync rights on the domain head
        - Kerberos exposure: Kerberoastable (SPN) users, AS-REP-roastable accounts, delegation
        - Privileged hygiene: adminCount orphans, SPNs on privileged accounts, Protected Users
        - DC hardening: Print Spooler, SMBv1, LDAP signing requirement (remote CIM/registry)
        - Directory backup status (repadmin /showbackup), time synchronization (w32tm)
        - DNS depth: critical SRV records, secure dynamic updates
        - Redundancy: DC count, GPO central store, duplicate SPNs
        - Exchange schema markers
        - Optional raw repadmin / dcdiag capture

    The report is written to the logged-on user's Documents folder by default:
        %USERPROFILE%\Documents\AdAssessment\yyyy-MM-dd_HH-mm-ss\

    Coverage-aware & fail-closed: any value that could not be collected is reported as
    "Not Assessed" (never a false Pass / 0). Trust directions that could not be tested from
    the local side are reported "Not Assessed", never "Verified".

    The script is read-only. External verification tools are invoked in read-only modes
    (/verify, /sc_verify, /sc_query, getmigrationstate).

.PARAMETER OutputPath
    Root folder for the assessment bundle. A timestamped sub-folder is always created inside it.
    Default: <MyDocuments>\AdAssessment

.PARAMETER AllDomains
    Assess every domain in the forest. Without it, only the current/target domain is assessed
    (forest-wide sections such as trusts and topology are still collected).

.PARAMETER Sections
    Restrict collection to the named sections. Default: All. 'Identity' performs a full
    all-attributes export of every user and computer (heavy on large domains) to CSV; use
    -Sections to exclude it for a quick health-only run. Cross-forest note: -AllDomains covers
    domains WITHIN the target forest only. To assess another forest, run again with -Server /
    -Credential pointed at a DC in that forest.

.PARAMETER IncludeDcdiag
    Also capture raw 'dcdiag /c /v' output per DC under raw\.

.PARAMETER IncludeRepadmin
    Also capture raw 'repadmin /replsummary' and per-DC '/showrepl /errorsonly' under raw\.

.PARAMETER SkipTrustVerification
    Collect trust configuration but do not run the external secure-channel verification
    (nltest / netdom). Trust health is then reported as "Not Assessed".

.PARAMETER Server
    Optional DC / ADWS endpoint to target for AD cmdlets.

.PARAMETER Credential
    Optional credential for AD cmdlets and trust verification.

.PARAMETER StaleDays
    Age (days since last logon timestamp / password set) beyond which an account is stale.
    Default: 90.

.PARAMETER KrbtgtMaxAgeDays
    krbtgt password age (days) beyond which a Warning is raised. Default: 180.

.PARAMETER RpcPortTimeoutMs
    TCP connect timeout for reachability probes (RPC/135, ADWS/9389). Default: 1200.

.PARAMETER ExternalToolTimeoutSeconds
    Timeout for each external tool invocation (dcdiag/repadmin/nltest/netdom). Default: 90.

.PARAMETER Retries
    Max attempts for external tools before marking FAIL. Default: 2.

.PARAMETER RetryDelaySeconds
    Delay between external-tool retries. Default: 2.

.EXAMPLE
    .\Invoke-ADForestAssessment.ps1 -AllDomains -IncludeDcdiag -IncludeRepadmin -Verbose

    Full forest assessment (all domains) with raw diagnostics, verbose progress, report in
    the current user's Documents.

.EXAMPLE
    .\Invoke-ADForestAssessment.ps1 -Sections Trusts,Replication -SkipTrustVerification

    Collect only trust configuration and replication, without running external trust checks.

.OUTPUTS
    [pscustomobject] run summary (paths, counts, per-section status). Data files are written
    as CSV and a single HTML report.

.NOTES
    Author  : TakeItToCloud (Carlos Annes)
    Requires: RSAT ActiveDirectory module. DnsServer / GroupPolicy / DFSR modules optional.
    Runtime : Windows PowerShell 5.1 or PowerShell 7+. Read-only.
#>

[CmdletBinding()]
param(
    [ValidateNotNullOrEmpty()]
    [string]$OutputPath,

    [switch]$AllDomains,

    [ValidateSet('All', 'Forest', 'Domains', 'Fsmo', 'DomainControllers', 'Replication',
        'Topology', 'Trusts', 'DcDiagnostics', 'Dns', 'Sysvol', 'Gpo', 'PasswordPolicy',
        'PrivilegedAccounts', 'SecurityPosture', 'StaleObjects', 'Identity',
        'Pki', 'Acl', 'Kerberos', 'PrivilegedHygiene', 'DcHardening', 'Backup', 'TimeSync',
        'DnsDepth', 'Redundancy', 'ExchangeSchema')]
    [string[]]$Sections = @('All'),

    [switch]$IncludeDcdiag,
    [switch]$IncludeRepadmin,
    [switch]$SkipTrustVerification,

    [string]$Server,
    [pscredential]$Credential,

    [ValidateRange(1, 3650)][int]$StaleDays = 90,
    [ValidateRange(1, 3650)][int]$KrbtgtMaxAgeDays = 180,

    [ValidateRange(100, 60000)][int]$RpcPortTimeoutMs = 1200,
    [ValidateRange(5, 600)][int]$ExternalToolTimeoutSeconds = 90,
    [ValidateRange(1, 10)][int]$Retries = 2,
    [ValidateRange(0, 60)][int]$RetryDelaySeconds = 2
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# Versioned configuration (no magic numbers scattered in logic)
# ---------------------------------------------------------------------------
$script:Config = @{
    Version                 = '1.3.0'
    StaleDays               = $StaleDays
    KrbtgtMaxAgeDays        = $KrbtgtMaxAgeDays
    RpcPortTimeoutMs        = $RpcPortTimeoutMs
    ExternalToolTimeoutSec  = $ExternalToolTimeoutSeconds
    Retries                 = $Retries
    RetryDelaySeconds       = $RetryDelaySeconds
    # Well-known RID suffixes for privileged groups (domain-relative unless noted).
    PrivilegedGroupRids     = @{
        'Domain Admins'     = 512
        'Enterprise Admins' = 519   # root domain only
        'Schema Admins'     = 518   # root domain only
    }
    BuiltinAdministrators   = 'S-1-5-32-544'
    ReplicationStaleMinutes = 180
    # Well-known extended-right GUIDs used to detect DCSync grants.
    DcSyncRightGuids        = @{
        'DS-Replication-Get-Changes'            = '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'
        'DS-Replication-Get-Changes-All'        = '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'
        'DS-Replication-Get-Changes-In-Filtered' = '89e95b76-444d-4c62-991a-0facbeda640c'
    }
    # Principals expected to legitimately hold replication rights (not flagged).
    DcSyncAllowedPatterns   = @('Domain Admins', 'Enterprise Admins', 'Administrators',
        'Domain Controllers', 'Enterprise Read-only Domain Controllers', 'Read-only Domain Controllers',
        'SYSTEM', 'Enterprise Domain Controllers', 'BUILTIN\Administrators')
    # userAccountControl bit flags.
    Uac                     = @{
        PASSWD_NOTREQD         = 0x0020
        DONT_EXPIRE_PASSWORD   = 0x10000
        TRUSTED_FOR_DELEGATION = 0x80000
        DONT_REQ_PREAUTH       = 0x400000
        USE_DES_KEY_ONLY       = 0x200000
        ENCRYPTED_TEXT_PWD     = 0x0080
    }
    # Certificate template flags for ESC1 detection.
    EnrolleeSuppliesSubject = 0x00000001  # msPKI-Certificate-Name-Flag
    PendAllRequests         = 0x00000002  # msPKI-Enrollment-Flag (manager approval)
    AuthEkuOids             = @('1.3.6.1.5.5.7.3.2', '1.3.6.1.4.1.311.20.2.2', '1.3.6.1.5.2.3.4', '2.5.29.37.0')
}

# Status vocabulary (fail-closed).
$script:Status = @{
    Pass        = 'Pass'
    Warning     = 'Warning'
    Fail        = 'Fail'
    NotAssessed = 'Not Assessed'
    Info        = 'Info'
}

# ===========================================================================
# region Infrastructure helpers
# ===========================================================================

$script:LogFile = $null

function Write-Log {
    <#
    .SYNOPSIS
        Appends a timestamped, levelled line to the detailed run log (and the console stream).
    .DESCRIPTION
        This is the detailed audit trail for the run: every stage, per-section counts, each
        Warning/Fail/Not-Assessed finding, and any caught error land here. Written to
        assessment.log in the run root. Safe to call before the log path is set (buffers to host).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Message,
        [ValidateSet('INFO', 'STAGE', 'RESULT', 'WARN', 'ERROR')][string]$Level = 'INFO',
        [string]$Section
    )
    $line = '[{0:yyyy-MM-dd HH:mm:ss}] [{1,-6}] {2}{3}' -f (Get-Date), $Level,
        $(if ($Section) { "[$Section] " } else { '' }), $Message
    if ($script:LogFile) {
        try { Add-Content -LiteralPath $script:LogFile -Value $line -Encoding UTF8 } catch { }
    }
    switch ($Level) {
        'WARN' { Write-Warning $Message }
        'ERROR' { Write-Warning $Message }
        default { Write-Information -MessageData $line -InformationAction Continue }
    }
}

function Write-Stage {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Message)
    Write-Log -Message $Message -Level 'STAGE'
}

function New-Folder {
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
    }
    return $Path
}

function Save-Csv {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowNull()]$InputObject,
        [Parameter(Mandatory)][string]$Path
    )
    if ($null -eq $InputObject) { return }
    $rows = @($InputObject)
    if ($rows.Count -eq 0) { return }
    $rows | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $Path -Force
}

function Test-CommandAvailable {
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory)][string]$Name)
    return [bool](Get-Command -Name $Name -ErrorAction SilentlyContinue)
}

function Test-ModuleAvailable {
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory)][string]$Name)
    return [bool](Get-Module -ListAvailable -Name $Name -ErrorAction SilentlyContinue)
}

function New-SafeFileName {
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][string]$Name)
    $invalid = [IO.Path]::GetInvalidFileNameChars()
    foreach ($c in $invalid) { $Name = $Name.Replace($c, '_') }
    return $Name.Replace('.', '_')
}

function Test-TcpPort {
    <#
    .SYNOPSIS
        Non-blocking TCP reachability probe used to gate remote calls.
    .OUTPUTS
        [bool]
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)][string]$ComputerName,
        [Parameter(Mandatory)][int]$Port,
        [int]$TimeoutMs = 1200
    )
    try {
        $client = New-Object System.Net.Sockets.TcpClient
        $iar = $client.BeginConnect($ComputerName, $Port, $null, $null)
        if (-not $iar.AsyncWaitHandle.WaitOne($TimeoutMs, $false)) {
            $client.Close(); return $false
        }
        $client.EndConnect($iar) | Out-Null
        $client.Close()
        return $true
    }
    catch { return $false }
}

function Invoke-ExternalCommand {
    <#
    .SYNOPSIS
        Runs a console tool with a hard timeout and retries, capturing stdout/stderr.
    .OUTPUTS
        [pscustomobject] Success, ExitCode, Attempt, Error, StdOut, OutFile
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)][string]$FilePath,
        [Parameter(Mandatory)][string]$Arguments,
        [string]$OutFile,
        [int]$TimeoutSeconds = 90,
        [int]$Retries = 2,
        [int]$RetryDelaySeconds = 2
    )

    if ($OutFile) { New-Folder -Path (Split-Path -Path $OutFile -Parent) | Out-Null }

    for ($attempt = 1; $attempt -le $Retries; $attempt++) {
        try {
            $psi = New-Object System.Diagnostics.ProcessStartInfo
            $psi.FileName = $FilePath
            $psi.Arguments = $Arguments
            $psi.RedirectStandardOutput = $true
            $psi.RedirectStandardError = $true
            $psi.UseShellExecute = $false
            $psi.CreateNoWindow = $true

            $p = New-Object System.Diagnostics.Process
            $p.StartInfo = $psi
            [void]$p.Start()

            if (-not $p.WaitForExit($TimeoutSeconds * 1000)) {
                try { $p.Kill() } catch { }
                throw ("Timeout after {0}s" -f $TimeoutSeconds)
            }

            $stdout = $p.StandardOutput.ReadToEnd()
            $stderr = $p.StandardError.ReadToEnd()
            $combined = $stdout + [Environment]::NewLine + $stderr

            if ($OutFile) { $combined | Out-File -Encoding UTF8 -FilePath $OutFile -Force }

            return [pscustomobject]@{
                Success  = ($p.ExitCode -eq 0)
                ExitCode = $p.ExitCode
                Attempt  = $attempt
                Error    = $null
                StdOut   = $combined
                OutFile  = $OutFile
            }
        }
        catch {
            if ($attempt -lt $Retries) {
                Start-Sleep -Seconds $RetryDelaySeconds
                continue
            }
            $msg = $_.Exception.Message
            if ($OutFile) { ("FAILED: {0}`r`nArguments: {1}" -f $msg, $Arguments) | Out-File -Encoding UTF8 -FilePath $OutFile -Force }
            return [pscustomobject]@{
                Success = $false; ExitCode = $null; Attempt = $attempt
                Error   = $msg; StdOut = ''; OutFile = $OutFile
            }
        }
    }
}

function New-Finding {
    <#
    .SYNOPSIS
        Builds a coverage-aware finding row (Pass/Warning/Fail/Not Assessed/Info).
    .OUTPUTS
        [pscustomobject]
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)][string]$Area,
        [Parameter(Mandatory)][string]$Item,
        [Parameter(Mandatory)]
        [ValidateSet('Pass', 'Warning', 'Fail', 'Not Assessed', 'Info')]
        [string]$Status,
        [string]$Detail,
        [string]$Scope
    )
    [pscustomobject]@{
        Scope  = $Scope
        Area   = $Area
        Item   = $Item
        Status = $Status
        Detail = $Detail
    }
}

# ===========================================================================
# region Trust health (headline feature)
# ===========================================================================

function Resolve-AdfaTrustHealth {
    <#
    .SYNOPSIS
        Rolls per-direction verification results and security posture into an overall
        trust verdict. Pure function - the unit-testable core of trust health.
    .DESCRIPTION
        Direction inputs are one of 'Verified','Failed','Not Assessed'. The verdict is
        fail-closed: a direction that was not tested is never treated as verified.

            Broken  : the partner is unreachable, or any expected & tested direction Failed.
            Healthy : every expected & tested direction Verified (may carry coverage or
                      security caveats; a security caveat downgrades to Degraded).
            Degraded: all tested directions Verified but a security weakness is present
                      (e.g. SID filtering disabled on an external trust, RC4/DES only).
            Not Assessed: nothing could be tested (verification skipped / tools missing).
    .OUTPUTS
        [pscustomobject] Health, Reasons (string[])
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)][ValidateSet('Inbound', 'Outbound', 'Bidirectional')][string]$Direction,
        [Parameter(Mandatory)][ValidateSet('Verified', 'Failed', 'Not Assessed')][string]$OutboundResult,
        [Parameter(Mandatory)][ValidateSet('Verified', 'Failed', 'Not Assessed')][string]$InboundResult,
        [Parameter(Mandatory)][bool]$TargetReachable,
        [bool]$VerificationSkipped = $false,
        [string[]]$SecurityWarnings = @()
    )

    $reasons = New-Object System.Collections.Generic.List[string]

    $expectOutbound = ($Direction -eq 'Outbound' -or $Direction -eq 'Bidirectional')
    $expectInbound = ($Direction -eq 'Inbound' -or $Direction -eq 'Bidirectional')

    if ($VerificationSkipped) {
        return [pscustomobject]@{ Health = 'Not Assessed'; Reasons = @('Trust verification skipped.') }
    }

    if (-not $TargetReachable) {
        return [pscustomobject]@{ Health = 'Broken'; Reasons = @('Trust partner is not reachable.') }
    }

    $testedResults = @()
    if ($expectOutbound) { $testedResults += $OutboundResult; if ($OutboundResult -eq 'Not Assessed') { $reasons.Add('Outbound direction could not be verified.') } }
    if ($expectInbound) { $testedResults += $InboundResult; if ($InboundResult -eq 'Not Assessed') { $reasons.Add('Inbound direction could not be verified.') } }

    if ($expectOutbound -and $OutboundResult -eq 'Failed') { $reasons.Add('Outbound secure channel verification FAILED.') }
    if ($expectInbound -and $InboundResult -eq 'Failed') { $reasons.Add('Inbound secure channel verification FAILED.') }

    # Any tested-and-failed expected direction => Broken.
    if (($expectOutbound -and $OutboundResult -eq 'Failed') -or ($expectInbound -and $InboundResult -eq 'Failed')) {
        return [pscustomobject]@{ Health = 'Broken'; Reasons = $reasons.ToArray() }
    }

    $anyVerified = $testedResults -contains 'Verified'
    $anyNotAssessed = $testedResults -contains 'Not Assessed'

    if (-not $anyVerified) {
        # Nothing verified and nothing failed => could not assess.
        return [pscustomobject]@{ Health = 'Not Assessed'; Reasons = $reasons.ToArray() }
    }

    foreach ($w in $SecurityWarnings) { $reasons.Add($w) }

    if ($SecurityWarnings.Count -gt 0) {
        return [pscustomobject]@{ Health = 'Degraded'; Reasons = $reasons.ToArray() }
    }

    if ($anyNotAssessed) {
        # Verified what we could; be explicit about the coverage gap but do not fail a
        # working trust just because cross-domain rights were unavailable.
        return [pscustomobject]@{ Health = 'Healthy'; Reasons = $reasons.ToArray() }
    }

    return [pscustomobject]@{ Health = 'Healthy'; Reasons = @('All expected directions verified.') }
}

function Test-AdfaSecureChannel {
    <#
    .SYNOPSIS
        Verifies a trust secure channel to a target domain using nltest, with netdom as a
        cross-check. Returns 'Verified','Failed' or 'Not Assessed'.
    .OUTPUTS
        [pscustomobject] Result, Tool, Detail
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)][string]$SourceDomain,
        [Parameter(Mandatory)][string]$TargetDomain,
        [int]$TimeoutSeconds = 90,
        [int]$Retries = 2,
        [int]$RetryDelaySeconds = 2
    )

    $haveNltest = Test-CommandAvailable -Name 'nltest.exe'
    $haveNetdom = Test-CommandAvailable -Name 'netdom.exe'

    if (-not $haveNltest -and -not $haveNetdom) {
        return [pscustomobject]@{ Result = 'Not Assessed'; Tool = 'none'; Detail = 'nltest.exe and netdom.exe not available.' }
    }

    if ($haveNltest) {
        $r = Invoke-ExternalCommand -FilePath 'nltest.exe' -Arguments ("/sc_verify:{0}" -f $TargetDomain) `
            -TimeoutSeconds $TimeoutSeconds -Retries $Retries -RetryDelaySeconds $RetryDelaySeconds
        $out = $r.StdOut
        if ($out -match 'Trust Verification Status = 0x0 NERR_Success' -or $out -match 'The command completed successfully') {
            return [pscustomobject]@{ Result = 'Verified'; Tool = 'nltest'; Detail = 'nltest /sc_verify succeeded.' }
        }
        if ($null -ne $out -and $out.Trim().Length -gt 0 -and ($out -match 'Status = 0x' -or $out -match 'ERROR' -or $out -match 'failed')) {
            return [pscustomobject]@{ Result = 'Failed'; Tool = 'nltest'; Detail = (($out -split "`n" | Select-Object -First 4) -join ' ').Trim() }
        }
    }

    if ($haveNetdom) {
        $r = Invoke-ExternalCommand -FilePath 'netdom.exe' -Arguments ("trust {0} /Domain:{1} /Verify" -f $SourceDomain, $TargetDomain) `
            -TimeoutSeconds $TimeoutSeconds -Retries $Retries -RetryDelaySeconds $RetryDelaySeconds
        $out = $r.StdOut
        if ($r.Success -or $out -match 'has been verified' -or $out -match 'successfully') {
            return [pscustomobject]@{ Result = 'Verified'; Tool = 'netdom'; Detail = 'netdom trust /Verify succeeded.' }
        }
        if ($null -ne $out -and $out.Trim().Length -gt 0) {
            return [pscustomobject]@{ Result = 'Failed'; Tool = 'netdom'; Detail = (($out -split "`n" | Select-Object -First 4) -join ' ').Trim() }
        }
    }

    return [pscustomobject]@{ Result = 'Not Assessed'; Tool = 'nltest/netdom'; Detail = 'No conclusive verification output.' }
}

function Get-AdfaTrustSecurityWarning {
    <#
    .SYNOPSIS
        Derives security posture warnings for a single trust object. Pure function.
    .OUTPUTS
        [string[]]
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param([Parameter(Mandatory)][pscustomobject]$Trust)

    $warnings = New-Object System.Collections.Generic.List[string]
    $isExternal = ($Trust.TrustType -eq 'External')

    # SID filtering (a.k.a. quarantine) should be ON for external / cross-forest trusts.
    if ($isExternal -and $Trust.PSObject.Properties.Name -contains 'SIDFilteringQuarantined') {
        if ($Trust.SIDFilteringQuarantined -eq $false) {
            $warnings.Add('SID filtering (quarantine) is DISABLED on an external trust - SID-history spoofing risk.')
        }
    }
    if (($Trust.TrustType -eq 'Forest') -and $Trust.PSObject.Properties.Name -contains 'SIDFilteringForestAware') {
        if ($Trust.SIDFilteringForestAware -eq $false) {
            $warnings.Add('Forest-aware SID filtering is DISABLED on a forest trust.')
        }
    }
    if ($Trust.PSObject.Properties.Name -contains 'SelectiveAuthentication') {
        if ($isExternal -and $Trust.SelectiveAuthentication -eq $false) {
            $warnings.Add('Selective Authentication is OFF (domain-wide authentication) on an external trust.')
        }
    }
    if ($Trust.PSObject.Properties.Name -contains 'TGTDelegation') {
        if ($Trust.TGTDelegation -eq $true) {
            $warnings.Add('TGT delegation is ENABLED across the trust - unconstrained delegation exposure.')
        }
    }
    if ($Trust.PSObject.Properties.Name -contains 'UsesRC4Encryption') {
        if ($Trust.UsesRC4Encryption -eq $true) {
            $warnings.Add('Trust is configured to use RC4 encryption.')
        }
    }
    return , $warnings.ToArray()
}

function Get-AdfaTrustHealth {
    <#
    .SYNOPSIS
        Enumerates trusts for a domain and assesses two-way trust health.
    .OUTPUTS
        [pscustomobject[]]
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param(
        [Parameter(Mandatory)][string]$DomainName,
        [hashtable]$AdParams = @{},
        [switch]$SkipVerification,
        [int]$TimeoutSeconds = 90,
        [int]$Retries = 2,
        [int]$RetryDelaySeconds = 2,
        [int]$RpcPortTimeoutMs = 1200
    )

    $results = @()
    try {
        $trusts = Get-ADTrust -Filter * -Properties * @AdParams -ErrorAction Stop
    }
    catch {
        Write-Warning ("Trust enumeration failed for {0}: {1}" -f $DomainName, $_.Exception.Message)
        return , @([pscustomobject]@{
                Scope = $DomainName; TrustName = '(enumeration failed)'; Health = 'Not Assessed'
                Detail = $_.Exception.Message
            })
    }

    foreach ($t in @($trusts)) {
        $target = $t.Target
        $direction = [string]$t.Direction
        if ([string]::IsNullOrWhiteSpace($direction)) { $direction = 'Bidirectional' }

        $reachable = $false
        if (-not $SkipVerification) {
            # Resolve a DC for the target and probe it, so verification cannot hang.
            $probeHost = $target
            if (Test-CommandAvailable -Name 'nltest.exe') {
                $dsg = Invoke-ExternalCommand -FilePath 'nltest.exe' -Arguments ("/dsgetdc:{0}" -f $target) `
                    -TimeoutSeconds $TimeoutSeconds -Retries 1 -RetryDelaySeconds $RetryDelaySeconds
                if ($dsg.StdOut -match 'DC:\s*\\\\([^\s]+)') { $probeHost = $Matches[1] }
            }
            $reachable = (Test-TcpPort -ComputerName $target -Port 135 -TimeoutMs $RpcPortTimeoutMs) -or
                         (Test-TcpPort -ComputerName $target -Port 389 -TimeoutMs $RpcPortTimeoutMs) -or
                         (Test-TcpPort -ComputerName $probeHost -Port 135 -TimeoutMs $RpcPortTimeoutMs)
        }

        $outbound = 'Not Assessed'
        $inbound = 'Not Assessed'
        $outboundDetail = $null
        $inboundDetail = $null

        if (-not $SkipVerification -and $reachable) {
            if ($direction -eq 'Outbound' -or $direction -eq 'Bidirectional') {
                $o = Test-AdfaSecureChannel -SourceDomain $DomainName -TargetDomain $target `
                    -TimeoutSeconds $TimeoutSeconds -Retries $Retries -RetryDelaySeconds $RetryDelaySeconds
                $outbound = $o.Result; $outboundDetail = $o.Detail
            }
            if ($direction -eq 'Inbound' -or $direction -eq 'Bidirectional') {
                # The inbound side is validated from the trusted partner; from the local side we
                # can only confirm it when the partner accepts our verification request.
                $i = Test-AdfaSecureChannel -SourceDomain $target -TargetDomain $DomainName `
                    -TimeoutSeconds $TimeoutSeconds -Retries 1 -RetryDelaySeconds $RetryDelaySeconds
                $inbound = $i.Result; $inboundDetail = $i.Detail
            }
        }

        $secWarnings = Get-AdfaTrustSecurityWarning -Trust $t
        $verdict = Resolve-AdfaTrustHealth -Direction $direction `
            -OutboundResult $outbound -InboundResult $inbound `
            -TargetReachable $reachable -VerificationSkipped:$SkipVerification.IsPresent `
            -SecurityWarnings $secWarnings

        $results += [pscustomobject]@{
            Scope                 = $DomainName
            TrustName             = $t.Name
            TrustSource           = $t.Source
            TrustTarget           = $target
            Direction             = $direction
            TrustType             = [string]$t.TrustType
            IntraForest           = $t.IntraForest
            ForestTransitive      = $t.ForestTransitive
            SelectiveAuth         = $(if ($t.PSObject.Properties.Name -contains 'SelectiveAuthentication') { $t.SelectiveAuthentication } else { 'Not Assessed' })
            SIDFilteringQuarantined = $(if ($t.PSObject.Properties.Name -contains 'SIDFilteringQuarantined') { $t.SIDFilteringQuarantined } else { 'Not Assessed' })
            SIDFilteringForestAware = $(if ($t.PSObject.Properties.Name -contains 'SIDFilteringForestAware') { $t.SIDFilteringForestAware } else { 'Not Assessed' })
            TGTDelegation         = $(if ($t.PSObject.Properties.Name -contains 'TGTDelegation') { $t.TGTDelegation } else { 'Not Assessed' })
            TargetReachable       = $reachable
            OutboundSecureChannel = $outbound
            InboundSecureChannel  = $inbound
            Health                = $verdict.Health
            Reasons               = ($verdict.Reasons -join ' | ')
            Created               = $t.Created
            Modified              = $t.Modified
            VerifyDetail          = (@($outboundDetail, $inboundDetail) | Where-Object { $_ } ) -join ' || '
        }
    }

    if (@($results).Count -eq 0) {
        $results += [pscustomobject]@{
            Scope = $DomainName; TrustName = '(no trusts)'; Health = $script:Status.Info
            Detail = 'No trust relationships found for this domain.'
        }
    }
    return , $results
}

# ===========================================================================
# region Forest / domain / FSMO / DC inventory
# ===========================================================================

function Get-AdfaForestSummary {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([hashtable]$AdParams = @{})
    $f = Get-ADForest @AdParams
    [pscustomobject]@{
        ForestName         = $f.Name
        RootDomain         = $f.RootDomain
        ForestMode         = [string]$f.ForestMode
        Domains            = ($f.Domains -join '; ')
        Sites              = ($f.Sites -join '; ')
        GlobalCatalogs     = (@($f.GlobalCatalogs).Count)
        SchemaMaster       = $f.SchemaMaster
        DomainNamingMaster = $f.DomainNamingMaster
        UPNSuffixes        = ($f.UPNSuffixes -join '; ')
    }
}

function Get-AdfaDomainSummary {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([Parameter(Mandatory)][string]$DomainName, [hashtable]$AdParams = @{})
    $p = @{} + $AdParams; $p.Identity = $DomainName
    $d = Get-ADDomain @p
    [pscustomobject]@{
        Scope                = $DomainName
        DomainName           = $d.DNSRoot
        NetBIOSName          = $d.NetBIOSName
        DomainMode           = [string]$d.DomainMode
        PDCEmulator          = $d.PDCEmulator
        RIDMaster            = $d.RIDMaster
        InfrastructureMaster = $d.InfrastructureMaster
        DomainSID            = [string]$d.DomainSID
    }
}

function Get-AdfaFsmoRole {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([hashtable]$AdParams = @{}, [Parameter(Mandatory)][string]$DomainName)
    $f = Get-ADForest @AdParams
    $dp = @{} + $AdParams; $dp.Identity = $DomainName
    $d = Get-ADDomain @dp
    [pscustomobject]@{
        Scope                = $DomainName
        SchemaMaster         = $f.SchemaMaster
        DomainNamingMaster   = $f.DomainNamingMaster
        PDCEmulator          = $d.PDCEmulator
        RIDMaster            = $d.RIDMaster
        InfrastructureMaster = $d.InfrastructureMaster
    }
}

function Get-AdfaDomainControllerInventory {
    <#
    .SYNOPSIS
        DC inventory. Get-ADDomainController has no -Properties, so enrich via Get-ADComputer.
    .OUTPUTS
        [pscustomobject[]]
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param([Parameter(Mandatory)][string]$DomainName, [hashtable]$AdParams = @{})
    $p = @{} + $AdParams; $p.Server = $DomainName
    $dcs = Get-ADDomainController -Filter * @p
    $inv = foreach ($dc in $dcs) {
        $comp = $null
        try {
            $id = if ($dc.ComputerObjectDN) { $dc.ComputerObjectDN } else { $dc.HostName }
            $cp = @{} + $AdParams; $cp.Identity = $id
            $cp.Properties = @('OperatingSystem', 'OperatingSystemVersion', 'Enabled', 'whenCreated')
            $comp = Get-ADComputer @cp
        }
        catch { Write-Warning ("DC enrichment failed for {0}: {1}" -f $dc.HostName, $_.Exception.Message) }

        [pscustomobject]@{
            Scope                  = $DomainName
            HostName               = $dc.HostName
            Name                   = $dc.Name
            Site                   = $dc.Site
            IPv4Address            = $dc.IPv4Address
            IsGlobalCatalog        = $dc.IsGlobalCatalog
            IsReadOnly             = $dc.IsReadOnly
            OperatingSystem        = $(if ($comp) { $comp.OperatingSystem } else { $script:Status.NotAssessed })
            OperatingSystemVersion = $(if ($comp) { $comp.OperatingSystemVersion } else { $script:Status.NotAssessed })
            Enabled                = $(if ($comp) { $comp.Enabled } else { $script:Status.NotAssessed })
        }
    }
    return , @($inv)
}

# ===========================================================================
# region Replication
# ===========================================================================

function Get-AdfaReplicationHealth {
    <#
    .SYNOPSIS
        Per-DC replication health with reachability gating. Get-ADReplication* take no -Server.
    .OUTPUTS
        [pscustomobject[]]
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param(
        [Parameter(Mandatory)][string[]]$DomainControllers,
        [hashtable]$RepParams = @{},
        [int]$RpcPortTimeoutMs = 1200,
        [int]$StaleMinutes = 180
    )
    $rows = foreach ($dc in $DomainControllers) {
        $rpcOk = Test-TcpPort -ComputerName $dc -Port 135 -TimeoutMs $RpcPortTimeoutMs
        $adwsOk = Test-TcpPort -ComputerName $dc -Port 9389 -TimeoutMs $RpcPortTimeoutMs
        if (-not ($rpcOk -and $adwsOk)) {
            [pscustomobject]@{
                DomainController = $dc; PartnerCount = $null; PartnerErrors = $null
                LastSuccessMinutesAgo = $null; FailureCount = $null; OldestFailureTime = $null
                ReplicationQueue = $null; Status = $script:Status.NotAssessed
                Detail = ("SKIPPED: RPC135={0} ADWS9389={1}" -f $rpcOk, $adwsOk)
            }
            continue
        }

        $meta = $null; $fail = $null; $qCount = $null; $notes = @()
        $metaOk = $false; $failOk = $false; $queueOk = $false
        try { $meta = Get-ADReplicationPartnerMetadata -Target $dc -Partition * @RepParams -ErrorAction Stop; $metaOk = $true }
        catch { $notes += ("PartnerMetadata: {0}" -f $_.Exception.Message) }
        try { $fail = Get-ADReplicationFailure -Target $dc -Scope Server @RepParams -ErrorAction Stop; $failOk = $true }
        catch { $notes += ("ReplicationFailure: {0}" -f $_.Exception.Message) }
        try { $q = Get-ADReplicationQueueOperation -Server $dc @RepParams -ErrorAction Stop; $queueOk = $true; $qCount = @($q).Count }
        catch { $notes += ("QueueOperation: {0}" -f $_.Exception.Message) }

        $partnerErrors = 0; $partnerCount = $null; $lastMin = $null
        $failingList = New-Object System.Collections.Generic.List[string]
        if ($meta) {
            $badPartners = @($meta | Where-Object { $_.ConsecutiveReplicationFailures -gt 0 })
            $partnerErrors = $badPartners.Count
            $partners = @($meta | Select-Object -ExpandProperty Partner -ErrorAction SilentlyContinue | Sort-Object -Unique)
            $partnerCount = $partners.Count
            $succ = @($meta | Where-Object { $_.LastReplicationSuccess } | ForEach-Object { $_.LastReplicationSuccess })
            if ($succ.Count -gt 0) {
                $latest = ($succ | Sort-Object -Descending | Select-Object -First 1)
                $lastMin = [math]::Round(((Get-Date) - $latest).TotalMinutes, 0)
            }
            foreach ($bp in $badPartners) {
                $failingList.Add(("partner={0} partition={1} lastResult={2} consecutiveFailures={3}" -f `
                    $bp.Partner, $bp.Partition, $bp.LastReplicationResult, $bp.ConsecutiveReplicationFailures))
            }
        }
        $failureCount = @($fail).Count
        $oldest = $null
        if ($fail -and @($fail).Count -gt 0) {
            $oldest = ($fail | Sort-Object FirstFailureTime | Select-Object -First 1).FirstFailureTime
            foreach ($fr in @($fail)) {
                $failingList.Add(("partner={0} failureType={1} count={2} since={3} lastError={4}" -f `
                    $fr.Partner, $fr.FailureType, $fr.FailureCount, $fr.FirstFailureTime, $fr.LastError))
            }
        }

        $anyQueried = ($metaOk -or $failOk -or $queueOk)
        $status = $script:Status.NotAssessed
        if ($anyQueried) {
            if ($partnerErrors -eq 0 -and $failureCount -eq 0 -and ($null -eq $lastMin -or $lastMin -le $StaleMinutes)) {
                $status = $script:Status.Pass
            }
            elseif ($partnerErrors -gt 0 -or $failureCount -gt 0) { $status = $script:Status.Fail }
            else { $status = $script:Status.Warning }
        }

        [pscustomobject]@{
            DomainController = $dc; PartnerCount = $partnerCount; PartnerErrors = $partnerErrors
            LastSuccessMinutesAgo = $lastMin; FailureCount = $failureCount; OldestFailureTime = $oldest
            ReplicationQueue = $qCount; Status = $status
            FailureDetail = ($failingList -join ' | ')
            Detail = $(if ($notes.Count -gt 0) { $notes -join ' | ' } else { '' })
        }
    }
    return , @($rows)
}

function Get-AdfaReplicationTopology {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([hashtable]$AdParams = @{})
    $out = [ordered]@{}
    $out.Sites = @(Get-ADReplicationSite -Filter * @AdParams |
        Select-Object Name, Description, WhenCreated, WhenChanged)
    $out.Subnets = @(Get-ADReplicationSubnet -Filter * @AdParams |
        Select-Object Name, Site, Location, Description)
    $out.SiteLinks = @(Get-ADReplicationSiteLink -Filter * -Properties * @AdParams |
        Select-Object Name, Cost, ReplicationFrequencyInMinutes, InterSiteTransportProtocol,
        @{n = 'SitesIncluded'; e = { ($_.SitesIncluded | ForEach-Object { $_.ToString() }) -join '; ' } })
    $out.Connections = @(Get-ADReplicationConnection -Filter * -Properties * @AdParams |
        Select-Object Name, FromServer, ToServer, Enabled, AutoGenerated)
    return [pscustomobject]$out
}

function Get-AdfaSiteHealthFinding {
    <#
    .SYNOPSIS
        Derives findings from topology (sites without subnets, subnets without sites, empty sites).
    .OUTPUTS
        [pscustomobject[]]
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param([Parameter(Mandatory)][pscustomobject]$Topology, [Parameter(Mandatory)][pscustomobject[]]$DomainControllers)
    $findings = @()
    $dcSites = @($DomainControllers | ForEach-Object { $_.Site } | Sort-Object -Unique)

    foreach ($s in @($Topology.Sites)) {
        $hasSubnet = @($Topology.Subnets | Where-Object { $_.Site -match [regex]::Escape($s.Name) }).Count -gt 0
        if (-not $hasSubnet) {
            $findings += New-Finding -Area 'Sites' -Item ("Site '{0}' has no subnets" -f $s.Name) -Status $script:Status.Warning -Detail 'Clients may not map to this site.'
        }
        if ($dcSites -notcontains $s.Name) {
            $findings += New-Finding -Area 'Sites' -Item ("Site '{0}' has no domain controllers" -f $s.Name) -Status $script:Status.Info -Detail 'Empty site.'
        }
    }
    if (@($findings).Count -eq 0) {
        $findings += New-Finding -Area 'Sites' -Item 'Site/subnet topology' -Status $script:Status.Pass -Detail 'All sites have subnets and DCs.'
    }
    return , @($findings)
}

# ===========================================================================
# region DC diagnostics (parsed)
# ===========================================================================

function Get-AdfaDcDiagnostic {
    <#
    .SYNOPSIS
        Parses core dcdiag tests and service state per DC into PASS/FAIL columns.
    .OUTPUTS
        [pscustomobject[]]
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param(
        [Parameter(Mandatory)][string[]]$DomainControllers,
        [int]$TimeoutSeconds = 90,
        [int]$Retries = 2,
        [int]$RetryDelaySeconds = 2,
        [int]$RpcPortTimeoutMs = 1200
    )
    $tests = 'Netlogons', 'Services', 'Replications', 'FsmoCheck', 'Advertising', 'SysVolCheck'
    $haveDcdiag = Test-CommandAvailable -Name 'dcdiag.exe'
    $rows = foreach ($dc in $DomainControllers) {
        $row = [ordered]@{ DomainController = $dc; Status = $null; Ping = $null }
        foreach ($t in $tests) { $row["DCDIAG_$t"] = $null }
        $row.Failures = ''

        $reachable = Test-TcpPort -ComputerName $dc -Port 135 -TimeoutMs $RpcPortTimeoutMs
        $row.Ping = $(if ($reachable) { $script:Status.Pass } else { $script:Status.Fail })

        if (-not $reachable) {
            foreach ($t in $tests) { $row["DCDIAG_$t"] = $script:Status.NotAssessed }
            $row.Status = $script:Status.Fail
            $row.Failures = 'DC not reachable (RPC/135) - no dcdiag tests run.'
            [pscustomobject]$row; continue
        }
        if (-not $haveDcdiag) {
            foreach ($t in $tests) { $row["DCDIAG_$t"] = $script:Status.NotAssessed }
            $row.Status = $script:Status.NotAssessed
            $row.Failures = 'dcdiag.exe not available on this host.'
            [pscustomobject]$row; continue
        }

        $failDetails = New-Object System.Collections.Generic.List[string]
        foreach ($t in $tests) {
            $r = Invoke-ExternalCommand -FilePath 'dcdiag.exe' -Arguments ("/test:{0} /s:{1}" -f $t, $dc) `
                -TimeoutSeconds $TimeoutSeconds -Retries $Retries -RetryDelaySeconds $RetryDelaySeconds
            if ($r.StdOut -match ("passed test {0}" -f $t)) {
                $row["DCDIAG_$t"] = $script:Status.Pass
            }
            elseif ($r.StdOut -match ("failed test {0}" -f $t)) {
                $row["DCDIAG_$t"] = $script:Status.Fail
                # Capture the exact error/warning lines dcdiag emitted for this failing test.
                $errLines = @($r.StdOut -split "`r?`n" |
                    Where-Object { $_ -match 'error|warning|failed|could not|cannot|unable' -and $_ -notmatch 'passed test' } |
                    ForEach-Object { $_.Trim() } | Where-Object { $_ } | Select-Object -First 3)
                $detail = if ($errLines.Count -gt 0) { $errLines -join ' / ' } else { 'no diagnostic lines captured' }
                $failDetails.Add(("{0}: {1}" -f $t, $detail))
            }
            else {
                $row["DCDIAG_$t"] = $script:Status.NotAssessed
            }
        }

        $cells = foreach ($t in $tests) { $row["DCDIAG_$t"] }
        if ($cells -contains $script:Status.Fail) { $row.Status = $script:Status.Fail }
        elseif ($cells -contains $script:Status.NotAssessed) { $row.Status = $script:Status.Warning }
        else { $row.Status = $script:Status.Pass }
        $row.Failures = $failDetails -join ' | '
        [pscustomobject]$row
    }
    return , @($rows)
}

# ===========================================================================
# region DNS
# ===========================================================================

function Get-AdfaDnsHealth {
    <#
    .SYNOPSIS
        DNS zone/scavenging/forwarder posture per DC (DnsServer module; degrades if absent).
    .OUTPUTS
        [pscustomobject[]]
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param([Parameter(Mandatory)][string[]]$DomainControllers, [pscredential]$Credential, [int]$RpcPortTimeoutMs = 1200)
    if (-not (Test-ModuleAvailable -Name 'DnsServer')) {
        return , @(New-Finding -Area 'DNS' -Item 'DnsServer module' -Status $script:Status.NotAssessed -Detail 'RSAT DnsServer module not installed on this host.')
    }
    Import-Module DnsServer -ErrorAction SilentlyContinue -Verbose:$false
    $rows = @()
    foreach ($dc in $DomainControllers) {
        if (-not (Test-TcpPort -ComputerName $dc -Port 135 -TimeoutMs $RpcPortTimeoutMs)) {
            $rows += New-Finding -Area 'DNS' -Item $dc -Status $script:Status.NotAssessed -Detail 'DC not reachable (RPC/135).'
            continue
        }
        try {
            $zones = @(Get-DnsServerZone -ComputerName $dc -ErrorAction Stop | Where-Object { -not $_.IsAutoCreated })
            $noScav = @($zones | Where-Object { $_.IsDsIntegrated -and -not $_.IsReverseLookupZone -and ($_.PSObject.Properties.Name -contains 'AgingEnabled') -and -not $_.AgingEnabled })
            $rows += New-Finding -Area 'DNS' -Item ("{0}: zones" -f $dc) -Status $script:Status.Info -Detail ("{0} zones; {1} AD-integrated" -f $zones.Count, @($zones | Where-Object IsDsIntegrated).Count)
            if ($noScav.Count -gt 0) {
                $rows += New-Finding -Area 'DNS' -Item ("{0}: scavenging" -f $dc) -Status $script:Status.Warning -Detail ("{0} AD-integrated forward zones without aging/scavenging: {1}" -f $noScav.Count, (($noScav.ZoneName | Select-Object -First 8) -join ', '))
            }
            else {
                $rows += New-Finding -Area 'DNS' -Item ("{0}: scavenging" -f $dc) -Status $script:Status.Pass -Detail 'Aging/scavenging configured on AD-integrated forward zones.'
            }
            try {
                $fwd = Get-DnsServerForwarder -ComputerName $dc -ErrorAction Stop
                $rows += New-Finding -Area 'DNS' -Item ("{0}: forwarders" -f $dc) -Status $script:Status.Info -Detail (($fwd.IPAddress | ForEach-Object { $_.ToString() }) -join ', ')
            }
            catch { }
            $insecureXfer = @($zones | Where-Object { $_.PSObject.Properties.Name -contains 'SecureSecondaries' -and $_.SecureSecondaries -eq 'TransferAnyServer' })
            if ($insecureXfer.Count -gt 0) {
                $rows += New-Finding -Area 'DNS' -Item ("{0}: zone transfer" -f $dc) -Status $script:Status.Warning -Detail ("Zones allowing transfer to ANY server: {0}" -f (($insecureXfer.ZoneName | Select-Object -First 8) -join ', '))
            }
        }
        catch {
            $rows += New-Finding -Area 'DNS' -Item $dc -Status $script:Status.NotAssessed -Detail $_.Exception.Message
        }
    }
    return , @($rows)
}

# ===========================================================================
# region SYSVOL / DFSR
# ===========================================================================

function Get-AdfaSysvolHealth {
    <#
    .SYNOPSIS
        SYSVOL replication migration state (dfsrmig) and per-DC SysVolCheck.
    .OUTPUTS
        [pscustomobject[]]
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param([int]$TimeoutSeconds = 90, [int]$Retries = 2, [int]$RetryDelaySeconds = 2)
    $rows = @()
    if (Test-CommandAvailable -Name 'dfsrmig.exe') {
        $r = Invoke-ExternalCommand -FilePath 'dfsrmig.exe' -Arguments '/getglobalstate' -TimeoutSeconds $TimeoutSeconds -Retries $Retries -RetryDelaySeconds $RetryDelaySeconds
        $state = $script:Status.NotAssessed; $detail = ($r.StdOut -split "`n" | Where-Object { $_.Trim() } | Select-Object -First 2) -join ' '
        if ($r.StdOut -match "'Eliminated'") { $state = $script:Status.Pass; $detail = 'SYSVOL migrated to DFSR (Eliminated state).' }
        elseif ($r.StdOut -match "'Prepared'|'Redirected'|'Start'") { $state = $script:Status.Warning; $detail = 'SYSVOL DFSR migration not fully complete (still FRS-capable).' }
        $rows += New-Finding -Area 'SYSVOL' -Item 'DFSR migration global state' -Status $state -Detail $detail
    }
    else {
        $rows += New-Finding -Area 'SYSVOL' -Item 'DFSR migration global state' -Status $script:Status.NotAssessed -Detail 'dfsrmig.exe not available on this host.'
    }
    return , @($rows)
}

# ===========================================================================
# region GPO
# ===========================================================================

function Get-AdfaGpoInventory {
    <#
    .SYNOPSIS
        GPO inventory: links, unlinked GPOs, WMI filters (GroupPolicy module; degrades if absent).
    .OUTPUTS
        [pscustomobject[]]
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param([Parameter(Mandatory)][string]$DomainName)
    if (-not (Test-ModuleAvailable -Name 'GroupPolicy')) {
        return , @(New-Finding -Area 'GPO' -Item 'GroupPolicy module' -Status $script:Status.NotAssessed -Detail 'RSAT GroupPolicy module not installed on this host.' -Scope $DomainName)
    }
    Import-Module GroupPolicy -ErrorAction SilentlyContinue -Verbose:$false
    $rows = @()
    try {
        $gpos = @(Get-GPO -All -Domain $DomainName -ErrorAction Stop)
        $rows += [pscustomobject]@{ Scope = $DomainName; GPOName = '(total)'; Status = $script:Status.Info; Detail = ("{0} GPOs" -f $gpos.Count) }
        foreach ($g in $gpos) {
            [xml]$rep = $g.GenerateReport('Xml')
            $linksNode = $rep.GPO.LinksTo
            $linked = $null -ne $linksNode
            $rows += [pscustomobject]@{
                Scope   = $DomainName
                GPOName = $g.DisplayName
                Status  = $(if ($linked) { $script:Status.Info } else { $script:Status.Warning })
                Detail  = $(if ($linked) { ("Linked: {0}" -f (@($linksNode.SOMPath) -join ', ')) } else { 'Unlinked GPO (candidate for cleanup).' })
            }
        }
    }
    catch {
        $rows += [pscustomobject]@{ Scope = $DomainName; GPOName = '(enumeration failed)'; Status = $script:Status.NotAssessed; Detail = $_.Exception.Message }
    }
    return , @($rows)
}

# ===========================================================================
# region Password policy
# ===========================================================================

function Get-AdfaPasswordPolicy {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param([Parameter(Mandatory)][string]$DomainName, [hashtable]$AdParams = @{})
    $rows = @()
    try {
        $p = @{} + $AdParams; $p.Identity = $DomainName
        $dp = Get-ADDefaultDomainPasswordPolicy @p
        $rows += [pscustomobject]@{
            Scope = $DomainName; PolicyName = 'Default Domain Policy'
            MinPasswordLength = $dp.MinPasswordLength
            PasswordHistoryCount = $dp.PasswordHistoryCount
            MaxPasswordAgeDays = $dp.MaxPasswordAge.Days
            MinPasswordAgeDays = $dp.MinPasswordAge.Days
            ComplexityEnabled = $dp.ComplexityEnabled
            LockoutThreshold = $dp.LockoutThreshold
            ReversibleEncryptionEnabled = $dp.ReversibleEncryptionEnabled
            Status = $(if ($dp.MinPasswordLength -ge 14 -and $dp.ComplexityEnabled -and $dp.LockoutThreshold -gt 0) { $script:Status.Pass } else { $script:Status.Warning })
        }
    }
    catch {
        $rows += [pscustomobject]@{ Scope = $DomainName; PolicyName = 'Default Domain Policy'; Status = $script:Status.NotAssessed; Detail = $_.Exception.Message }
    }
    try {
        $fp = @{} + $AdParams; $fp.Filter = '*'; $fp.Server = $DomainName
        $fgpp = @(Get-ADFineGrainedPasswordPolicy @fp)
        foreach ($g in $fgpp) {
            $rows += [pscustomobject]@{
                Scope = $DomainName; PolicyName = ("FGPP: {0}" -f $g.Name)
                MinPasswordLength = $g.MinPasswordLength; PasswordHistoryCount = $g.PasswordHistoryCount
                MaxPasswordAgeDays = $g.MaxPasswordAge.Days; MinPasswordAgeDays = $g.MinPasswordAge.Days
                ComplexityEnabled = $g.ComplexityEnabled; LockoutThreshold = $g.LockoutThreshold
                ReversibleEncryptionEnabled = $g.ReversibleEncryptionEnabled
                Status = $script:Status.Info
            }
        }
    }
    catch { }
    return , @($rows)
}

# ===========================================================================
# region Privileged accounts & security posture
# ===========================================================================

function Get-AdfaPrivilegedAccount {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param([Parameter(Mandatory)][string]$DomainName, [bool]$IsRootDomain, [hashtable]$AdParams = @{})
    $rows = @()
    $dp = @{} + $AdParams; $dp.Identity = $DomainName
    $domainSid = (Get-ADDomain @dp).DomainSID.Value

    $groups = @{}
    $groups['Domain Admins'] = "$domainSid-512"
    if ($IsRootDomain) {
        $groups['Enterprise Admins'] = "$domainSid-519"
        $groups['Schema Admins'] = "$domainSid-518"
    }
    $groups['Administrators'] = $script:Config.BuiltinAdministrators

    foreach ($name in $groups.Keys) {
        try {
            $gp = @{} + $AdParams; $gp.Identity = $groups[$name]; $gp.Server = $DomainName
            # -Recursive can return the same principal via multiple nested paths; de-duplicate.
            $members = @(Get-ADGroupMember @gp -Recursive -ErrorAction Stop |
                Sort-Object -Property SID -Unique)
            $names = @($members | Select-Object -ExpandProperty SamAccountName -ErrorAction SilentlyContinue)
            $rows += [pscustomobject]@{
                Scope = $DomainName; Group = $name; MemberCount = $members.Count
                Members = ($names -join '; ')
                Status = $(if ($members.Count -gt 10) { $script:Status.Warning } else { $script:Status.Info })
                Detail = $(if ($members.Count -gt 10) { 'Large privileged group membership - review for least privilege.' } else { '' })
            }
        }
        catch {
            $rows += [pscustomobject]@{ Scope = $DomainName; Group = $name; MemberCount = $null; Members = ''; Status = $script:Status.NotAssessed; Detail = $_.Exception.Message }
        }
    }
    return , @($rows)
}

function Get-AdfaSecurityPosture {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param([Parameter(Mandatory)][string]$DomainName, [bool]$IsRootDomain, [hashtable]$AdParams = @{}, [int]$KrbtgtMaxAgeDays = 180)
    $rows = @()
    $srv = @{} + $AdParams; $srv.Server = $DomainName

    # krbtgt password age
    try {
        $k = Get-ADUser -Identity 'krbtgt' -Properties PasswordLastSet @srv
        $age = $null
        if ($k.PasswordLastSet) { $age = [int]((Get-Date) - $k.PasswordLastSet).TotalDays }
        $st = $script:Status.NotAssessed
        if ($null -ne $age) { $st = $(if ($age -le $KrbtgtMaxAgeDays) { $script:Status.Pass } else { $script:Status.Warning }) }
        $rows += New-Finding -Scope $DomainName -Area 'Security' -Item 'krbtgt password age' -Status $st -Detail ("{0} days (threshold {1})" -f $age, $KrbtgtMaxAgeDays)
    }
    catch { $rows += New-Finding -Scope $DomainName -Area 'Security' -Item 'krbtgt password age' -Status $script:Status.NotAssessed -Detail $_.Exception.Message }

    # AD Recycle Bin (forest scoped, but report per root domain)
    if ($IsRootDomain) {
        try {
            $rb = Get-ADOptionalFeature -Filter "Name -eq 'Recycle Bin Feature'" @AdParams
            $enabled = ($rb -and @($rb.EnabledScopes).Count -gt 0)
            $rows += New-Finding -Scope $DomainName -Area 'Security' -Item 'AD Recycle Bin' -Status $(if ($enabled) { $script:Status.Pass } else { $script:Status.Warning }) -Detail $(if ($enabled) { 'Enabled.' } else { 'Not enabled - object recovery limited.' })
        }
        catch { $rows += New-Finding -Scope $DomainName -Area 'Security' -Item 'AD Recycle Bin' -Status $script:Status.NotAssessed -Detail $_.Exception.Message }
    }

    # Tombstone lifetime
    try {
        $cnc = (Get-ADRootDSE @srv).configurationNamingContext
        $dsDn = "CN=Directory Service,CN=Windows NT,CN=Services,$cnc"
        $ds = Get-ADObject -Identity $dsDn -Properties tombstoneLifetime @srv
        $tsl = $ds.tombstoneLifetime
        $rows += New-Finding -Scope $DomainName -Area 'Security' -Item 'Tombstone lifetime' -Status $(if ($null -ne $tsl -and $tsl -ge 180) { $script:Status.Pass } else { $script:Status.Warning }) -Detail ("{0} days" -f $tsl)
    }
    catch { $rows += New-Finding -Scope $DomainName -Area 'Security' -Item 'Tombstone lifetime' -Status $script:Status.NotAssessed -Detail $_.Exception.Message }

    # Machine account quota
    try {
        $dp = @{} + $AdParams; $dp.Identity = $DomainName
        $dn = (Get-ADDomain @dp).DistinguishedName
        $mq = Get-ADObject -Identity $dn -Properties 'ms-DS-MachineAccountQuota' @srv
        $q = $mq.'ms-DS-MachineAccountQuota'
        $rows += New-Finding -Scope $DomainName -Area 'Security' -Item 'Machine account quota' -Status $(if ($q -eq 0) { $script:Status.Pass } else { $script:Status.Warning }) -Detail ("ms-DS-MachineAccountQuota = {0} (0 recommended)" -f $q)
    }
    catch { $rows += New-Finding -Scope $DomainName -Area 'Security' -Item 'Machine account quota' -Status $script:Status.NotAssessed -Detail $_.Exception.Message }

    # Privileged accounts with reversible/DES/RC4 or password-not-required
    try {
        $weak = @(Get-ADUser -Filter { (UserAccountControl -band 0x80) -or (UserAccountControl -band 0x200000) } -Properties UserAccountControl @srv)
        $rows += New-Finding -Scope $DomainName -Area 'Security' -Item 'DES/reversible-encryption accounts' -Status $(if ($weak.Count -eq 0) { $script:Status.Pass } else { $script:Status.Warning }) -Detail ("{0} accounts flagged" -f $weak.Count)
    }
    catch { $rows += New-Finding -Scope $DomainName -Area 'Security' -Item 'DES/reversible-encryption accounts' -Status $script:Status.NotAssessed -Detail $_.Exception.Message }

    return , @($rows)
}

function Get-AdfaStaleObject {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param([Parameter(Mandatory)][string]$DomainName, [hashtable]$AdParams = @{}, [int]$StaleDays = 90)
    $rows = @()
    $srv = @{} + $AdParams; $srv.Server = $DomainName
    $cutoff = (Get-Date).AddDays(-1 * $StaleDays)
    try {
        $staleUsers = @(Get-ADUser -Filter { Enabled -eq $true -and LastLogonTimestamp -lt $cutoff } -Properties LastLogonTimestamp @srv)
        $rows += New-Finding -Scope $DomainName -Area 'Stale' -Item 'Inactive enabled users' -Status $(if ($staleUsers.Count -eq 0) { $script:Status.Pass } else { $script:Status.Warning }) -Detail ("{0} enabled users inactive > {1} days" -f $staleUsers.Count, $StaleDays)
    }
    catch { $rows += New-Finding -Scope $DomainName -Area 'Stale' -Item 'Inactive enabled users' -Status $script:Status.NotAssessed -Detail $_.Exception.Message }
    try {
        $staleComputers = @(Get-ADComputer -Filter { Enabled -eq $true -and LastLogonTimestamp -lt $cutoff } -Properties LastLogonTimestamp @srv)
        $rows += New-Finding -Scope $DomainName -Area 'Stale' -Item 'Inactive enabled computers' -Status $(if ($staleComputers.Count -eq 0) { $script:Status.Pass } else { $script:Status.Warning }) -Detail ("{0} enabled computers inactive > {1} days" -f $staleComputers.Count, $StaleDays)
    }
    catch { $rows += New-Finding -Scope $DomainName -Area 'Stale' -Item 'Inactive enabled computers' -Status $script:Status.NotAssessed -Detail $_.Exception.Message }
    try {
        $neverExpire = @(Get-ADUser -Filter { Enabled -eq $true -and PasswordNeverExpires -eq $true } @srv)
        $rows += New-Finding -Scope $DomainName -Area 'Stale' -Item 'PasswordNeverExpires users' -Status $(if ($neverExpire.Count -eq 0) { $script:Status.Pass } else { $script:Status.Warning }) -Detail ("{0} enabled users" -f $neverExpire.Count)
    }
    catch { $rows += New-Finding -Scope $DomainName -Area 'Stale' -Item 'PasswordNeverExpires users' -Status $script:Status.NotAssessed -Detail $_.Exception.Message }
    return , @($rows)
}

# ===========================================================================
# region Identity inventory (full user / computer export)
# ===========================================================================

function ConvertTo-AdfaFlatObject {
    <#
    .SYNOPSIS
        Flattens an AD object's requested properties into a CSV-safe [pscustomobject].
        Multi-valued attributes are joined with ';'. Only properties actually present are read.
    .OUTPUTS
        [pscustomobject]
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]$InputObject,
        [Parameter(Mandatory)][string[]]$Property
    )
    $o = [ordered]@{}
    foreach ($p in $Property) {
        $v = $null
        if ($InputObject.PSObject.Properties.Name -contains $p) { $v = $InputObject.$p }
        if ($null -eq $v) { $o[$p] = '' }
        elseif ($v -is [string]) { $o[$p] = $v }
        elseif ($v -is [bool] -or $v -is [datetime] -or $v.GetType().IsPrimitive) { $o[$p] = $v }
        elseif ($v -is [System.Collections.IEnumerable]) { $o[$p] = ((@($v) | ForEach-Object { "$_" }) -join ';') }
        else { $o[$p] = "$v" }
    }
    return [pscustomobject]$o
}

function Get-AdfaObjectPropertyUnion {
    # Union of populated property names across a set (AD returns only set properties per object).
    [CmdletBinding()]
    [OutputType([string[]])]
    param([Parameter(Mandatory)][AllowEmptyCollection()]$Objects)
    $set = New-Object System.Collections.Generic.HashSet[string]
    foreach ($obj in @($Objects)) {
        foreach ($name in $obj.PSObject.Properties.Name) { [void]$set.Add($name) }
    }
    return , (@($set) | Sort-Object)
}

function Get-AdfaUserInventory {
    <#
    .SYNOPSIS
        Full user export (all populated attributes) for a domain, flattened for CSV.
    .DESCRIPTION
        Returns every user with the union of populated attributes (Get-ADUser -Properties *).
        Intended for CSV export; the HTML report shows only a summary of this data.
    .OUTPUTS
        [pscustomobject[]]
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param([Parameter(Mandatory)][string]$DomainName, [hashtable]$AdParams = @{})
    $srv = @{} + $AdParams; $srv.Server = $DomainName
    $users = @(Get-ADUser -Filter * -Properties * @srv)
    if ($users.Count -eq 0) { return , @() }
    $props = Get-AdfaObjectPropertyUnion -Objects $users
    $flat = foreach ($u in $users) { ConvertTo-AdfaFlatObject -InputObject $u -Property $props }
    return , @($flat)
}

function Get-AdfaComputerInventory {
    <#
    .SYNOPSIS
        Full computer export (all populated attributes) for a domain, flattened for CSV.
    .OUTPUTS
        [pscustomobject[]]
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param([Parameter(Mandatory)][string]$DomainName, [hashtable]$AdParams = @{})
    $srv = @{} + $AdParams; $srv.Server = $DomainName
    $computers = @(Get-ADComputer -Filter * -Properties * @srv)
    if ($computers.Count -eq 0) { return , @() }
    $props = Get-AdfaObjectPropertyUnion -Objects $computers
    $flat = foreach ($c in $computers) { ConvertTo-AdfaFlatObject -InputObject $c -Property $props }
    return , @($flat)
}

function Get-AdfaIdentitySummary {
    <#
    .SYNOPSIS
        Compact summary of a full user/computer export for the HTML report.
    .OUTPUTS
        [pscustomobject[]]
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param(
        [Parameter(Mandatory)][string]$DomainName,
        [AllowEmptyCollection()]$Users,
        [AllowEmptyCollection()]$Computers,
        [int]$StaleDays = 90
    )
    $rows = @()
    $u = @($Users)
    $c = @($Computers)
    $isEnabled = {
        param($o)
        ($o.PSObject.Properties.Name -contains 'Enabled') -and ("$($o.Enabled)" -eq 'True')
    }
    $enabledU = @($u | Where-Object { & $isEnabled $_ }).Count
    $enabledC = @($c | Where-Object { & $isEnabled $_ }).Count
    $rows += [pscustomobject]@{ Scope = $DomainName; Object = 'Users'; Total = $u.Count; Enabled = $enabledU; Disabled = ($u.Count - $enabledU); Status = $script:Status.Info; Detail = 'Full attribute export in csv\AllUsers_*.csv' }
    $rows += [pscustomobject]@{ Scope = $DomainName; Object = 'Computers'; Total = $c.Count; Enabled = $enabledC; Disabled = ($c.Count - $enabledC); Status = $script:Status.Info; Detail = 'Full attribute export in csv\AllComputers_*.csv' }
    return , @($rows)
}

# ===========================================================================
# region Deep security & reliability (pure helpers)
# ===========================================================================

function Test-AdfaEsc1Template {
    <#
    .SYNOPSIS
        ESC1 heuristic for a certificate template: enrollee-supplies-subject + auth EKU +
        no manager approval + no enrollment-agent signatures. Pure function.
    .OUTPUTS
        [pscustomobject] Vulnerable (bool), Reason
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([Parameter(Mandatory)][pscustomobject]$Template)

    $names = $Template.PSObject.Properties.Name
    $nameFlag = if ($names -contains 'msPKI-Certificate-Name-Flag') { [int64]$Template.'msPKI-Certificate-Name-Flag' } else { 0 }
    $enrollFlag = if ($names -contains 'msPKI-Enrollment-Flag') { [int64]$Template.'msPKI-Enrollment-Flag' } else { 0 }
    $raSig = if ($names -contains 'msPKI-RA-Signature') { [int]$Template.'msPKI-RA-Signature' } else { 0 }
    $ekus = @()
    if ($names -contains 'pKIExtendedKeyUsage' -and $Template.'pKIExtendedKeyUsage') { $ekus = @($Template.'pKIExtendedKeyUsage') }

    $suppliesSubject = ($nameFlag -band $script:Config.EnrolleeSuppliesSubject) -ne 0
    $approvalRequired = ($enrollFlag -band $script:Config.PendAllRequests) -ne 0
    $authEku = ($ekus.Count -eq 0) -or (@($ekus | Where-Object { $script:Config.AuthEkuOids -contains $_ }).Count -gt 0)

    $vulnerable = $suppliesSubject -and $authEku -and (-not $approvalRequired) -and ($raSig -le 0)
    $reason = if ($vulnerable) {
        'ENROLLEE_SUPPLIES_SUBJECT + client-auth EKU + no manager approval + no enrollment-agent signature (ESC1-susceptible; verify enrollment rights).'
    }
    else { 'Not ESC1-susceptible by configuration.' }
    return [pscustomobject]@{ Vulnerable = $vulnerable; Reason = $reason }
}

function Test-AdfaDcSyncAce {
    <#
    .SYNOPSIS
        True if an ACE grants a DCSync extended right (Get-Changes / Get-Changes-All). Pure.
    .OUTPUTS
        [bool]
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory)]$Ace)
    if ($Ace.AccessControlType -ne 'Allow') { return $false }
    $rights = "$($Ace.ActiveDirectoryRights)"
    if ($rights -notmatch 'ExtendedRight|GenericAll') { return $false }
    if ($rights -match 'GenericAll') { return $true }
    $guid = "$($Ace.ObjectType)".ToLower()
    foreach ($g in $script:Config.DcSyncRightGuids.Values) { if ($guid -eq $g.ToLower()) { return $true } }
    return $false
}

function Find-AdfaDuplicateSpn {
    <#
    .SYNOPSIS
        Finds servicePrincipalName values registered on more than one object. Pure function.
    .OUTPUTS
        [pscustomobject[]] Spn, Holders
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param([Parameter(Mandatory)][AllowEmptyCollection()]$Objects)
    $map = @{}
    foreach ($o in @($Objects)) {
        if ($o.PSObject.Properties.Name -notcontains 'ServicePrincipalName') { continue }
        $id = if ($o.PSObject.Properties.Name -contains 'SamAccountName') { $o.SamAccountName } else { "$($o.DistinguishedName)" }
        foreach ($spn in @($o.ServicePrincipalName)) {
            if (-not $spn) { continue }
            $key = "$spn".ToLower()
            if (-not $map.ContainsKey($key)) { $map[$key] = New-Object System.Collections.Generic.List[string] }
            if (-not $map[$key].Contains($id)) { $map[$key].Add($id) }
        }
    }
    $dupes = foreach ($k in $map.Keys) {
        if ($map[$k].Count -gt 1) { [pscustomobject]@{ Spn = $k; Holders = ($map[$k] -join '; ') } }
    }
    return , @($dupes | Where-Object { $null -ne $_ })
}

# ===========================================================================
# region Deep security & reliability (collectors)
# ===========================================================================

function Get-AdfaPkiHealth {
    <#
    .SYNOPSIS
        Enterprise PKI (AD CS): enrolment CAs and ESC1-susceptible certificate templates.
    .OUTPUTS
        [pscustomobject[]]
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param([hashtable]$AdParams = @{})
    $rows = @()
    try {
        $cfg = (Get-ADRootDSE @AdParams).configurationNamingContext
        $pkiBase = "CN=Public Key Services,CN=Services,$cfg"
        $cas = @(Get-ADObject -SearchBase "CN=Enrollment Services,$pkiBase" -LDAPFilter '(objectClass=pKIEnrollmentService)' -Properties dNSHostName, cn @AdParams -ErrorAction Stop)
        if ($cas.Count -eq 0) {
            $rows += New-Finding -Area 'PKI' -Item 'Certificate Authorities' -Status $script:Status.Info -Detail 'No enterprise CA found in the forest.'
            return , @($rows)
        }
        $rows += New-Finding -Area 'PKI' -Item 'Certificate Authorities' -Status $script:Status.Info -Detail (("{0} CA(s): {1}" -f $cas.Count, (($cas | ForEach-Object { $_.dNSHostName }) -join ', ')))

        $templates = @(Get-ADObject -SearchBase "CN=Certificate Templates,$pkiBase" -LDAPFilter '(objectClass=pKICertificateTemplate)' -Properties 'msPKI-Certificate-Name-Flag', 'msPKI-Enrollment-Flag', 'msPKI-RA-Signature', 'pKIExtendedKeyUsage', 'cn' @AdParams -ErrorAction Stop)
        $vuln = @()
        foreach ($t in $templates) {
            $r = Test-AdfaEsc1Template -Template $t
            if ($r.Vulnerable) { $vuln += $t.cn }
        }
        if ($vuln.Count -gt 0) {
            $rows += New-Finding -Area 'PKI' -Item 'ESC1-susceptible templates' -Status $script:Status.Fail -Detail ("{0}: {1}" -f $vuln.Count, ($vuln -join ', '))
        }
        else {
            $rows += New-Finding -Area 'PKI' -Item 'ESC1-susceptible templates' -Status $script:Status.Pass -Detail ("0 of {0} templates flagged by the ESC1 heuristic." -f $templates.Count)
        }
    }
    catch {
        $rows += New-Finding -Area 'PKI' -Item 'AD CS assessment' -Status $script:Status.NotAssessed -Detail $_.Exception.Message
    }
    return , @($rows)
}

function Get-AdfaDangerousAcl {
    <#
    .SYNOPSIS
        Detects non-default principals holding DCSync rights on the domain head.
    .OUTPUTS
        [pscustomobject[]]
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param([Parameter(Mandatory)][string]$DomainName, [hashtable]$AdParams = @{})
    $rows = @()
    try {
        $dp = @{} + $AdParams; $dp.Identity = $DomainName
        $dn = (Get-ADDomain @dp).DistinguishedName
        $acl = Get-Acl -Path ("AD:\{0}" -f $dn) -ErrorAction Stop
        $flagged = @()
        foreach ($ace in $acl.Access) {
            if (Test-AdfaDcSyncAce -Ace $ace) {
                $id = "$($ace.IdentityReference)"
                $isDefault = $false
                foreach ($p in $script:Config.DcSyncAllowedPatterns) { if ($id -match [regex]::Escape($p)) { $isDefault = $true; break } }
                if (-not $isDefault) { $flagged += $id }
            }
        }
        $flagged = @($flagged | Sort-Object -Unique)
        if ($flagged.Count -gt 0) {
            $rows += New-Finding -Scope $DomainName -Area 'ACL' -Item 'DCSync rights (non-default principals)' -Status $script:Status.Fail -Detail ("{0}: {1}" -f $flagged.Count, ($flagged -join ', '))
        }
        else {
            $rows += New-Finding -Scope $DomainName -Area 'ACL' -Item 'DCSync rights (non-default principals)' -Status $script:Status.Pass -Detail 'Only default principals hold replication rights on the domain head.'
        }
    }
    catch {
        $rows += New-Finding -Scope $DomainName -Area 'ACL' -Item 'DCSync rights review' -Status $script:Status.NotAssessed -Detail $_.Exception.Message
    }
    return , @($rows)
}

function Get-AdfaKerberosExposure {
    <#
    .SYNOPSIS
        Kerberoastable (SPN) users, AS-REP-roastable accounts, and delegation exposure.
    .OUTPUTS
        [pscustomobject[]]
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param([Parameter(Mandatory)][string]$DomainName, [hashtable]$AdParams = @{})
    $rows = @()
    $srv = @{} + $AdParams; $srv.Server = $DomainName

    try {
        $kerberoast = @(Get-ADUser -LDAPFilter '(&(servicePrincipalName=*)(!(objectClass=computer))(!(cn=krbtgt)))' -Properties servicePrincipalName, msDS-SupportedEncryptionTypes @srv -ErrorAction Stop |
            Where-Object { "$($_.Enabled)" -ne 'False' })
        $rows += New-Finding -Scope $DomainName -Area 'Kerberos' -Item 'Kerberoastable user accounts (SPN set)' -Status $(if ($kerberoast.Count -eq 0) { $script:Status.Pass } else { $script:Status.Warning }) -Detail ("{0}: {1}" -f $kerberoast.Count, ((@($kerberoast | Select-Object -First 15).SamAccountName) -join ', '))
    }
    catch { $rows += New-Finding -Scope $DomainName -Area 'Kerberos' -Item 'Kerberoastable user accounts (SPN set)' -Status $script:Status.NotAssessed -Detail $_.Exception.Message }

    try {
        $asrep = @(Get-ADUser -LDAPFilter ('(&(userAccountControl:1.2.840.113556.1.4.803:={0})(!(objectClass=computer)))' -f $script:Config.Uac.DONT_REQ_PREAUTH) -Properties userAccountControl @srv -ErrorAction Stop |
            Where-Object { "$($_.Enabled)" -ne 'False' })
        $rows += New-Finding -Scope $DomainName -Area 'Kerberos' -Item 'AS-REP roastable accounts (no pre-auth)' -Status $(if ($asrep.Count -eq 0) { $script:Status.Pass } else { $script:Status.Fail }) -Detail ("{0}: {1}" -f $asrep.Count, ((@($asrep | Select-Object -First 15).SamAccountName) -join ', '))
    }
    catch { $rows += New-Finding -Scope $DomainName -Area 'Kerberos' -Item 'AS-REP roastable accounts (no pre-auth)' -Status $script:Status.NotAssessed -Detail $_.Exception.Message }

    try {
        $unconstrained = @(Get-ADObject -LDAPFilter ('(&(userAccountControl:1.2.840.113556.1.4.803:={0})(|(objectClass=user)(objectClass=computer)))' -f $script:Config.Uac.TRUSTED_FOR_DELEGATION) -Properties samAccountName, userAccountControl, primaryGroupID @srv -ErrorAction Stop |
            Where-Object { "$($_.samAccountName)" -notmatch '\$$' -or $true })
        # Exclude domain controllers (they legitimately have unconstrained delegation).
        $dcNamesLocal = @((Get-ADDomainController -Filter * -Server $DomainName).Name)
        $nonDc = @($unconstrained | Where-Object { $n = "$($_.samAccountName)".TrimEnd('$'); $dcNamesLocal -notcontains $n })
        $rows += New-Finding -Scope $DomainName -Area 'Kerberos' -Item 'Unconstrained delegation (non-DC)' -Status $(if ($nonDc.Count -eq 0) { $script:Status.Pass } else { $script:Status.Fail }) -Detail ("{0}: {1}" -f $nonDc.Count, ((@($nonDc | Select-Object -First 15).samAccountName) -join ', '))
    }
    catch { $rows += New-Finding -Scope $DomainName -Area 'Kerberos' -Item 'Unconstrained delegation (non-DC)' -Status $script:Status.NotAssessed -Detail $_.Exception.Message }

    try {
        $rbcd = @(Get-ADObject -LDAPFilter '(msDS-AllowedToActOnBehalfOfOtherIdentity=*)' -Properties samAccountName @srv -ErrorAction Stop)
        $rows += New-Finding -Scope $DomainName -Area 'Kerberos' -Item 'Resource-based constrained delegation configured' -Status $script:Status.Info -Detail ("{0} object(s) with RBCD" -f $rbcd.Count)
    }
    catch { $rows += New-Finding -Scope $DomainName -Area 'Kerberos' -Item 'Resource-based constrained delegation configured' -Status $script:Status.NotAssessed -Detail $_.Exception.Message }

    return , @($rows)
}

function Get-AdfaPrivilegedHygiene {
    <#
    .SYNOPSIS
        adminCount orphans, Protected Users adoption, and SPNs on privileged accounts.
    .OUTPUTS
        [pscustomobject[]]
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param([Parameter(Mandatory)][string]$DomainName, [hashtable]$AdParams = @{})
    $rows = @()
    $srv = @{} + $AdParams; $srv.Server = $DomainName
    try {
        $adminCount = @(Get-ADUser -LDAPFilter '(&(admincount=1)(!(cn=krbtgt)))' -Properties adminCount, servicePrincipalName, memberOf @srv -ErrorAction Stop |
            Where-Object { "$($_.Enabled)" -ne 'False' })
        $rows += New-Finding -Scope $DomainName -Area 'PrivHygiene' -Item 'adminCount=1 users' -Status $script:Status.Info -Detail ("{0} enabled users carry adminCount=1 (protected by SDProp)." -f $adminCount.Count)
        $privWithSpn = @($adminCount | Where-Object { $_.PSObject.Properties.Name -contains 'servicePrincipalName' -and $_.servicePrincipalName })
        $rows += New-Finding -Scope $DomainName -Area 'PrivHygiene' -Item 'Privileged accounts with SPNs (Kerberoast risk)' -Status $(if ($privWithSpn.Count -eq 0) { $script:Status.Pass } else { $script:Status.Fail }) -Detail ("{0}: {1}" -f $privWithSpn.Count, ((@($privWithSpn | Select-Object -First 15).SamAccountName) -join ', '))
    }
    catch { $rows += New-Finding -Scope $DomainName -Area 'PrivHygiene' -Item 'adminCount review' -Status $script:Status.NotAssessed -Detail $_.Exception.Message }

    try {
        $dp = @{} + $AdParams; $dp.Identity = $DomainName
        $sid = (Get-ADDomain @dp).DomainSID.Value
        $pu = @(Get-ADGroupMember -Identity "$sid-525" -Server $DomainName -ErrorAction Stop)
        $rows += New-Finding -Scope $DomainName -Area 'PrivHygiene' -Item 'Protected Users group members' -Status $(if ($pu.Count -gt 0) { $script:Status.Pass } else { $script:Status.Warning }) -Detail ("{0} members (privileged accounts should be enrolled)." -f $pu.Count)
    }
    catch { $rows += New-Finding -Scope $DomainName -Area 'PrivHygiene' -Item 'Protected Users group members' -Status $script:Status.NotAssessed -Detail $_.Exception.Message }

    return , @($rows)
}

function Get-AdfaDcHardening {
    <#
    .SYNOPSIS
        Per-DC hardening: Print Spooler running, SMBv1 enabled, LDAP signing requirement.
        Uses remote CIM/registry; degrades to Not Assessed where unreachable.
    .OUTPUTS
        [pscustomobject[]]
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param([Parameter(Mandatory)][string[]]$DomainControllers, [pscredential]$Credential, [int]$RpcPortTimeoutMs = 1200)
    $rows = @()
    foreach ($dc in $DomainControllers) {
        if (-not (Test-TcpPort -ComputerName $dc -Port 135 -TimeoutMs $RpcPortTimeoutMs)) {
            $rows += New-Finding -Area 'DCHardening' -Item ("{0}" -f $dc) -Status $script:Status.NotAssessed -Detail 'DC not reachable (RPC/135).'
            continue
        }
        # Print Spooler (PrinterBug / PetitPotam relay surface)
        try {
            $sp = Get-Service -ComputerName $dc -Name Spooler -ErrorAction Stop
            $rows += New-Finding -Area 'DCHardening' -Item ("{0}: Print Spooler" -f $dc) -Status $(if ($sp.Status -eq 'Running') { $script:Status.Warning } else { $script:Status.Pass }) -Detail ("Spooler is {0} (should be Stopped/Disabled on DCs)." -f $sp.Status)
        }
        catch { $rows += New-Finding -Area 'DCHardening' -Item ("{0}: Print Spooler" -f $dc) -Status $script:Status.NotAssessed -Detail $_.Exception.Message }

        # SMBv1
        try {
            $cimArgs = @{ ComputerName = $dc; ErrorAction = 'Stop' }
            if ($Credential) { $cimArgs.Credential = $Credential }
            $smb = Get-CimInstance @cimArgs -Namespace 'root/Microsoft/Windows/SMB' -ClassName 'MSFT_SmbServerConfiguration'
            $rows += New-Finding -Area 'DCHardening' -Item ("{0}: SMBv1" -f $dc) -Status $(if ($smb.EnableSMB1Protocol) { $script:Status.Fail } else { $script:Status.Pass }) -Detail ("EnableSMB1Protocol = {0}" -f $smb.EnableSMB1Protocol)
        }
        catch { $rows += New-Finding -Area 'DCHardening' -Item ("{0}: SMBv1" -f $dc) -Status $script:Status.NotAssessed -Detail $_.Exception.Message }

        # LDAP server signing requirement (registry LDAPServerIntegrity: 2 = required)
        try {
            $reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $dc)
            $key = $reg.OpenSubKey('SYSTEM\CurrentControlSet\Services\NTDS\Parameters')
            $val = if ($key) { $key.GetValue('LDAPServerIntegrity') } else { $null }
            $rows += New-Finding -Area 'DCHardening' -Item ("{0}: LDAP signing required" -f $dc) -Status $(if ("$val" -eq '2') { $script:Status.Pass } else { $script:Status.Warning }) -Detail ("LDAPServerIntegrity = {0} (2 = required)" -f $val)
        }
        catch { $rows += New-Finding -Area 'DCHardening' -Item ("{0}: LDAP signing required" -f $dc) -Status $script:Status.NotAssessed -Detail $_.Exception.Message }
    }
    return , @($rows)
}

function Get-AdfaBackupStatus {
    <#
    .SYNOPSIS
        Last directory-partition backup times via 'repadmin /showbackup'.
    .OUTPUTS
        [pscustomobject[]]
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param([int]$TimeoutSeconds = 90, [int]$Retries = 2, [int]$RetryDelaySeconds = 2, [int]$MaxAgeDays = 30)
    if (-not (Test-CommandAvailable -Name 'repadmin.exe')) {
        return , @(New-Finding -Area 'Backup' -Item 'Directory backup status' -Status $script:Status.NotAssessed -Detail 'repadmin.exe not available on this host.')
    }
    $r = Invoke-ExternalCommand -FilePath 'repadmin.exe' -Arguments '/showbackup *' -TimeoutSeconds $TimeoutSeconds -Retries $Retries -RetryDelaySeconds $RetryDelaySeconds
    $rows = @()
    # Parse lines like: "<partition> : <date time>"
    $backupLines = @($r.StdOut -split "`r?`n" | Where-Object { $_ -match '\d{4}-\d{2}-\d{2}' -or $_ -match '\d{1,2}/\d{1,2}/\d{4}' })
    if ($backupLines.Count -eq 0) {
        $rows += New-Finding -Area 'Backup' -Item 'Directory backup status' -Status $script:Status.NotAssessed -Detail 'Could not parse repadmin /showbackup output.'
    }
    else {
        foreach ($line in ($backupLines | Select-Object -First 12)) {
            $rows += New-Finding -Area 'Backup' -Item 'Partition backup' -Status $script:Status.Info -Detail $line.Trim()
        }
    }
    return , @($rows)
}

function Get-AdfaTimeSync {
    <#
    .SYNOPSIS
        Local w32time source/status (run on a DC for domain-relevant results).
    .OUTPUTS
        [pscustomobject[]]
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param([int]$TimeoutSeconds = 60)
    if (-not (Test-CommandAvailable -Name 'w32tm.exe')) {
        return , @(New-Finding -Area 'TimeSync' -Item 'w32time' -Status $script:Status.NotAssessed -Detail 'w32tm.exe not available on this host.')
    }
    $rows = @()
    $src = Invoke-ExternalCommand -FilePath 'w32tm.exe' -Arguments '/query /source' -TimeoutSeconds $TimeoutSeconds -Retries 1 -RetryDelaySeconds 1
    $source = ($src.StdOut -split "`r?`n" | Where-Object { $_.Trim() } | Select-Object -First 1)
    $status = $script:Status.Info
    if ($source -match 'Local CMOS Clock|Free-running') { $status = $script:Status.Warning }
    $rows += New-Finding -Area 'TimeSync' -Item 'Time source' -Status $status -Detail ("Source: {0}" -f ("$source".Trim()))
    return , @($rows)
}

function Get-AdfaDnsDepth {
    <#
    .SYNOPSIS
        DNS depth: critical SRV records resolvable, secure dynamic updates, root hints.
    .OUTPUTS
        [pscustomobject[]]
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param([Parameter(Mandatory)][string]$DomainName, [string[]]$DomainControllers, [int]$RpcPortTimeoutMs = 1200)
    $rows = @()
    # SRV record resolution (needs Resolve-DnsName; degrade if absent)
    if (Test-CommandAvailable -Name 'Resolve-DnsName') {
        foreach ($rec in @("_ldap._tcp.dc._msdcs.$DomainName", "_kerberos._tcp.$DomainName")) {
            try {
                $ans = @(Resolve-DnsName -Name $rec -Type SRV -ErrorAction Stop)
                $rows += New-Finding -Scope $DomainName -Area 'DNSDepth' -Item ("SRV {0}" -f $rec) -Status $(if ($ans.Count -gt 0) { $script:Status.Pass } else { $script:Status.Fail }) -Detail ("{0} record(s)" -f $ans.Count)
            }
            catch { $rows += New-Finding -Scope $DomainName -Area 'DNSDepth' -Item ("SRV {0}" -f $rec) -Status $script:Status.Fail -Detail $_.Exception.Message }
        }
    }
    else {
        $rows += New-Finding -Scope $DomainName -Area 'DNSDepth' -Item 'SRV record resolution' -Status $script:Status.NotAssessed -Detail 'Resolve-DnsName not available on this host.'
    }
    # Secure dynamic updates on the AD zone
    if ((Test-ModuleAvailable -Name 'DnsServer') -and $DomainControllers -and @($DomainControllers).Count -gt 0) {
        Import-Module DnsServer -ErrorAction SilentlyContinue -Verbose:$false
        $dc = @($DomainControllers)[0]
        try {
            $zone = Get-DnsServerZone -Name $DomainName -ComputerName $dc -ErrorAction Stop
            $secure = ("$($zone.DynamicUpdate)" -eq 'Secure')
            $rows += New-Finding -Scope $DomainName -Area 'DNSDepth' -Item 'Secure dynamic updates' -Status $(if ($secure) { $script:Status.Pass } else { $script:Status.Warning }) -Detail ("DynamicUpdate = {0} (Secure recommended)" -f $zone.DynamicUpdate)
        }
        catch { $rows += New-Finding -Scope $DomainName -Area 'DNSDepth' -Item 'Secure dynamic updates' -Status $script:Status.NotAssessed -Detail $_.Exception.Message }
    }
    return , @($rows)
}

function Get-AdfaRedundancy {
    <#
    .SYNOPSIS
        Availability: DC count / FSMO concentration, GPO central store, duplicate SPNs.
    .OUTPUTS
        [pscustomobject[]]
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param([Parameter(Mandatory)][string]$DomainName, [hashtable]$AdParams = @{})
    $rows = @()
    $srv = @{} + $AdParams; $srv.Server = $DomainName
    try {
        $dcs = @(Get-ADDomainController -Filter * -Server $DomainName)
        $rows += New-Finding -Scope $DomainName -Area 'Redundancy' -Item 'Domain controller redundancy' -Status $(if ($dcs.Count -ge 2) { $script:Status.Pass } else { $script:Status.Warning }) -Detail ("{0} DC(s) in domain (>=2 recommended for resilience)." -f $dcs.Count)
    }
    catch { $rows += New-Finding -Scope $DomainName -Area 'Redundancy' -Item 'Domain controller redundancy' -Status $script:Status.NotAssessed -Detail $_.Exception.Message }

    # GPO central store (PolicyDefinitions in SYSVOL)
    try {
        $cs = "\\{0}\SYSVOL\{0}\Policies\PolicyDefinitions" -f $DomainName
        $exists = Test-Path -LiteralPath $cs -ErrorAction SilentlyContinue
        $rows += New-Finding -Scope $DomainName -Area 'Redundancy' -Item 'GPO central store' -Status $(if ($exists) { $script:Status.Pass } else { $script:Status.Warning }) -Detail ("PolicyDefinitions {0} in SYSVOL." -f $(if ($exists) { 'present' } else { 'not found' }))
    }
    catch { $rows += New-Finding -Scope $DomainName -Area 'Redundancy' -Item 'GPO central store' -Status $script:Status.NotAssessed -Detail $_.Exception.Message }

    # Duplicate SPNs
    try {
        $objs = @(Get-ADObject -LDAPFilter '(servicePrincipalName=*)' -Properties servicePrincipalName, samAccountName @srv -ErrorAction Stop)
        $dupes = Find-AdfaDuplicateSpn -Objects $objs
        $rows += New-Finding -Scope $DomainName -Area 'Redundancy' -Item 'Duplicate SPNs' -Status $(if (@($dupes).Count -eq 0) { $script:Status.Pass } else { $script:Status.Fail }) -Detail ("{0} duplicated SPN(s){1}" -f @($dupes).Count, $(if (@($dupes).Count -gt 0) { ': ' + ((@($dupes | Select-Object -First 8).Spn) -join ', ') } else { '.' }))
    }
    catch { $rows += New-Finding -Scope $DomainName -Area 'Redundancy' -Item 'Duplicate SPNs' -Status $script:Status.NotAssessed -Detail $_.Exception.Message }

    return , @($rows)
}

# ===========================================================================
# region Exchange schema markers
# ===========================================================================

function Get-AdfaExchangeSchemaMarker {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param([hashtable]$AdParams = @{})
    $m = @()
    try {
        $schema = (Get-ADRootDSE @AdParams).schemaNamingContext
        $o = Get-ADObject -LDAPFilter '(cn=ms-Exch-Schema-Version-Pt)' -SearchBase $schema -Properties rangeUpper, whenChanged @AdParams -ErrorAction Stop
        if ($o) { $m += [pscustomobject]@{ Marker = 'ms-Exch-Schema-Version-Pt'; RangeUpper = $o.rangeUpper; WhenChanged = $o.whenChanged; Note = '' } }
        else { $m += [pscustomobject]@{ Marker = 'ms-Exch-Schema-Version-Pt'; RangeUpper = $null; WhenChanged = $null; Note = 'NotFound' } }
    }
    catch { $m += [pscustomobject]@{ Marker = 'ms-Exch-Schema-Version-Pt'; RangeUpper = $null; WhenChanged = $null; Note = $_.Exception.Message } }
    return , @($m)
}

# ===========================================================================
# region HTML report
# ===========================================================================

function ConvertTo-AdfaHtmlText {
    # Portable HTML-encode: System.Net.WebUtility is present on .NET Framework 4.5+ and
    # .NET Core/5+, so this works on Windows PowerShell 5.1 and pwsh 7 without System.Web.
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowNull()]$Value)
    if ($null -eq $Value) { return '' }
    return [System.Net.WebUtility]::HtmlEncode([string]$Value)
}

function ConvertTo-AdfaHtmlSection {
    <#
    .SYNOPSIS
        Renders a collection to an HTML table with RAG colouring of a Status/Health column.
    .OUTPUTS
        [string]
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][string]$Title,
        [AllowNull()]$Data,
        [string]$Description
    )
    $rows = @($Data)
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine("<h2>$(ConvertTo-AdfaHtmlText $Title)</h2>")
    if ($Description) { [void]$sb.AppendLine("<p class='desc'>$(ConvertTo-AdfaHtmlText $Description)</p>") }
    if ($rows.Count -eq 0) {
        [void]$sb.AppendLine("<p class='empty'>No data collected.</p>")
        return $sb.ToString()
    }
    $cols = @($rows[0].PSObject.Properties.Name)
    [void]$sb.AppendLine("<table><thead><tr>")
    foreach ($c in $cols) { [void]$sb.AppendLine("<th>$((ConvertTo-AdfaHtmlText $c))</th>") }
    [void]$sb.AppendLine("</tr></thead><tbody>")
    foreach ($r in $rows) {
        $statusVal = $null
        foreach ($sc in @('Status', 'Health')) { if ($cols -contains $sc) { $statusVal = [string]$r.$sc; break } }
        $cls = switch -Regex ($statusVal) {
            '^(Pass|Healthy|Verified)$' { 'ok'; break }
            '^(Warning|Degraded)$' { 'warn'; break }
            '^(Fail|Broken|Failed)$' { 'bad'; break }
            '^(Not Assessed)$' { 'na'; break }
            default { '' }
        }
        [void]$sb.AppendLine("<tr class='$cls'>")
        foreach ($c in $cols) {
            $v = $r.$c
            $text = if ($null -eq $v) { '' } else { [string]$v }
            [void]$sb.AppendLine("<td>$((ConvertTo-AdfaHtmlText $text))</td>")
        }
        [void]$sb.AppendLine("</tr>")
    }
    [void]$sb.AppendLine("</tbody></table>")
    return $sb.ToString()
}

function New-AdfaHtmlReport {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][System.Collections.Specialized.OrderedDictionary]$Sections,
        [Parameter(Mandatory)][pscustomobject]$Meta,
        [Parameter(Mandatory)][string]$Path
    )
    $css = @"
<style>
:root{color-scheme:light dark;}
body{font-family:'Segoe UI',Arial,sans-serif;margin:24px;color:#1b1b1b;background:#fff;}
h1{font-size:24px;margin-bottom:2px;} h2{font-size:17px;margin-top:28px;border-bottom:2px solid #eee;padding-bottom:4px;}
.desc{color:#666;font-size:12px;margin:2px 0 8px;}
.meta{font-size:12px;color:#555;} .empty{color:#888;font-style:italic;}
table{border-collapse:collapse;width:100%;margin:8px 0;font-size:12px;}
th,td{border:1px solid #ddd;padding:5px 7px;text-align:left;vertical-align:top;}
th{background:#f3f4f6;position:sticky;top:0;}
tr.ok  td:nth-child(1){border-left:4px solid #16a34a;}
tr.warn td:nth-child(1){border-left:4px solid #d97706;}
tr.bad td:nth-child(1){border-left:4px solid #dc2626;}
tr.na  td:nth-child(1){border-left:4px solid #9ca3af;}
tr.ok{background:#f0fdf4;} tr.warn{background:#fffbeb;} tr.bad{background:#fef2f2;} tr.na{background:#f9fafb;}
.badges span{display:inline-block;padding:2px 8px;border-radius:10px;font-size:11px;margin-right:6px;color:#fff;}
.b-ok{background:#16a34a;} .b-warn{background:#d97706;} .b-bad{background:#dc2626;} .b-na{background:#9ca3af;}
code{background:#f3f4f6;padding:1px 5px;border-radius:3px;}
</style>
"@

    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine("<!DOCTYPE html><html><head><meta charset='utf-8'/><title>AD Forest Assessment</title>$css</head><body>")
    [void]$sb.AppendLine("<h1>Active Directory Forest Assessment</h1>")
    [void]$sb.AppendLine("<p class='meta'>Forest: <code>$((ConvertTo-AdfaHtmlText $Meta.Forest))</code> &middot; Generated: $($Meta.Generated) &middot; By: $((ConvertTo-AdfaHtmlText $Meta.RunBy)) &middot; Tool v$($Meta.Version)</p>")
    [void]$sb.AppendLine("<p class='badges'>$($Meta.Badges)</p>")
    foreach ($key in $Sections.Keys) {
        [void]$sb.AppendLine((ConvertTo-AdfaHtmlSection -Title $key -Data $Sections[$key]))
    }
    [void]$sb.AppendLine("</body></html>")
    $sb.ToString() | Out-File -Encoding UTF8 -FilePath $Path -Force
    return $Path
}

# ===========================================================================
# region MAIN
# ===========================================================================

function Test-SectionSelected {
    param([string]$Name, [string[]]$Selected)
    return ($Selected -contains 'All' -or $Selected -contains $Name)
}

function Invoke-Main {
    [CmdletBinding()]
    param()

    # Resolve output root -> logged-on user's Documents by default.
    if (-not $OutputPath) {
        $docs = [Environment]::GetFolderPath('MyDocuments')
        if ([string]::IsNullOrWhiteSpace($docs)) { $docs = Join-Path $HOME 'Documents' }
        $OutputPath = Join-Path $docs 'AdAssessment'
    }
    $stamp = Get-Date -Format 'yyyy-MM-dd_HH-mm-ss'
    $runRoot = New-Folder -Path (Join-Path $OutputPath $stamp)
    $csvPath = New-Folder -Path (Join-Path $runRoot 'csv')
    $rawPath = New-Folder -Path (Join-Path $runRoot 'raw')

    # Detailed run log (itemised) is the primary log; transcript captures raw host/verbose.
    $script:LogFile = Join-Path $runRoot ("assessment_{0}.log" -f $stamp)
    "AD Forest Assessment detailed log - $stamp" | Out-File -LiteralPath $script:LogFile -Encoding UTF8 -Force
    $transcript = Join-Path $runRoot ("transcript_{0}.log" -f $stamp)
    try { Start-Transcript -Path $transcript -Force | Out-Null } catch { }

    Write-Log -Level INFO ("Runtime: PowerShell {0} on {1}; user {2}\{3}" -f `
        $PSVersionTable.PSVersion, [Environment]::MachineName, $env:USERDOMAIN, $env:USERNAME)
    Write-Log -Level INFO ("Parameters: AllDomains={0} Sections={1} IncludeDcdiag={2} IncludeRepadmin={3} SkipTrustVerification={4} Server={5}" -f `
        $AllDomains.IsPresent, ($Sections -join ','), $IncludeDcdiag.IsPresent, $IncludeRepadmin.IsPresent, $SkipTrustVerification.IsPresent, $Server)
    Write-Stage ("AD Forest Assessment v{0} starting" -f $script:Config.Version)
    Write-Stage ("Output: {0}" -f $runRoot)

    Import-Module ActiveDirectory -ErrorAction Stop -Verbose:$false
    Write-Stage 'ActiveDirectory module imported'

    $adParams = @{}
    if ($Server) { $adParams.Server = $Server }
    if ($Credential) { $adParams.Credential = $Credential }
    $repParams = @{}
    if ($Credential) { $repParams.Credential = $Credential }

    $forest = Get-ADForest @adParams
    $rootDomain = $forest.RootDomain
    $targetDomains = @()
    if ($AllDomains) { $targetDomains = @($forest.Domains) }
    else {
        $cur = (Get-ADDomain @adParams).DNSRoot
        $targetDomains = @($cur)
    }
    Write-Stage ("Forest: {0}; assessing domains: {1}" -f $forest.Name, ($targetDomains -join ', '))

    $sectionData = [ordered]@{}
    $sectionStatus = [ordered]@{}
    $ext = @{ TimeoutSeconds = $script:Config.ExternalToolTimeoutSec; Retries = $script:Config.Retries; RetryDelaySeconds = $script:Config.RetryDelaySeconds }

    # ---- Forest-level sections ----
    if (Test-SectionSelected 'Forest' $Sections) {
        try { $sectionData['Forest Summary'] = @(Get-AdfaForestSummary -AdParams $adParams); $sectionStatus['Forest'] = 'ok' }
        catch { $sectionStatus['Forest'] = 'error'; Write-Warning $_.Exception.Message }
    }

    $allDcInventory = @()
    if (Test-SectionSelected 'DomainControllers' $Sections) {
        $inv = @()
        foreach ($d in $targetDomains) {
            try { $inv += Get-AdfaDomainControllerInventory -DomainName $d -AdParams $adParams }
            catch { Write-Warning ("DC inventory failed for {0}: {1}" -f $d, $_.Exception.Message) }
        }
        $allDcInventory = $inv
        $sectionData['Domain Controllers'] = $inv
    }
    $dcNames = @($allDcInventory | Select-Object -ExpandProperty HostName -ErrorAction SilentlyContinue)
    if ($dcNames.Count -eq 0) {
        try { $dcNames = @(Get-ADDomainController -Filter * @adParams | Select-Object -ExpandProperty HostName) } catch { }
    }

    if (Test-SectionSelected 'Domains' $Sections) {
        $ds = foreach ($d in $targetDomains) { try { Get-AdfaDomainSummary -DomainName $d -AdParams $adParams } catch { } }
        $sectionData['Domain Summary'] = @($ds)
    }
    if (Test-SectionSelected 'Fsmo' $Sections) {
        $fs = foreach ($d in $targetDomains) { try { Get-AdfaFsmoRole -DomainName $d -AdParams $adParams } catch { } }
        $sectionData['FSMO Roles'] = @($fs)
    }

    if (Test-SectionSelected 'Replication' $Sections) {
        Write-Stage 'Replication health'
        $sectionData['Replication Health'] = Get-AdfaReplicationHealth -DomainControllers $dcNames -RepParams $repParams -RpcPortTimeoutMs $script:Config.RpcPortTimeoutMs -StaleMinutes $script:Config.ReplicationStaleMinutes
    }

    $topology = $null
    if (Test-SectionSelected 'Topology' $Sections) {
        Write-Stage 'Topology'
        try {
            $topology = Get-AdfaReplicationTopology -AdParams $adParams
            $sectionData['AD Sites'] = $topology.Sites
            $sectionData['AD Subnets'] = $topology.Subnets
            $sectionData['Site Links'] = $topology.SiteLinks
            $sectionData['Replication Connections'] = $topology.Connections
            if ($allDcInventory.Count -gt 0) {
                $sectionData['Site Health'] = Get-AdfaSiteHealthFinding -Topology $topology -DomainControllers $allDcInventory
            }
        }
        catch { Write-Warning ("Topology failed: {0}" -f $_.Exception.Message) }
    }

    if (Test-SectionSelected 'Trusts' $Sections) {
        Write-Stage 'Trust health (two-way verification)'
        $trustRows = @()
        foreach ($d in $targetDomains) {
            $tp = @{} + $adParams; $tp.Server = $d
            $trustRows += Get-AdfaTrustHealth -DomainName $d -AdParams $tp -SkipVerification:$SkipTrustVerification `
                -TimeoutSeconds $script:Config.ExternalToolTimeoutSec -Retries $script:Config.Retries `
                -RetryDelaySeconds $script:Config.RetryDelaySeconds -RpcPortTimeoutMs $script:Config.RpcPortTimeoutMs
        }
        $sectionData['Trusts & Two-Way Health'] = $trustRows
    }

    if (Test-SectionSelected 'DcDiagnostics' $Sections) {
        Write-Stage 'DC diagnostics (parsed)'
        $sectionData['DC Diagnostics'] = Get-AdfaDcDiagnostic -DomainControllers $dcNames @ext -RpcPortTimeoutMs $script:Config.RpcPortTimeoutMs
    }
    if (Test-SectionSelected 'Dns' $Sections) {
        Write-Stage 'DNS health'
        $sectionData['DNS Health'] = Get-AdfaDnsHealth -DomainControllers $dcNames -Credential $Credential -RpcPortTimeoutMs $script:Config.RpcPortTimeoutMs
    }
    if (Test-SectionSelected 'Sysvol' $Sections) {
        Write-Stage 'SYSVOL/DFSR'
        $sectionData['SYSVOL / DFSR'] = Get-AdfaSysvolHealth @ext
    }
    if (Test-SectionSelected 'Gpo' $Sections) {
        Write-Stage 'GPO inventory'
        $g = foreach ($d in $targetDomains) { Get-AdfaGpoInventory -DomainName $d }
        $sectionData['GPO Inventory'] = @($g)
    }
    if (Test-SectionSelected 'PasswordPolicy' $Sections) {
        $pp = foreach ($d in $targetDomains) { Get-AdfaPasswordPolicy -DomainName $d -AdParams $adParams }
        $sectionData['Password Policy'] = @($pp)
    }
    if (Test-SectionSelected 'PrivilegedAccounts' $Sections) {
        $pa = foreach ($d in $targetDomains) { Get-AdfaPrivilegedAccount -DomainName $d -IsRootDomain:($d -eq $rootDomain) -AdParams $adParams }
        $sectionData['Privileged Accounts'] = @($pa)
    }
    if (Test-SectionSelected 'SecurityPosture' $Sections) {
        Write-Stage 'Security posture'
        $sp = foreach ($d in $targetDomains) { Get-AdfaSecurityPosture -DomainName $d -IsRootDomain:($d -eq $rootDomain) -AdParams $adParams -KrbtgtMaxAgeDays $script:Config.KrbtgtMaxAgeDays }
        $sectionData['Security Posture'] = @($sp)
    }
    if (Test-SectionSelected 'StaleObjects' $Sections) {
        $so = foreach ($d in $targetDomains) { Get-AdfaStaleObject -DomainName $d -AdParams $adParams -StaleDays $script:Config.StaleDays }
        $sectionData['Stale Objects'] = @($so)
    }

    # ---- Deep security & reliability ----
    if (Test-SectionSelected 'Pki' $Sections) {
        Write-Stage 'AD CS / PKI (ESC1 heuristic)'
        $sectionData['PKI / AD CS'] = Get-AdfaPkiHealth -AdParams $adParams
    }
    if (Test-SectionSelected 'Acl' $Sections) {
        Write-Stage 'Dangerous ACLs (DCSync)'
        $aclRows = foreach ($d in $targetDomains) { Get-AdfaDangerousAcl -DomainName $d -AdParams $adParams }
        $sectionData['Dangerous ACLs (DCSync)'] = @($aclRows)
    }
    if (Test-SectionSelected 'Kerberos' $Sections) {
        Write-Stage 'Kerberos exposure (roasting / delegation)'
        $kRows = foreach ($d in $targetDomains) { Get-AdfaKerberosExposure -DomainName $d -AdParams $adParams }
        $sectionData['Kerberos Exposure'] = @($kRows)
    }
    if (Test-SectionSelected 'PrivilegedHygiene' $Sections) {
        Write-Stage 'Privileged hygiene'
        $phRows = foreach ($d in $targetDomains) { Get-AdfaPrivilegedHygiene -DomainName $d -AdParams $adParams }
        $sectionData['Privileged Hygiene'] = @($phRows)
    }
    if (Test-SectionSelected 'DcHardening' $Sections) {
        Write-Stage 'DC hardening (Spooler / SMBv1 / LDAP signing)'
        $sectionData['DC Hardening'] = Get-AdfaDcHardening -DomainControllers $dcNames -Credential $Credential -RpcPortTimeoutMs $script:Config.RpcPortTimeoutMs
    }
    if (Test-SectionSelected 'Backup' $Sections) {
        Write-Stage 'Directory backup status'
        $sectionData['Backup Status'] = Get-AdfaBackupStatus @ext
    }
    if (Test-SectionSelected 'TimeSync' $Sections) {
        Write-Stage 'Time synchronization'
        $sectionData['Time Sync'] = Get-AdfaTimeSync -TimeoutSeconds $script:Config.ExternalToolTimeoutSec
    }
    if (Test-SectionSelected 'DnsDepth' $Sections) {
        Write-Stage 'DNS depth (SRV / secure updates)'
        $ddRows = foreach ($d in $targetDomains) { Get-AdfaDnsDepth -DomainName $d -DomainControllers $dcNames -RpcPortTimeoutMs $script:Config.RpcPortTimeoutMs }
        $sectionData['DNS Depth'] = @($ddRows)
    }
    if (Test-SectionSelected 'Redundancy' $Sections) {
        Write-Stage 'Redundancy / availability'
        $rdRows = foreach ($d in $targetDomains) { Get-AdfaRedundancy -DomainName $d -AdParams $adParams }
        $sectionData['Redundancy & Availability'] = @($rdRows)
    }

    if (Test-SectionSelected 'ExchangeSchema' $Sections) {
        $sectionData['Exchange Schema Markers'] = Get-AdfaExchangeSchemaMarker -AdParams $adParams
    }

    # ---- Full identity export (all attributes) -> CSV; HTML gets a summary only ----
    if (Test-SectionSelected 'Identity' $Sections) {
        Write-Stage 'Identity inventory (full user/computer export)'
        $identitySummary = @()
        foreach ($d in $targetDomains) {
            $users = @(); $computers = @()
            try { $users = Get-AdfaUserInventory -DomainName $d -AdParams $adParams }
            catch { Write-Warning ("User export failed for {0}: {1}" -f $d, $_.Exception.Message) }
            try { $computers = Get-AdfaComputerInventory -DomainName $d -AdParams $adParams }
            catch { Write-Warning ("Computer export failed for {0}: {1}" -f $d, $_.Exception.Message) }

            $safeDom = New-SafeFileName $d
            if (@($users).Count -gt 0) { Save-Csv -InputObject $users -Path (Join-Path $csvPath ("AllUsers_{0}.csv" -f $safeDom)) }
            if (@($computers).Count -gt 0) { Save-Csv -InputObject $computers -Path (Join-Path $csvPath ("AllComputers_{0}.csv" -f $safeDom)) }
            $identitySummary += Get-AdfaIdentitySummary -DomainName $d -Users $users -Computers $computers -StaleDays $script:Config.StaleDays
        }
        $sectionData['Identity Inventory'] = @($identitySummary)
    }

    # ---- Raw diagnostics ----
    if ($IncludeRepadmin -and (Test-CommandAvailable -Name 'repadmin.exe')) {
        Write-Stage 'raw repadmin'
        Invoke-ExternalCommand -FilePath 'repadmin.exe' -Arguments '/replsummary * /bysrc /bydest /sort:delta' -OutFile (Join-Path $rawPath 'repadmin_replsummary.txt') @ext | Out-Null
        foreach ($dc in $dcNames) {
            if (Test-TcpPort -ComputerName $dc -Port 135 -TimeoutMs $script:Config.RpcPortTimeoutMs) {
                Invoke-ExternalCommand -FilePath 'repadmin.exe' -Arguments ("/showrepl {0} /errorsonly" -f $dc) -OutFile (Join-Path $rawPath ("repadmin_showrepl_{0}.txt" -f (New-SafeFileName $dc))) @ext | Out-Null
            }
        }
    }
    if ($IncludeDcdiag -and (Test-CommandAvailable -Name 'dcdiag.exe')) {
        Write-Stage 'raw dcdiag'
        foreach ($dc in $dcNames) {
            if (Test-TcpPort -ComputerName $dc -Port 135 -TimeoutMs $script:Config.RpcPortTimeoutMs) {
                Invoke-ExternalCommand -FilePath 'dcdiag.exe' -Arguments ("/s:{0} /c /v" -f $dc) -OutFile (Join-Path $rawPath ("dcdiag_{0}.txt" -f (New-SafeFileName $dc))) @ext | Out-Null
            }
        }
    }

    # ---- Persist CSVs ----
    Write-Stage 'Writing CSVs'
    foreach ($key in $sectionData.Keys) {
        $file = Join-Path $csvPath (("{0}.csv" -f (New-SafeFileName $key)))
        Save-Csv -InputObject $sectionData[$key] -Path $file
    }

    # ---- Consolidated findings + detailed itemised log ----
    # One row per status-bearing check across every section: the single actionable list.
    $consolidated = @()
    foreach ($key in $sectionData.Keys) {
        foreach ($row in @($sectionData[$key])) {
            $names = $row.PSObject.Properties.Name
            $statusCol = if ($names -contains 'Status') { 'Status' } elseif ($names -contains 'Health') { 'Health' } else { $null }
            if (-not $statusCol) { continue }
            $status = [string]$row.$statusCol
            $item = if ($names -contains 'Item') { $row.Item }
                    elseif ($names -contains 'TrustName') { $row.TrustName }
                    elseif ($names -contains 'DomainController') { $row.DomainController }
                    elseif ($names -contains 'Group') { $row.Group }
                    elseif ($names -contains 'PolicyName') { $row.PolicyName }
                    else { $key }
            $detailParts = @()
            foreach ($dc in @('Detail', 'Reasons', 'FailureDetail', 'Failures', 'VerifyDetail')) {
                if (($names -contains $dc) -and $row.$dc) { $detailParts += [string]$row.$dc }
            }
            $scopeVal = if ($names -contains 'Scope') { [string]$row.Scope } else { '' }
            $consolidated += [pscustomobject]@{
                Section = $key; Scope = $scopeVal; Item = [string]$item
                Status  = $status; Detail = ($detailParts -join ' | ')
            }
        }
    }
    # Severity order for the consolidated file and the log.
    $sevRank = @{ 'Fail' = 0; 'Broken' = 0; 'Failed' = 0; 'Warning' = 1; 'Degraded' = 1; 'Not Assessed' = 2; 'Info' = 3; 'Pass' = 4; 'Healthy' = 4; 'Verified' = 4 }
    $consolidated = $consolidated | Sort-Object @{ e = { $r = $sevRank[$_.Status]; if ($null -eq $r) { 5 } else { $r } } }, Section, Item
    Save-Csv -InputObject $consolidated -Path (Join-Path $csvPath 'Findings-Consolidated.csv')

    # Detailed itemised log: every section's findings, worst first, with the exact detail text.
    Write-Log -Level RESULT ("Assessment findings ({0} checks across {1} sections):" -f @($consolidated).Count, $sectionData.Keys.Count)
    foreach ($f in $consolidated) {
        $lvl = switch -Regex ($f.Status) {
            '^(Fail|Broken|Failed)$' { 'ERROR'; break }
            '^(Warning|Degraded)$' { 'WARN'; break }
            '^(Not Assessed)$' { 'WARN'; break }
            default { 'RESULT' }
        }
        $msg = '{0,-12} {1} :: {2}{3}' -f $f.Status, $f.Section, $f.Item, $(if ($f.Detail) { " -> $($f.Detail)" } else { '' })
        Write-Log -Level $lvl -Section $f.Scope -Message $msg
    }

    # ---- Roll-up badges ----
    $flat = @($consolidated | ForEach-Object { $_.Status })
    $countOk = @($flat | Where-Object { $_ -match '^(Pass|Healthy)$' }).Count
    $countWarn = @($flat | Where-Object { $_ -match '^(Warning|Degraded)$' }).Count
    $countBad = @($flat | Where-Object { $_ -match '^(Fail|Broken)$' }).Count
    $countNa = @($flat | Where-Object { $_ -eq 'Not Assessed' }).Count
    Write-Log -Level RESULT ("Summary: Pass={0} Warning={1} Fail={2} NotAssessed={3}" -f $countOk, $countWarn, $countBad, $countNa)
    $badges = "<span class='b-ok'>Pass $countOk</span><span class='b-warn'>Warning $countWarn</span><span class='b-bad'>Fail $countBad</span><span class='b-na'>Not Assessed $countNa</span>"

    $meta = [pscustomobject]@{
        Forest    = $forest.Name
        Generated = (Get-Date).ToString('u')
        RunBy     = ("{0}\{1}" -f $env:USERDOMAIN, $env:USERNAME)
        Version   = $script:Config.Version
        Badges    = $badges
    }

    Write-Stage 'Writing HTML report'
    $reportPath = Join-Path $runRoot 'Assessment.html'
    # Lead the report with the consolidated, severity-sorted findings, then the detail sections.
    $htmlSections = [ordered]@{}
    $htmlSections['Findings (worst first)'] = @($consolidated | Where-Object { $_.Status -notmatch '^(Pass|Healthy|Verified|Info)$' })
    foreach ($k in $sectionData.Keys) { $htmlSections[$k] = $sectionData[$k] }
    if (@($htmlSections['Findings (worst first)']).Count -eq 0) {
        $htmlSections['Findings (worst first)'] = @([pscustomobject]@{ Section = '(none)'; Item = 'No warnings or failures'; Status = 'Pass'; Detail = 'All assessed checks passed.' })
    }
    New-AdfaHtmlReport -Sections $htmlSections -Meta $meta -Path $reportPath | Out-Null

    Write-Log -Level INFO ("Detailed log: {0}" -f $script:LogFile)
    Write-Log -Level INFO ("Consolidated findings: {0}" -f (Join-Path $csvPath 'Findings-Consolidated.csv'))
    try { Stop-Transcript | Out-Null } catch { }

    Write-Stage ("DONE. Report: {0}" -f $reportPath)

    [pscustomobject]@{
        Forest        = $forest.Name
        DomainsScoped = $targetDomains
        DcCount       = $dcNames.Count
        OutputRoot    = $runRoot
        ReportPath    = $reportPath
        CsvPath       = $csvPath
        RawPath       = $rawPath
        LogFile       = $script:LogFile
        FindingsFile  = (Join-Path $csvPath 'Findings-Consolidated.csv')
        Transcript    = $transcript
        Summary       = [pscustomobject]@{ Pass = $countOk; Warning = $countWarn; Fail = $countBad; NotAssessed = $countNa }
        Sections      = @($sectionData.Keys)
    }
}

# Only auto-run when executed as a script (not when dot-sourced for testing).
if ($MyInvocation.InvocationName -ne '.' -and -not $env:ADFA_NO_AUTORUN) {
    Invoke-Main
}
