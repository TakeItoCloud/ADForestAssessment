#Requires -Version 5.1
# ------------------------------------------------------------------------------
#  ADForestAssessment
#  Copyright (c) 2026 Carlos Annes / TakeItToCloud. All rights reserved.
#  Licensed, not sold. Unauthorised copying, redistribution, or commercial use
#  is prohibited. See LICENSE at the repository root.
# ------------------------------------------------------------------------------
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
        - RECOVERY & CONSISTENCY (post-incident, e.g. after a restore-from-backup):
            * DNS vs AD divergence - DC locator SRV records compared against the DCs the
              directory actually contains (stale entries for removed DCs, live DCs not
              advertised)
            * DSA GUID CNAME records in _msdcs - the usual cause of RPC 1722 replication
              failures after metadata cleanup or restore
            * Global Catalog flag vs _gc._tcp DNS advertisement
            * Per-DC reachability matrix on the ports replication requires
              (Kerberos/RPC/LDAP/SMB + LDAPS/GC/ADWS)
            * DC machine-account password age (replicated attribute, collected centrally)
              and per-DC secure-channel verification over WinRM where reachable
            * Directory Service event log scan per DC for the events that block or mask
              recovery: lingering objects (1988), tombstone-lifetime exceeded (2042),
              USN rollback (2095), unsupported restore (2103), GUID DNS lookup failures
              (2087/2088), KCC topology failures (1311/1865/1925)
        - Exchange schema markers
        - Optional raw repadmin / dcdiag capture

    Every Fail / Warning / Broken / Degraded row in the consolidated findings carries a
    best-practice remediation recommendation (Recommendation column in
    csv\Findings-Consolidated.csv, the detailed log, and the HTML lead section).

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

    Recovery sections (post-incident): DnsAdConsistency, DsaCname, GcConsistency, PortMatrix,
    DcSecureChannel, DsEvents. For a focused post-restore triage run:
    -Sections DnsAdConsistency,DsaCname,GcConsistency,PortMatrix,Replication,Trusts,DcSecureChannel,DsEvents,TimeSync,Sysvol,Backup

.PARAMETER IncludeDcdiag
    Also capture raw 'dcdiag /c /v' output per DC under raw\.

.PARAMETER IncludeRepadmin
    Also capture raw 'repadmin /replsummary' and per-DC '/showrepl /errorsonly' under raw\.

.PARAMETER IncludeLingeringObjectScan
    Proactively enumerate lingering objects per DC with
    'repadmin /removelingeringobjects ... /advisory_mode' (each DC compared against its
    domain's PDC emulator). Advisory mode changes NOTHING in the directory, but it does
    write events (1938/1942/1946) to the target DCs' Directory Service logs - hence
    opt-in. Strongly recommended in a post-restore recovery, where tombstone lifetime
    may already have been exceeded.

.PARAMETER IncludeSysvolBacklog
    Measure the SYSVOL replication backlog in both directions between every DC and its domain's
    PDC emulator, using the DFSR module. Read-only. Opt-in because it costs two RPC round trips
    per DC. Get-DfsrBacklog displays at most 100 records and its true total appears only in the
    verbose stream, so where that cannot be read the count is reported as a floor, never as a
    total.

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
        'DnsDepth', 'Redundancy', 'ExchangeSchema', 'ExchangeSeReadiness',
        'DnsAdConsistency', 'DsaCname', 'GcConsistency', 'PortMatrix', 'DcSecureChannel',
        'DsEvents')]
    [string[]]$Sections = @('All'),

    [switch]$IncludeDcdiag,
    [switch]$IncludeRepadmin,
    [switch]$IncludeLingeringObjectScan,

    # Measures the SYSVOL backlog in both directions between each DC and its domain's PDC
    # emulator. Opt-in because it costs two RPC round trips per DC and needs the optional DFSR
    # module; strongly recommended on a post-restore run, where a standing SYSVOL backlog is the
    # difference between "Group Policy is converging" and "it silently is not".
    [switch]$IncludeSysvolBacklog,
    [switch]$SkipTrustVerification,

    [string]$Server,
    [pscredential]$Credential,

    # Replaces the built-in Exchange SE prerequisite table (supported forest functional levels
    # and DC operating systems) from a JSON file, so a revision to Microsoft's supportability
    # matrix is a config edit rather than a code change. Keys omitted from the file keep their
    # built-in value; an unreadable or malformed file is a terminating error rather than a
    # silent fall back to defaults, because a run that quietly judged against the wrong table
    # would be worse than one that stopped.
    [ValidateNotNullOrEmpty()]
    [string]$ExchangeSeConfigPath,

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
    Version                 = '1.8.0'
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
    # --- Recovery & consistency checks (post-incident) ---
    # DC machine-account passwords rotate every 30 days by default (client-initiated).
    # pwdLastSet is a replicated attribute, so age is collectable centrally; an old value
    # on a DC means rotation is not happening - typical of a DC restored from old backup.
    DcPasswordWarnDays      = 45
    DcPasswordFailDays      = 90
    # Ports replication and authentication actually require between DCs.
    ReplicationPorts        = @(
        @{ Port = 88;   Name = 'Kerberos';            Critical = $true }
        @{ Port = 135;  Name = 'RPC Endpoint Mapper'; Critical = $true }
        @{ Port = 389;  Name = 'LDAP';                Critical = $true }
        @{ Port = 445;  Name = 'SMB';                 Critical = $true }
        @{ Port = 636;  Name = 'LDAPS';               Critical = $false }
        @{ Port = 3268; Name = 'Global Catalog LDAP'; Critical = $false }
        @{ Port = 9389; Name = 'ADWS';                Critical = $false }
    )
    DsEventLookbackDays     = 14
    # --- DFS Replication log events that decide whether SYSVOL is actually replicating ------
    # Meanings are taken from the vendor's own troubleshooting articles, not inferred:
    #   https://learn.microsoft.com/troubleshoot/windows-server/networking/troubleshoot-missing-sysvol-and-netlogon-shares
    #   https://learn.microsoft.com/troubleshoot/windows-server/group-policy/force-authoritative-non-authoritative-synchronization  (KB 2218556)
    # Read: 2026-09-21. Events whose meaning the vendor does not publish are deliberately absent
    # rather than guessed.
    DfsrEventsOfInterest    = @(
        @{ Id = 2213; Severity = 'Fail'; Meaning = 'Dirty shutdown detected - DFSR replication is PAUSED on this volume and will not resume until the ResumeReplication WMI method is run.' }
        @{ Id = 4012; Severity = 'Fail'; Meaning = 'Content freshness protection stopped replication - the folder has not replicated for longer than MaxOfflineTimeInDays. SYSVOL will not converge without reinitialisation.' }
        @{ Id = 4114; Severity = 'Fail'; Meaning = 'SYSVOL is no longer being replicated on this DC (membership disabled, msDFSR-Enabled=FALSE).' }
        @{ Id = 4144; Severity = 'Fail'; Meaning = 'DFSR membership disabled for this replicated folder - logged during a D2/D4-equivalent reinitialisation.' }
        @{ Id = 4614; Severity = 'Warning'; Meaning = 'DFSR is WAITING to perform initial replication of SYSVOL. Until event 4604 follows, this DC has not initialised SYSVOL.' }
        @{ Id = 4604; Severity = 'Info'; Meaning = 'SYSVOL replicated folder initialised successfully - the healthy end state.' }
        @{ Id = 2212; Severity = 'Warning'; Meaning = 'Dirty shutdown - DFSR is rebuilding its database; expect 2214 to follow on completion.' }
        @{ Id = 2214; Severity = 'Info'; Meaning = 'Dirty shutdown recovery completed.' }
        @{ Id = 5002; Severity = 'Warning'; Meaning = 'DFSR connection error with a replication partner.' }
        @{ Id = 5014; Severity = 'Warning'; Meaning = 'DFSR RPC communication problem with a replication partner.' }
    )
    DfsrEventLookbackDays   = 14
    # --- SYSVOL backlog thresholds ---------------------------------------------------------
    # Microsoft is explicit that a DFSR backlog "is not necessarily an indication of problems"
    # and "indicates latency", so these are not vendor limits and are not presented as such:
    #   https://learn.microsoft.com/powershell/module/dfsr/get-dfsrbacklog  (read 2026-09-21)
    # The reasoning for applying a tighter bar to SYSVOL than to a general replicated folder is
    # that SYSVOL only changes when Group Policy changes, so it should sit at or near zero; a
    # standing backlog means a policy edit is not reaching that DC. Thresholds live here so an
    # operator can move them without touching code.
    SysvolBacklogWarnAt     = 1
    # FailAt is set to the cmdlet's own 100-record display cap: at or above it the true size is
    # no longer observable from the object count, and a folder that changes only with Group
    # Policy does not accumulate that much ordinary latency.
    SysvolBacklogFailAt     = 100
    # Get-DfsrBacklog returns at most 100 records; the true total appears only in the verbose
    # stream. Kept as data so the cap is not a magic number buried in the parser.
    DfsrBacklogDisplayCap   = 100
    SysvolReplicationGroup  = 'Domain System Volume'
    SysvolReplicatedFolder  = 'SYSVOL Share'
    # DN template for the SYSVOL subscription object, per KB 2218556. msDFSR-Enabled=FALSE means
    # SYSVOL replication is switched off on that DC; msDFSR-options=1 marks it authoritative (the
    # DFSR equivalent of FRS D4). Both are set by hand during a recovery and are easy to leave
    # behind, and neither is visible anywhere else in this report.
    SysvolSubscriptionDn    = 'CN=SYSVOL Subscription,CN=Domain System Volume,CN=DFSR-LocalSettings,{0}'
    SysvolShares            = @('SYSVOL', 'NETLOGON')
    # --- Exchange Server SE: the AD prerequisites, as a versioned table -------------------
    # Volatile vendor facts, so they live here with their source and read date and can be
    # replaced from a file via -ExchangeSeConfigPath when Microsoft revises the matrix. A new
    # supported OS or functional level must be a config edit, never a code edit.
    #
    # Source: https://learn.microsoft.com/exchange/plan-and-deploy/supportability-matrix#supported-active-directory-environments
    # Read:   2026-09-21
    ExchangeSe              = @{
        Release                     = 'Exchange Server SE'
        SourceUrl                   = 'https://learn.microsoft.com/exchange/plan-and-deploy/supportability-matrix#supported-active-directory-environments'
        ReadDate                    = '2026-09-21'
        # Get-ADForest().ForestMode enum names. Windows Server 2016 is the highest forest
        # functional level Microsoft has ever shipped - there is no 2019/2022/2025 value to
        # list, which is why this table stops there rather than being out of date.
        SupportedForestModes        = @('Windows2016Forest', 'Windows2012R2Forest')
        # Matched against Get-ADComputer's OperatingSystem string. Note 2012 R2 is supported
        # and plain 2012 is NOT, so the R2 pattern must not be loosened to bare '2012'.
        SupportedDomainControllerOs = @(
            @{ Label = 'Windows Server 2025'; Pattern = '(?i)windows server\s*2025' }
            @{ Label = 'Windows Server 2022'; Pattern = '(?i)windows server\s*2022' }
            @{ Label = 'Windows Server 2019'; Pattern = '(?i)windows server\s*2019' }
            @{ Label = 'Windows Server 2016'; Pattern = '(?i)windows server\s*2016' }
            @{ Label = 'Windows Server 2012 R2'; Pattern = '(?i)windows server\s*2012\s*r2' }
        )
        # "Read-only GCs and read-only DCs aren't supported" - same source.
        ReadOnlySupported           = $false
    }
    # Directory Service events that block or mask recovery in a mixed-restore forest.
    DsEventsOfInterest      = @(
        @{ Id = 1988; Severity = 'Fail';    Meaning = 'Lingering object detected - replication BLOCKED by strict consistency.' }
        @{ Id = 2042; Severity = 'Fail';    Meaning = 'Replication stopped - tombstone lifetime exceeded; will not resume without intervention.' }
        @{ Id = 2095; Severity = 'Fail';    Meaning = 'USN rollback detected - the directory is silently diverging.' }
        @{ Id = 2103; Severity = 'Fail';    Meaning = 'AD DS database restored using an unsupported restore procedure.' }
        @{ Id = 2087; Severity = 'Fail';    Meaning = 'DNS lookup failure resolving a source DC GUID - direct cause of RPC 1722 replication errors.' }
        @{ Id = 2088; Severity = 'Warning'; Meaning = 'DNS lookup failed but a fallback succeeded - DNS is broken and replication is masking it.' }
        @{ Id = 1311; Severity = 'Warning'; Meaning = 'KCC could not build a replication topology.' }
        @{ Id = 1865; Severity = 'Warning'; Meaning = 'KCC could not reach one or more sites.' }
        @{ Id = 1925; Severity = 'Warning'; Meaning = 'Failed to establish a replication link.' }
        @{ Id = 1084; Severity = 'Warning'; Meaning = 'Replication failed for a specific object.' }
    )
    # NTDS-DSA options bit 0 = this DSA is a Global Catalog.
    NtdsDsaOptionIsGc       = 1
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

function Expand-AdfaRowList {
    <#
    .SYNOPSIS
        Flattens nested row collections and drops nulls, so a section is always a flat
        list of finding objects.
    .DESCRIPTION
        Defence in depth for the aggregation fault found on the first multi-domain live
        run. Collectors used to end in `return , @($rows)`, which emits the array as ONE
        object; the per-domain pattern

            $rows = foreach ($d in $targetDomains) { Get-AdfaSomething -DomainName $d }

        then produced an array OF ARRAYS once there was more than one domain, and
        `@($rows)` does not flatten that. Downstream, every consumer looked for a Status
        property on what was actually an array, found none, and skipped the row - so whole
        sections were collected and then silently discarded. Single-domain runs were
        unaffected, which is why it went unseen.

        The collectors now return plainly, so nesting should not arise. This function
        makes the output path robust to it anyway: a shape mistake must never again cost
        data without saying so.
    .OUTPUTS
        [object[]]
    #>
    [CmdletBinding()]
    [OutputType([object[]])]
    param([Parameter(Mandatory)][AllowNull()][AllowEmptyCollection()]$Rows)

    $out = New-Object System.Collections.Generic.List[object]
    foreach ($r in @($Rows)) {
        if ($null -eq $r) { continue }
        # Flatten a nested collection, but never a string or a dictionary.
        if (($r -is [System.Collections.IEnumerable]) -and ($r -isnot [string]) -and ($r -isnot [System.Collections.IDictionary])) {
            foreach ($inner in $r) { if ($null -ne $inner) { [void]$out.Add($inner) } }
        }
        else { [void]$out.Add($r) }
    }
    return @($out.ToArray())
}

function ConvertTo-AdfaRowSet {
    <#
    .SYNOPSIS
        Normalises a collection of findings to one common column set, so every row carries
        every column (missing values become '').
    .DESCRIPTION
        A section's rows are not always the same shape: an unreachable DC, a domain whose
        trusts could not be enumerated, or a failed GPO query emit a shorter object than the
        full-data rows beside them. That heterogeneity broke both output paths:

          - HTML: the renderer took its columns from row 0 and then read every column off
            every row, so under Set-StrictMode a shorter row threw PropertyNotFoundStrict
            and the whole report failed to write.
          - CSV: Export-Csv takes its columns from the FIRST object only, so whenever a
            short row happened to sort first, the extra columns of every later row were
            silently dropped from the file.

        Both are fixed here rather than in each collector, because any future section can
        be heterogeneous. Column order is first-seen (row 0's columns first, then any new
        ones as they appear), so the report layout is unchanged when rows already agree.
    .OUTPUTS
        [pscustomobject[]]
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param([Parameter(Mandatory)][AllowNull()][AllowEmptyCollection()]$Rows)

    $items = @(Expand-AdfaRowList -Rows $Rows)
    if ($items.Count -eq 0) { return @() }

    # First-seen column order across every row.
    $cols = New-Object System.Collections.Generic.List[string]
    foreach ($item in $items) {
        foreach ($name in @($item.PSObject.Properties.Name)) {
            if (-not $cols.Contains($name)) { $cols.Add($name) }
        }
    }
    if ($cols.Count -eq 0) { return @() }

    $out = foreach ($item in $items) {
        $ordered = [ordered]@{}
        foreach ($c in $cols) {
            $prop = $item.PSObject.Properties[$c]   # $null when absent - StrictMode-safe
            if ($null -eq $prop -or $null -eq $prop.Value) { $ordered[$c] = '' }
            else { $ordered[$c] = $prop.Value }
        }
        [pscustomobject]$ordered
    }
    # Plain return: callers wrap with @(); `return @()` would hand back one element that
    # IS the empty array (PORT-PLAN P3).
    return @($out)
}

function Save-Csv {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowNull()]$InputObject,
        [Parameter(Mandatory)][string]$Path
    )
    if ($null -eq $InputObject) { return }
    # Normalise first: Export-Csv columns come from the first object, so a short row
    # sorting first would silently drop the other rows' columns from the file.
    $rows = @(ConvertTo-AdfaRowSet -Rows $InputObject)
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

    # Normalise before counting: collectors return plainly, so an empty result arrives as
    # $null and $null.Count throws under StrictMode.
    $warn = @($SecurityWarnings | Where-Object { $_ })
    foreach ($w in $warn) { $reasons.Add($w) }

    if ($warn.Count -gt 0) {
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

function Test-AdfaRemoteSecureChannel {
    <#
    .SYNOPSIS
        Verifies a trust direction by executing nltest /sc_verify ON a domain controller
        of the partner domain, over WinRM. The inbound side of a trust can only be proven
        from the partner's side: running nltest locally against our own domain name
        verifies this machine's own channel and returns NERR_Success on any healthy DC,
        regardless of the trust's real state. Fail-closed: when the partner DC cannot be
        remoted to, returns Not Assessed naming the exact command to run there - never a
        fabricated Verified.
    .OUTPUTS
        [pscustomobject] Result, Tool, Detail
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)][string]$PartnerDomain,
        [Parameter(Mandatory)][string]$VerifyDomain,
        [string]$PartnerDc,
        [pscredential]$Credential,
        [int]$RpcPortTimeoutMs = 1200
    )
    $remoteHost = $PartnerDc
    if ([string]::IsNullOrWhiteSpace($remoteHost)) { $remoteHost = $PartnerDomain }
    $manual = ("Run 'nltest /sc_verify:{0}' on a DC in {1} to verify this direction." -f $VerifyDomain, $PartnerDomain)

    if (-not (Test-TcpPort -ComputerName $remoteHost -Port 5985 -TimeoutMs $RpcPortTimeoutMs)) {
        return [pscustomobject]@{ Result = 'Not Assessed'; Tool = 'winrm'; Detail = ("WinRM (5985) not reachable on {0}. {1}" -f $remoteHost, $manual) }
    }
    try {
        $icm = @{
            ComputerName = $remoteHost
            ScriptBlock  = { param($d) & nltest.exe "/sc_verify:$d" 2>&1 | Out-String }
            ArgumentList = $VerifyDomain
            ErrorAction  = 'Stop'
        }
        if ($Credential) { $icm.Credential = $Credential }
        $out = [string](Invoke-Command @icm)
        if ($out -match 'NERR_Success') {
            return [pscustomobject]@{ Result = 'Verified'; Tool = 'winrm+nltest'; Detail = ("nltest /sc_verify:{0} executed on {1} reported NERR_Success." -f $VerifyDomain, $remoteHost) }
        }
        $excerpt = (($out -split "`r?`n") | Where-Object { $_ -match '\S' } | Select-Object -First 3) -join ' | '
        if (-not $excerpt) { $excerpt = 'no output' }
        return [pscustomobject]@{ Result = 'Failed'; Tool = 'winrm+nltest'; Detail = ("nltest /sc_verify:{0} executed on {1} did not report success: {2}" -f $VerifyDomain, $remoteHost, $excerpt) }
    }
    catch {
        return [pscustomobject]@{ Result = 'Not Assessed'; Tool = 'winrm'; Detail = ("WinRM query to {0} failed: {1} {2}" -f $remoteHost, $_.Exception.Message, $manual) }
    }
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
    return $warnings.ToArray()
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
        return @([pscustomobject]@{
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
                # The inbound direction can only be proven from the partner's side. A local
                # nltest against our own domain name verifies this machine's own channel and
                # succeeds on any healthy DC - a false Verified. Execute the verification ON
                # a partner DC over WinRM; degrade to Not Assessed when that is not possible.
                $trustCred = $null
                if ($AdParams.ContainsKey('Credential')) { $trustCred = $AdParams['Credential'] }
                $i = Test-AdfaRemoteSecureChannel -PartnerDomain $target -VerifyDomain $DomainName `
                    -PartnerDc $probeHost -Credential $trustCred -RpcPortTimeoutMs $RpcPortTimeoutMs
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
    return $results
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
    return @($inv)
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
        # AllowEmptyCollection: when DC enumeration fails the caller passes an empty list, and a
        # Mandatory [string[]] refuses to bind it - which aborted the whole run with a parameter
        # binding error instead of reporting the section as unassessed. The recovery sections
        # added in v1.4.0 already allowed an empty list; these older ones did not.
        [Parameter(Mandatory)][AllowEmptyCollection()][string[]]$DomainControllers,
        [hashtable]$RepParams = @{},
        [int]$RpcPortTimeoutMs = 1200,
        [int]$StaleMinutes = 180
    )
    if (@($DomainControllers).Count -eq 0) {
        return @(New-Finding -Area 'Replication' -Item 'Replication health' -Status $script:Status.NotAssessed `
                -Detail 'No domain controllers were enumerated, so replication health could not be assessed. This is not a clean result.')
    }
    $rows = foreach ($dc in $DomainControllers) {
        $rpcOk = Test-TcpPort -ComputerName $dc -Port 135 -TimeoutMs $RpcPortTimeoutMs
        $adwsOk = Test-TcpPort -ComputerName $dc -Port 9389 -TimeoutMs $RpcPortTimeoutMs
        if (-not ($rpcOk -and $adwsOk)) {
            # Same shape as the full row below - a section whose rows disagree breaks CSV
            # columns and, under StrictMode, the HTML renderer.
            [pscustomobject]@{
                DomainController = $dc; PartnerCount = $null; PartnerErrors = $null
                LastSuccessMinutesAgo = $null; FailureCount = $null; OldestFailureTime = $null
                ReplicationQueue = $null; Status = $script:Status.NotAssessed
                FailureDetail = ''
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
    return @($rows)
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
    param([Parameter(Mandatory)][pscustomobject]$Topology,
        # See the note on Get-AdfaReplicationHealth: an empty inventory must degrade, not abort.
        [Parameter(Mandatory)][AllowEmptyCollection()][pscustomobject[]]$DomainControllers)
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
    return @($findings)
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
        # AllowEmptyCollection: when DC enumeration fails the caller passes an empty list, and a
        # Mandatory [string[]] refuses to bind it - which aborted the whole run with a parameter
        # binding error instead of reporting the section as unassessed. The recovery sections
        # added in v1.4.0 already allowed an empty list; these older ones did not.
        [Parameter(Mandatory)][AllowEmptyCollection()][string[]]$DomainControllers,
        [int]$TimeoutSeconds = 90,
        [int]$Retries = 2,
        [int]$RetryDelaySeconds = 2,
        [int]$RpcPortTimeoutMs = 1200
    )
    if (@($DomainControllers).Count -eq 0) {
        return @(New-Finding -Area 'DcDiagnostics' -Item 'dcdiag grid' -Status $script:Status.NotAssessed `
                -Detail 'No domain controllers were enumerated, so no dcdiag test could be run. This is not a clean result.')
    }
    # Full post-restore grid. The nine beyond the original six matter specifically after
    # a restore: MachineAccount (DC computer object/SPNs), ObjectsReplicated (DSA objects
    # converged), RidManager (RID pool reachable), KccEvent (topology errors), Intersite,
    # VerifyReferences/CrossRefValidation (FSMO + partition cross-refs intact),
    # KnowsOfRoleHolders, DFSREvent (SYSVOL replication errors).
    $tests = 'Netlogons', 'Services', 'Replications', 'FsmoCheck', 'Advertising', 'SysVolCheck',
        'MachineAccount', 'ObjectsReplicated', 'RidManager', 'KccEvent', 'VerifyReferences',
        'CrossRefValidation', 'KnowsOfRoleHolders', 'Intersite', 'DFSREvent'
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
    return @($rows)
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
    param([Parameter(Mandatory)][AllowEmptyCollection()][string[]]$DomainControllers, [pscredential]$Credential, [int]$RpcPortTimeoutMs = 1200)
    if (@($DomainControllers).Count -eq 0) {
        return @(New-Finding -Area 'DNS' -Item 'DNS health' -Status $script:Status.NotAssessed `
                -Detail 'No domain controllers were enumerated, so no DNS server could be queried. This is not a clean result.')
    }
    if (-not (Test-ModuleAvailable -Name 'DnsServer')) {
        return @(New-Finding -Area 'DNS' -Item 'DnsServer module' -Status $script:Status.NotAssessed -Detail 'RSAT DnsServer module not installed on this host.')
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
            catch {
                # Previously silent: the forwarders row simply vanished, so a reader could not
                # tell "no forwarders configured" from "the query failed".
                $rows += New-Finding -Area 'DNS' -Item ("{0}: forwarders" -f $dc) -Status $script:Status.NotAssessed -Detail ("Forwarder list could not be read: {0}" -f $_.Exception.Message)
            }
            $insecureXfer = @($zones | Where-Object { $_.PSObject.Properties.Name -contains 'SecureSecondaries' -and $_.SecureSecondaries -eq 'TransferAnyServer' })
            if ($insecureXfer.Count -gt 0) {
                $rows += New-Finding -Area 'DNS' -Item ("{0}: zone transfer" -f $dc) -Status $script:Status.Warning -Detail ("Zones allowing transfer to ANY server: {0}" -f (($insecureXfer.ZoneName | Select-Object -First 8) -join ', '))
            }
        }
        catch {
            $rows += New-Finding -Area 'DNS' -Item $dc -Status $script:Status.NotAssessed -Detail $_.Exception.Message
        }
    }
    return @($rows)
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
    return @($rows)
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
        return @(New-Finding -Area 'GPO' -Item 'GroupPolicy module' -Status $script:Status.NotAssessed -Detail 'RSAT GroupPolicy module not installed on this host.' -Scope $DomainName)
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
    return @($rows)
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
    catch {
        # Previously silent. With no row at all, a report showing only the default policy could
        # not be distinguished from one where the FGPP query failed - and an absent key and a
        # measured absence are different claims.
        $rows += New-Finding -Scope $DomainName -Area 'PasswordPolicy' -Item 'Fine-grained password policies' `
            -Status $script:Status.NotAssessed `
            -Detail ("Could not be enumerated: {0}. This is NOT the same as 'no fine-grained policies exist'." -f $_.Exception.Message)
    }
    return @($rows)
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
    return @($rows)
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

    return @($rows)
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
    return @($rows)
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
    return (@($set) | Sort-Object)
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
    if ($users.Count -eq 0) { return @() }
    $props = Get-AdfaObjectPropertyUnion -Objects $users
    $flat = foreach ($u in $users) { ConvertTo-AdfaFlatObject -InputObject $u -Property $props }
    return @($flat)
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
    if ($computers.Count -eq 0) { return @() }
    $props = Get-AdfaObjectPropertyUnion -Objects $computers
    $flat = foreach ($c in $computers) { ConvertTo-AdfaFlatObject -InputObject $c -Property $props }
    return @($flat)
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
    return @($rows)
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
    return @($dupes | Where-Object { $null -ne $_ })
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
            return @($rows)
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
    return @($rows)
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
    return @($rows)
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

    return @($rows)
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

    return @($rows)
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
    param([Parameter(Mandatory)][AllowEmptyCollection()][string[]]$DomainControllers, [pscredential]$Credential, [int]$RpcPortTimeoutMs = 1200)
    if (@($DomainControllers).Count -eq 0) {
        return @(New-Finding -Area 'DCHardening' -Item 'DC hardening' -Status $script:Status.NotAssessed `
                -Detail 'No domain controllers were enumerated, so no hardening setting could be read. This is not a clean result.')
    }
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
    return @($rows)
}

function ConvertFrom-AdfaShowreplCsv {
    <#
    .SYNOPSIS
        Pure parser for 'repadmin /showrepl * /csv' output. Locates the CSV header and
        returns one object per replication link. Tolerates banner lines before the header.
    .OUTPUTS
        [pscustomobject[]]
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param([AllowEmptyString()][string]$Text = '')
    # Plain returns on purpose: callers wrap with @(...), and the `return @()` shape
    # would hand them one element that IS the empty array (PORT-PLAN P3).
    if ([string]::IsNullOrWhiteSpace($Text)) { return @() }
    $lines = @($Text -split "`r?`n")
    $headerIdx = -1
    for ($i = 0; $i -lt $lines.Count; $i++) {
        if ($lines[$i] -match 'Destination DSA' -and $lines[$i] -match 'Naming Context') { $headerIdx = $i; break }
    }
    if ($headerIdx -lt 0) { return @() }
    $csv = @($lines[$headerIdx..($lines.Count - 1)] | Where-Object { $_ -match '\S' })
    try { return @($csv | ConvertFrom-Csv) }
    catch { return @() }
}

function Get-AdfaRepadminReplication {
    <#
    .SYNOPSIS
        Cross-checks replication with 'repadmin /showrepl * /csv', which fans out from
        this host and reports links the Get-ADReplication* cmdlets miss when a partner
        is unreachable (the cmdlets query each DC's own view; repadmin reports the
        failing edge from the surviving side). One finding per failing link; a Pass
        summary when every reported link is clean.
    .OUTPUTS
        [pscustomobject[]]
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param([int]$TimeoutSeconds = 300, [int]$Retries = 2, [int]$RetryDelaySeconds = 2)
    if (-not (Test-CommandAvailable -Name 'repadmin.exe')) {
        return @(New-Finding -Area 'Replication' -Item 'repadmin cross-check' -Status $script:Status.NotAssessed -Detail 'repadmin.exe not available on this host.')
    }
    $r = Invoke-ExternalCommand -FilePath 'repadmin.exe' -Arguments '/showrepl * /csv' `
        -TimeoutSeconds $TimeoutSeconds -Retries $Retries -RetryDelaySeconds $RetryDelaySeconds
    $links = @(ConvertFrom-AdfaShowreplCsv -Text $r.StdOut)
    if (@($links).Count -eq 0) {
        return @(New-Finding -Area 'Replication' -Item 'repadmin cross-check' -Status $script:Status.NotAssessed -Detail ("Could not parse 'repadmin /showrepl * /csv' output. {0}" -f $(if ($r.Error) { $r.Error } else { 'See raw capture (-IncludeRepadmin) for the unparsed output.' })))
    }
    $rows = @()
    $failing = 0
    foreach ($l in $links) {
        $names = $l.PSObject.Properties.Name
        $failures = 0
        if ($names -contains 'Number of Failures' -and "$($l.'Number of Failures')" -match '^\d+$') { $failures = [int]$l.'Number of Failures' }
        if ($failures -gt 0) {
            $failing++
            $src = ''; $dst = ''; $nc = ''; $lastOk = ''; $status = ''
            if ($names -contains 'Source DSA') { $src = [string]$l.'Source DSA' }
            if ($names -contains 'Destination DSA') { $dst = [string]$l.'Destination DSA' }
            if ($names -contains 'Naming Context') { $nc = [string]$l.'Naming Context' }
            if ($names -contains 'Last Success Time') { $lastOk = [string]$l.'Last Success Time' }
            if ($names -contains 'Last Failure Status') { $status = [string]$l.'Last Failure Status' }
            $rows += New-Finding -Area 'Replication' -Item ("repadmin: {0} <- {1}" -f $dst, $src) -Status $script:Status.Fail `
                -Detail ("{0} consecutive failure(s) on {1}; last failure status {2}; last success {3}." -f $failures, $nc, $status, $(if ($lastOk) { $lastOk } else { 'unknown' }))
        }
    }
    if ($failing -eq 0) {
        $rows += New-Finding -Area 'Replication' -Item 'repadmin cross-check' -Status $script:Status.Pass -Detail ("repadmin /showrepl reports {0} link(s), all with zero failures." -f @($links).Count)
    }
    else {
        $rows += New-Finding -Area 'Replication' -Item 'repadmin cross-check summary' -Status $script:Status.Fail -Detail ("{0} of {1} replication link(s) report failures." -f $failing, @($links).Count)
    }
    return @($rows)
}

function Get-AdfaLatestBackupDate {
    <#
    .SYNOPSIS
        Pure parser: extracts the most recent date from 'repadmin /showbackup' output.
        Returns $null when no date can be found - the caller reports Not Assessed, never
        a fabricated age.
    .OUTPUTS
        [nullable[datetime]]
    #>
    [CmdletBinding()]
    [OutputType([nullable[datetime]])]
    param([AllowEmptyString()][string]$Text = '')
    $best = $null
    foreach ($m in [regex]::Matches($Text, '\d{4}-\d{2}-\d{2} \d{2}:\d{2}(:\d{2})?')) {
        $d = [datetime]::MinValue
        if ([datetime]::TryParseExact($m.Value, [string[]]@('yyyy-MM-dd HH:mm:ss', 'yyyy-MM-dd HH:mm'), [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::None, [ref]$d)) {
            if ($null -eq $best -or $d -gt $best) { $best = $d }
        }
    }
    foreach ($m in [regex]::Matches($Text, '\d{1,2}/\d{1,2}/\d{4}( \d{1,2}:\d{2}(:\d{2})?)?')) {
        $d = [datetime]::MinValue
        if ([datetime]::TryParse($m.Value, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::None, [ref]$d)) {
            if ($null -eq $best -or $d -gt $best) { $best = $d }
        }
    }
    return $best
}

function Get-AdfaBackupStatus {
    <#
    .SYNOPSIS
        Last directory-partition backup time PER DC via 'repadmin /showbackup <dc>'.
        In a restore-from-backup recovery this tells you which DCs were restored and
        when - correlate with the machine-account password ages in DcSecureChannel.
    .OUTPUTS
        [pscustomobject[]]
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param(
        [AllowEmptyCollection()][string[]]$DomainControllers = @(),
        [int]$TimeoutSeconds = 90,
        [int]$Retries = 2,
        [int]$RetryDelaySeconds = 2,
        [int]$MaxAgeDays = 30,
        [int]$RpcPortTimeoutMs = 1200
    )
    if (-not (Test-CommandAvailable -Name 'repadmin.exe')) {
        return @(New-Finding -Area 'Backup' -Item 'Directory backup status' -Status $script:Status.NotAssessed -Detail 'repadmin.exe not available on this host.')
    }
    $rows = @()
    $targets = @($DomainControllers | Where-Object { $_ })
    if (@($targets).Count -eq 0) {
        # No DC list - fall back to the local view.
        $r = Invoke-ExternalCommand -FilePath 'repadmin.exe' -Arguments '/showbackup' -TimeoutSeconds $TimeoutSeconds -Retries $Retries -RetryDelaySeconds $RetryDelaySeconds
        $latest = Get-AdfaLatestBackupDate -Text $r.StdOut
        if ($null -eq $latest) {
            $rows += New-Finding -Area 'Backup' -Item 'Directory backup (local DC)' -Status $script:Status.NotAssessed -Detail 'Could not parse repadmin /showbackup output.'
        }
        else {
            $age = ((Get-Date) - $latest).TotalDays
            $status = $script:Status.Pass
            if ($age -gt $MaxAgeDays) { $status = $script:Status.Warning }
            $rows += New-Finding -Area 'Backup' -Item 'Directory backup (local DC)' -Status $status -Detail ("Latest partition backup {0:yyyy-MM-dd HH:mm} ({1:N0} day(s) ago)." -f $latest, $age)
        }
        return @($rows)
    }
    foreach ($dc in $targets) {
        if (-not (Test-TcpPort -ComputerName $dc -Port 135 -TimeoutMs $RpcPortTimeoutMs)) {
            $rows += New-Finding -Area 'Backup' -Item ("Directory backup: {0}" -f $dc) -Status $script:Status.NotAssessed -Detail 'DC not reachable (RPC/135) - run repadmin /showbackup locally on it.'
            continue
        }
        $r = Invoke-ExternalCommand -FilePath 'repadmin.exe' -Arguments ("/showbackup {0}" -f $dc) -TimeoutSeconds $TimeoutSeconds -Retries $Retries -RetryDelaySeconds $RetryDelaySeconds
        $latest = Get-AdfaLatestBackupDate -Text $r.StdOut
        if ($null -eq $latest) {
            $rows += New-Finding -Area 'Backup' -Item ("Directory backup: {0}" -f $dc) -Status $script:Status.NotAssessed -Detail ("Could not parse repadmin /showbackup output for this DC.{0}" -f $(if ($r.Error) { ' ' + $r.Error } else { '' }))
        }
        else {
            $age = ((Get-Date) - $latest).TotalDays
            $status = $script:Status.Pass
            if ($age -gt $MaxAgeDays) { $status = $script:Status.Warning }
            $rows += New-Finding -Area 'Backup' -Item ("Directory backup: {0}" -f $dc) -Status $status -Detail ("Latest partition backup {0:yyyy-MM-dd HH:mm} ({1:N0} day(s) ago). A very old value on a restored DC dates the backup it came from." -f $latest, $age)
        }
    }
    return @($rows)
}

function Get-AdfaLingeringObjectScan {
    <#
    .SYNOPSIS
        Proactive lingering-object enumeration using
        'repadmin /removelingeringobjects <dc> <reference-dsa-guid> <NC> /advisory_mode'.
        Advisory mode makes NO directory changes - it only compares each DC against the
        reference DC (the domain's PDC emulator) and logs what WOULD be removed. This is
        the check that finds lingering objects BEFORE they block replication with event
        1988, instead of after. Opt-in via -IncludeLingeringObjectScan because it writes
        events (1938/1942/1946) to the target DCs' Directory Service logs.
    .OUTPUTS
        [pscustomobject[]]
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param(
        [Parameter(Mandatory)][string]$DomainName,
        [hashtable]$AdParams = @{},
        [int]$TimeoutSeconds = 300,
        [int]$RpcPortTimeoutMs = 1200
    )
    $rows = @()
    if (-not (Test-CommandAvailable -Name 'repadmin.exe')) {
        return @(New-Finding -Scope $DomainName -Area 'LingeringObjects' -Item 'Advisory-mode scan' -Status $script:Status.NotAssessed -Detail 'repadmin.exe not available on this host.')
    }
    $p = @{} + $AdParams; $p.Server = $DomainName
    $domainNc = ''; $refDc = ''; $dcs = @()
    try {
        $dom = Get-ADDomain @p
        $domainNc = [string]$dom.DistinguishedName
        $refDc = [string]$dom.PDCEmulator
        $dcs = @(Get-ADDomainController -Filter * @p | Select-Object -ExpandProperty HostName)
    }
    catch {
        return @(New-Finding -Scope $DomainName -Area 'LingeringObjects' -Item 'Advisory-mode scan' -Status $script:Status.NotAssessed -Detail $_.Exception.Message)
    }
    $refGuid = ''
    $refGuidError = ''
    try {
        $inv = @(Get-AdfaDsaInventory -AdParams $AdParams)
        $refNorm = $refDc.ToLowerInvariant().TrimEnd('.')
        foreach ($d in $inv) {
            if ($d.DnsHostName -and $d.DnsHostName.ToLowerInvariant().TrimEnd('.') -eq $refNorm) { $refGuid = $d.DsaGuid; break }
        }
    }
    catch {
        # The verdict below was already fail-closed, but the cause was discarded - so
        # "the DSA inventory threw" and "the reference DC simply was not in it" read alike.
        $refGuidError = $_.Exception.Message
    }
    if (-not $refGuid) {
        $why = ''
        if ($refGuidError) { $why = (" DSA inventory failed: {0}" -f $refGuidError) }
        else { $why = ' The DSA inventory was readable but contained no entry matching that host name.' }
        return @(New-Finding -Scope $DomainName -Area 'LingeringObjects' -Item 'Advisory-mode scan' -Status $script:Status.NotAssessed -Detail ("Could not resolve the DSA GUID of the reference DC ({0}).{1}" -f $refDc, $why))
    }

    foreach ($dc in $dcs) {
        if ($dc.ToLowerInvariant().TrimEnd('.') -eq $refDc.ToLowerInvariant().TrimEnd('.')) { continue }
        if (-not (Test-TcpPort -ComputerName $dc -Port 135 -TimeoutMs $RpcPortTimeoutMs)) {
            $rows += New-Finding -Scope $DomainName -Area 'LingeringObjects' -Item ("Advisory scan: {0}" -f $dc) -Status $script:Status.NotAssessed -Detail 'DC not reachable (RPC/135).'
            continue
        }
        $r = Invoke-ExternalCommand -FilePath 'repadmin.exe' `
            -Arguments ('/removelingeringobjects {0} {1} "{2}" /advisory_mode' -f $dc, $refGuid, $domainNc) `
            -TimeoutSeconds $TimeoutSeconds -Retries 1
        $out = [string]$r.StdOut
        $count = -1
        if ($out -match '(?i)(\d+)\s+lingering object') { $count = [int]$Matches[1] }
        else {
            $perLine = ([regex]::Matches($out, '(?i)^\s*lingering obj', [System.Text.RegularExpressions.RegexOptions]::Multiline)).Count
            if ($perLine -gt 0) { $count = $perLine }
            elseif ($r.Success) { $count = 0 }
        }
        if ($count -gt 0) {
            $rows += New-Finding -Scope $DomainName -Area 'LingeringObjects' -Item ("Advisory scan: {0}" -f $dc) -Status $script:Status.Fail -Detail ("{0} lingering object(s) found relative to {1} on {2}. Directory Service events 1946 on {3} list each object." -f $count, $refDc, $domainNc, $dc)
        }
        elseif ($count -eq 0) {
            $rows += New-Finding -Scope $DomainName -Area 'LingeringObjects' -Item ("Advisory scan: {0}" -f $dc) -Status $script:Status.Pass -Detail ("No lingering objects relative to {0} on {1}." -f $refDc, $domainNc)
        }
        else {
            $excerpt = (($out -split "`r?`n") | Where-Object { $_ -match '\S' } | Select-Object -First 3) -join ' | '
            $rows += New-Finding -Scope $DomainName -Area 'LingeringObjects' -Item ("Advisory scan: {0}" -f $dc) -Status $script:Status.NotAssessed -Detail ("Inconclusive output: {0}" -f $(if ($excerpt) { $excerpt } else { $r.Error }))
        }
    }
    if (@($rows).Count -eq 0) {
        $rows += New-Finding -Scope $DomainName -Area 'LingeringObjects' -Item 'Advisory-mode scan' -Status $script:Status.Info -Detail ("Only one DC in {0} - nothing to compare against the reference." -f $DomainName)
    }
    return @($rows)
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
        return @(New-Finding -Area 'TimeSync' -Item 'w32time' -Status $script:Status.NotAssessed -Detail 'w32tm.exe not available on this host.')
    }
    $rows = @()
    $src = Invoke-ExternalCommand -FilePath 'w32tm.exe' -Arguments '/query /source' -TimeoutSeconds $TimeoutSeconds -Retries 1 -RetryDelaySeconds 1
    $source = ($src.StdOut -split "`r?`n" | Where-Object { $_.Trim() } | Select-Object -First 1)
    $status = $script:Status.Info
    if ($source -match 'Local CMOS Clock|Free-running') { $status = $script:Status.Warning }
    $rows += New-Finding -Area 'TimeSync' -Item 'Time source' -Status $status -Detail ("Source: {0}" -f ("$source".Trim()))
    return @($rows)
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
    return @($rows)
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

    return @($rows)
}

# ===========================================================================
# region Exchange Server SE readiness (AD prerequisites only)
# ===========================================================================

function Test-AdfaOsSupported {
    <#
    .SYNOPSIS
        Pure match of a DC's OperatingSystem string against the supported-OS table.
    .DESCRIPTION
        Returns the matching table Label, or '' when nothing matches. Kept separate so the
        patterns are testable in isolation - the 2012 R2 / 2012 distinction in particular,
        where 2012 R2 is supported and plain 2012 is not, and a loosened pattern would
        silently pass an unsupported DC.
    .OUTPUTS
        [string] The supported-OS label, or '' when unsupported.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [AllowNull()][AllowEmptyString()][string]$OperatingSystem,
        [AllowNull()][AllowEmptyCollection()]$SupportedOs = @()
    )
    if ([string]::IsNullOrWhiteSpace($OperatingSystem)) { return '' }
    foreach ($entry in @($SupportedOs)) {
        if ($null -eq $entry) { continue }
        $pattern = ''
        if ($entry -is [hashtable]) { $pattern = [string]$entry['Pattern'] }
        else {
            $prop = $entry.PSObject.Properties['Pattern']   # $null when absent - StrictMode-safe
            if ($null -ne $prop) { $pattern = [string]$prop.Value }
        }
        if ([string]::IsNullOrWhiteSpace($pattern)) { continue }
        if ($OperatingSystem -match $pattern) {
            if ($entry -is [hashtable]) { return [string]$entry['Label'] }
            return [string]$entry.PSObject.Properties['Label'].Value
        }
    }
    return ''
}

function Merge-AdfaExchangeSeConfig {
    <#
    .SYNOPSIS
        Pure merge of an override table over the built-in Exchange SE prerequisite table.
    .DESCRIPTION
        Only the keys present in the override are replaced, so a file that names one key does
        not blank the rest. Separated from the file read so the merge rules are testable
        without a filesystem.

        An override MUST NOT be able to empty a gate: a SupportedForestModes or
        SupportedDomainControllerOs of zero entries would make every value unsupported (or,
        worse in a future refactor, everything vacuously fine), so an empty collection is
        rejected rather than honoured. Provenance is rewritten to name the override, because a
        finding that cites Microsoft Learn must not do so when the values came from elsewhere.
    .OUTPUTS
        [hashtable]
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)][hashtable]$BaseConfig,
        [AllowNull()]$Override,
        [string]$OverrideSource = ''
    )
    $merged = @{}
    foreach ($k in @($BaseConfig.Keys)) { $merged[$k] = $BaseConfig[$k] }
    if ($null -eq $Override) { return $merged }

    $names = @()
    if ($Override -is [hashtable]) { $names = @($Override.Keys) }
    else { $names = @($Override.PSObject.Properties.Name) }

    foreach ($k in $names) {
        $value = $null
        if ($Override -is [hashtable]) { $value = $Override[$k] }
        else { $value = $Override.PSObject.Properties[$k].Value }
        if ($null -eq $value) { continue }
        if (($k -eq 'SupportedForestModes' -or $k -eq 'SupportedDomainControllerOs') -and @($value).Count -eq 0) {
            throw ("Exchange SE config override sets '{0}' to an empty list. An empty gate cannot be honoured - remove the key to keep the built-in value." -f $k)
        }
        $merged[$k] = $value
    }
    if (-not [string]::IsNullOrWhiteSpace($OverrideSource)) {
        $merged['SourceUrl'] = $OverrideSource
        $merged['ReadDate'] = (Get-Date).ToString('yyyy-MM-dd')
    }
    return $merged
}

function Import-AdfaExchangeSeConfig {
    <#
    .SYNOPSIS
        Loads an Exchange SE prerequisite override from JSON and merges it over the built-in table.
    .DESCRIPTION
        Thin wrapper over Merge-AdfaExchangeSeConfig. A missing, unreadable or malformed file
        throws: silently judging a forest against the wrong table is worse than stopping.
    .OUTPUTS
        [hashtable]
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)][hashtable]$BaseConfig,
        [Parameter(Mandatory)][string]$Path
    )
    if (-not (Test-Path -LiteralPath $Path)) {
        throw ("Exchange SE config not found: {0}" -f $Path)
    }
    $raw = Get-Content -LiteralPath $Path -Raw -ErrorAction Stop
    if ([string]::IsNullOrWhiteSpace($raw)) {
        throw ("Exchange SE config is empty: {0}" -f $Path)
    }
    $obj = $null
    try { $obj = $raw | ConvertFrom-Json -ErrorAction Stop }
    catch { throw ("Exchange SE config is not valid JSON ({0}): {1}" -f $Path, $_.Exception.Message) }
    return (Merge-AdfaExchangeSeConfig -BaseConfig $BaseConfig -Override $obj -OverrideSource $Path)
}

function Get-AdfaExchangeSeCompatibility {
    <#
    .SYNOPSIS
        Verdict on whether the forest's AD level and DC operating systems permit Exchange SE.
    .DESCRIPTION
        Deliberately narrow. This answers only the two questions the directory can answer on
        its own - forest functional level, and the operating system of every DC in the forest -
        plus the read-only caveat from the same table. It is NOT an Exchange SE readiness
        assessment: schema and organisation object versions, the per-site writeable-GC
        requirement, Exchange server inventory and coexistence builds are out of scope here
        and belong to ExchangeAssessment, whose remit that is.

        Pure: every value is passed in, nothing is queried, so the whole verdict is testable
        without a directory.

        Fail-closed. A DC whose OperatingSystem could not be read is reported Not Assessed with
        that cause named - never assumed supported, and never counted as unsupported either,
        because an absent value and a measured unsupported value are different claims.
    .OUTPUTS
        [pscustomobject[]] Finding rows.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param(
        [AllowNull()][AllowEmptyString()][string]$ForestMode,
        [AllowNull()][AllowEmptyCollection()]$DomainSummaries = @(),
        [AllowNull()][AllowEmptyCollection()]$DomainControllers = @(),
        [Parameter(Mandatory)][hashtable]$SeConfig
    )
    $rows = @()
    $release = [string]$SeConfig['Release']
    $provenance = ("Per {0} (read {1})." -f [string]$SeConfig['SourceUrl'], [string]$SeConfig['ReadDate'])
    $supportedModes = @($SeConfig['SupportedForestModes'])
    $supportedOs = @($SeConfig['SupportedDomainControllerOs'])
    $osLabels = @($supportedOs | ForEach-Object {
            if ($_ -is [hashtable]) { [string]$_['Label'] } else { [string]$_.PSObject.Properties['Label'].Value }
        })

    # ---- Forest functional level ----
    if ([string]::IsNullOrWhiteSpace($ForestMode)) {
        $rows += New-Finding -Area 'ExchangeSeReadiness' -Item 'Forest functional level' -Status $script:Status.NotAssessed `
            -Detail ("Forest functional level could not be read, so {0} compatibility cannot be judged. {1}" -f $release, $provenance)
    }
    elseif ($supportedModes -contains $ForestMode) {
        $rows += New-Finding -Area 'ExchangeSeReadiness' -Item 'Forest functional level' -Status $script:Status.Pass `
            -Detail ("{0} - supported for {1}. {2}" -f $ForestMode, $release, $provenance)
    }
    else {
        $rows += New-Finding -Area 'ExchangeSeReadiness' -Item 'Forest functional level' -Status $script:Status.Fail `
            -Detail ("{0} is NOT supported for {1}. Supported: {2}. Setup will not proceed until the forest functional level is raised. {3}" -f `
                $ForestMode, $release, ($supportedModes -join ', '), $provenance)
    }

    # ---- Domain functional levels: informational ----
    # The supportability matrix states a FOREST functional level requirement and no domain one,
    # so these are reported rather than judged. Inventing a domain gate would be a fabricated
    # vendor requirement.
    foreach ($d in @($DomainSummaries)) {
        if ($null -eq $d) { continue }
        $dmProp = $d.PSObject.Properties['DomainMode']
        $dnProp = $d.PSObject.Properties['DomainName']
        $dm = ''
        if ($null -ne $dmProp -and $null -ne $dmProp.Value) { $dm = [string]$dmProp.Value }
        $dn = ''
        if ($null -ne $dnProp -and $null -ne $dnProp.Value) { $dn = [string]$dnProp.Value }
        if ([string]::IsNullOrWhiteSpace($dm)) { continue }
        $rows += New-Finding -Scope $dn -Area 'ExchangeSeReadiness' -Item ("Domain functional level - {0}" -f $dn) `
            -Status $script:Status.Info `
            -Detail ("{0}. Recorded for completeness: the supportability matrix states a forest functional level requirement and does not state a domain one. {1}" -f $dm, $provenance)
    }

    # ---- Domain controller operating systems ----
    # "All domain controllers in the forest must be running one of the supported versions",
    # so a single unsupported DC anywhere in the forest is a blocker, not a warning.
    $dcs = @($DomainControllers | Where-Object { $null -ne $_ })
    if ($dcs.Count -eq 0) {
        $rows += New-Finding -Area 'ExchangeSeReadiness' -Item 'Domain controller operating systems' -Status $script:Status.NotAssessed `
            -Detail ("No domain controllers were enumerated, so no OS could be checked against the {0} supported list ({1})." -f $release, ($osLabels -join ', '))
    }
    else {
        $unsupported = @()
        $unknown = @()
        $supported = @()
        foreach ($dc in $dcs) {
            $hostProp = $dc.PSObject.Properties['HostName']
            $osProp = $dc.PSObject.Properties['OperatingSystem']
            $dcName = '(unnamed)'
            if ($null -ne $hostProp -and $null -ne $hostProp.Value) { $dcName = [string]$hostProp.Value }
            $os = ''
            if ($null -ne $osProp -and $null -ne $osProp.Value) { $os = [string]$osProp.Value }

            # The inventory writes the literal 'Not Assessed' into OperatingSystem when the
            # Get-ADComputer enrichment failed. That is an absent measurement, not a bad OS.
            if ([string]::IsNullOrWhiteSpace($os) -or $os -eq $script:Status.NotAssessed) {
                $unknown += $dcName
                continue
            }
            $label = Test-AdfaOsSupported -OperatingSystem $os -SupportedOs $supportedOs
            if ([string]::IsNullOrWhiteSpace($label)) { $unsupported += ("{0} ({1})" -f $dcName, $os) }
            else { $supported += $dcName }
        }

        if ($unsupported.Count -gt 0) {
            $rows += New-Finding -Area 'ExchangeSeReadiness' -Item 'Domain controller operating systems' -Status $script:Status.Fail `
                -Detail ("{0} of {1} DC(s) run an OS not supported for {2}: {3}. Every DC in the forest must run a supported version. Supported: {4}. {5}" -f `
                    $unsupported.Count, $dcs.Count, $release, ($unsupported -join '; '), ($osLabels -join ', '), $provenance)
        }
        elseif ($unknown.Count -gt 0 -and $supported.Count -eq 0) {
            $rows += New-Finding -Area 'ExchangeSeReadiness' -Item 'Domain controller operating systems' -Status $script:Status.NotAssessed `
                -Detail ("No DC operating system could be read ({0} DC(s): {1}), so {2} compatibility is unverified. Supported: {3}." -f `
                    $unknown.Count, ($unknown -join ', '), $release, ($osLabels -join ', '))
        }
        else {
            $rows += New-Finding -Area 'ExchangeSeReadiness' -Item 'Domain controller operating systems' -Status $script:Status.Pass `
                -Detail ("All {0} DC(s) whose OS could be read run a version supported for {1}. Supported: {2}. {3}" -f `
                    $supported.Count, $release, ($osLabels -join ', '), $provenance)
        }

        # An unreadable OS is reported on its own, so a partial pass above can never hide it.
        if ($unknown.Count -gt 0) {
            $rows += New-Finding -Area 'ExchangeSeReadiness' -Item 'Domain controller OS - not readable' -Status $script:Status.NotAssessed `
                -Detail ("{0} of {1} DC(s) did not return an operating system: {2}. Re-run with credentials that can read the DC computer objects; until then these DCs are unverified, not compatible." -f `
                    $unknown.Count, $dcs.Count, ($unknown -join ', '))
        }

        # Read-only DCs. The same table says read-only DCs and GCs are not supported; Exchange
        # will not use one. Reported as a Warning rather than a blocker because an RODC in a site
        # Exchange is never installed into does not stop Setup - what stops Setup is a target
        # site with no writeable GC, which is ExchangeAssessment's check and not claimed here.
        if (-not [bool]$SeConfig['ReadOnlySupported']) {
            $rodc = @()
            foreach ($dc in $dcs) {
                $roProp = $dc.PSObject.Properties['IsReadOnly']
                $hostProp = $dc.PSObject.Properties['HostName']
                if ($null -eq $roProp -or $null -eq $roProp.Value) { continue }
                if ([string]$roProp.Value -eq $script:Status.NotAssessed) { continue }
                if ([bool]$roProp.Value) {
                    $n = '(unnamed)'
                    if ($null -ne $hostProp -and $null -ne $hostProp.Value) { $n = [string]$hostProp.Value }
                    $rodc += $n
                }
            }
            if ($rodc.Count -gt 0) {
                $rows += New-Finding -Area 'ExchangeSeReadiness' -Item 'Read-only domain controllers' -Status $script:Status.Warning `
                    -Detail ("{0} read-only DC(s): {1}. Read-only DCs and read-only global catalogs are not supported for {2} - Exchange will not use them. Confirm every site an Exchange server goes into also holds a writeable global catalog. {3}" -f `
                        $rodc.Count, ($rodc -join ', '), $release, $provenance)
            }
        }
    }

    # Scope statement, so nobody reads this section as full SE readiness.
    $rows += New-Finding -Area 'ExchangeSeReadiness' -Item 'Scope of this check' -Status $script:Status.Info `
        -Detail ("Covers the AD prerequisites this tool can answer from the directory: forest functional level and DC operating systems. It does NOT cover schema or organisation object versions, the per-site writeable global catalog requirement, Exchange server inventory or coexistence builds.")
    return @($rows)
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
    return @($m)
}

# ===========================================================================
# region Recovery & consistency (post-incident)
# ===========================================================================

function Get-AdfaDnsQueryOutcome {
    <#
    .SYNOPSIS
        Pure classification of a DNS query result. Distinguishes an authoritative
        "the record does not exist" from "the server did not answer" - conflating them
        would let a dead DNS server masquerade as a missing record (or vice versa).
    .OUTPUTS
        [string] NoTool | Resolved | NoRecord | NoAnswer
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [bool]$Available = $true,
        [int]$TargetCount = 0,
        [string]$ErrorText = ''
    )
    if (-not $Available) { return 'NoTool' }
    if ($TargetCount -gt 0) { return 'Resolved' }
    if ($ErrorText -match '(?i)does not exist|name_error|nxdomain|no records|non-existent|no such') { return 'NoRecord' }
    return 'NoAnswer'
}

function Resolve-AdfaDnsRecord {
    <#
    .SYNOPSIS
        Resolves a DNS record (SRV or CNAME) with Resolve-DnsName, falling back to
        nslookup where the DnsClient module is absent. -Server queries a specific DNS
        server, so AD-integrated zone content can be compared PER SERVER - in a forest
        with broken replication the _msdcs content genuinely differs between DCs, and
        one resolver's view is not forest truth. Fail-closed: "no tool", "no record"
        and "no answer" are reported as distinct outcomes, never conflated.
    .OUTPUTS
        [pscustomobject] Available (bool), Targets (string[]), Error (string),
        Outcome (NoTool|Resolved|NoRecord|NoAnswer)
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][ValidateSet('SRV', 'CNAME')][string]$Type,
        [string]$Server
    )
    $targets = @()
    if (Test-CommandAvailable -Name 'Resolve-DnsName') {
        $err = ''
        try {
            $rp = @{ Name = $Name; Type = $Type; DnsOnly = $true; ErrorAction = 'Stop' }
            if ($Server) { $rp.Server = $Server }
            $ans = @(Resolve-DnsName @rp)
            foreach ($a in $ans) {
                if ($Type -eq 'SRV' -and $a.PSObject.Properties['NameTarget'] -and $a.NameTarget) { $targets += [string]$a.NameTarget }
                elseif ($Type -eq 'CNAME' -and $a.PSObject.Properties['NameHost'] -and $a.NameHost) { $targets += [string]$a.NameHost }
            }
        }
        catch { $err = $_.Exception.Message }
        $targets = @($targets | Sort-Object -Unique)
        return [pscustomobject]@{
            Available = $true; Targets = $targets; Error = $err
            Outcome   = Get-AdfaDnsQueryOutcome -Available $true -TargetCount @($targets).Count -ErrorText $err
        }
    }
    if (Test-CommandAvailable -Name 'nslookup.exe') {
        $lookupArgs = "-type={0} {1}" -f $Type, $Name
        if ($Server) { $lookupArgs = "{0} {1}" -f $lookupArgs, $Server }
        $r = Invoke-ExternalCommand -FilePath 'nslookup.exe' -Arguments $lookupArgs -TimeoutSeconds 20 -Retries 1
        if ($r.StdOut) {
            foreach ($line in ($r.StdOut -split "`r?`n")) {
                if ($Type -eq 'SRV' -and $line -match 'svr hostname\s*=\s*(\S+)') { $targets += $Matches[1].TrimEnd('.') }
                elseif ($Type -eq 'CNAME' -and $line -match 'canonical name\s*=\s*(\S+)') { $targets += $Matches[1].TrimEnd('.') }
            }
        }
        $err = ''
        if (@($targets).Count -eq 0) {
            if ($r.StdOut -match '(?i)non-existent domain|NXDOMAIN') { $err = 'Non-existent domain (no such record).' }
            elseif ($r.StdOut -match '(?i)timed out|no response|server failed') { $err = 'DNS server did not answer.' }
            else { $err = 'No records returned by nslookup.' }
        }
        $targets = @($targets | Sort-Object -Unique)
        return [pscustomobject]@{
            Available = $true; Targets = $targets; Error = $err
            Outcome   = Get-AdfaDnsQueryOutcome -Available $true -TargetCount @($targets).Count -ErrorText $err
        }
    }
    return [pscustomobject]@{
        Available = $false; Targets = @()
        Error     = 'Neither Resolve-DnsName nor nslookup.exe is available on this host.'
        Outcome   = 'NoTool'
    }
}

function Compare-AdfaDnsServerView {
    <#
    .SYNOPSIS
        Pure comparison of multiple DNS servers' views of the same record set against
        the host set Active Directory contains. Reports per-server divergence plus a
        consensus summary, so "3 of 7 DNS servers advertise a DC that does not exist"
        is visible instead of one resolver's answer being printed as forest truth.
    .OUTPUTS
        [pscustomobject] PerServer, AgreeingServers, DivergentServers, ServersQueried
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [AllowEmptyCollection()][string[]]$AdHosts = @(),
        [hashtable]$ServerTargets = @{}
    )
    $perServer = @()
    foreach ($srv in @($ServerTargets.Keys | Sort-Object)) {
        $cmp = Compare-AdfaDnsAdvertisement -AdHosts $AdHosts -DnsTargets $ServerTargets[$srv]
        $perServer += [pscustomobject]@{
            Server         = $srv
            StaleInDns     = $cmp.StaleInDns
            MissingFromDns = $cmp.MissingFromDns
            Matched        = $cmp.Matched
            Agrees         = (@($cmp.StaleInDns).Count -eq 0 -and @($cmp.MissingFromDns).Count -eq 0)
        }
    }
    [pscustomobject]@{
        PerServer        = @($perServer)
        AgreeingServers  = @($perServer | Where-Object { $_.Agrees } | Select-Object -ExpandProperty Server)
        DivergentServers = @($perServer | Where-Object { -not $_.Agrees } | Select-Object -ExpandProperty Server)
        ServersQueried   = @($perServer).Count
    }
}

function Compare-AdfaDnsAdvertisement {
    <#
    .SYNOPSIS
        Pure comparison of the DC set Active Directory contains against the host set DNS
        advertises. Names are normalised (case, trailing dot) before comparing.
    .OUTPUTS
        [pscustomobject] StaleInDns (string[]), MissingFromDns (string[]), Matched (string[])
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [AllowEmptyCollection()][string[]]$AdHosts = @(),
        [AllowEmptyCollection()][string[]]$DnsTargets = @()
    )
    $ad = @{}
    foreach ($h in $AdHosts) { if ($h) { $ad[$h.ToLowerInvariant().TrimEnd('.')] = $true } }
    $dns = @{}
    foreach ($t in $DnsTargets) { if ($t) { $dns[$t.ToLowerInvariant().TrimEnd('.')] = $true } }

    $stale = @(); $missing = @(); $matched = @()
    foreach ($k in $dns.Keys) { if (-not $ad.ContainsKey($k)) { $stale += $k } }
    foreach ($k in $ad.Keys) {
        if ($dns.ContainsKey($k)) { $matched += $k } else { $missing += $k }
    }
    [pscustomobject]@{
        StaleInDns     = @($stale | Sort-Object)
        MissingFromDns = @($missing | Sort-Object)
        Matched        = @($matched | Sort-Object)
    }
}

function Resolve-AdfaDcPasswordVerdict {
    <#
    .SYNOPSIS
        Pure verdict for a DC machine-account password age. Rotation is client-initiated
        every 30 days by default, so an old replicated pwdLastSet means rotation is not
        happening - typical of a DC restored from an old backup.
    .OUTPUTS
        [string] Pass | Warning | Fail | Not Assessed
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [AllowNull()][nullable[double]]$AgeDays,
        [int]$WarnDays = 45,
        [int]$FailDays = 90
    )
    if ($null -eq $AgeDays) { return $script:Status.NotAssessed }
    if ($AgeDays -ge $FailDays) { return $script:Status.Fail }
    if ($AgeDays -ge $WarnDays) { return $script:Status.Warning }
    return $script:Status.Pass
}

function Get-AdfaDnsRecordView {
    <#
    .SYNOPSIS
        Queries one DNS record on every given DNS server (plus the local resolver) and
        buckets the outcomes: answering servers with their target lists, and servers
        that did not answer. AD-integrated zones replicate through AD, so when
        replication is broken the answer genuinely differs per server - each server's
        view is collected separately, never merged.
    .OUTPUTS
        [pscustomobject] ToolAvailable (bool), Views (hashtable server->targets),
        Unanswered (string[]), Error (string)
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][ValidateSet('SRV', 'CNAME')][string]$Type,
        [AllowEmptyCollection()][string[]]$DnsServers = @()
    )
    $views = @{}
    $unanswered = @()

    $local = Resolve-AdfaDnsRecord -Name $Name -Type $Type
    if ($local.Outcome -eq 'NoTool') {
        return [pscustomobject]@{ ToolAvailable = $false; Views = @{}; Unanswered = @(); Error = $local.Error }
    }
    if ($local.Outcome -eq 'NoAnswer') { $unanswered += '(local resolver)' }
    else { $views['(local resolver)'] = @($local.Targets) }

    foreach ($srv in @($DnsServers | Where-Object { $_ } | Sort-Object -Unique)) {
        $r = Resolve-AdfaDnsRecord -Name $Name -Type $Type -Server $srv
        if ($r.Outcome -eq 'NoAnswer') { $unanswered += $srv }
        else { $views[$srv] = @($r.Targets) }
    }
    [pscustomobject]@{ ToolAvailable = $true; Views = $views; Unanswered = @($unanswered); Error = '' }
}

function Get-AdfaDnsAdConsistency {
    <#
    .SYNOPSIS
        Compares the DC locator SRV records against the DCs Active Directory actually
        contains - PER DNS SERVER. Stale entries (a removed/dead DC still advertised)
        and missing entries (a live DC not advertised) are the divergences that surface
        as intermittent RPC 1722 and logon failures after a restore; in a forest with
        broken replication different DNS servers hold different zone content, so each
        server's view is assessed and a divergence summary is reported.
    .OUTPUTS
        [pscustomobject[]]
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param(
        [Parameter(Mandatory)][string]$DomainName,
        [hashtable]$AdParams = @{},
        [AllowEmptyCollection()][string[]]$DnsServers = @()
    )
    $rows = @()
    $p = @{} + $AdParams; $p.Server = $DomainName
    $adHosts = @()
    try {
        $adHosts = @(Get-ADDomainController -Filter * @p | Select-Object -ExpandProperty HostName)
    }
    catch {
        $rows += New-Finding -Scope $DomainName -Area 'DnsAdConsistency' -Item 'DC list from AD' -Status $script:Status.NotAssessed -Detail $_.Exception.Message
        return @($rows)
    }

    foreach ($rec in @(("_ldap._tcp.dc._msdcs.{0}" -f $DomainName), ("_kerberos._tcp.dc._msdcs.{0}" -f $DomainName))) {
        $view = Get-AdfaDnsRecordView -Name $rec -Type SRV -DnsServers $DnsServers
        if (-not $view.ToolAvailable) {
            $rows += New-Finding -Scope $DomainName -Area 'DnsAdConsistency' -Item ("SRV {0}" -f $rec) -Status $script:Status.NotAssessed -Detail $view.Error
            continue
        }
        if (@($view.Views.Keys).Count -eq 0) {
            $rows += New-Finding -Scope $DomainName -Area 'DnsAdConsistency' -Item ("SRV {0}" -f $rec) -Status $script:Status.NotAssessed -Detail ("No DNS server answered for this record ({0} queried: {1})." -f @($view.Unanswered).Count, ($view.Unanswered -join ', '))
            continue
        }
        $sum = Compare-AdfaDnsServerView -AdHosts $adHosts -ServerTargets $view.Views
        foreach ($ps in @($sum.PerServer | Where-Object { -not $_.Agrees })) {
            $bits = @()
            if (@($ps.StaleInDns).Count -gt 0) { $bits += ("stale (no such DC in AD): {0}" -f ((@($ps.StaleInDns) | Select-Object -First 8) -join ', ')) }
            if (@($ps.MissingFromDns).Count -gt 0) { $bits += ("missing (DC in AD, not advertised): {0}" -f ((@($ps.MissingFromDns) | Select-Object -First 8) -join ', ')) }
            $rows += New-Finding -Scope $DomainName -Area 'DnsAdConsistency' -Item ("SRV {0} on {1}" -f $rec, $ps.Server) -Status $script:Status.Fail -Detail ($bits -join '; ')
        }
        $unansweredNote = ''
        if (@($view.Unanswered).Count -gt 0) { $unansweredNote = (' {0} server(s) did not answer: {1}.' -f @($view.Unanswered).Count, ($view.Unanswered -join ', ')) }
        if (@($sum.DivergentServers).Count -eq 0) {
            $rows += New-Finding -Scope $DomainName -Area 'DnsAdConsistency' -Item ("SRV {0}" -f $rec) -Status $script:Status.Pass -Detail ("All {0} answering DNS server(s) agree with AD ({1} DC(s)).{2}" -f $sum.ServersQueried, @($adHosts).Count, $unansweredNote)
        }
        else {
            $rows += New-Finding -Scope $DomainName -Area 'DnsAdConsistency' -Item ("SRV {0} - divergence summary" -f $rec) -Status $script:Status.Fail -Detail ("{0} of {1} answering DNS server(s) diverge from AD: {2}.{3}" -f @($sum.DivergentServers).Count, $sum.ServersQueried, ($sum.DivergentServers -join ', '), $unansweredNote)
        }
    }

    # PDC locator record must point at the actual PDC emulator - on every DNS server.
    try {
        $pdc = (Get-ADDomain @p).PDCEmulator
        $actual = ''
        if ($pdc) { $actual = ([string]$pdc).ToLowerInvariant().TrimEnd('.') }
        $pdcRec = "_ldap._tcp.pdc._msdcs.{0}" -f $DomainName
        $view = Get-AdfaDnsRecordView -Name $pdcRec -Type SRV -DnsServers $DnsServers
        if (-not $view.ToolAvailable) {
            $rows += New-Finding -Scope $DomainName -Area 'DnsAdConsistency' -Item ("SRV {0}" -f $pdcRec) -Status $script:Status.NotAssessed -Detail $view.Error
        }
        elseif (@($view.Views.Keys).Count -eq 0) {
            $rows += New-Finding -Scope $DomainName -Area 'DnsAdConsistency' -Item ("SRV {0}" -f $pdcRec) -Status $script:Status.NotAssessed -Detail 'No DNS server answered for the PDC locator record.'
        }
        else {
            $wrong = @()
            foreach ($srv in @($view.Views.Keys | Sort-Object)) {
                $t = @($view.Views[$srv])
                if (@($t).Count -eq 0) { $wrong += ("{0} (record missing)" -f $srv) }
                else {
                    $adv = ([string]$t[0]).ToLowerInvariant().TrimEnd('.')
                    if ($adv -ne $actual) { $wrong += ("{0} (advertises {1})" -f $srv, $adv) }
                }
            }
            if (@($wrong).Count -eq 0) {
                $rows += New-Finding -Scope $DomainName -Area 'DnsAdConsistency' -Item ("SRV {0}" -f $pdcRec) -Status $script:Status.Pass -Detail ("All {0} answering DNS server(s) point at the PDC emulator ({1})." -f @($view.Views.Keys).Count, $pdc)
            }
            else {
                $rows += New-Finding -Scope $DomainName -Area 'DnsAdConsistency' -Item ("SRV {0}" -f $pdcRec) -Status $script:Status.Fail -Detail ("PDC emulator is {0} but: {1}. Logons and password changes will misroute on those servers." -f $actual, ($wrong -join '; '))
            }
        }
    }
    catch {
        $rows += New-Finding -Scope $DomainName -Area 'DnsAdConsistency' -Item 'PDC locator record' -Status $script:Status.NotAssessed -Detail $_.Exception.Message
    }

    return @($rows)
}

function Get-AdfaDsaInventory {
    <#
    .SYNOPSIS
        Enumerates every nTDSDSA object in the Configuration NC with its DSA GUID and
        the owning server's dNSHostName. Shared by the DSA CNAME check and the
        lingering-object scan. StrictMode-safe against objects missing properties.
    .OUTPUTS
        [pscustomobject[]] DsaGuid, ServerDn, DnsHostName ('' when orphaned)
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param([hashtable]$AdParams = @{})
    $out = @()
    $cfg = (Get-ADRootDSE @AdParams).configurationNamingContext
    $dsas = @(Get-ADObject -LDAPFilter '(objectClass=nTDSDSA)' -SearchBase $cfg -Properties objectGUID @AdParams)
    foreach ($dsa in $dsas) {
        $dsaDn = ''
        if ($dsa.PSObject.Properties['DistinguishedName'] -and $dsa.DistinguishedName) { $dsaDn = [string]$dsa.DistinguishedName }
        $dsaGuid = ''
        if ($dsa.PSObject.Properties['objectGUID'] -and $dsa.objectGUID) { $dsaGuid = [string]$dsa.objectGUID }
        if (-not $dsaDn -or -not $dsaGuid) { continue }
        $serverDn = $dsaDn -replace '^CN=NTDS Settings,', ''
        $dcHost = ''
        try {
            $srvObj = Get-ADObject -Identity $serverDn -Properties dNSHostName @AdParams
            if ($srvObj.PSObject.Properties['dNSHostName'] -and $srvObj.dNSHostName) { $dcHost = [string]$srvObj.dNSHostName }
        }
        catch {
            # Inventory rows carry no Status column, so there is nowhere here to put a finding.
            # It is logged instead: a blank DnsHostName silently fails to correlate with the DSA
            # CNAME and GC checks downstream, and that is worth a line in the run log.
            Write-Log -Level WARN -Section 'DsaInventory' -Message ("Server object {0} could not be read, so DSA {1} has no host name and will not correlate with the DNS checks: {2}" -f $serverDn, $dsaGuid, $_.Exception.Message)
        }
        $out += [pscustomobject]@{ DsaGuid = $dsaGuid; ServerDn = $serverDn; DnsHostName = $dcHost }
    }
    # Plain return on purpose: callers wrap with @(...); `return @()` would hand them
    # one element that IS the empty array and StrictMode then chokes on it (PORT-PLAN P3).
    return @($out)
}

function Get-AdfaDsaGuidCname {
    <#
    .SYNOPSIS
        Verifies the DSA GUID CNAME alias in _msdcs for every DC - on every DNS server.
        Replication resolves a source DC through <objectGUID-of-NTDS-Settings>._msdcs,
        not through its A record; a missing or wrong alias is the single most common
        cause of RPC 1722 replication failures after metadata cleanup or a restore, and
        with broken replication the alias can exist on some DNS servers and not others.
    .OUTPUTS
        [pscustomobject[]]
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param(
        [Parameter(Mandatory)][string]$ForestRoot,
        [hashtable]$AdParams = @{},
        [AllowEmptyCollection()][string[]]$DnsServers = @()
    )
    $rows = @()
    $dsas = @()
    try { $dsas = @(Get-AdfaDsaInventory -AdParams $AdParams) }
    catch {
        $rows += New-Finding -Area 'DsaCname' -Item 'nTDSDSA enumeration' -Status $script:Status.NotAssessed -Detail $_.Exception.Message
        return @($rows)
    }
    if (@($dsas).Count -eq 0) {
        $rows += New-Finding -Area 'DsaCname' -Item 'nTDSDSA enumeration' -Status $script:Status.NotAssessed -Detail 'No usable nTDSDSA objects returned from the Configuration NC.'
        return @($rows)
    }

    foreach ($dsa in $dsas) {
        if (-not $dsa.DnsHostName) {
            $rows += New-Finding -Area 'DsaCname' -Item ("Orphaned NTDS Settings: {0}" -f $dsa.ServerDn) -Status $script:Status.Warning -Detail 'nTDSDSA object exists but its server object has no dNSHostName - likely metadata left behind by an incomplete demotion or restore.'
            continue
        }
        $dcHost = $dsa.DnsHostName
        $expected = $dcHost.ToLowerInvariant().TrimEnd('.')
        $alias = "{0}._msdcs.{1}" -f $dsa.DsaGuid, $ForestRoot
        $view = Get-AdfaDnsRecordView -Name $alias -Type CNAME -DnsServers $DnsServers
        if (-not $view.ToolAvailable) {
            $rows += New-Finding -Area 'DsaCname' -Item ("DSA GUID CNAME for {0}" -f $dcHost) -Status $script:Status.NotAssessed -Detail $view.Error
            continue
        }
        if (@($view.Views.Keys).Count -eq 0) {
            $rows += New-Finding -Area 'DsaCname' -Item ("DSA GUID CNAME for {0}" -f $dcHost) -Status $script:Status.NotAssessed -Detail ("No DNS server answered for {0}." -f $alias)
            continue
        }
        $missingOn = @(); $wrongOn = @(); $okOn = @()
        foreach ($srv in @($view.Views.Keys | Sort-Object)) {
            $t = @($view.Views[$srv])
            if (@($t).Count -eq 0) { $missingOn += $srv }
            else {
                $got = ([string]$t[0]).ToLowerInvariant().TrimEnd('.')
                if ($got -eq $expected) { $okOn += $srv }
                else { $wrongOn += ("{0} (-> {1})" -f $srv, $got) }
            }
        }
        $unansweredNote = ''
        if (@($view.Unanswered).Count -gt 0) { $unansweredNote = (' {0} server(s) did not answer: {1}.' -f @($view.Unanswered).Count, ($view.Unanswered -join ', ')) }
        if (@($missingOn).Count -eq 0 -and @($wrongOn).Count -eq 0) {
            $rows += New-Finding -Area 'DsaCname' -Item ("DSA GUID CNAME for {0}" -f $dcHost) -Status $script:Status.Pass -Detail ("{0} -> {1} consistent on all {2} answering DNS server(s).{3}" -f $alias, $expected, @($okOn).Count, $unansweredNote)
        }
        else {
            $bits = @()
            if (@($missingOn).Count -gt 0) { $bits += ("MISSING on: {0}" -f ($missingOn -join ', ')) }
            if (@($wrongOn).Count -gt 0) { $bits += ("WRONG HOST on: {0} (expected {1})" -f ($wrongOn -join ', '), $expected) }
            if (@($okOn).Count -gt 0) { $bits += ("correct on: {0}" -f ($okOn -join ', ')) }
            $rows += New-Finding -Area 'DsaCname' -Item ("DSA GUID CNAME for {0}" -f $dcHost) -Status $script:Status.Fail -Detail ("{0}: {1}.{2} Inbound replication from this DC fails wherever the alias is absent or wrong." -f $alias, ($bits -join '; '), $unansweredNote)
        }
    }
    return @($rows)
}

function Get-AdfaGcConsistency {
    <#
    .SYNOPSIS
        Compares the Global Catalog set Active Directory believes in (forest
        GlobalCatalogs) against what each DNS server advertises under _gc._tcp.
    .OUTPUTS
        [pscustomobject[]]
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param(
        [Parameter(Mandatory)][string]$ForestRoot,
        [hashtable]$AdParams = @{},
        [AllowEmptyCollection()][string[]]$DnsServers = @()
    )
    $rows = @()
    $gcs = @()
    try { $gcs = @((Get-ADForest @AdParams).GlobalCatalogs) }
    catch {
        $rows += New-Finding -Area 'GcConsistency' -Item 'GC list from AD' -Status $script:Status.NotAssessed -Detail $_.Exception.Message
        return @($rows)
    }

    $rec = "_gc._tcp.{0}" -f $ForestRoot
    $view = Get-AdfaDnsRecordView -Name $rec -Type SRV -DnsServers $DnsServers
    if (-not $view.ToolAvailable) {
        $rows += New-Finding -Area 'GcConsistency' -Item ("SRV {0}" -f $rec) -Status $script:Status.NotAssessed -Detail $view.Error
        return @($rows)
    }
    if (@($view.Views.Keys).Count -eq 0) {
        $rows += New-Finding -Area 'GcConsistency' -Item ("SRV {0}" -f $rec) -Status $script:Status.NotAssessed -Detail ("No DNS server answered for {0} ({1} queried)." -f $rec, @($view.Unanswered).Count)
        return @($rows)
    }
    $sum = Compare-AdfaDnsServerView -AdHosts $gcs -ServerTargets $view.Views
    foreach ($ps in @($sum.PerServer | Where-Object { -not $_.Agrees })) {
        $bits = @()
        if (@($ps.StaleInDns).Count -gt 0) { $bits += ("advertised as GC but not a GC in AD (or gone): {0}" -f ((@($ps.StaleInDns) | Select-Object -First 8) -join ', ')) }
        if (@($ps.MissingFromDns).Count -gt 0) { $bits += ("GC in AD but not advertised: {0}" -f ((@($ps.MissingFromDns) | Select-Object -First 8) -join ', ')) }
        $rows += New-Finding -Area 'GcConsistency' -Item ("Global Catalogs on {0}" -f $ps.Server) -Status $script:Status.Fail -Detail ($bits -join '; ')
    }
    $unansweredNote = ''
    if (@($view.Unanswered).Count -gt 0) { $unansweredNote = (' {0} server(s) did not answer: {1}.' -f @($view.Unanswered).Count, ($view.Unanswered -join ', ')) }
    if (@($sum.DivergentServers).Count -eq 0) {
        $rows += New-Finding -Area 'GcConsistency' -Item ("SRV {0}" -f $rec) -Status $script:Status.Pass -Detail ("All {0} answering DNS server(s) agree with AD ({1} GC(s)).{2}" -f $sum.ServersQueried, @($gcs).Count, $unansweredNote)
    }
    else {
        $rows += New-Finding -Area 'GcConsistency' -Item ("SRV {0} - divergence summary" -f $rec) -Status $script:Status.Fail -Detail ("{0} of {1} answering DNS server(s) diverge from AD: {2}. Forest-wide logons and Exchange address-book lookups behave differently per DNS server.{3}" -f @($sum.DivergentServers).Count, $sum.ServersQueried, ($sum.DivergentServers -join ', '), $unansweredNote)
    }
    return @($rows)
}

function Get-AdfaPortMatrix {
    <#
    .SYNOPSIS
        Per-DC reachability on the ports replication and authentication require, probed
        from this host. Separates "unresolvable in DNS" from "resolvable but the port is
        closed" - they have completely different fixes.
    .OUTPUTS
        [pscustomobject[]]
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param(
        [AllowEmptyCollection()][string[]]$DomainControllers = @(),
        [int]$RpcPortTimeoutMs = 1200
    )
    $rows = @()
    foreach ($dc in $DomainControllers) {
        $resolvable = $true
        try { [void][System.Net.Dns]::GetHostAddresses($dc) }
        catch { $resolvable = $false }
        if (-not $resolvable) {
            $rows += New-Finding -Area 'PortMatrix' -Item $dc -Status $script:Status.Fail -Detail 'Host name does not resolve in DNS - no A record. Nothing can reach this DC by name.'
            continue
        }
        $closedCritical = @(); $closedOptional = @(); $open = @()
        foreach ($p in $script:Config.ReplicationPorts) {
            if (Test-TcpPort -ComputerName $dc -Port $p.Port -TimeoutMs $RpcPortTimeoutMs) { $open += ("{0}/{1}" -f $p.Port, $p.Name) }
            elseif ($p.Critical) { $closedCritical += ("{0}/{1}" -f $p.Port, $p.Name) }
            else { $closedOptional += ("{0}/{1}" -f $p.Port, $p.Name) }
        }
        if (@($closedCritical).Count -gt 0) {
            $rows += New-Finding -Area 'PortMatrix' -Item $dc -Status $script:Status.Fail -Detail ("Critical port(s) not reachable: {0}.{1}" -f ($closedCritical -join ', '), $(if (@($closedOptional).Count -gt 0) { ' Also closed: ' + ($closedOptional -join ', ') + '.' } else { '' }))
        }
        elseif (@($closedOptional).Count -gt 0) {
            $rows += New-Finding -Area 'PortMatrix' -Item $dc -Status $script:Status.Warning -Detail ("Optional port(s) not reachable: {0}. Core replication ports are open." -f ($closedOptional -join ', '))
        }
        else {
            $rows += New-Finding -Area 'PortMatrix' -Item $dc -Status $script:Status.Pass -Detail ("All {0} probed ports reachable." -f @($open).Count)
        }
    }
    if (@($DomainControllers).Count -eq 0) {
        $rows += New-Finding -Area 'PortMatrix' -Item 'Port matrix' -Status $script:Status.NotAssessed -Detail 'No domain controllers enumerated.'
    }
    return @($rows)
}

function Get-AdfaDcSecureChannel {
    <#
    .SYNOPSIS
        Two checks per DC. (1) Machine-account password age from the replicated
        pwdLastSet attribute - collected centrally, no remoting needed; a stale value is
        the fingerprint of a DC restored from an old backup. (2) Where WinRM is
        reachable, secure-channel verification run ON the DC via nltest /sc_verify;
        where it is not, the check reports Not Assessed and says what to run locally.
    .OUTPUTS
        [pscustomobject[]]
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param(
        [Parameter(Mandatory)][string]$DomainName,
        [hashtable]$AdParams = @{},
        [pscredential]$Credential,
        [int]$WarnDays = 45,
        [int]$FailDays = 90,
        [int]$RpcPortTimeoutMs = 1200
    )
    $rows = @()
    $p = @{} + $AdParams; $p.Server = $DomainName
    $dcs = @()
    try { $dcs = @(Get-ADDomainController -Filter * @p) }
    catch {
        $rows += New-Finding -Scope $DomainName -Area 'DcSecureChannel' -Item 'DC enumeration' -Status $script:Status.NotAssessed -Detail $_.Exception.Message
        return @($rows)
    }

    foreach ($dc in $dcs) {
        # (1) Machine-account password age - central, from the replicated attribute.
        try {
            $comp = Get-ADComputer -Identity $dc.ComputerObjectDN -Properties PasswordLastSet @p
            $age = $null
            if ($comp.PasswordLastSet) { $age = ((Get-Date) - $comp.PasswordLastSet).TotalDays }
            $verdict = Resolve-AdfaDcPasswordVerdict -AgeDays $age -WarnDays $WarnDays -FailDays $FailDays
            $ageText = 'never set / not readable'
            if ($null -ne $age) { $ageText = ('{0:N0} day(s) old (set {1:yyyy-MM-dd})' -f $age, $comp.PasswordLastSet) }
            $rows += New-Finding -Scope $DomainName -Area 'DcSecureChannel' -Item ("Machine-account password: {0}" -f $dc.HostName) -Status $verdict -Detail ("pwdLastSet is {0}. Default rotation is every 30 days; a stale value on a DC usually means it was restored from an old backup or rotation is disabled." -f $ageText)
        }
        catch {
            $rows += New-Finding -Scope $DomainName -Area 'DcSecureChannel' -Item ("Machine-account password: {0}" -f $dc.HostName) -Status $script:Status.NotAssessed -Detail $_.Exception.Message
        }

        # (2) Secure channel verified ON the DC, via WinRM where reachable.
        if (Test-TcpPort -ComputerName $dc.HostName -Port 5985 -TimeoutMs $RpcPortTimeoutMs) {
            try {
                $icm = @{
                    ComputerName = $dc.HostName
                    ScriptBlock  = { param($d) & nltest.exe "/sc_verify:$d" 2>&1 | Out-String }
                    ArgumentList = $DomainName
                    ErrorAction  = 'Stop'
                }
                if ($Credential) { $icm.Credential = $Credential }
                $out = [string](Invoke-Command @icm)
                if ($out -match 'NERR_Success') {
                    $rows += New-Finding -Scope $DomainName -Area 'DcSecureChannel' -Item ("Secure channel: {0}" -f $dc.HostName) -Status $script:Status.Pass -Detail 'nltest /sc_verify on the DC reported NERR_Success.'
                }
                else {
                    $excerpt = (($out -split "`r?`n") | Where-Object { $_ -match '\S' } | Select-Object -First 3) -join ' | '
                    $rows += New-Finding -Scope $DomainName -Area 'DcSecureChannel' -Item ("Secure channel: {0}" -f $dc.HostName) -Status $script:Status.Fail -Detail ("nltest /sc_verify on the DC did not report success: {0}" -f $excerpt)
                }
            }
            catch {
                $rows += New-Finding -Scope $DomainName -Area 'DcSecureChannel' -Item ("Secure channel: {0}" -f $dc.HostName) -Status $script:Status.NotAssessed -Detail ("WinRM query failed: {0}. Run 'nltest /sc_verify:{1}' locally on the DC." -f $_.Exception.Message, $DomainName)
            }
        }
        else {
            $rows += New-Finding -Scope $DomainName -Area 'DcSecureChannel' -Item ("Secure channel: {0}" -f $dc.HostName) -Status $script:Status.NotAssessed -Detail ("WinRM (5985) not reachable from this host. Run 'nltest /sc_verify:{0}' locally on the DC." -f $DomainName)
        }
    }
    return @($rows)
}


function Get-AdfaEventLogCoverage {
    <#
    .SYNOPSIS
        Pure classification of whether an event log actually covers a lookback window.
    .DESCRIPTION
        Absence of an event is only evidence if the log goes back far enough to have recorded
        one. Before this, a Directory Service log with nothing in it reported Pass - so a DC
        whose log had been cleared during a ransomware recovery, or had simply wrapped, read
        exactly like a healthy one on the checks that matter most (USN rollback 2095,
        unsupported restore 2103, lingering objects 1988).

        The signal is the oldest record the log still retains, compared with the start of the
        window being asked about. That one measurement covers every way the window can be
        incomplete - cleared, wrapped, or a DC rebuilt more recently than the window - and
        needs no vendor-specific "log was cleared" event ID. A specific marker event was
        considered and deliberately not used: the Windows Event Log docs on Microsoft Learn do
        not publish one for an arbitrary log (searched 2026-09-21), and it would add nothing,
        because clearing a log necessarily moves its oldest retained record forward.

        Verdicts:
          Covered   - the log reaches back to or past the window start; absence is meaningful.
          Truncated - the log starts inside the window; absence is NOT meaningful before
                      OldestRecord, and any count found is a floor rather than a total.
          Empty     - the log holds no records at all; nothing can be concluded.
          Unknown   - the log could not be inspected (unreachable, access denied, absent).
    .OUTPUTS
        [string] Covered | Truncated | Empty | Unknown
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [bool]$Inspected = $true,
        [AllowNull()][Nullable[int]]$RecordCount,
        [AllowNull()][Nullable[datetime]]$OldestRecord,
        [AllowNull()][Nullable[datetime]]$WindowStart
    )
    if (-not $Inspected) { return 'Unknown' }
    if ($null -ne $RecordCount -and $RecordCount -le 0) { return 'Empty' }
    # Either bound missing means the comparison cannot be made - say so rather than assume.
    if ($null -eq $OldestRecord -or $null -eq $WindowStart) { return 'Unknown' }
    if ($OldestRecord -le $WindowStart) { return 'Covered' }
    return 'Truncated'
}

function Get-AdfaEventCoverageDetail {
    <#
    .SYNOPSIS
        The sentence that explains a non-Covered verdict, naming what limits the claim.
    .DESCRIPTION
        Kept beside the classifier and pure, so the wording a report carries is testable
        rather than buried in string concatenation inside a collector.
    .OUTPUTS
        [string] Empty for 'Covered' - there is nothing to caveat.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][ValidateSet('Covered', 'Truncated', 'Empty', 'Unknown')][string]$Coverage,
        [AllowNull()][Nullable[datetime]]$OldestRecord,
        [int]$LookbackDays = 14,
        [string]$Reason = '',
        # Named by the caller so one guard serves both the Directory Service and the
        # DFS Replication logs rather than the wording being duplicated per log.
        [string]$LogName = 'Directory Service'
    )
    if ($Coverage -eq 'Covered') { return '' }
    if ($Coverage -eq 'Empty') {
        return (("The {0} log holds no records, so the absence of an event proves nothing. " +
                "A log cleared during recovery looks identical to a healthy one here - read the log on the DC itself.") -f $LogName)
    }
    if ($Coverage -eq 'Truncated') {
        $from = ''
        if ($null -ne $OldestRecord) { $from = $OldestRecord.ToString('yyyy-MM-dd HH:mm') }
        # The concatenation is parenthesised before -f on purpose: -f binds tighter than +, so
        # "a {0}" + "b" -f $x formats only the SECOND string and leaves {0} literal.
        return (("The {0} log only goes back to {1}, which is inside the {2}-day window, " +
                "so nothing can be concluded about the period before that. The log was cleared or has wrapped.") -f $LogName, $from, $LookbackDays)
    }
    $suffix = ''
    if (-not [string]::IsNullOrWhiteSpace($Reason)) { $suffix = (" Cause: {0}" -f $Reason) }
    return ("The {0} log could not be inspected, so its coverage of the {1}-day window is unknown.{2}" -f $LogName, $LookbackDays, $suffix)
}

function Get-AdfaEventLogCoverageForLog {
    <#
    .SYNOPSIS
        Measures how far back a named event log on a DC actually reaches.
    .DESCRIPTION
        Thin collector over Get-AdfaEventLogCoverage. Get-WinEvent -ListLog gives the record
        count but not the oldest record's timestamp, so the oldest record is read directly
        with -Oldest -MaxEvents 1.
    .OUTPUTS
        [pscustomobject] Coverage, OldestRecord, RecordCount, Reason
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)][string]$ComputerName,
        [Parameter(Mandatory)][string]$LogName,
        [pscredential]$Credential,
        [Parameter(Mandatory)][datetime]$WindowStart
    )
    $recordCount = $null
    $oldest = $null
    $reason = ''
    $inspected = $false
    try {
        $listArgs = @{ ListLog = $LogName; ComputerName = $ComputerName; ErrorAction = 'Stop' }
        if ($Credential) { $listArgs.Credential = $Credential }
        $log = Get-WinEvent @listArgs
        if ($null -ne $log) {
            $inspected = $true
            $prop = $log.PSObject.Properties['RecordCount']   # $null when absent - StrictMode-safe
            if ($null -ne $prop -and $null -ne $prop.Value) { $recordCount = [int]$prop.Value }
        }
        else { $reason = ("Get-WinEvent -ListLog returned nothing for the {0} log." -f $LogName) }
    }
    catch {
        $reason = $_.Exception.Message
    }

    if ($inspected -and ($null -eq $recordCount -or $recordCount -gt 0)) {
        try {
            $oldArgs = @{
                ComputerName = $ComputerName; LogName = $LogName
                Oldest = $true; MaxEvents = 1; ErrorAction = 'Stop'
            }
            if ($Credential) { $oldArgs.Credential = $Credential }
            $first = @(Get-WinEvent @oldArgs)
            if (@($first).Count -gt 0) { $oldest = [datetime]$first[0].TimeCreated }
            else { $recordCount = 0 }
        }
        catch {
            # The log listed but its oldest record could not be read: coverage is unknown, not
            # covered. Recorded rather than swallowed, so the report can name the cause.
            $reason = ("oldest record unreadable: {0}" -f $_.Exception.Message)
            $inspected = $false
        }
    }

    $coverage = Get-AdfaEventLogCoverage -Inspected $inspected -RecordCount $recordCount `
        -OldestRecord $oldest -WindowStart $WindowStart
    return [pscustomobject]@{
        Coverage     = $coverage
        OldestRecord = $oldest
        RecordCount  = $recordCount
        Reason       = $reason
    }
}


function Get-AdfaSysvolShareOutcome {
    <#
    .SYNOPSIS
        Pure classification of whether a DC is actually sharing SYSVOL and NETLOGON.
    .DESCRIPTION
        The distinction that matters is between "the share is not there" and "we could not
        look". A DC that is unreachable over SMB tells us nothing about its shares, and calling
        that a missing share would invent a failure; calling it healthy would hide one.

        Missing SYSVOL/NETLOGON is the vendor's own first diagnostic for broken SYSVOL
        replication, and it is a common state after a restore - the DFSR service will not share
        SYSVOL until the replicated folder has initialised (event 4604).
        https://learn.microsoft.com/troubleshoot/windows-server/networking/troubleshoot-missing-sysvol-and-netlogon-shares
        Read: 2026-09-21.
    .OUTPUTS
        [string] Shared | MissingSysvol | MissingNetlogon | MissingBoth | Unknown
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [bool]$SmbReachable = $true,
        [AllowNull()][Nullable[bool]]$SysvolPresent,
        [AllowNull()][Nullable[bool]]$NetlogonPresent
    )
    if (-not $SmbReachable) { return 'Unknown' }
    if ($null -eq $SysvolPresent -or $null -eq $NetlogonPresent) { return 'Unknown' }
    if ($SysvolPresent -and $NetlogonPresent) { return 'Shared' }
    if (-not $SysvolPresent -and -not $NetlogonPresent) { return 'MissingBoth' }
    if (-not $SysvolPresent) { return 'MissingSysvol' }
    return 'MissingNetlogon'
}

function Get-AdfaSysvolShareHealth {
    <#
    .SYNOPSIS
        Per-DC SYSVOL / NETLOGON share presence.
    .DESCRIPTION
        Thin collector over Get-AdfaSysvolShareOutcome. SMB (445) is probed first so an
        unreachable DC is reported as unknown rather than as a missing share.
    .OUTPUTS
        [pscustomobject[]]
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param(
        [AllowEmptyCollection()][string[]]$DomainControllers = @(),
        [int]$RpcPortTimeoutMs = 1200
    )
    $rows = @()
    if (@($DomainControllers).Count -eq 0) {
        return @(New-Finding -Area 'SYSVOL' -Item 'SYSVOL / NETLOGON shares' -Status $script:Status.NotAssessed `
                -Detail 'No domain controllers were enumerated, so no share could be probed. This is not a clean result.')
    }
    foreach ($dc in $DomainControllers) {
        $smbOk = Test-TcpPort -ComputerName $dc -Port 445 -TimeoutMs $RpcPortTimeoutMs
        $sysvol = $null
        $netlogon = $null
        if ($smbOk) {
            foreach ($share in @($script:Config.SysvolShares)) {
                $present = $null
                try { $present = [bool](Test-Path -LiteralPath ("\\{0}\{1}" -f $dc, $share) -ErrorAction Stop) }
                catch { $present = $null }
                if ($share -eq 'SYSVOL') { $sysvol = $present } else { $netlogon = $present }
            }
        }
        $outcome = Get-AdfaSysvolShareOutcome -SmbReachable $smbOk -SysvolPresent $sysvol -NetlogonPresent $netlogon
        $status = $script:Status.NotAssessed
        $detail = ''
        switch ($outcome) {
            'Shared' {
                $status = $script:Status.Pass
                $detail = 'Both SYSVOL and NETLOGON are shared.'
            }
            'MissingBoth' {
                $status = $script:Status.Fail
                $detail = 'Neither SYSVOL nor NETLOGON is shared. Group Policy and logon scripts are not being served by this DC, and DFSR has not initialised the replicated folder (look for event 4604, and for 2213 / 4012 / 4114 in the DFS Replication log).'
            }
            'MissingSysvol' {
                $status = $script:Status.Fail
                $detail = 'SYSVOL is NOT shared (NETLOGON is). Group Policy is not being served by this DC.'
            }
            'MissingNetlogon' {
                $status = $script:Status.Fail
                $detail = 'NETLOGON is NOT shared (SYSVOL is). Logon scripts are not being served by this DC.'
            }
            default {
                $status = $script:Status.NotAssessed
                $detail = 'SMB (445) was not reachable, so the shares could not be probed. Nothing can be concluded about them from here - check on the DC itself.'
            }
        }
        $rows += New-Finding -Area 'SYSVOL' -Item ("Shares on {0}" -f $dc) -Status $status -Detail $detail
    }
    return @($rows)
}

function Get-AdfaDfsrSubscriptionVerdict {
    <#
    .SYNOPSIS
        Pure verdict on the SYSVOL subscription state across every DC in a domain.
    .DESCRIPTION
        Per KB 2218556, a DFSR-replicated SYSVOL is reinitialised by hand through two attributes
        on each DC's SYSVOL subscription object: msDFSR-Enabled=FALSE takes that DC out of
        replication, and msDFSR-options=1 marks one DC authoritative (the DFSR equivalent of the
        FRS D4). Both are edited during a recovery and both are easy to leave behind - and
        nothing else in this report would show it.
        https://learn.microsoft.com/troubleshoot/windows-server/group-policy/force-authoritative-non-authoritative-synchronization
        Read: 2026-09-21.

        The cross-DC rule is the reason this is a whole-domain verdict rather than a per-DC one:
        the procedure marks exactly ONE member authoritative, so two or more is a conflict that
        cannot be seen by looking at any single DC.

        The verdict describes what the attributes say and what that means. It does not claim the
        reinitialisation is unfinished on the strength of msDFSR-options alone - the vendor does
        not document clearing it afterwards, so a set value is reported as state, not as a fault.
    .OUTPUTS
        [pscustomobject[]] Finding rows.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param(
        [Parameter(Mandatory)][string]$DomainName,
        [AllowNull()][AllowEmptyCollection()]$Subscriptions = @()
    )
    $rows = @()
    $subs = @($Subscriptions | Where-Object { $null -ne $_ })
    if ($subs.Count -eq 0) {
        return @(New-Finding -Scope $DomainName -Area 'SYSVOL' -Item 'DFSR SYSVOL subscription state' -Status $script:Status.NotAssessed `
                -Detail 'No SYSVOL subscription object could be read, so it is unknown whether SYSVOL replication is enabled on these DCs. This is not a clean result.')
    }

    $disabled = @()
    $unknown = @()
    $authoritative = @()
    foreach ($sub in $subs) {
        $name = '(unnamed)'
        $nProp = $sub.PSObject.Properties['DcName']
        if ($null -ne $nProp -and $null -ne $nProp.Value) { $name = [string]$nProp.Value }
        $eProp = $sub.PSObject.Properties['Enabled']
        $oProp = $sub.PSObject.Properties['Options']
        if ($null -eq $eProp -or $null -eq $eProp.Value) { $unknown += $name }
        elseif (-not [bool]$eProp.Value) { $disabled += $name }
        if ($null -ne $oProp -and $null -ne $oProp.Value -and [int]$oProp.Value -eq 1) { $authoritative += $name }
    }

    if ($disabled.Count -gt 0) {
        $rows += New-Finding -Scope $DomainName -Area 'SYSVOL' -Item 'DFSR SYSVOL replication disabled' -Status $script:Status.Fail `
            -Detail ("msDFSR-Enabled=FALSE on {0} of {1} DC(s): {2}. SYSVOL is NOT replicating on those DCs and they will not share SYSVOL. This attribute is only set by hand, during a D2/D4-equivalent reinitialisation - if that procedure was interrupted it must be completed by setting msDFSR-Enabled=TRUE and running 'dfsrdiag pollad'." -f `
                $disabled.Count, $subs.Count, ($disabled -join ', '))
    }
    else {
        $rows += New-Finding -Scope $DomainName -Area 'SYSVOL' -Item 'DFSR SYSVOL replication enabled' -Status $script:Status.Pass `
            -Detail ("msDFSR-Enabled is TRUE on all {0} DC(s) whose subscription object could be read." -f ($subs.Count - $unknown.Count))
    }

    if ($unknown.Count -gt 0) {
        $rows += New-Finding -Scope $DomainName -Area 'SYSVOL' -Item 'DFSR SYSVOL subscription - not readable' -Status $script:Status.NotAssessed `
            -Detail ("msDFSR-Enabled could not be read on {0} DC(s): {1}. Those DCs are unverified, not healthy." -f $unknown.Count, ($unknown -join ', '))
    }

    if ($authoritative.Count -gt 1) {
        $rows += New-Finding -Scope $DomainName -Area 'SYSVOL' -Item 'Conflicting authoritative SYSVOL members' -Status $script:Status.Fail `
            -Detail ("msDFSR-options=1 on {0} DCs: {1}. The reinitialisation procedure marks exactly ONE member authoritative; more than one is a conflict and the domain's SYSVOL content may diverge depending on which initialises first. Decide which DC holds the correct SYSVOL and clear the attribute on the others." -f `
                $authoritative.Count, ($authoritative -join ', '))
    }
    elseif ($authoritative.Count -eq 1) {
        $rows += New-Finding -Scope $DomainName -Area 'SYSVOL' -Item 'Authoritative SYSVOL member set' -Status $script:Status.Warning `
            -Detail ("msDFSR-options=1 on {0}, marking it the authoritative SYSVOL member (the DFSR equivalent of an FRS D4). That is expected DURING a deliberate SYSVOL rebuild and unexpected otherwise. Confirm the rebuild completed - DFS Replication event 4602 on that DC, then 4604 on the others - and that this DC genuinely holds the SYSVOL content you want to keep." -f $authoritative[0])
    }
    return @($rows)
}

function Get-AdfaDfsrSubscription {
    <#
    .SYNOPSIS
        Reads each DC's SYSVOL subscription object (msDFSR-Enabled, msDFSR-options).
    .OUTPUTS
        [pscustomobject[]] DcName, Enabled, Options, Error
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param(
        [Parameter(Mandatory)][string]$DomainName,
        [AllowNull()][AllowEmptyCollection()]$DomainControllers = @(),
        [hashtable]$AdParams = @{}
    )
    $out = @()
    foreach ($dc in @($DomainControllers | Where-Object { $null -ne $_ })) {
        $dn = ''
        $name = ''
        $hostProp = $dc.PSObject.Properties['HostName']
        $dnProp = $dc.PSObject.Properties['ComputerObjectDN']
        if ($null -ne $hostProp -and $null -ne $hostProp.Value) { $name = [string]$hostProp.Value }
        if ($null -ne $dnProp -and $null -ne $dnProp.Value) { $dn = [string]$dnProp.Value }
        if (-not $dn) {
            $out += [pscustomobject]@{ DcName = $name; Enabled = $null; Options = $null; Error = 'No computer object DN on the inventory row, so the subscription DN could not be built.' }
            continue
        }
        $subDn = $script:Config.SysvolSubscriptionDn -f $dn
        try {
            $p = @{} + $AdParams
            $p.Identity = $subDn
            $p.Properties = @('msDFSR-Enabled', 'msDFSR-options')
            $obj = Get-ADObject @p -ErrorAction Stop
            $en = $null
            $op = $null
            $eProp = $obj.PSObject.Properties['msDFSR-Enabled']
            $oProp = $obj.PSObject.Properties['msDFSR-options']
            if ($null -ne $eProp -and $null -ne $eProp.Value) { $en = [bool]$eProp.Value }
            if ($null -ne $oProp -and $null -ne $oProp.Value) { $op = [int]$oProp.Value }
            # An unset msDFSR-Enabled is the default-enabled state, not "unknown": the attribute
            # is only written when someone disables replication. Treated as TRUE so a healthy DC
            # is not reported as unverified, which would cry wolf on every normal forest.
            if ($null -eq $en) { $en = $true }
            $out += [pscustomobject]@{ DcName = $name; Enabled = $en; Options = $op; Error = '' }
        }
        catch {
            $out += [pscustomobject]@{ DcName = $name; Enabled = $null; Options = $null; Error = $_.Exception.Message }
        }
    }
    return @($out)
}


function Get-AdfaDfsrBacklogCount {
    <#
    .SYNOPSIS
        Pure resolution of a DFSR backlog size from what Get-DfsrBacklog actually returns.
    .DESCRIPTION
        Get-DfsrBacklog returns at most 100 records, and the true total appears only in its
        verbose stream - so counting the returned objects reports a FLOOR as if it were a total
        once the backlog reaches the cap. Microsoft's own documented way to get the real number
        is to read the verbose message, whose format is:

            The replicated folder has a backlog of files. Replicated folder: "RF01". Count: 2400

        https://learn.microsoft.com/powershell/module/dfsr/get-dfsrbacklog  (read 2026-09-21)

        So: prefer the verbose count when it parses; otherwise fall back to the object count,
        which is exact below the cap and a floor at it. The caller is told which, because
        "2400" and "at least 100" are different claims.

        Returns Count (int) and Exact (bool). Count is -1 when nothing could be determined.
    .OUTPUTS
        [pscustomobject] Count, Exact, Source
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [AllowNull()][AllowEmptyString()][string]$VerboseMessage = '',
        [int]$ObjectCount = 0,
        [int]$DisplayCap = 100,
        [bool]$Succeeded = $true
    )
    if (-not $Succeeded) {
        return [pscustomobject]@{ Count = -1; Exact = $false; Source = 'None' }
    }
    if (-not [string]::IsNullOrWhiteSpace($VerboseMessage)) {
        # Anchored on the vendor's documented wording rather than any trailing number in the
        # text, so an unrelated verbose line cannot be read as a backlog size.
        $m = [regex]::Match($VerboseMessage, '(?i)backlog of files.*?Count:\s*(\d+)')
        if ($m.Success) {
            return [pscustomobject]@{ Count = [int]$m.Groups[1].Value; Exact = $true; Source = 'Verbose' }
        }
    }
    if ($ObjectCount -ge $DisplayCap) {
        return [pscustomobject]@{ Count = $DisplayCap; Exact = $false; Source = 'CappedObjects' }
    }
    return [pscustomobject]@{ Count = $ObjectCount; Exact = $true; Source = 'Objects' }
}

function Get-AdfaSysvolBacklogVerdict {
    <#
    .SYNOPSIS
        Pure verdict on one directed SYSVOL backlog measurement.
    .DESCRIPTION
        Thresholds come from config, not from the vendor: Microsoft states a backlog indicates
        latency and is "not necessarily an indication of problems". The tighter bar applied here
        is reasoned and stated in the finding itself - SYSVOL changes only when Group Policy
        changes, so a standing backlog means a policy edit is not reaching that DC.

        A count that is a floor rather than a total is never reported as if it were exact.
    .OUTPUTS
        [pscustomobject] Status, Detail
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)][string]$SourceDc,
        [Parameter(Mandatory)][string]$DestinationDc,
        [int]$Count = -1,
        [bool]$Exact = $true,
        [int]$WarnAt = 1,
        [int]$FailAt = 100,
        [string]$Reason = ''
    )
    if ($Count -lt 0) {
        $why = 'the backlog could not be measured'
        if (-not [string]::IsNullOrWhiteSpace($Reason)) { $why = $Reason }
        return [pscustomobject]@{
            Status = $script:Status.NotAssessed
            Detail = ("SYSVOL backlog {0} -> {1} could not be measured: {2}. This is not a clean result." -f $SourceDc, $DestinationDc, $why)
        }
    }
    $shown = [string]$Count
    if (-not $Exact) { $shown = ("at least {0}" -f $Count) }
    if ($Count -eq 0) {
        return [pscustomobject]@{
            Status = $script:Status.Pass
            Detail = ("SYSVOL backlog {0} -> {1} is 0 - that direction has converged." -f $SourceDc, $DestinationDc)
        }
    }
    $status = $script:Status.Warning
    if ($Count -ge $FailAt) { $status = $script:Status.Fail }
    elseif ($Count -lt $WarnAt) { $status = $script:Status.Pass }
    $capNote = ''
    if (-not $Exact) {
        $capNote = ' The true figure may be far higher: Get-DfsrBacklog displays at most 100 records and its verbose count could not be read, so this is a floor, not a total.'
    }
    return [pscustomobject]@{
        Status = $status
        Detail = ("SYSVOL backlog {0} -> {1} is {2} file(s) pending. SYSVOL changes only when Group Policy changes, so it should sit at or near zero - a standing backlog means a policy edit is not reaching {1}. (A DFSR backlog on its own indicates latency rather than a fault; the tighter bar here is specific to SYSVOL.){3}" -f `
                $SourceDc, $DestinationDc, $shown, $capNote)
    }
}

function Get-AdfaSysvolBacklog {
    <#
    .SYNOPSIS
        Measures the SYSVOL backlog in both directions between a reference DC and every other DC.
    .DESCRIPTION
        Opt-in, because it costs two RPC round trips per DC and needs the optional DFSR module.
        The reference DC is the domain's PDC emulator, which is where Group Policy edits are
        normally written, so it is the DC the others should be catching up with.

        Both directions are measured: a backlog TO the PDC and a backlog FROM it are different
        faults, and testing only one would miss half of them.
    .OUTPUTS
        [pscustomobject[]]
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param(
        [Parameter(Mandatory)][string]$DomainName,
        [Parameter(Mandatory)][string]$ReferenceDc,
        [AllowEmptyCollection()][string[]]$DomainControllers = @(),
        [int]$RpcPortTimeoutMs = 1200
    )
    $rows = @()
    if (-not (Test-ModuleAvailable -Name 'DFSR')) {
        return @(New-Finding -Scope $DomainName -Area 'SysvolBacklog' -Item 'SYSVOL backlog' -Status $script:Status.NotAssessed `
                -Detail 'The DFSR PowerShell module is not installed on this host, so the SYSVOL backlog could not be measured. Install RSAT FS-DFS-Mgmt-Con, or run "dfsrdiag backlog" on a DC.')
    }
    Import-Module DFSR -ErrorAction SilentlyContinue -Verbose:$false
    $peers = @($DomainControllers | Where-Object {
            $null -ne $_ -and $_.ToLowerInvariant().TrimEnd('.') -ne $ReferenceDc.ToLowerInvariant().TrimEnd('.')
        })
    if ($peers.Count -eq 0) {
        return @(New-Finding -Scope $DomainName -Area 'SysvolBacklog' -Item 'SYSVOL backlog' -Status $script:Status.NotAssessed `
                -Detail ("No DC other than the reference ({0}) was available to compare against, so no backlog could be measured." -f $ReferenceDc))
    }

    $group = [string]$script:Config.SysvolReplicationGroup
    $folder = [string]$script:Config.SysvolReplicatedFolder
    foreach ($peer in $peers) {
        if (-not (Test-TcpPort -ComputerName $peer -Port 135 -TimeoutMs $RpcPortTimeoutMs)) {
            $rows += New-Finding -Scope $DomainName -Area 'SysvolBacklog' -Item ("Backlog with {0}" -f $peer) -Status $script:Status.NotAssessed `
                -Detail 'RPC (135) not reachable, so neither direction could be measured.'
            continue
        }
        foreach ($pair in @(@{ From = $ReferenceDc; To = $peer }, @{ From = $peer; To = $ReferenceDc })) {
            $objCount = 0
            $verboseText = ''
            $ok = $true
            $reason = ''
            try {
                # 4>&1 redirects the verbose stream into the output so the true count can be read;
                # the object count alone stops at the cmdlet's 100-record cap.
                $captured = @(Get-DfsrBacklog -GroupName $group -FolderName $folder `
                        -SourceComputerName $pair.From -DestinationComputerName $pair.To `
                        -Verbose -ErrorAction Stop 4>&1)
                foreach ($item in $captured) {
                    if ($item -is [System.Management.Automation.VerboseRecord]) { $verboseText = ("{0} {1}" -f $verboseText, $item.Message) }
                    else { $objCount++ }
                }
            }
            catch {
                $ok = $false
                $reason = $_.Exception.Message
            }
            $resolved = Get-AdfaDfsrBacklogCount -VerboseMessage $verboseText -ObjectCount $objCount `
                -DisplayCap ([int]$script:Config.DfsrBacklogDisplayCap) -Succeeded $ok
            $verdict = Get-AdfaSysvolBacklogVerdict -SourceDc ([string]$pair.From) -DestinationDc ([string]$pair.To) `
                -Count ([int]$resolved.Count) -Exact ([bool]$resolved.Exact) `
                -WarnAt ([int]$script:Config.SysvolBacklogWarnAt) -FailAt ([int]$script:Config.SysvolBacklogFailAt) -Reason $reason
            $rows += New-Finding -Scope $DomainName -Area 'SysvolBacklog' `
                -Item ("Backlog {0} -> {1}" -f $pair.From, $pair.To) -Status $verdict.Status -Detail $verdict.Detail
        }
    }
    return @($rows)
}

function Get-AdfaDfsrEventLog {
    <#
    .SYNOPSIS
        Scans each DC's DFS Replication log for the events that decide SYSVOL health.
    .DESCRIPTION
        The SYSVOL counterpart of Get-AdfaDsEventLog, and gated on log coverage the same way:
        finding no events only means something if the log reaches back across the window. After
        a ransomware recovery it frequently does not.
    .OUTPUTS
        [pscustomobject[]]
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param(
        [AllowEmptyCollection()][string[]]$DomainControllers = @(),
        [pscredential]$Credential,
        [int]$LookbackDays = 14,
        [int]$RpcPortTimeoutMs = 1200
    )
    $rows = @()
    if (@($DomainControllers).Count -eq 0) {
        return @(New-Finding -Area 'DfsrEvents' -Item 'DFS Replication events' -Status $script:Status.NotAssessed `
                -Detail 'No domain controllers were enumerated, so the DFS Replication log could not be read. This is not a clean result.')
    }
    $ids = @($script:Config.DfsrEventsOfInterest | ForEach-Object { [int]$_.Id })
    $meta = @{}
    foreach ($e in $script:Config.DfsrEventsOfInterest) { $meta[[int]$e.Id] = $e }
    $windowStart = (Get-Date).AddDays(-$LookbackDays)

    foreach ($dc in $DomainControllers) {
        if (-not (Test-TcpPort -ComputerName $dc -Port 135 -TimeoutMs $RpcPortTimeoutMs)) {
            $rows += New-Finding -Area 'DfsrEvents' -Item $dc -Status $script:Status.NotAssessed -Detail 'RPC (135) not reachable - the DFS Replication log could not be read remotely.'
            continue
        }
        $cov = Get-AdfaEventLogCoverageForLog -ComputerName $dc -LogName 'DFS Replication' -Credential $Credential -WindowStart $windowStart
        $covNote = ''
        if ($cov.Coverage -ne 'Covered') {
            $covNote = ("The DFS Replication log does not cover the full {0}-day window (coverage: {1}{2}), so absence of an event proves nothing." -f `
                    $LookbackDays, $cov.Coverage, $(if ($null -ne $cov.OldestRecord) { ("; oldest record {0:yyyy-MM-dd HH:mm}" -f $cov.OldestRecord) } else { '' }))
        }
        $rows += New-Finding -Area 'DfsrEvents' -Item ("Log coverage on {0}" -f $dc) `
            -Status $(if ($cov.Coverage -eq 'Covered') { $script:Status.Pass } else { $script:Status.NotAssessed }) `
            -Detail $(if ($cov.Coverage -eq 'Covered') { ("DFS Replication log covers the full {0}-day window." -f $LookbackDays) } else { $covNote })

        try {
            $gwe = @{
                ComputerName    = $dc
                FilterHashtable = @{ LogName = 'DFS Replication'; Id = $ids; StartTime = $windowStart }
                MaxEvents       = 500
                ErrorAction     = 'Stop'
            }
            if ($Credential) { $gwe.Credential = $Credential }
            $events = @(Get-WinEvent @gwe)
            if (@($events).Count -eq 0) {
                if ($cov.Coverage -eq 'Covered') {
                    # Not a Pass: SYSVOL health is proven by seeing 4604, not by silence.
                    $rows += New-Finding -Area 'DfsrEvents' -Item $dc -Status $script:Status.Warning `
                        -Detail ("No DFS Replication events of interest in {0} day(s) - including no 4604 (SYSVOL initialised). Silence is not evidence that SYSVOL initialised; confirm the shares are present and that DFSR has logged a 4604 at some point." -f $LookbackDays)
                }
                else {
                    $rows += New-Finding -Area 'DfsrEvents' -Item $dc -Status $script:Status.NotAssessed `
                        -Detail ("No DFS Replication events of interest found, but this is NOT a pass. {0}" -f $covNote)
                }
                continue
            }
            foreach ($g in ($events | Group-Object Id)) {
                $id = [int]$g.Name
                $m = $meta[$id]
                $sev = $script:Status.Warning
                $meaning = ''
                if ($m) {
                    $meaning = [string]$m.Meaning
                    if ([string]$m.Severity -eq 'Fail') { $sev = $script:Status.Fail }
                    elseif ([string]$m.Severity -eq 'Info') { $sev = $script:Status.Info }
                }
                $last = ($g.Group | Sort-Object TimeCreated -Descending | Select-Object -First 1).TimeCreated
                $floor = ''
                if ($cov.Coverage -ne 'Covered') { $floor = (" Count is a MINIMUM - {0}" -f $covNote) }
                $rows += New-Finding -Area 'DfsrEvents' -Item ("Event {0} on {1}" -f $id, $dc) -Status $sev `
                    -Detail ("{0} occurrence(s) in {1} day(s), last {2:yyyy-MM-dd HH:mm}. {3}{4}" -f $g.Count, $LookbackDays, $last, $meaning, $floor)
            }
        }
        catch {
            if ($_.Exception.Message -match 'No events were found|There is not an event log') {
                $rows += New-Finding -Area 'DfsrEvents' -Item $dc -Status $script:Status.NotAssessed `
                    -Detail ("The DFS Replication log held no matching events or is not present: {0}. Not a pass." -f $_.Exception.Message)
            }
            else {
                $rows += New-Finding -Area 'DfsrEvents' -Item $dc -Status $script:Status.NotAssessed -Detail ("DFS Replication log query failed: {0}" -f $_.Exception.Message)
            }
        }
    }
    return @($rows)
}

function Get-AdfaDsEventLog {
    <#
    .SYNOPSIS
        Scans each DC's Directory Service event log (remotely, over the event log RPC
        interface) for the events that block or mask recovery: lingering objects,
        tombstone-lifetime exceeded, USN rollback, unsupported restore, source-DC GUID
        DNS failures and KCC topology failures. Unreachable DCs degrade to Not Assessed.
    .DESCRIPTION
        Every DC's log coverage is measured before any conclusion is drawn from it. Finding no
        events is only evidence if the log actually reaches back across the window: a log
        cleared during a ransomware recovery, or one that has simply wrapped, is silent for the
        same reason a healthy one is. So a clean scan over an incomplete window reports
        Not Assessed naming where coverage begins, never Pass, and a scan that DOES find events
        over an incomplete window reports the count as a floor rather than a total.
    .OUTPUTS
        [pscustomobject[]]
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param(
        [AllowEmptyCollection()][string[]]$DomainControllers = @(),
        [pscredential]$Credential,
        [int]$LookbackDays = 14,
        [int]$RpcPortTimeoutMs = 1200
    )
    $rows = @()
    $ids = @($script:Config.DsEventsOfInterest | ForEach-Object { [int]$_.Id })
    $meta = @{}
    foreach ($e in $script:Config.DsEventsOfInterest) { $meta[[int]$e.Id] = $e }

    $windowStart = (Get-Date).AddDays(-$LookbackDays)

    foreach ($dc in $DomainControllers) {
        if (-not (Test-TcpPort -ComputerName $dc -Port 135 -TimeoutMs $RpcPortTimeoutMs)) {
            $rows += New-Finding -Area 'DsEvents' -Item $dc -Status $script:Status.NotAssessed -Detail 'RPC (135) not reachable - event log could not be read remotely. Check the Directory Service log on the DC itself.'
            continue
        }

        # How far back does this log actually reach? Asked before the scan, because it decides
        # whether "no events" means anything at all.
        $cov = Get-AdfaEventLogCoverageForLog -ComputerName $dc -LogName 'Directory Service' -Credential $Credential -WindowStart $windowStart
        $covNote = Get-AdfaEventCoverageDetail -Coverage $cov.Coverage -OldestRecord $cov.OldestRecord `
            -LookbackDays $LookbackDays -Reason $cov.Reason -LogName 'Directory Service'
        $rows += New-Finding -Area 'DsEvents' -Item ("Log coverage on {0}" -f $dc) `
            -Status $(if ($cov.Coverage -eq 'Covered') { $script:Status.Pass } else { $script:Status.NotAssessed }) `
            -Detail $(if ($cov.Coverage -eq 'Covered') {
                    ("Directory Service log covers the full {0}-day window (oldest record {1:yyyy-MM-dd HH:mm})." -f $LookbackDays, $cov.OldestRecord)
                }
                else { $covNote })

        try {
            $gwe = @{
                ComputerName    = $dc
                FilterHashtable = @{ LogName = 'Directory Service'; Id = $ids; StartTime = $windowStart }
                MaxEvents       = 500
                ErrorAction     = 'Stop'
            }
            if ($Credential) { $gwe.Credential = $Credential }
            $events = @(Get-WinEvent @gwe)
            if (@($events).Count -eq 0) {
                # The fail-closed branch: silence over an incomplete window is not a clean bill
                # of health. Reporting Pass here is what let a wiped log look healthy.
                if ($cov.Coverage -eq 'Covered') {
                    $rows += New-Finding -Area 'DsEvents' -Item $dc -Status $script:Status.Pass -Detail ("No events of interest in the last {0} day(s); log covers the whole window." -f $LookbackDays)
                }
                else {
                    $rows += New-Finding -Area 'DsEvents' -Item $dc -Status $script:Status.NotAssessed -Detail ("No events of interest found, but this is NOT a pass. {0}" -f $covNote)
                }
                continue
            }
            foreach ($g in ($events | Group-Object Id)) {
                $id = [int]$g.Name
                $m = $meta[$id]
                $sev = $script:Status.Warning
                $meaning = ''
                if ($m) {
                    $meaning = [string]$m.Meaning
                    if ([string]$m.Severity -eq 'Fail') { $sev = $script:Status.Fail }
                }
                $last = ($g.Group | Sort-Object TimeCreated -Descending | Select-Object -First 1).TimeCreated
                # A count taken from a partial log is a lower bound, and saying so costs nothing.
                $floor = ''
                if ($cov.Coverage -ne 'Covered') { $floor = (" Count is a MINIMUM - {0}" -f $covNote) }
                $rows += New-Finding -Area 'DsEvents' -Item ("Event {0} on {1}" -f $id, $dc) -Status $sev -Detail ("{0} occurrence(s) in {1} day(s), last {2:yyyy-MM-dd HH:mm}. {3}{4}" -f $g.Count, $LookbackDays, $last, $meaning, $floor)
            }
        }
        catch {
            if ($_.Exception.Message -match 'No events were found') {
                if ($cov.Coverage -eq 'Covered') {
                    $rows += New-Finding -Area 'DsEvents' -Item $dc -Status $script:Status.Pass -Detail ("No events of interest in the last {0} day(s); log covers the whole window." -f $LookbackDays)
                }
                else {
                    $rows += New-Finding -Area 'DsEvents' -Item $dc -Status $script:Status.NotAssessed -Detail ("No events of interest found, but this is NOT a pass. {0}" -f $covNote)
                }
            }
            else {
                $rows += New-Finding -Area 'DsEvents' -Item $dc -Status $script:Status.NotAssessed -Detail ("Event log query failed: {0}" -f $_.Exception.Message)
            }
        }
    }
    if (@($DomainControllers).Count -eq 0) {
        $rows += New-Finding -Area 'DsEvents' -Item 'Directory Service events' -Status $script:Status.NotAssessed -Detail 'No domain controllers enumerated.'
    }
    return @($rows)
}

# ===========================================================================
# region Best-practice recommendations
# ===========================================================================

# Table-driven mapping from a finding's section/item/detail text to a best-practice fix.
# First match wins; specific patterns must precede general ones. An entry may carry a
# Section regex - it is then considered only for findings from matching sections. This
# matters because detail text leaks across domains: a broken trust's reason reads
# "secure channel verification FAILED", which must route to the TRUST remediation, not
# the machine-account one. Kept as data so adding guidance never touches collector logic.
$script:RecommendationMap = @(
    # --- Section-scoped entries first: they cannot be hijacked by detail wording ---
    @{ Section = '(?i)trust'; Match = '(?i)sid filtering'
       Text  = 'Re-enable SID filtering on the trust: "netdom trust <local> /domain:<partner> /quarantine:Yes" (external trusts). Only relax for a documented, time-boxed migration.' }
    @{ Section = '(?i)trust'; Match = '(?i)rc4'
       Text  = 'Enable AES on the trust ("ksetup /setenctypeattr <partner> AES256-CTS-HMAC-SHA1-96 AES128-CTS-HMAC-SHA1-96" or the trust dialog''s AES checkbox), then reset the trust password so new AES keys are derived.' }
    @{ Section = '(?i)trust'; Match = '.'
       Text  = 'Confirm the network path and DNS name resolution (conditional forwarders / stub zones) to the partner domain in BOTH directions, then reset the trust secure channel: "netdom trust <local> /domain:<partner> /reset". Re-verify with "nltest /sc_verify:<partner>" from the local side and on a partner DC. After a ransomware incident, reset trust passwords as part of credential hygiene.' }
    @{ Section = '(?i)secure channel|machine password'; Match = '.'
       Text  = 'Reset the secure channel against a known-healthy DC. Member/workstation: "Reset-ComputerMachinePassword -Server <healthyDC>" or "nltest /sc_reset:<domain>". For a DC: stop the KDC service, run "netdom resetpwd /server:<healthyDC> /userd:<domain>\<admin> /passwordd:*", restart. Never disjoin/rejoin a domain controller.' }
    # --- Section-scoped: Exchange SE. Ahead of the unscoped entries so the generic
    #     replication/time wording in a detail line cannot hijack a readiness finding.
    @{ Section = '(?i)exchange se'; Match = '(?i)forest functional level'
       Text  = 'Raise the forest functional level before Setup: confirm every DC is on a supported OS first, then "Set-ADForestMode -Identity <forest> -ForestMode Windows2016Forest" (raise each domain with Set-ADDomainMode first where needed). This is a one-way change and cannot be reverted without a forest recovery, so take a verified system-state backup of two DCs per domain and confirm replication is healthy beforehand.' }
    @{ Section = '(?i)exchange se'; Match = '(?i)not supported for|not readable|unverified, not compatible'
       Text  = 'Every domain controller in the forest must run a supported Windows Server version, not only the ones in the Exchange site. Upgrade or decommission the named DCs before Setup, transferring any FSMO roles they hold first. Where the OS could not be read, re-run with credentials able to read the DC computer objects - an unreadable value is not a pass.' }
    @{ Section = '(?i)exchange se'; Match = '(?i)read-only domain controller'
       Text  = 'Exchange does not use a read-only DC or a read-only global catalog. No action is needed for an RODC in a site where no Exchange server will be installed; for any site that WILL host one, confirm it also contains a writeable global catalog, or Setup fails in that site alone.' }
    # --- SYSVOL / DFSR specifics, ahead of the generic sysvol|dfsr entry below, which would
    #     otherwise answer every one of these with "perform a D4". Reinitialising is the LAST
    #     resort: the vendor's own guidance is that it is unnecessary in most cases and can lose
    #     data, and it hides the cause.
    #     https://learn.microsoft.com/troubleshoot/windows-server/networking/troubleshoot-missing-sysvol-and-netlogon-shares
    #     https://learn.microsoft.com/troubleshoot/windows-server/group-policy/force-authoritative-non-authoritative-synchronization
    #     Read: 2026-09-21.
    @{ Match = '(?i)msDFSR-options=1 on \d+ DCs|conflicting authoritative'
       Text  = 'Only ONE member may be authoritative. Decide which DC holds the SYSVOL content you want to keep - normally the PDC emulator, and compare \\<dc>\SYSVOL\<domain>\Policies on the candidates first - then clear msDFSR-options on every other DC''s "CN=SYSVOL Subscription,CN=Domain System Volume,CN=DFSR-LocalSettings,<server DN>" object. Leaving two set means SYSVOL content depends on which DC initialises first.' }
    @{ Match = '(?i)msDFSR-Enabled=FALSE'
       Text  = 'SYSVOL replication is switched off on the named DCs, which only happens by hand during a D2/D4-equivalent rebuild - so finish it. Set msDFSR-Enabled=TRUE on "CN=SYSVOL Subscription,CN=Domain System Volume,CN=DFSR-LocalSettings,<server DN>", force AD replication, then run "dfsrdiag pollad" on that DC. Watch for DFS Replication events 4614 (waiting) then 4604 (initialised); only 4604 means SYSVOL is serving again. Recover from the authoritative DC outward through its direct partners, not all at once.' }
    @{ Match = '(?i)authoritative SYSVOL member'
       Text  = 'Expected only during a deliberate SYSVOL rebuild. Confirm it finished: DFS Replication event 4602 on this DC, then 4604 on the others, and \\<dc>\SYSVOL present everywhere. If no rebuild was intended, this attribute was left behind - establish which DC holds correct SYSVOL content before clearing anything, because the next DFSR initialisation will treat this DC as the source of truth.' }
    @{ Match = '(?i)neither SYSVOL nor NETLOGON|SYSVOL is NOT shared|NETLOGON is NOT shared'
       Text  = 'Do NOT jump to a D4 rebuild - find the cause first. On the DC, read the DFS Replication log: event 2213 means a dirty shutdown paused replication and the fix is the ResumeReplication WMI method, not a rebuild; 4012 means content freshness stopped it (MaxOfflineTimeInDays exceeded) and needs reinitialisation; 4114 means the membership is disabled. A DC that has never logged 4604 has never initialised SYSVOL. Confirm AD replication is healthy first - DFSR reads its configuration from the directory, so a broken AD replica cannot converge SYSVOL.' }
    @{ Match = '(?i)dirty shutdown detected'
       Text  = 'DFSR paused replication after a dirty shutdown and will not resume by itself. Run the ResumeReplication WMI method on that volume as the 2213 event instructs; event 2214 confirms recovery completed. Do not delete the DFSR database - that makes DFSR treat all local data as non-authoritative and risks losing SYSVOL content.' }
    @{ Match = '(?i)content freshness'
       Text  = 'Replication has been stopped for longer than MaxOfflineTimeInDays, so DFSR will not resume without reinitialisation. Recover the affected DCs non-authoritatively (msDFSR-Enabled FALSE then TRUE, with "dfsrdiag pollad"), fanning out from a known-healthy DC through its direct partners. Only set a DC authoritative if EVERY DC has logged 4012 - that is the single case where an authoritative rebuild is correct.' }
    @{ Match = '(?i)WAITING to perform initial replication'
       Text  = 'This DC has not initialised SYSVOL and is not serving it. Run "dfsrdiag pollad" on it and wait for event 4604. If 4604 never arrives, its upstream partner is not serving SYSVOL either - fix the upstream DC first; initial sync cannot complete from a partner that has nothing to give.' }
    # --- Unscoped entries: matched against "Section :: Item :: Detail" ---
    # Ahead of the event-specific entries: a log that cannot cover the window is a different
    # problem from an event found in it, and the fix is to recover the evidence, not the DC.
    @{ Match = '(?i)log coverage|absence of an event proves nothing|cleared or has wrapped|NOT a pass'
       Text  = 'Treat this DC as UNASSESSED for the window, not healthy - a cleared or wrapped Directory Service log is silent for the same reason a healthy one is. Recover the evidence before drawing any conclusion: check for an archived copy (%SystemRoot%\System32\winevt\Logs\*.evtx, any SIEM or log-forwarding target, or the backup the DC was restored from), and corroborate independently - "repadmin /showrepl <dc> /errorsonly" and "repadmin /showutdvec" reveal a replication break that the log would have reported. Then raise the log so the next run can conclude: "wevtutil sl \"Directory Service\" /ms:67108864" (64 MB) and confirm retention is Overwrite as needed. On a post-incident forest, also run the advisory lingering-object scan (-IncludeLingeringObjectScan), which does not depend on the event log at all.' }
    @{ Match = '(?i)dsa guid cname|orphaned ntds settings'
       Text  = 'If the DC is live: on that DC run "ipconfig /registerdns" and "nltest /dsregdns", then restart the Netlogon service, and confirm the _msdcs zone accepts secure dynamic updates. If the DC no longer exists: remove its metadata (ntdsutil "metadata cleanup", or delete the server object in AD Sites and Services) and delete the stale record. Replication resolves source DCs through this alias - fix it before chasing RPC 1722 errors.' }
    @{ Match = '(?i)stale dns entry'
       Text  = 'This host is advertised in DNS but does not exist in AD. Delete its stale SRV/A records, confirm metadata cleanup completed for the removed DC (ntdsutil "metadata cleanup"), then run "nltest /dsregdns" on surviving DCs to re-register clean records.' }
    @{ Match = '(?i)missing from dns|not advertised'
       Text  = 'On the affected DC: "ipconfig /registerdns", "nltest /dsregdns", restart Netlogon. Verify the zone allows secure dynamic updates and that the DC''s NIC points at working AD DNS servers (never an external resolver first).' }
    @{ Match = '(?i)pdc locator|pdc emulator'
       Text  = 'Re-register the PDC record: on the actual PDC emulator run "nltest /dsregdns" and restart Netlogon; if the role moved during recovery, confirm FSMO placement with "netdom query fsmo" and seize/transfer as intended before fixing DNS.' }
    @{ Match = '(?i)lingering object'
       Text  = 'Remove lingering objects rather than forcing replication through: "repadmin /removelingeringobjects <dc> <authoritative-dc-dsa-guid> <NC> /advisory_mode" first to preview, then without /advisory_mode. Do not disable strict replication consistency.' }
    @{ Match = '(?i)tombstone lifetime'
       Text  = 'Replication was stopped longer than tombstone lifetime; restarting it blindly risks lingering objects. Preferred fix: forcibly demote the divergent DC, clean its metadata, and repromote it. Only consider "allow replication with divergent and corrupt partner" after a full lingering-object scan.' }
    @{ Match = '(?i)usn rollback|unsupported restore'
       Text  = 'This DC was restored by snapshot/image, which is unsupported. Forcibly demote it (dcpromo /forceremoval), clean its metadata, and repromote. Recover DCs only via system-state restore or by rebuilding and repromoting.' }
    @{ Match = '(?i)replication'
       Text  = 'Fix the DNS findings first (stale records, DSA GUID CNAMEs) - most post-restore RPC 1722 replication errors are DNS, not the network. Then: "repadmin /replsummary", "repadmin /showrepl <dc>", force with "repadmin /replicate <dest> <source> <NC>", and re-run this assessment to confirm.' }
    @{ Match = '(?i)no a record|does not resolve'
       Text  = 'Fix name resolution first: create or re-register the A record (on the DC: "ipconfig /registerdns", restart Netlogon) and confirm this host points at AD DNS servers. A host that does not resolve is unreachable regardless of firewall state.' }
    @{ Match = '(?i)port.*not reachable'
       Text  = 'Open the AD replication port set between DCs: TCP 88, 135, 389, 445, 636, 3268 plus the dynamic RPC range 49152-65535 (or pin replication to a fixed port via the NTDS "TCP/IP Port" registry value and open that). Distinguish firewall blocks from a service not listening (check with netstat on the DC).' }
    @{ Match = '(?i)time sync|w32tm|time skew|clock'
       Text  = 'Point the forest-root PDC emulator at reliable external NTP: "w32tm /config /manualpeerlist:""<ntp1> <ntp2>"" /syncfromflags:manual /reliable:yes /update"; every other DC: "w32tm /config /syncfromflags:domhier /update"; then "w32tm /resync". Kerberos fails beyond 5 minutes of skew.' }
    @{ Match = '(?i)central store'
       Text  = 'Create the GPO central store: copy %SystemRoot%\PolicyDefinitions (including language subfolders) into \\<domain>\SYSVOL\<domain>\Policies\PolicyDefinitions on the PDC; DFSR replicates it to the other DCs.' }
    @{ Match = '(?i)sysvol|dfsr'
       Text  = 'Check "dfsrmig /getmigrationstate". If SYSVOL is not replicating after the restore, perform an authoritative (D4) DFSR restore on the best DC and non-authoritative (D2) on the others via msDFSR-Options, and verify the SYSVOL/NETLOGON shares exist on every DC before editing GPOs.' }
    @{ Match = '(?i)krbtgt'
       Text  = 'Reset the krbtgt password TWICE per domain, waiting for full replication (10+ hours / one ticket lifetime) between resets - mandatory after a ransomware incident to invalidate any forged golden tickets. Use Microsoft''s New-KrbtgtKeys.ps1 for a controlled rollout.' }
    @{ Match = '(?i)kerberoast'
       Text  = 'Move the flagged service accounts to Group Managed Service Accounts (gMSA); where impossible, set 30+ character random passwords and AES-only Kerberos ("Set-ADUser -KerberosEncryptionType AES256").' }
    @{ Match = '(?i)as-rep|preauth|pre-auth'
       Text  = 'Re-enable Kerberos pre-authentication on the flagged accounts (clear "Do not require Kerberos preauthentication" / the DONT_REQ_PREAUTH UAC bit).' }
    @{ Match = '(?i)delegation'
       Text  = 'Remove unconstrained delegation; replace with resource-based constrained delegation where delegation is genuinely required. Mark privileged accounts "sensitive and cannot be delegated" and add them to Protected Users.' }
    @{ Match = '(?i)dcsync|replication.*extended right'
       Text  = 'Remove the DS-Replication-Get-Changes* extended rights from every non-default principal on the domain head. After an incident, treat an unexplained grant as evidence of persistence: reset that principal''s credentials and audit its history.' }
    @{ Match = '(?i)esc1|certificate template|enrol'
       Text  = 'Harden the template: remove ENROLLEE_SUPPLIES_SUBJECT, require manager approval, and restrict enrollment permissions. Audit already-issued certificates (certutil -view) and revoke anything suspicious - certificates outlive password resets.' }
    @{ Match = '(?i)backup'
       Text  = 'Take a fresh system-state backup of at least two DCs per domain now ("wbadmin start systemstatebackup -backuptarget:<vol>"). After a restore-based recovery the newest backup is your safety net AND your tombstone-lifetime clock.' }
    @{ Match = '(?i)global catalog'
       Text  = 'Align GC state: if the DC should be a GC, verify partial-attribute-set replication completed (Directory Service event 1119) and re-register DNS ("nltest /dsregdns"); if it should not, clear the GC flag in AD Sites and Services and scavenge the stale _gc records.' }
    @{ Match = '(?i)duplicate spn'
       Text  = 'List duplicates with "setspn -X" and remove the SPN from the wrong account with "setspn -D <spn> <account>". Kerberos authentication is unreliable while duplicates exist.' }
    @{ Match = '(?i)smbv1'
       Text  = 'Remove SMBv1 on DCs: "Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol" / "Uninstall-WindowsFeature FS-SMB1". It is a ransomware lateral-movement vector with no place on a domain controller.' }
    @{ Match = '(?i)spooler'
       Text  = 'Disable the Print Spooler service on all domain controllers ("Stop-Service Spooler; Set-Service Spooler -StartupType Disabled") - PrintNightmare-class exploits give SYSTEM on a DC.' }
    @{ Match = '(?i)ldap signing'
       Text  = 'Require LDAP signing on DCs (GPO: "Domain controller: LDAP server signing requirements" = Require signing) and enable LDAP channel binding; audit first with events 2886-2889 to find clients that would break.' }
    @{ Match = '(?i)password policy|lockout'
       Text  = 'Raise the domain password policy to current guidance (14+ character minimum, no periodic-expiry theatre, lockout/throttling on) and use fine-grained password policies for privileged and service accounts.' }
    @{ Match = '(?i)recycle bin'
       Text  = 'Enable the AD Recycle Bin ("Enable-ADOptionalFeature ''Recycle Bin Feature'' ..."). It is irreversible but makes object recovery trivial - exactly what a recovery scenario needs.' }
    @{ Match = '(?i)machine account quota'
       Text  = 'Set ms-DS-MachineAccountQuota to 0 so ordinary users cannot join computers to the domain; delegate joins explicitly.' }
    @{ Match = '(?i)scavenging|aging'
       Text  = 'Enable DNS scavenging with matched refresh/no-refresh intervals (7/7 days typical) on the AD zones and one scavenging server - stale records after a recovery cause exactly the divergence this report checks for.' }
    @{ Match = '(?i)zone transfer'
       Text  = 'Restrict zone transfers to named secondaries only (or disable entirely for AD-integrated zones).' }
    @{ Match = '(?i)secure dynamic'
       Text  = 'Set the zone to Secure-only dynamic updates so only authenticated machines can register or overwrite records.' }
    @{ Match = '(?i)stale|inactive|never.expir'
       Text  = 'Disable first, delete later: disable the flagged accounts, monitor for breakage for 30 days, then remove. After an incident, stale enabled accounts are re-entry vectors.' }
    @{ Match = '(?i)dcdiag|advertising|netlogons|sysvolcheck|fsmocheck|kccevent'
       Text  = 'Read raw\dcdiag_<dc>.txt for the failing test detail; fix in dependency order: DNS -> replication -> SYSVOL -> advertising. A dcdiag failure is a symptom - the DNS/replication sections of this report usually name the cause.' }
    @{ Match = '(?i)event \d+ on'
       Text  = 'Correlate with the Replication and DNS sections of this report; the event detail names the object or partner involved. Fix the cause there, then confirm the event stops recurring.' }
)

function Get-AdfaRecommendation {
    <#
    .SYNOPSIS
        Pure lookup: maps a finding's section/item/detail text to a best-practice
        remediation recommendation. Returns '' when no guidance matches - an absent
        recommendation is honest, never invented.
    .OUTPUTS
        [string]
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [string]$Section = '',
        [string]$Item = '',
        [string]$Detail = ''
    )
    $combined = "{0} :: {1} :: {2}" -f $Section, $Item, $Detail
    foreach ($entry in $script:RecommendationMap) {
        if ($entry.ContainsKey('Section') -and -not ($Section -match $entry.Section)) { continue }
        if ($combined -match $entry.Match) { return [string]$entry.Text }
    }
    return ''
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
    # Normalise to one column set: a section can legitimately mix row shapes (an
    # unreachable DC or a failed enumeration emits a shorter object than its neighbours),
    # and reading a missing property under StrictMode would throw and lose the report.
    $rows = @(ConvertTo-AdfaRowSet -Rows $Data)
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

function New-AdfaReportSummary {
    <#
    .SYNOPSIS
        Builds a self-reconciling roll-up: every finding lands in exactly one bucket.
    .DESCRIPTION
        The four counters Invoke-Main computes for the log line and the HTML badges match
        Pass/Healthy, Warning/Degraded, Fail/Broken and Not Assessed. They do NOT match
        'Info', which is a valid New-Finding status, so those rows are counted nowhere.
        Measured on the three-domain fixture: 123 findings, 106 counted, 17 Info invisible.

        Those four are carried through unchanged, so the JSON agrees with the HTML and the
        log rather than quietly telling a third story. What is added is 'info', an
        'unclassified' bucket for any status none of them match, and 'total'. A consumer can
        assert that the buckets sum to the total; if a future status escapes every filter it
        shows up in 'unclassified' instead of vanishing.
    .OUTPUTS
        [System.Collections.Specialized.OrderedDictionary]
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param(
        [Parameter(Mandatory)][pscustomobject]$Summary,
        [Parameter(Mandatory)][AllowNull()][AllowEmptyCollection()]$Findings
    )
    $rows = @(Expand-AdfaRowList -Rows $Findings)
    $statuses = @($rows | ForEach-Object {
            $prop = $_.PSObject.Properties['Status']   # $null when absent - StrictMode-safe
            if ($null -eq $prop) { '' } else { [string]$prop.Value }
        })
    $info = @($statuses | Where-Object { $_ -eq 'Info' }).Count
    $classified = @($statuses | Where-Object {
            $_ -match '^(Pass|Healthy|Warning|Degraded|Fail|Broken|Not Assessed|Info)$'
        }).Count
    return [ordered]@{
        pass         = [int]$Summary.Pass
        warning      = [int]$Summary.Warning
        fail         = [int]$Summary.Fail
        notAssessed  = [int]$Summary.NotAssessed
        info         = [int]$info
        unclassified = [int](@($statuses).Count - $classified)
        total        = [int]@($statuses).Count
    }
}

function New-AdfaReportDocument {
    <#
    .SYNOPSIS
        Builds the machine-readable report object. Pure: no I/O, no collection.
    .DESCRIPTION
        Separated from the writer so the document's shape is unit-testable without a
        filesystem, in the same style as Get-AdfaDnsQueryOutcome and Resolve-AdfaTrustHealth.

        Every collection goes through ConvertTo-AdfaRowSet - the same normalisation the CSVs
        use - so a section whose rows differ in shape serialises with a stable column union
        instead of dropping the later rows' properties (the defect fixed for CSV and HTML in
        v1.5.1 and v1.6.0; JSON must not reintroduce it on a third output path).

        schemaVersion is emitted so a consumer diffing two runs can tell a tool change from
        an environment change. Bump it only when the shape changes incompatibly.
    .OUTPUTS
        [System.Collections.Specialized.OrderedDictionary]
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param(
        [Parameter(Mandatory)][pscustomobject]$Meta,
        [Parameter(Mandatory)][AllowNull()][AllowEmptyCollection()]$Findings,
        [Parameter(Mandatory)][AllowNull()][AllowEmptyCollection()]$Coverage,
        [Parameter(Mandatory)][AllowNull()]$Sections,
        [Parameter(Mandatory)][pscustomobject]$Summary
    )

    $sectionMap = [ordered]@{}
    if ($null -ne $Sections) {
        foreach ($key in @($Sections.Keys)) {
            $sectionMap[[string]$key] = @(ConvertTo-AdfaRowSet -Rows $Sections[$key])
        }
    }
    # Normalised once: the summary counts and the serialised findings must describe the same
    # rows, so they are derived from one collection rather than normalised twice.
    $findingRows = @(ConvertTo-AdfaRowSet -Rows $Findings)

    # Meta carries an HTML badge string for the report header; it is presentation and has no
    # place in a data document, so the fields are taken by name rather than splatted.
    $doc = [ordered]@{
        schemaVersion = 1
        tool          = [ordered]@{
            name    = 'ADForestAssessment'
            version = [string]$Meta.Version
        }
        run           = [ordered]@{
            forest        = [string]$Meta.Forest
            generated     = [string]$Meta.Generated
            runBy         = [string]$Meta.RunBy
            domainsScoped = @($Meta.DomainsScoped)
            dcCount       = [int]$Meta.DcCount
            sectionsRun   = @($sectionMap.Keys)
        }
        summary       = (New-AdfaReportSummary -Summary $Summary -Findings $findingRows)
        findings      = $findingRows
        coverage      = @(ConvertTo-AdfaRowSet -Rows $Coverage)
        sections      = $sectionMap
    }
    return $doc
}

function Export-AdfaJsonReport {
    <#
    .SYNOPSIS
        Writes the run as JSON beside the HTML report.
    .DESCRIPTION
        Serialises what Invoke-Main has already assembled. Nothing is collected here, so a
        serialisation fault costs no data - the CSVs and the itemised log are already on disk
        by the time this runs.

        Depth is explicit and generous. ConvertTo-Json defaults to 2, which would render a
        section's rows as type names instead of values - silent truncation, which is the
        precise failure mode this tool exists to avoid. A test asserts the default depth
        carries real section data rather than "System.Object[]".
    .OUTPUTS
        [string] The path written.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][pscustomobject]$Meta,
        [Parameter(Mandatory)][AllowNull()][AllowEmptyCollection()]$Findings,
        [Parameter(Mandatory)][AllowNull()][AllowEmptyCollection()]$Coverage,
        [Parameter(Mandatory)][AllowNull()]$Sections,
        [Parameter(Mandatory)][pscustomobject]$Summary,
        [Parameter(Mandatory)][string]$Path,
        [int]$Depth = 12
    )
    $doc = New-AdfaReportDocument -Meta $Meta -Findings $Findings -Coverage $Coverage -Sections $Sections -Summary $Summary
    $doc | ConvertTo-Json -Depth $Depth | Out-File -Encoding UTF8 -FilePath $Path -Force
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

    # Terminating on purpose: with no module there is no directory access and nothing to report
    # on. The message names the requirement instead of surfacing a raw module-load error.
    try { Import-Module ActiveDirectory -ErrorAction Stop -Verbose:$false }
    catch {
        Write-Log -Level ERROR ("RSAT ActiveDirectory module could not be loaded: {0}" -f $_.Exception.Message)
        throw ("The RSAT ActiveDirectory module is required and could not be loaded: {0}. Install RSAT-AD-PowerShell, or run this on a domain controller." -f $_.Exception.Message)
    }
    Write-Stage 'ActiveDirectory module imported'

    $adParams = @{}
    if ($Server) { $adParams.Server = $Server }
    if ($Credential) { $adParams.Credential = $Credential }
    $repParams = @{}
    if ($Credential) { $repParams.Credential = $Credential }

    # Forest and domain resolution. Previously unguarded: on a forest where either call throws -
    # a damaged or partially-recovered one, which is precisely what this tool exists for - the run
    # died with a raw exception and produced NO report at all. Now the failure becomes the
    # report's headline finding and every section degrades around it, which is only possible
    # because the collectors now tolerate an empty domain and DC list.
    $scopeRows = @()
    $forestError = ''
    $forest = $null
    try { $forest = Get-ADForest @adParams }
    catch { $forestError = $_.Exception.Message }

    if ($null -eq $forest) {
        Write-Log -Level ERROR -Section 'ForestScope' -Message ("Forest could not be read: {0}" -f $forestError)
        # A placeholder so the reporting path still runs and a bundle still lands on disk. Named
        # so nobody mistakes it for a forest: every section around it reports Not Assessed.
        $forest = [pscustomobject]@{ Name = '(forest unreadable)'; RootDomain = ''; Domains = @(); ForestMode = '' }
        $scopeRows += New-Finding -Area 'ForestScope' -Item 'Forest resolution' -Status $script:Status.Fail `
            -Detail ("The forest could not be read, so NOTHING in this report was assessed: {0}. Check that the target is reachable, that ADWS (9389) and LDAP (389) are open, and that the credentials can read the directory. Re-run with -Server pointed at a known-healthy DC." -f $forestError)
    }

    $rootDomain = [string]$forest.RootDomain
    $targetDomains = @()
    if (-not $forestError) {
        if ($AllDomains) { $targetDomains = @($forest.Domains) }
        else {
            try { $targetDomains = @((Get-ADDomain @adParams).DNSRoot) }
            catch {
                # The forest object read but the current domain did not. Falling back to the forest
                # root is a genuine recovery on a damaged forest - but it CHANGES THE SCOPE of the
                # run, so it is reported loudly rather than done quietly.
                Write-Log -Level ERROR -Section 'ForestScope' -Message ("Current domain could not be read: {0}" -f $_.Exception.Message)
                if ($rootDomain) {
                    $targetDomains = @($rootDomain)
                    $scopeRows += New-Finding -Area 'ForestScope' -Item 'Domain scope' -Status $script:Status.Warning `
                        -Detail ("The current domain could not be determined ({0}), so this run was scoped to the forest ROOT domain '{1}' instead. Confirm that is the domain you meant to assess; if not, re-run with -Server pointed at a DC in the intended domain." -f $_.Exception.Message, $rootDomain)
                }
                else {
                    $scopeRows += New-Finding -Area 'ForestScope' -Item 'Domain scope' -Status $script:Status.Fail `
                        -Detail ("The current domain could not be determined ({0}) and the forest reported no root domain to fall back to, so no domain was assessed." -f $_.Exception.Message)
                }
            }
        }
    }
    if (@($targetDomains).Count -eq 0 -and -not $forestError) {
        $scopeRows += New-Finding -Area 'ForestScope' -Item 'Domain scope' -Status $script:Status.Fail `
            -Detail 'The forest was readable but reported no domains to assess. Every per-domain section is therefore unassessed, not clean.'
    }
    Write-Stage ("Forest: {0}; assessing domains: {1}" -f $forest.Name, ($targetDomains -join ', '))

    $sectionData = [ordered]@{}
    $sectionStatus = [ordered]@{}
    # Scope problems lead the report: if the forest or the domain list could not be resolved,
    # every section below is unassessed and the reader needs to know that before reading them.
    if (@($scopeRows).Count -gt 0) { $sectionData['Forest & Domain Scope'] = @($scopeRows) }
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
    # Every per-DC section downstream reads $dcNames. When this fallback threw silently, all of
    # them reported "No domain controllers enumerated" and the actual cause - bad credentials, no
    # ADWS, a dead target DC - was discarded. The reason is captured so those sections can name
    # it, which is the difference between "this forest has no DCs" and "we could not ask".
    $script:DcEnumerationError = ''
    if ($dcNames.Count -eq 0) {
        try { $dcNames = @(Get-ADDomainController -Filter * @adParams | Select-Object -ExpandProperty HostName) }
        catch {
            $script:DcEnumerationError = $_.Exception.Message
            Write-Log -Level ERROR -Section 'DomainControllers' -Message ("Domain controller enumeration FAILED, so every per-DC section is unassessed rather than clean: {0}" -f $_.Exception.Message)
        }
    }
    if ($dcNames.Count -eq 0) {
        $whyNoDcs = 'No domain controllers could be enumerated.'
        if ($script:DcEnumerationError) { $whyNoDcs = ("Domain controller enumeration failed: {0}" -f $script:DcEnumerationError) }
        Write-Log -Level ERROR -Section 'DomainControllers' -Message $whyNoDcs
        # A first-class finding, so the report itself says the per-DC checks are unassessed.
        # Without this the only trace was each section's own terse "no DCs enumerated" line.
        $sectionData['Domain Controller Enumeration'] = @(New-Finding -Area 'DomainControllers' `
                -Item 'Domain controller enumeration' -Status $script:Status.NotAssessed `
                -Detail ("{0} Every per-DC check (replication, DNS consistency, ports, secure channels, DS events, diagnostics) is therefore UNASSESSED, not clean." -f $whyNoDcs))
    }

    # A throw here used to drop the domain from the section silently - the same shape of defect
    # as the v1.6.0 multi-domain data loss, where a reader saw a shorter list and no error. Each
    # failure now becomes a row, so the section's own count reconciles with the domains scoped.
    if (Test-SectionSelected 'Domains' $Sections) {
        $ds = foreach ($d in $targetDomains) {
            try { Get-AdfaDomainSummary -DomainName $d -AdParams $adParams }
            catch {
                Write-Log -Level ERROR -Section $d -Message ("Domain summary failed: {0}" -f $_.Exception.Message)
                New-Finding -Scope $d -Area 'Domains' -Item ("Domain summary - {0}" -f $d) -Status $script:Status.NotAssessed `
                    -Detail ("Could not be read: {0}. Functional level, FSMO holders and the domain SID are unknown for this domain." -f $_.Exception.Message)
            }
        }
        $sectionData['Domain Summary'] = @($ds)
    }
    if (Test-SectionSelected 'Fsmo' $Sections) {
        $fs = foreach ($d in $targetDomains) {
            try { Get-AdfaFsmoRole -DomainName $d -AdParams $adParams }
            catch {
                Write-Log -Level ERROR -Section $d -Message ("FSMO role lookup failed: {0}" -f $_.Exception.Message)
                New-Finding -Scope $d -Area 'Fsmo' -Item ("FSMO roles - {0}" -f $d) -Status $script:Status.NotAssessed `
                    -Detail ("Could not be read: {0}. Role holders for this domain are unknown - do not conclude they are healthy." -f $_.Exception.Message)
            }
        }
        $sectionData['FSMO Roles'] = @($fs)
    }

    if (Test-SectionSelected 'Replication' $Sections) {
        Write-Stage 'Replication health'
        $sectionData['Replication Health'] = Get-AdfaReplicationHealth -DomainControllers $dcNames -RepParams $repParams -RpcPortTimeoutMs $script:Config.RpcPortTimeoutMs -StaleMinutes $script:Config.ReplicationStaleMinutes
        Write-Stage 'Replication cross-check (repadmin /showrepl * /csv)'
        $sectionData['Replication Cross-Check (repadmin)'] = Get-AdfaRepadminReplication -TimeoutSeconds 300 -Retries $script:Config.Retries -RetryDelaySeconds $script:Config.RetryDelaySeconds
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
        $sysvolRows = @(Get-AdfaSysvolHealth @ext)

        # Whether each DC is actually serving SYSVOL and NETLOGON. The vendor's own first
        # diagnostic for broken SYSVOL replication, and a common state after a restore: DFSR
        # does not share SYSVOL until the replicated folder has initialised.
        $sysvolRows += @(Get-AdfaSysvolShareHealth -DomainControllers $dcNames -RpcPortTimeoutMs $script:Config.RpcPortTimeoutMs)

        # The two attributes a D2/D4-equivalent rebuild edits by hand, per KB 2218556. Read
        # per domain, because "exactly one member is authoritative" is a cross-DC rule that
        # cannot be checked from any single DC.
        foreach ($d in $targetDomains) {
            $domainDcs = @($allDcInventory | Where-Object {
                    $sc = $_.PSObject.Properties['Scope']   # $null when absent - StrictMode-safe
                    $null -ne $sc -and [string]$sc.Value -eq $d
                })
            $subs = @(Get-AdfaDfsrSubscription -DomainName $d -DomainControllers $domainDcs -AdParams $adParams)
            $sysvolRows += @(Get-AdfaDfsrSubscriptionVerdict -DomainName $d -Subscriptions $subs)
        }
        $sectionData['SYSVOL / DFSR'] = @($sysvolRows)

        Write-Stage 'DFS Replication events'
        $sectionData['DFS Replication Events'] = Get-AdfaDfsrEventLog -DomainControllers $dcNames -Credential $Credential `
            -LookbackDays $script:Config.DfsrEventLookbackDays -RpcPortTimeoutMs $script:Config.RpcPortTimeoutMs

        if ($IncludeSysvolBacklog) {
            Write-Stage 'SYSVOL backlog (DFSR, both directions against each domain PDC)'
            $backlogRows = @()
            foreach ($d in $targetDomains) {
                # The PDC emulator is where Group Policy edits are normally written, so it is the
                # DC the others should be catching up with.
                $pdc = ''
                try { $pdc = [string](Get-ADDomain -Identity $d @adParams).PDCEmulator }
                catch {
                    Write-Log -Level ERROR -Section $d -Message ("PDC emulator lookup failed, so no SYSVOL backlog could be measured: {0}" -f $_.Exception.Message)
                    $backlogRows += New-Finding -Scope $d -Area 'SysvolBacklog' -Item 'SYSVOL backlog' -Status $script:Status.NotAssessed `
                        -Detail ("The PDC emulator could not be identified, so there was no reference DC to measure against: {0}" -f $_.Exception.Message)
                    continue
                }
                $domainDcNames = @($allDcInventory | Where-Object {
                        $sc = $_.PSObject.Properties['Scope']   # $null when absent - StrictMode-safe
                        $null -ne $sc -and [string]$sc.Value -eq $d
                    } | Select-Object -ExpandProperty HostName)
                if (@($domainDcNames).Count -eq 0) { $domainDcNames = @($dcNames) }
                $backlogRows += @(Get-AdfaSysvolBacklog -DomainName $d -ReferenceDc $pdc `
                        -DomainControllers $domainDcNames -RpcPortTimeoutMs $script:Config.RpcPortTimeoutMs)
            }
            $sectionData['SYSVOL Backlog'] = @($backlogRows)
        }
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
        Write-Stage 'Directory backup status (per DC)'
        $sectionData['Backup Status'] = Get-AdfaBackupStatus -DomainControllers $dcNames -RpcPortTimeoutMs $script:Config.RpcPortTimeoutMs @ext
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

    # ---- Recovery & consistency (post-incident) ----
    if (Test-SectionSelected 'DnsAdConsistency' $Sections) {
        Write-Stage 'DNS vs AD consistency (per DNS server)'
        $dacRows = foreach ($d in $targetDomains) { Get-AdfaDnsAdConsistency -DomainName $d -AdParams $adParams -DnsServers $dcNames }
        $sectionData['DNS vs AD Consistency'] = @($dacRows)
    }
    if (Test-SectionSelected 'DsaCname' $Sections) {
        Write-Stage 'DSA GUID CNAME records (_msdcs, per DNS server)'
        $sectionData['DSA GUID CNAMEs'] = Get-AdfaDsaGuidCname -ForestRoot $forest.Name -AdParams $adParams -DnsServers $dcNames
    }
    if (Test-SectionSelected 'GcConsistency' $Sections) {
        Write-Stage 'Global Catalog consistency (AD flag vs DNS, per DNS server)'
        $sectionData['Global Catalog Consistency'] = Get-AdfaGcConsistency -ForestRoot $forest.Name -AdParams $adParams -DnsServers $dcNames
    }
    if (Test-SectionSelected 'PortMatrix' $Sections) {
        Write-Stage 'Port reachability matrix (replication port set)'
        $sectionData['Port Reachability'] = Get-AdfaPortMatrix -DomainControllers $dcNames -RpcPortTimeoutMs $script:Config.RpcPortTimeoutMs
    }
    if (Test-SectionSelected 'DcSecureChannel' $Sections) {
        Write-Stage 'DC machine-account passwords & secure channels'
        $scRows = foreach ($d in $targetDomains) {
            Get-AdfaDcSecureChannel -DomainName $d -AdParams $adParams -Credential $Credential `
                -WarnDays $script:Config.DcPasswordWarnDays -FailDays $script:Config.DcPasswordFailDays `
                -RpcPortTimeoutMs $script:Config.RpcPortTimeoutMs
        }
        $sectionData['DC Secure Channel & Machine Passwords'] = @($scRows)
    }
    if (Test-SectionSelected 'DsEvents' $Sections) {
        Write-Stage 'Directory Service event log (lingering / rollback / DNS failures)'
        $sectionData['Directory Service Events'] = Get-AdfaDsEventLog -DomainControllers $dcNames -Credential $Credential `
            -LookbackDays $script:Config.DsEventLookbackDays -RpcPortTimeoutMs $script:Config.RpcPortTimeoutMs
    }
    if ($IncludeLingeringObjectScan) {
        Write-Stage 'Lingering object scan (repadmin advisory mode - no changes)'
        $loRows = foreach ($d in $targetDomains) {
            Get-AdfaLingeringObjectScan -DomainName $d -AdParams $adParams -TimeoutSeconds 300 -RpcPortTimeoutMs $script:Config.RpcPortTimeoutMs
        }
        $sectionData['Lingering Object Scan (advisory)'] = @($loRows)
    }

    if (Test-SectionSelected 'ExchangeSchema' $Sections) {
        $sectionData['Exchange Schema Markers'] = Get-AdfaExchangeSchemaMarker -AdParams $adParams
    }

    if (Test-SectionSelected 'ExchangeSeReadiness' $Sections) {
        Write-Stage 'Exchange Server SE compatibility (forest level + DC operating systems)'
        # An override that cannot be read is fatal here rather than swallowed: the alternative
        # is judging the forest against the built-in table while the operator believes theirs
        # is in force.
        $seConfig = $script:Config.ExchangeSe
        if ($ExchangeSeConfigPath) {
            $seConfig = Import-AdfaExchangeSeConfig -BaseConfig $script:Config.ExchangeSe -Path $ExchangeSeConfigPath
            Write-Log -Level INFO ("Exchange SE prerequisite table overridden from {0}" -f $ExchangeSeConfigPath)
        }
        $forestMode = ''
        if ($null -ne $forest) {
            $fmProp = $forest.PSObject.Properties['ForestMode']   # $null when absent - StrictMode-safe
            if ($null -ne $fmProp -and $null -ne $fmProp.Value) { $forestMode = [string]$fmProp.Value }
        }
        $sectionData['Exchange SE Compatibility'] = Get-AdfaExchangeSeCompatibility -ForestMode $forestMode `
            -DomainSummaries $sectionData['Domain Summary'] -DomainControllers $allDcInventory -SeConfig $seConfig
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
    $unreadableRows = 0
    foreach ($key in $sectionData.Keys) {
        # Expand first: a nested collection here would present as a row with no Status and
        # be skipped, which is how whole sections were once discarded without a word.
        foreach ($row in @(Expand-AdfaRowList -Rows $sectionData[$key])) {
            $names = $row.PSObject.Properties.Name
            $statusCol = if ($names -contains 'Status') { 'Status' } elseif ($names -contains 'Health') { 'Health' } else { $null }
            if (-not $statusCol) {
                # Rows with no status column are informational inventory (sites, subnets,
                # site links) and belong only in their own section - expected, not an error.
                # Anything that is not a plain object, though, means a collector returned a
                # shape this build did not expect: say so rather than dropping it in silence.
                if (($row -is [System.Collections.IEnumerable]) -and ($row -isnot [string])) {
                    $unreadableRows++
                    Write-Log -Level ERROR ("Section '{0}' produced a row of type {1} that carries no status - it is NOT in the consolidated findings. This is a tool defect; report it." -f $key, $row.GetType().Name)
                }
                continue
            }
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
            $detailText = $detailParts -join ' | '
            # Attach a best-practice fix to every actionable (non-Pass) finding.
            $recommendation = ''
            if ($status -match '^(Fail|Broken|Failed|Warning|Degraded)$') {
                $recommendation = Get-AdfaRecommendation -Section $key -Item ([string]$item) -Detail $detailText
            }
            $consolidated += [pscustomobject]@{
                Section = $key; Scope = $scopeVal; Item = [string]$item
                Status  = $status; Detail = $detailText
                Recommendation = $recommendation
            }
        }
    }
    # Severity order for the consolidated file and the log.
    $sevRank = @{ 'Fail' = 0; 'Broken' = 0; 'Failed' = 0; 'Warning' = 1; 'Degraded' = 1; 'Not Assessed' = 2; 'Info' = 3; 'Pass' = 4; 'Healthy' = 4; 'Verified' = 4 }
    $consolidated = $consolidated | Sort-Object @{ e = { $r = $sevRank[$_.Status]; if ($null -eq $r) { 5 } else { $r } } }, Section, Item
    Save-Csv -InputObject $consolidated -Path (Join-Path $csvPath 'Findings-Consolidated.csv')

    # ---- Section reconciliation ----
    # Collected-vs-reported, per section. A section that produced rows but contributed no
    # finding is either pure inventory (expected) or data loss (a defect). Stating the
    # count for every section makes the second case impossible to miss - the failure mode
    # that discarded twelve sections on the first multi-domain run showed no symptom at all.
    $sectionAudit = @()
    foreach ($key in $sectionData.Keys) {
        $collected = @(Expand-AdfaRowList -Rows $sectionData[$key]).Count
        $reported = @($consolidated | Where-Object { $_.Section -eq $key }).Count
        $sectionAudit += [pscustomobject]@{
            Section = $key; RowsCollected = $collected; FindingsReported = $reported
            Note    = $(if ($collected -gt 0 -and $reported -eq 0) { 'No status-bearing rows (inventory section, or data loss - verify)' } else { '' })
        }
    }
    Save-Csv -InputObject $sectionAudit -Path (Join-Path $csvPath 'Section-Coverage.csv')
    Write-Log -Level RESULT ("Section reconciliation ({0} sections):" -f @($sectionAudit).Count)
    foreach ($a in $sectionAudit) {
        $lvl = if ($a.Note) { 'WARN' } else { 'RESULT' }
        Write-Log -Level $lvl ('{0,-42} collected={1,-6} reported={2}{3}' -f $a.Section, $a.RowsCollected, $a.FindingsReported, $(if ($a.Note) { ' <- ' + $a.Note } else { '' }))
    }
    if ($unreadableRows -gt 0) {
        Write-Log -Level ERROR ("{0} collected row(s) could not be interpreted and are absent from the consolidated findings. Treat this report as INCOMPLETE." -f $unreadableRows)
        Write-Warning ("{0} collected row(s) could not be interpreted - the consolidated findings are INCOMPLETE. See the log." -f $unreadableRows)
    }

    # Detailed itemised log: every section's findings, worst first, with the exact detail text.
    Write-Log -Level RESULT ("Assessment findings ({0} checks across {1} sections):" -f @($consolidated).Count, $sectionData.Keys.Count)
    foreach ($f in $consolidated) {
        $lvl = switch -Regex ($f.Status) {
            '^(Fail|Broken|Failed)$' { 'ERROR'; break }
            '^(Warning|Degraded)$' { 'WARN'; break }
            '^(Not Assessed)$' { 'WARN'; break }
            default { 'RESULT' }
        }
        $msg = '{0,-12} {1} :: {2}{3}{4}' -f $f.Status, $f.Section, $f.Item, $(if ($f.Detail) { " -> $($f.Detail)" } else { '' }), $(if ($f.Recommendation) { " || FIX: $($f.Recommendation)" } else { '' })
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
    # One summary object, consumed by the JSON document and by this function's return value,
    # so the two can never disagree about the same run.
    $runSummary = [pscustomobject]@{ Pass = $countOk; Warning = $countWarn; Fail = $countBad; NotAssessed = $countNa }

    $meta = [pscustomobject]@{
        Forest        = $forest.Name
        Generated     = (Get-Date).ToString('u')
        RunBy         = ("{0}\{1}" -f $env:USERDOMAIN, $env:USERNAME)
        Version       = $script:Config.Version
        DomainsScoped = @($targetDomains)
        DcCount       = @($dcNames).Count
        Badges        = $badges
    }

    Write-Stage 'Writing HTML report'
    $reportPath = Join-Path $runRoot 'Assessment.html'
    # Lead the report with the consolidated, severity-sorted findings, then the detail sections.
    $htmlSections = [ordered]@{}
    $htmlSections['Findings (worst first)'] = @($consolidated | Where-Object { $_.Status -notmatch '^(Pass|Healthy|Verified|Info)$' })
    # Reconciliation sits directly under the findings: what each section collected against
    # what it contributed, so a silently empty section is visible in the report itself.
    $htmlSections['Section Coverage (collected vs reported)'] = $sectionAudit
    foreach ($k in $sectionData.Keys) { $htmlSections[$k] = $sectionData[$k] }
    if (@($htmlSections['Findings (worst first)']).Count -eq 0) {
        $htmlSections['Findings (worst first)'] = @([pscustomobject]@{ Section = '(none)'; Item = 'No warnings or failures'; Status = 'Pass'; Detail = 'All assessed checks passed.'; Recommendation = '' })
    }
    # The CSVs and the itemised log are already on disk at this point. A rendering fault
    # must not discard them, stop the transcript from closing, or suppress the run summary
    # - the collection is the expensive part and on a recovery it may not be repeatable
    # cheaply. Report the failure loudly and carry on.
    $reportRendered = $false
    try {
        New-AdfaHtmlReport -Sections $htmlSections -Meta $meta -Path $reportPath | Out-Null
        $reportRendered = $true
    }
    catch {
        $reportPath = ''
        Write-Log -Level ERROR ("HTML report generation FAILED: {0}" -f $_.Exception.Message)
        Write-Warning ("HTML report could not be written: {0}" -f $_.Exception.Message)
        Write-Warning ("All findings are still on disk: {0}" -f (Join-Path $csvPath 'Findings-Consolidated.csv'))
    }
    if ($reportRendered) { Write-Log -Level INFO ("HTML report: {0}" -f $reportPath) }

    # JSON is the machine-readable twin of the HTML, for diffing one run against the next
    # (a phased rollout re-runs this between phases). Guarded separately from the HTML so
    # neither renderer can take the other down, and so a JSON fault cannot discard the CSVs.
    Write-Stage 'Writing JSON report'
    $jsonPath = Join-Path $runRoot 'Assessment.json'
    try {
        Export-AdfaJsonReport -Meta $meta -Findings $consolidated -Coverage $sectionAudit `
            -Sections $sectionData -Summary $runSummary -Path $jsonPath | Out-Null
        Write-Log -Level INFO ("JSON report: {0}" -f $jsonPath)
    }
    catch {
        $jsonPath = ''
        Write-Log -Level ERROR ("JSON report generation FAILED: {0}" -f $_.Exception.Message)
        Write-Warning ("JSON report could not be written: {0}" -f $_.Exception.Message)
    }

    Write-Log -Level INFO ("Detailed log: {0}" -f $script:LogFile)
    Write-Log -Level INFO ("Consolidated findings: {0}" -f (Join-Path $csvPath 'Findings-Consolidated.csv'))
    try { Stop-Transcript | Out-Null } catch { }

    if ($reportRendered) { Write-Stage ("DONE. Report: {0}" -f $reportPath) }
    else { Write-Stage ("DONE (HTML report failed to render). Findings: {0}" -f (Join-Path $csvPath 'Findings-Consolidated.csv')) }

    [pscustomobject]@{
        Forest        = $forest.Name
        DomainsScoped = $targetDomains
        DcCount       = $dcNames.Count
        OutputRoot    = $runRoot
        ReportPath    = $reportPath
        JsonPath      = $jsonPath
        CsvPath       = $csvPath
        RawPath       = $rawPath
        LogFile       = $script:LogFile
        FindingsFile  = (Join-Path $csvPath 'Findings-Consolidated.csv')
        Transcript    = $transcript
        Summary       = $runSummary
        Sections      = @($sectionData.Keys)
    }
}

# Only auto-run when executed as a script (not when dot-sourced for testing).
if ($MyInvocation.InvocationName -ne '.' -and -not $env:ADFA_NO_AUTORUN) {
    Invoke-Main
}
