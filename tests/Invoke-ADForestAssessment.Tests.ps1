#Requires -Version 5.1
<#
.SYNOPSIS
    Pester v5 tests for Invoke-ADForestAssessment.ps1.
.DESCRIPTION
    Runs on a host where Pester v5 is available (a DC or CI runner). Mirrors the pure-logic
    coverage of Tests/Run-Validation.ps1 in idiomatic Pester and adds PSScriptAnalyzer gating
    when that module is present. Where Pester/analyzer are NOT installable (sealed sandbox),
    use Tests/Run-Validation.ps1 and Tests/Run-SmokeTest.ps1 instead.
#>

BeforeAll {
    $script:RepoRoot = Split-Path -Parent $PSScriptRoot
    $script:Target = Join-Path $script:RepoRoot 'src/ADForestAssessment/Invoke-ADForestAssessment.ps1'
    $env:ADFA_NO_AUTORUN = '1'
    . $script:Target
}

AfterAll {
    Remove-Item Env:\ADFA_NO_AUTORUN -ErrorAction SilentlyContinue
}

Describe 'Syntax' {
    It 'parses with zero errors' {
        $errors = $null
        [System.Management.Automation.Language.Parser]::ParseFile($script:Target, [ref]$null, [ref]$errors) | Out-Null
        $errors.Count | Should -Be 0
    }
}

Describe 'Resolve-AdfaTrustHealth' {
    It 'reports Healthy when all expected directions verify' {
        (Resolve-AdfaTrustHealth -Direction Bidirectional -OutboundResult Verified -InboundResult Verified -TargetReachable $true).Health | Should -Be 'Healthy'
    }
    It 'reports Broken when an expected direction fails' {
        (Resolve-AdfaTrustHealth -Direction Bidirectional -OutboundResult Failed -InboundResult Verified -TargetReachable $true).Health | Should -Be 'Broken'
    }
    It 'reports Broken when the partner is unreachable' {
        (Resolve-AdfaTrustHealth -Direction Outbound -OutboundResult 'Not Assessed' -InboundResult 'Not Assessed' -TargetReachable $false).Health | Should -Be 'Broken'
    }
    It 'reports Not Assessed when verification is skipped' {
        (Resolve-AdfaTrustHealth -Direction Bidirectional -OutboundResult 'Not Assessed' -InboundResult 'Not Assessed' -TargetReachable $true -VerificationSkipped $true).Health | Should -Be 'Not Assessed'
    }
    It 'never fabricates a Pass when nothing could be verified' {
        (Resolve-AdfaTrustHealth -Direction Bidirectional -OutboundResult 'Not Assessed' -InboundResult 'Not Assessed' -TargetReachable $true).Health | Should -Be 'Not Assessed'
    }
    It 'downgrades to Degraded on a security warning' {
        (Resolve-AdfaTrustHealth -Direction Outbound -OutboundResult Verified -InboundResult 'Not Assessed' -TargetReachable $true -SecurityWarnings @('x')).Health | Should -Be 'Degraded'
    }
    It 'stays Healthy but notes the coverage gap when one side is untestable' {
        $r = Resolve-AdfaTrustHealth -Direction Bidirectional -OutboundResult Verified -InboundResult 'Not Assessed' -TargetReachable $true
        $r.Health | Should -Be 'Healthy'
        ($r.Reasons -join ' ') | Should -Match 'Inbound'
    }
}

Describe 'Get-AdfaTrustSecurityWarning' {
    It 'flags an external trust with SID filtering disabled' {
        $t = [pscustomobject]@{ TrustType = 'External'; SIDFilteringQuarantined = $false; SelectiveAuthentication = $true; TGTDelegation = $false; UsesRC4Encryption = $false }
        (Get-AdfaTrustSecurityWarning -Trust $t) -join ' ' | Should -Match 'SID filtering'
    }
    It 'flags TGT delegation and RC4' {
        $t = [pscustomobject]@{ TrustType = 'Forest'; SIDFilteringForestAware = $true; TGTDelegation = $true; UsesRC4Encryption = $true }
        $w = Get-AdfaTrustSecurityWarning -Trust $t
        ($w -join ' ') | Should -Match 'TGT delegation'
        ($w -join ' ') | Should -Match 'RC4'
    }
    It 'returns nothing for a clean trust' {
        $t = [pscustomobject]@{ TrustType = 'Forest'; SIDFilteringForestAware = $true; SelectiveAuthentication = $true; TGTDelegation = $false; UsesRC4Encryption = $false }

        # The function ends in `return , $warnings.ToArray()`. The comma stops a single
        # warning unrolling to a scalar, but it also means the empty case writes one object
        # (the empty array) to the pipeline - so `@(Get-Adfa... ).Count` is 1, not 0.
        # Every caller assigns first, which is what this asserts. See PORT-PLAN P3.
        $warnings = Get-AdfaTrustSecurityWarning -Trust $t
        @($warnings).Count | Should -Be 0
    }

    It 'reports a clean trust as Healthy end to end' {
        $t = [pscustomobject]@{ TrustType = 'Forest'; SIDFilteringForestAware = $true; SelectiveAuthentication = $true; TGTDelegation = $false; UsesRC4Encryption = $false }
        $warnings = Get-AdfaTrustSecurityWarning -Trust $t

        $verdict = Resolve-AdfaTrustHealth -Direction 'Bidirectional' `
            -OutboundResult 'Verified' -InboundResult 'Verified' `
            -TargetReachable $true -SecurityWarnings $warnings

        $verdict.Health | Should -Be 'Healthy'
    }
}

Describe 'Test-AdfaSecureChannel' {
    It 'parses nltest success as Verified' {
        Mock Test-CommandAvailable { $true }
        Mock Invoke-ExternalCommand { [pscustomobject]@{ Success = $true; ExitCode = 0; StdOut = 'Trust Verification Status = 0x0 NERR_Success' } }
        (Test-AdfaSecureChannel -SourceDomain a -TargetDomain b).Result | Should -Be 'Verified'
    }
    It 'parses an nltest error status as Failed' {
        Mock Test-CommandAvailable { $true }
        Mock Invoke-ExternalCommand { [pscustomobject]@{ Success = $false; ExitCode = 1; StdOut = 'Trust Verification Status = 0x35 ERROR' } }
        (Test-AdfaSecureChannel -SourceDomain a -TargetDomain b).Result | Should -Be 'Failed'
    }
    It 'returns Not Assessed when no tools are present' {
        Mock Test-CommandAvailable { $false }
        (Test-AdfaSecureChannel -SourceDomain a -TargetDomain b).Result | Should -Be 'Not Assessed'
    }
}

Describe 'ConvertTo-AdfaHtmlSection' {
    It 'applies RAG classes and encodes content' {
        $html = ConvertTo-AdfaHtmlSection -Title 'T' -Data @([pscustomobject]@{ Item = '<b>x</b>'; Health = 'Broken' })
        $html | Should -Match "tr class='bad'"
        $html | Should -Match '&lt;b&gt;'
    }
    It 'renders a placeholder for empty data' {
        (ConvertTo-AdfaHtmlSection -Title 'E' -Data @()) | Should -Match 'No data collected'
    }
}

Describe 'Identity export flattening' {
    It 'unions properties across objects with differing populated attributes' {
        $props = Get-AdfaObjectPropertyUnion -Objects @(
            [pscustomobject]@{ A = 1; B = 2 }, [pscustomobject]@{ B = 3; C = 4 })
        $props | Should -Contain 'A'
        $props | Should -Contain 'C'
    }
    It 'joins multi-valued attributes with a semicolon' {
        $o = [pscustomobject]@{ MemberOf = @('CN=A', 'CN=B') }
        (ConvertTo-AdfaFlatObject -InputObject $o -Property @('MemberOf')).MemberOf | Should -Be 'CN=A;CN=B'
    }
    It 'emits empty string for a missing property (StrictMode-safe)' {
        $o = [pscustomobject]@{ X = 1 }
        (ConvertTo-AdfaFlatObject -InputObject $o -Property @('Y')).Y | Should -Be ''
    }
    It 'summarises enabled counts safely when Enabled is absent' {
        $sum = Get-AdfaIdentitySummary -DomainName 'd' -Users @([pscustomobject]@{ SamAccountName = 'x' }) -Computers @()
        ($sum | Where-Object Object -eq 'Users').Total | Should -Be 1
    }
}

Describe 'Deep security pure logic' {
    It 'flags an ESC1-susceptible template' {
        $t = [pscustomobject]@{ 'msPKI-Certificate-Name-Flag' = 1; 'msPKI-Enrollment-Flag' = 0; 'msPKI-RA-Signature' = 0; 'pKIExtendedKeyUsage' = @('1.3.6.1.5.5.7.3.2') }
        (Test-AdfaEsc1Template -Template $t).Vulnerable | Should -BeTrue
    }
    It 'does not flag a template that requires manager approval' {
        $t = [pscustomobject]@{ 'msPKI-Certificate-Name-Flag' = 1; 'msPKI-Enrollment-Flag' = 2; 'msPKI-RA-Signature' = 0; 'pKIExtendedKeyUsage' = @('1.3.6.1.5.5.7.3.2') }
        (Test-AdfaEsc1Template -Template $t).Vulnerable | Should -BeFalse
    }
    It 'detects a DCSync Get-Changes-All grant' {
        $guid = $script:Config.DcSyncRightGuids['DS-Replication-Get-Changes-All']
        $ace = [pscustomobject]@{ AccessControlType = 'Allow'; ActiveDirectoryRights = 'ExtendedRight'; ObjectType = $guid; IdentityReference = 'x' }
        Test-AdfaDcSyncAce -Ace $ace | Should -BeTrue
    }
    It 'ignores a Deny ACE and an ordinary read' {
        $guid = $script:Config.DcSyncRightGuids['DS-Replication-Get-Changes-All']
        (Test-AdfaDcSyncAce -Ace ([pscustomobject]@{ AccessControlType = 'Deny'; ActiveDirectoryRights = 'ExtendedRight'; ObjectType = $guid; IdentityReference = 'x' })) | Should -BeFalse
        (Test-AdfaDcSyncAce -Ace ([pscustomobject]@{ AccessControlType = 'Allow'; ActiveDirectoryRights = 'ReadProperty'; ObjectType = ([guid]::Empty); IdentityReference = 'x' })) | Should -BeFalse
    }
    It 'finds duplicate SPNs and reports none for empty input' {
        $objs = @(
            [pscustomobject]@{ SamAccountName = 'a'; ServicePrincipalName = @('MSSQLSvc/x') },
            [pscustomobject]@{ SamAccountName = 'b'; ServicePrincipalName = @('MSSQLSvc/x') })
        @(Find-AdfaDuplicateSpn -Objects $objs).Count | Should -Be 1
        $empty = Find-AdfaDuplicateSpn -Objects @()
        @($empty).Count | Should -Be 0
    }
}

Describe 'Recovery & consistency pure logic' {

    Context 'Compare-AdfaDnsAdvertisement' {
        It 'separates stale, missing and matched hosts' {
            $c = Compare-AdfaDnsAdvertisement -AdHosts @('dc1.corp.local', 'dc2.corp.local') -DnsTargets @('dc2.corp.local', 'dc3.corp.local')
            $c.StaleInDns | Should -Be @('dc3.corp.local')
            $c.MissingFromDns | Should -Be @('dc1.corp.local')
            $c.Matched | Should -Be @('dc2.corp.local')
        }
        It 'normalises case and trailing dots before comparing' {
            $c = Compare-AdfaDnsAdvertisement -AdHosts @('DC1.Corp.Local') -DnsTargets @('dc1.corp.local.')
            @($c.StaleInDns).Count | Should -Be 0
            @($c.MissingFromDns).Count | Should -Be 0
            $c.Matched | Should -Be @('dc1.corp.local')
        }
        It 'treats empty inputs as agreement, not divergence' {
            $c = Compare-AdfaDnsAdvertisement -AdHosts @() -DnsTargets @()
            @($c.StaleInDns).Count | Should -Be 0
            @($c.MissingFromDns).Count | Should -Be 0
        }
    }

    Context 'Resolve-AdfaDcPasswordVerdict' {
        It 'passes a freshly rotated machine password' {
            Resolve-AdfaDcPasswordVerdict -AgeDays 10 | Should -Be 'Pass'
        }
        It 'warns at the warn threshold and fails at the fail threshold' {
            Resolve-AdfaDcPasswordVerdict -AgeDays 45 | Should -Be 'Warning'
            Resolve-AdfaDcPasswordVerdict -AgeDays 90 | Should -Be 'Fail'
        }
        It 'never fabricates a verdict when the age is unknown' {
            Resolve-AdfaDcPasswordVerdict -AgeDays $null | Should -Be 'Not Assessed'
        }
        It 'honours custom thresholds' {
            Resolve-AdfaDcPasswordVerdict -AgeDays 20 -WarnDays 15 -FailDays 30 | Should -Be 'Warning'
        }
    }

    Context 'Test-AdfaRemoteSecureChannel (inbound trust, executed on the partner side)' {
        It 'reports Not Assessed with the manual command when the partner DC has no WinRM' {
            Mock Test-TcpPort { $false }
            $r = Test-AdfaRemoteSecureChannel -PartnerDomain 'partner.example' -VerifyDomain 'ours.example' -PartnerDc 'dc1.partner.example'
            $r.Result | Should -Be 'Not Assessed'
            $r.Detail | Should -Match "nltest /sc_verify:ours\.example"
            $r.Detail | Should -Match 'partner\.example'
        }
        It 'parses NERR_Success from the partner DC as Verified' {
            Mock Test-TcpPort { $true }
            Mock Invoke-Command { 'Trust Verification Status = 0x0 NERR_Success' }
            (Test-AdfaRemoteSecureChannel -PartnerDomain 'partner.example' -VerifyDomain 'ours.example' -PartnerDc 'dc1.partner.example').Result | Should -Be 'Verified'
        }
        It 'parses an error status from the partner DC as Failed, never Verified' {
            Mock Test-TcpPort { $true }
            Mock Invoke-Command { 'Trust Verification Status = 0xc0000022 STATUS_ACCESS_DENIED' }
            (Test-AdfaRemoteSecureChannel -PartnerDomain 'partner.example' -VerifyDomain 'ours.example' -PartnerDc 'dc1.partner.example').Result | Should -Be 'Failed'
        }
        It 'reports Not Assessed when the WinRM call itself throws' {
            Mock Test-TcpPort { $true }
            Mock Invoke-Command { throw 'Access is denied' }
            $r = Test-AdfaRemoteSecureChannel -PartnerDomain 'partner.example' -VerifyDomain 'ours.example' -PartnerDc 'dc1.partner.example'
            $r.Result | Should -Be 'Not Assessed'
            $r.Detail | Should -Match 'Access is denied'
        }
    }

    Context 'Get-AdfaDnsQueryOutcome' {
        It 'classifies each outcome distinctly' {
            Get-AdfaDnsQueryOutcome -Available $false | Should -Be 'NoTool'
            Get-AdfaDnsQueryOutcome -Available $true -TargetCount 2 | Should -Be 'Resolved'
            Get-AdfaDnsQueryOutcome -Available $true -TargetCount 0 -ErrorText 'DNS name does not exist' | Should -Be 'NoRecord'
            Get-AdfaDnsQueryOutcome -Available $true -TargetCount 0 -ErrorText 'request timed out contacting server' | Should -Be 'NoAnswer'
        }
    }

    Context 'Compare-AdfaDnsServerView' {
        It 'reports per-server divergence instead of one merged view' {
            $views = @{ 'dns1' = @('dc1.x', 'dc2.x'); 'dns2' = @('dc2.x', 'dc3.x'); 'dns3' = @() }
            $s = Compare-AdfaDnsServerView -AdHosts @('dc1.x', 'dc2.x') -ServerTargets $views
            $s.ServersQueried | Should -Be 3
            $s.AgreeingServers | Should -Be @('dns1')
            $s.DivergentServers | Should -Be @('dns2', 'dns3')
            ($s.PerServer | Where-Object Server -eq 'dns2').StaleInDns | Should -Be @('dc3.x')
            ($s.PerServer | Where-Object Server -eq 'dns3').MissingFromDns | Should -Be @('dc1.x', 'dc2.x')
        }
    }

    Context 'ConvertFrom-AdfaShowreplCsv' {
        It 'parses links past banner lines and preserves failure counts' {
            $text = @"
Repadmin: running command /showrepl against full DC dc1.contoso.com
showrepl_COLUMNS,Destination DSA Site,Destination DSA,Naming Context,Source DSA Site,Source DSA,Transport Type,Number of Failures,Last Failure Time,Last Success Time,Last Failure Status
showrepl_INFO,Default-First-Site-Name,DC1,"DC=contoso,DC=com",Default-First-Site-Name,DC2,RPC,0,0,2026-08-30 10:00:00,0
showrepl_INFO,Default-First-Site-Name,DC1,"DC=contoso,DC=com",Default-First-Site-Name,DC3,RPC,42,2026-08-29 09:00:00,2026-08-01 10:00:00,1722
"@
            $rows = @(ConvertFrom-AdfaShowreplCsv -Text $text)
            $rows.Count | Should -Be 2
            ($rows | Where-Object { $_.'Source DSA' -eq 'DC3' }).'Number of Failures' | Should -Be '42'
        }
        It 'returns an empty set for unparsable text' {
            @(ConvertFrom-AdfaShowreplCsv -Text 'garbage with no header').Count | Should -Be 0
            @(ConvertFrom-AdfaShowreplCsv -Text '').Count | Should -Be 0
        }
    }

    Context 'Get-AdfaLatestBackupDate' {
        It 'extracts the most recent of several dates' {
            $d = Get-AdfaLatestBackupDate -Text "DC=x : 2026-07-01 10:00:00`nCN=Configuration : 2026-08-15 09:30:00"
            $d | Should -Be ([datetime]'2026-08-15 09:30:00')
        }
        It 'handles US-style dates and returns null when nothing parses' {
            (Get-AdfaLatestBackupDate -Text 'backup at 8/15/2026 09:30:00').Year | Should -Be 2026
            Get-AdfaLatestBackupDate -Text 'no dates here' | Should -BeNullOrEmpty
        }
    }

    Context 'Get-AdfaRecommendation' {
        It 'routes a trust failure whose detail mentions the secure channel to the TRUST fix, not the machine-account one' {
            $r = Get-AdfaRecommendation -Section 'Trusts & Two-Way Health' -Item 'corp-partner' -Detail 'Outbound secure channel verification FAILED.'
            $r | Should -Match 'netdom trust'
            $r | Should -Not -Match 'resetpwd'
        }
        It 'maps a broken trust to a netdom trust reset' {
            Get-AdfaRecommendation -Section 'Trusts & Two-Way Health' -Item 'corp-partner' -Detail 'Trust partner is not reachable.' |
                Should -Match 'netdom trust'
        }
        It 'maps a lingering-object event to removelingeringobjects, not a generic replication fix' {
            Get-AdfaRecommendation -Section 'Directory Service Events' -Item 'Event 1988 on DC1' -Detail 'Lingering object detected - replication BLOCKED.' |
                Should -Match 'removelingeringobjects'
        }
        It 'maps USN rollback to demote-and-repromote' {
            Get-AdfaRecommendation -Section 'Directory Service Events' -Item 'Event 2095 on DC1' -Detail 'USN rollback detected.' |
                Should -Match 'demote'
        }
        It 'maps a missing DSA GUID CNAME to DNS re-registration' {
            Get-AdfaRecommendation -Section 'DSA GUID CNAMEs' -Item 'DSA GUID CNAME for dc1' -Detail 'DSA GUID CNAME missing' |
                Should -Match 'dsregdns'
        }
        It 'maps a stale secure channel to a machine-password reset that never disjoins a DC' {
            $r = Get-AdfaRecommendation -Section 'DC Secure Channel & Machine Passwords' -Item 'Secure channel: dc1' -Detail 'verification failed'
            $r | Should -Match 'netdom resetpwd'
            $r | Should -Match 'Never disjoin'
        }
        It 'returns an empty string rather than inventing guidance' {
            Get-AdfaRecommendation -Section 'Forest Summary' -Item 'xyzzy' -Detail 'nothing matches this' | Should -Be ''
        }
    }
}

Describe 'Heterogeneous row shapes (regression: live run 2026-08-30)' {

    # A section's rows are not always the same shape. Get-AdfaReplicationHealth emits a
    # row WITHOUT FailureDetail for an unreachable DC and one WITH it for a reachable DC,
    # so a forest where the first DC answers and a later one does not produced:
    #   ConvertTo-AdfaHtmlSection : The property 'FailureDetail' cannot be found on this object
    # and the entire HTML report was lost after a full collection run.

    Context 'ConvertTo-AdfaRowSet' {
        It 'unions columns in first-seen order and fills missing values with empty string' {
            $rows = @(
                [pscustomobject]@{ DomainController = 'dc1'; Status = 'Fail'; FailureDetail = 'partner=dc9' },
                [pscustomobject]@{ DomainController = 'dc2'; Status = 'Not Assessed'; Detail = 'SKIPPED' }
            )
            $n = @(ConvertTo-AdfaRowSet -Rows $rows)
            $n.Count | Should -Be 2
            @($n[0].PSObject.Properties.Name) | Should -Be @('DomainController', 'Status', 'FailureDetail', 'Detail')
            @($n[1].PSObject.Properties.Name) | Should -Be @('DomainController', 'Status', 'FailureDetail', 'Detail')
            $n[1].FailureDetail | Should -Be ''
            $n[0].Detail | Should -Be ''
            $n[0].FailureDetail | Should -Be 'partner=dc9'
        }
        It 'converts nulls to empty string and drops null rows' {
            $n = @(ConvertTo-AdfaRowSet -Rows @([pscustomobject]@{ A = $null; B = 'x' }, $null))
            $n.Count | Should -Be 1
            $n[0].A | Should -Be ''
        }
        It 'returns a genuinely empty set for empty or null input' {
            @(ConvertTo-AdfaRowSet -Rows @()).Count | Should -Be 0
            @(ConvertTo-AdfaRowSet -Rows $null).Count | Should -Be 0
        }
        It 'leaves already-uniform rows untouched in order and value' {
            $rows = @([pscustomobject]@{ X = 1; Y = 'a' }, [pscustomobject]@{ X = 2; Y = 'b' })
            $n = @(ConvertTo-AdfaRowSet -Rows $rows)
            @($n[0].PSObject.Properties.Name) | Should -Be @('X', 'Y')
            $n[1].Y | Should -Be 'b'
        }
    }

    Context 'ConvertTo-AdfaHtmlSection' {
        It 'renders a mixed-shape section instead of throwing PropertyNotFoundStrict' {
            $rows = @(
                [pscustomobject]@{ DomainController = 'dc1'; Status = 'Fail'; FailureDetail = 'partner=dc9 lastError=1722' },
                [pscustomobject]@{ DomainController = 'dc2'; Status = 'Not Assessed'; Detail = 'SKIPPED: RPC135=False' }
            )
            { ConvertTo-AdfaHtmlSection -Title 'Replication Health' -Data $rows } | Should -Not -Throw
            # Assign outside the Should scriptblock - it runs in its own scope, so an
            # assignment made inside it would not be visible here.
            $html = ConvertTo-AdfaHtmlSection -Title 'Replication Health' -Data $rows
            $html | Should -Match 'FailureDetail'
            $html | Should -Match 'dc2'
            $html | Should -Match "tr class='na'"
            $html | Should -Match "tr class='bad'"
        }
        It 'renders when the SHORT row comes first (column union, not row-0 columns)' {
            $rows = @(
                [pscustomobject]@{ DomainController = 'dc2'; Status = 'Not Assessed'; Detail = 'SKIPPED' },
                [pscustomobject]@{ DomainController = 'dc1'; Status = 'Fail'; FailureDetail = 'partner=dc9' }
            )
            $html = ConvertTo-AdfaHtmlSection -Title 'Replication Health' -Data $rows
            $html | Should -Match 'FailureDetail'
            $html | Should -Match 'partner=dc9'
        }
        It 'renders a multi-domain trust section mixing full rows with an enumeration-failure row' {
            $rows = @(
                [pscustomobject]@{ Scope = 'a.local'; TrustName = 'b.local'; Health = 'Healthy'; Reasons = 'ok'; VerifyDetail = 'v' },
                [pscustomobject]@{ Scope = 'c.local'; TrustName = '(enumeration failed)'; Health = 'Not Assessed'; Detail = 'server down' }
            )
            { ConvertTo-AdfaHtmlSection -Title 'Trusts & Two-Way Health' -Data $rows } | Should -Not -Throw
        }
    }

    Context 'Get-AdfaReplicationHealth row shape' {
        It 'emits FailureDetail on the unreachable-DC row so the section is uniform at source' {
            Mock Test-TcpPort { $false }
            # No @() wrap: the function ends in `return , @($rows)`, so wrapping again
            # nests the array and $rows[0] would be the array itself (PORT-PLAN P3).
            $rows = Get-AdfaReplicationHealth -DomainControllers @('dc1.contoso.com')
            @($rows[0].PSObject.Properties.Name) | Should -Contain 'FailureDetail'
            $rows[0].Status | Should -Be 'Not Assessed'
        }
    }
}

Describe 'Multi-domain aggregation contract (regression: 12 sections silently discarded)' {

    # Per-domain sections are built as:
    #   $rows = foreach ($d in $targetDomains) { Get-AdfaSomething -DomainName $d }
    # While collectors ended in `return , @($rows)` each iteration emitted the array as ONE
    # object, so with more than one domain the section became an array of arrays. Consumers
    # looked for Status on an array, found none, and skipped it - collected, then discarded
    # without a word. Single-domain runs were unaffected, which is why it went unseen.

    It 'no collector still uses the return-comma idiom that caused it' {
        # Anchor to the start of a code line: the comments in the script quote the old
        # idiom while explaining this defect, and must not trip the guard.
        $offenders = @(Get-Content -Path $script:Target | Where-Object { $_ -match '^\s*return\s+,' })
        $offenders -join "`n" | Should -BeNullOrEmpty
    }

    It 'a collector returning several rows aggregates flat across domains' {
        function Get-AdfaFakeSection {
            param([string]$DomainName)
            $rows = @(
                [pscustomobject]@{ Scope = $DomainName; Area = 'X'; Item = 'a'; Status = 'Fail'; Detail = 'd' },
                [pscustomobject]@{ Scope = $DomainName; Area = 'X'; Item = 'b'; Status = 'Pass'; Detail = 'd' }
            )
            return @($rows)
        }
        $agg = foreach ($d in @('root.local', 'north.local', 'epal.local')) { Get-AdfaFakeSection -DomainName $d }
        $section = @($agg)
        $section.Count | Should -Be 6
        $section[0].PSObject.Properties.Name | Should -Contain 'Status'
        @($section | Select-Object -ExpandProperty Scope -Unique).Count | Should -Be 3
    }

    It 'a collector returning ONE row still aggregates flat across domains' {
        function Get-AdfaFakeSingle {
            param([string]$DomainName)
            return @(@([pscustomobject]@{ Scope = $DomainName; Item = 'only'; Status = 'Warning' }))
        }
        $agg = foreach ($d in @('a.local', 'b.local')) { Get-AdfaFakeSingle -DomainName $d }
        @($agg).Count | Should -Be 2
        @($agg)[0].PSObject.Properties.Name | Should -Contain 'Status'
    }

    Context 'Expand-AdfaRowList' {
        It 'flattens a nested section back to findings' {
            $nested = @(
                @([pscustomobject]@{ Item = 'a'; Status = 'Fail' }),
                @([pscustomobject]@{ Item = 'b'; Status = 'Pass' }, [pscustomobject]@{ Item = 'c'; Status = 'Warning' })
            )
            $flat = @(Expand-AdfaRowList -Rows $nested)
            $flat.Count | Should -Be 3
            $flat[0].PSObject.Properties.Name | Should -Contain 'Status'
        }
        It 'leaves a flat list alone and drops nulls' {
            $flat = @(Expand-AdfaRowList -Rows @([pscustomobject]@{ A = 1 }, $null, [pscustomobject]@{ A = 2 }))
            $flat.Count | Should -Be 2
        }
        It 'never splits a string into characters' {
            $r = @(Expand-AdfaRowList -Rows @('hello'))
            $r.Count | Should -Be 1
            $r[0] | Should -Be 'hello'
        }
        It 'returns empty for empty or null input' {
            @(Expand-AdfaRowList -Rows @()).Count | Should -Be 0
            @(Expand-AdfaRowList -Rows $null).Count | Should -Be 0
        }
    }

    It 'Resolve-AdfaTrustHealth tolerates a null warning list (plain returns yield null when empty)' {
        $v = Resolve-AdfaTrustHealth -Direction Bidirectional -OutboundResult Verified -InboundResult Verified `
            -TargetReachable $true -SecurityWarnings $null
        $v.Health | Should -Be 'Healthy'
    }
}

Describe 'PSScriptAnalyzer' {
    It 'has no Error/Warning findings against the committed settings' -Skip:(-not (Get-Module -ListAvailable PSScriptAnalyzer)) {
        $settings = Join-Path (Split-Path -Parent $PSScriptRoot) 'PSScriptAnalyzerSettings.psd1'
        $findings = Invoke-ScriptAnalyzer -Path $script:Target -Settings $settings
        $findings | Should -BeNullOrEmpty
    }
}

Describe 'JSON report document' {
    BeforeAll {
        $script:LegacySummary = [pscustomobject]@{ Pass = 1; Warning = 1; Fail = 1; NotAssessed = 1 }
        $script:MixedFindings = @(
            (New-Finding -Area 'A' -Item 'i1' -Status 'Pass'         -Detail 'd'),
            (New-Finding -Area 'A' -Item 'i2' -Status 'Warning'      -Detail 'd'),
            (New-Finding -Area 'A' -Item 'i3' -Status 'Fail'         -Detail 'd'),
            (New-Finding -Area 'A' -Item 'i4' -Status 'Not Assessed' -Detail 'd'),
            (New-Finding -Area 'A' -Item 'i5' -Status 'Info'         -Detail 'd'),
            (New-Finding -Area 'A' -Item 'i6' -Status 'Info'         -Detail 'd')
        )
        $script:DocMeta = [pscustomobject]@{
            Forest = 'contoso.com'; Generated = '2026-01-01 00:00:00Z'; RunBy = 'CONTOSO\tester'
            Version = '9.9.9'; DomainsScoped = @('contoso.com', 'north.contoso.com'); DcCount = 2
            Badges = "<span class='b-ok'>Pass 1</span>"
        }
        # Not $sections: the script under test declares a [ValidateSet] $Sections parameter and
        # PowerShell variable names are case-insensitive, so that name is taken in this scope.
        $docSections = [ordered]@{}
        $docSections['One Row'] = @([pscustomobject]@{ Name = 'dc1'; Site = 'HQ' })
        $docSections['Empty'] = @()
        $script:DocSections = $docSections
    }

    Context 'New-AdfaReportSummary' {
        # Invoke-Main's four counters match Pass/Healthy, Warning/Degraded, Fail/Broken and
        # Not Assessed, but not 'Info' - a valid New-Finding status. Measured on the
        # three-domain fixture: 123 findings, 106 counted, 17 Info counted nowhere.
        It 'counts every finding exactly once' {
            $s = New-AdfaReportSummary -Summary $script:LegacySummary -Findings $script:MixedFindings
            [int]$s.total | Should -Be 6
            $bucketSum = [int]$s.pass + [int]$s.warning + [int]$s.fail + [int]$s.notAssessed +
                [int]$s.info + [int]$s.unclassified
            $bucketSum | Should -Be 6
        }
        It 'counts Info findings instead of dropping them' {
            $s = New-AdfaReportSummary -Summary $script:LegacySummary -Findings $script:MixedFindings
            [int]$s.info | Should -Be 2
            [int]$s.unclassified | Should -Be 0
        }
        It 'surfaces a status no filter matches rather than losing it' {
            $s = New-AdfaReportSummary -Summary $script:LegacySummary `
                -Findings @([pscustomobject]@{ Area = 'A'; Item = 'i'; Status = 'Verified'; Detail = 'd' })
            [int]$s.unclassified | Should -Be 1
            [int]$s.total | Should -Be 1
        }
        It 'does not throw on a row with no Status column (StrictMode-safe)' {
            { New-AdfaReportSummary -Summary $script:LegacySummary -Findings @([pscustomobject]@{ Area = 'A' }) } |
                Should -Not -Throw
        }
        It 'reports zero for an empty finding set' {
            [int](New-AdfaReportSummary -Summary $script:LegacySummary -Findings @()).total | Should -Be 0
        }
    }

    Context 'New-AdfaReportDocument' {
        It 'emits a schema version so a consumer can tell a tool change from an environment change' {
            $doc = New-AdfaReportDocument -Meta $script:DocMeta -Findings $script:MixedFindings `
                -Coverage @() -Sections $script:DocSections -Summary $script:LegacySummary
            [int]$doc.schemaVersion | Should -Be 1
            [string]$doc.tool.name | Should -Be 'ADForestAssessment'
            [string]$doc.tool.version | Should -Be '9.9.9'
        }
        It 'records every scoped domain, not just the first' {
            $doc = New-AdfaReportDocument -Meta $script:DocMeta -Findings $script:MixedFindings `
                -Coverage @() -Sections $script:DocSections -Summary $script:LegacySummary
            @($doc.run.domainsScoped).Count | Should -Be 2
        }
        It 'keeps presentation markup out of the data document' {
            $doc = New-AdfaReportDocument -Meta $script:DocMeta -Findings $script:MixedFindings `
                -Coverage @() -Sections $script:DocSections -Summary $script:LegacySummary
            # $doc is an OrderedDictionary, so PSObject.Properties would enumerate .NET members
            # rather than keys and pass whatever the document held. Assert on the keys.
            @($doc.Keys) | Should -Not -Contain 'Badges'
            @($doc.Keys) | Should -Contain 'summary'   # non-vacuity: this is how keys surface
        }
        It 'keeps a section that collected nothing, as an empty array' {
            $doc = New-AdfaReportDocument -Meta $script:DocMeta -Findings $script:MixedFindings `
                -Coverage @() -Sections $script:DocSections -Summary $script:LegacySummary
            @($doc.sections.Keys) | Should -Contain 'Empty'
            @($doc.sections['Empty']).Count | Should -Be 0
        }
    }

    Context 'Serialisation' {
        It 'round-trips with a single-element section still addressable' {
            $doc = New-AdfaReportDocument -Meta $script:DocMeta -Findings $script:MixedFindings `
                -Coverage @() -Sections $script:DocSections -Summary $script:LegacySummary
            $back = $doc | ConvertTo-Json -Depth 12 | ConvertFrom-Json
            [string]@($back.sections.'One Row')[0].Name | Should -Be 'dc1'
            @($back.findings).Count | Should -Be 6
        }
        It 'leaks no HTML into the JSON' {
            $doc = New-AdfaReportDocument -Meta $script:DocMeta -Findings $script:MixedFindings `
                -Coverage @() -Sections $script:DocSections -Summary $script:LegacySummary
            $json = $doc | ConvertTo-Json -Depth 12
            $json | Should -Not -Match '<span'
            $json | Should -Not -Match 'b-ok'
        }
        It 'demonstrates that the ConvertTo-Json default depth of 2 loses section rows' {
            # Truncation stringifies the row to PowerShell's hashtable form - '@{Name=dc1; ...}' -
            # rather than emitting a type name, so that is the marker. Without this the explicit
            # -Depth on Export-AdfaJsonReport would be unjustified.
            $doc = New-AdfaReportDocument -Meta $script:DocMeta -Findings $script:MixedFindings `
                -Coverage @() -Sections $script:DocSections -Summary $script:LegacySummary
            ($doc | ConvertTo-Json -Depth 2 -WarningAction SilentlyContinue) | Should -Match '"@\{'
            ($doc | ConvertTo-Json -Depth 12) | Should -Not -Match '"@\{'
        }
    }

    Context 'Export-AdfaJsonReport' {
        It 'writes a parseable file and returns its path' {
            $tmp = Join-Path ([IO.Path]::GetTempPath()) ("adfa_json_{0}.json" -f [guid]::NewGuid().ToString('N'))
            try {
                $p = Export-AdfaJsonReport -Meta $script:DocMeta -Findings $script:MixedFindings `
                    -Coverage @() -Sections $script:DocSections -Summary $script:LegacySummary -Path $tmp
                $p | Should -Be $tmp
                Test-Path $tmp | Should -BeTrue
                $doc = Get-Content $tmp -Raw | ConvertFrom-Json
                [int]$doc.summary.total | Should -Be 6
                [string]$doc.run.forest | Should -Be 'contoso.com'
            }
            finally { Remove-Item $tmp -Force -ErrorAction SilentlyContinue }
        }
    }
}
