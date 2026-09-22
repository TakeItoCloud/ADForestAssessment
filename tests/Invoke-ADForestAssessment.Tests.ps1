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

Describe 'Directory Service log coverage' {
    # The defect this closes: finding no events reported Pass, so a DC whose Directory Service
    # log was wiped during a ransomware recovery read exactly like a healthy one on the checks
    # that matter most - USN rollback (2095), unsupported restore (2103), lingering objects
    # (1988). Absence is only evidence when the log reaches back across the window.
    BeforeAll { $script:WStart = (Get-Date).AddDays(-14) }

    Context 'Get-AdfaEventLogCoverage' {
        It 'reports Covered when the log predates the window' {
            Get-AdfaEventLogCoverage -Inspected $true -RecordCount 500 `
                -OldestRecord $script:WStart.AddDays(-30) -WindowStart $script:WStart | Should -Be 'Covered'
        }
        It 'reports Covered at the exact window boundary' {
            Get-AdfaEventLogCoverage -Inspected $true -RecordCount 500 `
                -OldestRecord $script:WStart -WindowStart $script:WStart | Should -Be 'Covered'
        }
        It 'reports Truncated when the log starts inside the window' {
            Get-AdfaEventLogCoverage -Inspected $true -RecordCount 500 `
                -OldestRecord $script:WStart.AddDays(1) -WindowStart $script:WStart | Should -Be 'Truncated'
        }
        It 'never reports Covered for a log cleared moments ago' {
            Get-AdfaEventLogCoverage -Inspected $true -RecordCount 3 `
                -OldestRecord (Get-Date) -WindowStart $script:WStart | Should -Be 'Truncated'
        }
        It 'reports Empty for a log with no records' {
            Get-AdfaEventLogCoverage -Inspected $true -RecordCount 0 `
                -OldestRecord $null -WindowStart $script:WStart | Should -Be 'Empty'
        }
        It 'reports Unknown rather than Covered when a bound is missing' {
            Get-AdfaEventLogCoverage -Inspected $true -RecordCount 500 `
                -OldestRecord $null -WindowStart $script:WStart | Should -Be 'Unknown'
            Get-AdfaEventLogCoverage -Inspected $true -RecordCount 500 `
                -OldestRecord $script:WStart.AddDays(-1) -WindowStart $null | Should -Be 'Unknown'
            Get-AdfaEventLogCoverage -Inspected $false -RecordCount $null `
                -OldestRecord $null -WindowStart $script:WStart | Should -Be 'Unknown'
        }
        It 'never classifies any degraded input as Covered' {
            # Non-vacuity: the declared population is the four ways coverage can be incomplete,
            # and all four are evaluated here rather than asserted in the aggregate.
            $degraded = @(
                (Get-AdfaEventLogCoverage -Inspected $false -RecordCount 10 -OldestRecord $script:WStart.AddDays(-5) -WindowStart $script:WStart),
                (Get-AdfaEventLogCoverage -Inspected $true  -RecordCount 0  -OldestRecord $null                      -WindowStart $script:WStart),
                (Get-AdfaEventLogCoverage -Inspected $true  -RecordCount 10 -OldestRecord $null                      -WindowStart $script:WStart),
                (Get-AdfaEventLogCoverage -Inspected $true  -RecordCount 10 -OldestRecord $script:WStart.AddDays(2)  -WindowStart $script:WStart)
            )
            @($degraded).Count | Should -Be 4
            @($degraded | Where-Object { $_ -eq 'Covered' }).Count | Should -Be 0
        }
    }

    Context 'Get-AdfaEventCoverageDetail' {
        It 'adds no caveat when coverage is complete' {
            Get-AdfaEventCoverageDetail -Coverage 'Covered' -OldestRecord $script:WStart -LookbackDays 14 |
                Should -BeNullOrEmpty
        }
        It 'names where coverage actually begins' {
            # Guards a real precedence bug: "a {0}" + "b" -f $x formats only the SECOND string,
            # so the timestamp silently stayed a literal {0} until this asserted on it.
            $d = Get-AdfaEventCoverageDetail -Coverage 'Truncated' `
                -OldestRecord ([datetime]'2026-09-15 08:30') -LookbackDays 14
            $d | Should -Match '2026-09-15 08:30'
            $d | Should -Not -Match '\{0\}'
            $d | Should -Match 'cleared or has wrapped'
        }
        It 'says absence proves nothing for an empty log' {
            Get-AdfaEventCoverageDetail -Coverage 'Empty' -OldestRecord $null -LookbackDays 14 |
                Should -Match 'proves nothing'
        }
        It 'carries the underlying cause when the log could not be inspected' {
            Get-AdfaEventCoverageDetail -Coverage 'Unknown' -OldestRecord $null -LookbackDays 14 `
                -Reason 'Access is denied' | Should -Match 'Access is denied'
        }
    }

    Context 'Remediation routing' {
        It 'routes a coverage finding to evidence recovery, not a secure-channel reset' {
            $r = Get-AdfaRecommendation -Section 'Directory Service Events' `
                -Item 'Log coverage on dc1.contoso.com' `
                -Detail (Get-AdfaEventCoverageDetail -Coverage 'Truncated' -OldestRecord (Get-Date) -LookbackDays 14)
            $r | Should -Not -BeNullOrEmpty
            $r | Should -Match 'UNASSESSED'
            $r | Should -Not -Match 'netdom trust'
        }
        It 'still routes a real USN rollback to rollback guidance' {
            # The coverage entry sits ahead of the event entries in a first-match-wins map,
            # so this pins the ordering rather than assuming it.
            $r = Get-AdfaRecommendation -Section 'Directory Service Events' `
                -Item 'Event 2095 on dc1.contoso.com' `
                -Detail '1 occurrence(s) in 14 day(s), last 2026-09-20 10:00. USN rollback detected - the directory is silently diverging.'
            $r | Should -Not -BeNullOrEmpty
            $r | Should -Not -Match 'UNASSESSED'
        }
    }
}

Describe 'Exchange Server SE compatibility' {
    BeforeAll {
        $script:SeCfg = $script:Config.ExchangeSe
        $script:DcOk = @([pscustomobject]@{ HostName = 'dc1.contoso.com'; OperatingSystem = 'Windows Server 2019 Datacenter'; IsReadOnly = $false })

        # Defined HERE, not in the Describe body. Pester v5 runs a Describe body during
        # discovery and It blocks during the run phase, so a function declared in the body is
        # gone by the time the tests execute (CommandNotFoundException). BeforeAll runs in the
        # run phase, so this is visible to every It in the container.
        # Returns $null rather than indexing [0] into an empty array, which throws under StrictMode.
        function Get-SeTestRow {
            param($Rows, [string]$Item)
            $m = @($Rows | Where-Object { [string]$_.Item -eq $Item })
            if ($m.Count -eq 0) { return $null }
            return $m[0]
        }
    }

    Context 'Config table provenance' {
        It 'records where the values came from and when' {
            # CLAUDE.md: volatile vendor facts carry their source URL and read date.
            $script:SeCfg.SourceUrl | Should -Match 'learn\.microsoft\.com'
            $script:SeCfg.ReadDate | Should -Match '^\d{4}-\d{2}-\d{2}$'
        }
    }

    Context 'Test-AdfaOsSupported' {
        It 'accepts every OS in the supported matrix' {
            foreach ($os in @('Windows Server 2025 Datacenter', 'Windows Server 2022 Standard',
                    'Windows Server 2019 Datacenter', 'Windows Server 2016 Standard',
                    'Windows Server 2012 R2 Datacenter')) {
                Test-AdfaOsSupported -OperatingSystem $os -SupportedOs $script:SeCfg.SupportedDomainControllerOs |
                    Should -Not -BeNullOrEmpty -Because "$os is listed as supported"
            }
        }
        It 'does not confuse plain Windows Server 2012 with 2012 R2' {
            # 2012 R2 is supported and plain 2012 is not. A pattern loosened to bare '2012'
            # would silently pass an unsupported DC, so this is pinned explicitly.
            Test-AdfaOsSupported -OperatingSystem 'Windows Server 2012 Standard' `
                -SupportedOs $script:SeCfg.SupportedDomainControllerOs | Should -BeNullOrEmpty
            Test-AdfaOsSupported -OperatingSystem 'Windows Server 2012 R2 Standard' `
                -SupportedOs $script:SeCfg.SupportedDomainControllerOs | Should -Be 'Windows Server 2012 R2'
        }
        It 'rejects an out-of-support OS and an empty string' {
            Test-AdfaOsSupported -OperatingSystem 'Windows Server 2008 R2 Enterprise' `
                -SupportedOs $script:SeCfg.SupportedDomainControllerOs | Should -BeNullOrEmpty
            Test-AdfaOsSupported -OperatingSystem '' `
                -SupportedOs $script:SeCfg.SupportedDomainControllerOs | Should -BeNullOrEmpty
        }
        It 'supports nothing when the table is empty, rather than everything' {
            Test-AdfaOsSupported -OperatingSystem 'Windows Server 2019' -SupportedOs @() | Should -BeNullOrEmpty
        }
    }

    Context 'Forest functional level verdict' {
        It 'passes the two supported levels and fails a lower one' {
            foreach ($m in @('Windows2016Forest', 'Windows2012R2Forest')) {
                $r = Get-AdfaExchangeSeCompatibility -ForestMode $m -DomainSummaries @() `
                    -DomainControllers $script:DcOk -SeConfig $script:SeCfg
                [string](Get-SeTestRow $r 'Forest functional level').Status | Should -Be 'Pass' -Because "$m is supported"
            }
            $bad = Get-AdfaExchangeSeCompatibility -ForestMode 'Windows2008R2Forest' -DomainSummaries @() `
                -DomainControllers $script:DcOk -SeConfig $script:SeCfg
            $row = Get-SeTestRow $bad 'Forest functional level'
            [string]$row.Status | Should -Be 'Fail'
            $row.Detail | Should -Match 'Windows2016Forest'   # names what IS supported
        }
        It 'reports Not Assessed when the level could not be read, never Pass' {
            $r = Get-AdfaExchangeSeCompatibility -ForestMode '' -DomainSummaries @() `
                -DomainControllers $script:DcOk -SeConfig $script:SeCfg
            [string](Get-SeTestRow $r 'Forest functional level').Status | Should -Be 'Not Assessed'
        }
    }

    Context 'Domain controller OS verdict' {
        It 'fails the forest when any single DC runs an unsupported OS' {
            # "All domain controllers in the forest must be running one of the supported
            # versions", so one bad DC is a blocker rather than a warning.
            $dcs = @(
                [pscustomobject]@{ HostName = 'dc1.contoso.com'; OperatingSystem = 'Windows Server 2019 Datacenter'; IsReadOnly = $false },
                [pscustomobject]@{ HostName = 'dc2.contoso.com'; OperatingSystem = 'Windows Server 2012 Standard'; IsReadOnly = $false }
            )
            $row = Get-SeTestRow (Get-AdfaExchangeSeCompatibility -ForestMode 'Windows2016Forest' `
                    -DomainSummaries @() -DomainControllers $dcs -SeConfig $script:SeCfg) 'Domain controller operating systems'
            [string]$row.Status | Should -Be 'Fail'
            $row.Detail | Should -Match 'dc2\.contoso\.com'
            $row.Detail | Should -Not -Match 'dc1\.contoso\.com'
        }
        It 'treats an unreadable OS as absent, not unsupported, and says so in its own row' {
            # An absent key and a measured absence are different claims (CLAUDE.md).
            $dcs = @(
                [pscustomobject]@{ HostName = 'dc1.contoso.com'; OperatingSystem = 'Windows Server 2019'; IsReadOnly = $false },
                [pscustomobject]@{ HostName = 'dc2.contoso.com'; OperatingSystem = 'Not Assessed'; IsReadOnly = $false }
            )
            $r = Get-AdfaExchangeSeCompatibility -ForestMode 'Windows2016Forest' -DomainSummaries @() `
                -DomainControllers $dcs -SeConfig $script:SeCfg
            [string](Get-SeTestRow $r 'Domain controller operating systems').Status | Should -Be 'Pass'
            $unk = Get-SeTestRow $r 'Domain controller OS - not readable'
            $unk | Should -Not -BeNullOrEmpty
            [string]$unk.Status | Should -Be 'Not Assessed'
            $unk.Detail | Should -Match 'unverified, not compatible'
        }
        It 'reports Not Assessed when nothing is readable and when no DCs were enumerated' {
            $allUnk = Get-AdfaExchangeSeCompatibility -ForestMode 'Windows2016Forest' -DomainSummaries @() `
                -DomainControllers @([pscustomobject]@{ HostName = 'dc1'; OperatingSystem = 'Not Assessed'; IsReadOnly = $false }) `
                -SeConfig $script:SeCfg
            [string](Get-SeTestRow $allUnk 'Domain controller operating systems').Status | Should -Be 'Not Assessed'
            $none = Get-AdfaExchangeSeCompatibility -ForestMode 'Windows2016Forest' -DomainSummaries @() `
                -DomainControllers @() -SeConfig $script:SeCfg
            [string](Get-SeTestRow $none 'Domain controller operating systems').Status | Should -Be 'Not Assessed'
        }
    }

    Context 'Read-only DCs and scope' {
        It 'warns about a read-only DC and stays silent when there is none' {
            $dcs = @(
                [pscustomobject]@{ HostName = 'dc1.contoso.com'; OperatingSystem = 'Windows Server 2019'; IsReadOnly = $false },
                [pscustomobject]@{ HostName = 'rodc1.contoso.com'; OperatingSystem = 'Windows Server 2019'; IsReadOnly = $true }
            )
            $r = Get-AdfaExchangeSeCompatibility -ForestMode 'Windows2016Forest' -DomainSummaries @() `
                -DomainControllers $dcs -SeConfig $script:SeCfg
            $row = Get-SeTestRow $r 'Read-only domain controllers'
            $row | Should -Not -BeNullOrEmpty
            [string]$row.Status | Should -Be 'Warning'
            $row.Detail | Should -Match 'rodc1\.contoso\.com'

            # Non-vacuity for the negative case: the lookup really does return null when absent.
            Get-SeTestRow $r 'No Such Item Exists' | Should -BeNullOrEmpty
            $clean = Get-AdfaExchangeSeCompatibility -ForestMode 'Windows2016Forest' -DomainSummaries @() `
                -DomainControllers $script:DcOk -SeConfig $script:SeCfg
            Get-SeTestRow $clean 'Read-only domain controllers' | Should -BeNullOrEmpty
        }
        It 'states its own limits so it is not mistaken for full SE readiness' {
            $r = Get-AdfaExchangeSeCompatibility -ForestMode 'Windows2016Forest' -DomainSummaries @() `
                -DomainControllers $script:DcOk -SeConfig $script:SeCfg
            (Get-SeTestRow $r 'Scope of this check').Detail | Should -Match 'does NOT cover'
        }
    }

    Context 'Merge-AdfaExchangeSeConfig' {
        It 'replaces only the keys the override names' {
            $m = Merge-AdfaExchangeSeConfig -BaseConfig $script:SeCfg `
                -Override @{ SupportedForestModes = @('Windows2025Forest') } -OverrideSource 'C:\cfg\se.json'
            @($m.SupportedForestModes).Count | Should -Be 1
            @($m.SupportedDomainControllerOs).Count | Should -Be 5
        }
        It 'rewrites provenance so findings do not cite Learn for overridden values' {
            $m = Merge-AdfaExchangeSeConfig -BaseConfig $script:SeCfg `
                -Override @{ SupportedForestModes = @('Windows2025Forest') } -OverrideSource 'C:\cfg\se.json'
            [string]$m.SourceUrl | Should -Be 'C:\cfg\se.json'
        }
        It 'changes nothing for a null override' {
            @((Merge-AdfaExchangeSeConfig -BaseConfig $script:SeCfg -Override $null).SupportedForestModes).Count |
                Should -Be 2
        }
        It 'refuses an override that would empty a gate' {
            # An empty list would make every value unsupported now, and could become vacuously
            # true under a future refactor. Neither is an acceptable config outcome.
            { Merge-AdfaExchangeSeConfig -BaseConfig $script:SeCfg -Override @{ SupportedForestModes = @() } } |
                Should -Throw
            { Merge-AdfaExchangeSeConfig -BaseConfig $script:SeCfg -Override @{ SupportedDomainControllerOs = @() } } |
                Should -Throw
        }
        It 'actually changes the verdict, rather than being decoration' {
            $strict = Merge-AdfaExchangeSeConfig -BaseConfig $script:SeCfg `
                -Override @{ SupportedForestModes = @('Windows2016Forest') }
            $r = Get-AdfaExchangeSeCompatibility -ForestMode 'Windows2012R2Forest' -DomainSummaries @() `
                -DomainControllers $script:DcOk -SeConfig $strict
            [string](Get-SeTestRow $r 'Forest functional level').Status | Should -Be 'Fail'
        }
    }

    Context 'Import-AdfaExchangeSeConfig' {
        It 'throws rather than silently falling back when the file is missing or malformed' {
            { Import-AdfaExchangeSeConfig -BaseConfig $script:SeCfg -Path (Join-Path ([IO.Path]::GetTempPath()) 'adfa-no-such-file.json') } |
                Should -Throw
            $bad = Join-Path ([IO.Path]::GetTempPath()) ("adfa_badcfg_{0}.json" -f [guid]::NewGuid().ToString('N'))
            try {
                'this is not json {' | Out-File -LiteralPath $bad -Encoding UTF8
                { Import-AdfaExchangeSeConfig -BaseConfig $script:SeCfg -Path $bad } | Should -Throw
            }
            finally { Remove-Item $bad -Force -ErrorAction SilentlyContinue }
        }
        It 'loads a valid override from disk' {
            $good = Join-Path ([IO.Path]::GetTempPath()) ("adfa_cfg_{0}.json" -f [guid]::NewGuid().ToString('N'))
            try {
                '{ "SupportedForestModes": [ "Windows2016Forest" ] }' | Out-File -LiteralPath $good -Encoding UTF8
                $m = Import-AdfaExchangeSeConfig -BaseConfig $script:SeCfg -Path $good
                @($m.SupportedForestModes).Count | Should -Be 1
                [string]$m.SourceUrl | Should -Be $good
            }
            finally { Remove-Item $good -Force -ErrorAction SilentlyContinue }
        }
    }
}

Describe 'SYSVOL / DFSR depth' {
    BeforeAll {
        # Defined in BeforeAll, not the Describe body: a Describe body runs during Pester's
        # discovery phase, so a function declared there does not exist when It blocks execute.
        function Get-SvTestRow {
            param($Rows, [string]$Item)
            $m = @($Rows | Where-Object { [string]$_.Item -eq $Item })
            if ($m.Count -eq 0) { return $null }
            return $m[0]
        }
    }

    Context 'Get-AdfaSysvolShareOutcome' {
        It 'distinguishes a missing share from an unreachable DC' {
            # The whole point: "not shared" is a finding, "could not look" is not.
            Get-AdfaSysvolShareOutcome -SmbReachable $true -SysvolPresent $true -NetlogonPresent $true | Should -Be 'Shared'
            Get-AdfaSysvolShareOutcome -SmbReachable $true -SysvolPresent $false -NetlogonPresent $false | Should -Be 'MissingBoth'
            Get-AdfaSysvolShareOutcome -SmbReachable $true -SysvolPresent $false -NetlogonPresent $true | Should -Be 'MissingSysvol'
            Get-AdfaSysvolShareOutcome -SmbReachable $true -SysvolPresent $true -NetlogonPresent $false | Should -Be 'MissingNetlogon'
            Get-AdfaSysvolShareOutcome -SmbReachable $false -SysvolPresent $null -NetlogonPresent $null | Should -Be 'Unknown'
        }
        It 'never reports Shared for a DC it could not reach' {
            Get-AdfaSysvolShareOutcome -SmbReachable $false -SysvolPresent $true -NetlogonPresent $true | Should -Be 'Unknown'
            Get-AdfaSysvolShareOutcome -SmbReachable $true -SysvolPresent $null -NetlogonPresent $true | Should -Be 'Unknown'
        }
    }

    Context 'Get-AdfaDfsrSubscriptionVerdict' {
        # Per KB 2218556 a DFSR SYSVOL rebuild is driven by msDFSR-Enabled and msDFSR-options,
        # both edited by hand. Nothing else in this report would show either one.
        It 'passes when every DC is enabled and none is marked authoritative' {
            $v = Get-AdfaDfsrSubscriptionVerdict -DomainName 'contoso.com' -Subscriptions @(
                [pscustomobject]@{ DcName = 'dc1.contoso.com'; Enabled = $true; Options = $null },
                [pscustomobject]@{ DcName = 'dc2.contoso.com'; Enabled = $true; Options = $null })
            [string](Get-SvTestRow $v 'DFSR SYSVOL replication enabled').Status | Should -Be 'Pass'
            Get-SvTestRow $v 'Authoritative SYSVOL member set' | Should -BeNullOrEmpty
            Get-SvTestRow $v 'No Such Item' | Should -BeNullOrEmpty   # non-vacuity
        }
        It 'fails and names the DC when msDFSR-Enabled is FALSE' {
            $v = Get-AdfaDfsrSubscriptionVerdict -DomainName 'contoso.com' -Subscriptions @(
                [pscustomobject]@{ DcName = 'dc1.contoso.com'; Enabled = $true; Options = $null },
                [pscustomobject]@{ DcName = 'dc2.contoso.com'; Enabled = $false; Options = $null })
            $row = Get-SvTestRow $v 'DFSR SYSVOL replication disabled'
            [string]$row.Status | Should -Be 'Fail'
            $row.Detail | Should -Match 'dc2\.contoso\.com'
            $row.Detail | Should -Not -Match 'dc1\.contoso\.com'
        }
        It 'fails when more than one DC is marked authoritative' {
            # A cross-DC rule: the procedure marks exactly one member authoritative, so this
            # conflict is invisible from any single DC and only a domain-wide verdict finds it.
            $v = Get-AdfaDfsrSubscriptionVerdict -DomainName 'contoso.com' -Subscriptions @(
                [pscustomobject]@{ DcName = 'dc1.contoso.com'; Enabled = $true; Options = 1 },
                [pscustomobject]@{ DcName = 'dc2.contoso.com'; Enabled = $true; Options = 1 })
            $row = Get-SvTestRow $v 'Conflicting authoritative SYSVOL members'
            [string]$row.Status | Should -Be 'Fail'
            $row.Detail | Should -Match 'dc1'
            $row.Detail | Should -Match 'dc2'
            Get-SvTestRow $v 'Authoritative SYSVOL member set' | Should -BeNullOrEmpty
        }
        It 'warns rather than fails for a single authoritative member' {
            # Expected during a deliberate rebuild, so it is state to confirm, not a defect.
            $v = Get-AdfaDfsrSubscriptionVerdict -DomainName 'contoso.com' -Subscriptions @(
                [pscustomobject]@{ DcName = 'dc1.contoso.com'; Enabled = $true; Options = 1 })
            [string](Get-SvTestRow $v 'Authoritative SYSVOL member set').Status | Should -Be 'Warning'
        }
        It 'reports Not Assessed when the subscription cannot be read' {
            $v = Get-AdfaDfsrSubscriptionVerdict -DomainName 'contoso.com' -Subscriptions @(
                [pscustomobject]@{ DcName = 'dc1.contoso.com'; Enabled = $null; Options = $null })
            [string](Get-SvTestRow $v 'DFSR SYSVOL subscription - not readable').Status | Should -Be 'Not Assessed'
            [string](Get-SvTestRow (Get-AdfaDfsrSubscriptionVerdict -DomainName 'contoso.com' -Subscriptions @()) `
                    'DFSR SYSVOL subscription state').Status | Should -Be 'Not Assessed'
        }
    }

    Context 'Remediation routing' {
        It 'does not answer every SYSVOL problem with "perform a D4"' {
            # Reinitialising is the vendor's last resort - unnecessary in most cases and able to
            # lose data - so each failure must route to its own fix.
            $share = Get-AdfaRecommendation -Section 'SYSVOL / DFSR' -Item 'Shares on dc1.contoso.com' `
                -Detail 'Neither SYSVOL nor NETLOGON is shared.'
            $share | Should -Match 'Do NOT jump to a D4'
            $dirty = Get-AdfaRecommendation -Section 'DFS Replication Events' -Item 'Event 2213 on dc1' `
                -Detail 'Dirty shutdown detected - DFSR replication is PAUSED on this volume.'
            $dirty | Should -Match 'ResumeReplication'
            $fresh = Get-AdfaRecommendation -Section 'DFS Replication Events' -Item 'Event 4012 on dc1' `
                -Detail 'Content freshness protection stopped replication - longer than MaxOfflineTimeInDays.'
            $fresh | Should -Match 'EVERY DC has logged 4012'
            $conflict = Get-AdfaRecommendation -Section 'SYSVOL / DFSR' -Item 'Conflicting authoritative SYSVOL members' `
                -Detail 'msDFSR-options=1 on 2 DCs: dc1, dc2.'
            $conflict | Should -Match 'Only ONE member may be authoritative'
        }
    }

    Context 'Log-agnostic coverage guard' {
        It 'names whichever log it is reporting on' {
            Get-AdfaEventCoverageDetail -Coverage 'Truncated' -OldestRecord ([datetime]'2026-09-15 08:30') `
                -LookbackDays 14 -LogName 'DFS Replication' | Should -Match 'DFS Replication log only goes back'
            Get-AdfaEventCoverageDetail -Coverage 'Empty' -OldestRecord $null -LookbackDays 14 |
                Should -Match 'Directory Service log holds no records'
        }
    }
}

Describe 'SYSVOL backlog' {
    # Get-DfsrBacklog returns at most 100 records and the true total appears only in its verbose
    # stream, so counting the returned objects reports a FLOOR as a total once the backlog
    # reaches the cap. That is the defect these tests exist to prevent.
    Context 'Get-AdfaDfsrBacklogCount' {
        It 'prefers the verbose count over a capped object count' {
            $v = 'The replicated folder has a backlog of files. Replicated folder: "SYSVOL Share". Count: 2400'
            $r = Get-AdfaDfsrBacklogCount -VerboseMessage $v -ObjectCount 100 -DisplayCap 100
            [int]$r.Count | Should -Be 2400
            [bool]$r.Exact | Should -BeTrue
        }
        It 'marks an at-cap object count as NOT exact' {
            $r = Get-AdfaDfsrBacklogCount -VerboseMessage '' -ObjectCount 100 -DisplayCap 100
            [int]$r.Count | Should -Be 100
            [bool]$r.Exact | Should -BeFalse
        }
        It 'uses the object count below the cap, exactly' {
            $r = Get-AdfaDfsrBacklogCount -VerboseMessage '' -ObjectCount 7 -DisplayCap 100
            [int]$r.Count | Should -Be 7
            [bool]$r.Exact | Should -BeTrue
            [int](Get-AdfaDfsrBacklogCount -VerboseMessage '' -ObjectCount 0 -DisplayCap 100).Count | Should -Be 0
        }
        It 'returns -1 for a failed call rather than 0' {
            # Unmeasured and zero are different claims; conflating them would report a broken
            # measurement as a converged folder.
            [int](Get-AdfaDfsrBacklogCount -VerboseMessage '' -ObjectCount 0 -DisplayCap 100 -Succeeded $false).Count |
                Should -Be -1
        }
        It 'does not mistake an unrelated verbose line for a count' {
            [int](Get-AdfaDfsrBacklogCount -VerboseMessage 'Connected to partner over port 135. Count: 99' `
                    -ObjectCount 3 -DisplayCap 100).Count | Should -Be 3
        }
    }

    Context 'Get-AdfaSysvolBacklogVerdict' {
        It 'passes only on a measured zero' {
            [string](Get-AdfaSysvolBacklogVerdict -SourceDc 'dc1' -DestinationDc 'dc2' -Count 0 -Exact $true).Status |
                Should -Be 'Pass'
            [string](Get-AdfaSysvolBacklogVerdict -SourceDc 'dc1' -DestinationDc 'dc2' -Count -1 -Exact $true -Reason 'RPC failed').Status |
                Should -Be 'Not Assessed'
        }
        It 'escalates with size' {
            [string](Get-AdfaSysvolBacklogVerdict -SourceDc 'dc1' -DestinationDc 'dc2' -Count 5 -Exact $true -WarnAt 1 -FailAt 100).Status |
                Should -Be 'Warning'
            [string](Get-AdfaSysvolBacklogVerdict -SourceDc 'dc1' -DestinationDc 'dc2' -Count 100 -Exact $false -WarnAt 1 -FailAt 100).Status |
                Should -Be 'Fail'
        }
        It 'never presents a floor as a total' {
            $floor = (Get-AdfaSysvolBacklogVerdict -SourceDc 'dc1' -DestinationDc 'dc2' -Count 100 -Exact $false -WarnAt 1 -FailAt 100).Detail
            $floor | Should -Match 'at least 100'
            $floor | Should -Match 'floor, not a total'
            # Non-vacuity: the caveat is conditional, not always present.
            $exact = (Get-AdfaSysvolBacklogVerdict -SourceDc 'dc1' -DestinationDc 'dc2' -Count 100 -Exact $true -WarnAt 1 -FailAt 100).Detail
            $exact | Should -Not -Match 'at least'
            $exact | Should -Not -Match 'floor, not a total'
        }
        It 'does not overstate the vendor position on backlogs' {
            # Microsoft: a backlog "is not necessarily an indication of problems" and "indicates
            # latency". The tighter bar applied to SYSVOL is ours, and the finding says so.
            (Get-AdfaSysvolBacklogVerdict -SourceDc 'dc1' -DestinationDc 'dc2' -Count 5 -Exact $true).Detail |
                Should -Match 'indicates latency rather than a fault'
        }
        It 'names the direction measured' {
            (Get-AdfaSysvolBacklogVerdict -SourceDc 'dcA' -DestinationDc 'dcB' -Count 5 -Exact $true).Detail |
                Should -Match 'dcA -> dcB'
        }
    }
}

Describe 'Restore integrity' {
    BeforeAll {
        # In BeforeAll, not the Describe body: a Describe body runs during Pester's discovery
        # phase, so a function declared there is gone when It blocks execute.
        function Get-RiTestRow {
            param($Rows, [string]$Item)
            $m = @($Rows | Where-Object { [string]$_.Item -eq $Item })
            if ($m.Count -eq 0) { return $null }
            return $m[0]
        }
    }

    Context 'Get-AdfaUsnRollbackVerdict' {
        # Microsoft names this registry value as the fallback when Directory Service event 2095
        # "may be overwritten before [it is] observed" - which is the ransomware-recovery case
        # exactly, and the reason this is the one restore signal not tied to the event log.
        It 'reports the documented value 4 as a rollback' {
            Get-AdfaUsnRollbackVerdict -Readable $true -Present $true -Value 4 | Should -Be 'Rollback'
            Get-AdfaUsnRollbackVerdict -Readable $true -Present $true -Value '4' | Should -Be 'Rollback'
        }
        It 'reports an undocumented value as found rather than interpreting it' {
            Get-AdfaUsnRollbackVerdict -Readable $true -Present $true -Value 1 | Should -Be 'OtherValue'
        }
        It 'distinguishes an absent marker from an unreadable registry' {
            Get-AdfaUsnRollbackVerdict -Readable $true -Present $false -Value $null | Should -Be 'NoEvidence'
            Get-AdfaUsnRollbackVerdict -Readable $false -Present $null -Value $null | Should -Be 'Unknown'
            Get-AdfaUsnRollbackVerdict -Readable $true -Present $null -Value $null | Should -Be 'Unknown'
        }
        It 'never reports NoEvidence for any degraded input' {
            # Fail-open here would be the worst possible defect: a DC that could not be read
            # would be reported as carrying no evidence of a rollback.
            $degraded = @(
                (Get-AdfaUsnRollbackVerdict -Readable $false -Present $true -Value 4),
                (Get-AdfaUsnRollbackVerdict -Readable $false -Present $false -Value $null),
                (Get-AdfaUsnRollbackVerdict -Readable $true -Present $null -Value 4)
            )
            @($degraded).Count | Should -Be 3
            @($degraded | Where-Object { $_ -eq 'NoEvidence' }).Count | Should -Be 0
        }
    }

    Context 'Get-AdfaUsnRollbackDetail' {
        It 'states the quarantine effect and warns against clearing the marker' {
            $d = Get-AdfaUsnRollbackDetail -Verdict 'Rollback' -Value 4
            $d | Should -Match 'USN ROLLBACK'
            $d | Should -Match 'Net Logon is paused'
            $d | Should -Match 'Do NOT delete or edit'
            $d | Should -Match 'overwritten'
        }
        It 'says what an absent marker does not prove' {
            $d = Get-AdfaUsnRollbackDetail -Verdict 'NoEvidence' -Value $null
            $d | Should -Match 'operating-system installation only'
            $d | Should -Not -Match 'healthy'
        }
        It 'carries the cause when the registry could not be read' {
            Get-AdfaUsnRollbackDetail -Verdict 'Unknown' -Value $null -Reason 'Access is denied' |
                Should -Match 'Access is denied'
        }
    }

    Context 'Get-AdfaInvocationIdVerdict' {
        It 'fails when two DSAs share an invocationId' {
            # The one conclusion a single point-in-time read supports: a shared value means one
            # database was cloned from the other, because it is unique per instantiation.
            $v = Get-AdfaInvocationIdVerdict -DsaInventory @(
                [pscustomobject]@{ DnsHostName = 'dc1.contoso.com'; ServerDn = 'CN=DC1'; InvocationId = 'aaaa' },
                [pscustomobject]@{ DnsHostName = 'dc2.contoso.com'; ServerDn = 'CN=DC2'; InvocationId = 'aaaa' })
            $row = Get-RiTestRow $v 'Duplicate database instantiation (invocationId)'
            [string]$row.Status | Should -Be 'Fail'
            $row.Detail | Should -Match 'CLONED'
            $row.Detail | Should -Match 'dc1'
            $row.Detail | Should -Match 'dc2'
            Get-RiTestRow $v 'Database instantiation (invocationId)' | Should -BeNullOrEmpty
        }
        It 'passes on distinct values while stating what it cannot conclude' {
            $v = Get-AdfaInvocationIdVerdict -DsaInventory @(
                [pscustomobject]@{ DnsHostName = 'dc1.contoso.com'; ServerDn = 'CN=DC1'; InvocationId = 'aaaa' },
                [pscustomobject]@{ DnsHostName = 'dc2.contoso.com'; ServerDn = 'CN=DC2'; InvocationId = 'bbbb' })
            $row = Get-RiTestRow $v 'Database instantiation (invocationId)'
            [string]$row.Status | Should -Be 'Pass'
            # A rollback needs the value compared against a previous run; the pass must say so
            # rather than implying the check rules one out.
            $row.Detail | Should -Match 'cannot detect a rollback on its own'
            Get-RiTestRow $v 'No Such Item' | Should -BeNullOrEmpty   # non-vacuity
        }
        It 'emits the per-DC value as a baseline for a later comparison' {
            $v = Get-AdfaInvocationIdVerdict -DsaInventory @(
                [pscustomobject]@{ DnsHostName = 'dc1.contoso.com'; ServerDn = 'CN=DC1'; InvocationId = 'aaaa' })
            Get-RiTestRow $v 'invocationId of dc1.contoso.com' | Should -Not -BeNullOrEmpty
        }
        It 'reports an unreadable value and says the clone check is partial' {
            $v = Get-AdfaInvocationIdVerdict -DsaInventory @(
                [pscustomobject]@{ DnsHostName = 'dc1.contoso.com'; ServerDn = 'CN=DC1'; InvocationId = 'aaaa' },
                [pscustomobject]@{ DnsHostName = 'dc2.contoso.com'; ServerDn = 'CN=DC2'; InvocationId = '' })
            $row = Get-RiTestRow $v 'invocationId - not readable'
            [string]$row.Status | Should -Be 'Not Assessed'
            $row.Detail | Should -Match 'partial result, not a clean one'
        }
        It 'reports Not Assessed when nothing could be read' {
            [string](Get-RiTestRow (Get-AdfaInvocationIdVerdict -DsaInventory @()) `
                    'Database instantiation (invocationId)').Status | Should -Be 'Not Assessed'
        }
    }

    Context 'Post-restore dcdiag tests and VM-revert events' {
        It 'adds CheckSecurityError and VerifyEnterpriseReferences to the grid' {
            $src = Get-Content $script:Target -Raw
            $src | Should -Match "'CheckSecurityError'"
            $src | Should -Match "'VerifyEnterpriseReferences'"
        }
        It 'tracks the VM-revert events with vendor-sourced meanings' {
            $ids = @($script:Config.DsEventsOfInterest | ForEach-Object { [int]$_.Id })
            $ids | Should -Contain 2170
            $ids | Should -Contain 2181
            $e = @($script:Config.DsEventsOfInterest | Where-Object { [int]$_.Id -eq 2170 })[0]
            $e.Meaning | Should -Match 'snapshot'
            $e.Meaning | Should -Match 'not a supported procedure'
        }
    }

    Context 'Remediation' {
        It 'no longer advises the retired dcpromo command anywhere in the map' {
            # dcpromo /forceremoval is Windows 2000 / Server 2003 era. Every OS this tool
            # supports uses Uninstall-ADDSDomainController.
            @($script:RecommendationMap | Where-Object { [string]$_.Text -match 'dcpromo\s*/forceremoval' }).Count |
                Should -Be 0
            @($script:RecommendationMap).Count | Should -BeGreaterThan 10   # non-vacuity
            @($script:RecommendationMap | Where-Object { [string]$_.Text -match 'Uninstall-ADDSDomainController' }).Count |
                Should -BeGreaterOrEqual 2
        }
        It 'routes each restore-integrity finding to its own fix' {
            $dnw = Get-AdfaRecommendation -Section 'Restore Integrity' -Item 'USN rollback marker on dc1' `
                -Detail (Get-AdfaUsnRollbackDetail -Verdict 'Rollback' -Value 4)
            $dnw | Should -Match 'Do NOT delete or change'
            $clone = Get-AdfaRecommendation -Section 'Restore Integrity' -Item 'Duplicate database instantiation (invocationId)' `
                -Detail '2 DCs share invocationId aaaa - database was CLONED from the other'
            $clone | Should -Match 'Do not leave both in service'
            $clone | Should -Not -Match 'Dsa Not Writable'
        }
    }
}

Describe 'Replication convergence' {
    Context 'ConvertFrom-AdfaRepadminDelta' {
        It 'parses the unit-token forms repadmin emits' {
            ConvertFrom-AdfaRepadminDelta -Delta '04h:02m:16s' | Should -Be 242
            ConvertFrom-AdfaRepadminDelta -Delta '15m:30s' | Should -Be 15
            ConvertFrom-AdfaRepadminDelta -Delta '3d.04h:02m:16s' | Should -Be 4562
            ConvertFrom-AdfaRepadminDelta -Delta '>60 days' | Should -Be 86400
        }
        It 'returns null rather than zero for an unreadable delta' {
            # The classic version of this bug: "(unknown)" means the DSA has NO successful
            # replication to measure from, which is worse than a large number, not better.
            ConvertFrom-AdfaRepadminDelta -Delta '(unknown)' | Should -BeNullOrEmpty
            ConvertFrom-AdfaRepadminDelta -Delta '' | Should -BeNullOrEmpty
            ConvertFrom-AdfaRepadminDelta -Delta 'garbage' | Should -BeNullOrEmpty
        }
    }

    Context 'ConvertFrom-AdfaReplsummary' {
        BeforeAll {
            # Layout per the vendor's own sample output in the error-8418 article.
            $script:ReplsumFixture = @"
Replication Summary Start Time: 2026-09-22 00:00:00

Beginning data collection for replication summary, this may take a while:
  .....

Source DSA          largest delta    fails/total %%   error
 DC1                      15m:30s     0 /  10    0
 DC2                    (unknown)     5 /   5  100  (8524) The DSA operation is unable to proceed because of a DNS lookup failure.

Destination DSA     largest delta    fails/total %%   error
 DC1                      15m:30s     0 /  10    0
"@
        }
        It 'attributes rows to the source and destination tables' {
            $p = @(ConvertFrom-AdfaReplsummary -Text $script:ReplsumFixture)
            $p.Count | Should -Be 3
            @($p | Where-Object { $_.Direction -eq 'Source' }).Count | Should -Be 2
            @($p | Where-Object { $_.Direction -eq 'Destination' }).Count | Should -Be 1
        }
        It 'carries fails, total, delta and the error code' {
            $dc2 = @(ConvertFrom-AdfaReplsummary -Text $script:ReplsumFixture |
                    Where-Object { $_.Dsa -eq 'DC2' })[0]
            [int]$dc2.Fails | Should -Be 5
            [int]$dc2.Total | Should -Be 5
            $dc2.DeltaMinutes | Should -BeNullOrEmpty
            $dc2.ErrorText | Should -Match '8524'
        }
        It 'does not read banner lines as DSA rows' {
            @(ConvertFrom-AdfaReplsummary -Text $script:ReplsumFixture |
                Where-Object { $_.Dsa -match 'Replication|Beginning' }).Count | Should -Be 0
        }
        It 'returns nothing for unrecognised text, so the caller can fail closed' {
            # Localised, version-dependent console output with no CSV option: a parse miss will
            # happen eventually and must not be mistaken for "no problems found".
            @(ConvertFrom-AdfaReplsummary -Text 'not the output of anything').Count | Should -Be 0
            @(ConvertFrom-AdfaReplsummary -Text '').Count | Should -Be 0
        }
    }

    Context 'Get-AdfaReplsummaryVerdict' {
        It 'fails on any failures, and says so when every attempt fails' {
            [string](Get-AdfaReplsummaryVerdict -Direction 'Source' -Dsa 'DC3' -Delta '04h' `
                    -DeltaMinutes 240 -Fails 4 -Total 5).Status | Should -Be 'Fail'
            $all = Get-AdfaReplsummaryVerdict -Direction 'Source' -Dsa 'DC2' -Delta '(unknown)' `
                -DeltaMinutes $null -Fails 5 -Total 5
            [string]$all.Status | Should -Be 'Fail'
            $all.Detail | Should -Match 'EVERY replication attempt'
        }
        It 'treats no-failures-but-no-measurable-delta as unassessed, not a pass' {
            $u = Get-AdfaReplsummaryVerdict -Direction 'Source' -Dsa 'DC4' -Delta '(unknown)' `
                -DeltaMinutes $null -Fails 0 -Total 3
            [string]$u.Status | Should -Be 'Not Assessed'
            $u.Detail | Should -Match 'NOT a clean result'
        }
        It 'escalates on lag and does not pass our thresholds off as the vendors' {
            [string](Get-AdfaReplsummaryVerdict -Direction 'Source' -Dsa 'DC5' -Delta '30h' `
                    -DeltaMinutes 1800 -Fails 0 -Total 3 -WarnHours 24 -FailHours 168).Status |
                Should -Be 'Warning'
            $s = Get-AdfaReplsummaryVerdict -Direction 'Source' -Dsa 'DC6' -Delta '10d' `
                -DeltaMinutes 14400 -Fails 0 -Total 3 -WarnHours 24 -FailHours 168
            [string]$s.Status | Should -Be 'Fail'
            $s.Detail | Should -Match 'stopped converging rather than lagged'
            $s.Detail | Should -Match "tool's, not Microsoft's"
            $s.Detail | Should -Match 'tombstone lifetime'
        }
    }

    Context 'Get-AdfaReplicationLagVerdict' {
        BeforeAll { $script:LagNow = [datetime]'2026-09-22 00:00:00' }
        It 'fails a link with ZERO failures whose last success is weeks old' {
            # The gap this closes: the cross-check judged links on failure count alone, so a
            # silently stalled link - disabled connection object, KCC fault, partner no longer
            # contacted - reported clean because nothing was being attempted to fail.
            $s = Get-AdfaReplicationLagVerdict -Destination 'DC1' -Source 'DC2' `
                -NamingContext 'DC=contoso,DC=com' -LastSuccess '2026-09-01 00:00:00' `
                -Now $script:LagNow -WarnHours 24 -FailHours 168
            [string]$s.Status | Should -Be 'Fail'
            $s.Detail | Should -Match 'nothing is being attempted'
            $s.Detail | Should -Match 'DC=contoso,DC=com'
        }
        It 'passes a recent success and warns past the threshold' {
            [string](Get-AdfaReplicationLagVerdict -Destination 'DC1' -Source 'DC2' `
                    -LastSuccess '2026-09-21 23:00:00' -Now $script:LagNow).Status | Should -Be 'Pass'
            [string](Get-AdfaReplicationLagVerdict -Destination 'DC1' -Source 'DC2' `
                    -LastSuccess '2026-09-20 12:00:00' -Now $script:LagNow -WarnHours 24 -FailHours 168).Status |
                Should -Be 'Warning'
        }
        It 'never passes an unreadable or future timestamp' {
            $degraded = @(
                (Get-AdfaReplicationLagVerdict -Destination 'a' -Source 'b' -LastSuccess '' -Now $script:LagNow),
                (Get-AdfaReplicationLagVerdict -Destination 'a' -Source 'b' -LastSuccess 'garbage' -Now $script:LagNow),
                (Get-AdfaReplicationLagVerdict -Destination 'a' -Source 'b' -LastSuccess '2026-09-23 00:00:00' -Now $script:LagNow)
            )
            @($degraded).Count | Should -Be 3
            @($degraded | Where-Object { $_.Status -eq 'Pass' }).Count | Should -Be 0
            # A future timestamp is a clock problem, named as such rather than as convergence.
            $degraded[2].Detail | Should -Match 'clock skew'
        }
    }
}

Describe '_msdcs delegation, time hierarchy, per-site GC coverage' {
    BeforeAll {
        # Declared in BeforeAll, not the Describe body: a Describe body runs during Pester's
        # discovery phase, so a function declared there does not exist when It blocks execute.
        function Get-H8TestRow {
            param($Rows, [string]$Pattern)
            $m = @($Rows | Where-Object { [string]$_.Item -match $Pattern })
            if ($m.Count -eq 0) { return $null }
            return $m[0]
        }
        function New-H8TestDc {
            param([string]$Name, [string]$Site, $Gc, $Ro)
            return [pscustomobject]@{ HostName = $Name; Site = $Site; IsGlobalCatalog = $Gc; IsReadOnly = $Ro }
        }
        $script:H8Dcs = @('dc1.contoso.com', 'dc2.contoso.com')
        $script:H8Healthy = @(
            [pscustomobject]@{ Server = 'dc1.contoso.com'; SoaApex = @('_msdcs.contoso.com'); NsTargets = @('dc1.contoso.com', 'dc2.contoso.com'); GlueMissing = @(); GlueUnknown = @() }
            [pscustomobject]@{ Server = 'dc2.contoso.com'; SoaApex = @('_msdcs.contoso.com'); NsTargets = @('dc1.contoso.com'); GlueMissing = @(); GlueUnknown = @() }
        )
    }

    Context 'Get-AdfaDnsNameNormalised' {
        It 'folds case and strips the root dot so two spellings compare equal' {
            Get-AdfaDnsNameNormalised -Name 'DC1.Contoso.COM.' | Should -Be 'dc1.contoso.com'
        }
        It 'returns empty for null and whitespace rather than a literal' {
            Get-AdfaDnsNameNormalised -Name $null | Should -Be ''
            Get-AdfaDnsNameNormalised -Name '   ' | Should -Be ''
        }
    }

    Context 'Get-AdfaMsdcsZoneVerdict' {
        # Which zone answers an SOA query is the discriminator between a delegated _msdcs zone
        # and a plain subdomain of the parent - the state a hand-rebuilt DNS server is left in.
        It 'recognises its own apex as a delegated zone, whatever the spelling' {
            Get-AdfaMsdcsZoneVerdict -ZoneName '_msdcs.contoso.com' -ParentZone 'contoso.com' -SoaApex @('_msdcs.contoso.com') | Should -Be 'DelegatedZone'
            Get-AdfaMsdcsZoneVerdict -ZoneName '_msdcs.contoso.com' -ParentZone 'contoso.com' -SoaApex @('_MSDCS.CONTOSO.COM.') | Should -Be 'DelegatedZone'
        }
        It 'distinguishes the parent apex, a third zone and no answer' {
            Get-AdfaMsdcsZoneVerdict -ZoneName '_msdcs.contoso.com' -ParentZone 'contoso.com' -SoaApex @('contoso.com') | Should -Be 'NotDelegated'
            Get-AdfaMsdcsZoneVerdict -ZoneName '_msdcs.contoso.com' -ParentZone 'contoso.com' -SoaApex @('fabrikam.com') | Should -Be 'OtherApex'
            Get-AdfaMsdcsZoneVerdict -ZoneName '_msdcs.contoso.com' -ParentZone 'contoso.com' -SoaApex @() | Should -Be 'NoAnswer'
            Get-AdfaMsdcsZoneVerdict -ZoneName '_msdcs.contoso.com' -ParentZone 'contoso.com' -SoaApex @('', '  ') | Should -Be 'NoAnswer'
        }
        It 'genuinely separates its three declared apex cases' {
            $v = @('_msdcs.contoso.com', 'contoso.com', 'fabrikam.com') | ForEach-Object {
                Get-AdfaMsdcsZoneVerdict -ZoneName '_msdcs.contoso.com' -ParentZone 'contoso.com' -SoaApex @($_)
            }
            @($v).Count | Should -Be 3
            @($v | Sort-Object -Unique).Count | Should -Be 3
        }
    }

    Context 'Get-AdfaMsdcsDelegationVerdict' {
        It 'reports a healthy view as passing on every checked property' {
            $rows = @(Get-AdfaMsdcsDelegationVerdict -ForestRoot 'contoso.com' -Observations $script:H8Healthy -AdDcHosts $script:H8Dcs)
            @($rows).Count | Should -Be 4
            @($rows | Where-Object { $_.Status -ne 'Pass' }).Count | Should -Be 0
        }
        It 'fails a _msdcs that is only a subdomain of its parent, and names the parent' {
            $rows = @(Get-AdfaMsdcsDelegationVerdict -ForestRoot 'contoso.com' -AdDcHosts $script:H8Dcs -Observations @(
                    [pscustomobject]@{ Server = 'dc1.contoso.com'; SoaApex = @('contoso.com'); NsTargets = @('dc1.contoso.com'); GlueMissing = @(); GlueUnknown = @() }
                ))
            $r = Get-H8TestRow -Rows $rows -Pattern 'is not a delegated zone'
            $r | Should -Not -BeNullOrEmpty
            [string]$r.Status | Should -Be 'Fail'
            $r.Detail | Should -Match 'PARENT zone contoso\.com'
            # The Pass row must be withheld while any server disagrees.
            @($rows | Where-Object { $_.Item -match 'is a delegated zone' }).Count | Should -Be 0
        }
        It 'fails a delegation with no NS record at all' {
            $rows = @(Get-AdfaMsdcsDelegationVerdict -ForestRoot 'contoso.com' -AdDcHosts $script:H8Dcs -Observations @(
                    [pscustomobject]@{ Server = 'dc1.contoso.com'; SoaApex = @('_msdcs.contoso.com'); NsTargets = @(); GlueMissing = @(); GlueUnknown = @() }
                ))
            [string](Get-H8TestRow -Rows $rows -Pattern 'no NS records').Status | Should -Be 'Fail'
        }
        It 'fails an NS record with no glue, and names the target' {
            $rows = @(Get-AdfaMsdcsDelegationVerdict -ForestRoot 'contoso.com' -AdDcHosts $script:H8Dcs -Observations @(
                    [pscustomobject]@{ Server = 'dc1.contoso.com'; SoaApex = @('_msdcs.contoso.com'); NsTargets = @('dc2.contoso.com'); GlueMissing = @('dc2.contoso.com'); GlueUnknown = @() }
                ))
            $r = Get-H8TestRow -Rows $rows -Pattern 'missing glue'
            [string]$r.Status | Should -Be 'Fail'
            $r.Detail | Should -Match 'dc2\.contoso\.com'
            @($rows | Where-Object { $_.Item -match 'glue records resolvable' }).Count | Should -Be 0
        }
        It 'treats glue it could not query as unknown, never as missing' {
            # The distinction the whole tool rests on: absence and silence are different claims.
            $rows = @(Get-AdfaMsdcsDelegationVerdict -ForestRoot 'contoso.com' -AdDcHosts $script:H8Dcs -Observations @(
                    [pscustomobject]@{ Server = 'dc1.contoso.com'; SoaApex = @('_msdcs.contoso.com'); NsTargets = @('dc2.contoso.com'); GlueMissing = @(); GlueUnknown = @('dc2.contoso.com') }
                ))
            [string](Get-H8TestRow -Rows $rows -Pattern 'glue not readable').Status | Should -Be 'Not Assessed'
            @($rows | Where-Object { $_.Item -match 'glue records resolvable' }).Count | Should -Be 0
        }
        It 'warns - not fails - on an NS host that is not a known DC' {
            # A non-DC DNS server can legitimately be authoritative, so this names what to
            # confirm rather than asserting a fault.
            $rows = @(Get-AdfaMsdcsDelegationVerdict -ForestRoot 'contoso.com' -AdDcHosts $script:H8Dcs -Observations @(
                    [pscustomobject]@{ Server = 'dc1.contoso.com'; SoaApex = @('_msdcs.contoso.com'); NsTargets = @('dc1.contoso.com', 'oldDC.contoso.com'); GlueMissing = @(); GlueUnknown = @() }
                ))
            $r = Get-H8TestRow -Rows $rows -Pattern 'not a known DC'
            [string]$r.Status | Should -Be 'Warning'
            $r.Detail | Should -Match 'oldDC\.contoso\.com'
        }
        It 'says so when it had no inventory to cross-check the NS hosts against' {
            $rows = @(Get-AdfaMsdcsDelegationVerdict -ForestRoot 'contoso.com' -AdDcHosts @() -Observations $script:H8Healthy)
            [string](Get-H8TestRow -Rows $rows -Pattern 'not cross-checked').Status | Should -Be 'Not Assessed'
        }
        It 'never passes when no DNS server answered' {
            $rows = @(Get-AdfaMsdcsDelegationVerdict -ForestRoot 'contoso.com' -Observations @() -AdDcHosts $script:H8Dcs -Unanswered @('dc1.contoso.com'))
            @($rows).Count | Should -Be 1
            [string]$rows[0].Status | Should -Be 'Not Assessed'
            $rows[0].Detail | Should -Match 'dc1\.contoso\.com'
        }
    }

    Context 'ConvertFrom-AdfaW32tmConfiguration' {
        # The key names are published; the line format of this command's output is not. So the
        # parser is tolerant, and an unmatched key returns '' - which a caller must read as
        # "not read", never as a value.
        It 'reads Type and NtpServer and strips the source annotation' {
            $cfg = ConvertFrom-AdfaW32tmConfiguration -Text "NtpClient (Local)`nType: NTP (Local)`nNtpServer: ntp.example.test,0x8 (Local)"
            $cfg.Type | Should -Be 'NTP'
            $cfg.NtpServer | Should -Be 'ntp.example.test,0x8'
        }
        It 'tolerates leading whitespace and a (Policy) annotation' {
            (ConvertFrom-AdfaW32tmConfiguration -Text '  Type: NT5DS (Policy)').Type | Should -Be 'NT5DS'
        }
        It 'returns empty rather than a guess when the output is not recognised' {
            (ConvertFrom-AdfaW32tmConfiguration -Text 'The following error occurred: Access is denied.').Type | Should -Be ''
            (ConvertFrom-AdfaW32tmConfiguration -Text $null).Type | Should -Be ''
        }
    }

    Context 'Get-AdfaTimeSourceVerdict' {
        It 'never concludes anything from a source it could not read' {
            $u = Get-AdfaTimeSourceVerdict -DomainController 'dc1.contoso.com' -Queried $false -ErrorText 'RPC (135) was not reachable' -DomainControllerHosts $script:H8Dcs
            [string]$u.Status | Should -Be 'Not Assessed'
            # Says why a denial is about rights, not about the clock.
            $u.Detail | Should -Match 'Domain Admins'
            [string](Get-AdfaTimeSourceVerdict -DomainController 'dc1.contoso.com' -Source '   ' -DomainControllerHosts $script:H8Dcs).Status | Should -Be 'Not Assessed'
        }
        It 'warns on host time sync on a member DC and names the documented consequence' {
            $v = Get-AdfaTimeSourceVerdict -DomainController 'dc2.contoso.com' -Source 'VM IC Time Synchronization Provider' -DomainControllerHosts $script:H8Dcs
            [string]$v.Status | Should -Be 'Warning'
            $v.Detail | Should -Match 'lingering objects'
            $v.Detail | Should -Match 'Integration Services'
        }
        It 'states that vendor guidance diverges for the root PDC rather than picking a side' {
            $v = Get-AdfaTimeSourceVerdict -DomainController 'dc1.contoso.com' -IsPdcEmulator $true -IsForestRootPdc $true `
                -Source 'VM IC Time Synchronization Provider' -DomainControllerHosts $script:H8Dcs
            [string]$v.Status | Should -Be 'Warning'
            $v.Detail | Should -Match 'guidance is split'
            $v.Detail | Should -Match 'KB 976924'
            $v.Detail | Should -Match 'Windows Server 2016'
        }
        It 'warns on a free-running clock, and says the forest has no upstream on the root PDC' {
            $root = Get-AdfaTimeSourceVerdict -DomainController 'dc1.contoso.com' -IsPdcEmulator $true -IsForestRootPdc $true `
                -Source 'Local CMOS Clock' -DomainControllerHosts $script:H8Dcs
            [string]$root.Status | Should -Be 'Warning'
            $root.Detail | Should -Match 'NO authoritative upstream'
            [string](Get-AdfaTimeSourceVerdict -DomainController 'dc2.contoso.com' -Source 'Free-running System Clock' -DomainControllerHosts $script:H8Dcs).Status |
                Should -Be 'Warning'
        }
        It 'warns when the root PDC takes time from the hierarchy it is the top of' {
            $v = Get-AdfaTimeSourceVerdict -DomainController 'dc1.contoso.com' -IsPdcEmulator $true -IsForestRootPdc $true `
                -Source 'dc2.contoso.com' -DomainControllerHosts $script:H8Dcs
            [string]$v.Status | Should -Be 'Warning'
            $v.Detail | Should -Match 'event ID 12'
        }
        It 'passes an external source on the root PDC, and says what it did not check' {
            $v = Get-AdfaTimeSourceVerdict -DomainController 'dc1.contoso.com' -IsPdcEmulator $true -IsForestRootPdc $true `
                -Source 'ntp.example.test' -DomainControllerHosts $script:H8Dcs
            [string]$v.Status | Should -Be 'Pass'
            $v.Detail | Should -Match 'does not verify'
        }
        It 'will not judge the root PDC external-vs-internal with no inventory to compare against' {
            [string](Get-AdfaTimeSourceVerdict -DomainController 'dc1.contoso.com' -IsForestRootPdc $true `
                    -Source 'ntp.example.test' -DomainControllerHosts @()).Status | Should -Be 'Not Assessed'
        }
        It 'passes a member DC on the domain hierarchy and flags an external source as Info' {
            [string](Get-AdfaTimeSourceVerdict -DomainController 'dc2.contoso.com' -Source 'DC1.CONTOSO.COM' -DomainControllerHosts $script:H8Dcs).Status |
                Should -Be 'Pass'
            [string](Get-AdfaTimeSourceVerdict -DomainController 'dc2.contoso.com' -Source 'ntp.example.test' -DomainControllerHosts $script:H8Dcs).Status |
                Should -Be 'Info'
        }
        It 'never passes any degraded source' {
            $degraded = @(
                (Get-AdfaTimeSourceVerdict -DomainController 'a' -Queried $false -DomainControllerHosts $script:H8Dcs),
                (Get-AdfaTimeSourceVerdict -DomainController 'a' -Source 'VM IC Time Synchronization Provider' -DomainControllerHosts $script:H8Dcs),
                (Get-AdfaTimeSourceVerdict -DomainController 'a' -Source 'Local CMOS Clock' -DomainControllerHosts $script:H8Dcs),
                (Get-AdfaTimeSourceVerdict -DomainController 'a' -IsForestRootPdc $true -Source 'dc2.contoso.com' -DomainControllerHosts $script:H8Dcs)
            )
            @($degraded).Count | Should -Be 4
            @($degraded | Where-Object { $_.Status -eq 'Pass' }).Count | Should -Be 0
        }
    }

    Context 'Get-AdfaRootPdcClientTypeVerdict' {
        It 'warns on NT5DS and cites the event the vendor logs for it' {
            $v = Get-AdfaRootPdcClientTypeVerdict -DomainController 'dc1.contoso.com' -ClientType 'NT5DS'
            [string]$v.Status | Should -Be 'Warning'
            $v.Detail | Should -Match 'event ID 12'
        }
        It 'warns on NoSync' {
            [string](Get-AdfaRootPdcClientTypeVerdict -DomainController 'dc1.contoso.com' -ClientType 'NoSync').Status | Should -Be 'Warning'
        }
        It 'passes an external type only when a peer list was actually read' {
            [string](Get-AdfaRootPdcClientTypeVerdict -DomainController 'dc1.contoso.com' -ClientType 'NTP' -NtpServer 'ntp.example.test,0x8').Status | Should -Be 'Pass'
            [string](Get-AdfaRootPdcClientTypeVerdict -DomainController 'dc1.contoso.com' -ClientType 'AllSync' -NtpServer 'ntp.example.test,0x8').Status | Should -Be 'Pass'
            [string](Get-AdfaRootPdcClientTypeVerdict -DomainController 'dc1.contoso.com' -ClientType 'NTP').Status | Should -Be 'Not Assessed'
        }
        It 'never passes an unread or undocumented type' {
            $degraded = @('', 'Something', 'NT5DS', 'NoSync') | ForEach-Object {
                Get-AdfaRootPdcClientTypeVerdict -DomainController 'dc1.contoso.com' -ClientType $_
            }
            @($degraded).Count | Should -Be 4
            @($degraded | Where-Object { $_.Status -eq 'Pass' }).Count | Should -Be 0
        }
    }

    Context 'Get-AdfaSiteGcCoverage' {
        It 'passes a site holding a writeable global catalog and names its population' {
            $rows = @(Get-AdfaSiteGcCoverage -DomainControllers @((New-H8TestDc 'dc1.contoso.com' 'HQ' $true $false)))
            @($rows).Count | Should -Be 1
            [string]$rows[0].Status | Should -Be 'Pass'
            $rows[0].Detail | Should -Match '1 of 1 site'
        }
        It 'does not accept a read-only GC as covering a site' {
            $rows = @(Get-AdfaSiteGcCoverage -DomainControllers @((New-H8TestDc 'rodc1.contoso.com' 'Branch' $true $true)))
            $r = Get-H8TestRow -Rows $rows -Pattern "Site 'Branch'"
            [string]$r.Status | Should -Be 'Warning'
            $r.Detail | Should -Match 'read-only GC: rodc1\.contoso\.com'
            $r.Detail | Should -Match 'read-only directory servers'
            @($rows | Where-Object { $_.Status -eq 'Pass' }).Count | Should -Be 0
        }
        It 'does not accept a writeable non-GC as covering a site' {
            $r = Get-H8TestRow -Rows @(Get-AdfaSiteGcCoverage -DomainControllers @((New-H8TestDc 'dc9.contoso.com' 'Branch' $false $false))) -Pattern "Site 'Branch'"
            [string]$r.Status | Should -Be 'Warning'
            $r.Detail | Should -Match 'writeable but not a GC'
        }
        It 'reports a covered and an uncovered site in the same run' {
            $rows = @(Get-AdfaSiteGcCoverage -DomainControllers @(
                    (New-H8TestDc 'dc1.contoso.com' 'HQ' $true $false),
                    (New-H8TestDc 'rodc1.contoso.com' 'Branch' $true $true)
                ))
            @($rows | Where-Object { $_.Status -eq 'Warning' }).Count | Should -Be 1
            $pass = @($rows | Where-Object { $_.Status -eq 'Pass' })
            @($pass).Count | Should -Be 1
            $pass[0].Detail | Should -Match '1 of 2 site'
        }
        It 'makes a site unknown, not uncovered, when the flags could not be read' {
            [string](Get-H8TestRow -Rows @(Get-AdfaSiteGcCoverage -DomainControllers @((New-H8TestDc 'dc5.contoso.com' 'Branch' $null $null))) -Pattern 'not readable').Status |
                Should -Be 'Not Assessed'
            # A non-boolean value (the inventory writes 'Not Assessed' when enrichment fails)
            # must not be coerced to $false.
            $r = Get-H8TestRow -Rows @(Get-AdfaSiteGcCoverage -DomainControllers @((New-H8TestDc 'dc6.contoso.com' 'Branch' 'Not Assessed' $false))) -Pattern 'not readable'
            $r | Should -Not -BeNullOrEmpty
            [string]$r.Status | Should -Be 'Not Assessed'
        }
        It 'reports a DC with no site rather than dropping it from the count' {
            [string](Get-H8TestRow -Rows @(Get-AdfaSiteGcCoverage -DomainControllers @((New-H8TestDc 'dc7.contoso.com' '' $true $false))) -Pattern 'no site').Status |
                Should -Be 'Not Assessed'
        }
        It 'never passes an empty or degraded inventory' {
            $empty = @(Get-AdfaSiteGcCoverage -DomainControllers @())
            @($empty).Count | Should -Be 1
            [string]$empty[0].Status | Should -Be 'Not Assessed'
            $degraded = @(
                @(Get-AdfaSiteGcCoverage -DomainControllers @((New-H8TestDc 'rodc1.contoso.com' 'Branch' $true $true))),
                @(Get-AdfaSiteGcCoverage -DomainControllers @((New-H8TestDc 'dc5.contoso.com' 'Branch' $null $null))),
                @(Get-AdfaSiteGcCoverage -DomainControllers @((New-H8TestDc 'dc7.contoso.com' '' $true $false))),
                $empty
            )
            @($degraded).Count | Should -Be 4
            @($degraded | ForEach-Object { $_ } | Where-Object { $_.Status -eq 'Pass' }).Count | Should -Be 0
        }
    }

    Context 'Versioned configuration' {
        It 'holds the volatile vendor strings as data, with their source recorded' {
            [string]$script:Config.MsdcsZoneLabel | Should -Be '_msdcs'
            [string]$script:Config.Time.DomainHierarchyType | Should -Be 'NT5DS'
            @($script:Config.Time.ExternalTypes) | Should -Contain 'NTP'
            @($script:Config.Time.ExternalTypes) | Should -Contain 'AllSync'
            $script:Config.Time.RootPdcUrl | Should -Match '^https://learn\.microsoft\.com/'
            $script:Config.Time.HypervisorUrl | Should -Match '^https://learn\.microsoft\.com/'
            [string]$script:Config.Time.ReadDate | Should -Be '2026-09-22'
        }
        It 'matches the published source strings without matching an ordinary host name' {
            'VM IC Time Synchronization Provider' | Should -Match $script:Config.Time.HypervisorPattern
            'Local CMOS Clock' | Should -Match $script:Config.Time.LocalClockPattern
            'dc1.contoso.com' | Should -Not -Match $script:Config.Time.LocalClockPattern
        }
    }

    Context 'Remediation routing' {
        It 'routes each new section to its own guidance and is not hijacked by the generic entries' {
            $msdcs = Get-AdfaRecommendation -Section '_msdcs Zone Delegation' -Item '_msdcs.contoso.com is not a delegated zone' -Detail 'answered by the PARENT zone contoso.com'
            $msdcs | Should -Match 'New Delegation'
            $msdcs | Should -Not -Match 'scavenging'
            Get-AdfaRecommendation -Section '_msdcs Zone Delegation' -Item '_msdcs.contoso.com delegation - missing glue records' -Detail 'no resolvable glue (A) record' |
                Should -Match 'glue host'
            Get-AdfaRecommendation -Section '_msdcs Zone Delegation' -Item '_msdcs.contoso.com delegation - NS host not a known DC' -Detail 'not domain controllers' |
                Should -Match 'dsderegdns'
            Get-AdfaRecommendation -Section 'Time Hierarchy' -Item 'Time source on dc2.contoso.com (domain controller)' -Detail "Source is the virtualisation host's time provider" |
                Should -Match 'VMICTimeProvider'
            $rootTime = Get-AdfaRecommendation -Section 'Time Hierarchy' -Item 'Time source on dc1.contoso.com (FOREST ROOT PDC emulator)' -Detail 'so the forest has NO authoritative upstream time'
            $rootTime | Should -Match 'manualpeerlist'
            $rootTime | Should -Match 'five minutes'
            Get-AdfaRecommendation -Section 'Site Global Catalog Coverage' -Item "Site 'Branch' has no writeable global catalog" -Detail 'read-only GC: rodc1.contoso.com' |
                Should -Match '\+IS_GC'
        }
    }

    Context 'Section wiring' {
        It 'declares the three new sections in the Sections ValidateSet' {
            # A function with no ValidateSet entry can never be selected, and a ValidateSet entry
            # with no branch in Invoke-Main silently produces no section at all.
            $ast = [System.Management.Automation.Language.Parser]::ParseFile($script:Target, [ref]$null, [ref]$null)
            $text = $ast.Extent.Text
            foreach ($s in @('MsdcsDelegation', 'TimeHierarchy', 'SiteGc')) {
                $text | Should -Match ("'{0}'" -f $s)
                $text | Should -Match ("Test-SectionSelected '{0}'" -f $s)
            }
        }
    }

    Context 'Resolve-AdfaDnsRecord record types' {
        It 'accepts every record type these checks need' {
            $set = @((Get-Command Resolve-AdfaDnsRecord).Parameters['Type'].Attributes |
                    Where-Object { $_ -is [System.Management.Automation.ValidateSetAttribute] } |
                    Select-Object -First 1).ValidValues
            foreach ($t in @('SRV', 'CNAME', 'NS', 'A', 'SOA')) { @($set) | Should -Contain $t }
        }
        It 'parses NS and A from the nslookup fallback, and refuses SOA' {
            # Must run with nslookup PRESENT and Resolve-DnsName ABSENT, or the SOA assertion is
            # vacuous: with no tool at all every type returns NoTool and the guard is never hit.
            Mock Test-CommandAvailable { return ($Name -eq 'nslookup.exe') }
            Mock Invoke-ExternalCommand {
                $out = ''
                if ($Arguments -match 'type=NS') {
                    $out = "Server:  ns1.contoso.com`r`nAddress:  192.0.2.10`r`n`r`n_msdcs.contoso.com`tnameserver = dc1.contoso.com`r`n_msdcs.contoso.com`tnameserver = dc2.contoso.com`r`n"
                }
                elseif ($Arguments -match 'type=A') {
                    $out = "Server:  ns1.contoso.com`r`nAddress:  192.0.2.10`r`n`r`nName:    dc1.contoso.com`r`nAddress:  192.0.2.11`r`n"
                }
                [pscustomobject]@{ Success = $true; ExitCode = 0; Attempt = 1; Error = $null; OutFile = $null; StdOut = $out }
            }
            $ns = Resolve-AdfaDnsRecord -Name '_msdcs.contoso.com' -Type NS
            [string]$ns.Outcome | Should -Be 'Resolved'
            @($ns.Targets).Count | Should -Be 2
            @($ns.Targets) | Should -Contain 'dc1.contoso.com'
            # The header Address line is the DNS server's own address, never the record's glue.
            $a = Resolve-AdfaDnsRecord -Name 'dc1.contoso.com' -Type A
            @($a.Targets).Count | Should -Be 1
            [string]@($a.Targets)[0] | Should -Be '192.0.2.11'
            [string](Resolve-AdfaDnsRecord -Name '_msdcs.contoso.com' -Type SOA).Outcome | Should -Be 'NoTool'
        }
    }
}
