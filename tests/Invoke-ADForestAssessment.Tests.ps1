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
        (Test-AdfaSecureChannel -SourceDomain a -TargetDomain b -LiveVerify).Result | Should -Be 'Verified'
    }
    It 'parses an nltest error status as Failed' {
        Mock Test-CommandAvailable { $true }
        Mock Invoke-ExternalCommand { [pscustomobject]@{ Success = $false; ExitCode = 1; StdOut = 'Trust Verification Status = 0x35 ERROR' } }
        (Test-AdfaSecureChannel -SourceDomain a -TargetDomain b -LiveVerify).Result | Should -Be 'Failed'
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
            $r.Detail | Should -Match "nltest /sc_query:ours\.example"
            $r.Detail | Should -Match 'partner\.example'
        }
        It 'parses NERR_Success from the partner DC as Verified' {
            Mock Test-TcpPort { $true }
            Mock Invoke-Command { 'Trust Verification Status = 0x0 NERR_Success' }
            (Test-AdfaRemoteSecureChannel -PartnerDomain 'partner.example' -VerifyDomain 'ours.example' -PartnerDc 'dc1.partner.example' -LiveVerify).Result | Should -Be 'Verified'
        }
        It 'parses an error status from the partner DC as Failed, never Verified' {
            Mock Test-TcpPort { $true }
            Mock Invoke-Command { 'Trust Verification Status = 0xc0000022 STATUS_ACCESS_DENIED' }
            (Test-AdfaRemoteSecureChannel -PartnerDomain 'partner.example' -VerifyDomain 'ours.example' -PartnerDc 'dc1.partner.example' -LiveVerify).Result | Should -Be 'Failed'
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
        $agg = foreach ($d in @('root.local', 'north.local', 'south.local')) { Get-AdfaFakeSection -DomainName $d }
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
            foreach ($m in @(@{ Mode = 'Windows2016Forest'; Level = '7' }, @{ Mode = 'Windows2012R2Forest'; Level = '6' })) {
                $r = Get-AdfaExchangeSeCompatibility -ForestMode $m.Mode -ForestLevel $m.Level -DomainSummaries @() `
                    -DomainControllers $script:DcOk -SeConfig $script:SeCfg
                [string](Get-SeTestRow $r 'Forest functional level').Status | Should -Be 'Pass' -Because "$($m.Mode) is supported"
            }
            $bad = Get-AdfaExchangeSeCompatibility -ForestMode 'Windows2008R2Forest' -ForestLevel '4' -DomainSummaries @() `
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

    Context 'Forest functional level is decided from the numeric level, not the mode name (H17)' {
        # Before H17 the verdict was `$supportedModes -contains $ForestMode`: anything outside
        # the list was "raise the forest functional level". A Windows Server 2025 level forest
        # is ABOVE the supported levels, so that advice pointed the wrong way.
        BeforeAll {
            function Get-FflRow {
                param([string]$Level, [string]$Mode = '', [string]$LevelError = '')
                $r = Get-AdfaExchangeSeCompatibility -ForestMode $Mode -ForestLevel $Level -ForestLevelError $LevelError `
                    -DomainSummaries @() -DomainControllers $script:DcOk -SeConfig $script:SeCfg
                return (Get-SeTestRow $r 'Forest functional level')
            }
        }
        It 'passes a Windows Server 2012 R2 level forest (msDS-Behavior-Version 6)' {
            $row = Get-FflRow -Level '6' -Mode 'Windows2012R2Forest'
            [string]$row.Status | Should -Be 'Pass'
            $row.Detail | Should -Match 'Windows Server 2012 R2'
        }
        It 'passes a Windows Server 2016 level forest (msDS-Behavior-Version 7)' {
            $row = Get-FflRow -Level '7' -Mode 'Windows2016Forest'
            [string]$row.Status | Should -Be 'Pass'
            $row.Detail | Should -Match 'Windows Server 2016'
        }
        It 'fails a Windows Server 2025 level forest as NOT LISTED, and does not tell anyone to raise it' {
            $row = Get-FflRow -Level '10' -Mode 'Windows2025Forest'
            [string]$row.Status | Should -Be 'Fail'
            $row.Detail | Should -Match 'Windows Server 2025'
            $row.Detail | Should -Match 'not listed in the supportability matrix'
            $row.Detail | Should -Match 'learn\.microsoft\.com/exchange/plan-and-deploy/supportability-matrix'
            $row.Detail | Should -Not -Match '(?i)is raised|Set-ADForestMode'
            # No remediation command for a level above the matrix: the map must return nothing.
            Get-AdfaRecommendation -Section 'Exchange SE Compatibility' -Item ([string]$row.Item) -Detail ([string]$row.Detail) |
                Should -BeNullOrEmpty
        }
        It 'gives an above-the-list forest no advice even when the override path contains a word other advice matches' {
            # Under an override the finding cites the FILE PATH. 'Backup' in that path would
            # otherwise match the unscoped backup entry and attach unrelated advice.
            $narrow = Merge-AdfaExchangeSeConfig -BaseConfig $script:SeCfg `
                -Override @{ SupportedForestModes = @('Windows2012R2Forest') } -OverrideSource 'C:\Scripts\Backup\se.json'
            $r = Get-AdfaExchangeSeCompatibility -ForestMode 'Windows2016Forest' -ForestLevel '7' -DomainSummaries @() `
                -DomainControllers $script:DcOk -SeConfig $narrow
            $row = Get-SeTestRow $r 'Forest functional level'
            [string]$row.Status | Should -Be 'Fail'
            # Non-vacuity: without the scoped empty entry this exact text DOES attract advice.
            Get-AdfaRecommendation -Section 'Some Other Section' -Item 'x' -Detail ([string]$row.Detail) | Should -Not -BeNullOrEmpty
            Get-AdfaRecommendation -Section 'Exchange SE Compatibility' -Item ([string]$row.Item) -Detail ([string]$row.Detail) |
                Should -BeNullOrEmpty
            # The real matrix lists Windows Server 2016, so the override's verdict must not be
            # attributed to Microsoft.
            $row.Detail | Should -Not -Match 'supportability matrix'
            $row.Detail | Should -Match 'the supplied config table'
        }
        It 'does not name a target mode in the raise advice, because the supported set can be overridden' {
            $only2025 = Merge-AdfaExchangeSeConfig -BaseConfig $script:SeCfg -Override @{ SupportedForestModes = @('Windows2025Forest') }
            $r = Get-AdfaExchangeSeCompatibility -ForestMode 'Windows2016Forest' -ForestLevel '7' -DomainSummaries @() `
                -DomainControllers $script:DcOk -SeConfig $only2025
            $row = Get-SeTestRow $r 'Forest functional level'
            [string]$row.Status | Should -Be 'Fail'
            $row.Detail | Should -Match 'Supported: Windows2025Forest'
            $rec = Get-AdfaRecommendation -Section 'Exchange SE Compatibility' -Item ([string]$row.Item) -Detail ([string]$row.Detail)
            $rec | Should -Match 'Set-ADForestMode'
            $rec | Should -Not -Match 'Windows2016Forest'   # would be "raise to where you already are"
        }
        It 'reports Not Assessed, not Fail, when no supported mode resolves to a level' {
            # Not reachable through Merge-AdfaExchangeSeConfig, which refuses such a config. The
            # verdict function is pure and takes any table, so it must not turn a broken table
            # into "every forest fails".
            $broken = @{} + $script:SeCfg
            $broken['SupportedForestModes'] = @('Windows2099Forest')
            $r = Get-AdfaExchangeSeCompatibility -ForestMode 'Windows2016Forest' -ForestLevel '7' -DomainSummaries @() `
                -DomainControllers $script:DcOk -SeConfig $broken
            $row = Get-SeTestRow $r 'Forest functional level'
            [string]$row.Status | Should -Be 'Not Assessed'
            $row.Detail | Should -Match 'Windows2099Forest'
        }
        It 'takes the direction from the number even when the mode name disagrees or is unknown' {
            # An older ActiveDirectory module may not know the newest level's name. What it
            # prints for such a forest is not published, so the name must not decide anything.
            foreach ($name in @('UnknownForest', 'Windows2016Forest', '')) {
                [string](Get-FflRow -Level '10' -Mode $name).Detail | Should -Match 'not listed in the supportability matrix' -Because "name '$name' must not override level 10"
            }
            $low = Get-FflRow -Level '4' -Mode 'Windows2016Forest'
            [string]$low.Status | Should -Be 'Fail'
            $low.Detail | Should -Match 'until the forest functional level is raised'
        }
        It 'keeps the raise wording and the raise advice for a level below the supported ones' {
            $row = Get-FflRow -Level '4' -Mode 'Windows2008R2Forest'
            [string]$row.Status | Should -Be 'Fail'
            $row.Detail | Should -Match 'Windows Server 2008 R2'
            $row.Detail | Should -Match 'Windows2016Forest'   # names what IS supported
            $row.Detail | Should -Match 'until the forest functional level is raised'
            Get-AdfaRecommendation -Section 'Exchange SE Compatibility' -Item ([string]$row.Item) -Detail ([string]$row.Detail) |
                Should -Match 'Set-ADForestMode'
        }
        It 'reports Not Assessed with the cause when the level could not be read' {
            $row = Get-FflRow -Level '' -Mode 'Windows2016Forest' -LevelError 'Access is denied'
            [string]$row.Status | Should -Be 'Not Assessed'
            $row.Detail | Should -Match 'Access is denied'
            # The mode name alone must never produce a verdict.
            [string](Get-FflRow -Level '' -Mode 'Windows2016Forest').Status | Should -Be 'Not Assessed'
        }
        It 'reports Not Assessed showing the raw value when the level is not recognised' {
            foreach ($raw in @('9', '11', '-1', 'abc', '7.5')) {
                $row = Get-FflRow -Level $raw -Mode 'Windows2016Forest'
                [string]$row.Status | Should -Be 'Not Assessed' -Because "'$raw' is not a known functional level"
                $row.Detail | Should -Match ([regex]::Escape("'$raw'"))
            }
        }
    }

    Context 'Get-AdfaForestLevelClass' {
        BeforeAll {
            $script:Known = @(0, 1, 2, 3, 4, 5, 6, 7, 10)
            $script:Supp = @(6, 7)
        }
        It 'classifies each level against the supported set' {
            Get-AdfaForestLevelClass -RawLevel '6' -KnownLevels $script:Known -SupportedLevels $script:Supp | Should -Be 'Supported'
            Get-AdfaForestLevelClass -RawLevel '7' -KnownLevels $script:Known -SupportedLevels $script:Supp | Should -Be 'Supported'
            Get-AdfaForestLevelClass -RawLevel '4' -KnownLevels $script:Known -SupportedLevels $script:Supp | Should -Be 'Below'
            Get-AdfaForestLevelClass -RawLevel '0' -KnownLevels $script:Known -SupportedLevels $script:Supp | Should -Be 'Below'
            Get-AdfaForestLevelClass -RawLevel '10' -KnownLevels $script:Known -SupportedLevels $script:Supp | Should -Be 'Above'
        }
        It 'treats a known level in a gap between supported levels as Below, never Above' {
            # Reachable only with an override (say 2016 + 2012, levels 7 and 5). Level 6 can be
            # raised to a supported level, so the raise advice is true; Above would be false.
            Get-AdfaForestLevelClass -RawLevel '6' -KnownLevels $script:Known -SupportedLevels @(5, 7) | Should -Be 'Below'
        }
        It 'never returns Supported or Above against an empty supported set' {
            Get-AdfaForestLevelClass -RawLevel '7' -KnownLevels $script:Known -SupportedLevels @() | Should -Be 'Below'
        }
        It 'fails closed on an absent or unrecognised value' {
            foreach ($raw in @($null, '', '   ')) {
                Get-AdfaForestLevelClass -RawLevel $raw -KnownLevels $script:Known -SupportedLevels $script:Supp | Should -Be 'Unreadable'
            }
            foreach ($raw in @('9', '11', '-1', 'abc', '7.5')) {
                Get-AdfaForestLevelClass -RawLevel $raw -KnownLevels $script:Known -SupportedLevels $script:Supp |
                    Should -Be 'Unrecognised' -Because "'$raw' is not a known functional level"
            }
        }
    }

    Context 'Get-AdfaForestBehaviorVersion (collector)' {
        BeforeAll {
            $script:FakeForest = [pscustomobject]@{ Name = 'contoso.com'; PartitionsContainer = 'CN=Partitions,CN=Configuration,DC=contoso,DC=com' }
        }
        It 'returns the raw attribute value from the Partitions container' {
            function Get-ADObject {
                param([string]$Identity, [string[]]$Properties, [Parameter(ValueFromRemainingArguments)]$a)
                if ($Identity -ne 'CN=Partitions,CN=Configuration,DC=contoso,DC=com') { throw "unexpected identity $Identity" }
                [pscustomobject]@{ DistinguishedName = $Identity; 'msDS-Behavior-Version' = 10 }
            }
            $r = Get-AdfaForestBehaviorVersion -Forest $script:FakeForest -AdParams @{}
            [string]$r.Level | Should -Be '10'
            [string]$r.Error | Should -BeNullOrEmpty
        }
        It 'carries the directory error verbatim when the read is refused' {
            function Get-ADObject { param([Parameter(ValueFromRemainingArguments)]$a) throw 'Access is denied' }
            $r = Get-AdfaForestBehaviorVersion -Forest $script:FakeForest -AdParams @{}
            [string]$r.Level | Should -BeNullOrEmpty
            [string]$r.Error | Should -Match 'Access is denied'
        }
        It 'does not read an attribute that was not returned as level 0' {
            function Get-ADObject { param([Parameter(ValueFromRemainingArguments)]$a) [pscustomobject]@{ DistinguishedName = 'x' } }
            $r = Get-AdfaForestBehaviorVersion -Forest $script:FakeForest -AdParams @{}
            [string]$r.Level | Should -BeNullOrEmpty
            [string]$r.Error | Should -Match 'msDS-Behavior-Version'
        }
        It 'names the missing PartitionsContainer instead of guessing a DN' {
            $r = Get-AdfaForestBehaviorVersion -Forest ([pscustomobject]@{ Name = 'contoso.com' }) -AdParams @{}
            [string]$r.Level | Should -BeNullOrEmpty
            [string]$r.Error | Should -Match 'PartitionsContainer'
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
            $row = Get-SeTestRow (Get-AdfaExchangeSeCompatibility -ForestMode 'Windows2016Forest' -ForestLevel '7' `
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
            $r = Get-AdfaExchangeSeCompatibility -ForestMode 'Windows2016Forest' -ForestLevel '7' -DomainSummaries @() `
                -DomainControllers $dcs -SeConfig $script:SeCfg
            [string](Get-SeTestRow $r 'Domain controller operating systems').Status | Should -Be 'Pass'
            $unk = Get-SeTestRow $r 'Domain controller OS - not readable'
            $unk | Should -Not -BeNullOrEmpty
            [string]$unk.Status | Should -Be 'Not Assessed'
            $unk.Detail | Should -Match 'unverified, not compatible'
        }
        It 'reports Not Assessed when nothing is readable and when no DCs were enumerated' {
            $allUnk = Get-AdfaExchangeSeCompatibility -ForestMode 'Windows2016Forest' -ForestLevel '7' -DomainSummaries @() `
                -DomainControllers @([pscustomobject]@{ HostName = 'dc1'; OperatingSystem = 'Not Assessed'; IsReadOnly = $false }) `
                -SeConfig $script:SeCfg
            [string](Get-SeTestRow $allUnk 'Domain controller operating systems').Status | Should -Be 'Not Assessed'
            $none = Get-AdfaExchangeSeCompatibility -ForestMode 'Windows2016Forest' -ForestLevel '7' -DomainSummaries @() `
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
            $r = Get-AdfaExchangeSeCompatibility -ForestMode 'Windows2016Forest' -ForestLevel '7' -DomainSummaries @() `
                -DomainControllers $dcs -SeConfig $script:SeCfg
            $row = Get-SeTestRow $r 'Read-only domain controllers'
            $row | Should -Not -BeNullOrEmpty
            [string]$row.Status | Should -Be 'Warning'
            $row.Detail | Should -Match 'rodc1\.contoso\.com'

            # Non-vacuity for the negative case: the lookup really does return null when absent.
            Get-SeTestRow $r 'No Such Item Exists' | Should -BeNullOrEmpty
            $clean = Get-AdfaExchangeSeCompatibility -ForestMode 'Windows2016Forest' -ForestLevel '7' -DomainSummaries @() `
                -DomainControllers $script:DcOk -SeConfig $script:SeCfg
            Get-SeTestRow $clean 'Read-only domain controllers' | Should -BeNullOrEmpty
        }
        It 'states its own limits so it is not mistaken for full SE readiness' {
            $r = Get-AdfaExchangeSeCompatibility -ForestMode 'Windows2016Forest' -ForestLevel '7' -DomainSummaries @() `
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
            $r = Get-AdfaExchangeSeCompatibility -ForestMode 'Windows2012R2Forest' -ForestLevel '6' -DomainSummaries @() `
                -DomainControllers $script:DcOk -SeConfig $strict
            [string](Get-SeTestRow $r 'Forest functional level').Status | Should -Be 'Fail'
        }
        It 'refuses a supported mode name that has no level in the table' {
            # The verdict reads the number, so a name with no number would silently drop out
            # of the supported set and fail a supported forest.
            { Merge-AdfaExchangeSeConfig -BaseConfig $script:SeCfg -Override @{ SupportedForestModes = @('Windows2099Forest') } } |
                Should -Throw -ExpectedMessage '*Windows2099Forest*'
        }
        It 'reads a level table that came from JSON, where entries are objects and not hashtables' {
            # 2099 / level 99 is deliberately not a real functional level: this proves a level
            # Microsoft has not shipped yet can be added by config alone.
            $json = '{ "SupportedForestModes": [ "Windows2099Forest", "Windows2016Forest" ],
                       "ForestFunctionalLevels": [
                         { "Level": 99, "Mode": "Windows2099Forest", "Label": "Fictional Server 2099" },
                         { "Level": "7", "Mode": "Windows2016Forest", "Label": "Windows Server 2016" },
                         { "Level": 6,  "Mode": "Windows2012R2Forest", "Label": "Windows Server 2012 R2" } ] }'
            $m = Merge-AdfaExchangeSeConfig -BaseConfig $script:SeCfg -Override ($json | ConvertFrom-Json)
            $t = @(Get-AdfaForestLevelTable -SeConfig $m)
            $t.Count | Should -Be 3
            ($t | Where-Object { $_.Level -eq 99 }).Mode | Should -Be 'Windows2099Forest'
            ($t | Where-Object { $_.Level -eq 99 }).Label | Should -Be 'Fictional Server 2099'
            ($t | Where-Object { $_.Mode -eq 'Windows2016Forest' }).Level | Should -Be 7   # "7" as a string still orders as a number
            $new = Get-SeTestRow (Get-AdfaExchangeSeCompatibility -ForestMode '' -ForestLevel '99' -DomainSummaries @() `
                    -DomainControllers $script:DcOk -SeConfig $m) 'Forest functional level'
            [string]$new.Status | Should -Be 'Pass'
            $new.Detail | Should -Match 'Fictional Server 2099'
            $old = Get-SeTestRow (Get-AdfaExchangeSeCompatibility -ForestMode '' -ForestLevel '6' -DomainSummaries @() `
                    -DomainControllers $script:DcOk -SeConfig $m) 'Forest functional level'
            [string]$old.Status | Should -Be 'Fail'
            $old.Detail | Should -Match 'until the forest functional level is raised'
        }
        It 'says a level table override replaces the whole table when that is what broke it' {
            # An operator adding one new level, expecting a row-by-row merge, drops the built-in
            # rows. The error must not blame a name the override never mentioned.
            $partial = '{ "ForestFunctionalLevels": [ { "Level": 99, "Mode": "Windows2099Forest", "Label": "n" } ] }' | ConvertFrom-Json
            { Merge-AdfaExchangeSeConfig -BaseConfig $script:SeCfg -Override $partial } |
                Should -Throw -ExpectedMessage '*replaces the whole built-in table*'
            { Merge-AdfaExchangeSeConfig -BaseConfig $script:SeCfg -Override @{ ForestFunctionalLevels = @() } } |
                Should -Throw -ExpectedMessage '*empty list*'
        }
        It 'judges a 2025 level forest as supported once an override lists it' {
            # A new supported level must be a config edit, never a code edit.
            $wide = Merge-AdfaExchangeSeConfig -BaseConfig $script:SeCfg `
                -Override @{ SupportedForestModes = @('Windows2025Forest', 'Windows2016Forest') }
            $r = Get-AdfaExchangeSeCompatibility -ForestMode 'Windows2025Forest' -ForestLevel '10' -DomainSummaries @() `
                -DomainControllers $script:DcOk -SeConfig $wide
            [string](Get-SeTestRow $r 'Forest functional level').Status | Should -Be 'Pass'
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

Describe 'Live-run defects (v1.11.0 first real forest run)' {
    Context 'Get-AdfaDcdiagTestOutcome' {
        # The live run produced dcdiag cells that were Not Assessed with NOTHING recorded about
        # why, on a tool whose own rule is that an unmeasured value carries a named cause.
        It 'reads a passed and a failed verdict' {
            Get-AdfaDcdiagTestOutcome -TestName 'Advertising' -StdOut '..... DC1 passed test Advertising' | Should -Be 'Pass'
            Get-AdfaDcdiagTestOutcome -TestName 'Advertising' -StdOut '..... DC1 failed test Advertising' | Should -Be 'Fail'
        }
        It 'never reports Pass for output it could not read' {
            Get-AdfaDcdiagTestOutcome -TestName 'VerifyEnterpriseReferences' -StdOut 'Doing initial required tests' | Should -Be 'Unparsed'
            Get-AdfaDcdiagTestOutcome -TestName 'Advertising' -StdOut '' | Should -Be 'Unparsed'
            Get-AdfaDcdiagTestOutcome -TestName 'Advertising' -Success $false -StdOut '' | Should -Be 'ToolFailed'
        }
        It 'keeps a real failure even though dcdiag exits non-zero for one' {
            # Reading Success before the verdict would throw a genuine measurement away.
            Get-AdfaDcdiagTestOutcome -TestName 'Advertising' -Success $false -StdOut '..... DC1 failed test Advertising' |
                Should -Be 'Fail'
        }
        It 'requires the verdict to name the test that was asked for' {
            Get-AdfaDcdiagTestOutcome -TestName 'VerifyReferences' -StdOut '..... DC1 passed test VerifyEnterpriseReferences' |
                Should -Be 'Unparsed'
            Get-AdfaDcdiagTestOutcome -TestName 'VerifyEnterpriseReferences' -StdOut '... PASSED TEST VerifyEnterpriseReferences' |
                Should -Be 'Pass'
        }
        It 'distinguishes all four declared outcomes' {
            $o = @(
                (Get-AdfaDcdiagTestOutcome -TestName 'T' -StdOut 'passed test T'),
                (Get-AdfaDcdiagTestOutcome -TestName 'T' -StdOut 'failed test T'),
                (Get-AdfaDcdiagTestOutcome -TestName 'T' -StdOut 'nothing'),
                (Get-AdfaDcdiagTestOutcome -TestName 'T' -Success $false -StdOut '')
            )
            @($o).Count | Should -Be 4
            @($o | Sort-Object -Unique).Count | Should -Be 4
        }
    }

    Context 'Get-AdfaDcdiagUnassessedCause' {
        It 'names the test, says nothing was measured, and carries the diagnostic line' {
            $c = Get-AdfaDcdiagUnassessedCause -TestName 'VerifyEnterpriseReferences' -Outcome 'Unparsed' -ExitCode 0 `
                -StdOut "Directory Server Diagnosis`nPerforming initial setup:`nHome Server = DC1`nLdap search capability attribute search failed on server DC1, return value = 81"
            $c | Should -Match 'VerifyEnterpriseReferences'
            $c | Should -Match 'NOT ASSESSED'
            $c | Should -Match 'return value = 81'
            # The banner is worthless here; excerpting the FIRST lines would return only that.
            $c | Should -Not -Match 'Directory Server Diagnosis'
        }
        It 'falls back to the tail, where dcdiag prints its summary' {
            Get-AdfaDcdiagUnassessedCause -TestName 'T' -Outcome 'Unparsed' -ExitCode 0 `
                -StdOut "Directory Server Diagnosis`nbanner two`nbanner three`nlast meaningful line" |
                Should -Match 'last meaningful line'
        }
        It 'describes a tool that never ran differently from output it could not parse' {
            $f = Get-AdfaDcdiagUnassessedCause -TestName 'CheckSecurityError' -Outcome 'ToolFailed' -StdOut '' -ErrorText 'timed out' -ExitCode 258
            $f | Should -Match 'did not complete'
            $f | Should -Match '258'
            $f | Should -Match 'timed out'
            $f | Should -Not -Match 'non-English'
            $s = Get-AdfaDcdiagUnassessedCause -TestName 'KnowsOfRoleHolders' -Outcome 'Unparsed' -StdOut '' -ExitCode 0
            $s | Should -Match 'NO output'
            $s | Should -Match 'dcdiag /test:KnowsOfRoleHolders'
        }
        It 'bounds the excerpt and says when it truncated' {
            $long = (1..80 | ForEach-Object { "error line $_ with a great deal of padding text to make it comfortably long" }) -join "`n"
            $c = Get-AdfaDcdiagUnassessedCause -TestName 'T' -Outcome 'Unparsed' -StdOut $long -ExitCode 0
            $c.Length | Should -BeLessThan 600
            $c | Should -Match '\.\.\.'
        }
        It 'never produces an empty cause for any unassessed case' {
            $causes = @(
                (Get-AdfaDcdiagUnassessedCause -TestName 'T' -Outcome 'Unparsed' -StdOut 'x' -ExitCode 0),
                (Get-AdfaDcdiagUnassessedCause -TestName 'T' -Outcome 'Unparsed' -StdOut '' -ExitCode 0),
                (Get-AdfaDcdiagUnassessedCause -TestName 'T' -Outcome 'ToolFailed' -StdOut '' -ExitCode 1)
            )
            @($causes).Count | Should -Be 3
            @($causes | Where-Object { [string]::IsNullOrWhiteSpace($_) }).Count | Should -Be 0
        }
    }

    Context 'Get-AdfaForwarderAddress' {
        # The live-run defect: a DC with NO forwarders threw "You cannot call a method on a
        # null-valued expression", which was caught upstream and reported as Not Assessed - a
        # measured absence presented as a failed measurement.
        It 'returns none configured instead of throwing, for every empty shape' {
            @(Get-AdfaForwarderAddress -Forwarder ([pscustomobject]@{ IPAddress = $null })).Count | Should -Be 0
            @(Get-AdfaForwarderAddress -Forwarder ([pscustomobject]@{ IPAddress = @() })).Count | Should -Be 0
            @(Get-AdfaForwarderAddress -Forwarder ([pscustomobject]@{ Other = 'x' })).Count | Should -Be 0
            @(Get-AdfaForwarderAddress -Forwarder $null).Count | Should -Be 0
        }
        It 'returns the configured addresses, dropping nulls and duplicates' {
            $two = @(Get-AdfaForwarderAddress -Forwarder ([pscustomobject]@{ IPAddress = @('192.0.2.53', '192.0.2.54') }))
            @($two).Count | Should -Be 2
            [string]$two[0] | Should -Be '192.0.2.53'
            @(Get-AdfaForwarderAddress -Forwarder ([pscustomobject]@{ IPAddress = @('192.0.2.53', $null, '192.0.2.53') })).Count |
                Should -Be 1
        }
        It 'survives every declared degraded shape' {
            $shapes = @(
                ([pscustomobject]@{ IPAddress = $null }),
                ([pscustomobject]@{ IPAddress = @() }),
                ([pscustomobject]@{ Other = 'x' }),
                $null
            )
            @($shapes).Count | Should -Be 4
            $survived = 0
            foreach ($s in $shapes) {
                { Get-AdfaForwarderAddress -Forwarder $s } | Should -Not -Throw
                $survived++
            }
            $survived | Should -Be 4
        }
    }
}

Describe 'dcdiag arguments (Intersite false Pass, DNS test)' {
    # Learn, dcdiag page, Intersite row (read 2026-09-22): "The /a or /e parameter must be used
    # as not providing a site would allow the test to run but SKIPS ACTUAL TESTING." Every run
    # before v1.13.0 omitted both, so the Intersite column reported Pass on a test that had
    # checked nothing.
    It 'gives Intersite the /a it needs to actually test anything' {
        $a = Get-AdfaDcdiagArgument -TestName 'Intersite' -DomainController 'dc1.contoso.com'
        $a | Should -Match '(^|\s)/a(\s|$)'
        $a | Should -Match '/test:Intersite'
        $a | Should -Match '/s:dc1\.contoso\.com'
    }
    It 'requests the DNS test explicitly with /DnsAll, and not the external-name test' {
        $a = Get-AdfaDcdiagArgument -TestName 'DNS' -DomainController 'dc1.contoso.com'
        $a | Should -Match '/test:DNS'
        $a | Should -Match '/DnsAll'
        $a | Should -Not -Match 'DnsResolveExtName'
    }
    It 'leaves every other test on the plain form' {
        $a = Get-AdfaDcdiagArgument -TestName 'Advertising' -DomainController 'dc1.contoso.com'
        $a | Should -Be '/test:Advertising /s:dc1.contoso.com'
    }
    It 'deviates from the plain form for exactly two of the eighteen grid tests' {
        $grid = @('Netlogons', 'Services', 'Replications', 'FsmoCheck', 'Advertising', 'SysVolCheck',
            'MachineAccount', 'ObjectsReplicated', 'RidManager', 'KccEvent', 'VerifyReferences',
            'CrossRefValidation', 'KnowsOfRoleHolders', 'Intersite', 'DFSREvent',
            'CheckSecurityError', 'VerifyEnterpriseReferences', 'DNS')
        @($grid).Count | Should -Be 18
        # Not $args: that is an automatic variable, and assigning to it inside a scriptblock
        # shadows the block's own argument array.
        $argList = @($grid | ForEach-Object { Get-AdfaDcdiagArgument -TestName $_ -DomainController 'dc1.contoso.com' })
        @($argList | Where-Object { $_ -match '/s:dc1\.contoso\.com' }).Count | Should -Be 18
        @($argList | Where-Object { $_ -notmatch '^/test:\S+ /s:dc1\.contoso\.com$' }).Count | Should -Be 2
    }
    It 'has the DNS test in the array the collector actually iterates' {
        # A builder that handles 'DNS' is worth nothing if nothing asks for it.
        (Get-Content -LiteralPath $script:Target -Raw) |
            Should -Match "'CheckSecurityError', 'VerifyEnterpriseReferences', 'DNS'"
    }
}

Describe 'Event lookback parameter and measured clock offset' {
    Context '-EventLookbackDays' {
        # Before v1.14.0 the window was a pair of constants in $script:Config with no runtime
        # override - on the tool built for assessing a forest AFTER a restore, so a restore
        # older than 14 days could not be reached without editing the script.
        It 'exists and is range-validated to a year' {
            $p = (Get-Command $script:Target).Parameters['EventLookbackDays']
            $p | Should -Not -BeNullOrEmpty
            $r = @($p.Attributes | Where-Object { $_ -is [System.Management.Automation.ValidateRangeAttribute] })
            @($r).Count | Should -Be 1
            [int]$r[0].MinRange | Should -Be 1
            [int]$r[0].MaxRange | Should -Be 365
        }
        It 'feeds both event windows, which no longer hold constants' {
            $src = Get-Content -LiteralPath $script:Target -Raw
            $src | Should -Match 'DsEventLookbackDays\s*=\s*\$EventLookbackDays'
            $src | Should -Match 'DfsrEventLookbackDays\s*=\s*\$EventLookbackDays'
        }
        It 'cannot fabricate coverage when the window outruns the log' {
            # This is what makes widening the window safe rather than a lie.
            Get-AdfaEventLogCoverage -Inspected $true -RecordCount 500 `
                -OldestRecord (Get-Date).AddDays(-30) -WindowStart (Get-Date).AddDays(-180) |
                Should -Be 'Truncated'
            Get-AdfaEventLogCoverage -Inspected $true -RecordCount 500 `
                -OldestRecord (Get-Date).AddDays(-200) -WindowStart (Get-Date).AddDays(-180) |
                Should -Be 'Covered'
        }
    }

    Context 'ConvertFrom-AdfaStripchartCsv' {
        # The only external-tool output whose format Microsoft publishes, which is why it is used.
        BeforeAll {
            $script:ScCsv = @"
Tracking dc1.contoso.com [192.0.2.11:123].
RdtscStart, RdtscEnd, FileTime, RoundtripDelay, NtpOffset
123, 456, 133000000000000000, 0.0021234, +0.0012218
124, 457, 133000000000000001, 0.0022000, -0.0009000
"@
        }
        It 'parses the documented headers, past a preamble line' {
            $r = ConvertFrom-AdfaStripchartCsv -Text $script:ScCsv
            @($r.Offsets).Count | Should -Be 2
            @($r.Delays).Count | Should -Be 2
            [Math]::Abs(([double]@($r.Offsets)[0]) - 0.0012218) | Should -BeLessThan 0.0000001
        }
        It 'drops a sample it cannot read rather than calling it zero' {
            # Zero would mean "perfectly synchronised" - the worst possible misreading.
            $bad = ConvertFrom-AdfaStripchartCsv -Text @"
RdtscStart, RdtscEnd, FileTime, RoundtripDelay, NtpOffset
123, 456, 133000000000000000, 0.002, error
124, 457, 133000000000000001, 0.002, +0.5
"@
            @($bad.Offsets).Count | Should -Be 1
            [int]$bad.RowsSeen | Should -Be 2
            $timeout = ConvertFrom-AdfaStripchartCsv -Text "Tracking dc9.contoso.com.`nRdtscStart, RdtscEnd, FileTime, RoundtripDelay, NtpOffset`nRequest timed out.`n"
            @($timeout.Offsets).Count | Should -Be 0
        }
        It 'yields nothing for output with no header, and for null' {
            @((ConvertFrom-AdfaStripchartCsv -Text 'no csv here').Offsets).Count | Should -Be 0
            @((ConvertFrom-AdfaStripchartCsv -Text $null).Offsets).Count | Should -Be 0
        }
    }

    Context 'Get-AdfaClockOffsetVerdict' {
        It 'separates the vendor threshold from ours, and says which is which' {
            $f = Get-AdfaClockOffsetVerdict -DomainController 'dc1.contoso.com' -Offsets @(400.0) -WarnSeconds 60 -FailSeconds 300
            [string]$f.Status | Should -Be 'Fail'
            $f.Detail | Should -Match '300s Kerberos maximum'
            $w = Get-AdfaClockOffsetVerdict -DomainController 'dc1.contoso.com' -Offsets @(90.0) -WarnSeconds 60 -FailSeconds 300
            [string]$w.Status | Should -Be 'Warning'
            $w.Detail | Should -Match 'OURS and not a vendor threshold'
        }
        It 'passes a small offset while stating what it does not prove' {
            $p = Get-AdfaClockOffsetVerdict -DomainController 'dc1.contoso.com' -Offsets @(0.4, -0.2) -WarnSeconds 60 -FailSeconds 300
            [string]$p.Status | Should -Be 'Pass'
            # The offset is measured from the host running the assessment.
            $p.Detail | Should -Match "not proof the forest's time is correct"
        }
        It 'judges on the worst sample and ignores the sign' {
            [string](Get-AdfaClockOffsetVerdict -DomainController 'a' -Offsets @(-400.0) -WarnSeconds 60 -FailSeconds 300).Status |
                Should -Be 'Fail'
            # Averaging +400 and -400 would report a swinging clock as perfect.
            [string](Get-AdfaClockOffsetVerdict -DomainController 'a' -Offsets @(400.0, -400.0) -WarnSeconds 60 -FailSeconds 300).Status |
                Should -Be 'Fail'
        }
        It 'never passes an offset it could not measure' {
            $degraded = @(
                (Get-AdfaClockOffsetVerdict -DomainController 'a' -Offsets @() -ErrorText 'every NTP sample timed out'),
                (Get-AdfaClockOffsetVerdict -DomainController 'a' -Queried $false),
                (Get-AdfaClockOffsetVerdict -DomainController 'a' -Offsets @('not a number'))
            )
            @($degraded).Count | Should -Be 3
            @($degraded | Where-Object { $_.Status -eq 'Pass' }).Count | Should -Be 0
            $degraded[1].Detail | Should -Match 'unmeasured offset is not a small one'
        }
    }

    Context 'Clock-skew configuration' {
        It 'keeps the vendor number and ours apart, each with a source' {
            [int]$script:Config.ClockSkew.KerberosMaxSeconds | Should -Be 300
            [double]$script:Config.ClockSkew.WarnSeconds | Should -BeLessThan 300
            $script:Config.ClockSkew.KerberosUrl | Should -Match '^https://learn\.microsoft\.com/'
            $script:Config.ClockSkew.StripchartUrl | Should -Match '^https://learn\.microsoft\.com/'
            [string]$script:Config.ClockSkew.ReadDate | Should -Be '2026-09-22'
        }
    }
}

Describe 'Cross-domain DC enrichment (live four-domain forest, 2026-09-26)' {
    # The inventory enriched via Get-ADComputer with no -Server, so a child-domain DN was asked
    # of a forest-root DC, which answers with an LDAP referral. Every child-domain DC lost its
    # OperatingSystem and the Exchange SE verdict called them "unverified, not compatible" -
    # a forest-wide readiness answer that was wrong for every domain but the one it ran in.
    # Single-domain runs never showed it: there the default server IS the target domain.
    Context 'The collector targets the domain being enumerated' {
        It 'splats the per-domain $p, which carries -Server, not the bare $AdParams' {
            $src = Get-Content -LiteralPath $script:Target -Raw
            $src | Should -Match '\$cp = @\{\} \+ \$p'
            $src | Should -Not -Match '\$cp = @\{\} \+ \$AdParams'
        }
    }

    Context 'An enrichment failure carries its cause' {
        It 'keeps the DC, reports the OS unassessed, and records why' {
            # Defined, not Mocked. Pester's Mock requires the command to already exist, and the
            # ActiveDirectory module is not present on the CI runner - "Could not find Command
            # Get-ADDomainController". Defining the stub in this scope is what the dependency-free
            # harness does, and it works with or without RSAT.
            function Get-ADDomainController {
                param([Parameter(ValueFromRemainingArguments)]$a)
                [pscustomobject]@{ HostName = 'dc9.contoso.com'; Name = 'DC9'; Site = 'HQ'; IPv4Address = '192.0.2.9'
                    IsGlobalCatalog = $true; IsReadOnly = $false
                    ComputerObjectDN = 'CN=DC9,OU=Domain Controllers,DC=child,DC=contoso,DC=com' }
            }
            function Get-ADComputer {
                param([Parameter(ValueFromRemainingArguments)]$a)
                throw 'A referral was returned from the server'
            }
            $inv = @(Get-AdfaDomainControllerInventory -DomainName 'child.contoso.com' -AdParams @{} -WarningAction SilentlyContinue)
            @($inv).Count | Should -Be 1
            [string]$inv[0].OperatingSystem | Should -Be 'Not Assessed'
            [string]$inv[0].EnrichmentError | Should -Match 'referral'
            # What Get-ADDomainController supplied must survive - SiteGc reads these, which is
            # why per-site GC coverage kept working on the live forest while the OS did not.
            [bool]$inv[0].IsGlobalCatalog | Should -BeTrue
            [string]$inv[0].Site | Should -Be 'HQ'
        }
    }

    Context 'Get-AdfaEnrichmentFailureAdvice' {
        It 'names a referral as a referral and rules out credentials' {
            $a = Get-AdfaEnrichmentFailureAdvice -Causes @('A referral was returned from the server')
            $a | Should -Match 'LDAP referral'
            $a | Should -Match "does not hold that domain's naming context"
            $a | Should -Match 'not a credentials problem'
            # The old fixed advice sent operators to check credentials, which had nothing to do
            # with it. Wrong advice is worse than none.
            $a | Should -Not -Match 're-run with credentials'
        }
        It 'keeps the credentials advice for an access failure, and gives both when both occur' {
            $d = Get-AdfaEnrichmentFailureAdvice -Causes @('Access is denied')
            $d | Should -Match 're-run with credentials'
            $d | Should -Not -Match 'LDAP referral'
            $b = Get-AdfaEnrichmentFailureAdvice -Causes @('A referral was returned from the server', 'Access is denied')
            $b | Should -Match 'LDAP referral'
            $b | Should -Match 're-run with credentials'
        }
        It 'quotes an unrecognised error rather than interpreting it' {
            $o = Get-AdfaEnrichmentFailureAdvice -Causes @('The server is not operational')
            $o | Should -Match 'Reported by the directory'
            $o | Should -Match 'The server is not operational'
            $o | Should -Not -Match 'LDAP referral'
            $o | Should -Not -Match 're-run with credentials'
        }
        It 'says nothing when there is nothing to say, and does not repeat a shared cause' {
            Get-AdfaEnrichmentFailureAdvice -Causes @() | Should -Be ''
            Get-AdfaEnrichmentFailureAdvice -Causes @('', '   ') | Should -Be ''
            Get-AdfaEnrichmentFailureAdvice -Causes $null | Should -Be ''
            $dupe = Get-AdfaEnrichmentFailureAdvice -Causes @('A referral was returned from the server', 'A referral was returned from the server')
            [regex]::Matches($dupe, 'A referral was returned from the server').Count | Should -Be 1
        }
    }
}

Describe 'dcdiag tests that change state are not run by default (H20)' {
    # Microsoft documents that the dcdiag DNS dynamic update test performs "registration of a
    # test record (_dcdiag_test_record)" which "is deleted automatically after the test", and
    # that Intersite works by "reporting back any replication failures after triggering a
    # replication". Until H20 both ran on every DC in every default run.
    BeforeAll {
        $script:H20Dc = 'dc1.contoso.com'
        function Invoke-H20Grid {
            param([switch]$Active)
            $script:H20Args = @()
            Mock Test-CommandAvailable { $true }
            Mock Test-TcpPort { $true }
            Mock Invoke-ExternalCommand {
                $script:H20Args += [string]$Arguments
                $name = ([regex]::Match([string]$Arguments, '/test:(\S+)')).Groups[1].Value
                [pscustomobject]@{ Success = $true; ExitCode = 0; Attempt = 1; Error = $null; StdOut = ("......................... DC1 passed test {0}" -f $name) }
            }
            return @(Get-AdfaDcDiagnostic -DomainControllers @($script:H20Dc) -TimeoutSeconds 5 -Retries 1 -RetryDelaySeconds 0 -IncludeActiveTests:$Active)
        }
    }

    Context 'Config' {
        It 'names the two tests, each with the vendor statement that puts it there' {
            $active = @($script:Config.DcdiagActiveTests)
            # Declared population: the two tests Microsoft documents as changing state.
            $active.Count | Should -Be 2
            @($active | ForEach-Object { [string]$_.Test }) | Should -Contain 'DNS'
            @($active | ForEach-Object { [string]$_.Test }) | Should -Contain 'Intersite'
            foreach ($a in $active) {
                [string]$a.Effect | Should -Not -BeNullOrEmpty
                [string]$a.Source | Should -Match '^https://learn\.microsoft\.com/'
                [string]$a.ReadDate | Should -Match '^\d{4}-\d{2}-\d{2}$'
            }
        }
    }

    Context 'Default run' {
        It 'never invokes dcdiag for DNS or Intersite, and still invokes it for the other 16 tests' {
            $rows = @(Invoke-H20Grid)
            @($script:H20Args | Where-Object { $_ -match '/test:(DNS|Intersite)\b' }).Count | Should -Be 0
            @($script:H20Args | Where-Object { $_ -match '/DnsAll|\s/a(\s|$)' }).Count | Should -Be 0
            @($script:H20Args).Count | Should -Be 16
            @($rows).Count | Should -Be 1
        }
        It 'holds the tests back when the switch is simply not given, not only when it is given as false' {
            # Every other call in this Describe binds the switch explicitly. A function that
            # defaulted to running the tests would pass all of them.
            $script:H20Args = @()
            Mock Test-CommandAvailable { $true }
            Mock Test-TcpPort { $true }
            Mock Invoke-ExternalCommand {
                $script:H20Args += [string]$Arguments
                $name = ([regex]::Match([string]$Arguments, '/test:(\S+)')).Groups[1].Value
                [pscustomobject]@{ Success = $true; ExitCode = 0; Attempt = 1; Error = $null; StdOut = ("DC1 passed test {0}" -f $name) }
            }
            Get-AdfaDcDiagnostic -DomainControllers @($script:H20Dc) -TimeoutSeconds 5 -Retries 1 -RetryDelaySeconds 0 | Out-Null
            @($script:H20Args).Count | Should -Be 16
            @($script:H20Args | Where-Object { $_ -match '/test:(DNS|Intersite)\b' }).Count | Should -Be 0
        }
        It 'holds them back on EVERY DC, and gives every DC its own note' {
            # Declared population: 3 DCs, 16 tests each. A defect that held the tests back only
            # for the first DC passed every single-DC test.
            $script:H20Args = @()
            Mock Test-CommandAvailable { $true }
            Mock Test-TcpPort { $true }
            Mock Invoke-ExternalCommand {
                $script:H20Args += [string]$Arguments
                $name = ([regex]::Match([string]$Arguments, '/test:(\S+)')).Groups[1].Value
                [pscustomobject]@{ Success = $true; ExitCode = 0; Attempt = 1; Error = $null; StdOut = ("passed test {0}" -f $name) }
            }
            $names = @('dc1.contoso.com', 'dc2.contoso.com', 'dc3.contoso.com')
            $rows = @(Get-AdfaDcDiagnostic -DomainControllers $names -TimeoutSeconds 5 -Retries 1 -RetryDelaySeconds 0)
            @($rows).Count | Should -Be 3
            @($script:H20Args).Count | Should -Be 48
            @($script:H20Args | Where-Object { $_ -match '/test:(DNS|Intersite)\b' }).Count | Should -Be 0
            foreach ($row in $rows) {
                [string]$row.DCDIAG_DNS | Should -Be 'Not Assessed'
                [string]$row.DCDIAG_Intersite | Should -Be 'Not Assessed'
                [string]$row.NotRun | Should -Match 'IncludeDcdiagActiveTests' -Because "$($row.DomainController) must carry its own reason"
                [string]$row.Status | Should -Be 'Pass'
            }
        }
        It 'reports the two cells Not Assessed, with the reason and the switch in the row' {
            $row = @(Invoke-H20Grid)[0]
            [string]$row.DCDIAG_DNS | Should -Be 'Not Assessed'
            [string]$row.DCDIAG_Intersite | Should -Be 'Not Assessed'
            [string]$row.NotRun | Should -Match 'DNS'
            [string]$row.NotRun | Should -Match 'Intersite'
            [string]$row.NotRun | Should -Match 'IncludeDcdiagActiveTests'
            [string]$row.NotRun | Should -Match '(?i)not run'
            # Nothing failed, so the column the advice is chosen from stays empty.
            [string]$row.Failures | Should -BeNullOrEmpty
        }
        It 'does not turn a DC whose 16 attempted tests all passed into a Warning' {
            # The two cells are a decision, not a failed measurement. A Warning on every DC in
            # every default run would bury the DCs that have a real unassessed test.
            $row = @(Invoke-H20Grid)[0]
            [string]$row.Status | Should -Be 'Pass'
            [string]$row.DCDIAG_Advertising | Should -Be 'Pass'
        }
        It 'still reports a Warning when a test that WAS attempted could not be read, and keeps the note' {
            Mock Test-CommandAvailable { $true }
            Mock Test-TcpPort { $true }
            Mock Invoke-ExternalCommand {
                if ([string]$Arguments -match '/test:Advertising\b') { return [pscustomobject]@{ Success = $true; ExitCode = 0; Attempt = 1; Error = $null; StdOut = 'unexpected text' } }
                $name = ([regex]::Match([string]$Arguments, '/test:(\S+)')).Groups[1].Value
                [pscustomobject]@{ Success = $true; ExitCode = 0; Attempt = 1; Error = $null; StdOut = ("DC1 passed test {0}" -f $name) }
            }
            $row = @(Get-AdfaDcDiagnostic -DomainControllers @($script:H20Dc) -TimeoutSeconds 5 -Retries 1 -RetryDelaySeconds 0)[0]
            [string]$row.Status | Should -Be 'Warning'
            [string]$row.DCDIAG_Advertising | Should -Be 'Not Assessed'
            [string]$row.Failures | Should -Match 'Advertising'
            [string]$row.Failures | Should -Not -Match 'IncludeDcdiagActiveTests'   # the note is not a failure
            [string]$row.NotRun | Should -Match 'IncludeDcdiagActiveTests'          # and is still in the row
        }
        It 'still reports Fail when a test that WAS attempted failed' {
            Mock Test-CommandAvailable { $true }
            Mock Test-TcpPort { $true }
            Mock Invoke-ExternalCommand {
                if ([string]$Arguments -match '/test:Replications\b') { return [pscustomobject]@{ Success = $false; ExitCode = 1; Attempt = 1; Error = $null; StdOut = "[Replications Check,DC1] A recent replication attempt failed`n......................... DC1 failed test Replications" } }
                $name = ([regex]::Match([string]$Arguments, '/test:(\S+)')).Groups[1].Value
                [pscustomobject]@{ Success = $true; ExitCode = 0; Attempt = 1; Error = $null; StdOut = ("DC1 passed test {0}" -f $name) }
            }
            $row = @(Get-AdfaDcDiagnostic -DomainControllers @($script:H20Dc) -TimeoutSeconds 5 -Retries 1 -RetryDelaySeconds 0)[0]
            [string]$row.Status | Should -Be 'Fail'
            [string]$row.DCDIAG_Replications | Should -Be 'Fail'
            [string]$row.NotRun | Should -Match 'IncludeDcdiagActiveTests'
        }
        It 'gives an unreachable DC its own cause and no "not run by default" note' {
            Mock Test-CommandAvailable { $true }
            Mock Test-TcpPort { $false }
            $row = @(Get-AdfaDcDiagnostic -DomainControllers @($script:H20Dc) -TimeoutSeconds 5 -Retries 1 -RetryDelaySeconds 0)[0]
            [string]$row.Failures | Should -Match 'not reachable'
            [string]$row.NotRun | Should -BeNullOrEmpty
        }
    }

    Context 'The note must not choose the advice' {
        # The recommendation map matches on the whole finding text, first match wins. The note
        # says the Intersite test "triggers a replication", and an unscoped entry matches the
        # word "replication": with the note in the Failures column, every failing dcdiag row in
        # a default run was given replication advice, whatever had actually failed.
        BeforeAll {
            $script:H20Note = 'Not run by default, so not assessed: DNS (its dynamic update test registers a test record in the DNS zone and then deletes it); Intersite (it triggers a replication). Microsoft documents these dcdiag tests as changing state. -IncludeDcdiagActiveTests runs them.'
            function New-H20Row { param([string]$Status, [string]$Failures, [string]$NotRun)
                [pscustomobject]@{ DomainController = 'dc1.contoso.com'; Status = $Status; Failures = $Failures; NotRun = $NotRun } }
        }
        It 'gives a failing row the same advice with the note as without it' {
            foreach ($failure in @('SysVolCheck: no diagnostic lines captured', 'Advertising: no diagnostic lines captured', 'RidManager: NOT ASSESSED - dcdiag printed no verdict for this test')) {
                $with = ConvertTo-AdfaConsolidatedFinding -Section 'DC Diagnostics' -Row (New-H20Row 'Fail' $failure $script:H20Note) -StatusColumn 'Status'
                $without = ConvertTo-AdfaConsolidatedFinding -Section 'DC Diagnostics' -Row (New-H20Row 'Fail' $failure '') -StatusColumn 'Status'
                $with.Recommendation | Should -Be $without.Recommendation -Because "the advice for '$failure' must come from the failure"
                $with.Recommendation | Should -Not -BeNullOrEmpty
            }
        }
        It 'proves the note WOULD change the advice if it were part of the failure text' {
            # Non-vacuity: without this, the test above could pass because the note is harmless.
            $failure = 'SysVolCheck: no diagnostic lines captured'
            $clean = Get-AdfaRecommendation -Section 'DC Diagnostics' -Item 'dc1.contoso.com' -Detail $failure
            $polluted = Get-AdfaRecommendation -Section 'DC Diagnostics' -Item 'dc1.contoso.com' -Detail ("{0} | {1}" -f $failure, $script:H20Note)
            $polluted | Should -Not -Be $clean
        }
        It 'still puts the note in the finding detail, after the failure' {
            $f = ConvertTo-AdfaConsolidatedFinding -Section 'DC Diagnostics' -Row (New-H20Row 'Fail' 'SysVolCheck: x' $script:H20Note) -StatusColumn 'Status'
            $f.Detail | Should -Match '^SysVolCheck: x \| Not run by default'
            $pass = ConvertTo-AdfaConsolidatedFinding -Section 'DC Diagnostics' -Row (New-H20Row 'Pass' '' $script:H20Note) -StatusColumn 'Status'
            $pass.Detail | Should -Match '^Not run by default'
            $pass.Recommendation | Should -BeNullOrEmpty
            $pass.Item | Should -Be 'dc1.contoso.com'
        }
        It 'leaves a row with no NotRun column exactly as it was' {
            $row = [pscustomobject]@{ Scope = 'contoso.com'; Item = 'Some check'; Status = 'Warning'; Detail = 'something about replication' }
            $f = ConvertTo-AdfaConsolidatedFinding -Section 'Replication Health' -Row $row -StatusColumn 'Status'
            $f.Detail | Should -Be 'something about replication'
            $f.Scope | Should -Be 'contoso.com'
            $f.Item | Should -Be 'Some check'
            $f.Recommendation | Should -Not -BeNullOrEmpty
        }
    }

    Context 'With the opt-in' {
        It 'runs all 18 tests, with /DnsAll and /a' {
            $row = @(Invoke-H20Grid -Active)[0]
            @($script:H20Args).Count | Should -Be 18
            @($script:H20Args | Where-Object { $_ -match '/test:DNS /DnsAll' }).Count | Should -Be 1
            @($script:H20Args | Where-Object { $_ -match '/test:Intersite .* /a$' }).Count | Should -Be 1
            [string]$row.DCDIAG_DNS | Should -Be 'Pass'
            [string]$row.DCDIAG_Intersite | Should -Be 'Pass'
            [string]$row.NotRun | Should -BeNullOrEmpty
        }
    }

    Context 'Wiring' {
        It 'declares -IncludeDcdiagActiveTests as a switch, and passes its value and nothing else to the collector' {
            $ast = [System.Management.Automation.Language.Parser]::ParseFile($script:Target, [ref]$null, [ref]$null)
            $p = @($ast.ParamBlock.Parameters | Where-Object { $_.Name.VariablePath.UserPath -eq 'IncludeDcdiagActiveTests' })
            $p.Count | Should -Be 1
            $p[0].StaticType.Name | Should -Be 'SwitchParameter'
            $calls = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true) | Where-Object { $_.GetCommandName() -eq 'Get-AdfaDcDiagnostic' })
            $calls.Count | Should -Be 1   # declared population: the one call in Invoke-Main
            $arg = @($calls[0].CommandElements | Where-Object { $_ -is [System.Management.Automation.Language.CommandParameterAst] -and $_.ParameterName -eq 'IncludeActiveTests' })
            $arg.Count | Should -Be 1
            $arg[0].Argument | Should -Not -BeNullOrEmpty
            $arg[0].Argument.Extent.Text | Should -Be '$IncludeDcdiagActiveTests'
        }
        It 'builds dcdiag arguments in one place, so no other code can run a state-changing test' {
            $ast = [System.Management.Automation.Language.Parser]::ParseFile($script:Target, [ref]$null, [ref]$null)
            $strings = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.StringConstantExpressionAst] -or $n -is [System.Management.Automation.Language.ExpandableStringExpressionAst] }, $true))
            $hits = @($strings | Where-Object { $_.Extent.Text -match '(?i)/test:(DNS|Intersite)\b' })
            $hits.Count | Should -Be 2   # declared population: one string per test, both in the builder
            foreach ($h in $hits) {
                $owner = $h.Parent
                while ($null -ne $owner -and $owner -isnot [System.Management.Automation.Language.FunctionDefinitionAst]) { $owner = $owner.Parent }
                $owner.Name | Should -Be 'Get-AdfaDcdiagArgument'
            }
        }
    }
}

Describe 'Secure channel checks are read-only by default (H19)' {
    # Microsoft's nltest reference says of /sc_verify: "If the secure channel does not work, this
    # parameter removes the existing channel, and then builds a new one." Until H19 the tool ran
    # it by default, on the host and on every DC, while describing itself as strictly read-only.
    BeforeAll {
        # The sample Microsoft publishes for /sc_query, and the same with a non-zero status.
        $script:ScOk = "Flags: 30 HAS_IP  HAS_TIMESERV`nTrusted DC Name \\dc1.contoso.com`nTrusted DC Connection Status Status = 0 0x0 NERR_Success`nThe command completed successfully"
        $script:ScBad = "Flags: 0`nTrusted DC Name`nTrusted DC Connection Status Status = 1311 0x51f ERROR_NO_LOGON_SERVERS`nThe command completed successfully"
    }

    Context 'Get-AdfaNltestScArgument' {
        It 'asks for /sc_query unless a live verification was explicitly requested' {
            Get-AdfaNltestScArgument -Domain 'contoso.com' | Should -Be '/sc_query:contoso.com'
            Get-AdfaNltestScArgument -Domain 'contoso.com' -LiveVerify | Should -Be '/sc_verify:contoso.com'
        }
        It 'is the only place in the script that builds an /sc_verify argument' {
            # Read from the parsed script, not matched as text: every string literal anywhere
            # in the code that could become an /sc_verify argument - "sc_verify:" followed by
            # anything but the "<partner>" placeholder of advice text - must sit inside the one
            # builder. A text count of two spellings missed '/sc_verify:' + $d.
            $ast = [System.Management.Automation.Language.Parser]::ParseFile($script:Target, [ref]$null, [ref]$null)
            $strings = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.StringConstantExpressionAst] -or $n -is [System.Management.Automation.Language.ExpandableStringExpressionAst] }, $true))
            $strings.Count | Should -BeGreaterThan 1000   # non-vacuity: the script's strings really were enumerated
            $hits = @($strings | Where-Object { $_.Extent.Text -match '(?i)sc_verify:(?!<)' })
            $hits.Count | Should -Be 1
            $owner = $hits[0].Parent
            while ($null -ne $owner -and $owner -isnot [System.Management.Automation.Language.FunctionDefinitionAst]) { $owner = $owner.Parent }
            $owner.Name | Should -Be 'Get-AdfaNltestScArgument'
        }
        It 'runs exactly the argument it was given on the remote side, and nothing composed there' {
            # The script blocks sent to a DC are the last place an argument could be rewritten.
            $ast = [System.Management.Automation.Language.Parser]::ParseFile($script:Target, [ref]$null, [ref]$null)
            $blocks = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.ScriptBlockExpressionAst] -and $n.Extent.Text -match 'nltest' }, $true))
            $blocks.Count | Should -Be 2   # declared population: the partner-DC check and the per-DC check
            foreach ($b in $blocks) { $b.Extent.Text | Should -Be '{ param($a) & nltest.exe $a 2>&1 | Out-String }' }
        }
    }

    Context 'Get-AdfaScVerifyOutcome (the opt-in live test)' {
        It 'needs a zero code on every status line, and is not satisfied by the closing line' {
            (Get-AdfaScVerifyOutcome -Output 'Trust Verification Status = 0x0 NERR_Success').Outcome | Should -Be 'Ok'
            (Get-AdfaScVerifyOutcome -Output "Trusted DC Connection Status Status = 0 0x0 NERR_Success`nTrust Verification Status = 0 0x0 NERR_Success`nThe command completed successfully").Outcome | Should -Be 'Ok'
            $mixed = Get-AdfaScVerifyOutcome -Output "Trusted DC Connection Status Status = 0 0x0 NERR_Success`nTrust Verification Status = 1311 0x51f ERROR_NO_LOGON_SERVERS`nThe command completed successfully"
            $mixed.Outcome | Should -Be 'Bad'
            $mixed.Status | Should -Match 'ERROR_NO_LOGON_SERVERS'
            (Get-AdfaScVerifyOutcome -Output 'Trust Verification Status = 0xc0000022 STATUS_ACCESS_DENIED').Outcome | Should -Be 'Bad'
            foreach ($o in @('', $null, 'The command completed successfully', 'NERR_Success')) {
                (Get-AdfaScVerifyOutcome -Output $o).Outcome | Should -Be 'Unparsed'
            }
        }
    }

    Context 'Get-AdfaScQueryOutcome' {
        It 'reads the connection status line, not the "command completed" line' {
            (Get-AdfaScQueryOutcome -Output $script:ScOk).Outcome | Should -Be 'Ok'
            $bad = Get-AdfaScQueryOutcome -Output $script:ScBad
            $bad.Outcome | Should -Be 'Bad'   # the command "completed successfully" and the channel is still not working
            $bad.Status | Should -Match 'ERROR_NO_LOGON_SERVERS'
        }
        It 'does not read past the end of the status line, and reads a status that has no name' {
            $noName = Get-AdfaScQueryOutcome -Output "Trusted DC Connection Status Status = 0 0x0`r`nThe command completed successfully"
            $noName.Outcome | Should -Be 'Ok'
            $noName.Status | Should -Be '0 0x0'   # not '0 0x0 The'
            (Get-AdfaScQueryOutcome -Output 'Trusted DC Connection Status Status = 1311 0x51f').Outcome | Should -Be 'Bad'
            (Get-AdfaScQueryOutcome -Output "  Trusted DC Connection Status Status = 5 0x5 ERROR_ACCESS_DENIED  `r`n").Outcome | Should -Be 'Bad'
        }
        It 'does not guess when the status line is absent' {
            foreach ($o in @('', $null, 'The command completed successfully', 'I_NetLogonControl failed: Status = 5 0x5 ERROR_ACCESS_DENIED', 'Estado da ligacao = 0')) {
                (Get-AdfaScQueryOutcome -Output $o).Outcome | Should -Be 'Unparsed' -Because "'$o' carries no connection status line"
            }
        }
    }

    Context 'Test-AdfaSecureChannel (local, outbound)' {
        BeforeEach { $script:H19Args = @() }
        It 'runs /sc_query by default, never /sc_verify, and says what kind of result that is' {
            Mock Test-CommandAvailable { $true }
            Mock Invoke-ExternalCommand { $script:H19Args += ("{0} {1}" -f $FilePath, $Arguments); [pscustomobject]@{ Success = $true; ExitCode = 0; StdOut = $script:ScOk } }
            $r = Test-AdfaSecureChannel -SourceDomain 'contoso.com' -TargetDomain 'fabrikam.com'
            $r.Result | Should -Be 'Verified'
            @($script:H19Args | Where-Object { $_ -match 'sc_verify' }).Count | Should -Be 0
            @($script:H19Args | Where-Object { $_ -match 'nltest\.exe /sc_query:fabrikam\.com' }).Count | Should -Be 1
            $r.Detail | Should -Match 'last'                          # last recorded state, not a live test
            $r.Detail | Should -Match 'IncludeSecureChannelVerify'    # how to get the live test
        }
        It 'reports Failed for a non-zero status even though the command "completed successfully"' {
            Mock Test-CommandAvailable { $true }
            Mock Invoke-ExternalCommand { [pscustomobject]@{ Success = $true; ExitCode = 0; StdOut = $script:ScBad } }
            $r = Test-AdfaSecureChannel -SourceDomain 'contoso.com' -TargetDomain 'fabrikam.com'
            $r.Result | Should -Be 'Failed'
            $r.Detail | Should -Match 'ERROR_NO_LOGON_SERVERS'
            $r.Detail | Should -Match 'not a live test'   # a Failed row is a last-recorded state too
        }
        It 'never runs netdom by default, even when nltest output cannot be read and netdom would say "verified"' {
            # netdom trust /Verify is a live test. Before the review of H19 the default path fell
            # through to it and returned its answer with no caveat.
            Mock Test-CommandAvailable { $true }
            Mock Invoke-ExternalCommand {
                $script:H19Args += ("{0} {1}" -f $FilePath, $Arguments)
                if ($FilePath -eq 'netdom.exe') { return [pscustomobject]@{ Success = $true; ExitCode = 0; StdOut = 'The trust has been verified.' } }
                [pscustomobject]@{ Success = $true; ExitCode = 0; StdOut = 'I_NetLogonControl failed: Status = 1355 0x54b ERROR_NO_SUCH_DOMAIN' }
            }
            $r = Test-AdfaSecureChannel -SourceDomain 'contoso.com' -TargetDomain 'fabrikam.com'
            $r.Result | Should -Be 'Not Assessed'
            $r.Detail | Should -Match 'ERROR_NO_SUCH_DOMAIN'   # what nltest printed is quoted, not discarded
            @($script:H19Args | Where-Object { $_ -match 'netdom' }).Count | Should -Be 0
            @($script:H19Args).Count | Should -Be 1
        }
        It 'does not run netdom in place of a missing nltest by default' {
            Mock Test-CommandAvailable { $Name -eq 'netdom.exe' }
            Mock Invoke-ExternalCommand { $script:H19Args += $FilePath; [pscustomobject]@{ Success = $true; ExitCode = 0; StdOut = 'The trust has been verified.' } }
            $r = Test-AdfaSecureChannel -SourceDomain 'contoso.com' -TargetDomain 'fabrikam.com'
            $r.Result | Should -Be 'Not Assessed'
            @($script:H19Args).Count | Should -Be 0
        }
        It 'with the opt-in, falls back to netdom, and does not read "failed to complete successfully" as success' {
            Mock Test-CommandAvailable { $true }
            Mock Invoke-ExternalCommand {
                if ($FilePath -eq 'netdom.exe') { return [pscustomobject]@{ Success = $false; ExitCode = 1; StdOut = 'The command failed to complete successfully.' } }
                [pscustomobject]@{ Success = $true; ExitCode = 0; StdOut = 'unreadable' }
            }
            (Test-AdfaSecureChannel -SourceDomain 'contoso.com' -TargetDomain 'fabrikam.com' -LiveVerify).Result | Should -Be 'Failed'
            Mock Invoke-ExternalCommand {
                if ($FilePath -eq 'netdom.exe') { return [pscustomobject]@{ Success = $true; ExitCode = 0; StdOut = 'The trust has been verified.' } }
                [pscustomobject]@{ Success = $true; ExitCode = 0; StdOut = 'unreadable' }
            }
            (Test-AdfaSecureChannel -SourceDomain 'contoso.com' -TargetDomain 'fabrikam.com' -LiveVerify).Result | Should -Be 'Verified'
        }
        It 'with the opt-in, fails a live test that prints an error status beside "completed successfully"' {
            Mock Test-CommandAvailable { $Name -eq 'nltest.exe' }
            Mock Invoke-ExternalCommand { [pscustomobject]@{ Success = $true; ExitCode = 0; StdOut = "Trust Verification Status = 1311 0x51f ERROR_NO_LOGON_SERVERS`nThe command completed successfully" } }
            (Test-AdfaSecureChannel -SourceDomain 'contoso.com' -TargetDomain 'fabrikam.com' -LiveVerify).Result | Should -Be 'Failed'
        }
        It 'runs /sc_verify only when asked, and says in the result that it can reset a channel' {
            Mock Test-CommandAvailable { $true }
            Mock Invoke-ExternalCommand { $script:H19Args += ("{0} {1}" -f $FilePath, $Arguments); [pscustomobject]@{ Success = $true; ExitCode = 0; StdOut = 'Trust Verification Status = 0x0 NERR_Success' } }
            $r = Test-AdfaSecureChannel -SourceDomain 'contoso.com' -TargetDomain 'fabrikam.com' -LiveVerify
            $r.Result | Should -Be 'Verified'
            @($script:H19Args | Where-Object { $_ -match 'nltest\.exe /sc_verify:fabrikam\.com' }).Count | Should -Be 1
            $r.Detail | Should -Match 'sc_verify'
        }
    }

    Context 'Test-AdfaRemoteSecureChannel (on a partner DC)' {
        It 'sends /sc_query to the partner DC by default' {
            Mock Test-TcpPort { $true }
            Mock Invoke-Command { $script:H19Remote = $ArgumentList; $script:ScOk }
            $r = Test-AdfaRemoteSecureChannel -PartnerDomain 'fabrikam.com' -VerifyDomain 'contoso.com' -PartnerDc 'dc1.fabrikam.com'
            $r.Result | Should -Be 'Verified'
            [string]@($script:H19Remote)[0] | Should -Be '/sc_query:contoso.com'
            $r.Detail | Should -Match 'not a live test'
            $r.Detail | Should -Match 'IncludeSecureChannelVerify'
        }
        It 'reports Failed for a non-zero status and Not Assessed for output it cannot read' {
            Mock Test-TcpPort { $true }
            Mock Invoke-Command { $script:ScBad }
            $bad = Test-AdfaRemoteSecureChannel -PartnerDomain 'fabrikam.com' -VerifyDomain 'contoso.com' -PartnerDc 'dc1.fabrikam.com'
            $bad.Result | Should -Be 'Failed'
            $bad.Detail | Should -Match 'not a live test'
            Mock Invoke-Command { 'The command completed successfully' }
            (Test-AdfaRemoteSecureChannel -PartnerDomain 'fabrikam.com' -VerifyDomain 'contoso.com' -PartnerDc 'dc1.fabrikam.com').Result | Should -Be 'Not Assessed'
        }
        It 'sends /sc_verify only when asked' {
            Mock Test-TcpPort { $true }
            Mock Invoke-Command { $script:H19Remote = $ArgumentList; 'Trust Verification Status = 0x0 NERR_Success' }
            Test-AdfaRemoteSecureChannel -PartnerDomain 'fabrikam.com' -VerifyDomain 'contoso.com' -PartnerDc 'dc1.fabrikam.com' -LiveVerify | Out-Null
            [string]@($script:H19Remote)[0] | Should -Be '/sc_verify:contoso.com'
        }
    }

    Context 'Get-AdfaDcSecureChannel (on every DC)' {
        BeforeEach {
            function Get-ADDomainController { param([Parameter(ValueFromRemainingArguments)]$a)
                [pscustomobject]@{ HostName = 'dc1.contoso.com'; ComputerObjectDN = 'CN=DC1,OU=Domain Controllers,DC=contoso,DC=com' } }
            function Get-ADComputer { param([Parameter(ValueFromRemainingArguments)]$a) [pscustomobject]@{ PasswordLastSet = (Get-Date).AddDays(-5) } }
        }
        It 'sends /sc_query to each DC by default and passes on a zero status' {
            Mock Test-TcpPort { $true }
            Mock Invoke-Command { $script:H19Remote = $ArgumentList; $script:ScOk }
            $rows = @(Get-AdfaDcSecureChannel -DomainName 'contoso.com' -AdParams @{})
            $row = @($rows | Where-Object { $_.Item -eq 'Secure channel: dc1.contoso.com' })[0]
            $row.Status | Should -Be 'Pass'
            [string]@($script:H19Remote)[0] | Should -Be '/sc_query:contoso.com'
            $row.Detail | Should -Match 'sc_query'
            $row.Detail | Should -Match 'IncludeSecureChannelVerify'
        }
        It 'fails a non-zero status, and is Not Assessed when the output cannot be read' {
            Mock Test-TcpPort { $true }
            Mock Invoke-Command { $script:ScBad }
            $failed = @(Get-AdfaDcSecureChannel -DomainName 'contoso.com' -AdParams @{}) | Where-Object { $_.Item -like 'Secure channel:*' }
            $failed.Status | Should -Be 'Fail'
            $failed.Detail | Should -Match 'not a live test'
            Mock Invoke-Command { 'unexpected text' }
            $na = @(Get-AdfaDcSecureChannel -DomainName 'contoso.com' -AdParams @{}) | Where-Object { $_.Item -like 'Secure channel:*' }
            $na.Status | Should -Be 'Not Assessed'
            $na.Detail | Should -Match 'unexpected text'
        }
        It 'sends /sc_verify only when asked' {
            Mock Test-TcpPort { $true }
            Mock Invoke-Command { $script:H19Remote = $ArgumentList; 'Trust Verification Status = 0x0 NERR_Success' }
            $rows = @(Get-AdfaDcSecureChannel -DomainName 'contoso.com' -AdParams @{} -LiveVerify)
            [string]@($script:H19Remote)[0] | Should -Be '/sc_verify:contoso.com'
            (@($rows | Where-Object { $_.Item -like 'Secure channel:*' })[0]).Status | Should -Be 'Pass'
        }
    }

    Context 'Wiring' {
        It 'declares -IncludeSecureChannelVerify as a switch that is off unless given' {
            $ast = [System.Management.Automation.Language.Parser]::ParseFile($script:Target, [ref]$null, [ref]$null)
            $p = @($ast.ParamBlock.Parameters | Where-Object { $_.Name.VariablePath.UserPath -eq 'IncludeSecureChannelVerify' })
            $p.Count | Should -Be 1
            $p[0].StaticType.Name | Should -Be 'SwitchParameter'
            $p[0].DefaultValue | Should -BeNullOrEmpty
        }
        It 'gives -LiveVerify only the value of the switch at every call in the script, never a bare or constant one' {
            # Read from the parsed commands. A text count of "-LiveVerify:$IncludeSecureChannelVerify"
            # passed with that text in a comment and a bare -LiveVerify on the real call.
            $ast = [System.Management.Automation.Language.Parser]::ParseFile($script:Target, [ref]$null, [ref]$null)
            $targets = @('Get-AdfaTrustHealth', 'Get-AdfaDcSecureChannel', 'Test-AdfaSecureChannel', 'Test-AdfaRemoteSecureChannel', 'Get-AdfaNltestScArgument')
            $calls = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true) |
                Where-Object { $targets -contains $_.GetCommandName() })
            # Declared population: 2 calls from Invoke-Main, 2 from the trust collector, 3 to the argument builder.
            $calls.Count | Should -Be 7
            $allowed = @{
                'Get-AdfaTrustHealth' = '$IncludeSecureChannelVerify'; 'Get-AdfaDcSecureChannel' = '$IncludeSecureChannelVerify'
                'Test-AdfaSecureChannel' = '$LiveVerify'; 'Test-AdfaRemoteSecureChannel' = '$LiveVerify'; 'Get-AdfaNltestScArgument' = '$LiveVerify'
            }
            foreach ($call in $calls) {
                $name = $call.GetCommandName()
                $live = @($call.CommandElements | Where-Object { $_ -is [System.Management.Automation.Language.CommandParameterAst] -and $_.ParameterName -eq 'LiveVerify' })
                $live.Count | Should -Be 1 -Because "$name must be told the mode explicitly (line $($call.Extent.StartLineNumber))"
                $live[0].Argument | Should -Not -BeNullOrEmpty -Because "a bare -LiveVerify on $name would force the live test (line $($call.Extent.StartLineNumber))"
                $live[0].Argument.Extent.Text | Should -Be $allowed[$name] -Because "line $($call.Extent.StartLineNumber)"
            }
        }
        It 'passes it from the trust collector to both directions' {
            $script:H19Live = @()
            function Get-ADTrust { param([Parameter(ValueFromRemainingArguments)]$a)
                [pscustomobject]@{ Name = 'fabrikam.com'; Source = 'contoso.com'; Target = 'fabrikam.com'; Direction = 'Bidirectional'; TrustType = 'Forest'
                    IntraForest = $false; ForestTransitive = $true; SelectiveAuthentication = $false; SIDFilteringForestAware = $false
                    SIDFilteringQuarantined = $true; TGTDelegation = $false; UsesRC4Encryption = $false; Created = (Get-Date); Modified = (Get-Date) } }
            Mock Test-CommandAvailable { $false }
            Mock Test-TcpPort { $true }
            Mock Test-AdfaSecureChannel { $script:H19Live += ("out:{0}" -f [bool]$LiveVerify); [pscustomobject]@{ Result = 'Verified'; Tool = 't'; Detail = 'd' } }
            Mock Test-AdfaRemoteSecureChannel { $script:H19Live += ("in:{0}" -f [bool]$LiveVerify); [pscustomobject]@{ Result = 'Verified'; Tool = 't'; Detail = 'd' } }
            Get-AdfaTrustHealth -DomainName 'contoso.com' -AdParams @{} | Out-Null
            ($script:H19Live -join ',') | Should -Be 'out:False,in:False'
            $script:H19Live = @()
            Get-AdfaTrustHealth -DomainName 'contoso.com' -AdParams @{} -LiveVerify | Out-Null
            ($script:H19Live -join ',') | Should -Be 'out:True,in:True'
        }
    }
}

Describe 'DC system: OS lifecycle and patch level (C1)' {
    BeforeAll {
        $script:Dsc = $script:Config.DcSystem
        $script:Life = $script:Dsc.OsLifecycle
        $script:Today = [datetime]'2026-11-13'
        # Held in a variable: PSAvoidUsingComputerNameHardcoded flags a literal -ComputerName.
        $script:C1Dc = 'dc1.contoso.com'
        function Get-C1Row {
            param($Rows, [string]$Item)
            $m = @($Rows | Where-Object { [string]$_.Item -eq $Item })
            if ($m.Count -eq 0) { return $null }
            return $m[0]
        }
        function New-C1Dc {
            param([string]$Name, [string]$Os, [string]$Ver, [string]$Err = '')
            [pscustomobject]@{ Scope = 'contoso.com'; HostName = $Name; OperatingSystem = $Os; OperatingSystemVersion = $Ver; EnrichmentError = $Err }
        }
    }

    Context 'Section wiring' {
        It 'is a value of the -Sections ValidateSet, read from the parsed parameter and not from the text' {
            # A text match for 'DcSystem' passes on any of a dozen other uses of the word. The
            # parameter attribute is what decides whether -Sections DcSystem binds at all.
            $ast = [System.Management.Automation.Language.Parser]::ParseFile($script:Target, [ref]$null, [ref]$null)
            $param = @($ast.ParamBlock.Parameters | Where-Object { $_.Name.VariablePath.UserPath -eq 'Sections' })
            $param.Count | Should -Be 1
            $set = @($param[0].Attributes | Where-Object { $_.TypeName.Name -eq 'ValidateSet' })
            $set.Count | Should -Be 1
            $values = @($set[0].PositionalArguments | ForEach-Object { $_.Value })
            $values | Should -Contain 'DcSystem'
            $values | Should -Contain 'DomainControllers'   # non-vacuity: the list really was read
        }
        It 'has a branch in Invoke-Main' {
            (Get-Content -LiteralPath $script:Target -Raw) | Should -Match "Test-SectionSelected 'DcSystem'"
        }
    }

    Context 'Config table' {
        It 'records its source and read date, and one row per supported release' {
            [string]$script:Dsc.SourceUrl | Should -Match '^https://learn\.microsoft\.com/'
            [string]$script:Dsc.ReadDate | Should -Match '^\d{4}-\d{2}-\d{2}$'
            $labels = @($script:Life | ForEach-Object { [string]$_.Label })
            # Declared population: the six releases the table is meant to hold.
            foreach ($l in @('Windows Server 2025', 'Windows Server 2022', 'Windows Server 2019', 'Windows Server 2016', 'Windows Server 2012 R2', 'Windows Server 2012')) {
                $labels | Should -Contain $l
            }
            $labels.Count | Should -Be 6
        }
        It 'holds $null, not a guessed date, where no ESU programme is published' {
            foreach ($l in @('Windows Server 2025', 'Windows Server 2022', 'Windows Server 2019')) {
                ($script:Life | Where-Object { $_.Label -eq $l }).EsuEnd | Should -BeNullOrEmpty -Because "$l has no published ESU end date"
            }
            ($script:Life | Where-Object { $_.Label -eq 'Windows Server 2016' }).EsuEnd | Should -Be '2030-01-08'
        }
    }

    Context 'Get-AdfaOsBuild' {
        It 'reads the build from the parenthesised part and nothing else' {
            Get-AdfaOsBuild -OperatingSystemVersion '10.0 (17763)' | Should -Be 17763
            Get-AdfaOsBuild -OperatingSystemVersion '6.3 (9600)' | Should -Be 9600
            Get-AdfaOsBuild -OperatingSystemVersion '10.0' | Should -BeNullOrEmpty
            Get-AdfaOsBuild -OperatingSystemVersion '' | Should -BeNullOrEmpty
            Get-AdfaOsBuild -OperatingSystemVersion 'Not Assessed' | Should -BeNullOrEmpty
        }
    }

    Context 'Get-AdfaOsLifecycleVerdict' {
        It 'passes an OS inside extended support and states the end date' {
            $v = Get-AdfaOsLifecycleVerdict -OperatingSystem 'Windows Server 2019 Datacenter' -OperatingSystemVersion '10.0 (17763)' -Today $script:Today -Entries $script:Life
            $v.Status | Should -Be 'Pass'
            $v.Detail | Should -Match '2029-01-09'
        }
        It 'fails an OS past extended support whose ESU window is still open, and says ESU enrolment is not assessed' {
            $after = [datetime]'2027-02-01'   # 2016: extended ended 2027-01-12, ESU runs to 2030-01-08
            $v = Get-AdfaOsLifecycleVerdict -OperatingSystem 'Windows Server 2016 Standard' -OperatingSystemVersion '10.0 (14393)' -Today $after -Entries $script:Life
            $v.Status | Should -Be 'Fail'
            $v.Detail | Should -Match '2027-01-12'
            $v.Detail | Should -Match '2030-01-08'
            $v.Detail | Should -Match 'not assessed'
        }
        It 'fails an OS whose ESU programme has also ended, and says so' {
            $v = Get-AdfaOsLifecycleVerdict -OperatingSystem 'Windows Server 2012 R2 Standard' -OperatingSystemVersion '6.3 (9600)' -Today $script:Today -Entries $script:Life
            $v.Status | Should -Be 'Fail'
            $v.Detail | Should -Match '2023-10-10'
            $v.Detail | Should -Match 'ended on 2026-10-13'
        }
        It 'fails past extended support with no published ESU date, and says the date is not published' {
            $far = [datetime]'2030-06-01'   # 2019: extended ended 2029-01-09, no ESU published
            $v = Get-AdfaOsLifecycleVerdict -OperatingSystem 'Windows Server 2019' -OperatingSystemVersion '10.0 (17763)' -Today $far -Entries $script:Life
            $v.Status | Should -Be 'Fail'
            $v.Detail | Should -Match 'ESU end date not published'
        }
        It 'treats the end date itself as still supported and the next day as past' {
            $on = Get-AdfaOsLifecycleVerdict -OperatingSystem 'Windows Server 2016' -OperatingSystemVersion '10.0 (14393)' -Today ([datetime]'2027-01-12') -Entries $script:Life
            $on.Status | Should -Be 'Pass'
            $next = Get-AdfaOsLifecycleVerdict -OperatingSystem 'Windows Server 2016' -OperatingSystemVersion '10.0 (14393)' -Today ([datetime]'2027-01-13') -Entries $script:Life
            $next.Status | Should -Be 'Fail'
        }
        It 'does not identify a release from the build alone: a Semi-Annual Channel DC sharing build 17763 is not passed as 2019' {
            # "Windows Server, version 1809" reports no year in its name and shares build 17763
            # with Windows Server 2019, whose dates are not its dates.
            $v = Get-AdfaOsLifecycleVerdict -OperatingSystem 'Windows Server Datacenter' -OperatingSystemVersion '10.0 (17763)' -Today $script:Today -Entries $script:Life
            $v.Status | Should -Be 'Not Assessed'
            $v.Detail | Should -Match 'Windows Server Datacenter'
            $v.Detail | Should -Match '10\.0 \(17763\)'
            $v.Detail | Should -Match 'build number alone does not identify'
        }
        It 'refuses to pick a side when the name and the build point at different releases' {
            $v = Get-AdfaOsLifecycleVerdict -OperatingSystem 'Windows Server 2012 R2 Standard' -OperatingSystemVersion '10.0 (26100)' -Today $script:Today -Entries $script:Life
            $v.Status | Should -Be 'Not Assessed'   # by name alone this is a Fail, by build alone a Pass
            $v.Detail | Should -Match 'Windows Server 2025'
            $v.Detail | Should -Match 'Windows Server 2012 R2'
            $w = Get-AdfaOsLifecycleVerdict -OperatingSystem 'Windows Server 2019 Standard' -OperatingSystemVersion '10.0 (99999)' -Today $script:Today -Entries $script:Life
            $w.Status | Should -Be 'Not Assessed'
            $w.Detail | Should -Match '99999'
        }
        It 'identifies a release when name and build agree' {
            $v = Get-AdfaOsLifecycleVerdict -OperatingSystem 'Windows Server 2022 Datacenter' -OperatingSystemVersion '10.0 (20348)' -Today $script:Today -Entries $script:Life
            $v.Status | Should -Be 'Pass'
            $v.Detail | Should -Match 'Windows Server 2022 \('
        }
        It 'falls back to the name when the version carries no build, and keeps 2012 apart from 2012 R2' {
            (Get-AdfaOsLifecycleVerdict -OperatingSystem 'Windows Server 2019' -OperatingSystemVersion '10.0' -Today $script:Today -Entries $script:Life).Status | Should -Be 'Pass'
            (Get-AdfaOsLifecycleVerdict -OperatingSystem 'Windows Server 2012 Standard' -OperatingSystemVersion '6.2 (9200)' -Today $script:Today -Entries $script:Life).Detail | Should -Match 'Windows Server 2012 \('
            (Get-AdfaOsLifecycleVerdict -OperatingSystem 'Windows Server 2012 R2 Standard' -OperatingSystemVersion '6.3 (9600)' -Today $script:Today -Entries $script:Life).Detail | Should -Match 'Windows Server 2012 R2 \('
        }
        It 'reports an OS that is not in the table as Not Assessed with the raw values, never Pass and never Fail' {
            $v = Get-AdfaOsLifecycleVerdict -OperatingSystem 'Windows Server 2008 R2 Enterprise' -OperatingSystemVersion '6.1 (7601)' -Today $script:Today -Entries $script:Life
            $v.Status | Should -Be 'Not Assessed'
            $v.Detail | Should -Match 'Windows Server 2008 R2 Enterprise'
            $v.Detail | Should -Match '6\.1 \(7601\)'
        }
        It 'reports an unreadable OS as Not Assessed with the cause the inventory recorded' {
            $v = Get-AdfaOsLifecycleVerdict -OperatingSystem 'Not Assessed' -OperatingSystemVersion 'Not Assessed' -EnrichmentError 'Access is denied' -Today $script:Today -Entries $script:Life
            $v.Status | Should -Be 'Not Assessed'
            $v.Detail | Should -Match 'Access is denied'
            (Get-AdfaOsLifecycleVerdict -OperatingSystem '' -OperatingSystemVersion '' -Today $script:Today -Entries $script:Life).Status | Should -Be 'Not Assessed'
        }
    }

    Context 'Get-AdfaDcOsLifecycle' {
        It 'gives one row per DC, carries the domain as Scope, and handles a mixed set' {
            $dcs = @(
                (New-C1Dc 'dc1.contoso.com' 'Windows Server 2022 Standard' '10.0 (20348)'),
                (New-C1Dc 'dc2.contoso.com' 'Windows Server 2012 R2 Standard' '6.3 (9600)'),
                (New-C1Dc 'dc3.contoso.com' 'Not Assessed' 'Not Assessed' 'A referral was returned from the server')
            )
            $rows = @(Get-AdfaDcOsLifecycle -DomainControllers $dcs -Config $script:Dsc -Today $script:Today)
            $rows.Count | Should -Be 3
            (Get-C1Row $rows 'OS lifecycle: dc1.contoso.com').Status | Should -Be 'Pass'
            (Get-C1Row $rows 'OS lifecycle: dc2.contoso.com').Status | Should -Be 'Fail'
            $r3 = Get-C1Row $rows 'OS lifecycle: dc3.contoso.com'
            $r3.Status | Should -Be 'Not Assessed'
            $r3.Detail | Should -Match 'referral'
            @($rows | Where-Object { $_.Scope -eq 'contoso.com' }).Count | Should -Be 3
        }
        It 'gives a domain whose inventory failed its own Not Assessed row, beside the DCs that were read' {
            $dcs = @((New-C1Dc 'dc1.contoso.com' 'Windows Server 2022 Standard' '10.0 (20348)'))
            $failed = @([pscustomobject]@{ Domain = 'child.contoso.com'; Error = 'The server is not operational' })
            $rows = @(Get-AdfaDcOsLifecycle -DomainControllers $dcs -Config $script:Dsc -Today $script:Today -InventoryFailures $failed)
            $rows.Count | Should -Be 2
            $gap = Get-C1Row $rows 'OS lifecycle - child.contoso.com'
            $gap.Status | Should -Be 'Not Assessed'
            $gap.Scope | Should -Be 'child.contoso.com'
            $gap.Detail | Should -Match 'not operational'
            (Get-C1Row $rows 'OS lifecycle: dc1.contoso.com').Status | Should -Be 'Pass'
        }
        It 'cites both source pages, because neither holds every date' {
            $row = @(Get-AdfaDcOsLifecycle -DomainControllers @((New-C1Dc 'dc1.contoso.com' 'Windows Server 2019' '10.0 (17763)')) -Config $script:Dsc -Today $script:Today)[0]
            $row.Detail | Should -Match 'windows-server-release-info'
            $row.Detail | Should -Match 'extended-security-updates'
        }
        It 'reports Not Assessed, naming the section to add, when there is no DC inventory' {
            $rows = @(Get-AdfaDcOsLifecycle -DomainControllers @() -Config $script:Dsc -Today $script:Today)
            $rows.Count | Should -Be 1
            $rows[0].Status | Should -Be 'Not Assessed'
            $rows[0].Detail | Should -Match 'DomainControllers'
        }
        It 'gives a failing DC a recommendation and does not let a later generic entry answer for it' {
            $dcs = @((New-C1Dc 'dc2.contoso.com' 'Windows Server 2012 R2 Standard' '6.3 (9600)'))
            $row = @(Get-AdfaDcOsLifecycle -DomainControllers $dcs -Config $script:Dsc -Today $script:Today)[0]
            $rec = Get-AdfaRecommendation -Section 'DC System' -Item ([string]$row.Item) -Detail ([string]$row.Detail)
            $rec | Should -Match 'supported Windows Server'
            $rec | Should -Not -Match 'backup|scavenging|w32tm'
        }
    }

    Context 'Hotfix install dates' {
        It 'converts a DateTime, an ISO date and a hex FILETIME' {
            ConvertTo-AdfaHotfixDate -Value ([datetime]'2026-11-10') | Should -Be ([datetime]'2026-11-10')
            ConvertTo-AdfaHotfixDate -Value '2026-11-10' | Should -Be ([datetime]'2026-11-10')
            $ft = ([datetime]::SpecifyKind([datetime]'2026-11-10', 'Utc')).ToFileTimeUtc().ToString('x16')
            (ConvertTo-AdfaHotfixDate -Value $ft).ToString('yyyy-MM-dd') | Should -Be '2026-11-10'
        }
        It 'refuses to guess an ambiguous day/month order, and returns nothing for junk' {
            ConvertTo-AdfaHotfixDate -Value '11/10/2026' | Should -BeNullOrEmpty
            ConvertTo-AdfaHotfixDate -Value '11/10/2026' -Order 'MonthFirst' | Should -Be ([datetime]'2026-11-10')
            ConvertTo-AdfaHotfixDate -Value '11/10/2026' -Order 'DayFirst' | Should -Be ([datetime]'2026-10-11')
            ConvertTo-AdfaHotfixDate -Value '23-10-2013' | Should -Be ([datetime]'2013-10-23')   # day > 12 settles it
            ConvertTo-AdfaHotfixDate -Value '10/23/2013' | Should -Be ([datetime]'2013-10-23')
            foreach ($junk in @('', $null, 'abc', '13/13/2020', '0/0/0')) { ConvertTo-AdfaHotfixDate -Value $junk | Should -BeNullOrEmpty }
        }
        It 'infers the order for a whole set from its unambiguous members, and refuses when they disagree' {
            Get-AdfaHotfixDateOrder -Values @('11/10/2026', '10/23/2026') | Should -Be 'MonthFirst'
            Get-AdfaHotfixDateOrder -Values @('11/10/2026', '23/10/2026') | Should -Be 'DayFirst'
            Get-AdfaHotfixDateOrder -Values @('11/10/2026', '10/11/2026') | Should -Be 'Unknown'
            Get-AdfaHotfixDateOrder -Values @('10/23/2026', '23/10/2026') | Should -Be 'Unknown'
        }
        It 'summarises a set: latest date, and how many could not be read' {
            $s = Get-AdfaHotfixSummary -InstalledOn @('11/10/2026', '10/23/2026', 'garbage')
            $s.Total | Should -Be 3
            $s.Parsed | Should -Be 2
            $s.Unparsed | Should -Be 1
            $s.Latest.ToString('yyyy-MM-dd') | Should -Be '2026-11-10'
            $none = Get-AdfaHotfixSummary -InstalledOn @()
            $none.Total | Should -Be 0
            $none.Latest | Should -BeNullOrEmpty
            $amb = Get-AdfaHotfixSummary -InstalledOn @('11/10/2026', '01/02/2026')
            $amb.Parsed | Should -Be 0
            $amb.Latest | Should -BeNullOrEmpty
            (Get-AdfaHotfixSummary -InstalledOn $null).Total | Should -Be 0
        }
    }

    Context 'Remote read failure classes' {
        It 'separates access denied from every other failure' {
            Get-AdfaRemoteReadErrorClass -Message 'Access is denied.' | Should -Be 'AccessDenied'
            Get-AdfaRemoteReadErrorClass -Message 'Access denied ' | Should -Be 'AccessDenied'
            Get-AdfaRemoteReadErrorClass -Message 'HRESULT 0x80070005' | Should -Be 'AccessDenied'
            Get-AdfaRemoteReadErrorClass -Message 'The WinRM client cannot process the request.' | Should -Be 'Error'
            Get-AdfaRemoteReadErrorClass -Message '' | Should -Be 'Error'
        }
        It 'recognises a refusal by its error code when the message is not in English' {
            Get-AdfaRemoteReadErrorClass -Message 'Acesso negado.' | Should -Be 'Error'   # text alone cannot tell
            Get-AdfaRemoteReadErrorClass -Message 'Acesso negado.' -ErrorCode 'AccessDenied' | Should -Be 'AccessDenied'
            Get-AdfaRemoteReadErrorClass -Message 'Zugriff verweigert' -ErrorCode 'Failed' | Should -Be 'Error'
        }
    }

    Context 'Test-AdfaDcPort probes a DC once per port' {
        It 'asks the network once and answers from the cache afterwards' {
            $script:C1Probes = 0
            function Test-TcpPort { param([string]$ComputerName, [int]$Port, [int]$TimeoutMs) $script:C1Probes++; return ($Port -eq 135) }
            Clear-AdfaDcPortCache
            Test-AdfaDcPort -ComputerName $script:C1Dc -Port 135 -TimeoutMs 100 | Should -BeTrue
            Test-AdfaDcPort -ComputerName $script:C1Dc.ToUpperInvariant() -Port 135 -TimeoutMs 100 | Should -BeTrue
            Test-AdfaDcPort -ComputerName $script:C1Dc -Port 5985 -TimeoutMs 100 | Should -BeFalse
            Test-AdfaDcPort -ComputerName $script:C1Dc -Port 5985 -TimeoutMs 100 | Should -BeFalse
            $script:C1Probes | Should -Be 2
            Clear-AdfaDcPortCache
            Test-AdfaDcPort -ComputerName $script:C1Dc -Port 135 -TimeoutMs 100 | Out-Null
            $script:C1Probes | Should -Be 3
        }
    }

    Context 'Get-AdfaDcPatchLevel' {
        BeforeEach { Clear-AdfaDcPortCache }
        It 'reports build, uptime and last update for a DC that answers' {
            function Test-TcpPort { param([string]$ComputerName, [int]$Port, [int]$TimeoutMs) return $true }
            function Get-AdfaDcSystemRaw {
                param([string]$ComputerName, [string]$Protocol, [pscredential]$Credential, [int]$OperationTimeoutSec)
                [pscustomobject]@{ Ok = $true; Protocol = $Protocol; LastBootUpTime = [datetime]'2026-11-01 06:00:00'; BuildNumber = '20348'; Version = '10.0.20348'
                    HotfixOk = $true; InstalledOn = @('11/10/2026', '10/23/2026'); Error = ''; HotfixError = '' }
            }
            $rows = @(Get-AdfaDcPatchLevel -DomainControllers @('dc1.contoso.com') -Config $script:Dsc -Now ([datetime]'2026-11-13 06:00:00'))
            $os = Get-C1Row $rows 'OS build and uptime: dc1.contoso.com'
            $os.Status | Should -Be 'Info'
            $os.Detail | Should -Match '20348'
            $os.Detail | Should -Match '12 day'
            $hf = Get-C1Row $rows 'Last update installed: dc1.contoso.com'
            $hf.Status | Should -Be 'Info'
            $hf.Detail | Should -Match '2026-11-10'
        }
        It 'reports Not Assessed, never a clean result, when there are no DCs' {
            $rows = @(Get-AdfaDcPatchLevel -DomainControllers @() -Config $script:Dsc -Now $script:Today)
            $rows.Count | Should -Be 1
            $rows[0].Status | Should -Be 'Not Assessed'
        }
        It 'reports an unreachable DC as unreachable, without attempting a read' {
            $script:C1Reads = 0
            function Test-TcpPort { param([string]$ComputerName, [int]$Port, [int]$TimeoutMs) return $false }
            function Get-AdfaDcSystemRaw { param([string]$ComputerName, [string]$Protocol, [pscredential]$Credential, [int]$OperationTimeoutSec) $script:C1Reads++ }
            $rows = @(Get-AdfaDcPatchLevel -DomainControllers @('dc9.contoso.com') -Config $script:Dsc -Now $script:Today)
            $rows.Count | Should -Be 1
            $rows[0].Status | Should -Be 'Not Assessed'
            $rows[0].Detail | Should -Match '(?i)unreachable'
            $rows[0].Detail | Should -Match '5985'
            $script:C1Reads | Should -Be 0
        }
        It 'reports access denied as access denied, not as unreachable' {
            function Test-TcpPort { param([string]$ComputerName, [int]$Port, [int]$TimeoutMs) return $true }
            function Get-AdfaDcSystemRaw {
                param([string]$ComputerName, [string]$Protocol, [pscredential]$Credential, [int]$OperationTimeoutSec)
                [pscustomobject]@{ Ok = $false; Protocol = $Protocol; LastBootUpTime = $null; BuildNumber = ''; Version = ''; HotfixOk = $false; InstalledOn = @(); Error = 'Access is denied.'; HotfixError = '' }
            }
            $rows = @(Get-AdfaDcPatchLevel -DomainControllers @('dc1.contoso.com') -Config $script:Dsc -Now $script:Today)
            $rows.Count | Should -Be 1
            $rows[0].Status | Should -Be 'Not Assessed'
            $rows[0].Detail | Should -Match '(?i)access denied'
            $rows[0].Detail | Should -Not -Match '(?i)unreachable'
            $rows[0].Detail | Should -Match 'Access is denied\.'
        }
        It 'handles a mixed set: one DC read, one unreachable, one with no update records' {
            function Test-TcpPort { param([string]$ComputerName, [int]$Port, [int]$TimeoutMs) return ($ComputerName -ne 'dc2.contoso.com') }
            function Get-AdfaDcSystemRaw {
                param([string]$ComputerName, [string]$Protocol, [pscredential]$Credential, [int]$OperationTimeoutSec)
                $dates = @('2026-11-10')
                if ($ComputerName -eq 'dc3.contoso.com') { $dates = @() }
                [pscustomobject]@{ Ok = $true; Protocol = $Protocol; LastBootUpTime = [datetime]'2026-11-12'; BuildNumber = '17763'; Version = '10.0.17763'
                    HotfixOk = $true; InstalledOn = $dates; Error = ''; HotfixError = '' }
            }
            $rows = @(Get-AdfaDcPatchLevel -DomainControllers @('dc1.contoso.com', 'dc2.contoso.com', 'dc3.contoso.com') -Config $script:Dsc -Now $script:Today)
            (Get-C1Row $rows 'Last update installed: dc1.contoso.com').Status | Should -Be 'Info'
            (Get-C1Row $rows 'Patch level: dc2.contoso.com').Status | Should -Be 'Not Assessed'
            $zero = Get-C1Row $rows 'Last update installed: dc3.contoso.com'
            $zero.Status | Should -Be 'Not Assessed'
            $zero.Detail | Should -Match '0 records'
            (Get-C1Row $rows 'OS build and uptime: dc3.contoso.com').Status | Should -Be 'Info'
            # No row in this section is ever a Pass: it is inventory.
            @($rows | Where-Object { $_.Status -eq 'Pass' }).Count | Should -Be 0
        }
        It 'tries WinRM first and DCOM second, and reports which one answered' {
            $script:C1Calls = @()
            function Test-TcpPort { param([string]$ComputerName, [int]$Port, [int]$TimeoutMs) return $true }
            function Get-AdfaDcSystemRaw {
                param([string]$ComputerName, [string]$Protocol, [pscredential]$Credential, [int]$OperationTimeoutSec)
                $script:C1Calls += $Protocol
                if ($Protocol -eq 'Wsman') {
                    return [pscustomobject]@{ Ok = $false; Protocol = $Protocol; LastBootUpTime = $null; BuildNumber = ''; Version = ''; HotfixOk = $false; InstalledOn = @(); Error = 'The WinRM client cannot process the request.'; ErrorCode = 'Failed'; HotfixError = '' }
                }
                [pscustomobject]@{ Ok = $true; Protocol = $Protocol; LastBootUpTime = [datetime]'2026-11-12'; BuildNumber = '17763'; Version = '10.0.17763'
                    HotfixOk = $true; InstalledOn = @('2026-11-10'); Error = ''; ErrorCode = ''; HotfixError = '' }
            }
            $rows = @(Get-AdfaDcPatchLevel -DomainControllers @('dc1.contoso.com') -Config $script:Dsc -Now $script:Today)
            ($script:C1Calls -join ',') | Should -Be 'Wsman,Dcom'
            (Get-C1Row $rows 'OS build and uptime: dc1.contoso.com').Detail | Should -Match 'Read over Dcom'
        }
        It 'does not retry a refusal over the second transport, even when the refusal is not in English' {
            $script:C1Calls = @()
            function Test-TcpPort { param([string]$ComputerName, [int]$Port, [int]$TimeoutMs) return $true }
            function Get-AdfaDcSystemRaw {
                param([string]$ComputerName, [string]$Protocol, [pscredential]$Credential, [int]$OperationTimeoutSec)
                $script:C1Calls += $Protocol
                [pscustomobject]@{ Ok = $false; Protocol = $Protocol; LastBootUpTime = $null; BuildNumber = ''; Version = ''; HotfixOk = $false; InstalledOn = @(); Error = 'Acesso negado.'; ErrorCode = 'AccessDenied'; HotfixError = '' }
            }
            $rows = @(Get-AdfaDcPatchLevel -DomainControllers @('dc1.contoso.com') -Config $script:Dsc -Now $script:Today)
            ($script:C1Calls -join ',') | Should -Be 'Wsman'
            $rows[0].Detail | Should -Match '(?i)^Access denied'
            $rows[0].Detail | Should -Match 'Acesso negado'
        }
        It 'reports any other failure as a read failure, with both attempts quoted, and not as a refusal' {
            function Test-TcpPort { param([string]$ComputerName, [int]$Port, [int]$TimeoutMs) return $true }
            function Get-AdfaDcSystemRaw {
                param([string]$ComputerName, [string]$Protocol, [pscredential]$Credential, [int]$OperationTimeoutSec)
                [pscustomobject]@{ Ok = $false; Protocol = $Protocol; LastBootUpTime = $null; BuildNumber = ''; Version = ''; HotfixOk = $false; InstalledOn = @(); Error = "The RPC server is unavailable ($Protocol)."; ErrorCode = 'Failed'; HotfixError = '' }
            }
            $rows = @(Get-AdfaDcPatchLevel -DomainControllers @('dc1.contoso.com') -Config $script:Dsc -Now $script:Today)
            $rows.Count | Should -Be 1
            $rows[0].Status | Should -Be 'Not Assessed'
            $rows[0].Detail | Should -Match '^Read failed'
            $rows[0].Detail | Should -Not -Match '^Access denied'
            $rows[0].Detail | Should -Match 'unavailable \(Wsman\)'
            $rows[0].Detail | Should -Match 'unavailable \(Dcom\)'
        }
        It 'uses only the transport whose port answered' {
            $script:C1Calls = @()
            function Test-TcpPort { param([string]$ComputerName, [int]$Port, [int]$TimeoutMs) return ($Port -eq 135) }
            function Get-AdfaDcSystemRaw {
                param([string]$ComputerName, [string]$Protocol, [pscredential]$Credential, [int]$OperationTimeoutSec)
                $script:C1Calls += $Protocol
                [pscustomobject]@{ Ok = $true; Protocol = $Protocol; LastBootUpTime = [datetime]'2026-11-12'; BuildNumber = '17763'; Version = '10.0.17763'
                    HotfixOk = $true; InstalledOn = @('2026-11-10'); Error = ''; ErrorCode = ''; HotfixError = '' }
            }
            Get-AdfaDcPatchLevel -DomainControllers @('dc1.contoso.com') -Config $script:Dsc -Now $script:Today | Out-Null
            ($script:C1Calls -join ',') | Should -Be 'Dcom'
        }
        It 'reports Not Assessed, not Info, when the class answered but returned neither build nor boot time' {
            function Test-TcpPort { param([string]$ComputerName, [int]$Port, [int]$TimeoutMs) return $true }
            function Get-AdfaDcSystemRaw {
                param([string]$ComputerName, [string]$Protocol, [pscredential]$Credential, [int]$OperationTimeoutSec)
                [pscustomobject]@{ Ok = $true; Protocol = $Protocol; LastBootUpTime = $null; BuildNumber = ''; Version = ''; HotfixOk = $true; InstalledOn = @('2026-11-10'); Error = ''; ErrorCode = ''; HotfixError = '' }
            }
            $rows = @(Get-AdfaDcPatchLevel -DomainControllers @('dc1.contoso.com') -Config $script:Dsc -Now $script:Today)
            (Get-C1Row $rows 'OS build and uptime: dc1.contoso.com').Status | Should -Be 'Not Assessed'
        }
        It 'never grades: every row in every outcome above is Info or Not Assessed' {
            function Test-TcpPort { param([string]$ComputerName, [int]$Port, [int]$TimeoutMs) return ($ComputerName -ne 'dc2.contoso.com') }
            function Get-AdfaDcSystemRaw {
                param([string]$ComputerName, [string]$Protocol, [pscredential]$Credential, [int]$OperationTimeoutSec)
                if ($ComputerName -eq 'dc3.contoso.com') { return [pscustomobject]@{ Ok = $false; Protocol = $Protocol; LastBootUpTime = $null; BuildNumber = ''; Version = ''; HotfixOk = $false; InstalledOn = @(); Error = 'Access is denied.'; ErrorCode = 'AccessDenied'; HotfixError = '' } }
                $dates = @('11/10/2026', '10/23/2026')
                if ($ComputerName -eq 'dc4.contoso.com') { $dates = @() }
                if ($ComputerName -eq 'dc5.contoso.com') { $dates = @('11/10/2026') }
                [pscustomobject]@{ Ok = $true; Protocol = $Protocol; LastBootUpTime = [datetime]'2020-01-01'; BuildNumber = '14393'; Version = '10.0.14393'
                    HotfixOk = $true; InstalledOn = $dates; Error = ''; ErrorCode = ''; HotfixError = '' }
            }
            $names = @('dc1.contoso.com', 'dc2.contoso.com', 'dc3.contoso.com', 'dc4.contoso.com', 'dc5.contoso.com')
            $rows = @(Get-AdfaDcPatchLevel -DomainControllers $names -Config $script:Dsc -Now $script:Today)
            # Declared population: 2 rows for each of dc1, dc4, dc5 that were read; 1 each for dc2, dc3.
            $rows.Count | Should -Be 8
            @($rows | Where-Object { @('Info', 'Not Assessed') -notcontains [string]$_.Status }).Count | Should -Be 0
            # A six-year uptime is still Info: no threshold exists to grade it against.
            (Get-C1Row $rows 'OS build and uptime: dc1.contoso.com').Status | Should -Be 'Info'
        }
        It 'keeps the OS row when only the update query failed, and says which half failed' {
            function Test-TcpPort { param([string]$ComputerName, [int]$Port, [int]$TimeoutMs) return $true }
            function Get-AdfaDcSystemRaw {
                param([string]$ComputerName, [string]$Protocol, [pscredential]$Credential, [int]$OperationTimeoutSec)
                [pscustomobject]@{ Ok = $true; Protocol = $Protocol; LastBootUpTime = [datetime]'2026-11-12'; BuildNumber = '26100'; Version = '10.0.26100'
                    HotfixOk = $false; InstalledOn = @(); Error = ''; HotfixError = 'The operation has timed out.' }
            }
            $rows = @(Get-AdfaDcPatchLevel -DomainControllers @('dc1.contoso.com') -Config $script:Dsc -Now $script:Today)
            (Get-C1Row $rows 'OS build and uptime: dc1.contoso.com').Status | Should -Be 'Info'
            $hf = Get-C1Row $rows 'Last update installed: dc1.contoso.com'
            $hf.Status | Should -Be 'Not Assessed'
            $hf.Detail | Should -Match 'timed out'
        }
    }

    Context 'Get-AdfaDcSystemRaw (the CIM seam)' {
        BeforeAll {
            function New-CimSessionOption { param([string]$Protocol) [pscustomobject]@{ Protocol = $Protocol } }
            function Remove-CimSession { param([Parameter(ValueFromRemainingArguments)]$a) }
        }
        It 'returns the two classes in one shape, and closes the session' {
            $script:C1Closed = 0
            function New-CimSession { param([string]$ComputerName, $SessionOption, [uint32]$OperationTimeoutSec, [pscredential]$Credential, $ErrorAction) [pscustomobject]@{ ComputerName = $ComputerName } }
            function Remove-CimSession { param([Parameter(ValueFromRemainingArguments)]$a) $script:C1Closed++ }
            function Get-CimInstance {
                param($CimSession, [string]$ClassName, [string[]]$Property, [uint32]$OperationTimeoutSec, $ErrorAction)
                if ($ClassName -eq 'Win32_OperatingSystem') { return [pscustomobject]@{ LastBootUpTime = [datetime]'2026-11-01'; BuildNumber = '17763'; Version = '10.0.17763' } }
                return @([pscustomobject]@{ HotFixID = 'KB1'; InstalledOn = [datetime]'2026-11-10' }, [pscustomobject]@{ HotFixID = 'KB2'; InstalledOn = $null })
            }
            $r = Get-AdfaDcSystemRaw -ComputerName $script:C1Dc -Protocol 'Wsman' -OperationTimeoutSec 30
            $r.Ok | Should -BeTrue
            $r.BuildNumber | Should -Be '17763'
            $r.HotfixOk | Should -BeTrue
            @($r.InstalledOn).Count | Should -Be 2
            $script:C1Closed | Should -Be 1
        }
        It 'reads the RAW InstalledOn, not the DateTime the 5.1 type adapter puts in its place' {
            # Shape measured on a real Get-CimInstance result under Windows PowerShell 5.1: the
            # InstalledOn member is a DateTime produced by [DateTime]::Parse, and the string the
            # DC actually returned is in CimInstanceProperties. The adapter guesses month-first
            # and yields nothing for a day-first date, so only the raw value may be used.
            function New-CimSession { param([Parameter(ValueFromRemainingArguments)]$a) [pscustomobject]@{ ComputerName = 'x' } }
            function Get-CimInstance {
                param($CimSession, [string]$ClassName, [string[]]$Property, [uint32]$OperationTimeoutSec, $ErrorAction)
                if ($ClassName -eq 'Win32_OperatingSystem') { return [pscustomobject]@{ LastBootUpTime = [datetime]'2026-11-01'; BuildNumber = '17763'; Version = '10.0.17763' } }
                return @(
                    [pscustomobject]@{ HotFixID = 'KB1'; InstalledOn = [datetime]'2026-11-10'; CimInstanceProperties = @{ InstalledOn = [pscustomobject]@{ Value = '10/11/2026' } } }
                    [pscustomobject]@{ HotFixID = 'KB2'; InstalledOn = $null; CimInstanceProperties = @{ InstalledOn = [pscustomobject]@{ Value = '23/11/2026' } } }
                )
            }
            $r = Get-AdfaDcSystemRaw -ComputerName $script:C1Dc -Protocol 'Wsman' -OperationTimeoutSec 30
            @($r.InstalledOn) | Should -Be @('10/11/2026', '23/11/2026')
            # And the set then proves day-first, which the adapter's guess contradicted.
            $s = Get-AdfaHotfixSummary -InstalledOn @($r.InstalledOn)
            $s.Order | Should -Be 'DayFirst'
            $s.Latest.ToString('yyyy-MM-dd') | Should -Be '2026-11-23'
        }
        It 'asks for a DCOM session option only for DCOM' {
            $script:C1Opts = @()
            function New-CimSessionOption { param([string]$Protocol) [pscustomobject]@{ Protocol = $Protocol } }
            function New-CimSession { param([string]$ComputerName, $SessionOption, [uint32]$OperationTimeoutSec, [pscredential]$Credential, $ErrorAction)
                $p = 'none'; if ($null -ne $SessionOption) { $p = [string]$SessionOption.Protocol }; $script:C1Opts += $p; [pscustomobject]@{ ComputerName = $ComputerName } }
            function Get-CimInstance { param($CimSession, [string]$ClassName, [string[]]$Property, [uint32]$OperationTimeoutSec, $ErrorAction)
                if ($ClassName -eq 'Win32_OperatingSystem') { return [pscustomobject]@{ LastBootUpTime = [datetime]'2026-11-01'; BuildNumber = '17763'; Version = '10.0.17763' } }
                return @() }
            Get-AdfaDcSystemRaw -ComputerName $script:C1Dc -Protocol 'Wsman' -OperationTimeoutSec 30 | Out-Null
            Get-AdfaDcSystemRaw -ComputerName $script:C1Dc -Protocol 'Dcom' -OperationTimeoutSec 30 | Out-Null
            ($script:C1Opts -join ',') | Should -Be 'none,Dcom'
        }
        It 'carries the CIM error code of a failure, for the refusal check' {
            function New-CimSession { param([Parameter(ValueFromRemainingArguments)]$a)
                $e = New-Object System.Exception 'Acesso negado.'
                $e | Add-Member -NotePropertyName NativeErrorCode -NotePropertyValue 'AccessDenied'
                throw $e }
            $r = Get-AdfaDcSystemRaw -ComputerName $script:C1Dc -Protocol 'Wsman' -OperationTimeoutSec 30
            $r.Ok | Should -BeFalse
            $r.ErrorCode | Should -Be 'AccessDenied'
        }
        It 'returns the error text, not an exception, when the session cannot be opened' {
            function New-CimSession { param([Parameter(ValueFromRemainingArguments)]$a) throw 'Access is denied.' }
            $r = Get-AdfaDcSystemRaw -ComputerName $script:C1Dc -Protocol 'Wsman' -OperationTimeoutSec 30
            $r.Ok | Should -BeFalse
            $r.Error | Should -Match 'Access is denied'
        }
        It 'keeps the OS data when only the update class fails' {
            function New-CimSession { param([Parameter(ValueFromRemainingArguments)]$a) [pscustomobject]@{ ComputerName = 'x' } }
            function Get-CimInstance {
                param($CimSession, [string]$ClassName, [string[]]$Property, [uint32]$OperationTimeoutSec, $ErrorAction)
                if ($ClassName -eq 'Win32_OperatingSystem') { return [pscustomobject]@{ LastBootUpTime = [datetime]'2026-11-01'; BuildNumber = '17763'; Version = '10.0.17763' } }
                throw 'The operation has timed out.'
            }
            $r = Get-AdfaDcSystemRaw -ComputerName $script:C1Dc -Protocol 'Dcom' -OperationTimeoutSec 30
            $r.Ok | Should -BeTrue
            $r.HotfixOk | Should -BeFalse
            $r.HotfixError | Should -Match 'timed out'
        }
    }

    Context 'Config override' {
        It 'replaces the lifecycle table and rewrites provenance' {
            $o = '{ "OsLifecycle": [ { "Label": "Windows Server 2099", "Build": 99999, "Pattern": "(?i)windows server\\s*2099", "ExtendedEnd": "2099-01-01", "EsuEnd": null } ] }' | ConvertFrom-Json
            $m = Merge-AdfaDcSystemConfig -BaseConfig $script:Dsc -Override $o -OverrideSource 'C:\cfg\dcsystem.json'
            @($m.OsLifecycle).Count | Should -Be 1
            [string]$m.SourceUrl | Should -Be 'C:\cfg\dcsystem.json'
            $v = Get-AdfaOsLifecycleVerdict -OperatingSystem 'Windows Server 2099 Standard' -OperatingSystemVersion '10.0 (99999)' -Today $script:Today -Entries $m.OsLifecycle
            $v.Status | Should -Be 'Pass'
            # The built-in table is untouched.
            @($script:Dsc.OsLifecycle).Count | Should -Be 6
        }
        It 'refuses an empty table, a bad date, and a row that can match nothing' {
            { Merge-AdfaDcSystemConfig -BaseConfig $script:Dsc -Override @{ OsLifecycle = @() } } | Should -Throw
            { Merge-AdfaDcSystemConfig -BaseConfig $script:Dsc -Override @{ OsLifecycle = @(@{ Label = 'X'; Build = 1; ExtendedEnd = 'next year' }) } } | Should -Throw -ExpectedMessage '*ExtendedEnd*'
            { Merge-AdfaDcSystemConfig -BaseConfig $script:Dsc -Override @{ OsLifecycle = @(@{ Label = 'X'; ExtendedEnd = '2030-01-01' }) } } | Should -Throw -ExpectedMessage '*Build*'
            { Merge-AdfaDcSystemConfig -BaseConfig $script:Dsc -Override @{ OsLifecycle = @(@{ Label = 'X'; Build = 1; ExtendedEnd = '2030-01-01'; EsuEnd = 'soon' }) } } | Should -Throw -ExpectedMessage '*EsuEnd*'
        }
        It 'refuses an override that is not one object with known keys' {
            # Each of these used to be accepted: the built-in dates were judged and the report
            # cited the operator's file for them.
            # Built as an array directly: Windows PowerShell 5.1 hands a top-level JSON array to the
            # merge as one Object[], while PowerShell 7 unrolls it, so the JSON text would test
            # a different thing on each.
            $asArray = @([pscustomobject]@{ OsLifecycle = @() }, [pscustomobject]@{ OsLifecycle = @() })
            { Merge-AdfaDcSystemConfig -BaseConfig $script:Dsc -Override $asArray -OverrideSource 'C:\cfg\x.json' } | Should -Throw -ExpectedMessage '*single object*'
            { Merge-AdfaDcSystemConfig -BaseConfig $script:Dsc -Override 'abc' } | Should -Throw -ExpectedMessage '*single object*'
            { Merge-AdfaDcSystemConfig -BaseConfig $script:Dsc -Override 5 } | Should -Throw -ExpectedMessage '*single object*'
            { Merge-AdfaDcSystemConfig -BaseConfig $script:Dsc -Override ('{}' | ConvertFrom-Json) } | Should -Throw -ExpectedMessage '*empty object*'
            { Merge-AdfaDcSystemConfig -BaseConfig $script:Dsc -Override ('{ "OsLifecycles": [] }' | ConvertFrom-Json) } | Should -Throw -ExpectedMessage '*OsLifecycles*'
            { Merge-AdfaDcSystemConfig -BaseConfig $script:Dsc -Override ('{ "OsLifecycle": null }' | ConvertFrom-Json) } | Should -Throw -ExpectedMessage '*null*'
        }
        It 'refuses a port that is not a port' {
            { Merge-AdfaDcSystemConfig -BaseConfig $script:Dsc -Override @{ WsmanPort = 'abc' } } | Should -Throw -ExpectedMessage '*WsmanPort*'
            { Merge-AdfaDcSystemConfig -BaseConfig $script:Dsc -Override @{ RpcPort = -1 } } | Should -Throw -ExpectedMessage '*RpcPort*'
            { Merge-AdfaDcSystemConfig -BaseConfig $script:Dsc -Override @{ RpcPort = 70000 } } | Should -Throw -ExpectedMessage '*RpcPort*'
        }
        It 'goes on citing Microsoft when the override changes a port and leaves the dates alone' {
            $m = Merge-AdfaDcSystemConfig -BaseConfig $script:Dsc -Override @{ WsmanPort = 5986 } -OverrideSource 'C:\cfg\dcsystem.json'
            $m.WsmanPort | Should -Be 5986
            [string]$m.SourceUrl | Should -Match '^https://learn\.microsoft\.com/'
            @($m.OsLifecycle).Count | Should -Be 6
        }
        It 'throws for a file holding JSON null, and names the file in any merge error' {
            $f = Join-Path ([IO.Path]::GetTempPath()) ("adfa_dcs_{0}.json" -f [guid]::NewGuid().ToString('N'))
            try {
                'null' | Out-File -LiteralPath $f -Encoding UTF8
                { Import-AdfaDcSystemConfig -BaseConfig $script:Dsc -Path $f } | Should -Throw -ExpectedMessage '*JSON null*'
                '[]' | Out-File -LiteralPath $f -Encoding UTF8
                { Import-AdfaDcSystemConfig -BaseConfig $script:Dsc -Path $f } | Should -Throw
                '{ "Typo": 1 }' | Out-File -LiteralPath $f -Encoding UTF8
                { Import-AdfaDcSystemConfig -BaseConfig $script:Dsc -Path $f } | Should -Throw -ExpectedMessage "*$([IO.Path]::GetFileName($f))*"
            }
            finally { Remove-Item $f -Force -ErrorAction SilentlyContinue }
        }
        It 'throws for a missing or malformed file instead of falling back to the built-in table' {
            { Import-AdfaDcSystemConfig -BaseConfig $script:Dsc -Path (Join-Path ([IO.Path]::GetTempPath()) 'adfa-no-such-dcsystem.json') } | Should -Throw
            $bad = Join-Path ([IO.Path]::GetTempPath()) ("adfa_baddcs_{0}.json" -f [guid]::NewGuid().ToString('N'))
            try {
                'not json {' | Out-File -LiteralPath $bad -Encoding UTF8
                { Import-AdfaDcSystemConfig -BaseConfig $script:Dsc -Path $bad } | Should -Throw
            }
            finally { Remove-Item $bad -Force -ErrorAction SilentlyContinue }
        }
    }
}

Describe 'DC disk space, and the generic config override (C2)' {
    BeforeAll {
        $script:Ddc = $script:Config.DcDisk
        # Held in variables: PSAvoidUsingComputerNameHardcoded flags a literal -ComputerName.
        $script:C2Dc1 = 'dc1.contoso.com'
        $script:C2Dc2 = 'dc2.contoso.com'
        $script:C2Dc3 = 'dc3.fabrikam.com'
        $script:C2GB = [double]1073741824
        # Declared population of this section: the three roles a DC's volumes are judged for.
        $script:C2Roles = @('NTDS database', 'NTDS logs', 'SYSVOL')
        $script:C2NtdsKey = 'SYSTEM\CurrentControlSet\Services\NTDS\Parameters'
        $script:C2NetlogonKey = 'SYSTEM\CurrentControlSet\Services\Netlogon\Parameters'

        function Get-C2Row {
            param($Rows, [string]$Item)
            $m = @($Rows | Where-Object { [string]$_.Item -eq $Item })
            if ($m.Count -eq 0) { return $null }
            return $m[0]
        }
        # A Win32_Volume instance in the shape the class returns: Name is the mount path,
        # DeviceID the volume GUID path, DriveType a uint32, Capacity and FreeSpace uint64 bytes.
        function New-C2Volume {
            param([string]$Name, [double]$CapacityGB, [double]$FreeGB, [int]$DriveType = 3, [string]$DeviceID = '')
            if ($DeviceID -eq '') { $DeviceID = ('\\?\Volume{{{0}}}\' -f ($Name -replace '[^A-Za-z0-9]', '')) }
            [pscustomobject]@{ Name = $Name; DeviceID = $DeviceID; DriveType = [uint32]$DriveType
                Capacity = [uint64]($CapacityGB * $script:C2GB); FreeSpace = [uint64]($FreeGB * $script:C2GB) }
        }
        # One registry read result, in the shape Get-AdfaDcDiskRaw returns it.
        function New-C2Path {
            param([string]$Role, [string]$Value = '', $ReturnValue = 0, [string]$Err = '', [string]$Code = '', $ExpandedReturnValue = $null, [string]$Method = 'GetStringValue')
            $key = $script:C2NtdsKey
            $name = 'DSA Database File'
            if ($Role -eq 'NTDS logs') { $name = 'Database Log Files Path' }
            if ($Role -eq 'SYSVOL') { $key = $script:C2NetlogonKey; $name = 'SysVol' }
            $read = ($Err -eq '' -and $null -ne $ReturnValue -and [int64]$ReturnValue -eq 0 -and $Value -ne '')
            [pscustomobject]@{ Role = $Role; Key = $key; ValueName = $name; Read = $read; ReturnValue = $ReturnValue; Value = $Value
                Method = $Method; Error = $Err; ErrorCode = $Code; ExpandedReturnValue = $ExpandedReturnValue }
        }
        function New-C2Raw {
            param($Paths, $Volumes = @(), [bool]$VolumesOk = $true, [string]$VolumeError = '', [string]$VolumeErrorCode = '', [string]$Protocol = 'Wsman')
            [pscustomobject]@{ Ok = $true; Protocol = $Protocol; Error = ''; ErrorCode = ''; Paths = @($Paths)
                VolumesOk = $VolumesOk; Volumes = @($Volumes); VolumeError = $VolumeError; VolumeErrorCode = $VolumeErrorCode }
        }
        # The default layout: database, logs and SYSVOL all under %systemroot% on C:.
        function New-C2DefaultPaths {
            @(
                (New-C2Path -Role 'NTDS database' -Value 'C:\Windows\NTDS\ntds.dit'),
                (New-C2Path -Role 'NTDS logs' -Value 'C:\Windows\NTDS'),
                (New-C2Path -Role 'SYSVOL' -Value 'C:\Windows\SYSVOL\sysvol')
            )
        }
        # How many rows name each role. Every reachable DC must account for each role exactly once.
        function Get-C2RoleCount {
            param($Rows, [string]$Dc, [string]$Role)
            $pattern = [regex]::Escape($Role)
            return @($Rows | Where-Object { [string]$_.Item -like ("Disk space: {0} *" -f $Dc) -and [string]$_.Item -match $pattern }).Count
        }
        function Get-C2FailedRaw {
            param([string]$Protocol, [string]$Message, [string]$Code = '')
            [pscustomobject]@{ Ok = $false; Protocol = $Protocol; Error = $Message; ErrorCode = $Code; Paths = @()
                VolumesOk = $false; Volumes = @(); VolumeError = ''; VolumeErrorCode = '' }
        }
        $script:C2Ast = [System.Management.Automation.Language.Parser]::ParseFile($script:Target, [ref]$null, [ref]$null)
        $script:C2Main = @($script:C2Ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Invoke-Main' }, $true))
        $script:C2Commands = @($script:C2Ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true))
        function Get-C2Parameter {
            param($Call, [string]$Name)
            $elements = @($Call.CommandElements)
            for ($i = 0; $i -lt $elements.Count; $i++) {
                $e = $elements[$i]
                if ($e -is [System.Management.Automation.Language.CommandParameterAst] -and $e.ParameterName -eq $Name) {
                    if ($null -ne $e.Argument) { return $e.Argument }
                    if (($i + 1) -lt $elements.Count) { return $elements[$i + 1] }
                }
            }
            return $null
        }
    }

    Context 'Section wiring' {
        It 'is a value of the -Sections ValidateSet, read from the parsed parameter and not from the text' {
            $param = @($script:C2Ast.ParamBlock.Parameters | Where-Object { $_.Name.VariablePath.UserPath -eq 'Sections' })
            $param.Count | Should -Be 1
            $set = @($param[0].Attributes | Where-Object { $_.TypeName.Name -eq 'ValidateSet' })
            $set.Count | Should -Be 1
            $values = @($set[0].PositionalArguments | ForEach-Object { $_.Value })
            $values | Should -Contain 'DcDisk'
            $values | Should -Contain 'DcSystem'   # non-vacuity: the list really was read
        }
        It 'is part of the default All run' {
            Test-SectionSelected 'DcDisk' @('All') | Should -BeTrue
            Test-SectionSelected 'DcDisk' @('DcSystem') | Should -BeFalse
        }
        It 'has a branch in Invoke-Main that calls the collector with the config, the inventory failures and the enumeration error, and stores the rows' {
            $script:C2Main.Count | Should -Be 1
            $branches = @($script:C2Main[0].FindAll({ param($n)
                        $n -is [System.Management.Automation.Language.IfStatementAst] -and
                        $n.Clauses[0].Item1.Extent.Text -match "^Test-SectionSelected 'DcDisk' \`$Sections$" }, $true))
            # Declared population: the one branch for this section.
            $branches.Count | Should -Be 1
            $body = $branches[0].Clauses[0].Item2
            $calls = @($body.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] -and $n.GetCommandName() -eq 'Get-AdfaDcDiskSpace' }, $true))
            $calls.Count | Should -Be 1
            # WHAT each parameter is given, not only that it is given: an -EnumerationError of ''
            # or a -Credential of $null is still "a parameter", and would pass a presence check.
            $expected = [ordered]@{
                DomainControllers   = '$dcDiskTargets'
                Config              = '$dcDiskConfig'
                Credential          = '$Credential'
                PortTimeoutMs       = '$script:Config.RpcPortTimeoutMs'
                OperationTimeoutSec = '$script:Config.ExternalToolTimeoutSec'
                InventoryFailures   = '$dcDiskFailures'
                EnumerationError    = '$script:DcEnumerationError'
                ScopedDomains       = '$targetDomains'
            }
            # Declared population: the eight parameters the collector is called with.
            @($expected.Keys).Count | Should -Be 8
            foreach ($p in @($expected.Keys)) {
                $given = Get-C2Parameter -Call $calls[0] -Name $p
                $given | Should -Not -BeNullOrEmpty -Because "the collector must be given -$p"
                $given.Extent.Text | Should -Be $expected[$p] -Because "-$p must carry that value"
            }
            $assign = @($body.FindAll({ param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst] -and $n.Left.Extent.Text -eq "`$sectionData['DC Disk Space']" }, $true))
            $assign.Count | Should -Be 1
            # The override reaches the collector. Read from the parsed branch, not from its text:
            # the collector is given $dcDiskConfig, which starts as the built-in table and is
            # replaced by the file's table inside an if that tests for the file's DcDisk key.
            (Get-C2Parameter -Call $calls[0] -Name 'Config').Extent.Text | Should -Be '$dcDiskConfig'
            $configAssigns = @($body.FindAll({ param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst] -and $n.Left.Extent.Text -eq '$dcDiskConfig' }, $true))
            # Declared population: the built-in table, then the override.
            $configAssigns.Count | Should -Be 2
            $configAssigns[0].Right.Extent.Text | Should -Be '$script:Config.DcDisk'
            $configAssigns[1].Right.Extent.Text | Should -Be "`$configOverrides['DcDisk']"
            $guard = $configAssigns[1].Parent
            while ($null -ne $guard -and $guard -isnot [System.Management.Automation.Language.IfStatementAst]) { $guard = $guard.Parent }
            $guard.Clauses[0].Item1.Extent.Text | Should -Be "`$configOverrides.ContainsKey('DcDisk')"
        }
        It 'takes its targets from the DC inventory, from its own per-domain enumeration when there is no inventory, and from the unscoped fallback only last' {
            $branches = @($script:C2Main[0].FindAll({ param($n)
                        $n -is [System.Management.Automation.Language.IfStatementAst] -and
                        $n.Clauses[0].Item1.Extent.Text -match "^Test-SectionSelected 'DcDisk' \`$Sections$" }, $true))
            $branches.Count | Should -Be 1
            $body = $branches[0].Clauses[0].Item2
            function Get-C2Guard {
                param($Node)
                $g = $Node.Parent
                while ($null -ne $g -and $g -isnot [System.Management.Automation.Language.IfStatementAst]) { $g = $g.Parent }
                return $g.Clauses[0].Item1.Extent.Text
            }
            $targets = @($body.FindAll({ param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst] -and $n.Left.Extent.Text -eq '$dcDiskTargets' }, $true))
            # Declared population: the inventory, the section's own enumeration, the fallback - in that order.
            $targets.Count | Should -Be 3
            $targets[0].Right.Extent.Text | Should -Be '@($allDcInventory)'
            Get-C2Guard $targets[0] | Should -Be "Test-SectionSelected 'DcDisk' `$Sections"
            $targets[1].Right.Extent.Text | Should -Be '@($dcDiskEnumeration.Targets)'
            Get-C2Guard $targets[1] | Should -Be '-not $dcInventoryCollected'
            $targets[2].Right.Extent.Text | Should -Be '@($dcNames)'
            Get-C2Guard $targets[2] | Should -Be '$dcDiskTargets.Count -eq 0'
            $failures = @($body.FindAll({ param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst] -and $n.Left.Extent.Text -eq '$dcDiskFailures' }, $true))
            $failures.Count | Should -Be 2
            $failures[0].Right.Extent.Text | Should -Be '@($dcInventoryFailures)'
            $failures[1].Right.Extent.Text | Should -Be '@($dcDiskEnumeration.Failures)'
            Get-C2Guard $failures[1] | Should -Be '-not $dcInventoryCollected'
            # The section's own enumeration is asked for every scoped domain, with the run's AD parameters.
            $own = @($body.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] -and $n.GetCommandName() -eq 'Get-AdfaDcTargetsByDomain' }, $true))
            $own.Count | Should -Be 1
            (Get-C2Parameter -Call $own[0] -Name 'Domains').Extent.Text | Should -Be '$targetDomains'
            (Get-C2Parameter -Call $own[0] -Name 'AdParams').Extent.Text | Should -Be '$adParams'
            Get-C2Guard $own[0] | Should -Be '-not $dcInventoryCollected'
            # $dcInventoryCollected is true only where the DomainControllers section ran.
            $flag = @($script:C2Main[0].FindAll({ param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst] -and $n.Left.Extent.Text -eq '$dcInventoryCollected' }, $true))
            $flag.Count | Should -Be 2
            $flag[0].Right.Extent.Text | Should -Be '$false'
            $flag[1].Right.Extent.Text | Should -Be '$true'
            Get-C2Guard $flag[1] | Should -Be "Test-SectionSelected 'DomainControllers' `$Sections"
            $flag[0].Extent.StartLineNumber | Should -BeLessThan $flag[1].Extent.StartLineNumber
        }
        It 'declares -ConfigOverridePath as a string that may not be empty, and leaves the two older override parameters in place' {
            $p = @($script:C2Ast.ParamBlock.Parameters | Where-Object { $_.Name.VariablePath.UserPath -eq 'ConfigOverridePath' })
            $p.Count | Should -Be 1
            $p[0].StaticType.Name | Should -Be 'String'
            @($p[0].Attributes | Where-Object { $_.TypeName.Name -eq 'ValidateNotNullOrEmpty' }).Count | Should -Be 1
            foreach ($older in @('ExchangeSeConfigPath', 'DcSystemConfigPath')) {
                @($script:C2Ast.ParamBlock.Parameters | Where-Object { $_.Name.VariablePath.UserPath -eq $older }).Count | Should -Be 1 -Because "-$older must keep working"
            }
        }
        It 'loads the override file once, before any section runs, so a bad file stops the run before any work' {
            $loads = @($script:C2Main[0].FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] -and $n.GetCommandName() -eq 'Import-AdfaConfigOverride' }, $true))
            $loads.Count | Should -Be 1
            (Get-C2Parameter -Call $loads[0] -Name 'Path').Extent.Text | Should -Be '$ConfigOverridePath'
            # It runs when, and only when, the parameter was given: the nearest enclosing if tests it.
            $when = $loads[0].Parent
            while ($null -ne $when -and $when -isnot [System.Management.Automation.Language.IfStatementAst]) { $when = $when.Parent }
            $when.Clauses[0].Item1.Extent.Text | Should -Be '$ConfigOverridePath'
            # And what it returns is what the section branches read.
            $kept = $loads[0].Parent
            while ($null -ne $kept -and $kept -isnot [System.Management.Automation.Language.AssignmentStatementAst]) { $kept = $kept.Parent }
            $kept.Left.Extent.Text | Should -Be '$configOverrides'
            # A refusal STOPS the run: the load sits in a try whose catch rethrows. A catch that
            # only logged would let the run go on against the built-in thresholds.
            $guarded = $loads[0].Parent
            while ($null -ne $guarded -and $guarded -isnot [System.Management.Automation.Language.TryStatementAst]) { $guarded = $guarded.Parent }
            $guarded | Should -Not -BeNullOrEmpty
            @($guarded.CatchClauses).Count | Should -Be 1
            $rethrow = @($guarded.CatchClauses[0].Body.FindAll({ param($n) $n -is [System.Management.Automation.Language.ThrowStatementAst] }, $true))
            $rethrow.Count | Should -Be 1 -Because 'the catch must rethrow what the loader threw'
            $rethrow[0].IsRethrow | Should -BeTrue
            # The rethrow is the catch block's last statement, not something an earlier return skips.
            $last = @($guarded.CatchClauses[0].Body.Statements)[-1]
            $last.Extent.Text | Should -Be 'throw'
            $sections =@($script:C2Main[0].FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] -and $n.GetCommandName() -eq 'Test-SectionSelected' }, $true))
            # Non-vacuity: the section branches really were found (there are dozens).
            $sections.Count | Should -BeGreaterThan 30
            $first = ($sections | ForEach-Object { $_.Extent.StartLineNumber } | Measure-Object -Minimum).Minimum
            $loads[0].Extent.StartLineNumber | Should -BeLessThan $first
            # And before the directory is touched at all.
            $adImport = @($script:C2Main[0].FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] -and $n.GetCommandName() -eq 'Import-Module' }, $true))
            $adImport.Count | Should -Be 1
            $loads[0].Extent.StartLineNumber | Should -BeLessThan $adImport[0].Extent.StartLineNumber
        }
        It 'documents the section and the parameter in the comment-based help, and the help is readable at all' {
            # Read the way Get-Help reads it. Until v1.19.0 the licence banner sat directly above
            # the help block with no blank line, which made the two one comment: this returned
            # $null and Get-Help showed only the auto-generated syntax, for every parameter.
            $help = $script:C2Ast.GetHelpContent()
            $help | Should -Not -BeNullOrEmpty -Because 'a comment touching the help block hides the whole of it from Get-Help'
            [string]$help.Synopsis | Should -Match 'Active Directory forest assessment'
            [string]$help.Parameters['CONFIGOVERRIDEPATH'] | Should -Match 'DcDisk'
            [string]$help.Parameters['SECTIONS'] | Should -Match 'DcDisk'
            [string]$help.Description | Should -Match 'GetStringValue'
        }
        It 'has one row in the README Coverage table' {
            $readme = @(Get-Content -LiteralPath (Join-Path $script:RepoRoot 'README.md'))
            @($readme | Where-Object { $_ -match '^\| \*\*DC disk space\*\* \|' }).Count | Should -Be 1
            @($readme | Where-Object { $_ -match '^\| \*\*DC system\*\* \|' }).Count | Should -Be 1   # non-vacuity: the table was read
        }
    }

    Context 'Read-only guard' {
        It 'invokes no CIM method except a literal StdRegProv Get* read' {
            $calls = @($script:C2Commands | Where-Object { $_.GetCommandName() -eq 'Invoke-CimMethod' })
            # Declared population: one GetStringValue call and one GetExpandedStringValue call.
            $calls.Count | Should -Be 2
            $allowed = @('GetStringValue', 'GetExpandedStringValue')
            $seen = @()
            foreach ($call in $calls) {
                $line = $call.Extent.StartLineNumber
                $class = Get-C2Parameter -Call $call -Name 'ClassName'
                $class | Should -BeOfType ([System.Management.Automation.Language.StringConstantExpressionAst]) -Because "line $line must name the class literally"
                $class.Value | Should -Be 'StdRegProv' -Because "line $line"
                $method = Get-C2Parameter -Call $call -Name 'MethodName'
                $method | Should -BeOfType ([System.Management.Automation.Language.StringConstantExpressionAst]) -Because "a computed -MethodName on line $line could name a method that writes"
                $allowed | Should -Contain $method.Value -Because "line $line calls '$($method.Value)', which is not a registry read on the allow-list"
                $seen += [string]$method.Value
                $ns = Get-C2Parameter -Call $call -Name 'Namespace'
                $ns | Should -BeOfType ([System.Management.Automation.Language.StringConstantExpressionAst])
                $ns.Value | Should -Be 'root/cimv2'
            }
            (@($seen | Sort-Object) -join ',') | Should -Be 'GetExpandedStringValue,GetStringValue'
        }
        It 'forces -WhatIf and -Confirm off on those reads, so neither preference can silently skip one or stop to ask' {
            $calls = @($script:C2Commands | Where-Object { $_.GetCommandName() -eq 'Invoke-CimMethod' })
            $calls.Count | Should -Be 2
            foreach ($call in $calls) {
                foreach ($switch in @('WhatIf', 'Confirm')) {
                    $w = @($call.CommandElements | Where-Object { $_ -is [System.Management.Automation.Language.CommandParameterAst] -and $_.ParameterName -eq $switch })
                    $w.Count | Should -Be 1 -Because "line $($call.Extent.StartLineNumber) must carry -$switch"
                    $w[0].Argument | Should -Not -BeNullOrEmpty -Because "-$switch must be given a value, not left as a bare switch"
                    $w[0].Argument.Extent.Text | Should -Be '$false'
                }
            }
        }
        It 'forces -WhatIf and -Confirm off where a CIM session is closed, so a preference cannot leave sessions open' {
            $closes = @($script:C2Commands | Where-Object { $_.GetCommandName() -eq 'Remove-CimSession' })
            # Declared population: the DcSystem seam and the DcDisk seam, the two places a CIM session is opened.
            $closes.Count | Should -Be 2
            @($script:C2Commands | Where-Object { $_.GetCommandName() -eq 'New-CimSession' }).Count | Should -Be 2
            foreach ($call in $closes) {
                foreach ($switch in @('WhatIf', 'Confirm')) {
                    $w = @($call.CommandElements | Where-Object { $_ -is [System.Management.Automation.Language.CommandParameterAst] -and $_.ParameterName -eq $switch })
                    $w.Count | Should -Be 1 -Because "line $($call.Extent.StartLineNumber) must carry -$switch"
                    $w[0].Argument | Should -Not -BeNullOrEmpty
                    $w[0].Argument.Extent.Text | Should -Be '$false'
                }
            }
        }
        It 'bounds every operation of the seam with the caller''s timeout: the session, each method call and the volume query' {
            $fn = @($script:C2Ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and @('Get-AdfaDcDiskRaw', 'Get-AdfaStdRegStringValue') -contains $n.Name }, $true))
            $fn.Count | Should -Be 2
            $bounded = @()
            foreach ($f in $fn) {
                $bounded += @($f.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] -and @('Invoke-CimMethod', 'Get-CimInstance') -contains $n.GetCommandName() }, $true))
            }
            # Declared population: GetStringValue, GetExpandedStringValue and the Win32_Volume query.
            $bounded.Count | Should -Be 3
            foreach ($call in $bounded) {
                $t = Get-C2Parameter -Call $call -Name 'OperationTimeoutSec'
                $t | Should -Not -BeNullOrEmpty -Because "$($call.GetCommandName()) on line $($call.Extent.StartLineNumber) must be bounded"
                $t.Extent.Text | Should -Match '\$OperationTimeoutSec' -Because 'the bound must be the caller''s, not a constant'
            }
        }
        It 'uses no cmdlet that writes through CIM or WMI' {
            $names = @($script:C2Commands | ForEach-Object { [string]$_.GetCommandName() })
            foreach ($banned in @('Set-CimInstance', 'New-CimInstance', 'Remove-CimInstance', 'Invoke-WmiMethod', 'Set-WmiInstance', 'Remove-WmiObject')) {
                $names | Should -Not -Contain $banned
            }
            # Non-vacuity, declared population: the four instance reads this script makes -
            # MSFT_SmbServerConfiguration, Win32_OperatingSystem, Win32_QuickFixEngineering, Win32_Volume.
            @($names | Where-Object { $_ -eq 'Get-CimInstance' }).Count | Should -Be 4
        }
        It 'reads Win32_Volume as instances only, naming the properties it wants' {
            $vol = @($script:C2Commands | Where-Object { $_.GetCommandName() -eq 'Get-CimInstance' -and $_.Extent.Text -match 'Win32_Volume' })
            $vol.Count | Should -Be 1
            $vol[0].Extent.Text | Should -Match "-Property 'Name', 'DeviceID', 'DriveType', 'Capacity', 'FreeSpace'"
        }
    }

    Context 'Config table' {
        It 'labels its thresholds as tool defaults and records where the vendor facts were read' {
            [string]$script:Ddc.ThresholdSource | Should -Be 'tool default, not a Microsoft value'
            [string]$script:Ddc.SourceUrl | Should -Match '^https://learn\.microsoft\.com/'
            [string]$script:Ddc.ReadDate | Should -Be '2026-11-13'
            $script:Ddc.WarnBelowPercent | Should -Be 20
            $script:Ddc.FailBelowPercent | Should -Be 10
            $script:Ddc.WarnBelowFreeGB | Should -BeGreaterThan $script:Ddc.FailBelowFreeGB
            $script:Ddc.FailBelowFreeGB | Should -BeGreaterThan 0
        }
        It 'names the three registry values, one per role' {
            $paths = @($script:Ddc.Paths)
            # Declared population: NTDS database, NTDS logs, SYSVOL.
            $paths.Count | Should -Be 3
            (@($paths | ForEach-Object { [string]$_.Role }) -join '|') | Should -Be ($script:C2Roles -join '|')
            ($paths | Where-Object { $_.Role -eq 'NTDS database' }).ValueName | Should -Be 'DSA Database File'
            ($paths | Where-Object { $_.Role -eq 'NTDS logs' }).ValueName | Should -Be 'Database Log Files Path'
            ($paths | Where-Object { $_.Role -eq 'SYSVOL' }).ValueName | Should -Be 'SysVol'
            ($paths | Where-Object { $_.Role -eq 'NTDS database' }).Key | Should -Be $script:C2NtdsKey
            ($paths | Where-Object { $_.Role -eq 'NTDS logs' }).Key | Should -Be $script:C2NtdsKey
            ($paths | Where-Object { $_.Role -eq 'SYSVOL' }).Key | Should -Be $script:C2NetlogonKey
        }
    }

    Context 'Get-AdfaDiskSpaceVerdict' {
        BeforeAll {
            function Get-C2Verdict {
                param([double]$CapacityGB, [double]$FreeGB, [double]$WarnGB = 0, [double]$FailGB = 0)
                Get-AdfaDiskSpaceVerdict -CapacityBytes ([uint64]($CapacityGB * $script:C2GB)) -FreeBytes ([uint64]($FreeGB * $script:C2GB)) `
                    -WarnBelowPercent 20 -FailBelowPercent 10 -WarnBelowFreeGB $WarnGB -FailBelowFreeGB $FailGB
            }
        }
        It 'passes a volume with plenty of space and states the figures' {
            $v = Get-C2Verdict -CapacityGB 120 -FreeGB 60
            $v.Status | Should -Be 'Pass'
            $v.Trigger | Should -Be 'None'
            $v.Detail | Should -Match '50\.00 % free'
            $v.Detail | Should -Match '60\.00 GB free of 120\.00 GB'
        }
        It 'fails below 10 %, warns from exactly 10 % up to but not including 20 %, and passes at exactly 20 %' {
            (Get-C2Verdict -CapacityGB 1000 -FreeGB 99.9).Status | Should -Be 'Fail'
            (Get-C2Verdict -CapacityGB 1000 -FreeGB 100).Status | Should -Be 'Warning'
            (Get-C2Verdict -CapacityGB 1000 -FreeGB 199.9).Status | Should -Be 'Warning'
            (Get-C2Verdict -CapacityGB 1000 -FreeGB 200).Status | Should -Be 'Pass'
            (Get-C2Verdict -CapacityGB 1000 -FreeGB 0).Status | Should -Be 'Fail'
        }
        It 'says which threshold was crossed' {
            $f = Get-C2Verdict -CapacityGB 1000 -FreeGB 50
            $f.Trigger | Should -Be 'Percent'
            $f.Detail | Should -Match 'Below the Fail threshold of 10 % free'
            $w = Get-C2Verdict -CapacityGB 1000 -FreeGB 150
            $w.Trigger | Should -Be 'Percent'
            $w.Detail | Should -Match 'Below the Warning threshold of 20 % free'
        }
        It 'applies the absolute floor on a small volume whose percentage looks healthy' {
            # 4.9 GB of 20 GB is 24.5 % free: fine by percentage, under a 5 GB floor.
            $w = Get-C2Verdict -CapacityGB 20 -FreeGB 4.9 -WarnGB 5 -FailGB 2
            $w.Status | Should -Be 'Warning'
            $w.Trigger | Should -Be 'Floor'
            $w.Detail | Should -Match 'Below the Warning floor of 5 GB free'
            # Exactly on the floor is not below it.
            (Get-C2Verdict -CapacityGB 20 -FreeGB 5 -WarnGB 5 -FailGB 2).Status | Should -Be 'Pass'
            $f = Get-C2Verdict -CapacityGB 8 -FreeGB 1.9 -WarnGB 5 -FailGB 2
            $f.Status | Should -Be 'Fail'
            $f.Trigger | Should -Be 'Floor'
            (Get-C2Verdict -CapacityGB 8 -FreeGB 2 -WarnGB 5 -FailGB 2).Status | Should -Be 'Warning'
        }
        It 'reports both triggers when both fired, and takes the worse of the two verdicts' {
            $b = Get-C2Verdict -CapacityGB 30 -FreeGB 1 -WarnGB 5 -FailGB 2
            $b.Status | Should -Be 'Fail'
            $b.Trigger | Should -Be 'Both'
            # Percentage says Warning (15 %), the floor says Fail (1.5 GB < 2 GB): Fail wins.
            $mixed = Get-C2Verdict -CapacityGB 10 -FreeGB 1.5 -WarnGB 5 -FailGB 2
            $mixed.Status | Should -Be 'Fail'
            $mixed.Trigger | Should -Be 'Floor'
        }
        It 'never prints a figure that reaches the threshold it says the volume is below' {
            # One byte short of 10 % of 100 GB: 9.99999999906868 %. Rounding prints "10.00 %
            # free ... Below the Fail threshold of 10 % free"; so did the earlier floor with a
            # 0.0000001 addend.
            $oneByteShort = Get-AdfaDiskSpaceVerdict -CapacityBytes ([uint64]107374182400) -FreeBytes ([uint64]10737418239) -WarnBelowPercent 20 -FailBelowPercent 10 -WarnBelowFreeGB 5 -FailBelowFreeGB 2
            $oneByteShort.Status | Should -Be 'Fail'
            $oneByteShort.Detail | Should -Be '9.99 % free: 9.99 GB free of 100.00 GB. Below the Fail threshold of 10 % free.'
            $decimalDisk = Get-AdfaDiskSpaceVerdict -CapacityBytes ([uint64]1000000000000) -FreeBytes ([uint64]99999999999) -WarnBelowPercent 20 -FailBelowPercent 10
            $decimalDisk.Status | Should -Be 'Fail'
            $decimalDisk.Detail | Should -Match '^9\.99 % free: 93\.13 GB free of 931\.32 GB\.'
            $warn = Get-AdfaDiskSpaceVerdict -CapacityBytes ([uint64]10000000000000) -FreeBytes ([uint64]1999999999999) -WarnBelowPercent 20 -FailBelowPercent 10
            $warn.Status | Should -Be 'Warning'
            $warn.Detail | Should -Match '^19\.99 % free'
            $warn.Detail | Should -Not -Match '^20\.00'
            # One byte short of the 5 GB floor on a 10 GB volume, and of the 2 GB floor.
            $floor = Get-AdfaDiskSpaceVerdict -CapacityBytes ([uint64]10737418240) -FreeBytes ([uint64]5368709119) -WarnBelowPercent 20 -FailBelowPercent 10 -WarnBelowFreeGB 5 -FailBelowFreeGB 2
            $floor.Status | Should -Be 'Warning'
            $floor.Detail | Should -Be '49.99 % free: 4.99 GB free of 10.00 GB. Below the Warning floor of 5 GB free.'
            $failFloor = Get-AdfaDiskSpaceVerdict -CapacityBytes ([uint64]10737418240) -FreeBytes ([uint64]2147483647) -WarnBelowPercent 20 -FailBelowPercent 10 -WarnBelowFreeGB 5 -FailBelowFreeGB 2
            $failFloor.Detail | Should -Match '1\.99 GB free of 10\.00 GB\. Below the Fail floor of 2 GB free\.$'
        }
        It 'truncates a figure to two decimals without rounding it up or shaving a cent off an exact value' {
            $cases = @(
                @{ V = [double]9.99999999906868; T = '9.99' }
                @{ V = [double]9.99999999999; T = '9.99' }
                @{ V = [double]9.99; T = '9.99' }     # 9.99 * 100 is 998.9999999999999 in binary
                @{ V = [double]19.999; T = '19.99' }
                @{ V = [double]2.675; T = '2.67' }
                @{ V = [double]0.005; T = '0.00' }
                @{ V = [double]10; T = '10.00' }
                @{ V = [double]50; T = '50.00' }
                @{ V = [double]0; T = '0.00' }
            )
            # Declared population: the nine values above.
            $cases.Count | Should -Be 9
            foreach ($c in $cases) { ConvertTo-AdfaFixedText -Value $c.V | Should -Be $c.T -Because "$($c.V) truncated to two decimals" }
            ConvertTo-AdfaFixedText -Value 1.23456 -Decimals 4 | Should -Be '1.2345'
            ConvertTo-AdfaFixedText -Value 7.9 -Decimals 0 | Should -Be '7'
            # Too large for a decimal: still a number, not an exception.
            ConvertTo-AdfaFixedText -Value 1e30 | Should -Match '^1\d{30}\.00$'
        }
        It 'does not apply a floor of 0' {
            (Get-C2Verdict -CapacityGB 20 -FreeGB 4.9 -WarnGB 0 -FailGB 0).Status | Should -Be 'Pass'
        }
        It 'gives the same answer for UInt64, Int64, Double and deserialized string values' {
            $cap = [uint64](500 * $script:C2GB)
            $free = [uint64](40 * $script:C2GB)   # 8 %
            $shapes = @(
                @{ C = $cap; F = $free }
                @{ C = [int64]$cap; F = [int64]$free }
                @{ C = [double]$cap; F = [double]$free }
                @{ C = [string]$cap; F = [string]$free }
            )
            # Declared population: the four numeric shapes a CIM value can arrive in.
            $shapes.Count | Should -Be 4
            foreach ($s in $shapes) {
                $v = Get-AdfaDiskSpaceVerdict -CapacityBytes $s.C -FreeBytes $s.F -WarnBelowPercent 20 -FailBelowPercent 10
                $v.Status | Should -Be 'Fail' -Because ("a {0} value must be read like any other" -f $s.C.GetType().Name)
                $v.Detail | Should -Match '8\.00 % free'
            }
            $max = Get-AdfaDiskSpaceVerdict -CapacityBytes ([uint64]::MaxValue) -FreeBytes ([uint64]([uint64]::MaxValue / 2)) -WarnBelowPercent 20 -FailBelowPercent 10
            $max.Status | Should -Be 'Pass'
        }
        It 'is Not Assessed, never Pass and never 0 %, when capacity or free space is missing, zero or inconsistent' {
            $cases = @(
                @{ C = $null; F = 100; Why = 'no capacity' }
                @{ C = 0; F = 0; Why = 'capacity is zero' }
                @{ C = 'abc'; F = 100; Why = 'not a number' }
                @{ C = 1000; F = $null; Why = 'no free space' }
                @{ C = 1000; F = 'n/a'; Why = 'not a number' }
                @{ C = 1000; F = -1; Why = 'negative' }
                @{ C = 1000; F = 2000; Why = 'larger than the capacity' }
                @{ C = $true; F = 100; Why = 'not a number' }
            )
            # Declared population: the eight unusable shapes above.
            $cases.Count | Should -Be 8
            foreach ($c in $cases) {
                $v = Get-AdfaDiskSpaceVerdict -CapacityBytes $c.C -FreeBytes $c.F -WarnBelowPercent 20 -FailBelowPercent 10 -WarnBelowFreeGB 5 -FailBelowFreeGB 2
                $v.Status | Should -Be 'Not Assessed' -Because $c.Why
                $v.Detail | Should -Match $c.Why
                $v.PercentFree | Should -BeNullOrEmpty
            }
            (Get-AdfaDiskSpaceVerdict -CapacityBytes $null -FreeBytes 5 -WarnBelowPercent 20 -FailBelowPercent 10).Detail | Should -Match "FreeSpace '5'"
        }
    }

    Context 'Resolve-AdfaVolumeForPath' {
        BeforeAll {
            $script:C2Vols = @(
                (New-C2Volume -Name 'C:\' -CapacityGB 120 -FreeGB 60),
                (New-C2Volume -Name 'D:\' -CapacityGB 200 -FreeGB 100),
                (New-C2Volume -Name 'D:\Mount\NTDS\' -CapacityGB 50 -FreeGB 25),
                (New-C2Volume -Name '\\?\Volume{11111111-2222-3333-4444-555555555555}\' -CapacityGB 0.5 -FreeGB 0.1),
                (New-C2Volume -Name 'E:\' -CapacityGB 4 -FreeGB 0 -DriveType 5)
            )
        }
        It 'maps a path to the volume whose mount path is its longest prefix' {
            (Resolve-AdfaVolumeForPath -Path 'C:\Windows\NTDS\ntds.dit' -Volumes $script:C2Vols).Volume.Name | Should -Be 'C:\'
            (Resolve-AdfaVolumeForPath -Path 'D:\Logs' -Volumes $script:C2Vols).Volume.Name | Should -Be 'D:\'
            (Resolve-AdfaVolumeForPath -Path 'D:\Mount\NTDS\ntds.dit' -Volumes $script:C2Vols).Volume.Name | Should -Be 'D:\Mount\NTDS\'
            (Resolve-AdfaVolumeForPath -Path 'D:\Mount\NTDS' -Volumes $script:C2Vols).Volume.Name | Should -Be 'D:\Mount\NTDS\'
            # A folder that merely starts with the same letters is not under the mounted folder.
            (Resolve-AdfaVolumeForPath -Path 'D:\Mount\NTDSX\ntds.dit' -Volumes $script:C2Vols).Volume.Name | Should -Be 'D:\'
        }
        It 'ignores case and the direction of the slashes' {
            (Resolve-AdfaVolumeForPath -Path 'c:\windows\sysvol\sysvol' -Volumes $script:C2Vols).Volume.Name | Should -Be 'C:\'
            (Resolve-AdfaVolumeForPath -Path 'd:/mount/ntds/ntds.dit' -Volumes $script:C2Vols).Volume.Name | Should -Be 'D:\Mount\NTDS\'
        }
        It 'does not resolve a path to a volume that is not a local disk, or one with no mount path' {
            $r = Resolve-AdfaVolumeForPath -Path 'E:\NTDS\ntds.dit' -Volumes $script:C2Vols
            $r.Resolved | Should -BeFalse
            $r.Volume | Should -BeNullOrEmpty
            $r.Reason | Should -Match 'C:\\'   # the volumes that were candidates are listed
            $r.Reason | Should -Not -Match 'Volume\{'
            (Resolve-AdfaVolumeForPath -Path '\\?\Volume{11111111-2222-3333-4444-555555555555}\x' -Volumes $script:C2Vols).Resolved | Should -BeFalse
        }
        It 'reports why when nothing can be resolved' {
            (Resolve-AdfaVolumeForPath -Path '' -Volumes $script:C2Vols).Resolved | Should -BeFalse
            (Resolve-AdfaVolumeForPath -Path '' -Volumes $script:C2Vols).Reason | Should -Match 'empty'
            $none = Resolve-AdfaVolumeForPath -Path 'C:\Windows\NTDS' -Volumes @()
            $none.Resolved | Should -BeFalse
            $none.Reason | Should -Match 'no local-disk volume'
            (Resolve-AdfaVolumeForPath -Path 'C:\Windows\NTDS' -Volumes $null).Resolved | Should -BeFalse
        }
        It 'accepts a mount path given without its trailing backslash' {
            $v = @((New-C2Volume -Name 'F:' -CapacityGB 10 -FreeGB 5))
            (Resolve-AdfaVolumeForPath -Path 'F:\NTDS' -Volumes $v).Resolved | Should -BeTrue
        }
    }

    Context 'Get-AdfaDcDiskFinding (pure: one DC''s raw read to rows)' {
        It 'gives one row for a volume that holds all three roles, with the figures, the thresholds and their label' {
            $raw = New-C2Raw -Paths (New-C2DefaultPaths) -Volumes @((New-C2Volume -Name 'C:\' -CapacityGB 120 -FreeGB 60))
            $rows = @(Get-AdfaDcDiskFinding -DomainController $script:C2Dc1 -Scope 'contoso.com' -Raw $raw -Config $script:Ddc)
            $rows.Count | Should -Be 1
            $rows[0].Item | Should -Be 'Disk space: dc1.contoso.com C:\ (NTDS database, NTDS logs, SYSVOL)'
            $rows[0].Status | Should -Be 'Pass'
            $rows[0].Scope | Should -Be 'contoso.com'
            $rows[0].Area | Should -Be 'DcDisk'
            $rows[0].Detail | Should -Match '50\.00 % free'
            $rows[0].Detail | Should -Match 'C:\\Windows\\NTDS\\ntds\.dit'
            $rows[0].Detail | Should -Match 'Warning below 20 % free or below 5 GB free'
            $rows[0].Detail | Should -Match 'Fail below 10 % free or below 2 GB free'
            $rows[0].Detail | Should -Match 'tool default, not a Microsoft value'
            $rows[0].Detail | Should -Match 'Read over Wsman'
        }
        It 'gives one row per distinct volume and a mixed result when the three roles sit on three volumes' {
            $paths = @(
                (New-C2Path -Role 'NTDS database' -Value 'D:\NTDS\ntds.dit'),
                (New-C2Path -Role 'NTDS logs' -Value 'E:\Logs'),
                (New-C2Path -Role 'SYSVOL' -Value 'C:\Windows\SYSVOL_DFSR\sysvol')
            )
            $vols = @(
                (New-C2Volume -Name 'C:\' -CapacityGB 100 -FreeGB 50),
                (New-C2Volume -Name 'D:\' -CapacityGB 100 -FreeGB 15),
                (New-C2Volume -Name 'E:\' -CapacityGB 100 -FreeGB 5)
            )
            $rows = @(Get-AdfaDcDiskFinding -DomainController $script:C2Dc1 -Scope 'contoso.com' -Raw (New-C2Raw -Paths $paths -Volumes $vols) -Config $script:Ddc)
            $rows.Count | Should -Be 3
            (Get-C2Row $rows 'Disk space: dc1.contoso.com C:\ (SYSVOL)').Status | Should -Be 'Pass'
            (Get-C2Row $rows 'Disk space: dc1.contoso.com D:\ (NTDS database)').Status | Should -Be 'Warning'
            (Get-C2Row $rows 'Disk space: dc1.contoso.com E:\ (NTDS logs)').Status | Should -Be 'Fail'
            foreach ($role in $script:C2Roles) { Get-C2RoleCount -Rows $rows -Dc $script:C2Dc1 -Role $role | Should -Be 1 -Because "$role must be accounted for by exactly one row" }
        }
        It 'states the documented consequence on a failing database or log volume, and not on a SYSVOL-only volume' {
            $paths = @(
                (New-C2Path -Role 'NTDS database' -Value 'D:\NTDS\ntds.dit'),
                (New-C2Path -Role 'NTDS logs' -Value 'D:\NTDS'),
                (New-C2Path -Role 'SYSVOL' -Value 'E:\SYSVOL\sysvol')
            )
            $vols = @((New-C2Volume -Name 'D:\' -CapacityGB 100 -FreeGB 3), (New-C2Volume -Name 'E:\' -CapacityGB 100 -FreeGB 3))
            $rows = @(Get-AdfaDcDiskFinding -DomainController $script:C2Dc1 -Scope 'contoso.com' -Raw (New-C2Raw -Paths $paths -Volumes $vols) -Config $script:Ddc)
            $db = Get-C2Row $rows 'Disk space: dc1.contoso.com D:\ (NTDS database, NTDS logs)'
            $db.Status | Should -Be 'Fail'
            $db.Detail | Should -Match 'event 1393'
            $db.Detail | Should -Match 'Net Logon'
            $sv = Get-C2Row $rows 'Disk space: dc1.contoso.com E:\ (SYSVOL)'
            $sv.Status | Should -Be 'Fail'
            $sv.Detail | Should -Not -Match '1393'
        }
        It 'states that consequence for each of the two roles on its own: a volume with only the logs, and one with only the database' {
            # The test above has the database and the logs on one volume, so either role alone
            # would satisfy it. Here each sits alone on a failing volume.
            $paths = @(
                (New-C2Path -Role 'NTDS database' -Value 'D:\NTDS\ntds.dit'),
                (New-C2Path -Role 'NTDS logs' -Value 'L:\Logs'),
                (New-C2Path -Role 'SYSVOL' -Value 'E:\SYSVOL\sysvol')
            )
            $vols = @(
                (New-C2Volume -Name 'D:\' -CapacityGB 100 -FreeGB 3),
                (New-C2Volume -Name 'L:\' -CapacityGB 100 -FreeGB 3),
                (New-C2Volume -Name 'E:\' -CapacityGB 100 -FreeGB 3)
            )
            $rows = @(Get-AdfaDcDiskFinding -DomainController $script:C2Dc1 -Scope 'contoso.com' -Raw (New-C2Raw -Paths $paths -Volumes $vols) -Config $script:Ddc)
            # Declared population: one failing row per volume.
            $rows.Count | Should -Be 3
            @($rows | Where-Object { $_.Status -eq 'Fail' }).Count | Should -Be 3
            $logs = Get-C2Row $rows 'Disk space: dc1.contoso.com L:\ (NTDS logs)'
            $logs.Detail | Should -Match 'event 1393' -Because 'a full log volume stops database updates as a full database volume does'
            $logs.Detail | Should -Match 'Net Logon'
            (Get-C2Row $rows 'Disk space: dc1.contoso.com D:\ (NTDS database)').Detail | Should -Match 'event 1393'
            (Get-C2Row $rows 'Disk space: dc1.contoso.com E:\ (SYSVOL)').Detail | Should -Not -Match '1393'
            # And it is the consequence of a FAIL: a log volume that only warns does not carry it.
            $warnVols = @(
                (New-C2Volume -Name 'D:\' -CapacityGB 100 -FreeGB 50),
                (New-C2Volume -Name 'L:\' -CapacityGB 100 -FreeGB 15),
                (New-C2Volume -Name 'E:\' -CapacityGB 100 -FreeGB 50)
            )
            $warnRows = @(Get-AdfaDcDiskFinding -DomainController $script:C2Dc1 -Scope 'contoso.com' -Raw (New-C2Raw -Paths $paths -Volumes $warnVols) -Config $script:Ddc)
            $warnLogs = Get-C2Row $warnRows 'Disk space: dc1.contoso.com L:\ (NTDS logs)'
            $warnLogs.Status | Should -Be 'Warning'
            $warnLogs.Detail | Should -Not -Match '1393'
        }
        It 'keeps the note about Microsoft''s 110 % figure out of the detail, in NotRun, on the database volume only' {
            $paths = @(
                (New-C2Path -Role 'NTDS database' -Value 'D:\NTDS\ntds.dit'),
                (New-C2Path -Role 'NTDS logs' -Value 'C:\Logs'),
                (New-C2Path -Role 'SYSVOL' -Value 'C:\Windows\SYSVOL\sysvol')
            )
            $vols = @((New-C2Volume -Name 'C:\' -CapacityGB 100 -FreeGB 50), (New-C2Volume -Name 'D:\' -CapacityGB 100 -FreeGB 50))
            $rows = @(Get-AdfaDcDiskFinding -DomainController $script:C2Dc1 -Scope 'contoso.com' -Raw (New-C2Raw -Paths $paths -Volumes $vols) -Config $script:Ddc)
            $db = Get-C2Row $rows 'Disk space: dc1.contoso.com D:\ (NTDS database)'
            [string]$db.NotRun | Should -Match '110 %'
            [string]$db.NotRun | Should -Match 'not measured'
            [string]$db.Detail | Should -Not -Match '110 %'
            [string](Get-C2Row $rows 'Disk space: dc1.contoso.com C:\ (NTDS logs, SYSVOL)').NotRun | Should -Be ''
        }
        It 'reports a registry value that is not set (provider return 1) as Not found for that role only, and assumes no default path' {
            # The return the provider gives for a value that does not exist under a key that
            # does: 1, not 2. Measured on a workstation, not published - and the row says so.
            $paths = @(
                (New-C2Path -Role 'NTDS database' -Value 'C:\Windows\NTDS\ntds.dit'),
                (New-C2Path -Role 'NTDS logs' -Value 'C:\Windows\NTDS'),
                (New-C2Path -Role 'SYSVOL' -Value '' -ReturnValue 1 -ExpandedReturnValue 1)
            )
            $rows = @(Get-AdfaDcDiskFinding -DomainController $script:C2Dc1 -Scope 'contoso.com' -Raw (New-C2Raw -Paths $paths -Volumes @((New-C2Volume -Name 'C:\' -CapacityGB 120 -FreeGB 60))) -Config $script:Ddc)
            $rows.Count | Should -Be 2
            (Get-C2Row $rows 'Disk space: dc1.contoso.com C:\ (NTDS database, NTDS logs)').Status | Should -Be 'Pass'
            $gap = Get-C2Row $rows 'Disk space: dc1.contoso.com - SYSVOL path'
            $gap.Status | Should -Be 'Not Assessed'
            $gap.Detail | Should -Match '^Not found: StdRegProv returned 1,'
            $gap.Detail | Should -Match 'the value not being set on this DC'
            $gap.Detail | Should -Match 'measured, not published by Microsoft'
            $gap.Detail | Should -Match 'not a domain controller'
            $gap.Detail | Should -Match 'Netlogon\\Parameters'
            $gap.Detail | Should -Match 'SysVol'
            $gap.Detail | Should -Match 'No default location is assumed'
            $gap.Detail | Should -Match 'GetExpandedStringValue was also tried and returned 1'
            $gap.Detail | Should -Not -Match '^Read failed'
            $gap.Detail | Should -Not -Match '(?i)access denied'
            foreach ($role in $script:C2Roles) { Get-C2RoleCount -Rows $rows -Dc $script:C2Dc1 -Role $role | Should -Be 1 }
        }
        It 'reports a registry key that does not exist (provider return 2) as Not found, and says it is the key' {
            $paths = @(
                (New-C2Path -Role 'NTDS database' -Value 'C:\Windows\NTDS\ntds.dit'),
                (New-C2Path -Role 'NTDS logs' -Value 'C:\Windows\NTDS'),
                (New-C2Path -Role 'SYSVOL' -Value '' -ReturnValue 2 -ExpandedReturnValue 2)
            )
            $rows = @(Get-AdfaDcDiskFinding -DomainController $script:C2Dc1 -Scope 'contoso.com' -Raw (New-C2Raw -Paths $paths -Volumes @((New-C2Volume -Name 'C:\' -CapacityGB 120 -FreeGB 60))) -Config $script:Ddc)
            $gap = Get-C2Row $rows 'Disk space: dc1.contoso.com - SYSVOL path'
            $gap.Status | Should -Be 'Not Assessed'
            $gap.Detail | Should -Match '^Not found: StdRegProv returned 2,'
            $gap.Detail | Should -Match 'ERROR_FILE_NOT_FOUND'
            $gap.Detail | Should -Match 'the registry key not existing on this DC'
            $gap.Detail | Should -Match 'measured, not published by Microsoft'
            $gap.Detail | Should -Match 'No default location is assumed'
            $gap.Detail | Should -Not -Match 'the value not being set'
        }
        It 'reads the two WbemErrorEnum codes Microsoft defines for a refusal and a type mismatch, and no others' {
            $paths = @(
                (New-C2Path -Role 'NTDS database' -Value '' -ReturnValue ([uint32]2147749891)),
                (New-C2Path -Role 'NTDS logs' -Value '' -ReturnValue ([uint32]2147749893) -ExpandedReturnValue ([uint32]2147749893)),
                (New-C2Path -Role 'SYSVOL' -Value '' -ReturnValue ([uint32]2147749890) -ExpandedReturnValue ([uint32]2147749890))
            )
            $rows = @(Get-AdfaDcDiskFinding -DomainController $script:C2Dc1 -Scope 'contoso.com' -Raw (New-C2Raw -Paths $paths -Volumes @((New-C2Volume -Name 'C:\' -CapacityGB 120 -FreeGB 60))) -Config $script:Ddc)
            # Declared population: one Not Assessed row per role.
            $rows.Count | Should -Be 3
            @($rows | Where-Object { $_.Status -ne 'Not Assessed' }).Count | Should -Be 0
            $denied = Get-C2Row $rows 'Disk space: dc1.contoso.com - NTDS database path'
            $denied.Detail | Should -Match '^Access denied: StdRegProv returned 2147749891 \(0x80041003\)'
            $denied.Detail | Should -Match 'wbemErrAccessDenied'
            $denied.Detail | Should -Match 'Administrators'
            $typed = Get-C2Row $rows 'Disk space: dc1.contoso.com - NTDS logs path'
            $typed.Detail | Should -Match '^The value is present but is not a string: StdRegProv returned 2147749893 \(0x80041005\)'
            $typed.Detail | Should -Match 'wbemErrTypeMismatch'
            # 0x80041002 is wbemErrNotFound in the enumeration, but nothing measured shows this
            # provider returning it, so it is quoted with its hex form and not given a meaning.
            $other = Get-C2Row $rows 'Disk space: dc1.contoso.com - SYSVOL path'
            $other.Detail | Should -Match '^Read failed: StdRegProv returned 2147749890 \(0x80041002\)\.'
            $other.Detail | Should -Match 'not interpreted'
        }
        It 'reports a refused registry read as access denied, not as absent' {
            $paths = @(
                (New-C2Path -Role 'NTDS database' -Value '' -ReturnValue 5),
                (New-C2Path -Role 'NTDS logs' -Value '' -ReturnValue 5),
                (New-C2Path -Role 'SYSVOL' -Value 'C:\Windows\SYSVOL\sysvol')
            )
            $rows = @(Get-AdfaDcDiskFinding -DomainController $script:C2Dc1 -Scope 'contoso.com' -Raw (New-C2Raw -Paths $paths -Volumes @((New-C2Volume -Name 'C:\' -CapacityGB 120 -FreeGB 60))) -Config $script:Ddc)
            $denied = Get-C2Row $rows 'Disk space: dc1.contoso.com - NTDS database path'
            $denied.Status | Should -Be 'Not Assessed'
            $denied.Detail | Should -Match '^Access denied'
            $denied.Detail | Should -Match 'ERROR_ACCESS_DENIED'
            $denied.Detail | Should -Match 'Administrators'
            $denied.Detail | Should -Not -Match '^Not found'
            (Get-C2Row $rows 'Disk space: dc1.contoso.com - NTDS logs path').Detail | Should -Match '^Access denied'
            (Get-C2Row $rows 'Disk space: dc1.contoso.com C:\ (SYSVOL)').Status | Should -Be 'Pass'
        }
        It 'quotes any other return code without interpreting it, and a thrown error by its class' {
            $paths = @(
                (New-C2Path -Role 'NTDS database' -Value '' -ReturnValue 87 -ExpandedReturnValue 87),
                (New-C2Path -Role 'NTDS logs' -Value '' -ReturnValue $null -Err 'The operation has timed out.' -Code 'Failed'),
                (New-C2Path -Role 'SYSVOL' -Value '' -ReturnValue $null -Err 'Acesso negado.' -Code 'AccessDenied')
            )
            $rows = @(Get-AdfaDcDiskFinding -DomainController $script:C2Dc1 -Scope 'contoso.com' -Raw (New-C2Raw -Paths $paths -Volumes @((New-C2Volume -Name 'C:\' -CapacityGB 120 -FreeGB 60))) -Config $script:Ddc)
            # Declared population: one Not Assessed row per role, none of them judged.
            $rows.Count | Should -Be 3
            @($rows | Where-Object { $_.Status -ne 'Not Assessed' }).Count | Should -Be 0
            $code = Get-C2Row $rows 'Disk space: dc1.contoso.com - NTDS database path'
            $code.Detail | Should -Match '^Read failed'
            $code.Detail | Should -Match 'returned 87 \(0x00000057\)\.'
            $code.Detail | Should -Match 'not interpreted'
            $code.Detail | Should -Match 'WinError\.h or WbemErrorEnum'
            $code.Detail | Should -Match 'GetExpandedStringValue was also tried and returned 87'
            $thrown = Get-C2Row $rows 'Disk space: dc1.contoso.com - NTDS logs path'
            $thrown.Detail | Should -Match '^Read failed'
            $thrown.Detail | Should -Match 'timed out'
            $refused = Get-C2Row $rows 'Disk space: dc1.contoso.com - SYSVOL path'
            $refused.Detail | Should -Match '^Access denied'
            $refused.Detail | Should -Match 'Acesso negado'
        }
        It 'reports an empty value, and a value with an unexpanded environment variable, as not resolvable' {
            $paths = @(
                (New-C2Path -Role 'NTDS database' -Value '' -ReturnValue 0),
                (New-C2Path -Role 'NTDS logs' -Value '%SystemRoot%\NTDS'),
                (New-C2Path -Role 'SYSVOL' -Value 'C:\Windows\SYSVOL\sysvol')
            )
            $rows = @(Get-AdfaDcDiskFinding -DomainController $script:C2Dc1 -Scope 'contoso.com' -Raw (New-C2Raw -Paths $paths -Volumes @((New-C2Volume -Name 'C:\' -CapacityGB 120 -FreeGB 60))) -Config $script:Ddc)
            $empty = Get-C2Row $rows 'Disk space: dc1.contoso.com - NTDS database path'
            $empty.Status | Should -Be 'Not Assessed'
            $empty.Detail | Should -Match 'present but empty'
            $env = Get-C2Row $rows 'Disk space: dc1.contoso.com - NTDS logs path'
            $env.Status | Should -Be 'Not Assessed'
            $env.Detail | Should -Match '%SystemRoot%\\NTDS'
            $env.Detail | Should -Match 'not expanded'
            foreach ($role in $script:C2Roles) { Get-C2RoleCount -Rows $rows -Dc $script:C2Dc1 -Role $role | Should -Be 1 }
        }
        It 'reports a path that is on no returned volume as Not Assessed, naming the path and the volumes' {
            $paths = @(
                (New-C2Path -Role 'NTDS database' -Value 'C:\Windows\NTDS\ntds.dit'),
                (New-C2Path -Role 'NTDS logs' -Value 'C:\Windows\NTDS'),
                (New-C2Path -Role 'SYSVOL' -Value 'S:\SYSVOL\sysvol')
            )
            $rows = @(Get-AdfaDcDiskFinding -DomainController $script:C2Dc1 -Scope 'contoso.com' -Raw (New-C2Raw -Paths $paths -Volumes @((New-C2Volume -Name 'C:\' -CapacityGB 120 -FreeGB 60))) -Config $script:Ddc)
            $gap = Get-C2Row $rows 'Disk space: dc1.contoso.com - SYSVOL path'
            $gap.Status | Should -Be 'Not Assessed'
            $gap.Detail | Should -Match 'S:\\SYSVOL\\sysvol'
            $gap.Detail | Should -Match 'C:\\'
        }
        It 'reports every role as Not Assessed, with the cause, when the volume list could not be read' {
            $raw = New-C2Raw -Paths (New-C2DefaultPaths) -Volumes @() -VolumesOk $false -VolumeError 'The operation has timed out.'
            $rows = @(Get-AdfaDcDiskFinding -DomainController $script:C2Dc1 -Scope 'contoso.com' -Raw $raw -Config $script:Ddc)
            $rows.Count | Should -Be 3
            @($rows | Where-Object { $_.Status -ne 'Not Assessed' }).Count | Should -Be 0
            $rows[0].Detail | Should -Match 'timed out'
            $rows[0].Detail | Should -Match 'C:\\Windows\\NTDS\\ntds\.dit'
            $deniedRaw = New-C2Raw -Paths (New-C2DefaultPaths) -Volumes @() -VolumesOk $false -VolumeError 'Acesso negado.' -VolumeErrorCode 'AccessDenied'
            $deniedRows = @(Get-AdfaDcDiskFinding -DomainController $script:C2Dc1 -Scope 'contoso.com' -Raw $deniedRaw -Config $script:Ddc)
            $deniedRows[0].Detail | Should -Match '(?i)access denied'
        }
        It 'does not pass a volume that returned no capacity (unformatted or offline)' {
            $vol = [pscustomobject]@{ Name = 'C:\'; DeviceID = '\\?\Volume{c}\'; DriveType = [uint32]3; Capacity = $null; FreeSpace = $null }
            $rows = @(Get-AdfaDcDiskFinding -DomainController $script:C2Dc1 -Scope 'contoso.com' -Raw (New-C2Raw -Paths (New-C2DefaultPaths) -Volumes @($vol)) -Config $script:Ddc)
            $rows.Count | Should -Be 1
            $rows[0].Status | Should -Be 'Not Assessed'
            $rows[0].Item | Should -Be 'Disk space: dc1.contoso.com C:\ (NTDS database, NTDS logs, SYSVOL)'
        }
        It 'reports a role the raw read holds no result for, instead of leaving it out' {
            $paths = @((New-C2Path -Role 'NTDS database' -Value 'C:\Windows\NTDS\ntds.dit'))
            $rows = @(Get-AdfaDcDiskFinding -DomainController $script:C2Dc1 -Scope 'contoso.com' -Raw (New-C2Raw -Paths $paths -Volumes @((New-C2Volume -Name 'C:\' -CapacityGB 120 -FreeGB 60))) -Config $script:Ddc)
            foreach ($role in $script:C2Roles) { Get-C2RoleCount -Rows $rows -Dc $script:C2Dc1 -Role $role | Should -Be 1 }
            (Get-C2Row $rows 'Disk space: dc1.contoso.com - SYSVOL path').Status | Should -Be 'Not Assessed'
        }
        It 'applies thresholds from an override and cites the file for them' {
            $cfg = Merge-AdfaDcDiskConfig -BaseConfig $script:Ddc -Override @{ WarnBelowPercent = 60; FailBelowPercent = 55 } -OverrideSource 'C:\cfg\disk.json'
            $raw = New-C2Raw -Paths (New-C2DefaultPaths) -Volumes @((New-C2Volume -Name 'C:\' -CapacityGB 120 -FreeGB 60))
            $row = @(Get-AdfaDcDiskFinding -DomainController $script:C2Dc1 -Scope 'contoso.com' -Raw $raw -Config $cfg)[0]
            $row.Status | Should -Be 'Fail'   # 50 % free, below the file's 55 %
            $row.Detail | Should -Match 'C:\\cfg\\disk\.json'
            $row.Detail | Should -Match 'Fail below 55 % free'
        }
    }

    Context 'Get-AdfaDcDiskSpace (collector)' {
        BeforeEach {
            Clear-AdfaDcPortCache
            $script:C2Reads = @()
        }
        It 'reads every DC, not only the first, and gives each its own rows and domain' {
            function Test-TcpPort { param([string]$ComputerName, [int]$Port, [int]$TimeoutMs) return $true }
            function Get-AdfaDcDiskRaw {
                param([string]$ComputerName, [string]$Protocol, [pscredential]$Credential, [int]$OperationTimeoutSec, $Paths)
                $script:C2Reads += $ComputerName
                $free = 60
                if ($ComputerName -eq $script:C2Dc2) { $free = 6 }
                if ($ComputerName -eq $script:C2Dc3) { $free = 18 }
                New-C2Raw -Paths (New-C2DefaultPaths) -Volumes @((New-C2Volume -Name 'C:\' -CapacityGB 120 -FreeGB $free)) -Protocol $Protocol
            }
            $dcs = @(
                [pscustomobject]@{ Scope = 'contoso.com'; HostName = $script:C2Dc1 },
                [pscustomobject]@{ Scope = 'contoso.com'; HostName = $script:C2Dc2 },
                [pscustomobject]@{ Scope = 'fabrikam.com'; HostName = $script:C2Dc3 }
            )
            $rows = @(Get-AdfaDcDiskSpace -DomainControllers $dcs -Config $script:Ddc)
            # Declared population: three DCs, one shared volume each.
            $rows.Count | Should -Be 3
            ($script:C2Reads -join ',') | Should -Be 'dc1.contoso.com,dc2.contoso.com,dc3.fabrikam.com'
            (Get-C2Row $rows 'Disk space: dc1.contoso.com C:\ (NTDS database, NTDS logs, SYSVOL)').Status | Should -Be 'Pass'
            (Get-C2Row $rows 'Disk space: dc2.contoso.com C:\ (NTDS database, NTDS logs, SYSVOL)').Status | Should -Be 'Fail'
            $third = Get-C2Row $rows 'Disk space: dc3.fabrikam.com C:\ (NTDS database, NTDS logs, SYSVOL)'
            $third.Status | Should -Be 'Warning'
            $third.Scope | Should -Be 'fabrikam.com'
            @($rows | Where-Object { $_.Scope -eq 'contoso.com' }).Count | Should -Be 2
        }
        It 'accepts plain host names as well as inventory rows' {
            function Test-TcpPort { param([string]$ComputerName, [int]$Port, [int]$TimeoutMs) return $true }
            function Get-AdfaDcDiskRaw {
                param([string]$ComputerName, [string]$Protocol, [pscredential]$Credential, [int]$OperationTimeoutSec, $Paths)
                New-C2Raw -Paths (New-C2DefaultPaths) -Volumes @((New-C2Volume -Name 'C:\' -CapacityGB 120 -FreeGB 60)) -Protocol $Protocol
            }
            $rows = @(Get-AdfaDcDiskSpace -DomainControllers @($script:C2Dc1, $script:C2Dc2) -Config $script:Ddc)
            $rows.Count | Should -Be 2
            (Get-C2Row $rows 'Disk space: dc2.contoso.com C:\ (NTDS database, NTDS logs, SYSVOL)').Status | Should -Be 'Pass'
            [string]$rows[0].Scope | Should -Be ''
        }
        It 'reports Not Assessed, never a clean result, when there are no DCs, and carries the enumeration error' {
            $rows = @(Get-AdfaDcDiskSpace -DomainControllers @() -Config $script:Ddc)
            $rows.Count | Should -Be 1
            $rows[0].Item | Should -Be 'Disk space'
            $rows[0].Status | Should -Be 'Not Assessed'
            $rows[0].Detail | Should -Match 'not a clean result'
            $why = @(Get-AdfaDcDiskSpace -DomainControllers $null -Config $script:Ddc -EnumerationError 'The server is not operational')
            $why.Count | Should -Be 1
            $why[0].Status | Should -Be 'Not Assessed'
            $why[0].Detail | Should -Match 'not operational'
        }
        It 'gives a domain whose inventory failed its own Not Assessed row, beside the DCs that were read' {
            function Test-TcpPort { param([string]$ComputerName, [int]$Port, [int]$TimeoutMs) return $true }
            function Get-AdfaDcDiskRaw {
                param([string]$ComputerName, [string]$Protocol, [pscredential]$Credential, [int]$OperationTimeoutSec, $Paths)
                New-C2Raw -Paths (New-C2DefaultPaths) -Volumes @((New-C2Volume -Name 'C:\' -CapacityGB 120 -FreeGB 60)) -Protocol $Protocol
            }
            $failed = @([pscustomobject]@{ Domain = 'child.contoso.com'; Error = 'The server is not operational' })
            $rows = @(Get-AdfaDcDiskSpace -DomainControllers @([pscustomobject]@{ Scope = 'contoso.com'; HostName = $script:C2Dc1 }) -Config $script:Ddc -InventoryFailures $failed)
            $rows.Count | Should -Be 2
            $gap = Get-C2Row $rows 'Disk space - child.contoso.com'
            $gap.Status | Should -Be 'Not Assessed'
            $gap.Scope | Should -Be 'child.contoso.com'
            $gap.Detail | Should -Match 'not operational'
            # The DC that was read belongs to another domain, so for this one the statement holds.
            $gap.Detail | Should -Match 'None of its volumes was read\.$'
        }
        It 'does not say "none of its volumes was read" for a failed domain when DCs without a domain follow it' {
            # The inventory of the only scoped domain threw, and the unscoped fallback
            # enumeration still returned a DC. The domain row used to claim nothing was read,
            # directly above a Pass row for that DC.
            function Test-TcpPort { param([string]$ComputerName, [int]$Port, [int]$TimeoutMs) return $true }
            function Get-AdfaDcDiskRaw {
                param([string]$ComputerName, [string]$Protocol, [pscredential]$Credential, [int]$OperationTimeoutSec, $Paths)
                New-C2Raw -Paths (New-C2DefaultPaths) -Volumes @((New-C2Volume -Name 'C:\' -CapacityGB 120 -FreeGB 60)) -Protocol $Protocol
            }
            $failed = @([pscustomobject]@{ Domain = 'contoso.com'; Error = 'ADWS down' })
            $rows = @(Get-AdfaDcDiskSpace -DomainControllers @($script:C2Dc1, $script:C2Dc2) -Config $script:Ddc -InventoryFailures $failed -ScopedDomains @('contoso.com'))
            # Declared population: the domain row, then one volume row for each of the two DCs.
            $rows.Count | Should -Be 3
            $gap = Get-C2Row $rows 'Disk space - contoso.com'
            $gap.Status | Should -Be 'Not Assessed'
            $gap.Detail | Should -Match 'ADWS down'
            $gap.Detail | Should -Not -Match '(?i)none of (its|their) volumes was read'
            $gap.Detail | Should -Match 'The 2 domain controller\(s\) listed in this section without a domain came from the fallback enumeration'
            $gap.Detail | Should -Match 'not shown as read'
            @($rows | Where-Object { $_.Status -eq 'Pass' -and [string]$_.Scope -eq '' }).Count | Should -Be 2
        }
        It 'accounts for every scoped domain: a domain with no DC row gets a Not Assessed row of its own, never a gap' {
            function Test-TcpPort { param([string]$ComputerName, [int]$Port, [int]$TimeoutMs) return $true }
            function Get-AdfaDcDiskRaw {
                param([string]$ComputerName, [string]$Protocol, [pscredential]$Credential, [int]$OperationTimeoutSec, $Paths)
                New-C2Raw -Paths (New-C2DefaultPaths) -Volumes @((New-C2Volume -Name 'C:\' -CapacityGB 120 -FreeGB 60)) -Protocol $Protocol
            }
            $scoped = @('contoso.com', 'north.contoso.com', 'south.contoso.com', 'fabrikam.com')
            $dcs = @(
                [pscustomobject]@{ Scope = 'contoso.com'; HostName = $script:C2Dc1 },
                [pscustomobject]@{ Scope = 'CONTOSO.com'; HostName = $script:C2Dc2 },
                [pscustomobject]@{ Scope = 'fabrikam.com'; HostName = $script:C2Dc3 }
            )
            $failed = @([pscustomobject]@{ Domain = 'south.contoso.com'; Error = 'The server is not operational' })
            $rows = @(Get-AdfaDcDiskSpace -DomainControllers $dcs -Config $script:Ddc -InventoryFailures $failed -ScopedDomains $scoped)
            # Declared population: the four scoped domains. Two are covered by DC rows (three
            # DCs), one failed, one returned no DC.
            $rows.Count | Should -Be 5
            foreach ($d in $scoped) {
                @($rows | Where-Object { [string]$_.Scope -eq $d }).Count | Should -BeGreaterThan 0 -Because "scoped domain $d must appear in the section"
            }
            (Get-C2Row $rows 'Disk space - contoso.com') | Should -BeNullOrEmpty
            (Get-C2Row $rows 'Disk space - fabrikam.com') | Should -BeNullOrEmpty
            $south = Get-C2Row $rows 'Disk space - south.contoso.com'
            $south.Status | Should -Be 'Not Assessed'
            $south.Detail | Should -Match 'could not be enumerated\. Cause: The server is not operational'
            $south.Detail | Should -Match 'None of its volumes was read\.$'
            $north = Get-C2Row $rows 'Disk space - north.contoso.com'
            $north.Status | Should -Be 'Not Assessed'
            $north.Scope | Should -Be 'north.contoso.com'
            $north.Detail | Should -Match 'returned no domain controller for this domain'
            $north.Detail | Should -Match 'None of its volumes was read\.$'
            @($rows | Where-Object { $_.Status -eq 'Pass' }).Count | Should -Be 3
            # With no DC at all, every scoped domain still has its row, and nothing passes.
            $none = @(Get-AdfaDcDiskSpace -DomainControllers @() -Config $script:Ddc -ScopedDomains $scoped)
            $none.Count | Should -Be 5   # four domain rows and the section's own "no DC enumerated" row
            @($none | Where-Object { $_.Status -ne 'Not Assessed' }).Count | Should -Be 0
            foreach ($d in $scoped) { (Get-C2Row $none ("Disk space - {0}" -f $d)).Status | Should -Be 'Not Assessed' }
        }
        It 'passes the run''s credential to the seam for every DC and transport, and none when there is none' {
            $script:C2Creds = @()
            function Test-TcpPort { param([string]$ComputerName, [int]$Port, [int]$TimeoutMs) return $true }
            function Get-AdfaDcDiskRaw {
                param([string]$ComputerName, [string]$Protocol, [pscredential]$Credential, [int]$OperationTimeoutSec, $Paths)
                $user = '(none)'
                if ($PSBoundParameters.ContainsKey('Credential') -and $null -ne $Credential) { $user = [string]$Credential.UserName }
                $script:C2Creds += ("{0}/{1}/{2}/{3}" -f $ComputerName, $Protocol, $user, $OperationTimeoutSec)
                if ($Protocol -eq 'Wsman') { return (Get-C2FailedRaw -Protocol $Protocol -Message 'The WinRM client cannot process the request.' -Code 'Failed') }
                New-C2Raw -Paths (New-C2DefaultPaths) -Volumes @((New-C2Volume -Name 'C:\' -CapacityGB 120 -FreeGB 60)) -Protocol $Protocol
            }
            $secret = New-Object System.Security.SecureString
            foreach ($ch in 'stub'.ToCharArray()) { $secret.AppendChar($ch) }
            $cred = New-Object System.Management.Automation.PSCredential -ArgumentList 'CONTOSO\reader', $secret
            Get-AdfaDcDiskSpace -DomainControllers @($script:C2Dc1, $script:C2Dc2) -Config $script:Ddc -Credential $cred -OperationTimeoutSec 45 | Out-Null
            # Declared population: two DCs, two transports each.
            ($script:C2Creds -join ',') | Should -Be 'dc1.contoso.com/Wsman/CONTOSO\reader/45,dc1.contoso.com/Dcom/CONTOSO\reader/45,dc2.contoso.com/Wsman/CONTOSO\reader/45,dc2.contoso.com/Dcom/CONTOSO\reader/45'
            Clear-AdfaDcPortCache
            $script:C2Creds = @()
            Get-AdfaDcDiskSpace -DomainControllers @($script:C2Dc1) -Config $script:Ddc | Out-Null
            ($script:C2Creds -join ',') | Should -Be 'dc1.contoso.com/Wsman/(none)/90,dc1.contoso.com/Dcom/(none)/90'
        }
        It 'reports an unreachable DC as unreachable, without attempting a read' {
            function Test-TcpPort { param([string]$ComputerName, [int]$Port, [int]$TimeoutMs) return $false }
            function Get-AdfaDcDiskRaw { param([string]$ComputerName, [string]$Protocol, [pscredential]$Credential, [int]$OperationTimeoutSec, $Paths) $script:C2Reads += $ComputerName }
            $rows = @(Get-AdfaDcDiskSpace -DomainControllers @($script:C2Dc1) -Config $script:Ddc)
            $rows.Count | Should -Be 1
            $rows[0].Item | Should -Be 'Disk space: dc1.contoso.com'
            $rows[0].Status | Should -Be 'Not Assessed'
            $rows[0].Detail | Should -Match '^Unreachable'
            $rows[0].Detail | Should -Match '5985'
            $rows[0].Detail | Should -Match '135'
            @($script:C2Reads).Count | Should -Be 0
        }
        It 'reports access denied as access denied, not as unreachable, and does not retry it over DCOM' {
            function Test-TcpPort { param([string]$ComputerName, [int]$Port, [int]$TimeoutMs) return $true }
            function Get-AdfaDcDiskRaw {
                param([string]$ComputerName, [string]$Protocol, [pscredential]$Credential, [int]$OperationTimeoutSec, $Paths)
                $script:C2Reads += $Protocol
                Get-C2FailedRaw -Protocol $Protocol -Message 'Acesso negado.' -Code 'AccessDenied'
            }
            $rows = @(Get-AdfaDcDiskSpace -DomainControllers @($script:C2Dc1) -Config $script:Ddc)
            $rows.Count | Should -Be 1
            $rows[0].Status | Should -Be 'Not Assessed'
            $rows[0].Detail | Should -Match '^Access denied'
            $rows[0].Detail | Should -Match 'Administrators'
            $rows[0].Detail | Should -Match 'Acesso negado'
            $rows[0].Detail | Should -Not -Match '(?i)unreachable'
            ($script:C2Reads -join ',') | Should -Be 'Wsman'
        }
        It 'recognises a refusal by its English text when no error code came with it' {
            function Test-TcpPort { param([string]$ComputerName, [int]$Port, [int]$TimeoutMs) return $true }
            function Get-AdfaDcDiskRaw {
                param([string]$ComputerName, [string]$Protocol, [pscredential]$Credential, [int]$OperationTimeoutSec, $Paths)
                Get-C2FailedRaw -Protocol $Protocol -Message 'Access is denied.'
            }
            $rows = @(Get-AdfaDcDiskSpace -DomainControllers @($script:C2Dc1) -Config $script:Ddc)
            $rows[0].Detail | Should -Match '^Access denied'
        }
        It 'reports any other failure as a read failure, with both attempts quoted, and not as a refusal' {
            function Test-TcpPort { param([string]$ComputerName, [int]$Port, [int]$TimeoutMs) return $true }
            function Get-AdfaDcDiskRaw {
                param([string]$ComputerName, [string]$Protocol, [pscredential]$Credential, [int]$OperationTimeoutSec, $Paths)
                Get-C2FailedRaw -Protocol $Protocol -Message "The RPC server is unavailable ($Protocol)." -Code 'Failed'
            }
            $rows = @(Get-AdfaDcDiskSpace -DomainControllers @($script:C2Dc1) -Config $script:Ddc)
            $rows.Count | Should -Be 1
            $rows[0].Status | Should -Be 'Not Assessed'
            $rows[0].Detail | Should -Match '^Read failed'
            $rows[0].Detail | Should -Not -Match '^Access denied'
            $rows[0].Detail | Should -Match 'unavailable \(Wsman\)'
            $rows[0].Detail | Should -Match 'unavailable \(Dcom\)'
        }
        It 'tries WinRM first and DCOM second, and reports which one answered' {
            function Test-TcpPort { param([string]$ComputerName, [int]$Port, [int]$TimeoutMs) return $true }
            function Get-AdfaDcDiskRaw {
                param([string]$ComputerName, [string]$Protocol, [pscredential]$Credential, [int]$OperationTimeoutSec, $Paths)
                $script:C2Reads += $Protocol
                if ($Protocol -eq 'Wsman') { return (Get-C2FailedRaw -Protocol $Protocol -Message 'The WinRM client cannot process the request.' -Code 'Failed') }
                New-C2Raw -Paths (New-C2DefaultPaths) -Volumes @((New-C2Volume -Name 'C:\' -CapacityGB 120 -FreeGB 60)) -Protocol $Protocol
            }
            $rows = @(Get-AdfaDcDiskSpace -DomainControllers @($script:C2Dc1) -Config $script:Ddc)
            ($script:C2Reads -join ',') | Should -Be 'Wsman,Dcom'
            $rows[0].Status | Should -Be 'Pass'
            $rows[0].Detail | Should -Match 'Read over Dcom'
        }
        It 'uses only the transport whose port answered, and the ports the config names' {
            $script:C2Probed = @()
            function Test-TcpPort { param([string]$ComputerName, [int]$Port, [int]$TimeoutMs) $script:C2Probed += $Port; return ($Port -eq 1135) }
            function Get-AdfaDcDiskRaw {
                param([string]$ComputerName, [string]$Protocol, [pscredential]$Credential, [int]$OperationTimeoutSec, $Paths)
                $script:C2Reads += $Protocol
                New-C2Raw -Paths (New-C2DefaultPaths) -Volumes @((New-C2Volume -Name 'C:\' -CapacityGB 120 -FreeGB 60)) -Protocol $Protocol
            }
            $cfg = Merge-AdfaDcDiskConfig -BaseConfig $script:Ddc -Override @{ WsmanPort = 5986; RpcPort = 1135 }
            Get-AdfaDcDiskSpace -DomainControllers @($script:C2Dc1) -Config $cfg | Out-Null
            ($script:C2Reads -join ',') | Should -Be 'Dcom'
            (@($script:C2Probed | Sort-Object) -join ',') | Should -Be '1135,5986'
        }
        It 'hands the seam the registry values the config names' {
            function Test-TcpPort { param([string]$ComputerName, [int]$Port, [int]$TimeoutMs) return $true }
            function Get-AdfaDcDiskRaw {
                param([string]$ComputerName, [string]$Protocol, [pscredential]$Credential, [int]$OperationTimeoutSec, $Paths)
                $script:C2Reads += (@($Paths | ForEach-Object { [string]$_.ValueName }) -join '|')
                New-C2Raw -Paths (New-C2DefaultPaths) -Volumes @((New-C2Volume -Name 'C:\' -CapacityGB 120 -FreeGB 60)) -Protocol $Protocol
            }
            Get-AdfaDcDiskSpace -DomainControllers @($script:C2Dc1) -Config $script:Ddc | Out-Null
            $script:C2Reads[0] | Should -Be 'DSA Database File|Database Log Files Path|SysVol'
        }
        It 'handles a mixed set: one DC read, one unreachable, one refused - and passes nothing it did not read' {
            function Test-TcpPort { param([string]$ComputerName, [int]$Port, [int]$TimeoutMs) return ($ComputerName -ne $script:C2Dc2) }
            function Get-AdfaDcDiskRaw {
                param([string]$ComputerName, [string]$Protocol, [pscredential]$Credential, [int]$OperationTimeoutSec, $Paths)
                if ($ComputerName -eq $script:C2Dc3) { return (Get-C2FailedRaw -Protocol $Protocol -Message 'Access is denied.' -Code 'AccessDenied') }
                New-C2Raw -Paths (New-C2DefaultPaths) -Volumes @((New-C2Volume -Name 'C:\' -CapacityGB 120 -FreeGB 60)) -Protocol $Protocol
            }
            $rows = @(Get-AdfaDcDiskSpace -DomainControllers @($script:C2Dc1, $script:C2Dc2, $script:C2Dc3) -Config $script:Ddc)
            # Declared population: one row for each of the three DCs.
            $rows.Count | Should -Be 3
            (Get-C2Row $rows 'Disk space: dc1.contoso.com C:\ (NTDS database, NTDS logs, SYSVOL)').Status | Should -Be 'Pass'
            $down = Get-C2Row $rows 'Disk space: dc2.contoso.com'
            $down.Status | Should -Be 'Not Assessed'
            $down.Detail | Should -Match '^Unreachable'
            $refused = Get-C2Row $rows 'Disk space: dc3.fabrikam.com'
            $refused.Status | Should -Be 'Not Assessed'
            $refused.Detail | Should -Match '^Access denied'
            @($rows | Where-Object { $_.Status -eq 'Pass' }).Count | Should -Be 1
        }
        It 'never reports Info: a row is a verdict or it is Not Assessed' {
            function Test-TcpPort { param([string]$ComputerName, [int]$Port, [int]$TimeoutMs) return ($ComputerName -ne $script:C2Dc2) }
            function Get-AdfaDcDiskRaw {
                param([string]$ComputerName, [string]$Protocol, [pscredential]$Credential, [int]$OperationTimeoutSec, $Paths)
                $paths = @((New-C2Path -Role 'NTDS database' -Value 'C:\Windows\NTDS\ntds.dit'), (New-C2Path -Role 'NTDS logs' -Value '' -ReturnValue 2), (New-C2Path -Role 'SYSVOL' -Value 'D:\SYSVOL\sysvol'))
                New-C2Raw -Paths $paths -Volumes @((New-C2Volume -Name 'C:\' -CapacityGB 120 -FreeGB 60), (New-C2Volume -Name 'D:\' -CapacityGB 100 -FreeGB 1)) -Protocol $Protocol
            }
            $rows = @(Get-AdfaDcDiskSpace -DomainControllers @($script:C2Dc1, $script:C2Dc2) -Config $script:Ddc)
            # Declared population: dc1 gives C: (Pass), D: (Fail) and the logs path (Not Assessed); dc2 one row.
            $rows.Count | Should -Be 4
            @($rows | Where-Object { @('Pass', 'Warning', 'Fail', 'Not Assessed') -notcontains [string]$_.Status }).Count | Should -Be 0
            (@($rows | ForEach-Object { [string]$_.Status } | Sort-Object) -join ',') | Should -Be 'Fail,Not Assessed,Not Assessed,Pass'
        }
        It 'shares the per-run probe cache, and never probes a port directly' {
            $script:C2ProbeCount = 0
            function Test-TcpPort { param([string]$ComputerName, [int]$Port, [int]$TimeoutMs) $script:C2ProbeCount++; return $true }
            function Get-AdfaDcDiskRaw {
                param([string]$ComputerName, [string]$Protocol, [pscredential]$Credential, [int]$OperationTimeoutSec, $Paths)
                New-C2Raw -Paths (New-C2DefaultPaths) -Volumes @((New-C2Volume -Name 'C:\' -CapacityGB 120 -FreeGB 60)) -Protocol $Protocol
            }
            Get-AdfaDcDiskSpace -DomainControllers @($script:C2Dc1, $script:C2Dc2) -Config $script:Ddc | Out-Null
            Get-AdfaDcDiskSpace -DomainControllers @($script:C2Dc1, $script:C2Dc2) -Config $script:Ddc | Out-Null
            # Two DCs, two ports each, asked once per run however many times the section reads them.
            $script:C2ProbeCount | Should -Be 4
            $fn = @($script:C2Ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Get-AdfaDcDiskSpace' }, $true))
            $fn.Count | Should -Be 1
            $inner = @($fn[0].FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true) | ForEach-Object { [string]$_.GetCommandName() })
            $inner | Should -Contain 'Test-AdfaDcPort'
            $inner | Should -Not -Contain 'Test-TcpPort'
        }
        It 'gives a low-space row its own advice, which no later generic entry or file path can replace' {
            function Test-TcpPort { param([string]$ComputerName, [int]$Port, [int]$TimeoutMs) return $true }
            function Get-AdfaDcDiskRaw {
                param([string]$ComputerName, [string]$Protocol, [pscredential]$Credential, [int]$OperationTimeoutSec, $Paths)
                New-C2Raw -Paths (New-C2DefaultPaths) -Volumes @((New-C2Volume -Name 'C:\' -CapacityGB 120 -FreeGB 3)) -Protocol $Protocol
            }
            # A file path full of words the unscoped entries match on.
            $cfg = Merge-AdfaDcDiskConfig -BaseConfig $script:Ddc -Override @{ WarnBelowPercent = 25 } -OverrideSource 'C:\Backup\replication\sysvol-dfsr-stale-clock.json'
            $row = @(Get-AdfaDcDiskSpace -DomainControllers @($script:C2Dc1) -Config $cfg)[0]
            $row.Status | Should -Be 'Fail'
            $row.Item | Should -Match 'SYSVOL'
            $rec = Get-AdfaRecommendation -Section 'DC Disk Space' -Item ([string]$row.Item) -Detail ([string]$row.Detail)
            $rec | Should -Match 'Move unrelated files'
            $rec | Should -Match 'system state backup'
            $rec | Should -Not -Match 'D4|dfsrmig|repadmin|wbadmin|w32tm|scavenging|Disable first'
            # The section's own entry is what answered, not a coincidence of wording.
            (Get-AdfaRecommendation -Section 'SYSVOL / DFSR' -Item ([string]$row.Item) -Detail ([string]$row.Detail)) | Should -Not -Be $rec
        }
        It 'chooses the advice before the not-measured note is added to the finding' {
            function Test-TcpPort { param([string]$ComputerName, [int]$Port, [int]$TimeoutMs) return $true }
            function Get-AdfaDcDiskRaw {
                param([string]$ComputerName, [string]$Protocol, [pscredential]$Credential, [int]$OperationTimeoutSec, $Paths)
                New-C2Raw -Paths (New-C2DefaultPaths) -Volumes @((New-C2Volume -Name 'C:\' -CapacityGB 120 -FreeGB 18)) -Protocol $Protocol
            }
            $row = @(Get-AdfaDcDiskSpace -DomainControllers @($script:C2Dc1) -Config $script:Ddc)[0]
            $row.Status | Should -Be 'Warning'
            $f = ConvertTo-AdfaConsolidatedFinding -Section 'DC Disk Space' -Row $row -StatusColumn 'Status'
            $f.Recommendation | Should -Match 'Move unrelated files'
            $f.Detail | Should -Match '110 %'
            $f.Status | Should -Be 'Warning'
            # A Pass row and a Not Assessed row carry no advice.
            $pass = [pscustomobject]@{ Scope = ''; Area = 'DcDisk'; Item = 'Disk space: x C:\ (SYSVOL)'; Status = 'Pass'; Detail = 'd'; NotRun = '' }
            (ConvertTo-AdfaConsolidatedFinding -Section 'DC Disk Space' -Row $pass -StatusColumn 'Status').Recommendation | Should -Be ''
        }
    }

    Context 'Get-AdfaDcTargetsByDomain (the section''s own enumeration, when there is no DC inventory)' {
        BeforeEach {
            $script:C2Asked = @()
            # Get-ADDomainController in the shape the cmdlet returns: one object per DC with a
            # HostName. It answers per -Server, so a call that carried none is visible.
            function Get-ADDomainController {
                param($Filter, [string]$Server, [pscredential]$Credential)
                $user = '(none)'
                if ($null -ne $Credential) { $user = [string]$Credential.UserName }
                $script:C2Asked += ("{0}|{1}|{2}" -f $Server, [string]$Filter, $user)
                if ($Server -eq 'north.contoso.com') { throw 'The server is not operational' }
                if ($Server -eq 'contoso.com') { return @([pscustomobject]@{ HostName = 'dc1.contoso.com' }, [pscustomobject]@{ HostName = 'dc2.contoso.com' }) }
                if ($Server -eq 'south.contoso.com') { return @([pscustomobject]@{ HostName = 'dc1.south.contoso.com' }) }
                if ($Server -eq 'empty.contoso.com') { return @() }
                return @([pscustomobject]@{ HostName = 'dc-of-the-default-server.contoso.com' })
            }
        }
        It 'asks each scoped domain for its own DCs and gives each DC its domain' {
            $domains = @('contoso.com', 'north.contoso.com', 'south.contoso.com', 'empty.contoso.com')
            $r = Get-AdfaDcTargetsByDomain -Domains $domains
            # Declared population: the four domains, each asked once, by name.
            ($script:C2Asked -join ',') | Should -Be 'contoso.com|*|(none),north.contoso.com|*|(none),south.contoso.com|*|(none),empty.contoso.com|*|(none)'
            @($r.Targets).Count | Should -Be 3
            (@($r.Targets | ForEach-Object { "{0}={1}" -f $_.Scope, $_.HostName }) -join ',') | Should -Be 'contoso.com=dc1.contoso.com,contoso.com=dc2.contoso.com,south.contoso.com=dc1.south.contoso.com'
            # The DC of the default server was never returned: no call went out without -Server.
            @($r.Targets | Where-Object { $_.HostName -like 'dc-of-the-default-server*' }).Count | Should -Be 0
            @($r.Failures).Count | Should -Be 1
            $r.Failures[0].Domain | Should -Be 'north.contoso.com'
            $r.Failures[0].Error | Should -Match 'not operational'
        }
        It 'carries the run''s AD parameters, with the domain replacing any -Server' {
            $secret = New-Object System.Security.SecureString
            foreach ($ch in 'stub'.ToCharArray()) { $secret.AppendChar($ch) }
            $cred = New-Object System.Management.Automation.PSCredential -ArgumentList 'CONTOSO\reader', $secret
            $adParams = @{ Server = 'dc9.contoso.com'; Credential = $cred }
            $r = Get-AdfaDcTargetsByDomain -Domains @('contoso.com', 'south.contoso.com') -AdParams $adParams
            ($script:C2Asked -join ',') | Should -Be 'contoso.com|*|CONTOSO\reader,south.contoso.com|*|CONTOSO\reader'
            @($r.Targets).Count | Should -Be 3
            # The caller's table is not changed by the call.
            $adParams.Server | Should -Be 'dc9.contoso.com'
        }
        It 'returns nothing, and does not throw, for no domains' {
            $r = Get-AdfaDcTargetsByDomain -Domains @()
            @($r.Targets).Count | Should -Be 0
            @($r.Failures).Count | Should -Be 0
            @($script:C2Asked).Count | Should -Be 0
            $n = Get-AdfaDcTargetsByDomain -Domains $null
            @($n.Targets).Count | Should -Be 0
        }
        It 'feeds the collector so that every scoped domain is in the section, with the failed and the empty one as Not Assessed' {
            function Test-TcpPort { param([string]$ComputerName, [int]$Port, [int]$TimeoutMs) return $true }
            function Get-AdfaDcDiskRaw {
                param([string]$ComputerName, [string]$Protocol, [pscredential]$Credential, [int]$OperationTimeoutSec, $Paths)
                New-C2Raw -Paths (New-C2DefaultPaths) -Volumes @((New-C2Volume -Name 'C:\' -CapacityGB 120 -FreeGB 60)) -Protocol $Protocol
            }
            Clear-AdfaDcPortCache
            $domains = @('contoso.com', 'north.contoso.com', 'south.contoso.com', 'empty.contoso.com')
            $r = Get-AdfaDcTargetsByDomain -Domains $domains
            $rows = @(Get-AdfaDcDiskSpace -DomainControllers $r.Targets -Config $script:Ddc -InventoryFailures $r.Failures -ScopedDomains $domains)
            # Declared population: three DC rows and one row each for the failed and the empty domain.
            $rows.Count | Should -Be 5
            foreach ($d in $domains) { @($rows | Where-Object { [string]$_.Scope -eq $d }).Count | Should -BeGreaterThan 0 -Because "$d was scoped" }
            @($rows | Where-Object { $_.Scope -eq 'contoso.com' -and $_.Status -eq 'Pass' }).Count | Should -Be 2
            @($rows | Where-Object { $_.Scope -eq 'south.contoso.com' -and $_.Status -eq 'Pass' }).Count | Should -Be 1
            (Get-C2Row $rows 'Disk space - north.contoso.com').Status | Should -Be 'Not Assessed'
            (Get-C2Row $rows 'Disk space - empty.contoso.com').Status | Should -Be 'Not Assessed'
        }
    }

    Context 'Get-AdfaDcDiskRaw (the CIM seam)' {
        BeforeAll {
            function New-CimSessionOption { param([string]$Protocol) [pscustomobject]@{ Protocol = $Protocol } }
            # Simple functions on purpose, with -WhatIf and -Confirm NOT declared: the values the
            # caller passes for them then arrive in $args as '-WhatIf:' followed by the value.
            function Get-C2Switch {
                param($Arguments, [string]$Name)
                for ($i = 0; $i -lt @($Arguments).Count; $i++) {
                    if ([string]$Arguments[$i] -eq ("-{0}:" -f $Name) -and ($i + 1) -lt @($Arguments).Count) { return $Arguments[$i + 1] }
                }
                return $null
            }
            function Remove-CimSession {
                param($CimSession)
                $script:C2Closed++
                $script:C2CloseCalls += [pscustomobject]@{ WhatIf = (Get-C2Switch -Arguments $args -Name 'WhatIf'); Confirm = (Get-C2Switch -Arguments $args -Name 'Confirm') }
            }
            function New-CimSession { param([string]$ComputerName, $SessionOption, [uint32]$OperationTimeoutSec, [pscredential]$Credential, $ErrorAction)
                $p = 'none'; if ($null -ne $SessionOption) { $p = [string]$SessionOption.Protocol }; $script:C2Opts += $p
                $user = '(none)'
                if ($PSBoundParameters.ContainsKey('Credential') -and $null -ne $Credential) { $user = [string]$Credential.UserName }
                $script:C2Sessions += [pscustomobject]@{ ComputerName = $ComputerName; User = $user; OperationTimeoutSec = $OperationTimeoutSec }
                [pscustomobject]@{ ComputerName = $ComputerName } }
            # StdRegProv through Invoke-CimMethod returns an object with ReturnValue (uint32) and the
            # method's [out] parameter, sValue.
            # The return codes are the ones MEASURED from the real provider on 2026-11-13 (one
            # Windows 11 workstation, not a DC; both methods, both PowerShell editions):
            #   1  a value that does not exist under a key that does
            #   2  a key that does not exist
            # An earlier version of this stub answered 2 for an absent value, which the real
            # provider does not, so every "Not found" test was green over a shape that could
            # not occur. The stub's registry holds the three keys a DC has; a value it does not
            # hold answers 1, and a key listed in $script:C2AbsentKeys answers 2.
            function Invoke-CimMethod {
                param($CimSession, [string]$Namespace, [string]$ClassName, [string]$MethodName, $Arguments, [uint32]$OperationTimeoutSec, $ErrorAction)
                $bounded = $PSBoundParameters.ContainsKey('OperationTimeoutSec')
                $script:C2Calls += [pscustomobject]@{ Namespace = $Namespace; ClassName = $ClassName; MethodName = $MethodName
                    Hive = $Arguments['hDefKey']; Key = [string]$Arguments['sSubKeyName']; ValueName = [string]$Arguments['sValueName']
                    WhatIf = (Get-C2Switch -Arguments $args -Name 'WhatIf'); Confirm = (Get-C2Switch -Arguments $args -Name 'Confirm')
                    Bounded = $bounded; OperationTimeoutSec = $OperationTimeoutSec }
                if (@($script:C2AbsentKeys) -contains [string]$Arguments['sSubKeyName']) { return [pscustomobject]@{ ReturnValue = [uint32]2; sValue = $null; PSComputerName = 'x' } }
                $answer = $script:C2Registry[("{0}|{1}" -f $MethodName, [string]$Arguments['sValueName'])]
                if ($null -eq $answer) { return [pscustomobject]@{ ReturnValue = [uint32]1; sValue = $null; PSComputerName = 'x' } }
                if ($answer -is [System.Exception]) { throw $answer }
                return [pscustomobject]@{ ReturnValue = [uint32]$answer.Code; sValue = $answer.Value; PSComputerName = 'x' }
            }
            function Get-CimInstance {
                param($CimSession, [string]$Namespace, [string]$ClassName, [string[]]$Property, [uint32]$OperationTimeoutSec, $ErrorAction)
                $script:C2Queries += $ClassName
                $script:C2QueryCalls += [pscustomobject]@{ ClassName = $ClassName; Bounded = $PSBoundParameters.ContainsKey('OperationTimeoutSec'); OperationTimeoutSec = $OperationTimeoutSec }
                if ($null -ne $script:C2VolumeError) { throw $script:C2VolumeError }
                return $script:C2VolumeAnswer
            }
            $script:C2Paths = $script:Config.DcDisk.Paths
        }
        BeforeEach {
            $script:C2Closed = 0
            $script:C2CloseCalls = @()
            $script:C2Sessions = @()
            $script:C2AbsentKeys = @()
            $script:C2QueryCalls = @()
            $script:C2Opts = @()
            $script:C2Calls = @()
            $script:C2Queries = @()
            $script:C2VolumeError = $null
            $script:C2VolumeAnswer = @(
                (New-C2Volume -Name 'C:\' -CapacityGB 120 -FreeGB 60),
                (New-C2Volume -Name '\\?\Volume{11111111-2222-3333-4444-555555555555}\' -CapacityGB 0.5 -FreeGB 0.1)
            )
            $script:C2Registry = @{
                'GetStringValue|DSA Database File'       = @{ Code = 0; Value = 'C:\Windows\NTDS\ntds.dit' }
                'GetStringValue|Database Log Files Path' = @{ Code = 0; Value = 'C:\Windows\NTDS' }
                'GetStringValue|SysVol'                  = @{ Code = 0; Value = 'C:\Windows\SYSVOL\sysvol' }
            }
        }
        It 'reads the three values from HKLM with GetStringValue, then the volumes, and closes the session' {
            $r = Get-AdfaDcDiskRaw -ComputerName $script:C2Dc1 -Protocol 'Wsman' -OperationTimeoutSec 30 -Paths $script:C2Paths
            $r.Ok | Should -BeTrue
            $r.Protocol | Should -Be 'Wsman'
            # Declared population: one read per role.
            @($r.Paths).Count | Should -Be 3
            @($script:C2Calls).Count | Should -Be 3
            foreach ($c in $script:C2Calls) {
                $c.ClassName | Should -Be 'StdRegProv'
                $c.MethodName | Should -Be 'GetStringValue'
                $c.Namespace | Should -Be 'root/cimv2'
                [uint32]$c.Hive | Should -Be ([uint32]2147483650)   # HKEY_LOCAL_MACHINE
                # Given, and given as $false: $null here would mean the switch was not passed.
                ($null -ne $c.WhatIf) | Should -BeTrue -Because '-WhatIf must be passed'
                $c.WhatIf | Should -Be $false
                ($null -ne $c.Confirm) | Should -BeTrue -Because '-Confirm must be passed'
                $c.Confirm | Should -Be $false
                # Bounded by the caller's timeout, not left to the session default.
                $c.Bounded | Should -BeTrue
                $c.OperationTimeoutSec | Should -Be 30
            }
            # The volume query is bounded by the same timeout, and so is the session.
            @($script:C2QueryCalls).Count | Should -Be 1
            $script:C2QueryCalls[0].Bounded | Should -BeTrue
            $script:C2QueryCalls[0].OperationTimeoutSec | Should -Be 30
            @($script:C2Sessions).Count | Should -Be 1
            $script:C2Sessions[0].OperationTimeoutSec | Should -Be 30
            $script:C2Sessions[0].User | Should -Be '(none)'
            # Closing the session is not left to a WhatIf or Confirm preference either.
            @($script:C2CloseCalls).Count | Should -Be 1
            ($null -ne $script:C2CloseCalls[0].WhatIf) | Should -BeTrue -Because '-WhatIf must be passed'
            $script:C2CloseCalls[0].WhatIf | Should -Be $false
            ($null -ne $script:C2CloseCalls[0].Confirm) | Should -BeTrue -Because '-Confirm must be passed'
            $script:C2CloseCalls[0].Confirm | Should -Be $false
            (@($script:C2Calls | ForEach-Object { "{0}\{1}" -f $_.Key, $_.ValueName }) -join '|') | Should -Be (
                'SYSTEM\CurrentControlSet\Services\NTDS\Parameters\DSA Database File|SYSTEM\CurrentControlSet\Services\NTDS\Parameters\Database Log Files Path|SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\SysVol')
            $db = @($r.Paths | Where-Object { $_.Role -eq 'NTDS database' })[0]
            $db.Read | Should -BeTrue
            $db.Value | Should -Be 'C:\Windows\NTDS\ntds.dit'
            $db.ReturnValue | Should -Be 0
            $db.Method | Should -Be 'GetStringValue'
            $r.VolumesOk | Should -BeTrue
            @($r.Volumes).Count | Should -Be 2
            $r.Volumes[0].Name | Should -Be 'C:\'
            $r.Volumes[0].Capacity | Should -Be ([uint64](120 * $script:C2GB))
            $r.Volumes[0].DriveType | Should -Be 3
            ($script:C2Queries -join ',') | Should -Be 'Win32_Volume'
            $script:C2Closed | Should -Be 1
        }
        It 'feeds the pure layer a result it can judge' {
            $r = Get-AdfaDcDiskRaw -ComputerName $script:C2Dc1 -Protocol 'Wsman' -OperationTimeoutSec 30 -Paths $script:C2Paths
            $rows = @(Get-AdfaDcDiskFinding -DomainController $script:C2Dc1 -Scope 'contoso.com' -Raw $r -Config $script:Ddc)
            $rows.Count | Should -Be 1
            $rows[0].Status | Should -Be 'Pass'
        }
        It 'keeps the return code of a value that is not set (1), still reads the other two, and the row names it Not found' {
            $script:C2Registry.Remove('GetStringValue|SysVol')   # the stub, like the provider, answers 1 for a value its key does not hold
            $r = Get-AdfaDcDiskRaw -ComputerName $script:C2Dc1 -Protocol 'Wsman' -OperationTimeoutSec 30 -Paths $script:C2Paths
            $r.Ok | Should -BeTrue
            $sv = @($r.Paths | Where-Object { $_.Role -eq 'SYSVOL' })[0]
            $sv.Read | Should -BeFalse
            $sv.ReturnValue | Should -Be 1
            $sv.ExpandedReturnValue | Should -Be 1
            @($r.Paths | Where-Object { $_.Read }).Count | Should -Be 2
            # The string read failed, so the expanded-string read was tried for that one value only.
            (@($script:C2Calls | ForEach-Object { "{0}:{1}" -f $_.MethodName, $_.ValueName }) -join '|') | Should -Be (
                'GetStringValue:DSA Database File|GetStringValue:Database Log Files Path|GetStringValue:SysVol|GetExpandedStringValue:SysVol')
            # Seam to row: the not-configured case reaches the operator as Not found, not as an
            # uninterpreted read failure.
            $rows = @(Get-AdfaDcDiskFinding -DomainController $script:C2Dc1 -Scope 'contoso.com' -Raw $r -Config $script:Ddc)
            $gap = Get-C2Row $rows 'Disk space: dc1.contoso.com - SYSVOL path'
            $gap.Status | Should -Be 'Not Assessed'
            $gap.Detail | Should -Match '^Not found: StdRegProv returned 1,'
            $gap.Detail | Should -Match 'the value not being set'
            (Get-C2Row $rows 'Disk space: dc1.contoso.com C:\ (NTDS database, NTDS logs)').Status | Should -Be 'Pass'
        }
        It 'keeps the return code of a key that does not exist (2), for both values under it, and the rows say it is the key' {
            $script:C2AbsentKeys = @($script:C2NtdsKey)
            $r = Get-AdfaDcDiskRaw -ComputerName $script:C2Dc1 -Protocol 'Wsman' -OperationTimeoutSec 30 -Paths $script:C2Paths
            $r.Ok | Should -BeTrue
            # Declared population: the two values under NTDS\Parameters.
            $under = @($r.Paths | Where-Object { $_.Key -eq $script:C2NtdsKey })
            $under.Count | Should -Be 2
            foreach ($p in $under) {
                $p.Read | Should -BeFalse
                $p.ReturnValue | Should -Be 2
                $p.ExpandedReturnValue | Should -Be 2
            }
            @($r.Paths | Where-Object { $_.Role -eq 'SYSVOL' })[0].Read | Should -BeTrue
            $rows = @(Get-AdfaDcDiskFinding -DomainController $script:C2Dc1 -Scope 'contoso.com' -Raw $r -Config $script:Ddc)
            foreach ($role in @('NTDS database', 'NTDS logs')) {
                $row = Get-C2Row $rows ("Disk space: dc1.contoso.com - {0} path" -f $role)
                $row.Status | Should -Be 'Not Assessed'
                $row.Detail | Should -Match '^Not found: StdRegProv returned 2,'
                $row.Detail | Should -Match 'the registry key not existing'
            }
            (Get-C2Row $rows 'Disk space: dc1.contoso.com C:\ (SYSVOL)').Status | Should -Be 'Pass'
        }
        It 'tries the expanded read for a value that came back empty with a return of 0' {
            # Return 0 with nothing in it is not a path. The other triggers (a nonzero return, a
            # %VARIABLE%) have their own tests; without this one the "empty value" trigger could
            # be removed unnoticed.
            $script:C2Registry['GetStringValue|Database Log Files Path'] = @{ Code = 0; Value = '   ' }
            $script:C2Registry['GetExpandedStringValue|Database Log Files Path'] = @{ Code = 0; Value = 'E:\Logs' }
            $r = Get-AdfaDcDiskRaw -ComputerName $script:C2Dc1 -Protocol 'Wsman' -OperationTimeoutSec 30 -Paths $script:C2Paths
            $lg = @($r.Paths | Where-Object { $_.Role -eq 'NTDS logs' })[0]
            (@($script:C2Calls | ForEach-Object { "{0}:{1}" -f $_.MethodName, $_.ValueName }) -join '|') | Should -Be (
                'GetStringValue:DSA Database File|GetStringValue:Database Log Files Path|GetExpandedStringValue:Database Log Files Path|GetStringValue:SysVol')
            $lg.Read | Should -BeTrue
            $lg.Value | Should -Be 'E:\Logs'
            $lg.Method | Should -Be 'GetExpandedStringValue'
            $lg.ExpandedReturnValue | Should -Be 0
        }
        It 'opens the session with the credential it was given, and with none when it was given none' {
            $secret = New-Object System.Security.SecureString
            foreach ($ch in 'stub'.ToCharArray()) { $secret.AppendChar($ch) }
            $cred = New-Object System.Management.Automation.PSCredential -ArgumentList 'CONTOSO\reader', $secret
            Get-AdfaDcDiskRaw -ComputerName $script:C2Dc1 -Protocol 'Wsman' -OperationTimeoutSec 30 -Paths $script:C2Paths -Credential $cred | Out-Null
            Get-AdfaDcDiskRaw -ComputerName $script:C2Dc2 -Protocol 'Dcom' -OperationTimeoutSec 30 -Paths $script:C2Paths -Credential $cred | Out-Null
            Get-AdfaDcDiskRaw -ComputerName $script:C2Dc3 -Protocol 'Wsman' -OperationTimeoutSec 30 -Paths $script:C2Paths | Out-Null
            # Declared population: the three sessions opened above.
            (@($script:C2Sessions | ForEach-Object { "{0}={1}" -f $_.ComputerName, $_.User }) -join ',') | Should -Be 'dc1.contoso.com=CONTOSO\reader,dc2.contoso.com=CONTOSO\reader,dc3.fabrikam.com=(none)'
        }
        It 'does not ask a second time after the refusal WbemErrorEnum defines either' {
            $script:C2Registry['GetStringValue|SysVol'] = @{ Code = [uint32]2147749891; Value = $null }
            $r = Get-AdfaDcDiskRaw -ComputerName $script:C2Dc1 -Protocol 'Wsman' -OperationTimeoutSec 30 -Paths $script:C2Paths
            $sv = @($r.Paths | Where-Object { $_.Role -eq 'SYSVOL' })[0]
            $sv.Read | Should -BeFalse
            $sv.ReturnValue | Should -Be 2147749891
            @($script:C2Calls | Where-Object { $_.MethodName -eq 'GetExpandedStringValue' }).Count | Should -Be 0
            # Non-vacuity: the three string reads did happen.
            @($script:C2Calls).Count | Should -Be 3
        }
        It 'is Ok, with one row per role, when all three registry reads threw and only the volume list answered' {
            $e = New-Object System.Exception 'Acesso negado.'
            $e | Add-Member -NotePropertyName NativeErrorCode -NotePropertyValue 'AccessDenied'
            foreach ($k in @($script:C2Registry.Keys)) { $script:C2Registry[$k] = $e }
            $r = Get-AdfaDcDiskRaw -ComputerName $script:C2Dc1 -Protocol 'Wsman' -OperationTimeoutSec 30 -Paths $script:C2Paths
            # The DC answered one of the four operations, so this is not a whole-DC failure and
            # the other transport is not tried on the strength of it.
            $r.Ok | Should -BeTrue
            $r.Error | Should -Be ''
            $r.VolumesOk | Should -BeTrue
            @($r.Volumes).Count | Should -Be 2
            @($r.Paths).Count | Should -Be 3
            @($r.Paths | Where-Object { $_.Read }).Count | Should -Be 0
            $rows = @(Get-AdfaDcDiskFinding -DomainController $script:C2Dc1 -Scope 'contoso.com' -Raw $r -Config $script:Ddc)
            # Declared population: one Access denied row per role, each naming its registry value.
            $rows.Count | Should -Be 3
            foreach ($role in $script:C2Roles) {
                $row = Get-C2Row $rows ("Disk space: dc1.contoso.com - {0} path" -f $role)
                $row.Status | Should -Be 'Not Assessed'
                $row.Detail | Should -Match '^Access denied'
            }
        }
        It 'does not ask a second time after a refusal' {
            $script:C2Registry['GetStringValue|SysVol'] = @{ Code = 5; Value = $null }
            $r = Get-AdfaDcDiskRaw -ComputerName $script:C2Dc1 -Protocol 'Wsman' -OperationTimeoutSec 30 -Paths $script:C2Paths
            $sv = @($r.Paths | Where-Object { $_.Role -eq 'SYSVOL' })[0]
            $sv.Read | Should -BeFalse
            $sv.ReturnValue | Should -Be 5
            @($script:C2Calls | Where-Object { $_.MethodName -eq 'GetExpandedStringValue' }).Count | Should -Be 0
        }
        It 'reads an expandable value through GetExpandedStringValue and says so' {
            $script:C2Registry['GetStringValue|Database Log Files Path'] = @{ Code = 0; Value = '%SystemRoot%\NTDS' }
            $script:C2Registry['GetExpandedStringValue|Database Log Files Path'] = @{ Code = 0; Value = 'C:\Windows\NTDS' }
            $r = Get-AdfaDcDiskRaw -ComputerName $script:C2Dc1 -Protocol 'Wsman' -OperationTimeoutSec 30 -Paths $script:C2Paths
            $lg = @($r.Paths | Where-Object { $_.Role -eq 'NTDS logs' })[0]
            $lg.Read | Should -BeTrue
            $lg.Value | Should -Be 'C:\Windows\NTDS'
            $lg.Method | Should -Be 'GetExpandedStringValue'
            @($script:C2Calls | Where-Object { $_.MethodName -eq 'GetExpandedStringValue' }).Count | Should -Be 1
        }
        It 'keeps the unexpanded value, for the row to report, when the expanded read does not help' {
            $script:C2Registry['GetStringValue|Database Log Files Path'] = @{ Code = 0; Value = '%NoSuchVar%\NTDS' }
            $script:C2Registry['GetExpandedStringValue|Database Log Files Path'] = @{ Code = 0; Value = '%NoSuchVar%\NTDS' }
            $r = Get-AdfaDcDiskRaw -ComputerName $script:C2Dc1 -Protocol 'Wsman' -OperationTimeoutSec 30 -Paths $script:C2Paths
            $rows = @(Get-AdfaDcDiskFinding -DomainController $script:C2Dc1 -Scope 'contoso.com' -Raw $r -Config $script:Ddc)
            $row = Get-C2Row $rows 'Disk space: dc1.contoso.com - NTDS logs path'
            $row.Status | Should -Be 'Not Assessed'
            $row.Detail | Should -Match '%NoSuchVar%'
        }
        It 'does not discard two values because the read of the third threw' {
            $e = New-Object System.Exception 'The operation has timed out.'
            $script:C2Registry['GetStringValue|Database Log Files Path'] = $e
            $r = Get-AdfaDcDiskRaw -ComputerName $script:C2Dc1 -Protocol 'Wsman' -OperationTimeoutSec 30 -Paths $script:C2Paths
            $r.Ok | Should -BeTrue
            $lg = @($r.Paths | Where-Object { $_.Role -eq 'NTDS logs' })[0]
            $lg.Read | Should -BeFalse
            $lg.Error | Should -Match 'timed out'
            @($r.Paths | Where-Object { $_.Read }).Count | Should -Be 2
            $r.VolumesOk | Should -BeTrue
        }
        It 'keeps the paths when only the volume query failed, and carries its error code' {
            $e = New-Object System.Exception 'Acesso negado.'
            $e | Add-Member -NotePropertyName NativeErrorCode -NotePropertyValue 'AccessDenied'
            $script:C2VolumeError = $e
            $r = Get-AdfaDcDiskRaw -ComputerName $script:C2Dc1 -Protocol 'Dcom' -OperationTimeoutSec 30 -Paths $script:C2Paths
            $r.Ok | Should -BeTrue
            $r.VolumesOk | Should -BeFalse
            $r.VolumeError | Should -Match 'Acesso negado'
            $r.VolumeErrorCode | Should -Be 'AccessDenied'
            @($r.Paths | Where-Object { $_.Read }).Count | Should -Be 3
        }
        It 'reports the read as failed, with the first error and its code, when nothing at all answered' {
            $e = New-Object System.Exception 'Acesso negado.'
            $e | Add-Member -NotePropertyName NativeErrorCode -NotePropertyValue 'AccessDenied'
            foreach ($k in @($script:C2Registry.Keys)) { $script:C2Registry[$k] = $e }
            $script:C2VolumeError = $e
            $r = Get-AdfaDcDiskRaw -ComputerName $script:C2Dc1 -Protocol 'Wsman' -OperationTimeoutSec 30 -Paths $script:C2Paths
            $r.Ok | Should -BeFalse
            $r.Error | Should -Match 'Acesso negado'
            $r.ErrorCode | Should -Be 'AccessDenied'
            $script:C2Closed | Should -Be 1
        }
        It 'returns the error text and code, not an exception, when the session cannot be opened' {
            function New-CimSession { param([Parameter(ValueFromRemainingArguments)]$a)
                $e = New-Object System.Exception 'Acesso negado.'
                $e | Add-Member -NotePropertyName NativeErrorCode -NotePropertyValue 'AccessDenied'
                throw $e }
            $r = Get-AdfaDcDiskRaw -ComputerName $script:C2Dc1 -Protocol 'Wsman' -OperationTimeoutSec 30 -Paths $script:C2Paths
            $r.Ok | Should -BeFalse
            $r.Error | Should -Match 'Acesso negado'
            $r.ErrorCode | Should -Be 'AccessDenied'
            @($script:C2Calls).Count | Should -Be 0
        }
        It 'asks for a DCOM session option only for DCOM' {
            Get-AdfaDcDiskRaw -ComputerName $script:C2Dc1 -Protocol 'Wsman' -OperationTimeoutSec 30 -Paths $script:C2Paths | Out-Null
            Get-AdfaDcDiskRaw -ComputerName $script:C2Dc1 -Protocol 'Dcom' -OperationTimeoutSec 30 -Paths $script:C2Paths | Out-Null
            ($script:C2Opts -join ',') | Should -Be 'none,Dcom'
        }
        It 'reads the RAW capacity and free space where the instance carries an unadapted store' {
            $script:C2VolumeAnswer = @([pscustomobject]@{
                    Name = 'C:\'; DeviceID = '\\?\Volume{c}\'; DriveType = [uint32]3; Capacity = 'adapted'; FreeSpace = 'adapted'
                    CimInstanceProperties = @{
                        Name = [pscustomobject]@{ Value = 'C:\' }; DeviceID = [pscustomobject]@{ Value = '\\?\Volume{c}\' }; DriveType = [pscustomobject]@{ Value = [uint32]3 }
                        Capacity = [pscustomobject]@{ Value = [uint64](100 * $script:C2GB) }; FreeSpace = [pscustomobject]@{ Value = [uint64](40 * $script:C2GB) }
                    } })
            $r = Get-AdfaDcDiskRaw -ComputerName $script:C2Dc1 -Protocol 'Wsman' -OperationTimeoutSec 30 -Paths $script:C2Paths
            $r.Volumes[0].Capacity | Should -Be ([uint64](100 * $script:C2GB))
            $r.Volumes[0].FreeSpace | Should -Be ([uint64](40 * $script:C2GB))
        }
    }

    Context 'Merge-AdfaDcDiskConfig (the DcDisk validator)' {
        It 'replaces only the keys the override names, and leaves the built-in table untouched' {
            $o = '{ "WarnBelowPercent": 25, "FailBelowFreeGB": 1.5 }' | ConvertFrom-Json
            $m = Merge-AdfaDcDiskConfig -BaseConfig $script:Ddc -Override $o -OverrideSource 'C:\cfg\disk.json'
            $m.WarnBelowPercent | Should -Be 25
            $m.FailBelowFreeGB | Should -Be 1.5
            $m.FailBelowPercent | Should -Be 10
            $m.WarnBelowFreeGB | Should -Be 5
            @($m.Paths).Count | Should -Be 3
            $script:Ddc.WarnBelowPercent | Should -Be 20
            [string]$script:Ddc.ThresholdSource | Should -Be 'tool default, not a Microsoft value'
        }
        It 'cites the file for the thresholds it supplied and goes on labelling the others as tool defaults' {
            $m = Merge-AdfaDcDiskConfig -BaseConfig $script:Ddc -Override @{ WarnBelowPercent = 25 } -OverrideSource 'C:\cfg\disk.json'
            [string]$m.ThresholdSource | Should -Match 'C:\\cfg\\disk\.json'
            [string]$m.ThresholdSource | Should -Match 'for WarnBelowPercent;'
            [string]$m.ThresholdSource | Should -Match 'tool default, not a Microsoft value, for FailBelowPercent, WarnBelowFreeGB, FailBelowFreeGB'
            $all = Merge-AdfaDcDiskConfig -BaseConfig $script:Ddc -Override @{ WarnBelowPercent = 25; FailBelowPercent = 5; WarnBelowFreeGB = 8; FailBelowFreeGB = 4 } -OverrideSource 'C:\cfg\disk.json'
            [string]$all.ThresholdSource | Should -Match 'C:\\cfg\\disk\.json'
            [string]$all.ThresholdSource | Should -Not -Match 'tool default'
        }
        It 'goes on calling the thresholds tool defaults when the override changes only a port' {
            $m = Merge-AdfaDcDiskConfig -BaseConfig $script:Ddc -Override @{ WsmanPort = 5986 } -OverrideSource 'C:\cfg\disk.json'
            $m.WsmanPort | Should -Be 5986
            [string]$m.ThresholdSource | Should -Be 'tool default, not a Microsoft value'
        }
        It 'returns the built-in table when there is no override' {
            $m = Merge-AdfaDcDiskConfig -BaseConfig $script:Ddc -Override $null
            $m.WarnBelowPercent | Should -Be 20
            [string]$m.ThresholdSource | Should -Be 'tool default, not a Microsoft value'
        }
        It 'accepts a floor of 0 as "no floor", and equal Warning and Fail thresholds' {
            $m = Merge-AdfaDcDiskConfig -BaseConfig $script:Ddc -Override @{ WarnBelowFreeGB = 0; FailBelowFreeGB = 0 }
            $m.WarnBelowFreeGB | Should -Be 0
            (Merge-AdfaDcDiskConfig -BaseConfig $script:Ddc -Override @{ WarnBelowPercent = 10 }).WarnBelowPercent | Should -Be 10
        }
        It 'refuses an override that is not one object with known keys' {
            $asArray = @([pscustomobject]@{ WarnBelowPercent = 25 }, [pscustomobject]@{ WarnBelowPercent = 30 })
            { Merge-AdfaDcDiskConfig -BaseConfig $script:Ddc -Override $asArray } | Should -Throw -ExpectedMessage '*single object*'
            { Merge-AdfaDcDiskConfig -BaseConfig $script:Ddc -Override 'abc' } | Should -Throw -ExpectedMessage '*single object*'
            { Merge-AdfaDcDiskConfig -BaseConfig $script:Ddc -Override 5 } | Should -Throw -ExpectedMessage '*single object*'
            { Merge-AdfaDcDiskConfig -BaseConfig $script:Ddc -Override ('{}' | ConvertFrom-Json) } | Should -Throw -ExpectedMessage '*empty object*'
            { Merge-AdfaDcDiskConfig -BaseConfig $script:Ddc -Override ('{ "WarnBelowPercents": 25 }' | ConvertFrom-Json) } | Should -Throw -ExpectedMessage '*WarnBelowPercents*'
            { Merge-AdfaDcDiskConfig -BaseConfig $script:Ddc -Override ('{ "WarnBelowPercent": null }' | ConvertFrom-Json) } | Should -Throw -ExpectedMessage '*null*'
        }
        It 'refuses to let a file change what the tool reads or where the facts are cited from' {
            foreach ($fixed in @('Paths', 'SourceUrl', 'ReadDate', 'ThresholdSource')) {
                { Merge-AdfaDcDiskConfig -BaseConfig $script:Ddc -Override @{ $fixed = 'x' } } | Should -Throw -ExpectedMessage "*unknown key '$fixed'*"
            }
        }
        It 'refuses a threshold that is not a number in range' {
            $bad = @(
                @{ O = @{ WarnBelowPercent = 'abc' }; Msg = '*WarnBelowPercent*' }
                @{ O = @{ WarnBelowPercent = '25' }; Msg = '*WarnBelowPercent*number*' }
                @{ O = @{ WarnBelowPercent = $true }; Msg = '*WarnBelowPercent*' }
                @{ O = @{ WarnBelowPercent = @(20, 30) }; Msg = '*WarnBelowPercent*' }
                @{ O = @{ WarnBelowPercent = 101 }; Msg = '*WarnBelowPercent*0 to 100*' }
                @{ O = @{ FailBelowPercent = -1 }; Msg = '*FailBelowPercent*0 to 100*' }
                @{ O = @{ WarnBelowFreeGB = -5 }; Msg = '*WarnBelowFreeGB*' }
                @{ O = @{ FailBelowFreeGB = 'two' }; Msg = '*FailBelowFreeGB*' }
            )
            # Declared population: the eight malformed threshold values above.
            $bad.Count | Should -Be 8
            foreach ($b in $bad) { { Merge-AdfaDcDiskConfig -BaseConfig $script:Ddc -Override $b.O } | Should -Throw -ExpectedMessage $b.Msg }
        }
        It 'refuses thresholds that contradict each other, judged on the merged table' {
            { Merge-AdfaDcDiskConfig -BaseConfig $script:Ddc -Override @{ WarnBelowPercent = 10; FailBelowPercent = 20 } } | Should -Throw -ExpectedMessage '*FailBelowPercent*WarnBelowPercent*'
            # The file names only one key; it is above the built-in Warning threshold of 20.
            { Merge-AdfaDcDiskConfig -BaseConfig $script:Ddc -Override @{ FailBelowPercent = 25 } } | Should -Throw -ExpectedMessage '*FailBelowPercent*WarnBelowPercent*'
            { Merge-AdfaDcDiskConfig -BaseConfig $script:Ddc -Override @{ FailBelowFreeGB = 6 } } | Should -Throw -ExpectedMessage '*FailBelowFreeGB*WarnBelowFreeGB*'
            # One step inside the rule is accepted, so the refusals above are the rule and not a blanket.
            (Merge-AdfaDcDiskConfig -BaseConfig $script:Ddc -Override @{ FailBelowPercent = 20 }).FailBelowPercent | Should -Be 20
        }
        It 'refuses a table with no threshold left, which would pass every volume' {
            { Merge-AdfaDcDiskConfig -BaseConfig $script:Ddc -Override @{ WarnBelowPercent = 0; FailBelowPercent = 0; WarnBelowFreeGB = 0; FailBelowFreeGB = 0 } } | Should -Throw -ExpectedMessage '*no threshold*'
        }
        It 'refuses a port that is not a port' {
            { Merge-AdfaDcDiskConfig -BaseConfig $script:Ddc -Override @{ WsmanPort = 'abc' } } | Should -Throw -ExpectedMessage '*WsmanPort*'
            { Merge-AdfaDcDiskConfig -BaseConfig $script:Ddc -Override @{ RpcPort = 0 } } | Should -Throw -ExpectedMessage '*RpcPort*'
            { Merge-AdfaDcDiskConfig -BaseConfig $script:Ddc -Override @{ RpcPort = 70000 } } | Should -Throw -ExpectedMessage '*RpcPort*'
            { Merge-AdfaDcDiskConfig -BaseConfig $script:Ddc -Override @{ RpcPort = 135.5 } } | Should -Throw -ExpectedMessage '*RpcPort*'
        }
    }

    Context 'Generic -ConfigOverridePath (Resolve- and Import-AdfaConfigOverride)' {
        BeforeAll {
            function New-C2File {
                param([string]$Text)
                $f = Join-Path ([IO.Path]::GetTempPath()) ("adfa_c2_{0}.json" -f [guid]::NewGuid().ToString('N'))
                $Text | Out-File -LiteralPath $f -Encoding UTF8
                return $f
            }
        }
        It 'registers DcDisk with its own validator, which exists' {
            @($script:ConfigOverrideSections.Keys) | Should -Contain 'DcDisk'
            [string]$script:ConfigOverrideSections['DcDisk'].Merge | Should -Be 'Merge-AdfaDcDiskConfig'
            [string]$script:ConfigOverrideSections['DcDisk'].ConfigKey | Should -Be 'DcDisk'
            $param = @($script:C2Ast.ParamBlock.Parameters | Where-Object { $_.Name.VariablePath.UserPath -eq 'Sections' })
            $sectionValues = @(@($param[0].Attributes | Where-Object { $_.TypeName.Name -eq 'ValidateSet' })[0].PositionalArguments | ForEach-Object { $_.Value })
            foreach ($k in @($script:ConfigOverrideSections.Keys)) {
                Get-Command -Name ([string]$script:ConfigOverrideSections[$k].Merge) -CommandType Function -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty
                $script:Config.ContainsKey([string]$script:ConfigOverrideSections[$k].ConfigKey) | Should -BeTrue
                # The -Sections value that uses the table must be one that exists.
                $sectionValues | Should -Contain ([string]$script:ConfigOverrideSections[$k].Section)
            }
        }
        It 'returns a merged table for the sections the file supplied, and nothing for the others' {
            $o = '{ "DcDisk": { "WarnBelowPercent": 30 } }' | ConvertFrom-Json
            $r = Resolve-AdfaConfigOverride -Override $o -BaseConfig $script:Config -Sections $script:ConfigOverrideSections -OverrideSource 'C:\cfg\all.json'
            @($r.Keys).Count | Should -Be 1
            $r['DcDisk'].WarnBelowPercent | Should -Be 30
            $r['DcDisk'].FailBelowPercent | Should -Be 10
            [string]$r['DcDisk'].ThresholdSource | Should -Match 'C:\\cfg\\all\.json'
            # The built-in table still says what it said.
            $script:Config.DcDisk.WarnBelowPercent | Should -Be 20
        }
        It 'sends each section to its own validator, so a later row adds one registry line and one function' {
            function Merge-C2FakeSection {
                param([hashtable]$BaseConfig, $Override, [string]$OverrideSource)
                if ($null -ne $Override.PSObject.Properties['Bad']) { throw 'fake section refuses Bad' }
                return @{ From = $OverrideSource; Limit = $Override.Limit; Base = $BaseConfig['Limit'] }
            }
            $registry = [ordered]@{
                DcDisk = @{ ConfigKey = 'DcDisk'; Merge = 'Merge-AdfaDcDiskConfig' }
                Later  = @{ ConfigKey = 'Later'; Merge = 'Merge-C2FakeSection' }
            }
            $base = @{ DcDisk = $script:Ddc; Later = @{ Limit = 1 } }
            $o = '{ "Later": { "Limit": 7 }, "DcDisk": { "FailBelowPercent": 5 } }' | ConvertFrom-Json
            $r = Resolve-AdfaConfigOverride -Override $o -BaseConfig $base -Sections $registry -OverrideSource 'C:\cfg\all.json'
            # Declared population: the two sections the file names.
            @($r.Keys).Count | Should -Be 2
            $r['Later'].Limit | Should -Be 7
            $r['Later'].Base | Should -Be 1
            $r['Later'].From | Should -Be 'C:\cfg\all.json'
            $r['DcDisk'].FailBelowPercent | Should -Be 5
            # Only the section the file named is returned.
            $only = Resolve-AdfaConfigOverride -Override ('{ "Later": { "Limit": 9 } }' | ConvertFrom-Json) -BaseConfig $base -Sections $registry
            (@($only.Keys) -join ',') | Should -Be 'Later'
            # A section's own refusal is passed on, named.
            { Resolve-AdfaConfigOverride -Override ('{ "Later": { "Bad": 1 } }' | ConvertFrom-Json) -BaseConfig $base -Sections $registry } | Should -Throw -ExpectedMessage "*section 'Later'*fake section refuses Bad*"
        }
        It 'refuses a file that is not one object, is empty, names an unknown section, or sets a section to null' {
            $asArray = @([pscustomobject]@{ DcDisk = @{} }, [pscustomobject]@{ DcDisk = @{} })
            { Resolve-AdfaConfigOverride -Override $asArray -BaseConfig $script:Config -Sections $script:ConfigOverrideSections } | Should -Throw -ExpectedMessage '*single object*'
            { Resolve-AdfaConfigOverride -Override 'abc' -BaseConfig $script:Config -Sections $script:ConfigOverrideSections } | Should -Throw -ExpectedMessage '*single object*'
            { Resolve-AdfaConfigOverride -Override 5 -BaseConfig $script:Config -Sections $script:ConfigOverrideSections } | Should -Throw -ExpectedMessage '*single object*'
            { Resolve-AdfaConfigOverride -Override $null -BaseConfig $script:Config -Sections $script:ConfigOverrideSections } | Should -Throw -ExpectedMessage '*null*'
            { Resolve-AdfaConfigOverride -Override ('{}' | ConvertFrom-Json) -BaseConfig $script:Config -Sections $script:ConfigOverrideSections } | Should -Throw -ExpectedMessage '*empty object*'
            { Resolve-AdfaConfigOverride -Override ('{ "DcDisks": { "WarnBelowPercent": 30 } }' | ConvertFrom-Json) -BaseConfig $script:Config -Sections $script:ConfigOverrideSections } | Should -Throw -ExpectedMessage "*unknown section 'DcDisks'*DcDisk*"
            # A threshold written at the top level, outside its section, is an unknown section too.
            { Resolve-AdfaConfigOverride -Override ('{ "WarnBelowPercent": 30 }' | ConvertFrom-Json) -BaseConfig $script:Config -Sections $script:ConfigOverrideSections } | Should -Throw -ExpectedMessage "*unknown section 'WarnBelowPercent'*"
            { Resolve-AdfaConfigOverride -Override ('{ "DcDisk": null }' | ConvertFrom-Json) -BaseConfig $script:Config -Sections $script:ConfigOverrideSections } | Should -Throw -ExpectedMessage "*'DcDisk'*null*"
        }
        It 'passes on a malformed value inside a section, naming the section' {
            { Resolve-AdfaConfigOverride -Override ('{ "DcDisk": { "WarnBelowPercent": "high" } }' | ConvertFrom-Json) -BaseConfig $script:Config -Sections $script:ConfigOverrideSections } | Should -Throw -ExpectedMessage "*section 'DcDisk'*WarnBelowPercent*"
            { Resolve-AdfaConfigOverride -Override ('{ "DcDisk": { "Typo": 1 } }' | ConvertFrom-Json) -BaseConfig $script:Config -Sections $script:ConfigOverrideSections } | Should -Throw -ExpectedMessage "*section 'DcDisk'*unknown key 'Typo'*"
            { Resolve-AdfaConfigOverride -Override ('{ "DcDisk": [ 1, 2 ] }' | ConvertFrom-Json) -BaseConfig $script:Config -Sections $script:ConfigOverrideSections } | Should -Throw -ExpectedMessage "*section 'DcDisk'*single object*"
            { Resolve-AdfaConfigOverride -Override ('{ "DcDisk": {} }' | ConvertFrom-Json) -BaseConfig $script:Config -Sections $script:ConfigOverrideSections } | Should -Throw -ExpectedMessage "*section 'DcDisk'*empty object*"
        }
        It 'does not let Exchange SE or DC system be set from this file: they keep their own parameters' {
            { Resolve-AdfaConfigOverride -Override ('{ "DcSystem": { "WsmanPort": 5986 } }' | ConvertFrom-Json) -BaseConfig $script:Config -Sections $script:ConfigOverrideSections } | Should -Throw -ExpectedMessage "*unknown section 'DcSystem'*"
            { Resolve-AdfaConfigOverride -Override ('{ "ExchangeSe": { "ReadOnlySupported": true } }' | ConvertFrom-Json) -BaseConfig $script:Config -Sections $script:ConfigOverrideSections } | Should -Throw -ExpectedMessage "*unknown section 'ExchangeSe'*"
        }
        It 'loads a valid file and cites it' {
            $f = New-C2File '{ "DcDisk": { "WarnBelowPercent": 35, "FailBelowPercent": 15 } }'
            try {
                $r = Import-AdfaConfigOverride -Path $f -BaseConfig $script:Config -Sections $script:ConfigOverrideSections
                $r['DcDisk'].WarnBelowPercent | Should -Be 35
                $r['DcDisk'].FailBelowPercent | Should -Be 15
                [string]$r['DcDisk'].ThresholdSource | Should -Match ([regex]::Escape($f))
            }
            finally { Remove-Item $f -Force -ErrorAction SilentlyContinue }
        }
        It 'throws for a missing, empty or malformed file instead of falling back to the built-in tables' {
            { Import-AdfaConfigOverride -Path (Join-Path ([IO.Path]::GetTempPath()) 'adfa-no-such-override.json') -BaseConfig $script:Config -Sections $script:ConfigOverrideSections } | Should -Throw -ExpectedMessage '*not found*'
            $cases = @(
                @{ Text = '   '; Msg = '*empty*' }
                @{ Text = 'not json {'; Msg = '*not valid JSON*' }
                @{ Text = 'null'; Msg = '*JSON null*' }
                @{ Text = '"abc"'; Msg = '*single object*' }
                @{ Text = '{ "Typo": { "x": 1 } }'; Msg = "*unknown section 'Typo'*" }
                @{ Text = '{ "DcDisk": { "WarnBelowPercent": 500 } }'; Msg = '*0 to 100*' }
            )
            # Declared population: the six malformed files above.
            $cases.Count | Should -Be 6
            foreach ($c in $cases) {
                $f = New-C2File $c.Text
                try {
                    { Import-AdfaConfigOverride -Path $f -BaseConfig $script:Config -Sections $script:ConfigOverrideSections } | Should -Throw -ExpectedMessage $c.Msg
                    # Every refusal names the file it came from.
                    { Import-AdfaConfigOverride -Path $f -BaseConfig $script:Config -Sections $script:ConfigOverrideSections } | Should -Throw -ExpectedMessage "*$([IO.Path]::GetFileName($f))*"
                }
                finally { Remove-Item $f -Force -ErrorAction SilentlyContinue }
            }
            # A top-level array: Windows PowerShell 5.1 hands it over whole, PowerShell 7 unrolls it. Either way it stops.
            $arr = New-C2File '[]'
            try { { Import-AdfaConfigOverride -Path $arr -BaseConfig $script:Config -Sections $script:ConfigOverrideSections } | Should -Throw }
            finally { Remove-Item $arr -Force -ErrorAction SilentlyContinue }
        }
        It 'refuses a top-level array on both PowerShell editions, even when it holds exactly one valid object' {
            # PowerShell 7 unrolls a one-element array on the pipeline, so the loader used to
            # see the inner object and apply the file; Windows PowerShell 5.1 refused it. The
            # message is asserted, not only the throw, so the two editions must refuse it the
            # same way and for this reason.
            $arrays = @(
                '[{"DcDisk":{"WarnBelowPercent":25}}]'
                '[ { "DcDisk": { "WarnBelowPercent": 99, "FailBelowPercent": 98 } } ]'
                "`r`n  [ { `"DcDisk`": { `"WarnBelowPercent`": 25 } }, { `"DcDisk`": { `"WarnBelowPercent`": 30 } } ]"
            )
            # Declared population: the three array files above.
            $arrays.Count | Should -Be 3
            foreach ($text in $arrays) {
                $f = New-C2File $text
                try {
                    { Import-AdfaConfigOverride -Path $f -BaseConfig $script:Config -Sections $script:ConfigOverrideSections } | Should -Throw -ExpectedMessage '*single object*not a JSON array*'
                    { Import-AdfaConfigOverride -Path $f -BaseConfig $script:Config -Sections $script:ConfigOverrideSections } | Should -Throw -ExpectedMessage "*$([IO.Path]::GetFileName($f))*"
                }
                finally { Remove-Item $f -Force -ErrorAction SilentlyContinue }
            }
            # The same content as one object is accepted: the refusal is of the array, not of the keys.
            $ok = New-C2File '{"DcDisk":{"WarnBelowPercent":25}}'
            try { (Import-AdfaConfigOverride -Path $ok -BaseConfig $script:Config -Sections $script:ConfigOverrideSections)['DcDisk'].WarnBelowPercent | Should -Be 25 }
            finally { Remove-Item $ok -Force -ErrorAction SilentlyContinue }
        }
        It 'refuses a file that names a key or a section twice, instead of applying the last one silently' {
            $cases = @(
                @{ Text = '{"DcDisk":{"WarnBelowPercent":25,"WarnBelowPercent":90}}'; Msg = "*'DcDisk.WarnBelowPercent' more than once*" }
                @{ Text = '{"DcDisk":{"WarnBelowPercent":25},"DcDisk":{"WarnBelowPercent":90}}'; Msg = "*'DcDisk' more than once*" }
                @{ Text = '{"DcDisk":{"WarnBelowPercent":25,"WarnBelowPercent":90},"DcDisk":{"WarnBelowPercent":30}}'; Msg = "*'DcDisk.WarnBelowPercent', 'DcDisk' more than once*" }
                @{ Text = "{`r`n  `"DcDisk`": {`r`n    `"FailBelowPercent`": 5,`r`n    `"WsmanPort`": 5985,`r`n    `"FailBelowPercent`": 15`r`n  }`r`n}"; Msg = "*'DcDisk.FailBelowPercent' more than once*" }
            )
            # Declared population: the four contradictory files above.
            $cases.Count | Should -Be 4
            foreach ($c in $cases) {
                $f = New-C2File $c.Text
                try {
                    { Import-AdfaConfigOverride -Path $f -BaseConfig $script:Config -Sections $script:ConfigOverrideSections } | Should -Throw -ExpectedMessage $c.Msg
                    { Import-AdfaConfigOverride -Path $f -BaseConfig $script:Config -Sections $script:ConfigOverrideSections } | Should -Throw -ExpectedMessage "*$([IO.Path]::GetFileName($f))*"
                }
                finally { Remove-Item $f -Force -ErrorAction SilentlyContinue }
            }
            # Keys that differ only by case are a repeat too. ConvertFrom-Json refuses those itself.
            $mixed = New-C2File '{"DcDisk":{"WarnBelowPercent":25,"warnbelowpercent":90}}'
            try { { Import-AdfaConfigOverride -Path $mixed -BaseConfig $script:Config -Sections $script:ConfigOverrideSections } | Should -Throw }
            finally { Remove-Item $mixed -Force -ErrorAction SilentlyContinue }
            # The same key in two different sections of one document is not a repeat.
            Get-AdfaJsonDuplicateKey -Text '{"DcDisk":{"WsmanPort":5986},"Later":{"WsmanPort":1}}' | Should -BeNullOrEmpty
        }
        It 'finds a repeated key in the text, and only a real one (Get-AdfaJsonDuplicateKey)' {
            $cases = @(
                @{ T = '{"a":1,"a":2}'; D = 'a' }
                @{ T = '{"a":1,"A":2}'; D = 'A' }
                @{ T = '{"A":1,"a":2}'; D = 'a' }                        # an escaped key is the same key
                @{ T = '{"x":{"a":1,"b":{"c":1,"c":2}}}'; D = 'x.b.c' }
                @{ T = '{"a":1,"a":2,"a":3}'; D = 'a' }                       # reported once
                @{ T = '{"a":{"b":1},"c":{"b":2}}'; D = '' }                  # same name, different objects
                @{ T = '{"a":[{"x":1},{"x":2}]}'; D = '' }                    # same name, different array elements
                @{ T = '{"a":"a","b":"a"}'; D = '' }                          # a value is not a key
                @{ T = '{"a":"x\"y","b":"{\"a\":1,\"a\":2}"}'; D = '' }       # JSON inside a string is a string
                @{ T = '{"a":"\\","b":1}'; D = '' }                           # an escaped backslash ends the string
                @{ T = "{ // `"a`": 0`n `"a`": 1 /* `"a`": 2 */ }"; D = '' }  # comments, which PowerShell 7 accepts
                @{ T = ''; D = '' }
            )
            # Declared population: the twelve documents above.
            $cases.Count | Should -Be 12
            foreach ($c in $cases) { (@(Get-AdfaJsonDuplicateKey -Text $c.T) -join '|') | Should -Be $c.D -Because $c.T }
            (@(Get-AdfaJsonDuplicateKey -Text '{"a":1,"a":2,"b":{"c":1,"c":2}}') -join '|') | Should -Be 'a|b.c'
        }
        It 'reads what a JSON text holds at its top level from the text (Get-AdfaJsonTopLevelKind)' {
            Get-AdfaJsonTopLevelKind -Text '{"a":1}' | Should -Be 'Object'
            Get-AdfaJsonTopLevelKind -Text "`r`n`t {`"a`":1}" | Should -Be 'Object'
            Get-AdfaJsonTopLevelKind -Text ([string][char]0xFEFF + '{"a":1}') | Should -Be 'Object'
            Get-AdfaJsonTopLevelKind -Text '[{"a":1}]' | Should -Be 'Array'
            Get-AdfaJsonTopLevelKind -Text '  []' | Should -Be 'Array'
            Get-AdfaJsonTopLevelKind -Text '"abc"' | Should -Be 'String'
            Get-AdfaJsonTopLevelKind -Text '5' | Should -Be 'Other'
            Get-AdfaJsonTopLevelKind -Text 'null' | Should -Be 'Other'
            Get-AdfaJsonTopLevelKind -Text '   ' | Should -Be 'Empty'
            Get-AdfaJsonTopLevelKind -Text '' | Should -Be 'Empty'
            Get-AdfaJsonTopLevelKind -Text ([string][char]0xFEFF) | Should -Be 'Empty'
        }
    }
}
