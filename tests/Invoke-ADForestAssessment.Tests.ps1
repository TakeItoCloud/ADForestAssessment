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
