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

Describe 'PSScriptAnalyzer' {
    It 'has no Error/Warning findings against the committed settings' -Skip:(-not (Get-Module -ListAvailable PSScriptAnalyzer)) {
        $settings = Join-Path (Split-Path -Parent $PSScriptRoot) 'PSScriptAnalyzerSettings.psd1'
        $findings = Invoke-ScriptAnalyzer -Path $script:Target -Settings $settings
        $findings | Should -BeNullOrEmpty
    }
}
