@{
    # Run the full set of built-in PSScriptAnalyzer rules...
    IncludeDefaultRules = $true

    # ...but only fail on findings that actually matter for a shipped tool.
    Severity            = @('Error', 'Warning')

    # --- Carried over from the tool's own settings in infra-scripting-suite -------------
    #   PSAvoidUsingWriteHost       Progress goes through Write-Information in the assessment
    #                               script itself. All 25 remaining hits are in
    #                               tests\harness\, where the dependency-free runners print
    #                               their own results to the console by design.
    #   PSUseShouldProcessForStateChangingFunctions
    #                               6 hits. The assessment is strictly read-only against the
    #                               directory; the New-* functions build in-memory finding
    #                               objects and write the local report bundle.
    #   PSReviewUnusedParameter     65 hits. 53 are in tests\harness\, where the stub
    #                               cmdlets declare the real cmdlets' parameters for
    #                               signature fidelity and ignore most of them. The other 12
    #                               are collectors that take the shared collector parameter
    #                               set for interface symmetry.
    #
    # --- Added for this repository -------------------------------------------------------
    #   PSAvoidUsingEmptyCatchBlock 9 hits, all in the assessment script. Each optional
    #                               module or external tool degrades to "Not Assessed", which
    #                               is the tool's fail-closed contract - but the catch should
    #                               still log why. PORT-PLAN P2.
    #   PSAvoidOverwritingBuiltInCmdlets
    #                               4 hits. Write-Log in the assessment script (PORT-PLAN
    #                               P2); Import-Module / Start-Transcript / Stop-Transcript
    #                               deliberately stubbed in tests\harness\Run-SmokeTest.ps1
    #                               so the smoke run never touches the real host.
    #   PSAvoidAssignmentToAutomaticVariable
    #                               3 hits, all $args in the harness stubs, which is the
    #                               point of a stub.
    #   PSAvoidUsingPlainTextForPassword / PSUsePSCredentialType
    #                               1 hit each, on the stub Get-ADTrust in
    #                               tests\harness\Run-Validation.ps1. No credential is ever
    #                               handled - the stub only needs the parameter to exist.
    #   PSUseSingularNouns          1 hit in the harness.
    ExcludeRules        = @(
        'PSAvoidUsingWriteHost'
        'PSUseShouldProcessForStateChangingFunctions'
        'PSReviewUnusedParameter'
        'PSAvoidUsingEmptyCatchBlock'
        'PSAvoidOverwritingBuiltInCmdlets'
        'PSAvoidAssignmentToAutomaticVariable'
        'PSAvoidUsingPlainTextForPassword'
        'PSUsePSCredentialType'
        'PSUseSingularNouns'
    )

    # Rules this tool relies on, named explicitly so they survive future changes to the
    # analyzer defaults.
    Rules               = @{
        PSUseDeclaredVarsMoreThanAssignments = @{ Enable = $true }

        # The assessment script is deliberately 5.1-safe so it runs on a stock domain
        # controller's Windows PowerShell as well as on pwsh 7.
        PSUseCompatibleSyntax                = @{
            Enable         = $true
            TargetVersions = @('5.1', '7.4')
        }
    }
}
