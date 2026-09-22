@{
    # ADForestAssessment ships as a single self-contained script, not a module: there is no
    # RootModule and nothing is exported. This manifest exists so the repository has one
    # versioned artifact that build\package.ps1 can read and zip.
    # Kept identical to $script:Config.Version in the assessment script - the HTML report
    # prints that value, and a client-facing report must not claim a version the package
    # does not. A repo test asserts the two match.
    ModuleVersion        = '1.13.0'
    GUID                 = '2c6821ed-37a0-4ddc-8e53-dd76ac171829'
    Author               = 'TakeItoCloud'
    CompanyName          = 'TakeItoCloud'
    Copyright            = '(c) TakeItoCloud. All rights reserved.'
    Description          = 'Near-enterprise-grade Active Directory forest assessment with verified two-way trust health, coverage-aware and fail-closed.'

    # Deliberately 5.1: the assessment is written with 5.1-safe idioms so it runs on a stock
    # domain controller's Windows PowerShell as well as on pwsh 7. Do not raise this without
    # re-reading the "5.1-safe idioms" note in PORT-PLAN.md.
    PowerShellVersion    = '5.1'
    CompatiblePSEditions = @('Desktop', 'Core')

    FunctionsToExport    = @()
    CmdletsToExport      = @()
    VariablesToExport    = @()
    AliasesToExport      = @()

    FileList             = @('Invoke-ADForestAssessment.ps1')

    PrivateData          = @{
        PSData = @{
            Tags       = @('ActiveDirectory', 'Assessment', 'Forest', 'Trusts', 'Replication', 'Security')
            ProjectUri = 'https://github.com/TakeItoCloud/ADForestAssessment'
        }
    }
}
