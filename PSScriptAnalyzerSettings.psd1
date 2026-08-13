@{
    # Run the full set of built-in PSScriptAnalyzer rules...
    IncludeDefaultRules = $true

    # ...but only fail on findings that actually matter for a shipped tool.
    Severity            = @('Error', 'Warning')

    # Rules this template relies on, named explicitly so they survive future
    # changes to the analyzer defaults.
    Rules               = @{
        PSUseApprovedVerbs                   = @{ Enable = $true }
        PSAvoidUsingWriteHost                = @{ Enable = $true }
        PSUseDeclaredVarsMoreThanAssignments = @{ Enable = $true }

        # 'Status' is a singular noun; the pluralisation heuristic disagrees.
        PSUseSingularNouns                   = @{
            Enable        = $true
            NounAllowList = @('Data', 'Status', 'Windows')
        }

        PSUseCompatibleSyntax                = @{
            Enable         = $true
            TargetVersions = @('7.4')
        }
    }
}
