@{
    RootModule           = '__TOOLNAME__.psm1'
    ModuleVersion        = '0.1.0'
    GUID                 = 'b1f0c6a4-7d3e-4b1a-9c2f-5e8a0d6f4c31'
    Author               = 'TakeItoCloud'
    CompanyName          = 'TakeItoCloud'
    Copyright            = '(c) TakeItoCloud. All rights reserved.'
    Description          = 'PowerShell tool module scaffolded from template-ps-tool.'
    PowerShellVersion    = '7.4'
    CompatiblePSEditions = @('Core')

    FunctionsToExport    = @('Get-ToolStatus')
    CmdletsToExport      = @()
    VariablesToExport    = @()
    AliasesToExport      = @()

    PrivateData          = @{
        PSData = @{
            Tags       = @('PowerShell', 'Tool', 'TakeItoCloud')
            ProjectUri = 'https://github.com/TakeItoCloud/__TOOLNAME__'
        }
    }
}
