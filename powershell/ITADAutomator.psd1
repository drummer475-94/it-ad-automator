@{
    # Module manifest for ITADAutomator
    RootModule = 'ITADAutomator.psm1'
    ModuleVersion = '1.0.0'
    GUID = '9d3a7e4b-8f12-4c56-9a23-1e5f8b9d0c21'
    Author = 'drummer475-94'
    CompanyName = 'Enterprise IT & SecOps Labs'
    Copyright = '(c) 2026 drummer475-94. All rights reserved.'
    Description = 'Production-grade PowerShell Core & Python automation suite for Active Directory identity lifecycle, GPO security compliance audits, and infrastructure health monitoring.'
    PowerShellVersion = '5.1'

    FunctionsToExport = @(
        'Write-ADAuditLog',
        'Get-ADCredentialFromEnv',
        'Test-IntakeJsonSchema',
        'Revoke-ADUserSession',
        'New-ADUserAutomated',
        'Disable-ADUserOffboard',
        'Set-ADUserRoleAdjustment',
        'Invoke-StaleAccountAudit',
        'Test-DomainAdminHygiene',
        'Get-GPOAuditReport',
        'Invoke-ADHealthCheck'
    )
    CmdletsToExport = @()
    VariablesToExport = @()
    AliasesToExport = @()

    PrivateData = @{
        PSData = @{
            Tags = @('ActiveDirectory', 'IdentityLifecycle', 'GPO', 'SecurityAudit', 'IAM', 'Automation', 'Compliance')
            ProjectUri = 'https://github.com/drummer475-94/it-ad-automator'
        }
    }
}
