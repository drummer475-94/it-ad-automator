# ITADAutomator.psm1 - Root Module for Active Directory & Identity Automation
# Imports all submodules and exports public cmdlets

$moduleRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$modulesDir = Join-Path -Path $moduleRoot -ChildPath 'Modules'

foreach ($moduleFile in @('Common.psm1', 'IdentityLifecycle.psm1', 'GPOAudit.psm1', 'HealthCheck.psm1', 'PrivilegeAudit.psm1')) {
    $modulePath = Join-Path -Path $modulesDir -ChildPath $moduleFile
    if (-not (Test-Path -LiteralPath $modulePath)) {
        throw "Required module component not found: $modulePath"
    }
    Import-Module -Name $modulePath -Force -Scope Local
}

Export-ModuleMember -Function `
    Write-ADAuditLog, `
    Get-ADCredentialFromEnv, `
    Test-IntakeJsonSchema, `
    Revoke-ADUserSession, `
    New-ADUserAutomated, `
    Disable-ADUserOffboard, `
    Set-ADUserRoleAdjustment, `
    Invoke-StaleAccountAudit, `
    Test-DomainAdminHygiene, `
    Get-GPOAuditReport, `
    Invoke-ADHealthCheck
