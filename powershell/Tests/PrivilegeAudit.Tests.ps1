# PrivilegeAudit.Tests.ps1 - Pester tests with no live domain dependency
. (Join-Path $PSScriptRoot 'TestBootstrap.ps1')
$modulePath = Join-Path -Path $PSScriptRoot -ChildPath '../ITADAutomator.psd1'
Import-Module $modulePath -Force -Global

InModuleScope PrivilegeAudit {
Describe 'Identity privilege and stale-account audits' {
    Context 'Invoke-StaleAccountAudit' {
        Mock -ModuleName PrivilegeAudit Get-ADUser {
            @(
                [PSCustomObject]@{ SamAccountName = 'inactive.user'; DistinguishedName = 'CN=Inactive,OU=Users,DC=corp,DC=local'; Enabled = $true; LastLogonDate = (Get-Date).AddDays(-120); PasswordNeverExpires = $false; MemberOf = @() },
                [PSCustomObject]@{ SamAccountName = 'disabled.admin'; DistinguishedName = 'CN=Disabled,OU=Users,DC=corp,DC=local'; Enabled = $false; LastLogonDate = (Get-Date).AddDays(-10); PasswordNeverExpires = $true; MemberOf = @('CN=Admins,DC=corp,DC=local') }
            )
        }

        It 'reports inactive, disabled-with-groups, and non-expiring-password hygiene risks' {
            $outputPath = Join-Path $env:TEMP 'stale_account_audit_test.json'
            $report = Invoke-StaleAccountAudit -InactiveThresholdDays 90 -OutputPath $outputPath -LogPath (Join-Path $env:TEMP 'ad_test_audit.json')

            $report.FindingCount | Should Be 2
            ($report.Findings[0].FindingTypes -contains 'InactiveEnabledAccount') | Should Be $true
            ($report.Findings[1].FindingTypes -contains 'DisabledAccountRetainsGroups') | Should Be $true
            ($report.Findings[1].FindingTypes -contains 'PasswordNeverExpires') | Should Be $true
            Test-Path $outputPath | Should Be $true
            Remove-Item $outputPath -Force -ErrorAction SilentlyContinue
        }
    }

    Context 'Test-DomainAdminHygiene' {
        Mock -ModuleName PrivilegeAudit Get-ADGroupMember {
            @(
                [PSCustomObject]@{ SamAccountName = 'Legacy Admins'; DistinguishedName = 'CN=Legacy Admins,DC=corp,DC=local'; objectClass = 'group' },
                [PSCustomObject]@{ SamAccountName = 'daily.user'; DistinguishedName = 'CN=Daily User,OU=Users,DC=corp,DC=local'; objectClass = 'user' }
            )
        }
        Mock -ModuleName PrivilegeAudit Get-ADUser {
            [PSCustomObject]@{ SamAccountName = 'daily.user'; DistinguishedName = 'CN=Daily User,OU=Users,DC=corp,DC=local'; TrustedForDelegation = $true }
        }

        It 'detects nested admins, unconstrained delegation, and Tier-0 separation violations' {
            $outputPath = Join-Path $env:TEMP 'domain_admin_hygiene_test.json'
            $report = Test-DomainAdminHygiene -OutputPath $outputPath -LogPath (Join-Path $env:TEMP 'ad_test_audit.json')

            $report.ComplianceStatus | Should Be 'NonCompliant'
            ($report.Findings | Where-Object { $_.FindingType -eq 'NestedPrivilegedGroup' }) | Should Not Be $null
            ($report.Findings | Where-Object { $_.FindingType -eq 'UnconstrainedDelegation' }) | Should Not Be $null
            ($report.Findings | Where-Object { $_.FindingType -eq 'TierZeroSeparationViolation' }) | Should Not Be $null
            Remove-Item $outputPath -Force -ErrorAction SilentlyContinue
        }
    }
}
}
