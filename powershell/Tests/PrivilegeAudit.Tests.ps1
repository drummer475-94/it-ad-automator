# PrivilegeAudit.Tests.ps1 - Pester tests with no live domain dependency
. (Join-Path $PSScriptRoot 'TestBootstrap.ps1')
$modulePath = Join-Path -Path $PSScriptRoot -ChildPath '../ITADAutomator.psd1'
Import-Module $modulePath -Force -Global

InModuleScope PrivilegeAudit {
Describe 'Identity privilege and stale-account audits' {
    Context 'Invoke-StaleAccountAudit' {
        Mock -ModuleName PrivilegeAudit Get-ADUser {
            @(
                [PSCustomObject]@{ SamAccountName = 'inactive.user'; SID = 'S-1-5-21-1-2-3-1105'; DistinguishedName = 'CN=Inactive,OU=Users,DC=corp,DC=local'; Enabled = $true; LastLogonDate = (Get-Date).AddDays(-120); whenCreated = (Get-Date).AddDays(-400); PasswordNeverExpires = $false; MemberOf = @() },
                [PSCustomObject]@{ SamAccountName = 'disabled.admin'; SID = 'S-1-5-21-1-2-3-1106'; DistinguishedName = 'CN=Disabled,OU=Users,DC=corp,DC=local'; Enabled = $false; LastLogonDate = (Get-Date).AddDays(-10); whenCreated = (Get-Date).AddDays(-400); PasswordNeverExpires = $true; MemberOf = @('CN=Admins,DC=corp,DC=local') },
                [PSCustomObject]@{ SamAccountName = 'new.hire'; SID = 'S-1-5-21-1-2-3-1107'; DistinguishedName = 'CN=New Hire,OU=Users,DC=corp,DC=local'; Enabled = $true; LastLogonDate = $null; whenCreated = (Get-Date).AddDays(-2); PasswordNeverExpires = $false; MemberOf = @() },
                [PSCustomObject]@{ SamAccountName = 'never.used'; SID = 'S-1-5-21-1-2-3-1108'; DistinguishedName = 'CN=Never Used,OU=Users,DC=corp,DC=local'; Enabled = $true; LastLogonDate = $null; whenCreated = (Get-Date).AddDays(-200); PasswordNeverExpires = $false; MemberOf = @() },
                [PSCustomObject]@{ SamAccountName = 'krbtgt'; SID = 'S-1-5-21-1-2-3-502'; DistinguishedName = 'CN=krbtgt,CN=Users,DC=corp,DC=local'; Enabled = $false; LastLogonDate = $null; whenCreated = (Get-Date).AddDays(-900); PasswordNeverExpires = $false; MemberOf = @('CN=Denied RODC Password Replication Group,CN=Users,DC=corp,DC=local') },
                [PSCustomObject]@{ SamAccountName = 'krbtgt_12345'; SID = 'S-1-5-21-1-2-3-1500'; DistinguishedName = 'CN=krbtgt_12345,CN=Users,DC=corp,DC=local'; Enabled = $false; LastLogonDate = $null; whenCreated = (Get-Date).AddDays(-900); PasswordNeverExpires = $false; MemberOf = @('CN=Denied RODC Password Replication Group,CN=Users,DC=corp,DC=local') }
            )
        }

        $outputPath = Join-Path $TestDrive 'stale_account_audit_test.json'
        $report = Invoke-StaleAccountAudit -InactiveThresholdDays 90 -OutputPath $outputPath -LogPath (Join-Path $TestDrive 'ad_test_audit.json')

        It 'reports inactive, disabled-with-groups, and non-expiring-password hygiene risks' {
            ($report.Findings | Where-Object SamAccountName -eq 'inactive.user').FindingTypes | Should Be @('InactiveEnabledAccount')
            $disabled = $report.Findings | Where-Object SamAccountName -eq 'disabled.admin'
            ($disabled.FindingTypes -contains 'DisabledAccountRetainsGroups') | Should Be $true
            ($disabled.FindingTypes -contains 'PasswordNeverExpires') | Should Be $true
            $disabled.Severity | Should Be 'High'
            Test-Path $outputPath | Should Be $true
        }

        It 'flags never-used accounts only once they are older than the threshold' {
            ($report.Findings | Where-Object SamAccountName -eq 'never.used').FindingTypes | Should Be @('InactiveEnabledAccount')
            ($report.Findings | Where-Object SamAccountName -eq 'new.hire') | Should Be $null
        }

        It 'does not flag built-in disabled krbtgt accounts for retaining groups' {
            @($report.Findings | Where-Object { $_.SamAccountName -like 'krbtgt*' }).Count | Should Be 0
            $report.FindingCount | Should Be 3
        }
    }

    Context 'Test-DomainAdminHygiene' {
        $directMembers = @(
            [PSCustomObject]@{ SamAccountName = 'Legacy Admins'; DistinguishedName = 'CN=Legacy Admins,OU=Groups,DC=corp,DC=local'; objectClass = 'group' },
            [PSCustomObject]@{ SamAccountName = 'daily.user'; DistinguishedName = 'CN=Daily User,OU=Users,DC=corp,DC=local'; objectClass = 'user' },
            [PSCustomObject]@{ SamAccountName = 'adm.alex'; DistinguishedName = 'CN=adm.alex,OU=Admins,OU=Tier 0,DC=corp,DC=local'; objectClass = 'user' },
            [PSCustomObject]@{ SamAccountName = 'adm.lookalike'; DistinguishedName = 'CN=adm.lookalike,OU=Tier 01,DC=corp,DC=local'; objectClass = 'user' }
        )
        $effectiveMembers = @(
            $directMembers[1], $directMembers[2], $directMembers[3],
            [PSCustomObject]@{ SamAccountName = 'nested.user'; DistinguishedName = 'CN=Nested User,OU=Users,DC=corp,DC=local'; objectClass = 'user' },
            [PSCustomObject]@{ SamAccountName = 'APP01$'; DistinguishedName = 'CN=APP01,OU=Tier 0,DC=corp,DC=local'; objectClass = 'computer' }
        )
        $uacByDn = @{
            'CN=Daily User,OU=Users,DC=corp,DC=local' = 0x200 -bor 0x80000
            'CN=adm.alex,OU=Admins,OU=Tier 0,DC=corp,DC=local' = 0x200
            'CN=adm.lookalike,OU=Tier 01,DC=corp,DC=local' = 0x200
            'CN=Nested User,OU=Users,DC=corp,DC=local' = 0x200
            'CN=APP01,OU=Tier 0,DC=corp,DC=local' = 0x1000 -bor 0x80000
        }
        Mock -ModuleName PrivilegeAudit Get-ADGroupMember { $directMembers } -ParameterFilter { -not $Recursive }
        Mock -ModuleName PrivilegeAudit Get-ADGroupMember { $effectiveMembers } -ParameterFilter { $Recursive }
        Mock -ModuleName PrivilegeAudit Get-ADObject { [PSCustomObject]@{ DistinguishedName = $Identity; userAccountControl = $uacByDn[$Identity] } }

        $report = Test-DomainAdminHygiene -OutputPath (Join-Path $TestDrive 'domain_admin_hygiene_test.json') -LogPath (Join-Path $TestDrive 'ad_test_audit.json')
        $findingsFor = { param($identity, $type) @($report.Findings | Where-Object { $_.Identity -eq $identity -and $_.FindingType -eq $type }) }

        It 'detects nested admins, unconstrained delegation, and Tier-0 separation violations' {
            $report.ComplianceStatus | Should Be 'NonCompliant'
            (& $findingsFor 'Legacy Admins' 'NestedPrivilegedGroup').Count | Should Be 1
            (& $findingsFor 'daily.user' 'UnconstrainedDelegation').Count | Should Be 1
            (& $findingsFor 'daily.user' 'TierZeroSeparationViolation').Count | Should Be 1
        }

        It 'checks members that hold the privilege only through a nested group' {
            $nested = & $findingsFor 'nested.user' 'TierZeroSeparationViolation'
            $nested.Count | Should Be 1
            $nested[0].ViaNestedGroup | Should Be $true
            $report.EffectiveMemberCount | Should Be 5
        }

        It 'checks delegation on computer members, not only users' {
            (& $findingsFor 'APP01$' 'UnconstrainedDelegation').Count | Should Be 1
            (& $findingsFor 'APP01$' 'TierZeroSeparationViolation').Count | Should Be 0
        }

        It 'matches the Tier-0 OU by whole DN component, not substring' {
            @($report.Findings | Where-Object Identity -eq 'adm.alex').Count | Should Be 0
            (& $findingsFor 'adm.lookalike' 'TierZeroSeparationViolation').Count | Should Be 1
        }
    }

    Context 'Test-DomainAdminHygiene with a clean group' {
        Mock -ModuleName PrivilegeAudit Get-ADGroupMember {
            @([PSCustomObject]@{ SamAccountName = 'adm.alex'; DistinguishedName = 'CN=adm.alex,OU=Admins,OU=Tier 0,DC=corp,DC=local'; objectClass = 'user' })
        }
        Mock -ModuleName PrivilegeAudit Get-ADObject { [PSCustomObject]@{ userAccountControl = 0x200 } }

        It 'returns Passed when every member is a Tier-0 identity without delegation' {
            $report = Test-DomainAdminHygiene -TierZeroOU 'OU=Tier 0,DC=corp,DC=local' -OutputPath (Join-Path $TestDrive 'clean.json') -LogPath (Join-Path $TestDrive 'ad_test_audit.json')
            $report.ComplianceStatus | Should Be 'Passed'
            $report.FindingCount | Should Be 0
        }
    }

    Context 'Test-DistinguishedNameInContainer' {
        It 'handles escaped commas, spacing and case' {
            Test-DistinguishedNameInContainer -DistinguishedName 'CN=Doe\, Jane, OU=TIER 0 ,DC=corp,DC=local' -Container 'ou=tier 0' | Should Be $true
        }

        It 'requires a full container DN to match the end of the parent path' {
            Test-DistinguishedNameInContainer -DistinguishedName 'CN=a,OU=Tier 0,OU=Old,DC=corp,DC=local' -Container 'OU=Tier 0,DC=corp,DC=local' | Should Be $false
            Test-DistinguishedNameInContainer -DistinguishedName 'CN=a,OU=Admins,OU=Tier 0,DC=corp,DC=local' -Container 'OU=Tier 0,DC=corp,DC=local' | Should Be $true
        }

        It 'does not treat the object own RDN as its container' {
            Test-DistinguishedNameInContainer -DistinguishedName 'OU=Tier 0,DC=corp,DC=local' -Container 'OU=Tier 0' | Should Be $false
        }
    }
}
}
