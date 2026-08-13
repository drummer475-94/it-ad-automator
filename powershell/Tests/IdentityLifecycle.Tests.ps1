# IdentityLifecycle.Tests.ps1 - Pester Unit Tests for Identity Lifecycle Cmdlets
# 100% Mocked - No live AD domain required

. (Join-Path $PSScriptRoot 'TestBootstrap.ps1')
$modulePath = Join-Path -Path $PSScriptRoot -ChildPath "../ITADAutomator.psd1"
Import-Module $modulePath -Force -Global

InModuleScope IdentityLifecycle {
Describe "Identity Lifecycle Cmdlets" {

    Context "Revoke-ADUserSession" {
        It "uses an injected provider and reports its result" {
            $result = Revoke-ADUserSession -Identity 'jdoe@corp.local' -RevocationHandler { param($identity) $identity -eq 'jdoe@corp.local' }
            $result | Should Be $true
        }

        It "does not claim session revocation during WhatIf" {
            $result = Revoke-ADUserSession -Identity 'jdoe@corp.local' -RevocationHandler { $true } -WhatIf
            $result | Should Be $false
        }
    }

    Context "New-ADUserAutomated" {
        $tempIntakeValid = Join-Path $env:TEMP "test_intake_valid.json"
        $tempIntakeInvalid = Join-Path $env:TEMP "test_intake_invalid.json"

        $validJsonContent = @{
            FirstName  = "John"
            LastName   = "Doe"
            Department = "Engineering"
            Manager    = "Jane.Smith"
            EmployeeID = "EMP1001"
        } | ConvertTo-Json

        $invalidJsonContent = @{
            FirstName  = "John"
            Department = "Engineering"
        } | ConvertTo-Json

        Set-Content -Path $tempIntakeValid -Value $validJsonContent -Force
        Set-Content -Path $tempIntakeInvalid -Value $invalidJsonContent -Force

        Mock -ModuleName IdentityLifecycle New-ADUser {}
        Mock -ModuleName IdentityLifecycle Add-ADGroupMember {}
        $testPassword = ConvertTo-SecureString 'Only-For-Mocked-Test-1!' -AsPlainText -Force

        It "Successfully creates AD user and assigns baseline group for valid intake JSON" {
            $result = New-ADUserAutomated -IntakeJsonPath $tempIntakeValid -InitialPassword $testPassword -LogPath "$env:TEMP/ad_test_audit.json"

            $result | Should Not Be $null
            $result.UserPrincipalName | Should Be "john.doe@corp.local"
            $result.SamAccountName | Should Be "jdoe"
            $result.Status | Should Be "Created"
            $result.GroupAssigned | Should Be "GRP-ENG-Baseline"
            $result.AuditId | Should Not Be $null
            Assert-MockCalled -ModuleName IdentityLifecycle New-ADUser -Exactly 1
            Assert-MockCalled -ModuleName IdentityLifecycle Add-ADGroupMember -Exactly 1
        }

        It "Assigns correct baseline group for HR department" {
            $hrJsonPath = Join-Path $env:TEMP "test_intake_hr.json"
            @{
                FirstName  = "Alice"
                LastName   = "Wong"
                Department = "HR"
                Manager    = "Bob.Jones"
                EmployeeID = "EMP1002"
            } | ConvertTo-Json | Set-Content -Path $hrJsonPath -Force

            $result = New-ADUserAutomated -IntakeJsonPath $hrJsonPath -InitialPassword $testPassword -LogPath "$env:TEMP/ad_test_audit.json"
            $result.GroupAssigned | Should Be "GRP-HR-Baseline"
            $result.UserPrincipalName | Should Be "alice.wong@corp.local"
            Remove-Item $hrJsonPath -Force -ErrorAction SilentlyContinue
        }

        It "Throws exception when mandatory intake fields are missing" {
            { New-ADUserAutomated -IntakeJsonPath $tempIntakeInvalid -InitialPassword $testPassword -LogPath "$env:TEMP/ad_test_audit.json" } | Should Throw
        }

        It "Requires a caller-supplied SecureString instead of embedding a default password" {
            { New-ADUserAutomated -IntakeJsonPath $tempIntakeValid -LogPath "$env:TEMP/ad_test_audit.json" } | Should Throw
        }

        It "Supports -WhatIf dry run without calling AD mutation cmdlets" {
            $result = New-ADUserAutomated -IntakeJsonPath $tempIntakeValid -WhatIf -LogPath "$env:TEMP/ad_test_audit.json"
            $result.Status | Should Be "WhatIf-Created"
            $result.UserPrincipalName | Should Be "john.doe@corp.local"
        }

        Remove-Item $tempIntakeValid -Force -ErrorAction SilentlyContinue
        Remove-Item $tempIntakeInvalid -Force -ErrorAction SilentlyContinue
    }

    Context "Disable-ADUserOffboard" {
        Mock -ModuleName IdentityLifecycle Get-ADPrincipalGroupMembership {
            return @(
                [PSCustomObject]@{ SamAccountName = "GRP-ENG-Baseline"; Name = "GRP-ENG-Baseline"; GroupScope = "Global" },
                [PSCustomObject]@{ SamAccountName = "Domain Users"; Name = "Domain Users"; GroupScope = "Primary" }
            )
        }
        Mock -ModuleName IdentityLifecycle Remove-ADGroupMember {}
        Mock -ModuleName IdentityLifecycle Disable-ADAccount {}
        Mock -ModuleName IdentityLifecycle Revoke-ADUserSession { $true }

        It "Offboards user by stripping groups, revoking sessions, and disabling account" {
            $result = Disable-ADUserOffboard -Identity "jdoe" -ArchiveProfile -LogPath "$env:TEMP/ad_test_audit.json"

            $result | Should Not Be $null
            $result.Identity | Should Be "jdoe"
            $result.Status | Should Be "Offboarded"
            $result.ProfileArchived | Should Be $true
            $result.SessionsRevoked | Should Be $true
            $result.GroupsRemoved.Count | Should Be 1
            $result.GroupsRemoved[0] | Should Be "GRP-ENG-Baseline"

            Assert-MockCalled -ModuleName IdentityLifecycle Get-ADPrincipalGroupMembership -Exactly 1
            Assert-MockCalled -ModuleName IdentityLifecycle Remove-ADGroupMember -Exactly 1
            Assert-MockCalled -ModuleName IdentityLifecycle Disable-ADAccount -Exactly 1
            Assert-MockCalled -ModuleName IdentityLifecycle Revoke-ADUserSession -Exactly 1
        }

        It "Supports -WhatIf dry run for offboarding" {
            $result = Disable-ADUserOffboard -Identity "jdoe" -WhatIf -LogPath "$env:TEMP/ad_test_audit.json"
            $result.Status | Should Be "WhatIf-Offboarded"
            $result.SessionsRevoked | Should Be $false
        }
    }

    Context "Set-ADUserRoleAdjustment" {
        Mock -ModuleName IdentityLifecycle Set-ADUser {}
        Mock -ModuleName IdentityLifecycle Add-ADGroupMember {}

        It "Adjusts user role and department group" {
            $result = Set-ADUserRoleAdjustment -Identity "jdoe" -NewRole "Senior Security Engineer" -NewDepartment "IT" -LogPath "$env:TEMP/ad_test_audit.json"

            $result | Should Not Be $null
            $result.Identity | Should Be "jdoe"
            $result.NewRole | Should Be "Senior Security Engineer"
            $result.NewDepartment | Should Be "IT"
            $result.GroupAssigned | Should Be "GRP-IT-Baseline"
            $result.Status | Should Be "RoleAdjusted"

            Assert-MockCalled -ModuleName IdentityLifecycle Set-ADUser -Exactly 1
            Assert-MockCalled -ModuleName IdentityLifecycle Add-ADGroupMember -Exactly 1
        }

        It "Supports -WhatIf dry run for role adjustment" {
            $result = Set-ADUserRoleAdjustment -Identity "jdoe" -NewRole "Manager" -WhatIf -LogPath "$env:TEMP/ad_test_audit.json"
            $result.Status | Should Be "WhatIf-RoleAdjusted"
        }
    }
}
}
