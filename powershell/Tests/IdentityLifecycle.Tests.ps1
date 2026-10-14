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

        It "Refuses to create an account whose derived name already exists and grants no group" {
            Mock -ModuleName IdentityLifecycle Get-ADUser { [PSCustomObject]@{ SamAccountName = 'jdoe'; UserPrincipalName = 'jane.doe@corp.local' } }

            { New-ADUserAutomated -IntakeJsonPath $tempIntakeValid -InitialPassword $testPassword -LogPath "$env:TEMP/ad_test_audit.json" } | Should Throw 'already uses'

            Assert-MockCalled -ModuleName IdentityLifecycle Get-ADUser -Exactly 1 -Scope It -ParameterFilter { $Filter -match "SamAccountName -eq 'jdoe'" -and $Filter -match "UserPrincipalName -eq 'john.doe@corp.local'" }
            Assert-MockCalled -ModuleName IdentityLifecycle New-ADUser -Exactly 0 -Scope It
            Assert-MockCalled -ModuleName IdentityLifecycle Add-ADGroupMember -Exactly 0 -Scope It
        }

        It "Stops without granting a group when New-ADUser fails" {
            Mock -ModuleName IdentityLifecycle Get-ADUser {}
            Mock -ModuleName IdentityLifecycle New-ADUser { throw 'Access is denied' }
            Mock -ModuleName IdentityLifecycle Add-ADGroupMember {}

            { New-ADUserAutomated -IntakeJsonPath $tempIntakeValid -InitialPassword $testPassword -LogPath "$env:TEMP/ad_test_audit.json" } | Should Throw 'Access is denied'

            Assert-MockCalled -ModuleName IdentityLifecycle Add-ADGroupMember -Exactly 0 -Scope It
        }

        It "Audits and reports a created account whose baseline group assignment failed" {
            Mock -ModuleName IdentityLifecycle Get-ADUser {}
            Mock -ModuleName IdentityLifecycle New-ADUser {}
            Mock -ModuleName IdentityLifecycle Add-ADGroupMember { throw 'Insufficient access rights' }
            $logPath = Join-Path $TestDrive 'group_failure_audit.json'

            { New-ADUserAutomated -IntakeJsonPath $tempIntakeValid -InitialPassword $testPassword -LogPath $logPath } | Should Throw 'was created but could not be added'

            $entry = @(Get-Content -Path $logPath -Raw | ConvertFrom-Json)[-1]
            $entry.Status | Should Be 'CreatedGroupAssignmentFailed'
            $entry.Details.BaselineGroup | Should Be 'GRP-ENG-Baseline'
        }

        It "Rejects a last name that sanitizes to an empty account name" {
            $symbolsPath = Join-Path $TestDrive 'symbols_intake.json'
            @{ FirstName = 'Jordan'; LastName = '---'; Department = 'IT'; Manager = 'cmorgan'; EmployeeID = 'EMP1003' } | ConvertTo-Json | Set-Content -Path $symbolsPath

            { New-ADUserAutomated -IntakeJsonPath $symbolsPath -InitialPassword $testPassword -LogPath "$env:TEMP/ad_test_audit.json" } | Should Throw 'contains no ASCII letters'

            Assert-MockCalled -ModuleName IdentityLifecycle New-ADUser -Exactly 0 -Scope It
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
        Mock -ModuleName IdentityLifecycle Get-ADUser { [PSCustomObject]@{ SamAccountName = 'jdoe'; UserPrincipalName = 'jdoe@corp.local' } }

        It "Offboards user by stripping groups, revoking sessions, and disabling account" {
            $result = Disable-ADUserOffboard -Identity "jdoe" -ArchiveProfile -LogPath "$env:TEMP/ad_test_audit.json"

            $result | Should Not Be $null
            $result.Identity | Should Be "jdoe"
            $result.Status | Should Be "Offboarded"
            $result.ProfileArchived | Should Be $true
            $result.SessionsRevoked | Should Be $true
            $result.GroupsRemoved.Count | Should Be 1
            $result.GroupsRemoved[0] | Should Be "GRP-ENG-Baseline"
            $result.AccountDisabled | Should Be $true
            $result.Errors.Count | Should Be 0

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

    Context "Disable-ADUserOffboard failure handling" {
        # Pester 4 keeps a Mock declared inside an It active for the rest of the Context, so each
        # failure test below re-declares the mocks it depends on.
        Mock -ModuleName IdentityLifecycle Get-ADUser { [PSCustomObject]@{ SamAccountName = 'jdoe'; UserPrincipalName = 'jdoe@corp.local' } }
        Mock -ModuleName IdentityLifecycle Get-ADPrincipalGroupMembership {
            return @(
                [PSCustomObject]@{ SamAccountName = "GRP-ENG-Baseline"; Name = "GRP-ENG-Baseline"; GroupScope = "Global" },
                [PSCustomObject]@{ SamAccountName = "GRP-VPN"; Name = "GRP-VPN"; GroupScope = "Global" }
            )
        }
        Mock -ModuleName IdentityLifecycle Remove-ADGroupMember {}
        Mock -ModuleName IdentityLifecycle Disable-ADAccount {}

        It "Passes the account UPN, not the SamAccountName, to the session revocation provider" {
            $captured = @{}
            $handler = { param($id) $captured.Identity = $id; $true }.GetNewClosure()

            $result = Disable-ADUserOffboard -Identity "jdoe" -SessionRevocationHandler $handler -LogPath "$env:TEMP/ad_test_audit.json"

            $captured.Identity | Should Be 'jdoe@corp.local'
            $result.SessionsRevoked | Should Be $true
            $result.Status | Should Be 'Offboarded'
        }

        It "Still disables the account when session revocation and one group removal fail" {
            Mock -ModuleName IdentityLifecycle Remove-ADGroupMember { throw 'Access is denied' } -ParameterFilter { $Identity -eq 'GRP-VPN' }

            $result = Disable-ADUserOffboard -Identity "jdoe" -SessionRevocationHandler { throw 'Graph unavailable' } -LogPath "$env:TEMP/ad_test_audit.json" -WarningAction SilentlyContinue

            $result.Status | Should Be 'PartiallyOffboarded'
            $result.AccountDisabled | Should Be $true
            $result.SessionsRevoked | Should Be $false
            @($result.GroupsRemoved) -join ',' | Should Be 'GRP-ENG-Baseline'
            @($result.GroupsFailed) -join ',' | Should Be 'GRP-VPN'
            $result.Errors.Count | Should Be 2
            Assert-MockCalled -ModuleName IdentityLifecycle Disable-ADAccount -Exactly 1 -Scope It
        }

        It "Reports OffboardFailed and writes an error when the account cannot be disabled" {
            Mock -ModuleName IdentityLifecycle Get-ADPrincipalGroupMembership { @() }
            Mock -ModuleName IdentityLifecycle Disable-ADAccount { throw 'Insufficient access rights' }
            $logPath = Join-Path $TestDrive 'offboard_failure_audit.json'

            $result = Disable-ADUserOffboard -Identity "jdoe" -SessionRevocationHandler { $true } -LogPath $logPath -ErrorAction SilentlyContinue -ErrorVariable offboardErrors

            $result.Status | Should Be 'OffboardFailed'
            $result.AccountDisabled | Should Be $false
            $offboardErrors.Count | Should BeGreaterThan 0
            @(Get-Content -Path $logPath -Raw | ConvertFrom-Json)[-1].Status | Should Be 'OffboardFailed'
        }

        It "Records a failed group lookup and still disables the account" {
            Mock -ModuleName IdentityLifecycle Get-ADPrincipalGroupMembership { throw 'The server is not operational' }
            Mock -ModuleName IdentityLifecycle Disable-ADAccount {}

            $result = Disable-ADUserOffboard -Identity "jdoe" -SessionRevocationHandler { $true } -LogPath "$env:TEMP/ad_test_audit.json" -WarningAction SilentlyContinue

            $result.Status | Should Be 'PartiallyOffboarded'
            $result.AccountDisabled | Should Be $true
            ($result.Errors -join ' ') | Should Match 'Group membership lookup failed'
        }

        It "Changes nothing when the identity cannot be resolved" {
            Mock -ModuleName IdentityLifecycle Get-ADUser { throw 'Cannot find an object with identity' }

            { Disable-ADUserOffboard -Identity "nosuchuser" -SessionRevocationHandler { $true } -LogPath "$env:TEMP/ad_test_audit.json" } | Should Throw 'Cannot find an object'

            Assert-MockCalled -ModuleName IdentityLifecycle Remove-ADGroupMember -Exactly 0 -Scope It
            Assert-MockCalled -ModuleName IdentityLifecycle Disable-ADAccount -Exactly 0 -Scope It
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
