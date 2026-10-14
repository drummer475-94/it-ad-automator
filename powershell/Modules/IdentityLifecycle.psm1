# IdentityLifecycle.psm1 - Active Directory User Onboarding, Offboarding & Role Adjustments
# Part of ITADAutomator PowerShell Suite

function Revoke-ADUserSession {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Identity,

        [Parameter(Mandatory = $false)]
        [scriptblock]$RevocationHandler
    )

    process {
        if ($PSCmdlet.ShouldProcess($Identity, "Revoke Active Directory & Kerberos Ticket Sessions")) {
            if ($RevocationHandler) {
                $result = & $RevocationHandler $Identity
                return ($result -ne $false)
            }

            $graphCommand = Get-Command -Name 'Revoke-MgUserSignInSession' -ErrorAction SilentlyContinue
            if ($graphCommand) {
                $null = Revoke-MgUserSignInSession -UserId $Identity -ErrorAction Stop
                return $true
            }

            Write-Warning 'No session-revocation provider is configured. Install Microsoft.Graph.Users.Actions or pass -RevocationHandler.'
            return $false
        }
        return $false
    }
}

function New-ADUserAutomated {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$IntakeJsonPath,

        [Parameter(Mandatory = $false)]
        [string]$DomainName = "corp.local",

        [Parameter(Mandatory = $false)]
        [string]$BaseOU = "OU=Users,OU=CORP,DC=corp,DC=local",

        [Parameter(Mandatory = $false)]
        [string]$LogPath = "ad_audit_log.json",

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]$Credential,

        [Parameter(Mandatory = $false)]
        [System.Security.SecureString]$InitialPassword
    )

    process {
        # Validate intake JSON and mandatory fields using helper in Common module
        $intake = Test-IntakeJsonSchema -IntakeJsonPath $IntakeJsonPath

        $cleanFirst = $intake.FirstName -replace '[^a-zA-Z0-9]', ''
        $cleanLast  = $intake.LastName  -replace '[^a-zA-Z0-9]', ''
        if ([string]::IsNullOrEmpty($cleanLast)) {
            throw "LastName '$($intake.LastName)' contains no ASCII letters or digits; an account name cannot be derived. Create this account manually."
        }

        $upn = "$($cleanFirst.ToLower()).$($cleanLast.ToLower())@$DomainName"

        $firstInitial = if ($cleanFirst.Length -gt 0) { $cleanFirst.Substring(0,1).ToLower() } else { "u" }
        $sam = "$firstInitial$($cleanLast.ToLower())"
        if ($sam.Length -gt 20) {
            $sam = $sam.Substring(0, 20)
        }

        # Determine department baseline group
        $deptGroupMap = @{
            'Engineering'      = 'GRP-ENG-Baseline'
            'Software'         = 'GRP-ENG-Baseline'
            'HR'               = 'GRP-HR-Baseline'
            'Human Resources'  = 'GRP-HR-Baseline'
            'Finance'          = 'GRP-FIN-Baseline'
            'Accounting'       = 'GRP-FIN-Baseline'
            'Sales'            = 'GRP-SALES-Baseline'
            'Marketing'        = 'GRP-SALES-Baseline'
            'IT'               = 'GRP-IT-Baseline'
        }

        $baselineGroup = "GRP-Domain-Users-Baseline"
        if ($deptGroupMap.ContainsKey($intake.Department)) {
            $baselineGroup = $deptGroupMap[$intake.Department]
        }

        if ($PSCmdlet.ShouldProcess($upn, "Create AD User account ($sam) and assign to $baselineGroup")) {
            if (-not $InitialPassword) {
                throw "InitialPassword is required for account creation. Pass a SecureString; passwords are never read from intake JSON or stored in source."
            }

            # Refuse to continue when the derived names already belong to someone else; otherwise the
            # baseline group grant below would land on the existing account.
            $escapedUpn = $upn -replace "'", "''"
            $lookupParams = @{
                Filter      = "SamAccountName -eq '$sam' -or UserPrincipalName -eq '$escapedUpn'"
                ErrorAction = 'Stop'
            }
            if ($Credential) { $lookupParams['Credential'] = $Credential }
            $existing = @(Get-ADUser @lookupParams)
            if ($existing.Count -gt 0) {
                throw "An AD account already uses SamAccountName '$sam' or UserPrincipalName '$upn'. Resolve the naming collision manually; no changes were made."
            }

            $adUserParams = @{
                SamAccountName     = $sam
                UserPrincipalName  = $upn
                GivenName          = $intake.FirstName
                Surname            = $intake.LastName
                DisplayName        = "$($intake.FirstName) $($intake.LastName)"
                Department         = $intake.Department
                Manager            = $intake.Manager
                EmployeeID         = $intake.EmployeeID
                Path               = $BaseOU
                Enabled            = $true
                AccountPassword    = $InitialPassword
                ErrorAction        = 'Stop'
            }

            if ($Credential) {
                $adUserParams['Credential'] = $Credential
            }

            # Invoke New-ADUser cmdlet
            $null = New-ADUser @adUserParams

            # Assign baseline group
            $groupParams = @{
                Identity    = $baselineGroup
                Members     = $sam
                ErrorAction = 'Stop'
            }
            if ($Credential) {
                $groupParams['Credential'] = $Credential
            }
            try {
                $null = Add-ADGroupMember @groupParams
            }
            catch {
                $null = Write-ADAuditLog -Action "New-ADUserAutomated" -Target $upn -Status "CreatedGroupAssignmentFailed" -Details @{
                    SamAccountName = $sam
                    BaselineGroup  = $baselineGroup
                    Error          = $_.Exception.Message
                } -LogPath $LogPath
                throw "Account '$sam' was created but could not be added to '$baselineGroup': $($_.Exception.Message)"
            }

            $auditLog = Write-ADAuditLog -Action "New-ADUserAutomated" -Target $upn -Status "Created" -Details @{
                SamAccountName = $sam
                BaselineGroup  = $baselineGroup
                EmployeeID     = $intake.EmployeeID
                Department     = $intake.Department
            } -LogPath $LogPath

            return [PSCustomObject]@{
                UserPrincipalName = $upn
                SamAccountName    = $sam
                Status            = "Created"
                GroupAssigned     = $baselineGroup
                Department        = $intake.Department
                EmployeeID        = $intake.EmployeeID
                AuditId           = $auditLog.AuditId
            }
        }
        else {
            return [PSCustomObject]@{
                UserPrincipalName = $upn
                SamAccountName    = $sam
                Status            = "WhatIf-Created"
                GroupAssigned     = $baselineGroup
                Department        = $intake.Department
                EmployeeID        = $intake.EmployeeID
                AuditId           = "WHATIF-SIMULATED"
            }
        }
    }
}

function Disable-ADUserOffboard {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Identity,

        [Parameter(Mandatory = $false)]
        [switch]$ArchiveProfile,

        [Parameter(Mandatory = $false)]
        [string]$LogPath = "ad_audit_log.json",

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]$Credential,

        [Parameter(Mandatory = $false)]
        [scriptblock]$SessionRevocationHandler
    )

    process {
        if ($PSCmdlet.ShouldProcess($Identity, "Offboard AD user (revoke sessions, strip security groups, disable account)")) {
            # Resolve the account first so a bad identity fails before anything is changed, and so the
            # cloud session provider receives the UPN rather than an on-premises SamAccountName or DN.
            $getUserParams = @{ Identity = $Identity; Properties = @('UserPrincipalName'); ErrorAction = 'Stop' }
            if ($Credential) { $getUserParams['Credential'] = $Credential }
            $adUser = Get-ADUser @getUserParams
            $sessionIdentity = if ($adUser.UserPrincipalName) { $adUser.UserPrincipalName } else { $Identity }

            $errors = @()

            # 1. Revoke sessions. A provider failure must not stop the account from being disabled.
            $sessionRevoked = $false
            try {
                $sessionRevoked = [bool](Revoke-ADUserSession -Identity $sessionIdentity -RevocationHandler $SessionRevocationHandler)
            }
            catch {
                $errors += "Session revocation failed: $($_.Exception.Message)"
            }

            # 2. Get group memberships & strip security/distribution groups
            $getGroupParams = @{ Identity = $Identity; ErrorAction = 'Stop' }
            if ($Credential) { $getGroupParams['Credential'] = $Credential }

            $userGroups = @()
            try {
                $userGroups = @(Get-ADPrincipalGroupMembership @getGroupParams)
            }
            catch {
                $errors += "Group membership lookup failed: $($_.Exception.Message)"
            }

            $removedGroups = @()
            $failedGroups = @()
            foreach ($group in $userGroups) {
                # Skip primary group (Domain Users / SID ending in 513)
                if ($group.Name -ne 'Domain Users' -and $group.GroupScope -ne 'Primary') {
                    $removeGroupParams = @{
                        Identity    = $group.SamAccountName
                        Members     = $Identity
                        Confirm     = $false
                        ErrorAction = 'Stop'
                    }
                    if ($Credential) { $removeGroupParams['Credential'] = $Credential }
                    try {
                        $null = Remove-ADGroupMember @removeGroupParams
                        $removedGroups += $group.Name
                    }
                    catch {
                        $failedGroups += $group.Name
                        $errors += "Removal from '$($group.Name)' failed: $($_.Exception.Message)"
                    }
                }
            }

            # 3. Disable account
            $disableParams = @{ Identity = $Identity; ErrorAction = 'Stop' }
            if ($Credential) { $disableParams['Credential'] = $Credential }
            $accountDisabled = $false
            try {
                $null = Disable-ADAccount @disableParams
                $accountDisabled = $true
            }
            catch {
                $errors += "Disable-ADAccount failed: $($_.Exception.Message)"
            }

            $status = if (-not $accountDisabled) { "OffboardFailed" } elseif ($errors.Count -gt 0) { "PartiallyOffboarded" } else { "Offboarded" }

            $auditLog = Write-ADAuditLog -Action "Disable-ADUserOffboard" -Target $Identity -Status $status -Details @{
                GroupsRemoved   = $removedGroups
                GroupsFailed    = $failedGroups
                SessionsRevoked = $sessionRevoked
                AccountDisabled = $accountDisabled
                ArchiveProfile  = [bool]$ArchiveProfile
                Errors          = $errors
            } -LogPath $LogPath

            $result = [PSCustomObject]@{
                Identity        = $Identity
                Status          = $status
                GroupsRemoved   = $removedGroups
                GroupsFailed    = $failedGroups
                SessionsRevoked = $sessionRevoked
                AccountDisabled = $accountDisabled
                ProfileArchived = [bool]$ArchiveProfile
                Errors          = $errors
                AuditId         = $auditLog.AuditId
            }

            if (-not $accountDisabled) {
                Write-Error "Offboarding '$Identity' failed: the account is still enabled. $($errors -join ' ')"
            }
            elseif ($errors.Count -gt 0) {
                Write-Warning "Offboarding '$Identity' completed with errors: $($errors -join ' ')"
            }
            return $result
        }
        else {
            return [PSCustomObject]@{
                Identity        = $Identity
                Status          = "WhatIf-Offboarded"
                GroupsRemoved   = @()
                GroupsFailed    = @()
                SessionsRevoked = $false
                AccountDisabled = $false
                ProfileArchived = [bool]$ArchiveProfile
                AuditId         = "WHATIF-SIMULATED"
            }
        }
    }
}

function Set-ADUserRoleAdjustment {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Identity,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$NewRole,

        [Parameter(Mandatory = $false)]
        [string]$NewDepartment = "",

        [Parameter(Mandatory = $false)]
        [string]$LogPath = "ad_audit_log.json",

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]$Credential
    )

    process {
        if ($PSCmdlet.ShouldProcess($Identity, "Adjust user role to '$NewRole' in department '$NewDepartment'")) {
            $setParams = @{ Identity = $Identity; Title = $NewRole }
            if (-not [string]::IsNullOrWhiteSpace($NewDepartment)) {
                $setParams['Department'] = $NewDepartment
            }
            if ($Credential) { $setParams['Credential'] = $Credential }

            $null = Set-ADUser @setParams

            $targetGroup = "GRP-Domain-Users-Baseline"
            if (-not [string]::IsNullOrWhiteSpace($NewDepartment)) {
                $deptGroupMap = @{
                    'Engineering'     = 'GRP-ENG-Baseline'
                    'HR'              = 'GRP-HR-Baseline'
                    'Finance'         = 'GRP-FIN-Baseline'
                    'Sales'           = 'GRP-SALES-Baseline'
                    'IT'              = 'GRP-IT-Baseline'
                }
                if ($deptGroupMap.ContainsKey($NewDepartment)) {
                    $targetGroup = $deptGroupMap[$NewDepartment]
                    $addGroupParams = @{ Identity = $targetGroup; Members = $Identity }
                    if ($Credential) { $addGroupParams['Credential'] = $Credential }
                    $null = Add-ADGroupMember @addGroupParams
                }
            }

            $auditLog = Write-ADAuditLog -Action "Set-ADUserRoleAdjustment" -Target $Identity -Status "RoleAdjusted" -Details @{
                NewRole       = $NewRole
                NewDepartment = $NewDepartment
                GroupAssigned = $targetGroup
            } -LogPath $LogPath

            return [PSCustomObject]@{
                Identity      = $Identity
                NewRole       = $NewRole
                NewDepartment = $NewDepartment
                GroupAssigned = $targetGroup
                Status        = "RoleAdjusted"
                AuditId       = $auditLog.AuditId
            }
        }
        else {
            return [PSCustomObject]@{
                Identity      = $Identity
                NewRole       = $NewRole
                NewDepartment = $NewDepartment
                Status        = "WhatIf-RoleAdjusted"
                AuditId       = "WHATIF-SIMULATED"
            }
        }
    }
}
