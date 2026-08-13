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
            }

            if ($Credential) {
                $adUserParams['Credential'] = $Credential
            }

            # Invoke New-ADUser cmdlet
            $null = New-ADUser @adUserParams

            # Assign baseline group
            $groupParams = @{
                Identity = $baselineGroup
                Members  = $sam
            }
            if ($Credential) {
                $groupParams['Credential'] = $Credential
            }
            $null = Add-ADGroupMember @groupParams

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
            # 1. Revoke sessions
            $sessionRevoked = Revoke-ADUserSession -Identity $Identity -RevocationHandler $SessionRevocationHandler

            # 2. Get group memberships & strip security/distribution groups
            $getGroupParams = @{ Identity = $Identity }
            if ($Credential) { $getGroupParams['Credential'] = $Credential }

            $userGroups = Get-ADPrincipalGroupMembership @getGroupParams
            $removedGroups = @()

            if ($userGroups) {
                foreach ($group in $userGroups) {
                    # Skip primary group (Domain Users / SID ending in 513)
                    if ($group.Name -ne 'Domain Users' -and $group.GroupScope -ne 'Primary') {
                        $removeGroupParams = @{
                            Identity = $group.SamAccountName
                            Members  = $Identity
                            Confirm  = $false
                        }
                        if ($Credential) { $removeGroupParams['Credential'] = $Credential }
                        $null = Remove-ADGroupMember @removeGroupParams
                        $removedGroups += $group.Name
                    }
                }
            }

            # 3. Disable account
            $disableParams = @{ Identity = $Identity }
            if ($Credential) { $disableParams['Credential'] = $Credential }
            $null = Disable-ADAccount @disableParams

            $auditLog = Write-ADAuditLog -Action "Disable-ADUserOffboard" -Target $Identity -Status "Offboarded" -Details @{
                GroupsRemoved   = $removedGroups
                SessionsRevoked = $sessionRevoked
                ArchiveProfile  = [bool]$ArchiveProfile
            } -LogPath $LogPath

            return [PSCustomObject]@{
                Identity        = $Identity
                Status          = "Offboarded"
                GroupsRemoved   = $removedGroups
                SessionsRevoked = [bool]$sessionRevoked
                ProfileArchived = [bool]$ArchiveProfile
                AuditId         = $auditLog.AuditId
            }
        }
        else {
            return [PSCustomObject]@{
                Identity        = $Identity
                Status          = "WhatIf-Offboarded"
                GroupsRemoved   = @()
                SessionsRevoked = $false
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
