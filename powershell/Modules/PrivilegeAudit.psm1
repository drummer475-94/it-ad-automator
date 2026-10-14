# PrivilegeAudit.psm1 - Identity hygiene and Tier-0 privilege reporting

function ConvertTo-DistinguishedNameComponent {
    # Splits a DN into normalized RDNs ("ou=tier 0"), honouring escaped commas such as "CN=Doe\, Jane".
    param([string]$DistinguishedName)

    if ([string]::IsNullOrWhiteSpace($DistinguishedName)) { return @() }
    return @([regex]::Split($DistinguishedName, '(?<!\\),') |
        ForEach-Object { ($_.Trim() -replace '^([^=]+?)\s*=\s*', '$1=').ToLowerInvariant() } |
        Where-Object { $_ })
}

function Test-DistinguishedNameInContainer {
    # True when the object's parent path contains the container's RDNs as a contiguous run.
    # A full container DN (one with DC= components) must match the end of the parent path exactly.
    param(
        [string]$DistinguishedName,
        [string]$Container
    )

    $parentPath = @(ConvertTo-DistinguishedNameComponent -DistinguishedName $DistinguishedName | Select-Object -Skip 1)
    $containerPath = @(ConvertTo-DistinguishedNameComponent -DistinguishedName $Container)
    if ($containerPath.Count -eq 0 -or $containerPath.Count -gt $parentPath.Count) { return $false }

    $containerText = $containerPath -join ','
    $lastStart = $parentPath.Count - $containerPath.Count
    $firstStart = if (@($containerPath | Where-Object { $_ -like 'dc=*' }).Count -gt 0) { $lastStart } else { 0 }
    for ($start = $firstStart; $start -le $lastStart; $start++) {
        if (($parentPath[$start..($start + $containerPath.Count - 1)] -join ',') -eq $containerText) {
            return $true
        }
    }
    return $false
}

function Invoke-StaleAccountAudit {
    [CmdletBinding()]
    param(
        [ValidateRange(1, 3650)]
        [int]$InactiveThresholdDays = 90,

        [string]$OutputPath = "stale_account_audit.json",

        [string]$LogPath,

        [System.Management.Automation.PSCredential]$Credential
    )

    process {
        $cutoff = (Get-Date).ToUniversalTime().AddDays(-$InactiveThresholdDays)
        $query = @{
            Filter = '*'
            Properties = @('Enabled', 'LastLogonDate', 'PasswordNeverExpires', 'DistinguishedName', 'MemberOf', 'whenCreated')
            ErrorAction = 'Stop'
        }
        if ($Credential) { $query['Credential'] = $Credential }

        $findings = foreach ($user in @(Get-ADUser @query)) {
            $reasons = @()
            # An account that has never logged on is only stale once it is older than the threshold.
            $isInactive = if ($user.LastLogonDate) {
                $user.LastLogonDate.ToUniversalTime() -lt $cutoff
            }
            else {
                -not $user.whenCreated -or $user.whenCreated.ToUniversalTime() -lt $cutoff
            }
            if ($user.Enabled -and $isInactive) {
                $reasons += 'InactiveEnabledAccount'
            }
            # Guest (RID 501), krbtgt (502), DefaultAccount (503) and RODC krbtgt_NNNNN accounts are disabled
            # by design and keep built-in memberships, so they are not offboarding leftovers.
            $isBuiltInDisabledAccount = ("$($user.SID)" -match '-50[123]$') -or ($user.SamAccountName -match '^krbtgt(_\d+)?$')
            if (-not $user.Enabled -and -not $isBuiltInDisabledAccount -and @($user.MemberOf).Count -gt 0) {
                $reasons += 'DisabledAccountRetainsGroups'
            }
            if ($user.PasswordNeverExpires) {
                $reasons += 'PasswordNeverExpires'
            }

            if ($reasons.Count -gt 0) {
                [PSCustomObject]@{
                    SamAccountName = $user.SamAccountName
                    DistinguishedName = $user.DistinguishedName
                    Enabled = [bool]$user.Enabled
                    LastLogonDate = $user.LastLogonDate
                    FindingTypes = $reasons
                    Severity = if ($reasons -contains 'PasswordNeverExpires') { 'High' } else { 'Medium' }
                    Recommendation = 'Validate the owner and business need, then disable or remediate access through the approved change process.'
                }
            }
        }

        $report = [PSCustomObject]@{
            GeneratedAt = (Get-Date).ToUniversalTime().ToString('o')
            InactiveThresholdDays = $InactiveThresholdDays
            FindingCount = @($findings).Count
            Findings = @($findings)
        }
        $report | ConvertTo-Json -Depth 8 | Set-Content -Path $OutputPath -Encoding UTF8 -Force
        $null = Write-ADAuditLog -Action 'Invoke-StaleAccountAudit' -Target 'ActiveDirectory' -Status 'Completed' -Details @{ FindingCount = $report.FindingCount; OutputPath = $OutputPath } -LogPath $LogPath
        return $report
    }
}

function Test-DomainAdminHygiene {
    [CmdletBinding()]
    param(
        [string]$PrivilegedGroup = 'Domain Admins',

        [string]$TierZeroOU = 'OU=Tier 0',

        [string]$OutputPath = 'domain_admin_hygiene.json',

        [string]$LogPath,

        [System.Management.Automation.PSCredential]$Credential
    )

    process {
        $memberQuery = @{ Identity = $PrivilegedGroup; Recursive = $false; ErrorAction = 'Stop' }
        if ($Credential) { $memberQuery['Credential'] = $Credential }
        $members = @(Get-ADGroupMember @memberQuery)
        $findings = @()

        foreach ($member in $members | Where-Object { $_.objectClass -eq 'group' }) {
            $findings += [PSCustomObject]@{
                Identity = $member.SamAccountName
                ObjectClass = $member.objectClass
                FindingType = 'NestedPrivilegedGroup'
                Severity = 'High'
                Recommendation = 'Remove nested membership and grant named, separately managed Tier-0 admin identities.'
            }
        }

        # Every effective member - users, computers and service accounts, including those that only hold the
        # privilege through a nested group - is checked for delegation and Tier-0 placement.
        $effectiveQuery = @{ Identity = $PrivilegedGroup; Recursive = $true; ErrorAction = 'Stop' }
        if ($Credential) { $effectiveQuery['Credential'] = $Credential }
        $effectiveMembers = @(Get-ADGroupMember @effectiveQuery | Where-Object { $_.objectClass -ne 'group' })
        $directMemberDns = @($members | ForEach-Object { $_.DistinguishedName })

        foreach ($member in $effectiveMembers) {
            $objectQuery = @{ Identity = $member.DistinguishedName; Properties = @('userAccountControl'); ErrorAction = 'Stop' }
            if ($Credential) { $objectQuery['Credential'] = $Credential }
            $principal = Get-ADObject @objectQuery
            $viaNestedGroup = $directMemberDns -notcontains $member.DistinguishedName

            # 0x80000 = TRUSTED_FOR_DELEGATION (unconstrained Kerberos delegation)
            if (([int64]$principal.userAccountControl -band 0x80000) -ne 0) {
                $findings += [PSCustomObject]@{
                    Identity = $member.SamAccountName
                    ObjectClass = $member.objectClass
                    ViaNestedGroup = $viaNestedGroup
                    FindingType = 'UnconstrainedDelegation'
                    Severity = 'Critical'
                    Recommendation = 'Disable unconstrained delegation and migrate to constrained or resource-based constrained delegation.'
                }
            }
            if (-not (Test-DistinguishedNameInContainer -DistinguishedName $member.DistinguishedName -Container $TierZeroOU)) {
                $findings += [PSCustomObject]@{
                    Identity = $member.SamAccountName
                    ObjectClass = $member.objectClass
                    ViaNestedGroup = $viaNestedGroup
                    FindingType = 'TierZeroSeparationViolation'
                    Severity = 'High'
                    Recommendation = 'Move privileged administration to a dedicated Tier-0 identity governed by the Tier-0 OU policy.'
                }
            }
        }

        $report = [PSCustomObject]@{
            GeneratedAt = (Get-Date).ToUniversalTime().ToString('o')
            PrivilegedGroup = $PrivilegedGroup
            MemberCount = $members.Count
            EffectiveMemberCount = $effectiveMembers.Count
            FindingCount = $findings.Count
            ComplianceStatus = if ($findings.Count -eq 0) { 'Passed' } else { 'NonCompliant' }
            Findings = $findings
        }
        $report | ConvertTo-Json -Depth 8 | Set-Content -Path $OutputPath -Encoding UTF8 -Force
        $null = Write-ADAuditLog -Action 'Test-DomainAdminHygiene' -Target $PrivilegedGroup -Status $report.ComplianceStatus -Details @{ FindingCount = $report.FindingCount; OutputPath = $OutputPath } -LogPath $LogPath
        return $report
    }
}
