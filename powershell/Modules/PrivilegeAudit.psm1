# PrivilegeAudit.psm1 - Identity hygiene and Tier-0 privilege reporting

function Invoke-StaleAccountAudit {
    [CmdletBinding()]
    param(
        [ValidateRange(1, 3650)]
        [int]$InactiveThresholdDays = 90,

        [string]$OutputPath = "stale_account_audit.json",

        [string]$LogPath = "ad_audit_log.json",

        [System.Management.Automation.PSCredential]$Credential
    )

    process {
        $cutoff = (Get-Date).ToUniversalTime().AddDays(-$InactiveThresholdDays)
        $query = @{
            Filter = '*'
            Properties = @('Enabled', 'LastLogonDate', 'PasswordNeverExpires', 'DistinguishedName', 'MemberOf')
            ErrorAction = 'Stop'
        }
        if ($Credential) { $query['Credential'] = $Credential }

        $findings = foreach ($user in @(Get-ADUser @query)) {
            $reasons = @()
            if ($user.Enabled -and (-not $user.LastLogonDate -or $user.LastLogonDate.ToUniversalTime() -lt $cutoff)) {
                $reasons += 'InactiveEnabledAccount'
            }
            if (-not $user.Enabled -and @($user.MemberOf).Count -gt 0) {
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

        [string]$LogPath = 'ad_audit_log.json',

        [System.Management.Automation.PSCredential]$Credential
    )

    process {
        $memberQuery = @{ Identity = $PrivilegedGroup; Recursive = $false; ErrorAction = 'Stop' }
        if ($Credential) { $memberQuery['Credential'] = $Credential }
        $members = @(Get-ADGroupMember @memberQuery)
        $findings = @()

        foreach ($member in $members) {
            if ($member.objectClass -eq 'group') {
                $findings += [PSCustomObject]@{
                    Identity = $member.SamAccountName
                    FindingType = 'NestedPrivilegedGroup'
                    Severity = 'High'
                    Recommendation = 'Remove nested membership and grant named, separately managed Tier-0 admin identities.'
                }
                continue
            }

            if ($member.objectClass -eq 'user') {
                $userQuery = @{ Identity = $member.DistinguishedName; Properties = @('TrustedForDelegation', 'DistinguishedName'); ErrorAction = 'Stop' }
                if ($Credential) { $userQuery['Credential'] = $Credential }
                $user = Get-ADUser @userQuery

                if ($user.TrustedForDelegation) {
                    $findings += [PSCustomObject]@{
                        Identity = $member.SamAccountName
                        FindingType = 'UnconstrainedDelegation'
                        Severity = 'Critical'
                        Recommendation = 'Disable unconstrained delegation and migrate to constrained or resource-based constrained delegation.'
                    }
                }
                if ($user.DistinguishedName -notlike "*$TierZeroOU*") {
                    $findings += [PSCustomObject]@{
                        Identity = $member.SamAccountName
                        FindingType = 'TierZeroSeparationViolation'
                        Severity = 'High'
                        Recommendation = 'Move privileged administration to a dedicated Tier-0 identity governed by the Tier-0 OU policy.'
                    }
                }
            }
        }

        $report = [PSCustomObject]@{
            GeneratedAt = (Get-Date).ToUniversalTime().ToString('o')
            PrivilegedGroup = $PrivilegedGroup
            MemberCount = $members.Count
            FindingCount = $findings.Count
            ComplianceStatus = if ($findings.Count -eq 0) { 'Passed' } else { 'NonCompliant' }
            Findings = $findings
        }
        $report | ConvertTo-Json -Depth 8 | Set-Content -Path $OutputPath -Encoding UTF8 -Force
        $null = Write-ADAuditLog -Action 'Test-DomainAdminHygiene' -Target $PrivilegedGroup -Status $report.ComplianceStatus -Details @{ FindingCount = $report.FindingCount; OutputPath = $OutputPath } -LogPath $LogPath
        return $report
    }
}
