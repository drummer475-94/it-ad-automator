# GPOAudit.psm1 - Active Directory Group Policy Audit & Security Scanner
# Part of ITADAutomator PowerShell Suite

function Get-LegacyProtocolSetting {
    # Returns a description for each NTLMv1/LM or SMBv1 setting configured in a SYSVOL policy file.
    # Covers Security Settings (GptTmpl.inf) and Group Policy Preferences registry items (*.xml).
    # LmCompatibilityLevel 0-2 still sends LM/NTLMv1 responses; 3 or higher is NTLMv2-only.
    param(
        [Parameter(Mandatory = $true)]
        [System.IO.FileInfo]$File,

        [Parameter(Mandatory = $true)]
        [string]$Content
    )

    $settings = @()

    if ($File.Extension -eq '.inf') {
        $lmMatch = [regex]::Match($Content, '(?im)^\s*MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\LmCompatibilityLevel\s*=\s*\d+\s*,\s*(\d+)\s*$')
        if ($lmMatch.Success -and [int]$lmMatch.Groups[1].Value -lt 3) {
            $settings += "LmCompatibilityLevel=$($lmMatch.Groups[1].Value) permits LM/NTLMv1"
        }
        $smbMatch = [regex]::Match($Content, '(?im)^\s*MACHINE\\System\\CurrentControlSet\\Services\\LanmanServer\\Parameters\\SMB1\s*=\s*\d+\s*,\s*(\d+)\s*$')
        if ($smbMatch.Success -and [int]$smbMatch.Groups[1].Value -ne 0) {
            $settings += "SMB1=$($smbMatch.Groups[1].Value) enables the SMBv1 server"
        }
        return $settings
    }

    try {
        $xml = [xml]$Content
    }
    catch {
        return $settings
    }

    foreach ($item in @($xml.SelectNodes('//Properties[@name]'))) {
        if ($item.GetAttribute('action') -eq 'D') { continue }
        $rawValue = $item.GetAttribute('value')
        if ([string]::IsNullOrWhiteSpace($rawValue)) { continue }
        # GPP stores REG_DWORD values as hexadecimal strings, e.g. "00000005".
        $value = if ($item.GetAttribute('type') -eq 'REG_DWORD') { [Convert]::ToInt64($rawValue, 16) } else { $rawValue -as [long] }
        if ($null -eq $value) { continue }

        $name = $item.GetAttribute('name')
        $key = $item.GetAttribute('key')
        if ($name -eq 'LmCompatibilityLevel' -and $key -match '\\Control\\Lsa$' -and $value -lt 3) {
            $settings += "LmCompatibilityLevel=$value permits LM/NTLMv1"
        }
        elseif ($name -eq 'SMB1' -and $key -match '\\LanmanServer\\Parameters$' -and $value -ne 0) {
            $settings += "SMB1=$value enables the SMBv1 server"
        }
    }

    return $settings
}

function Get-GPOAuditReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$Domain = "corp.local",

        [Parameter(Mandatory = $false)]
        [string]$SysvolPath = "",

        [Parameter(Mandatory = $false)]
        [string]$OutputPath = "gpo_audit_report.json",

        [Parameter(Mandatory = $false)]
        [string]$LogPath = "ad_audit_log.json"
    )

    process {
        $findings = @()
        $scanErrors = @()
        $gpos = @()

        # Step 1: Retrieve GPOs (mockable via Get-GPO -All)
        try {
            $gpos = @(Get-GPO -All -Domain $Domain -ErrorAction Stop)
        }
        catch {
            # An unreachable domain is not a clean domain; record it so the report cannot read as Passed.
            $scanErrors += "Get-GPO failed for domain '$Domain': $($_.Exception.Message)"
            $gpos = @()
        }

        # Step 2: Analyze GPOs
        $scannedCount = $gpos.Count

        if ($gpos) {
            foreach ($gpo in $gpos) {
                $gpoName = $gpo.DisplayName
                $gpoId = $gpo.Id.ToString()

                # Check 1: Unlinked GPO detection
                try {
                    $reportXml = Get-GPOReport -Guid $gpoId -ReportType Xml -Domain $Domain -ErrorAction Stop
                    if ($reportXml) {
                        $reportObjXml = [xml]$reportXml

                        # Check if links exist in XML report
                        $links = $reportObjXml.GPO.LinksTo
                        if (-not $links) {
                            $findings += [PSCustomObject]@{
                                GPOName     = $gpoName
                                GPOId       = $gpoId
                                Category    = "UnlinkedGPO"
                                Severity    = "Low"
                                Description = "GPO '$gpoName' is unlinked and not applied to any OU or Site."
                                Remediation = "Review and delete unlinked GPO if deprecated."
                            }
                        }

                        # Check 3: Excessive Permissions on GPO
                        $permissions = $reportObjXml.GPO.UserPermissions
                        if ($permissions) {
                            foreach ($perm in $permissions.TrusteePermissions) {
                                $trustee = $perm.Trustee.Name
                                $permissionType = $perm.PermissionType
                                if ($trustee -eq "Authenticated Users" -and $permissionType -match "Edit|FullControl|Write") {
                                    $findings += [PSCustomObject]@{
                                        GPOName     = $gpoName
                                        GPOId       = $gpoId
                                        Category    = "ExcessivePermissions"
                                        Severity    = "High"
                                        Description = "Authenticated Users granted '$permissionType' on GPO '$gpoName'."
                                        Remediation = "Revoke write/edit permissions from Authenticated Users."
                                    }
                                }
                            }
                        }
                    }
                }
                catch {
                    $scanErrors += "Could not analyze GPO report for '$gpoName': $($_.Exception.Message)"
                }
            }
        }

        # Step 3: SYSVOL Scan for hardcoded cpassword and legacy protocol policies
        $targetSysvol = if ($SysvolPath) { $SysvolPath } else { "\\$Domain\sysvol\$Domain\Policies" }
        
        if (Test-Path -Path $targetSysvol) {
            # Search policy XML (Group Policy Preferences) and GptTmpl.inf (Security Settings) files
            $policyFiles = @(Get-ChildItem -Path $targetSysvol -Recurse -File -Include '*.xml', '*.inf' -ErrorAction SilentlyContinue -ErrorVariable sysvolErrors)
            foreach ($sysvolError in $sysvolErrors) {
                $scanErrors += "SYSVOL enumeration error: $($sysvolError.Exception.Message)"
            }
            foreach ($file in $policyFiles) {
                try {
                    $content = Get-Content -Path $file.FullName -Raw -ErrorAction Stop
                    if (-not $content) { continue }

                    if ($file.Extension -eq '.xml' -and $content -match 'cpassword\s*=\s*("[^"]+"|''[^'']+'')') {
                        $findings += [PSCustomObject]@{
                            GPOName     = $file.Directory.Name
                            GPOId       = $file.FullName
                            Category    = "CPasswordSecret"
                            Severity    = "Critical"
                            Description = "Hardcoded MS14-025 cpassword secret detected in Group Policy XML file: $($file.Name)."
                            Remediation = "Remove Group Policy Preferences password and deploy LAPS."
                        }
                    }

                    # Legacy SMBv1 / NTLMv1 check
                    $legacySettings = @(Get-LegacyProtocolSetting -File $file -Content $content)
                    if ($legacySettings.Count -gt 0) {
                        $findings += [PSCustomObject]@{
                            GPOName     = $file.Directory.Name
                            GPOId       = $file.FullName
                            Category    = "LegacyProtocolSettings"
                            Severity    = "High"
                            Description = "Legacy protocol settings configured in $($file.Name): $($legacySettings -join '; ')."
                            Remediation = "Set LmCompatibilityLevel to 5 (NTLMv2 only) and disable SMBv1."
                        }
                    }
                }
                catch {
                    $scanErrors += "Could not scan SYSVOL file $($file.FullName): $($_.Exception.Message)"
                }
            }
        }
        else {
            $scanErrors += "SYSVOL path '$targetSysvol' is not accessible; cpassword and legacy protocol checks did not run."
        }

        # Format output summary & report
        $hasCritical = ($findings | Where-Object { $_.Severity -eq "Critical" }).Count -gt 0
        $hasHigh = ($findings | Where-Object { $_.Severity -eq "High" }).Count -gt 0
        $complianceStatus = if ($hasCritical -or $hasHigh) { "NonCompliant" } elseif ($scanErrors.Count -gt 0) { "Incomplete" } else { "Passed" }

        $reportObj = [PSCustomObject]@{
            Domain            = $Domain
            Timestamp         = (Get-Date).ToUniversalTime().ToString("o")
            ScannedGPOCount   = $scannedCount
            ComplianceStatus  = $complianceStatus
            TotalFindings     = $findings.Count
            Findings          = $findings
            ScanErrors        = $scanErrors
        }

        # Write output JSON
        try {
            $jsonContent = $reportObj | ConvertTo-Json -Depth 10
            Set-Content -Path $OutputPath -Value $jsonContent -Encoding UTF8 -Force
        }
        catch {
            Write-Warning "Failed to write GPO audit report JSON to $OutputPath"
        }

        # Write audit log entry (suppress output from pipeline)
        $null = Write-ADAuditLog -Action "Get-GPOAuditReport" -Target $Domain -Status $complianceStatus -Details @{
            ScannedGPOCount = $scannedCount
            TotalFindings   = $findings.Count
            ScanErrorCount  = $scanErrors.Count
            OutputPath      = $OutputPath
        } -LogPath $LogPath

        return $reportObj
    }
}
