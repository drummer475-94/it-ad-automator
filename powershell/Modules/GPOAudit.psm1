# GPOAudit.psm1 - Active Directory Group Policy Audit & Security Scanner
# Part of ITADAutomator PowerShell Suite

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
        $gpos = @()

        # Step 1: Retrieve GPOs (mockable via Get-GPO -All)
        try {
            $gpos = Get-GPO -All -Domain $Domain -ErrorAction Stop
        }
        catch {
            Write-Verbose "Get-GPO -All call failed or domain not reached; generating simulated/scanned findings."
            $gpos = @()
        }

        # Step 2: Analyze GPOs
        $scannedCount = if ($gpos) { $gpos.Count } else { 0 }

        if ($gpos) {
            foreach ($gpo in $gpos) {
                $gpoName = $gpo.DisplayName
                $gpoId = $gpo.Id.ToString()

                # Check 1: Unlinked GPO detection
                try {
                    $reportXml = Get-GPOReport -Guid $gpoId -ReportType Xml -ErrorAction Stop
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
                    Write-Verbose "Could not analyze GPO XML report for $gpoName."
                }
            }
        }

        # Step 3: SYSVOL Scan for hardcoded cpassword and legacy protocol policies
        $targetSysvol = if ($SysvolPath) { $SysvolPath } else { "\\$Domain\sysvol\$Domain\Policies" }
        
        if (Test-Path -Path $targetSysvol) {
            # Search for Groups.xml or cpassword in SYSVOL
            $xmlFiles = Get-ChildItem -Path $targetSysvol -Recurse -Filter "*.xml" -ErrorAction SilentlyContinue
            if ($xmlFiles) {
                foreach ($file in $xmlFiles) {
                    try {
                        $content = Get-Content -Path $file.FullName -Raw -ErrorAction SilentlyContinue
                        if ($content -and $content -match 'cpassword\s*=\s*"[^"]+"') {
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
                        if ($content -and ($content -match 'LmCompatibilityLevel.*[0-2]' -or $content -match 'SMB1.*Enabled.*1')) {
                            $findings += [PSCustomObject]@{
                                GPOName     = $file.Directory.Name
                                GPOId       = $file.FullName
                                Category    = "LegacyProtocolSettings"
                                Severity    = "Medium"
                                Description = "Legacy SMBv1 or NTLMv1 authentication settings configured in GPO policy."
                                Remediation = "Upgrade authentication level to NTLMv2 minimum and enforce SMBv2/v3."
                            }
                        }
                    }
                    catch {
                        Write-Verbose "Error scanning SYSVOL file $($file.FullName): $_"
                    }
                }
            }
        }

        # Format output summary & report
        $hasCritical = ($findings | Where-Object { $_.Severity -eq "Critical" }).Count -gt 0
        $hasHigh = ($findings | Where-Object { $_.Severity -eq "High" }).Count -gt 0
        $complianceStatus = if ($hasCritical -or $hasHigh) { "NonCompliant" } else { "Passed" }

        $reportObj = [PSCustomObject]@{
            Domain            = $Domain
            Timestamp         = (Get-Date).ToUniversalTime().ToString("o")
            ScannedGPOCount   = $scannedCount
            ComplianceStatus  = $complianceStatus
            TotalFindings     = $findings.Count
            Findings          = $findings
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
            OutputPath      = $OutputPath
        } -LogPath $LogPath

        return $reportObj
    }
}
