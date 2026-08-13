# GPOAudit.Tests.ps1 - Pester Unit Tests for Group Policy Audit Cmdlets
# 100% Mocked - No live AD domain required

. (Join-Path $PSScriptRoot 'TestBootstrap.ps1')
$modulePath = Join-Path -Path $PSScriptRoot -ChildPath "../ITADAutomator.psd1"
Import-Module $modulePath -Force -Global

InModuleScope GPOAudit {
Describe "GPO Audit Cmdlets" {

    Context "Get-GPOAuditReport" {
        $tempGpoJson = Join-Path $env:TEMP "gpo_test_report.json"
        $mockSysvolDir = Join-Path $env:TEMP "mock_sysvol"

        Mock -ModuleName GPOAudit Get-GPO {
            return @(
                [PSCustomObject]@{ DisplayName = "Default Domain Policy"; Id = [Guid]::NewGuid() },
                [PSCustomObject]@{ DisplayName = "Deprecated Policy Unlinked"; Id = [Guid]::NewGuid() }
            )
        }

        Mock -ModuleName GPOAudit Get-GPOReport {
            param($Guid, $ReportType)
            if ($Guid) {
                return @"
<GPO>
  <Name>Deprecated Policy Unlinked</Name>
  <UserPermissions>
    <TrusteePermissions>
      <Trustee><Name>Authenticated Users</Name></Trustee>
      <PermissionType>Edit</PermissionType>
    </TrusteePermissions>
  </UserPermissions>
</GPO>
"@
            }
            return ""
        }

        It "Scans GPOs and identifies unlinked GPOs and excessive permissions" {
            $report = Get-GPOAuditReport -Domain "corp.local" -OutputPath $tempGpoJson -LogPath "$env:TEMP/ad_test_audit.json"

            $report | Should Not Be $null
            $report.Domain | Should Be "corp.local"
            $report.ScannedGPOCount | Should Be 2
            $report.Findings.Count | Should BeGreaterThan 0
            $report.ComplianceStatus | Should Be "NonCompliant"

            Test-Path $tempGpoJson | Should Be $true

            Remove-Item $tempGpoJson -Force -ErrorAction SilentlyContinue
        }

        It "Detects cpassword secrets in SYSVOL XML files" {
            if (-not (Test-Path $mockSysvolDir)) { New-Item -ItemType Directory -Path $mockSysvolDir -Force | Out-Null }
            $groupsXmlPath = Join-Path $mockSysvolDir "Groups.xml"
            @"
<Groups>
  <UserProperties cpassword="j2A1V3u8N9/1A2B3C4D5E6F7G8H9I0J1K2L3M4N5O6P" name="localadmin" />
</Groups>
"@ | Set-Content -Path $groupsXmlPath -Force

            $report = Get-GPOAuditReport -SysvolPath $mockSysvolDir -OutputPath $tempGpoJson -LogPath "$env:TEMP/ad_test_audit.json"

            $report.Findings | Should Not Be $null
            $cpassFindings = $report.Findings | Where-Object { $_.Category -eq "CPasswordSecret" }
            $cpassFindings | Should Not Be $null
            $cpassFindings.Severity | Should Be "Critical"

            Remove-Item $mockSysvolDir -Recurse -Force -ErrorAction SilentlyContinue
            Remove-Item $tempGpoJson -Force -ErrorAction SilentlyContinue
        }
    }
}
}
