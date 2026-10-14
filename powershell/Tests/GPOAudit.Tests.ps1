# GPOAudit.Tests.ps1 - Pester Unit Tests for Group Policy Audit Cmdlets
# 100% Mocked - No live AD domain required

. (Join-Path $PSScriptRoot 'TestBootstrap.ps1')
$modulePath = Join-Path -Path $PSScriptRoot -ChildPath "../ITADAutomator.psd1"
Import-Module $modulePath -Force -Global

InModuleScope GPOAudit {
Describe "GPO Audit Cmdlets" {

    Context "Get-GPOAuditReport" {
        $tempGpoJson = Join-Path $TestDrive "gpo_test_report.json"
        $mockSysvolDir = Join-Path $TestDrive "mock_sysvol"

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
            $emptySysvol = Join-Path $TestDrive 'empty_sysvol'
            New-Item -ItemType Directory -Path $emptySysvol -Force | Out-Null
            $report = Get-GPOAuditReport -Domain "corp.local" -SysvolPath $emptySysvol -OutputPath $tempGpoJson -LogPath "$TestDrive/ad_test_audit.json"

            $report | Should Not Be $null
            $report.Domain | Should Be "corp.local"
            $report.ScannedGPOCount | Should Be 2
            @($report.Findings | Where-Object { $_.Category -eq "UnlinkedGPO" }).Count | Should Be 2
            @($report.Findings | Where-Object { $_.Category -eq "ExcessivePermissions" }).Count | Should Be 2
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

            $report = Get-GPOAuditReport -SysvolPath $mockSysvolDir -OutputPath $tempGpoJson -LogPath "$TestDrive/ad_test_audit.json"

            $report.Findings | Should Not Be $null
            $cpassFindings = $report.Findings | Where-Object { $_.Category -eq "CPasswordSecret" }
            $cpassFindings | Should Not Be $null
            $cpassFindings.Severity | Should Be "Critical"

            Remove-Item $mockSysvolDir -Recurse -Force -ErrorAction SilentlyContinue
            Remove-Item $tempGpoJson -Force -ErrorAction SilentlyContinue
        }

        It "Reports Incomplete instead of Passed when GPOs cannot be retrieved" {
            Mock -ModuleName GPOAudit Get-GPO { throw 'The specified domain either does not exist or could not be contacted.' }
            $emptySysvol = Join-Path $TestDrive 'empty_sysvol'
            New-Item -ItemType Directory -Path $emptySysvol -Force | Out-Null

            $report = Get-GPOAuditReport -Domain "corp.local" -SysvolPath $emptySysvol -OutputPath $tempGpoJson -LogPath "$TestDrive/ad_test_audit.json"

            $report.ScannedGPOCount | Should Be 0
            $report.ComplianceStatus | Should Be "Incomplete"
            ($report.ScanErrors -join ' ') | Should Match 'Get-GPO failed'
        }

        It "Reports Incomplete when the SYSVOL path is not accessible" {
            Mock -ModuleName GPOAudit Get-GPO { @() }

            $report = Get-GPOAuditReport -Domain "corp.local" -SysvolPath (Join-Path $TestDrive 'missing_sysvol') -OutputPath $tempGpoJson -LogPath "$TestDrive/ad_test_audit.json"

            $report.ComplianceStatus | Should Be "Incomplete"
            ($report.ScanErrors -join ' ') | Should Match 'not accessible'
        }

        It "Requests each GPO report from the audited domain" {
            Mock -ModuleName GPOAudit Get-GPO {
                return @(
                    [PSCustomObject]@{ DisplayName = "Default Domain Policy"; Id = [Guid]::NewGuid() },
                    [PSCustomObject]@{ DisplayName = "Workstation Baseline"; Id = [Guid]::NewGuid() }
                )
            }
            $emptySysvol = Join-Path $TestDrive 'empty_sysvol'
            New-Item -ItemType Directory -Path $emptySysvol -Force | Out-Null

            $null = Get-GPOAuditReport -Domain "contoso.com" -SysvolPath $emptySysvol -OutputPath $tempGpoJson -LogPath "$TestDrive/ad_test_audit.json"

            Assert-MockCalled -ModuleName GPOAudit Get-GPOReport -Exactly 2 -Scope It -ParameterFilter { $Domain -eq 'contoso.com' }
        }

        It "Does not flag compliant NTLM and SMB settings whose other attributes contain 0-2" {
            Mock -ModuleName GPOAudit Get-GPO { @() }
            $sysvol = Join-Path $TestDrive 'compliant_sysvol'
            New-Item -ItemType Directory -Path $sysvol -Force | Out-Null
            @"
<RegistrySettings>
  <Registry name="LmCompatibilityLevel" changed="2021-01-02 10:12:21" uid="{1D2E3F40-0000-0000-0000-000000000012}">
    <Properties action="U" hive="HKEY_LOCAL_MACHINE" key="SYSTEM\CurrentControlSet\Control\Lsa" name="LmCompatibilityLevel" type="REG_DWORD" value="00000005" />
  </Registry>
  <Registry name="SMB1" changed="2021-01-02 10:12:21" uid="{1D2E3F40-0000-0000-0000-000000000011}">
    <Properties action="U" hive="HKEY_LOCAL_MACHINE" key="SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" name="SMB1" type="REG_DWORD" value="00000000" />
  </Registry>
</RegistrySettings>
"@ | Set-Content -Path (Join-Path $sysvol 'Registry.xml')
            @"
[Registry Values]
MACHINE\System\CurrentControlSet\Control\Lsa\LmCompatibilityLevel=4,5
"@ | Set-Content -Path (Join-Path $sysvol 'GptTmpl.inf')

            $report = Get-GPOAuditReport -Domain "corp.local" -SysvolPath $sysvol -OutputPath $tempGpoJson -LogPath "$TestDrive/ad_test_audit.json"

            @($report.Findings | Where-Object { $_.Category -eq "LegacyProtocolSettings" }).Count | Should Be 0
            $report.ComplianceStatus | Should Be "Passed"
        }

        It "Flags NTLMv1 in GptTmpl.inf and SMBv1 in preference registry items as High severity" {
            Mock -ModuleName GPOAudit Get-GPO { @() }
            $sysvol = Join-Path $TestDrive 'legacy_sysvol'
            New-Item -ItemType Directory -Path $sysvol -Force | Out-Null
            @"
<RegistrySettings>
  <Registry name="SMB1" changed="2021-01-02 10:12:21" uid="{1D2E3F40-0000-0000-0000-000000000011}">
    <Properties action="U" hive="HKEY_LOCAL_MACHINE" key="SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" name="SMB1" type="REG_DWORD" value="00000001" />
  </Registry>
</RegistrySettings>
"@ | Set-Content -Path (Join-Path $sysvol 'Registry.xml')
            @"
[Registry Values]
MACHINE\System\CurrentControlSet\Control\Lsa\LmCompatibilityLevel=4,1
"@ | Set-Content -Path (Join-Path $sysvol 'GptTmpl.inf')

            $report = Get-GPOAuditReport -Domain "corp.local" -SysvolPath $sysvol -OutputPath $tempGpoJson -LogPath "$TestDrive/ad_test_audit.json"

            $legacy = @($report.Findings | Where-Object { $_.Category -eq "LegacyProtocolSettings" })
            $legacy.Count | Should Be 2
            ($legacy.Description -join ' ') | Should Match 'LmCompatibilityLevel=1'
            ($legacy.Description -join ' ') | Should Match 'SMB1=1'
            $legacy[0].Severity | Should Be "High"
            $report.ComplianceStatus | Should Be "NonCompliant"
        }

        It "Detects single-quoted cpassword attributes" {
            Mock -ModuleName GPOAudit Get-GPO { @() }
            $sysvol = Join-Path $TestDrive 'quoted_sysvol'
            New-Item -ItemType Directory -Path $sysvol -Force | Out-Null
            "<Groups><User><Properties cpassword='j2A1V3u8N9/1A2B3C4D5E6F7G8H9' userName='localadmin' /></User></Groups>" | Set-Content -Path (Join-Path $sysvol 'Groups.xml')

            $report = Get-GPOAuditReport -Domain "corp.local" -SysvolPath $sysvol -OutputPath $tempGpoJson -LogPath "$TestDrive/ad_test_audit.json"

            @($report.Findings | Where-Object { $_.Category -eq "CPasswordSecret" }).Count | Should Be 1
        }

        It "Names the owning GPO for SYSVOL findings instead of the leaf folder" {
            $gpoGuid = [Guid]'31B2F340-016D-11D2-945F-00C04FB984F9'
            Mock -ModuleName GPOAudit Get-GPO { @([PSCustomObject]@{ DisplayName = "Default Domain Policy"; Id = $gpoGuid }) }
            Mock -ModuleName GPOAudit Get-GPOReport { '<GPO><LinksTo><SOMPath>corp.local</SOMPath></LinksTo></GPO>' }
            $groupsDir = Join-Path $TestDrive 'named_sysvol/{31B2F340-016D-11D2-945F-00C04FB984F9}/Machine/Preferences/Groups'
            New-Item -ItemType Directory -Path $groupsDir -Force | Out-Null
            '<Groups><User><Properties cpassword="j2A1V3u8N9/1A2B3C4D5E6F7G8H9" userName="localadmin" /></User></Groups>' | Set-Content -Path (Join-Path $groupsDir 'Groups.xml')

            $report = Get-GPOAuditReport -Domain "corp.local" -SysvolPath (Join-Path $TestDrive 'named_sysvol') -OutputPath $tempGpoJson -LogPath "$TestDrive/ad_test_audit.json"

            $finding = @($report.Findings | Where-Object { $_.Category -eq "CPasswordSecret" })
            $finding.Count | Should Be 1
            $finding[0].GPOName | Should Be "Default Domain Policy"
            $finding[0].GPOId | Should Be "31B2F340-016D-11D2-945F-00C04FB984F9"
            $finding[0].FilePath | Should Match 'Groups\.xml$'
        }
    }
}
}
