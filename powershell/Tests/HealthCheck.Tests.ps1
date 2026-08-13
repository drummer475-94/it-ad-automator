# HealthCheck.Tests.ps1 - Pester unit tests with injected, offline-safe providers
. (Join-Path $PSScriptRoot 'TestBootstrap.ps1')
$modulePath = Join-Path -Path $PSScriptRoot -ChildPath '../ITADAutomator.psd1'
Import-Module $modulePath -Force -Global

InModuleScope HealthCheck {
Describe 'AD Health Check Cmdlets' {
    It 'returns Healthy when DCs, SYSVOL, and accounts are valid' {
        $report = Invoke-ADHealthCheck -DomainControllers @('DC01.corp.local', 'DC02.corp.local') `
            -DnsResolver { param($name) [PSCustomObject]@{ IPAddress = '10.0.20.10' } } `
            -ConnectionTester { param($name) [PSCustomObject]@{ ResponseTime = 5 } } `
            -PathTester { param($path) $true } `
            -InactiveAccountSearcher { param($days) @() } `
            -LogPath (Join-Path $env:TEMP 'ad_test_audit.json')

        $report.OverallHealth | Should Be 'Healthy'
        $report.DCHealth.Count | Should Be 2
        $report.SYSVOLStatus.Count | Should Be 2
        $report.InactiveAccountCount | Should Be 0
        $report.Findings.Count | Should Be 0
    }

    It 'returns Critical when DNS, connectivity, and SYSVOL checks fail' {
        $report = Invoke-ADHealthCheck -DomainControllers @('DC01.corp.local') `
            -DnsResolver { param($name) throw 'DNS Name Not Found' } `
            -ConnectionTester { param($name) throw 'Host unreachable' } `
            -PathTester { param($path) $false } `
            -InactiveAccountSearcher { param($days) @() } `
            -LogPath (Join-Path $env:TEMP 'ad_test_audit.json')

        $report.OverallHealth | Should Be 'Critical'
        $report.DCHealth[0].Status | Should Be 'Unhealthy'
        $report.SYSVOLStatus[0].Status | Should Be 'Offline'
        $report.Findings.Count | Should BeGreaterThan 0
    }

    It 'returns Warning for accounts inactive longer than the threshold' {
        $report = Invoke-ADHealthCheck -DomainControllers @('DC01.corp.local') `
            -DnsResolver { param($name) [PSCustomObject]@{ IPAddress = '10.0.20.10' } } `
            -ConnectionTester { param($name) [PSCustomObject]@{ ResponseTime = 4 } } `
            -PathTester { param($path) $true } `
            -InactiveAccountSearcher { param($days) @([PSCustomObject]@{ SamAccountName = 'olduser1' }, [PSCustomObject]@{ SamAccountName = 'olduser2' }) } `
            -InactiveThresholdDays 90 `
            -LogPath (Join-Path $env:TEMP 'ad_test_audit.json')

        $report.OverallHealth | Should Be 'Warning'
        $report.InactiveAccountCount | Should Be 2
    }
}
}
