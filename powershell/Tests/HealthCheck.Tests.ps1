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
            -LogPath (Join-Path $TestDrive 'ad_test_audit.json')

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
            -LogPath (Join-Path $TestDrive 'ad_test_audit.json')

        $report.OverallHealth | Should Be 'Critical'
        $report.DCHealth[0].Status | Should Be 'Unhealthy'
        $report.SYSVOLStatus[0].Status | Should Be 'Offline'
        $findingsText = $report.Findings -join ' '
        $findingsText | Should Match 'DNS resolution failed'
        $findingsText | Should Match 'connectivity test failed'
        $findingsText | Should Match 'SYSVOL share .* is inaccessible'
    }

    It 'treats a PowerShell 7 ping reply with a non-Success status as unreachable' {
        $report = Invoke-ADHealthCheck -DomainControllers @('DC01.corp.local') `
            -DnsResolver { param($name) [PSCustomObject]@{ IPAddress = '10.0.20.10' } } `
            -ConnectionTester { param($name) [PSCustomObject]@{ Status = 'TimedOut'; Latency = 0 } } `
            -PathTester { param($path) $true } `
            -InactiveAccountSearcher { param($days) @() } `
            -LogPath (Join-Path $TestDrive 'ad_test_audit.json')

        $report.DCHealth[0].PingSuccess | Should Be $false
        $report.DCHealth[0].Status | Should Be 'Unhealthy'
        $report.OverallHealth | Should Be 'Critical'
    }

    It 'reads latency from PowerShell 7 and Windows PowerShell ping replies' {
        $report = Invoke-ADHealthCheck -DomainControllers @('DC01.corp.local', 'DC02.corp.local') `
            -DnsResolver { param($name) [PSCustomObject]@{ IPAddress = '10.0.20.10' } } `
            -ConnectionTester { param($name) if ($name -like 'DC01*') { [PSCustomObject]@{ Status = 'Success'; Latency = 7 } } else { [PSCustomObject]@{ StatusCode = 0; ResponseTime = 9 } } } `
            -PathTester { param($path) $true } `
            -InactiveAccountSearcher { param($days) @() } `
            -LogPath (Join-Path $TestDrive 'ad_test_audit.json')

        $report.DCHealth[0].LatencyMs | Should Be 7
        $report.DCHealth[1].LatencyMs | Should Be 9
        $report.OverallHealth | Should Be 'Healthy'
    }

    It 'returns Warning for accounts inactive longer than the threshold' {
        $report = Invoke-ADHealthCheck -DomainControllers @('DC01.corp.local') `
            -DnsResolver { param($name) [PSCustomObject]@{ IPAddress = '10.0.20.10' } } `
            -ConnectionTester { param($name) [PSCustomObject]@{ ResponseTime = 4 } } `
            -PathTester { param($path) $true } `
            -InactiveAccountSearcher { param($days) @([PSCustomObject]@{ SamAccountName = 'olduser1' }, [PSCustomObject]@{ SamAccountName = 'olduser2' }) } `
            -InactiveThresholdDays 90 `
            -LogPath (Join-Path $TestDrive 'ad_test_audit.json')

        $report.OverallHealth | Should Be 'Warning'
        $report.InactiveAccountCount | Should Be 2
    }

    It 'queries Search-ADAccount with the real -UsersOnly parameter when no searcher is injected' {
        Mock -ModuleName HealthCheck Search-ADAccount { @([PSCustomObject]@{ SamAccountName = 'olduser1' }) } -ParameterFilter { $UsersOnly -and $AccountInactive -and $Server -eq 'corp.local' }

        $report = Invoke-ADHealthCheck -DomainControllers @('DC01.corp.local') `
            -DnsResolver { param($name) [PSCustomObject]@{ IPAddress = '10.0.20.10' } } `
            -ConnectionTester { param($name) [PSCustomObject]@{ ResponseTime = 4 } } `
            -PathTester { param($path) $true } `
            -LogPath (Join-Path $TestDrive 'ad_test_audit.json')

        $report.InactiveAccountCount | Should Be 1
        $report.InactiveSearchStatus | Should Be 'Succeeded'
        $report.OverallHealth | Should Be 'Warning'
        Assert-MockCalled -ModuleName HealthCheck Search-ADAccount -Exactly 1 -Scope It
    }

    It 'does not report Healthy when the inactive account search fails' {
        $report = Invoke-ADHealthCheck -DomainControllers @('DC01.corp.local') `
            -DnsResolver { param($name) [PSCustomObject]@{ IPAddress = '10.0.20.10' } } `
            -ConnectionTester { param($name) [PSCustomObject]@{ ResponseTime = 4 } } `
            -PathTester { param($path) $true } `
            -InactiveAccountSearcher { param($days) throw 'Unable to contact the server' } `
            -LogPath (Join-Path $TestDrive 'ad_test_audit.json')

        $report.OverallHealth | Should Be 'Warning'
        $report.InactiveSearchStatus | Should Be 'Failed'
        ($report.Findings -join ' ') | Should Match 'Inactive account search failed'
    }
}
}
