# Common.Tests.ps1 - validation, credentials, and append-only audit tests
. (Join-Path $PSScriptRoot 'TestBootstrap.ps1')
$modulePath = Join-Path -Path $PSScriptRoot -ChildPath '../ITADAutomator.psd1'
Import-Module $modulePath -Force -Global

InModuleScope Common {
Describe 'Common security helpers' {
    It 'returns an explicitly supplied credential without consulting environment variables' {
        $secure = ConvertTo-SecureString 'test-value-not-a-production-secret' -AsPlainText -Force
        $credential = [PSCredential]::new('CORP\operator', $secure)
        (Get-ADCredentialFromEnv -Credential $credential).UserName | Should Be 'CORP\operator'
    }

    It 'returns null when configured credential environment variables are absent' {
        Get-ADCredentialFromEnv | Should Be $null
    }

    It 'rejects missing and empty intake files' {
        { Test-IntakeJsonSchema -IntakeJsonPath (Join-Path $env:TEMP 'does-not-exist-itad.json') } | Should Throw
        $emptyPath = Join-Path $env:TEMP 'empty-itad.json'
        Set-Content -Path $emptyPath -Value '' -Force
        { Test-IntakeJsonSchema -IntakeJsonPath $emptyPath } | Should Throw
        Remove-Item $emptyPath -Force -ErrorAction SilentlyContinue
    }

    It 'appends structured entries to an existing audit log' {
        $logPath = Join-Path $env:TEMP 'common_audit_test.json'
        Remove-Item $logPath -Force -ErrorAction SilentlyContinue
        $null = Write-ADAuditLog -Action 'First' -Target 'user1' -Status 'Complete' -LogPath $logPath
        $null = Write-ADAuditLog -Action 'Second' -Target 'user2' -Status 'Complete' -LogPath $logPath
        $entries = Get-Content $logPath -Raw | ConvertFrom-Json
        $entries.Count | Should Be 2
        $entries[1].Action | Should Be 'Second'
        Remove-Item $logPath -Force -ErrorAction SilentlyContinue
    }
}
}
