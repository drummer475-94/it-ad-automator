# Common.Tests.ps1 - validation, credentials, and append-only audit tests
. (Join-Path $PSScriptRoot 'TestBootstrap.ps1')
$modulePath = Join-Path -Path $PSScriptRoot -ChildPath '../ITADAutomator.psd1'
Import-Module $modulePath -Force -Global

InModuleScope Common {
Describe 'Common security helpers' {
    It 'returns an explicitly supplied credential without consulting SecretManagement' {
        $secure = ConvertTo-SecureString 'test-value-not-a-production-secret' -AsPlainText -Force
        $credential = [PSCredential]::new('CORP\operator', $secure)
        (Get-ADCredentialFromEnv -Credential $credential).UserName | Should Be 'CORP\operator'
    }

    It 'returns null when neither a credential nor a credential name is supplied' {
        Mock Get-Command {}
        Get-ADCredentialFromEnv | Should Be $null
        Assert-MockCalled Get-Command -Exactly 0 -Scope It
    }

    It 'fails closed when a named credential is requested without SecretManagement' {
        Mock Get-Command { $null } -ParameterFilter { $Name -eq 'Get-Secret' }
        { Get-ADCredentialFromEnv -CredentialName 'missing-test-secret' } | Should Throw 'SecretManagement is required'
    }

    It 'rejects missing and empty intake files' {
        { Test-IntakeJsonSchema -IntakeJsonPath (Join-Path $TestDrive 'does-not-exist-itad.json') } | Should Throw 'not found'
        $emptyPath = Join-Path $TestDrive 'empty-itad.json'
        Set-Content -Path $emptyPath -Value '' -Force
        { Test-IntakeJsonSchema -IntakeJsonPath $emptyPath } | Should Throw 'is empty'
    }

    Context 'Test-IntakeJsonSchema allowlist' {
        $validIntake = @{ FirstName = 'Jordan'; LastName = "O'Neil-Lee"; Department = 'IT'; Manager = 'Casey.Morgan'; EmployeeID = 'EMP-1042' }

        It 'accepts the shipped example intake file' {
            $intake = Test-IntakeJsonSchema -IntakeJsonPath (Join-Path $PSScriptRoot '../../examples/new-hire.json')
            $intake.EmployeeID | Should Be 'EMP-1042'
        }

        It 'accepts a valid intake with apostrophes and hyphens in names' {
            $path = Join-Path $TestDrive 'valid.json'
            $validIntake | ConvertTo-Json | Set-Content -Path $path
            (Test-IntakeJsonSchema -IntakeJsonPath $path).LastName | Should Be "O'Neil-Lee"
        }

        It 'rejects fields outside the allowlist' {
            $path = Join-Path $TestDrive 'extra.json'
            ($validIntake + @{ AdminCount = 1 }) | ConvertTo-Json | Set-Content -Path $path
            { Test-IntakeJsonSchema -IntakeJsonPath $path } | Should Throw 'not allowed: AdminCount'
        }

        It 'rejects values that do not match the field pattern' {
            $path = Join-Path $TestDrive 'pattern.json'
            $bad = $validIntake.Clone()
            $bad.Manager = '*)(objectClass=*'
            $bad | ConvertTo-Json | Set-Content -Path $path
            { Test-IntakeJsonSchema -IntakeJsonPath $path } | Should Throw 'invalid values: Manager'
        }

        It 'rejects non-string values such as arrays' {
            $path = Join-Path $TestDrive 'array-value.json'
            '{"FirstName":"Jordan","LastName":"Lee","Department":["IT","HR"],"Manager":"cmorgan","EmployeeID":"EMP-1"}' | Set-Content -Path $path
            { Test-IntakeJsonSchema -IntakeJsonPath $path } | Should Throw 'invalid values: Department'
        }

        It 'rejects a JSON array instead of a single object' {
            $path = Join-Path $TestDrive 'array-root.json'
            '[{"FirstName":"Jordan"}]' | Set-Content -Path $path
            { Test-IntakeJsonSchema -IntakeJsonPath $path } | Should Throw 'single JSON object'
        }

        It 'reports missing mandatory fields' {
            $path = Join-Path $TestDrive 'missing.json'
            @{ FirstName = 'Jordan'; LastName = 'Lee' } | ConvertTo-Json | Set-Content -Path $path
            { Test-IntakeJsonSchema -IntakeJsonPath $path } | Should Throw 'missing mandatory fields: Department, Manager, EmployeeID'
        }
    }

    Context 'Write-ADAuditLog' {
        It 'appends one JSON line per entry without rewriting earlier entries' {
            $logPath = Join-Path $TestDrive 'append/audit.jsonl'
            $null = Write-ADAuditLog -Action 'First' -Target 'user1' -Status 'Complete' -LogPath $logPath
            $firstLine = Get-Content -Path $logPath
            $null = Write-ADAuditLog -Action 'Second' -Target 'user2' -Status 'Complete' -Details @{ Count = 2 } -LogPath $logPath

            $lines = @(Get-Content -Path $logPath)
            $lines.Count | Should Be 2
            $lines[0] | Should Be $firstLine
            ($lines[1] | ConvertFrom-Json).Action | Should Be 'Second'
            ($lines[1] | ConvertFrom-Json).Details.Count | Should Be 2
        }

        It 'keeps appending after an unparseable line instead of dropping new entries' {
            $logPath = Join-Path $TestDrive 'corrupt.jsonl'
            Set-Content -Path $logPath -Value '{"truncated":'
            $entry = Write-ADAuditLog -Action 'AfterCorruption' -Target 'user1' -Status 'Complete' -LogPath $logPath

            $lines = @(Get-Content -Path $logPath)
            $lines.Count | Should Be 2
            ($lines[1] | ConvertFrom-Json).AuditId | Should Be $entry.AuditId
        }

        It 'uses ITAD_AUDIT_LOG_PATH when no LogPath is given' {
            $envPath = Join-Path $TestDrive 'env/audit.jsonl'
            $previous = $env:ITAD_AUDIT_LOG_PATH
            try {
                $env:ITAD_AUDIT_LOG_PATH = $envPath
                $null = Write-ADAuditLog -Action 'EnvDefault' -Target 'user1' -Status 'Complete'
            }
            finally {
                $env:ITAD_AUDIT_LOG_PATH = $previous
            }
            (Get-Content -Path $envPath | ConvertFrom-Json).Action | Should Be 'EnvDefault'
        }

        It 'defaults to a per-user application data path instead of the current directory' {
            $previous = $env:ITAD_AUDIT_LOG_PATH
            try {
                $env:ITAD_AUDIT_LOG_PATH = $null
                $defaultPath = Get-ADAuditLogDefaultPath
            }
            finally {
                $env:ITAD_AUDIT_LOG_PATH = $previous
            }
            [System.IO.Path]::IsPathRooted($defaultPath) | Should Be $true
            $defaultPath | Should Match 'ITADAutomator[\\/]ad_audit_log\.jsonl$'
        }

        It 'writes an error instead of claiming success when the entry cannot be persisted' {
            $logPath = Join-Path $TestDrive 'locked.jsonl'
            $lock = [System.IO.File]::Open($logPath, [System.IO.FileMode]::OpenOrCreate, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)
            try {
                $entry = Write-ADAuditLog -Action 'Locked' -Target 'user1' -Status 'Complete' -LogPath $logPath -ErrorAction SilentlyContinue -ErrorVariable auditErrors
            }
            finally {
                $lock.Dispose()
            }
            $entry.AuditId | Should Not BeNullOrEmpty
            # -ErrorVariable also collects the lock exceptions caught during retries; one error reports the loss.
            @($auditErrors | Where-Object { "$_" -match 'was NOT written' }).Count | Should Be 1
        }
    }
}
}
