# Common.psm1 - Shared Helpers, Security & Audit Logging Module
# Part of ITADAutomator PowerShell Suite

function Get-ADAuditLogDefaultPath {
    # Audit entries default to one stable per-machine location instead of whatever directory the caller is in.
    if (-not [string]::IsNullOrWhiteSpace($env:ITAD_AUDIT_LOG_PATH)) {
        return $env:ITAD_AUDIT_LOG_PATH
    }
    $dataRoot = [Environment]::GetFolderPath('LocalApplicationData')
    return Join-Path -Path (Join-Path -Path $dataRoot -ChildPath 'ITADAutomator') -ChildPath 'ad_audit_log.jsonl'
}

function Write-ADAuditLog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Action,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Target,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Status,

        [Parameter(Mandatory = $false)]
        [object]$Details = @{},

        # Defaults to $env:ITAD_AUDIT_LOG_PATH, else <LocalApplicationData>/ITADAutomator/ad_audit_log.jsonl.
        [Parameter(Mandatory = $false)]
        [string]$LogPath
    )

    process {
        $auditId = [System.Guid]::NewGuid().ToString()
        $timestamp = (Get-Date).ToUniversalTime().ToString("o")

        $logEntry = [PSCustomObject]@{
            AuditId   = $auditId
            Timestamp = $timestamp
            Action    = $Action
            Target    = $Target
            Status    = $Status
            Details   = $Details
        }

        if ([string]::IsNullOrWhiteSpace($LogPath)) {
            $LogPath = Get-ADAuditLogDefaultPath
        }

        try {
            # Resolve relative paths against the PowerShell location, not the process working directory.
            $resolvedPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($LogPath)
            $logDirectory = Split-Path -Path $resolvedPath -Parent
            if ($logDirectory -and -not (Test-Path -LiteralPath $logDirectory)) {
                $null = New-Item -ItemType Directory -Path $logDirectory -Force -ErrorAction Stop
            }

            # JSON Lines: each entry is appended as one line and earlier entries are never rewritten.
            $line = ($logEntry | ConvertTo-Json -Depth 10 -Compress) + "`n"
            $bytes = [System.Text.Encoding]::UTF8.GetBytes($line)

            # The exclusive write handle serializes concurrent writers; retry briefly while another holds it.
            $written = $false
            for ($attempt = 1; $attempt -le 20 -and -not $written; $attempt++) {
                try {
                    $stream = [System.IO.File]::Open($resolvedPath, [System.IO.FileMode]::Append, [System.IO.FileAccess]::Write, [System.IO.FileShare]::Read)
                    try {
                        $stream.Write($bytes, 0, $bytes.Length)
                        $written = $true
                    }
                    finally {
                        $stream.Dispose()
                    }
                }
                catch [System.IO.IOException] {
                    if ($attempt -eq 20) { throw }
                    Start-Sleep -Milliseconds 50
                }
            }
        }
        catch {
            # The caller's action already happened; it must not look audited when it was not.
            Write-Error "Audit entry $auditId for '$Action' on '$Target' was NOT written to ${LogPath}: $($_.Exception.Message)"
        }

        return $logEntry
    }
}

function Get-ADCredentialFromEnv {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]$Credential,

        [Parameter(Mandatory = $false)]
        [string]$CredentialName
    )

    process {
        if ($Credential) {
            return $Credential
        }

        if ($CredentialName) {
            $secretCommand = Get-Command -Name 'Get-Secret' -ErrorAction SilentlyContinue
            if (-not $secretCommand) {
                throw "Microsoft.PowerShell.SecretManagement is required to resolve CredentialName '$CredentialName'."
            }
            $storedCredential = Get-Secret -Name $CredentialName -ErrorAction Stop
            if ($storedCredential -isnot [System.Management.Automation.PSCredential]) {
                throw "Secret '$CredentialName' must be stored as a PSCredential."
            }
            return $storedCredential
        }

        return $null
    }
}

function Test-IntakeJsonSchema {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$IntakeJsonPath
    )

    process {
        if (-not (Test-Path -Path $IntakeJsonPath)) {
            throw "Intake file not found at path: $IntakeJsonPath"
        }

        $rawJson = Get-Content -Path $IntakeJsonPath -Raw -ErrorAction Stop
        if ([string]::IsNullOrWhiteSpace($rawJson)) {
            throw "Intake file at '$IntakeJsonPath' is empty."
        }

        # Check the raw text: PowerShell 7 unwraps a one-element JSON array into a bare object.
        if (-not $rawJson.TrimStart().StartsWith('{')) {
            throw "Validation failed: Intake JSON must be a single JSON object."
        }
        $intakeData = $rawJson | ConvertFrom-Json -ErrorAction Stop
        if ($intakeData -isnot [System.Management.Automation.PSCustomObject]) {
            throw "Validation failed: Intake JSON must be a single JSON object."
        }

        # Allowlist: every permitted field, the pattern its value must match, and nothing else.
        $fieldRules = [ordered]@{
            FirstName  = "^[\p{L}\p{M}][\p{L}\p{M}' .-]{0,63}$"
            LastName   = "^[\p{L}\p{M}][\p{L}\p{M}' .-]{0,63}$"
            Department = '^[\p{L}\p{N}][\p{L}\p{N} &/.-]{0,63}$'
            Manager    = '^[A-Za-z0-9][A-Za-z0-9._-]{0,19}$'
            EmployeeID = '^[A-Za-z0-9][A-Za-z0-9-]{0,31}$'
        }

        $unknownFields = @($intakeData.PSObject.Properties.Name | Where-Object { -not $fieldRules.Contains($_) })
        if ($unknownFields.Count -gt 0) {
            throw "Validation failed: Intake JSON contains fields that are not allowed: $($unknownFields -join ', ')"
        }

        $missingFields = @()
        $invalidFields = @()
        foreach ($field in $fieldRules.Keys) {
            $val = $intakeData.$field
            if ($null -eq $val -or ($val -is [string] -and [string]::IsNullOrWhiteSpace($val))) {
                $missingFields += $field
            }
            elseif ($val -isnot [string] -or $val -notmatch $fieldRules[$field]) {
                $invalidFields += $field
            }
        }

        if ($missingFields.Count -gt 0) {
            $missingStr = $missingFields -join ', '
            throw "Validation failed: Intake JSON is missing mandatory fields: $missingStr"
        }
        if ($invalidFields.Count -gt 0) {
            throw "Validation failed: Intake JSON fields have invalid values: $($invalidFields -join ', '). Manager must be a SamAccountName."
        }

        return $intakeData
    }
}
