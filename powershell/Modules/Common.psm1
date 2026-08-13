# Common.psm1 - Shared Helpers, Security & Audit Logging Module
# Part of ITADAutomator PowerShell Suite

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

        [Parameter(Mandatory = $false)]
        [string]$LogPath = "ad_audit_log.json"
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

        try {
            $existingLogs = @()
            if (Test-Path -Path $LogPath) {
                $rawContent = Get-Content -Path $LogPath -Raw -ErrorAction SilentlyContinue
                if ($rawContent) {
                    $existingLogs = $rawContent | ConvertFrom-Json
                    if ($existingLogs -isnot [array]) {
                        $existingLogs = @($existingLogs)
                    }
                }
            }

            $existingLogs += $logEntry
            $jsonOutput = $existingLogs | ConvertTo-Json -Depth 10
            Set-Content -Path $LogPath -Value $jsonOutput -Encoding UTF8 -Force
        }
        catch {
            Write-Warning "Failed to write audit log to ${LogPath}: $_"
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

        $intakeData = $rawJson | ConvertFrom-Json -ErrorAction Stop

        $mandatoryFields = @('FirstName', 'LastName', 'Department', 'Manager', 'EmployeeID')
        $missingFields = @()

        foreach ($field in $mandatoryFields) {
            $val = $intakeData.$field
            if ([string]::IsNullOrWhiteSpace($val)) {
                $missingFields += $field
            }
        }

        if ($missingFields.Count -gt 0) {
            $missingStr = $missingFields -join ', '
            throw "Validation failed: Intake JSON is missing mandatory fields: $missingStr"
        }

        return $intakeData
    }
}
