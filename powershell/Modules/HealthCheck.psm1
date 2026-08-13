# HealthCheck.psm1 - Active Directory Infrastructure Health & Active Hygiene Scanner
# Part of ITADAutomator PowerShell Suite

function Invoke-ADHealthCheck {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string[]]$DomainControllers = @("DC01.corp.local", "DC02.corp.local"),

        [Parameter(Mandatory = $false)]
        [string]$Domain = "corp.local",

        [Parameter(Mandatory = $false)]
        [int]$InactiveThresholdDays = 90,

        [Parameter(Mandatory = $false)]
        [string]$LogPath = "ad_audit_log.json",

        [Parameter(Mandatory = $false)]
        [scriptblock]$DnsResolver,

        [Parameter(Mandatory = $false)]
        [scriptblock]$ConnectionTester,

        [Parameter(Mandatory = $false)]
        [scriptblock]$PathTester,

        [Parameter(Mandatory = $false)]
        [scriptblock]$InactiveAccountSearcher
    )

    process {
        $dcHealth = @()
        $sysvolStatus = @()
        $findings = @()

        # Step 1: Validate Domain Controllers DNS resolution and ping latency
        foreach ($dc in $DomainControllers) {
            $dnsResolved = $false
            $pingSuccess = $false
            $latencyMs   = -1

            try {
                $dnsRes = if ($DnsResolver) { & $DnsResolver $dc } else { Resolve-DnsName -Name $dc -ErrorAction Stop }
                if ($dnsRes) { $dnsResolved = $true }
            }
            catch {
                $dnsResolved = $false
            }

            try {
                $conn = if ($ConnectionTester) { & $ConnectionTester $dc } else { Test-Connection -ComputerName $dc -Count 1 -ErrorAction Stop }
                if ($conn) {
                    $pingSuccess = $true
                    $latencyMs = if ($conn.ResponseTime) { $conn.ResponseTime } else { 0 }
                }
            }
            catch {
                $pingSuccess = $false
            }

            if (-not $dnsResolved) {
                $findings += "DC '$dc' DNS resolution failed."
            }
            if (-not $pingSuccess) {
                $findings += "DC '$dc' ping/connectivity test failed."
            }

            $dcHealth += [PSCustomObject]@{
                DomainController = $dc
                DNSResolved      = $dnsResolved
                PingSuccess      = $pingSuccess
                LatencyMs        = $latencyMs
                Status           = if ($dnsResolved -and $pingSuccess) { "Healthy" } else { "Unhealthy" }
            }
        }

        # Step 2: Validate SYSVOL replication availability
        foreach ($dc in $DomainControllers) {
            $sysvolPath = "\\$dc\SYSVOL"
            $sysvolAccessible = $false
            try {
                $sysvolAccessible = if ($PathTester) { [bool](& $PathTester $sysvolPath) } else { Test-Path -Path $sysvolPath -ErrorAction Stop }
            }
            catch {
                $sysvolAccessible = $false
            }

            if (-not $sysvolAccessible) {
                $findings += "SYSVOL share on DC '$dc' ($sysvolPath) is inaccessible."
            }

            $sysvolStatus += [PSCustomObject]@{
                DomainController = $dc
                SysvolPath       = $sysvolPath
                Accessible       = $sysvolAccessible
                Status           = if ($sysvolAccessible) { "Online" } else { "Offline" }
            }
        }

        # Step 3: Check tombstone/inactive accounts > Threshold Days
        $inactiveUsers = @()
        try {
            if ($InactiveAccountSearcher) {
                $inactiveUsers = @(& $InactiveAccountSearcher $InactiveThresholdDays)
            }
            else {
                $timeSpan = New-TimeSpan -Days $InactiveThresholdDays
                $inactiveUsers = Search-ADAccount -AccountInactive -TimeSpan $timeSpan -UserOnly -ErrorAction Stop
            }
        }
        catch {
            Write-Verbose "Search-ADAccount call failed or domain unreachable; defaulting to empty list."
            $inactiveUsers = @()
        }

        $inactiveCount = if ($inactiveUsers) { $inactiveUsers.Count } else { 0 }
        if ($inactiveCount -gt 0) {
            $findings += "Found $inactiveCount inactive AD user accounts with no activity in over $InactiveThresholdDays days."
        }

        # Determine overall health status
        $unhealthyDCs = @($dcHealth | Where-Object { $_.Status -ne "Healthy" }).Count
        $offlineSysvols = @($sysvolStatus | Where-Object { $_.Status -ne "Online" }).Count

        $overallHealth = "Healthy"
        if ($unhealthyDCs -gt 0 -or $offlineSysvols -gt 0) {
            $overallHealth = "Critical"
        }
        elseif ($inactiveCount -gt 0) {
            $overallHealth = "Warning"
        }

        $healthReport = [PSCustomObject]@{
            Timestamp            = (Get-Date).ToUniversalTime().ToString("o")
            Domain               = $Domain
            OverallHealth        = $overallHealth
            DCHealth             = $dcHealth
            SYSVOLStatus         = $sysvolStatus
            InactiveAccountCount = $inactiveCount
            Findings             = $findings
        }

        # Write audit log entry (suppress output from pipeline)
        $null = Write-ADAuditLog -Action "Invoke-ADHealthCheck" -Target $Domain -Status $overallHealth -Details @{
            InactiveAccountCount = $inactiveCount
            UnhealthyDCs         = $unhealthyDCs
            OfflineSysvols       = $offlineSysvols
        } -LogPath $LogPath

        return $healthReport
    }
}
