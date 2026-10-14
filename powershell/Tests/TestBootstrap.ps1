# Test-only command shims let Pester mock RSAT commands on hosts without AD/GPO modules.
# They are deliberately outside the production module so they can never shadow real cmdlets.
# Parameter names must match the real RSAT cmdlets exactly so a misspelled parameter fails binding in tests.
function global:New-ADUser { param($SamAccountName, $UserPrincipalName, $GivenName, $Surname, $DisplayName, $Department, $Manager, $EmployeeID, $Path, $Enabled, $AccountPassword, $Credential, $ErrorAction) }
function global:Get-ADUser { param($Identity, $Properties, $Filter, $Credential, $ErrorAction) }
function global:Set-ADUser { param($Identity, $Title, $Department, $Credential) }
function global:Disable-ADAccount { param($Identity, $Credential, $ErrorAction) }
function global:Get-ADPrincipalGroupMembership { param($Identity, $Credential, $ErrorAction) }
function global:Remove-ADGroupMember { param($Identity, $Members, $Confirm, $Credential, $ErrorAction) }
function global:Add-ADGroupMember { param($Identity, $Members, $Credential, $ErrorAction) }
function global:Search-ADAccount { param([switch]$AccountInactive, $TimeSpan, [switch]$UsersOnly, $Server, $ErrorAction) }
function global:Get-ADObject { param($Identity, $Properties, $Filter, $Credential, $ErrorAction) }
function global:Get-ADGroupMember { param($Identity, [switch]$Recursive, $Credential, $ErrorAction) }
function global:Get-GPO { param([switch]$All, $Domain, $ErrorAction) }
function global:Get-GPOReport { param($Guid, $ReportType, $Domain, $ErrorAction) }
