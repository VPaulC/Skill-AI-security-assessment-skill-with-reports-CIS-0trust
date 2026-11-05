<#
.SYNOPSIS
    Read-only evidence collector for the tenant-ai-security-assessment skill (CIS M365 Benchmark aligned).

.DESCRIPTION
    Prompts the operator to sign in interactively (device code) to the named tenant with READ-ONLY
    Microsoft Graph scopes, then exports evidence to <OutputPath>\raw\*.json for analyse_findings.py.
    Only Invoke-MgGraphRequest -Method GET and Get-* cmdlets are used. No configuration is changed.
    Tokens are never written to disk. If the tenant blocks the device code flow (CIS M365 5.2.2.12), use -UseBrowser.

.EXAMPLE
    ./Invoke-TenantAiAssessment.ps1 -TenantId contoso.onmicrosoft.com -OutputPath ./assessment
    ./Invoke-TenantAiAssessment.ps1 -TenantId <guid> -OutputPath ./a -IncludePurview -IncludeExchange `
        -IncludeSharePoint -SharePointAdminUrl https://contoso-admin.sharepoint.com -IncludePowerPlatform -IncludeTeams

.NOTES
    Requires: Microsoft.Graph.Authentication. Optional: ExchangeOnlineManagement,
    Microsoft.Online.SharePoint.PowerShell, Microsoft.PowerApps.Administration.PowerShell, Az.CognitiveServices,
    MicrosoftTeams.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $TenantId,
    [Parameter(Mandatory)] [string] $OutputPath,
    [switch] $IncludePurview,
    [switch] $IncludeExchange,
    [switch] $IncludeSharePoint,
    [string] $SharePointAdminUrl,
    [switch] $IncludePowerPlatform,
    [switch] $IncludeTeams,
    [string] $AzureSubscriptionId,
    [switch] $UseBrowser
)

$ErrorActionPreference = 'Stop'
$raw = Join-Path $OutputPath 'raw'
New-Item -ItemType Directory -Force -Path $raw | Out-Null
$log = [ordered]@{ tenant = $TenantId; calls = [ordered]@{} }

$ReadOnlyScopes = @(
    'Directory.Read.All','Policy.Read.All','Organization.Read.All','Reports.Read.All','AuditLog.Read.All',
    'SecurityEvents.Read.All','RoleManagement.Read.Directory','Application.Read.All',
    'IdentityRiskyUser.Read.All','AccessReview.Read.All','EntitlementManagement.Read.All',
    'InformationProtectionPolicy.Read','SharePointTenantSettings.Read.All','UserAuthenticationMethod.Read.All',
    'RoleManagementPolicy.Read.Directory',   # CIS 5.3.4 PIM approval settings
    'OrgSettings-AppsAndServices.Read.All'   # CIS 1.3.4 user owned apps and services [verify]
)
$GA = '62e90394-69f5-4237-9190-012177145e10'
$GraphApp = '00000003-0000-0000-c000-000000000000'

$Endpoints = [ordered]@{
    organization              = '/v1.0/organization'
    subscribedSkus            = '/v1.0/subscribedSkus'
    users_licences            = '/v1.0/users?$select=id,userType,accountEnabled,assignedLicenses&$top=999'
    securityDefaults          = '/v1.0/policies/identitySecurityDefaultsEnforcementPolicy'
    caPolicies                = '/v1.0/identity/conditionalAccess/policies'
    namedLocations            = '/v1.0/identity/conditionalAccess/namedLocations'
    authMethodsPolicy         = '/v1.0/policies/authenticationMethodsPolicy'
    authStrengths             = '/v1.0/policies/authenticationStrengthPolicies'
    mfaRegistration           = '/v1.0/reports/authenticationMethods/userRegistrationDetails?$top=999'
    authorizationPolicy       = '/v1.0/policies/authorizationPolicy'
    adminConsentPolicy        = '/v1.0/policies/adminConsentRequestPolicy'
    roleAssignments_GA        = "/v1.0/roleManagement/directory/roleAssignments?`$filter=roleDefinitionId eq '$GA'&`$expand=principal"
    roleEligibility           = '/v1.0/roleManagement/directory/roleEligibilitySchedules'
    privilegedRoleAssignments = '/v1.0/roleManagement/directory/roleAssignments?$expand=roleDefinition'
    servicePrincipals         = '/v1.0/servicePrincipals?$select=id,appId,displayName,appOwnerOrganizationId,servicePrincipalType,accountEnabled,tags&$top=999'
    graphServicePrincipal     = "/v1.0/servicePrincipals(appId='$GraphApp')?`$select=id,appRoles"
    appRoleAssignments_graph  = "/v1.0/servicePrincipals(appId='$GraphApp')/appRoleAssignedTo?`$top=999"
    oauth2Grants              = '/v1.0/oauth2PermissionGrants?$top=999'
    riskyUsers                = "/v1.0/identityProtection/riskyUsers?`$filter=riskState eq 'atRisk'"
    crossTenantDefault        = '/v1.0/policies/crossTenantAccessPolicy/default'
    accessReviews             = '/v1.0/identityGovernance/accessReviews/definitions'
    accessPackages            = '/v1.0/identityGovernance/entitlementManagement/accessPackages'
    spoSettings               = '/v1.0/admin/sharepoint/settings'
    sensitivityLabels         = '/beta/security/informationProtection/sensitivityLabels'
    secureScore               = '/v1.0/security/secureScores?$top=1'
    defaultAppManagementPolicy = '/v1.0/policies/defaultAppManagementPolicy'
    groupSettings             = '/v1.0/groupSettings'
    roleManagementPolicy_GA   = "/v1.0/policies/roleManagementPolicyAssignments?`$filter=scopeId eq '/' and scopeType eq 'DirectoryRole' and roleDefinitionId eq '$GA'&`$expand=policy(`$expand=rules)"
    appsAndServices           = '/beta/admin/appsAndServices'
}

function Save-Evidence([string]$Name, $Data) {
    $Data | ConvertTo-Json -Depth 20 | Set-Content -Path (Join-Path $raw "$Name.json") -Encoding utf8
}

function Get-GraphAll([string]$Uri) {
    # GET only — this function never issues any other HTTP method.
    $items = @(); $next = $Uri; $single = $null
    while ($next) {
        $resp = Invoke-MgGraphRequest -Method GET -Uri $next -OutputType PSObject -Headers @{ ConsistencyLevel = 'eventual' }
        if ($resp.PSObject.Properties.Name -contains 'value') {
            $items += $resp.value; $next = $resp.'@odata.nextLink'
        } else { $single = $resp; $next = $null }
    }
    if ($single) { return $single } else { return @{ value = $items } }
}

function Invoke-Safe([string]$Name, [scriptblock]$Block) {
    try {
        $data = & $Block
        Save-Evidence $Name $data
        $log.calls[$Name] = @{ status = 200; error = $null }
        Write-Host "  $Name : OK" -ForegroundColor Green
    } catch {
        $msg = $_.Exception.Message
        $code = if ($msg -match '(\d{3})') { [int]$Matches[1] } else { 0 }
        $log.calls[$Name] = @{ status = $code; error = $msg.Substring(0, [Math]::Min(300, $msg.Length)) }
        Write-Host "  $Name : Not assessed ($msg)" -ForegroundColor Yellow
    }
}

# ---- 1. Interactive, read-only sign-in (operator authenticates themselves) ----
Write-Host "Signing in to tenant $TenantId with READ-ONLY scopes..." -ForegroundColor Cyan
if ($UseBrowser) {
    Connect-MgGraph -TenantId $TenantId -Scopes $ReadOnlyScopes -NoWelcome
} else {
    Connect-MgGraph -TenantId $TenantId -Scopes $ReadOnlyScopes -UseDeviceCode -NoWelcome
}
$ctx = Get-MgContext
$log.account = $ctx.Account
$log.granted_scopes = $ctx.Scopes

# ---- 2. Microsoft Graph evidence ----
foreach ($k in $Endpoints.Keys) { Invoke-Safe $k { Get-GraphAll $Endpoints[$k] } }

# ---- 3. Optional modules (each prompts the operator to sign in; Get-* only) ----
if ($IncludeExchange) {
    Connect-ExchangeOnline -ShowBanner:$false -Organization $TenantId
    Invoke-Safe 'ps_auditConfig' { Get-AdminAuditLogConfig | Select-Object UnifiedAuditLogIngestionEnabled }
    Invoke-Safe 'ps_orgConfig' { Get-OrganizationConfig | Select-Object AuditDisabled }
    Invoke-Safe 'ps_roleAssignmentPolicy' { Get-RoleAssignmentPolicy | Select-Object Name, IsDefault, AssignedRoles }
    Invoke-Safe 'ps_owaPolicy' { Get-OwaMailboxPolicy | Select-Object Name, AdditionalStorageProvidersAvailable }
    Invoke-Safe 'ps_safeLinksPolicy' {
        Get-SafeLinksPolicy | Select-Object Name, IsBuiltInProtection, EnableSafeLinksForEmail, EnableSafeLinksForTeams,
            EnableSafeLinksForOffice, TrackClicks, AllowClickThrough, ScanUrls, EnableForInternalSenders, DeliverMessageAfterScan
    }
    Invoke-Safe 'ps_safeLinksRule' { Get-SafeLinksRule | Select-Object Name, SafeLinksPolicy, State }
}
if ($IncludePurview) {
    Connect-IPPSSession -ShowBanner:$false
    Invoke-Safe 'ps_dlpPolicies' {
        $rules = Get-DlpComplianceRule
        Get-DlpCompliancePolicy | ForEach-Object {
            $p = $_
            [pscustomobject]@{ Name = $p.Name; Mode = "$($p.Mode)"; Enabled = $p.Enabled; Workload = "$($p.Workload)"
                Locations = ($p | Select-Object *Location* | ConvertTo-Json -Depth 3 -Compress)
                Rules = @($rules | Where-Object ParentPolicyName -eq $p.Name | Select-Object -ExpandProperty Name) }
        }
    }
    Invoke-Safe 'ps_retentionPolicies' { Get-RetentionCompliancePolicy -DistributionDetail | Select-Object Name, Enabled, Mode, Workload, *Location* }
    Invoke-Safe 'ps_labelPolicies' { Get-LabelPolicy | Select-Object Name, Enabled, Labels, Settings }
    Invoke-Safe 'ps_insiderRisk' { Get-InsiderRiskPolicy | Select-Object Name, Enabled, InsiderRiskScenario }
    Invoke-Safe 'ps_commCompliance' { Get-SupervisoryReviewPolicyV2 | Select-Object Name, Enabled }
}
if ($IncludeSharePoint -and $SharePointAdminUrl) {
    Connect-SPOService -Url $SharePointAdminUrl
    Invoke-Safe 'ps_spoTenant' {
        Get-SPOTenant | Select-Object SharingCapability, DefaultSharingLinkType, RequireAnonymousLinksExpireInDays,
            OneDriveSharingCapability, DefaultLinkPermission, ConditionalAccessPolicy,
            PreventExternalUsersFromResharing, SharingDomainRestrictionMode, ExternalUserExpirationRequired,
            ExternalUserExpireInDays, EmailAttestationRequired, EmailAttestationReAuthDays, LegacyAuthProtocolsEnabled
    }
    Invoke-Safe 'ps_spoRestrictedSearch' { @{ Mode = "$(Get-SPOTenantRestrictedSearchMode)" } }
}
if ($IncludeTeams) {
    # Separate, opt-in sign-in — the skill confirms with the user before running this.
    Connect-MicrosoftTeams -TenantId $TenantId | Out-Null
    Invoke-Safe 'ps_teamsMeetingPolicy' {
        Get-CsTeamsMeetingPolicy -Identity Global | Select-Object Identity, AllowCloudRecording, AllowTranscription
    }
    Disconnect-MicrosoftTeams | Out-Null
}
if ($IncludePowerPlatform) {
    Add-PowerAppsAccount
    Invoke-Safe 'ps_powerPlatformDlp' { Get-DlpPolicy | Select-Object -ExpandProperty value }
}
if ($AzureSubscriptionId) {
    Connect-AzAccount -Tenant $TenantId -Subscription $AzureSubscriptionId | Out-Null
    Invoke-Safe 'ps_azureOpenAI' {
        Get-AzCognitiveServicesAccount | Where-Object { $_.AccountType -in 'OpenAI','AIServices' } |
            Select-Object AccountName, ResourceGroupName, Location, PublicNetworkAccess, DisableLocalAuth
    }
}

# ---- 4. Log (no tokens) and sign out ----
$log | ConvertTo-Json -Depth 6 | Set-Content -Path (Join-Path $raw 'collection-log.json') -Encoding utf8
Disconnect-MgGraph | Out-Null
Write-Host "Evidence written to $raw. Next: python analyse_findings.py --raw $raw --out $OutputPath" -ForegroundColor Cyan
