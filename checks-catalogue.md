# Checks Catalogue — Tenant AI Security Assessment (CIS-aligned)

All checks are **read-only**. "Raw file" is the file name the collectors write under `raw/` and that
`analyse_findings.py` reads. "Eval" = how *this skill* evaluates the check ("Auto" by the analyser;
"Manual" = the agent judges from PowerShell output or records *Not assessed — manual verification required*
with the portal path). "CIS assessment" = the Automated/Manual status CIS gives the recommendation.

**Primary benchmark (authoritative):** CIS Microsoft 365 Foundations Benchmark **v7.0.0** (released 19 May 2026;
sections 1 Admin centre · 2 Defender · 3 Purview · 4 Intune · 5 Entra · 6 Exchange · 7 SharePoint · 8 Teams ·
9 Fabric). Each finding is also mapped to a **CIS Critical Security Controls v8.1** safeguard and its lowest
Implementation Group. See [cis-benchmark.md](cis-benchmark.md) for profiles, scoring and terms of use.

- The machine-readable mapping is [cis-mapping.json](cis-mapping.json) — the single source of truth the
  analyser reads. Edit mappings there, then keep this table in step.
- Pass criteria below **paraphrase** the CIS audit procedure intent; they never reproduce CIS text. Confirm
  exact values against the licensed benchmark PDF.
- **[verify]** marks any ID, profile, assessment status or safeguard mapping not yet confirmed against the
  licensed v7.0.0 document. Never remove a [verify] marker without checking the source.
- AI-specific checks with no CIS M365 equivalent are **Supplementary – no direct CIS M365 recommendation**,
  mapped to the nearest CIS Controls v8.1 safeguard. They are excluded from the CIS M365 score but included in
  the IG coverage figures.
- The only secondary cross-reference is **Microsoft Zero Trust for Microsoft 365 Copilot** (`secondary_refs` in
  cis-mapping.json). It is shown only if the user opts in at Step 1. NIST AI RMF and NZISM are not used.

## Collected endpoints (Microsoft Graph, GET only)

| Raw file | Endpoint | Scope |
|---|---|---|
| organization.json | `/v1.0/organization` | Organization.Read.All |
| subscribedSkus.json | `/v1.0/subscribedSkus` | Organization.Read.All |
| users_licences.json | `/v1.0/users?$select=id,userType,accountEnabled,assignedLicenses&$top=999` (paged) | Directory.Read.All |
| securityDefaults.json | `/v1.0/policies/identitySecurityDefaultsEnforcementPolicy` | Policy.Read.All |
| caPolicies.json | `/v1.0/identity/conditionalAccess/policies` | Policy.Read.All |
| namedLocations.json | `/v1.0/identity/conditionalAccess/namedLocations` | Policy.Read.All |
| authMethodsPolicy.json | `/v1.0/policies/authenticationMethodsPolicy` | Policy.Read.All |
| authStrengths.json | `/v1.0/policies/authenticationStrengthPolicies` | Policy.Read.All |
| mfaRegistration.json | `/v1.0/reports/authenticationMethods/userRegistrationDetails` (paged) | AuditLog.Read.All |
| authorizationPolicy.json | `/v1.0/policies/authorizationPolicy` | Policy.Read.All |
| adminConsentPolicy.json | `/v1.0/policies/adminConsentRequestPolicy` | Policy.Read.All |
| roleAssignments_GA.json | `/v1.0/roleManagement/directory/roleAssignments?$filter=roleDefinitionId eq '62e90394-69f5-4237-9190-012177145e10'&$expand=principal` | RoleManagement.Read.Directory |
| roleEligibility.json | `/v1.0/roleManagement/directory/roleEligibilitySchedules` | RoleManagement.Read.Directory |
| privilegedRoleAssignments.json | `/v1.0/roleManagement/directory/roleAssignments?$expand=roleDefinition` | RoleManagement.Read.Directory |
| servicePrincipals.json | `/v1.0/servicePrincipals?$select=id,appId,displayName,appOwnerOrganizationId,servicePrincipalType,accountEnabled,tags` (paged) | Application.Read.All |
| appRoleAssignments_graph.json | `/v1.0/servicePrincipals(appId='00000003-0000-0000-c000-000000000000')/appRoleAssignedTo` (paged) | Application.Read.All |
| oauth2Grants.json | `/v1.0/oauth2PermissionGrants` (paged) | Directory.Read.All |
| riskyUsers.json | `/v1.0/identityProtection/riskyUsers?$filter=riskState eq 'atRisk'` | IdentityRiskyUser.Read.All |
| crossTenantDefault.json | `/v1.0/policies/crossTenantAccessPolicy/default` | Policy.Read.All |
| accessReviews.json | `/v1.0/identityGovernance/accessReviews/definitions` | AccessReview.Read.All |
| accessPackages.json | `/v1.0/identityGovernance/entitlementManagement/accessPackages` | EntitlementManagement.Read.All |
| spoSettings.json | `/v1.0/admin/sharepoint/settings` | SharePointTenantSettings.Read.All |
| sensitivityLabels.json | `/beta/security/informationProtection/sensitivityLabels` | InformationProtectionPolicy.Read |
| secureScore.json | `/v1.0/security/secureScores?$top=1` | SecurityEvents.Read.All |
| defaultAppManagementPolicy.json | `/v1.0/policies/defaultAppManagementPolicy` | Policy.Read.All |
| groupSettings.json | `/v1.0/groupSettings` | Directory.Read.All |
| roleManagementPolicy_GA.json | `/v1.0/policies/roleManagementPolicyAssignments?$filter=scopeId eq '/' and scopeType eq 'DirectoryRole' and roleDefinitionId eq '<GA>'&$expand=policy($expand=rules)` | RoleManagementPolicy.Read.Directory |
| appsAndServices.json | `/beta/admin/appsAndServices` [verify] | OrgSettings-AppsAndServices.Read.All [verify] |

## Optional PowerShell evidence (Get-* only; user signs in to each module)

| Raw file | Cmdlet | Module |
|---|---|---|
| ps_auditConfig.json | `Get-AdminAuditLogConfig` | ExchangeOnlineManagement |
| ps_orgConfig.json | `Get-OrganizationConfig` (AuditDisabled) | ExchangeOnlineManagement |
| ps_roleAssignmentPolicy.json | `Get-RoleAssignmentPolicy` (AssignedRoles) | ExchangeOnlineManagement |
| ps_owaPolicy.json | `Get-OwaMailboxPolicy` (AdditionalStorageProvidersAvailable) | ExchangeOnlineManagement |
| ps_safeLinksPolicy.json / ps_safeLinksRule.json | `Get-SafeLinksPolicy`, `Get-SafeLinksRule` | ExchangeOnlineManagement |
| ps_dlpPolicies.json | `Get-DlpCompliancePolicy` + `Get-DlpComplianceRule` | IPPSSession |
| ps_retentionPolicies.json | `Get-RetentionCompliancePolicy` (look for Microsoft 365 Copilot / AI apps locations) | IPPSSession |
| ps_labelPolicies.json | `Get-LabelPolicy` (default label, mandatory labelling) | IPPSSession |
| ps_insiderRisk.json | `Get-InsiderRiskPolicy` | IPPSSession |
| ps_commCompliance.json | `Get-SupervisoryReviewPolicyV2` | IPPSSession |
| ps_spoTenant.json | `Get-SPOTenant` (SharingCapability, DefaultSharingLinkType, DefaultLinkPermission, RequireAnonymousLinksExpireInDays, OneDriveSharingCapability, PreventExternalUsersFromResharing, SharingDomainRestrictionMode, ExternalUserExpiration*, EmailAttestation*, LegacyAuthProtocolsEnabled) | SharePoint Online |
| ps_spoRestrictedSearch.json | `Get-SPOTenantRestrictedSearchMode` | SharePoint Online |
| ps_powerPlatformDlp.json | `Get-DlpPolicy` | Microsoft.PowerApps.Administration.PowerShell |
| ps_teamsMeetingPolicy.json | `Get-CsTeamsMeetingPolicy -Identity Global` — collector `-IncludeTeams`; separate opt-in sign-in, confirmed with the user first | MicrosoftTeams |
| ps_azureOpenAI.json | `Get-AzCognitiveServicesAccount` (Kind=OpenAI/AIServices; publicNetworkAccess, disableLocalAuth) | Az.CognitiveServices |

## Checks

| ID | Area | Control | CIS M365 ID – title | Profile | CIS assessment | Pass criteria (paraphrased) | Raw file(s) | Eval | Licence | CIS Controls v8.1 | IG |
|---|---|---|---|---|---|---|---|---|---|---|---|
| ENT-SD-01 | Entra ID | Security defaults vs Conditional Access | Supplementary – no direct CIS M365 recommendation [verify] | — | — | CA policies enforced, or security defaults on when no CA | securityDefaults, caPolicies | Auto | Free / P1 | 6.3 Require MFA for externally-exposed applications | IG1 |
| ENT-CA-01 | Entra ID | MFA required for all users | 5.2.2.2 – Ensure multifactor authentication is enabled for all users | E3 L1 | Automated | Enabled CA: All users, All resources, grant MFA or authentication strength | caPolicies | Auto | Entra ID P1 | 6.3 Require MFA for externally-exposed applications | IG1 |
| ENT-CA-02 | Entra ID | MFA for administrative roles | 5.2.2.1 – Ensure multifactor authentication is enabled for all users in administrative roles | E3 L1 | Automated | Enabled CA targeting privileged directory roles (incl. Global Administrator) with MFA | caPolicies | Auto | Entra ID P1 | 6.5 Require MFA for administrative access | IG1 |
| ENT-CA-09 | Entra ID | Phishing-resistant MFA strength for administrators | 5.2.2.5 – Ensure 'Phishing-resistant MFA strength' is required for Administrators | E3 L2 | Automated | Enabled CA for admin roles requiring the built-in phishing-resistant strength | caPolicies | Auto | Entra ID P1 | 6.5 Require MFA for administrative access | IG1 |
| ENT-CA-03 | Entra ID | Block legacy authentication | 5.2.2.3 – Enable Conditional Access policies to block legacy authentication | E3 L1 | Automated | Enabled CA, client apps Exchange ActiveSync + Other, grant block | caPolicies | Auto | Entra ID P1 | 4.8 [verify] Uninstall or disable unnecessary services | IG2 |
| ENT-CA-04 | Entra ID | Managed device required for authentication (incl. Copilot) | 5.2.2.9 – Ensure a managed device is required for authentication | E3 L1 | Automated | Enabled CA: All users, All resources, require compliant or hybrid-joined device | caPolicies | Auto | Entra ID P1 + Intune | 4.1 [verify] Establish and maintain a secure configuration process | IG1 |
| ENT-CA-05 | Entra ID | Sign-in risk policy | 5.2.2.7 – Enable Identity Protection sign-in risk policies | E5 L1 [verify] | Automated | Enabled CA for medium+high sign-in risk requiring MFA (or block) | caPolicies | Auto | Entra ID P2 | 6.3 [verify] Require MFA for externally-exposed applications | IG1 |
| ENT-CA-06 | Entra ID | User risk policy | 5.2.2.6 – Enable Identity Protection user risk policies | E5 L1 [verify] | Automated | Enabled CA for high user risk requiring secure password change / risk remediation | caPolicies | Auto | Entra ID P2 | 6.3 [verify] Require MFA for externally-exposed applications | IG1 |
| ENT-CA-10 | Entra ID | Block medium/high sign-in risk | 5.2.2.8 – Ensure 'sign-in risk' is blocked for medium and high risk | E5 L2 | Automated | Enabled CA blocking medium+high sign-in risk | caPolicies | Auto | Entra ID P2 | 6.3 [verify] Require MFA for externally-exposed applications | IG1 |
| ENT-CA-11 | Entra ID | Admin sign-in frequency and non-persistent browser | 5.2.2.4 – Ensure Sign-in frequency is enabled and browser sessions are not persistent for Administrative users | E3 L1 | Automated | Admin-role CA with sign-in frequency set (≤4 h [verify]) and persistent browser 'never' | caPolicies | Auto | Entra ID P1 | 4.3 [verify] Configure automatic session locking | IG1 |
| ENT-CA-12 | Entra ID | Periodic reauthentication for all users | 5.2.2.13 – Ensure that periodic reauthentication is required for all users | E3 L1 | Automated | All-users CA with a sign-in frequency session control [verify value] | caPolicies | Auto | Entra ID P1 | 4.3 [verify] Configure automatic session locking | IG1 |
| ENT-CA-13 | Entra ID | Device code flow blocked | 5.2.2.12 – Ensure the device code sign-in flow is blocked | E3 L1 | Automated | Enabled CA, All users, authentication flows = device code flow, grant block | caPolicies | Auto | Entra ID P1 | 4.8 [verify] Uninstall or disable unnecessary services | IG2 |
| ENT-CA-14 | Entra ID | Authentication transfer blocked | 5.2.2.17 – Ensure authentication transfer is blocked | E3 L1 | Automated | Enabled CA, All users, authentication flows = authentication transfer, grant block | caPolicies | Auto | Entra ID P1 | 4.8 [verify] Uninstall or disable unnecessary services | IG2 |
| ENT-CA-07 | AI Governance | CA targeting Microsoft 365 Copilot / AI apps | Supplementary – no direct CIS M365 recommendation | — | — | Enabled CA including Copilot/AI app IDs, or All resources with strong controls | caPolicies, servicePrincipals | Auto (partial) | Entra ID P1 | 6.7 Centralise access control | IG2 |
| ENT-CA-08 | Entra ID | Report-only CA policies | Supplementary – no direct CIS M365 recommendation | — | — | No stale report-only policies | caPolicies | Auto (Info) | Entra ID P1 | 4.1 Establish and maintain a secure configuration process | IG1 |
| ENT-AM-01 | Entra ID | Phishing-resistant methods enabled | Supplementary – no direct CIS M365 recommendation | — | — | FIDO2/passkey, Windows Hello or certificate auth enabled | authMethodsPolicy | Auto | Free | 6.5 Require MFA for administrative access | IG1 |
| ENT-AM-02 | Entra ID | Weak authentication methods disabled | 5.2.3.5 – Ensure weak authentication methods are disabled | E3 L1 [verify] | Automated | SMS and voice call methods disabled | authMethodsPolicy | Auto | Free | 6.3 [verify] Require MFA for externally-exposed applications | IG1 |
| ENT-AM-03 | Entra ID | All member users MFA capable | 5.2.3.4 – Ensure all member users are 'MFA capable' | E3 L1 [verify] | Automated | Every enabled member user is MFA capable (documented exceptions only) | mfaRegistration | Auto | Entra ID P1 (report) | 6.3 Require MFA for externally-exposed applications | IG1 |
| ENT-AM-04 | Entra ID | Authenticator protected against MFA fatigue | 5.2.3.1 – Ensure Microsoft Authenticator is configured to protect against MFA fatigue | E3 L1 [verify] | Automated | Authenticator push shows application name and geographic location | authMethodsPolicy | Auto | Free | 6.3 Require MFA for externally-exposed applications | IG1 |
| ENT-AM-05 | Entra ID | System-preferred MFA enabled | 5.2.3.6 [verify] – Ensure system-preferred multifactor authentication is enabled | E3 L1 [verify] | Automated | System-preferred MFA state enabled | authMethodsPolicy | Auto / Manual if not in API | Free | 6.3 Require MFA for externally-exposed applications | IG1 |
| ENT-AM-06 | Entra ID | Email OTP method disabled | 5.2.3.7 – Ensure the email OTP authentication method is disabled | E3 L2 | Automated | Email OTP authentication method disabled | authMethodsPolicy | Auto | Free | 6.3 [verify] Require MFA for externally-exposed applications | IG1 |
| ENT-PIM-01 | Entra ID | Between two and four Global Administrators | 1.1.3 – Ensure that between two and four global admins are designated | E3 L1 | Automated | 2–4 active GA assignments (incl. break-glass) | roleAssignments_GA | Auto | Free | 5.4 Restrict administrator privileges to dedicated administrator accounts | IG1 |
| ENT-PIM-03 | Entra ID | Administrative accounts are cloud-only | 1.1.1 – Ensure Administrative accounts are cloud-only | E3 L1 | Automated | No privileged account synced from on-premises | roleAssignments_GA | Auto (GA only) / Manual | Free | 5.4 [verify] Restrict administrator privileges to dedicated administrator accounts | IG1 |
| ENT-PIM-02 | Entra ID | Privileged roles activated, not permanently assigned | 5.3.1 – Ensure privileged role assignments are activated and not assigned | E5 L2 | Automated | Eligible PIM assignments; no standing privileged assignments except break-glass | roleEligibility, privilegedRoleAssignments | Auto | Entra ID P2 / Governance | 5.4 Restrict administrator privileges to dedicated administrator accounts | IG1 |
| ENT-PIM-04 | Entra ID | Approval required for GA activation | 5.3.4 – Ensure approval is required for Global Administrator role activation | E5 L1 [verify] | Manual [verify] | PIM role setting for Global Administrator requires approval with ≥1 approver | roleManagementPolicy_GA | Auto | Entra ID P2 / Governance | 6.1 [verify] Establish an access granting process | IG1 |
| ENT-PIM-05 | Entra ID | Two emergency access (break-glass) accounts | 1.1.2 – Ensure two emergency access accounts have been defined | E3 L1 | Manual [verify] | Two cloud-only permanent GA accounts, documented CA exclusions, strong auth, monitored — the user identifies the accounts | — | Manual (ask user) | Free | 5.4 [verify] Restrict administrator privileges to dedicated administrator accounts | IG1 |
| ENT-IDP-01 | Entra ID | Identity Protection risky users | Supplementary – no direct CIS M365 recommendation | — | — | No unremediated high-risk users | riskyUsers | Auto | Entra ID P2 | 13.1 [verify] Centralise security event alerting | IG2 |
| ENT-WID-01 | Entra ID | Workload identity protection | Supplementary – no direct CIS M365 recommendation | — | — | CA for workload identities where SPs hold high privilege | caPolicies, appRoleAssignments_graph | Auto (partial) | Workload ID Premium | 5.5 [verify] Establish and maintain an inventory of service accounts | IG2 |
| ENT-DIR-01 | Apps & Consent | Users cannot register applications | 5.1.2.2 – Ensure users cannot register applications | E3 L1 | Automated | Default user permission to register apps = No | authorizationPolicy | Auto | Free | 2.5 [verify] Allowlist authorised software | IG2 |
| ENT-DIR-02 | Entra ID | Users cannot create security groups | 5.1.3.1 – Ensure users cannot create security groups | E3 L1 | Automated | Default user permission to create security groups = No | authorizationPolicy | Auto | Free | 6.1 [verify] Establish an access granting process | IG1 |
| ENT-DIR-04 | Entra ID | Non-admin users cannot create tenants | 5.1.2.3 – Ensure 'Restrict non-admin users from creating tenants' is set to 'Yes' | E3 L1 | Automated | allowedToCreateTenants = false | authorizationPolicy | Auto | Free | 4.1 [verify] Establish and maintain a secure configuration process | IG1 |
| ENT-DIR-03 | Entra ID | Users cannot create Microsoft 365 groups | 5.1.3.4 – Ensure 'Users can create Microsoft 365 groups in Azure portals, API or PowerShell' is set to 'No' | E3 L2 | Automated | Group.Unified EnableGroupCreation = false (approved group only) | groupSettings | Auto | Free / P1 | 3.3 [verify] Configure data access control lists | IG1 |
| APP-CON-01 | Apps & Consent | User consent to apps not allowed | 5.1.5.1 – Ensure user consent to apps accessing company data on their behalf is not allowed | E3 L2 | Automated | No user self-consent policy assigned | authorizationPolicy | Auto | Free | 2.5 [verify] Allowlist authorised software | IG2 |
| APP-CON-02 | Apps & Consent | Admin consent workflow | 5.1.5.2 – Ensure the admin consent workflow is enabled | E3 L1 | Automated | Admin consent request workflow enabled with reviewers | adminConsentPolicy | Auto | Free | 2.5 [verify] Allowlist authorised software | IG2 |
| APP-CRED-01 | Apps & Consent | Password (secret) addition blocked for applications | 5.1.5.3 – Ensure password addition is blocked for applications | E3 L2 | Automated | Default app management policy enabled with passwordAddition restriction | defaultAppManagementPolicy | Auto | Free [verify] | 5.5 [verify] Establish and maintain an inventory of service accounts | IG2 |
| APP-CRED-02 | Apps & Consent | Application password lifetime ≤180 days | 5.1.5.4 – Ensure password lifetime for applications does not exceed 180 days | E3 L1 | Automated | Default app management policy passwordLifetime ≤ 180 days | defaultAppManagementPolicy | Auto | Free [verify] | 5.5 [verify] Establish and maintain an inventory of service accounts | IG2 |
| APP-PERM-01 | Apps & Consent | High-risk Graph application permissions | Supplementary – no direct CIS M365 recommendation | — | — | No third-party SP holds high-risk app permissions without justification | appRoleAssignments_graph, servicePrincipals, graphServicePrincipal | Auto | Free | 3.3 Configure data access control lists | IG1 |
| APP-AI-01 | AI Governance | Third-party AI/LLM apps | Supplementary – no direct CIS M365 recommendation | — | — | Inventory of SPs matching AI keywords reviewed | servicePrincipals | Auto (heuristic) | Free (MDA for discovery) | 2.1 Establish and maintain a software inventory | IG1 |
| EXT-GST-01 | External Collaboration | Guest invitations limited | 5.1.6.3 – Ensure guest user invitations are limited | E3 L2 | Automated | allowInvitesFrom = adminsAndGuestInviters or none | authorizationPolicy | Auto | Free | 6.1 Establish an access granting process | IG1 |
| EXT-GST-02 | External Collaboration | Guest user access restricted | 5.1.6.2 – Ensure that guest user access is restricted | E3 L1 | Automated | Guest role = limited access or most restrictive | authorizationPolicy | Auto | Free | 3.3 Configure data access control lists | IG1 |
| EXT-GST-03 | External Collaboration | Collaboration invitations to allowed domains only | 5.1.6.1 – Ensure that collaboration invitations are sent to allowed domains only | E3 L2 | Automated | Collaboration restrictions use an allow-list of domains | — | Manual | Free | 6.1 [verify] Establish an access granting process | IG1 |
| EXT-XTA-01 | External Collaboration | Cross-tenant inbound defaults | Supplementary – no direct CIS M365 recommendation | — | — | Default inbound B2B collaboration/trust reviewed | crossTenantDefault | Auto (Info) | Free | 6.1 [verify] Establish an access granting process | IG1 |
| GOV-AR-01 | Entra ID | Access reviews for guest users | 5.3.2 – Ensure 'Access reviews' for Guest Users are configured | E5 L1 [verify] | Automated | Recurring access review scoped to guests | accessReviews | Auto (heuristic) | Entra ID P2 / Governance | 5.3 [verify] Disable dormant accounts | IG1 |
| GOV-AR-02 | Entra ID | Access reviews for privileged roles | 5.3.3 – Ensure 'Access reviews' for privileged roles are configured | E5 L1 [verify] | Automated | Recurring access review of privileged directory roles | accessReviews | Auto (heuristic) | Entra ID P2 / Governance | 5.4 [verify] Restrict administrator privileges to dedicated administrator accounts | IG1 |
| GOV-EM-01 | Entra ID | Entitlement management | Supplementary – no direct CIS M365 recommendation | — | — | Access packages used for external/project access | accessPackages | Auto (Info) | Entra ID P2 / Governance | 6.1 Establish an access granting process | IG1 |
| DATA-SP-01 | Data Protection | SharePoint external content sharing restricted | 7.2.3 – Ensure external content sharing is restricted | E3 L1 [verify] | Automated | Tenant sharing = New and existing guests or more restrictive | ps_spoTenant / spoSettings | Auto | Free | 3.3 Configure data access control lists | IG1 |
| DATA-SP-02 | Data Protection | Default link type is 'Specific people' | 7.2.7 – Ensure link sharing is restricted in SharePoint and OneDrive | E3 L1 [verify] | Automated | DefaultSharingLinkType = Direct | ps_spoTenant | Auto (if present) | Free | 3.3 Configure data access control lists | IG1 |
| DATA-SP-06 | Data Protection | Default link permission is 'View' | 7.2.11 – Ensure the SharePoint default sharing link permission is set | E3 L1 [verify] | Automated | DefaultLinkPermission = View | ps_spoTenant | Auto (if present) | Free | 3.3 Configure data access control lists | IG1 |
| DATA-SP-07 | Data Protection | OneDrive content sharing restricted | 7.2.4 – Ensure OneDrive content sharing is restricted | E3 L2 | Automated | OneDrive sharing limited to the organisation [verify] | ps_spoTenant / spoSettings | Auto | Free | 3.3 Configure data access control lists | IG1 |
| DATA-SP-08 | Data Protection | Guests cannot reshare items they don't own | 7.2.5 – Ensure that SharePoint guest users cannot share items they don't own | E3 L2 | Automated | PreventExternalUsersFromResharing = True | ps_spoTenant / spoSettings | Auto | Free | 3.3 Configure data access control lists | IG1 |
| DATA-SP-09 | Data Protection | External sharing restricted by domain | 7.2.6 – Ensure SharePoint external sharing is restricted | E3 L2 | Automated | SharingDomainRestrictionMode = AllowList | ps_spoTenant / spoSettings | Auto | Free | 3.3 Configure data access control lists | IG1 |
| DATA-SP-10 | Data Protection | Guest access expires automatically | 7.2.9 – Ensure guest access to a site or OneDrive will expire automatically | E3 L1 [verify] | Automated | Guest expiry required, ≤30 days | ps_spoTenant | Auto (if present) | Free | 5.3 [verify] Disable dormant accounts | IG1 |
| DATA-SP-11 | Data Protection | Verification-code reauthentication restricted | 7.2.10 – Ensure reauthentication with verification code is restricted | E3 L1 [verify] | Automated | Reauthentication required, ≤15 days | ps_spoTenant | Auto (if present) | Free | 6.3 [verify] Require MFA for externally-exposed applications | IG1 |
| DATA-SP-12 | Data Protection | Modern authentication required for SharePoint | 7.2.1 – Ensure modern authentication for SharePoint applications is required | E3 L1 [verify] | Automated | LegacyAuthProtocolsEnabled = False | ps_spoTenant / spoSettings | Auto | Free | 4.8 [verify] Uninstall or disable unnecessary services | IG2 |
| DATA-SP-03 | Data Protection | Anyone link expiry | Supplementary – no direct CIS M365 recommendation [verify] | — | — | RequireAnonymousLinksExpireInDays set (≤30) | ps_spoTenant | Auto (if present) | Free | 3.3 Configure data access control lists | IG1 |
| DATA-SP-04 | AI Governance | Restricted SharePoint Search / Restricted Content Discovery | Supplementary – no direct CIS M365 recommendation | — | — | Temporary control while oversharing is remediated, or justified | ps_spoRestrictedSearch | Manual | M365 Copilot / SAM | 3.3 Configure data access control lists | IG1 |
| DATA-SP-05 | AI Governance | SharePoint Advanced Management (DAG, site access reviews) | Supplementary – no direct CIS M365 recommendation | — | — | Used to find overshared sites before rollout | — | Manual | SAM (with Copilot [verify]) | 3.2 Establish and maintain a data inventory | IG1 |
| DATA-MIP-01 | Data Protection | Sensitivity label policies published | 3.3.1 – Ensure Information Protection sensitivity label policies are published | E3 L1 | Automated | ≥1 enabled label policy published to users | ps_labelPolicies, sensitivityLabels | Auto | M365 E3 / Business Premium | 3.7 Establish and maintain a data classification scheme | IG2 |
| DATA-MIP-02 | Data Protection | Default / mandatory labelling | Supplementary – no direct CIS M365 recommendation | — | — | Label policy with default label or mandatory labelling | ps_labelPolicies | Auto (if present) | E3 / E5 | 3.7 Establish and maintain a data classification scheme | IG2 |
| DATA-DLP-01 | Data Protection | DLP policies enabled | 3.2.1 – Ensure DLP policies are enabled | E3 L1 | Automated | ≥1 enforced DLP policy | ps_dlpPolicies | Auto (if present) | E3 / E5 | 3.13 Deploy a data loss prevention solution | IG3 |
| DATA-DLP-02 | AI Governance | DLP policies for Microsoft 365 Copilot | 3.2.3 – Ensure DLP policies are published for Copilot users | E5 L1 | Automated [verify] | Enforced DLP policy for the Microsoft 365 Copilot / Copilot Chat location | ps_dlpPolicies | Auto (if present) | E5 Compliance [verify] | 3.13 Deploy a data loss prevention solution | IG3 |
| DATA-DLP-03 | Data Protection | DLP policies for Microsoft Teams | 3.2.2 – Ensure DLP policies are enabled for Microsoft Teams | E5 L1 | Automated | Enforced DLP policy including Teams messages | ps_dlpPolicies | Auto (if present) | E5 | 3.13 Deploy a data loss prevention solution | IG3 |
| DATA-DSPM-01 | AI Governance | Purview DSPM for AI configured | Supplementary – no direct CIS M365 recommendation | — | — | One-click policies activated; AI activity visible | — | Manual | Purview (E5 Compliance) | 3.14 [verify] Log sensitive data access | IG3 |
| DATA-AUD-01 | Data Protection | Microsoft 365 audit log search enabled | 3.1.1 – Ensure Microsoft 365 audit log search is Enabled | E3 L1 | Automated | UnifiedAuditLogIngestionEnabled = True | ps_auditConfig | Auto (if present) | Free | 8.2 Collect audit logs | IG1 |
| DATA-AUD-02 | Data Protection | Mailbox auditing not disabled organisation-wide | 6.1.1 – Ensure 'AuditDisabled' organisationally is set to 'False' | E3 L1 [verify] | Automated | Organisation AuditDisabled = False | ps_orgConfig | Auto (if present) | Free | 8.2 Collect audit logs | IG1 |
| DATA-RET-01 | AI Governance | Retention for Copilot / AI interactions | Supplementary – no direct CIS M365 recommendation | — | — | Retention policy including Copilot / AI apps location | ps_retentionPolicies | Auto (if present) | E3 / E5 | 3.4 Enforce data retention | IG1 |
| DATA-IRM-01 | AI Governance | Insider Risk (risky AI usage) | Supplementary – no direct CIS M365 recommendation | — | — | Policy present, e.g. risky AI usage template | ps_insiderRisk | Auto (if present) | E5 Insider Risk | 13.1 [verify] Centralise security event alerting | IG2 |
| DATA-CC-01 | AI Governance | Communication Compliance for Copilot | Supplementary – no direct CIS M365 recommendation | — | — | Policy covering Copilot interactions | ps_commCompliance | Auto (if present) | E5 Comm Compliance | 8.11 [verify] Conduct audit log reviews | IG2 |
| AI-MDA-01 | AI Governance | Defender for Cloud Apps enabled and configured (shadow AI) | 2.4.3 – Ensure Microsoft Defender for Cloud Apps is enabled and configured | E5 L2 | Manual [verify] | MDA enabled with M365 connector and Cloud Discovery; Generative AI category reviewed | — | Manual | MDA (E5 Security) | 2.3 Address unauthorised software | IG1 |
| AI-COP-01 | AI Governance | Copilot agents / plugins control | Supplementary – no direct CIS M365 recommendation | — | — | Agent deployment restricted to admin-approved | — | Manual | M365 Copilot | 2.5 Allowlist authorised software | IG2 |
| AI-COP-02 | AI Governance | Web grounding (web search) setting | Supplementary – no direct CIS M365 recommendation | — | — | Decision documented; aligned to data policy | — | Manual | M365 Copilot | 3.3 [verify] Configure data access control lists | IG1 |
| AI-M365-01 | AI Governance | User owned apps and services restricted | 1.3.4 – Ensure 'User owned apps and services' is restricted | E3 L1 | Automated | Office Store access and user trials off | appsAndServices | Auto [verify API] | Free | 2.5 [verify] Allowlist authorised software | IG2 |
| AI-DEF-01 | AI Governance | Safe Links for Office applications | 2.1.1 – Ensure Safe Links for Office Applications is Enabled | E5 L2 | Automated | Enabled Safe Links policy (applied by an enabled rule) covering email, Teams and Office apps; URL scanning, click tracking, no click-through. Built-in preset only = Partial (check against CIS 2.1.1) | ps_safeLinksPolicy, ps_safeLinksRule | Auto (if present) | Defender for Office 365 (E5) | 9.3 [verify] Maintain and enforce network-based URL filters | IG2 |
| AI-M365-02 | Data Protection | Third-party storage restricted in Microsoft 365 on the web | 1.3.7 – Ensure 'third-party storage services' are restricted in 'Microsoft 365 on the web' | E3 L2 | Automated | 'Office 365 third party storage' SP present and disabled [verify] | servicePrincipals | Auto | Free | 3.3 [verify] Configure data access control lists | IG1 |
| AI-EXO-01 | AI Governance | Users cannot install Outlook add-ins | 6.3.1 – Ensure users installing Outlook add-ins is not allowed | E3 L2 | Automated | No role assignment policy grants My Custom / Marketplace / ReadWriteMailbox Apps | ps_roleAssignmentPolicy | Auto (if present) | Free | 2.5 Allowlist authorised software | IG2 |
| AI-EXO-02 | Data Protection | Additional storage providers restricted in OWA | 6.5.3 – Ensure additional storage providers are restricted in Outlook on the web | E3 L2 | Automated | AdditionalStorageProvidersAvailable = False on OWA policies | ps_owaPolicy | Auto (if present) | Free | 3.3 [verify] Configure data access control lists | IG1 |
| AI-TMS-01 | AI Governance | Teams app permission policies (agents / bots) | 8.4.1 [verify] – Ensure app permission policies are configured | E3 L1 [verify] | Manual [verify] | Third-party and custom apps limited to approved apps | — | Manual | Free | 2.5 Allowlist authorised software | IG2 |
| AI-TMS-02 | AI Governance | Meeting recording off by default | 8.5.9 – Ensure meeting recording is off by default | E3 L2 | Automated | Global meeting policy AllowCloudRecording = False | ps_teamsMeetingPolicy (opt-in Teams sign-in) | Auto (if present) | Free | 3.3 [verify] Configure data access control lists | IG1 |
| AI-PP-01 | AI Governance | Copilot Studio / Power Platform DLP | Supplementary – no direct CIS M365 recommendation | — | — | Tenant-wide DLP blocks unapproved connectors | ps_powerPlatformDlp | Auto (if present) | Power Platform | 3.13 [verify] Deploy a data loss prevention solution | IG3 |
| AI-AOAI-01 | AI Governance | Azure OpenAI exposure | Supplementary – no direct CIS M365 recommendation | — | — | Public network access disabled/restricted; key auth disabled | ps_azureOpenAI | Auto (if present) | Azure | 12.2 [verify] Establish and maintain a secure network architecture | IG2 |
| SEC-SS-01 | Entra ID | Microsoft Secure Score | Supplementary – no direct CIS M365 recommendation | — | — | Context only — excluded from CIS scores | secureScore | Auto (Info) | Free | — | — |
| LIC-01..n | Licensing | Licence inventory, upgrade needs, tenant-wide compliance | Not applicable (licensing) | — | — | See licensing-map.md | subscribedSkus, users_licences | Auto | — | — | — |


## Well-known IDs
- Global Administrator role template: `62e90394-69f5-4237-9190-012177145e10`
- Microsoft Graph app ID: `00000003-0000-0000-c000-000000000000`
- Restricted guest role: `2af84b1e-32c8-42b7-82bc-daa82404023b`; limited guest role: `10dae51f-b6af-4016-8d66-8c2a99b929b3`
- Built-in phishing-resistant MFA authentication strength: `00000000-0000-0000-0000-000000000004`
- 'Office 365 third party storage' app ID (AI-M365-02): `c1f33bc0-bdb4-4248-ba9b-096807ddb43e` [verify]
- Microsoft 365 Copilot / Enterprise Copilot Platform app IDs change — resolve by display name from
  `servicePrincipals.json` ("Microsoft 365 Copilot", "Enterprise Copilot Platform") [verify].

## High-risk Graph application permissions (APP-PERM-01)
Treat as High when granted as *application* permissions to a non-Microsoft service principal:
`Mail.Read, Mail.ReadWrite, Mail.Send, Files.Read.All, Files.ReadWrite.All, Sites.Read.All, Sites.ReadWrite.All,
Sites.FullControl.All, User.ReadWrite.All, Directory.ReadWrite.All, Application.ReadWrite.All,
AppRoleAssignment.ReadWrite.All, RoleManagement.ReadWrite.Directory, Chat.Read.All, ChannelMessage.Read.All,
Group.ReadWrite.All`.

## AI app keyword heuristic (APP-AI-01)
Display names containing: `openai, chatgpt, gpt, claude, anthropic, gemini, bard, copilot (non-Microsoft
publisher), perplexity, jasper, otter, fireflies, grammarly, notion ai, mistral, llama, hugging, cohere,
writer, read.ai, tl;dv, poe`. Heuristic only — confirm each match manually.
