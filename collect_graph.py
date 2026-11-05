#!/usr/bin/env python3
"""Read-only Microsoft Graph evidence collector for the tenant-ai-security-assessment skill.

The user signs in interactively (device-code flow) to the tenant they name. Only HTTP GET is ever
issued; tokens are held in memory only and never written to disk or printed.

Usage:
    pip install msal requests
    python collect_graph.py --tenant contoso.onmicrosoft.com --out ./assessment
"""
import argparse
import json
import os
import sys
import time

GRAPH = "https://graph.microsoft.com"
# Microsoft Graph Command Line Tools (public client used by Microsoft Graph PowerShell).
DEFAULT_CLIENT_ID = "14d82eec-204b-4c2f-b7e8-296a70dab67e"

READ_ONLY_SCOPES = [
    "Directory.Read.All", "Policy.Read.All", "Organization.Read.All", "Reports.Read.All",
    "AuditLog.Read.All", "SecurityEvents.Read.All", "RoleManagement.Read.Directory",
    "Application.Read.All", "IdentityRiskyUser.Read.All", "AccessReview.Read.All",
    "EntitlementManagement.Read.All", "InformationProtectionPolicy.Read",
    "SharePointTenantSettings.Read.All", "UserAuthenticationMethod.Read.All",
    "RoleManagementPolicy.Read.Directory",          # CIS 5.3.4 — PIM approval settings
    "OrgSettings-AppsAndServices.Read.All",         # CIS 1.3.4 — user owned apps and services [verify]
]

GA_ROLE = "62e90394-69f5-4237-9190-012177145e10"
GRAPH_APP = "00000003-0000-0000-c000-000000000000"

# raw file name -> (relative URL, paged?)
ENDPOINTS = {
    "organization": ("/v1.0/organization", False),
    "subscribedSkus": ("/v1.0/subscribedSkus", False),
    "users_licences": ("/v1.0/users?$select=id,userType,accountEnabled,assignedLicenses&$top=999", True),
    "securityDefaults": ("/v1.0/policies/identitySecurityDefaultsEnforcementPolicy", False),
    "caPolicies": ("/v1.0/identity/conditionalAccess/policies", True),
    "namedLocations": ("/v1.0/identity/conditionalAccess/namedLocations", True),
    "authMethodsPolicy": ("/v1.0/policies/authenticationMethodsPolicy", False),
    "authStrengths": ("/v1.0/policies/authenticationStrengthPolicies", True),
    "mfaRegistration": ("/v1.0/reports/authenticationMethods/userRegistrationDetails?$top=999", True),
    "authorizationPolicy": ("/v1.0/policies/authorizationPolicy", False),
    "adminConsentPolicy": ("/v1.0/policies/adminConsentRequestPolicy", False),
    "roleAssignments_GA": ("/v1.0/roleManagement/directory/roleAssignments?$filter=roleDefinitionId eq '"
                           + GA_ROLE + "'&$expand=principal", True),
    "roleEligibility": ("/v1.0/roleManagement/directory/roleEligibilitySchedules", True),
    "privilegedRoleAssignments": ("/v1.0/roleManagement/directory/roleAssignments?$expand=roleDefinition", True),
    "servicePrincipals": ("/v1.0/servicePrincipals?$select=id,appId,displayName,appOwnerOrganizationId,"
                          "servicePrincipalType,accountEnabled,tags&$top=999", True),
    "graphServicePrincipal": ("/v1.0/servicePrincipals(appId='" + GRAPH_APP + "')?$select=id,appRoles", False),
    "appRoleAssignments_graph": ("/v1.0/servicePrincipals(appId='" + GRAPH_APP + "')/appRoleAssignedTo?$top=999", True),
    "oauth2Grants": ("/v1.0/oauth2PermissionGrants?$top=999", True),
    "riskyUsers": ("/v1.0/identityProtection/riskyUsers?$filter=riskState eq 'atRisk'", True),
    "crossTenantDefault": ("/v1.0/policies/crossTenantAccessPolicy/default", False),
    "accessReviews": ("/v1.0/identityGovernance/accessReviews/definitions", True),
    "accessPackages": ("/v1.0/identityGovernance/entitlementManagement/accessPackages", True),
    "spoSettings": ("/v1.0/admin/sharepoint/settings", False),
    "sensitivityLabels": ("/beta/security/informationProtection/sensitivityLabels", True),
    "secureScore": ("/v1.0/security/secureScores?$top=1", False),
    "defaultAppManagementPolicy": ("/v1.0/policies/defaultAppManagementPolicy", False),
    "groupSettings": ("/v1.0/groupSettings", True),
    "roleManagementPolicy_GA": ("/v1.0/policies/roleManagementPolicyAssignments?$filter=scopeId eq '/' and "
                                "scopeType eq 'DirectoryRole' and roleDefinitionId eq '" + GA_ROLE +
                                "'&$expand=policy($expand=rules)", False),
    "appsAndServices": ("/beta/admin/appsAndServices", False),  # [verify] beta endpoint
}

SENSITIVE_KEYS = {"access_token", "refresh_token", "id_token", "client_secret", "password"}


def get_token(tenant, client_id):
    try:
        import msal  # imported lazily so static validation does not need it installed
    except ImportError:
        sys.exit("msal is required: pip install msal requests")
    app = msal.PublicClientApplication(client_id, authority=f"https://login.microsoftonline.com/{tenant}")
    flow = app.initiate_device_flow(scopes=[f"{GRAPH}/{s}" for s in READ_ONLY_SCOPES])
    if "user_code" not in flow:
        sys.exit("Could not start device-code sign-in: " + str(flow.get("error_description", flow)))
    print(flow["message"], flush=True)  # tells the user where to sign in and the code to enter
    result = app.acquire_token_by_device_flow(flow)
    if "access_token" not in result:
        sys.exit("Sign-in failed: " + str(result.get("error_description", "unknown error")))
    granted = result.get("scope", "")
    return result["access_token"], granted


def graph_get(session, token, url):
    """GET only. Any other verb is deliberately impossible in this module."""
    import requests  # lazy import
    full = url if url.startswith("http") else GRAPH + url
    for attempt in range(4):
        resp = session.request("GET", full, headers={"Authorization": f"Bearer {token}",
                                                     "ConsistencyLevel": "eventual"}, timeout=60)
        if resp.status_code == 429:
            time.sleep(int(resp.headers.get("Retry-After", "5")))
            continue
        return resp
    return resp


def scrub(obj):
    if isinstance(obj, dict):
        return {k: ("[removed]" if k.lower() in SENSITIVE_KEYS else scrub(v)) for k, v in obj.items()}
    if isinstance(obj, list):
        return [scrub(v) for v in obj]
    return obj


def collect(tenant, out_dir, client_id):
    import requests  # lazy import
    raw = os.path.join(out_dir, "raw")
    os.makedirs(raw, exist_ok=True)
    token, granted = get_token(tenant, client_id)
    log = {"tenant": tenant, "granted_scopes": granted.split(), "calls": {}}
    session = requests.Session()
    for name, (url, paged) in ENDPOINTS.items():
        items, next_url, status, error = [], url, None, None
        single = None
        while next_url:
            resp = graph_get(session, token, next_url)
            status = resp.status_code
            if status != 200:
                try:
                    error = resp.json().get("error", {}).get("message", resp.text[:300])
                except ValueError:
                    error = resp.text[:300]
                break
            body = resp.json()
            if "value" in body:
                items.extend(body["value"])
                next_url = body.get("@odata.nextLink") if paged else None
            else:
                single, next_url = body, None
        log["calls"][name] = {"url": url, "status": status, "error": error}
        if status == 200:
            data = single if single is not None else {"value": items}
            with open(os.path.join(raw, f"{name}.json"), "w", encoding="utf-8") as fh:
                json.dump(scrub(data), fh, indent=2)
        print(f"{name}: {status}{' - ' + error if error else ''}", flush=True)
    with open(os.path.join(raw, "collection-log.json"), "w", encoding="utf-8") as fh:
        json.dump(log, fh, indent=2)
    del token


def main():
    ap = argparse.ArgumentParser(description="Read-only Graph collector (device-code sign-in)")
    ap.add_argument("--tenant", required=True, help="Tenant ID (GUID) or primary domain")
    ap.add_argument("--out", required=True, help="Output folder (raw/ is created inside)")
    ap.add_argument("--client-id", default=DEFAULT_CLIENT_ID, help="Public client app ID")
    args = ap.parse_args()
    collect(args.tenant, args.out, args.client_id)


if __name__ == "__main__":
    main()
