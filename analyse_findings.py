#!/usr/bin/env python3
"""Analyse raw evidence into findings.json, licensing.json and cis_scores.json (offline, no network calls).

Usage:
    python analyse_findings.py --raw ./assessment/raw --out ./assessment --cis-licence-profile E3|E5 --cis-levels L1|L1L2

Both CIS options are REQUIRED and must come from the user's answers at launch (never assumed).

Primary benchmark: CIS Microsoft 365 Foundations Benchmark (version in cis-mapping.json) plus
CIS Critical Security Controls v8.1 safeguards / Implementation Groups. Every check's CIS metadata comes
from cis-mapping.json (single source of truth). CIS content is (c) Center for Internet Security;
this script cites recommendation IDs and short titles only and paraphrases pass criteria.

Reads JSON files written by collect_graph.py / Invoke-TenantAiAssessment.ps1 (see
checks-catalogue.md). Missing evidence -> status "Not assessed" with a reason; a Pass is
never inferred from missing data.
"""
import argparse
import json
import os
import re

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_MAP = os.path.join(HERE, "cis-mapping.json")

GA_ROLE = "62e90394-69f5-4237-9190-012177145e10"
RESTRICTED_GUEST_ROLE = "2af84b1e-32c8-42b7-82bc-daa82404023b"
LIMITED_GUEST_ROLE = "10dae51f-b6af-4016-8d66-8c2a99b929b3"
PHISHING_RESISTANT_STRENGTH = "00000000-0000-0000-0000-000000000004"
THIRD_PARTY_STORAGE_APP = "c1f33bc0-bdb4-4248-ba9b-096807ddb43e"  # "Office 365 third party storage" [verify]
MICROSOFT_TENANTS = {"f8cdef31-a31e-4b4a-93e4-5f571e91255a", "72f988bf-86f1-41af-91ab-2d7cd011db47"}
HIGH_RISK_PERMS = {
    "Mail.Read", "Mail.ReadWrite", "Mail.Send", "Files.Read.All", "Files.ReadWrite.All", "Sites.Read.All",
    "Sites.ReadWrite.All", "Sites.FullControl.All", "User.ReadWrite.All", "Directory.ReadWrite.All",
    "Application.ReadWrite.All", "AppRoleAssignment.ReadWrite.All", "RoleManagement.ReadWrite.Directory",
    "Chat.Read.All", "ChannelMessage.Read.All", "Group.ReadWrite.All",
}
AI_KEYWORDS = ["openai", "chatgpt", "gpt", "claude", "anthropic", "gemini", "bard", "perplexity", "jasper",
               "otter", "fireflies", "grammarly", "notion", "mistral", "llama", "hugging", "cohere",
               "read.ai", "tl;dv", "poe"]
PRIV_ROLE_NAMES = {"Global Administrator", "Privileged Role Administrator", "Security Administrator",
                   "Exchange Administrator", "SharePoint Administrator", "User Administrator",
                   "Application Administrator", "Cloud Application Administrator",
                   "Conditional Access Administrator", "Privileged Authentication Administrator",
                   "Compliance Administrator", "AI Administrator"}
RISKY_OUTLOOK_ADDIN_ROLES = {"my custom apps", "my marketplace apps", "my readwritemailbox apps"}
PLAN_MAP = {
    "Entra ID P1": ["AAD_PREMIUM"],
    "Entra ID P2": ["AAD_PREMIUM_P2"],
    "Entra ID Governance": ["IDENTITY_GOVERNANCE", "ENTRA_IDENTITY_GOVERNANCE"],
    "Workload Identities Premium": ["AAD_WRKLDID"],
    "Intune": ["INTUNE_A"],
    "Microsoft 365 Copilot": ["M365_COPILOT", "MICROSOFT_365_COPILOT"],
    "Auto-labelling / Purview IP P2": ["MIP_S_CLP2", "RMS_S_PREMIUM2"],
    "Audit (Premium)": ["M365_ADVANCED_AUDITING"],
    "Insider Risk Management": ["INSIDER_RISK"],
    "Communication Compliance": ["COMMUNICATIONS_COMPLIANCE", "COMMUNICATION_COMPLIANCE"],
    "Defender for Cloud Apps": ["ADALLOM_S_STANDALONE"],
    "SharePoint Advanced Management": ["SHAREPOINT_ADVANCED_MANAGEMENT"],
}
SUPPLEMENTARY = "Supplementary – no direct CIS M365 recommendation"
RISK_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
EFFORT_ORDER = {"Low": 0, "Medium": 1, "High": 2}


def load_map(path):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def vtag(meta, field):
    return " [verify]" if field in (meta.get("verify") or []) else ""


def cis_fields(cmap, fid):
    """Return the four CIS finding fields for a check ID (licensing / analyser rows get n/a values)."""
    meta = (cmap.get("checks") or {}).get(fid)
    if fid.startswith("LIC-") or fid.startswith("ERR-"):
        return {"cis_m365_id": "Not applicable (licensing / analyser)", "cis_profile": "—",
                "cis_controls_safeguard": "—", "implementation_group": "—"}
    if meta is None:
        return {"cis_m365_id": "Unmapped [verify]", "cis_profile": "—",
                "cis_controls_safeguard": "Unmapped [verify]", "implementation_group": "—"}
    ver = meta.get("cis_benchmark_label") or cmap.get("benchmark", "CIS M365")
    short = "CIS M365 v" + re.sub(r".*v", "", ver) if " v" in ver else "CIS M365"
    if meta.get("cis_m365_id"):
        rid = f"{short} {meta['cis_m365_id']}{vtag(meta, 'cis_m365_id')} – {meta['cis_title']}"
        prof = f"{meta['profile']}{vtag(meta, 'profile')} · {meta['cis_assessment']}{vtag(meta, 'cis_assessment')}"
    else:
        rid = SUPPLEMENTARY + vtag(meta, "cis_m365_id")
        prof = "—"
    sg = meta.get("safeguard")
    if sg:
        sgm = cmap["safeguards"][sg]
        sgs = f"{sg}{vtag(meta, 'safeguard')} {sgm['title']}"
        ig = sgm["ig"]
    else:
        sgs, ig = "— (context only)", "—"
    return {"cis_m365_id": rid, "cis_profile": prof, "cis_controls_safeguard": sgs, "implementation_group": ig}


class Ctx:
    def __init__(self, raw, cmap):
        self.raw = raw
        self.cmap = cmap
        self.findings = []

    def load(self, name):
        path = os.path.join(self.raw, f"{name}.json")
        if not os.path.exists(path):
            return None
        with open(path, encoding="utf-8-sig") as fh:
            return json.load(fh)

    def values(self, name):
        data = self.load(name)
        if data is None:
            return None
        if isinstance(data, dict) and "value" in data:
            return data["value"]
        return data if isinstance(data, list) else [data]

    def first(self, name):
        v = self.values(name)
        return v[0] if v else None

    def reason(self, name):
        log = self.load("collection-log") or {}
        call = (log.get("calls") or {}).get(name)
        if call and call.get("status") not in (200, None):
            return f"Graph returned {call['status']}: {call.get('error') or 'no detail'} (permission or licence)"
        return f"No evidence collected ({name}.json missing) — module not run, permission declined or no read API"

    def add(self, fid, area, control, status, evidence, risk, rec, lic, effort):
        rec_out = {
            "id": fid, "area": area, "control": control, "status": status, "evidence": evidence,
            "risk": risk if status != "Pass" else "Info",
            "recommendation": rec if status != "Pass" else "No action required; keep under review.",
            "licence_required": lic, "effort": effort}
        rec_out.update(cis_fields(self.cmap, fid))
        self.findings.append(rec_out)

    def na(self, fid, area, control, src, lic, risk="Medium", manual_path=None):
        reason = manual_path and f"Manual verification required: {manual_path}" or self.reason(src)
        self.add(fid, area, control, "Not assessed", reason, risk,
                 "Verify manually against the CIS audit procedure and record the result; re-run with the "
                 "required module/permission.", lic, "Low")


def enabled_ca(policies):
    return [p for p in policies or [] if p.get("state") == "enabled"]


def grant(p):
    g = p.get("grantControls") or {}
    return set(g.get("builtInControls") or []), g.get("authenticationStrength")


def cond(p):
    return p.get("conditions") or {}


def users_c(p):
    return cond(p).get("users") or {}


def all_users(p):
    return "All" in (users_c(p).get("includeUsers") or [])


def all_apps(p):
    return "All" in ((cond(p).get("applications") or {}).get("includeApplications") or [])


def strength_id(p):
    s = grant(p)[1]
    return (s or {}).get("id") if isinstance(s, dict) else None


def mfa_like(p):
    return "mfa" in grant(p)[0] or bool(grant(p)[1])


def names(ps):
    return ", ".join(p.get("displayName", "?") for p in ps) or "none"


def sif_hours(p):
    sif = ((p.get("sessionControls") or {}).get("signInFrequency") or {})
    if not sif.get("isEnabled"):
        return None
    if sif.get("frequencyInterval") == "everyTime":
        return 0
    val = sif.get("value") or 0
    return val * 24 if sif.get("type") == "days" else val


def transfer_block(en, method):
    return [p for p in en if "block" in grant(p)[0] and all_users(p) and method in
            str(((cond(p).get("authenticationFlows") or {}).get("transferMethods") or "")).split(",")]


def check_identity(c):
    ca = c.values("caPolicies")
    sd = c.load("securityDefaults")
    if ca is None:
        for fid, ctl, lic in [("ENT-CA-01", "MFA required for all users", "Entra ID P1"),
                              ("ENT-CA-02", "MFA for administrative roles", "Entra ID P1"),
                              ("ENT-CA-03", "Block legacy authentication", "Entra ID P1"),
                              ("ENT-CA-04", "Managed device required for authentication", "Entra ID P1 + Intune"),
                              ("ENT-CA-05", "Sign-in risk policy", "Entra ID P2"),
                              ("ENT-CA-06", "User risk policy", "Entra ID P2"),
                              ("ENT-CA-07", "Conditional Access targeting Copilot / AI apps", "Entra ID P1"),
                              ("ENT-CA-09", "Phishing-resistant MFA strength for administrators", "Entra ID P1"),
                              ("ENT-CA-10", "Block medium/high sign-in risk", "Entra ID P2"),
                              ("ENT-CA-11", "Admin sign-in frequency and non-persistent browser", "Entra ID P1"),
                              ("ENT-CA-12", "Periodic reauthentication for all users", "Entra ID P1"),
                              ("ENT-CA-13", "Device code flow blocked", "Entra ID P1"),
                              ("ENT-CA-14", "Authentication transfer blocked", "Entra ID P1")]:
            c.na(fid, "Entra ID", ctl, "caPolicies", lic, risk="High")
    en = enabled_ca(ca)
    if sd is not None or ca is not None:
        sd_on = bool((sd or {}).get("isEnabled"))
        if en and not sd_on:
            c.add("ENT-SD-01", "Entra ID", "Security defaults vs Conditional Access", "Pass",
                  f"{len(en)} enabled CA policies; security defaults off.", "Info", "", "Entra ID P1", "Low")
        elif sd_on:
            c.add("ENT-SD-01", "Entra ID", "Security defaults vs Conditional Access", "Partial",
                  "Security defaults enabled (baseline only; most CIS 5.2.2.x recommendations need Conditional "
                  "Access).", "Medium",
                  "Move to Conditional Access (if P1 is licensed) to meet the CIS 5.2.2.x recommendations and "
                  "target Copilot/AI apps and devices.", "Entra ID P1", "Medium")
        else:
            c.add("ENT-SD-01", "Entra ID", "Security defaults vs Conditional Access", "Fail",
                  "Security defaults off and no enabled CA policies.", "Critical",
                  "Enable security defaults immediately or deploy a Conditional Access baseline aligned to CIS "
                  "5.2.2.x.", "Free / Entra ID P1", "Low")
    if ca is None:
        return
    # CIS 5.2.2.2 — all users, all resources, MFA or authentication strength.
    mfa_all = [p for p in en if all_users(p) and all_apps(p) and mfa_like(p)]
    c.add("ENT-CA-01", "Entra ID", "MFA required for all users", "Pass" if mfa_all else "Fail",
          f"Enabled policies covering All users + All resources with MFA: {names(mfa_all)}.", "High",
          "Create a CA policy: All users (exclude break-glass only), All resources, grant require MFA or an "
          "authentication strength. Pilot in report-only first.", "Entra ID P1", "Low")
    # CIS 5.2.2.1 — admin roles targeted with MFA.
    adm = [p for p in en if users_c(p).get("includeRoles") and mfa_like(p)]
    adm_ga = [p for p in adm if GA_ROLE in (users_c(p).get("includeRoles") or [])]
    c.add("ENT-CA-02", "Entra ID", "MFA for administrative roles",
          "Pass" if adm_ga else "Partial" if (adm or mfa_all) else "Fail",
          f"Admin-role MFA policies: {names(adm)} (includes Global Administrator = {bool(adm_ga)}); "
          f"all-users MFA policy present = {bool(mfa_all)}.", "Critical",
          "Create a CA policy targeting all privileged directory roles (at least the roles listed in the CIS "
          "audit procedure) requiring MFA.", "Entra ID P1", "Low")
    # CIS 5.2.2.5 — phishing-resistant strength for admins.
    pr = [p for p in en if users_c(p).get("includeRoles") and strength_id(p) == PHISHING_RESISTANT_STRENGTH]
    c.add("ENT-CA-09", "Entra ID", "Phishing-resistant MFA strength for administrators", "Pass" if pr else "Fail",
          f"Admin policies requiring the built-in phishing-resistant strength: {names(pr)}.", "High",
          "Require the 'Phishing-resistant MFA' authentication strength for privileged roles (passkeys/FIDO2, "
          "Windows Hello, certificate-based). Register methods before enforcing.", "Entra ID P1", "Medium")
    # CIS 5.2.2.3 — block legacy auth.
    legacy = [p for p in en if "block" in grant(p)[0] and {"exchangeActiveSync", "other"} <=
              set(cond(p).get("clientAppTypes") or [])]
    c.add("ENT-CA-03", "Entra ID", "Block legacy authentication", "Pass" if legacy else "Fail",
          f"Legacy-auth block policies: {names(legacy)}.", "High",
          "Create a CA policy blocking 'Exchange ActiveSync clients' and 'Other clients' for all users.",
          "Entra ID P1", "Low")
    # CIS 5.2.2.9 — managed device required (all users, all resources).
    dev = [p for p in en if grant(p)[0] & {"compliantDevice", "domainJoinedDevice"}]
    dev_all = [p for p in dev if all_users(p) and all_apps(p)]
    c.add("ENT-CA-04", "Entra ID", "Managed device required for authentication (incl. Copilot)",
          "Pass" if dev_all else "Partial" if dev else "Fail",
          f"Device-based policies: {names(dev)}; covering All users + All resources: {names(dev_all)}.", "Medium",
          "Require a compliant or hybrid-joined device for all users and resources (use app protection for "
          "mobile), so Copilot and AI apps are only reachable from managed devices.",
          "Entra ID P1 + Intune", "Medium")
    # CIS 5.2.2.7 / 5.2.2.6 / 5.2.2.8 — risk policies.
    sr = [p for p in en if cond(p).get("signInRiskLevels")]
    sr_full = [p for p in sr if {"high", "medium"} <= set(cond(p)["signInRiskLevels"]) and
               (mfa_like(p) or "block" in grant(p)[0])]
    c.add("ENT-CA-05", "Entra ID", "Sign-in risk policy", "Pass" if sr_full else "Partial" if sr else "Fail",
          f"Sign-in risk policies: {names(sr)}; covering medium+high with MFA/block: {names(sr_full)}.", "High",
          "Require MFA (sign-in frequency every time) for medium and high sign-in risk. Every user in scope "
          "needs Entra ID P2.", "Entra ID P2", "Low")
    ur = [p for p in en if cond(p).get("userRiskLevels")]
    ur_full = [p for p in ur if "high" in cond(p)["userRiskLevels"] and
               grant(p)[0] & {"passwordChange", "riskRemediation"}]
    c.add("ENT-CA-06", "Entra ID", "User risk policy", "Pass" if ur_full else "Partial" if ur else "Fail",
          f"User risk policies: {names(ur)}; high risk with secure password change/remediation: "
          f"{names(ur_full)}.", "High",
          "Require MFA plus secure password change (or risk remediation) for high user risk.",
          "Entra ID P2", "Low")
    blk = [p for p in en if {"high", "medium"} <= set(cond(p).get("signInRiskLevels") or [])
           and "block" in grant(p)[0]]
    c.add("ENT-CA-10", "Entra ID", "Block medium/high sign-in risk", "Pass" if blk else "Fail",
          f"Policies blocking medium+high sign-in risk: {names(blk)}.", "Medium",
          "Add a CA policy that blocks access when sign-in risk is medium or high (CIS Level 2).",
          "Entra ID P2", "Low")
    # CIS 5.2.2.4 — admin sign-in frequency + never persistent browser.
    sif_adm = [p for p in en if users_c(p).get("includeRoles") and sif_hours(p) is not None and
               sif_hours(p) <= 4 and ((p.get("sessionControls") or {}).get("persistentBrowser") or {})
               .get("mode") == "never"]
    c.add("ENT-CA-11", "Entra ID", "Admin sign-in frequency and non-persistent browser",
          "Pass" if sif_adm else "Fail",
          f"Admin policies with sign-in frequency ≤4 h [verify threshold] and persistent browser 'never': "
          f"{names(sif_adm)}.", "Medium",
          "Set a short sign-in frequency and 'Never persistent' browser sessions for privileged roles.",
          "Entra ID P1", "Low")
    # CIS 5.2.2.13 — periodic reauthentication for all users.
    sif_all = [p for p in en if all_users(p) and sif_hours(p) is not None]
    c.add("ENT-CA-12", "Entra ID", "Periodic reauthentication for all users", "Pass" if sif_all else "Fail",
          f"All-user policies with sign-in frequency enabled: {names(sif_all)}.", "Low",
          "Configure a sign-in frequency session control for all users (value per CIS guidance [verify]).",
          "Entra ID P1", "Low")
    # CIS 5.2.2.12 / 5.2.2.17 — authentication flows.
    has_flows = any(cond(p).get("authenticationFlows") for p in ca)
    note = "" if has_flows else " No policy exposes 'authenticationFlows' in the API output — confirm in the portal."
    dc = transfer_block(en, "deviceCodeFlow")
    c.add("ENT-CA-13", "Entra ID", "Device code flow blocked", "Pass" if dc else "Fail",
          f"Policies blocking device code flow: {names(dc)}.{note}", "High",
          "Block the device code flow for all users (exclude only documented exceptions). Note: this skill's "
          "collector then needs -UseBrowser sign-in.", "Entra ID P1", "Low")
    at = transfer_block(en, "authenticationTransfer")
    c.add("ENT-CA-14", "Entra ID", "Authentication transfer blocked", "Pass" if at else "Fail",
          f"Policies blocking authentication transfer: {names(at)}.{note}", "Medium",
          "Block authentication transfer for all users and resources; pilot in report-only first.",
          "Entra ID P1", "Low")
    # Supplementary — Copilot-targeted CA.
    sps = {s.get("appId"): s.get("displayName", "") for s in c.values("servicePrincipals") or []}
    copilot_ids = {a for a, n in sps.items() if "copilot" in n.lower()}
    ai = [p for p in en if copilot_ids & set((cond(p).get("applications") or {}).get("includeApplications") or [])]
    status = "Pass" if ai else ("Partial" if mfa_all and dev else "Fail")
    c.add("ENT-CA-07", "AI Governance", "Conditional Access targeting Copilot / AI apps", status,
          f"Copilot-targeted policies: {names(ai)}; broad MFA+device policies cover Copilot indirectly"
          f" = {bool(mfa_all and dev)}.", "Medium",
          "Add CA for Microsoft 365 Copilot / Enterprise Copilot Platform requiring compliant device and "
          "phishing-resistant MFA; consider session controls for unmanaged devices.", "Entra ID P1", "Low")
    ro = [p for p in ca if p.get("state") == "enabledForReportingButNotEnforced"]
    c.add("ENT-CA-08", "Entra ID", "Report-only Conditional Access policies",
          "Partial" if ro else "Pass", f"{len(ro)} report-only: {names(ro)}.", "Low",
          "Review report-only policies; enforce or remove those that have been piloted.", "Entra ID P1", "Low")


def check_auth_methods(c):
    am = c.load("authMethodsPolicy")
    if am is None:
        for fid, ctl in [("ENT-AM-01", "Phishing-resistant methods enabled"),
                         ("ENT-AM-02", "Weak authentication methods disabled"),
                         ("ENT-AM-04", "Authenticator protected against MFA fatigue"),
                         ("ENT-AM-05", "System-preferred MFA enabled"),
                         ("ENT-AM-06", "Email OTP method disabled")]:
            c.na(fid, "Entra ID", ctl, "authMethodsPolicy", "Free")
    else:
        confs = {x.get("id", "").lower(): x for x in am.get("authenticationMethodConfigurations", [])}
        state = {k: v.get("state") for k, v in confs.items()}
        pr = [k for k in ("fido2", "windowshelloforbusiness", "x509certificate") if state.get(k) == "enabled"]
        c.add("ENT-AM-01", "Entra ID", "Phishing-resistant methods enabled", "Pass" if pr else "Fail",
              f"Enabled phishing-resistant methods: {', '.join(pr) or 'none'}.", "High",
              "Enable passkeys (FIDO2) and Windows Hello for Business; prerequisite for CIS 5.2.2.5.",
              "Free", "Low")
        weak = [k for k in ("sms", "voice") if state.get(k) == "enabled"]
        c.add("ENT-AM-02", "Entra ID", "Weak authentication methods disabled", "Fail" if weak else "Pass",
              f"Weak methods enabled: {', '.join(weak) or 'none'}.", "Medium",
              "Disable SMS and voice call methods (or restrict to a time-boxed migration group); move users to "
              "Authenticator/passkeys.", "Free", "Medium")
        fs = (confs.get("microsoftauthenticator") or {}).get("featureSettings") or {}
        app_ctx = (fs.get("displayAppInformationRequiredState") or {}).get("state")
        loc_ctx = (fs.get("displayLocationInformationRequiredState") or {}).get("state")
        if state.get("microsoftauthenticator") != "enabled":
            st, ev = "Pass", "Microsoft Authenticator method not enabled (no push fatigue exposure)."
        else:
            st = "Pass" if app_ctx == "enabled" and loc_ctx == "enabled" else "Fail"
            ev = f"Show application name = {app_ctx}; show geographic location = {loc_ctx}."
        c.add("ENT-AM-04", "Entra ID", "Authenticator protected against MFA fatigue", st, ev, "Medium",
              "Enable 'show application name' and 'show geographic location' in Authenticator push "
              "notifications for all users.", "Free", "Low")
        scp = am.get("systemCredentialPreferences")
        if scp is None:
            c.na("ENT-AM-05", "Entra ID", "System-preferred MFA enabled", "authMethodsPolicy", "Free", risk="Low",
                 manual_path="Entra admin centre › Protection › Authentication methods › Settings › "
                             "System-preferred multifactor authentication (not in v1.0 API output)")
        else:
            on = scp.get("state") == "enabled"
            c.add("ENT-AM-05", "Entra ID", "System-preferred MFA enabled", "Pass" if on else "Fail",
                  f"systemCredentialPreferences.state = {scp.get('state')}.", "Low",
                  "Enable system-preferred MFA so users are prompted for their strongest registered method.",
                  "Free", "Low")
        em = state.get("email")
        c.add("ENT-AM-06", "Entra ID", "Email OTP method disabled", "Fail" if em == "enabled" else "Pass",
              f"Email OTP state = {em}.", "Low",
              "Disable the email one-time passcode method (check guest sign-in dependencies first).",
              "Free", "Low")
    reg = c.values("mfaRegistration")
    if reg is None:
        c.na("ENT-AM-03", "Entra ID", "All member users MFA capable", "mfaRegistration", "Entra ID P1")
    else:
        members = [r for r in reg if r.get("userType", "member") == "member"]
        capable = [r for r in members if r.get("isMfaCapable")]
        pct = 100 * len(capable) / len(members) if members else 0
        st = "Pass" if members and len(capable) == len(members) else "Partial" if pct >= 95 else "Fail"
        c.add("ENT-AM-03", "Entra ID", "All member users MFA capable", st,
              f"{len(capable)}/{len(members)} members MFA-capable ({pct:.0f}%). CIS expects every member user "
              "to be MFA capable (documented exceptions only).", "High",
              "Run a registration campaign (Authenticator / passkeys) and follow up unregistered users.",
              "Entra ID P1", "Medium")


def check_privileged(c):
    ga = c.values("roleAssignments_GA")
    if ga is None:
        c.na("ENT-PIM-01", "Entra ID", "Between two and four Global Administrators", "roleAssignments_GA", "Free",
             risk="High")
        c.na("ENT-PIM-03", "Entra ID", "Administrative accounts are cloud-only", "roleAssignments_GA", "Free",
             risk="High")
    else:
        n = len(ga)
        st = "Pass" if 2 <= n <= 4 else "Fail"
        prin = [a.get("principal") or {} for a in ga]
        upns = [p.get("userPrincipalName") or p.get("displayName") or a.get("principalId")
                for p, a in zip(prin, ga)]
        c.add("ENT-PIM-01", "Entra ID", "Between two and four Global Administrators", st,
              f"{n} active Global Administrator assignments: {'; '.join(map(str, upns))}.", "Critical",
              "Keep two cloud-only break-glass accounts plus a small number of named GAs (2–4 total); make "
              "all other GA assignments eligible via PIM with approval and MFA.",
              "Free (PIM: Entra ID P2 / Governance)", "Low")
        known = [p for p in prin if "onPremisesSyncEnabled" in p]
        synced = [p.get("userPrincipalName", "?") for p in known if p.get("onPremisesSyncEnabled")]
        if not known:
            c.na("ENT-PIM-03", "Entra ID", "Administrative accounts are cloud-only", "roleAssignments_GA",
                 "Free", risk="High",
                 manual_path="Entra admin centre › Roles & admins — check 'On-premises sync enabled' for every "
                             "privileged role member (onPremisesSyncEnabled not returned by the API)")
        else:
            c.add("ENT-PIM-03", "Entra ID", "Administrative accounts are cloud-only",
                  "Fail" if synced else "Pass",
                  f"Global Administrators checked: {len(known)}; synced from on-premises: "
                  f"{', '.join(synced) or 'none'}. Other privileged roles: verify in review.", "High",
                  "Use dedicated cloud-only accounts for all administrative roles.", "Free", "Medium")
    el = c.values("roleEligibility")
    pra = c.values("privilegedRoleAssignments")
    if el is None:
        c.na("ENT-PIM-02", "Entra ID", "Privileged roles activated (PIM), not permanently assigned",
             "roleEligibility", "Entra ID P2 / Governance")
    else:
        active = [a for a in pra or [] if ((a.get("roleDefinition") or {}).get("displayName") in PRIV_ROLE_NAMES
                                         and (a.get("roleDefinition") or {}).get("displayName")
                                         != "Global Administrator")]
        st = "Fail" if not el else "Pass" if pra is not None and not active else "Partial"
        c.add("ENT-PIM-02", "Entra ID", "Privileged roles activated (PIM), not permanently assigned", st,
              f"{len(el)} eligible role assignments; {len(active) if pra is not None else 'unknown'} active "
              "non-GA privileged assignments at read time (may include current activations).", "High",
              "Make privileged role assignments eligible in PIM (time-bound activation with MFA and "
              "justification); remove standing assignments other than break-glass.",
              "Entra ID P2 / Governance", "Medium")
    rmp = c.values("roleManagementPolicy_GA")
    if rmp is None:
        c.na("ENT-PIM-04", "Entra ID", "Approval required for Global Administrator activation",
             "roleManagementPolicy_GA", "Entra ID P2 / Governance")
    else:
        rules = [r for a in rmp for r in ((a.get("policy") or {}).get("rules") or [])]
        appr = [r for r in rules if r.get("id") == "Approval_EndUser_Assignment"]
        setting = (appr[0].get("setting") or {}) if appr else {}
        stages = setting.get("approvalStages") or []
        approvers = sum(len(st.get("primaryApprovers") or []) for st in stages)
        ok = bool(setting.get("isApprovalRequired")) and approvers >= 1
        c.add("ENT-PIM-04", "Entra ID", "Approval required for Global Administrator activation",
              "Pass" if ok else "Fail",
              f"Approval rule found = {bool(appr)}; isApprovalRequired = {setting.get('isApprovalRequired')}; "
              f"primary approvers = {approvers}.", "High",
              "In PIM, require approval (with named approvers) to activate the Global Administrator role.",
              "Entra ID P2 / Governance", "Low")
    c.na("ENT-PIM-05", "Entra ID", "Two emergency access (break-glass) accounts defined", "", "Free",
         risk="High",
         manual_path="Ask the user which accounts are break-glass, then confirm: two cloud-only accounts "
                     "(*.onmicrosoft.com), permanent Global Administrator, excluded from CA policies only as "
                     "documented, strong (phishing-resistant) authentication, sign-in monitored. Do not guess "
                     "which accounts they are")
    ru = c.values("riskyUsers")
    if ru is None:
        c.na("ENT-IDP-01", "Entra ID", "Identity Protection risky users", "riskyUsers", "Entra ID P2")
    else:
        high = [u for u in ru if u.get("riskLevel") == "high"]
        c.add("ENT-IDP-01", "Entra ID", "Identity Protection risky users",
              "Pass" if not ru else "Fail" if high else "Partial",
              f"{len(ru)} users at risk ({len(high)} high).", "High",
              "Investigate and remediate risky users; enforce a user risk policy (CIS 5.2.2.6).",
              "Entra ID P2", "Medium")


def check_apps(c):
    az = c.load("authorizationPolicy")
    if az is None:
        for fid, area, ctl, risk in [
                ("APP-CON-01", "Apps & Consent", "User consent to apps not allowed", "High"),
                ("ENT-DIR-01", "Apps & Consent", "Users cannot register applications", "Medium"),
                ("ENT-DIR-02", "Entra ID", "Users cannot create security groups", "Low"),
                ("ENT-DIR-04", "Entra ID", "Non-admin users cannot create tenants", "Medium"),
                ("EXT-GST-01", "External Collaboration", "Guest invitations limited", "Medium"),
                ("EXT-GST-02", "External Collaboration", "Guest user access restricted", "Medium")]:
            c.na(fid, area, ctl, "authorizationPolicy", "Free", risk=risk)
    else:
        az = az["value"][0] if isinstance(az, dict) and "value" in az else az[0] if isinstance(az, list) else az
        perms = az.get("defaultUserRolePermissions") or {}
        grants = perms.get("permissionGrantPoliciesAssigned") or []
        self_grants = [g for g in grants if "managepermissiongrantsforself" in g.lower()]
        legacy = any("legacy" in g for g in self_grants)
        c.add("APP-CON-01", "Apps & Consent", "User consent to apps not allowed", "Fail" if self_grants else "Pass",
              f"User consent policies assigned: {self_grants or 'none (user consent disabled)'}.",
              "High" if legacy else "Medium",
              "Set user consent to 'Do not allow user consent' and route requests through the admin consent "
              "workflow, so users cannot grant third-party AI apps access to mail and files.", "Free", "Low")
        apps = perms.get("allowedToCreateApps")
        c.add("ENT-DIR-01", "Apps & Consent", "Users cannot register applications",
              "Fail" if apps is not False else "Pass", f"allowedToCreateApps = {apps}.", "Medium",
              "Set 'Users can register applications' to No; delegate app registration to the Application "
              "Developer role.", "Free", "Low")
        ten = perms.get("allowedToCreateTenants")
        c.add("ENT-DIR-04", "Entra ID", "Non-admin users cannot create tenants",
              "Pass" if ten is False else "Fail" if ten is True else "Not assessed",
              f"allowedToCreateTenants = {ten}" + ("" if ten is not None else " (property not returned)") + ".",
              "Medium", "Set 'Restrict non-admin users from creating tenants' to Yes to prevent ungoverned "
              "tenants (shadow AI/IT environments).", "Free", "Low")
        sg = perms.get("allowedToCreateSecurityGroups")
        c.add("ENT-DIR-02", "Entra ID", "Users cannot create security groups",
              "Fail" if sg is not False else "Pass", f"allowedToCreateSecurityGroups = {sg}.", "Low",
              "Restrict security group creation to administrators so access-granting groups stay governed.",
              "Free", "Low")
        inv = az.get("allowInvitesFrom")
        c.add("EXT-GST-01", "External Collaboration", "Guest invitations limited",
              "Pass" if inv in ("adminsAndGuestInviters", "none") else "Fail", f"allowInvitesFrom = {inv}.",
              "Medium", "Limit guest invitations to admins and users in the Guest Inviter role.", "Free", "Low")
        role = az.get("guestUserRoleId")
        c.add("EXT-GST-02", "External Collaboration", "Guest user access restricted",
              "Pass" if role in (RESTRICTED_GUEST_ROLE, LIMITED_GUEST_ROLE) else "Fail",
              f"guestUserRoleId = {role}.", "Medium",
              "Set guest user access to 'limited access' or 'most restrictive'.", "Free", "Low")
    c.na("EXT-GST-03", "External Collaboration", "Collaboration invitations to allowed domains only", "",
         "Free", risk="Medium",
         manual_path="Entra admin centre › External Identities › External collaboration settings › "
                     "Collaboration restrictions (allow-list of domains)")
    gs = c.values("groupSettings")
    if gs is None:
        c.na("ENT-DIR-03", "Entra ID", "Users cannot create Microsoft 365 groups", "groupSettings", "Free",
             risk="Medium")
    else:
        uni = [s for s in gs if s.get("displayName") == "Group.Unified"]
        vals = {v.get("name"): v.get("value") for s in uni for v in s.get("values", [])}
        en_ = str(vals.get("EnableGroupCreation", "true")).lower()
        c.add("ENT-DIR-03", "Entra ID", "Users cannot create Microsoft 365 groups",
              "Pass" if en_ == "false" else "Fail",
              f"Group.Unified EnableGroupCreation = {vals.get('EnableGroupCreation', 'not set (default true)')}.",
              "Medium",
              "Restrict Microsoft 365 group creation to an approved group; ungoverned groups create ungoverned "
              "SharePoint sites that Copilot can surface.", "Entra ID P1 (for group-based allow list)", "Low")
    acp = c.load("adminConsentPolicy")
    if acp is None:
        c.na("APP-CON-02", "Apps & Consent", "Admin consent workflow", "adminConsentPolicy", "Free")
    else:
        on = bool(acp.get("isEnabled"))
        c.add("APP-CON-02", "Apps & Consent", "Admin consent workflow", "Pass" if on else "Fail",
              f"Admin consent workflow enabled = {on}.", "Medium",
              "Enable the admin consent request workflow with named reviewers.", "Free", "Low")
    amp = c.load("defaultAppManagementPolicy")
    if amp is None:
        c.na("APP-CRED-01", "Apps & Consent", "Password (secret) addition blocked for applications",
             "defaultAppManagementPolicy", "Free")
        c.na("APP-CRED-02", "Apps & Consent", "Application password lifetime ≤180 days",
             "defaultAppManagementPolicy", "Free")
    else:
        on = amp.get("isEnabled")
        pcs = ((amp.get("applicationRestrictions") or {}).get("passwordCredentials") or [])
        add = [p for p in pcs if p.get("restrictionType") == "passwordAddition" and p.get("state", "enabled") == "enabled"]
        life = [p for p in pcs if p.get("restrictionType") == "passwordLifetime" and p.get("state", "enabled") == "enabled"]

        def days(iso):
            m = re.match(r"P(\d+)D", str(iso or ""))
            return int(m.group(1)) if m else None
        c.add("APP-CRED-01", "Apps & Consent", "Password (secret) addition blocked for applications",
              "Pass" if on and add else "Fail", f"Policy enabled = {on}; passwordAddition restriction = {bool(add)}.",
              "Medium", "Block new client secrets in the default app management policy; use certificates or "
              "workload identity federation for apps and AI agents.", "Free (Workload ID Premium for some "
              "restrictions [verify])", "Medium")
        ok = [p for p in life if (days(p.get("maxLifetime")) or 9999) <= 180]
        c.add("APP-CRED-02", "Apps & Consent", "Application password lifetime ≤180 days",
              "Pass" if on and ok else "Fail",
              f"Policy enabled = {on}; passwordLifetime maxLifetime = "
              f"{[p.get('maxLifetime') for p in life] or 'not set'}.", "Medium",
              "Set a maximum application password lifetime of 180 days or less.", "Free [verify]", "Low")
    ca_en = enabled_ca(c.values("caPolicies"))
    if any(cond(p).get("clientApplications") for p in ca_en):
        c.add("ENT-WID-01", "Entra ID", "Workload identity protection (CA for workload identities)", "Pass",
              "Enabled CA policy targeting workload identities present.", "Info", "", "Workload ID Premium", "Low")
    else:
        c.na("ENT-WID-01", "Entra ID", "Workload identity protection (CA for workload identities)", "",
             "Workload ID Premium", manual_path="No CA policy targets workload identities; review service "
             "principals holding high-risk permissions (see APP-PERM-01) and decide whether CA for workload "
             "identities is warranted")
    sps = c.values("servicePrincipals")
    ara = c.values("appRoleAssignments_graph")
    gsp = c.load("graphServicePrincipal") or {}
    role_names = {r.get("id"): r.get("value") for r in gsp.get("appRoles", [])}
    if sps is None or ara is None:
        c.na("APP-PERM-01", "Apps & Consent", "High-risk Graph application permissions",
             "appRoleAssignments_graph", "Free", risk="High")
    else:
        sp_by_id = {s.get("id"): s for s in sps}
        risky = {}
        for a in ara:
            perm = role_names.get(a.get("appRoleId"), a.get("appRoleId"))
            sp = sp_by_id.get(a.get("principalId"), {})
            if perm in HIGH_RISK_PERMS and sp.get("appOwnerOrganizationId") not in MICROSOFT_TENANTS:
                risky.setdefault(sp.get("displayName", a.get("principalDisplayName")), set()).add(perm)
        ev = "; ".join(f"{k}: {', '.join(sorted(v))}" for k, v in list(risky.items())[:25]) or "none"
        c.add("APP-PERM-01", "Apps & Consent", "High-risk Graph application permissions",
              "Fail" if risky else "Pass" if role_names else "Partial",
              f"{len(risky)} non-Microsoft apps with high-risk app permissions: {ev}." +
              ("" if role_names else " (Graph role names unavailable; IDs only)"), "High",
              "Review each app's business need; remove unused permissions; use Sites.Selected / RBAC for "
              "Applications; apply CA for workload identities.", "Free", "Medium")
    if sps is None:
        c.na("APP-AI-01", "AI Governance", "Third-party AI/LLM apps", "servicePrincipals", "Free")
        c.na("AI-M365-02", "Data Protection", "Third-party storage restricted in Microsoft 365 on the web",
             "servicePrincipals", "Free")
    else:
        ai = sorted({s.get("displayName", "") for s in sps if s.get("appOwnerOrganizationId") not in
                     MICROSOFT_TENANTS and any(k in s.get("displayName", "").lower() for k in AI_KEYWORDS)})
        c.add("APP-AI-01", "AI Governance", "Third-party AI/LLM apps", "Partial" if ai else "Pass",
              f"{len(ai)} possible AI apps (keyword heuristic): {', '.join(ai[:30]) or 'none'}.", "Medium",
              "Confirm each app's data access; sanction or block via Defender for Cloud Apps; publish an "
              "approved-AI-tools list.", "Free (MDA for discovery)", "Medium")
        tps = [s for s in sps if s.get("appId") == THIRD_PARTY_STORAGE_APP]
        st = "Pass" if tps and tps[0].get("accountEnabled") is False else "Fail"
        c.add("AI-M365-02", "Data Protection", "Third-party storage restricted in Microsoft 365 on the web", st,
              f"'Office 365 third party storage' service principal present = {bool(tps)}; accountEnabled = "
              f"{tps[0].get('accountEnabled') if tps else 'n/a'} [verify app ID].", "Medium",
              "Turn off 'Let users open files stored in third-party storage services in Microsoft 365 on the web' "
              "(M365 admin centre › Settings › Org settings › Microsoft 365 on the web).", "Free", "Low")
    ctd = c.load("crossTenantDefault")
    if ctd is None:
        c.na("EXT-XTA-01", "External Collaboration", "Cross-tenant inbound defaults", "crossTenantDefault", "Free",
             risk="Low")
    else:
        trust = ctd.get("inboundTrust") or {}
        c.add("EXT-XTA-01", "External Collaboration", "Cross-tenant inbound defaults", "Partial",
              f"Inbound trust: MFA={trust.get('isMfaAccepted')}, compliant device="
              f"{trust.get('isCompliantDeviceAccepted')}. Review B2B defaults.", "Low",
              "Restrict default inbound B2B collaboration; trust partner MFA only for named organisations.",
              "Free", "Low")


def check_governance(c):
    ar = c.values("accessReviews")
    if ar is None:
        c.na("GOV-AR-01", "Entra ID", "Access reviews for guest users", "accessReviews", "Entra ID P2 / Governance")
        c.na("GOV-AR-02", "Entra ID", "Access reviews for privileged roles", "accessReviews",
             "Entra ID P2 / Governance")
    else:
        txt = [json.dumps(d).lower() for d in ar]
        guest = [t for t in txt if "guest" in t]
        priv = [t for t in txt if "rolemanagement" in t or "roleeligibility" in t or "roleassignment" in t]
        c.add("GOV-AR-01", "Entra ID", "Access reviews for guest users", "Pass" if guest else "Fail",
              f"{len(ar)} review definitions; {len(guest)} scoped to guests (heuristic).", "Medium",
              "Configure recurring access reviews of guest users in Microsoft 365 groups/Teams; auto-remove "
              "denied guests.", "Entra ID P2 / Governance", "Medium")
        c.add("GOV-AR-02", "Entra ID", "Access reviews for privileged roles", "Pass" if priv else "Fail",
              f"{len(priv)} review definitions scoped to privileged roles (heuristic).", "Medium",
              "Configure recurring PIM access reviews for privileged directory roles.",
              "Entra ID P2 / Governance", "Medium")
    v = c.values("accessPackages")
    if v is None:
        c.na("GOV-EM-01", "Entra ID", "Entitlement management", "accessPackages", "Entra ID P2 / Governance",
             risk="Low")
    else:
        c.add("GOV-EM-01", "Entra ID", "Entitlement management", "Pass" if v else "Fail", f"{len(v)} access packages.",
              "Low", "Use access packages for external and project access, with expiry.", "Entra ID P2 / Governance",
              "Medium")
    ss = c.values("secureScore")
    if ss:
        s = ss[0]
        c.add("SEC-SS-01", "Entra ID", "Microsoft Secure Score (context only)", "Partial",
              f"Secure Score {s.get('currentScore')} / {s.get('maxScore')}.", "Info",
              "Use Secure Score recommendations to track remediation progress.", "Free", "Low")


def spo_get(spo, *keys):
    for k in keys:
        if k in spo:
            return spo[k]
    return None


def check_data(c):
    spo = c.load("ps_spoTenant") or c.load("spoSettings")
    if spo is None:
        for fid, ctl, risk in [("DATA-SP-01", "SharePoint external content sharing restricted", "High"),
                               ("DATA-SP-02", "Default link type is 'Specific people'", "Medium"),
                               ("DATA-SP-06", "Default link permission is 'View'", "Medium"),
                               ("DATA-SP-07", "OneDrive content sharing restricted", "Medium"),
                               ("DATA-SP-08", "Guests cannot reshare items they don't own", "Medium"),
                               ("DATA-SP-09", "External sharing restricted by domain", "Medium"),
                               ("DATA-SP-10", "Guest access expires automatically", "Medium"),
                               ("DATA-SP-11", "Verification-code reauthentication restricted", "Low"),
                               ("DATA-SP-12", "Modern authentication required for SharePoint", "Medium")]:
            c.na(fid, "Data Protection", ctl, "spoSettings", "Free", risk=risk)
    else:
        def rec(fid, ctl, val, ok, ev, risk, fix, effort="Low"):
            if val is None:
                c.na(fid, "Data Protection", ctl, "ps_spoTenant", "Free", risk=risk)
            else:
                c.add(fid, "Data Protection", ctl, "Pass" if ok else "Fail", ev, risk, fix, "Free", effort)
        cap = spo_get(spo, "SharingCapability", "sharingCapability")
        rec("DATA-SP-01", "SharePoint external content sharing restricted", cap,
            str(cap).lower() != "externaluserandguestsharing", f"Sharing capability = {cap}.", "High",
            "Set SharePoint external sharing to 'New and existing guests' or more restrictive; allow Anyone links "
            "only on approved sites.")
        link = spo_get(spo, "DefaultSharingLinkType")
        rec("DATA-SP-02", "Default link type is 'Specific people'", link, str(link).lower() == "direct",
            f"DefaultSharingLinkType = {link}.",
            "High" if str(link).lower() == "anonymousaccess" else "Medium",
            "Set the default sharing link to 'Specific people' to reduce oversharing that Copilot can surface.")
        perm = spo_get(spo, "DefaultLinkPermission")
        rec("DATA-SP-06", "Default link permission is 'View'", perm, str(perm).lower() == "view",
            f"DefaultLinkPermission = {perm}.", "Medium", "Set the default link permission to 'View'.")
        od = spo_get(spo, "OneDriveSharingCapability", "oneDriveSharingCapability")
        rec("DATA-SP-07", "OneDrive content sharing restricted", od, str(od).lower() == "disabled",
            f"OneDriveSharingCapability = {od} (CIS L2 expects organisation-only [verify]).", "Medium",
            "Restrict OneDrive sharing to people in the organisation (or as tightly as the business allows).")
        resh = spo_get(spo, "PreventExternalUsersFromResharing")
        if resh is None and "isResharingByExternalUsersEnabled" in spo:
            resh = not spo["isResharingByExternalUsersEnabled"]
        rec("DATA-SP-08", "Guests cannot reshare items they don't own", resh, resh is True,
            f"PreventExternalUsersFromResharing = {resh}.", "Medium",
            "Prevent guests from resharing items they don't own.")
        dom = spo_get(spo, "SharingDomainRestrictionMode", "sharingDomainRestrictionMode")
        rec("DATA-SP-09", "External sharing restricted by domain", dom, str(dom).lower() == "allowlist",
            f"SharingDomainRestrictionMode = {dom}.", "Medium",
            "Limit external sharing to an allow-list of partner domains.")
        exp_req, exp_days = spo_get(spo, "ExternalUserExpirationRequired"), spo_get(spo, "ExternalUserExpireInDays")
        rec("DATA-SP-10", "Guest access expires automatically", exp_req,
            exp_req is True and exp_days is not None and int(exp_days) <= 30,
            f"ExternalUserExpirationRequired = {exp_req}; ExternalUserExpireInDays = {exp_days}.", "Medium",
            "Require guest access to sites and OneDrive to expire after 30 days or fewer.")
        att, att_days = spo_get(spo, "EmailAttestationRequired"), spo_get(spo, "EmailAttestationReAuthDays")
        rec("DATA-SP-11", "Verification-code reauthentication restricted", att,
            att is True and att_days is not None and int(att_days) <= 15,
            f"EmailAttestationRequired = {att}; EmailAttestationReAuthDays = {att_days}.", "Low",
            "Require people using verification codes to reauthenticate within 15 days or fewer.")
        leg = spo_get(spo, "LegacyAuthProtocolsEnabled", "isLegacyAuthProtocolsEnabled")
        rec("DATA-SP-12", "Modern authentication required for SharePoint", leg, leg is False,
            f"LegacyAuthProtocolsEnabled = {leg}.", "Medium",
            "Block apps that don't use modern authentication from SharePoint and OneDrive.")
        anon = spo_get(spo, "RequireAnonymousLinksExpireInDays")
        if anon is not None:
            c.add("DATA-SP-03", "Data Protection", "Anyone link expiry",
                  "Pass" if anon and 0 < int(anon) <= 30 else "Fail", f"Expiry days = {anon}.", "Medium",
                  "Require Anyone links to expire within 30 days or fewer.", "Free", "Low")
        else:
            c.na("DATA-SP-03", "Data Protection", "Anyone link expiry", "ps_spoTenant", "Free")
    rss = c.load("ps_spoRestrictedSearch")
    if rss is None:
        c.na("DATA-SP-04", "AI Governance", "Restricted SharePoint Search / Restricted Content Discovery",
             "ps_spoRestrictedSearch", "M365 Copilot / SAM")
    else:
        mode = rss.get("Mode", rss) if isinstance(rss, dict) else rss
        c.add("DATA-SP-04", "AI Governance", "Restricted SharePoint Search / Restricted Content Discovery",
              "Partial", f"Restricted SharePoint Search mode = {mode}. Confirm RCD on overshared sites.", "Medium",
              "Use RSS/RCD only as a temporary control while oversharing is remediated with DAG reports and "
              "site access reviews.", "M365 Copilot / SAM", "Medium")
    c.na("DATA-SP-05", "AI Governance", "SharePoint Advanced Management (DAG reports, site access reviews)", "",
         "SAM (included with Copilot [verify])", risk="High",
         manual_path="SharePoint admin centre › Reports › Data access governance")
    labels = c.values("sensitivityLabels")
    lp = c.values("ps_labelPolicies")
    if labels is None and lp is None:
        c.na("DATA-MIP-01", "Data Protection", "Sensitivity label policies published", "sensitivityLabels",
             "M365 E3 / Business Premium", risk="High")
    else:
        pub = [p for p in lp or [] if p.get("Enabled", True)]
        st = "Pass" if pub else "Partial" if labels else "Fail"
        c.add("DATA-MIP-01", "Data Protection", "Sensitivity label policies published", st,
              f"{len(labels or [])} labels visible; {len(pub)} enabled label policies"
              f"{'' if lp is not None else ' (label policies not collected — Purview module not run)'}.", "High",
              "Publish a sensitivity label policy to all users; Copilot honours label encryption and usage rights.",
              "M365 E3 / Business Premium", "Medium")
    if lp is None:
        c.na("DATA-MIP-02", "Data Protection", "Default / mandatory labelling", "ps_labelPolicies",
             "E3 (manual) / E5 (auto)")
    else:
        dflt = [p for p in lp if any("defaultlabel" in str(s).lower() or "mandatory" in str(s).lower()
                                     for s in (p.get("Settings") or []))]
        c.add("DATA-MIP-02", "Data Protection", "Default / mandatory labelling", "Pass" if dflt else "Fail",
              f"{len(dflt)} policies with default/mandatory labelling.", "Medium",
              "Set a default label for documents and email; consider mandatory labelling.",
              "E3 (manual) / E5 (auto)", "Medium")
    dlp = c.values("ps_dlpPolicies")
    if dlp is None:
        c.na("DATA-DLP-01", "Data Protection", "DLP policies enabled", "ps_dlpPolicies", "E3/E5", risk="High")
        c.na("DATA-DLP-02", "AI Governance", "DLP policies for Microsoft 365 Copilot", "ps_dlpPolicies",
             "E5 Compliance [verify]", risk="High")
        c.na("DATA-DLP-03", "Data Protection", "DLP policies for Microsoft Teams", "ps_dlpPolicies", "E5")
    else:
        def enforced(p):
            return str(p.get("Mode", "")).lower() == "enable" and p.get("Enabled", True) is not False
        on = [p for p in dlp if enforced(p)]
        c.add("DATA-DLP-01", "Data Protection", "DLP policies enabled", "Pass" if on else "Fail",
              f"{len(on)}/{len(dlp)} DLP policies enforced.", "High",
              "Enforce DLP for sensitive information types across Exchange, SharePoint, OneDrive and Teams.",
              "E3/E5", "Medium")
        cop = [p for p in dlp if "copilot" in json.dumps(p).lower()]
        cop_on = [p for p in cop if enforced(p)]
        c.add("DATA-DLP-02", "AI Governance", "DLP policies for Microsoft 365 Copilot",
              "Pass" if cop_on else "Partial" if cop else "Fail",
              f"{len(cop)} DLP policies reference the Microsoft 365 Copilot location; {len(cop_on)} enforced.",
              "High",
              "Publish an enforced DLP policy for the Microsoft 365 Copilot and Copilot Chat location (e.g. "
              "exclude highly confidential labelled content from Copilot processing).", "E5 Compliance [verify]",
              "Medium")
        tms = [p for p in on if "teams" in json.dumps(p).lower()]
        c.add("DATA-DLP-03", "Data Protection", "DLP policies for Microsoft Teams", "Pass" if tms else "Fail",
              f"{len(tms)} enforced DLP policies include Teams chat/channel messages.", "Medium",
              "Extend enforced DLP to Teams chats and channel messages.", "E5", "Medium")
    c.na("DATA-DSPM-01", "AI Governance", "Purview DSPM for AI configured", "", "Purview (E5 Compliance)",
         manual_path="Purview portal › DSPM for AI › Recommendations")
    aud = c.load("ps_auditConfig")
    if aud is None:
        c.na("DATA-AUD-01", "Data Protection", "Microsoft 365 audit log search enabled", "ps_auditConfig", "Free",
             risk="High")
    else:
        on = bool(aud.get("UnifiedAuditLogIngestionEnabled"))
        c.add("DATA-AUD-01", "Data Protection", "Microsoft 365 audit log search enabled", "Pass" if on else "Fail",
              f"UnifiedAuditLogIngestionEnabled = {on}.", "Critical",
              "Enable unified audit logging so Copilot and AI interactions are recorded.", "Free", "Low")
    org = c.load("ps_orgConfig")
    if org is None:
        c.na("DATA-AUD-02", "Data Protection", "Mailbox auditing not disabled organisation-wide", "ps_orgConfig",
             "Free")
    else:
        dis = org.get("AuditDisabled")
        c.add("DATA-AUD-02", "Data Protection", "Mailbox auditing not disabled organisation-wide",
              "Pass" if dis is False else "Fail", f"AuditDisabled = {dis}.", "High",
              "Set organisation AuditDisabled to False so mailbox actions are audited.", "Free", "Low")
    for fid, src, ctl, kw, lic in [
            ("DATA-RET-01", "ps_retentionPolicies", "Retention for Copilot / AI interactions", "copilot", "E3/E5"),
            ("DATA-IRM-01", "ps_insiderRisk", "Insider Risk (risky AI usage)", "", "E5 Insider Risk"),
            ("DATA-CC-01", "ps_commCompliance", "Communication Compliance for Copilot", "", "E5 Comm Compliance")]:
        v = c.values(src)
        if v is None:
            c.na(fid, "AI Governance", ctl, src, lic)
        else:
            hit = [p for p in v if kw in json.dumps(p).lower()] if kw else v
            c.add(fid, "AI Governance", ctl, "Pass" if hit else "Fail", f"{len(hit)} relevant policies found.",
                  "Medium", f"Configure {ctl.lower()} before broad AI rollout.", lic, "Medium")


def check_ai(c):
    c.na("AI-MDA-01", "AI Governance", "Defender for Cloud Apps enabled and configured (shadow AI discovery)", "",
         "MDA (E5 Security)", risk="High",
         manual_path="Defender portal › Cloud apps — confirm MDA is enabled with the Microsoft 365 app "
                     "connector and Cloud Discovery; then review the Generative AI category and tag "
                     "unsanctioned AI apps")
    c.na("AI-COP-01", "AI Governance", "Copilot agents / plugins control", "", "M365 Copilot",
         manual_path="Microsoft 365 admin centre › Copilot › Settings / Agents [verify path]")
    c.na("AI-COP-02", "AI Governance", "Web grounding (web search) setting", "", "M365 Copilot", risk="Low",
         manual_path="Microsoft 365 admin centre › Copilot › Settings › Web search [verify path]")
    aas = c.load("appsAndServices")
    if aas is None:
        c.na("AI-M365-01", "AI Governance", "User owned apps and services restricted", "appsAndServices", "Free",
             manual_path="Microsoft 365 admin centre › Settings › Org settings › User owned apps and services — "
                         "Office Store access and trial starts off")
    else:
        st_ = aas.get("settings") or aas
        store, trial = st_.get("isOfficeStoreEnabled"), st_.get("isAppAndServicesTrialEnabled")
        if store is None or trial is None:
            c.na("AI-M365-01", "AI Governance", "User owned apps and services restricted", "appsAndServices",
                 "Free", manual_path="Properties not returned [verify API] — check Microsoft 365 admin centre › "
                                     "Settings › Org settings › User owned apps and services")
        else:
            c.add("AI-M365-01", "AI Governance", "User owned apps and services restricted",
                  "Pass" if store is False and trial is False else "Fail",
                  f"Office Store access = {store}; users can start trials = {trial}.", "Medium",
                  "Turn off user access to the Office Store and user-initiated trials, so users cannot add "
                  "unapproved AI add-ins or services.", "Free", "Low")
    c.na("AI-TMS-01", "AI Governance", "Teams app permission policies configured (agents / bots)", "",
         "Free", manual_path="Teams admin centre › Teams apps › Manage apps / Permission policies — third-party "
                             "and custom apps (incl. AI agents) limited to approved apps")
    tmp = c.values("ps_teamsMeetingPolicy")
    if tmp is None:
        c.na("AI-TMS-02", "AI Governance", "Meeting recording off by default", "ps_teamsMeetingPolicy", "Free",
             risk="Low", manual_path="Teams admin centre › Meetings › Meeting policies › Global › Recording & "
                                     "transcription (or Get-CsTeamsMeetingPolicy -Identity Global)")
    else:
        g = [p for p in tmp if str(p.get("Identity", "")).lower().endswith("global")] or tmp
        on = g[0].get("AllowCloudRecording")
        c.add("AI-TMS-02", "AI Governance", "Meeting recording off by default", "Pass" if on is False else "Fail",
              f"Global AllowCloudRecording = {on}.", "Low",
              "Turn recording off by default and enable it for groups that need it; recordings/transcripts "
              "become Copilot-searchable content.", "Free", "Low")
    rap = c.values("ps_roleAssignmentPolicy")
    if rap is None:
        c.na("AI-EXO-01", "AI Governance", "Users cannot install Outlook add-ins", "ps_roleAssignmentPolicy", "Free")
    else:
        bad = [p.get("Name") for p in rap if RISKY_OUTLOOK_ADDIN_ROLES &
               {str(r).lower() for r in (p.get("AssignedRoles") or [])}]
        c.add("AI-EXO-01", "AI Governance", "Users cannot install Outlook add-ins", "Fail" if bad else "Pass",
              f"Role assignment policies allowing user add-in install: {', '.join(bad) or 'none'}.", "Medium",
              "Remove 'My Custom Apps', 'My Marketplace Apps' and 'My ReadWriteMailbox Apps' from role "
              "assignment policies; deploy approved AI add-ins centrally.", "Free", "Low")
    owa = c.values("ps_owaPolicy")
    if owa is None:
        c.na("AI-EXO-02", "Data Protection", "Additional storage providers restricted in Outlook on the web",
             "ps_owaPolicy", "Free")
    else:
        bad = [p.get("Name") for p in owa if p.get("AdditionalStorageProvidersAvailable") is not False]
        c.add("AI-EXO-02", "Data Protection", "Additional storage providers restricted in Outlook on the web",
              "Fail" if bad else "Pass", f"OWA policies allowing additional storage providers: "
              f"{', '.join(map(str, bad)) or 'none'}.", "Medium",
              "Set AdditionalStorageProvidersAvailable to False on OWA mailbox policies.", "Free", "Low")
    sl = c.values("ps_safeLinksPolicy")
    if sl is None:
        c.na("AI-DEF-01", "AI Governance", "Safe Links for Office applications (incl. Teams / Copilot links "
             "[verify])", "ps_safeLinksPolicy", "Defender for Office 365 P1/P2 (E5)")
    else:
        good = [p for p in sl if p.get("EnableSafeLinksForOffice") is True and p.get("EnableSafeLinksForEmail")
                is not False and p.get("EnableSafeLinksForTeams") is not False and p.get("TrackClicks") is not False
                and p.get("AllowClickThrough") is not True and p.get("ScanUrls") is not False]
        rules = c.values("ps_safeLinksRule")
        enabled_rules = {r.get("SafeLinksPolicy") for r in rules or [] if str(r.get("State", "")).lower() == "enabled"}
        good_on = [p for p in good if rules is None or p.get("Name") in enabled_rules or p.get("IsBuiltInProtection")]
        builtin_only = bool(good_on) and all(p.get("IsBuiltInProtection") for p in good_on)
        c.add("AI-DEF-01", "AI Governance", "Safe Links for Office applications (incl. Teams / Copilot links "
              "[verify])", "Partial" if builtin_only else "Pass" if good_on else "Partial" if good else "Fail",
              f"{len(sl)} Safe Links policies; {len(good)} protect email, Teams and Office apps with URL "
              f"scanning, click tracking and no click-through; {len(good_on)} applied by an enabled rule"
              f"{'' if rules is not None else ' (rules not collected)'}"
              f"{' — only the built-in protection preset protects users; check it against CIS 2.1.1 [verify]' if builtin_only else ''}.",
              "Medium",
              "Enable a Safe Links policy applied to all recipients covering email, Teams and Office apps, with "
              "real-time URL scanning, click tracking and no click-through.", "Defender for Office 365 P1/P2 (E5)",
              "Low")
    pp = c.values("ps_powerPlatformDlp")
    if pp is None:
        c.na("AI-PP-01", "AI Governance", "Copilot Studio / Power Platform DLP", "ps_powerPlatformDlp",
             "Power Platform", risk="High")
    else:
        c.add("AI-PP-01", "AI Governance", "Copilot Studio / Power Platform DLP", "Pass" if pp else "Fail",
              f"{len(pp)} Power Platform DLP policies.", "High",
              "Create a tenant-wide DLP policy blocking unapproved connectors; govern the default environment.",
              "Power Platform", "Medium")
    ao = c.values("ps_azureOpenAI")
    if ao is None:
        c.na("AI-AOAI-01", "AI Governance", "Azure OpenAI exposure", "ps_azureOpenAI", "Azure", risk="Low")
    else:
        pub = [a for a in ao if str(a.get("PublicNetworkAccess", "")).lower() == "enabled"
               or a.get("DisableLocalAuth") is False]
        c.add("AI-AOAI-01", "AI Governance", "Azure OpenAI exposure", "Fail" if pub else "Pass",
              f"{len(pub)}/{len(ao)} accounts with public access or key auth.", "High",
              "Disable public network access (use private endpoints) and local key auth; use Entra ID auth.",
              "Azure", "Medium")


def licensing(c):
    skus = c.values("subscribedSkus")
    users = c.values("users_licences")
    out = {"skus": [], "capabilities": {}, "compliance": [], "caveat": (
        "This licensing analysis is advisory and indicative only. It is based on configuration data read at "
        "the time of assessment and Microsoft's published licensing guidance, and is not a legal licensing "
        "determination. Confirm with your Microsoft licensing partner or the current Microsoft Product Terms.")}
    if skus is None:
        c.na("LIC-01", "Licensing", "Licence inventory", "subscribedSkus", "—", risk="Medium")
        return out
    sku_plans = {}
    for s in skus:
        pu = s.get("prepaidUnits") or {}
        plans = [p.get("servicePlanName", "") for p in s.get("servicePlans", [])
                 if p.get("provisioningStatus") != "Disabled"]
        sku_plans[s.get("skuId")] = plans
        out["skus"].append({"sku": s.get("skuPartNumber"), "purchased": pu.get("enabled", 0),
                            "assigned": s.get("consumedUnits", 0), "warning": pu.get("warning", 0),
                            "suspended": pu.get("suspended", 0)})
    for cap, subs in PLAN_MAP.items():
        holders = [s["skuPartNumber"] for s in skus if any(
            any(x.upper().startswith(sub) and not (sub == "AAD_PREMIUM" and "P2" in x.upper())
                for sub in subs) for x in sku_plans.get(s.get("skuId"), []))]
        out["capabilities"][cap] = holders
    over = [s for s in out["skus"] if s["assigned"] > s["purchased"]]
    c.add("LIC-01", "Licensing", "Licence inventory and over-assignment", "Fail" if over else "Pass",
          f"{len(out['skus'])} SKUs; over-assigned: {', '.join(s['sku'] for s in over) or 'none'}.", "Medium",
          "Resolve over-assigned or expiring (warning/suspended) subscriptions.", "—", "Low")

    def licensed_count(caps, members):
        subs = [sub for cap in caps for sub in PLAN_MAP[cap]]
        n = 0
        for u in members:
            plans = [p for lic in u.get("assignedLicenses", []) for p in sku_plans.get(lic.get("skuId"), [])]
            if any(any(p.upper().startswith(sub) and not (sub == "AAD_PREMIUM" and "P2" in p.upper())
                       for sub in subs) for p in plans):
                n += 1
        return n

    if users is None:
        out["compliance"].append({"rule": "LIC-ENT-*", "status": "Unable to determine",
                                  "detail": c.reason("users_licences")})
    else:
        members = [u for u in users if u.get("accountEnabled") and u.get("userType") == "Member"]
        p1 = licensed_count(["Entra ID P1", "Entra ID P2"], members)
        p2 = licensed_count(["Entra ID P2"], members)
        pim = licensed_count(["Entra ID P2", "Entra ID Governance"], members)
        en = enabled_ca(c.values("caPolicies"))
        rules = []
        if en is not None and any(all_users(p) for p in en):
            rules.append(("LIC-ENT-01", "Conditional Access scoped to All users", len(members), p1, "Entra ID P1"))
        if any((p.get("conditions") or {}).get("signInRiskLevels") or (p.get("conditions") or {})
               .get("userRiskLevels") for p in en or []):
            scope = len(members) if any(all_users(p) for p in en) else None
            rules.append(("LIC-ENT-02", "Risk-based CA / Identity Protection", scope, p2, "Entra ID P2"))
        el = c.values("roleEligibility")
        if el:
            rules.append(("LIC-ENT-03", "PIM eligible assignments", len({e.get("principalId") for e in el}),
                          pim, "Entra ID P2 / Governance"))
        if c.values("accessReviews"):
            rules.append(("LIC-ENT-04", "Access reviews", None, pim, "Entra ID P2 / Governance"))
        if any((p.get("conditions") or {}).get("clientApplications") for p in en or []):
            rules.append(("LIC-ENT-06", "CA for workload identities", None,
                          len(out["capabilities"].get("Workload Identities Premium", [])), "Workload ID Premium"))
        for rid, feat, benefit, lic_n, lic in rules:
            if benefit is None:
                st, gap = "Unable to determine", None
            else:
                gap = max(0, benefit - lic_n)
                st = "Compliant (indicative)" if gap == 0 else f"Potential gap — {gap} users"
            out["compliance"].append({"rule": rid, "feature": feat, "users_benefiting": benefit,
                                      "users_licensed": lic_n, "licence": lic, "status": st})
            c.add(rid, "Licensing", f"Tenant-wide licence coverage: {feat}",
                  "Pass" if gap == 0 else "Not assessed" if gap is None else "Partial",
                  f"Benefiting: {benefit if benefit is not None else 'unknown'}; licensed ({lic}): {lic_n}. "
                  "Advisory only.", "Medium",
                  f"Licence all users who benefit from {feat} with {lic}, or narrow policy scope. Confirm with "
                  "your licensing partner.", lic, "Low")
    return out




def detect_profile_hint(c):
    """Hint only — the profile used for scoring is always the one the user confirmed (--cis-licence-profile)."""
    skus = c.values("subscribedSkus") or []
    e5 = [s.get("skuPartNumber", "") for s in skus if (s.get("prepaidUnits") or {}).get("enabled", 0) > 0 and
          re.search(r"E5|ENTERPRISEPREMIUM", s.get("skuPartNumber", "").upper())]
    if e5:
        return f"E5 SKUs present: {', '.join(e5)}"
    return "no E5 SKU found" if skus else "no SKU evidence collected"


def pct(n, d):
    return round(100.0 * n / d, 1) if d else None


def tally(rows):
    app = [r for r in rows if r["applicable"] and r["status"] != "Not assessed"]
    passed = [r for r in app if r["passed"]]
    return {"applicable_assessed": len(app), "passed": len(passed), "not_passed": len(app) - len(passed),
            "not_assessed": len([r for r in rows if r["applicable"] and r["status"] == "Not assessed"]),
            "not_applicable": len([r for r in rows if not r["applicable"]]), "pct_passed": pct(len(passed), len(app))}


def cis_scores(c, profile, levels, hint):
    cmap = c.cmap
    by_id = {f["id"]: f for f in c.findings}
    recs = {}
    for fid, meta in cmap["checks"].items():
        rid = meta.get("cis_m365_id")
        if not rid or fid not in by_id:
            continue
        recs.setdefault(rid, {"meta": meta, "findings": []})["findings"].append(by_id[fid])
    rows = []
    for rid, r in sorted(recs.items(), key=lambda kv: [int(x) for x in kv[0].split(".")]):
        meta, fs = r["meta"], r["findings"]
        lic_prof, level = meta["profile"].split()
        statuses = [f["status"] for f in fs]
        if all(s == "Pass" for s in statuses):
            st = "Pass"
        elif "Fail" in statuses:
            st = "Fail"
        elif "Partial" in statuses:
            st = "Partial"
        else:
            st = "Not assessed"
        in_licence = not (lic_prof == "E5" and profile == "E3")
        in_levels = level in levels
        applicable = in_licence and in_levels
        why = ("" if applicable else " (not scored – E5 profile)" if not in_licence
               else " (not scored – L2 out of chosen scope)")
        rows.append({"cis_id": rid, "title": meta["cis_title"], "level": level, "licence_profile": lic_prof,
                     "profile": meta["profile"], "cis_assessment": meta["cis_assessment"],
                     "section": meta["section"], "verify": meta.get("verify") or [],
                     "status": st + why, "in_licence_profile": in_licence, "in_level_scope": in_levels,
                     "passed": st == "Pass", "applicable": applicable,
                     "finding_ids": [f["id"] for f in fs],
                     "risk": min((f["risk"] for f in fs), key=lambda x: RISK_ORDER.get(x, 9))})
    l1 = [r for r in rows if r["level"] == "L1"]
    l2 = [r for r in rows if r["level"] == "L2"]
    sections = {}
    for r in rows:
        sections.setdefault(r["section"], []).append(r)
    by_section = {s: dict({lv: tally([r for r in rs if r["level"] == lv]) for lv in levels}, all=tally(rs))
                  for s, rs in sorted(sections.items())}
    # CIS Controls v8.1 — safeguard and IG coverage over every assessed check (CIS-mapped + supplementary).
    sg_rows = {}
    for f in c.findings:
        meta = cmap["checks"].get(f["id"])
        if not meta or not meta.get("safeguard") or f["status"] == "Not assessed" or f["id"] == "SEC-SS-01":
            continue
        sg_rows.setdefault(meta["safeguard"], []).append(f)
    safeguards = []
    for sg, fs in sorted(sg_rows.items(), key=lambda kv: [int(x) for x in kv[0].split(".")]):
        info = cmap["safeguards"][sg]
        safeguards.append({"safeguard": sg, "title": info["title"], "ig": info["ig"], "checks": len(fs),
                           "checks_passed": sum(f["status"] == "Pass" for f in fs),
                           "met": all(f["status"] == "Pass" for f in fs),
                           "finding_ids": [f["id"] for f in fs]})
    ig = {}
    for g in ("IG1", "IG2", "IG3"):
        s = [x for x in safeguards if x["ig"] == g]
        chk = sum(x["checks"] for x in s)
        ok = sum(x["checks_passed"] for x in s)
        ig[g] = {"safeguards_assessed": len(s), "safeguards_met": sum(x["met"] for x in s),
                 "pct_safeguards_met": pct(sum(x["met"] for x in s), len(s)),
                 "checks_assessed": chk, "checks_passed": ok, "pct_checks_passed": pct(ok, chk)}
    # Remediation order: CIS L1 → CIS L2 (both within the tenant's licence profile) → supplementary (AI-specific)
    # → E5-profile recommendations that need a licence upgrade; within each tier by risk, then effort.
    tier_of = {}
    for r in rows:
        for fid in r["finding_ids"]:
            if r["applicable"]:
                tier_of[fid] = (0 if r["level"] == "L1" else 1, r["cis_id"], r["level"])
            elif not r["in_licence_profile"]:
                tier_of[fid] = (4, r["cis_id"], f"{r['level']} (E5 profile – licence upgrade)")
            else:
                tier_of[fid] = (3, r["cis_id"], "L2 (outside chosen scoring scope)")
    rem = []
    for f in c.findings:
        if f["status"] not in ("Fail", "Partial") or f["id"].startswith(("LIC-", "ERR-", "SEC-")):
            continue
        tier, rid, lvl = tier_of.get(f["id"], (2, None, "Supplementary"))
        rem.append({"finding_id": f["id"], "control": f["control"], "cis_id": rid, "cis_level": lvl,
                    "risk": f["risk"], "effort": f["effort"], "status": f["status"],
                    "_k": (tier, 0 if lvl.startswith("L1") else 1, RISK_ORDER.get(f["risk"], 9),
                           EFFORT_ORDER.get(f["effort"], 9))})
    rem.sort(key=lambda x: x["_k"])
    for i, x in enumerate(rem, 1):
        x.pop("_k")
        x["order"] = i
    l1t = tally(l1)
    return {
        "benchmark": cmap.get("benchmark"), "controls": cmap.get("controls"),
        "tenant_licence_profile": profile, "licence_profile_hint": hint,
        "levels_scored": levels,
        "scope_note": ("Scores cover the CIS recommendations this AI-readiness assessment evaluates (a subset of "
                       "the full benchmark), not a full CIS certification. Not assessed items are excluded from "
                       "the percentage and listed separately; Partial counts as not passed."),
        "headline": (f"{l1t['pct_passed'] if l1t['pct_passed'] is not None else 'n/a'}% of assessed CIS "
                     f"Level 1 recommendations met ({l1t['passed']}/{l1t['applicable_assessed']}); "
                     f"CIS Controls IG1 coverage {ig['IG1']['pct_safeguards_met']}% of assessed safeguards met"),
        "level1": l1t, "level2": tally(l2) if "L2" in levels else "not scored (user chose L1 only)",
        "overall": tally(rows), "by_section": by_section,
        "implementation_groups": ig, "safeguards": safeguards, "recommendations": rows,
        "remediation_order": rem,
        "verify_items": [{"finding_id": fid, "cis_id": meta.get("cis_m365_id"),
                          "fields_to_verify": meta.get("verify")}
                         for fid, meta in cmap["checks"].items() if meta.get("verify") and fid in by_id],
        "copyright": ("CIS Benchmarks and CIS Controls are (c) Center for Internet Security, Inc., used for "
                      "reference under CIS terms of use. This assessment cites recommendation IDs and short "
                      "titles and paraphrases intent; it does not reproduce CIS text. Items marked [verify] "
                      "have an unconfirmed mapping."),
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--raw", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--cis-map", default=DEFAULT_MAP, help="Path to cis-mapping.json")
    ap.add_argument("--cis-licence-profile", required=True, choices=["E3", "E5"],
                    help="CIS profile family the USER confirmed (E5 adds E5-only recommendations). Never guess.")
    ap.add_argument("--cis-levels", required=True, choices=["L1", "L1L2"],
                    help="Levels the USER chose to score at launch: L1 only, or L1 and L2. Never guess.")
    a = ap.parse_args()
    c = Ctx(a.raw, load_map(a.cis_map))
    for fn in (check_identity, check_auth_methods, check_privileged, check_apps, check_governance,
               check_data, check_ai):
        try:
            fn(c)
        except Exception as exc:  # keep going; record the analyser error as evidence
            c.add(f"ERR-{fn.__name__}", "Analyser", fn.__name__, "Not assessed", f"Analyser error: {exc}",
                  "Info", "Review raw evidence manually.", "—", "Low")
    lic = licensing(c)
    levels = ["L1"] if a.cis_levels == "L1" else ["L1", "L2"]
    scores = cis_scores(c, a.cis_licence_profile, levels, detect_profile_hint(c))
    os.makedirs(a.out, exist_ok=True)
    for name, data in (("findings.json", c.findings), ("licensing.json", lic), ("cis_scores.json", scores)):
        with open(os.path.join(a.out, name), "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, ensure_ascii=False)
    counts = {}
    for f in c.findings:
        counts[f["status"]] = counts.get(f["status"], 0) + 1
    print(json.dumps({"findings": len(c.findings), "by_status": counts, "cis_headline": scores["headline"],
                      "cis_level1_pct": scores["level1"]["pct_passed"],
                      "cis_level2_pct": scores["level2"]["pct_passed"] if "L2" in levels else "not scored",
                      "ig1_safeguards_met_pct": scores["implementation_groups"]["IG1"]["pct_safeguards_met"]},
                     indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
