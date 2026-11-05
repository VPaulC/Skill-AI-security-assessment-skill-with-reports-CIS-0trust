# Licensing Map — controls, service plans, and tenant-wide compliance rules

> Service plan names (`servicePlanName`) and SKU part numbers change. Match by the plan name substrings
> below, then confirm against Microsoft's "Product names and service plan identifiers for licensing"
> reference. Mark any uncertain mapping **[verify]** in the report.

## Capability → service plan substring(s)

| Capability | Service plan substring(s) | Typical SKUs |
|---|---|---|
| Entra ID P1 (Conditional Access, MFA reports, dynamic groups) | `AAD_PREMIUM` (not `_P2`) | M365 E3/E5, Business Premium, EMS E3/E5, Entra ID P1 |
| Entra ID P2 (Identity Protection, risk-based CA, PIM, access reviews) | `AAD_PREMIUM_P2` | M365 E5, EMS E5, Entra ID P2 |
| Entra ID Governance (PIM, access reviews, entitlement mgmt, lifecycle workflows) | `Entra_Identity_Governance`, `ENTRA_IDENTITY_GOVERNANCE` [verify] | Entra ID Governance, Entra Suite |
| Entra Suite (Internet/Private Access, Verified ID premium, Governance) | `Entra_Premium_Internet_Access`, `Entra_Premium_Private_Access` [verify] | Microsoft Entra Suite |
| Workload Identities Premium | `AAD_WRKLDID` [verify] | Workload Identities Premium |
| Intune (device compliance) | `INTUNE_A` | M365 E3/E5, Business Premium, EMS |
| Microsoft 365 Copilot | `M365_COPILOT`, `Microsoft_365_Copilot` [verify] | Microsoft 365 Copilot |
| Sensitivity labels – manual | `MIP_S_CLP1`, `RMS_S_PREMIUM` | E3, Business Premium |
| Sensitivity labels – auto-labelling | `MIP_S_CLP2`, `RMS_S_PREMIUM2` | E5, E5 Compliance, E5 Info Protection & Governance |
| DLP (Exchange/SPO/ODB) | `EXCHANGE_S_ENTERPRISE`/`SHAREPOINTENTERPRISE` (E3 baseline) | E3+ |
| DLP for Teams / Endpoint / Copilot | `MIP_S_CLP2`, `MICROSOFTENDPOINTDLP` | E5 / E5 Compliance |
| Audit (Premium) | `M365_ADVANCED_AUDITING` | E5 / E5 Compliance |
| Insider Risk Management | `INSIDER_RISK` | E5 / E5 Compliance / IRM add-on |
| Communication Compliance | `COMMUNICATIONS_COMPLIANCE`, `MICROSOFT_COMMUNICATION_COMPLIANCE` | E5 / E5 Compliance |
| Records / retention (advanced) | `RECORDS_MANAGEMENT`, `INFO_GOVERNANCE` | E5 Compliance |
| Defender for Cloud Apps | `ADALLOM_S_STANDALONE` (full), `ADALLOM_S_O365` (O365 only, no shadow-AI discovery) | E5 Security, EMS E5 |
| SharePoint Advanced Management | `SHAREPOINT_ADVANCED_MANAGEMENT` [verify]; rights included with Microsoft 365 Copilot [verify] | SAM add-on / Copilot |
| Power Platform Managed Environments | — (premium per-user/app licences) | Power Apps/Automate premium, Copilot Studio |

## Tenant-wide Entra compliance rules (advisory)

Microsoft's guidance: users who **benefit** from a premium Entra feature should be licensed for it, even though
the tenant technically enables the feature for everyone once one licence exists.

| Rule ID | Feature in use (evidence) | Users benefiting | Licence required | Gap calculation |
|---|---|---|---|---|
| LIC-ENT-01 | Enabled CA policy with `includeUsers` = All | Enabled member users (minus excluded) | Entra ID P1 | benefiting − P1-licensed enabled members |
| LIC-ENT-02 | CA with sign-in/user risk conditions, or risky user data present | Users in scope of risk policies | Entra ID P2 | in-scope − P2-licensed |
| LIC-ENT-03 | PIM eligible / time-bound assignments | Distinct principals with eligible assignments + approvers | Entra ID P2 or Governance | principals − (P2 + Governance) licensed |
| LIC-ENT-04 | Access review definitions | Reviewed users (members) | Entra ID P2 or Governance | estimate; guests via MAU billing (needs Azure subscription link) |
| LIC-ENT-05 | Access packages | Users requesting/assigned | Entra ID P2 or Governance | estimate |
| LIC-ENT-06 | CA policies including `clientApplications` (workload identities) | Targeted service principals | Workload Identities Premium | targeted SPs − Workload ID licences |
| LIC-ENT-07 | Guests in scope of P1/P2 features | Guest MAU | External ID MAU billing (first 50,000 MAU free [verify]) | Report "Check Azure subscription link for External ID billing" |
| LIC-COP-01 | Microsoft 365 Copilot assigned | Copilot users | Prerequisite base licence (M365/O365 E3/E5/Business etc.) | Copilot users lacking a qualifying base licence |
| LIC-PUR-01 | Auto-labelling / DLP for Copilot / IRM / Comm Compliance policies found | Users in policy scope | E5 / E5 Compliance plan | in-scope − licensed |
| LIC-SKU-01 | Any SKU | — | — | consumedUnits > prepaidUnits.enabled → over-assigned; warning/suspended units → expiring |

Statuses: **Compliant (indicative)**, **Potential gap — N users**, **Unable to determine** (with reason).

## Required caveat (verbatim in both documents)
"This licensing analysis is advisory and indicative only. It is based on configuration data read at the
time of assessment and Microsoft's published licensing guidance, and is not a legal licensing determination.
Confirm with your Microsoft licensing partner or the current Microsoft Product Terms."
