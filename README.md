# Tenant AI Security Assessment

A Cowork skill for assessing a Microsoft 365 / Microsoft Entra ID tenant's readiness for secure AI adoption, including Microsoft 365 Copilot, Copilot Studio agents and third-party AI apps.

The assessment uses an AI-relevant subset of the **CIS Microsoft 365 Foundations Benchmark v7.0.0** and maps findings to **CIS Critical Security Controls v8.1** safeguards and Implementation Groups. Microsoft Zero Trust for Copilot is an optional secondary cross-reference, off by default.

**Tenant collection is read-only.** The workflow requires explicit consent and confirmation that the operator is authorised to assess the target tenant. It does not change configuration, perform penetration testing or execute remediation.

## What it assesses

| Area | Examples |
| --- | --- |
| Identity and privileged access | Conditional Access, MFA, authentication methods, legacy authentication, Global Administrators and PIM |
| Apps and consent | User consent, admin consent workflows, app credential policies, high-risk Graph permissions and third-party AI apps |
| External collaboration | Guest access, invitations and cross-tenant defaults |
| Data protection | SharePoint/OneDrive sharing, sensitivity labels, DLP, Copilot DLP, audit and retention |
| AI governance | Shadow AI, Safe Links, Teams recording policies, Power Platform DLP and Azure OpenAI exposure |
| Licensing | SKU inventory, service plans, indicative Entra entitlement gaps and implementable-now versus upgrade requirements |

Some checks require optional service modules or manual verification. Unsupported, inaccessible or missing evidence must remain **Not assessed** with a reason; uncertain benchmark mappings retain **[verify]** markers.

## Deliverables

The collectors and offline analyser produce:

- `raw/`: JSON evidence and `collection-log.json`.
- `findings.json`: control status, evidence, risk, recommendations, licensing requirements and CIS mappings.
- `licensing.json`: licence inventory and indicative entitlement analysis.
- `cis_scores.json`: scores by level and section, safeguard coverage, remediation order and mappings requiring verification.

The complete skill workflow then uses the **docx** and **pptx** skills to build:

| Deliverable | File name |
| --- | --- |
| Technical findings report | `<Org>-AI-Security-Technical-Findings-<YYYY-MM-DD>.docx` |
| Executive briefing paper | `<Org>-AI-Adoption-Executive-Briefing-<YYYY-MM-DD>.docx` |
| Combined branded deck, 20-25 slides | `<Org>-AI-Security-Assessment-Deck-<YYYY-MM-DD>.pptx` |

**The scripts do not generate Word or PowerPoint files themselves.** Document generation requires an environment with those skills available, using [report-outlines.md](report-outlines.md), [branding.md](branding.md) and the bundled [brand-template.potx](brand-template.potx).

Reports use en-NZ spelling, NZ date formatting and Pacific/Auckland time. Output names and locations are confirmed with the user; OneDrive delivery is opt-in.

## Prerequisites

Use an account authorised for the target tenant with **Global Reader + Security Reader**, and the appropriate read roles for any optional services, including Purview. Delegated scopes may require administrator consent.

For the recommended PowerShell collection route, install `Microsoft.Graph.Authentication` on the operator's machine:

```powershell
Install-Module Microsoft.Graph.Authentication -Scope CurrentUser
```

The optional collectors require the corresponding modules:

| Collection option | Module / requirement |
| --- | --- |
| `-IncludeExchange` | `ExchangeOnlineManagement` |
| `-IncludePurview` | `ExchangeOnlineManagement` and a Purview read role |
| `-IncludeSharePoint` | `Microsoft.Online.SharePoint.PowerShell` and `-SharePointAdminUrl` |
| `-IncludePowerPlatform` | `Microsoft.PowerApps.Administration.PowerShell` |
| `-IncludeTeams` | `MicrosoftTeams` |
| `-AzureSubscriptionId` | `Az.Accounts` and `Az.CognitiveServices` |

Use Python 3 for offline analysis; `analyse_findings.py` uses the standard library. The alternative Graph collector depends on `msal` and `requests`, but see its current limitation below.

## Quick start

### 1. Confirm scope and consent

Before signing in, follow [SKILL.md](SKILL.md) to confirm the tenant, organisation and assessor, exact requested scopes, authorised access, optional modules, output location and consent.

The user must explicitly choose the CIS licence profile (**E3** or **E5**), levels (**L1** or **L1 and L2**) and confirm benchmark version **v7.0.0**. Do not infer these choices from the examples below.

In Cowork, start with a request such as:

> Assess our Microsoft 365 tenant for secure AI use and prepare the technical report, executive briefing and branded deck.

### 2. Collect evidence on the operator's machine

From the repository root, after consent:

```powershell
./Invoke-TenantAiAssessment.ps1 `
  -TenantId contoso.onmicrosoft.com `
  -OutputPath ./assessment
```

Replace the example domain with the confirmed tenant ID or primary domain. The user signs in interactively using device code. If device-code authentication is blocked, add `-UseBrowser`.

Add only the service switches the user approved. Each optional service requires separate authentication, and the skill must re-confirm before that sign-in. Collection writes to `./assessment/raw/`; review `collection-log.json` for failed or unavailable calls.

### 3. Analyse the collected evidence

For a user who confirmed **E3** and **L1 only**:

```bash
python analyse_findings.py \
  --raw ./assessment/raw \
  --out ./assessment \
  --cis-licence-profile E3 \
  --cis-levels L1
```

Use `E5` and/or `L1L2` only if the user selected them. The analyser defaults to the root-level `cis-mapping.json`; pass `--cis-map <path>` only when using a different mapping file.

The analyser runs offline and writes the three JSON outputs. Review findings, collection failures and all `[verify]` entries before building the reports.

### 4. Build and deliver the reports

Follow the reporting steps in [SKILL.md](SKILL.md): build both Word documents first, then the combined deck using the bundled template. Include score scope, verification items and the licensing caveat in all three deliverables.

Mark the documents **Sensitive - security assessment** and ask the user to apply their organisation's correct Microsoft Purview sensitivity label. Neither the skill nor the bundled template applies a label automatically.

## Repository guide

| File | Purpose |
| --- | --- |
| [SKILL.md](SKILL.md) | Skill instructions, consent workflow, authentication, reporting and guardrails |
| [Invoke-TenantAiAssessment.ps1](Invoke-TenantAiAssessment.ps1) | Graph evidence collector with optional service collectors |
| [collect_graph.py](collect_graph.py) | Alternative device-code collector for core Microsoft Graph evidence |
| [analyse_findings.py](analyse_findings.py) | Offline findings, licensing and CIS scoring |
| [checks-catalogue.md](checks-catalogue.md) | Checks, evidence sources, pass criteria and mappings |
| [cis-mapping.json](cis-mapping.json) | Machine-readable benchmark and safeguard mappings |
| [cis-benchmark.md](cis-benchmark.md) | Benchmark scope, scoring method and verification rules |
| [licensing-map.md](licensing-map.md) | Licence requirements and advisory guidance |
| [report-outlines.md](report-outlines.md) | Technical report, executive briefing and deck outlines |
| [branding.md](branding.md) / [brand-template.potx](brand-template.potx) | Deck branding and layout guidance |

## Limitations and data handling

**Current layout:** files are stored at the repository root. Run scripts from this directory; this README does not provide a one-click Cowork installer.

**Python collector:** `collect_graph.py` supports core Microsoft Graph evidence collection using interactive device-code sign-in. Optional Exchange, Purview, SharePoint, Power Platform, Teams and Azure evidence is collected only by the PowerShell script.

**Scoring:** CIS percentages cover applicable, assessed recommendations in this AI-readiness subset, not the full benchmark. `Partial` counts as not passed; `Not assessed` is excluded from the percentage and reported separately. IG coverage includes all assessed checks, including supplementary and L2 checks even when only L1 is scored. These results are not CIS certification or a declaration of full compliance.

**Evidence:** configuration exports and reports can contain tenant identifiers, account identifiers, role assignments and policy details. Treat both collected evidence and the JSON files already in this repository as potentially sensitive, not as guaranteed anonymised fixtures. Keep new assessment outputs in an approved, access-controlled location; do not commit them or share them publicly. Never paste passwords, client secrets or tokens into chat or reports.

**Licensing:** include this caveat verbatim in all three reports:

> This licensing analysis is advisory and indicative only. It is based on configuration data read at the time of assessment and Microsoft's published licensing guidance, and is not a legal licensing determination. Confirm with your Microsoft licensing partner or the current Microsoft Product Terms.

**CIS and usage terms:** CIS Benchmarks and CIS Controls belong to Center for Internet Security, Inc. This project references recommendation IDs and short titles and paraphrases intent; the licensed benchmark is authoritative. Confirm all `[verify]` mappings against it. `SKILL.md` declares **Proprietary - personal use**; do not assume an open-source licence.
