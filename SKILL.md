---
name: tenant-ai-security-assessment
description: |
  Runs a read-only security assessment of a Microsoft 365 / Entra ID tenant for
  secure AI use (Copilot, agents, shadow AI), benchmarked against the CIS
  Microsoft 365 Foundations Benchmark and CIS Controls v8.1. Shows the plan and
  asks consent first, then produces a technical Word report, an executive
  briefing and a branded PowerPoint deck with CIS scores. Use when the user asks
  to "assess my tenant for secure AI use", "run a CIS benchmark check before
  Copilot", "check if our tenant is ready for AI", or "audit Entra licensing
  compliance for Copilot". Do NOT use for making configuration changes,
  penetration testing or attack simulation, or general Copilot licensing
  questions with no tenant to assess.
license: Proprietary - personal use
compatibility: Needs interactive sign-in to the target tenant (Microsoft Graph PowerShell or Python + msal) with read-only delegated scopes; the docx and pptx skills build the Word and PowerPoint deliverables.
metadata:
  category: analysis
  icon: ShieldCheckmark
  author: Paul Caldwell
  locale: en-NZ
---

# Tenant AI Security Assessment (CIS-benchmarked)

## Overview
Assesses whether a Microsoft 365 tenant has the identity, data-protection and governance controls needed for
**secure AI use** (Microsoft 365 Copilot, Copilot Studio agents, third-party AI apps), using **CIS as the
primary and authoritative benchmark**:
- **CIS Microsoft 365 Foundations Benchmark v7.0.0** — every configuration check carries its CIS
  recommendation ID, title, profile (E3/E5, L1/L2) and CIS Automated/Manual status.
- **CIS Critical Security Controls v8.1** — every finding maps to a safeguard and Implementation Group (IG1 =
  essential cyber hygiene).
- AI-specific checks with no CIS M365 equivalent are marked *Supplementary – no direct CIS M365
  recommendation* and mapped to the nearest CIS Controls safeguard.
- Microsoft Zero Trust for Copilot is the only optional secondary cross-reference (off by default).

Every test is **benign and read-only** — GET requests and `Get-*` cmdlets only. Deliverables:
1. `findings.json`, `licensing.json`, `cis_scores.json`.
2. **Technical findings report** (.docx) for a security professional to implement.
3. **Executive briefing paper** (.docx) — posture against CIS and what is required before wider AI adoption.
4. **Combined PowerPoint deck** (.pptx, 20–25 slides) built from both documents on the branding template.
5. An inline chat summary of CIS scores and top risks.

All outputs use **en-NZ spelling** (organisation, licence (noun) / license (verb), prioritise, analyse,
behaviour, programme) and NZ date format (5 November 2026), with times in NZ time (Pacific/Auckland).

## When to Use
- "Assess my tenant / customer tenant for secure AI use", "CIS benchmark check before Copilot rollout"
- "Are we ready to roll out Copilot more widely?" with a tenant to inspect
- "Check our Entra licensing compliance for Conditional Access / PIM / Identity Protection"
- "Produce a security findings report, an exec briefing and a deck on AI adoption"

## When NOT to Use
- Changing configuration, creating policies, users or apps — this skill never writes to a tenant.
- Penetration testing, phishing/attack simulation, password spraying, or any active exploitation.
- General Copilot licensing or feature questions with no tenant to assess — answer directly.
- A full CIS certification audit of every benchmark recommendation — this covers the AI-relevant subset.
- Building a Purview deployment repo or pipeline — use `purview-deployment-gh` instead.
- A generic Word document or deck unrelated to an assessment — use the `docx` / `pptx` skill directly.

## Core rule: ask, never assume
Whenever anything material is ambiguous or uncertain — tenant identity, scope, CIS benchmark version,
licence profile or levels, licence interpretation, missing evidence, template choice, output names or
locations — **ask the user with `AskUserQuestion`** before acting. Never fill a gap with an assumed value.
Anything that cannot be verified from evidence is recorded **Not assessed** (with the reason) or marked
**[verify]** — never inferred. An empty or unclear answer is not consent and not a choice: ask again or stop.

## Quick Start
```
User: "Assess contoso.onmicrosoft.com for secure AI use"
1. Create the progress task list; gather facts (Step 0)
2. Show the plan and get explicit consent + CIS choices via AskUserQuestion (Step 1) — no consent = stop
3. User signs in interactively with read-only scopes (Step 2)
4. Collectors → raw/*.json (Step 3) → analyser → findings/licensing/cis_scores (Steps 4–5), chart shown
5. Two Word documents (Step 6) → combined branded deck (Step 7), previews shown as each is built
6. Inline summary with CIS L1/L2 % and IG1 coverage (Step 8)
```

## Core Instructions

### Step 0: Progress tracking (whole run)
Create a visible task list with `TaskCreate` at the start (one task per step below) and keep it current with
`TaskUpdate` (in progress → done / blocked with reason). Show visual progress wherever the environment allows:
- **Phase charts:** after Step 4, show a `render_ui` card (load the `render-ui` skill first) with CIS L1/L2
  % bars, scores by section and IG1/IG2/IG3 coverage — numbers taken from `cis_scores.json` only.
- **Document previews:** after each Word document and the deck is built, render page/slide images with
  `RenderArtifact` (title page, CIS summary, a findings page; deck title, scores, roadmap slides) and show them.
  Fix any `qa_status` fail before moving on.
- **Sign-in screenshots:** if sign-in runs in a browser the session can see (e.g. via the browser tool),
  show a screenshot of the sign-in prompt — never of passwords, codes being typed, or tokens.
- If screenshots or rendering are not available, say so once and continue with text progress updates.

### Step 1: Plan, consent and choices (always first — before any sign-in or check)
Collect the facts, then **show the plan in chat** and ask for consent with `AskUserQuestion`. Never guess
the tenant; ask for anything missing. The plan must state:
- **Target tenant** (ID or primary domain), organisation name for the reports, assessor name.
- **Sign-in method**: interactive device code (or browser if the tenant blocks device code — CIS 5.2.2.12),
  performed by the user; the account needs Global Reader + Security Reader (and a Purview read role for
  compliance cmdlets).
- **Exact read-only scopes** (the Step 2 list, including RoleManagementPolicy.Read.Directory and
  OrgSettings-AppsAndServices.Read.All) and any optional modules (Exchange incl. Safe Links, Purview,
  SharePoint, Power Platform, Azure subscription, Teams) — each module is a separate sign-in.
- **Check areas** (Step 3 list) and that **nothing will be changed** in the tenant.
- **Data collected**: configuration settings, policy names, counts, licence data; Global Administrator UPNs
  only for the appendix; no passwords, secrets or tokens are stored.
- **Outputs and where they go**: two Word documents and one PowerPoint deck in `output/` (ask whether to also
  save to OneDrive, and confirm file names), plus the JSON evidence.

Ask in the same `AskUserQuestion` call:
1. **Consent** — "Proceed with this read-only assessment?" (Proceed / Stop). Stop, or an empty answer = stop
   and say nothing was run. Also require confirmation that they are **authorised** to assess this tenant.
2. **CIS levels to score** — *Level 1 only* or *Level 1 and Level 2* (ask every run; never default).
3. **CIS licence profile** — E3 or E5 (offer a hint from SKUs only after sign-in; if unknown now, ask again
   after Step 3 before running the analyser).
4. **Optional modules** (multi-select) and **Zero Trust for Copilot cross-reference** (include / omit).
5. **CIS version** — confirm v7.0.0. If the user names another version, warn that IDs are mapped to v7.0.0
   and mark them all [verify].

**Re-confirm before every additional sign-in** (Exchange, Purview, SharePoint, Power Platform, Azure, Teams)
with a short `AskUserQuestion` naming the module, its cmdlets and that they are read-only.

If the user's **own connected M365 tenant** is the target, the session's read tools (`graph-QueryGraph`,
`ExecuteSql`) may be used for Graph GET calls instead of a fresh sign-in — still read-only, still after
consent. Save each response into `raw/<check-file>.json` using the catalogue file names.

### Step 2: Authenticate interactively (read-only scopes only)
Preferred (runs on the user's machine): PowerShell —
`./Invoke-TenantAiAssessment.ps1 -TenantId <id> -OutputPath <dir> [-IncludeExchange] [-IncludePurview] [-IncludeSharePoint -SharePointAdminUrl <url>] [-IncludePowerPlatform] [-IncludeTeams] [-AzureSubscriptionId <id>] [-UseBrowser]`.
Each `-Include*` switch is a separate sign-in and runs only after the user confirmed that module (Step 1).
`-IncludeExchange` also reads Safe Links (CIS 2.1.1); `-IncludeTeams` connects the MicrosoftTeams module and
runs `Get-CsTeamsMeetingPolicy` (CIS 8.5.9) — read-only.
It calls `Connect-MgGraph -TenantId <id> -Scopes <read-only list> -UseDeviceCode` (or browser with
`-UseBrowser`), so the **user signs in themselves**. Alternative: `python collect_graph.py --tenant <id> --out <dir>`
(msal device-code flow).

Read-only scopes requested (never request `*.ReadWrite.*`):
`Directory.Read.All, Policy.Read.All, Organization.Read.All, Reports.Read.All, AuditLog.Read.All,
SecurityEvents.Read.All, RoleManagement.Read.Directory, Application.Read.All, IdentityRiskyUser.Read.All,
AccessReview.Read.All, EntitlementManagement.Read.All, InformationProtectionPolicy.Read,
SharePointTenantSettings.Read.All, UserAuthenticationMethod.Read.All, RoleManagementPolicy.Read.Directory,
OrgSettings-AppsAndServices.Read.All [verify scope name]`. List these exact scopes in the Step 1 plan.

Relay the device code / sign-in prompt to the user and wait. Do **not** ask the user to paste passwords,
client secrets or tokens into chat. If a scope is declined or admin consent is required, continue with what
was granted and mark the dependent checks **Not assessed** with the reason.

### Step 3: Collect evidence (benign tests)
The collectors write one JSON file per endpoint/cmdlet to `<out>/raw/` plus `collection-log.json`. The full
check list — endpoints, cmdlets, CIS IDs, profiles, paraphrased pass criteria, licences and CIS Controls
safeguards — is in [checks-catalogue.md](checks-catalogue.md); the machine mapping is
[cis-mapping.json](cis-mapping.json). Areas:
- **Entra ID identity** — CIS 5.2.2.x Conditional Access (MFA all users/admins, phishing-resistant admin
  strength, legacy auth, managed devices, risk policies, sign-in frequency, device code / authentication
  transfer), CIS 5.2.3.x authentication methods, CIS 1.1.x / 5.3.x privileged access, PIM approval (5.3.4), break-glass accounts
  (1.1.2 — ask the user which accounts they are), non-admin tenant creation (5.1.2.3), access reviews.
- **Apps and consent** — CIS 5.1.5.x user consent, admin consent workflow, app credential policy; CIS 5.1.2.2
  app registration; high-risk Graph permissions and third-party AI apps (Supplementary).
- **External collaboration** — CIS 5.1.6.x guest invitations and access; cross-tenant defaults.
- **Copilot data readiness** — CIS 7.2.x SharePoint/OneDrive sharing; CIS 3.3.1 labels; CIS 3.2.x DLP incl.
  **3.2.3 DLP for Copilot**; CIS 3.1.1 / 6.1.1 audit; RSS/RCD, SAM, DSPM for AI, retention, Insider Risk,
  Communication Compliance (Supplementary).
- **AI app and agent governance** — CIS 2.4.3 Defender for Cloud Apps (shadow AI), 2.1.1 Safe Links, 1.3.4 / 1.3.7 / 6.3.1 /
  6.5.3 add-ins and third-party storage, 8.4.1 / 8.5.9 Teams apps and recordings; Copilot agents, web grounding,
  Power Platform DLP, Azure OpenAI exposure (Supplementary). Reference the CIS AI companion guides by name
  (see [cis-benchmark.md](cis-benchmark.md)).

Settings with no read API are recorded **Not assessed — manual verification required** with the admin-centre path.

### Step 4: Analyse controls → findings.json + cis_scores.json
Run, with the user's Step 1 answers (both CIS options are required — never guess them):
`python analyse_findings.py --raw <out>/raw --out <out> --cis-licence-profile <E3|E5> --cis-levels <L1|L1L2>`.
It writes `findings.json` with exactly these fields per record:

| Field | Values |
|---|---|
| `id` | catalogue ID, e.g. `ENT-CA-01` |
| `area` | Entra ID / Apps & Consent / External Collaboration / Data Protection / AI Governance / Licensing |
| `control` | short control name |
| `status` | `Pass` / `Fail` / `Partial` / `Not assessed` |
| `evidence` | factual summary of what was read — no secrets |
| `risk` | `Critical` / `High` / `Medium` / `Low` / `Info` |
| `recommendation` | what to change and why |
| `licence_required` | e.g. `Entra ID P1`, `Entra ID P2`, `None` |
| `effort` | `Low` / `Medium` / `High` |
| `cis_m365_id` | e.g. `CIS M365 v7.0.0 5.2.2.2 – <title>`, or `Supplementary – no direct CIS M365 recommendation` |
| `cis_profile` | e.g. `E3 L1 · Automated` (`—` for Supplementary) |
| `cis_controls_safeguard` | e.g. `6.3 Require MFA for externally-exposed applications` |
| `implementation_group` | `IG1` / `IG2` / `IG3` |

`cis_scores.json` holds the CIS compliance scores (L1, L2 if chosen, by benchmark section), CIS Controls IG
coverage, the full recommendation table and the remediation order (CIS L1 → L2 → Supplementary → out-of-scope /
E5-upgrade, each by risk). Method: [cis-benchmark.md](cis-benchmark.md). Quote these
numbers; never re-tally. IG coverage counts every assessed check, L2 included, even when only L1 is scored —
say so. `verify_items` lists every [verify] mapping; all deliverables must show them for manual checking.
Then show the Step 0 phase chart.

Review the output: adjust risk for context, and complete any check left `Not assessed` only where real evidence
allows a judgement. Every `Fail`/`Partial` needs a concrete recommendation; every `Not assessed` needs a reason.
If you are unsure how evidence maps to a CIS pass criterion, ask the user or mark it [verify] — never guess.
If the user opted in, add the Zero Trust for Copilot reference from `secondary_refs` in cis-mapping.json.

### Step 5: Licensing analysis and tenant-wide Entra compliance
`analyse_findings.py` also writes `licensing.json` from `subscribedSkus` and user licence assignments, using
[licensing-map.md](licensing-map.md):
1. **Inventory** — per SKU: purchased, assigned, suspended/warning units, key service plans.
2. **Implementable now vs upgrade** — per recommended control: *Implement now*, *Implement for licensed users
   only* or *Requires upgrade: <SKU>* (E5-profile CIS items on an E3 tenant fall here).
3. **Tenant-wide Entra compliance** — users *in scope / benefiting* vs users *licensed*: CA (P1), risk-based
   CA / Identity Protection (P2), PIM (P2/Governance), access reviews / entitlement management (P2/Governance;
   guest MAU), CA for workload identities, Copilot base licences, Purview features.
   Status: *Compliant (indicative)*, *Potential gap — N users*, or *Unable to determine*.
4. Over-assignment (assigned > purchased) and unused licences.
If a licence interpretation is uncertain, ask the user or mark it [verify]; never state it as fact.

**Include this caveat verbatim in all three deliverables:** "This licensing analysis is advisory and indicative
only. It is based on configuration data read at the time of assessment and Microsoft's published licensing
guidance, and is not a legal licensing determination. Confirm with your Microsoft licensing partner or the
current Microsoft Product Terms."

### Step 6: Build the two Word documents (docx skill)
Invoke the **`docx` skill** and give it `findings.json`, `licensing.json`, `cis_scores.json` and the outlines in
[report-outlines.md](report-outlines.md) (sections A and B). File names (confirm with
the user in Step 1): `<Org>-AI-Security-Technical-Findings-<YYYY-MM-DD>.docx` and
`<Org>-AI-Adoption-Executive-Briefing-<YYYY-MM-DD>.docx`.
- **Technical report** — includes the **CIS benchmark summary** (scores by section and level, IG coverage,
  table of all assessed recommendations with pass/fail) and remediation ordered CIS L1 → L2, cross-referenced
  with risk.
- **Executive briefing** — states posture against CIS ("X% of the CIS Level 1 baseline assessed is met",
  IG1 coverage) and that **meeting CIS L1 + IG1 is the minimum prerequisite before wider AI adoption**.
Mark both "Sensitive — security assessment". Include the CIS terms-of-use note. Show page previews (Step 0).
**Sensitivity labels:** the skill applies no Microsoft Purview sensitivity label. When delivering, tell the user
to apply their organisation's correct label to each Word document and the deck; if they ask the skill to label
them, ask which label — never assume one.

### Step 7: Build the combined PowerPoint deck (pptx skill) — after both documents are complete
Invoke the **`pptx` skill** and build a **full 20–25-slide deck** covering both documents in detail (outline C
in report-outlines.md), with charts for the CIS scores, findings by area and the roadmap.
- **Branding:** use the bundled template `brand-template.potx` (it has no content slides) with the
  slide-type → layout mapping in branding.md. The template carries no sensitivity label (see the labelling
  note in Step 6). Red/amber/green are for pass/fail status marks only; everything else uses theme colours. Never fetch the SharePoint original at run time. If the bundled template is missing or
  unreadable, **ask the user** to attach a template or approve a plain unbranded deck — never invent branding.
  See [branding.md](branding.md).
- File name: `<Org>-AI-Security-Assessment-Deck-<YYYY-MM-DD>.pptx`. Show slide previews (Step 0).

### Step 8: Inline chat summary
End with: overall posture rating; CIS L1 % (and L2 % if scored) and IG1 coverage, quoted from
`cis_scores.json` with the scope caveat; counts by status; the **top 5 risks** (ID, CIS ID, risk, one-line fix);
licensing headline; open [verify] items; the three file names; and a reminder to apply the correct
sensitivity label to each file.

## Output
- `findings.json`, `licensing.json`, `cis_scores.json`, `raw/` evidence folder (tokens are never written).
- Two .docx files and one .pptx delivered to `output/` (and OneDrive only if the user asked).
- Chat summary ≤15 lines.

## Guardrails
- **Consent first.** No sign-in, collection or check before explicit consent via `AskUserQuestion`; no or empty
  answer = stop. Re-confirm before every additional module sign-in.
- **Ask, never assume.** Ambiguity goes to the user; unverifiable results are *Not assessed* or [verify].
- **Read-only, always.** Only GET requests and `Get-*` cmdlets. Never create, update or delete anything, never
  run attack simulation, never test credentials. The Python collector refuses non-GET methods.
- **The user authenticates themselves** via device code or browser. Never ask for, display, log or store
  passwords, secrets or tokens; never put them in reports, JSON or screenshots.
- **No fabrication**: if a call fails (403/404/licence missing) mark the check **Not assessed** with the reason;
  never infer a Pass from missing data.
- **CIS content**: CIS Benchmarks and CIS Controls are © Center for Internet Security, used for reference under
  their terms. Cite IDs and short titles and paraphrase; never reproduce benchmark text. Uncertain mappings stay
  "[verify]". Scores cover the assessed subset — never call the tenant "CIS compliant" or "certified".
- **Licensing is advisory** — always include the caveat; say "potential gap", never "non-compliant" as fact.
- **Minimise personal data**: counts and role names, not user lists — except permanent Global Admin UPNs in
  the technical report appendix (needed for remediation).
- Remediation steps are for a human to perform after change approval — never execute them.
- Service plan names, portal paths and CIS mappings change; mark uncertain ones "[verify]" rather than guessing.
