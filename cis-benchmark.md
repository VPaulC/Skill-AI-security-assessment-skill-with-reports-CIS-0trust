# CIS Benchmark Reference — how this skill uses CIS

## Terms of use (include in both Word documents and the deck appendix)
CIS Benchmarks™ and CIS Critical Security Controls® are © Center for Internet Security, Inc. They are used
here for reference under CIS's terms of use. This skill **cites recommendation IDs and short titles and
paraphrases intent**; it never reproduces CIS benchmark text, audit or remediation procedures. The licensed
benchmark document is the authority. Where a mapping is uncertain it is marked **[verify]**.

## Layer 1 — CIS Microsoft 365 Foundations Benchmark (configuration benchmark, authoritative)
- **Version in use: v7.0.0** (released 19 May 2026). v7.0.0 removed the (L1)/(L2) tags from titles (the
  profile now sits under each recommendation's Profile Applicability) and introduced Global Recommendation IDs
  (GRIDs) alongside the numbered IDs. This skill cites the numbered ID; GRIDs are not recorded [verify if needed].
- **At run time, confirm the version with the user** (Step 1). If the user names a different version, do not
  re-map silently: tell them the mapping is for v7.0.0 and mark every ID "[verify]" in the outputs.
- Sections: 1 Microsoft 365 admin centre · 2 Microsoft 365 Defender · 3 Microsoft Purview · 4 Microsoft Intune
  admin centre · 5 Microsoft Entra admin centre · 6 Exchange admin centre · 7 SharePoint admin centre ·
  8 Microsoft Teams admin centre · 9 Microsoft Fabric.
- **Profiles:** `E3 L1`, `E3 L2`, `E5 L1`, `E5 L2`. E3 recommendations also apply to E5 tenants; E5
  recommendations apply only when the user confirms the E5 profile. L1 = essential baseline with low business
  impact; L2 = defence in depth, may reduce functionality.
- **Assessment status:** each recommendation is Automated or Manual in CIS's own terms (distinct from how this
  skill evaluates it — see the "Eval" column in the catalogue).
- Profile/ID sources used to build the mapping: Tenable's published v7.0.0 audit item lists for L1 E3, L1 E5,
  L2 E3 and L2 E5 (partially visible) and public v7.0.0 change summaries. Anything not confirmed there carries
  [verify].

## Layer 2 — CIS Critical Security Controls v8.1
Every finding carries one primary safeguard and its **lowest Implementation Group** (IG1 safeguards are
also part of IG2 and IG3). IG1 = "essential cyber hygiene". Safeguards used (titles paraphrased):

| Safeguard | Short title | IG |
|---|---|---|
| 2.1 | Software inventory | IG1 |
| 2.3 | Address unauthorised software | IG1 |
| 2.5 | Allowlist authorised software | IG2 |
| 3.2 | Data inventory | IG1 |
| 3.3 | Data access control lists | IG1 |
| 3.4 | Data retention | IG1 |
| 3.7 | Data classification scheme | IG2 |
| 3.13 | Data loss prevention | IG3 |
| 3.14 | Log sensitive data access | IG3 |
| 4.1 | Secure configuration process | IG1 |
| 4.3 | Automatic session locking | IG1 |
| 4.8 | Uninstall/disable unnecessary services | IG2 |
| 5.3 | Disable dormant accounts | IG1 |
| 5.4 | Restrict admin privileges to dedicated admin accounts | IG1 |
| 5.5 | Inventory of service accounts | IG2 |
| 6.1 | Access granting process | IG1 |
| 6.2 | Access revoking process | IG1 |
| 6.3 | MFA for externally-exposed applications | IG1 |
| 6.5 | MFA for administrative access | IG1 |
| 6.7 | Centralise access control | IG2 |
| 8.2 | Collect audit logs | IG1 |
| 8.11 | Audit log reviews | IG2 |
| 9.3 | Network-based URL filters | IG2 |
| 12.2 | Secure network architecture | IG2 |
| 13.1 | Centralise security event alerting | IG2 |

Many safeguard mappings are this skill's judgement of the *nearest* safeguard and are marked [verify]; the
licensed benchmark lists CIS's own Controls mapping per recommendation — prefer that when available.

### CIS AI companion guidance (verified to exist, published by CIS)
Reference these by name only, for AI-specific (Supplementary) findings — do not quote them:
- *CIS Controls v8.1 — Artificial Intelligence and Large Language Models Companion Guide* (20 April 2026).
- *CIS Controls v8.1 — AI Agents Companion Guide* (20 April 2026) — relevant to Copilot agents / Copilot Studio.
- *CIS Controls v8.1 — Model Context Protocol (MCP) Companion Guide* (20 April 2026).
- *CIS Controls v8.1.2 AI Security Guidance Workbook* (27 July 2026).

## Scoring (computed by `analyse_findings.py` → `cis_scores.json`; never re-tally by hand)
- **Inputs the user must choose at launch:** licence profile (`--cis-licence-profile E3|E5`) and levels to
  score (`--cis-levels L1|L1L2`). Both are required; the script refuses to run without them.
- **CIS M365 compliance %** = recommendations passed ÷ recommendations *applicable and assessed*, reported
  for L1, for L2 (only if chosen) and per benchmark section. A recommendation passes only if every check
  mapped to it is Pass; **Partial counts as not passed**; **Not assessed is excluded** from the denominator
  and listed separately; E5-profile items on an E3 tenant and L2 items when only L1 was chosen are "not scored"
  but still reported as findings.
- **CIS Controls IG coverage** = safeguards met ÷ safeguards assessed, per IG (a safeguard is met only if every
  assessed check mapped to it passes). IG1 is the headline. **IG coverage always includes every assessed
  check — Supplementary checks and CIS Level 2 checks included — even when the user chose to score Level 1
  only.** The level choice changes the CIS M365 % only, never the IG figures. Say this beside the IG numbers.
- **Scope caveat (always state it):** scores cover the CIS recommendations this AI-readiness assessment
  evaluates — a subset of the full benchmark — not a full CIS audit or certification.
- **Remediation order:** CIS L1 → CIS L2 (in scope) → Supplementary (AI-specific) → L2 outside chosen scope →
  E5-profile items needing a licence upgrade; within each tier by risk (Critical → Low) then effort.

## Showing [verify] items (the user has no licensed v7.0.0 document)
`cis_scores.json.verify_items` lists every finding whose CIS ID, profile, assessment status or safeguard is
unconfirmed. Every deliverable must make these visible for manual checking:
- keep the literal "[verify]" text in every table cell where it appears, styled bold amber;
- technical report: an appendix table "Mappings requiring manual verification" (finding ID, CIS ID, fields to
  verify, what to check) and a sentence in Scope and method giving the count;
- executive briefing: one footnote giving the count and pointing to that appendix;
- deck: an appendix slide listing them.
Never drop a [verify] marker or present a [verify] mapping as confirmed.

## Minimum bar for wider AI adoption (exec briefing wording)
Meeting **CIS M365 Level 1** (in the confirmed licence profile) **and CIS Controls IG1** for the areas assessed
is the minimum prerequisite before wider AI adoption. State the current % against both.
