# Report Outlines (pass to the docx and pptx skills)

Common: en-NZ spelling; NZ date format (e.g. 5 November 2026); header "Sensitive — security assessment";
footer with organisation name, document title, page X of Y; Calibri/Aptos 11pt; tables with a header row;
status colours (status marks only; all other styling uses the theme) — Pass green, Partial amber, Fail red, Not assessed grey; risk colours — Critical dark red,
High red, Medium amber, Low green, Info blue. Every CIS number quoted comes from `cis_scores.json` — never
re-tallied by hand. Include the CIS terms-of-use note from [cis-benchmark.md](cis-benchmark.md) and the
scope caveat (scores cover the CIS recommendations assessed, not a full CIS audit). Keep every "[verify]"
marker visible (bold amber) and list all of them for manual checking — see "Showing [verify] items" in
cis-benchmark.md. State beside IG figures that IG coverage includes every assessed check (L2 included).

## A. Technical Findings Report (for the security professional)
Title: "<Organisation> — Secure AI Use: Technical Security Assessment against CIS Benchmarks"

1. **Document control** — version, date, assessor, tenant ID/domain, classification, CIS benchmark version
   and licence profile / levels the user chose.
2. **Executive summary** — posture rating (Red/Amber/Green), CIS L1 % (and L2 % if scored), IG1 coverage %,
   counts by status and risk, top 5 risks, headline licensing position (½ page).
3. **Scope and method** — tenant, date/time (NZ time), sign-in account role, scopes granted/declined, modules
   used, read-only statement ("No configuration changes were made"), CIS M365 Benchmark v7.0.0 + CIS Controls
   v8.1 as the benchmark, Zero Trust for Copilot cross-reference only if chosen, limitations (manual checks,
   Not assessed items and why, [verify] mappings).
4. **CIS benchmark summary** —
   - Score table: L1 / L2 (if chosen) — applicable assessed, passed, not passed, not assessed, % passed.
   - Scores by benchmark section (1–9) and level, with a bar chart.
   - CIS Controls v8.1: IG1 (headline), IG2, IG3 safeguards met / assessed; safeguard table (safeguard, title,
     IG, checks, met).
   - Table of **all assessed CIS recommendations**: CIS ID, title, profile, CIS assessment status, section,
     status (Pass/Fail/Partial/Not assessed/not scored), finding ID(s), risk.
5. **Tenant and licence overview** — organisation details, user counts, SKU table, key capabilities.
6. **Findings summary table** — ID | Area | Control | Status | Risk | CIS M365 Benchmark ID | CIS Profile level |
   CIS Controls v8.1 safeguard | IG | Licence required | Effort. Sorted by the CIS remediation order.
7. **Detailed findings** — one sub-section per Fail/Partial (and High-risk Not assessed): control and why it
   matters for AI; evidence; recommendation; remediation steps (portal path, then a PowerShell/Graph example
   labelled "Example — review and test before running; deploy in report-only mode first"); licence required
   and whether held; effort; CIS M365 ID, profile, safeguard, IG (and Zero Trust reference if chosen);
   validation step.
8. **Licensing compliance** — implementable-now vs requires-upgrade; tenant-wide Entra compliance table;
   over-assignment/unused; caveat (verbatim).
9. **Prioritised remediation roadmap** — ordered by `cis_scores.json.remediation_order`: CIS L1 first, then
   L2, then Supplementary, then E5-profile upgrade items; risk shown beside each. Also bucket as Quick wins
   (≤2 weeks) / 30 days / 90 days with finding IDs, owner role, dependency, licence.
10. **Appendix A — Raw check results** (ID, status, evidence, data source, collection status).
11. **Appendix B — CIS mapping** — finding ID → CIS M365 ID/title/profile → CIS Controls safeguard/IG
    (→ Zero Trust for Copilot reference only if the user opted in). CIS terms-of-use note.
12. **Appendix C — Permanent Global Administrators** (UPNs) and break-glass recommendation.
13. **Appendix D — Mappings requiring manual verification** — every `verify_items` entry: finding ID, CIS ID,
    fields to verify (ID / profile / assessment status / safeguard), what to check in the licensed benchmark.

## B. Executive Briefing Paper (~2–4 pages, plain language, no jargon)
Title: "Preparing <Organisation> for Wider AI Adoption — Executive Briefing"

1. **Purpose** (2–3 sentences).
2. **Bottom line** — posture rating (Red/Amber/Green); **"X% of the CIS Level 1 baseline assessed is met"**
   (and L2 if chosen) and **IG1 coverage Y%**; "ready / ready with conditions / not ready". State plainly:
   **meeting CIS Level 1 and CIS Controls IG1 is the minimum prerequisite before wider AI adoption.**
3. **What we found** — 3–5 key risks in business terms, each with impact and likelihood and its CIS ID.
4. **Must-do before scaling AI** — numbered prerequisites, led by the outstanding CIS L1 items.
5. **Licensing and investment implications** — what current licences allow, what needs upgrade (incl. E5-only
   CIS items), indicative compliance position, caveat (verbatim). No prices unless the user supplies them.
6. **Recommended decisions** — 3–5 decisions (approve, fund, assign owner).
7. **Timeline** — Now (0–2 weeks), 30 days, 90 days, then the AI rollout gate (CIS L1 + IG1 met).
8. **Next steps and contacts.** CIS terms-of-use note as a footnote, plus a footnote: "N CIS mappings are
   marked [verify] and listed in the technical report, Appendix D." 

## C. Combined PowerPoint deck (third deliverable — after both Word documents are complete)
Built with the **pptx skill** on the bundled template `brand-template.potx` (see
[branding.md](branding.md) for the theme and the slide-type → layout mapping): use its masters, layouts and
theme only. **Full deck, 20–25 slides**, covering both
documents in detail, executive-readable, one message per slide, speaker notes carrying the detail.
File name: `<Org>-AI-Security-Assessment-Deck-<YYYY-MM-DD>.pptx`.

Suggested structure (adapt counts to the findings; stay within 20–25):
1. Title (organisation, date, "Sensitive — security assessment").
2. Agenda.
3. Purpose, scope and method (read-only; CIS M365 v7.0.0 + CIS Controls v8.1).
4. Executive summary — RAG posture and the bottom line.
5. CIS M365 scores — L1 / L2 (chart).
6. CIS scores by benchmark section (bar chart).
7. CIS Controls v8.1 — IG1/IG2/IG3 coverage (chart) and "CIS L1 + IG1 is the minimum bar for AI".
8. Top 5 risks (business terms + CIS IDs).
9. AI readiness prerequisites (must-do before scaling AI).
10–15. **Key findings by area** — one slide each: Identity & Conditional Access; Authentication methods &
    privileged access; Apps, consent & AI apps; External collaboration; Data protection (SharePoint/OneDrive
    oversharing, labels, DLP, audit); AI governance (Copilot DLP, agents, shadow AI, Exchange/Teams add-ins).
    Each: status counts, worst findings, CIS IDs, fix.
16. Entra tenant-wide licence compliance (table) + caveat.
17. Licensing implications — implement now vs upgrade.
18. Remediation roadmap — quick wins (≤2 weeks).
19. Remediation roadmap — 30 and 90 days (ordered CIS L1 → L2).
20. Decisions required.
21. Next steps and timeline (AI rollout gate).
22. Appendix — full CIS recommendation pass/fail table, [verify] markers visible (split across slides if needed).
23. Appendix — Not assessed items and manual checks.
24. Appendix — mappings requiring manual verification ([verify] list), CIS terms of use, licensing caveat.
25. Closing logo slide.
