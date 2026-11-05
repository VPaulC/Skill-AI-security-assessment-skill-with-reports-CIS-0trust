# Branding — PowerPoint deck template

## Bundled template (use this by default)
- **File:** `assets/brand-template.potx` (12.0 MB). Built on 5 November 2026 from the user's file "branded .pptx"
  (OneDrive /Documents). Theme name **"MSFT Cloud_Industry Slide Template-16x9"**, 16:9 widescreen
  (13.333 × 7.5 in), 1 slide master, 65 layouts, 1 notes master.
- **Cleaning done:** the one content slide (title "Microsoft Security" with a presenter name) and the document
  thumbnail were removed; author / last-modified-by were blanked and the title set to "Brand template (layouts
  only)"; slide counts and slide titles were removed from document properties. A scan of every XML part found
  no names or content text — only the template's own generic placeholder prompts (e.g. "Click to edit Master
  title style", "Event name or presentation title") and the closing-slide copyright line.
- **Kept:** slide master, all layouts, theme colours and fonts, background artwork (19 images), Microsoft
  logos (title and closing layouts) and table styles.
- **Sensitivity label removed (at the user's request):** the source file's Microsoft Information Protection
  label metadata (`docMetadata/LabelInfo.xml`, its relationship and content-type entries) was stripped; the
  file had no MSIP_Label custom properties. The template therefore carries **no label**. Every generated deck
  and Word document must be labelled by the user — see SKILL.md Step 6/7; the skill never assumes a label.
- **Preview:** `assets/brand-template-preview.png` — 12 representative layouts rendered from the cleaned
  template (Title Slide 1–3, Title and Content, Two Column Bullet text, Three Column Bullet with Subtitles,
  Title Only, Title Only - left side, Section Title 2, Content Graphic, Big Number, Closing logo slide).

## Run-time rule (always)
1. Use `assets/brand-template.potx` in this skill folder. **Never** fetch a SharePoint/OneDrive original at
   run time.
2. If the bundled template is missing or unreadable, **ask the user** (AskUserQuestion) to attach a template
   or approve a plain unbranded deck. Never invent colours, fonts, logos or layout names.
3. Use only the template's masters, layouts and theme — it contains no content slides. Seed the deck from the
   template (pptx skill), then add slides with the layouts mapped below.
4. Fonts: Segoe Sans Display / Segoe Sans Display Semibold may not be installed where previews are rendered,
   so previews can show a substitute font; the delivered .pptx still references the theme fonts. Don't
   override theme fonts to "fix" a preview.

## Theme details (read from the template)
| Slot | Hex | Use |
|---|---|---|
| dk1 (Text/Background dark 1) | `#091F2C` | Body text, titles |
| lt1 (light 1) | `#FFFFFF` | Light background |
| dk2 (dark 2) | `#000000` | Dark background (closing slide) |
| lt2 (light 2) | `#FFF8F5` | Warm off-white background |
| accent1 | `#702573` | Plum — primary accent |
| accent2 | `#C03BC4` | Magenta |
| accent3 | `#0078D4` | Microsoft blue (also hyperlink) |
| accent4 | `#8DC8E8` | Light blue |
| accent5 | `#225B62` | Teal |
| accent6 | `#D4EC8E` | Lime |
| hlink / folHlink | `#0078D4` / `#C03BC4` | Links |

- **Colour scheme name:** "MSFT Cloud". **Font scheme:** "FantasyxMSFT" — headings **Segoe Sans Display
  Semibold**, body **Segoe Sans Display** (Segoe UI and Consolas also used in some layouts).
- **Logo placement:** Microsoft logo (EMF, grey-text version) top-left on Title Slide 1–3 — offset
  0.64 in × 0.64 in, about 1.49 in × 0.32 in. White-text version in the same position on "Closing logo
  slide" (black background, with a small copyright line bottom-left). Content layouts carry no logo.
- **Backgrounds:** Title Slide 1–3, Section Title 2–4, Demo slides, Blank 2–4, Content Graphic 1–3 and
  Big Number 1–3 carry abstract 3-D ribbon artwork; content layouts are plain white with a small "eyebrow" text
  placeholder above the title.
- **Status colours (user decision, 5 November 2026):** red / amber / green (plus grey for Not assessed) are
  used **only** for pass/fail status marks — status chips, RAG tiles, pass/fail cells and score bars. Everything
  else (titles, text, backgrounds, non-status chart series, shapes, tables) uses the theme colours above.

## Deck slide type → layout (defaults; the user may change them)
| Deck slide (outline C) | Layout name |
|---|---|
| 1 Title | Title Slide |
| 2 Agenda | Title and Content |
| 3 Purpose, scope and method | Two Column Bullet text |
| 4 Executive summary — RAG posture | Title Only (RAG tiles built as shapes) |
| 5 CIS M365 scores L1 / L2 (headline number) | Big Number |
| 6 CIS scores by section (chart) | Title Only |
| 7 CIS Controls IG coverage + minimum bar | Title Only |
| 8 Top 5 risks | Title and Content |
| 9 AI readiness prerequisites | Title & Non-bulleted text |
| 10–15 Key findings by area (one per area) | Two Column Content with Subheads |
| 16 Entra licence compliance (table) | Title Only |
| 17 Licensing implications (now vs upgrade) | Two Column Bullet with Subheads |
| 18–19 Remediation roadmap (quick wins / 30 / 90 days) | Three Column Bullet with Subtitles |
| 20 Decisions required | Title and Content |
| 21 Next steps and timeline | Title Only |
| Optional section dividers (count towards 20–25) | Section Title 2 |
| 22–24 Appendix tables ([verify] items, Not assessed, CIS terms) | Title Only |
| Closing | Closing logo slide |

## All layouts in master order
| # | Layout name |
|---|---|
| 1 | Title Slide |
| 2 | Title Slide 2 |
| 3 | Title Slide 3 |
| 4 | Title and Content |
| 5 | Title & Non-bulleted text |
| 6 | Two Column Bullet text |
| 7 | Two Column Non-bulleted text |
| 8 | Two Column Bullet with Subheads |
| 9 | Two Column Content with Subheads |
| 10 | Three Column Bullet with Subtitles |
| 11 | Four Column Bullet with Subtitles |
| 12 | Five Column Bullet with Subtitles |
| 13 | Title Only |
| 14 | Title Only - left side |
| 15 | Small title - half page |
| 16 | Device |
| 17 | Device 2 |
| 18 | Title - Floating Square Photo Graphic |
| 19 | Title - Floating Square Photo Graphic 2 |
| 20 | Title - Square Photo Graphic |
| 21 | Title - Square Photo Graphic 2 |
| 22 | Title - Square Photo Graphic 3 |
| 23 | Title - Square Photo |
| 24 | Square Photo |
| 25 | Square Photo 2 |
| 26 | Top horizontal photo and title |
| 27 | Bottom horizontal photo and title |
| 28 | Two picture content |
| 29 | Three picture content |
| 30 | Four picture content |
| 31 | Two filmstrip photos |
| 32 | Three filmstrip photos |
| 33 | Four filmstrip photos |
| 34 | Five filmstrip photos |
| 35 | Three round photos |
| 36 | Four round photos |
| 37 | Five round photos |
| 38 | Title and text side by side |
| 39 | Title and text side by side 2 |
| 40 | Developer Code Layout |
| 41 | Code Bottom |
| 42 | Code Top |
| 43 | Code Right side |
| 44 | Code Left sde |
| 45 | Demo slide |
| 46 | Demo slide 2 |
| 47 | Demo slide 3 |
| 48 | Demo slide 4 |
| 49 | Section Title |
| 50 | Section Title 2 |
| 51 | Section Title 3 |
| 52 | Section Title 4 |
| 53 | Blank |
| 54 | Blank 2 |
| 55 | Blank 3 |
| 56 | Blank 4 |
| 57 | Content Graphic |
| 58 | Content Graphic 2 |
| 59 | Content Graphic 3 |
| 60 | Big Number |
| 61 | Big Number 2 |
| 62 | Big Number 3 |
| 63 | Quote Slide |
| 64 | Closing logo slide |
| 65 | Black Notes slide Layout |
