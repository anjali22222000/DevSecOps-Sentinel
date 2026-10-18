# Dashboard design

A single static file (`src/sentinel/dashboard/index.html`): vanilla HTML, CSS and JavaScript, no framework,
no build step, no network requests except an optional `fetch("report.json")` from the same folder.
It reads the real `report.json`; with nothing loaded it shows an honest empty state, not sample numbers.
Reports generated from fixtures are labelled **Demo data**; reports produced without `--registry` say so.

## Layout
Compact header (name, section navigation, "Open report.json" file picker) over a single centred column
(max 1080 px). Views via the URL hash: Overview, Scan results, Finding detail, Configuration, Reports.

## Colour system
Neutral white/near-black text with a light panel colour and 1 px borders; light and dark themes follow
`prefers-color-scheme`. Severity uses four muted colours (red, orange, amber, green) **plus the severity word**
and a small square marker, so meaning never depends on colour alone. No gradients, glows, shadows or animation.

## Typography
System UI font stack, 14 px body, 15-18 px headings, monospace (system stack) for package names, paths and commands.

## Tables
Dense rows, sticky meaning through `scope="col"` headers and a caption stating the count and ordering, horizontal
scroll inside the table wrapper on narrow screens, package names are links to the finding. Filter by severity and search by name.

## Views
1. **Overview** - verdict banner (blocked / scanner error / passed), counts by severity, packages assessed, partial
   assessments, scanner errors, registry mode and lookup results, highest-risk findings.
2. **Scan results** - package, ecosystem, evidence, score, severity, assessment, recommended investigation.
3. **Finding detail** - score calculation table (V, S, T value, weight, contribution), formula result, floor and reason,
   evidence, limitations, recommendation, file/line locations, rule id.
4. **Configuration** - read-only view of effective policy, weights, floors, trusted namespaces, similarity and privacy settings.
5. **Reports** - links to `report.html`, `report.sarif`, `report.json` (work when served from the same folder) and a download button.

## Accessibility and safety
Semantic landmarks and labels, visible focus outlines, `aria-current` on navigation, keyboard-operable controls.
All report data is untrusted (package names come from the scanned repo) and is inserted only with `textContent`/text nodes
(a test forbids `innerHTML` and similar in the file).

## Verification status
Checked in jsdom with generated reports (`scripts/run_dashboard_check.sh`): empty state, counts equal `report.json`,
filtering/search, detail view, error and clean reports, invalid input, and an XSS attempt. **Not verified in a real browser.**
There are no charts: the proposal mentions "visual charts", but a handful of counts are clearer as numbers than as decorative graphs.
