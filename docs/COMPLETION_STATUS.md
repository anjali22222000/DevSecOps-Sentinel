# Completion status against the proposal and the project brief

Legend: **Done+tested** = implemented and covered by automated tests or a recorded run. **Done, not verified on GitHub** =
implemented with static/local checks only. **Not done** = absent.

## Required features
| Requirement | Status |
|---|---|
| Parse `package.json`, `package-lock.json` (v1/v2/v3) | Done+tested |
| Parse `requirements.txt` | Done+tested |
| Parse `Pipfile.lock` (secondary priority) | Done+tested |
| Inspect NPM and PyPI public metadata, async, timeouts, concurrency limit, retry/backoff, rate-limit awareness, bounded cache | Done+tested (mock + local server + live runs) |
| Distinguish not-found from failed lookup; never classify unavailable evidence as SAFE | Done+tested |
| Normalized similarity and Levenshtein/Damerau distance | Done+tested |
| Configurable, transparent scoring; weights validated; boundaries tested | Done+tested |
| SAFE / MEDIUM / HIGH / CRITICAL; severity separate from blocking | Done+tested |
| Trusted internal configuration (scopes, prefixes, expected versions, owned names) | Done+tested |
| Privacy-conscious mode and documentation of what is sent | Done+tested |
| JSON, HTML (Jinja2), SARIF reports that agree | Done+tested |
| SARIF structurally valid | Done+tested (own validator, not the official schema) |
| CLI with predictable exit codes (0/1/2) | Done+tested |
| GitHub Actions gate (pre-install, reports on failure, SARIF upload, least privilege) | **Done, not verified on GitHub** |
| Passing and blocking workflow scenarios | Done locally (CLI and simulated action steps); **GitHub run pending** |
| Static dashboard (Overview, Results, Finding details, Configuration, Reports) with honest empty state | Done, checked in jsdom, **not viewed in a real browser** |
| Safe vulnerable-pattern fixtures, sample reports, documentation, demo | Done |
| Scan duration measured | Done (docs/PERFORMANCE.md); target met at default concurrency for tested sizes |
| False-positive / false-negative evaluation on a described dataset | Done (small, synthetic positives; docs/EVALUATION.md) |

## Deviations from the proposal (all documented)
| Proposal | Implemented | Why |
|---|---|---|
| S = 100 if scope unclaimed | S depends on declared internal names, public registration and reservation | A registry cannot prove ownership; a 404 is ambiguous |
| V = 100 if public > "internal" version | Expected version from config / lockfile / manifest; highest public version; semver / PEP 440 | "Internal version" must come from somewhere |
| Pure weighted sum defines severity | Weighted sum **plus floors** | The sum alone cannot reach the proposal's own CRITICAL/HIGH definitions |
| Levenshtein | Damerau (default) or Levenshtein | Swaps are the commonest typo; measured difference in EVALUATION.md |
| MEDIUM includes "unverified maintainer metadata" | Not implemented | No maintainer data is collected |
| HIGH and CRITICAL both abort | Default `fail_on = high`, configurable | Teams need to choose strictness |
| Tailwind / Bootstrap; "visual charts" | Vanilla CSS; counts and tables, no charts | No build step or CDN; charts would be decoration |
| `requirements-parser`, RapidFuzz | `packaging` and hand-written edit distance | Fewer dependencies; logic is explainable |
| Custom GitHub Action | Composite action (`action.yml`) | Simplest form that needs no container build |
| "Under 5 seconds" | Measured, with limits stated | Only concurrency 10 meets it for >= 100 packages at 50 ms latency |

## Not done
`.npmrc`/`pip.conf` scanning, recursive/monorepo scan, following `-r` includes, other ecosystems, CVE data, maintainer metadata,
on-disk cache, hash pinning of scanner dependencies, SHA-pinned actions, licence file, real-browser and mobile verification,
Python 3.10 execution, and any run on GitHub.
