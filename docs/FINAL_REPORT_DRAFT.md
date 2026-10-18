# DevSecOps Sentinel: Static Code Scanner for CI/CD Pipeline Dependency Confusion Vulnerabilities

*Final-year project report: DRAFT.* Written from the implemented system. Numbers in sections 9-10 are copied
from the generated files in `docs/` (re-run the scripts to refresh them). Rewrite sections in your own words,
and update any statement that stops being true.

## Abstract
Modern software depends on third-party packages installed automatically by CI/CD pipelines. Dependency
confusion and typosquatting let an attacker run code on a build machine through package *names* alone, before any
conventional scanner looks at the code. DevSecOps Sentinel is a Python command-line scanner and GitHub Action that
reads dependency manifests and lockfiles (`package.json`, `package-lock.json`, `requirements.txt`, `Pipfile.lock`),
queries the public NPM and PyPI registries asynchronously, scores each package from three indicators (version
mismatch, namespace exposure, name similarity) with an explainable formula, and blocks the pipeline before dependencies
are installed when findings reach a configurable severity. It produces JSON, HTML and SARIF reports and a static dashboard.
The implementation has 312 automated tests passing and 12 of 12 recorded end-to-end scenarios matching expectations.
Limitations, notably that the GitHub workflow has not yet been run on GitHub and that the similarity evaluation is small and
partly synthetic, are stated in section 11.

## 1. Introduction and background
CI/CD systems such as GitHub Actions install dependencies automatically. Package managers resolve names against registries;
when an organisation's internal package name can also be answered by a public registry, a higher public version may be
preferred (Birsan, 2021). Existing static application security tools mostly look for known vulnerabilities (CVEs) in code
or dependencies, not for resolution-configuration flaws that execute attacker code at install time.

## 2. Problem statement
1. Internal package names may be unclaimed or claimed publicly with higher versions (namespace squatting, version hijacking).
2. Developers mistype popular package names (typosquatting).
3. Most scanning happens after the build, when install scripts have already run.
4. There is no lightweight, automatic gate in the pipeline that evaluates these risks and aborts the build.

## 3. Objectives
Parse manifests and lockfiles; inspect public registries concurrently; detect lookalike names with string distance; compute a
composite, explainable risk score with four severity levels; enforce the result in GitHub Actions with predictable exit codes;
export JSON, HTML and SARIF reports.

## 4. Existing-system limitations
CVE-oriented scanners do not model name-resolution risk; manual review does not scale; post-build scanning is late; and tools that
rely on public metadata alone cannot know which names are internal (addressed here by explicit configuration).

## 5. Proposed system
A pre-install scanner with: multi-ecosystem parsing; an async, hardened registry layer; a transparent scoring engine with
floors for decisive evidence; separate severity and blocking policy; a privacy mode; reports in three formats; a composite
GitHub Action that uploads evidence even when it fails the build; and a static dashboard that reads the real JSON.

## 6. System architecture
See [ARCHITECTURE.md](ARCHITECTURE.md) for the data-flow diagram and module table. Pipeline: parse -> (optional) registry
evidence -> analyse (V, S, T, floors) -> score and classify -> policy decision and exit code -> reports.

## 7. Methodology
Work proceeded in eight stages: assessment of the proposal, parsing, registry clients, similarity and versions, scoring and
configuration, reports, GitHub Action and dashboard, validation. Each stage had acceptance criteria and tests before the next began.
Corrections to the proposal's model were identified early (section 8) and documented rather than silently applied.

## 8. Mathematical model
Original: `R = min(100, Wv*V + Ws*S + Wt*T)`, `Wv+Ws+Wt = 1`, bands SAFE < 30 <= MEDIUM < 60 <= HIGH < 80 <= CRITICAL.
Normalised similarity: `T = (1 - d / max(len(a), len(b))) * 100`.
Implemented: the same formula, weights (0.4, 0.3, 0.3) and bands, with four adjustments (full table in [SCORING.md](SCORING.md)):
(1) **floors**, because the weighted sum alone cannot reach CRITICAL for a higher public version (0.4 x 100 = 40) or HIGH for a lookalike
(87.5% x 0.3 = 26.25); (2) V compares against an **expected internal version** supplied by configuration or lockfile; (3) S is derived from declared
internal names and public registration, because a registry cannot prove ownership; (4) an adjacent swap counts as one edit (Damerau), measured below.
Worked example: `@acme-demo/auth` with public version 99.0.0 vs expected 1.4.0: V=100, S=100, T=0 gives 70, raised to 80 (CRITICAL) by the floor.

## 9. Implementation details
Python 3.10+, `asyncio`/`aiohttp` for lookups (timeout, concurrency limit, retry with backoff and `Retry-After`, size cap, no redirects, bounded LRU cache),
`packaging` for requirement and PEP 440 parsing, a hand-written semver comparer, hand-written Levenshtein/Damerau distance, `tomllib`/`tomli` for configuration,
Jinja2 for HTML, SARIF 2.1.0 generated from the same findings as the JSON, a composite GitHub Action, and a dependency-free static dashboard.
Security-relevant decisions are listed in [ARCHITECTURE.md](ARCHITECTURE.md): name validation before URL construction, redaction of credentials, escaping of untrusted
names in every report, failed lookups never treated as safe, and a three-valued exit code (0 pass, 1 policy block, 2 scanner error).

## 10. Testing methodology and results
**Automated tests:** 312 passed, 0 failed, 0 skipped (312 total); per-file table in [TEST_RESULTS.md](TEST_RESULTS.md). They cover parsers, every severity
boundary, the fetcher against a real local HTTP server (timeouts, 503/429 with `Retry-After`, oversized bodies, redirects, connection failure), analyzer scenarios, policy
exit codes, report agreement, SARIF validation, HTML escaping and static checks of the workflow files.

**End-to-end scenarios:** 12 of 12 matched expectations ([SCENARIOS.md](SCENARIOS.md)), including a clean project, a project with deliberate
dependency-confusion and typosquat patterns (exit 1), a registry-failure case (exit 2), offline and privacy modes, a live NPM/PyPI lookup, and a simulated network outage (exit 2).

**Performance** ([PERFORMANCE.md](PERFORMANCE.md)): controlled test against a local mock registry with a fixed 50 ms delay (median of 5 runs):

| Packages | Concurrency | Median lookup time | Ideal |
|---|---|---|---|
| 10 | 1 | 0.515 s | 0.500 s |
| 10 | 10 | 0.059 s | 0.050 s |
| 50 | 1 | 2.578 s | 2.500 s |
| 50 | 10 | 0.276 s | 0.250 s |
| 100 | 1 | 5.169 s | 5.000 s |
| 100 | 10 | 0.545 s | 0.500 s |
| 200 | 1 | 10.329 s | 10.000 s |
| 200 | 10 | 1.107 s | 1.000 s |

A live scan of the 13-package demo project from the sandbox took 0.61 / 0.69 / 0.93 s (min / median / max of 5, including interpreter start-up). The proposal's
"under 5 seconds" target holds at the default concurrency for the sizes tested and **not** for sequential lookups of 100 or more packages. It is not proven for arbitrary projects or networks.

**Typosquat evaluation** ([EVALUATION.md](EVALUATION.md)): on synthetic mutations of 137 NPM / 120 PyPI well-known names, detection was 96% (NPM, 486 of 504) and 96% (PyPI, 485 of 505)
with Damerau, versus 86% and 86% with plain Levenshtein, the difference coming from adjacent swaps. On 168 legitimate, registry-verified package names, 8 (4.8%) were flagged by name alone;
after the established-package filter, 1 of 8 remained. Because positives are synthetic and the seed list is hand-curated, these figures describe behaviour on this dataset
and are not real-world accuracy.

## 11. Limitations and future scope
See [LIMITATIONS.md](LIMITATIONS.md) and [COMPLETION_STATUS.md](COMPLETION_STATUS.md). Main points: ownership of names cannot be proven from public data; the well-known-name list is a seed list;
`.npmrc`/`pip.conf` and recursive scanning are not covered; the GitHub Action, SARIF upload and a real-browser dashboard check are still to be verified; malicious package behaviour is out of scope.
Future work: download-ranked top-N data, `.npmrc` and `pip.conf` parsing, monorepo scanning, hash-pinned scanner dependencies, additional ecosystems, maintainer-metadata signals.

## 12. Conclusion
The project delivers a working, tested pre-install gate whose decisions are explainable (every score shows its inputs, floors and limitations) and whose failure modes are explicit (an outage is never a pass).
It demonstrates that name-resolution risk can be checked cheaply before installation, while being honest that public metadata alone cannot establish ownership and that name similarity is only evidence.

## References
[1] A. Birsan, "Dependency Confusion: How I Hacked Into Apple, Microsoft and Dozens of Other Companies," Medium, Feb. 2021.
[2] OpenSSF, "Securing the Software Supply Chain," Linux Foundation, 2022.
[3] OASIS, "Static Analysis Results Interchange Format (SARIF) Version 2.1.0," OASIS Standard, Mar. 2020.
[4] GitHub Docs, "Security in GitHub Actions," GitHub Documentation.
[5] Python Software Foundation, "asyncio - Asynchronous I/O," Python 3 Documentation.
[6] V. I. Levenshtein, "Binary codes capable of correcting deletions, insertions, and reversals," Soviet Physics Doklady, 1966.
[7] npm Docs, "About scoped packages," npm Documentation.
[8] PEP 503 (Simple Repository API, name normalization) and PEP 440 (Version Identification), Python Packaging Authority.
[9] Semantic Versioning 2.0.0, semver.org.
