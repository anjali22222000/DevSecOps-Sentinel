# Viva and interview preparation

Use these as prompts to *practise explaining in your own words*, not as text to memorise. For each, open the
file named in brackets and be able to point to the code.

## Concepts
**What is dependency confusion?** A build asks a package manager for a name. If both a private registry and the public
registry can answer, and the resolver prefers the higher version or the public source, an attacker who publishes the
same name publicly with a very high version gets their code installed and run (install scripts run on the CI runner). [SCORING.md, THREAT_MODEL.md]

**How is it different from typosquatting?** Confusion targets *your* internal names; typosquatting targets a developer's
*typing mistakes* on popular names. Different attacks, one scanner, two kinds of evidence.

**What can public metadata prove, and what can't it?** It can show that a name exists, its versions and (PyPI) dates.
It cannot prove who owns a name; a 404 for a scoped NPM name also happens for private packages in a scope you own. That is why
ownership is declared in `sentinel.toml`. [analyzer.py, `_assess_package`]

**Why scan before install?** `npm install`/`pip install` can execute package code (install scripts, setup.py). Detecting after
install is too late. The gate runs first and the build job `needs` it. [action.yml, examples/workflows/protected-build.yml]

## The algorithm
**Explain Levenshtein distance.** Minimum single-character inserts, deletes or substitutions to turn one string into another;
computed with a dynamic-programming table, here with two rows. [similarity.py `levenshtein`]

**Why also Damerau?** Levenshtein counts a swapped pair ("reqeusts") as two edits, but it is the commonest typo; Damerau (OSA) counts it
as one. Measured: on synthetic swaps, detection is 100% with Damerau and about 50% with Levenshtein. [EVALUATION.md]

**Walk through the scoring formula.** `R = min(100, Wv*V + Ws*S + Wt*T)`. Show `@acme-demo/auth`: V=100, S=100, T=0, weights .4/.3/.3
give 70; the CRITICAL floor raises it to 80. [SCORING.md worked examples]

**Why floors? Isn't that cheating the model?** With weights summing to 1 a single strong signal cannot reach CRITICAL, contradicting the
proposal's own definition. Floors make specific evidence decisive, and both the formula value and the floor are shown. It is the smallest
change that makes the model match its stated intent.

**How are false positives reduced?** Exact matches are legitimate; allowlist; names under 5 characters skipped; edit-distance limit by
length; internal names skipped; "established" packages (10+ versions or 2+ years) get no lookalike floor. Measured: 8 of 168 legitimate names
were flagged by name alone and 1 remained after the filter. [EVALUATION.md]

**How do you compare versions correctly?** Never as strings (1.10.0 > 1.4.0). Semver rules for NPM including pre-releases; PEP 440 via `packaging` for PyPI.
Tests include 1.10.0 vs 1.4.0 and pre-release ordering. [versions.py, test_versions.py]

## Engineering
**Why async?** Each lookup waits on the network; `asyncio` lets many wait at once. Measured with a 50 ms mock latency: 100 packages take
about 5.2 s sequentially and about 0.55 s at concurrency 10. [PERFORMANCE.md]

**How does the fetcher behave under failure?** Total timeout, concurrency semaphore (released while backing off), retries only for 429/5xx/network errors,
exponential backoff with jitter, `Retry-After` honoured but capped, redirects refused, 20 MB cap. 404 is an answer; failures are `error`. [http.py, test_fetcher.py]

**Why is an outage exit 2, not 0?** A security gate that passes when it cannot see anything gives false assurance. Exit 2 keeps "scanner broke" distinct
from exit 1 "risk found". [policy.py]

**Why separate severity from blocking?** Severity says how risky; policy says what the team tolerates. `--fail-on never` leaves every severity unchanged. [test_cli_scenarios.py]

**How does the pipeline avoid installing dependencies first?** The action installs only the scanner's pinned requirements; the application job `needs` the gate.
Inputs reach shell scripts only through `env:`, avoiding script injection. [test_workflows.py]

**What is SARIF and why?** A JSON standard for static-analysis results; GitHub code scanning ingests it to show alerts in the Security tab. We emit 2.1.0 with stable rule IDs,
per-result fingerprints and file/line locations. It is validated structurally; **GitHub ingestion is unverified until you test it**. [sarif.py]

**How did you stop the dashboard being an XSS vector?** Package names are attacker-controlled text. Reports are autoescaped; the dashboard uses `textContent` only,
a test forbids `innerHTML`, and a jsdom check feeds it `<img onerror>` / `<script>` names. [test_reports.py, scripts/dashboard_check.js]

**What did you not do / what would you do next?** See LIMITATIONS.md: no `.npmrc`/`pip.conf`, no recursion, no CVE scanning, seed list, GitHub not yet tested, no hash pins.
Next: download-ranked top-N list, `.npmrc` parsing, recursive scan, hash pinning.

## Hard questions to prepare
- "Your own 80-floor contradicts the proposal's 'R'. Defend it." (above)
- "Your evaluation uses synthetic typosquats. What can you actually claim?" (only regression behaviour, not real-world accuracy; EVALUATION.md says so)
- "What if an attacker publishes a lookalike that is old and popular?" (established filter would downgrade it; a known gap)
- "What if the registry lies or is compromised?" (out of scope; HTTPS and shape checks only)
- "How would you test the GitHub workflow?" (static checks done; run `demo.yml` in a repository, confirm both jobs and the Security tab)
