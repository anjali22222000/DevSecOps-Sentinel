# Limitations and known issues

Stated plainly so they can be defended in a viva or interview.

## What the tool cannot detect
- **Malicious code inside a package.** Packages are never downloaded, installed or run. A package with a
  clean name and no internal-name link is invisible to this tool. It does not check CVEs.
- **Who owns a package name.** Registry metadata cannot prove ownership. A 404 for a scoped name is
  ambiguous (unclaimed vs. private in a scope you own). Ownership comes only from your `sentinel.toml`.
- **Attacks that do not resemble a well-known name** and do not target a declared internal name.
- **A compromised registry or CDN** (responses are trusted after HTTPS and shape checks).

## Coverage gaps
- Only the directory passed to `sentinel scan` is read (not recursive), so monorepo sub-projects need separate scans.
- `-r` / `-c` references inside `requirements.txt` are not followed (a warning is printed).
- `.npmrc`, `pip.conf`, `pyproject.toml`, `Pipfile` (non-lock), `yarn.lock`, `pnpm-lock.yaml`, `poetry.lock` are not read.
  Registry configuration in those places is therefore not assessed.
- Transitive NPM dependencies are visible only through `package-lock.json`; transitive PyPI dependencies are visible
  only through `Pipfile.lock`. A plain `requirements.txt` lists only what it lists.
- Environment markers are recorded, not evaluated (every requirement is considered).
- Direct URL, git and local dependencies are recorded but not assessed.

## Accuracy
- The list of well-known names used for typosquat comparison is a **hand-curated seed list** (137 NPM, 120 PyPI
  names), not a download-ranked source. Detection quality depends heavily on it.
- Name similarity is evidence of resemblance, not proof of intent. Measured false positives on a small
  hand-built set, and a remaining one (`safer-buffer`), are in [EVALUATION.md](EVALUATION.md).
- NPM abbreviated metadata has no publish dates, so the "established package" age rule applies to PyPI only.
- The proposal's "unverified maintainer metadata" MEDIUM criterion is **not implemented** (no maintainer
  data is collected).
- No claim is made about real-world detection rates; the evaluation uses synthetic positives.

## Verification gaps (what was NOT done)
- The GitHub Actions workflows, the composite action and SARIF upload were **not run on GitHub**. They have
  static tests, a local simulation of the action's shell steps, and a structural SARIF validator that does not use
  the official JSON schema. Confirm on a real repository before claiming GitHub Security tab integration.
- The dashboard was exercised in jsdom with real reports, including an XSS attempt, but **not viewed in a real
  browser**: layout, colours and mobile responsiveness are unverified.
- Python 3.10 (where `tomli` is used instead of `tomllib`) was not run here; CI is configured for it.
- The PyPI JSON `releases` field and NPM metadata shape were verified against live responses on one date; a
  change by either registry would surface as `malformed response` errors (exit 2), not silent passes.

## Performance
Measured, with caveats, in [PERFORMANCE.md](PERFORMANCE.md). There is no on-disk cache and no load test.

## Hardening that is not done yet
- `requirements-scanner.txt` has no `--hash` pins; GitHub Actions are pinned by major version tag, not commit SHA
  (Dependabot is configured to propose updates).
- No licence file is included.
- Reports contain internal package names if you declare them; treat artifacts as sensitive.
