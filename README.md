# DevSecOps Sentinel

A static scanner that checks a project's dependency files for **dependency-confusion** and
**typosquatting** risks *before* any `npm install` / `pip install` runs, and can block a GitHub
Actions pipeline when a finding reaches a configurable severity.

It reads `package.json`, `package-lock.json`, `requirements.txt` and `Pipfile.lock`, asks the public
NPM and PyPI registries what they know about each package name, scores the evidence with a
transparent formula, and writes JSON, HTML and SARIF reports plus a static dashboard.
It never installs or executes any scanned package.

> **Status and honesty:** every claim here is backed by something you can re-run. What was and was
> not verified is listed in [docs/COMPLETION_STATUS.md](docs/COMPLETION_STATUS.md) and
> [docs/LIMITATIONS.md](docs/LIMITATIONS.md). The tool is a student project, not a production
> security product, and it has not been audited.

## Quick start

```bash
python -m venv .venv            # Windows: py -m venv .venv
# activate the venv, then:
pip install -e ".[dev]"
pytest

sentinel scan examples/clean-demo      --registry-fixture examples/clean-demo/registry-fixture.json
sentinel scan examples/vulnerable-demo --registry-fixture examples/vulnerable-demo/registry-fixture.json \
    --output-dir reports
echo $?        # 1 = blocked      (Windows PowerShell: $LASTEXITCODE)
```

Open `reports/report.html`, or serve the folder and open the dashboard:

```bash
cd reports && python -m http.server 8000     # then visit http://localhost:8000/dashboard.html
```

(`dashboard.html` also has an "Open report.json" button, so serving is optional.)

Scan a real project against the live registries (this sends its package names to npmjs.org and pypi.org):

```bash
sentinel scan path/to/project --registry --config path/to/project/sentinel.toml
```

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Passed: nothing reached the blocking threshold and evidence collection did not fail |
| 1 | **Policy block:** at least one finding is at or above `policy.fail_on` (default `high`) |
| 2 | **Scanner error:** bad input/config, or a registry lookup failed. *Never* a pass |

If both apply, 1 wins (the more specific verdict). Either way the pipeline fails.

## Severity and policy are separate

Findings are classified from a 0-100 score: **SAFE** < 30, **MEDIUM** 30-59.99, **HIGH** 60-79.99,
**CRITICAL** >= 80. Whether the build is blocked is a *policy* (`fail_on = critical|high|medium|never`),
so a team can change strictness without changing how risk is scored. See [docs/SCORING.md](docs/SCORING.md).

## Configuration

Copy [`sentinel.example.toml`](sentinel.example.toml) to your project as `sentinel.toml`. Public registry
metadata cannot prove who owns a package name, so **you** declare internal scopes/prefixes, names you
have reserved publicly, and (optionally) the internal versions to compare against. Unknown keys are
rejected so a typo cannot silently weaken the policy.

Privacy mode (`[privacy] query_internal_names = false`) keeps internal package names off public
registries; those checks are then reported as incomplete rather than silently passing.

## GitHub Actions

`action.yml` is a composite action that installs only the scanner's own pinned dependencies, runs the
scan, uploads reports **even when the gate fails**, optionally uploads SARIF, and finally enforces the
verdict. See [docs/GITHUB_ACTIONS.md](docs/GITHUB_ACTIONS.md) and
[examples/workflows/protected-build.yml](examples/workflows/protected-build.yml).

## Project layout

```
action.yml                   composite GitHub Action (the security gate)
sentinel.example.toml        documented configuration example
requirements-scanner.txt     pinned runtime dependencies of the scanner itself
src/sentinel/
  cli.py                     command line, exit codes, report writing
  config.py  policy.py       sentinel.toml loading; blocking decision
  scoring.py analyzer.py     score formula, floors, findings
  analysis/                  names, similarity (Levenshtein/Damerau), versions (semver/PEP 440)
  parsers/                   package.json, package-lock.json, requirements.txt, Pipfile.lock
  registry/                  async NPM/PyPI clients, retry/backoff, bounded cache, fixtures
  reporting/                 JSON, HTML (Jinja2), SARIF 2.1.0 + validator
  dashboard/index.html       static dashboard (vanilla HTML/CSS/JS)
  data/                      hand-curated seed lists of well-known package names
examples/                    safe synthetic fixtures (@acme-demo) and an example workflow
scripts/                     scenario runner, benchmark, similarity evaluation, dashboard check
tests/                       pytest suite
docs/                        architecture, scoring, threat model, limitations, measured results, report draft
```

## Measured results (regenerate with the scripts)

| What | Where | Command |
|---|---|---|
| Automated tests | [docs/TEST_RESULTS.md](docs/TEST_RESULTS.md) | `python scripts/summarize_tests.py` |
| End-to-end scenarios | [docs/SCENARIOS.md](docs/SCENARIOS.md) | `python scripts/run_scenarios.py` |
| Scan timing | [docs/PERFORMANCE.md](docs/PERFORMANCE.md) | `python scripts/benchmark.py` |
| Typosquat evaluation | [docs/EVALUATION.md](docs/EVALUATION.md) | `python scripts/evaluate_similarity.py` |
| Dashboard behaviour (jsdom) | - | `bash scripts/run_dashboard_check.sh` |

## Development

```bash
pip install -e ".[dev]"
pytest -q                      # no network needed
python scripts/run_scenarios.py   # network optional (S11, S12)
```

Conventions: type hints, small modules, no hidden logic (the edit-distance functions are written
out in `analysis/similarity.py`), tests for every behaviour in the findings above. Keep
`requirements-scanner.txt` pins at least two weeks old and re-check them when updating.
No license file is included; choose one before publishing.
