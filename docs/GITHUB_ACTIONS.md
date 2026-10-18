# GitHub Actions integration

## Using the gate
```yaml
jobs:
  security-gate:
    runs-on: ubuntu-latest
    permissions: { contents: read }
    steps:
      - uses: actions/checkout@v6
      - uses: YOUR-ORG/devsecops-sentinel@v0.3.0     # the repository/tag where you publish Sentinel
        with:
          path: .
          config: sentinel.toml
  build:
    needs: security-gate        # npm ci / pip install happen only after the gate passes
    ...
```
Full example: `examples/workflows/protected-build.yml`.

## Inputs
`path`, `config`, `fail-on`, `registry` (default `true`), `registry-fixture` (demos), `output-dir`,
`artifact-name` (must be unique per job), `upload-sarif` (default `false`), `python-version`. Output: `exit-code`.

## What the action does
1. Sets up Python.
2. Installs the **scanner's** pinned dependencies (`requirements-scanner.txt`) and the scanner. It never installs the
   scanned project's dependencies.
3. Runs `sentinel scan`, capturing the exit code without failing the step.
4. Uploads the reports as an artifact (`always()`).
5. Optionally uploads `report.sarif` to code scanning (the calling job needs `security-events: write`).
6. **Enforces the verdict last:** exit 0 passes; exit 1 fails with "policy gate"; exit 2 fails with "scanner error ... NOT a pass".

## Policy failure vs scanner error
| Exit | Meaning | Typical fix |
|---|---|---|
| 1 | A finding reached `fail_on` | Investigate the finding (see the report); fix the dependency or, for a verified false positive, allowlist it |
| 2 | Scan could not complete (bad config/path, registry unreachable, unexpected response) | Fix the cause or retry; do not treat as safe |

## Security properties (checked by `tests/test_workflows.py`)
Top-level `permissions: contents: read`; `security-events: write` only on the SARIF demo job; no `pull_request_target`;
no `${{ }}` inside any `run:` script (inputs arrive through `env:`); all third-party actions carry a version;
artifact names are unique; the example installs dependencies only in a job that `needs` the gate.
Versions used: `actions/checkout@v6`, `actions/setup-python@v6`, `actions/upload-artifact@v7`,
`github/codeql-action/upload-sarif@v4` (v3 of the CodeQL action is scheduled for deprecation), taken from current
repositories' usage when this was written. Pin by commit SHA for stricter supply-chain hygiene.

## Demo workflow
`.github/workflows/demo.yml` runs a passing scenario (`examples/clean-demo`) and a blocking scenario
(`examples/vulnerable-demo`, asserts exit code 1 specifically) using local registry fixtures, so the outcome does
not depend on the network. Run it with *Actions -> Gate demo -> Run workflow*; tick `upload_sarif` to also try the SARIF upload.

## Verification status
**Not yet run on GitHub.** What was done: YAML parsed, static security checks, and a local execution of the action's
exact shell steps for the pass / block / scanner-error / bad-path cases (reports written every time, exit codes 0 / 1 / 2).
Treat the first run in your repository as the real test, and the Security-tab integration as unverified until you
have seen the alerts there.
