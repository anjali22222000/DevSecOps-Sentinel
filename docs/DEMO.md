# Demonstration script (about 8 minutes)

All commands run from the repository root with the virtual environment active. Fixtures are fictional
(`@acme-demo`, `.example` domains) and nothing is ever installed or published.

## 1. A clean scan
```bash
sentinel scan examples/clean-demo --registry-fixture examples/clean-demo/registry-fixture.json
echo $?          # 0
```
Say: registry answers come from a local fixture so the demo is deterministic; the report is labelled `fixture`.
Point out `Policy: PASS` and `CRITICAL 0 HIGH 0 MEDIUM 0`.

## 2. A suspicious dependency being detected
```bash
sentinel scan examples/vulnerable-demo --registry-fixture examples/vulnerable-demo/registry-fixture.json --output-dir reports
echo $?          # 1
```
Observed output (from a real run):
```
Findings: CRITICAL 2  HIGH 3  MEDIUM 1  SAFE 2  (partial evidence: 0)
F001  CRITICAL  80  @acme-demo/auth      public registry has 99.0.0, higher than expected internal 1.4.0
F002  CRITICAL  80  @acme-demo/billing   internal package was resolved from public registry host registry.npmjs.org
F003  HIGH      65  configuration        pip merges all indexes and installs the highest version it finds; ...
F004  HIGH      60  expresss             name resembles 'express' (87.5% similar)
F005  HIGH      60  reqeusts             name resembles 'requests' (87.5% similar)
F006  MEDIUM    30  acme-demo-reports    internal name is registered on the public registry and is not declared as owned by you
Policy: BLOCKED (exit 1)
```

## 3. The score and its explanation
Open `reports/report.html` and expand **F001**: the V, S, T table shows value, weight and contribution, then
"R = ... = 70; minimum forced by rule: 80". Explain why the floor exists ([SCORING.md](SCORING.md)).
Then show `reqeusts`: formula 26.25 (SAFE) raised to 60 (HIGH) by the lookalike rule, and the stated limitation
"similarity is evidence of resemblance, not proof".

## 4. Reports and dashboard
```bash
cd reports && python -m http.server 8000      # open http://localhost:8000/dashboard.html
```
Show Overview, filter Scan results to CRITICAL, open a Finding, Configuration, Reports. Mention the **Demo data** banner.
Show that `report.sarif` has the same findings (same IDs, scores and severities as the JSON).

## 5. Pipeline pass and fail
Show `.github/workflows/demo.yml`. In GitHub: *Actions -> Gate demo -> Run workflow*; `gate-passes` is green and
`gate-blocks` is green *because it asserts exit code 1*; download the `sentinel-reports-vulnerable` artifact.
(If you have not run it on GitHub yet, say so and show the local equivalent: `python scripts/run_scenarios.py`.)
Then show `examples/workflows/protected-build.yml`: the build job `needs` the gate, so `npm ci` never runs.

## 6. Limitations and false positives
```bash
sentinel scan examples/vulnerable-demo                   # offline: no registry evidence
```
Observed: still BLOCKED (lockfile evidence works offline) but `partial evidence: 7` - the version evidence for
`@acme-demo/auth` needs the registry. Then show the outage case:
```bash
HTTPS_PROXY=http://127.0.0.1:9 sentinel scan examples/acme-demo-fixture --registry --timeout 3 ; echo $?   # 2
```
A registry failure is exit 2, never a pass. Close with [EVALUATION.md](EVALUATION.md): legitimate names such as
`safer-buffer` are still flagged, which is why similarity is evidence, and why `similarity.allowlist` exists.

## Optional: live run
```bash
sentinel scan examples/acme-demo-fixture --registry     # real NPM/PyPI; sends 13 names
```
