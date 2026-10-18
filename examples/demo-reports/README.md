# Sample reports (DEMO DATA)

Generated from the synthetic fixtures in `examples/clean-demo` and `examples/vulnerable-demo` with
`--registry-fixture`, so the registry answers are **local fixture data, not live registry results**.
Every report says so (`metadata.registry_mode = "fixture"`, `demo_data = true`) and the dashboard shows a
"Demo data" banner.

Regenerate:
```bash
sentinel scan examples/vulnerable-demo --registry-fixture examples/vulnerable-demo/registry-fixture.json \
    --output-dir examples/demo-reports/vulnerable-demo
```
Open `vulnerable-demo/report.html`, or `vulnerable-demo/dashboard.html` (use "Open report.json").
Timestamps differ between runs; everything else is reproducible.
