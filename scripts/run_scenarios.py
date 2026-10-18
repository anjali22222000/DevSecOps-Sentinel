#!/usr/bin/env python3
"""Run end-to-end scenarios through the real CLI and write docs/SCENARIOS.md with OBSERVED results."""
from __future__ import annotations

import datetime
import os
import platform
import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CLEAN, VULN = "examples/clean-demo", "examples/vulnerable-demo"


def sentinel(args, env_extra=None, timeout=120):
    env = dict(os.environ, **(env_extra or {}))
    p = subprocess.run([sys.executable, "-m", "sentinel", *args], cwd=ROOT, env=env,
                       capture_output=True, text=True, timeout=timeout)
    return p.returncode, p.stdout, p.stderr


def line(out, prefix):
    return next((l for l in out.splitlines() if l.startswith(prefix)), "(not printed)")


def network_ok() -> bool:
    try:
        import urllib.request
        urllib.request.urlopen("https://pypi.org/pypi/requests/json", timeout=10).read(1)
        return True
    except Exception:
        return False


tmp = Path(tempfile.mkdtemp())
(tmp / "bad.toml").write_text("[weights]\nversion=0.9\nscope=0.9\nsimilarity=0.9\n")
(tmp / "privacy.toml").write_text('[privacy]\nquery_internal_names = false\n[internal.npm]\nscopes = ["@acme-demo"]\n')

rows = []


def scenario(sid, title, args, expect_code, expect_text, env=None, note="", needs_network=False):
    if needs_network and not network_ok():
        rows.append((sid, title, "sentinel " + " ".join(args), f"exit {expect_code}", "NOT RUN (no network)", "n/a", note))
        return
    code, out, err = sentinel(args, env)
    text = out + err
    ok = code == expect_code and all(re.search(t, text) for t in expect_text)
    summary = f"exit {code}; " + (line(out, "Findings:") if "Findings:" in out else line(err, "error:")).strip()
    rows.append((sid, title, "sentinel " + " ".join(args), f"exit {expect_code}; matches {expect_text}", summary,
                 "PASS" if ok else "FAIL", note))


scenario("S1", "Clean project, registry answers from fixture", ["scan", CLEAN, "--registry-fixture", f"{CLEAN}/registry-fixture.json"],
         0, [r"Policy: PASS", r"CRITICAL 0  HIGH 0  MEDIUM 0"], note="Demonstrates a clean scan.")
scenario("S2", "Project with deliberate dependency-confusion and typosquat patterns",
         ["scan", VULN, "--registry-fixture", f"{VULN}/registry-fixture.json"], 1,
         [r"Policy: BLOCKED", r"CRITICAL 2  HIGH 3  MEDIUM 1", r"@acme-demo/auth", r"reqeusts"],
         note="Higher public version, public lockfile source, extra index, two lookalikes, one exposed name.")
scenario("S3", "Same project, blocking threshold raised to CRITICAL", ["scan", VULN, "--registry-fixture", f"{VULN}/registry-fixture.json", "--fail-on", "critical"],
         1, [r"CRITICAL 2  HIGH 3  MEDIUM 1"], note="Two CRITICAL findings still block.")
scenario("S4", "Same project, policy never blocks", ["scan", VULN, "--registry-fixture", f"{VULN}/registry-fixture.json", "--fail-on", "never"],
         0, [r"CRITICAL 2  HIGH 3  MEDIUM 1", r"fail_on=never"], note="Severity is unchanged; only the decision changes.")
scenario("S5", "Registry evidence unavailable (every lookup fails)", ["scan", CLEAN, "--registry-fixture", f"{CLEAN}/registry-error-fixture.json"],
         2, [r"SCANNER ERROR", r"registry lookup failed"], note="An outage is a scanner error, never a pass.")
scenario("S6", "Offline scan (no registry checks) of the vulnerable project", ["scan", VULN], 1,
         [r"Registry mode: off", r"partial evidence: 7", r"registry\.npmjs\.org"],
         note="Lockfile evidence still blocks offline; version evidence needs the registry.")
scenario("S7", "Offline scan of the clean project", ["scan", CLEAN], 0, [r"Registry mode: off", r"partial evidence: 5"],
         note="Passes, but every assessment is flagged partial.")
(tmp / "incomplete.toml").write_text("[policy]\nblock_on_incomplete = true\n")
scenario("S8", "Offline clean scan with block_on_incomplete = true", ["scan", CLEAN, "--config", str(tmp / "incomplete.toml")], 1,
         [r"incomplete evidence"], note="Teams can refuse to pass on partial evidence.")
scenario("S9", "Invalid configuration (weights do not sum to 1)", ["scan", CLEAN, "--config", str(tmp / "bad.toml")], 2,
         [r"sum to 1\.0"], note="A bad security config is an error, not ignored.")
scenario("S10", "Privacy mode: internal names not sent to registries", ["scan", CLEAN, "--config", str(tmp / "privacy.toml"),
         "--registry-fixture", f"{CLEAN}/registry-fixture.json", "--format", "json"], 0, [r'"status": "skipped"', r"privacy mode"],
         note="Internal lookups are SKIPPED (see docs/ARCHITECTURE.md for what is sent otherwise).")
scenario("S11", "Live NPM/PyPI lookup of the fictional @acme-demo fixture", ["scan", "examples/acme-demo-fixture", "--registry", "--timeout", "10"], 0,
         [r"Registry mode: live", r"Registry lookups: 13", r"error: 0"],
         note="Uses the real registries; results depend on the day (fictional names could be registered later).", needs_network=True)
scenario("S12", "Network outage simulated with a proxy to a closed port", ["scan", "examples/acme-demo-fixture", "--registry", "--timeout", "3"], 2,
         [r"Registry lookups: 13", r"error: 13", r"registry lookup failed"], env={"HTTPS_PROXY": "http://127.0.0.1:9", "HTTP_PROXY": "http://127.0.0.1:9"},
         note="Real aiohttp connection failures after retries; exit 2, never a pass.", needs_network=True)

passed = sum(1 for r in rows if r[5] == "PASS")
failed = [r for r in rows if r[5] == "FAIL"]
md = ["# End-to-end scenarios (observed)", "",
      f"Generated by `scripts/run_scenarios.py` on {datetime.date.today()} with Python {platform.python_version()} on {platform.platform()}.",
      "The *Observed* column is the real output of the real CLI in that run, not a prediction.", "",
      f"**Result: {passed} of {len(rows)} scenarios matched expectations**"
      + (f"; FAILED: {', '.join(r[0] for r in failed)}" if failed else "") + ".", "",
      "| ID | Scenario | Expected | Observed | Pass? | What it demonstrates |", "|---|---|---|---|---|---|"]
for sid, title, cmd, exp, obs, ok, note in rows:
    md.append(f"| {sid} | {title}<br>`{cmd}` | {exp} | {obs} | {ok} | {note} |")
md += ["", "S11 and S12 need internet access (S12 uses a proxy pointing at a closed local port to fail every request).",
       "Registry fixtures (S1-S10) are local JSON files, so those scenarios are deterministic and clearly labelled `fixture` mode in every report.", ""]
(ROOT / "docs").mkdir(exist_ok=True)
(ROOT / "docs" / "SCENARIOS.md").write_text("\n".join(md), encoding="utf-8")
print("\n".join(f"{r[0]:4}{r[5]:8}{r[1]}" for r in rows))
print(f"{passed}/{len(rows)} matched")
sys.exit(1 if failed else 0)
