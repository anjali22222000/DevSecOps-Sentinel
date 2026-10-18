import json
import subprocess
import sys
from pathlib import Path

import pytest

from sentinel.cli import main

ROOT = Path(__file__).resolve().parents[1]
CLEAN = ROOT / "examples" / "clean-demo"
VULN = ROOT / "examples" / "vulnerable-demo"
CLEAN_FX = str(CLEAN / "registry-fixture.json")
VULN_FX = str(VULN / "registry-fixture.json")


def run(argv, capsys):
    code = main(argv)
    out = capsys.readouterr()
    return code, out.out, out.err


def test_clean_demo_passes(capsys):
    code, out, _ = run(["scan", str(CLEAN), "--registry-fixture", CLEAN_FX], capsys)
    assert code == 0 and "Policy: PASS" in out and "CRITICAL 0  HIGH 0  MEDIUM 0" in out


def test_vulnerable_demo_blocks_with_expected_findings(capsys):
    code, out, _ = run(["scan", str(VULN), "--registry-fixture", VULN_FX], capsys)
    assert code == 1 and "Policy: BLOCKED" in out
    assert "CRITICAL 2  HIGH 3  MEDIUM 1" in out
    for expected in ("@acme-demo/auth", "@acme-demo/billing", "expresss", "reqeusts", "acme-demo-reports"):
        assert expected in out


def test_fail_on_threshold_changes_only_the_decision_not_the_severities(capsys):
    never = run(["scan", str(VULN), "--registry-fixture", VULN_FX, "--fail-on", "never"], capsys)
    critical = run(["scan", str(VULN), "--registry-fixture", VULN_FX, "--fail-on", "critical"], capsys)
    medium = run(["scan", str(VULN), "--registry-fixture", VULN_FX, "--fail-on", "medium"], capsys)
    assert (never[0], critical[0], medium[0]) == (0, 1, 1)
    for _, out, _ in (never, critical, medium):
        assert "CRITICAL 2  HIGH 3  MEDIUM 1" in out


def test_registry_error_fixture_is_a_scanner_error_not_a_pass(capsys):
    code, out, err = run(["scan", str(CLEAN), "--registry-fixture", str(CLEAN / "registry-error-fixture.json")], capsys)
    assert code == 2 and "SCANNER ERROR" in out and "registry lookup failed" in err


def test_offline_scan_still_catches_lockfile_evidence_and_marks_partial(capsys):
    code, out, _ = run(["scan", str(VULN)], capsys)
    assert code == 1 and "resolved from public registry host registry.npmjs.org" in out
    assert "Registry mode: off" in out and "partial evidence: 7" in out


def test_clean_offline_is_pass_but_partial(capsys):
    code, out, _ = run(["scan", str(CLEAN)], capsys)
    assert code == 0 and "partial evidence: 5" in out


def test_block_on_incomplete_turns_offline_partial_into_a_block(tmp_path, capsys):
    cfg = tmp_path / "s.toml"
    cfg.write_text("[policy]\nblock_on_incomplete = true\n")
    code, out, _ = run(["scan", str(CLEAN), "--config", str(cfg)], capsys)
    assert code == 1 and "incomplete evidence" in out


def test_bad_config_is_exit_2(tmp_path, capsys):
    cfg = tmp_path / "bad.toml"
    cfg.write_text("[weights]\nversion=0.9\nscope=0.9\nsimilarity=0.9\n")
    code, _, err = run(["scan", str(CLEAN), "--config", str(cfg)], capsys)
    assert code == 2 and "configuration" in err and "sum to 1.0" in err


def test_missing_fixture_file_is_exit_2(capsys):
    code, _, err = run(["scan", str(CLEAN), "--registry-fixture", "/no/such/file.json"], capsys)
    assert code == 2 and "registry fixture" in err


def test_registry_and_fixture_flags_are_mutually_exclusive():
    with pytest.raises(SystemExit) as exc:
        main(["scan", str(CLEAN), "--registry", "--registry-fixture", CLEAN_FX])
    assert exc.value.code == 2


def test_json_stdout_matches_report_file(tmp_path, capsys):
    out_dir = tmp_path / "r"
    code, out, _ = run(["scan", str(VULN), "--registry-fixture", VULN_FX, "--format", "json",
                        "--output-dir", str(out_dir)], capsys)
    stdout_report = json.loads(out)
    file_report = json.loads((out_dir / "report.json").read_text())
    assert code == 1
    assert stdout_report["findings"] == file_report["findings"]
    assert stdout_report["summary"] == file_report["summary"]


def test_privacy_mode_never_queries_internal_names(tmp_path, capsys):
    cfg = tmp_path / "s.toml"
    cfg.write_text('[privacy]\nquery_internal_names = false\n[internal.npm]\nscopes = ["@acme-demo"]\n')
    code, out, _ = run(["scan", str(CLEAN), "--config", str(cfg), "--registry-fixture", CLEAN_FX,
                        "--format", "json"], capsys)
    results = {r["name"]: r for r in json.loads(out)["registry_lookup"]["results"]}
    assert results["@acme-demo/auth"]["status"] == "skipped"
    assert "privacy mode" in results["@acme-demo/auth"]["detail"]
    assert results["express"]["status"] == "found"


def test_privacy_mode_with_live_flag_sends_only_non_internal_names(tmp_path, monkeypatch, capsys):
    seen = []

    async def fake_inspect(dependencies, timeout, concurrency):
        seen.extend(d.name for d in dependencies)
        return {}

    monkeypatch.setattr("sentinel.cli._inspect", fake_inspect)
    cfg = tmp_path / "s.toml"
    cfg.write_text('[privacy]\nquery_internal_names = false\n[internal.npm]\nscopes = ["@acme-demo"]\n')
    run(["scan", str(CLEAN), "--config", str(cfg), "--registry"], capsys)
    assert "express" in seen and not any(n.startswith("@acme-demo") for n in seen)


def test_verbose_flag_is_accepted(capsys):
    assert run(["scan", str(CLEAN), "--registry-fixture", CLEAN_FX, "-v"], capsys)[0] == 0


def test_module_entry_point_exit_codes():
    blocked = subprocess.run([sys.executable, "-m", "sentinel", "scan", str(VULN),
                              "--registry-fixture", VULN_FX], capture_output=True, text=True)
    passed = subprocess.run([sys.executable, "-m", "sentinel", "scan", str(CLEAN),
                             "--registry-fixture", CLEAN_FX], capture_output=True, text=True)
    assert (blocked.returncode, passed.returncode) == (1, 0)
