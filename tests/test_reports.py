import json
import re
from importlib import resources
from pathlib import Path

import pytest

from sentinel.cli import main
from sentinel.config import parse_config
from sentinel.models import ParseResult
from sentinel.reporting.html_report import render_html
from sentinel.reporting.json_report import SCHEMA_VERSION, build_report
from sentinel.reporting.sarif import build_sarif, validate_sarif
from sentinel.scanner import build_result
from helpers import dep

ROOT = Path(__file__).resolve().parents[1]
VULN = ROOT / "examples" / "vulnerable-demo"
CLEAN = ROOT / "examples" / "clean-demo"


@pytest.fixture()
def vuln_reports(tmp_path):
    out = tmp_path / "reports"
    code = main(["scan", str(VULN), "--registry-fixture", str(VULN / "registry-fixture.json"),
                 "--output-dir", str(out)])
    assert code == 1
    return out


def load(out):
    return (json.loads((out / "report.json").read_text()),
            (out / "report.html").read_text(),
            json.loads((out / "report.sarif").read_text()))


def test_all_four_files_are_written_even_when_the_build_is_blocked(vuln_reports):
    for name in ("report.json", "report.html", "report.sarif", "dashboard.html"):
        assert (vuln_reports / name).stat().st_size > 0


def test_json_report_structure(vuln_reports):
    report, _, _ = load(vuln_reports)
    assert report["schema_version"] == SCHEMA_VERSION
    assert report["metadata"]["registry_mode"] == "fixture" and report["metadata"]["demo_data"] is True
    s = report["summary"]
    assert sum(s["findings_by_severity"].values()) == len(report["findings"]) == s["findings_total"]
    assert report["policy"]["exit_code"] == 1 and report["policy"]["blocked"] is True
    f = report["findings"][0]
    for key in ("id", "rule_id", "severity", "score", "indicators", "evidence", "limitations",
                "recommendation", "locations", "assessment", "reason"):
        assert key in f
    assert {i["key"] for i in f["indicators"]} == {"V", "S", "T"}


def test_sarif_is_structurally_valid(vuln_reports):
    _, _, sarif = load(vuln_reports)
    assert validate_sarif(sarif) == []
    assert sarif["version"] == "2.1.0" and len(sarif["runs"]) == 1
    run = sarif["runs"][0]
    assert run["invocations"][0]["executionSuccessful"] is True
    assert {r["id"] for r in run["tool"]["driver"]["rules"]} >= {"SENT-DC-001", "SENT-TS-001", "SENT-CFG-001"}


def test_all_three_formats_agree_on_counts_scores_and_severities(vuln_reports):
    report, html, sarif = load(vuln_reports)
    non_safe = {f["id"]: f for f in report["findings"] if f["severity"] != "SAFE"}
    results = sarif["runs"][0]["results"]
    assert len(results) == len(non_safe)
    for r in results:
        f = non_safe[r["properties"]["finding_id"]]
        assert r["properties"]["score"] == f["score"] and r["properties"]["severity"] == f["severity"]
        assert r["ruleId"] == f["rule_id"]
        assert r["level"] == ("error" if f["severity"] in ("CRITICAL", "HIGH") else "warning")
    html_ids = re.findall(r'<td class="mono">(F\d{3})</td>', html)
    assert html_ids == [f["id"] for f in report["findings"]]
    for sev, n in report["summary"]["findings_by_severity"].items():
        assert f'<b class="{sev}">{n}</b>' in html


def test_sarif_locations_point_at_declaring_files_with_real_lines(vuln_reports):
    _, _, sarif = load(vuln_reports)
    locs = {r["properties"]["package"]: r["locations"][0]["physicalLocation"]
            for r in sarif["runs"][0]["results"] if "package" in r["properties"]}
    assert locs["reqeusts"]["region"]["startLine"] == 2
    assert locs["reqeusts"]["artifactLocation"]["uri"].endswith("requirements.txt")
    assert locs["expresss"]["region"]["startLine"] >= 1
    assert all(p["artifactLocation"]["uriBaseId"] == "%SRCROOT%" for p in locs.values())


def test_sarif_fingerprints_are_stable_and_unique(vuln_reports):
    first = [r["partialFingerprints"]["sentinelFingerprint/v1"] for r in load(vuln_reports)[2]["runs"][0]["results"]]
    assert len(first) == len(set(first))
    again = main(["scan", str(VULN), "--registry-fixture", str(VULN / "registry-fixture.json"),
                  "--output-dir", str(vuln_reports / "second")])
    second = [r["partialFingerprints"]["sentinelFingerprint/v1"]
              for r in json.loads((vuln_reports / "second" / "report.sarif").read_text())["runs"][0]["results"]]
    assert first == second and again == 1


def test_clean_scan_has_no_sarif_results_and_html_says_passed(tmp_path):
    out = tmp_path / "r"
    assert main(["scan", str(CLEAN), "--registry-fixture", str(CLEAN / "registry-fixture.json"),
                 "--output-dir", str(out)]) == 0
    report, html, sarif = load(out)
    assert sarif["runs"][0]["results"] == [] and validate_sarif(sarif) == []
    assert "<b>Passed.</b>" in html and report["summary"]["findings_by_severity"]["CRITICAL"] == 0


def test_scanner_error_is_reflected_in_every_format(tmp_path):
    out = tmp_path / "r"
    assert main(["scan", str(CLEAN), "--registry-fixture", str(CLEAN / "registry-error-fixture.json"),
                 "--output-dir", str(out)]) == 2
    report, html, sarif = load(out)
    assert report["policy"]["exit_code"] == 2 and report["summary"]["scanner_errors"] > 0
    assert sarif["runs"][0]["invocations"][0]["executionSuccessful"] is False
    assert sarif["runs"][0]["invocations"][0]["toolExecutionNotifications"]
    assert "<b>Scanner error.</b>" in html


def test_html_escapes_untrusted_package_names():
    evil = '<script>alert("x")</script>'
    parse = ParseResult(dependencies=[dep(evil, pinned="1.0.0")])
    result = build_result(Path("."), parse_config({}), parse, {}, "off")
    html = render_html(result)
    assert evil not in html and "&lt;script&gt;" in html


def test_report_is_valid_json_with_unusual_names():
    name = 'weird"name\\with\u2028chars'
    parse = ParseResult(dependencies=[dep(name, pinned="1.0.0")])
    result = build_result(Path("."), parse_config({}), parse, {}, "off")
    assert json.loads(json.dumps(build_report(result)))["findings"][0]["package"] == name
    assert validate_sarif(build_sarif(result)) == []


@pytest.mark.parametrize("mutate, expected", [
    (lambda d: d.update(version="2.0"), "version"),
    (lambda d: d.pop("$schema"), "$schema"),
    (lambda d: d["runs"][0]["results"][0].update(ruleId="NOPE"), "ruleId"),
    (lambda d: d["runs"][0]["results"][0].update(level="fatal"), "level"),
    (lambda d: d["runs"][0]["results"][0].update(locations=[]), "location"),
    (lambda d: d["runs"][0]["results"][0]["message"].update(text=""), "message"),
    (lambda d: d["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"].update(startLine=0), "startLine"),
    (lambda d: d["runs"][0]["tool"]["driver"].update(name=""), "driver.name"),
])
def test_sarif_validator_catches_problems(vuln_reports, mutate, expected):
    doc = load(vuln_reports)[2]
    mutate(doc)
    problems = validate_sarif(doc)
    assert problems and any(expected in p for p in problems)


def test_dashboard_never_inserts_data_as_html_and_has_no_external_resources():
    page = resources.files("sentinel.dashboard").joinpath("index.html").read_text(encoding="utf-8")
    for forbidden in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "new Function"):
        assert forbidden not in page
    assert "textContent" in page or "createTextNode" in page
    assert not re.search(r'(src|href)="https?://', page)
    assert "<link" not in page.lower()


def test_dashboard_copy_matches_packaged_file(vuln_reports):
    packaged = resources.files("sentinel.dashboard").joinpath("index.html").read_text(encoding="utf-8")
    assert (vuln_reports / "dashboard.html").read_text(encoding="utf-8") == packaged
