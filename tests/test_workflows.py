"""Static checks on the GitHub Actions files. These do NOT prove the workflows run on GitHub."""
import re
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = sorted((ROOT / ".github" / "workflows").glob("*.yml")) + [ROOT / "examples" / "workflows" / "protected-build.yml"]
ACTION = ROOT / "action.yml"
UNTRUSTED = re.compile(r"\$\{\{\s*(inputs\.|github\.event\.|github\.head_ref|steps\.[^}]*outputs)")


def load(path):
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def steps_of(doc):
    if "runs" in doc:
        yield from doc["runs"]["steps"]
    for job in (doc.get("jobs") or {}).values():
        yield from job.get("steps", [])


@pytest.mark.parametrize("path", WORKFLOWS + [ACTION], ids=lambda p: p.name)
def test_files_are_valid_yaml(path):
    assert isinstance(load(path), dict)


@pytest.mark.parametrize("path", WORKFLOWS, ids=lambda p: p.name)
def test_workflows_declare_least_privilege_permissions(path):
    doc = load(path)
    assert doc["permissions"] == {"contents": "read"}              # top-level default is read-only
    for name, job in doc["jobs"].items():
        extra = job.get("permissions", {})
        assert set(extra) <= {"contents", "security-events"}, name
        if "security-events" in extra:
            assert extra["security-events"] == "write" and "sarif" in name


@pytest.mark.parametrize("path", WORKFLOWS, ids=lambda p: p.name)
def test_no_dangerous_triggers(path):
    text = path.read_text()
    assert "pull_request_target" not in text and "workflow_run" not in text


@pytest.mark.parametrize("path", WORKFLOWS + [ACTION], ids=lambda p: p.name)
def test_no_untrusted_expressions_inside_run_scripts(path):
    for step in steps_of(load(path)):
        script = step.get("run", "")
        assert not UNTRUSTED.search(script), f"script injection risk in step: {step.get('name')}"


@pytest.mark.parametrize("path", WORKFLOWS + [ACTION], ids=lambda p: p.name)
def test_third_party_actions_are_versioned(path):
    for step in steps_of(load(path)):
        uses = step.get("uses")
        if uses and not uses.startswith("./"):
            assert re.search(r"@(v\d+(\.\d+){0,2}|[0-9a-f]{40})$", uses), uses


def test_action_uploads_reports_even_on_failure_and_enforces_last():
    steps = load(ACTION)["runs"]["steps"]
    names = [s.get("name") for s in steps]
    upload = next(s for s in steps if s.get("uses", "").startswith("actions/upload-artifact"))
    assert "always()" in upload["if"]
    assert names[-1] == "Enforce gate"                              # verdict applied after upload
    scan = next(s for s in steps if s.get("id") == "scan")
    last = [l.strip() for l in scan["run"].splitlines() if l.strip() and not l.strip().startswith("#")][-1]
    assert last == "exit 0"                                         # scan step never fails the job itself


def test_action_distinguishes_policy_failure_from_scanner_error():
    enforce = load(ACTION)["runs"]["steps"][-1]["run"]
    assert re.search(r'1\)[^;]*policy gate', enforce) and re.search(r'2\)[^;]*scanner error', enforce)
    assert "NOT a pass" in enforce


def test_action_installs_only_the_scanner_never_the_scanned_project():
    install = next(s for s in load(ACTION)["runs"]["steps"] if "Install scanner" in s.get("name", ""))["run"]
    assert "requirements-scanner.txt" in install and "npm" not in install
    assert "inputs.path" not in install


def test_protected_build_installs_dependencies_only_after_the_gate():
    doc = load(ROOT / "examples" / "workflows" / "protected-build.yml")
    jobs = doc["jobs"]
    assert jobs["build"]["needs"] == "security-gate"
    gate_text = str(jobs["security-gate"])
    assert "npm ci" not in gate_text and "pip install" not in gate_text
    assert any("npm ci" in s.get("run", "") for s in jobs["build"]["steps"])


def test_demo_workflow_covers_passing_and_blocking_scenarios():
    jobs = load(ROOT / ".github" / "workflows" / "demo.yml")["jobs"]
    assert {"gate-passes", "gate-blocks"} <= set(jobs)
    blocks = " ".join(s.get("run", "") for s in jobs["gate-blocks"]["steps"])
    assert 'CODE" = "1"' in blocks                                  # asserts policy block, not scanner error
    names = [s["with"]["artifact-name"] for j in jobs.values() for s in j["steps"] if "artifact-name" in s.get("with", {})]
    assert len(names) == len(set(names))                            # artifact names must be unique per run


def test_action_pins_exist_for_every_runtime_dependency():
    pins = (ROOT / "requirements-scanner.txt").read_text()
    for needed in ("aiohttp==", "Jinja2==", "packaging==", "tomli=="):
        assert needed in pins


@pytest.mark.parametrize("path", WORKFLOWS + [ACTION], ids=lambda p: p.name)
def test_run_scripts_contain_no_expression_syntax_at_all(path):
    # GitHub evaluates ${{ }} even inside shell comments; values must arrive via env: instead.
    for step in steps_of(load(path)):
        assert "${{" not in step.get("run", ""), step.get("name")
