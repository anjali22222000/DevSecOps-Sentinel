import pytest

from sentinel.config import PolicyConfig
from sentinel.models import Finding, Severity
from sentinel.policy import decide


def finding(fid, severity, assessment="complete"):
    return Finding(id=fid, rule_id="R", kind="dependency", title="t", reason="r", ecosystem=None,
                   package=fid, versions=(), indicators=(), formula_score=None, floor=None,
                   floor_reason=None, score=0, severity=severity, assessment=assessment,
                   evidence=(), limitations=(), recommendation="", locations=())


ALL = [finding("a", Severity.CRITICAL), finding("b", Severity.HIGH),
       finding("c", Severity.MEDIUM), finding("d", Severity.SAFE)]


@pytest.mark.parametrize("fail_on, blocking", [
    ("critical", ["a"]), ("high", ["a", "b"]), ("medium", ["a", "b", "c"]), ("never", []),
])
def test_threshold_decides_blocking_independently_of_severity(fail_on, blocking):
    d = decide(ALL, PolicyConfig(fail_on=fail_on), scanner_error=False)
    assert list(d.blocking_findings) == blocking
    assert d.blocked is bool(blocking) and d.exit_code == (1 if blocking else 0)


def test_safe_findings_never_block():
    assert decide([finding("d", Severity.SAFE)], PolicyConfig(fail_on="medium"), False).exit_code == 0


def test_scanner_error_without_block_is_exit_2_never_pass():
    d = decide([finding("d", Severity.SAFE)], PolicyConfig(), scanner_error=True)
    assert d.exit_code == 2 and not d.blocked and d.scanner_error


def test_block_takes_precedence_over_scanner_error():
    d = decide(ALL, PolicyConfig(fail_on="high"), scanner_error=True)
    assert d.exit_code == 1 and d.scanner_error


def test_scanner_error_with_fail_on_never_is_still_exit_2():
    assert decide(ALL, PolicyConfig(fail_on="never"), scanner_error=True).exit_code == 2


def test_block_on_incomplete():
    findings = [finding("p", Severity.SAFE, assessment="partial")]
    assert decide(findings, PolicyConfig(), False).exit_code == 0
    d = decide(findings, PolicyConfig(block_on_incomplete=True), False)
    assert d.exit_code == 1 and list(d.blocking_findings) == ["p"]
