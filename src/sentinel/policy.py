"""Policy: decides whether to block. Separate from severity classification."""
from __future__ import annotations

from sentinel.config import PolicyConfig
from sentinel.models import Finding, PolicyDecision, Severity

EXIT_OK = 0
EXIT_POLICY_BLOCK = 1
EXIT_ERROR = 2

_THRESHOLD = {"critical": Severity.CRITICAL, "high": Severity.HIGH, "medium": Severity.MEDIUM}


def decide(findings: list[Finding], policy: PolicyConfig, scanner_error: bool) -> PolicyDecision:
    """Exit codes: 1 = policy block, 2 = scanner error (no block), 0 = pass.

    A policy block takes precedence over a scanner error because it is the more specific
    security verdict; either way the pipeline fails. A scanner error is never a pass.
    """
    reasons: list[str] = []
    blocking: list[str] = []
    threshold = _THRESHOLD.get(policy.fail_on)
    if threshold is not None:
        for f in findings:
            if f.severity.rank >= threshold.rank:
                blocking.append(f.id)
        if blocking:
            reasons.append(f"{len(blocking)} finding(s) at or above {threshold.value}")
    if policy.block_on_incomplete:
        partial = [f.id for f in findings if f.assessment == "partial"]
        if partial:
            blocking.extend(i for i in partial if i not in blocking)
            reasons.append(f"{len(partial)} finding(s) have incomplete evidence (block_on_incomplete)")

    blocked = bool(blocking)
    if scanner_error:
        reasons.append("scanner error: evidence could not be fully collected")
    if blocked:
        code = EXIT_POLICY_BLOCK
    elif scanner_error:
        code = EXIT_ERROR
    else:
        code = EXIT_OK
    if code == EXIT_OK:
        reasons.append("no findings at or above the blocking threshold"
                       if policy.fail_on != "never" else "policy fail_on = never")
    return PolicyDecision(blocked, policy.fail_on, tuple(blocking), scanner_error, code, tuple(reasons))
