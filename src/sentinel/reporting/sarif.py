"""SARIF 2.1.0 report (for GitHub code scanning) plus a structural validator."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any

from sentinel import __version__
from sentinel.models import Severity
from sentinel.rules import RULES
from sentinel.scanner import ScanResult

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"

# GitHub maps numeric security-severity: >9.0 critical, 7.0-8.9 high, 4.0-6.9 medium, 0.1-3.9 low
_SECURITY_SEVERITY = {Severity.CRITICAL: "9.5", Severity.HIGH: "8.0", Severity.MEDIUM: "5.0"}
_RULE_DEFAULTS = {  # (level, security-severity)
    "SENT-DC-001": ("error", "9.5"), "SENT-DC-002": ("warning", "5.0"),
    "SENT-TS-001": ("warning", "7.5"), "SENT-CFG-001": ("warning", "5.5"),
    "SENT-CFG-002": ("warning", "5.0"), "SENT-CFG-003": ("error", "7.5"),
}
_VALID_LEVELS = {"none", "note", "warning", "error"}


def _level(severity: Severity) -> str:
    return "error" if severity.rank >= Severity.HIGH.rank else "warning"


def _uri(root: Path, filename: str) -> str:
    try:
        rel = os.path.relpath((root / filename).resolve(), start=Path.cwd())
    except ValueError:
        rel = filename
    if rel.startswith(".."):
        rel = filename
    return rel.replace("\\", "/")


def build_sarif(result: ScanResult) -> dict[str, Any]:
    rule_ids = list(RULES)
    rules = []
    for rid in rule_ids:
        rule = RULES[rid]
        level, sec = _RULE_DEFAULTS[rid]
        rules.append({
            "id": rid, "name": rule.name,
            "shortDescription": {"text": rule.short},
            "fullDescription": {"text": rule.help},
            "help": {"text": rule.help},
            "defaultConfiguration": {"level": level},
            "properties": {"tags": ["security", "supply-chain"], "security-severity": sec},
        })

    results = []
    for f in result.findings:
        if f.severity is Severity.SAFE or f.rule_id is None:
            continue
        loc = f.locations[0] if f.locations else None
        filename = loc.file if loc else "package.json"
        subject = f.package or "configuration"
        reason = f.reason
        fingerprint = hashlib.sha256(
            f"{f.rule_id}|{f.ecosystem.value if f.ecosystem else ''}|{subject}|{filename}".encode()
        ).hexdigest()[:32]
        results.append({
            "ruleId": f.rule_id,
            "ruleIndex": rule_ids.index(f.rule_id),
            "level": _level(f.severity),
            "message": {"text": f"{f.title}: {subject} scored {f.score:g} ({f.severity.value}). {reason}"},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": _uri(result.root, filename), "uriBaseId": "%SRCROOT%"},
                "region": {"startLine": max(1, loc.line or 1) if loc else 1},
            }}],
            "partialFingerprints": {"sentinelFingerprint/v1": fingerprint},
            "properties": {
                "finding_id": f.id, "severity": f.severity.value, "score": f.score,
                "assessment": f.assessment, "security-severity": _SECURITY_SEVERITY[f.severity],
                **({"package": f.package, "ecosystem": f.ecosystem.value} if f.package else {}),
            },
        })

    notifications = [{"level": "error", "message": {"text": f"{e.file}: {e.message}"}}
                     for e in result.errors]
    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [{
            "tool": {"driver": {"name": "DevSecOps Sentinel", "version": __version__,
                                "semanticVersion": __version__, "rules": rules}},
            "results": results,
            "invocations": [{"executionSuccessful": not result.errors,
                             "toolExecutionNotifications": notifications}],
        }],
    }


def render_sarif(result: ScanResult) -> str:
    return json.dumps(build_sarif(result), indent=2, ensure_ascii=False) + "\n"


def validate_sarif(doc: Any) -> list[str]:
    """Structural checks only (no network, no official JSON schema). Returns a list of problems."""
    problems: list[str] = []
    if not isinstance(doc, dict):
        return ["document is not an object"]
    if doc.get("version") != SARIF_VERSION:
        problems.append(f"version must be {SARIF_VERSION}")
    if "$schema" not in doc:
        problems.append("missing $schema")
    runs = doc.get("runs")
    if not isinstance(runs, list) or len(runs) != 1:
        return problems + ["runs must be a list with exactly one run"]
    run = runs[0]
    driver = (run.get("tool") or {}).get("driver") or {}
    if not driver.get("name"):
        problems.append("tool.driver.name is required")
    rules = driver.get("rules", [])
    ids = [r.get("id") for r in rules]
    if len(ids) != len(set(ids)) or not all(ids):
        problems.append("rule ids must be present and unique")
    for i, res in enumerate(run.get("results", [])):
        where = f"results[{i}]"
        if res.get("ruleId") not in ids:
            problems.append(f"{where}.ruleId is not a defined rule")
        elif "ruleIndex" in res and ids[res["ruleIndex"]] != res["ruleId"]:
            problems.append(f"{where}.ruleIndex does not match ruleId")
        if res.get("level") not in _VALID_LEVELS:
            problems.append(f"{where}.level is invalid")
        if not (res.get("message") or {}).get("text"):
            problems.append(f"{where}.message.text is required")
        locations = res.get("locations") or []
        if not locations:
            problems.append(f"{where} needs at least one location")
        for loc in locations:
            phys = loc.get("physicalLocation") or {}
            if not (phys.get("artifactLocation") or {}).get("uri"):
                problems.append(f"{where} location is missing artifactLocation.uri")
            start = (phys.get("region") or {}).get("startLine")
            if not isinstance(start, int) or start < 1:
                problems.append(f"{where} region.startLine must be an integer >= 1")
    return problems
