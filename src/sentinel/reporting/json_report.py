"""JSON report: the single source of truth that the HTML report and dashboard also use."""
from __future__ import annotations

import json
from dataclasses import asdict
from typing import Any

from sentinel import __version__
from sentinel.models import LookupStatus
from sentinel.scanner import ScanResult

SCHEMA_VERSION = "1.0"


def _plain(obj: Any) -> Any:
    """Dataclasses/enums/tuples -> plain JSON types."""
    return json.loads(json.dumps(asdict(obj) if hasattr(obj, "__dataclass_fields__") else obj))


def build_report(result: ScanResult) -> dict[str, Any]:
    lookup_counts = {s.value: 0 for s in LookupStatus}
    for e in result.evidence:
        lookup_counts[e.status.value] += 1
    dependency_findings = [f for f in result.findings if f.kind == "dependency"]
    return {
        "schema_version": SCHEMA_VERSION,
        "tool": {"name": "devsecops-sentinel", "version": __version__},
        "tool_version": __version__,
        "scan_root": str(result.root),
        "metadata": {
            "generated_at": result.generated_at,
            "registry_mode": result.registry_mode,
            "registry_source": result.registry_source,
            "demo_data": result.registry_mode == "fixture",
        },
        "summary": {
            "dependencies_total": len(result.parse.dependencies),
            "packages_assessed": len(dependency_findings),
            "findings_total": len(result.findings),
            "findings_by_severity": result.severity_counts(),
            "partial_assessments": sum(1 for f in result.findings if f.assessment == "partial"),
            "registry_lookups": lookup_counts,
            "scanner_errors": len(result.errors),
        },
        "policy": _plain(result.decision),
        "config": result.config.snapshot(),
        "findings": [_plain(f) for f in result.findings],
        "dependencies": [_plain(d) for d in result.parse.dependencies],
        "registry_options": [_plain(o) for o in result.parse.registry_options],
        "registry_lookup": {"enabled": result.registry_mode != "off",
                            "results": [_plain(e) for e in result.evidence]},
        "warnings": [_plain(w) for w in result.parse.warnings],
        "errors": [_plain(e) for e in result.errors],
    }


def render_json(result: ScanResult) -> str:
    return json.dumps(build_report(result), indent=2, ensure_ascii=False) + "\n"
