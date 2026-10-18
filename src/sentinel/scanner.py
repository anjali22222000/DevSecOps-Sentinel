"""Glue: combine parsed files, registry evidence, analysis and policy into one ScanResult."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from sentinel.analyzer import analyze
from sentinel.config import Config
from sentinel.models import (
    Dependency, Diagnostic, Ecosystem, Finding, LookupStatus, ParseResult, PolicyDecision,
    RegistryEvidence, Severity, SourceType,
)
from sentinel.policy import decide

Key = tuple[Ecosystem, str]


@dataclass
class ScanResult:
    root: Path
    config: Config
    parse: ParseResult
    evidence: list[RegistryEvidence]
    findings: list[Finding]
    decision: PolicyDecision
    errors: list[Diagnostic]
    registry_mode: str                 # "off", "live" or "fixture"
    registry_source: str | None = None
    generated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat(timespec="seconds"))

    def severity_counts(self) -> dict[str, int]:
        counts = {s.value: 0 for s in Severity}
        for f in self.findings:
            counts[f.severity.value] += 1
        return counts


def split_for_lookup(dependencies: list[Dependency], config: Config
                     ) -> tuple[list[Dependency], dict[Key, RegistryEvidence]]:
    """Privacy mode: internal names are never sent to a public registry."""
    if config.query_internal_names:
        return dependencies, {}
    queryable: list[Dependency] = []
    skipped: dict[Key, RegistryEvidence] = {}
    for dep in dependencies:
        if dep.source_type is SourceType.REGISTRY and config.internal.is_internal(dep.ecosystem, dep.name):
            skipped[(dep.ecosystem, dep.name)] = RegistryEvidence(
                ecosystem=dep.ecosystem, name=dep.name, status=LookupStatus.SKIPPED, registry_url="",
                detail="privacy mode: internal name not sent to public registry")
        else:
            queryable.append(dep)
    return queryable, skipped


def build_result(root: Path, config: Config, parse: ParseResult,
                 evidence_map: dict[Key, RegistryEvidence], registry_mode: str,
                 registry_source: str | None = None, now: datetime | None = None) -> ScanResult:
    evidence = sorted(evidence_map.values(), key=lambda e: (e.ecosystem.value, e.name))
    errors = list(parse.errors)
    for e in evidence:
        if e.status is LookupStatus.ERROR:
            errors.append(Diagnostic(f"registry:{e.ecosystem.value}:{e.name}",
                                     f"registry lookup failed: {e.detail}"))
    findings = analyze(parse, evidence_map, config, root, now)
    decision = decide(findings, config.policy, scanner_error=bool(errors))
    stamp = (now or datetime.now(timezone.utc)).isoformat(timespec="seconds")
    return ScanResult(root, config, parse, evidence, findings, decision, errors,
                      registry_mode, registry_source, stamp)
