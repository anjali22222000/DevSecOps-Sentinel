"""Builders shared by analyzer / report tests."""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from sentinel.analyzer import analyze
from sentinel.config import parse_config
from sentinel.models import (
    Dependency, Ecosystem, LookupStatus, Origin, ParseResult, RegistryEvidence, SourceType,
)

NOW = datetime(2026, 10, 17, tzinfo=timezone.utc)


def dep(name, eco=Ecosystem.NPM, pinned=None, spec="", origin=Origin.MANIFEST, resolved=None,
        source=SourceType.REGISTRY, file="package.json", line=None, alias=None):
    return Dependency(name=name, ecosystem=eco, origin=origin, source_file=file, section="dependencies",
                      version_spec=spec or pinned or "", pinned_version=pinned, source_type=source,
                      resolved_url=resolved, line=line, alias=alias)


def ev(name, status=LookupStatus.FOUND, eco=Ecosystem.NPM, versions=(), latest=None, first=None, detail=None):
    return RegistryEvidence(ecosystem=eco, name=name, status=status, registry_url="fixture://t",
                            latest_version=latest, versions=tuple(versions), first_published=first,
                            detail=detail)


def run(deps, evidence=(), config=None, options=(), root=Path(".")):
    cfg = config or parse_config({})
    parse = ParseResult(dependencies=list(deps), registry_options=list(options))
    emap = {(e.ecosystem, e.name): e for e in evidence}
    return analyze(parse, emap, cfg, root, NOW)


def by_package(findings):
    return {f.package: f for f in findings if f.package}


ACME = parse_config({"internal": {"npm": {"scopes": ["@acme-demo"]}, "pypi": {"prefixes": ["acme-demo-"]}}})
ACME_OWNED = parse_config({"internal": {"npm": {"scopes": ["@acme-demo"]}, "owned_public": ["npm:@acme-demo"]}})
