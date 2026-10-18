"""Load registry evidence from a local JSON fixture (deterministic demos and tests)."""
from __future__ import annotations

import json
from pathlib import Path

from sentinel.models import Dependency, Ecosystem, LookupStatus, RegistryEvidence, SourceType


class FixtureError(Exception):
    pass


def load_fixture(path: Path, dependencies: list[Dependency]) -> dict[tuple[Ecosystem, str], RegistryEvidence]:
    """Fixture format: {"npm:name": {"status": "found", "latest_version": "1.0.0", "versions": [...]},
    "_default": "found"|"not_found"|"error"}. Unlisted names use _default (else "error")."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise FixtureError(f"cannot load registry fixture {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise FixtureError("registry fixture must be a JSON object")

    default = data.get("_default", "error")
    keys = list(dict.fromkeys(
        (d.ecosystem, d.name) for d in dependencies if d.source_type is SourceType.REGISTRY))
    out: dict[tuple[Ecosystem, str], RegistryEvidence] = {}
    for eco, name in keys:
        entry = data.get(f"{eco.value}:{name}")
        if entry is None:
            entry = {"status": default, "detail": "no fixture entry" if default == "error" else None}
        try:
            status = LookupStatus(entry["status"])
        except (KeyError, ValueError) as exc:
            raise FixtureError(f"invalid status for {eco.value}:{name}") from exc
        out[(eco, name)] = RegistryEvidence(
            ecosystem=eco, name=name, status=status,
            registry_url=f"fixture://{path.name}",
            latest_version=entry.get("latest_version"),
            versions=tuple(entry.get("versions", ())),
            first_published=entry.get("first_published"),
            detail=entry.get("detail"), attempts=0)
    return out
