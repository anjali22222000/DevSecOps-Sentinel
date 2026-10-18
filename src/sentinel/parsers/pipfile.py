"""Parser for Pipfile.lock (secondary priority; never installs anything)."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from sentinel.analysis.names import normalize_name
from sentinel.models import (
    Dependency, Diagnostic, Ecosystem, Origin, ParseResult, ParserError,
    RegistryOption, SourceType,
)
from sentinel.privacy import redact_url


def parse_pipfile_lock(path: Path) -> ParseResult:
    try:
        data: Any = json.loads(path.read_text(encoding="utf-8-sig"))
    except json.JSONDecodeError as exc:
        raise ParserError(f"invalid JSON in {path.name}: {exc}") from exc
    except (OSError, UnicodeDecodeError) as exc:
        raise ParserError(f"cannot read {path.name}: {exc}") from exc
    if not isinstance(data, dict):
        raise ParserError(f"{path.name}: top-level value must be a JSON object")

    result = ParseResult()
    sources: dict[str, str] = {}
    meta = data.get("_meta")
    raw_sources = meta.get("sources", []) if isinstance(meta, dict) else []
    for position, source in enumerate(raw_sources if isinstance(raw_sources, list) else []):
        if not isinstance(source, dict) or not isinstance(source.get("url"), str):
            continue
        url = redact_url(source["url"])
        if isinstance(source.get("name"), str):
            sources[source["name"]] = url
        # Pipenv passes the first source as --index-url and the rest as --extra-index-url.
        kind = "index-url" if position == 0 else "extra-index-url"
        result.registry_options.append(RegistryOption(kind, url, path.name, 1))

    found_section = False
    for section in ("default", "develop"):
        block = data.get(section)
        if block is None:
            continue
        found_section = True
        if not isinstance(block, dict):
            result.warnings.append(Diagnostic(path.name, f"'{section}' is not an object; skipped"))
            continue
        for raw_name, entry in block.items():
            if not isinstance(entry, dict):
                result.warnings.append(Diagnostic(path.name, f"entry '{raw_name}' is not an object; skipped"))
                continue
            source_type, spec, pinned, resolved = SourceType.REGISTRY, "", None, None
            if "git" in entry:
                source_type, spec = SourceType.GIT, redact_url(str(entry["git"]))
            elif "path" in entry or "file" in entry:
                source_type, spec = SourceType.LOCAL, redact_url(str(entry.get("path") or entry.get("file")))
            else:
                spec = str(entry.get("version", ""))
                if spec.startswith("==") and not spec.endswith(".*"):
                    pinned = spec[2:]
                index = entry.get("index")
                resolved = sources.get(index) if isinstance(index, str) else None
            result.dependencies.append(Dependency(
                name=normalize_name(Ecosystem.PYPI, raw_name), ecosystem=Ecosystem.PYPI,
                origin=Origin.LOCKFILE, source_file=path.name, section=section,
                version_spec=spec, pinned_version=pinned, source_type=source_type,
                resolved_url=resolved, editable=bool(entry.get("editable", False))))
    if not found_section:
        result.warnings.append(Diagnostic(path.name, "no 'default' or 'develop' section found"))
    return result
