"""Parsers for package.json and package-lock.json (never installs anything)."""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from sentinel.analysis.names import normalize_name
from sentinel.models import (
    Dependency, Diagnostic, Ecosystem, Origin, ParseResult, ParserError, SourceType,
)
from sentinel.privacy import redact_url

MANIFEST_SECTIONS = (
    "dependencies", "devDependencies", "optionalDependencies", "peerDependencies",
)
_EXACT_VERSION = re.compile(r"^=?v?(\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.+-]+)?)$")
_GITHUB_SHORTHAND = re.compile(r"^[\w.-]+/[\w.-]+(?:#.*)?$")
_GIT_PREFIXES = ("git+", "git:", "git@", "github:", "gitlab:", "bitbucket:", "gist:")
_LOCAL_PREFIXES = ("file:", "link:", "workspace:", "portal:", "./", "../", "/", "~/")


def _read_json(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8-sig"))
    except json.JSONDecodeError as exc:
        raise ParserError(f"invalid JSON in {path.name}: {exc}") from exc
    except (OSError, UnicodeDecodeError) as exc:
        raise ParserError(f"cannot read {path.name}: {exc}") from exc
    if not isinstance(data, dict):
        raise ParserError(f"{path.name}: top-level value must be a JSON object")
    return data


def _split_alias(spec: str) -> tuple[str, str]:
    """'npm:@scope/pkg@^1.0.0' -> ('@scope/pkg', '^1.0.0')."""
    rest = spec[len("npm:"):]
    at = rest.find("@", 1) if rest.startswith("@") else rest.find("@")
    if at == -1:
        return rest, ""
    return rest[:at], rest[at + 1:]


def _classify_spec(spec: str) -> SourceType:
    if spec.startswith(_LOCAL_PREFIXES):
        return SourceType.LOCAL
    if spec.startswith(("http://", "https://")):
        return SourceType.URL
    if spec.startswith(_GIT_PREFIXES) or _GITHUB_SHORTHAND.match(spec):
        return SourceType.GIT
    return SourceType.REGISTRY


def _manifest_dependency(declared: str, spec: str, section: str, source_file: str) -> Dependency:
    spec = spec.strip()
    name, alias, version_spec = declared, None, spec
    if spec.startswith("npm:"):
        name, version_spec = _split_alias(spec)
        alias = declared
        source_type = SourceType.REGISTRY
    else:
        source_type = _classify_spec(spec)

    pinned = None
    if source_type is SourceType.REGISTRY:
        match = _EXACT_VERSION.match(version_spec)
        pinned = match.group(1) if match else None
    else:
        version_spec = redact_url(spec)

    return Dependency(
        name=normalize_name(Ecosystem.NPM, name),
        ecosystem=Ecosystem.NPM,
        origin=Origin.MANIFEST,
        source_file=source_file,
        section=section,
        version_spec=version_spec,
        pinned_version=pinned,
        source_type=source_type,
        alias=alias,
    )


def parse_package_json(path: Path) -> ParseResult:
    data = _read_json(path)
    result = ParseResult()
    for section in MANIFEST_SECTIONS:
        block = data.get(section)
        if block is None:
            continue
        if not isinstance(block, dict):
            result.warnings.append(
                Diagnostic(path.name, f"'{section}' is not an object; section skipped"))
            continue
        for declared, spec in block.items():
            if not isinstance(spec, str):
                result.warnings.append(
                    Diagnostic(path.name, f"'{declared}' in '{section}' has a non-string version; skipped"))
                continue
            result.dependencies.append(_manifest_dependency(declared, spec, section, path.name))
    return result


def _lock_dependency(result: ParseResult, path: Path, key_name: str, entry: Any) -> None:
    if not isinstance(entry, dict):
        result.warnings.append(Diagnostic(path.name, f"entry '{key_name}' is not an object; skipped"))
        return

    name = entry.get("name", key_name)   # v2/v3: aliases carry the real name here
    version = entry.get("version", "")
    version = version if isinstance(version, str) else ""
    resolved = entry.get("resolved")
    resolved = resolved if isinstance(resolved, str) else None

    if version.startswith("npm:"):       # v1: alias encoded in the version field
        name, version = _split_alias(version)
    alias = key_name if name != key_name else None

    if entry.get("link") is True:
        source_type = SourceType.LOCAL
    elif version.startswith(("http://", "https://")):
        source_type = SourceType.URL
    elif version.startswith(_GIT_PREFIXES) or (resolved or "").startswith("git+"):
        source_type = SourceType.GIT
    else:
        source_type = SourceType.REGISTRY

    result.dependencies.append(Dependency(
        name=normalize_name(Ecosystem.NPM, name),
        ecosystem=Ecosystem.NPM,
        origin=Origin.LOCKFILE,
        source_file=path.name,
        section="lockfile",
        version_spec=redact_url(version) if source_type is not SourceType.REGISTRY else version,
        pinned_version=(version or None) if source_type is SourceType.REGISTRY else None,
        source_type=source_type,
        alias=alias,
        resolved_url=redact_url(resolved) if resolved else None,
    ))


def _walk_v1(result: ParseResult, path: Path, deps: dict[str, Any]) -> None:
    for key_name, entry in deps.items():
        _lock_dependency(result, path, key_name, entry)
        if isinstance(entry, dict) and isinstance(entry.get("dependencies"), dict):
            _walk_v1(result, path, entry["dependencies"])


def parse_package_lock(path: Path) -> ParseResult:
    data = _read_json(path)
    result = ParseResult()
    packages = data.get("packages")
    if isinstance(packages, dict):                       # lockfileVersion 2 and 3
        for key, entry in packages.items():
            if key == "" or "node_modules/" not in key:  # root project / workspace folders
                continue
            _lock_dependency(result, path, key.rsplit("node_modules/", 1)[-1], entry)
    elif isinstance(data.get("dependencies"), dict):     # lockfileVersion 1
        _walk_v1(result, path, data["dependencies"])
    else:
        result.warnings.append(
            Diagnostic(path.name, "no 'packages' or 'dependencies' section found"))
    return result
