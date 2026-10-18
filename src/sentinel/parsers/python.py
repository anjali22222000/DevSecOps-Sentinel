"""Parser for requirements.txt (never installs anything)."""
from __future__ import annotations

import re
from collections.abc import Iterator
from pathlib import Path

from packaging.requirements import InvalidRequirement, Requirement

from sentinel.analysis.names import normalize_name
from sentinel.models import (
    Dependency, Diagnostic, Ecosystem, Origin, ParseResult, ParserError,
    RegistryOption, SourceType,
)
from sentinel.privacy import redact_url

_COMMENT = re.compile(r"(^|\s+)#.*$")
_INLINE_OPTIONS = re.compile(r"\s+--(?:hash|global-option|install-option|config-settings)\b.*$")
_EGG = re.compile(r"[#&]egg=([A-Za-z0-9_.\-]+)")

_REGISTRY_OPTIONS = {
    "-i": "index-url", "--index-url": "index-url",
    "--extra-index-url": "extra-index-url",
    "-f": "find-links", "--find-links": "find-links",
    "--trusted-host": "trusted-host",
}
_FOLLOW_OPTIONS = {"-r", "--requirement", "-c", "--constraint"}


def _logical_lines(text: str) -> Iterator[tuple[int, str]]:
    """Join backslash-continued lines; yield (first_line_number, text)."""
    buffer, start = "", 0
    for number, raw in enumerate(text.splitlines(), start=1):
        if not buffer:
            start = number
        line = raw.rstrip()
        if line.endswith("\\") and not line.lstrip().startswith("#"):
            buffer += line[:-1] + " "
            continue
        buffer += line
        yield start, buffer
        buffer = ""
    if buffer:
        yield start, buffer


def _url_source_type(url: str) -> SourceType:
    if url.startswith("git+"):
        return SourceType.GIT
    if url.startswith("file:"):
        return SourceType.LOCAL
    return SourceType.URL


def _handle_unnamed(result: ParseResult, file: str, number: int, text: str, editable: bool) -> None:
    """Handle lines that are a URL or path rather than 'name specifier'."""
    shown = redact_url(text)
    looks_like_target = "://" in text or text.startswith((".", "/", "~"))
    if not looks_like_target:
        result.warnings.append(Diagnostic(file, f"could not parse requirement '{shown}'; skipped", number))
        return
    egg = _EGG.search(text)
    if egg is None:
        result.warnings.append(Diagnostic(
            file, f"cannot determine package name for '{shown}' (no #egg=); skipped", number))
        return
    source_type = _url_source_type(text) if "://" in text else SourceType.LOCAL
    result.dependencies.append(Dependency(
        name=normalize_name(Ecosystem.PYPI, egg.group(1)),
        ecosystem=Ecosystem.PYPI, origin=Origin.MANIFEST, source_file=file,
        section="requirements", version_spec=shown, source_type=source_type,
        editable=editable, line=number,
    ))


def _handle_requirement(result: ParseResult, file: str, number: int, text: str, editable: bool) -> None:
    if not text:
        result.warnings.append(Diagnostic(file, "option is missing its value; skipped", number))
        return
    try:
        req = Requirement(text)
    except InvalidRequirement:
        _handle_unnamed(result, file, number, text, editable)
        return

    source_type, version_spec, pinned = SourceType.REGISTRY, str(req.specifier), None
    if req.url:
        source_type, version_spec = _url_source_type(req.url), redact_url(req.url)
    else:
        specs = list(req.specifier)
        if len(specs) == 1 and specs[0].operator in ("==", "===") \
                and not specs[0].version.endswith(".*"):
            pinned = specs[0].version

    result.dependencies.append(Dependency(
        name=normalize_name(Ecosystem.PYPI, req.name),
        ecosystem=Ecosystem.PYPI, origin=Origin.MANIFEST, source_file=file,
        section="requirements", version_spec=version_spec, pinned_version=pinned,
        source_type=source_type, marker=str(req.marker) if req.marker else None,
        editable=editable, line=number,
    ))


def _handle_option(result: ParseResult, file: str, number: int, line: str) -> None:
    parts = re.split(r"[=\s]+", line, maxsplit=1)
    flag = parts[0]
    value = parts[1].strip() if len(parts) > 1 else ""

    if flag in _REGISTRY_OPTIONS:
        if not value:
            result.warnings.append(Diagnostic(file, f"'{flag}' is missing its value; skipped", number))
            return
        result.registry_options.append(RegistryOption(
            kind=_REGISTRY_OPTIONS[flag], value=redact_url(value), source_file=file, line=number))
    elif flag == "--no-index":
        result.registry_options.append(RegistryOption("no-index", "", file, number))
    elif flag in ("-e", "--editable"):
        _handle_requirement(result, file, number, value, editable=True)
    elif flag in _FOLLOW_OPTIONS:
        result.warnings.append(Diagnostic(
            file, f"'{flag} {redact_url(value)}' is not followed; dependencies in that file are not scanned", number))
    else:
        result.warnings.append(Diagnostic(file, f"unsupported option '{flag}' ignored", number))


def parse_requirements_txt(path: Path) -> ParseResult:
    try:
        text = path.read_text(encoding="utf-8-sig")
    except (OSError, UnicodeDecodeError) as exc:
        raise ParserError(f"cannot read {path.name}: {exc}") from exc

    result = ParseResult()
    for number, raw in _logical_lines(text):
        line = _INLINE_OPTIONS.sub("", _COMMENT.sub("", raw)).strip()
        if not line:
            continue
        if line.startswith("-"):
            _handle_option(result, path.name, number, line)
        else:
            _handle_requirement(result, path.name, number, line, editable=False)
    return result
