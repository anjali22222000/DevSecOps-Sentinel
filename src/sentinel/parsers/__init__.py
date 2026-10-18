"""Discover supported dependency files in a directory and parse them."""
from __future__ import annotations

from pathlib import Path

from sentinel.models import Diagnostic, ParseResult, ParserError
from sentinel.parsers.npm import parse_package_json, parse_package_lock
from sentinel.parsers.pipfile import parse_pipfile_lock
from sentinel.parsers.python import parse_requirements_txt

_PARSERS = (
    ("package.json", parse_package_json),
    ("package-lock.json", parse_package_lock),
    ("requirements.txt", parse_requirements_txt),
    ("Pipfile.lock", parse_pipfile_lock),
)


def scan_directory(root: Path) -> ParseResult:
    """Parse every supported file directly inside `root` (not recursive yet)."""
    result = ParseResult()
    found: set[str] = set()
    for filename, parser in _PARSERS:
        path = root / filename
        if not path.is_file():
            continue
        found.add(filename)
        try:
            result.merge(parser(path))
        except ParserError as exc:
            result.errors.append(Diagnostic(filename, str(exc)))

    if not found:
        result.errors.append(Diagnostic(str(root), "no supported dependency files found"))
    elif "package.json" in found and "package-lock.json" not in found:
        result.warnings.append(Diagnostic(
            "package.json", "no package-lock.json found; transitive NPM dependencies are not analyzed"))
    return result
