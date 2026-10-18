"""Version comparison: semver for NPM, PEP 440 for PyPI. Invalid versions return None."""
from __future__ import annotations

import re
from collections.abc import Iterable

from packaging.version import InvalidVersion, Version

from sentinel.models import Ecosystem

_SEMVER = re.compile(
    r"^v?(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$")


def parse_semver(text: str) -> tuple[int, int, int, tuple[str, ...]] | None:
    match = _SEMVER.match(text.strip())
    if not match:
        return None
    major, minor, patch, pre = match.groups()
    return int(major), int(minor), int(patch), tuple(pre.split(".")) if pre else ()


def _compare_prerelease(a: tuple[str, ...], b: tuple[str, ...]) -> int:
    if not a and not b:
        return 0
    if not a:
        return 1          # a release is higher than any of its pre-releases
    if not b:
        return -1
    for x, y in zip(a, b):
        if x == y:
            continue
        x_num, y_num = x.isdigit(), y.isdigit()
        if x_num and y_num:
            return (int(x) > int(y)) - (int(x) < int(y))
        if x_num:
            return -1     # numeric identifiers sort below alphanumeric ones
        if y_num:
            return 1
        return (x > y) - (x < y)
    return (len(a) > len(b)) - (len(a) < len(b))


def compare_semver(a: str, b: str) -> int | None:
    pa, pb = parse_semver(a), parse_semver(b)
    if pa is None or pb is None:
        return None
    if pa[:3] != pb[:3]:
        return 1 if pa[:3] > pb[:3] else -1
    return _compare_prerelease(pa[3], pb[3])


def compare_versions(ecosystem: Ecosystem, a: str, b: str) -> int | None:
    """-1, 0 or 1; None when either version cannot be parsed."""
    if ecosystem is Ecosystem.PYPI:
        try:
            va, vb = Version(a), Version(b)
        except InvalidVersion:
            return None
        return (va > vb) - (va < vb)
    return compare_semver(a, b)


def highest_version(ecosystem: Ecosystem, versions: Iterable[str]) -> str | None:
    """Highest parseable version in the list (unparseable entries are ignored)."""
    best: str | None = None
    for candidate in versions:
        if best is None:
            if compare_versions(ecosystem, candidate, candidate) is not None:
                best = candidate
            continue
        result = compare_versions(ecosystem, candidate, best)
        if result is not None and result > 0:
            best = candidate
    return best
