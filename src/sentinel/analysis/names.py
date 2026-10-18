"""Package-name normalization rules per ecosystem."""
from __future__ import annotations

import re

from sentinel.models import Ecosystem

_PYPI_SEPARATORS = re.compile(r"[-_.]+")


def normalize_name(ecosystem: Ecosystem, name: str) -> str:
    """Return the canonical form of a package name.

    PyPI (PEP 503): runs of '-', '_' and '.' are equivalent, case-insensitive.
    NPM: names are lowercase; scopes ('@scope/name') are kept intact.
    """
    name = name.strip()
    if ecosystem is Ecosystem.PYPI:
        return _PYPI_SEPARATORS.sub("-", name).lower()
    return name.lower()


def npm_scope(name: str) -> str | None:
    """'@acme-demo/auth' -> '@acme-demo'; unscoped names -> None."""
    if name.startswith("@") and "/" in name:
        return name.split("/", 1)[0]
    return None
