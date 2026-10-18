"""Core data models shared by every Sentinel module."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any


class ParserError(Exception):
    """A manifest or lockfile could not be read or is structurally invalid."""


class Ecosystem(str, Enum):
    NPM = "npm"
    PYPI = "pypi"


class SourceType(str, Enum):
    REGISTRY = "registry"  # resolved by name from a package registry
    GIT = "git"
    URL = "url"
    LOCAL = "local"


class Origin(str, Enum):
    MANIFEST = "manifest"  # declared in package.json / requirements.txt
    LOCKFILE = "lockfile"  # resolved entry in package-lock.json


@dataclass(frozen=True)
class Dependency:
    name: str                      # normalized registry name (alias target for aliases)
    ecosystem: Ecosystem
    origin: Origin
    source_file: str
    section: str                   # e.g. "dependencies", "devDependencies", "lockfile"
    version_spec: str = ""         # what was requested, as written (URLs redacted)
    pinned_version: str | None = None   # exact version if one is known
    source_type: SourceType = SourceType.REGISTRY
    alias: str | None = None       # local name when installed under an alias
    resolved_url: str | None = None     # lockfile download URL (redacted)
    marker: str | None = None      # PEP 508 environment marker, not evaluated
    editable: bool = False
    line: int | None = None


@dataclass(frozen=True)
class RegistryOption:
    """A package-resolution setting found in a manifest, e.g. --extra-index-url."""
    kind: str
    value: str                     # redacted
    source_file: str
    line: int


@dataclass(frozen=True)
class Diagnostic:
    file: str
    message: str
    line: int | None = None


@dataclass
class ParseResult:
    dependencies: list[Dependency] = field(default_factory=list)
    registry_options: list[RegistryOption] = field(default_factory=list)
    warnings: list[Diagnostic] = field(default_factory=list)
    errors: list[Diagnostic] = field(default_factory=list)

    def merge(self, other: ParseResult) -> None:
        self.dependencies.extend(other.dependencies)
        self.registry_options.extend(other.registry_options)
        self.warnings.extend(other.warnings)
        self.errors.extend(other.errors)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class LookupStatus(str, Enum):
    FOUND = "found"
    NOT_FOUND = "not_found"
    ERROR = "error"      # the request failed; says nothing about the package
    SKIPPED = "skipped"  # deliberately not queried


@dataclass(frozen=True)
class RegistryEvidence:
    ecosystem: Ecosystem
    name: str
    status: LookupStatus
    registry_url: str                  # public endpoint consulted
    latest_version: str | None = None
    versions: tuple[str, ...] = ()
    first_published: str | None = None  # PyPI only for now
    detail: str | None = None          # error or skip reason
    attempts: int = 0


# ---------------------------------------------------------------------------
# Analysis results (Milestones 3-4)
# ---------------------------------------------------------------------------

class Severity(str, Enum):
    SAFE = "SAFE"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self]


_SEVERITY_RANK = {Severity.SAFE: 0, Severity.MEDIUM: 1, Severity.HIGH: 2, Severity.CRITICAL: 3}


@dataclass(frozen=True)
class Location:
    file: str
    line: int | None = None


@dataclass(frozen=True)
class Indicator:
    """One term of R = Wv*V + Ws*S + Wt*T, with the evidence behind it."""
    key: str                  # "V", "S" or "T"
    label: str
    value: float | None       # 0-100; None = evidence unavailable
    weight: float
    contribution: float       # weight * value (0 when unavailable)
    note: str


@dataclass(frozen=True)
class Finding:
    id: str
    rule_id: str | None
    kind: str                         # "dependency" or "configuration"
    title: str
    reason: str                       # one-line explanation of the score
    ecosystem: Ecosystem | None
    package: str | None
    versions: tuple[str, ...]
    indicators: tuple[Indicator, ...]
    formula_score: float | None       # weighted sum before floors (None for rule-based findings)
    floor: float | None               # minimum score forced by an explicit rule
    floor_reason: str | None
    score: float
    severity: Severity
    assessment: str                   # "complete" or "partial"
    evidence: tuple[str, ...]
    limitations: tuple[str, ...]
    recommendation: str
    locations: tuple[Location, ...]


@dataclass(frozen=True)
class PolicyDecision:
    blocked: bool
    fail_on: str
    blocking_findings: tuple[str, ...]
    scanner_error: bool
    exit_code: int
    reasons: tuple[str, ...]
