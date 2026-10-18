"""Turn parsed dependencies plus registry evidence into explainable findings."""
from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

from sentinel.analysis.similarity import find_lookalike, load_top_packages
from sentinel.analysis.versions import compare_versions, highest_version
from sentinel.config import Config
from sentinel.models import (
    Dependency, Ecosystem, Finding, Location, LookupStatus, Origin, ParseResult,
    RegistryEvidence, RegistryOption, SourceType,
)
from sentinel.rules import RULES
from sentinel.scoring import Floor, classify, compute_score

PUBLIC_REGISTRY_HOSTS = frozenset({
    "registry.npmjs.org", "registry.yarnpkg.com", "pypi.org", "files.pythonhosted.org",
})
_UNAVAILABLE = (LookupStatus.ERROR, LookupStatus.SKIPPED)
Key = tuple[Ecosystem, str]


@dataclass
class _Group:
    ecosystem: Ecosystem
    name: str
    deps: list[Dependency]


class _Locator:
    """Finds the file and line a dependency was declared on (best effort)."""

    def __init__(self, root: Path) -> None:
        self._root = root
        self._cache: dict[str, list[str]] = {}

    def _lines(self, filename: str) -> list[str]:
        if filename not in self._cache:
            try:
                self._cache[filename] = (self._root / filename).read_text(
                    encoding="utf-8-sig").splitlines()
            except (OSError, UnicodeDecodeError):
                self._cache[filename] = []
        return self._cache[filename]

    def locate(self, dep: Dependency) -> Location:
        if dep.line:
            return Location(dep.source_file, dep.line)
        declared = dep.alias or dep.name
        needle = f'"{declared}"' if dep.origin is Origin.MANIFEST else f'node_modules/{declared}"'
        for number, line in enumerate(self._lines(dep.source_file), start=1):
            if needle in line:
                return Location(dep.source_file, number)
        return Location(dep.source_file, None)


def _host(url: str | None) -> str | None:
    if not url:
        return None
    try:
        return (urlsplit(url).hostname or "").lower() or None
    except ValueError:
        return None


def _group(dependencies: list[Dependency]) -> list[_Group]:
    groups: dict[Key, _Group] = {}
    for dep in dependencies:
        if dep.source_type is not SourceType.REGISTRY:
            continue
        key = (dep.ecosystem, dep.name)
        groups.setdefault(key, _Group(dep.ecosystem, dep.name, [])).deps.append(dep)
    return [groups[k] for k in sorted(groups, key=lambda k: (k[0].value, k[1]))]


def _expected_version(group: _Group, config: Config) -> tuple[str | None, str]:
    configured = config.internal.expected_version(group.ecosystem, group.name)
    if configured:
        return configured, "from sentinel.toml"
    for origin, label in ((Origin.LOCKFILE, "from the lockfile"), (Origin.MANIFEST, "from the manifest")):
        pinned = [d.pinned_version for d in group.deps if d.origin is origin and d.pinned_version]
        best = highest_version(group.ecosystem, pinned)
        if best:
            return best, label
    return None, ""


def _age_days(first_published: str | None, now: datetime) -> int | None:
    if not first_published:
        return None
    try:
        stamp = datetime.fromisoformat(first_published.replace("Z", "+00:00"))
    except ValueError:
        return None
    if stamp.tzinfo is None:
        stamp = stamp.replace(tzinfo=timezone.utc)
    return max(0, (now - stamp).days)


def _registry_line(ev: RegistryEvidence | None) -> str:
    if ev is None:
        return "Public registry: not queried (registry checks were not run)"
    if ev.status is LookupStatus.FOUND:
        latest = ev.latest_version or "unknown"
        return f"Public registry: found; latest {latest}; {len(ev.versions)} published version(s)"
    if ev.status is LookupStatus.NOT_FOUND:
        return "Public registry: no package with this name (HTTP 404)"
    if ev.status is LookupStatus.SKIPPED:
        return f"Public registry: not queried ({ev.detail})"
    return f"Public registry: lookup FAILED ({ev.detail})"


RECOMMENDATIONS = {
    "SENT-DC-001": ("Treat as a possible dependency-confusion exposure: confirm which registry served this "
                    "package, pin the internal version with integrity hashes, make the package manager "
                    "resolve this name only from your private registry, and reserve the name publicly."),
    "SENT-DC-002": ("Decide whether this is an internal package. If yes, declare it in sentinel.toml [internal] "
                    "and reserve the name (or scope) on the public registry. If not, check for a typo."),
    "SENT-TS-001": ("Compare with the well-known package named in the evidence. Check the publisher, "
                    "repository link, creation date and download counts before installing. If it is "
                    "legitimate, add it to similarity.allowlist."),
}


def _assess_package(group: _Group, ev: RegistryEvidence | None, config: Config,
                    locator: _Locator, now: datetime) -> Finding:
    eco, name = group.ecosystem, group.name
    internal = config.internal.is_internal(eco, name)
    sc, sim = config.scoring, config.similarity
    floors: list[Floor] = []
    evidence: list[str] = []
    limitations: list[str] = []
    partial_reasons: list[str] = []
    unavailable = ev is None or ev.status in _UNAVAILABLE

    # --- how and where the dependency is declared ---
    for dep in group.deps[:6]:
        where = locator.locate(dep)
        place = f"{where.file}:{where.line}" if where.line else where.file
        spec = dep.pinned_version or dep.version_spec or "(no version)"
        extra = f", resolved from {dep.resolved_url}" if dep.resolved_url else ""
        evidence.append(f"Declared in {place} as {spec}{extra}")
    evidence.append(_registry_line(ev))
    if internal:
        evidence.append("Declared internal in sentinel.toml")

    # --- lockfile provenance (works offline) ---
    if internal:
        for dep in group.deps:
            host = _host(dep.resolved_url)
            if dep.origin is Origin.LOCKFILE and host in PUBLIC_REGISTRY_HOSTS:
                floors.append(Floor(sc.floor_critical,
                                    f"internal package was resolved from public registry host {host}",
                                    "SENT-DC-001"))
                break

    # --- V: version mismatch ---
    if not internal:
        v: tuple[float | None, str] = (0.0, "not applicable: package is not declared internal")
    elif unavailable:
        v = (None, "unavailable: public registry evidence missing")
        partial_reasons.append("V (public registry evidence missing)")
    elif ev.status is LookupStatus.NOT_FOUND:
        v = (0.0, "no public package exists, so there is no higher public version")
    else:
        expected, source = _expected_version(group, config)
        highest = highest_version(eco, ev.versions) or ev.latest_version
        cmp = compare_versions(eco, highest, expected) if (highest and expected) else None
        if expected is None:
            v = (None, "unavailable: no expected internal version known "
                       "(pin the dependency or set internal.expected_versions)")
            partial_reasons.append("V (no expected internal version)")
        elif cmp is None:
            v = (None, "unavailable: versions could not be compared")
            partial_reasons.append("V (versions not comparable)")
        elif cmp > 0:
            v = (100.0, f"highest public version {highest} > expected {expected} ({source})")
            floors.append(Floor(sc.floor_critical,
                                f"public registry has {highest}, higher than expected internal {expected}",
                                "SENT-DC-001"))
        else:
            v = (0.0, f"highest public version {highest} <= expected {expected} ({source})")

    # --- S: unclaimed / unverified namespace ---
    if unavailable:
        s: tuple[float | None, str] = (None, "unavailable: public registry evidence missing")
        partial_reasons.append("S (public registry evidence missing)")
    elif internal and config.internal.owns_public(eco, name):
        s = (0.0, "name or scope is declared as reserved by you (internal.owned_public)")
    elif ev.status is LookupStatus.FOUND:
        if internal:
            s = (sc.s_public_exists, "internal name is registered on the public registry "
                                     "and is not declared as owned by you")
        else:
            s = (0.0, "name exists on the public registry")
    else:  # NOT_FOUND
        if internal:
            s = (sc.s_unclaimed, "no public package with this name; cannot confirm the name or "
                                 "scope is reserved by you")
            limitations.append("A 404 also occurs for private packages in a scope you own; public "
                               "metadata cannot distinguish that from an unclaimed name.")
        else:
            s = (sc.s_unclaimed, "name is not registered publicly and is not declared internal")
        floors.append(Floor(sc.floor_medium,
                            "name is not registered on the public registry"
                            + (" and not confirmed reserved" if internal else
                               " and not declared internal (possible unconfigured internal name)"),
                            "SENT-DC-002"))

    # --- T: similarity to well-known names ---
    match = None
    if internal:
        t: tuple[float | None, str] = (0.0, "not applicable: internal names are not compared")
    else:
        match = find_lookalike(name, eco, sim)
        if match is None:
            t = (0.0, f"no close match among {len(load_top_packages(eco))} well-known names")
        else:
            algo = "Damerau-Levenshtein" if sim.algorithm == "damerau" else "Levenshtein"
            t = (match.similarity,
                 f"closest well-known name '{match.target}': {algo} distance {match.distance}, "
                 f"similarity {match.similarity:.1f}%")
            evidence.append(f"Resembles well-known package '{match.target}' "
                            f"(distance {match.distance}, similarity {match.similarity:.1f}%)")
            established = False
            if ev is not None and ev.status is LookupStatus.FOUND:
                age = _age_days(ev.first_published, now)
                established = (len(ev.versions) >= sim.established_versions
                               or (age is not None and age >= sim.established_age_days))
            if established:
                evidence.append(f"Package looks established ({len(ev.versions)} versions); "
                                "lookalike floor not applied")
            else:
                level = sc.floor_high if match.similarity >= sim.high_similarity else sc.floor_medium
                floors.append(Floor(level, f"name resembles '{match.target}' "
                                           f"({match.similarity:.1f}% similar)", "SENT-TS-001"))
            limitations.append("String similarity is evidence of resemblance, not proof of malicious intent.")
            if ev is None or ev.status is not LookupStatus.FOUND:
                limitations.append("Package history was not available to check whether it is established.")

    result = compute_score(v, s, t, config.weights, floors)
    if internal:
        limitations.append("Public metadata cannot prove who owns a name; ownership comes from sentinel.toml.")
    assessment = "partial" if partial_reasons else "complete"
    if partial_reasons:
        limitations.append("Incomplete evidence: " + "; ".join(partial_reasons) + ".")

    rule_id = result.floor.rule_id if result.floor else None
    if rule_id is None and match is not None:
        rule_id = "SENT-TS-001"
    if rule_id is None and internal and s[0] is not None and s[0] >= sc.s_public_exists:
        rule_id = "SENT-DC-001"          # internal name is registered publicly (score came from S)
    recommendation = RECOMMENDATIONS.get(rule_id, "No action needed for the evidence collected.")
    if match is not None and rule_id == "SENT-TS-001":
        recommendation = recommendation.replace("the well-known package named in the evidence",
                                                f"'{match.target}'")
    if partial_reasons:
        recommendation += " Evidence is incomplete: re-run with registry checks enabled and configured."

    seen: set[tuple[str, int | None]] = set()
    locations: list[Location] = []
    for dep in sorted(group.deps, key=lambda d: d.origin is Origin.LOCKFILE):
        loc = locator.locate(dep)
        if (loc.file, loc.line) not in seen and len(locations) < 5:
            seen.add((loc.file, loc.line))
            locations.append(loc)

    versions = tuple(dict.fromkeys(d.pinned_version or d.version_spec or "-" for d in group.deps))
    title = RULES[rule_id].short if rule_id else "No risk indicators found"
    if result.floor and result.floor.value >= result.formula_score:
        reason = result.floor.reason
    else:
        top = max(result.indicators, key=lambda i: i.contribution)
        reason = top.note if result.score > 0 and top.contribution > 0 else title
    return Finding(
        id="", rule_id=rule_id, kind="dependency", title=title, reason=reason, ecosystem=eco, package=name,
        versions=versions, indicators=result.indicators, formula_score=result.formula_score,
        floor=result.floor.value if result.floor else None,
        floor_reason=result.floor.reason if result.floor else None,
        score=result.score, severity=result.severity, assessment=assessment,
        evidence=tuple(evidence), limitations=tuple(dict.fromkeys(limitations)),
        recommendation=recommendation, locations=tuple(locations))


def _config_findings(options: list[RegistryOption], config: Config) -> list[Finding]:
    findings: list[Finding] = []
    pypi_internal = bool(config.internal.pypi_packages or config.internal.pypi_prefixes)

    def add(rule_id: str, score: float, o: RegistryOption, why: str, fix: str) -> None:
        findings.append(Finding(
            id="", rule_id=rule_id, kind="configuration", title=RULES[rule_id].short,
            reason=why, ecosystem=Ecosystem.PYPI, package=None, versions=(), indicators=(),
            formula_score=None, floor=None, floor_reason=None, score=score,
            severity=classify(score), assessment="complete",
            evidence=(f"{o.kind} {o.value} ({o.source_file}:{o.line})", why),
            limitations=("Severity is rule-based, not computed by the weighted formula.",
                         "pip.conf, environment variables and .npmrc are not scanned."),
            recommendation=fix, locations=(Location(o.source_file, o.line),)))

    for o in options:
        if o.kind == "extra-index-url":
            add("SENT-CFG-001", 65.0 if pypi_internal else 40.0, o,
                "pip merges all indexes and installs the highest version it finds"
                + ("; internal PyPI packages are declared in sentinel.toml" if pypi_internal else ""),
                "Use a single --index-url (a proxy that serves internal and mirrored public packages) "
                "or pin hashes with --require-hashes.")
        if o.kind == "trusted-host":
            add("SENT-CFG-002", 35.0, o, "TLS verification is skipped for this host",
                "Remove --trusted-host and fix the certificate instead.")
        if o.kind in ("index-url", "extra-index-url", "find-links") and o.value.lower().startswith("http://"):
            add("SENT-CFG-003", 60.0, o, "downloads over plain HTTP can be tampered with in transit",
                "Serve the index over HTTPS.")
    return findings


def analyze(parse: ParseResult, evidence: dict[Key, RegistryEvidence], config: Config,
            root: Path, now: datetime | None = None) -> list[Finding]:
    """Findings for every registry-sourced package plus configuration findings, worst first."""
    now = now or datetime.now(timezone.utc)
    locator = _Locator(root)
    findings = [_assess_package(g, evidence.get((g.ecosystem, g.name)), config, locator, now)
                for g in _group(parse.dependencies)]
    findings += _config_findings(parse.registry_options, config)
    findings.sort(key=lambda f: (-f.score, f.kind, f.package or "", f.rule_id or ""))
    return [replace(f, id=f"F{i:03d}") for i, f in enumerate(findings, start=1)]
