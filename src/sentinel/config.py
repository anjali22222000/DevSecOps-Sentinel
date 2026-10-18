"""Configuration and policy loading (sentinel.toml). Unknown keys are rejected."""
from __future__ import annotations

import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from sentinel.analysis.names import normalize_name
from sentinel.models import Ecosystem

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover - exercised only on Python 3.10
    import tomli as tomllib

FAIL_ON_LEVELS = ("critical", "high", "medium", "never")


class ConfigError(Exception):
    """The configuration file is invalid. A bad security config must never be ignored."""


@dataclass(frozen=True)
class Weights:
    version: float = 0.4      # Wv
    scope: float = 0.3        # Ws
    similarity: float = 0.3   # Wt

    def validate(self) -> None:
        values = (self.version, self.scope, self.similarity)
        if any(v < 0 or v > 1 for v in values):
            raise ConfigError("each weight must be between 0 and 1")
        if abs(sum(values) - 1.0) > 1e-6:
            raise ConfigError(f"weights must sum to 1.0 (got {sum(values):.6f})")


@dataclass(frozen=True)
class ScoringConfig:
    s_public_exists: float = 100.0   # internal name is registered on the public registry
    s_unclaimed: float = 70.0        # name is not registered publicly (exposure)
    floor_critical: float = 80.0
    floor_high: float = 60.0
    floor_medium: float = 30.0


@dataclass(frozen=True)
class SimilarityConfig:
    algorithm: str = "damerau"            # "damerau" (counts a swap as 1 edit) or "levenshtein"
    min_length: int = 5                   # shorter names are never compared
    long_length: int = 8                  # names this long or longer may differ by 2 edits
    max_distance_short: int = 1
    max_distance_long: int = 2
    high_similarity: float = 85.0         # T >= this raises the HIGH floor (proposal value)
    established_versions: int = 10        # >= this many public versions => established package
    established_age_days: int = 730       # first published at least this long ago => established
    allowlist: frozenset[str] = frozenset()


@dataclass(frozen=True)
class PolicyConfig:
    fail_on: str = "high"                 # block at this severity or above
    block_on_incomplete: bool = False     # also block when evidence is partial


@dataclass(frozen=True)
class RegistrySettings:
    timeout: float = 10.0
    concurrency: int = 10


@dataclass(frozen=True)
class InternalConfig:
    npm_scopes: frozenset[str] = frozenset()
    npm_packages: frozenset[str] = frozenset()
    npm_prefixes: tuple[str, ...] = ()
    pypi_packages: frozenset[str] = frozenset()
    pypi_prefixes: tuple[str, ...] = ()
    owned_public: frozenset[tuple[Ecosystem, str]] = frozenset()
    expected_versions: dict[tuple[Ecosystem, str], str] = field(default_factory=dict)

    @property
    def configured(self) -> bool:
        return bool(self.npm_scopes or self.npm_packages or self.npm_prefixes
                    or self.pypi_packages or self.pypi_prefixes)

    def is_internal(self, ecosystem: Ecosystem, name: str) -> bool:
        if ecosystem is Ecosystem.NPM:
            if name in self.npm_packages:
                return True
            if name.startswith("@") and name.split("/", 1)[0] in self.npm_scopes:
                return True
            return any(name.startswith(p) for p in self.npm_prefixes)
        return name in self.pypi_packages or any(name.startswith(p) for p in self.pypi_prefixes)

    def owns_public(self, ecosystem: Ecosystem, name: str) -> bool:
        """True if the name (or, for NPM, its whole scope) is declared as reserved by you."""
        if (ecosystem, name) in self.owned_public:
            return True
        if ecosystem is Ecosystem.NPM and name.startswith("@"):
            return (ecosystem, name.split("/", 1)[0]) in self.owned_public
        return False

    def expected_version(self, ecosystem: Ecosystem, name: str) -> str | None:
        return self.expected_versions.get((ecosystem, name))


@dataclass(frozen=True)
class Config:
    weights: Weights = Weights()
    scoring: ScoringConfig = ScoringConfig()
    similarity: SimilarityConfig = SimilarityConfig()
    policy: PolicyConfig = PolicyConfig()
    registry: RegistrySettings = RegistrySettings()
    internal: InternalConfig = InternalConfig()
    query_internal_names: bool = True     # False = privacy mode

    def snapshot(self) -> dict[str, Any]:
        """JSON-friendly view of the effective configuration, for reports."""
        sim = asdict(self.similarity)
        sim["allowlist"] = sorted(self.similarity.allowlist)
        i = self.internal
        return {
            "weights": asdict(self.weights),
            "scoring": asdict(self.scoring),
            "similarity": sim,
            "policy": asdict(self.policy),
            "registry": asdict(self.registry),
            "privacy": {"query_internal_names": self.query_internal_names},
            "internal": {
                "npm_scopes": sorted(i.npm_scopes),
                "npm_packages": sorted(i.npm_packages),
                "npm_prefixes": list(i.npm_prefixes),
                "pypi_packages": sorted(i.pypi_packages),
                "pypi_prefixes": list(i.pypi_prefixes),
                "owned_public": sorted(f"{e.value}:{n}" for e, n in i.owned_public),
                "expected_versions": {f"{e.value}:{n}": v
                                      for (e, n), v in sorted(i.expected_versions.items(),
                                                              key=lambda kv: (kv[0][0].value, kv[0][1]))},
            },
        }


def _table(data: dict[str, Any], key: str, allowed: set[str], where: str) -> dict[str, Any]:
    table = data.get(key, {})
    if not isinstance(table, dict):
        raise ConfigError(f"[{where}] must be a table")
    unknown = set(table) - allowed
    if unknown:
        raise ConfigError(f"unknown key(s) in [{where}]: {', '.join(sorted(unknown))}")
    return table


def _typed(value: Any, kind: type | tuple[type, ...], where: str) -> Any:
    ok = isinstance(value, kind) and not (kind is not bool and isinstance(value, bool))
    if kind is float:
        ok = isinstance(value, (int, float)) and not isinstance(value, bool)
    if not ok:
        raise ConfigError(f"{where} has the wrong type")
    return value


def _str_list(value: Any, where: str) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise ConfigError(f"{where} must be a list of strings")
    return value


def _eco_key(raw: str, where: str) -> tuple[Ecosystem, str]:
    prefix, sep, name = raw.partition(":")
    if not sep or prefix not in ("npm", "pypi") or not name:
        raise ConfigError(f"{where}: key '{raw}' must look like 'npm:<name>' or 'pypi:<name>'")
    eco = Ecosystem(prefix)
    return eco, normalize_name(eco, name)


def parse_config(data: dict[str, Any]) -> Config:
    allowed_top = {"weights", "scoring", "similarity", "policy", "registry", "internal", "privacy"}
    unknown = set(data) - allowed_top
    if unknown:
        raise ConfigError(f"unknown top-level section(s): {', '.join(sorted(unknown))}")

    w = _table(data, "weights", {"version", "scope", "similarity"}, "weights")
    weights = Weights(**{k: float(_typed(v, float, f"weights.{k}")) for k, v in w.items()})
    weights.validate()

    sc = _table(data, "scoring", set(asdict(ScoringConfig())), "scoring")
    scoring = ScoringConfig(**{k: float(_typed(v, float, f"scoring.{k}")) for k, v in sc.items()})

    s = _table(data, "similarity", set(asdict(SimilarityConfig())), "similarity")
    sim_kwargs: dict[str, Any] = {}
    for k, v in s.items():
        if k == "algorithm":
            if v not in ("damerau", "levenshtein"):
                raise ConfigError("similarity.algorithm must be 'damerau' or 'levenshtein'")
            sim_kwargs[k] = v
        elif k == "allowlist":
            sim_kwargs[k] = frozenset(normalize_name(Ecosystem.NPM, n)
                                      for n in _str_list(v, "similarity.allowlist"))
        elif k == "high_similarity":
            sim_kwargs[k] = float(_typed(v, float, "similarity.high_similarity"))
        else:
            sim_kwargs[k] = int(_typed(v, int, f"similarity.{k}"))
    similarity = SimilarityConfig(**sim_kwargs)

    p = _table(data, "policy", {"fail_on", "block_on_incomplete"}, "policy")
    fail_on = str(p.get("fail_on", "high")).lower()
    if fail_on not in FAIL_ON_LEVELS:
        raise ConfigError(f"policy.fail_on must be one of {', '.join(FAIL_ON_LEVELS)}")
    policy = PolicyConfig(
        fail_on=fail_on,
        block_on_incomplete=bool(_typed(p.get("block_on_incomplete", False), bool,
                                        "policy.block_on_incomplete")))

    r = _table(data, "registry", {"timeout", "concurrency"}, "registry")
    timeout = float(_typed(r.get("timeout", 10.0), float, "registry.timeout"))
    concurrency = int(_typed(r.get("concurrency", 10), int, "registry.concurrency"))
    if timeout <= 0 or concurrency < 1:
        raise ConfigError("registry.timeout must be > 0 and registry.concurrency >= 1")

    pr = _table(data, "privacy", {"query_internal_names"}, "privacy")
    query_internal = bool(_typed(pr.get("query_internal_names", True), bool,
                                 "privacy.query_internal_names"))

    internal = _parse_internal(data.get("internal", {}))
    return Config(weights, scoring, similarity, policy,
                  RegistrySettings(timeout, concurrency), internal, query_internal)


def _parse_internal(raw: Any) -> InternalConfig:
    if not isinstance(raw, dict):
        raise ConfigError("[internal] must be a table")
    unknown = set(raw) - {"npm", "pypi", "owned_public", "expected_versions"}
    if unknown:
        raise ConfigError(f"unknown key(s) in [internal]: {', '.join(sorted(unknown))}")

    npm = _table(raw, "npm", {"scopes", "packages", "prefixes"}, "internal.npm")
    pypi = _table(raw, "pypi", {"packages", "prefixes"}, "internal.pypi")

    scopes = frozenset(n.lower() for n in _str_list(npm.get("scopes", []), "internal.npm.scopes"))
    for scope in scopes:
        if not scope.startswith("@") or "/" in scope:
            raise ConfigError(f"internal.npm.scopes: '{scope}' must look like '@scope'")

    owned = frozenset(_eco_key(k, "internal.owned_public")
                      for k in _str_list(raw.get("owned_public", []), "internal.owned_public"))
    expected_raw = raw.get("expected_versions", {})
    if not isinstance(expected_raw, dict) or not all(isinstance(v, str) for v in expected_raw.values()):
        raise ConfigError("internal.expected_versions must map 'eco:name' to a version string")
    expected = {_eco_key(k, "internal.expected_versions"): v for k, v in expected_raw.items()}

    return InternalConfig(
        npm_scopes=scopes,
        npm_packages=frozenset(normalize_name(Ecosystem.NPM, n)
                               for n in _str_list(npm.get("packages", []), "internal.npm.packages")),
        npm_prefixes=tuple(n.lower() for n in _str_list(npm.get("prefixes", []), "internal.npm.prefixes")),
        pypi_packages=frozenset(normalize_name(Ecosystem.PYPI, n)
                                for n in _str_list(pypi.get("packages", []), "internal.pypi.packages")),
        pypi_prefixes=tuple(normalize_name(Ecosystem.PYPI, n)
                            for n in _str_list(pypi.get("prefixes", []), "internal.pypi.prefixes")),
        owned_public=owned,
        expected_versions=expected,
    )


def load_config(path: Path | None) -> Config:
    if path is None:
        return Config()
    try:
        with path.open("rb") as handle:
            data = tomllib.load(handle)
    except OSError as exc:
        raise ConfigError(f"cannot read {path}: {exc}") from exc
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"invalid TOML in {path}: {exc}") from exc
    return parse_config(data)
