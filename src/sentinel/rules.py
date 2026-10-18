"""Stable rule identifiers shared by the JSON, HTML and SARIF reports."""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Rule:
    id: str
    name: str
    short: str
    help: str


RULES: dict[str, Rule] = {r.id: r for r in (
    Rule("SENT-DC-001", "InternalNamePubliclyExposed",
         "Internal package name is exposed on a public registry",
         "A package you declared as internal exists on the public registry with a higher "
         "version than expected, or its lockfile entry was resolved from a public registry. "
         "A resolver that prefers the public source can install attacker-controlled code."),
    Rule("SENT-DC-002", "UnregisteredDependencyName",
         "Dependency name is not registered on the public registry",
         "The name does not exist publicly and is not declared internal. If it is a private "
         "package, anyone could register that name publicly (dependency confusion). If it is "
         "a typo, the install will fail or resolve unexpectedly. Declare internal names in "
         "sentinel.toml and reserve them on the public registry."),
    Rule("SENT-TS-001", "PossibleTyposquat",
         "Package name closely resembles a well-known package",
         "The name is within a small edit distance of a popular package. Similarity is "
         "evidence of resemblance, not proof of malicious intent: verify the package."),
    Rule("SENT-CFG-001", "ExtraIndexUrl",
         "Extra package index configured",
         "pip treats all configured indexes as equal and installs the highest version found, "
         "which is the classic dependency-confusion misconfiguration."),
    Rule("SENT-CFG-002", "TlsVerificationDisabled",
         "TLS verification disabled for a package host",
         "--trusted-host tells pip to skip TLS verification for that host, allowing "
         "on-path tampering with downloaded packages."),
    Rule("SENT-CFG-003", "InsecureIndexUrl",
         "Package index uses plain HTTP",
         "Packages fetched over plain HTTP can be modified in transit."),
)}
