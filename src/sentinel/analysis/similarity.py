"""String similarity for typosquatting detection.

Two edit-distance functions are implemented by hand (no hidden library logic):
  levenshtein()  - the classic metric from the proposal
  damerau_osa()  - Levenshtein plus adjacent transposition as a single edit
"""
from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from importlib import resources

from sentinel.config import SimilarityConfig
from sentinel.models import Ecosystem


def levenshtein(a: str, b: str) -> int:
    """Minimum single-character insertions, deletions or substitutions turning a into b."""
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    previous = list(range(len(b) + 1))
    for i, ca in enumerate(a, start=1):
        current = [i]
        for j, cb in enumerate(b, start=1):
            current.append(min(
                previous[j] + 1,                   # deletion
                current[j - 1] + 1,                # insertion
                previous[j - 1] + (ca != cb),      # substitution (free if equal)
            ))
        previous = current
    return previous[-1]


def damerau_osa(a: str, b: str) -> int:
    """Optimal string alignment: Levenshtein where swapping two adjacent characters costs 1."""
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    rows = [list(range(len(b) + 1))]
    for i in range(1, len(a) + 1):
        row = [i] + [0] * len(b)
        for j in range(1, len(b) + 1):
            cost = a[i - 1] != b[j - 1]
            row[j] = min(rows[i - 1][j] + 1, row[j - 1] + 1, rows[i - 1][j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                row[j] = min(row[j], rows[i - 2][j - 2] + 1)     # transposition
        rows.append(row)
    return rows[-1][-1]


def similarity_percent(a: str, b: str, distance: int) -> float:
    """T = (1 - d / max(len(a), len(b))) * 100, as defined in the proposal."""
    longest = max(len(a), len(b))
    if longest == 0:
        return 100.0
    return (1 - distance / longest) * 100


@dataclass(frozen=True)
class LookalikeMatch:
    target: str
    distance: int
    similarity: float


@lru_cache(maxsize=None)
def load_top_packages(ecosystem: Ecosystem) -> tuple[str, ...]:
    """Curated seed list of well-known package names (see docs/LIMITATIONS.md)."""
    filename = f"top_packages_{ecosystem.value}.txt"
    text = resources.files("sentinel.data").joinpath(filename).read_text(encoding="utf-8")
    names = [line.strip().lower() for line in text.splitlines()
             if line.strip() and not line.startswith("#")]
    return tuple(dict.fromkeys(names))


def find_lookalike(
    name: str,
    ecosystem: Ecosystem,
    config: SimilarityConfig,
    targets: tuple[str, ...] | None = None,
) -> LookalikeMatch | None:
    """Closest well-known package that `name` resembles, after false-positive filters.

    Filters: exact matches are legitimate; allowlisted names are skipped; very short
    names are never compared; the allowed edit distance depends on name length.
    """
    targets = targets if targets is not None else load_top_packages(ecosystem)
    if name in targets or name in config.allowlist or len(name) < config.min_length:
        return None
    allowed = config.max_distance_long if len(name) >= config.long_length \
        else config.max_distance_short
    distance_fn = damerau_osa if config.algorithm == "damerau" else levenshtein

    best: LookalikeMatch | None = None
    for target in targets:
        if len(target) < config.min_length or abs(len(target) - len(name)) > allowed:
            continue
        d = distance_fn(name, target)
        if d == 0 or d > allowed:
            continue
        candidate = LookalikeMatch(target, d, similarity_percent(name, target, d))
        if best is None or (candidate.distance, -candidate.similarity) < (best.distance, -best.similarity):
            best = candidate
    return best
