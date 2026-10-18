"""Risk scoring: R = min(100, Wv*V + Ws*S + Wt*T), explicit floors, severity bands."""
from __future__ import annotations

from dataclasses import dataclass

from sentinel.config import Weights
from sentinel.models import Indicator, Severity

# Bands from the proposal: SAFE 0-29.99, MEDIUM 30-59.99, HIGH 60-79.99, CRITICAL 80-100.
_BANDS = ((80.0, Severity.CRITICAL), (60.0, Severity.HIGH), (30.0, Severity.MEDIUM))


def classify(score: float) -> Severity:
    """Severity of an (already rounded) score. Independent of any blocking decision."""
    for lower_bound, severity in _BANDS:
        if score >= lower_bound:
            return severity
    return Severity.SAFE


@dataclass(frozen=True)
class Floor:
    value: float
    reason: str
    rule_id: str


@dataclass(frozen=True)
class ScoreResult:
    indicators: tuple[Indicator, ...]
    formula_score: float
    floor: Floor | None
    score: float
    severity: Severity


def make_indicator(key: str, label: str, value: float | None, weight: float, note: str) -> Indicator:
    contribution = 0.0 if value is None else weight * value
    return Indicator(key, label, value, weight, round(contribution, 4), note)


def compute_score(
    v: tuple[float | None, str],
    s: tuple[float | None, str],
    t: tuple[float | None, str],
    weights: Weights,
    floors: list[Floor],
) -> ScoreResult:
    """Combine indicators. An unavailable indicator contributes 0 and is flagged by the caller."""
    indicators = (
        make_indicator("V", "Version mismatch", v[0], weights.version, v[1]),
        make_indicator("S", "Unclaimed / unverified namespace", s[0], weights.scope, s[1]),
        make_indicator("T", "Name similarity", t[0], weights.similarity, t[1]),
    )
    formula = round(min(100.0, sum(i.contribution for i in indicators)), 2)
    applied = max(floors, key=lambda f: f.value) if floors else None
    final = round(max(formula, applied.value), 2) if applied else formula
    return ScoreResult(indicators, formula, applied, final, classify(final))
