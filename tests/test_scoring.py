import pytest

from sentinel.config import Weights
from sentinel.models import Severity
from sentinel.scoring import Floor, classify, compute_score

W = Weights()  # 0.4 / 0.3 / 0.3


@pytest.mark.parametrize("score, expected", [
    (0, Severity.SAFE), (29.99, Severity.SAFE),
    (30, Severity.MEDIUM), (59.99, Severity.MEDIUM),
    (60, Severity.HIGH), (79.99, Severity.HIGH),
    (80, Severity.CRITICAL), (100, Severity.CRITICAL),
])
def test_every_severity_boundary(score, expected):
    assert classify(score) is expected


def test_formula_matches_proposal():
    r = compute_score((100, ""), (100, ""), (100, ""), W, [])
    assert r.formula_score == 100.0 and r.severity is Severity.CRITICAL
    r = compute_score((100, ""), (0, ""), (0, ""), W, [])
    assert r.formula_score == 40.0 and r.severity is Severity.MEDIUM
    r = compute_score((0, ""), (100, ""), (0, ""), W, [])
    assert r.formula_score == 30.0 and r.severity is Severity.MEDIUM
    r = compute_score((0, ""), (0, ""), (85, ""), W, [])
    assert r.formula_score == 25.5 and r.severity is Severity.SAFE


def test_unavailable_indicator_contributes_zero_and_is_visible():
    r = compute_score((None, "no evidence"), (100, ""), (0, ""), W, [])
    v = r.indicators[0]
    assert v.value is None and v.contribution == 0 and v.note == "no evidence"
    assert r.formula_score == 30.0


def test_floor_raises_but_never_lowers_the_score():
    r = compute_score((0, ""), (0, ""), (87.5, ""), W, [Floor(60, "lookalike", "R")])
    assert r.formula_score == 26.25 and r.score == 60 and r.floor.reason == "lookalike"
    assert r.severity is Severity.HIGH
    r = compute_score((100, ""), (100, ""), (100, ""), W, [Floor(60, "x", "R")])
    assert r.score == 100.0                           # formula already higher than the floor


def test_highest_floor_wins():
    r = compute_score((0, ""), (0, ""), (0, ""), W,
                      [Floor(30, "a", "R1"), Floor(80, "b", "R2"), Floor(60, "c", "R3")])
    assert r.score == 80 and r.floor.rule_id == "R2" and r.severity is Severity.CRITICAL


def test_score_is_capped_at_100():
    heavy = Weights(version=1.0, scope=0.0, similarity=0.0)
    assert compute_score((100, ""), (0, ""), (0, ""), heavy, []).score == 100.0


def test_custom_weights_change_the_result():
    only_version = Weights(version=1.0, scope=0.0, similarity=0.0)
    assert compute_score((100, ""), (100, ""), (100, ""), only_version, []).formula_score == 100.0
    only_t = Weights(version=0.0, scope=0.0, similarity=1.0)
    assert compute_score((100, ""), (100, ""), (50, ""), only_t, []).formula_score == 50.0
