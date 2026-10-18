import pytest

from sentinel.analysis.similarity import (
    damerau_osa, find_lookalike, levenshtein, load_top_packages, similarity_percent,
)
from sentinel.config import SimilarityConfig
from sentinel.models import Ecosystem

CFG = SimilarityConfig()


@pytest.mark.parametrize("a, b, expected", [
    ("kitten", "sitting", 3), ("flaw", "lawn", 2), ("", "abc", 3), ("abc", "", 3),
    ("same", "same", 0), ("a", "b", 1), ("requests", "reqeusts", 2),
])
def test_levenshtein_known_values(a, b, expected):
    assert levenshtein(a, b) == expected


def test_damerau_counts_adjacent_swap_as_one_edit():
    assert levenshtein("ab", "ba") == 2
    assert damerau_osa("ab", "ba") == 1
    assert damerau_osa("requests", "reqeusts") == 1


@pytest.mark.parametrize("a, b", [("kitten", "sitting"), ("abc", "xyz"), ("lodash", "lodahs"), ("", "q")])
def test_distances_are_symmetric_and_osa_never_exceeds_levenshtein(a, b):
    assert levenshtein(a, b) == levenshtein(b, a)
    assert damerau_osa(a, b) == damerau_osa(b, a)
    assert damerau_osa(a, b) <= levenshtein(a, b)


def test_similarity_percent_matches_proposal_formula():
    assert similarity_percent("requests", "reqeusts", 1) == pytest.approx(87.5)
    assert similarity_percent("abc", "abc", 0) == 100.0
    assert similarity_percent("", "", 0) == 100.0
    assert similarity_percent("abcd", "wxyz", 4) == 0.0


def test_top_lists_load_without_duplicates():
    for eco in Ecosystem:
        names = load_top_packages(eco)
        assert len(names) > 50 and len(names) == len(set(names))
        assert all(n == n.lower() for n in names)


def test_typosquat_swap_is_detected():
    match = find_lookalike("reqeusts", Ecosystem.PYPI, CFG)
    assert match and match.target == "requests" and match.distance == 1
    assert match.similarity == pytest.approx(87.5)


def test_exact_match_is_legitimate():
    assert find_lookalike("requests", Ecosystem.PYPI, CFG) is None
    assert find_lookalike("express", Ecosystem.NPM, CFG) is None


def test_extra_character_and_missing_character_detected():
    assert find_lookalike("expresss", Ecosystem.NPM, CFG).target == "express"
    assert find_lookalike("lodas", Ecosystem.NPM, CFG).target == "lodash"


def test_short_names_are_never_compared():
    assert find_lookalike("jes", Ecosystem.NPM, CFG) is None
    assert find_lookalike("jest", Ecosystem.NPM, CFG) is None


def test_short_names_allow_only_one_edit_long_names_two():
    assert find_lookalike("lodxsh", Ecosystem.NPM, CFG) is not None      # 1 edit, 6 chars
    assert find_lookalike("lodxxh", Ecosystem.NPM, CFG) is None          # 2 edits, 6 chars
    assert find_lookalike("reqxxsts", Ecosystem.PYPI, CFG) is not None   # 2 edits, 8 chars


def test_allowlist_suppresses_a_match():
    cfg = SimilarityConfig(allowlist=frozenset({"expresss"}))
    assert find_lookalike("expresss", Ecosystem.NPM, cfg) is None


def test_unrelated_names_do_not_match():
    for name in ("acme-demo-auth", "my-internal-billing-service", "completely-different"):
        assert find_lookalike(name, Ecosystem.PYPI, CFG) is None


def test_levenshtein_algorithm_option_changes_swap_behaviour():
    cfg = SimilarityConfig(algorithm="levenshtein")
    # a swap costs 2 edits, which exceeds the allowed distance for a 6-letter name
    assert find_lookalike("lodahs", Ecosystem.NPM, cfg) is None
    assert find_lookalike("lodahs", Ecosystem.NPM, CFG) is not None


def test_custom_target_list_is_used():
    match = find_lookalike("acme-utils", Ecosystem.NPM, CFG, targets=("acme-utilz",))
    assert match and match.target == "acme-utilz"
