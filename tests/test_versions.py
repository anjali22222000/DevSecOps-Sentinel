import pytest

from sentinel.analysis.versions import compare_semver, compare_versions, highest_version, parse_semver
from sentinel.models import Ecosystem


@pytest.mark.parametrize("a, b, expected", [
    ("1.0.0", "1.0.0", 0), ("1.0.1", "1.0.0", 1), ("1.2.0", "1.10.0", -1),
    ("2.0.0", "1.99.99", 1), ("99.0.0", "1.4.0", 1), ("v1.0.0", "1.0.0", 0),
    ("1.0.0", "1.0.0-beta.1", 1),                  # release > pre-release
    ("1.0.0-alpha", "1.0.0-alpha.1", -1),          # shorter pre-release is lower
    ("1.0.0-alpha.2", "1.0.0-alpha.10", -1),       # numeric identifiers compare numerically
    ("1.0.0-alpha", "1.0.0-1", 1),                 # alphanumeric > numeric
    ("1.0.0-beta", "1.0.0-alpha", 1),
    ("1.0.0+build.5", "1.0.0", 0),                 # build metadata ignored
])
def test_semver_ordering(a, b, expected):
    assert compare_semver(a, b) == expected
    assert compare_semver(b, a) == -expected


@pytest.mark.parametrize("bad", ["", "1.0", "x.y.z", "1.0.0.0", "latest", "^1.0.0"])
def test_invalid_semver_returns_none(bad):
    assert parse_semver(bad) is None
    assert compare_semver(bad, "1.0.0") is None


def test_pep440_ordering():
    assert compare_versions(Ecosystem.PYPI, "2.0", "1.9.9") == 1
    assert compare_versions(Ecosystem.PYPI, "1.0rc1", "1.0") == -1
    assert compare_versions(Ecosystem.PYPI, "1.0", "1.0.0") == 0
    assert compare_versions(Ecosystem.PYPI, "99.0.0", "3.0.0") == 1


def test_pep440_invalid_returns_none():
    assert compare_versions(Ecosystem.PYPI, "not-a-version", "1.0") is None


def test_highest_version_ignores_unparseable_entries():
    assert highest_version(Ecosystem.NPM, ["1.0.0", "garbage", "99.0.0", "2.0.0"]) == "99.0.0"
    assert highest_version(Ecosystem.PYPI, ["1.0", "2.0b1", "1.5"]) == "2.0b1"
    assert highest_version(Ecosystem.NPM, []) is None
    assert highest_version(Ecosystem.NPM, ["garbage"]) is None
