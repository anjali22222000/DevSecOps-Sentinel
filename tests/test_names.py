import pytest

from sentinel.analysis.names import normalize_name, npm_scope
from sentinel.models import Ecosystem


@pytest.mark.parametrize("raw, expected", [
    ("Acme_Demo.Auth", "acme-demo-auth"),
    ("foo--bar", "foo-bar"),
    ("  Requests ", "requests"),
])
def test_pypi_normalization(raw, expected):
    assert normalize_name(Ecosystem.PYPI, raw) == expected


def test_npm_normalization_keeps_scope_and_lowercases():
    assert normalize_name(Ecosystem.NPM, "@Acme-Demo/Auth") == "@acme-demo/auth"


def test_npm_scope():
    assert npm_scope("@acme-demo/auth") == "@acme-demo"
    assert npm_scope("lodash") is None
    assert npm_scope("@broken") is None
