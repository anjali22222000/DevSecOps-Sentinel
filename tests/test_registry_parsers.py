import pytest

from sentinel.registry.common import MalformedResponse
from sentinel.registry.npm import NpmClient, is_valid_npm_name, parse_npm_metadata
from sentinel.registry.pypi import is_valid_pypi_name, parse_pypi_metadata


@pytest.mark.parametrize("name", ["express", "@acme-demo/utils", "a.b_c-d~e", "left-pad"])
def test_valid_npm_names(name):
    assert is_valid_npm_name(name)


@pytest.mark.parametrize("name", [
    "", "../etc/passwd", "a b", "@scope", "@scope/", "pkg?x=1", "pkg#frag", "UPPER",
    "a/b", "x" * 215, "-leading", "@acme-demo/../x", "http://evil", "express\n",
])
def test_invalid_npm_names(name):
    assert not is_valid_npm_name(name)


@pytest.mark.parametrize("name", ["requests", "acme-demo-auth", "a", "a1"])
def test_valid_pypi_names(name):
    assert is_valid_pypi_name(name)


@pytest.mark.parametrize("name", ["", "-a", "a-", "a_b", "A", "../x", "a.b", "requests\n"])
def test_invalid_pypi_names(name):
    assert not is_valid_pypi_name(name)


def test_npm_scoped_name_is_encoded_in_url():
    client = NpmClient(fetcher=None, base_url="https://npm.test")
    assert client.url_for("@acme-demo/utils") == "https://npm.test/@acme-demo%2Futils"
    assert client.url_for("express") == "https://npm.test/express"


def test_npm_parse_basic():
    meta = parse_npm_metadata("express", {
        "name": "express", "dist-tags": {"latest": "4.18.2"}, "versions": {"4.18.2": {}}})
    assert meta.latest_version == "4.18.2" and meta.versions == ("4.18.2",)


@pytest.mark.parametrize("payload", [
    [], {"name": "express"}, {"name": "express", "versions": []},
    {"name": "other", "versions": {}},
])
def test_npm_malformed(payload):
    with pytest.raises(MalformedResponse):
        parse_npm_metadata("express", payload)


def test_pypi_parse_basic_and_first_published():
    meta = parse_pypi_metadata("requests", {
        "info": {"name": "Requests", "version": "2.31.0"},
        "releases": {
            "2.30.0": [{"upload_time_iso_8601": "2023-05-03T00:00:00.000000Z"}],
            "2.31.0": [{"upload_time_iso_8601": "2023-05-22T00:00:00.000000Z"}],
            "0.0.1": [],
        }})
    assert meta.latest_version == "2.31.0"
    assert meta.versions == ("2.30.0", "2.31.0", "0.0.1")
    assert meta.first_published == "2023-05-03T00:00:00.000000Z"


def test_pypi_missing_releases_is_tolerated():
    meta = parse_pypi_metadata("requests", {"info": {"name": "requests", "version": "1.0"}})
    assert meta.latest_version == "1.0" and meta.versions == () and meta.first_published is None


@pytest.mark.parametrize("payload", [
    [], {}, {"info": []}, {"info": {"name": "other"}},
    {"info": {"name": "requests"}, "releases": []},
])
def test_pypi_malformed(payload):
    with pytest.raises(MalformedResponse):
        parse_pypi_metadata("requests", payload)
