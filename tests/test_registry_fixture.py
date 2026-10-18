import json

import pytest

from sentinel.models import Ecosystem, LookupStatus
from sentinel.registry.fixture import FixtureError, load_fixture
from helpers import dep


def write(tmp_path, data):
    path = tmp_path / "fx.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def test_entries_and_default(tmp_path):
    path = write(tmp_path, {"_default": "found",
                            "npm:a": {"status": "found", "latest_version": "2.0.0", "versions": ["1.0.0", "2.0.0"]},
                            "npm:b": {"status": "not_found"}})
    out = load_fixture(path, [dep("a"), dep("b"), dep("c")])
    assert out[(Ecosystem.NPM, "a")].versions == ("1.0.0", "2.0.0")
    assert out[(Ecosystem.NPM, "b")].status is LookupStatus.NOT_FOUND
    assert out[(Ecosystem.NPM, "c")].status is LookupStatus.FOUND


def test_unlisted_name_without_default_is_an_error_status(tmp_path):
    out = load_fixture(write(tmp_path, {}), [dep("a")])
    assert out[(Ecosystem.NPM, "a")].status is LookupStatus.ERROR


@pytest.mark.parametrize("data", [["x"], {"npm:a": {"status": "weird"}}, {"npm:a": {}}])
def test_bad_fixture_raises(tmp_path, data):
    with pytest.raises(FixtureError):
        load_fixture(write(tmp_path, data), [dep("a")])


def test_missing_file_raises(tmp_path):
    with pytest.raises(FixtureError):
        load_fixture(tmp_path / "nope.json", [])
