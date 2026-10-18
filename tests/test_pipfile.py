import json

import pytest

from sentinel.models import Ecosystem, Origin, ParserError, SourceType
from sentinel.parsers import scan_directory
from sentinel.parsers.pipfile import parse_pipfile_lock

LOCK = {
    "_meta": {"sources": [
        {"name": "pypi", "url": "https://pypi.org/simple", "verify_ssl": True},
        {"name": "acme", "url": "https://user:tok@pypi.acme-demo.example/simple", "verify_ssl": True}]},
    "default": {
        "requests": {"hashes": ["sha256:aa"], "index": "pypi", "version": "==2.31.0"},
        "Acme_Demo.Core": {"index": "acme", "version": "==1.2.0"},
        "flask": {"version": ">=2.0"},
        "tools": {"git": "https://github.com/acme-demo/tools.git", "ref": "abc"},
        "localpkg": {"path": "./local", "editable": True},
    },
    "develop": {"pytest": {"index": "pypi", "version": "==7.4.0"}},
}


def write(tmp_path, data):
    path = tmp_path / "Pipfile.lock"
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def test_parses_default_and_develop_sections(tmp_path):
    result = parse_pipfile_lock(write(tmp_path, LOCK))
    deps = {d.name: d for d in result.dependencies}
    assert set(deps) == {"requests", "acme-demo-core", "flask", "tools", "localpkg", "pytest"}
    assert deps["requests"].pinned_version == "2.31.0" and deps["requests"].origin is Origin.LOCKFILE
    assert deps["flask"].pinned_version is None and deps["flask"].version_spec == ">=2.0"
    assert deps["pytest"].section == "develop"
    assert deps["tools"].source_type is SourceType.GIT and deps["localpkg"].source_type is SourceType.LOCAL
    assert deps["localpkg"].editable and all(d.ecosystem is Ecosystem.PYPI for d in deps.values())


def test_extra_sources_become_extra_index_options_and_are_redacted(tmp_path):
    result = parse_pipfile_lock(write(tmp_path, LOCK))
    kinds = [(o.kind, o.value) for o in result.registry_options]
    assert kinds == [("index-url", "https://pypi.org/simple"),
                     ("extra-index-url", "https://***@pypi.acme-demo.example/simple")]
    assert "tok" not in repr(result.registry_options)


def test_index_maps_to_resolved_url(tmp_path):
    deps = {d.name: d for d in parse_pipfile_lock(write(tmp_path, LOCK)).dependencies}
    assert deps["requests"].resolved_url == "https://pypi.org/simple"
    assert deps["acme-demo-core"].resolved_url == "https://***@pypi.acme-demo.example/simple"


def test_invalid_json_and_wrong_shape(tmp_path):
    bad = tmp_path / "Pipfile.lock"
    bad.write_text("{ nope", encoding="utf-8")
    with pytest.raises(ParserError):
        parse_pipfile_lock(bad)
    with pytest.raises(ParserError):
        parse_pipfile_lock(write(tmp_path, ["x"]))


def test_missing_sections_warn(tmp_path):
    result = parse_pipfile_lock(write(tmp_path, {"_meta": {}}))
    assert result.dependencies == [] and len(result.warnings) == 1


def test_non_object_entry_is_skipped_with_warning(tmp_path):
    result = parse_pipfile_lock(write(tmp_path, {"default": {"a": "x", "b": {"version": "==1.0"}}}))
    assert [d.name for d in result.dependencies] == ["b"] and len(result.warnings) == 1


def test_scan_directory_picks_up_pipfile_lock(tmp_path):
    write(tmp_path, LOCK)
    result = scan_directory(tmp_path)
    assert result.errors == [] and len(result.dependencies) == 6
