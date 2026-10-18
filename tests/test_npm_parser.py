import json

import pytest

from sentinel.models import Origin, ParserError, SourceType
from sentinel.parsers.npm import parse_package_json, parse_package_lock


def write_json(tmp_path, name, data):
    path = tmp_path / name
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def by_name(result):
    return {d.name: d for d in result.dependencies}


def test_all_four_sections_are_read(tmp_path):
    path = write_json(tmp_path, "package.json", {
        "dependencies": {"a": "1.0.0"},
        "devDependencies": {"b": "^2.0.0"},
        "optionalDependencies": {"c": "~3.0.0"},
        "peerDependencies": {"d": ">=4"},
    })
    result = parse_package_json(path)
    assert {d.section for d in result.dependencies} == {
        "dependencies", "devDependencies", "optionalDependencies", "peerDependencies"}
    assert all(d.origin is Origin.MANIFEST for d in result.dependencies)


def test_scoped_name_and_pinning(tmp_path):
    path = write_json(tmp_path, "package.json", {"dependencies": {
        "@acme-demo/auth": "1.4.0", "express": "^4.18.2", "lodash": "=4.17.21"}})
    deps = by_name(parse_package_json(path))
    assert deps["@acme-demo/auth"].pinned_version == "1.4.0"
    assert deps["express"].pinned_version is None
    assert deps["express"].version_spec == "^4.18.2"
    assert deps["lodash"].pinned_version == "4.17.21"


def test_alias_resolves_to_real_package_name(tmp_path):
    path = write_json(tmp_path, "package.json", {"dependencies": {
        "my-utils": "npm:@acme-demo/utils@^1.0.0", "short": "npm:left-pad@1.3.0"}})
    deps = by_name(parse_package_json(path))
    assert deps["@acme-demo/utils"].alias == "my-utils"
    assert deps["@acme-demo/utils"].version_spec == "^1.0.0"
    assert deps["left-pad"].alias == "short"
    assert deps["left-pad"].pinned_version == "1.3.0"


@pytest.mark.parametrize("spec, expected", [
    ("^1.2.3", SourceType.REGISTRY),
    ("latest", SourceType.REGISTRY),
    ("git+https://github.com/acme-demo/x.git", SourceType.GIT),
    ("github:acme-demo/x", SourceType.GIT),
    ("acme-demo/x#v1", SourceType.GIT),
    ("https://example.com/x.tgz", SourceType.URL),
    ("file:../x", SourceType.LOCAL),
    ("../x", SourceType.LOCAL),
    ("workspace:*", SourceType.LOCAL),
])
def test_spec_classification(tmp_path, spec, expected):
    path = write_json(tmp_path, "package.json", {"dependencies": {"pkg": spec}})
    assert parse_package_json(path).dependencies[0].source_type is expected


def test_non_string_version_is_skipped_with_warning(tmp_path):
    path = write_json(tmp_path, "package.json", {"dependencies": {"a": 1, "b": "1.0.0"}})
    result = parse_package_json(path)
    assert [d.name for d in result.dependencies] == ["b"]
    assert len(result.warnings) == 1


def test_invalid_json_raises_parser_error(tmp_path):
    path = tmp_path / "package.json"
    path.write_text("{ not json", encoding="utf-8")
    with pytest.raises(ParserError):
        parse_package_json(path)


def test_top_level_array_raises_parser_error(tmp_path):
    path = write_json(tmp_path, "package.json", ["a"])
    with pytest.raises(ParserError):
        parse_package_json(path)


def test_lock_v3_root_skipped_and_nested_names_extracted(tmp_path):
    path = write_json(tmp_path, "package-lock.json", {"lockfileVersion": 3, "packages": {
        "": {"name": "root"},
        "node_modules/express": {"version": "4.18.2",
                                 "resolved": "https://registry.npmjs.org/express/-/express-4.18.2.tgz"},
        "node_modules/express/node_modules/qs": {"version": "6.11.0"},
        "node_modules/@acme-demo/auth": {"version": "1.4.0",
                                         "resolved": "https://npm.acme-demo.example/a.tgz"},
    }})
    deps = by_name(parse_package_lock(path))
    assert set(deps) == {"express", "qs", "@acme-demo/auth"}
    assert deps["@acme-demo/auth"].pinned_version == "1.4.0"
    assert deps["@acme-demo/auth"].resolved_url == "https://npm.acme-demo.example/a.tgz"
    assert deps["express"].origin is Origin.LOCKFILE


def test_lock_v3_alias_uses_name_field(tmp_path):
    path = write_json(tmp_path, "package-lock.json", {"packages": {
        "node_modules/my-utils": {"name": "@acme-demo/utils", "version": "1.2.0"}}})
    dep = parse_package_lock(path).dependencies[0]
    assert dep.name == "@acme-demo/utils" and dep.alias == "my-utils"


def test_lock_link_entry_is_local(tmp_path):
    path = write_json(tmp_path, "package-lock.json", {"packages": {
        "node_modules/ws-pkg": {"resolved": "packages/ws-pkg", "link": True}}})
    assert parse_package_lock(path).dependencies[0].source_type is SourceType.LOCAL


def test_lock_v1_nested_dependencies(tmp_path):
    path = write_json(tmp_path, "package-lock.json", {"lockfileVersion": 1, "dependencies": {
        "a": {"version": "1.0.0", "dependencies": {"b": {"version": "2.0.0"}}}}})
    assert set(by_name(parse_package_lock(path))) == {"a", "b"}


def test_lock_v1_alias_encoded_in_version(tmp_path):
    path = write_json(tmp_path, "package-lock.json", {"lockfileVersion": 1, "dependencies": {
        "my-utils": {"version": "npm:@acme-demo/utils@1.2.0"}}})
    dep = parse_package_lock(path).dependencies[0]
    assert (dep.name, dep.alias, dep.pinned_version) == ("@acme-demo/utils", "my-utils", "1.2.0")


def test_lock_without_dependency_sections_warns(tmp_path):
    path = write_json(tmp_path, "package-lock.json", {"lockfileVersion": 3})
    result = parse_package_lock(path)
    assert result.dependencies == [] and len(result.warnings) == 1
