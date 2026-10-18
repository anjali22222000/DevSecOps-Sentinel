from sentinel.models import SourceType
from sentinel.parsers.python import parse_requirements_txt


def parse(tmp_path, text):
    path = tmp_path / "requirements.txt"
    path.write_text(text, encoding="utf-8")
    return parse_requirements_txt(path)


def by_name(result):
    return {d.name: d for d in result.dependencies}


def test_pinned_and_range(tmp_path):
    deps = by_name(parse(tmp_path, "requests==2.31.0\nflask>=2.3,<3.0\n"))
    assert deps["requests"].pinned_version == "2.31.0"
    assert deps["flask"].pinned_version is None
    assert set(deps["flask"].version_spec.split(",")) == {">=2.3", "<3.0"}


def test_wildcard_is_not_a_pin_but_triple_equals_is(tmp_path):
    deps = by_name(parse(tmp_path, "a==1.*\nb===1.0\n"))
    assert deps["a"].pinned_version is None
    assert deps["b"].pinned_version == "1.0"


def test_name_normalization_and_extras(tmp_path):
    deps = by_name(parse(tmp_path, "Acme_Demo.Auth==1.0\nrequests[security]==2.0\n"))
    assert "acme-demo-auth" in deps and "requests" in deps


def test_marker_is_recorded_not_evaluated(tmp_path):
    dep = parse(tmp_path, 'numpy ; python_version >= "3.9"\n').dependencies[0]
    assert dep.marker == 'python_version >= "3.9"'


def test_comments_blank_lines_and_continuations(tmp_path):
    text = "# header\n\nrequests==2.0  # trailing\nacme==1.0 \\\n    --hash=sha256:abc\n"
    result = parse(tmp_path, text)
    assert {d.name for d in result.dependencies} == {"requests", "acme"}
    assert by_name(result)["acme"].pinned_version == "1.0"
    assert result.warnings == []


def test_direct_url_requirement(tmp_path):
    dep = parse(tmp_path, "lib @ https://dl.example/lib-1.0.tar.gz\n").dependencies[0]
    assert dep.source_type is SourceType.URL and dep.pinned_version is None


def test_editable_git_with_egg(tmp_path):
    dep = parse(tmp_path, "-e git+https://github.com/acme-demo/t.git#egg=acme-tools\n").dependencies[0]
    assert (dep.name, dep.source_type, dep.editable) == ("acme-tools", SourceType.GIT, True)


def test_unnamed_url_without_egg_warns(tmp_path):
    result = parse(tmp_path, "git+https://github.com/acme-demo/t.git\n")
    assert result.dependencies == [] and len(result.warnings) == 1


def test_local_path_warns(tmp_path):
    result = parse(tmp_path, "-e ./local-pkg\n")
    assert result.dependencies == [] and len(result.warnings) == 1


def test_garbage_line_warns_and_does_not_raise(tmp_path):
    result = parse(tmp_path, "!!!not a requirement\nrequests==2.0\n")
    assert [d.name for d in result.dependencies] == ["requests"]
    assert result.warnings[0].line == 1


def test_registry_options_recorded_and_redacted(tmp_path):
    text = ("--index-url https://pypi.org/simple\n"
            "--extra-index-url=https://u:secret@pypi.acme-demo.example/simple\n"
            "--trusted-host pypi.acme-demo.example\n--no-index\n")
    result = parse(tmp_path, text)
    kinds = [o.kind for o in result.registry_options]
    assert kinds == ["index-url", "extra-index-url", "trusted-host", "no-index"]
    assert "secret" not in repr(result.registry_options)


def test_requirement_file_reference_is_warned_not_followed(tmp_path):
    result = parse(tmp_path, "-r other.txt\n")
    assert result.dependencies == [] and "not followed" in result.warnings[0].message
