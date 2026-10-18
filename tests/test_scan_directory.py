from sentinel.parsers import scan_directory


def test_empty_directory_is_an_error(tmp_path):
    result = scan_directory(tmp_path)
    assert len(result.errors) == 1


def test_missing_lockfile_is_a_warning(tmp_path):
    (tmp_path / "package.json").write_text('{"dependencies": {"a": "1.0.0"}}', encoding="utf-8")
    result = scan_directory(tmp_path)
    assert result.errors == []
    assert any("package-lock.json" in w.message for w in result.warnings)


def test_malformed_file_becomes_error_and_others_still_parse(tmp_path):
    (tmp_path / "package.json").write_text("{ nope", encoding="utf-8")
    (tmp_path / "requirements.txt").write_text("requests==2.0\n", encoding="utf-8")
    result = scan_directory(tmp_path)
    assert len(result.errors) == 1
    assert [d.name for d in result.dependencies] == ["requests"]
