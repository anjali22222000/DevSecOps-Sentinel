import json
from pathlib import Path

from sentinel.cli import EXIT_ERROR, EXIT_OK, main
from sentinel.models import LookupStatus, RegistryEvidence, SourceType

FIXTURE = Path(__file__).resolve().parents[1] / "examples" / "acme-demo-fixture"


def test_scan_fixture_text(capsys):
    assert main(["scan", str(FIXTURE), "--list-dependencies"]) == EXIT_OK
    out = capsys.readouterr().out
    assert "Dependencies: 20" in out
    assert "@acme-demo/utils (as my-utils)" in out
    assert "not-a-real-secret" not in out


def test_scan_fixture_json(capsys):
    assert main(["scan", str(FIXTURE), "--format", "json"]) == EXIT_OK
    raw = capsys.readouterr().out
    data = json.loads(raw)
    assert len(data["dependencies"]) == 20
    assert len(data["registry_options"]) == 2
    assert data["errors"] == []
    assert "not-a-real-secret" not in raw
    ecosystems = {d["ecosystem"] for d in data["dependencies"]}
    assert ecosystems == {"npm", "pypi"}


def test_missing_directory_exits_2(capsys):
    assert main(["scan", "/definitely/not/here"]) == EXIT_ERROR
    assert "not a directory" in capsys.readouterr().err


def test_empty_directory_exits_2(tmp_path):
    assert main(["scan", str(tmp_path)]) == EXIT_ERROR


def test_malformed_manifest_exits_2(tmp_path):
    (tmp_path / "package.json").write_text("{ nope", encoding="utf-8")
    assert main(["scan", str(tmp_path)]) == EXIT_ERROR


def fake_inspect(status):
    async def fake(dependencies, timeout, concurrency):
        out = {}
        for d in dependencies:
            if d.source_type is SourceType.REGISTRY:
                out[(d.ecosystem, d.name)] = RegistryEvidence(
                    ecosystem=d.ecosystem, name=d.name, status=status,
                    registry_url="https://registry.invalid")
        return out
    return fake


def test_default_scan_never_touches_the_network(monkeypatch, capsys):
    async def boom(*args):
        raise AssertionError("network lookup attempted without --registry")
    monkeypatch.setattr("sentinel.cli._inspect", boom)
    assert main(["scan", str(FIXTURE), "--format", "json"]) == EXIT_OK
    data = json.loads(capsys.readouterr().out)
    assert data["registry_lookup"] == {"enabled": False, "results": []}


def test_registry_flag_reports_unique_registry_names(monkeypatch, capsys):
    monkeypatch.setattr("sentinel.cli._inspect", fake_inspect(LookupStatus.FOUND))
    assert main(["scan", str(FIXTURE), "--registry", "--format", "json"]) == EXIT_OK
    data = json.loads(capsys.readouterr().out)
    assert data["registry_lookup"]["enabled"] is True
    assert len(data["registry_lookup"]["results"]) == 13   # 8 npm + 5 pypi; git/url deps excluded


def test_registry_text_output(monkeypatch, capsys):
    monkeypatch.setattr("sentinel.cli._inspect", fake_inspect(LookupStatus.NOT_FOUND))
    assert main(["scan", str(FIXTURE), "--registry"]) == EXIT_OK
    assert "Registry lookups: 13" in capsys.readouterr().out


def test_lookup_error_exits_2_never_passes(monkeypatch, capsys):
    monkeypatch.setattr("sentinel.cli._inspect", fake_inspect(LookupStatus.ERROR))
    assert main(["scan", str(FIXTURE), "--registry"]) == EXIT_ERROR
    assert "registry lookup failed" in capsys.readouterr().err
