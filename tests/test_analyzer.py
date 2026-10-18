import pytest

from sentinel.config import parse_config
from sentinel.models import Ecosystem, LookupStatus, Origin, RegistryOption, Severity, SourceType
from sentinel.scanner import split_for_lookup
from helpers import ACME, ACME_OWNED, by_package, dep, ev, run

AUTH = "@acme-demo/auth"


def test_internal_name_with_higher_public_version_is_critical():
    f = by_package(run([dep(AUTH, pinned="1.4.0")],
                       [ev(AUTH, versions=["1.4.0", "99.0.0"], latest="99.0.0")], ACME))[AUTH]
    assert f.severity is Severity.CRITICAL and f.score == 80 and f.rule_id == "SENT-DC-001"
    assert f.indicators[0].key == "V" and f.indicators[0].value == 100
    assert "99.0.0" in f.reason and f.assessment == "complete"


def test_higher_version_uses_semver_not_string_order():
    f = by_package(run([dep(AUTH, pinned="1.4.0")], [ev(AUTH, versions=["1.10.0"])], ACME))[AUTH]
    assert f.indicators[0].value == 100                  # 1.10.0 > 1.4.0 (string order would say no)
    f = by_package(run([dep(AUTH, pinned="1.10.0")], [ev(AUTH, versions=["1.4.0"])], ACME))[AUTH]
    assert f.indicators[0].value == 0


def test_public_version_equal_or_lower_is_not_a_version_mismatch():
    f = by_package(run([dep(AUTH, pinned="1.4.0")], [ev(AUTH, versions=["1.0.0", "1.4.0"])], ACME))[AUTH]
    assert f.indicators[0].value == 0
    assert f.indicators[1].value == 100                  # still registered publicly and not owned
    assert f.score == 30 and f.severity is Severity.MEDIUM and f.rule_id == "SENT-DC-001"


def test_owned_scope_and_not_public_is_safe_and_complete():
    f = by_package(run([dep(AUTH, pinned="1.4.0")], [ev(AUTH, LookupStatus.NOT_FOUND)], ACME_OWNED))[AUTH]
    assert f.severity is Severity.SAFE and f.score == 0 and f.assessment == "complete"
    assert f.rule_id is None


def test_internal_name_not_found_and_not_reserved_is_medium_with_404_caveat():
    f = by_package(run([dep(AUTH, pinned="1.4.0")], [ev(AUTH, LookupStatus.NOT_FOUND)], ACME))[AUTH]
    assert f.severity is Severity.MEDIUM and f.rule_id == "SENT-DC-002"
    assert any("private packages" in l for l in f.limitations)


def test_lockfile_resolved_from_public_registry_is_critical_even_offline():
    d = dep(AUTH, pinned="1.4.0", origin=Origin.LOCKFILE, file="package-lock.json",
            resolved="https://registry.npmjs.org/@acme-demo/auth/-/auth-1.4.0.tgz")
    f = by_package(run([d], [], ACME))[AUTH]
    assert f.severity is Severity.CRITICAL and "registry.npmjs.org" in f.reason
    assert f.assessment == "partial"                     # registry evidence is still missing


def test_lockfile_from_private_host_adds_no_floor():
    d = dep(AUTH, pinned="1.4.0", origin=Origin.LOCKFILE, file="package-lock.json",
            resolved="https://npm.acme-demo.example/a.tgz")
    f = by_package(run([d], [ev(AUTH, LookupStatus.NOT_FOUND)], ACME_OWNED))[AUTH]
    assert f.severity is Severity.SAFE


def test_missing_expected_version_makes_v_unavailable_not_safe():
    f = by_package(run([dep(AUTH, spec="^1.0.0")], [ev(AUTH, versions=["99.0.0"])], ACME_OWNED))[AUTH]
    assert f.indicators[0].value is None and f.assessment == "partial"
    assert any("expected" in l or "Incomplete" in l for l in f.limitations)


def test_expected_version_from_config_beats_manifest_range():
    cfg = parse_config({"internal": {"npm": {"scopes": ["@acme-demo"]},
                                     "expected_versions": {"npm:@acme-demo/auth": "1.4.0"}}})
    f = by_package(run([dep(AUTH, spec="^1.0.0")], [ev(AUTH, versions=["99.0.0"])], cfg))[AUTH]
    assert f.severity is Severity.CRITICAL


def test_expected_version_prefers_lockfile_pin():
    deps = [dep(AUTH, spec="^1.0.0"),
            dep(AUTH, pinned="1.4.0", origin=Origin.LOCKFILE, file="package-lock.json")]
    f = by_package(run(deps, [ev(AUTH, versions=["1.9.0"])], ACME))[AUTH]
    assert f.indicators[0].value == 100 and "lockfile" in f.indicators[0].note


def test_pypi_internal_prefix_and_pep440():
    d = dep("acme-demo-reports", Ecosystem.PYPI, pinned="3.0.0", file="requirements.txt", line=2)
    f = by_package(run([d], [ev("acme-demo-reports", eco=Ecosystem.PYPI, versions=["3.0.0", "99.0"])], ACME))["acme-demo-reports"]
    assert f.severity is Severity.CRITICAL and f.locations[0].line == 2


def test_typosquat_is_high_when_package_is_new():
    f = by_package(run([dep("expresss", pinned="1.0.0")],
                       [ev("expresss", versions=["1.0.0"])]))["expresss"]
    assert f.severity is Severity.HIGH and f.score == 60 and f.rule_id == "SENT-TS-001"
    assert f.indicators[2].value == pytest.approx(87.5)
    assert "express" in f.recommendation
    assert any("resemblance" in l for l in f.limitations)


def test_lower_similarity_lookalike_is_medium():
    f = by_package(run([dep("lodahs", pinned="1.0.0")], [ev("lodahs", versions=["1.0.0"])]))["lodahs"]
    assert f.severity is Severity.MEDIUM and f.rule_id == "SENT-TS-001"


def test_established_package_is_not_flagged_by_similarity_floor():
    many = [f"1.0.{i}" for i in range(12)]
    f = by_package(run([dep("expresss", pinned="1.0.0")], [ev("expresss", versions=many)]))["expresss"]
    assert f.severity is Severity.SAFE and f.floor is None       # formula alone is 26.25
    assert any("established" in e for e in f.evidence)


def test_old_package_by_age_is_established():
    f = by_package(run([dep("expresss", pinned="1.0.0")],
                       [ev("expresss", versions=["1.0.0"], first="2020-01-01T00:00:00Z")]))["expresss"]
    assert f.floor is None


def test_exact_well_known_name_is_not_flagged():
    f = by_package(run([dep("express", pinned="4.18.2")], [ev("express", versions=["4.18.2"])]))["express"]
    assert f.severity is Severity.SAFE and f.assessment == "complete"


def test_unconfigured_unregistered_name_is_medium():
    f = by_package(run([dep("mystery-internal-lib", pinned="1.0.0")],
                       [ev("mystery-internal-lib", LookupStatus.NOT_FOUND)]))["mystery-internal-lib"]
    assert f.severity is Severity.MEDIUM and f.rule_id == "SENT-DC-002"
    assert "not declared internal" in f.reason


def test_registry_error_is_partial_never_silently_safe():
    f = by_package(run([dep("express", pinned="4.18.2")],
                       [ev("express", LookupStatus.ERROR, detail="timeout")]))["express"]
    assert f.assessment == "partial" and any("Public registry: lookup FAILED" in e for e in f.evidence)


def test_offline_scan_marks_everything_partial():
    findings = run([dep("express", pinned="4.18.2"), dep("lodash", pinned="4.17.21")], [])
    assert all(f.assessment == "partial" for f in findings)


def test_privacy_mode_skips_internal_names():
    cfg = parse_config({"privacy": {"query_internal_names": False},
                        "internal": {"npm": {"scopes": ["@acme-demo"]}}})
    deps = [dep(AUTH, pinned="1.4.0"), dep("express", pinned="4.18.2")]
    queryable, skipped = split_for_lookup(deps, cfg)
    assert [d.name for d in queryable] == ["express"]
    assert skipped[(Ecosystem.NPM, AUTH)].status is LookupStatus.SKIPPED
    f = by_package(run(deps, list(skipped.values()) + [ev("express")], cfg))[AUTH]
    assert f.assessment == "partial" and any("privacy mode" in e for e in f.evidence)


def test_non_registry_dependencies_are_not_assessed():
    findings = run([dep("tools", source=SourceType.GIT), dep("local", source=SourceType.LOCAL)], [])
    assert findings == []


def test_duplicate_manifest_and_lockfile_entries_make_one_finding():
    deps = [dep("express", spec="^4.0.0"),
            dep("express", pinned="4.18.2", origin=Origin.LOCKFILE, file="package-lock.json")]
    findings = run(deps, [ev("express")])
    assert len([f for f in findings if f.package == "express"]) == 1


def test_findings_are_sorted_worst_first_with_sequential_ids():
    deps = [dep("express", pinned="4.18.2"), dep(AUTH, pinned="1.4.0"), dep("expresss", pinned="1.0.0")]
    findings = run(deps, [ev("express"), ev(AUTH, versions=["99.0.0"]), ev("expresss", versions=["1.0.0"])], ACME)
    assert [f.id for f in findings] == ["F001", "F002", "F003"]
    assert [f.severity for f in findings] == [Severity.CRITICAL, Severity.HIGH, Severity.SAFE]
    assert [f.score for f in findings] == sorted((f.score for f in findings), reverse=True)


def test_config_findings_extra_index_url_severity_depends_on_internal_pypi_config():
    opt = RegistryOption("extra-index-url", "https://pypi.acme-demo.example/simple", "requirements.txt", 1)
    plain = run([], options=[opt])[0]
    assert plain.rule_id == "SENT-CFG-001" and plain.severity is Severity.MEDIUM and plain.score == 40
    with_internal = run([], config=ACME, options=[opt])[0]
    assert with_internal.severity is Severity.HIGH and with_internal.score == 65
    assert with_internal.formula_score is None and with_internal.kind == "configuration"


def test_config_findings_trusted_host_and_plain_http():
    opts = [RegistryOption("trusted-host", "pypi.example", "requirements.txt", 3),
            RegistryOption("index-url", "http://pypi.example/simple", "requirements.txt", 2)]
    rules = {f.rule_id: f for f in run([], options=opts)}
    assert rules["SENT-CFG-002"].severity is Severity.MEDIUM
    assert rules["SENT-CFG-003"].severity is Severity.HIGH
    assert run([], options=[RegistryOption("index-url", "https://pypi.org/simple", "r.txt", 1)]) == []


def test_locator_finds_line_numbers_in_real_files(tmp_path):
    (tmp_path / "package.json").write_text('{\n  "dependencies": {\n    "expresss": "1.0.0"\n  }\n}\n')
    f = by_package(run([dep("expresss", pinned="1.0.0")], [ev("expresss", versions=["1.0.0"])], root=tmp_path))["expresss"]
    assert f.locations[0].file == "package.json" and f.locations[0].line == 3
