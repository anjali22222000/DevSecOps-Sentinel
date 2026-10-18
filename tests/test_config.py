from pathlib import Path

import pytest

from sentinel.config import Config, ConfigError, Weights, load_config, parse_config
from sentinel.models import Ecosystem

EXAMPLE = Path(__file__).resolve().parents[1] / "sentinel.example.toml"


def write(tmp_path, text):
    path = tmp_path / "sentinel.toml"
    path.write_text(text, encoding="utf-8")
    return path


def test_defaults_and_none_path():
    cfg = load_config(None)
    assert cfg == Config()
    assert (cfg.weights.version, cfg.weights.scope, cfg.weights.similarity) == (0.4, 0.3, 0.3)
    assert cfg.policy.fail_on == "high" and cfg.query_internal_names is True


def test_example_config_in_repo_is_valid():
    cfg = load_config(EXAMPLE)
    assert cfg.internal.is_internal(Ecosystem.NPM, "@acme-demo/auth")
    assert cfg.internal.is_internal(Ecosystem.PYPI, "acme-demo-billing")
    assert cfg.internal.owns_public(Ecosystem.NPM, "@acme-demo/anything")   # whole scope reserved
    assert cfg.internal.expected_version(Ecosystem.NPM, "@acme-demo/auth") == "1.4.0"


@pytest.mark.parametrize("weights", [(0.5, 0.5, 0.5), (0.4, 0.3, 0.2), (1.2, -0.1, -0.1)])
def test_weights_must_sum_to_one_and_be_in_range(weights):
    with pytest.raises(ConfigError):
        Weights(*weights).validate()


def test_weights_validated_when_loading(tmp_path):
    with pytest.raises(ConfigError, match="sum to 1.0"):
        load_config(write(tmp_path, "[weights]\nversion=0.5\nscope=0.5\nsimilarity=0.5\n"))
    cfg = load_config(write(tmp_path, "[weights]\nversion=0.2\nscope=0.2\nsimilarity=0.6\n"))
    assert cfg.weights.similarity == 0.6


@pytest.mark.parametrize("text", [
    "[typo_section]\nx=1\n",
    "[policy]\nfail_onn='high'\n",
    "[weights]\nversoin=1.0\n",
    "[internal]\nnpm_scopes=['@a']\n",
    "[internal.npm]\nscopez=['@a']\n",
])
def test_unknown_keys_are_rejected(tmp_path, text):
    with pytest.raises(ConfigError):
        load_config(write(tmp_path, text))


@pytest.mark.parametrize("text", [
    "[policy]\nfail_on='sometimes'\n",
    "[policy]\nblock_on_incomplete='yes'\n",
    "[similarity]\nalgorithm='magic'\n",
    "[registry]\ntimeout=0\n",
    "[internal.npm]\nscopes=['acme']\n",
    "[internal]\nowned_public=['acme']\n",
    "[internal.expected_versions]\n'acme'='1.0.0'\n",
    "[privacy]\nquery_internal_names='no'\n",
    "this is = not toml [",
])
def test_invalid_values_are_rejected(tmp_path, text):
    with pytest.raises(ConfigError):
        load_config(write(tmp_path, text))


def test_missing_file_is_a_config_error(tmp_path):
    with pytest.raises(ConfigError):
        load_config(tmp_path / "nope.toml")


def test_internal_matching_rules():
    cfg = parse_config({"internal": {
        "npm": {"scopes": ["@Acme"], "packages": ["legacy-lib"], "prefixes": ["acme-"]},
        "pypi": {"packages": ["Acme_Core"], "prefixes": ["acme_"]}}})
    i = cfg.internal
    assert i.is_internal(Ecosystem.NPM, "@acme/x")
    assert i.is_internal(Ecosystem.NPM, "legacy-lib")
    assert i.is_internal(Ecosystem.NPM, "acme-tools")
    assert not i.is_internal(Ecosystem.NPM, "@other/x")
    assert not i.is_internal(Ecosystem.NPM, "lodash")
    assert i.is_internal(Ecosystem.PYPI, "acme-core")          # PEP 503 normalized
    assert i.is_internal(Ecosystem.PYPI, "acme-billing")
    assert not i.is_internal(Ecosystem.PYPI, "requests")


def test_snapshot_is_json_friendly():
    import json
    snap = load_config(EXAMPLE).snapshot()
    assert json.loads(json.dumps(snap)) == snap
    assert snap["internal"]["expected_versions"]["npm:@acme-demo/auth"] == "1.4.0"
