import asyncio
import json

from sentinel.models import Dependency, Ecosystem, LookupStatus, Origin, SourceType
from sentinel.registry import RegistryInspector
from sentinel.registry.http import FetchResult
from sentinel.registry.npm import NpmClient
from sentinel.registry.pypi import PypiClient
from support import FakeFetcher

NPM = "https://npm.test"
PYPI = "https://pypi.test"


def ok(payload):
    return FetchResult(status=200, body=json.dumps(payload).encode())


def npm_lookup(responses, name):
    fetcher = FakeFetcher(responses)
    return fetcher, asyncio.run(NpmClient(fetcher, NPM).lookup(name))


def test_npm_found_uses_abbreviated_metadata_header():
    fetcher, ev = npm_lookup({f"{NPM}/express": ok({
        "name": "express", "dist-tags": {"latest": "4.18.2"},
        "versions": {"4.18.1": {}, "4.18.2": {}}})}, "express")
    assert ev.status is LookupStatus.FOUND
    assert ev.latest_version == "4.18.2" and ev.versions == ("4.18.1", "4.18.2")
    assert fetcher.calls[0][1]["Accept"].startswith("application/vnd.npm.install-v1")


def test_npm_scoped_name_requests_encoded_url():
    fetcher, ev = npm_lookup({f"{NPM}/@acme-demo%2Futils": ok({
        "name": "@acme-demo/utils", "versions": {}})}, "@acme-demo/utils")
    assert fetcher.calls[0][0] == f"{NPM}/@acme-demo%2Futils"
    assert ev.status is LookupStatus.FOUND


def test_npm_404_is_not_found():
    _, ev = npm_lookup({}, "ghost-pkg")
    assert ev.status is LookupStatus.NOT_FOUND


def test_npm_invalid_name_is_skipped_and_never_requested():
    fetcher, ev = npm_lookup({}, "../../admin")
    assert ev.status is LookupStatus.SKIPPED and fetcher.calls == []


def test_network_failure_is_error_not_not_found():
    _, ev = npm_lookup({f"{NPM}/express": FetchResult(
        status=None, error="boom (gave up after 4 attempt(s))", attempts=4)}, "express")
    assert ev.status is LookupStatus.ERROR and "boom" in ev.detail and ev.attempts == 4


def test_unexpected_status_and_redirect_are_errors():
    for status in (301, 403):
        _, ev = npm_lookup({f"{NPM}/express": FetchResult(status=status)}, "express")
        assert ev.status is LookupStatus.ERROR


def test_invalid_json_and_wrong_shape_are_errors():
    _, ev = npm_lookup({f"{NPM}/express": FetchResult(status=200, body=b"<html>")}, "express")
    assert ev.status is LookupStatus.ERROR and "not valid JSON" in ev.detail
    _, ev = npm_lookup({f"{NPM}/express": ok({"unexpected": True})}, "express")
    assert ev.status is LookupStatus.ERROR and "malformed" in ev.detail


def test_pypi_found_and_not_found():
    fetcher = FakeFetcher({f"{PYPI}/pypi/requests/json": ok({
        "info": {"name": "requests", "version": "2.31.0"},
        "releases": {"2.31.0": [{"upload_time_iso_8601": "2023-05-22T00:00:00.000000Z"}]}})})
    client = PypiClient(fetcher, PYPI)
    found = asyncio.run(client.lookup("requests"))
    assert found.status is LookupStatus.FOUND and found.first_published.startswith("2023-05-22")
    assert asyncio.run(client.lookup("no-such-pkg")).status is LookupStatus.NOT_FOUND


def dep(name, eco=Ecosystem.NPM, source=SourceType.REGISTRY, origin=Origin.MANIFEST):
    return Dependency(name=name, ecosystem=eco, origin=origin, source_file="f",
                      section="s", source_type=source)


def test_inspector_dedupes_skips_non_registry_and_caches_only_definitive_results():
    fetcher = FakeFetcher({
        f"{NPM}/express": ok({"name": "express", "dist-tags": {}, "versions": {}}),
        f"{NPM}/flaky": FetchResult(status=None, error="boom", attempts=4),
    })
    inspector = RegistryInspector(fetcher, npm_base_url=NPM, pypi_base_url=PYPI)
    deps = [dep("express"), dep("express", origin=Origin.LOCKFILE), dep("flaky"),
            dep("tools", source=SourceType.GIT), dep("ghost")]

    results = asyncio.run(inspector.inspect(deps))
    assert set(results) == {(Ecosystem.NPM, "express"), (Ecosystem.NPM, "flaky"),
                            (Ecosystem.NPM, "ghost")}
    assert results[(Ecosystem.NPM, "ghost")].status is LookupStatus.NOT_FOUND
    assert results[(Ecosystem.NPM, "flaky")].status is LookupStatus.ERROR
    assert len(fetcher.calls) == 3               # duplicates and GIT dependency not queried

    asyncio.run(inspector.inspect(deps))
    assert len(fetcher.calls) == 4               # only the ERROR was retried; others cached
