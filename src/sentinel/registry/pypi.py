"""PyPI registry client."""
from __future__ import annotations

import re
from typing import Any

from sentinel.analysis.names import normalize_name
from sentinel.models import Ecosystem, LookupStatus, RegistryEvidence
from sentinel.registry.common import MalformedResponse, ParsedMetadata, lookup_package
from sentinel.registry.http import Fetcher

PYPI_BASE_URL = "https://pypi.org"
_PYPI_NAME = re.compile(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?")   # PEP 503 normalized form


def is_valid_pypi_name(name: str) -> bool:
    return len(name) <= 200 and _PYPI_NAME.fullmatch(name) is not None


def parse_pypi_metadata(name: str, payload: Any) -> ParsedMetadata:
    if not isinstance(payload, dict):
        raise MalformedResponse("top-level value is not an object")
    info = payload.get("info")
    if not isinstance(info, dict):
        raise MalformedResponse("'info' is missing or not an object")
    doc_name = info.get("name")
    if isinstance(doc_name, str) and normalize_name(Ecosystem.PYPI, doc_name) != name:
        raise MalformedResponse("response is for a different package than requested")
    latest = info.get("version")
    latest = latest if isinstance(latest, str) and latest else None

    releases = payload.get("releases", {})      # lenient if absent, strict if wrong type
    if not isinstance(releases, dict):
        raise MalformedResponse("'releases' is not an object")
    first: str | None = None
    for files in releases.values():
        if not isinstance(files, list):
            continue
        for item in files:
            stamp = item.get("upload_time_iso_8601") if isinstance(item, dict) else None
            if isinstance(stamp, str) and (first is None or stamp < first):
                first = stamp
    return ParsedMetadata(latest_version=latest, versions=tuple(releases), first_published=first)


class PypiClient:
    ecosystem = Ecosystem.PYPI

    def __init__(self, fetcher: Fetcher, base_url: str = PYPI_BASE_URL) -> None:
        self._fetcher = fetcher
        self._base_url = base_url.rstrip("/")

    def url_for(self, name: str) -> str:
        return f"{self._base_url}/pypi/{name}/json"    # name already validated

    async def lookup(self, name: str) -> RegistryEvidence:
        if not is_valid_pypi_name(name):
            return RegistryEvidence(
                ecosystem=self.ecosystem, name=name, status=LookupStatus.SKIPPED,
                registry_url=self._base_url, detail="invalid PyPI package name; not queried")
        return await lookup_package(
            self._fetcher, ecosystem=self.ecosystem, name=name,
            url=self.url_for(name), headers=None, parse=parse_pypi_metadata)
