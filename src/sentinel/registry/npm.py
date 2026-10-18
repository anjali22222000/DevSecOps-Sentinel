"""NPM registry client."""
from __future__ import annotations

import re
from typing import Any
from urllib.parse import quote

from sentinel.models import Ecosystem, LookupStatus, RegistryEvidence
from sentinel.registry.common import MalformedResponse, ParsedMetadata, lookup_package
from sentinel.registry.http import Fetcher

NPM_BASE_URL = "https://registry.npmjs.org"
_NPM_NAME = re.compile(r"(?:@[a-z0-9][a-z0-9._~-]*/)?[a-z0-9][a-z0-9._~-]*")
_HEADERS = {"Accept": "application/vnd.npm.install-v1+json"}  # abbreviated metadata


def is_valid_npm_name(name: str) -> bool:
    return len(name) <= 214 and _NPM_NAME.fullmatch(name) is not None


def parse_npm_metadata(name: str, payload: Any) -> ParsedMetadata:
    if not isinstance(payload, dict):
        raise MalformedResponse("top-level value is not an object")
    doc_name = payload.get("name")
    if isinstance(doc_name, str) and doc_name.lower() != name:
        raise MalformedResponse("response is for a different package than requested")
    versions = payload.get("versions")
    if not isinstance(versions, dict):
        raise MalformedResponse("'versions' is missing or not an object")
    tags = payload.get("dist-tags")
    latest = tags.get("latest") if isinstance(tags, dict) else None
    return ParsedMetadata(
        latest_version=latest if isinstance(latest, str) else None,
        versions=tuple(versions),
    )


class NpmClient:
    ecosystem = Ecosystem.NPM

    def __init__(self, fetcher: Fetcher, base_url: str = NPM_BASE_URL) -> None:
        self._fetcher = fetcher
        self._base_url = base_url.rstrip("/")

    def url_for(self, name: str) -> str:
        return f"{self._base_url}/{quote(name, safe='@')}"   # '@scope/x' -> '@scope%2Fx'

    async def lookup(self, name: str) -> RegistryEvidence:
        if not is_valid_npm_name(name):
            return RegistryEvidence(
                ecosystem=self.ecosystem, name=name, status=LookupStatus.SKIPPED,
                registry_url=self._base_url, detail="invalid npm package name; not queried")
        return await lookup_package(
            self._fetcher, ecosystem=self.ecosystem, name=name,
            url=self.url_for(name), headers=_HEADERS, parse=parse_npm_metadata)
