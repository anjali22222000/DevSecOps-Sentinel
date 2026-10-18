"""Turn a fetch result into RegistryEvidence (shared by both ecosystems)."""
from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from sentinel.models import Ecosystem, LookupStatus, RegistryEvidence
from sentinel.registry.http import Fetcher


class MalformedResponse(Exception):
    """HTTP 200, but the body is not what we expected."""


@dataclass(frozen=True)
class ParsedMetadata:
    latest_version: str | None
    versions: tuple[str, ...]
    first_published: str | None = None


async def lookup_package(
    fetcher: Fetcher,
    *,
    ecosystem: Ecosystem,
    name: str,
    url: str,
    headers: dict[str, str] | None,
    parse: Callable[[str, Any], ParsedMetadata],
) -> RegistryEvidence:
    result = await fetcher.fetch(url, headers=headers)

    def evidence(status: LookupStatus, **extra: Any) -> RegistryEvidence:
        return RegistryEvidence(ecosystem=ecosystem, name=name, status=status,
                                registry_url=url, attempts=result.attempts, **extra)

    if result.error:
        return evidence(LookupStatus.ERROR, detail=result.error)
    if result.status == 404:
        return evidence(LookupStatus.NOT_FOUND)
    if result.status != 200:
        return evidence(LookupStatus.ERROR, detail=f"unexpected HTTP status {result.status}")
    try:
        payload = json.loads(result.body)
    except (ValueError, RecursionError):
        return evidence(LookupStatus.ERROR, detail="response is not valid JSON")
    try:
        meta = parse(name, payload)
    except MalformedResponse as exc:
        return evidence(LookupStatus.ERROR, detail=f"malformed response: {exc}")
    return evidence(LookupStatus.FOUND, latest_version=meta.latest_version,
                    versions=meta.versions, first_published=meta.first_published)
