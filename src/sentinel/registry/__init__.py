"""Look up dependencies on public registries, concurrently."""
from __future__ import annotations

import asyncio
from collections.abc import Iterable

from sentinel.models import Dependency, Ecosystem, LookupStatus, RegistryEvidence, SourceType
from sentinel.registry.cache import BoundedCache
from sentinel.registry.http import Fetcher
from sentinel.registry.npm import NPM_BASE_URL, NpmClient
from sentinel.registry.pypi import PYPI_BASE_URL, PypiClient

Key = tuple[Ecosystem, str]


class RegistryInspector:
    def __init__(
        self,
        fetcher: Fetcher,
        *,
        npm_base_url: str = NPM_BASE_URL,
        pypi_base_url: str = PYPI_BASE_URL,
        cache: BoundedCache[RegistryEvidence] | None = None,
    ) -> None:
        self._clients = {
            Ecosystem.NPM: NpmClient(fetcher, npm_base_url),
            Ecosystem.PYPI: PypiClient(fetcher, pypi_base_url),
        }
        # `cache or ...` would be wrong: an empty cache is falsy because it defines __len__
        self._cache = cache if cache is not None else BoundedCache()

    async def lookup(self, ecosystem: Ecosystem, name: str) -> RegistryEvidence:
        key: Key = (ecosystem, name)
        cached = self._cache.get(key)
        if cached is not None:
            return cached
        evidence = await self._clients[ecosystem].lookup(name)
        if evidence.status in (LookupStatus.FOUND, LookupStatus.NOT_FOUND):
            self._cache.put(key, evidence)      # never cache ERROR or SKIPPED
        return evidence

    async def inspect(self, dependencies: Iterable[Dependency]) -> dict[Key, RegistryEvidence]:
        """One lookup per unique registry-sourced (ecosystem, name)."""
        keys = list(dict.fromkeys(
            (d.ecosystem, d.name) for d in dependencies if d.source_type is SourceType.REGISTRY))
        results = await asyncio.gather(*(self.lookup(*key) for key in keys))
        return dict(zip(keys, results))
