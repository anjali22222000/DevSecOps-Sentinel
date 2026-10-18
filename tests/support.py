"""Test helpers: a local HTTP server and an in-memory fake fetcher."""
from __future__ import annotations

from collections.abc import Awaitable, Callable

from aiohttp import web
from aiohttp.test_utils import TestServer

from sentinel.registry.http import FetchResult


async def serve(routes: dict[str, Callable], body: Callable[[str], Awaitable]):
    """Start a throwaway server on localhost, run body(base_url), then shut it down."""
    app = web.Application()
    for path, handler in routes.items():
        app.router.add_get(path, handler)
    async with TestServer(app) as server:
        base = str(server.make_url("/")).rstrip("/")
        return await body(base)


def recording_sleep():
    """A fake sleep that records requested delays instead of waiting."""
    delays: list[float] = []

    async def sleep(seconds: float) -> None:
        delays.append(seconds)

    return delays, sleep


class FakeFetcher:
    """Answers from a dict of url -> FetchResult; 404 for anything unknown."""

    def __init__(self, responses: dict[str, FetchResult] | None = None) -> None:
        self.responses = responses or {}
        self.calls: list[tuple[str, dict | None]] = []

    async def fetch(self, url: str, headers: dict | None = None) -> FetchResult:
        self.calls.append((url, headers))
        return self.responses.get(url, FetchResult(status=404))
