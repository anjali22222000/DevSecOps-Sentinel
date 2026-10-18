"""Hardened async HTTP fetcher shared by the NPM and PyPI clients."""
from __future__ import annotations

import asyncio
import random
from collections.abc import Awaitable, Callable
from dataclasses import dataclass

import aiohttp

from sentinel import __version__

RETRYABLE_STATUS = frozenset({429, 500, 502, 503, 504})


@dataclass(frozen=True)
class FetchResult:
    status: int | None          # None when no usable HTTP response was obtained
    body: bytes = b""
    error: str | None = None    # set when the request ultimately failed
    attempts: int = 1


class _BodyTooLarge(Exception):
    pass


def _parse_retry_after(value: str | None) -> float | None:
    """Only the delta-seconds form is supported; anything else falls back to backoff."""
    if value is None:
        return None
    try:
        seconds = float(value)
    except ValueError:
        return None
    return seconds if seconds >= 0 else None


class Fetcher:
    """Use as `async with Fetcher(...) as fetcher: await fetcher.fetch(url)`."""

    def __init__(
        self,
        *,
        timeout: float = 10.0,
        concurrency: int = 10,
        max_retries: int = 3,
        backoff_base: float = 0.5,
        backoff_cap: float = 30.0,
        max_body_bytes: int = 20 * 1024 * 1024,
        trust_env: bool = True,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
        jitter: Callable[[], float] = random.random,
    ) -> None:
        if timeout <= 0 or concurrency < 1 or max_retries < 0:
            raise ValueError("timeout must be > 0, concurrency >= 1, max_retries >= 0")
        self._timeout = timeout
        self._concurrency = concurrency
        self._max_retries = max_retries
        self._backoff_base = backoff_base
        self._backoff_cap = backoff_cap
        self._max_body_bytes = max_body_bytes
        self._trust_env = trust_env
        self._sleep = sleep
        self._jitter = jitter
        self._session: aiohttp.ClientSession | None = None
        self._semaphore: asyncio.Semaphore | None = None

    async def __aenter__(self) -> Fetcher:
        self._session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=self._timeout),
            connector=aiohttp.TCPConnector(limit=self._concurrency),
            headers={"User-Agent": f"devsecops-sentinel/{__version__}",
                     "Accept": "application/json"},
            trust_env=self._trust_env,
        )
        self._semaphore = asyncio.Semaphore(self._concurrency)
        return self

    async def __aexit__(self, *exc_info: object) -> None:
        if self._session is not None:
            await self._session.close()

    def _delay(self, attempt: int, retry_after: float | None) -> float:
        if retry_after is not None:
            return min(self._backoff_cap, retry_after)
        delay = self._backoff_base * 2 ** (attempt - 1)
        return min(self._backoff_cap, delay * (1 + 0.25 * self._jitter()))

    async def _read_body(self, response: aiohttp.ClientResponse) -> bytes:
        chunks: list[bytes] = []
        size = 0
        async for chunk in response.content.iter_chunked(64 * 1024):
            size += len(chunk)
            if size > self._max_body_bytes:
                raise _BodyTooLarge
            chunks.append(chunk)
        return b"".join(chunks)

    async def fetch(self, url: str, headers: dict[str, str] | None = None) -> FetchResult:
        if self._session is None or self._semaphore is None:
            raise RuntimeError("Fetcher must be used as an async context manager")

        attempt = 0
        last_status: int | None = None
        last_error = "no attempt made"
        while attempt <= self._max_retries:
            attempt += 1
            retry_after: float | None = None
            async with self._semaphore:          # slot is released while we back off
                try:
                    async with self._session.get(
                        url, headers=headers, allow_redirects=False
                    ) as response:
                        if response.status in RETRYABLE_STATUS:
                            last_status = response.status
                            last_error = f"HTTP {response.status}"
                            retry_after = _parse_retry_after(response.headers.get("Retry-After"))
                        else:
                            body = await self._read_body(response)
                            return FetchResult(response.status, body, None, attempt)
                except _BodyTooLarge:
                    return FetchResult(
                        None, b"",
                        f"response body too large (limit {self._max_body_bytes} bytes)", attempt)
                except (aiohttp.ClientError, asyncio.TimeoutError) as exc:
                    last_status, last_error = None, type(exc).__name__
            if attempt <= self._max_retries:
                await self._sleep(self._delay(attempt, retry_after))

        return FetchResult(
            last_status, b"", f"{last_error} (gave up after {attempt} attempt(s))", attempt)
