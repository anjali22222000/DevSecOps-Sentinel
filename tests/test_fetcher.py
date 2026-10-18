import asyncio

from aiohttp import web

from sentinel.registry.http import Fetcher
from support import recording_sleep, serve


def make(**kwargs):
    return Fetcher(trust_env=False, jitter=lambda: 0.0, **kwargs)


def test_success_returns_body_and_sends_user_agent():
    seen = {}

    async def handler(request):
        seen["ua"] = request.headers.get("User-Agent", "")
        return web.json_response({"ok": True})

    async def run(base):
        async with make() as fetcher:
            return await fetcher.fetch(f"{base}/x")

    result = asyncio.run(serve({"/x": handler}, run))
    assert result.status == 200 and result.error is None and result.attempts == 1
    assert b'"ok"' in result.body
    assert seen["ua"].startswith("devsecops-sentinel/")


def test_404_is_a_normal_answer_not_an_error():
    async def handler(request):
        return web.Response(status=404)

    async def run(base):
        async with make() as fetcher:
            return await fetcher.fetch(f"{base}/x")

    result = asyncio.run(serve({"/x": handler}, run))
    assert result.status == 404 and result.error is None and result.attempts == 1


def test_retries_503_then_succeeds_with_backoff():
    state = {"n": 0}

    async def handler(request):
        state["n"] += 1
        if state["n"] == 1:
            return web.Response(status=503)
        return web.json_response({})

    delays, sleep = recording_sleep()

    async def run(base):
        async with make(sleep=sleep, backoff_base=0.5) as fetcher:
            return await fetcher.fetch(f"{base}/x")

    result = asyncio.run(serve({"/x": handler}, run))
    assert result.status == 200 and result.attempts == 2
    assert delays == [0.5]


def test_persistent_503_gives_up_with_error():
    async def handler(request):
        return web.Response(status=503)

    delays, sleep = recording_sleep()

    async def run(base):
        async with make(sleep=sleep, max_retries=2, backoff_base=0.5) as fetcher:
            return await fetcher.fetch(f"{base}/x")

    result = asyncio.run(serve({"/x": handler}, run))
    assert result.status == 503 and result.attempts == 3
    assert result.error and "gave up after 3" in result.error
    assert delays == [0.5, 1.0]            # exponential backoff


def test_429_honors_retry_after():
    state = {"n": 0}

    async def handler(request):
        state["n"] += 1
        if state["n"] == 1:
            return web.Response(status=429, headers={"Retry-After": "7"})
        return web.json_response({})

    delays, sleep = recording_sleep()

    async def run(base):
        async with make(sleep=sleep) as fetcher:
            return await fetcher.fetch(f"{base}/x")

    result = asyncio.run(serve({"/x": handler}, run))
    assert result.status == 200 and delays == [7.0]


def test_retry_after_is_capped():
    state = {"n": 0}

    async def handler(request):
        state["n"] += 1
        if state["n"] == 1:
            return web.Response(status=429, headers={"Retry-After": "999"})
        return web.json_response({})

    delays, sleep = recording_sleep()

    async def run(base):
        async with make(sleep=sleep, backoff_cap=5.0) as fetcher:
            return await fetcher.fetch(f"{base}/x")

    asyncio.run(serve({"/x": handler}, run))
    assert delays == [5.0]


def test_timeout_is_an_error():
    async def handler(request):
        await asyncio.sleep(0.6)
        return web.json_response({})

    async def run(base):
        async with make(timeout=0.2, max_retries=0) as fetcher:
            return await fetcher.fetch(f"{base}/x")

    result = asyncio.run(serve({"/x": handler}, run))
    assert result.status is None and result.error and result.attempts == 1


def test_redirects_are_not_followed():
    async def handler(request):
        raise web.HTTPFound("/other")

    async def run(base):
        async with make() as fetcher:
            return await fetcher.fetch(f"{base}/x")

    result = asyncio.run(serve({"/x": handler}, run))
    assert result.status == 302 and result.error is None


def test_oversized_body_is_rejected():
    async def handler(request):
        return web.Response(body=b"x" * 10_000)

    async def run(base):
        async with make(max_body_bytes=1_000) as fetcher:
            return await fetcher.fetch(f"{base}/x")

    result = asyncio.run(serve({"/x": handler}, run))
    assert result.status is None and "too large" in result.error


def test_concurrency_limit_is_respected():
    state = {"now": 0, "max": 0}

    async def handler(request):
        state["now"] += 1
        state["max"] = max(state["max"], state["now"])
        await asyncio.sleep(0.05)
        state["now"] -= 1
        return web.json_response({})

    async def run(base):
        async with make(concurrency=2) as fetcher:
            return await asyncio.gather(*(fetcher.fetch(f"{base}/x?i={i}") for i in range(8)))

    results = asyncio.run(serve({"/x": handler}, run))
    assert all(r.status == 200 for r in results)
    assert state["max"] <= 2


def test_connection_failure_is_an_error_not_a_crash():
    delays, sleep = recording_sleep()

    async def run():
        async with make(sleep=sleep, max_retries=1, timeout=3) as fetcher:
            return await fetcher.fetch("http://127.0.0.1:1/x")   # nothing listens on port 1

    result = asyncio.run(run())
    assert result.status is None and result.error and result.attempts == 2
    assert len(delays) == 1
