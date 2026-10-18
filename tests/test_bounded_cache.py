import pytest

from sentinel.registry.cache import BoundedCache


def test_evicts_least_recently_used():
    cache = BoundedCache(max_entries=2)
    cache.put("a", 1)
    cache.put("b", 2)
    assert cache.get("a") == 1          # touching 'a' makes 'b' the oldest
    cache.put("c", 3)
    assert cache.get("b") is None
    assert cache.get("a") == 1 and cache.get("c") == 3
    assert len(cache) == 2


def test_missing_key_returns_none():
    assert BoundedCache().get("nope") is None


def test_invalid_size_rejected():
    with pytest.raises(ValueError):
        BoundedCache(max_entries=0)
