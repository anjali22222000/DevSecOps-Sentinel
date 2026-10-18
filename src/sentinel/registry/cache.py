"""Small bounded LRU cache so memory use cannot grow without limit."""
from __future__ import annotations

from collections import OrderedDict
from typing import Generic, Hashable, TypeVar

V = TypeVar("V")


class BoundedCache(Generic[V]):
    def __init__(self, max_entries: int = 1024) -> None:
        if max_entries < 1:
            raise ValueError("max_entries must be >= 1")
        self._max_entries = max_entries
        self._data: OrderedDict[Hashable, V] = OrderedDict()

    def get(self, key: Hashable) -> V | None:
        if key not in self._data:
            return None
        self._data.move_to_end(key)
        return self._data[key]

    def put(self, key: Hashable, value: V) -> None:
        self._data[key] = value
        self._data.move_to_end(key)
        while len(self._data) > self._max_entries:
            self._data.popitem(last=False)     # evict least recently used

    def __len__(self) -> int:
        return len(self._data)
