"""Async cache backend abstraction.

Ships :class:`InMemoryCache` (process-local) and :class:`RedisCache` (cross-worker).
"""

from __future__ import annotations

import asyncio
import time
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any, TypeAlias, cast

if TYPE_CHECKING:
    from collections.abc import Iterable

_StrSet: TypeAlias = set[str]  # avoids shadowing by CacheBackend.set()


class CacheBackend(ABC):
    """Async key/value backend contract (``str`` keys and values, TTL in seconds)."""

    @abstractmethod
    async def get(self, key: str) -> str | None: ...

    @abstractmethod
    async def set(self, key: str, value: str) -> None: ...

    @abstractmethod
    async def setex(self, key: str, ttl: int, value: str) -> None: ...

    @abstractmethod
    async def delete(self, key: str) -> None: ...

    @abstractmethod
    async def exists(self, key: str) -> bool: ...

    @abstractmethod
    async def set_if_not_exists(self, key: str, value: str, ttl: int) -> bool:
        """Atomically set ``key`` only if absent. Must be race-condition-free."""

    @abstractmethod
    async def mget(self, keys: Iterable[str]) -> list[str | None]: ...

    @abstractmethod
    async def getdel(self, key: str) -> str | None:
        """Atomically return and remove the value (for one-time-use tokens)."""

    @abstractmethod
    async def sadd(self, key: str, *values: str) -> int: ...

    @abstractmethod
    async def smembers(self, key: str) -> _StrSet: ...

    @abstractmethod
    async def srem(self, key: str, *values: str) -> int: ...

    @abstractmethod
    async def expire(self, key: str, ttl: int) -> bool: ...

    @abstractmethod
    async def smembers_and_delete(self, key: str) -> _StrSet:
        """Atomically return all members of ``key`` and delete the set.

        Closes the race window in bulk-revocation paths where a caller
        reads the membership, iterates, then deletes the index — allowing
        a concurrent add to escape revocation. Implementations MUST perform
        the read and delete in a single atomic step (Lua/MULTI for Redis,
        lock-held for in-memory).
        """

    @abstractmethod
    async def sadd_with_ttl(self, key: str, ttl: int, *values: str) -> int:
        """Atomically add ``values`` to ``key`` and set its TTL.

        The set's expiry is (re)set to ``ttl`` seconds in one step so a
        crash between the add and the expiry cannot leave the index
        without a TTL (which would cause unbounded Redis memory growth
        on high-churn hotkeys).
        """


class InMemoryCache(CacheBackend):
    """Process-local cache with monotonic-clock TTL expiry.

    All state is guarded by an :class:`asyncio.Lock`. Expired entries are
    lazily evicted on access (no background sweeper), so entries that are
    never re-read accumulate in memory. Suitable for tests and low-traffic
    deployments. Use :class:`RedisCache` for production under high traffic.
    """

    def __init__(self) -> None:
        self._store: dict[str, tuple[str, float | None]] = {}
        self._sets: dict[str, tuple[_StrSet, float | None]] = {}
        self._lock = asyncio.Lock()

    def _is_expired(self, expires_at: float | None) -> bool:
        return expires_at is not None and time.monotonic() >= expires_at

    def _get_locked(self, key: str) -> str | None:
        entry = self._store.get(key)
        if entry is None:
            return None
        value, expires_at = entry
        if self._is_expired(expires_at):
            del self._store[key]
            return None
        return value

    async def get(self, key: str) -> str | None:
        async with self._lock:
            return self._get_locked(key)

    async def set(self, key: str, value: str) -> None:
        async with self._lock:
            self._store[key] = (value, None)

    async def setex(self, key: str, ttl: int, value: str) -> None:
        async with self._lock:
            self._store[key] = (value, time.monotonic() + ttl)

    async def delete(self, key: str) -> None:
        async with self._lock:
            self._store.pop(key, None)

    async def exists(self, key: str) -> bool:
        async with self._lock:
            return self._get_locked(key) is not None

    async def set_if_not_exists(self, key: str, value: str, ttl: int) -> bool:
        async with self._lock:
            if self._get_locked(key) is not None:
                return False
            self._store[key] = (value, time.monotonic() + ttl)
            return True

    async def mget(self, keys: Iterable[str]) -> list[str | None]:
        async with self._lock:
            return [self._get_locked(k) for k in keys]

    async def getdel(self, key: str) -> str | None:
        async with self._lock:
            value = self._get_locked(key)
            if value is not None:
                del self._store[key]
            return value

    def _get_set_locked(self, key: str) -> _StrSet | None:
        entry = self._sets.get(key)
        if entry is None:
            return None
        members, expires_at = entry
        if self._is_expired(expires_at):
            del self._sets[key]
            return None
        return members

    async def sadd(self, key: str, *values: str) -> int:
        if not values:
            return 0
        async with self._lock:
            existing = self._get_set_locked(key)
            members: _StrSet = existing if existing is not None else set()
            if existing is None:
                self._sets[key] = (members, None)
            before = len(members)
            members.update(values)
            return len(members) - before

    async def smembers(self, key: str) -> _StrSet:
        async with self._lock:
            members = self._get_set_locked(key)
            return set(members) if members is not None else set()

    async def srem(self, key: str, *values: str) -> int:
        if not values:
            return 0
        async with self._lock:
            members = self._get_set_locked(key)
            if members is None:
                return 0
            before = len(members)
            members.difference_update(values)
            removed = before - len(members)
            if not members:
                del self._sets[key]
            return removed

    async def expire(self, key: str, ttl: int) -> bool:
        async with self._lock:
            expires_at = time.monotonic() + ttl
            entry = self._store.get(key)
            if entry is not None and not self._is_expired(entry[1]):
                self._store[key] = (entry[0], expires_at)
                return True
            set_entry = self._sets.get(key)
            if set_entry is not None and not self._is_expired(set_entry[1]):
                self._sets[key] = (set_entry[0], expires_at)
                return True
            self._store.pop(key, None)
            self._sets.pop(key, None)
            return False

    async def smembers_and_delete(self, key: str) -> _StrSet:
        async with self._lock:
            members = self._get_set_locked(key)
            if members is None:
                return set()
            snapshot = set(members)
            del self._sets[key]
            return snapshot

    async def sadd_with_ttl(self, key: str, ttl: int, *values: str) -> int:
        if not values:
            return 0
        async with self._lock:
            existing = self._get_set_locked(key)
            members: _StrSet = existing if existing is not None else set()
            before = len(members)
            members.update(values)
            self._sets[key] = (members, time.monotonic() + ttl)
            return len(members) - before

    async def clear(self) -> None:
        async with self._lock:
            self._store.clear()
            self._sets.clear()


class RedisCache(CacheBackend):
    """Redis-backed cache for cross-process deployments.

    The underlying client MUST be configured with ``decode_responses=True``
    so that returned values are ``str``, not ``bytes``.
    """

    def __init__(self, client: Any) -> None:
        self._client = client

    @classmethod
    def from_url(cls, url: str) -> RedisCache:
        """Construct from a Redis URL. Imports ``redis.asyncio`` lazily."""
        try:
            from redis.asyncio import Redis
        except ImportError as e:
            raise ImportError(
                "RedisCache.from_url requires the optional 'redis' dependency. "
                "Install with: pip install bittensor-auth[redis]"
            ) from e
        return cls(Redis.from_url(url, decode_responses=True))

    async def get(self, key: str) -> str | None:
        return cast("str | None", await self._client.get(key))

    async def set(self, key: str, value: str) -> None:
        await self._client.set(key, value)

    async def setex(self, key: str, ttl: int, value: str) -> None:
        await self._client.setex(key, ttl, value)

    async def delete(self, key: str) -> None:
        await self._client.delete(key)

    async def exists(self, key: str) -> bool:
        return bool(await self._client.exists(key))

    async def set_if_not_exists(self, key: str, value: str, ttl: int) -> bool:
        result = await self._client.set(key, value, nx=True, ex=ttl)
        return result is not None

    async def mget(self, keys: Iterable[str]) -> list[str | None]:
        key_list = list(keys)
        if not key_list:
            return []
        return cast("list[str | None]", await self._client.mget(key_list))

    # Lua fallback for Redis < 6.2 (predates native GETDEL).
    _GETDEL_SCRIPT = (
        "local value = redis.call('GET', KEYS[1]) "
        "if value then redis.call('DEL', KEYS[1]) end "
        "return value"
    )

    async def getdel(self, key: str) -> str | None:
        return cast("str | None", await self._client.eval(self._GETDEL_SCRIPT, 1, key))

    async def sadd(self, key: str, *values: str) -> int:
        if not values:
            return 0
        return int(await self._client.sadd(key, *values))

    async def smembers(self, key: str) -> _StrSet:
        members = await self._client.smembers(key)
        return set(members) if members else set()

    async def srem(self, key: str, *values: str) -> int:
        if not values:
            return 0
        return int(await self._client.srem(key, *values))

    async def expire(self, key: str, ttl: int) -> bool:
        return bool(await self._client.expire(key, ttl))

    # Atomic SMEMBERS + DEL so bulk-revocation paths close their race window.
    _SMEMBERS_AND_DELETE_SCRIPT = (
        "local members = redis.call('SMEMBERS', KEYS[1]) redis.call('DEL', KEYS[1]) return members"
    )

    async def smembers_and_delete(self, key: str) -> _StrSet:
        members = await self._client.eval(self._SMEMBERS_AND_DELETE_SCRIPT, 1, key)
        return set(members) if members else set()

    async def sadd_with_ttl(self, key: str, ttl: int, *values: str) -> int:
        if not values:
            return 0
        # MULTI/EXEC guarantees both commands apply atomically on the
        # server; a mid-call crash can't leave the set without a TTL.
        pipe = self._client.pipeline(transaction=True)
        pipe.sadd(key, *values)
        pipe.expire(key, ttl)
        results = await pipe.execute()
        return int(results[0])

    async def close(self) -> None:
        await self._client.aclose()
