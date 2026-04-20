"""Tests for the in-memory cache backend.

The RedisCache backend is covered by integration tests elsewhere; here we
focus on InMemoryCache, which must provide the same observable semantics
(TTL expiry, atomic set-if-not-exists, batched mget) without any external
service so the core test suite is self-contained.
"""

from __future__ import annotations

import asyncio

import pytest

from bittensor_auth.cache import CacheBackend, InMemoryCache


def test_concrete_class_satisfies_abc() -> None:
    assert isinstance(InMemoryCache(), CacheBackend)


def test_cannot_instantiate_abstract_backend() -> None:
    with pytest.raises(TypeError):
        CacheBackend()  # type: ignore[abstract]


class TestBasicOperations:
    async def test_get_missing_returns_none(self, cache: InMemoryCache) -> None:
        assert await cache.get("missing") is None

    async def test_set_then_get_round_trip(self, cache: InMemoryCache) -> None:
        await cache.set("k", "v")
        assert await cache.get("k") == "v"

    async def test_set_overwrites_existing(self, cache: InMemoryCache) -> None:
        await cache.set("k", "v1")
        await cache.set("k", "v2")
        assert await cache.get("k") == "v2"

    async def test_delete_removes_key(self, cache: InMemoryCache) -> None:
        await cache.set("k", "v")
        await cache.delete("k")
        assert await cache.get("k") is None

    async def test_delete_missing_is_noop(self, cache: InMemoryCache) -> None:
        await cache.delete("nope")

    async def test_exists_reflects_presence(self, cache: InMemoryCache) -> None:
        assert await cache.exists("k") is False
        await cache.set("k", "v")
        assert await cache.exists("k") is True
        await cache.delete("k")
        assert await cache.exists("k") is False


class TestTTLExpiry:
    async def test_setex_value_expires(self, cache: InMemoryCache) -> None:
        await cache.setex("k", ttl=1, value="v")
        assert await cache.get("k") == "v"
        await asyncio.sleep(1.05)
        assert await cache.get("k") is None

    async def test_exists_returns_false_after_expiry(self, cache: InMemoryCache) -> None:
        await cache.setex("k", ttl=1, value="v")
        assert await cache.exists("k") is True
        await asyncio.sleep(1.05)
        assert await cache.exists("k") is False

    async def test_set_has_no_expiry(self, cache: InMemoryCache) -> None:
        await cache.set("k", "v")
        await asyncio.sleep(0.05)
        assert await cache.get("k") == "v"


class TestSetIfNotExists:
    async def test_returns_true_when_key_absent(self, cache: InMemoryCache) -> None:
        assert await cache.set_if_not_exists("k", "v", ttl=60) is True
        assert await cache.get("k") == "v"

    async def test_returns_false_when_key_present(self, cache: InMemoryCache) -> None:
        await cache.set_if_not_exists("k", "first", ttl=60)
        assert await cache.set_if_not_exists("k", "second", ttl=60) is False
        assert await cache.get("k") == "first"

    async def test_expired_key_allows_reclaim(self, cache: InMemoryCache) -> None:
        await cache.set_if_not_exists("k", "first", ttl=1)
        await asyncio.sleep(1.05)
        assert await cache.set_if_not_exists("k", "second", ttl=60) is True
        assert await cache.get("k") == "second"

    async def test_concurrent_callers_see_exactly_one_winner(self, cache: InMemoryCache) -> None:
        """Replay protection depends on this primitive being atomic."""
        results = await asyncio.gather(
            *(cache.set_if_not_exists("k", str(i), ttl=60) for i in range(50))
        )
        assert sum(results) == 1


class TestMget:
    async def test_empty_keys_returns_empty_list(self, cache: InMemoryCache) -> None:
        assert await cache.mget([]) == []

    async def test_returns_values_in_order(self, cache: InMemoryCache) -> None:
        await cache.set("a", "1")
        await cache.set("b", "2")
        await cache.set("c", "3")
        assert await cache.mget(["a", "b", "c"]) == ["1", "2", "3"]

    async def test_missing_keys_are_none(self, cache: InMemoryCache) -> None:
        await cache.set("b", "2")
        assert await cache.mget(["a", "b", "c"]) == [None, "2", None]

    async def test_expired_keys_are_none(self, cache: InMemoryCache) -> None:
        await cache.set("persistent", "yes")
        await cache.setex("ephemeral", ttl=1, value="bye")
        await asyncio.sleep(1.05)
        assert await cache.mget(["persistent", "ephemeral"]) == ["yes", None]


class TestClear:
    async def test_clear_removes_all_entries(self, cache: InMemoryCache) -> None:
        await cache.set("a", "1")
        await cache.setex("b", ttl=60, value="2")
        await cache.clear()
        assert await cache.get("a") is None
        assert await cache.get("b") is None


class TestGetDel:
    async def test_returns_and_removes_value(self, cache: InMemoryCache) -> None:
        await cache.set("k", "v")
        assert await cache.getdel("k") == "v"
        assert await cache.get("k") is None

    async def test_missing_key_returns_none(self, cache: InMemoryCache) -> None:
        assert await cache.getdel("nope") is None

    async def test_expired_key_returns_none(self, cache: InMemoryCache) -> None:
        await cache.setex("k", ttl=1, value="v")
        await asyncio.sleep(1.05)
        assert await cache.getdel("k") is None

    async def test_concurrent_getdel_one_winner(self, cache: InMemoryCache) -> None:
        """Two consumers racing for the same one-time token must not both win."""
        await cache.set("once", "v")
        results = await asyncio.gather(*(cache.getdel("once") for _ in range(20)))
        assert results.count("v") == 1


class TestSetOperations:
    async def test_sadd_adds_members(self, cache: InMemoryCache) -> None:
        added = await cache.sadd("s", "a", "b", "c")
        assert added == 3
        assert await cache.smembers("s") == {"a", "b", "c"}

    async def test_sadd_deduplicates(self, cache: InMemoryCache) -> None:
        await cache.sadd("s", "a", "b")
        added = await cache.sadd("s", "b", "c")
        assert added == 1
        assert await cache.smembers("s") == {"a", "b", "c"}

    async def test_smembers_missing_set_is_empty(self, cache: InMemoryCache) -> None:
        assert await cache.smembers("nope") == set()

    async def test_srem_removes_members(self, cache: InMemoryCache) -> None:
        await cache.sadd("s", "a", "b", "c")
        removed = await cache.srem("s", "a", "missing")
        assert removed == 1
        assert await cache.smembers("s") == {"b", "c"}

    async def test_srem_on_empty_set_is_noop(self, cache: InMemoryCache) -> None:
        assert await cache.srem("nope", "a") == 0


class TestExpire:
    async def test_sets_ttl_on_existing_value(self, cache: InMemoryCache) -> None:
        await cache.set("k", "v")
        assert await cache.expire("k", 1) is True
        await asyncio.sleep(1.05)
        assert await cache.get("k") is None

    async def test_sets_ttl_on_set(self, cache: InMemoryCache) -> None:
        await cache.sadd("s", "a")
        assert await cache.expire("s", 1) is True
        await asyncio.sleep(1.05)
        assert await cache.smembers("s") == set()

    async def test_returns_false_for_missing_key(self, cache: InMemoryCache) -> None:
        assert await cache.expire("nope", 60) is False


class TestSmembersAndDelete:
    async def test_returns_snapshot_and_clears_set(self, cache: InMemoryCache) -> None:
        await cache.sadd("s", "a", "b", "c")
        snapshot = await cache.smembers_and_delete("s")
        assert snapshot == {"a", "b", "c"}
        assert await cache.smembers("s") == set()

    async def test_missing_set_returns_empty(self, cache: InMemoryCache) -> None:
        assert await cache.smembers_and_delete("nope") == set()

    async def test_snapshot_isolated_from_later_adds(self, cache: InMemoryCache) -> None:
        """The returned snapshot must not reflect concurrent additions."""
        await cache.sadd("s", "a", "b")
        snapshot = await cache.smembers_and_delete("s")
        # New SADD against the same key creates a fresh set; snapshot must
        # NOT mutate to reflect the new members.
        await cache.sadd("s", "c")
        assert snapshot == {"a", "b"}
        assert await cache.smembers("s") == {"c"}

    async def test_concurrent_calls_only_one_sees_members(self, cache: InMemoryCache) -> None:
        """Under concurrency, exactly one caller receives the members."""
        await cache.sadd("s", "a", "b", "c")

        async def drain() -> set[str]:
            return await cache.smembers_and_delete("s")

        results = await asyncio.gather(*(drain() for _ in range(10)))
        non_empty = [r for r in results if r]
        assert len(non_empty) == 1
        assert non_empty[0] == {"a", "b", "c"}
