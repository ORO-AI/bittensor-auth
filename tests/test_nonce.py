"""Unit tests for NonceTracker."""

from __future__ import annotations

import asyncio

import pytest

from bittensor_auth.cache import InMemoryCache
from bittensor_auth.errors import AuthenticationError, AuthErrorCode
from bittensor_auth.nonce import NonceTracker
from tests.conftest import ALICE_HOTKEY


class TestNonceRegistration:
    async def test_fresh_nonce_registers_successfully(self, cache: InMemoryCache) -> None:
        tracker = NonceTracker(cache)
        await tracker.register(ALICE_HOTKEY, "nonce-1")

    async def test_replay_raises_nonce_reused(self, cache: InMemoryCache) -> None:
        tracker = NonceTracker(cache)
        await tracker.register(ALICE_HOTKEY, "nonce-1")

        with pytest.raises(AuthenticationError) as exc_info:
            await tracker.register(ALICE_HOTKEY, "nonce-1")

        assert exc_info.value.error is AuthErrorCode.NONCE_REUSED

    async def test_different_nonces_same_hotkey_both_succeed(self, cache: InMemoryCache) -> None:
        tracker = NonceTracker(cache)
        await tracker.register(ALICE_HOTKEY, "nonce-a")
        await tracker.register(ALICE_HOTKEY, "nonce-b")

    async def test_same_nonce_different_hotkeys_both_succeed(self, cache: InMemoryCache) -> None:
        tracker = NonceTracker(cache)
        from tests.conftest import BOB_HOTKEY

        await tracker.register(ALICE_HOTKEY, "shared-nonce")
        await tracker.register(BOB_HOTKEY, "shared-nonce")

    async def test_nonce_expires_after_ttl(self, cache: InMemoryCache) -> None:
        tracker = NonceTracker(cache, ttl_seconds=1)
        await tracker.register(ALICE_HOTKEY, "nonce-1")

        await asyncio.sleep(1.05)

        await tracker.register(ALICE_HOTKEY, "nonce-1")


class TestNonceLength:
    async def test_exceeding_max_length_raises(self, cache: InMemoryCache) -> None:
        tracker = NonceTracker(cache, max_nonce_length=8)

        with pytest.raises(AuthenticationError) as exc_info:
            await tracker.register(ALICE_HOTKEY, "a" * 9)

        assert exc_info.value.error is AuthErrorCode.NONCE_TOO_LONG

    async def test_exact_max_length_accepted(self, cache: InMemoryCache) -> None:
        tracker = NonceTracker(cache, max_nonce_length=8)
        await tracker.register(ALICE_HOTKEY, "a" * 8)

    async def test_oversized_nonce_does_not_hit_cache(self, cache: InMemoryCache) -> None:
        """Length check must short-circuit before any backend write."""
        tracker = NonceTracker(cache, max_nonce_length=8)

        with pytest.raises(AuthenticationError):
            await tracker.register(ALICE_HOTKEY, "a" * 100)

        assert await cache.get(f"nonce:{ALICE_HOTKEY}:{'a' * 100}") is None


class TestNonceConcurrency:
    async def test_concurrent_replays_only_one_succeeds(self, cache: InMemoryCache) -> None:
        """Race 50 coroutines presenting the same nonce; exactly one must win."""
        tracker = NonceTracker(cache)

        async def attempt() -> bool:
            try:
                await tracker.register(ALICE_HOTKEY, "racey-nonce")
                return True
            except AuthenticationError:
                return False

        results = await asyncio.gather(*(attempt() for _ in range(50)))
        assert sum(results) == 1


class TestNonceKeyFormat:
    async def test_key_format_matches_reference_implementation(self, cache: InMemoryCache) -> None:
        """The canonical Redis key pattern is ``nonce:{hotkey}:{nonce}``."""
        tracker = NonceTracker(cache)
        await tracker.register(ALICE_HOTKEY, "probe")

        assert await cache.get(f"nonce:{ALICE_HOTKEY}:probe") == "1"


class TestNonceConstructorValidation:
    @pytest.mark.parametrize(
        ("kwargs", "error_type"),
        [
            ({"max_nonce_length": 0}, ValueError),
            ({"ttl_seconds": 0}, ValueError),
            # Negative or zero explicit skew is a misconfiguration.
            ({"ttl_seconds": 60, "skew_seconds": 0}, ValueError),
            ({"ttl_seconds": 60, "skew_seconds": -5}, ValueError),
            # TTL < skew opens a replay window; constructor must refuse.
            ({"ttl_seconds": 30, "skew_seconds": 60}, ValueError),
        ],
        ids=[
            "non-positive-max-length",
            "non-positive-ttl",
            "zero-skew",
            "negative-skew",
            "ttl-below-skew",
        ],
    )
    def test_rejects_invalid_constructor_args(
        self, cache: InMemoryCache, kwargs: dict, error_type: type
    ) -> None:
        with pytest.raises(error_type):
            NonceTracker(cache, **kwargs)

    def test_ttl_equal_to_skew_is_accepted(self, cache: InMemoryCache) -> None:
        # Equal TTL = skew is the tightest safe configuration.
        NonceTracker(cache, ttl_seconds=60, skew_seconds=60)

    def test_short_ttl_without_explicit_skew_warns(
        self, cache: InMemoryCache, caplog: pytest.LogCaptureFixture
    ) -> None:
        import logging

        with caplog.at_level(logging.WARNING, logger="bittensor_auth.nonce"):
            NonceTracker(cache, ttl_seconds=10)
        assert any("ttl_seconds" in rec.message for rec in caplog.records)
