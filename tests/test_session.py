"""Unit tests for session and challenge management."""

from __future__ import annotations

import asyncio

import pytest

from bittensor_auth.cache import InMemoryCache
from bittensor_auth.session import (
    ChallengeData,
    SessionData,
    SessionStore,
    extract_nonce_from_challenge,
    generate_challenge,
    generate_session_token,
)
from tests.conftest import ALICE_HOTKEY, BOB_HOTKEY


class TestGenerateSessionToken:
    def test_has_ses_prefix(self) -> None:
        assert generate_session_token().startswith("ses_")

    def test_hex_body_length(self) -> None:
        token = generate_session_token()
        # 32 random bytes -> 64 hex characters, plus "ses_"
        assert len(token) == len("ses_") + 64

    def test_tokens_are_unique(self) -> None:
        tokens = {generate_session_token() for _ in range(100)}
        assert len(tokens) == 100


class TestGenerateChallenge:
    def test_default_prefix(self) -> None:
        assert generate_challenge().startswith("bittensor-auth:")

    def test_custom_prefix(self) -> None:
        assert generate_challenge(prefix="myapp").startswith("myapp:")

    def test_three_parts(self) -> None:
        assert len(generate_challenge().split(":")) == 3

    def test_timestamp_is_integer(self) -> None:
        int(generate_challenge().split(":")[1])

    def test_challenges_are_unique(self) -> None:
        challenges = {generate_challenge() for _ in range(100)}
        assert len(challenges) == 100


class TestExtractNonce:
    @pytest.mark.parametrize(
        ("challenge", "expected"),
        [
            ("bittensor-auth:123456:abc123", "abc123"),
            ("oro-auth:999:zz", "zz"),
        ],
        ids=["default-prefix", "custom-prefix"],
    )
    def test_extracts_trailing_segment(self, challenge: str, expected: str) -> None:
        assert extract_nonce_from_challenge(challenge) == expected

    @pytest.mark.parametrize(
        "malformed",
        ["only:two", "nocolons"],
        ids=["two-parts", "no-separators"],
    )
    def test_rejects_malformed_input(self, malformed: str) -> None:
        with pytest.raises(ValueError):
            extract_nonce_from_challenge(malformed)


class TestSessionStoreSessions:
    async def test_create_returns_unique_tokens(self, cache: InMemoryCache) -> None:
        store = SessionStore(cache)
        tokens = {await store.create_session(ALICE_HOTKEY, "user") for _ in range(20)}
        assert len(tokens) == 20

    async def test_round_trip(self, cache: InMemoryCache) -> None:
        store = SessionStore(cache)
        token = await store.create_session(ALICE_HOTKEY, "validator")

        session = await store.get_session(token)
        assert session is not None
        assert isinstance(session, SessionData)
        assert session.hotkey == ALICE_HOTKEY
        assert session.role == "validator"
        assert isinstance(session.created_at, int)

    async def test_get_missing_returns_none(self, cache: InMemoryCache) -> None:
        store = SessionStore(cache)
        assert await store.get_session("ses_nonexistent") is None

    async def test_delete_invalidates(self, cache: InMemoryCache) -> None:
        store = SessionStore(cache)
        token = await store.create_session(ALICE_HOTKEY, "user")
        await store.delete_session(token)
        assert await store.get_session(token) is None

    async def test_delete_is_idempotent(self, cache: InMemoryCache) -> None:
        store = SessionStore(cache)
        await store.delete_session("ses_missing")

    async def test_session_expires_after_ttl(self, cache: InMemoryCache) -> None:
        store = SessionStore(cache, session_ttl_seconds=1)
        token = await store.create_session(ALICE_HOTKEY, "user")
        await asyncio.sleep(1.05)
        assert await store.get_session(token) is None


class TestSessionStoreChallenges:
    async def test_store_and_consume(self, cache: InMemoryCache) -> None:
        store = SessionStore(cache)
        challenge = "bittensor-auth:1700000000:abc123"

        await store.store_challenge(ALICE_HOTKEY, challenge)

        consumed = await store.get_challenge("abc123")
        assert consumed is not None
        assert isinstance(consumed, ChallengeData)
        assert consumed.hotkey == ALICE_HOTKEY
        assert consumed.challenge == challenge

    async def test_get_challenge_consumes_exactly_once(self, cache: InMemoryCache) -> None:
        store = SessionStore(cache)
        await store.store_challenge(ALICE_HOTKEY, "bittensor-auth:1700000000:once-only")

        first = await store.get_challenge("once-only")
        second = await store.get_challenge("once-only")

        assert first is not None
        assert second is None

    async def test_get_missing_challenge_returns_none(self, cache: InMemoryCache) -> None:
        store = SessionStore(cache)
        assert await store.get_challenge("never-stored") is None

    async def test_challenge_expires_after_ttl(self, cache: InMemoryCache) -> None:
        store = SessionStore(cache, challenge_ttl_seconds=1)
        await store.store_challenge(ALICE_HOTKEY, "bittensor-auth:1700000000:ephemeral")
        await asyncio.sleep(1.05)
        assert await store.get_challenge("ephemeral") is None

    async def test_generated_challenge_round_trip(self, cache: InMemoryCache) -> None:
        """Integration: generate -> store -> consume."""
        store = SessionStore(cache)
        challenge = generate_challenge()
        await store.store_challenge(ALICE_HOTKEY, challenge)

        nonce = extract_nonce_from_challenge(challenge)
        consumed = await store.get_challenge(nonce)

        assert consumed is not None
        assert consumed.challenge == challenge


class TestSessionStoreConstruction:
    @pytest.mark.parametrize(
        "kwargs",
        [{"session_ttl_seconds": 0}, {"challenge_ttl_seconds": 0}],
        ids=["non-positive-session-ttl", "non-positive-challenge-ttl"],
    )
    def test_rejects_non_positive_ttl(self, cache: InMemoryCache, kwargs: dict) -> None:
        with pytest.raises(ValueError):
            SessionStore(cache, **kwargs)


class TestAtomicChallengeConsumption:
    async def test_concurrent_consumers_exactly_one_wins(self, cache: InMemoryCache) -> None:
        """Only one of N racing consumers may receive the challenge."""
        store = SessionStore(cache)
        await store.store_challenge(ALICE_HOTKEY, "bittensor-auth:1700000000:race")

        results = await asyncio.gather(*(store.get_challenge("race") for _ in range(25)))

        winners = [r for r in results if r is not None]
        assert len(winners) == 1


class TestRevokeAllSessions:
    async def test_revokes_every_active_token(self, cache: InMemoryCache) -> None:
        store = SessionStore(cache)
        tokens = [await store.create_session(ALICE_HOTKEY, "user") for _ in range(3)]

        revoked = await store.revoke_all_sessions(ALICE_HOTKEY)

        assert revoked == 3
        for token in tokens:
            assert await store.get_session(token) is None

    async def test_isolated_per_hotkey(self, cache: InMemoryCache) -> None:
        """Revoking one hotkey's sessions must leave other hotkeys untouched."""
        store = SessionStore(cache)

        my_token = await store.create_session(ALICE_HOTKEY, "user")
        their_token = await store.create_session(BOB_HOTKEY, "user")

        await store.revoke_all_sessions(ALICE_HOTKEY)

        assert await store.get_session(my_token) is None
        assert await store.get_session(their_token) is not None

    async def test_revoke_with_no_sessions_is_noop(self, cache: InMemoryCache) -> None:
        store = SessionStore(cache)
        assert await store.revoke_all_sessions(ALICE_HOTKEY) == 0

    async def test_delete_session_removes_from_index(self, cache: InMemoryCache) -> None:
        """After deleting a single token, revoke_all_sessions should not find it."""
        store = SessionStore(cache)
        keep = await store.create_session(ALICE_HOTKEY, "user")
        drop = await store.create_session(ALICE_HOTKEY, "user")

        await store.delete_session(drop)
        revoked = await store.revoke_all_sessions(ALICE_HOTKEY)

        assert revoked == 1
        assert await store.get_session(keep) is None

    async def test_revoked_after_barrier_rejects_orphan_sessions(
        self, cache: InMemoryCache
    ) -> None:
        """Simulate the race: a session record slips through the index
        sweep. The ``revoked_after`` barrier in ``get_session`` must
        still reject it because the session was created before revoke.
        """
        store = SessionStore(cache)
        token = await store.create_session(ALICE_HOTKEY, "user")
        # Simulate the race by clearing the index (as if SMEMBERS read
        # happened before this token's sadd, then sadd ran after the
        # index was deleted — token survives in session:<key> but
        # revoke wouldn't see it via the index). We simulate by
        # removing the token from the index manually.
        await cache.delete(SessionStore._index_key(ALICE_HOTKEY))

        # Token is still fetchable because its session key is intact.
        assert await store.get_session(token) is not None

        # Now revoke. Zero tokens found via the index, but the
        # barrier should reject the in-flight token.
        await store.revoke_all_sessions(ALICE_HOTKEY)
        assert await store.get_session(token) is None

    async def test_revoked_after_does_not_affect_new_sessions(
        self, cache: InMemoryCache
    ) -> None:
        """Sessions created after revoke_all_sessions must remain valid."""
        import asyncio

        store = SessionStore(cache)
        await store.create_session(ALICE_HOTKEY, "user")
        await store.revoke_all_sessions(ALICE_HOTKEY)

        # Small sleep so the post-revoke session's created_at is
        # strictly greater than the revoked_after stamp (both are
        # int seconds).
        await asyncio.sleep(1.1)
        fresh = await store.create_session(ALICE_HOTKEY, "user")
        assert await store.get_session(fresh) is not None
