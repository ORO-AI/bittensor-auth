"""Challenge/response and session management backed by a :class:`CacheBackend`.

Challenges are consumed exactly once (atomic getdel). Sessions are bearer
tokens with a per-hotkey index for bulk revocation on ban.
"""

from __future__ import annotations

import json
import logging
import secrets
import time
from dataclasses import asdict, dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .cache import CacheBackend

logger = logging.getLogger(__name__)

DEFAULT_CHALLENGE_PREFIX = "bittensor-auth"
_SESSION_TOKEN_PREFIX = "ses_"
_SESSION_TOKEN_HEX_BYTES = 32
_CHALLENGE_NONCE_HEX_BYTES = 16


@dataclass(frozen=True)
class SessionData:
    hotkey: str
    role: str
    created_at: int


@dataclass(frozen=True)
class ChallengeData:
    hotkey: str
    challenge: str
    created_at: int


def generate_session_token() -> str:
    """Return a ``ses_``-prefixed cryptographically random token."""
    return f"{_SESSION_TOKEN_PREFIX}{secrets.token_hex(_SESSION_TOKEN_HEX_BYTES)}"


def generate_challenge(prefix: str = DEFAULT_CHALLENGE_PREFIX) -> str:
    """Return a challenge string: ``{prefix}:{timestamp}:{nonce}``."""
    timestamp = int(time.time())
    nonce = secrets.token_hex(_CHALLENGE_NONCE_HEX_BYTES)
    return f"{prefix}:{timestamp}:{nonce}"


def extract_nonce_from_challenge(challenge: str) -> str:
    """Return the nonce segment from a ``{prefix}:{timestamp}:{nonce}`` challenge."""
    parts = challenge.split(":")
    if len(parts) < 3:
        raise ValueError(f"Invalid challenge format (length={len(challenge)})")
    return parts[-1]


class SessionStore:
    """Cache-backed store for challenges and session tokens."""

    def __init__(
        self,
        cache: CacheBackend,
        *,
        session_ttl_seconds: int = 7200,
        challenge_ttl_seconds: int = 60,
    ) -> None:
        if session_ttl_seconds <= 0:
            raise ValueError("session_ttl_seconds must be positive")
        if challenge_ttl_seconds <= 0:
            raise ValueError("challenge_ttl_seconds must be positive")
        self._cache = cache
        self._session_ttl = session_ttl_seconds
        self._challenge_ttl = challenge_ttl_seconds

    @property
    def session_ttl_seconds(self) -> int:
        return self._session_ttl

    @property
    def challenge_ttl_seconds(self) -> int:
        return self._challenge_ttl

    @staticmethod
    def _session_key(token: str) -> str:
        return f"session:{token}"

    @staticmethod
    def _challenge_key(nonce: str) -> str:
        return f"challenge:{nonce}"

    @staticmethod
    def _index_key(hotkey: str) -> str:
        return f"sessions_by_hotkey:{hotkey}"

    @staticmethod
    def _revoked_after_key(hotkey: str) -> str:
        return f"session_revoked_after:{hotkey}"

    async def create_session(self, hotkey: str, role: str) -> str:
        """Issue a session token and add it to the per-hotkey index."""
        token = generate_session_token()
        data = SessionData(hotkey=hotkey, role=role, created_at=int(time.time()))
        await self._cache.setex(
            self._session_key(token), self._session_ttl, json.dumps(asdict(data))
        )
        # SADD + EXPIRE in a single atomic step so a mid-call crash can't
        # leave the index without a TTL.
        await self._cache.sadd_with_ttl(self._index_key(hotkey), self._session_ttl, token)
        return token

    async def get_session(self, token: str) -> SessionData | None:
        raw = await self._cache.get(self._session_key(token))
        if raw is None:
            return None
        try:
            parsed = json.loads(raw)
            session = SessionData(
                hotkey=parsed["hotkey"],
                role=parsed["role"],
                created_at=parsed["created_at"],
            )
        except (json.JSONDecodeError, KeyError, TypeError):
            # Treat malformed session records as missing so the caller
            # returns a clean 401 instead of 500. Malformation indicates
            # cache corruption or a version mismatch.
            logger.warning(
                "Session %s... has malformed data; treating as invalid",
                token[:12],
            )
            return None

        # Revocation barrier: a session created at or before the most
        # recent ``revoke_all_sessions`` call is invalid even if it
        # survived the index sweep (e.g. token written to Redis after
        # SMEMBERS read but before operator expected revocation to
        # take effect). The comparison is inclusive (``<=``) because
        # both stamps are whole-second ``int(time.time())``, so strict
        # ``<`` would leak any session created in the same wall-clock
        # second as revocation.
        revoked_after = await self._get_revoked_after(session.hotkey)
        if revoked_after is not None and session.created_at <= revoked_after:
            return None
        return session

    async def _get_revoked_after(self, hotkey: str) -> int | None:
        raw = await self._cache.get(self._revoked_after_key(hotkey))
        if raw is None:
            return None
        try:
            return int(raw)
        except ValueError:
            logger.warning("Malformed revoked_after stamp for %s...", hotkey[:12])
            return None

    async def delete_session(self, token: str) -> None:
        """Invalidate ``token`` and prune from the hotkey index. Idempotent."""
        key = self._session_key(token)
        raw = await self._cache.get(key)
        if raw is not None:
            try:
                hotkey = json.loads(raw).get("hotkey")
                if hotkey:
                    await self._cache.srem(self._index_key(hotkey), token)
            except json.JSONDecodeError:
                logger.warning(
                    "Session %s... has malformed data; index cleanup skipped",
                    token[:12],
                )
        await self._cache.delete(key)

    async def revoke_all_sessions(self, hotkey: str) -> int:
        """Invalidate all sessions for ``hotkey``. Returns the count revoked.

        Closes the bulk-revocation race in two layers:

        1. A ``revoked_after`` epoch is stamped *before* the index sweep.
           ``get_session`` rejects any session whose ``created_at``
           predates this stamp, catching tokens that were written to
           Redis concurrently with (or slipped through) the index sweep.
        2. The cache's atomic ``smembers_and_delete`` reads and deletes
           the index in one step, so tokens sadd-ed before the sweep
           are caught and their session records are purged.

        Tokens created *after* the stamp are legitimate new sessions
        and survive — pair revocation with a ``ban_checker`` if you
        need those to be rejected as well.
        """
        # Stamp the barrier FIRST. ``created_at`` on every session is
        # captured before the session key hits Redis, so anything that
        # was "in flight" at the moment we called revoke has
        # ``created_at <= revoked_after`` and will fail the check in
        # ``get_session`` even if its index sadd races past the sweep.
        stamp = int(time.time())
        await self._cache.setex(self._revoked_after_key(hotkey), self._session_ttl, str(stamp))

        index_key = self._index_key(hotkey)
        tokens = await self._cache.smembers_and_delete(index_key)
        for token in tokens:
            await self._cache.delete(self._session_key(token))
        return len(tokens)

    async def store_challenge(self, hotkey: str, challenge: str) -> None:
        nonce = extract_nonce_from_challenge(challenge)
        data = ChallengeData(hotkey=hotkey, challenge=challenge, created_at=int(time.time()))
        await self._cache.setex(
            self._challenge_key(nonce), self._challenge_ttl, json.dumps(asdict(data))
        )

    async def get_challenge(self, nonce: str) -> ChallengeData | None:
        """Consume the challenge for ``nonce`` exactly once (atomic getdel)."""
        raw = await self._cache.getdel(self._challenge_key(nonce))
        if raw is None:
            return None
        parsed = json.loads(raw)
        return ChallengeData(
            hotkey=parsed["hotkey"],
            challenge=parsed["challenge"],
            created_at=parsed["created_at"],
        )
