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

    async def create_session(self, hotkey: str, role: str) -> str:
        """Issue a session token and add it to the per-hotkey index."""
        token = generate_session_token()
        data = SessionData(hotkey=hotkey, role=role, created_at=int(time.time()))
        await self._cache.setex(
            self._session_key(token), self._session_ttl, json.dumps(asdict(data))
        )
        index_key = self._index_key(hotkey)
        await self._cache.sadd(index_key, token)
        await self._cache.expire(index_key, self._session_ttl)
        return token

    async def get_session(self, token: str) -> SessionData | None:
        raw = await self._cache.get(self._session_key(token))
        if raw is None:
            return None
        try:
            parsed = json.loads(raw)
            return SessionData(
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

        Uses the cache's atomic ``smembers_and_delete`` so the member
        read and index deletion cannot interleave with a concurrent
        ``create_session``. A token added AFTER ``smembers_and_delete``
        returns will survive (it gets its own fresh index key) — for
        ban-enforcement, pair this with a ban-aware dependency that
        re-checks the ban table on each authenticated request.
        """
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
