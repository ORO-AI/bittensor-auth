"""Nonce replay protection.

Rejects duplicate ``(hotkey, nonce)`` pairs within a TTL window using
atomic ``set_if_not_exists`` on the cache backend. The TTL must be at
least as long as the server's timestamp skew window, otherwise replay
protection has a gap: a nonce entry can expire while a matching
timestamp is still accepted.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from .errors import AuthenticationError, AuthErrorCode

if TYPE_CHECKING:
    from .cache import CacheBackend

logger = logging.getLogger(__name__)


class NonceTracker:
    """Atomic nonce replay protection backed by a :class:`CacheBackend`.

    Pass ``skew_seconds`` to enforce ``ttl_seconds >= skew_seconds`` at
    construction. Without an explicit skew, a very short TTL logs a
    warning since it almost certainly indicates a misconfigured replay
    window.
    """

    _KEY_PREFIX = "nonce"

    def __init__(
        self,
        cache: CacheBackend,
        *,
        max_nonce_length: int = 256,
        ttl_seconds: int = 60,
        skew_seconds: int | None = None,
    ) -> None:
        if max_nonce_length <= 0:
            raise ValueError("max_nonce_length must be positive")
        if ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be positive")
        if skew_seconds is not None:
            if skew_seconds <= 0:
                raise ValueError("skew_seconds must be positive")
            if ttl_seconds < skew_seconds:
                raise ValueError(
                    f"ttl_seconds ({ttl_seconds}) must be >= skew_seconds "
                    f"({skew_seconds}) — otherwise a replay window opens "
                    "when nonces expire while matching timestamps are still "
                    "accepted"
                )
        elif ttl_seconds < 60:
            logger.warning(
                "NonceTracker ttl_seconds=%d is short; replay protection is "
                "only as strong as ttl_seconds >= timestamp skew window. "
                "Pass skew_seconds= to enforce this invariant at construction.",
                ttl_seconds,
            )
        self._cache = cache
        self._max_nonce_length = max_nonce_length
        self._ttl_seconds = ttl_seconds

    @staticmethod
    def _key(hotkey: str, nonce: str) -> str:
        return f"{NonceTracker._KEY_PREFIX}:{hotkey}:{nonce}"

    async def register(self, hotkey: str, nonce: str) -> None:
        """Record a ``(hotkey, nonce)`` pair. Raises on replay or oversized nonce."""
        if len(nonce) > self._max_nonce_length:
            raise AuthenticationError(AuthErrorCode.NONCE_TOO_LONG)

        is_new = await self._cache.set_if_not_exists(
            self._key(hotkey, nonce), "1", self._ttl_seconds
        )
        if not is_new:
            raise AuthenticationError(AuthErrorCode.NONCE_REUSED)
