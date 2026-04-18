"""Nonce replay protection.

Rejects duplicate ``(hotkey, nonce)`` pairs within a TTL window using
atomic ``set_if_not_exists`` on the cache backend. The TTL should match
the server's timestamp skew so expired nonces are garbage-collected promptly.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from .errors import AuthenticationError, AuthErrorCode

if TYPE_CHECKING:
    from .cache import CacheBackend


class NonceTracker:
    """Atomic nonce replay protection backed by a :class:`CacheBackend`."""

    _KEY_PREFIX = "nonce"

    def __init__(
        self,
        cache: CacheBackend,
        *,
        max_nonce_length: int = 256,
        ttl_seconds: int = 60,
    ) -> None:
        if max_nonce_length <= 0:
            raise ValueError("max_nonce_length must be positive")
        if ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be positive")
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
