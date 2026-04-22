"""Nonce replay protection.

Rejects duplicate ``(hotkey, nonce)`` pairs within a TTL window using
atomic ``set_if_not_exists`` on the cache backend. The TTL must be at
least **twice** the server's timestamp skew window: the skew is
two-sided (``abs(now - timestamp) <= skew``), so a signature dated
``now + skew`` remains within skew for another ``skew`` seconds after
registration. A TTL of only ``skew`` leaves a ``skew``-wide replay
window once the nonce evicts — ``NonceTracker.__init__`` enforces
``ttl_seconds >= 2 * skew_seconds`` to close that gap.
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

    Pass ``skew_seconds`` to enforce ``ttl_seconds >= 2 * skew_seconds``
    at construction. The factor of two is required because timestamp
    skew is two-sided: a signature dated ``now + skew`` stays valid for
    another ``skew`` seconds after it first arrives, so a TTL of only
    ``skew`` leaves a ``skew``-wide replay gap once the nonce evicts.
    Without an explicit skew, a very short TTL logs a warning since it
    almost certainly indicates a misconfigured replay window.
    """

    _KEY_PREFIX = "nonce"

    def __init__(
        self,
        cache: CacheBackend,
        *,
        max_nonce_length: int = 256,
        ttl_seconds: int = 120,
        skew_seconds: int | None = None,
    ) -> None:
        if max_nonce_length <= 0:
            raise ValueError("max_nonce_length must be positive")
        if ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be positive")
        if skew_seconds is not None:
            if skew_seconds <= 0:
                raise ValueError("skew_seconds must be positive")
            if ttl_seconds < 2 * skew_seconds:
                raise ValueError(
                    f"ttl_seconds ({ttl_seconds}) must be >= 2 * skew_seconds "
                    f"({2 * skew_seconds}) — the skew window is two-sided, "
                    "so a future-dated signature remains in skew for another "
                    "skew_seconds after the nonce is first seen. A tighter "
                    "TTL leaves a replay gap when nonces evict while matching "
                    "timestamps are still accepted."
                )
        elif ttl_seconds < 120:
            logger.warning(
                "NonceTracker ttl_seconds=%d is short; replay protection is "
                "only as strong as ttl_seconds >= 2 * timestamp skew window. "
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
        """Record a ``(hotkey, nonce)`` pair. Raises on replay or invalid nonce."""
        if len(nonce) > self._max_nonce_length:
            raise AuthenticationError(AuthErrorCode.NONCE_TOO_LONG)
        # ``:`` is the delimiter in the composite cache key. Allowing it
        # in a nonce lets pathological values alias different
        # ``(hotkey, nonce)`` pairs to the same Redis key.
        if ":" in nonce:
            raise AuthenticationError(AuthErrorCode.NONCE_INVALID_CHARS)

        is_new = await self._cache.set_if_not_exists(
            self._key(hotkey, nonce), "1", self._ttl_seconds
        )
        if not is_new:
            raise AuthenticationError(AuthErrorCode.NONCE_REUSED)
