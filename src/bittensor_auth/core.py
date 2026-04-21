"""Core SR25519 signature verification primitives.

Framework-agnostic functions that operate on plain strings/bytes. No FastAPI,
no Redis, no metagraph — just cryptography.
"""

from __future__ import annotations

import logging
import time

from bittensor_wallet import Keypair

from .errors import AuthenticationError, AuthErrorCode

logger = logging.getLogger(__name__)

_SLOW_CALL_WARN_MS = 50


def validate_hotkey_format(hotkey: str) -> None:
    """Raise ``INVALID_HOTKEY_FORMAT`` if ``hotkey`` is not a valid SS58 address."""
    t0 = time.monotonic()
    try:
        Keypair(ss58_address=hotkey)
    except Exception as e:
        raise AuthenticationError(AuthErrorCode.INVALID_HOTKEY_FORMAT) from e
    finally:
        elapsed_ms = (time.monotonic() - t0) * 1000
        if elapsed_ms > _SLOW_CALL_WARN_MS:
            logger.warning("validate_hotkey_format blocked event loop for %.1fms", elapsed_ms)


def parse_signature(signature_hex: str) -> bytes:
    """Decode hex signature to bytes, stripping optional ``0x`` prefix."""
    try:
        return bytes.fromhex(signature_hex.removeprefix("0x").removeprefix("0X"))
    except (ValueError, AttributeError) as e:
        raise AuthenticationError(AuthErrorCode.INVALID_SIGNATURE_FORMAT) from e


def verify_sr25519(hotkey: str, message: str, signature_hex: str) -> bool:
    """Low-level SR25519 verify. Returns ``False`` on any failure; never raises."""
    try:
        signature_bytes = parse_signature(signature_hex)
    except AuthenticationError:
        return False

    t0 = time.monotonic()
    try:
        return bool(Keypair(ss58_address=hotkey).verify(message.encode(), signature_bytes))
    except (ValueError, TypeError) as e:
        logger.warning("Malformed signature input for %s: %s: %s", hotkey, type(e).__name__, e)
        return False
    except Exception as e:
        logger.error(
            "Unexpected error during signature verification for %s: %s: %s",
            hotkey,
            type(e).__name__,
            e,
            exc_info=True,
        )
        return False
    finally:
        elapsed_ms = (time.monotonic() - t0) * 1000
        if elapsed_ms > _SLOW_CALL_WARN_MS:
            logger.warning("verify_sr25519 blocked event loop for %.1fms", elapsed_ms)
