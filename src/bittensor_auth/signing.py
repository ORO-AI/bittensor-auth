"""Pluggable signing-message construction and verification.

Presets: :func:`colon_separated` (default), :func:`dot_separated`.
Supply a custom ``MessageBuilder`` for other formats.
"""

from __future__ import annotations

import time
from collections.abc import Callable

from .core import verify_sr25519
from .errors import AuthenticationError, AuthErrorCode

MessageBuilder = Callable[[str, str | int, str], str]


def colon_separated(hotkey: str, timestamp: str | int, nonce: str) -> str:
    """``{hotkey}:{timestamp}:{nonce}`` — the most common format.

    Used by ORO, and similar to Chutes' ``{hotkey}:{nonce}:{payload_hash}``.
    """
    return f"{hotkey}:{timestamp}:{nonce}"


def dot_separated(hotkey: str, timestamp: str | int, nonce: str) -> str:
    """``{hotkey}.{timestamp}.{nonce}`` — dot-delimited variant.

    Closer to the Bittensor native ``nonce.sender.receiver.uuid.hash`` style,
    though native Synapse messages include additional fields.
    """
    return f"{hotkey}.{timestamp}.{nonce}"


construct_signing_message = colon_separated  # backward-compat alias


def validate_timestamp(timestamp_str: str, skew_seconds: int) -> int:
    """Parse a Unix-epoch timestamp and reject it if the clock skew exceeds ``skew_seconds``."""
    try:
        timestamp = int(timestamp_str)
    except (ValueError, TypeError) as e:
        raise AuthenticationError(AuthErrorCode.INVALID_TIMESTAMP) from e

    if abs(int(time.time()) - timestamp) > skew_seconds:
        raise AuthenticationError(AuthErrorCode.TIMESTAMP_SKEW)
    return timestamp


def verify_signature(
    hotkey: str,
    timestamp: str | int,
    nonce: str,
    signature_hex: str,
    *,
    message_builder: MessageBuilder | None = None,
) -> bool:
    """Verify a signature over the message built by ``message_builder`` (default: colon-separated).

    Returns ``True`` if valid, ``False`` otherwise. Does not raise.
    """
    builder = message_builder or colon_separated
    message = builder(hotkey, timestamp, nonce)
    return verify_sr25519(hotkey, message, signature_hex)
