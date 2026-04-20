"""Bittensor authentication for Python web frameworks.

Client-side symbols are lazily loaded to avoid requiring ``httpx`` at import
time. Install ``bittensor-auth[client]`` to use them.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from .cache import CacheBackend, InMemoryCache, RedisCache
from .config import BittensorAuthConfig
from .core import parse_signature, validate_hotkey_format, verify_sr25519
from .errors import AuthenticationError, AuthErrorCode
from .metagraph import MetagraphCache, MetagraphLike
from .nonce import NonceTracker
from .session import (
    ChallengeData,
    SessionData,
    SessionStore,
    extract_nonce_from_challenge,
    generate_challenge,
    generate_session_token,
)
from .signing import (
    MessageBuilder,
    colon_separated,
    construct_signing_message,
    dot_separated,
    validate_timestamp,
    verify_signature,
)

if TYPE_CHECKING:  # pragma: no cover - typing only
    from .client import (
        AsyncSigningTransport,
        BittensorAuthClient,
        IsPublicEndpoint,
        Signer,
        SigningTransport,
        default_is_public_endpoint,
        generate_auth_headers,
    )

_CLIENT_SYMBOLS = {
    "AsyncSigningTransport",
    "BittensorAuthClient",
    "IsPublicEndpoint",
    "Signer",
    "SigningTransport",
    "default_is_public_endpoint",
    "generate_auth_headers",
}


def __getattr__(name: str) -> Any:
    if name in _CLIENT_SYMBOLS:
        from . import client as _client

        return getattr(_client, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = [
    "AsyncSigningTransport",
    "AuthErrorCode",
    "AuthenticationError",
    "BittensorAuthClient",
    "BittensorAuthConfig",
    "CacheBackend",
    "ChallengeData",
    "InMemoryCache",
    "IsPublicEndpoint",
    "MessageBuilder",
    "MetagraphCache",
    "MetagraphLike",
    "NonceTracker",
    "RedisCache",
    "SessionData",
    "SessionStore",
    "Signer",
    "SigningTransport",
    "colon_separated",
    "construct_signing_message",
    "default_is_public_endpoint",
    "dot_separated",
    "extract_nonce_from_challenge",
    "generate_auth_headers",
    "generate_challenge",
    "generate_session_token",
    "parse_signature",
    "validate_hotkey_format",
    "validate_timestamp",
    "verify_signature",
    "verify_sr25519",
]
