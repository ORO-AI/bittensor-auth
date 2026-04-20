"""FastAPI integration for bittensor-auth."""

from __future__ import annotations

from ._utils import BanChecker, RoleResolver
from .dependencies import (
    HEADER_HOTKEY,
    HEADER_NONCE,
    HEADER_SIGNATURE,
    HEADER_TIMESTAMP,
    AuthenticatedUser,
    BittensorAuth,
)
from .errors import auth_error_to_http
from .router import (
    ChallengeRequest,
    ChallengeResponse,
    LogoutResponse,
    SessionRequest,
    SessionResponse,
    build_auth_router,
)

__all__ = [
    "AuthenticatedUser",
    "BanChecker",
    "BittensorAuth",
    "ChallengeRequest",
    "ChallengeResponse",
    "HEADER_HOTKEY",
    "HEADER_NONCE",
    "HEADER_SIGNATURE",
    "HEADER_TIMESTAMP",
    "LogoutResponse",
    "RoleResolver",
    "SessionRequest",
    "SessionResponse",
    "auth_error_to_http",
    "build_auth_router",
]
