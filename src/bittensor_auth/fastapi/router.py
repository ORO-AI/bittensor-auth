"""Mountable APIRouter for the challenge/response session flow.

Endpoints: ``POST /challenge``, ``POST /session``, ``POST /logout``.
"""

from __future__ import annotations

import logging
import time
from typing import TYPE_CHECKING, Any

from fastapi import APIRouter, Header, HTTPException, status
from pydantic import BaseModel, Field

from ..core import validate_hotkey_format, verify_sr25519
from ..errors import AuthenticationError
from ..session import (
    DEFAULT_CHALLENGE_PREFIX,
    extract_nonce_from_challenge,
    generate_challenge,
)
from ._utils import BanChecker, RoleResolver, maybe_await

if TYPE_CHECKING:  # pragma: no cover - typing only
    from ..session import SessionStore

logger = logging.getLogger(__name__)


class ChallengeRequest(BaseModel):
    hotkey: str = Field(..., description="SS58 address requesting a challenge.")


class ChallengeResponse(BaseModel):
    challenge: str = Field(..., description="Challenge string the client must sign.")
    expires_at: int = Field(..., description="Unix timestamp when this challenge expires.")


class SessionRequest(BaseModel):
    hotkey: str = Field(..., description="SS58 address claiming the session.")
    challenge: str = Field(..., description="Challenge string from /challenge.")
    signature: str = Field(
        ...,
        description="Hex-encoded SR25519 signature over the challenge (0x prefix accepted).",
    )


class SessionResponse(BaseModel):
    session_token: str = Field(..., description="Bearer token for subsequent requests.")
    expires_at: int = Field(..., description="Unix timestamp when the session expires.")
    role: str = Field(..., description="Role assigned by the resolver hook.")


class LogoutResponse(BaseModel):
    success: bool


def _require_bearer_token(authorization: str | None) -> str:
    if not authorization:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing Authorization header",
        )
    if not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid Authorization header format",
        )
    return authorization[len("Bearer ") :]


def build_auth_router(
    *,
    session_store: SessionStore,
    role_resolver: RoleResolver,
    ban_checker: BanChecker | None = None,
    challenge_prefix: str = DEFAULT_CHALLENGE_PREFIX,
    tags: list[str] | None = None,
) -> APIRouter:
    """Return an APIRouter with ``/challenge``, ``/session``, ``/logout`` endpoints."""
    resolved_tags: list[str | Any] = list(tags) if tags is not None else ["auth"]
    router = APIRouter(tags=resolved_tags)

    @router.post("/challenge", response_model=ChallengeResponse)
    async def request_challenge(body: ChallengeRequest) -> ChallengeResponse:
        try:
            validate_hotkey_format(body.hotkey)
        except AuthenticationError as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={"code": exc.error_code, "message": exc.message},
            ) from exc

        challenge = generate_challenge(prefix=challenge_prefix)
        await session_store.store_challenge(body.hotkey, challenge)
        return ChallengeResponse(
            challenge=challenge,
            expires_at=int(time.time()) + session_store.challenge_ttl_seconds,
        )

    @router.post("/session", response_model=SessionResponse)
    async def create_session(body: SessionRequest) -> SessionResponse:
        try:
            nonce = extract_nonce_from_challenge(body.challenge)
        except ValueError as exc:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid challenge format",
            ) from exc

        stored = await session_store.get_challenge(nonce)
        if stored is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired challenge",
            )

        if stored.hotkey != body.hotkey:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Hotkey mismatch",
            )

        if stored.challenge != body.challenge:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Challenge mismatch",
            )

        if not verify_sr25519(body.hotkey, body.challenge, body.signature):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid signature",
            )

        role = await maybe_await(role_resolver(body.hotkey))
        if role is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Not registered on subnet",
            )

        if ban_checker is not None:
            is_banned = await maybe_await(ban_checker(body.hotkey, role))
            if bool(is_banned):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Hotkey is banned",
                )

        token = await session_store.create_session(body.hotkey, role)
        return SessionResponse(
            session_token=token,
            expires_at=int(time.time()) + session_store.session_ttl_seconds,
            role=role,
        )

    @router.post("/logout", response_model=LogoutResponse)
    async def logout(
        authorization: str | None = Header(default=None),
    ) -> LogoutResponse:
        token = _require_bearer_token(authorization)
        session = await session_store.get_session(token)
        if session is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired session",
            )
        await session_store.delete_session(token)
        return LogoutResponse(success=True)

    return router


__all__ = [
    "ChallengeRequest",
    "ChallengeResponse",
    "LogoutResponse",
    "SessionRequest",
    "SessionResponse",
    "build_auth_router",
]
