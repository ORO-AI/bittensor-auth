"""FastAPI dependencies for Bittensor per-request authentication."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING, cast

from fastapi import HTTPException, Request, status

from ..core import validate_hotkey_format
from ..errors import AuthenticationError, AuthErrorCode
from ..signing import MessageBuilder, validate_timestamp, verify_signature
from ._utils import BanChecker, RoleResolver, maybe_await
from .errors import auth_error_to_http

if TYPE_CHECKING:
    from ..cache import CacheBackend
    from ..config import BittensorAuthConfig
    from ..metagraph import MetagraphCache
    from ..nonce import NonceTracker
    from ..session import SessionStore

logger = logging.getLogger(__name__)


HEADER_HOTKEY = "X-Hotkey"
HEADER_TIMESTAMP = "X-Timestamp"
HEADER_NONCE = "X-Nonce"
HEADER_SIGNATURE = "X-Signature"
_AUTH_HEADERS = (HEADER_HOTKEY, HEADER_TIMESTAMP, HEADER_NONCE, HEADER_SIGNATURE)


@dataclass(frozen=True)
class AuthenticatedUser:
    """Result of a successful per-request authentication."""

    hotkey: str
    timestamp: int
    nonce: str
    role: str | None = None


def _missing_headers_error(missing: list[str]) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail={
            "code": "MISSING_HEADERS",
            "message": f"Missing required authentication headers: {', '.join(missing)}",
        },
    )


def _banned_error() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail={"code": "BANNED", "message": "Hotkey is banned"},
    )


class BittensorAuth:
    """Factory producing FastAPI authentication dependencies."""

    def __init__(
        self,
        *,
        config: BittensorAuthConfig,
        cache: CacheBackend,
        metagraph: MetagraphCache,
        nonce_tracker: NonceTracker | None = None,
        role_resolver: RoleResolver | None = None,
        ban_checker: BanChecker | None = None,
        message_builder: MessageBuilder | None = None,
        session_store: SessionStore | None = None,
    ) -> None:
        from ..nonce import NonceTracker as _NonceTracker

        self._config = config
        self._cache = cache
        self._metagraph = metagraph
        self._nonce_tracker = nonce_tracker or _NonceTracker(
            cache,
            max_nonce_length=config.max_nonce_length,
            ttl_seconds=config.timestamp_skew_seconds,
        )
        self._role_resolver = role_resolver
        self._ban_checker = ban_checker
        self._message_builder = message_builder
        self._session_store = session_store

    async def authenticate(self, request: Request) -> AuthenticatedUser:
        """Signature + nonce + timestamp checks only (no registration check)."""
        return await self._authenticate(request)

    async def require_registered(self, request: Request) -> AuthenticatedUser:
        """Authenticate and require subnet registration."""
        user = await self._authenticate(request)
        try:
            if not self._metagraph.is_hotkey_registered(user.hotkey):
                raise AuthenticationError(AuthErrorCode.NOT_REGISTERED)
        except AuthenticationError as exc:
            raise auth_error_to_http(exc) from exc
        await self._check_banned(user)
        return user

    async def require_validator(self, request: Request) -> AuthenticatedUser:
        """Authenticate and require an active validator permit."""
        user = await self._authenticate(request)
        try:
            if not self._metagraph.has_validator_permit(user.hotkey):
                raise AuthenticationError(AuthErrorCode.NOT_REGISTERED_AS_VALIDATOR)
        except AuthenticationError as exc:
            raise auth_error_to_http(exc) from exc
        await self._check_banned(user)
        return user

    async def require_session(self, request: Request) -> AuthenticatedUser:
        """Authenticate via Bearer session token. Requires ``session_store``."""
        if self._session_store is None:
            raise RuntimeError(
                "require_session needs a session_store. "
                "Pass session_store= to BittensorAuth()."
            )

        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Missing or invalid Authorization header",
            )
        token = auth_header[7:]
        session = await self._session_store.get_session(token)
        if session is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired session",
            )
        user = AuthenticatedUser(
            hotkey=session.hotkey, timestamp=0, nonce="", role=session.role,
        )
        await self._check_banned(user)
        return user

    async def require_auth(self, request: Request) -> AuthenticatedUser:
        """Accept Bearer token or per-request signing. Ban check runs on both paths."""
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer ") and self._session_store is not None:
            token = auth_header[7:]
            session = await self._session_store.get_session(token)
            if session is not None:
                user = AuthenticatedUser(
                    hotkey=session.hotkey, timestamp=0, nonce="", role=session.role,
                )
                await self._check_banned(user)
                return user
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired session",
            )

        # Fall back to per-request signing (require_registered already checks bans)
        return await self.require_registered(request)

    async def _authenticate(self, request: Request) -> AuthenticatedUser:
        headers, missing = self._extract_headers(request)
        if missing:
            raise _missing_headers_error(missing)

        hotkey = headers[HEADER_HOTKEY]
        timestamp_str = headers[HEADER_TIMESTAMP]
        nonce = headers[HEADER_NONCE]
        signature = headers[HEADER_SIGNATURE]

        try:
            validate_hotkey_format(hotkey)
            timestamp = validate_timestamp(timestamp_str, self._config.timestamp_skew_seconds)

            if len(nonce) > self._config.max_nonce_length:
                raise AuthenticationError(AuthErrorCode.NONCE_TOO_LONG)

            if not verify_signature(
                hotkey, timestamp_str, nonce, signature,
                message_builder=self._message_builder,
            ):
                raise AuthenticationError(AuthErrorCode.INVALID_SIGNATURE)

            await self._nonce_tracker.register(hotkey, nonce)
        except AuthenticationError as exc:
            raise auth_error_to_http(exc) from exc

        role = await self._resolve_role(hotkey)
        return AuthenticatedUser(hotkey=hotkey, timestamp=timestamp, nonce=nonce, role=role)

    def _extract_headers(self, request: Request) -> tuple[dict[str, str], list[str]]:
        headers: dict[str, str] = {}
        missing: list[str] = []
        for name in _AUTH_HEADERS:
            value = request.headers.get(name)
            if value is None:
                missing.append(name)
            else:
                headers[name] = value
        return headers, missing

    async def _resolve_role(self, hotkey: str) -> str | None:
        if self._role_resolver is None:
            return None
        result = await maybe_await(self._role_resolver(hotkey))
        return cast("str | None", result)

    async def _check_banned(self, user: AuthenticatedUser) -> None:
        if self._ban_checker is None:
            return
        is_banned = await maybe_await(self._ban_checker(user.hotkey, user.role))
        if is_banned:
            raise _banned_error()
