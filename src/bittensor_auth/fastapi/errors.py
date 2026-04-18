"""Map :class:`AuthenticationError` to HTTP status codes.

400 = malformed input, 401 = bad credentials / clock skew, 403 = not authorized.
"""

from __future__ import annotations

from fastapi import HTTPException, status

from ..errors import AuthenticationError, AuthErrorCode

_STATUS_BY_CODE: dict[AuthErrorCode, int] = {
    AuthErrorCode.INVALID_HOTKEY_FORMAT: status.HTTP_400_BAD_REQUEST,
    AuthErrorCode.INVALID_TIMESTAMP: status.HTTP_400_BAD_REQUEST,
    AuthErrorCode.INVALID_SIGNATURE_FORMAT: status.HTTP_400_BAD_REQUEST,
    AuthErrorCode.NONCE_TOO_LONG: status.HTTP_400_BAD_REQUEST,
    AuthErrorCode.TIMESTAMP_SKEW: status.HTTP_401_UNAUTHORIZED,
    AuthErrorCode.INVALID_SIGNATURE: status.HTTP_401_UNAUTHORIZED,
    AuthErrorCode.NONCE_REUSED: status.HTTP_401_UNAUTHORIZED,
    AuthErrorCode.NOT_REGISTERED: status.HTTP_403_FORBIDDEN,
    AuthErrorCode.NOT_REGISTERED_AS_VALIDATOR: status.HTTP_403_FORBIDDEN,
}


def auth_error_to_http(error: AuthenticationError) -> HTTPException:
    """Convert to ``HTTPException`` with ``{"code": ..., "message": ...}`` detail."""
    http_status = _STATUS_BY_CODE.get(error.error, status.HTTP_401_UNAUTHORIZED)
    return HTTPException(
        status_code=http_status,
        detail={"code": error.error_code, "message": error.message},
    )


__all__ = ["auth_error_to_http"]
