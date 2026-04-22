"""Map :class:`AuthenticationError` to HTTP status codes.

400 = malformed input, 401 = bad credentials / clock skew, 403 = not authorized.
"""

from __future__ import annotations

import logging

from fastapi import HTTPException, status

from ..errors import AuthenticationError, AuthErrorCode

logger = logging.getLogger(__name__)

_STATUS_BY_CODE: dict[AuthErrorCode, int] = {
    AuthErrorCode.INVALID_HOTKEY_FORMAT: status.HTTP_400_BAD_REQUEST,
    AuthErrorCode.INVALID_TIMESTAMP: status.HTTP_400_BAD_REQUEST,
    AuthErrorCode.INVALID_SIGNATURE_FORMAT: status.HTTP_400_BAD_REQUEST,
    AuthErrorCode.NONCE_TOO_LONG: status.HTTP_400_BAD_REQUEST,
    AuthErrorCode.NONCE_INVALID_CHARS: status.HTTP_400_BAD_REQUEST,
    AuthErrorCode.TIMESTAMP_SKEW: status.HTTP_401_UNAUTHORIZED,
    AuthErrorCode.INVALID_SIGNATURE: status.HTTP_401_UNAUTHORIZED,
    AuthErrorCode.NONCE_REUSED: status.HTTP_401_UNAUTHORIZED,
    AuthErrorCode.NOT_REGISTERED: status.HTTP_403_FORBIDDEN,
    AuthErrorCode.NOT_REGISTERED_AS_VALIDATOR: status.HTTP_403_FORBIDDEN,
}

_OPAQUE_401_DETAIL = {"code": "UNAUTHORIZED", "message": "Authentication required"}


def auth_error_to_http(
    error: AuthenticationError, *, collapse_codes: bool = False
) -> HTTPException:
    """Convert to ``HTTPException`` with ``{"code": ..., "message": ...}`` detail.

    When ``collapse_codes`` is ``True``, every 401 response collapses to
    a single ``UNAUTHORIZED`` code so clients can't distinguish
    ``INVALID_SIGNATURE`` from ``NONCE_REUSED`` (a mild enumeration
    side channel). 400/403 responses keep their specific codes because
    those represent caller-fixable input errors / authorization
    decisions, not credential validity. The server log line below
    preserves the specific code for operators regardless.
    """
    http_status = _STATUS_BY_CODE.get(error.error, status.HTTP_401_UNAUTHORIZED)
    if collapse_codes and http_status == status.HTTP_401_UNAUTHORIZED:
        logger.info("auth rejected: %s", error.error_code)
        return HTTPException(status_code=http_status, detail=_OPAQUE_401_DETAIL)
    return HTTPException(
        status_code=http_status,
        detail={"code": error.error_code, "message": error.message},
    )


__all__ = ["auth_error_to_http"]
