"""Authentication error codes and exceptions."""

from __future__ import annotations

from enum import Enum


class AuthErrorCode(Enum):
    """Each member carries a stable ``code`` string and a human-readable ``message``."""

    INVALID_HOTKEY_FORMAT = ("INVALID_HOTKEY_FORMAT", "Invalid hotkey format")
    INVALID_TIMESTAMP = ("INVALID_TIMESTAMP", "Invalid timestamp format")
    TIMESTAMP_SKEW = ("TIMESTAMP_SKEW", "Timestamp outside acceptable window")
    INVALID_SIGNATURE_FORMAT = ("INVALID_SIGNATURE_FORMAT", "Invalid signature format")
    INVALID_SIGNATURE = ("INVALID_SIGNATURE", "Invalid signature")
    NONCE_TOO_LONG = ("NONCE_TOO_LONG", "Nonce exceeds maximum allowed length")
    NONCE_REUSED = ("NONCE_REUSED", "Nonce has already been used")
    NOT_REGISTERED = ("NOT_REGISTERED", "Hotkey not registered on subnet")
    NOT_REGISTERED_AS_VALIDATOR = (
        "NOT_REGISTERED_AS_VALIDATOR",
        "Not registered as validator",
    )

    @property
    def code(self) -> str:
        return self.value[0]

    @property
    def message(self) -> str:
        return self.value[1]


class AuthenticationError(Exception):
    """Carries an :class:`AuthErrorCode` for machine-readable failure identification."""

    def __init__(self, error: AuthErrorCode):
        self.error = error
        self.error_code = error.code
        self.message = error.message
        super().__init__(error.message)
