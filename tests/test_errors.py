"""Tests for AuthErrorCode and AuthenticationError."""

from __future__ import annotations

import pytest

from bittensor_auth.errors import AuthenticationError, AuthErrorCode


def test_error_code_exposes_stable_code_and_message() -> None:
    assert AuthErrorCode.INVALID_SIGNATURE.code == "INVALID_SIGNATURE"
    assert AuthErrorCode.INVALID_SIGNATURE.message == "Invalid signature"
    assert AuthErrorCode.NONCE_REUSED.code == "NONCE_REUSED"
    assert AuthErrorCode.NOT_REGISTERED_AS_VALIDATOR.code == "NOT_REGISTERED_AS_VALIDATOR"


def test_all_required_codes_present() -> None:
    expected = {
        "INVALID_HOTKEY_FORMAT",
        "INVALID_TIMESTAMP",
        "TIMESTAMP_SKEW",
        "INVALID_SIGNATURE_FORMAT",
        "INVALID_SIGNATURE",
        "NONCE_TOO_LONG",
        "NONCE_INVALID_CHARS",
        "NONCE_REUSED",
        "NOT_REGISTERED",
        "NOT_REGISTERED_AS_VALIDATOR",
    }
    actual = {code.code for code in AuthErrorCode}
    assert expected == actual


def test_authentication_error_carries_code() -> None:
    err = AuthenticationError(AuthErrorCode.INVALID_SIGNATURE)
    assert err.error is AuthErrorCode.INVALID_SIGNATURE
    assert err.error_code == "INVALID_SIGNATURE"
    assert err.message == "Invalid signature"
    assert str(err) == "Invalid signature"


def test_authentication_error_is_raisable() -> None:
    with pytest.raises(AuthenticationError) as exc_info:
        raise AuthenticationError(AuthErrorCode.NONCE_REUSED)
    assert exc_info.value.error_code == "NONCE_REUSED"
