"""Tests for bittensor_auth.signing."""

from __future__ import annotations

import time

import pytest
from bittensor import Keypair

from bittensor_auth import (
    AuthenticationError,
    AuthErrorCode,
    construct_signing_message,
    validate_timestamp,
    verify_signature,
)


class TestConstructSigningMessage:
    @pytest.mark.parametrize(
        ("timestamp", "expected"),
        [
            ("1234567890", "HOTKEY:1234567890:abc"),
            (1234567890, "HOTKEY:1234567890:abc"),
        ],
        ids=["string-timestamp", "int-timestamp"],
    )
    def test_format(self, timestamp: str | int, expected: str) -> None:
        assert construct_signing_message("HOTKEY", timestamp, "abc") == expected

    def test_int_and_str_timestamps_produce_same_string(self) -> None:
        assert construct_signing_message("HOTKEY", 42, "n") == construct_signing_message(
            "HOTKEY", "42", "n"
        )


class TestValidateTimestamp:
    def test_accepts_current_time(self) -> None:
        now = int(time.time())
        assert validate_timestamp(str(now), skew_seconds=60) == now

    def test_accepts_within_skew(self) -> None:
        now = int(time.time())
        assert validate_timestamp(str(now - 30), skew_seconds=60) == now - 30
        assert validate_timestamp(str(now + 30), skew_seconds=60) == now + 30

    def test_rejects_outside_skew(self) -> None:
        now = int(time.time())
        with pytest.raises(AuthenticationError) as exc:
            validate_timestamp(str(now - 300), skew_seconds=60)
        assert exc.value.error is AuthErrorCode.TIMESTAMP_SKEW

    @pytest.mark.parametrize(
        ("bad_ts", "error_code"),
        [
            ("not-a-number", AuthErrorCode.INVALID_TIMESTAMP),
            ("1234567890.5", AuthErrorCode.INVALID_TIMESTAMP),
        ],
        ids=["non-integer", "float-string"],
    )
    def test_rejects_invalid_timestamps(
        self, bad_ts: str, error_code: AuthErrorCode
    ) -> None:
        with pytest.raises(AuthenticationError) as exc:
            validate_timestamp(bad_ts, skew_seconds=60)
        assert exc.value.error is error_code


class TestVerifySignatureRoundTrip:
    def test_valid_round_trip(self, alice: Keypair) -> None:
        timestamp = str(int(time.time()))
        nonce = "unique-nonce-1"
        message = construct_signing_message(alice.ss58_address, timestamp, nonce)
        signature = alice.sign(message.encode()).hex()

        assert verify_signature(alice.ss58_address, timestamp, nonce, signature) is True

    def test_int_timestamp_matches_string(self, alice: Keypair) -> None:
        ts_int = int(time.time())
        nonce = "n"
        message = construct_signing_message(alice.ss58_address, ts_int, nonce)
        signature = alice.sign(message.encode()).hex()

        assert verify_signature(alice.ss58_address, ts_int, nonce, signature) is True
        assert verify_signature(alice.ss58_address, str(ts_int), nonce, signature) is True

    def test_tampered_nonce_fails(self, alice: Keypair) -> None:
        timestamp = str(int(time.time()))
        message = construct_signing_message(alice.ss58_address, timestamp, "real-nonce")
        signature = alice.sign(message.encode()).hex()

        result = verify_signature(alice.ss58_address, timestamp, "different-nonce", signature)
        assert result is False
