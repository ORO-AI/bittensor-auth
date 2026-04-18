"""Tests for bittensor_auth.core."""

from __future__ import annotations

import pytest
from bittensor import Keypair

from bittensor_auth import (
    AuthenticationError,
    AuthErrorCode,
    parse_signature,
    validate_hotkey_format,
    verify_sr25519,
)


class TestValidateHotkeyFormat:
    def test_accepts_valid_ss58(self, alice: Keypair) -> None:
        validate_hotkey_format(alice.ss58_address)

    @pytest.mark.parametrize("bad_input", ["not-a-real-ss58-address", ""])
    def test_rejects_invalid_input(self, bad_input: str) -> None:
        with pytest.raises(AuthenticationError) as exc:
            validate_hotkey_format(bad_input)
        assert exc.value.error is AuthErrorCode.INVALID_HOTKEY_FORMAT

    def test_rejects_truncated_address(self, alice: Keypair) -> None:
        with pytest.raises(AuthenticationError):
            validate_hotkey_format(alice.ss58_address[:-5])


class TestParseSignature:
    @pytest.mark.parametrize(
        ("input_hex", "expected"),
        [
            ("deadbeef", b"\xde\xad\xbe\xef"),
            ("0xdeadbeef", b"\xde\xad\xbe\xef"),
            ("0XDEADBEEF", b"\xde\xad\xbe\xef"),
        ],
        ids=["plain", "0x-prefix", "0X-prefix"],
    )
    def test_decodes_valid_hex(self, input_hex: str, expected: bytes) -> None:
        assert parse_signature(input_hex) == expected

    @pytest.mark.parametrize(
        ("bad_hex", "error_code"),
        [
            ("zzzz", AuthErrorCode.INVALID_SIGNATURE_FORMAT),
            ("abc", AuthErrorCode.INVALID_SIGNATURE_FORMAT),
        ],
        ids=["non-hex", "odd-length"],
    )
    def test_rejects_invalid_hex(self, bad_hex: str, error_code: AuthErrorCode) -> None:
        with pytest.raises(AuthenticationError) as exc:
            parse_signature(bad_hex)
        assert exc.value.error is error_code


class TestVerifySr25519:
    def test_valid_signature_round_trip(self, alice: Keypair) -> None:
        message = "hello-bittensor"
        signature = alice.sign(message.encode()).hex()
        assert verify_sr25519(alice.ss58_address, message, signature) is True

    def test_signature_with_0x_prefix_verifies(self, alice: Keypair) -> None:
        message = "hello-bittensor"
        signature = "0x" + alice.sign(message.encode()).hex()
        assert verify_sr25519(alice.ss58_address, message, signature) is True

    def test_wrong_signer_fails(self, alice: Keypair, bob: Keypair) -> None:
        message = "hello-bittensor"
        signature = bob.sign(message.encode()).hex()
        assert verify_sr25519(alice.ss58_address, message, signature) is False

    def test_tampered_message_fails(self, alice: Keypair) -> None:
        signature = alice.sign(b"original").hex()
        assert verify_sr25519(alice.ss58_address, "tampered", signature) is False

    def test_tampered_signature_fails(self, alice: Keypair) -> None:
        message = "hello"
        sig_bytes = bytearray(alice.sign(message.encode()))
        sig_bytes[0] ^= 0xFF
        assert verify_sr25519(alice.ss58_address, message, sig_bytes.hex()) is False

    @pytest.mark.parametrize(
        ("hotkey", "signature"),
        [
            ("placeholder", "not-hex"),
            ("not-a-valid-ss58", "deadbeef"),
            ("placeholder", "deadbeef"),
        ],
        ids=["malformed-hex", "invalid-hotkey", "wrong-length"],
    )
    def test_invalid_inputs_return_false(
        self, alice: Keypair, hotkey: str, signature: str
    ) -> None:
        actual_hotkey = alice.ss58_address if hotkey == "placeholder" else hotkey
        assert verify_sr25519(actual_hotkey, "hello", signature) is False
