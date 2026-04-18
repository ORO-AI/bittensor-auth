"""Tests for bittensor_auth.client -- client-side signing helpers.

These tests exercise the real ``bittensor.Keypair`` for signing and route
through the real ``httpx`` transport stack using a ``MockTransport`` as the
wrapped layer. No network and no Bittensor node are required.
"""

from __future__ import annotations

import time
from typing import Any

import httpx
import pytest
from bittensor import Keypair

from bittensor_auth.client import (
    AsyncSigningTransport,
    BittensorAuthClient,
    SigningTransport,
    default_is_public_endpoint,
    generate_auth_headers,
)
from bittensor_auth.signing import verify_signature
from tests.conftest import FakeWallet


class TestGenerateAuthHeaders:
    def test_returns_all_four_headers(self, alice: Keypair) -> None:
        headers = generate_auth_headers(alice)
        assert set(headers.keys()) == {"X-Hotkey", "X-Timestamp", "X-Nonce", "X-Signature"}

    def test_hotkey_matches_signer(self, alice: Keypair) -> None:
        assert generate_auth_headers(alice)["X-Hotkey"] == alice.ss58_address

    def test_timestamp_is_decimal_string(self, alice: Keypair) -> None:
        assert generate_auth_headers(alice)["X-Timestamp"].isdigit()

    def test_signature_has_0x_prefix(self, alice: Keypair) -> None:
        assert generate_auth_headers(alice)["X-Signature"].startswith("0x")

    def test_injected_nonce_is_preserved(self, alice: Keypair) -> None:
        headers = generate_auth_headers(alice, nonce="explicit-nonce-1")
        assert headers["X-Nonce"] == "explicit-nonce-1"

    def test_injected_timestamp_is_preserved(self, alice: Keypair) -> None:
        assert generate_auth_headers(alice, timestamp=42)["X-Timestamp"] == "42"

    def test_auto_nonce_is_fresh_each_call(self, alice: Keypair) -> None:
        a = generate_auth_headers(alice)
        b = generate_auth_headers(alice)
        assert a["X-Nonce"] != b["X-Nonce"]

    def test_auto_timestamp_is_near_now(self, alice: Keypair) -> None:
        before = int(time.time())
        headers = generate_auth_headers(alice)
        after = int(time.time())
        ts = int(headers["X-Timestamp"])
        assert before <= ts <= after

    def test_round_trip_through_verify_signature(self, alice: Keypair) -> None:
        headers = generate_auth_headers(alice)
        assert verify_signature(
            hotkey=headers["X-Hotkey"],
            timestamp=headers["X-Timestamp"],
            nonce=headers["X-Nonce"],
            signature_hex=headers["X-Signature"],
        ) is True

    def test_tampered_nonce_fails_verification(self, alice: Keypair) -> None:
        headers = generate_auth_headers(alice, nonce="original")
        assert verify_signature(
            hotkey=headers["X-Hotkey"],
            timestamp=headers["X-Timestamp"],
            nonce="tampered",
            signature_hex=headers["X-Signature"],
        ) is False

    def test_wrong_signer_fails_verification(self, alice: Keypair, bob: Keypair) -> None:
        headers = generate_auth_headers(alice)
        assert verify_signature(
            hotkey=bob.ss58_address,
            timestamp=headers["X-Timestamp"],
            nonce=headers["X-Nonce"],
            signature_hex=headers["X-Signature"],
        ) is False

    def test_accepts_wallet_like_object(self, alice: Keypair) -> None:
        wallet = FakeWallet(hotkey=alice)
        headers = generate_auth_headers(wallet)
        assert headers["X-Hotkey"] == alice.ss58_address
        assert verify_signature(
            hotkey=headers["X-Hotkey"],
            timestamp=headers["X-Timestamp"],
            nonce=headers["X-Nonce"],
            signature_hex=headers["X-Signature"],
        ) is True


class TestDefaultIsPublicEndpoint:
    @pytest.mark.parametrize(
        "url",
        [
            "/health",
            "https://api.example.com/health",
            "https://api.example.com/v1/health",
            "/v1/nested/health",
        ],
    )
    def test_health_paths_are_public(self, url: str) -> None:
        assert default_is_public_endpoint(url) is True

    @pytest.mark.parametrize(
        "url",
        ["/protected", "https://api.example.com/v1/private", "/api/resource", "", None],
    )
    def test_non_health_paths_are_not_public(self, url: str | None) -> None:
        assert default_is_public_endpoint(url) is False


class TestSigningTransport:
    def test_signs_non_public_request(self, alice: Keypair) -> None:
        captured: dict[str, httpx.Headers] = {}

        def mock_handler(request: httpx.Request) -> httpx.Response:
            captured["headers"] = request.headers
            return httpx.Response(200, json={"ok": True})

        transport = SigningTransport(alice, wrapped=httpx.MockTransport(mock_handler))
        with httpx.Client(base_url="https://example.com", transport=transport) as client:
            resp = client.get("/protected")

        assert resp.status_code == 200
        assert captured["headers"]["X-Hotkey"] == alice.ss58_address
        assert captured["headers"]["X-Signature"].startswith("0x")
        assert captured["headers"]["X-Nonce"]
        assert captured["headers"]["X-Timestamp"].isdigit()

    def test_does_not_sign_public_request(self, alice: Keypair) -> None:
        captured: dict[str, httpx.Headers] = {}

        def mock_handler(request: httpx.Request) -> httpx.Response:
            captured["headers"] = request.headers
            return httpx.Response(200, json={"ok": True})

        transport = SigningTransport(alice, wrapped=httpx.MockTransport(mock_handler))
        with httpx.Client(base_url="https://example.com", transport=transport) as client:
            resp = client.get("/health")

        assert resp.status_code == 200
        assert "x-hotkey" not in captured["headers"]
        assert "x-signature" not in captured["headers"]

    def test_custom_is_public_endpoint_is_respected(self, alice: Keypair) -> None:
        captured: list[dict[str, str]] = []

        def mock_handler(request: httpx.Request) -> httpx.Response:
            captured.append(dict(request.headers))
            return httpx.Response(200)

        transport = SigningTransport(
            alice,
            wrapped=httpx.MockTransport(mock_handler),
            is_public_endpoint=lambda url: "/public/" in url,
        )
        with httpx.Client(base_url="https://example.com", transport=transport) as client:
            client.get("/public/info")
            client.get("/private/info")

        assert "x-hotkey" not in captured[0]
        assert captured[1]["x-hotkey"] == alice.ss58_address

    def test_signed_headers_verify_on_server_side(self, alice: Keypair) -> None:
        """End-to-end: transport-signed headers verify cleanly on the server side."""
        outcome: dict[str, Any] = {}

        def mock_handler(request: httpx.Request) -> httpx.Response:
            outcome["ok"] = verify_signature(
                hotkey=request.headers["X-Hotkey"],
                timestamp=request.headers["X-Timestamp"],
                nonce=request.headers["X-Nonce"],
                signature_hex=request.headers["X-Signature"],
            )
            return httpx.Response(200)

        transport = SigningTransport(alice, wrapped=httpx.MockTransport(mock_handler))
        with httpx.Client(base_url="https://example.com", transport=transport) as client:
            client.post("/v1/submit", json={"value": 1})

        assert outcome["ok"] is True

    def test_fresh_headers_on_each_request(self, alice: Keypair) -> None:
        nonces: list[str] = []

        def mock_handler(request: httpx.Request) -> httpx.Response:
            nonces.append(request.headers["X-Nonce"])
            return httpx.Response(200)

        transport = SigningTransport(alice, wrapped=httpx.MockTransport(mock_handler))
        with httpx.Client(base_url="https://example.com", transport=transport) as client:
            for _ in range(3):
                client.get("/protected")

        assert len(set(nonces)) == 3


class TestAsyncSigningTransport:
    async def test_signs_non_public_request(self, alice: Keypair) -> None:
        captured: dict[str, httpx.Headers] = {}

        async def mock_handler(request: httpx.Request) -> httpx.Response:
            captured["headers"] = request.headers
            return httpx.Response(200)

        transport = AsyncSigningTransport(alice, wrapped=httpx.MockTransport(mock_handler))
        async with httpx.AsyncClient(
            base_url="https://example.com", transport=transport
        ) as client:
            resp = await client.get("/protected")

        assert resp.status_code == 200
        assert captured["headers"]["X-Hotkey"] == alice.ss58_address

    async def test_does_not_sign_public_request(self, alice: Keypair) -> None:
        captured: dict[str, httpx.Headers] = {}

        async def mock_handler(request: httpx.Request) -> httpx.Response:
            captured["headers"] = request.headers
            return httpx.Response(200)

        transport = AsyncSigningTransport(alice, wrapped=httpx.MockTransport(mock_handler))
        async with httpx.AsyncClient(
            base_url="https://example.com", transport=transport
        ) as client:
            await client.get("/health")

        assert "x-hotkey" not in captured["headers"]


class TestBittensorAuthClient:
    def test_lazy_sync_client_construction(self, alice: Keypair) -> None:
        c = BittensorAuthClient(base_url="https://example.com", signer=alice)
        assert c._client is None  # noqa: SLF001
        _ = c.get_httpx_client()
        assert c._client is not None  # noqa: SLF001

    def test_sync_client_is_reused(self, alice: Keypair) -> None:
        c = BittensorAuthClient(base_url="https://example.com", signer=alice)
        assert c.get_httpx_client() is c.get_httpx_client()

    def test_async_client_is_reused(self, alice: Keypair) -> None:
        c = BittensorAuthClient(base_url="https://example.com", signer=alice)
        assert c.get_async_httpx_client() is c.get_async_httpx_client()

    def test_accepts_wallet_object(self, alice: Keypair) -> None:
        wallet = FakeWallet(hotkey=alice)
        c = BittensorAuthClient(base_url="https://example.com", signer=wallet)
        assert c.get_httpx_client() is not None

    def test_context_manager_sync(self, alice: Keypair) -> None:
        with BittensorAuthClient(base_url="https://example.com", signer=alice) as c:
            assert c.get_httpx_client() is not None

    async def test_context_manager_async(self, alice: Keypair) -> None:
        async with BittensorAuthClient(base_url="https://example.com", signer=alice) as c:
            assert c.get_async_httpx_client() is not None
