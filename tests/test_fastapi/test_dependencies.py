"""Integration-style tests for :mod:`bittensor_auth.fastapi.dependencies`.

These tests boot a real FastAPI app (via ``TestClient``) and exercise the
request/response path end-to-end: unsigned calls return 401, properly signed
calls return 200, replayed nonces are rejected, and optional hooks
(``role_resolver``, ``ban_checker``) are invoked. A FakeMetagraph
stands in for a live Bittensor node.
"""

from __future__ import annotations

import asyncio
import time
import uuid

import pytest
from bittensor import Keypair
from fastapi.testclient import TestClient

from bittensor_auth import (
    BittensorAuthConfig,
    InMemoryCache,
    SessionStore,
    generate_auth_headers,
)
from bittensor_auth.fastapi import BittensorAuth
from tests.conftest import make_synced_metagraph_cache
from tests.test_fastapi.conftest import build_test_app, make_auth, make_auth_with_session


class TestMissingHeaders:
    def test_returns_401_when_all_headers_missing(self, alice: Keypair) -> None:
        auth = make_auth(alice)
        with TestClient(build_test_app(auth)) as client:
            resp = client.get("/registered")
        assert resp.status_code == 401
        detail = resp.json()["detail"]
        assert detail["code"] == "MISSING_HEADERS"
        assert "X-Hotkey" in detail["message"]

    def test_lists_only_the_missing_header(self, alice: Keypair) -> None:
        auth = make_auth(alice)
        headers = generate_auth_headers(alice)
        headers.pop("X-Signature")
        with TestClient(build_test_app(auth)) as client:
            resp = client.get("/registered", headers=headers)
        assert resp.status_code == 401
        assert resp.json()["detail"]["message"].endswith("X-Signature")


class TestSignedRequests:
    def test_authenticate_accepts_signed_request(self, alice: Keypair) -> None:
        auth = make_auth(alice)
        with TestClient(build_test_app(auth)) as client:
            resp = client.get("/base", headers=generate_auth_headers(alice))
        assert resp.status_code == 200
        assert resp.json() == {"hotkey": alice.ss58_address, "role": None}

    def test_require_registered_accepts_registered_hotkey(self, alice: Keypair) -> None:
        auth = make_auth(alice)
        with TestClient(build_test_app(auth)) as client:
            resp = client.get("/registered", headers=generate_auth_headers(alice))
        assert resp.status_code == 200

    def test_require_registered_rejects_unregistered_hotkey(self, bob: Keypair) -> None:
        metagraph = make_synced_metagraph_cache(
            hotkeys=["5OtherHotkey"], validator_permit=[False], stake=[0.0]
        )
        auth = BittensorAuth(
            config=BittensorAuthConfig(),
            cache=InMemoryCache(),
            metagraph=metagraph,
        )
        with TestClient(build_test_app(auth)) as client:
            resp = client.get("/registered", headers=generate_auth_headers(bob))
        assert resp.status_code == 403
        assert resp.json()["detail"]["code"] == "NOT_REGISTERED"

    def test_require_validator_accepts_validator(self, alice: Keypair) -> None:
        auth = make_auth(alice)
        with TestClient(build_test_app(auth)) as client:
            resp = client.get("/validator", headers=generate_auth_headers(alice))
        assert resp.status_code == 200

    def test_require_validator_rejects_non_validator(self, alice: Keypair) -> None:
        auth = make_auth(alice, validator_permit=False, stake=0.0)
        with TestClient(build_test_app(auth)) as client:
            resp = client.get("/validator", headers=generate_auth_headers(alice))
        assert resp.status_code == 403
        assert resp.json()["detail"]["code"] == "NOT_REGISTERED_AS_VALIDATOR"


class TestInvalidSignatures:
    def test_tampered_signature_rejected(self, alice: Keypair) -> None:
        auth = make_auth(alice)
        headers = generate_auth_headers(alice)
        sig = headers["X-Signature"]
        headers["X-Signature"] = sig[:-1] + ("0" if sig[-1] != "0" else "1")
        with TestClient(build_test_app(auth)) as client:
            resp = client.get("/registered", headers=headers)
        assert resp.status_code == 401
        assert resp.json()["detail"]["code"] == "INVALID_SIGNATURE"

    def test_wrong_signer_rejected(self, alice: Keypair, bob: Keypair) -> None:
        metagraph = make_synced_metagraph_cache(
            hotkeys=[alice.ss58_address, bob.ss58_address],
            validator_permit=[True, True],
            stake=[100.0, 100.0],
        )
        auth = BittensorAuth(
            config=BittensorAuthConfig(),
            cache=InMemoryCache(),
            metagraph=metagraph,
        )
        headers = generate_auth_headers(bob)
        headers["X-Hotkey"] = alice.ss58_address
        with TestClient(build_test_app(auth)) as client:
            resp = client.get("/registered", headers=headers)
        assert resp.status_code == 401
        assert resp.json()["detail"]["code"] == "INVALID_SIGNATURE"

    def test_invalid_hotkey_format_rejected(self, alice: Keypair) -> None:
        auth = make_auth(alice)
        headers = generate_auth_headers(alice)
        headers["X-Hotkey"] = "not-a-valid-ss58-address"
        with TestClient(build_test_app(auth)) as client:
            resp = client.get("/registered", headers=headers)
        assert resp.status_code == 400
        assert resp.json()["detail"]["code"] == "INVALID_HOTKEY_FORMAT"

    def test_timestamp_skew_rejected(self, alice: Keypair) -> None:
        auth = make_auth(alice, config=BittensorAuthConfig(timestamp_skew_seconds=30))
        headers = generate_auth_headers(alice, timestamp=int(time.time()) - 300)
        with TestClient(build_test_app(auth)) as client:
            resp = client.get("/registered", headers=headers)
        assert resp.status_code == 401
        assert resp.json()["detail"]["code"] == "TIMESTAMP_SKEW"

    def test_non_integer_timestamp_rejected(self, alice: Keypair) -> None:
        auth = make_auth(alice)
        headers = generate_auth_headers(alice)
        headers["X-Timestamp"] = "not-a-number"
        with TestClient(build_test_app(auth)) as client:
            resp = client.get("/registered", headers=headers)
        assert resp.status_code == 400
        assert resp.json()["detail"]["code"] == "INVALID_TIMESTAMP"


class TestNonceReplay:
    def test_replayed_nonce_rejected(self, alice: Keypair) -> None:
        auth = make_auth(alice)
        headers = generate_auth_headers(alice, nonce="fixed-nonce-for-test")
        with TestClient(build_test_app(auth)) as client:
            first = client.get("/registered", headers=headers)
            second = client.get("/registered", headers=headers)
        assert first.status_code == 200
        assert second.status_code == 401
        assert second.json()["detail"]["code"] == "NONCE_REUSED"

    def test_fresh_nonce_accepted_after_first(self, alice: Keypair) -> None:
        auth = make_auth(alice)
        with TestClient(build_test_app(auth)) as client:
            first = client.get(
                "/registered",
                headers=generate_auth_headers(alice, nonce=str(uuid.uuid4())),
            )
            second = client.get(
                "/registered",
                headers=generate_auth_headers(alice, nonce=str(uuid.uuid4())),
            )
        assert first.status_code == 200
        assert second.status_code == 200


class TestRoleResolverHook:
    def test_role_resolver_invoked_and_populated(self, alice: Keypair) -> None:
        calls: list[str] = []

        def resolve_role(hotkey: str) -> str | None:
            calls.append(hotkey)
            return "admin"

        auth = make_auth(alice, role_resolver=resolve_role)
        with TestClient(build_test_app(auth)) as client:
            resp = client.get("/registered", headers=generate_auth_headers(alice))
        assert resp.status_code == 200
        assert resp.json()["role"] == "admin"
        assert calls == [alice.ss58_address]

    def test_async_role_resolver_supported(self, alice: Keypair) -> None:
        async def resolve_role(hotkey: str) -> str | None:
            return "user"

        auth = make_auth(alice, role_resolver=resolve_role)
        with TestClient(build_test_app(auth)) as client:
            resp = client.get("/registered", headers=generate_auth_headers(alice))
        assert resp.status_code == 200
        assert resp.json()["role"] == "user"


class TestBanCheckerHook:
    def test_ban_checker_rejects_banned_hotkey(self, alice: Keypair) -> None:
        auth = make_auth(
            alice,
            ban_checker=lambda hotkey, role: hotkey == alice.ss58_address,
        )
        with TestClient(build_test_app(auth)) as client:
            resp = client.get("/registered", headers=generate_auth_headers(alice))
        assert resp.status_code == 403
        assert resp.json()["detail"]["code"] == "BANNED"

    def test_ban_checker_passes_role_from_resolver(self, alice: Keypair) -> None:
        seen: list[tuple[str, str | None]] = []

        def ban_checker(hotkey: str, role: str | None) -> bool:
            seen.append((hotkey, role))
            return False

        auth = make_auth(
            alice,
            role_resolver=lambda hotkey: "validator",
            ban_checker=ban_checker,
        )
        with TestClient(build_test_app(auth)) as client:
            resp = client.get("/registered", headers=generate_auth_headers(alice))
        assert resp.status_code == 200
        assert seen == [(alice.ss58_address, "validator")]

    def test_async_ban_checker_supported(self, alice: Keypair) -> None:
        async def ban_checker(hotkey: str, role: str | None) -> bool:
            return True

        auth = make_auth(alice, ban_checker=ban_checker)
        with TestClient(build_test_app(auth)) as client:
            resp = client.get("/registered", headers=generate_auth_headers(alice))
        assert resp.status_code == 403
        assert resp.json()["detail"]["code"] == "BANNED"

    def test_ban_checker_not_called_on_base_authenticate(self, alice: Keypair) -> None:
        """``authenticate`` skips registration + ban checks by design."""
        calls: list[str] = []

        metagraph = make_synced_metagraph_cache(hotkeys=[], validator_permit=[], stake=[])
        auth = BittensorAuth(
            config=BittensorAuthConfig(),
            cache=InMemoryCache(),
            metagraph=metagraph,
            ban_checker=lambda hotkey, role: (calls.append(hotkey), True)[-1],
        )
        with TestClient(build_test_app(auth)) as client:
            resp = client.get("/base", headers=generate_auth_headers(alice))
        assert resp.status_code == 200
        assert calls == []


class TestRequireSession:
    def test_valid_bearer_token_accepted(self, alice: Keypair) -> None:
        auth, store = make_auth_with_session(alice)
        token = asyncio.get_event_loop().run_until_complete(
            store.create_session(alice.ss58_address, "user")
        )
        with TestClient(build_test_app(auth)) as client:
            resp = client.get("/session-only", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 200
        assert resp.json()["hotkey"] == alice.ss58_address
        assert resp.json()["role"] == "user"

    def test_missing_bearer_rejected(self, alice: Keypair) -> None:
        auth, _ = make_auth_with_session(alice)
        with TestClient(build_test_app(auth)) as client:
            resp = client.get("/session-only")
        assert resp.status_code == 401

    def test_invalid_token_rejected(self, alice: Keypair) -> None:
        auth, _ = make_auth_with_session(alice)
        with TestClient(build_test_app(auth)) as client:
            resp = client.get("/session-only", headers={"Authorization": "Bearer ses_bogus"})
        assert resp.status_code == 401

    def test_no_session_store_raises_runtime_error(self, alice: Keypair) -> None:
        auth = make_auth(alice)
        with (
            TestClient(build_test_app(auth)) as client,
            pytest.raises(RuntimeError, match="session_store"),
        ):
            client.get("/session-only", headers={"Authorization": "Bearer ses_anything"})


class TestRequireAuth:
    def test_bearer_token_accepted(self, alice: Keypair) -> None:
        auth, store = make_auth_with_session(alice)
        token = asyncio.get_event_loop().run_until_complete(
            store.create_session(alice.ss58_address, "validator")
        )
        with TestClient(build_test_app(auth)) as client:
            resp = client.get("/dual", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 200
        assert resp.json()["role"] == "validator"

    def test_per_request_signing_accepted(self, alice: Keypair) -> None:
        auth, _ = make_auth_with_session(alice)
        with TestClient(build_test_app(auth)) as client:
            resp = client.get("/dual", headers=generate_auth_headers(alice))
        assert resp.status_code == 200
        assert resp.json()["hotkey"] == alice.ss58_address

    def test_unsigned_rejected(self, alice: Keypair) -> None:
        auth, _ = make_auth_with_session(alice)
        with TestClient(build_test_app(auth)) as client:
            resp = client.get("/dual")
        assert resp.status_code == 401

    def test_expired_bearer_rejected(self, alice: Keypair) -> None:
        auth, _ = make_auth_with_session(alice)
        with TestClient(build_test_app(auth)) as client:
            resp = client.get("/dual", headers={"Authorization": "Bearer ses_expired_token"})
        assert resp.status_code == 401

    def test_unregistered_signing_rejected(self, bob: Keypair) -> None:
        """Per-request signing falls back to require_registered which checks metagraph."""
        cache = InMemoryCache()
        metagraph = make_synced_metagraph_cache(
            hotkeys=["5OtherHotkey"], validator_permit=[False], stake=[0.0]
        )
        auth = BittensorAuth(
            config=BittensorAuthConfig(),
            cache=cache,
            metagraph=metagraph,
            session_store=SessionStore(cache),
        )
        with TestClient(build_test_app(auth)) as client:
            resp = client.get("/dual", headers=generate_auth_headers(bob))
        assert resp.status_code == 403


class TestSessionRecheck:
    """Regression tests for the session-recheck plumbing.

    When ``recheck_registration_on_session`` / ``recheck_ban_on_session``
    are enabled (default), a hotkey that deregisters mid-session loses
    access on the next request instead of waiting for the session TTL.
    """

    def test_deregistered_hotkey_rejected_by_default(self, alice: Keypair, bob: Keypair) -> None:
        """With recheck enabled, a hotkey not in the metagraph is rejected
        even though its session token is still within TTL."""
        cache = InMemoryCache()
        # Metagraph contains alice only; bob is not registered.
        metagraph = make_synced_metagraph_cache(
            hotkeys=[alice.ss58_address], validator_permit=[False], stake=[0.0]
        )
        store = SessionStore(cache)
        auth = BittensorAuth(
            config=BittensorAuthConfig(),  # defaults: recheck on
            cache=cache,
            metagraph=metagraph,
            session_store=store,
        )
        # Create a session for bob manually (as if bob had been registered
        # at session-creation time and later deregistered).
        token = asyncio.get_event_loop().run_until_complete(
            store.create_session(bob.ss58_address, "miner")
        )
        with TestClient(build_test_app(auth)) as client:
            resp = client.get("/session-only", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 401

    def test_opt_out_allows_stale_session(self, alice: Keypair, bob: Keypair) -> None:
        """With both rechecks disabled, session role is frozen at issuance."""
        cache = InMemoryCache()
        metagraph = make_synced_metagraph_cache(
            hotkeys=[alice.ss58_address], validator_permit=[False], stake=[0.0]
        )
        store = SessionStore(cache)
        auth = BittensorAuth(
            config=BittensorAuthConfig(
                recheck_registration_on_session=False,
                recheck_ban_on_session=False,
            ),
            cache=cache,
            metagraph=metagraph,
            session_store=store,
        )
        token = asyncio.get_event_loop().run_until_complete(
            store.create_session(bob.ss58_address, "miner")
        )
        with TestClient(build_test_app(auth)) as client:
            resp = client.get("/session-only", headers={"Authorization": f"Bearer {token}"})
        # The session is honored since recheck is disabled — this is the
        # old (pre-fix) behavior, kept available as an opt-in.
        assert resp.status_code == 200

    def test_role_resolver_rebinds_role_on_session_auth(self, alice: Keypair) -> None:
        """When the role resolver is configured, session auth honors the
        resolver's current answer rather than the cached session.role."""
        cache = InMemoryCache()
        metagraph = make_synced_metagraph_cache(
            hotkeys=[alice.ss58_address], validator_permit=[True], stake=[100.0]
        )
        store = SessionStore(cache)

        # Resolver "upgrades" alice from miner → validator live.
        def resolver(hotkey: str) -> str | None:
            return "validator" if hotkey == alice.ss58_address else None

        auth = BittensorAuth(
            config=BittensorAuthConfig(),
            cache=cache,
            metagraph=metagraph,
            role_resolver=resolver,
            session_store=store,
        )
        token = asyncio.get_event_loop().run_until_complete(
            store.create_session(alice.ss58_address, "miner")
        )
        with TestClient(build_test_app(auth)) as client:
            resp = client.get("/session-only", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 200
        assert resp.json()["role"] == "validator"


class TestBearerTokenParsing:
    """Bearer token extraction must be case-insensitive and whitespace-tolerant."""

    def test_lowercase_bearer_scheme_accepted(self, alice: Keypair) -> None:
        auth, store = make_auth_with_session(alice)
        token = asyncio.get_event_loop().run_until_complete(
            store.create_session(alice.ss58_address, "user")
        )
        with TestClient(build_test_app(auth)) as client:
            resp = client.get("/session-only", headers={"Authorization": f"bearer {token}"})
        assert resp.status_code == 200

    def test_extra_spaces_accepted(self, alice: Keypair) -> None:
        auth, store = make_auth_with_session(alice)
        token = asyncio.get_event_loop().run_until_complete(
            store.create_session(alice.ss58_address, "user")
        )
        with TestClient(build_test_app(auth)) as client:
            resp = client.get("/session-only", headers={"Authorization": f"  Bearer   {token}  "})
        assert resp.status_code == 200

    def test_missing_token_rejected(self, alice: Keypair) -> None:
        auth, _ = make_auth_with_session(alice)
        with TestClient(build_test_app(auth)) as client:
            resp = client.get("/session-only", headers={"Authorization": "Bearer"})
        assert resp.status_code == 401
