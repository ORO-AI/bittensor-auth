"""End-to-end tests for :func:`bittensor_auth.fastapi.build_auth_router`.

Boots a real FastAPI app over a :class:`SessionStore` backed by
:class:`InMemoryCache` and exercises the challenge -> session -> logout flow
with real SR25519 signatures. No Redis, no Bittensor node required.
"""

from __future__ import annotations

from bittensor import Keypair
from fastapi import FastAPI
from fastapi.testclient import TestClient

from bittensor_auth import InMemoryCache, SessionStore
from bittensor_auth.fastapi import build_auth_router
from tests.test_fastapi.conftest import sign_challenge


def _build_app(
    *,
    role_resolver,
    ban_checker=None,
    challenge_prefix: str = "bittensor-auth",
    session_ttl: int = 7200,
    challenge_ttl: int = 60,
) -> tuple[FastAPI, SessionStore]:
    cache = InMemoryCache()
    store = SessionStore(
        cache,
        session_ttl_seconds=session_ttl,
        challenge_ttl_seconds=challenge_ttl,
    )
    app = FastAPI()
    app.include_router(
        build_auth_router(
            session_store=store,
            role_resolver=role_resolver,
            ban_checker=ban_checker,
            challenge_prefix=challenge_prefix,
        ),
        prefix="/auth",
    )
    return app, store


def _get_challenge(client: TestClient, hotkey: str) -> str:
    """Request a challenge and return the challenge string."""
    return client.post(
        "/auth/challenge", json={"hotkey": hotkey}
    ).json()["challenge"]


def _create_session(
    client: TestClient, keypair: Keypair, challenge: str
) -> dict:
    """Exchange a signed challenge for a session and return the response body."""
    return client.post(
        "/auth/session",
        json={
            "hotkey": keypair.ss58_address,
            "challenge": challenge,
            "signature": sign_challenge(keypair, challenge),
        },
    ).json()


class TestChallenge:
    def test_returns_challenge_and_expiry(self, alice: Keypair) -> None:
        app, _ = _build_app(role_resolver=lambda hk: "user")
        with TestClient(app) as client:
            resp = client.post("/auth/challenge", json={"hotkey": alice.ss58_address})
        assert resp.status_code == 200
        body = resp.json()
        assert body["challenge"].startswith("bittensor-auth:")
        assert isinstance(body["expires_at"], int)
        assert body["expires_at"] > 0

    def test_custom_prefix_applied(self, alice: Keypair) -> None:
        app, _ = _build_app(role_resolver=lambda hk: "user", challenge_prefix="myapp")
        with TestClient(app) as client:
            resp = client.post("/auth/challenge", json={"hotkey": alice.ss58_address})
        assert resp.json()["challenge"].startswith("myapp:")

    def test_invalid_hotkey_returns_400(self) -> None:
        app, _ = _build_app(role_resolver=lambda hk: "user")
        with TestClient(app) as client:
            resp = client.post("/auth/challenge", json={"hotkey": "not-ss58"})
        assert resp.status_code == 400
        assert resp.json()["detail"]["code"] == "INVALID_HOTKEY_FORMAT"

    def test_missing_body_returns_422(self) -> None:
        app, _ = _build_app(role_resolver=lambda hk: "user")
        with TestClient(app) as client:
            resp = client.post("/auth/challenge", json={})
        assert resp.status_code == 422


class TestSession:
    def test_round_trip_issues_session_token(self, alice: Keypair) -> None:
        app, _ = _build_app(role_resolver=lambda hk: "validator")
        with TestClient(app) as client:
            challenge = _get_challenge(client, alice.ss58_address)
            resp = client.post(
                "/auth/session",
                json={
                    "hotkey": alice.ss58_address,
                    "challenge": challenge,
                    "signature": sign_challenge(alice, challenge),
                },
            )
        assert resp.status_code == 200
        body = resp.json()
        assert body["session_token"].startswith("ses_")
        assert body["role"] == "validator"
        assert body["expires_at"] > 0

    def test_challenge_is_single_use(self, alice: Keypair) -> None:
        app, _ = _build_app(role_resolver=lambda hk: "user")
        with TestClient(app) as client:
            challenge = _get_challenge(client, alice.ss58_address)
            body = {
                "hotkey": alice.ss58_address,
                "challenge": challenge,
                "signature": sign_challenge(alice, challenge),
            }
            first = client.post("/auth/session", json=body)
            second = client.post("/auth/session", json=body)
        assert first.status_code == 200
        assert second.status_code == 401
        detail = second.json()["detail"].lower()
        assert "expired" in detail or "invalid" in detail

    def test_unknown_challenge_rejected(self, alice: Keypair) -> None:
        app, _ = _build_app(role_resolver=lambda hk: "user")
        fake_challenge = "bittensor-auth:1700000000:deadbeefdeadbeefdeadbeefdeadbeef"
        with TestClient(app) as client:
            resp = client.post(
                "/auth/session",
                json={
                    "hotkey": alice.ss58_address,
                    "challenge": fake_challenge,
                    "signature": sign_challenge(alice, fake_challenge),
                },
            )
        assert resp.status_code == 401

    def test_malformed_challenge_rejected(self, alice: Keypair) -> None:
        app, _ = _build_app(role_resolver=lambda hk: "user")
        with TestClient(app) as client:
            resp = client.post(
                "/auth/session",
                json={
                    "hotkey": alice.ss58_address,
                    "challenge": "no-colons-here",
                    "signature": "0xdeadbeef",
                },
            )
        assert resp.status_code == 401
        assert "challenge" in resp.json()["detail"].lower()

    def test_hotkey_mismatch_rejected(self, alice: Keypair, bob: Keypair) -> None:
        app, _ = _build_app(role_resolver=lambda hk: "user")
        with TestClient(app) as client:
            challenge = _get_challenge(client, alice.ss58_address)
            resp = client.post(
                "/auth/session",
                json={
                    "hotkey": bob.ss58_address,
                    "challenge": challenge,
                    "signature": sign_challenge(bob, challenge),
                },
            )
        assert resp.status_code == 401
        assert "hotkey" in resp.json()["detail"].lower()

    def test_wrong_signature_rejected(self, alice: Keypair, bob: Keypair) -> None:
        app, _ = _build_app(role_resolver=lambda hk: "user")
        with TestClient(app) as client:
            challenge = _get_challenge(client, alice.ss58_address)
            resp = client.post(
                "/auth/session",
                json={
                    "hotkey": alice.ss58_address,
                    "challenge": challenge,
                    "signature": sign_challenge(bob, challenge),
                },
            )
        assert resp.status_code == 401
        assert "signature" in resp.json()["detail"].lower()

    def test_role_resolver_none_rejects(self, alice: Keypair) -> None:
        app, _ = _build_app(role_resolver=lambda hk: None)
        with TestClient(app) as client:
            challenge = _get_challenge(client, alice.ss58_address)
            resp = client.post(
                "/auth/session",
                json={
                    "hotkey": alice.ss58_address,
                    "challenge": challenge,
                    "signature": sign_challenge(alice, challenge),
                },
            )
        assert resp.status_code == 401
        assert "registered" in resp.json()["detail"].lower()

    def test_async_role_resolver_supported(self, alice: Keypair) -> None:
        async def resolve(hotkey: str) -> str:
            return "async-role"

        app, _ = _build_app(role_resolver=resolve)
        with TestClient(app) as client:
            challenge = _get_challenge(client, alice.ss58_address)
            resp = client.post(
                "/auth/session",
                json={
                    "hotkey": alice.ss58_address,
                    "challenge": challenge,
                    "signature": sign_challenge(alice, challenge),
                },
            )
        assert resp.status_code == 200
        assert resp.json()["role"] == "async-role"

    def test_ban_checker_rejects(self, alice: Keypair) -> None:
        app, _ = _build_app(
            role_resolver=lambda hk: "user",
            ban_checker=lambda hk, role: True,
        )
        with TestClient(app) as client:
            challenge = _get_challenge(client, alice.ss58_address)
            resp = client.post(
                "/auth/session",
                json={
                    "hotkey": alice.ss58_address,
                    "challenge": challenge,
                    "signature": sign_challenge(alice, challenge),
                },
            )
        assert resp.status_code == 403
        assert "ban" in resp.json()["detail"].lower()

    def test_ban_checker_receives_resolved_role(self, alice: Keypair) -> None:
        observed: list[tuple[str, str]] = []

        def ban(hotkey: str, role: str) -> bool:
            observed.append((hotkey, role))
            return False

        app, _ = _build_app(role_resolver=lambda hk: "validator", ban_checker=ban)
        with TestClient(app) as client:
            challenge = _get_challenge(client, alice.ss58_address)
            resp = client.post(
                "/auth/session",
                json={
                    "hotkey": alice.ss58_address,
                    "challenge": challenge,
                    "signature": sign_challenge(alice, challenge),
                },
            )
        assert resp.status_code == 200
        assert observed == [(alice.ss58_address, "validator")]

    def test_async_ban_checker_supported(self, alice: Keypair) -> None:
        async def ban(hotkey: str, role: str) -> bool:
            return True

        app, _ = _build_app(role_resolver=lambda hk: "user", ban_checker=ban)
        with TestClient(app) as client:
            challenge = _get_challenge(client, alice.ss58_address)
            resp = client.post(
                "/auth/session",
                json={
                    "hotkey": alice.ss58_address,
                    "challenge": challenge,
                    "signature": sign_challenge(alice, challenge),
                },
            )
        assert resp.status_code == 403


class TestLogout:
    def _login(self, client: TestClient, keypair: Keypair) -> str:
        """Complete the challenge -> session flow and return the session token."""
        challenge = _get_challenge(client, keypair.ss58_address)
        return client.post(
            "/auth/session",
            json={
                "hotkey": keypair.ss58_address,
                "challenge": challenge,
                "signature": sign_challenge(keypair, challenge),
            },
        ).json()["session_token"]

    def test_logout_invalidates_session(self, alice: Keypair) -> None:
        app, _ = _build_app(role_resolver=lambda hk: "user")
        with TestClient(app) as client:
            token = self._login(client, alice)
            resp = client.post("/auth/logout", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 200
        assert resp.json() == {"success": True}

    def test_logout_missing_header_returns_401(self) -> None:
        app, _ = _build_app(role_resolver=lambda hk: "user")
        with TestClient(app) as client:
            resp = client.post("/auth/logout")
        assert resp.status_code == 401
        assert "authorization" in resp.json()["detail"].lower()

    def test_logout_bad_header_returns_401(self) -> None:
        app, _ = _build_app(role_resolver=lambda hk: "user")
        with TestClient(app) as client:
            resp = client.post("/auth/logout", headers={"Authorization": "Basic abc"})
        assert resp.status_code == 401

    def test_logout_unknown_token_returns_401(self) -> None:
        app, _ = _build_app(role_resolver=lambda hk: "user")
        with TestClient(app) as client:
            resp = client.post(
                "/auth/logout", headers={"Authorization": "Bearer ses_unknowntoken"}
            )
        assert resp.status_code == 401
        assert "session" in resp.json()["detail"].lower()

    def test_logout_twice_rejects_second(self, alice: Keypair) -> None:
        app, _ = _build_app(role_resolver=lambda hk: "user")
        with TestClient(app) as client:
            token = self._login(client, alice)
            first = client.post("/auth/logout", headers={"Authorization": f"Bearer {token}"})
            second = client.post("/auth/logout", headers={"Authorization": f"Bearer {token}"})
        assert first.status_code == 200
        assert second.status_code == 401
