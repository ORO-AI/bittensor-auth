"""End-to-end demo of bittensor-auth.

Each step prints the actual API call being made, pauses so it's readable
in a screen recording, then shows the result.
"""

from __future__ import annotations

import sys
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from bittensor import Keypair
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.testclient import TestClient

from bittensor_auth import (
    BittensorAuthConfig,
    InMemoryCache,
    MetagraphCache,
    SessionStore,
    generate_auth_headers,
)
from bittensor_auth.fastapi import (
    AuthenticatedUser,
    BittensorAuth,
    build_auth_router,
)

PAUSE = 1.5  # seconds between steps


def out(text: str = "") -> None:
    print(text, flush=True)


def header(text: str) -> None:
    out()
    out(f"\033[1;36m{'─' * 60}\033[0m")
    out(f"\033[1;37m  {text}\033[0m")
    out(f"\033[1;36m{'─' * 60}\033[0m")
    time.sleep(PAUSE)


def explain(text: str) -> None:
    out(f"\033[0;90m  {text}\033[0m")


def cmd(text: str) -> None:
    out(f"\033[0;33m  $ {text}\033[0m")


def _truncate_hotkeys(body: dict) -> dict:
    """Shorten hotkey strings in response for cleaner demo output."""
    result = {}
    for k, v in body.items():
        if k == "hotkey" and isinstance(v, str) and len(v) > 16:
            result[k] = v[:8] + "..." + v[-4:]
        elif isinstance(v, dict):
            result[k] = _truncate_hotkeys(v)
        else:
            result[k] = v
    return result


def result(status: int, body: dict) -> None:
    color = "\033[0;32m" if status < 400 else "\033[0;31m"
    out(f"{color}  → {status} {_truncate_hotkeys(body)}\033[0m")
    time.sleep(PAUSE)


# --- Build the app ---

alice = Keypair.create_from_uri("//Alice")
bob = Keypair.create_from_uri("//Bob")


class FakeMetagraph:
    def __init__(self) -> None:
        self.hotkeys = [alice.ss58_address]
        self.validator_permit = [True]
        self.S = [1000.0]


config = BittensorAuthConfig(subnet_netuid=9, subtensor_network="test")
cache = InMemoryCache()
metagraph = MetagraphCache(
    config,
    subtensor_factory=lambda network: None,
    metagraph_factory=lambda netuid, subtensor: FakeMetagraph(),
)
session_store = SessionStore(cache, session_ttl_seconds=3600, challenge_ttl_seconds=60)
auth = BittensorAuth(config=config, cache=cache, metagraph=metagraph)


async def resolve_role(hotkey: str) -> str | None:
    if metagraph.has_validator_permit(hotkey):
        return "validator"
    if metagraph.is_hotkey_registered(hotkey):
        return "user"
    return None


async def require_auth(request: Request) -> AuthenticatedUser:
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        token = auth_header[7:]
        session = await session_store.get_session(token)
        if session is not None:
            return AuthenticatedUser(
                hotkey=session.hotkey, timestamp=0, nonce="", role=session.role,
            )
        raise HTTPException(status_code=401, detail="Invalid or expired session")
    return await auth.require_registered(request)


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    await metagraph.start()
    try:
        yield
    finally:
        await metagraph.stop()


app = FastAPI(lifespan=lifespan)
app.include_router(
    build_auth_router(session_store=session_store, role_resolver=resolve_role),
    prefix="/auth",
)


@app.get("/me")
async def me(user: AuthenticatedUser = Depends(require_auth)) -> dict:
    return {"hotkey": user.hotkey, "role": user.role}


@app.get("/validator-only")
async def validator_only(user: AuthenticatedUser = Depends(auth.require_validator)) -> dict:
    return {"hotkey": user.hotkey, "stake": metagraph.get_stake_weight(user.hotkey)}


# --- Run the demo ---

def main() -> None:
    out("\033[1;37m  bittensor-auth  \033[0;36m— drop-in authentication for Bittensor subnets\033[0m")
    time.sleep(PAUSE)

    with TestClient(app) as client:

        # 1. Unsigned request
        header("GET /me  (no auth headers)")
        explain("Request without any authentication — should be rejected")
        cmd("curl http://localhost:8000/me")
        r = client.get("/me")
        result(r.status_code, r.json())

        # 2. Signed request from registered hotkey
        header("GET /me  (signed by registered hotkey)")
        explain("SR25519 signature from a hotkey registered on the subnet")
        explain("The server verifies the signature, checks metagraph registration")
        cmd("curl -H 'X-Hotkey: 5Grw...' -H 'X-Signature: 0x...' http://localhost:8000/me")
        headers = generate_auth_headers(alice)
        r = client.get("/me", headers=headers)
        result(r.status_code, r.json())

        # 3. Signed request from unregistered hotkey
        header("GET /me  (signed by unregistered hotkey)")
        explain("Valid signature, but this hotkey is NOT registered on the subnet")
        cmd("curl -H 'X-Hotkey: 5FHn...' -H 'X-Signature: 0x...' http://localhost:8000/me")
        headers = generate_auth_headers(bob)
        r = client.get("/me", headers=headers)
        result(r.status_code, r.json())

        # 4. Validator-only endpoint
        header("GET /validator-only  (signed by validator)")
        explain("Endpoint restricted to hotkeys with a validator permit + minimum stake")
        cmd("curl -H 'X-Hotkey: 5Grw...' -H 'X-Signature: 0x...' http://localhost:8000/validator-only")
        headers = generate_auth_headers(alice)
        r = client.get("/validator-only", headers=headers)
        result(r.status_code, r.json())

        # 5. Challenge/session flow
        header("POST /auth/challenge  (start session login)")
        explain("Server issues a one-time challenge string for the wallet to sign")
        explain("This is how browser wallets (polkadot.js) authenticate")
        cmd("curl -X POST -d '{\"hotkey\": \"5Grw...\"}' http://localhost:8000/auth/challenge")
        r = client.post("/auth/challenge", json={"hotkey": alice.ss58_address})
        challenge = r.json()["challenge"]
        result(r.status_code, {"challenge": challenge[:40] + "..."})

        header("POST /auth/session  (exchange signed challenge for token)")
        explain("Client signs the challenge with SR25519, server verifies and issues a session")
        cmd("curl -X POST -d '{\"hotkey\": ..., \"challenge\": ..., \"signature\": ...}' /auth/session")
        sig = "0x" + alice.sign(challenge.encode()).hex()
        r = client.post("/auth/session", json={
            "hotkey": alice.ss58_address,
            "challenge": challenge,
            "signature": sig,
        })
        token = r.json()["session_token"]
        result(r.status_code, {"token": token[:20] + "...", "role": r.json()["role"]})

        header("GET /me  (Bearer token)")
        explain("Using the session token — no need to sign every request")
        cmd(f"curl -H 'Authorization: Bearer {token[:16]}...' http://localhost:8000/me")
        r = client.get("/me", headers={"Authorization": f"Bearer {token}"})
        result(r.status_code, r.json())

        header("POST /auth/logout  (invalidate session)")
        explain("Session is destroyed — token can no longer be used")
        cmd(f"curl -X POST -H 'Authorization: Bearer {token[:16]}...' /auth/logout")
        r = client.post("/auth/logout", headers={"Authorization": f"Bearer {token}"})
        result(r.status_code, r.json())

    out()
    out(f"\033[1;32m  ✓ All flows verified — 0 external dependencies required\033[0m")
    out()
    time.sleep(2)


if __name__ == "__main__":
    main()
