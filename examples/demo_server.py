"""Demo server for screen recordings and browser wallet demos.

Runs a real FastAPI server with bittensor-auth. Uses a fake metagraph so
no Bittensor node is needed — any valid SR25519 signature is accepted.

Usage::

    uvicorn examples.demo_server:app --port 8000

Then open examples/browser-demo.html in a browser, or run examples/client.py.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Depends, FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse

from bittensor_auth import (
    BittensorAuthConfig,
    InMemoryCache,
    MetagraphCache,
    SessionStore,
)
from bittensor_auth.fastapi import (
    AuthenticatedUser,
    BittensorAuth,
    build_auth_router,
)

# --- Fake metagraph: accepts any hotkey as registered ---


class OpenMetagraph:
    """A metagraph where everyone is registered. For demos only."""

    def __init__(self) -> None:
        self.hotkeys: list[str] = []
        self.validator_permit: list[bool] = []
        self.S: list[float] = []

    def add(self, hotkey: str) -> None:
        if hotkey not in self.hotkeys:
            self.hotkeys.append(hotkey)
            self.validator_permit.append(True)
            self.S.append(1000.0)


_open_metagraph = OpenMetagraph()

config = BittensorAuthConfig(subnet_netuid=1, subtensor_network="test")
cache = InMemoryCache()
metagraph = MetagraphCache(
    config,
    subtensor_factory=lambda network: None,
    metagraph_factory=lambda netuid, subtensor: _open_metagraph,
)
session_store = SessionStore(cache, session_ttl_seconds=3600, challenge_ttl_seconds=120)
auth = BittensorAuth(
    config=config,
    cache=cache,
    metagraph=metagraph,
    session_store=session_store,
)


async def resolve_role(hotkey: str) -> str | None:
    """Auto-register any hotkey that connects. Demo only."""
    _open_metagraph.add(hotkey)
    if metagraph.has_validator_permit(hotkey):
        return "validator"
    if metagraph.is_hotkey_registered(hotkey):
        return "user"
    return None


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    await metagraph.start()
    try:
        yield
    finally:
        await metagraph.stop()


app = FastAPI(lifespan=lifespan, title="bittensor-auth demo")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(
    build_auth_router(session_store=session_store, role_resolver=resolve_role),
    prefix="/auth",
)


@app.get("/")
async def index() -> FileResponse:
    """Serve the browser demo page."""
    return FileResponse(Path(__file__).parent / "browser-demo.html")


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/me")
async def me(
    user: AuthenticatedUser = Depends(auth.require_auth),  # noqa: B008
) -> dict[str, str | int | float | None]:
    """Accepts both Bearer token and per-request signing."""
    return {
        "hotkey": user.hotkey,
        "role": user.role,
        "stake": metagraph.get_stake_weight(user.hotkey),
    }
