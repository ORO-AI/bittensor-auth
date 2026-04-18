"""Minimal FastAPI server using ``bittensor-auth``.

Run it with::

    uvicorn examples.server:app --reload

Then sign a request with ``examples/client.py`` (or any polkadot.js-equipped
browser) and hit ``GET /me``. Unauthenticated requests will be rejected.

This example uses :class:`InMemoryCache` so it runs standalone. For
production, swap in :class:`RedisCache.from_url(...)` so replay-protection
state and sessions are shared across workers.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI

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

config = BittensorAuthConfig(subnet_netuid=9, subtensor_network="finney")
cache = InMemoryCache()
metagraph = MetagraphCache(config)
session_store = SessionStore(cache)
auth = BittensorAuth(
    config=config, cache=cache, metagraph=metagraph, session_store=session_store,
)


async def resolve_role(hotkey: str) -> str | None:
    """Minimal role resolver — anyone registered gets a session."""
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


app = FastAPI(lifespan=lifespan, title="bittensor-auth example")

app.include_router(
    build_auth_router(session_store=session_store, role_resolver=resolve_role),
    prefix="/auth",
)


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/me")
async def me(
    user: AuthenticatedUser = Depends(auth.require_registered),  # noqa: B008
) -> dict[str, str | int]:
    return {"hotkey": user.hotkey, "timestamp": user.timestamp}


@app.get("/validator-only")
async def validator_only(
    user: AuthenticatedUser = Depends(auth.require_validator),  # noqa: B008
) -> dict[str, float | str | None]:
    return {"hotkey": user.hotkey, "stake": metagraph.get_stake_weight(user.hotkey)}
