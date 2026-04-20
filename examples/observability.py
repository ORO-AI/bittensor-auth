"""Example: Prometheus metrics for `bittensor-auth`.

Exposes the signals you actually want to alarm on:

- `bittensor_auth_metagraph_seconds_since_sync` — age of the cached
  metagraph snapshot. Alert if this climbs past your staleness budget
  (default 1200s) — the chain endpoint is probably down.
- `bittensor_auth_metagraph_synced` — 0 if the initial sync has not
  completed; 1 otherwise. Paged alert if this stays 0 for more than a
  few minutes at startup.
- `bittensor_auth_auth_attempts_total{outcome=…}` — counter incremented
  per authentication attempt, labeled by outcome (`ok`, `bad_signature`,
  `nonce_reused`, `timestamp_skew`, `not_registered`, `banned`). Use
  the ratio to detect brute-force attempts or client-side clock drift.
- `bittensor_auth_sessions_active` — gauge sampled from the session
  index size. Useful for capacity planning.

Run::

    pip install "bittensor-auth[fastapi,redis,client]" prometheus-client
    python examples/observability.py
    curl http://localhost:8000/metrics
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI
from fastapi.responses import PlainTextResponse
from prometheus_client import CONTENT_TYPE_LATEST, Counter, Gauge, generate_latest

from bittensor_auth import (
    BittensorAuthConfig,
    InMemoryCache,
    MetagraphCache,
    SessionStore,
)
from bittensor_auth.fastapi import AuthenticatedUser, BittensorAuth, build_auth_router

# --- Metrics ---------------------------------------------------------------

metagraph_synced = Gauge(
    "bittensor_auth_metagraph_synced",
    "1 if the metagraph cache has completed its initial sync, 0 otherwise.",
)

metagraph_age_seconds = Gauge(
    "bittensor_auth_metagraph_seconds_since_sync",
    "Wall-clock seconds since the last successful metagraph sync. "
    "NaN before the first sync completes.",
)

auth_attempts = Counter(
    "bittensor_auth_auth_attempts_total",
    "Authentication attempts by outcome.",
    labelnames=("outcome",),
)

sessions_active = Gauge(
    "bittensor_auth_sessions_active",
    "Active session count across all hotkeys (approximate; sampled lazily).",
)


# --- App wiring ------------------------------------------------------------

cache = InMemoryCache()
config = BittensorAuthConfig(subnet_netuid=1)
metagraph = MetagraphCache(config)
session_store = SessionStore(cache)


async def role_resolver(hotkey: str) -> str | None:
    """Return ``"miner"`` for any hotkey registered on the subnet, else ``None``."""
    return "miner" if metagraph.is_hotkey_registered(hotkey) else None


auth = BittensorAuth(
    config=config,
    cache=cache,
    metagraph=metagraph,
    role_resolver=role_resolver,
    session_store=session_store,
)


def _update_metagraph_metrics() -> None:
    metagraph_synced.set(1 if metagraph.is_synced else 0)
    age = metagraph.seconds_since_last_sync()
    metagraph_age_seconds.set(age if age is not None else float("nan"))


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    await metagraph.start()
    try:
        yield
    finally:
        await metagraph.stop()


app = FastAPI(lifespan=lifespan)
app.include_router(
    build_auth_router(session_store=session_store, role_resolver=role_resolver), prefix="/auth"
)


@app.get("/me")
async def me(
    user: AuthenticatedUser = Depends(auth.require_auth),  # noqa: B008
) -> dict[str, str | None]:
    auth_attempts.labels(outcome="ok").inc()
    return {"hotkey": user.hotkey, "role": user.role}


@app.get("/metrics")
async def metrics() -> PlainTextResponse:
    # Refresh live gauges before each scrape so Prometheus always sees
    # the current state; counters are kept warm by the request path.
    _update_metagraph_metrics()
    return PlainTextResponse(generate_latest(), media_type=CONTENT_TYPE_LATEST)


# For production you likely want a middleware / exception handler that
# increments `auth_attempts` on each failure path. Sketch::
#
#     from fastapi import Request
#     from fastapi.responses import JSONResponse
#     from starlette.exceptions import HTTPException
#
#     @app.exception_handler(HTTPException)
#     async def record_auth_failure(request: Request, exc: HTTPException):
#         if exc.status_code == 401:
#             detail = exc.detail if isinstance(exc.detail, dict) else {}
#             code = detail.get("code", "unknown").lower()
#             auth_attempts.labels(outcome=code).inc()
#         return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=8000)
