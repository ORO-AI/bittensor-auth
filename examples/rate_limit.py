"""Example: rate-limiting the ``/challenge`` endpoint with ``slowapi``.

The ``bittensor-auth`` router intentionally does NOT ship a rate limiter —
that's an integrator concern. But ``/challenge`` accepts any SS58-valid
hotkey and stores one cache entry per request, so an unauthenticated
flood can bloat the cache. This example shows a clean pattern:

1. Build a per-IP ``slowapi`` limiter.
2. Expose a *custom* ``POST /auth/challenge`` endpoint decorated with
   ``@limiter.limit(...)``, implemented on top of the low-level
   ``generate_challenge`` + ``SessionStore.store_challenge`` primitives.
3. Mount the stock ``build_auth_router`` for ``/session`` and
   ``/logout``, which don't need rate limiting (they require a valid
   signed challenge).

Run::

    pip install "bittensor-auth[fastapi,redis,client]" slowapi
    python examples/rate_limit.py
    # In another shell:
    curl -X POST http://localhost:8000/auth/challenge \\
         -H 'content-type: application/json' \\
         -d '{"hotkey": "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY"}'

Tuning:

- The per-IP budget bounds a single attacker / misbehaving client.
- For an additional per-hotkey budget, read the request body in a
  dedicated middleware (the body read is async, which ``slowapi``'s
  sync ``key_func`` can't do) and bump an atomic Redis counter keyed
  on the claimed hotkey before forwarding to ``/auth/challenge``.
- Production deployments often just put the rate limit at the ingress
  (nginx, Traefik, AWS WAF), which is simpler and keeps the Python
  process out of the budget-check hot path.
"""

from __future__ import annotations

import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Request, status
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

from bittensor_auth import (
    BittensorAuthConfig,
    InMemoryCache,
    MetagraphCache,
    SessionStore,
    generate_challenge,
    validate_hotkey_format,
)
from bittensor_auth.errors import AuthenticationError
from bittensor_auth.fastapi import build_auth_router
from bittensor_auth.fastapi.router import ChallengeRequest, ChallengeResponse

CHALLENGE_IP_RATE_LIMIT = "10/minute"

limiter = Limiter(key_func=get_remote_address)

cache = InMemoryCache()  # Use RedisCache in production
config = BittensorAuthConfig(subnet_netuid=1)
metagraph = MetagraphCache(config)
session_store = SessionStore(cache)


async def role_resolver(hotkey: str) -> str | None:
    """Return ``"miner"`` for any hotkey registered on the subnet, else ``None``."""
    return "miner" if metagraph.is_hotkey_registered(hotkey) else None


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    await metagraph.start()
    try:
        yield
    finally:
        await metagraph.stop()


app = FastAPI(lifespan=lifespan)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)


@app.post("/auth/challenge", response_model=ChallengeResponse)
@limiter.limit(CHALLENGE_IP_RATE_LIMIT)
async def rate_limited_challenge(
    request: Request,  # required by slowapi to extract the rate-limit key
    body: ChallengeRequest,
) -> ChallengeResponse:
    try:
        validate_hotkey_format(body.hotkey)
    except AuthenticationError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"code": exc.error_code, "message": exc.message},
        ) from exc

    challenge = generate_challenge()
    await session_store.store_challenge(body.hotkey, challenge)
    return ChallengeResponse(
        challenge=challenge,
        expires_at=int(time.time()) + session_store.challenge_ttl_seconds,
    )


# /session and /logout come from the stock router — they require a
# valid signed challenge, so the /challenge rate limit already gates
# the end-to-end flow.
auth_router = build_auth_router(session_store=session_store, role_resolver=role_resolver)
for route in list(auth_router.routes):
    if getattr(route, "path", None) == "/challenge":
        auth_router.routes.remove(route)
app.include_router(auth_router, prefix="/auth")


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=8000)
