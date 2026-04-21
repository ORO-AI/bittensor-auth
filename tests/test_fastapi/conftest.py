"""Shared fixtures for FastAPI integration tests."""

from __future__ import annotations

from bittensor_wallet import Keypair
from fastapi import Depends, FastAPI

from bittensor_auth import (
    BittensorAuthConfig,
    InMemoryCache,
    SessionStore,
)
from bittensor_auth.fastapi import AuthenticatedUser, BittensorAuth
from tests.conftest import make_synced_metagraph_cache


def build_test_app(auth: BittensorAuth) -> FastAPI:
    """Build a FastAPI app with all standard auth endpoints for testing."""
    app = FastAPI()

    @app.get("/base")
    async def base_endpoint(
        user: AuthenticatedUser = Depends(auth.authenticate),  # noqa: B008
    ) -> dict[str, str | None]:
        return {"hotkey": user.hotkey, "role": user.role}

    @app.get("/registered")
    async def registered_endpoint(
        user: AuthenticatedUser = Depends(auth.require_registered),  # noqa: B008
    ) -> dict[str, str | None]:
        return {"hotkey": user.hotkey, "role": user.role}

    @app.get("/validator")
    async def validator_endpoint(
        user: AuthenticatedUser = Depends(auth.require_validator),  # noqa: B008
    ) -> dict[str, str | None]:
        return {"hotkey": user.hotkey, "role": user.role}

    @app.get("/session-only")
    async def session_endpoint(
        user: AuthenticatedUser = Depends(auth.require_session),  # noqa: B008
    ) -> dict[str, str | None]:
        return {"hotkey": user.hotkey, "role": user.role}

    @app.get("/dual")
    async def dual_endpoint(
        user: AuthenticatedUser = Depends(auth.require_auth),  # noqa: B008
    ) -> dict[str, str | None]:
        return {"hotkey": user.hotkey, "role": user.role}

    return app


def make_auth(
    keypair: Keypair,
    *,
    validator_permit: bool = True,
    stake: float = 100.0,
    role_resolver: object | None = None,
    ban_checker: object | None = None,
    session_store: SessionStore | None = None,
    config: BittensorAuthConfig | None = None,
) -> BittensorAuth:
    """Build a BittensorAuth wired to a single-hotkey metagraph."""
    if config is None:
        config = BittensorAuthConfig()
    metagraph = make_synced_metagraph_cache(
        hotkeys=[keypair.ss58_address],
        validator_permit=[validator_permit],
        stake=[stake],
    )
    kwargs: dict[str, object] = {
        "config": config,
        "cache": InMemoryCache(),
        "metagraph": metagraph,
    }
    if role_resolver is not None:
        kwargs["role_resolver"] = role_resolver
    if ban_checker is not None:
        kwargs["ban_checker"] = ban_checker
    if session_store is not None:
        kwargs["session_store"] = session_store
    return BittensorAuth(**kwargs)  # type: ignore[arg-type]


def make_auth_with_session(
    keypair: Keypair,
) -> tuple[BittensorAuth, SessionStore]:
    """Build a BittensorAuth with a SessionStore for session-based tests."""
    cache = InMemoryCache()
    metagraph = make_synced_metagraph_cache(
        hotkeys=[keypair.ss58_address],
        validator_permit=[True],
        stake=[100.0],
    )
    session_store = SessionStore(cache)
    auth = BittensorAuth(
        config=BittensorAuthConfig(),
        cache=cache,
        metagraph=metagraph,
        session_store=session_store,
    )
    return auth, session_store


def sign_challenge(keypair: Keypair, message: str) -> str:
    """Sign a challenge string and return 0x-prefixed hex signature."""
    return "0x" + keypair.sign(message.encode()).hex()
