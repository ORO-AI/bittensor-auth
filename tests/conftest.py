"""Shared fixtures for the bittensor-auth test suite."""

from __future__ import annotations

import pytest
from bittensor_wallet import Keypair

from bittensor_auth.cache import InMemoryCache
from bittensor_auth.config import BittensorAuthConfig
from bittensor_auth.metagraph import MetagraphCache, MetagraphLike

# Well-known SS58 addresses from the Substrate dev keyring.
ALICE_HOTKEY = "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY"
BOB_HOTKEY = "5FHneW46xGXgs5mUiveU4sbTyGBzmstUspZC92UhjJM694ty"


@pytest.fixture
def alice() -> Keypair:
    return Keypair.create_from_uri("//Alice")


@pytest.fixture
def bob() -> Keypair:
    return Keypair.create_from_uri("//Bob")


@pytest.fixture
def cache() -> InMemoryCache:
    return InMemoryCache()


class FakeMetagraph:
    """Minimal metagraph stub satisfying :class:`MetagraphLike`."""

    def __init__(
        self,
        hotkeys: list[str],
        validator_permit: list[bool],
        stake: list[float],
    ) -> None:
        self.hotkeys = hotkeys
        self.validator_permit = validator_permit
        self.S = stake


class FakeWallet:
    """Duck-typed stand-in for ``bittensor_wallet.Wallet``."""

    def __init__(self, hotkey: Keypair) -> None:
        self.hotkey = hotkey


def make_config(**overrides: object) -> BittensorAuthConfig:
    """Build a BittensorAuthConfig with sensible test defaults."""
    defaults: dict[str, object] = {
        "subnet_netuid": 7,
        "metagraph_refresh_interval": 3600,
        "validator_min_stake": 0.0,
    }
    defaults.update(overrides)
    return BittensorAuthConfig(**defaults)  # type: ignore[arg-type]


def make_metagraph_factories(
    *,
    snapshots: list[FakeMetagraph] | None = None,
    counter: list[int] | None = None,
    raise_on_call: Exception | None = None,
) -> tuple[object, object]:
    """Build (subtensor_factory, metagraph_factory) for tests.

    The metagraph factory returns snapshots[counter[0]] (cycling at the end)
    and increments counter so tests can measure how many syncs have happened.
    """
    if counter is None:
        counter = [0]
    if snapshots is None:
        snapshots = [FakeMetagraph([], [], [])]

    def subtensor_factory(network: str) -> object:
        return object()

    def metagraph_factory(netuid: int, subtensor: object) -> MetagraphLike:
        if raise_on_call is not None:
            raise raise_on_call
        idx = min(counter[0], len(snapshots) - 1)
        counter[0] += 1
        return snapshots[idx]

    return subtensor_factory, metagraph_factory


def make_synced_metagraph_cache(
    *,
    hotkeys: list[str],
    validator_permit: list[bool],
    stake: list[float],
    config: BittensorAuthConfig | None = None,
) -> MetagraphCache:
    """Create and sync a MetagraphCache with a single FakeMetagraph snapshot."""
    snap = FakeMetagraph(hotkeys, validator_permit, stake)

    def subtensor_factory(network: str) -> object:
        return object()

    def metagraph_factory(netuid: int, subtensor: object) -> FakeMetagraph:
        return snap

    if config is None:
        config = BittensorAuthConfig(subnet_netuid=1, validator_min_stake=0.0)

    cache = MetagraphCache(
        config,
        subtensor_factory=subtensor_factory,
        metagraph_factory=metagraph_factory,
    )
    cache.sync_now()
    return cache
