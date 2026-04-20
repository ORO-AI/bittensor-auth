"""Tests for BittensorAuthConfig."""

from __future__ import annotations

from dataclasses import FrozenInstanceError

import pytest

from bittensor_auth.config import BittensorAuthConfig


def test_default_values() -> None:
    cfg = BittensorAuthConfig()
    assert cfg.subnet_netuid == 1
    assert cfg.subtensor_network == "finney"
    assert cfg.timestamp_skew_seconds == 60
    assert cfg.validator_min_stake == 0.0
    assert cfg.metagraph_refresh_interval == 300
    assert cfg.session_ttl_seconds == 7200
    assert cfg.challenge_ttl_seconds == 60
    assert cfg.max_nonce_length == 256


def test_overrides() -> None:
    cfg = BittensorAuthConfig(
        subnet_netuid=42,
        subtensor_network="test",
        validator_min_stake=1000.0,
    )
    assert cfg.subnet_netuid == 42
    assert cfg.subtensor_network == "test"
    assert cfg.validator_min_stake == 1000.0
    assert cfg.timestamp_skew_seconds == 60


def test_is_frozen() -> None:
    cfg = BittensorAuthConfig()
    with pytest.raises(FrozenInstanceError):
        cfg.subnet_netuid = 99  # type: ignore[misc]
