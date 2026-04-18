"""Configuration for bittensor-auth."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class BittensorAuthConfig:
    """All fields have sensible defaults. Override per-deployment as needed.

    Attributes:
        subnet_netuid: Subnet UID to check hotkey registration against.
        subtensor_network: Network name (``finney``, ``test``, ``local``)
            or a ``ws://``/``wss://`` URL for a custom subtensor endpoint.
        timestamp_skew_seconds: Allowed clock skew (seconds). Also the nonce TTL.
        validator_min_stake: Minimum stake (TAO) for validator checks. ``0`` disables.
        metagraph_refresh_interval: Background sync interval (seconds).
        session_ttl_seconds: Session token lifetime (seconds).
        challenge_ttl_seconds: Challenge nonce lifetime (seconds).
        max_nonce_length: Max nonce length to prevent DoS via oversized cache keys.
    """

    subnet_netuid: int = 1
    subtensor_network: str = "finney"
    timestamp_skew_seconds: int = 60
    validator_min_stake: float = 0.0
    metagraph_refresh_interval: int = 300
    session_ttl_seconds: int = 7200
    challenge_ttl_seconds: int = 60
    max_nonce_length: int = 256
