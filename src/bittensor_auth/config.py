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
    # If True, Bearer-token session authentication re-checks the caller's
    # subnet registration / validator permit on every request instead of
    # trusting the role cached at session creation. Makes deregistrations
    # and permit revocations take effect within one request instead of
    # waiting up to session_ttl_seconds. Slight per-request cost (a
    # metagraph-cache lookup; no chain round-trip).
    recheck_registration_on_session: bool = True
    # If True, a session whose underlying hotkey falls out of the
    # metagraph is rejected immediately. Also a slight per-request cost
    # (same metagraph lookup as above).
    recheck_ban_on_session: bool = True
    # Maximum age of the cached metagraph snapshot (seconds) before the
    # cache is treated as stale and queries fail closed. Defaults to
    # 4x the refresh interval, which tolerates a few consecutive sync
    # failures but still alarms if the chain endpoint is wholly down.
    # Set to 0 to disable the staleness check (not recommended in prod).
    metagraph_max_age_seconds: int = 1200
    # If True, all 401 authentication failures return a single opaque
    # ``UNAUTHORIZED`` code to clients instead of distinct codes like
    # ``INVALID_SIGNATURE`` / ``NONCE_REUSED`` / ``TIMESTAMP_SKEW``.
    # Collapses a low-severity enumeration side channel at the cost of
    # slightly less helpful client-facing errors. Server logs retain
    # the specific error code either way. Disabled by default to keep
    # existing behavior; enable for deployments that surface these
    # errors directly to untrusted clients.
    collapse_auth_error_codes: bool = False
