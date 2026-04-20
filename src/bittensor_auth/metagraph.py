"""Background-synced subnet metagraph for registration and validator checks.

Request-path queries read from a cached snapshot and never touch the chain.
Chain clients are dependency-injected via factory callables for testability.
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import contextlib
import logging
import threading
import time
from collections.abc import Callable
from typing import Any, Protocol, runtime_checkable

from .config import BittensorAuthConfig

logger = logging.getLogger(__name__)


@runtime_checkable
class MetagraphLike(Protocol):
    """Minimal protocol satisfied by ``bittensor.Metagraph``."""

    hotkeys: list[str]
    validator_permit: Any
    S: Any


SubtensorFactory = Callable[[str], Any]
"""``(network) -> subtensor_client`` — constructs the chain client."""

MetagraphFactory = Callable[[int, Any], MetagraphLike]
"""``(netuid, subtensor_client) -> metagraph`` — returns a freshly-synced metagraph."""


def _default_subtensor_factory(network: str) -> Any:
    from bittensor import Subtensor

    return Subtensor(network=network)


def _default_metagraph_factory(netuid: int, subtensor: Any) -> MetagraphLike:
    from bittensor import Metagraph

    metagraph = Metagraph(netuid=netuid)
    metagraph.sync(subtensor=subtensor, lite=True)
    return metagraph


class MetagraphCache:
    """In-memory metagraph snapshot with background refresh.

    Lifecycle: ``start()`` -> query methods -> ``stop()``.
    Queries are synchronous; the snapshot is swapped atomically on refresh.
    """

    def __init__(
        self,
        config: BittensorAuthConfig,
        *,
        subtensor_factory: SubtensorFactory = _default_subtensor_factory,
        metagraph_factory: MetagraphFactory = _default_metagraph_factory,
    ) -> None:
        self._config = config
        self._subtensor_factory = subtensor_factory
        self._metagraph_factory = metagraph_factory

        self._metagraph: MetagraphLike | None = None
        self._subtensor: Any = None
        self._chain_lock = threading.Lock()
        self._sync_executor = concurrent.futures.ThreadPoolExecutor(
            max_workers=1, thread_name_prefix="metagraph-sync"
        )
        self._refresh_task: asyncio.Task[None] | None = None
        self._hotkey_index: dict[str, int] = {}
        self._last_synced_at: float | None = None

    @property
    def is_synced(self) -> bool:
        return self._metagraph is not None

    @property
    def metagraph(self) -> MetagraphLike | None:
        return self._metagraph

    @property
    def last_synced_at(self) -> float | None:
        """Unix timestamp of the last successful sync, or ``None`` if never synced.

        Expose this to your monitoring layer to alarm on prolonged chain
        partitions — a silent stale snapshot can freeze ban/deregistration
        state across the fleet.
        """
        return self._last_synced_at

    def seconds_since_last_sync(self) -> float | None:
        """Wall-clock seconds since the last successful sync, or ``None``."""
        if self._last_synced_at is None:
            return None
        return time.time() - self._last_synced_at

    def _is_snapshot_stale(self) -> bool:
        """Return True if the snapshot age exceeds ``metagraph_max_age_seconds``.

        When the limit is zero, staleness checking is disabled.
        """
        max_age = self._config.metagraph_max_age_seconds
        if max_age <= 0:
            return False
        age = self.seconds_since_last_sync()
        return age is not None and age > max_age

    def sync_now(self) -> None:
        """Refresh the cached metagraph from the chain. Never raises."""
        try:
            with self._chain_lock:
                if self._subtensor is None:
                    self._subtensor = self._subtensor_factory(self._config.subtensor_network)
                metagraph = self._metagraph_factory(self._config.subnet_netuid, self._subtensor)
                # Build the hotkey-to-uid index once per sync so request-path
                # queries are O(1) instead of O(n) linear scans. Both the
                # snapshot and index are swapped together under the lock.
                hotkey_index = {hk: i for i, hk in enumerate(metagraph.hotkeys)}
                self._metagraph = metagraph
                self._hotkey_index = hotkey_index
                self._last_synced_at = time.time()
            logger.info(
                "Metagraph synced: %d neurons on netuid %d",
                len(metagraph.hotkeys),
                self._config.subnet_netuid,
            )
        except (OSError, ConnectionError, TimeoutError) as exc:
            logger.warning("Metagraph sync network error: %s", exc)
        except Exception:
            logger.exception("Metagraph sync failed unexpectedly")

    async def start(self) -> None:
        """Run the initial sync and launch the background refresh loop. Idempotent."""
        if self._refresh_task is not None:
            return
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(self._sync_executor, self.sync_now)
        self._refresh_task = asyncio.create_task(self._refresh_loop())
        logger.info("MetagraphCache background sync started")

    async def stop(self) -> None:
        """Cancel the background loop. Recreates executor so start() can be called again."""
        if self._refresh_task is None:
            return
        self._refresh_task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await self._refresh_task
        self._refresh_task = None
        self._sync_executor.shutdown(wait=False)
        # Recreate executor so start() works after stop()
        self._sync_executor = concurrent.futures.ThreadPoolExecutor(
            max_workers=1, thread_name_prefix="metagraph-sync"
        )
        self._subtensor = None
        logger.info("MetagraphCache background sync stopped")

    async def _refresh_loop(self) -> None:
        interval = self._config.metagraph_refresh_interval
        loop = asyncio.get_running_loop()
        while True:
            await asyncio.sleep(interval)
            try:
                await loop.run_in_executor(self._sync_executor, self.sync_now)
            except RuntimeError:
                # Executor already shut down — stop() was called concurrently.
                return

    def _snapshot_or_none(self, op: str, hotkey: str) -> MetagraphLike | None:
        """Return the current snapshot, or ``None`` if unsynced or stale."""
        metagraph = self._metagraph
        if metagraph is None:
            logger.warning(
                "Metagraph not synced; %s(%s...) returning None",
                op,
                hotkey[:16],
            )
            return None
        if self._is_snapshot_stale():
            logger.error(
                "Metagraph snapshot stale (age=%.0fs > max=%ds); %s(%s...) failing closed",
                self.seconds_since_last_sync() or 0.0,
                self._config.metagraph_max_age_seconds,
                op,
                hotkey[:16],
            )
            return None
        return metagraph

    def is_hotkey_registered(self, hotkey: str) -> bool:
        """Return whether ``hotkey`` is registered. ``False`` if unsynced or stale."""
        if self._snapshot_or_none("is_hotkey_registered", hotkey) is None:
            return False
        return hotkey in self._hotkey_index

    def has_validator_permit(self, hotkey: str) -> bool:
        """Check validator permit and stake floor.

        ``False`` if unsynced, snapshot is stale, hotkey not in metagraph,
        permit flag is unset, or stake is below the configured minimum.
        """
        metagraph = self._snapshot_or_none("has_validator_permit", hotkey)
        if metagraph is None:
            return False
        uid = self._hotkey_index.get(hotkey)
        if uid is None:
            return False
        if not bool(metagraph.validator_permit[uid]):
            return False
        min_stake = self._config.validator_min_stake
        if min_stake > 0:
            stake = float(metagraph.S[uid])
            if stake < min_stake:
                logger.warning(
                    "Validator %s... has permit but stake %.2f < %.2f required",
                    hotkey[:16],
                    stake,
                    min_stake,
                )
                return False
        return True

    def get_stake_weight(self, hotkey: str) -> float | None:
        """Return stake weight, or ``None`` if unsynced, stale, or unknown."""
        metagraph = self._snapshot_or_none("get_stake_weight", hotkey)
        if metagraph is None:
            return None
        uid = self._hotkey_index.get(hotkey)
        if uid is None:
            return None
        return float(metagraph.S[uid])
