"""Unit tests for :class:`bittensor_auth.metagraph.MetagraphCache`.

These tests inject fake subtensor + metagraph factories to exercise the
full lifecycle -- initial sync, background refresh, registration and
validator-permit queries, stop semantics -- without a live Bittensor node.
"""

from __future__ import annotations

import asyncio
import threading

import pytest

from bittensor_auth.config import BittensorAuthConfig
from bittensor_auth.metagraph import MetagraphCache, MetagraphLike
from tests.conftest import FakeMetagraph, make_config, make_metagraph_factories


class TestSyncNow:
    def test_populates_metagraph(self) -> None:
        snap = FakeMetagraph(["5HK1"], [True], [100.0])
        stf, mgf = make_metagraph_factories(snapshots=[snap])
        cache = MetagraphCache(make_config(), subtensor_factory=stf, metagraph_factory=mgf)
        assert cache.is_synced is False
        cache.sync_now()
        assert cache.is_synced is True
        assert cache.metagraph is snap

    def test_subtensor_factory_called_once_across_syncs(self) -> None:
        calls: list[str] = []

        def stf(network: str) -> object:
            calls.append(network)
            return object()

        mgf_counter = [0]
        _, mgf = make_metagraph_factories(
            snapshots=[FakeMetagraph([], [], []), FakeMetagraph([], [], [])],
            counter=mgf_counter,
        )
        cache = MetagraphCache(make_config(), subtensor_factory=stf, metagraph_factory=mgf)
        cache.sync_now()
        cache.sync_now()
        assert calls == ["finney"]
        assert mgf_counter[0] == 2

    def test_failure_retains_previous_snapshot(self) -> None:
        first = FakeMetagraph(["5HK1"], [True], [50.0])
        stf, mgf = make_metagraph_factories(snapshots=[first])
        cache = MetagraphCache(make_config(), subtensor_factory=stf, metagraph_factory=mgf)
        cache.sync_now()
        assert cache.metagraph is first

        def exploding_mgf(netuid: int, subtensor: object) -> MetagraphLike:
            raise ConnectionError("boom")

        cache._metagraph_factory = exploding_mgf  # type: ignore[assignment]
        cache.sync_now()
        assert cache.metagraph is first

    def test_never_raises_on_exception(self) -> None:
        stf, mgf = make_metagraph_factories(raise_on_call=RuntimeError("network down"))
        cache = MetagraphCache(make_config(), subtensor_factory=stf, metagraph_factory=mgf)
        cache.sync_now()
        assert cache.is_synced is False


class TestIsHotkeyRegistered:
    def test_unsynced_returns_false(self) -> None:
        stf, mgf = make_metagraph_factories()
        cache = MetagraphCache(make_config(), subtensor_factory=stf, metagraph_factory=mgf)
        assert cache.is_hotkey_registered("5HK1") is False

    def test_registered_true(self) -> None:
        snap = FakeMetagraph(["5HK1", "5HK2"], [False, True], [0.0, 100.0])
        stf, mgf = make_metagraph_factories(snapshots=[snap])
        cache = MetagraphCache(make_config(), subtensor_factory=stf, metagraph_factory=mgf)
        cache.sync_now()
        assert cache.is_hotkey_registered("5HK1") is True
        assert cache.is_hotkey_registered("5HK2") is True

    def test_unregistered_false(self) -> None:
        snap = FakeMetagraph(["5HK1"], [False], [0.0])
        stf, mgf = make_metagraph_factories(snapshots=[snap])
        cache = MetagraphCache(make_config(), subtensor_factory=stf, metagraph_factory=mgf)
        cache.sync_now()
        assert cache.is_hotkey_registered("5UNKNOWN") is False


class TestHasValidatorPermit:
    def test_unsynced_returns_false(self) -> None:
        stf, mgf = make_metagraph_factories()
        cache = MetagraphCache(make_config(), subtensor_factory=stf, metagraph_factory=mgf)
        assert cache.has_validator_permit("5HK1") is False

    def test_unregistered_returns_false(self) -> None:
        snap = FakeMetagraph(["5HK1"], [True], [100.0])
        stf, mgf = make_metagraph_factories(snapshots=[snap])
        cache = MetagraphCache(make_config(), subtensor_factory=stf, metagraph_factory=mgf)
        cache.sync_now()
        assert cache.has_validator_permit("5UNKNOWN") is False

    def test_permit_false_returns_false(self) -> None:
        snap = FakeMetagraph(["5HK1"], [False], [10_000.0])
        stf, mgf = make_metagraph_factories(snapshots=[snap])
        cache = MetagraphCache(make_config(), subtensor_factory=stf, metagraph_factory=mgf)
        cache.sync_now()
        assert cache.has_validator_permit("5HK1") is False

    def test_permit_true_no_stake_floor(self) -> None:
        snap = FakeMetagraph(["5HK1"], [True], [0.0])
        stf, mgf = make_metagraph_factories(snapshots=[snap])
        cache = MetagraphCache(
            make_config(validator_min_stake=0.0),
            subtensor_factory=stf,
            metagraph_factory=mgf,
        )
        cache.sync_now()
        assert cache.has_validator_permit("5HK1") is True

    def test_stake_below_floor_returns_false(self) -> None:
        snap = FakeMetagraph(["5HK1"], [True], [50.0])
        stf, mgf = make_metagraph_factories(snapshots=[snap])
        cache = MetagraphCache(
            make_config(validator_min_stake=100.0),
            subtensor_factory=stf,
            metagraph_factory=mgf,
        )
        cache.sync_now()
        assert cache.has_validator_permit("5HK1") is False

    def test_stake_at_or_above_floor_returns_true(self) -> None:
        snap = FakeMetagraph(["5HK1", "5HK2"], [True, True], [100.0, 150.0])
        stf, mgf = make_metagraph_factories(snapshots=[snap])
        cache = MetagraphCache(
            make_config(validator_min_stake=100.0),
            subtensor_factory=stf,
            metagraph_factory=mgf,
        )
        cache.sync_now()
        assert cache.has_validator_permit("5HK1") is True
        assert cache.has_validator_permit("5HK2") is True


class TestGetStakeWeight:
    def test_unsynced_returns_none(self) -> None:
        stf, mgf = make_metagraph_factories()
        cache = MetagraphCache(make_config(), subtensor_factory=stf, metagraph_factory=mgf)
        assert cache.get_stake_weight("5HK1") is None

    def test_registered_returns_weight(self) -> None:
        snap = FakeMetagraph(["5HK1"], [True], [42.5])
        stf, mgf = make_metagraph_factories(snapshots=[snap])
        cache = MetagraphCache(make_config(), subtensor_factory=stf, metagraph_factory=mgf)
        cache.sync_now()
        assert cache.get_stake_weight("5HK1") == pytest.approx(42.5)

    def test_unregistered_returns_none(self) -> None:
        snap = FakeMetagraph(["5HK1"], [True], [42.5])
        stf, mgf = make_metagraph_factories(snapshots=[snap])
        cache = MetagraphCache(make_config(), subtensor_factory=stf, metagraph_factory=mgf)
        cache.sync_now()
        assert cache.get_stake_weight("5UNKNOWN") is None


class TestLifecycle:
    @pytest.mark.asyncio
    async def test_start_performs_initial_sync(self) -> None:
        snap = FakeMetagraph(["5HK1"], [True], [100.0])
        counter = [0]
        stf, mgf = make_metagraph_factories(snapshots=[snap], counter=counter)
        cache = MetagraphCache(make_config(), subtensor_factory=stf, metagraph_factory=mgf)
        try:
            await cache.start()
            assert cache.is_synced is True
            assert counter[0] == 1
        finally:
            await cache.stop()

    @pytest.mark.asyncio
    async def test_start_is_idempotent(self) -> None:
        snap = FakeMetagraph([], [], [])
        counter = [0]
        stf, mgf = make_metagraph_factories(snapshots=[snap], counter=counter)
        cache = MetagraphCache(make_config(), subtensor_factory=stf, metagraph_factory=mgf)
        try:
            await cache.start()
            await cache.start()
            assert counter[0] == 1
        finally:
            await cache.stop()

    @pytest.mark.asyncio
    async def test_background_refresh_runs(self) -> None:
        snapshots = [FakeMetagraph([f"5HK{i}"], [True], [float(i)]) for i in range(5)]
        counter = [0]
        stf, mgf = make_metagraph_factories(snapshots=snapshots, counter=counter)
        cache = MetagraphCache(
            make_config(metagraph_refresh_interval=0),
            subtensor_factory=stf,
            metagraph_factory=mgf,
        )
        cache._config = BittensorAuthConfig(metagraph_refresh_interval=1)
        try:
            await cache.start()
            await asyncio.sleep(1.2)
            assert counter[0] >= 2
        finally:
            await cache.stop()

    @pytest.mark.asyncio
    async def test_stop_is_idempotent(self) -> None:
        stf, mgf = make_metagraph_factories()
        cache = MetagraphCache(make_config(), subtensor_factory=stf, metagraph_factory=mgf)
        await cache.stop()
        await cache.start()
        await cache.stop()
        await cache.stop()

    @pytest.mark.asyncio
    async def test_stop_before_start_does_not_shutdown_executor(self) -> None:
        stf, mgf = make_metagraph_factories()
        cache = MetagraphCache(make_config(), subtensor_factory=stf, metagraph_factory=mgf)
        await cache.stop()
        try:
            await cache.start()
            assert cache.is_synced is True
        finally:
            await cache.stop()

    @pytest.mark.asyncio
    async def test_sync_uses_dedicated_executor(self) -> None:
        observed_threads: list[str] = []

        def mgf(netuid: int, subtensor: object) -> MetagraphLike:
            observed_threads.append(threading.current_thread().name)
            return FakeMetagraph([], [], [])

        def stf(network: str) -> object:
            return object()

        cache = MetagraphCache(make_config(), subtensor_factory=stf, metagraph_factory=mgf)
        try:
            await cache.start()
            assert observed_threads, "sync_now never executed"
            assert observed_threads[0].startswith("metagraph-sync")
        finally:
            await cache.stop()
