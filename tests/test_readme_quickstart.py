"""Smoke test that the README.md quickstart actually runs.

The README advertises a "15-line FastAPI quickstart" that a new subnet
developer can paste into a file and have working auth in minutes. That
promise is only useful if the snippet keeps compiling against the real
public API -- so here we extract the block out of README.md, patch the
default metagraph factories so no real Bittensor node is contacted,
``exec()`` the block to get the ``app`` object, and make signed +
unsigned requests through :class:`fastapi.testclient.TestClient` to
confirm the published contract (200 on signed, 401 on unsigned).

Drift between README snippets and the library will break this test.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import pytest
from bittensor_wallet import Keypair
from fastapi.testclient import TestClient

import bittensor_auth as bittensor_auth_pkg
from bittensor_auth import generate_auth_headers
from bittensor_auth import metagraph as metagraph_module

README = Path(__file__).resolve().parent.parent / "README.md"


def _extract_python_blocks(markdown: str) -> list[str]:
    return re.findall(r"```python\n(.*?)```", markdown, re.DOTALL)


def _quickstart_block() -> str:
    blocks = _extract_python_blocks(README.read_text(encoding="utf-8"))
    for block in blocks:
        if "from fastapi import FastAPI" in block and "auth.require_registered" in block:
            return block
    pytest.fail("Could not locate the FastAPI quickstart block in README.md")


class _FakeMetagraph:
    def __init__(self, hotkeys: list[str]) -> None:
        self.hotkeys = hotkeys
        self.validator_permit = [False] * len(hotkeys)
        self.S = [0.0] * len(hotkeys)


@pytest.fixture
def patched_factories(monkeypatch: pytest.MonkeyPatch, alice: Keypair) -> _FakeMetagraph:
    snapshot = _FakeMetagraph([alice.ss58_address])
    real_cls = metagraph_module.MetagraphCache

    def fake_subtensor(network: str) -> object:
        return object()

    def fake_metagraph(netuid: int, subtensor: Any) -> _FakeMetagraph:
        return snapshot

    class PatchedMetagraphCache(real_cls):  # type: ignore[valid-type,misc]
        def __init__(self, config: Any, **kwargs: Any) -> None:
            kwargs.setdefault("subtensor_factory", fake_subtensor)
            kwargs.setdefault("metagraph_factory", fake_metagraph)
            super().__init__(config, **kwargs)

    monkeypatch.setattr(bittensor_auth_pkg, "MetagraphCache", PatchedMetagraphCache)
    monkeypatch.setattr(metagraph_module, "MetagraphCache", PatchedMetagraphCache)
    return snapshot


def test_readme_quickstart_runs_end_to_end(
    alice: Keypair, patched_factories: _FakeMetagraph
) -> None:
    block = _quickstart_block()
    namespace: dict[str, Any] = {}
    exec(compile(block, "README.md::quickstart", "exec"), namespace)

    app = namespace["app"]
    assert app is not None, "quickstart must define a FastAPI `app`"

    with TestClient(app) as client:
        unsigned = client.get("/me")
        assert unsigned.status_code == 401, unsigned.text

        signed = client.get("/me", headers=generate_auth_headers(alice))
        assert signed.status_code == 200, signed.text
        assert signed.json() == {"hotkey": alice.ss58_address}


def test_quickstart_block_exists_in_readme() -> None:
    block = _quickstart_block()
    for expected in (
        "BittensorAuthConfig",
        "InMemoryCache",
        "MetagraphCache",
        "BittensorAuth",
        "AuthenticatedUser",
        "auth.require_registered",
    ):
        assert expected in block, f"quickstart lost reference to {expected}"
