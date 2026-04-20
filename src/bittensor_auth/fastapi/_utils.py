"""Shared utilities for the FastAPI integration layer."""

from __future__ import annotations

import inspect
from collections.abc import Awaitable, Callable
from typing import Any

RoleResolver = Callable[[str], "str | None | Awaitable[str | None]"]
"""``(hotkey) -> role | None`` — sync or async role lookup."""

BanChecker = Callable[[str, "str | None"], "bool | Awaitable[bool]"]
"""``(hotkey, role) -> is_banned`` — sync or async ban predicate."""


async def maybe_await(value: Any) -> Any:
    if inspect.isawaitable(value):
        return await value
    return value
