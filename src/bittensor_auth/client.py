"""Client-side Bittensor authentication: ``httpx`` transports that sign
outbound requests with SR25519. Requires ``bittensor-auth[client]``.
"""

from __future__ import annotations

import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable
from urllib.parse import urlparse

import httpx

if TYPE_CHECKING:  # pragma: no cover - typing only
    from types import TracebackType

    from .signing import MessageBuilder


__all__ = [
    "AsyncSigningTransport",
    "BittensorAuthClient",
    "IsPublicEndpoint",
    "Signer",
    "SigningTransport",
    "default_is_public_endpoint",
    "generate_auth_headers",
]


@runtime_checkable
class Signer(Protocol):
    """Satisfied by ``bittensor.Keypair`` and ``Wallet.hotkey``."""

    ss58_address: str

    def sign(self, data: bytes) -> bytes: ...


IsPublicEndpoint = Callable[[str], bool]


def _resolve_signer(signer_or_wallet: Any) -> Signer:
    """Unwrap a ``Wallet`` to its ``hotkey``; pass through ``Keypair`` directly."""
    if hasattr(signer_or_wallet, "hotkey") and not hasattr(signer_or_wallet, "sign"):
        return signer_or_wallet.hotkey  # type: ignore[no-any-return]
    return signer_or_wallet  # type: ignore[no-any-return]


def default_is_public_endpoint(url: str | None) -> bool:
    """Skip auth for ``/health`` only. Pass a custom predicate for other public paths."""
    if not url:
        return False
    try:
        pathname = urlparse(url).path or url
    except Exception:
        pathname = url
    return pathname == "/health" or pathname.endswith("/health")


def generate_auth_headers(
    signer_or_wallet: Any,
    nonce: str | None = None,
    *,
    timestamp: int | None = None,
    message_builder: MessageBuilder | None = None,
) -> dict[str, str]:
    """Return ``X-Hotkey``, ``X-Timestamp``, ``X-Nonce``, ``X-Signature`` headers."""
    from .signing import colon_separated

    signer = _resolve_signer(signer_or_wallet)
    builder = message_builder or colon_separated
    hotkey = signer.ss58_address
    ts = str(int(time.time()) if timestamp is None else int(timestamp))
    n = nonce if nonce is not None else str(uuid.uuid4())
    message = builder(hotkey, ts, n)
    signature_hex = signer.sign(message.encode()).hex()
    return {
        "X-Hotkey": hotkey,
        "X-Timestamp": ts,
        "X-Nonce": n,
        "X-Signature": f"0x{signature_hex}",
    }


class SigningTransport(httpx.BaseTransport):
    """Sync ``httpx`` transport that signs every non-public outbound request."""

    def __init__(
        self,
        signer_or_wallet: Any,
        wrapped: httpx.BaseTransport | None = None,
        *,
        is_public_endpoint: IsPublicEndpoint | None = None,
        message_builder: MessageBuilder | None = None,
    ) -> None:
        self._signer = _resolve_signer(signer_or_wallet)
        self._wrapped = wrapped if wrapped is not None else httpx.HTTPTransport()
        self._is_public_endpoint = is_public_endpoint or default_is_public_endpoint
        self._message_builder = message_builder

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        if not self._is_public_endpoint(str(request.url)):
            headers = generate_auth_headers(
                self._signer, message_builder=self._message_builder
            )
            for key, value in headers.items():
                request.headers[key] = value
        return self._wrapped.handle_request(request)

    def close(self) -> None:
        self._wrapped.close()


class AsyncSigningTransport(httpx.AsyncBaseTransport):
    """Async ``httpx`` transport that signs every non-public outbound request."""

    def __init__(
        self,
        signer_or_wallet: Any,
        wrapped: httpx.AsyncBaseTransport | None = None,
        *,
        is_public_endpoint: IsPublicEndpoint | None = None,
        message_builder: MessageBuilder | None = None,
    ) -> None:
        self._signer = _resolve_signer(signer_or_wallet)
        self._wrapped = wrapped if wrapped is not None else httpx.AsyncHTTPTransport()
        self._is_public_endpoint = is_public_endpoint or default_is_public_endpoint
        self._message_builder = message_builder

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        if not self._is_public_endpoint(str(request.url)):
            headers = generate_auth_headers(
                self._signer, message_builder=self._message_builder
            )
            for key, value in headers.items():
                request.headers[key] = value
        return await self._wrapped.handle_async_request(request)

    async def aclose(self) -> None:
        await self._wrapped.aclose()


@dataclass
class BittensorAuthClient:
    """Convenience ``httpx`` client pre-wired with a signing transport.

    Lazily constructs sync/async clients on first use.
    """

    base_url: str
    signer: Any
    timeout: httpx.Timeout | float | None = None
    verify_ssl: bool = True
    headers: dict[str, str] = field(default_factory=dict)
    is_public_endpoint: IsPublicEndpoint | None = None
    message_builder: MessageBuilder | None = None

    _client: httpx.Client | None = field(default=None, init=False, repr=False)
    _async_client: httpx.AsyncClient | None = field(default=None, init=False, repr=False)

    def get_httpx_client(self) -> httpx.Client:
        if self._client is None:
            transport = SigningTransport(
                self.signer,
                is_public_endpoint=self.is_public_endpoint,
                message_builder=self.message_builder,
            )
            self._client = httpx.Client(
                base_url=self.base_url,
                timeout=self.timeout,
                verify=self.verify_ssl,
                headers=self.headers,
                transport=transport,
            )
        return self._client

    def get_async_httpx_client(self) -> httpx.AsyncClient:
        if self._async_client is None:
            transport = AsyncSigningTransport(
                self.signer,
                is_public_endpoint=self.is_public_endpoint,
                message_builder=self.message_builder,
            )
            self._async_client = httpx.AsyncClient(
                base_url=self.base_url,
                timeout=self.timeout,
                verify=self.verify_ssl,
                headers=self.headers,
                transport=transport,
            )
        return self._async_client

    def __enter__(self) -> BittensorAuthClient:
        self.get_httpx_client().__enter__()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        if self._client is not None:
            self._client.__exit__(exc_type, exc, tb)

    async def __aenter__(self) -> BittensorAuthClient:
        await self.get_async_httpx_client().__aenter__()
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        if self._async_client is not None:
            await self._async_client.__aexit__(exc_type, exc, tb)
