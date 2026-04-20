"""Minimal signing client for the ``bittensor-auth`` example server.

Usage::

    # 1. Start the example server in another shell:
    #    uvicorn examples.server:app --reload
    # 2. Run this script:
    python examples/client.py

The script builds a real SR25519 ``Keypair`` (here using the well-known
``//Alice`` URI — replace with your own wallet in production), wraps an
``httpx`` client with a :class:`SigningTransport`, and calls ``GET /me``.
Every outbound request gets fresh ``X-Hotkey`` / ``X-Timestamp`` /
``X-Nonce`` / ``X-Signature`` headers; the ``/health`` endpoint is skipped
by ``default_is_public_endpoint``.
"""

from __future__ import annotations

from bittensor import Keypair

from bittensor_auth import BittensorAuthClient


def main() -> None:
    # In production: load from ``bittensor_wallet.Wallet(name=..., hotkey=...)``
    # or unlock your coldkey + hotkey pair as you would for any other
    # signed Bittensor interaction.
    keypair = Keypair.create_from_uri("//Alice")

    with BittensorAuthClient(
        base_url="http://localhost:8000",
        signer=keypair,
    ) as client:
        http = client.get_httpx_client()

        health = http.get("/health")
        print(f"/health  -> {health.status_code} {health.json()}")

        me = http.get("/me")
        print(f"/me      -> {me.status_code} {me.text}")


if __name__ == "__main__":
    main()
