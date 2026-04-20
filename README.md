# bittensor-auth

Production-ready Bittensor authentication for Python web frameworks.

`bittensor-auth` is a small, focused library that gives any Bittensor subnet
operator a drop-in authentication layer: SR25519 signature verification,
metagraph-based registration and validator-permit checks, nonce replay
protection, and a challenge/response session flow — with first-class FastAPI
bindings and a signing `httpx` transport for clients.

## Why this exists

Every Bittensor subnet needs to verify SR25519 signatures from hotkeys,
check metagraph registration, protect against nonce replay, and manage
sessions — but there is no standard library for it. Each team rewrites the
same plumbing from scratch.

The Bittensor ecosystem uses several signing conventions:

| Convention | Used by | Message format |
|-----------|---------|----------------|
| **Bittensor native** | Axon/Synapse communication | `nonce.sender.receiver.uuid.body_hash` |
| **Epistula** | SN4 Targon, SN19 Vision | `sha256(body).uuid.timestamp.signed_for` |
| **Colon-separated** | ORO, similar to Chutes | `{hotkey}:{timestamp}:{nonce}` |
| **Custom** | ResiLabs, Taoshi, others | Varies per subnet |

This package provides the **common building blocks** — SR25519 verification,
metagraph caching, nonce replay protection, session management — with a
**pluggable message format** so you can use whichever signing convention
your subnet needs.

It is **not** specific to any subnet. There are no "miner" / "admin"
concepts in the public API, no assumptions about database schema, and no
hard dependency on Redis or any particular web framework.

## Install

```bash
pip install bittensor-auth             # core only
pip install bittensor-auth[fastapi]    # + FastAPI dependencies / router
pip install bittensor-auth[redis]      # + Redis-backed CacheBackend
pip install bittensor-auth[client]     # + httpx signing transport
pip install bittensor-auth[all]        # everything
```

## Quickstart — FastAPI server (15 lines)

```python
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from fastapi import FastAPI, Depends
from bittensor_auth import BittensorAuthConfig, InMemoryCache, MetagraphCache
from bittensor_auth.fastapi import AuthenticatedUser, BittensorAuth

config = BittensorAuthConfig(subnet_netuid=9, subtensor_network="finney")
cache = InMemoryCache()
metagraph = MetagraphCache(config)
auth = BittensorAuth(config=config, cache=cache, metagraph=metagraph)

@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    await metagraph.start()
    try:
        yield
    finally:
        await metagraph.stop()

app = FastAPI(lifespan=lifespan)

@app.get("/me")
async def me(user: AuthenticatedUser = Depends(auth.require_registered)) -> dict:
    return {"hotkey": user.hotkey}
```

That's it. Any request to `GET /me` must carry a valid
`X-Hotkey`/`X-Timestamp`/`X-Nonce`/`X-Signature` quartet produced by a hotkey
that is registered on subnet 9. Unregistered hotkeys get 403; bad signatures,
stale timestamps, and replayed nonces get 401; malformed input gets 400.

> **Note:** `metagraph.start()` performs an initial sync with the Bittensor
> chain, which takes 5-30 seconds depending on the network. The server will
> not accept requests until the sync completes. On `test` or `local`
> networks this is faster.

### Ranking by role: `require_validator`

```python
@app.get("/admin")
async def admin(user: AuthenticatedUser = Depends(auth.require_validator)) -> dict:
    return {"stake": metagraph.get_stake_weight(user.hotkey)}
```

### The full challenge/session flow

If you want long-lived bearer tokens rather than signing every request
(e.g. for browser wallets):

```python
from bittensor_auth import SessionStore
from bittensor_auth.fastapi import build_auth_router

session_store = SessionStore(cache)

# Pass session_store so require_auth and require_session work
auth = BittensorAuth(
    config=config, cache=cache, metagraph=metagraph,
    session_store=session_store,
)

async def resolve_role(hotkey: str) -> str | None:
    if metagraph.has_validator_permit(hotkey):
        return "validator"
    if metagraph.is_hotkey_registered(hotkey):
        return "user"
    return None

app.include_router(
    build_auth_router(session_store=session_store, role_resolver=resolve_role),
    prefix="/auth",
)
```

Mounts `POST /auth/challenge`, `POST /auth/session`, `POST /auth/logout`.

Use `require_auth` on your endpoints to accept **both** bearer tokens and
per-request signing — browser wallets use the session token, server-side
clients sign each request:

```python
@app.get("/me")
async def me(user: AuthenticatedUser = Depends(auth.require_auth)) -> dict:
    return {"hotkey": user.hotkey, "role": user.role}
```

| Dependency | Bearer token | Per-request signing | Use case |
|-----------|-------------|-------------------|----------|
| `auth.require_registered` | No | Yes | Server-to-server APIs |
| `auth.require_validator` | No | Yes | Validator-only endpoints |
| `auth.require_session` | Yes | No | Browser-only endpoints |
| `auth.require_auth` | Yes (preferred) | Fallback | **Most endpoints** |

## Custom message formats

The default signing message is `{hotkey}:{timestamp}:{nonce}` (the
`colon_separated` preset). If your subnet uses a different format, pass a
custom `message_builder` — a function `(hotkey, timestamp, nonce) -> str`:

```python
# Use the dot-separated preset
from bittensor_auth import dot_separated

auth = BittensorAuth(
    config=config, cache=cache, metagraph=metagraph,
    message_builder=dot_separated,  # {hotkey}.{timestamp}.{nonce}
)
```

Or define your own:

```python
def my_subnet_message(hotkey: str, timestamp: str | int, nonce: str) -> str:
    """My subnet signs {nonce}:{hotkey}:{timestamp}."""
    return f"{nonce}:{hotkey}:{timestamp}"

auth = BittensorAuth(
    config=config, cache=cache, metagraph=metagraph,
    message_builder=my_subnet_message,
)
```

The same `message_builder` parameter is accepted by `generate_auth_headers`,
`verify_signature`, `SigningTransport`, `AsyncSigningTransport`, and
`BittensorAuthClient` — client and server must agree on the same builder.

For protocols that include a request body hash (e.g. Epistula), implement a
builder that captures the hash from a higher layer:

```python
def make_epistula_builder(body_hash: str, signed_for: str = "") -> MessageBuilder:
    """Epistula-style: {body_hash}.{nonce}.{timestamp}.{signed_for}

    Call this per-request with the actual body hash, then pass the
    returned builder to verify_signature or generate_auth_headers.
    """
    def builder(hotkey: str, timestamp: str | int, nonce: str) -> str:
        return f"{body_hash}.{nonce}.{timestamp}.{signed_for}"
    return builder
```

## Python client (signing `httpx` transport)

```python
from bittensor import Keypair
from bittensor_auth import BittensorAuthClient

keypair = Keypair.create_from_uri("//Alice")  # or Wallet(name=..., hotkey=...)

with BittensorAuthClient(base_url="https://api.example.com", signer=keypair) as c:
    httpx_client = c.get_httpx_client()
    resp = httpx_client.get("/me")
```

Every non-public request is transparently signed with fresh
`X-Hotkey`/`X-Timestamp`/`X-Nonce`/`X-Signature` headers. Need an async
client? Call `c.get_async_httpx_client()` instead.

If you want to drop your own transport into an existing `httpx.Client`:

```python
import httpx
from bittensor_auth import SigningTransport

client = httpx.Client(
    base_url="https://api.example.com",
    transport=SigningTransport(keypair),
)
```

Or compute headers by hand for a non-`httpx` transport:

```python
from bittensor_auth import generate_auth_headers

headers = generate_auth_headers(keypair)
# {'X-Hotkey': '...', 'X-Timestamp': '...', 'X-Nonce': '...', 'X-Signature': '0x...'}
```

## Browser client (polkadot.js)

```ts
import { stringToHex } from '@polkadot/util';
import { web3FromAddress } from '@polkadot/extension-dapp';

async function signedHeaders(address: string): Promise<Record<string, string>> {
  const timestamp = String(Math.floor(Date.now() / 1000));
  const nonce = crypto.randomUUID();
  const message = `${address}:${timestamp}:${nonce}`;

  const injector = await web3FromAddress(address);
  const { signature } = await injector.signer.signRaw!({
    address,
    data: stringToHex(message),
    type: 'bytes',
  });

  return {
    'X-Hotkey': address,
    'X-Timestamp': timestamp,
    'X-Nonce': nonce,
    'X-Signature': signature, // already 0x-prefixed hex
  };
}
```

The server happily accepts `0x`-prefixed signatures from polkadot.js without
any client-side fixup.

> **Important:** Use `signRaw`, not `signPayload`. The `signPayload` method
> wraps messages with `<Bytes>...</Bytes>` which breaks server-side
> verification. `signRaw` signs the raw hex bytes, which is what the server
> expects.

### Challenge/session flow from the browser

For long-lived sessions instead of per-request signing:

```ts
import { stringToHex } from '@polkadot/util';
import { web3Enable, web3FromAddress } from '@polkadot/extension-dapp';

const API_BASE = 'https://api.your-subnet.com';

async function login(address: string): Promise<string> {
  // 1. Enable the wallet extension
  await web3Enable('My Subnet App');
  const injector = await web3FromAddress(address);

  // 2. Request a challenge from the server
  const challengeResp = await fetch(`${API_BASE}/auth/challenge`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ hotkey: address }),
  });
  const { challenge } = await challengeResp.json();

  // 3. Sign the challenge with the wallet (signRaw, NOT signPayload)
  const { signature } = await injector.signer.signRaw!({
    address,
    data: stringToHex(challenge),
    type: 'bytes',
  });

  // 4. Exchange the signed challenge for a session token
  const sessionResp = await fetch(`${API_BASE}/auth/session`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ hotkey: address, challenge, signature }),
  });
  const { session_token, role } = await sessionResp.json();

  // 5. Use the bearer token for all subsequent requests
  return session_token;
}

// Authenticated request using the session token
async function fetchMe(token: string) {
  const resp = await fetch(`${API_BASE}/me`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  return resp.json();
}
```

## Using Redis in production

Swap `InMemoryCache` for `RedisCache`:

```python
from bittensor_auth import RedisCache

cache = RedisCache.from_url("redis://localhost:6379/0")
```

`RedisCache` wraps `redis.asyncio`. You can also pass a pre-configured
`redis.asyncio.Redis` client if you already manage connections elsewhere —
just construct it with `decode_responses=True`.

## Configuration reference

`BittensorAuthConfig` is a frozen dataclass; all fields have production-safe
defaults and may be overridden per deployment.

| Field | Default | Meaning |
| --- | --- | --- |
| `subnet_netuid` | `1` | Subnet UID registration is checked against. |
| `subtensor_network` | `"finney"` | Network name (`finney`/`test`/`local`) or a `ws(s)://` URL. |
| `timestamp_skew_seconds` | `60` | Clock-skew window; also the nonce replay-protection TTL. |
| `validator_min_stake` | `0.0` | Minimum TAO stake required for `has_validator_permit` to pass. `0` disables the stake check. |
| `metagraph_refresh_interval` | `300` | Seconds between background metagraph syncs. |
| `session_ttl_seconds` | `7200` | Lifetime of session tokens issued by the router. |
| `challenge_ttl_seconds` | `60` | Lifetime of `/challenge` nonces. |
| `max_nonce_length` | `256` | Max character length of client-supplied nonces — defends against cache-key DoS. |
| `recheck_registration_on_session` | `True` | If `True`, Bearer-token auth re-resolves role each request via `role_resolver`. Disable only if you accept role staleness up to `session_ttl_seconds`. |
| `recheck_ban_on_session` | `True` | If `True`, Bearer-token auth rechecks metagraph registration each request. Makes deregistrations take effect immediately. |
| `metagraph_max_age_seconds` | `1200` | Maximum age of the cached metagraph snapshot before queries fail closed. Guards against silent chain partitions freezing ban/registration state. Set to `0` to disable. |

## Session semantics

The package offers two authentication modes and they have different freshness contracts:

- **Per-request signing** (`authenticate`, `require_registered`, `require_validator`) — every request re-runs signature verification, metagraph registration, and the ban check. The request is as fresh as the metagraph snapshot.

- **Bearer-token sessions** (`require_session`, `require_auth`) — the challenge/response flow exchanges a signed challenge for a short-lived Bearer token stored server-side. By default the role and registration are re-checked on every request (`recheck_registration_on_session=True`, `recheck_ban_on_session=True`), so a hotkey that deregisters from the subnet loses access on its next call. If you opt out of these flags, role and registration are frozen at session-creation time for up to `session_ttl_seconds` (default 2 h) — only flip them off if you have an explicit reason.

Banning a hotkey calls `SessionStore.revoke_all_sessions`, which uses the atomic `smembers_and_delete` primitive so there's no classic check-then-delete race. A truly concurrent `create_session` can still land a session in a fresh index after revocation finishes; pair `revoke_all_sessions` with a per-request `ban_checker` to catch that survivor on its next call. See `SECURITY.md` for the full threat model.

## Deployment requirements

The package covers authentication; a few adjacent concerns are **your** responsibility:

- **Rate-limit `/challenge`.** The endpoint only format-validates the claimed hotkey, so anyone who can reach the server can create cache entries. Put a rate limiter (ingress or framework level) in front of it — a per-IP budget on the order of 10–30 req/min and a per-hotkey budget of a handful per minute is a sensible starting point.
- **Use `RedisCache` in production.** `InMemoryCache` is process-local (sessions/nonces don't cross workers) and has no background sweeper. It's for tests and single-process development only.
- **Monitor `MetagraphCache.last_synced_at`.** Expose the staleness in your alerting so you hear about a chain-endpoint partition before requests start failing closed.
- **Keep `verify_ssl=True` on the client.** The SDK transport defaults to TLS verification; don't flip it off in production.

## Public API at a glance

```python
# Core primitives (framework-agnostic)
from bittensor_auth import (
    BittensorAuthConfig, AuthErrorCode, AuthenticationError,
    verify_sr25519, validate_hotkey_format, parse_signature,
    construct_signing_message, validate_timestamp, verify_signature,
    MessageBuilder, colon_separated, dot_separated,
    CacheBackend, InMemoryCache, RedisCache,
    NonceTracker,
    MetagraphCache, MetagraphLike,
    SessionStore, SessionData, ChallengeData,
    generate_session_token, generate_challenge, extract_nonce_from_challenge,
)

# Client transport (requires bittensor-auth[client])
from bittensor_auth import (
    BittensorAuthClient, SigningTransport, AsyncSigningTransport,
    generate_auth_headers, default_is_public_endpoint,
)

# FastAPI integration (requires bittensor-auth[fastapi])
from bittensor_auth.fastapi import (
    BittensorAuth, AuthenticatedUser, RoleResolver, BanChecker,
    HEADER_HOTKEY, HEADER_TIMESTAMP, HEADER_NONCE, HEADER_SIGNATURE,
    build_auth_router,
    ChallengeRequest, ChallengeResponse,
    SessionRequest, SessionResponse, LogoutResponse,
    auth_error_to_http,
)
```

## Migrating from an inline auth middleware

If your subnet already has hand-rolled auth code, the most mechanical
migration path is:

1. Replace your `verify_signature(hotkey, timestamp, nonce, signature)` helper
   with `bittensor_auth.verify_signature` — the signing message format and
   header names are already the ecosystem standard.
2. Swap your Redis replay-protection code for `NonceTracker` — it uses
   `set_if_not_exists` for single-round-trip atomicity.
3. Replace your metagraph-sync loop with `MetagraphCache.start()` — drop the
   manual `ThreadPoolExecutor` and websocket locking.
4. For FastAPI, replace `@requires_auth` decorators with
   `Depends(auth.require_registered)` / `Depends(auth.require_validator)`.

The `AuthErrorCode` enum values match the de-facto codes most subnets already
emit (`NOT_REGISTERED`, `TIMESTAMP_SKEW`, `NONCE_REUSED`, …), so clients that
parse the old error codes keep working.

## What this package explicitly does NOT do

- **Rate limiting.** That belongs in host middleware (`slowapi`, nginx,
  CloudFront, …). Wrapping the router with a rate-limit library would couple
  every consumer to that library's lifecycle.
- **User/validator databases.** `role_resolver` and `ban_checker` are hooks;
  your application decides what a "role" is and where it's stored.
- **Opinionated retry/backoff on the client.** `BittensorAuthClient` gives
  you a wired `httpx` client; wrap it in your own retry transport if you need
  one.

## Examples

- `examples/server.py` — minimal FastAPI server with `/me` + the session router
- `examples/client.py` — Python client signing requests with `SigningTransport`

## License

Apache-2.0.
