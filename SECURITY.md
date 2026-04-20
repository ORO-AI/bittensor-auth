# Security notes for `bittensor-auth`

This document captures the threat model the package is designed to resist, the assumptions it places on the integrator, and the review history that has shaped the current implementation. If you are wiring `bittensor-auth` into a production service, skim the Integrator requirements section first.

## Reporting a vulnerability

Email `team@oroagents.com` with a clear description of the issue, a reproduction, and an impact assessment. Please do not open a public GitHub issue for exploitable findings. We aim to acknowledge within two business days and to coordinate a fix and disclosure timeline with you before publication.

## Threat model

The package provides two authentication primitives with distinct threat profiles:

1. **Per-request signing** — every authenticated request carries `X-Hotkey`, `X-Timestamp`, `X-Nonce`, `X-Signature` headers. The signature is an SR25519 signature over `{hotkey}:{timestamp}:{nonce}` (default) produced by the hotkey's keypair. The server verifies the signature, the timestamp's skew, and the nonce's uniqueness under the hotkey.

2. **Challenge / session** — the client requests a challenge, signs it once, and exchanges the signed challenge for a short-lived Bearer token. Subsequent requests present only the Bearer token.

Threats the package is designed to resist:

| Threat | How it's resisted |
|---|---|
| Signature forgery | SR25519 verification via `bittensor.Keypair.verify`; no homegrown crypto. |
| Replay of a signed request | Nonce registered under `(hotkey, nonce)` with TTL ≥ the timestamp-skew window; atomic `set_if_not_exists` on the cache backend. TTL < skew is refused at `NonceTracker` construction. |
| Replay outside the skew window | `validate_timestamp` rejects anything outside ±`timestamp_skew_seconds`. |
| Cross-hotkey challenge reuse | The challenge is stored server-side indexed by its nonce; the `/session` endpoint rejects if the claimed hotkey doesn't match the stored challenge's owner. |
| One-time-use challenges | Atomic `getdel` against the cache — two concurrent `/session` calls for the same challenge produce exactly one success. |
| Cross-role ban evasion via stolen session | When a hotkey is banned, sessions for that hotkey are bulk-revoked via atomic `smembers_and_delete`. See the *Residual race* note below. |
| Stale session after deregistration / permit change | When `recheck_registration_on_session=True` (default), Bearer-token auth re-queries the metagraph cache each request; deregistered hotkeys are rejected immediately. |
| Stale metagraph during chain partition | `MetagraphCache` refuses to serve snapshots older than `metagraph_max_age_seconds` (default 4× the refresh interval). Queries fail closed under prolonged chain outages. |
| Malformed input DoS | Hotkey format, timestamp, nonce length, and signature hex are all bounded before reaching SR25519 verify. Oversized nonces are rejected before they hit the cache. |

Threats **not** handled by the package — you must layer defenses:

| Threat | Where it lives |
|---|---|
| Unauthenticated flood of `/challenge` | Rate limit at the framework / ingress (see *Integrator requirements*). The endpoint only format-validates the claimed hotkey, so a low-rate-limit is required to prevent cache pressure. |
| TLS / transport security | `httpx` defaults are used. Adopters running public endpoints must front the service with TLS and leave `verify_ssl=True`. |
| Key custody | The package never touches secret keys — it delegates signing to `bittensor.Keypair`. Clients are responsible for secure storage. |

## Residual race — `revoke_all_sessions`

`SessionStore.revoke_all_sessions(hotkey)` uses the atomic `smembers_and_delete` primitive to list and drop every session in one step, so the classic check-then-delete race is closed. A truly concurrent `create_session(hotkey, ...)` issued *after* `smembers_and_delete` returns will land in a fresh index key and survive revocation — there is no way to prevent this at the cache layer without a distributed lock.

Recommended defense in depth: pair revocation with a per-request ban check so a survived session is caught on its next use. This is what `BittensorAuth(..., ban_checker=…)` provides. Adopters who cannot tolerate the window (e.g., legal compliance requirements) should take an additional lock around ban + revocation at the application layer.

## Integrator requirements

Running `bittensor-auth` safely in production requires the following configuration:

1. **Redis backend, not `InMemoryCache`.** `InMemoryCache` is process-local (sessions/nonces don't cross workers) and has no background sweeper. Use it only for tests and single-process development.

2. **Rate-limit `/challenge`.** The endpoint accepts any SS58-valid hotkey and stores one cache entry per request. Put a rate limiter (ingress-level or framework-level) in front of it. A sensible default is a per-IP budget on the order of 10–30 requests per minute and a per-hotkey budget of a handful per minute.

3. **`timestamp_skew_seconds` small.** 60 seconds is the default and is usually enough for real-world clock drift. Increasing it widens the replay window for captured signatures; don't push it beyond what your client population needs.

4. **`metagraph_max_age_seconds` set and monitored.** The default (`4 × metagraph_refresh_interval`) tolerates a few consecutive sync failures but alarms if the chain endpoint is wholly down. Expose `MetagraphCache.last_synced_at` in your monitoring so you can alarm on staleness before requests begin failing closed.

5. **Pair `revoke_all_sessions` with `ban_checker`.** As noted in *Residual race*, a concurrent session creation can survive revocation. A `ban_checker` on the per-request path closes the window on next use.

6. **Don't downgrade the default `recheck_*_on_session` flags without understanding the trade-off.** The defaults cost one metagraph-cache lookup per authenticated request (in-memory, no chain round-trip). Disabling them freezes role and registration at session creation for up to `session_ttl_seconds`.

## Reviewed scope

As of `v0.1.0 + security hardening`, the following code paths have been reviewed end-to-end:

- `core.py` — SR25519 verify, hotkey SS58 decode
- `signing.py` — timestamp/skew validation, message builders
- `nonce.py` — replay prevention, TTL vs skew invariant
- `session.py` — challenge/session lifecycle, `getdel`, `smembers_and_delete`
- `cache.py` — in-memory + Redis backends, atomic primitives
- `metagraph.py` — background sync, staleness floor, O(1) hotkey index
- `fastapi/router.py` — challenge/session/logout endpoints
- `fastapi/dependencies.py` — per-request and session-based FastAPI dependencies
- `client.py` — `SigningTransport`, `generate_auth_headers`, `default_is_public_endpoint`

Out of scope for the package's review (handled by the adopter):

- TLS / transport security
- Rate limiting / WAF
- Key custody on the client side
- Any authorization decision past the role returned by `role_resolver`

## Changelog

**v0.1.x — security hardening (post-initial-release review)**

- Pinned `bittensor` to the 8.x line (`>=8.0.0,<9.0.0`) — a major bump could change `Keypair.verify` semantics silently.
- Added `recheck_registration_on_session` and `recheck_ban_on_session` config flags (default `True`): Bearer-token auth now re-resolves role and rechecks registration on every request.
- Added `MetagraphCache.last_synced_at` and `seconds_since_last_sync()` for integrator monitoring; `metagraph_max_age_seconds` fails closed when snapshots age out.
- Added `CacheBackend.smembers_and_delete` atomic primitive; `SessionStore.revoke_all_sessions` no longer has the classic SMEMBERS-then-DEL race.
- `NonceTracker` constructor enforces `ttl_seconds >= skew_seconds` when the explicit skew is provided.
- `default_is_public_endpoint` uses an exact-match whitelist instead of `endswith("/health")` (which previously leaked on paths like `/admin/x/health`).
- Bearer-token parsing is case-insensitive and whitespace-tolerant.
- `SessionStore.get_session` returns `None` on malformed JSON instead of raising.
- Hotkey-to-uid lookup is O(1) via a cached index swapped atomically with the metagraph snapshot.

**v0.1.0** — initial release.
