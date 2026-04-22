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
| Replay of a signed request | Nonce registered under `(hotkey, nonce)` with TTL ≥ `2 × timestamp_skew_seconds` (the full two-sided skew window); atomic `set_if_not_exists` on the cache backend. A smaller TTL is refused at `NonceTracker` construction. |
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
| Request-body tampering by a TLS-internal adversary | See *What the signature binds to* below. The default signing message covers only `(hotkey, timestamp, nonce)`, so an attacker who can observe *and modify* a signed request in flight (compromised TLS-terminating proxy, logging sidecar, traffic-replay tool) can swap the body and the signature still verifies. Mitigate by (a) ensuring TLS terminates at your application layer — not at an untrusted proxy — and/or (b) applying application-level HMAC/signing on sensitive endpoints until the opt-in request binding lands (tracked for 0.2.0). |
| Cross-endpoint replay within the skew window | A captured signed request can be replayed to a *different* URL/method within the same skew window, since the default signing message is not bound to the target endpoint. Same mitigations as above. |
| Unauthenticated flood of `/challenge` | Rate limit at the framework / ingress (see *Integrator requirements*). The endpoint only format-validates the claimed hotkey, so a low-rate-limit is required to prevent cache pressure. |
| TLS / transport security | `httpx` defaults are used. Adopters running public endpoints must front the service with TLS and leave `verify_ssl=True`. |
| Key custody | The package never touches secret keys — it delegates signing to `bittensor.Keypair`. Clients are responsible for secure storage. |

## What the signature binds to

The default `MessageBuilder` constructs the signing message as:

```
{hotkey}:{timestamp}:{nonce}
```

The signature therefore proves *only* that the keypair authorized **some** request at that timestamp with that nonce. It does **not** cover:

- the HTTP method (GET vs POST)
- the URL path or query string
- the request body
- any other request headers

**Why this matters.** Against an internet attacker over TLS, none of the above is observable, so this is not a concern in the default threat model. But certain deployment topologies place a TLS-internal party on the request path:

- A corporate TLS-intercepting proxy
- A logging / APM sidecar that receives decrypted traffic
- A traffic-replay tool used for load testing or debugging
- A compromised ingress or L7 load balancer

An attacker who holds one of those positions can:

1. **Tamper with the body** of an in-flight request. The signature still verifies because it wasn't over the body.
2. **Replay a captured signed request to a different endpoint.** `GET /foo` headers reused against `POST /admin/delete-all` within the `timestamp_skew_seconds` window (nonce permitting).
3. **Swap query-string parameters.** `?limit=10` → `?limit=100000`.

**What we are doing about it.** Opt-in request binding — signing the method, path, and a hash of the body alongside the existing fields — is on the 0.2.0 roadmap. It is not a one-line change: it touches the client signing transport (streaming-body handling, canonical path), the server FastAPI middleware (body buffering, re-hashing, `X-Body-SHA256` verification), and the `MessageBuilder` API shape. Subtle interactions with reverse proxies that rewrite paths also need a deliberate design. We would rather ship it once, correctly, than leave a partial mitigation in place.

**What you can do in the meantime.**

- Make sure TLS terminates at the same process (or one you fully trust) as your application. A TLS-terminating LB controlled by your org, running the same ops team's code, is a reasonable trust boundary; a vendor middlebox that receives decrypted traffic is not.
- For endpoints where the body carries high-stakes authorization data (admin actions, money movement, irreversible mutations), consider an additional application-level HMAC over `(method, path, canonical body)` until the opt-in binding lands. The HMAC key can ride alongside the Bittensor signature.
- Keep `timestamp_skew_seconds` as small as your clocks tolerate (default 60s is usually enough). The cross-endpoint replay window is exactly `timestamp_skew_seconds` wide — shrinking it proportionally shrinks the attack surface.

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

**v0.1.1 — second hardening pass**

- `NonceTracker` now enforces `ttl_seconds >= 2 × skew_seconds` (the full two-sided skew window). The previous `ttl ≥ skew` bound left a one-sided replay gap for future-dated signatures after the nonce evicted; the default `ttl_seconds` is now 120s to match the default 60s skew.
- `SessionStore.get_session` rejects sessions with `created_at <= revoked_after` (inclusive), closing a same-second race where a session created in the same wall-clock second as `revoke_all_sessions` could survive the barrier.
- `CacheBackend.sadd_with_ttl` atomic primitive; `SessionStore.create_session` uses it so a crash between SADD and EXPIRE cannot leave the per-hotkey index without a TTL (previously a potential unbounded-memory path in Redis).
- `SessionStore.revoke_all_sessions` stamps a per-hotkey `session_revoked_after` epoch before sweeping the index; `get_session` rejects any session whose `created_at` predates the stamp. Catches tokens that slip the SMEMBERS atomic step (e.g. sadd-ed concurrently with revocation).
- `NonceTracker.register` rejects nonces containing `:` (the cache-key delimiter) so pathological values can't alias `(hotkey, nonce)` pairs to the same Redis key. New `AuthErrorCode.NONCE_INVALID_CHARS` (400).
- `BittensorAuthConfig.collapse_auth_error_codes` (default `False`) — opt-in opaque `UNAUTHORIZED` on every 401 response, for deployments that want to close a mild error-code enumeration side channel.
- This `SECURITY.md` now documents the request-body / cross-endpoint replay gap under *What the signature binds to* (the signature covers `(hotkey, timestamp, nonce)` only — opt-in request binding is on the 0.2.0 roadmap).

**v0.1.x — initial hardening (pre-0.1.1)**

- Pinned `bittensor-wallet` to `>=2.1.0,<3.0.0`. Note: `bittensor-wallet` is the only direct dependency; the full `bittensor` SDK is *not* a direct dependency and is pulled transitively only when adopters construct a `MetagraphCache`. Adopters using `MetagraphCache` should pin `bittensor` themselves to control `Keypair.verify` stability.
- Added `recheck_registration_on_session` and `recheck_ban_on_session` config flags (default `True`): Bearer-token auth now re-resolves role and rechecks registration on every request.
- Added `MetagraphCache.last_synced_at` and `seconds_since_last_sync()` for integrator monitoring; `metagraph_max_age_seconds` fails closed when snapshots age out.
- Added `CacheBackend.smembers_and_delete` atomic primitive; `SessionStore.revoke_all_sessions` no longer has the classic SMEMBERS-then-DEL race.
- `default_is_public_endpoint` uses an exact-match whitelist instead of `endswith("/health")` (which previously leaked on paths like `/admin/x/health`).
- Bearer-token parsing is case-insensitive and whitespace-tolerant.
- `SessionStore.get_session` returns `None` on malformed JSON instead of raising.
- Hotkey-to-uid lookup is O(1) via a cached index swapped atomically with the metagraph snapshot.

**v0.1.0** — initial release.
