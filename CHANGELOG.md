# Changelog

All notable changes to `bittensor-auth` are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `CacheBackend.sadd_with_ttl(key, ttl, *values)` — atomically add set members and (re)set TTL, closing a window where a mid-call crash could leave a set without expiry (unbounded Redis growth).
- `SessionStore` now stamps a per-hotkey `session_revoked_after` epoch on every `revoke_all_sessions` call, and `get_session` rejects any session whose `created_at` predates the stamp. Closes the bulk-revocation race where a token's `sadd` could slip past the index sweep.
- `BittensorAuthConfig.collapse_auth_error_codes` — opt-in; when `True`, all 401 responses return a single opaque `UNAUTHORIZED` code instead of distinct codes like `INVALID_SIGNATURE` / `NONCE_REUSED` / `TIMESTAMP_SKEW`, closing a mild enumeration side channel. Server logs retain the specific code.
- `AuthErrorCode.NONCE_INVALID_CHARS` — `NonceTracker.register` now rejects nonces containing `:` (the cache key delimiter) so pathological values can't alias different `(hotkey, nonce)` pairs to the same Redis key.

### Fixed

- **Signature replay window closed** — `NonceTracker` now enforces `ttl_seconds >= 2 * skew_seconds` at construction. The skew window is two-sided, so a signature dated `now + skew` stayed valid for another `skew` seconds after registration; a TTL of only `skew` (the previous default) evicted the nonce before the timestamp expired and allowed a one-time replay. `BittensorAuth` auto-wires the tracker with `ttl = 2 * config.timestamp_skew_seconds`.
- **Same-second revocation race** — `SessionStore.get_session` compares `created_at <= revoked_after` (inclusive) instead of strict `<`. Both stamps are whole-second `int(time.time())`, so the prior strict comparison let any session created in the same wall-clock second as `revoke_all_sessions` slip the barrier.

### Documentation

- `SECURITY.md` now documents the request-body / cross-endpoint replay gap under a new *What the signature binds to* section. The default signing message covers `(hotkey, timestamp, nonce)` only, so a TLS-internal adversary can tamper with bodies or replay to a different endpoint within the skew window; opt-in request binding is on the 0.2.0 roadmap. Also updates the Changelog section and corrects the stale `bittensor >= 8.0` pin claim (the direct dep is `bittensor-wallet`; the full `bittensor` SDK is transitive).

### Changed

- `bittensor-wallet` dependency now pinned `>=2.1.0,<3.0.0` so a breaking 3.x release cannot silently alter signature verification semantics.
- `SessionStore.create_session` uses the new `sadd_with_ttl` under the hood.
- `NonceTracker` default `ttl_seconds` raised from 60 to 120 so it covers the default 60s timestamp skew on both sides.

## [0.1.0] — 2026-04-20

Initial public release.

### Added

- **SR25519 per-request authentication** via `X-Hotkey`, `X-Timestamp`, `X-Nonce`, `X-Signature` headers, with pluggable message builders (`colon_separated`, `dot_separated`, or custom).
- **Challenge / session flow** with one-shot challenge consumption and bearer-token sessions. Sessions can bulk-revoke atomically on ban.
- **Nonce replay protection** with constructor-enforced `ttl_seconds >= skew_seconds` invariant.
- **Background-synced metagraph cache** with staleness fail-closed (`metagraph_max_age_seconds`) and an exposed `last_synced_at` / `seconds_since_last_sync()` pair for monitoring.
- **Session-auth recheck**: Bearer tokens re-resolve role and re-check metagraph registration per request by default (`recheck_registration_on_session`, `recheck_ban_on_session`), so deregistrations and permit changes take effect without waiting for session TTL.
- **Cache backends**: `InMemoryCache` (tests / single-process dev) and `RedisCache` (production) with atomic `set_if_not_exists`, `getdel`, and `smembers_and_delete` primitives.
- **FastAPI bindings**: mountable auth router (`/challenge`, `/session`, `/logout`) and per-request / session-based dependencies.
- **httpx signing transport** for Python clients, plus a `BittensorAuthClient` convenience wrapper with sync and async variants.
- **Security documentation**: `SECURITY.md` with threat model, residual-race analysis, and integrator requirements (rate-limit `/challenge`, Redis in production, monitor `last_synced_at`, keep `verify_ssl=True`).

### Security posture

Reviewed end-to-end against the following threat classes:

- Signature forgery, replay inside and outside the skew window, cross-hotkey challenge reuse, one-time-use challenges, stale sessions after deregistration or permit change, stale metagraph during chain partitions, nonce-store DoS via oversized nonces.

See `SECURITY.md` for the full matrix.

[Unreleased]: https://github.com/ORO-AI/bittensor-auth/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/ORO-AI/bittensor-auth/releases/tag/v0.1.0
