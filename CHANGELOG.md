# Changelog

All notable changes to `bittensor-auth` are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
