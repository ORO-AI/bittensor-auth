# Contributing to `bittensor-auth`

Thanks for your interest in improving `bittensor-auth`. This document covers the practical bits — local setup, how to run the tests, and what we look for in a PR.

## Reporting an issue

- **Bugs**: open a [GitHub issue](https://github.com/ORO-AI/bittensor-auth/issues/new?template=bug_report.yml). Include a minimal reproduction, the version you're on, and the Python / `bittensor` versions of your environment.
- **Security vulnerabilities**: do **not** open a public issue. Email `team@oroagents.com` with a clear description and reproduction. See `SECURITY.md` for the full policy.
- **Feature requests**: open a [feature request](https://github.com/ORO-AI/bittensor-auth/issues/new?template=feature_request.yml) describing the problem you're trying to solve — we're more likely to say yes when the proposal lands as a gap in the current API rather than a new API invented in isolation.

## Local development

The package uses [uv](https://github.com/astral-sh/uv) for environment management; if you prefer pip, the `pyproject.toml` lists all extras.

```bash
# Clone and sync
git clone https://github.com/ORO-AI/bittensor-auth.git
cd bittensor-auth
uv sync --extra dev --extra fastapi --extra redis --extra client

# Run the test suite (no external services needed)
uv run pytest

# Lint + format check
uv run ruff check src/ tests/
uv run ruff format --check src/ tests/

# Type check (strict mypy)
uv run mypy src/

# Dependency advisory scan
uv run pip-audit
```

All four gates — tests, ruff, mypy, pip-audit — are enforced in CI on every PR. We recommend running them locally before pushing.

## PR expectations

- **One topic per PR.** Bug fixes, features, and refactors in separate PRs. Easier to review, easier to revert.
- **Tests for every behavior change.** New feature → new test. Bug fix → regression test that would have caught the bug. Pure refactor → existing tests pass and coverage doesn't drop.
- **Public API changes require a justification.** The package is meant to be stable for integrators; any rename, removed argument, or wire-format tweak needs a rationale in the PR description and a `CHANGELOG.md` entry under `## [Unreleased]`.
- **Security-sensitive changes** (anything in `core.py`, `signing.py`, `nonce.py`, `session.py`, or `fastapi/`) should walk through the threat model in `SECURITY.md` and note which threats the change affects.
- **Docs updates ride with the code.** README, docstrings, and `SECURITY.md` should move together with the behavior they describe.

## Commit style

- Imperative mood, short subject (`fix: reject malformed session JSON`). Conventional-commits-like prefixes are welcome but not required.
- Body (when useful) should explain *why*, not *what* — the diff shows what changed.

## Releasing (maintainers)

1. Land everything in `## [Unreleased]` under `CHANGELOG.md`.
2. Rename `[Unreleased]` to the new version + date, add a fresh `[Unreleased]` stub.
3. Bump the version in `pyproject.toml`.
4. Tag: `git tag v<version> && git push origin v<version>`.
5. The GitHub release workflow builds and publishes to PyPI on tag push.

## Code of conduct

Be kind. Assume good faith. We follow the [Contributor Covenant](https://www.contributor-covenant.org/version/2/1/code_of_conduct/) — disagreements are welcome, personal attacks are not.
