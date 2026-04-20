<!--
Thanks for the PR! A few prompts to help get it landed quickly:

- Keep one topic per PR (easier to review, easier to revert)
- Tests for every behavior change
- Public API changes need a rationale and a CHANGELOG entry
- Security-sensitive changes (core / signing / nonce / session / fastapi)
  should walk through the threat model in SECURITY.md
-->

## What

<!-- One or two sentences describing the change. -->

## Why

<!-- Link to an issue if one exists. Otherwise explain the problem this
     fixes or the capability it adds. -->

## How

<!-- A short tour of the implementation. Call out design decisions a
     reviewer might otherwise miss. -->

## Security impact

<!-- Delete this section if the change is purely docs or tooling.

     If you touched anything under core/, signing/, nonce/, session/, or
     fastapi/, describe which threat classes from SECURITY.md the change
     affects and why the new behavior is safe. -->

## Checklist

- [ ] Tests cover the new behavior (or a regression test for the bug)
- [ ] `uv run pytest` passes locally
- [ ] `uv run ruff check src/ tests/` passes
- [ ] `uv run ruff format --check src/ tests/` passes
- [ ] `uv run mypy src/` passes
- [ ] `CHANGELOG.md` has an entry under `## [Unreleased]` (if user-visible)
- [ ] Docs updated (README / docstrings / SECURITY.md) if the public API or threat model changed
