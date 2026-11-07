# soul-contracts

Versioned contracts for the Soul Agent Platform: schemas, canonicalization vectors, fixtures and the error registry. This repository holds no runtime code.

Requirements, tests, vocabulary, traceability and the source papers live in true-line/agent-bot-platform; `AGENTS.md` and `platform.lock.json` name the pinned commit. The source of record is the platform's S6, *Soul Agent Platform* draft 0.4 (2026-10-27), SHA-256 `6e8b85af5aea5454314b7563fef83d50b5582f2b6bd9bd2a8a9bd64cdedd3030`. `errors/registry.json` names it by that hash.

## Owns

- `schemas/` — one JSON Schema per contract record (`hq/v1`, `wire/v1`, `task/v1`, `records/v1`), canonical form RFC 8785.
- `fixtures/` — golden records and negative vectors every implementation loads.
- `errors/registry.json` — the error code registry; codes are added here before any implementation emits them.
- `schemas/README.md` — the field encodings, which schema encodes each platform term, and the enumeration values.
- `platform.lock.json` — the platform commit these contracts are written against, with the requirement and test IDs that exist there.

`glossary/`, `traceability/` and `papers/` now hold only links to the platform.

## Consumed by

`soul-package`, `agent-comms`, `agent-bot-daemon` (HQ, per agent-bot-daemon decision D1), `agent-bot-identity`, `soul-adapters` and `soul-conformance`. Each pins a revision of this repository and loads its fixtures rather than keeping local copies. Dependencies point toward this repository, never away from it.

## Rules

- Contracts before code (R7): a cross-component change starts here as a versioned schema and fixture change; implementations follow.
- N and N−1: the broker wire and `hq/v1` support the current and previous major versions; a breaking change bumps the major and keeps the previous fixtures.
- Vendor-neutral (R10): no schema, fixture, or glossary entry names a model, provider, or harness vendor. Vendor names belong in `soul-adapters` and configuration.
- No implementer edits a schema to make its own implementation pass. Changes land through the integrator (WP1), and `soul-conformance` is the check.

## Validate

```sh
pip install "jsonschema>=4.23" rfc3339-validator
python scripts/validate.py   # BASE_REF=origin/main by default, for the registry ratchet
```

To move the platform pin, from a local checkout of the platform:

```sh
python scripts/platform_lock.py <platform checkout> --commit <sha> --write
```

Then update the platform block in `AGENTS.md` and the links in `glossary/`, `traceability/` and `papers/` in the same change; `validate.py` fails until they agree.

## Work package

WP1 Contracts — protocol maintainer. Deliverables: versioned schemas, error registry, fixtures and canonicalization vectors.
