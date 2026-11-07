# soul-contracts

Versioned contracts for the Soul Agent Platform: schemas, glossary, fixtures, error registry, requirement traceability, and the papers that define them. This repository holds no runtime code.

Source of record: *Soul Agent Platform* draft 0.4 (2026-10-27), pinned by SHA-256 `6e8b85af5aea5454314b7563fef83d50b5582f2b6bd9bd2a8a9bd64cdedd3030` (Section 2 requirements, Section 3 vocabulary, Section 14 tests, Appendix A records, Appendix D traceability). The DOCX is `papers/Soul_Agent_Platform_draft_0.4.docx`, and `scripts/validate.py` checks it against that hash. Draft 0.3 stays in `papers/` for history.

## Owns

- `schemas/` — one JSON Schema per contract record (`hq/v1`, `wire/v1`, `task/v1`, `records/v1`), canonical form RFC 8785.
- `fixtures/` — golden records and negative vectors every implementation loads.
- `glossary/` — the entity and component vocabulary; every repository uses it unchanged.
- `errors/registry.json` — the error code registry; codes are added here before any implementation emits them.
- `traceability/` — requirements R1–R12, tests T01–T30, and the requirement → section → test → stage matrix.
- `papers/` — whitepaper drafts, the operator questions companion, and figure sources.

## Consumed by

`soul-package`, `agent-comms`, `agent-bot-daemon` (HQ, per decision D1), `agent-bot-identity`, `soul-adapters` and `soul-conformance`. Each pins a revision of this repository and loads its fixtures rather than keeping local copies. Dependencies point toward this repository, never away from it.

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

## Work package

WP1 Contracts — protocol maintainer. Deliverables: versioned schemas, glossary, error registry, fixtures, decision log, traceability matrix.
