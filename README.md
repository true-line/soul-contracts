# soul-contracts

Versioned contracts for the Soul Agent Platform: schemas, glossary, fixtures, error registry, requirement traceability, and the papers that define them. This repository holds no runtime code.

Source of record: `papers/soul-agent-platform-draft-0.3.md` (Section 2 requirements, Section 3 vocabulary, Appendix A records, Appendix D traceability).

## Owns

- `schemas/` — one JSON Schema per contract record (`hq/v1`, `task/v1`, `wire/v1`), canonical form RFC 8785.
- `fixtures/` — golden records and negative vectors every implementation loads.
- `glossary/` — the entity and component vocabulary; every repository uses it unchanged.
- `errors/registry.json` — the error code registry; codes are added here before any implementation emits them.
- `traceability/` — requirements R1–R12 and the requirement → section → test → stage matrix.
- `papers/` — whitepaper drafts, the operator questions companion, and figure sources.

## Consumed by

`soul-package` → `agent-comms` → `managed-machine` (HQ), and `agent-bot-identity`, `soul-adapters`, `soul-conformance`. Dependencies point toward this repository, never away from it.

## Rules

- Contracts before code (R7): a cross-component change starts here as a versioned schema and fixture change; implementations follow.
- N and N−1: the broker wire and `hq/v1` support the current and previous major versions; a breaking change bumps the major and keeps the previous fixtures.
- Vendor-neutral (R10): no schema, fixture, or glossary entry names a model, provider, or harness vendor. Vendor names belong in `soul-adapters` and configuration.
- No implementer edits a schema to make its own implementation pass. Changes land through the integrator (WP1), and `soul-conformance` is the check.

## Work package

WP1 Contracts — protocol maintainer. Deliverables: versioned schemas, glossary, error registry, fixtures, decision log, traceability matrix.
