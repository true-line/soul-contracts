# Fixtures

Golden records and negative vectors shared by every implementation (runtime, broker, HQ, adapters). Both sides of a contract load the same files; a fixture change is a contract change and ships with its schema change.

- `positive/` — one valid instance per schema, plus canonicalization vectors (input → JCS bytes → digest).
- `negative/` — one file per refusal: wrong purpose, stale epoch, copied handle, duplicate key, oversized frame, unknown required capability, changed content under a repeated operation ID. Each names the error code it must produce (see `errors/registry.json`).

Fixture files are named `<schema>.<case>.json`. A fixture that no implementation loads is deleted, not kept.
