# Changelog

## 0.1.0 — 2026-10-24
- Initial scaffold from Soul Agent Platform draft 0.3: glossary, requirements, traceability matrix, error registry, schema index, fixture layout, papers.

## 0.2.0 — 2026-10-24
- `hq/v1/hello.schema.json` and `hq/v1/admission-result.schema.json` (draft 2020-12, additionalProperties false, exactly one lead, pinned adapter versions).
- Fixtures: 3 positive, 9 negative (5 schema-invalid, 4 semantic refusals naming their error code), one canonicalization vector with digest.
- `scripts/validate.py` and a CI workflow that runs it on every push.
