# Changelog

## 0.1.0 — 2026-10-24
- Initial scaffold from Soul Agent Platform draft 0.3: glossary, requirements, traceability matrix, error registry, schema index, fixture layout, papers.

## 0.2.0 — 2026-10-24
- `hq/v1/hello.schema.json` and `hq/v1/admission-result.schema.json` (draft 2020-12, additionalProperties false, exactly one lead, pinned adapter versions).
- Fixtures: 3 positive, 9 negative (5 schema-invalid, 4 semantic refusals naming their error code), one canonicalization vector with digest.
- `scripts/validate.py` and a CI workflow that runs it on every push.

## 0.3.0 — 2026-11-07
Contract baseline against draft 0.4. Merges the independently derived baseline from true-line/agent-bot-daemon#59 into this repository.
- Schemas for every Appendix A record, plus the `task/v1` commitment request and the `wire/v1` outer frame (18 in all). New `wire/v1`, `task/v1` and `records/v1` directories; credential issuance record is new in paper 0.4.
- `hq/v1` Hello: `capabilities` → `supported_capabilities` (paper wording); optional `task` in `supported_versions`. Roles use `^[a-z][a-z0-9-]{0,31}$`. Identifiers allow `:` for namespaced references.
- `hq/v1` admission result: channel bindings are opaque, 16–128 characters; optional `task` in `negotiated_versions`.
- Every hq/v1 socket message carries `contract: "hq/v1"`; every digest is `sha256:<hex>`; installation epochs are ≥ 1; capabilities are versioned tokens.
- Path patterns refuse `.`, `..` and empty segments; a dream grant can no longer reach `primitives/` by traversal (T29).
- Error registry: the 27 draft 0.4 codes (adds `quarantined`, `credential_unavailable`, `device_revoked`), with descriptions, `retryable`, `raised_by`, contiguous numbering, and an add-only ratchet against the merge base.
- Fixtures: 29 positive, 46 negative, 8 JCS vectors. Negatives pin their base positive by SHA-256; parse refusals (duplicate keys) and rule-based semantic refusals with pinned context are new. Vendor adapter ids in the Hello fixtures replaced with `fake-adapter` (R10).
- `scripts/jcs.py` (RFC 8785 and strict parse) and an extended `scripts/validate.py`: R10 vendor-token scan, traceability coverage, registry ratchet. CI fetches full history for the ratchet.
- Glossary, requirements and matrix updated to draft 0.4; `traceability/TESTS.md` defines T01–T30. Glossary repository column follows decision D1 (HQ is agent-bot-daemon).
- `papers/Soul_Agent_Platform_draft_0.4.docx`, the governing source, checked by `validate.py` against its pinned SHA-256. T19 in `TESTS.md` is now verbatim from Section 14.
