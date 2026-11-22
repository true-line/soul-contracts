# Changelog

## Unreleased

- Add a historical, release-produced keyless signed v1 qualification verifier fixture with exact-byte and refusal evidence. It is test-only and does not qualify the private Stage 2a pilot.

## 0.7.0 — 2026-11-22

This version publishes Stage 2a contract shapes and synthetic fixtures. It
does not qualify an adapter, sign a `.soul` package, establish protected host
launch authority, or prove T01/T02/T03/T21. Consumers must verify the published
tag and release before pinning this version.

- Add measured qualification host-report v3 and its synthetic protected and
  cooperative profile fixtures. These records bind exact host, bridge, Soul
  and policy inputs but contain no physical acceptance result.
- Add Machine's secure-admin-owned frozen snapshot identity and signed one-use
  reservation contracts. The `machine/v2` payload separates installed source
  from the frozen definition passed to the Soul runner.
- Add the `control/v3` policy flag for future `.soul` release provenance. The
  private Stage 2a pilot keeps it off while retaining frozen Soul ID, artifact
  and measured-definition bindings and artifact revocation.
- Add a pre-sign execution-completion record and post-sign completed-run
  commitment for the v3 qualification report's no-cycle evidence chain.
- Add a draft, supplemental Machine/keyd policy acceptance-witness payload and
  fixed-purpose ES256 envelope. Synthetic shape and comparison fixtures cover
  pair and HQ epoch changes, one-use challenge replay, ledger/key loss, policy
  rollback including a higher-revision v1 after v2, the 3,600-to-3,601-second
  revocation boundary, and untrusted time
  across reboot. They do not verify signatures or authorize protected launch.

## 0.6.0 — 2026-11-21

This version publishes contract shapes and refusal fixtures. It does not qualify
an adapter, prove a protected host run, or authorize protected launch. Consumers
must verify the published tag and release before pinning this version.

- Add the initial `adapter/v1` package manifest schema and canonical fixtures for adapters that declare no qualified profiles.
- Add draft authenticated macOS qualification v1 host-report, designated-host signature, owner-policy envelope and release attestation contracts. Specify fixed signing purposes, canonical bytes and binding fields for released adapter and runner bytes, HQ-started Soul evidence, measured host inputs, and T01/T02/T03/T21 results. Keep `profiles_qualified: []` until cryptographic, release and physical checks pass.
- Add draft bridge-aware qualification v2 contracts with distinct Souls source/build receipt, pinned source tree and runtime archive digest, trusted release roots, and a 3,600-second revocation-snapshot limit. Synthetic fixtures test byte substitution and provenance refusals; they are not physical Mac evidence.
- Add the PDR-0047 `control/v1` linked-machine records: signed policy bundle and relayed owner request, owner session open/exchange, device enrollment, physical link/unlink, and machine plan. Add a separate local-only credential issuer variant and domain-separated signing/verification rules. Negative fixtures cover owner-presence, wrong or revoked keys, policy widening, untrusted issuer, malformed binding and first-device bootstrap failures. These contracts do not open the linked control path until host implementations enforce them.
- Register control refusal codes for missing owner presence, revoked or unrecognized control keys, untrusted issuer, binding mismatch and action outside policy. The error response enumeration stays in lockstep with the add-only registry.

## 0.5.0 — 2026-11-15
Version metadata alone does not establish publication. Consumers must verify the actual tag and release before pinning.

- Add bounded `hq/v1` notice query/result contracts for scoped local peek and fixed-one consume, with explicit `notices-v1` operation requirements. Existing contracts and errors are unchanged.
- Pin sanitized legacy payload compatibility, trusted scope semantics, durable ordering, JCS byte budgets, typed refusals and a release/consumer-digest plan. Add executable positive, schema-negative and semantic-refusal fixtures.

## 0.1.0 — 2026-10-24
- Initial scaffold from Soul Agent Platform draft 0.3: glossary, requirements, traceability matrix, error registry, schema index, fixture layout, papers.

## 0.2.0 — 2026-10-24
- `hq/v1/hello.schema.json` and `hq/v1/admission-result.schema.json` (draft 2020-12, additionalProperties false, exactly one lead, pinned adapter versions).
- Fixtures: 3 positive, 9 negative (5 schema-invalid, 4 semantic refusals naming their error code), one canonicalization vector with digest.
- `scripts/validate.py` and a CI workflow that runs it on every push.

## 0.3.0 — 2026-11-07
Contract baseline against draft 0.4. Merges the independently derived baseline from true-line/agent-bot-daemon#59 into this repository.
- Schemas for every Appendix A record, plus the `task/v1` commitment request and the `wire/v1` outer frame (18 here; the typed refusal below makes 19). New `wire/v1`, `task/v1` and `records/v1` directories; credential issuance record is new in paper 0.4.
- `hq/v1` Hello: `capabilities` → `supported_capabilities` (paper wording); optional `task` in `supported_versions`. Roles use `^[a-z][a-z0-9-]{0,31}$`. Identifiers allow `:` for namespaced references.
- `hq/v1` admission result: channel bindings are opaque, 16–128 characters; optional `task` in `negotiated_versions`.
- Every hq/v1 socket message carries `contract: "hq/v1"`; every digest is `sha256:<hex>`; installation epochs are ≥ 1; capabilities are versioned tokens.
- Path patterns refuse `.`, `..` and empty segments; a dream grant can no longer reach `primitives/` by traversal (T29).
- Error registry: the 27 draft 0.4 codes (adds `quarantined`, `credential_unavailable`, `device_revoked`), with descriptions, `retryable`, `raised_by`, contiguous numbering, and an add-only ratchet against the merge base.
- Fixtures: 31 positive, 51 negative, 8 JCS vectors. Negatives pin their base positive by SHA-256; parse refusals (duplicate keys) and rule-based semantic refusals with pinned context are new. Vendor adapter ids in the Hello fixtures replaced with `fake-adapter` (R10).
- `scripts/jcs.py` (RFC 8785 and strict parse) and an extended `scripts/validate.py`: R10 vendor-token scan, traceability coverage, registry ratchet. CI fetches full history for the ratchet.
- Glossary, requirements and matrix updated to draft 0.4; `traceability/TESTS.md` defines T01–T30. Glossary repository column follows decision D1 (HQ is agent-bot-daemon).
- `papers/Soul_Agent_Platform_draft_0.4.docx`, the governing source, checked by `validate.py` against its pinned SHA-256. T19 in `TESTS.md` is now verbatim from Section 14.
- `common/v1/error-response.schema.json`: the typed refusal (error code, safe explanation, correlation ID), with its code enumeration kept equal to the registry. Ready and lease renewal gains a required `auth_state` (Section 5).
- `.github/CODEOWNERS`: the owner (`@qwts`) is the integrator and reviews every contract change. The curation notes in `schemas/README.md` were accepted on 2026-11-07.

## 0.4.0 — 2026-11-07
- `hq/v1` client identity (decision C20, [discussion #23](https://github.com/true-line/soul-contracts/discussions/23)). These are optional fields, so earlier Hello and admission messages stay valid:
  - **Hello:** `requested_roles[].client` (`app_id`, optional `profile`) is the adapter's claim.
  - **Admission result:** `admitted_runtimes[].client` adds a required `source` (`adapter`, `process` or `owner-label`), so a weak identification is visible.
- Fixtures: 2 positive and 4 negative. The negatives cover a Hello claiming a source, a bad app id, a missing source, and an unknown source.

## 0.4.1 — 2026-11-07
Tooling and documentation only: no schema, fixture or error registry changes.
- Adopts the platform (true-line/agent-bot-platform), read at `main` (platform PDR-0020). `AGENTS.md` carries the platform block, which names no commit.
- The glossary, requirements, conformance tests, traceability matrix and papers moved to the platform. `glossary/`, `traceability/` and `papers/` now link to them on `main`.
- `schemas/README.md` takes over the schema encodings and the enumerations, which are contract content.
- `scripts/validate.py` replaces the paper-pin and traceability checks with platform checks. It fetches the platform's `main` on every run, logs the commit SHA it checked, and fails, never skips, when it cannot. These must hold on `main`:
  - R1–R12 and T01–T30 are defined;
  - the error registry's paper hash equals S6 in `registry/sources.yaml`;
  - the `AGENTS.md` block is the read-at-main block;
  - every platform link uses `main` and resolves;
  - contract artifacts cite only requirement and test IDs defined there.

  The R10 vendor scan now covers `schemas/README.md` instead of the moved files.
