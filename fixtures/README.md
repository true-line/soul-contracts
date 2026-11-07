# Fixtures

Golden records and negative vectors shared by every implementation (runtime, broker, HQ, adapters). Both sides of a contract load the same files; a fixture change is a contract change and ships with its schema change. Implementations load these files from a pinned revision of this repository and keep no local copies.

- `positive/`: at least one valid instance per schema.
- `negative/`: one file per refusal, and at least one per schema.
- `canonicalization/`: RFC 8785 vectors (input → exact canonical text → digest).

Fixture files are named `<schema>.<case>.json`. A fixture that no implementation loads is deleted, not kept.

## Envelope

```json
{
  "schema": "<path under schemas/>",
  "base": { "fixture": "positive/<file>", "sha256": "sha256:<hex of that file's bytes>" },
  "expect": { "schema": "valid" | "invalid", "parse": "invalid", "error": "<code>", "rule": "<rule>" },
  "context": { "now": "<date-time>", "negotiated_capabilities": ["..."] },
  "note": "...",
  "input": { ... },
  "input_raw": "...",
  "canonical_sha256": "sha256:<hex>"
}
```

- **Positive:** `expect.schema` is `valid` and names no error. `canonical_sha256` is the SHA-256 of the input's JCS bytes.
- **Negative:** carries `base`, which pins the exact bytes of one positive fixture of the same record. A positive cannot change without someone revisiting its negatives.
  - **Schema refusal:** `expect.schema` is `invalid`. It names an `error` only when the paper ties the refusal to a code (for example, `frame_too_large` for an oversized frame). Otherwise the refusal is a malformed-request rejection that implementations report in their own way.
  - **Parse refusal:** `expect.parse` is `invalid`, and the raw text is in `input_raw`. A lenient JSON parser accepts it; a strict one (duplicate keys, non-JSON constants) must refuse it.
  - **Semantic refusal:** `expect.schema` is `valid`, plus the `error` that HQ or the broker must return. When the refusal depends on time or negotiation, `expect.rule` names it (`expiry-before-now`, `capability-not-negotiated`) and `context` pins its inputs, so the vector never depends on the wall clock.

`scripts/validate.py` checks the schema, parse and rule halves, the pins, and that every `error` is registered in `errors/registry.json`. `soul-conformance` checks the error half against a live HQ.

Fixtures name no vendor (R10): adapters are `fake-adapter`, and providers and models are placeholders.

`positive/hello.first-start.canonical.txt` and `.digest.txt` hold the exact JCS bytes and digest of `hello.first-start.json`, for implementations that compare bytes rather than recompute them.
