# Scoped local notices

These additive `hq/v1` records implement the accepted [PDR-0062](https://github.com/true-line/agent-bot-platform/blob/main/docs/04-decisions/PDR-0062-hq-notice-scope-and-legacy-consume-one.md) boundary. Product requirements remain in the platform. The generic broker envelope is separate work (soul-contracts #34); these records fit the existing HQ broker's payload/result positions.

## Operations and validation

Register `notices.peek` with `notice-query.schema.json` and require `operation: "peek"`; register `notices.consume-one` with the same schema and require `operation: "consume-one"`. Return `notice-result.schema.json`, preserving request correlation and operation. Registration alone is insufficient: the current broker host does not execute its registered schemas. Consumers must explicitly validate the full request and result using their digest-pinned shared schemas before effects or acceptance. No schema or fixture copies belong in consumer repositories.

Every operation explicitly requires `required_capabilities: ["notices-v1"]`. This is an operation-level requirement, not an existing negotiated Hello advertisement; Hello and admission-result are unchanged. Check the contract discriminator first (`unsupported_version`), then required capability support (`required_capability_missing`), then the full closed schema. A structural const failure is not a substitute for those typed checks. A host without these registered kinds returns its existing `host.unknown_kind` refusal. Never retry against the upstream service as a fallback. The caller must likewise check version, requirement, correlation and operation before accepting a result.

The request has no runtime, harness, app or repository selector. `expected_repository`, when supplied, asserts equality with the host's frozen scope; it cannot select or widen that scope. Repository spelling is preserved, with ASCII case-insensitive equality. Repositories have one owner and name, not URLs, wildcards, lists, `.` or `..` names.

The runtime ID comes only from trusted bound broker metadata. The host checks current admission, installation epoch, lease generation, and an immutable scope derived from owner-controlled configuration and the accepted member/adapter/role definition. Unmapped runtimes remain admitted for normal work but cannot use these operations. The host persists a scope snapshot or explicit null; changing/removing its owner mapping requires a fresh Hello. The enrolled remote harness must also match. A caller cannot provide any of these authority inputs.

| Refusal | Existing code |
| --- | --- |
| Wrong installation epoch | `stale_epoch` |
| Expired/superseded admission or wrong lease generation | `lease_expired` |
| Missing/changed scope, repository inequality, or operation/kind mismatch | `caller_mismatch` |
| Canonical source content or result exceeds byte budget | `frame_too_large` |
| Malformed request, extra selector, or invalid field | Existing host `host.invalid_request` |

Shared registry refusals use `common/v1/error-response.schema.json`; host-local refusals keep the existing HQ envelope. No error code is added here. Capability/version negatives are structurally invalid; freshness, scope and byte negatives are structurally valid and use executable semantic fixture rules with trusted context.

## Custody, ordering and bounds

`peek` defaults to one and accepts count 1–50. It is read-only. `consume-one` always selects at most one (count, if supplied, must be 1), atomically marks it consumed/tombstoned in the same durable local transaction, and returns it once. Selection is after exact harness/repository scope filtering, ordered by ascending HQ durable custody sequence, never by source timestamp. A later arrival with an earlier `createdAt` cannot jump ahead. No source sequence or host custody internals are exposed in the result.

The positive peek fixture deliberately has decreasing source timestamps. Storage implementations must test that actual durable selection obeys the sequence order and that peek neither consumes nor acknowledges. The shared JSON schema cannot prove these storage effects.

Two semantic byte checks apply in addition to schema validation:

1. For each notice, reconstruct `{id: message_id, ...content}` and measure its RFC 8785 JCS UTF-8 bytes: at most **65,536 bytes**, inclusive. This matches the pump's sanitized source-content boundary without charging new result metadata against an already valid source payload.
2. Measure the entire `notice-result` record's JCS UTF-8 bytes: at most **524,288 bytes**, inclusive. Wrapper fields, array syntax and metadata count. This is a result-payload limit, not a claim about a future generic outer envelope.

The exact reference oracle is `scripts/jcs.py:canonicalize`; the executable byte rules are in `scripts/validate.py`. JSON `maxLength` counts Unicode code points and does not enforce UTF-8 budgets: the oversized source fixture remains schema-valid. The aggregate fixture contains individually legal notices but an oversized result. Stop adding peek entries before either bound; never consume entries that are not returned. An oversized single notice refuses without mutation. Transport framing still enforces its independent wire limit. Do not truncate individual content fields to manufacture a fit.

`request_id` is correlation, not a durable idempotency key. A destructive call may have committed when its reply is lost. Do not automatically replay it: this retains the legacy at-most-once handoff limitation rather than inventing acknowledgement/replay guarantees.

## Legacy payload compatibility

| Legacy event field | Shared record | Policy |
| --- | --- | --- |
| `id` | `message_id` | Preserve stable service identifier, 1–256 ASCII identifier characters |
| `repo` | `content.repo` | Required repository, original spelling preserved |
| `app`, `event`, `action`, `kind`, `title`, `actor`, `url`, `text` | Same field in `content` | Preserve if present; no content becomes trusted |
| `type` | `content.type` | Up to 10 strings, each at most 64 code points |
| `number` | `content.number` | Nonnegative safe integer |
| `createdAt` | `content.createdAt` | Nonnegative safe integer epoch **milliseconds**, preserved exactly |
| `pulled` | Legacy adapter only | Set `true` after successful local consume |
| `lease`, `lease_expires_at`, `attempts`, unknown fields | None | Intentionally omitted; transport credentials, retry state and unreviewed fields are not public content |

Each notice carries `provenance: ["external-untrusted"]` and `wake_class: "none" | "notify"`; neither grants authority. They are not inserted into the legacy event envelope. `message_id` owns source identity, so `content.id` is forbidden. The 256-character limit is specific to source notices: all existing generic 128-character routing IDs stay unchanged. `createdAt` is explicitly a source compatibility exception to protocol RFC 3339 timestamps.

The shim maps an empty consume to `{event:null}` and a notice to `{event:{id:message_id,...content,pulled:true}}`. The old implementation passed through attempts/unknown fields after removing lease fields; dropping those fields is intentional sanitization, not a claim of byte-for-byte legacy parity. A separate scoped peek stays read-only. Explicit standalone remote clients remain possible only outside migrated custody policy. The service migration gate must fence old queue consumers; local contracts alone cannot establish exclusive custody. Upstream policy revision/device identity and opaque lease tokens never enter these local records.

## Release and consumer pin plan

This is additive contract work, intended for a reviewed minor release after merge (candidate `v0.5.0`), not an activation or release. Existing schema, fixture and error-registry bytes remain unchanged. Do not invent the final commit/digest before publication. After the reviewed commit is tagged, each consumer updates its exact tag, full commit, paths `errors`, `fixtures`, `schemas`, file count and `sha256-manifest-v1` digest together. Its manifest maps each canonical relative git path to `{sha256:<file-byte hex>,size:<bytes>,mode:<git mode>}`; hash the manifest's RFC 8785 bytes, prefix `sha256:`. Refuse moved tags and digest mismatches.

HQ's current reproducible commands are `node scripts/soul-contracts.mjs pin v0.5.0` and `node scripts/soul-contracts.mjs verify` after that tag exists; other consumers use the same manifest algorithm. Run the complete shared corpus plus explicit consumer validation of these exact pinned schemas. Implement storage/authority/migration tests in their owning repositories. Contract merge/release and consumer pinning precede activation; the custody fence, scope guard, mailbox transaction and shim must all be reviewed together before closing the roadmap row.
