# Schemas

One JSON Schema (draft 2020-12) per record in draft 0.4 Appendix A, plus the `task/v1` commitment request and the `wire/v1` outer frame. Each schema's `$id` is `https://true-line.ai/soul-contracts/<path>`. Canonical form: RFC 8785 JCS (`scripts/jcs.py`, vectors in `fixtures/canonicalization/`).

| Record | Schema file | Since |
| --- | --- | --- |
| Hello (admission request) | `hq/v1/hello.schema.json` | 0.3.0 |
| Admission result | `hq/v1/admission-result.schema.json` | 0.3.0 |
| Equip | `hq/v1/equip.schema.json` | 0.3.0 |
| Ready and lease renewal | `hq/v1/ready-and-lease-renewal.schema.json` | 0.3.0 |
| Lifecycle request | `hq/v1/lifecycle-request.schema.json` | 0.3.0 |
| Approval record | `hq/v1/approval-record.schema.json` | 0.3.0 |
| Outer frame | `wire/v1/wire-frame.schema.json` | 0.3.0 |
| Directive or query | `wire/v1/directive-or-query.schema.json` | 0.3.0 |
| Task commitment request | `task/v1/task-commitment.schema.json` | 0.3.0 |
| Task record | `task/v1/task-record.schema.json` | 0.3.0 |
| Action record | `task/v1/action-record.schema.json` | 0.3.0 |
| Grant record | `records/v1/grant-record.schema.json` | 0.3.0 |
| Credential issuance record | `records/v1/credential-issuance-record.schema.json` | 0.3.0 (new in paper 0.4) |
| Typed note | `records/v1/typed-note.schema.json` | 0.3.0 |
| Transfer record | `records/v1/transfer-record.schema.json` | 0.3.0 |
| Dream grant record | `records/v1/dream-grant-record.schema.json` | 0.3.0 |
| Eval plan record | `records/v1/eval-plan-record.schema.json` | 0.3.0 |
| Candidate revision record | `records/v1/candidate-revision-record.schema.json` | 0.3.0 |
| Typed refusal (error response) | `common/v1/error-response.schema.json` | 0.3.0 (paper: Appendix A, Minimum error codes) |

`hq/v1`, `wire/v1` and `task/v1` are the versioned protocols (N and N−1 apply, R7). `records/v1` holds stored records that no protocol carries on its own, and `common/v1` holds shapes every protocol shares (the typed refusal). Both are versioned with this repository.

All versions are pre-release until an implementation pins them. Until then a shape change is made in place and recorded in `CHANGELOG.md`; after the first pin, a breaking change bumps the major and keeps the previous fixtures.

## Conventions

| Field kind | Encoding |
| --- | --- |
| Soul ID | `^agent_<uuid>$`, lowercase hex (R1) |
| Other identifiers | `^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`; `:` namespaces a reference such as `principal:owner_1` or `workspace:scratch` |
| Grant handles, channel bindings, credential references, idempotency keys | `^[A-Za-z0-9_-]{16,128}$`, broker-generated and opaque, never user-chosen |
| Digests | `sha256:<64 lowercase hex>`; the prefix names the algorithm so it can change without a new field |
| Installation epoch | Integer ≥ 1. `destination_epoch` on the outer frame is a routing hint and may be 0 when the sender has none |
| Revisions, sequences, watermarks | Non-negative integers; lease generations and renewal sequences start at 1 |
| Timestamps | RFC 3339 `date-time` |
| Capabilities | Versioned tokens, `^[a-z0-9]+(-[a-z0-9]+)*-v[0-9]+$` (e.g. `sealed-inner-v1`) |
| Roles | `^[a-z][a-z0-9-]{0,31}$`; exactly one `lead` in Hello |
| Adapter versions | Exact semver; pins are exact (R12) |
| Paths inside a Soul | Relative; no `.` or `..` segment, no empty segment |
| Profiles, provenance, states | The enumerations in `glossary/GLOSSARY.md` |

Every object is `additionalProperties: false`, so a record that tries to carry a secret, a handle, or any unknown field fails closed. hq/v1 socket messages (Hello, admission result, Equip, Ready and lease renewal, lifecycle request) carry `contract: "hq/v1"`, so a version mismatch is visible before any other field is read (T14).

## Curation notes

These are the places where a schema deliberately differs from, or fills a gap in, the paper's illustrative text. The owner accepted all of them on 2026-11-07 ([Decisions](https://github.com/true-line/soul-contracts/discussions/categories/decisions)). On any conflict not listed here, the paper wins.

- **Task commitment `transition`.** The illustrative request uses `"complete"`. The schema lists the Section 7 target states instead (`completed`, `failed`, `canceled`, …).
- **Profile and provenance spelling.** The schemas use kebab-case (`managed-protected`, `external-untrusted`); the paper writes them as prose.
- **`retryable` and `raised_by` in `errors/registry.json`** are WP1 curation. The paper names the codes but not these attributes, except where Sections 6 and 9 state the behavior (for example, `credential_unavailable` is retried once the service returns).
- **Hello `requested_roles`** carry member, adapter and pinned adapter version, not bare role names. Admission pins adapter versions, eval cells key on them, and the "exactly one lead" rule needs the structure.
- **The admission result** echoes `request_id` and issues the first `lease_generation`. Ready and lease renewal requires a lease generation, and only admission can issue the first one (T07).

- **Ready `auth_state`** (`authenticated`, `unauthenticated`, `expired`) carries the per-role auth state that Section 5 lists and Appendix A's field list omits. The three values are WP1 curation, as is `observed_health` (`healthy`, `degraded`, `unreachable`); the paper says only that a missed lease makes reachability stale.
- **The typed refusal** carries `error`, `explanation` and `correlation_id`, as the paper requires, plus an optional `request_id` echo and a `retry_after_seconds` hint that is allowed only for codes registered as retryable. Its code enumeration is the registry, and `validate.py` keeps the two equal.

- **Client identity** (decision C20). A session is the device plus the client app or profile, because two apps of one harness family can run on one device (Operator Questions; the paper is silent). Hello's `requested_roles[].client` is the adapter's claim. The admission result's `admitted_runtimes[].client` is HQ's identification, and its `source` (`adapter`, `process`, `owner-label`) shows how strong that identification is. Both are optional, so earlier messages stay valid.

## Validator

`scripts/validate.py` uses `jsonschema>=4.23` with full draft 2020-12 support. Schemas may use any draft 2020-12 keyword.
