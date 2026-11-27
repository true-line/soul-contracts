# Schemas

One JSON Schema (draft 2020-12) per record in draft 0.4 Appendix A, plus the `task/v1` commitment request and the `wire/v1` outer frame. Each schema's `$id` is `https://true-line.ai/soul-contracts/<path>`. Canonical form: RFC 8785 JCS (`scripts/jcs.py`, vectors in `fixtures/canonicalization/`).

| Record | Schema file | Since |
| --- | --- | --- |
| Descriptive harness adapter package manifest (no qualified profiles) | `adapter/v1/adapter-manifest.schema.json` | 0.6.0 |
| [Protected package content, custody, disclosure and restore](package/protected-v1/README.md) | `package/protected-v1/protected-*.schema.json` | draft |
| [Portable package core inspection records](package/core-v1/README.md) | `package/core-v1/portable-*.schema.json` | draft |
| Draft adapter qualification evidence payload (unverified) | `adapter/v1/qualification-evidence.schema.json` | draft |
| Draft macOS protected qualification statement (decoded attestation payload) | `adapter/v1/qualification-attestation.schema.json` | draft |
| Draft fixed macOS qualification conformance report | `adapter/v1/qualification-host-report.schema.json` | draft |
| Draft designated-host report signature and [verification rules](adapter/v1/qualification-signatures.md) | `adapter/v1/qualification-host-signature.schema.json` | draft |
| Draft [bridge-aware protected macOS report](adapter/v2/qualification-host-report.md) | `adapter/v2/qualification-host-report.schema.json` | draft |
| Draft bridge-aware designated-host signature | `adapter/v2/qualification-host-signature.schema.json` | draft |
| Draft [bridge-aware protected qualification record](adapter/v2/qualification-attestation.md) | `adapter/v2/qualification-evidence.schema.json` | draft |
| Draft bridge-aware protected release Statement | `adapter/v2/qualification-attestation.schema.json` | draft |
| Draft [Stage 2a measured host report and offline verification bytes](adapter/v3/qualification-host-report.md) for protected T01-T03 and cooperative T21 | `adapter/v3/qualification-host-report.schema.json`, `adapter/v3/qualification-host-signature.schema.json` | draft |
| Draft Stage 2a measured release record and Statement, with separate completed-run references | `adapter/v3/qualification-evidence.schema.json`, `adapter/v3/qualification-attestation.schema.json` | draft |
| Draft [installed H/R inventories, static H descriptor and one-use Machine v3 reservation](machine/v3/stage2a-installed-hr.md) | `machine/v3/domain-inventory.schema.json`, `machine/v3/inventory-ref.schema.json`, `machine/v3/h-service-descriptor-payload.schema.json`, `machine/v3/h-service-descriptor-signed.schema.json`, `machine/v3/measurement-binding.schema.json`, `machine/v3/stage2a-reservation-payload.schema.json`, `machine/v3/stage2a-signed-reservation.schema.json` | draft |
| Draft exact two-member Stage 2a assignment, H provisional map, A-observed ACP children and aggregate B-arm readiness | `machine/v3/stage2a-member-set-*.schema.json`, `hq/v1/stage2a-provisional-member-map.schema.json` | draft; no physical result or live CLI peer proof |
| Draft [observed-body local-test source contract](machine/local-test-v1/stage2a-observed-body-local-test.md): one-use reservation, two-member assignment, B policy/FD3, A ingress authorization and prewrite acceptance, HQ reply and completion ack | `machine/local-test-v1/stage2a-*.schema.json`, `hq/v1/stage2a-local-test-*.schema.json` | draft; no installed route or physical result |
| Draft [c5 child path and order source contract](machine/local-test-v2/stage2a-child-path-order.md): signed per-start work/home/memory and ancillary order with synthetic stale-path/target-first refusals | `machine/local-test-v2/stage2a-*.schema.json` | source-only neutral twin; no installed selection or physical result |
| Draft Machine-to-R pre-Hello FD3 delivery of the exact A-signed two-member assignment and v3 reservation, with protected and cooperative frame versions | `machine/v3/stage2a-runner-member-set-fd3.schema.json` | draft; synthetic schema and authority joins only, no physical result |
| Draft live relay-peer [challenge and verification](machine/v3/stage2a-relay-peer.md) after aggregate readiness | `hq/v1/stage2a-relay-peer-challenge.schema.json`, `machine/v3/stage2a-relay-peer-attestation-payload.schema.json`, `machine/v3/stage2a-relay-peer-signed-attestation.schema.json`, `hq/v1/stage2a-relay-peer-verified.schema.json` | draft; no provider ingress from schema alone |
| Draft A-signed exact two-member B authority from explicit owner policy rows and private Machine-to-B FD3 v3 delivery | `machine/v3/stage2a-b-member-*.schema.json` | draft; B must verify the fixed A pin before bind, then enforce each live peer gate; no physical result |
| Draft same-bound B-to-H observe/arm exchange: A-signed child envelope first, B's two exact arm receipts second, A-signed aggregate Ready last | `hq/v1/stage2a-b-member-arm-exchange.schema.json` | draft; pending acknowledgment grants no ingress or physical result |
| Draft versioned H-to-R prestarted two-member attach preparation for protected and cooperative profiles: full A-signed child/B-policy/Ready envelopes and exact selector/socket joins | `hq/v1/stage2a-member-attach.schema.json` | draft; requires same live R kernel identity on prepare/takeover, no legacy launch change or physical result |
| Draft closed cooperative two-member first reply and delayed one-use owner ACP ticket after both signed member attaches and live B readiness | `hq/v1/cooperative-member-set-attach.schema.json`, `hq/v1/cooperative-owner-acp-ticket.schema.json` | draft; no early ACP ticket, no provider ingress or physical result |
| Draft purpose-separated cooperative B-to-H HMAC bind and same-bound two-member A-policy delivery | `hq/v1/stage2a-cooperative-bridge-bind-exchange.schema.json`, `hq/v1/stage2a-cooperative-member-policy-exchange.schema.json` | draft; B FD3 detached assignment digest differs from later two-member B authority digest; no ingress before both verify |
| Draft separate 32 KiB cooperative B FD3: exact A-signed primary and detached B assignment only, no member policy or ACP ticket | `machine/v3/stage2a-cooperative-b-fd3.schema.json` | draft; protected 16 KiB FD3 remains separate; HMAC bind and same-bound A-policy still required |
| Draft A-signed pre-finalization live lease for each inert ACP wrapper, bound to member grant, two-child observation and kernel tuple, valid at most five seconds | `machine/v3/stage2a-member-live-lease-payload.schema.json`, `machine/v3/stage2a-member-signed-live-lease.schema.json` | draft; does not release ACP input or change singular finalized-Hello leases |
| Draft protected post-Ready A-signed member runtime lease and exact prior-envelope renewal chain, capped by reloaded installed owner approval | `machine/v3/stage2a-member-runtime-lease-payload.schema.json`, `machine/v3/stage2a-member-signed-runtime-lease.schema.json` | draft; protected profile only; no cooperative support or physical result |
| Draft distinct A-signed cooperative aggregate Ready after exact two H observations and B arms | `machine/v3/soul-cooperative-member-ready-payload.schema.json`, `machine/v3/soul-cooperative-member-signed-ready.schema.json` | draft; signed child/H/B observation bytes must resolve before use; protected Ready v1 remains separate |
| Draft distinct same-bound cooperative B observe/arm wire and paired A Ready request | `hq/v1/soul-cooperative-b-member-arm-exchange.schema.json`, `machine/v3/soul-cooperative-member-ready-request.schema.json` | draft; B-to-H request.bridge_arm JCS bytes define each receipt digest; protected op kinds remain separate |
| Draft [Q pre-sign framed wire, argv proof, signed index and clean EOF](machine/v3/stage2a-q-presign.md) | `machine/v3/stage2a-q-*.schema.json` | draft |
| Draft decoded Souls source and build receipt Statement | `adapter/v2/qualification-build-receipt.schema.json` | draft |
| Draft linked-machine [control records and verification rules](control/v1/control-records.md): policy, relayed owner request, owner session, enrollment, link/unlink and machine plan | `control/v1/*.schema.json` | draft |
| Draft local-only credential issuer variant | `records/v1/local-credential-issuance-record.schema.json` | draft |
| Draft owner-signed policy envelope | `control/v1/qualification-policy-envelope.schema.json` | draft |
| Draft macOS protected manifest entry referencing the attestation bundle | `adapter/v1/qualification-reference.schema.json` | draft |
| Draft decoded owner-signed qualification trust policy payload (no signature verification) | `control/v1/qualification-trust-policy.schema.json` | draft |
| Draft [v2 owner qualification trust policy](control/v2/qualification-trust-policy.md) with separate Souls build authority | `control/v2/qualification-trust-policy.schema.json` | draft |
| Draft v2 owner policy signature envelope | `control/v2/qualification-policy-envelope.schema.json` | draft |
| Draft [v3 owner qualification trust policy](control/v3/qualification-trust-policy.md) with distinct frozen `.soul` authority and owner mapping | `control/v3/qualification-trust-policy.schema.json`, `control/v3/qualification-policy-envelope.schema.json` | draft; no production signer or trust root |
| Draft supplemental [Machine/keyd policy acceptance witness](control/v1/qualification-acceptance-witness.md), payload and envelope | `control/v1/qualification-acceptance-witness-payload.schema.json`, `control/v1/qualification-acceptance-witness.schema.json` | draft |
| Draft [controlled Stage 2a measurement bytes](machine/v1/stage2a-measurement.md), snapshot identity and per-start binding | `machine/v1/definition-records.schema.json`, `machine/v1/launch-input-records.schema.json`, `machine/v1/snapshot-identity.schema.json`, `machine/v1/measurement-binding.schema.json` | draft |
| Draft [Machine v2 admin-owned frozen snapshot and signed reservation](machine/v2/stage2a-measurement.md) | `machine/v2/snapshot-identity.schema.json`, `machine/v2/measurement-binding.schema.json`, `machine/v2/stage2a-reservation-payload.schema.json`, `machine/v2/stage2a-signed-reservation.schema.json` | draft |
| Draft Machine pre-sign execution completion and post-sign report commitment | `machine/v1/stage2a-execution-completion-payload.schema.json`, `machine/v1/stage2a-signed-execution-completion.schema.json`, `machine/v1/stage2a-report-commitment-payload.schema.json`, `machine/v1/stage2a-signed-report-commitment.schema.json` | draft |
| Hello (admission request) | `hq/v1/hello.schema.json` | 0.3.0 |
| Scoped notice query/result ([contract and compatibility](hq/v1/notices.md)) | `hq/v1/notice-query.schema.json`, `hq/v1/notice-result.schema.json` | 0.5.0 |
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

The adapter manifest describes package metadata. Its ID and version use the
`hq/v1` Hello encodings. The initial schema covers `profiles_qualified: []`,
including scaffolds with unknown state redirection. It checks the containers
for harness metadata, render targets and session reuse. Their package-specific
contents remain descriptive. A nonempty qualification list needs a versioned
qualification reference and a verified signed record. Package validation alone
establishes neither. [Adapter contract tracking](https://github.com/true-line/soul-adapters/issues/1)
The separate [draft qualification attestation](adapter/v1/qualification-attestation.md)
binds the exact bytes of the [evidence payload](adapter/v1/qualification-evidence.md)
to fixed conformance reports. The existing manifest continues to allow only
unqualified packages.

## Conventions

| Field kind | Encoding |
| --- | --- |
| Soul ID | `^agent_<uuid>$`, lowercase hex (R1) |
| Source notice IDs | Scoped notice `message_id` accepts 1–256 characters; this does not widen generic routing IDs |
| Other identifiers | `^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`; `:` namespaces a reference such as `principal:owner_1` or `workspace:scratch` |
| Grant handles, channel bindings, credential references, idempotency keys | `^[A-Za-z0-9_-]{16,128}$`, broker-generated and opaque, never user-chosen |
| Digests | `sha256:<64 lowercase hex>`; the prefix names the algorithm so it can change without a new field |
| Installation epoch | Integer ≥ 1. `destination_epoch` on the outer frame is a routing hint and may be 0 when the sender has none |
| Revisions, sequences, watermarks | Non-negative integers; lease generations and renewal sequences start at 1 |
| Timestamps | RFC 3339 `date-time`; scoped source `content.createdAt` explicitly preserves epoch milliseconds |
| Capabilities | Versioned tokens, `^[a-z0-9]+(-[a-z0-9]+)*-v[0-9]+$` (e.g. `sealed-inner-v1`) |
| Roles | `^[a-z][a-z0-9-]{0,31}$`; exactly one `lead` in Hello |
| Adapter versions | Exact semver; pins are exact (R12) |
| Paths inside a Soul | Relative; no `.` or `..` segment, no empty segment |
| Profiles, provenance, states | The [enumerations](#enumerations) below |

Every object is `additionalProperties: false`, so a record that tries to carry a secret, a handle, or any unknown field fails closed. hq/v1 socket messages (Hello, admission result, Equip, Ready and lease renewal, lifecycle request) carry `contract: "hq/v1"`, so a version mismatch is visible before any other field is read (T14).

## Schema encodings

Which schema encodes each term. The terms themselves are defined in the platform [glossary](https://github.com/true-line/agent-bot-platform/blob/main/docs/glossary.md).

| Term | Schema |
| --- | --- |
| Admission (clock-in) | `hq/v1/hello.schema.json`, `hq/v1/admission-result.schema.json` |
| Session (device plus client app or profile) | `requested_roles[].client` in Hello; `admitted_runtimes[].client` in the admission result |
| Grant handle, credential reference | `hq/v1/equip.schema.json` |
| Approval | `hq/v1/approval-record.schema.json` |
| Directive, query | `wire/v1/directive-or-query.schema.json` |
| Task | `task/v1/task-record.schema.json`, `task/v1/task-commitment.schema.json` |
| Grant | `records/v1/grant-record.schema.json` |
| Dream run | `records/v1/dream-grant-record.schema.json` |
| Eval cell | `records/v1/eval-plan-record.schema.json` |
| Candidate revision | `records/v1/candidate-revision-record.schema.json` |
| Typed refusal | `common/v1/error-response.schema.json` |

## Enumerations

**Enforcement profiles (Section 4).** Every receipt names the profile in force; a protected claim under a weaker profile is refused with `profile_insufficient` (R8, T21).

| Value | Meaning |
| --- | --- |
| `managed-protected` | Host-enforced member boundaries, broker-only protected egress, caller-bound grants, durable receipts |
| `managed-cooperative` | HQ protects keys, but members share a trust domain or have bypass routes |
| `standalone-unenforced` | Local stub and local credentials within the agent's trust domain |

**Wake classes (Section 6).** A frame whose provenance is `external-untrusted` never cold-starts a Soul, whatever its declared class.

| Value | May cold-start an idle Soul |
| --- | --- |
| `none` | No: mailbox only |
| `notify` | No: warm session only |
| `task` | Yes, when the local broker confirms wake grant and budget |
| `owner` | Yes: originated by the authenticated owner through HQ |

**Task states (Section 7):** `offered`, `accepted`, `running`, `waiting`, `reconciling`, `completed`, `failed`, `canceled`, `expired`. The active states are `accepted`, `running`, `waiting`, `reconciling`. A `waiting` task records one of `owner_input`, `owner_pause`, `dependency`, `provider_availability`, `credential_unavailable`, `reconciliation_decision`.

**Action states (Section 7):** `prepared`, `submitted`, `succeeded`, `rejected`, `unknown`. An `unknown` outcome is reconciled by lookup, never by blind replay (T06).

**Provenance (Section 4):** `owner`, `hq`, `member`, `peer`, `external-untrusted`. Source provenance is recorded separately from data sensitivity; derived outputs inherit the union of source restrictions, and a model cannot clear its own taint.

**Error codes:** `errors/registry.json` (add-only, snake_case exactly as the paper lists them).

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
