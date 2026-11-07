# Glossary

Source: Soul Agent Platform draft 0.4, Section 3 (SHA-256 `6e8b85af5aea5454314b7563fef83d50b5582f2b6bd9bd2a8a9bd64cdedd3030`). Every repository in the platform uses these terms unchanged; a change here is a contract change. The paper wins on conflict.

## Entities

| Entity               | Meaning                                                                                          | Identity lifetime                          |
|----------------------|--------------------------------------------------------------------------------------------------|--------------------------------------------|
| Principal            | A human or organization that can own or delegate authority                                       | Independent of an agent                    |
| Owner                | The principal whose host account installed HQ and who configures a Soul's authority              | Per HQ installation                        |
| Soul                 | Persistent agent with one address and inbox; one stable public identity (R1)                     | Across moves and revisions                 |
| Definition revision  | Immutable accepted configuration and content digest                                              | One configuration version                  |
| Life                 | A Soul's selected durable state: knowledge, dream inputs, comms mirror, member homes, workspaces | Across moves; distinct from the definition |
| Member               | A role-bearing participant inside a Soul; the lead or a specialist                               | Across replacement runtimes                |
| Lead                 | The one member that plans, routes work, and may finalize task decisions                          | Per role assignment                        |
| Specialist           | A member that returns proposals and evidence to the lead                                         | Per role assignment                        |
| Installation         | A Soul deployed on a particular host                                                             | One deployment                             |
| Installation epoch   | Monotonic fencing value for an installation authority                                            | Advances on authorized replacement         |
| Runtime              | One admitted execution instance of a member                                                      | Until exit or revocation                   |
| Session              | A bounded interaction context within a runtime                                                   | Per context or conversation                |
| Task                 | A durable objective with an owner, state, budget, and completion criteria                        | Until a terminal state                     |
| Grant                | HQ's record that a principal authorized a class of action for a Soul, member, or runtime         | Until expiry or revocation                 |
| Grant handle         | A broker-generated opaque reference to a grant, bound to the admitted caller; never user-chosen  | Per runtime admission                      |
| Credential reference | An opaque pointer to a short-lived credential HQ obtains from the identity service; never the secret itself | Per equip                       |
| Directive            | A task offer from HQ backed by authenticated local authority; peer text cannot acquire the kind (T04) | Until accepted or expired             |
| Query                | A member's question to HQ, answered with a decision record                                       | Per request                                |
| Approval             | HQ-signed record from the authenticated owner session, bound to the digest of the proposed action | Until expiry or a change to the action   |
| Receipt              | An enforcing service's record of a decision or action; notes are self-reported and are not receipts | Under retention policy                  |
| Enrollment           | One-time registration of a Soul, node, or relay with an owner-confirmed challenge                | Until revoked                              |
| Admission (clock-in) | Per-start verification of a Soul and its runtimes by local HQ                                    | Per runtime                                |
| Primitive            | An accepted skill, helper script, tool guidance, or hook in harness-neutral canonical form       | Per definition revision                    |
| Render               | The deterministic build step that turns primitives into each adapter's native configuration      | Per revision and adapter version           |
| Dream run            | One admitted sleep workflow under a dream grant                                                  | Until completion, checkpoint, or limit     |
| Candidate revision   | A staged definition revision awaiting evaluation and owner acceptance                            | Until accepted, rejected, or superseded    |
| Eval cell            | One role on one harness version and one provider within an evaluation plan                       | Per dream run                              |

## Schema encodings

| Term | Schema |
| --- | --- |
| Admission (clock-in) | `hq/v1/hello.schema.json`, `hq/v1/admission-result.schema.json` |
| Grant handle, credential reference | `hq/v1/equip.schema.json` |
| Approval | `hq/v1/approval-record.schema.json` |
| Directive, query | `wire/v1/directive-or-query.schema.json` |
| Task | `task/v1/task-record.schema.json`, `task/v1/task-commitment.schema.json` |
| Grant | `records/v1/grant-record.schema.json` |
| Dream run | `records/v1/dream-grant-record.schema.json` |
| Eval cell | `records/v1/eval-plan-record.schema.json` |
| Candidate revision | `records/v1/candidate-revision-record.schema.json` |

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

## Components and trust domains

Repository column per the owner's decision D1 (2026-10-27, `true-line/agent-bot-daemon` `docs/daemon-plugin-split.md` §1.2 and §10.1): HQ is agent-bot-daemon, and managed-machine stays the provisioner. Draft 0.4's Appendix C still names managed-machine; draft 0.4.1 carries the change.

| Component                         | Source repository                                 | Trust domain                                                                 | Enforces                                                                                               |
|-----------------------------------|---------------------------------------------------|------------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------------|
| HQ                                | agent-bot-daemon                                  | Trusted host service, outside every Soul                                     | Admission, grants, approvals, task commits, action ledger, budgets                                     |
| Broker                            | agent-comms, broker mode, hosted by HQ            | Same trust domain as HQ                                                      | Caller binding, send and consume authorization, dedup, receipts, brokered inference and service egress |
| Relay (site, cloud)               | agent-comms, relay mode                           | Untrusted for content; trusted only for routing and custody of sealed frames | Nothing about authority; stores and forwards                                                           |
| Identity service                  | agent-bot (server)                                | Remote, owner-operated; custody and issuance only                            | Short-lived device-bound credential issuance and its records; never lifecycle                          |
| Installation authority (post-MVP) | Owner-operated service, separate key              | Trusted for installation leases only                                         | Epoch advancement and lease surrender; never lifecycle                                                 |
| Entry point                       | agent-bot-soul-runtime (`agent-bot soul run`)     | Inside the Soul; untrusted for authority                                     | Member supervision, scheduling, recovery ladder; holds no keys                                         |
| Comms client                      | agent-comms, client mode                          | Inside the Soul; untrusted for authority                                     | Early validation only; every security-critical check is repeated by the broker                         |
| Lead, specialist                  | Harness adapters over ACP (soul-adapters)         | Inside the Soul; the model and tool trust domain                             | Nothing; proposes and acts within admitted scopes                                                      |
| GeniusBar, HQ CLI                 | GeniusBar; the `agent-bot` CLI from agent-bot-daemon | Owner's authenticated session on the host                                 | Nothing; a client of HQ                                                                                |
