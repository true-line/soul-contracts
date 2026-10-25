# Glossary

Source: Soul Agent Platform draft 0.3, Section 3. Every repository in the platform uses these terms unchanged; a change here is a contract change.

## Entities

| Entity               | Meaning                                                                                          | Identity lifetime                          |
|----------------------|--------------------------------------------------------------------------------------------------|--------------------------------------------|
| Principal            | A human or organization that can own or delegate authority                                       | Independent of an agent                    |
| Owner                | The principal whose host account installed HQ and who configures a Soul's authority              | Per HQ installation                        |
| Soul                 | Persistent agent with one address and inbox                                                      | Across moves and revisions                 |
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
| Grant handle         | A broker-generated opaque reference to a grant, bound to the admitted caller                     | Per runtime admission                      |
| Credential reference | An opaque pointer to a secret HQ holds; never the secret itself                                  | Per equip                                  |
| Directive            | A task offer from HQ backed by authenticated local authority                                     | Until accepted or expired                  |
| Query                | A member's question to HQ, answered with a decision record                                       | Per request                                |
| Receipt              | An enforcing service's record of a decision or action                                            | Under retention policy                     |
| Enrollment           | One-time registration of a Soul, node, or relay with an owner-confirmed challenge                | Until revoked                              |
| Admission (clock-in) | Per-start verification of a Soul and its runtimes by local HQ                                    | Per runtime                                |
| Primitive | An accepted skill, helper script, tool guidance, or hook in harness-neutral canonical form | Per definition revision |
| Render | The deterministic build step that turns primitives into each adapter's native configuration | Per revision and adapter version |
| Dream run | One admitted sleep workflow under a dream grant | Until completion, checkpoint, or limit |
| Candidate revision | A staged definition revision awaiting evaluation and owner acceptance | Until accepted, rejected, or superseded |
| Eval cell | One role on one harness version and one provider within an evaluation plan | Per dream run |

## Components and trust domains

| Component                         | Source repository                       | Trust domain                                                                 | Enforces                                                                                               |
|-----------------------------------|-----------------------------------------|------------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------------|
| HQ                                | managed-machine (daemon)                | Trusted host service, outside every Soul                                     | Admission, grants, keys, task commits, action ledger, budgets                                          |
| Broker                            | agent-comms, broker mode, hosted by HQ  | Same trust domain as HQ                                                      | Caller binding, send and consume authorization, dedup, receipts, brokered inference and service egress |
| Relay (site, cloud)               | agent-comms, relay mode                 | Untrusted for content; trusted only for routing and custody of sealed frames | Nothing about authority; stores and forwards                                                           |
| Installation authority (post-MVP) | Owner-operated service, separate key    | Trusted for installation leases only                                         | Epoch advancement and lease surrender; never lifecycle                                                 |
| Entry point                       | agent-bot-identity (agent-bot soul run) | Inside the Soul; untrusted for authority                                     | Member supervision, scheduling, recovery ladder; holds no keys                                         |
| Comms client                      | agent-comms, client mode                | Inside the Soul; untrusted for authority                                     | Early validation only; every security-critical check is repeated by the broker                         |
| Lead, specialist                  | Harness adapters over ACP               | Inside the Soul; the model and tool trust domain                             | Nothing; proposes and acts within admitted scopes                                                      |
| GeniusBar, HQ CLI                 | GeniusBar; managed-machine CLI          | Owner's authenticated session on the host                                    | Nothing; a client of HQ                                                                                |
