# Requirements R1–R12

Source: draft 0.3, Section 2. "Must" and "never" in any contract document trace to one of these.

| ID  | Requirement                                                                                                                                                                                                           |
|-----|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| R1  | A Soul has one stable public identity. Members, installations, runtimes, sessions, and revisions remain separately attributable.                                                                                      |
| R2  | Only local HQ controls lifecycle and protected operations on its host. Relays deliver messages and presence; they do not obtain an execution channel. The owner's administrative channel also terminates at local HQ. |
| R3  | A task's authority is enforced outside the trust domain of the model and its tools. Credentials and signing keys stay there.                                                                                          |
| R4  | The owner chooses role assignments and approved data destinations. Evaluations inform those choices and do not grant permission.                                                                                      |
| R5  | One Soul has one aggregate communication and spending ceiling with named sub-allocations. Nested members do not multiply it.                                                                                          |
| R6  | External material remains data. Its claimed instructions cannot become owner directives through summarization, delegation, or sleep.                                                                                  |
| R7  | Cross-component behavior is specified and tested before implementations depend on it. The wire supports the current and previous supported major contract versions, with explicit capability negotiation.             |
| R8  | Every operating profile reports its actual enforcement guarantees. Missing protection produces a refusal or an explicit weaker profile, never a silent downgrade.                                                     |
| R9  | Every tier keeps working without its upstream. Local conversations, local tasks, and permitted local operations continue during a relay outage; messages queue store-and-forward.                                     |
| R10 | No contract names a model, provider, or harness vendor. Vendor names appear only in configuration, adapter manifests, and evaluation records.                                                                         |
| R11 | A Soul looks like one harness to its user: terminal chat and an ACP agent server in front; the members behind them are invisible except through the audit trail.                                                      |
| R12 | A Soul vendors and pins everything it runs on except the declared OS baseline and declared host toolchains, which are checked at activation and reported when missing.                                                |
