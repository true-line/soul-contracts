# Draft T01 protected grant caller-binding wire

This is a source-only interface proposal for [Platform T01](https://github.com/true-line/agent-bot-platform/blob/main/docs/02-requirements/traceability-matrix.md) and [PDR-0102](https://github.com/true-line/agent-bot-platform/blob/main/docs/04-decisions/PDR-0102-protected-adapter-qualification.md). It supplies no live refusal, restart evidence, host signature, or qualification. The existing `bridge.qualification.messages.v1` request cannot prove which member used a copied handle because it carries only a model and prompt digest.

## Request and broker authority

The separate `hq.notices.protected.peek.v1` broker kind uses the closed
[protected notice peek request](protected-notice-peek.schema.json): exactly
`{grant_handle, query}`. Its `grant_handle` is the same 35-byte lowercase
`gh_` Equip handle used by this draft's protected grant request. Its `query`
is the released `notice-query` record with `operation: "peek"`; the result is
the released `notice-result` with matching request ID and operation. The
broker kind supplies the outer version discriminator. No runtime, member,
installation or repository selector is accepted outside the closed query.
HQ takes runtime identity exclusively from the authenticated Comms broker
member binding and checks the live grant and notice scope before the read.
The kind remains unregistered unless this exact schema is in HQ's pinned
Contracts bundle. This additive wire does not itself prove a B2-issued handle,
a copied-handle refusal, zero protected effects, or a restart; physical T01
credit still requires independently verified live evidence.

The [invoke request](stage2a-protected-grant-invoke.schema.json) is exact RFC 8785 JCS UTF-8. Its `runtime_id`, installation, start and launch selectors are caller assertions. HQ must compare them to the authenticated broker peer and current protected start under its live admission/lease guard. The request carries the raw ephemeral `gh_` handle only on that authenticated local channel. The one-use nonce, fixed `provider.invoke` operation, provider/model selector and prompt digest prevent a refusal for one operation from substituting for another. HQ hashes the **exact canonical request bytes** as `request_sha256` and the **exact ASCII handle bytes** as `grant_handle_sha256`. The raw handle never enters a retained refusal artifact.

**Member identity is an unresolved authority boundary.** Machine currently gives
R and B access to the same per-start Member socket, and its signed
`stage2a-peer-role/v1` identifies an observed runner or child process, not a
logical member. A socket peer UID, an asserted `runtime_id`, and a finalization
record do not prove which member made an invoke request. The required successor
member role must bind the exact live endpoint path/device/inode/generation,
connecting peer process, current A-signed finalization, runtime, member and a
fresh connection challenge to a separately authenticated member proof. The
proof source and its isolation from other members require owner review in
[Platform discussion #129](https://github.com/true-line/agent-bot-platform/discussions/129#discussioncomment-19830104).
The approved OS model remains one account per Soul installation; this draft
does not require or grant a separate account per member. Until the member
proof is produced and independently verified, `member_id` in the HQ refusal
is an HQ attribution claim, and no T01 credit follows from this wire.

HQ's [refusal assertion](stage2a-protected-grant-refusal-assertion.schema.json) names the broker-attributed runtime and member, not values taken from the request; it also carries the current installation/start/launch, pairing epoch, installation epoch and lease generation. Those names remain claims until the separate member proof above verifies. `seq` is HQ's durable receipt sequence and `effect_invoked: false` with `decision_stage: before_effect` is explicitly HQ's internal claim. HQ must commit this row in the same transaction as refusing the operation, before any protected effect. For T01, `code` is exactly `caller_mismatch`. The assertion composer must join that durable row to the authenticated peer, exact validated request bytes and verified installed host/start/launch/HQ epoch before forwarding it to Machine. It must refuse arbitrary unsigned receipt rows or caller-composed assertions. The verifier checks the assertion's echoed request digest, handle digest, operation, selector, prompt and nonce against the captured request and checks authenticated peer metadata separately.

## Machine custody and offline join

HQ forwards the exact canonical assertion bytes on the authenticated paired HQ→Machine channel. Machine A, running in its secure administrator account, verifies the current pair and signed reservation and issues the [purpose-separated envelope](../../machine/v1/stage2a-protected-grant-signed-refusal.schema.json) over the [payload](../../machine/v1/stage2a-protected-grant-refusal-payload.schema.json). The fixed A purpose is `agent-bot/stage2a-protected-grant-refusal/v1`; the Ed25519 preimage is ASCII purpose, one NUL byte, then the exact canonical payload bytes. The envelope's public key is informational: an offline verifier obtains the Machine key and paired HQ identity from reviewed release/installation evidence, not from either envelope. The A payload embeds the exact HQ assertion bytes and digest, reservation and run IDs, the authenticated HQ request digest and pair epoch, and fixes `evidence_class` to `authenticated-hq-assertion-only`. Machine must not use an HQ-local signing key or issue this envelope after pairing loss.

This signed assertion is **not** an independent no-effect verdict. T01 also requires A's independent owner-driver capture receipt and OS corroboration for the same challenge, request, child process, no protected operation and zero effects, plus a separate restart session. The second-member request must use A's fresh handle, and the previous handle must also fail when replayed after restart. The offline physical verifier must resolve all exact bytes and authenticate the A/Q/driver/HQ chain before giving T01 credit. A missing signature, unknown signer, stale owner policy/revocation snapshot, sequence discontinuity, mismatched member, attempt, request or handle, any effect, or absent restart record refuses. Protected launch and Stage 2a acceptance remain closed until the live producer and verifier exist.
