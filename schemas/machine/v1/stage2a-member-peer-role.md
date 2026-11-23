# Draft T01 member peer role proof

This proposed source-only wire addresses the member attribution gap in
[Platform discussion #129](https://github.com/true-line/agent-bot-platform/discussions/129#discussioncomment-19830104).
The current per-start Member socket is shared by R and B peer UIDs. Existing
Machine `stage2a-peer-role/v1` identifies a runner or child process, and its
hello finalization does not independently map later Member connections to
logical member IDs. None of those records alone proves member B used a copied
member-A handle. One OS account per Soul installation remains the account
model; this proposal does not create an OS account per member.

The [payload](stage2a-member-peer-role-payload.schema.json) records an
owner-plan-bound logical member and runtime, the exact observed member process
identity, current reservation and A-signed hello finalization, the derived
per-start Member socket path plus device/inode/generation/birthtime, and the
connecting peer process and fresh challenge. The distinct
[Machine envelope](stage2a-member-peer-signed-role.schema.json) uses purpose
`agent-bot/stage2a-member-peer-role/v1`; Ed25519 signs ASCII purpose, NUL,
then exact RFC 8785 JCS UTF-8 payload bytes. Its embedded public key is
informational. The verifier obtains Machine A's key from independently
reviewed release/installation evidence.

Before A issues a role, it must verify the current owner-reviewed plan maps
this member ID to a **distinct observed member process** under the exact
HQ-started Soul, match the live connection's kernel peer credentials and
process start, remeasure the socket identity, check pairing/reservation and
finalization, and recheck those facts after signing. Merely copying a
`member_id` from HQ or using R's shared UID is forbidden. The role expires
within 60 seconds, is bound to one fresh connection challenge, and cannot be
replayed on another start, endpoint generation, member or process. A runtime
that cannot establish an independently observable member/process mapping
must refuse this role. The owner must approve this process assignment model
and its isolation properties before a producer is enabled.

HQ must authenticate the signed role on the same live Member connection and
atomically bind its exact envelope digest and connection challenge to the
pre-effect refusal row. The current #84 refusal assertion lacks those fields;
the producer and offline verifier must add them after the owner reviews this
interface. The A-signed refusal still attests HQ's internal claim only.
Independent A OS capture, effect count, restart-session evidence and raw Q
chain remain mandatory for T01. A synthetic fixture signature here proves
only test-key byte semantics. There is no live role producer, no authenticated
member evidence, no T01 credit and no protected launch authority.
