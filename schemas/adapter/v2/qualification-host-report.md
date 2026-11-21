# Draft bridge-aware protected host report

This is a proposed signed payload for the protected macOS T01–T03 run under
[PDR-0052](https://github.com/true-line/agent-bot-platform/blob/main/docs/04-decisions/PDR-0052-process-isolation-for-harness-egress.md)
and [PDR-0102](https://github.com/true-line/agent-bot-platform/blob/main/docs/04-decisions/PDR-0102-protected-adapter-qualification.md).
The v1 host report remains an archival shape and can still describe a
cooperative T21 run. A protected release must not interpret a v1 report as
proof of the per-installation B principal or its custody. A v2 report has
`schema_version: 2`, `profile_in_force: managed-protected`, passing T01–T03
gates and the required `bridge` block. The positive fixture is synthetic; it
does not qualify any adapter.

## Exact signed bytes

Use the v1 designated-host key and owner-policy designation rules, but a new
ASCII purpose: `agent-bot/qualification-host-report/v2`. The payload is exact
UTF-8 JCS bytes, with no BOM or final newline and duplicate keys refused.
The ES256 preimage is `ASCII(purpose) || 0x00 || report_bytes`; the P-256
signature is 64 raw `r || s` bytes in unpadded base64url. The v2 envelope
names the same host and signer and hashes the exact report bytes. A v1
signature, purpose, envelope or decoded-and-reserialized payload cannot
authenticate v2. The current Machine/keyd fixed report signer and Go
`reportShape` accept v1 only; v2 signing and verification remain unavailable
until separately implemented and reviewed.

Machine may request v2 signing only after the one-use approved attempt is
consumed, its immutable completed-run record exists, and Machine has
independently observed the live HQ-started Soul, runner, B process and actual
host profile. Neither HQ's launch receipt nor a `started` attempt proves
that observation. The completed record and Machine observation must bind the
exact report digest, approved plan and candidate, installed binaries and
host. keyd must compare the fixed v2 shape and Machine-authenticated request
before signing; HQ cannot submit arbitrary report bytes for signing.

The Machine start assignment carries the approved `plan_digest` as exactly
64 lowercase hexadecimal characters. The signed v2 report carries that same
digest as `sha256:` followed by those 64 characters. Machine must construct
this normalization only after checking the approved plan's actual bytes and
must compare the report value to the normalized approved value before asking
keyd to sign. A direct unverified copy from HQ or a shape-valid but different
64-character digest fails. The synthetic fixture tests the conversion and a
well-formed digest mismatch; production signer and verifier tests must also
bind the approved plan and Machine reservation before allowing a positive.

## Bridge proof requirements

`bridge.assignment` binds installation, Soul, Machine start, HQ launch,
runtime, plan ID and digest to the exact authenticated Machine reservation
and Machine observation. For this one protected start,
`bridge.assignment.machine_observation` and
`soul_start.machine_observation` must be the exact same `{uri,sha256}`
reference to Machine's independently retained process observation.
`machine_reservation_sha256` is a separate digest of the earlier principal
and endpoint reservation, and cannot substitute for that observation.
`bridge.principals` records kernel UIDs R, B, C,
HQ and Machine. R, B and C are pairwise distinct; B is also distinct from
HQ and Machine. A matching string or declared UID is insufficient: Machine
must compare process and endpoint kernel identity with the signed reservation.

`bridge.endpoints` records the assigned HQ broker, per-start Souls member
socket and B-owned HTTP relay. Each carries its absolute socket path,
parent/socket UID, GID, mode and inode, actual peer UID, and independently
retained Machine custody and kernel-peer evidence. All parents are `2750`,
all sockets `0660`. Broker parent/socket belong to HQ and B's private group;
member parent/socket belong to R and B's private group; relay parent/socket
belong to B and R's private group. Broker and member hello see B as peer;
relay sees R. Paths and inodes must agree with the Machine reservation, be
pairwise distinct, and be retired on stop. Group/mode alone cannot replace
the kernel peer check.

`bridge.handoff` records the digest of B's one-use inherited-anonymous-FD
bootstrap and bind-receipt payloads, with independent evidence that only B
received them. R, C and another B must fail to obtain the B-only broker HMAC
binding or replace B's listener. The signed report contains no broker key,
member token, bootstrap bytes or bearer secret. The logical bootstrap and
receipt fields are being drafted in the separate bridge handoff contract;
its wire field spellings, FD framing and Machine launcher integration must be
reviewed together before accepting a protected run.

`bridge.admission` requires the assigned runner endpoint, B-UID member
hello, actual HQ-hosted Comms HMAC bind on B's live broker connection, HQ's
opaque bind receipt, relay peer R and bind completion before ACP starts.
Machine must compare the retained HQ broker observation and receipt with
the exact start/plan/runtime; a self-reported HMAC outcome or HTTP listener
is insufficient. `bridge.lifecycle` requires observed one-use bootstrap and
receipt, refusal of stale/replayed proof across HQ restart, no ACP start on
failed bind, and cleanup of B/R, tokens and all three endpoints on stop.
The report's `pass` labels are claims until each evidence digest resolves to
the independently captured observation and the protected hostile-member
suite actually exercises the negative cases.

At verification, apply the owner policy and exact **3,600-second** revocation
snapshot freshness rule before the release bundle and host signature. Then
verify the v2 purpose, exact signed bytes, designated physical host, Machine
reservation and completed-run record, installed inputs and all bridge
observations. Require cooperative T21 separately. Any missing, stale,
mismatched, unverifiable or revoked element refuses protected launch; neither
this draft nor a schema-valid fixture enables qualification.
