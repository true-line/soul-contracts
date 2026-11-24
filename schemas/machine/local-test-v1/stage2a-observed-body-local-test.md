# Stage 2a observed-body local-test source contract

This draft family encodes the frozen candidate-4 record shapes as a separate
`machine/local-test-v1` namespace. The private source JSON is pinned by SHA-256
`bca0837385815cefc86b1158e7aad564f1885721e24670e415d3dae41ddbf167`.
The checked-in neutral tuple is re-signed with a deterministic test key; it
preserves record shape and cross-record joins without carrying a provider's
brand or production authority. Run `scripts/validate.py` for schema, signature,
JCS, selector, reply, ack and refusal checks. The generator requires the
private file with that exact digest and is not part of a runtime parser.

The signed reservation identifies the outer launch and host assignment. The
signed two-member assignment binds the reservation, member selectors and
reviewed member set. The signed B authority selects the lead for local-test
ingress, disables the sibling, binds the approved response text hash and names
the **outer** launch at top level. B verifies that launch against both the
reservation assignment and FD3 selectors before opening its socket. The
selected lead member launch remains separate. B's canonical FD3 must be at
most 32 KiB and carries the assignment and B authority envelopes, not the
whole reservation. These schemas close record shapes; consumers must verify
the pinned A key, purpose-separated Ed25519 signatures, canonical bytes,
digests, lifetime, live peer and every cross-record join before granting access.

The HQ ingress reply carries the exact A authorization envelope, ingress-core
digest, one provider result and request/response body digests. B verifies the
A envelope and approved UTF-8 response text hash before preparing a response.
HQ's completion ack echoes the selectors, observed body, authorization and
completion-core digest after Machine has accepted and persisted the completed
run. A late or missing ack leaves the run unqualified even if bytes reached the
client.

## Separate Machine prewrite acceptance

The prewrite proof is a new source checkpoint beyond frozen candidate 4. Its
Ed25519 signature purpose is
`agent-bot/stage2a-observed-body-local-test-prewrite-acceptance/v1`. The signed
payload has `schema`, `kind`, `schema_version`, `selectors`, `hq_epoch`,
`authorization_envelope_sha256`, `prewrite_core_sha256`, `prewrite_receipt`,
`issued_at` and `expires_at`. `prewrite_core_sha256` is SHA-256 of the exact JCS
B prewrite core. That core binds the observed request body, prepared response
wire length and digest, HTTP status, ingress core, peer and bind receipt. The
proof's `expires_at` is no later than ingress authorization, B policy and
reservation expiry, and its lifetime is at most 30 seconds. The proof's
receipt names Machine's durable prewrite acceptance.

Machine signs only after recording that acceptance. HQ forwards the envelope
and receipt unchanged in the three-field prewrite reply:
`prewrite_receipt`, `prewrite_proof_envelope_base64url`, and
`prewrite_proof_envelope_sha256`. B checks the A key, signature, purpose, proof digest,
all selectors and epoch, recomputed prewrite core, receipt and both live
expiries immediately before the first response byte. A forged, expired or
mismatched proof permits zero response bytes. After a timely first byte,
bounded full write and completion may finish after the authorization expires.
The checked-in proof fixture is a new neutral synthetic vector with forged,
expired and mismatched refusal cases. It does not alter candidate 4 or claim a
Machine implementation, provider effect, guest result or acceptance credit.
