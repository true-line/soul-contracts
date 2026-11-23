# Stage 2a live relay peer challenge (draft)

This additive exchange follows the exact two-member assignment, A-observed
ACP child set, B-arm acknowledgments, aggregate A-signed ready record, and H
finalization. It applies to both `managed-protected` and
`managed-cooperative`. It creates no new account, socket, network permission,
or provider authorization. A ready record anchors each assigned ACP adapter
child but explicitly leaves the later adjacent CLI relay peer unobserved.
The CLI may rotate during ACP `session/new`.

## Wire and signer

1. B accepts one request on the existing Unix relay. Before sending any
   response, including a local policy GET, B reads Darwin `LOCAL_PEERTOKEN`
   UID, PID, and PIDVersion, then calls broker operation literal
   `stage2a-relay-peer-challenge` with one
   `hq/v1/stage2a-relay-peer-challenge` payload over its existing bound broker
   connection to H. The broker frame ID equals payload `rpc_id`. The
   challenge is exact RFC 8785 JCS UTF-8. `nonce_hex`
   is 32 random bytes encoded as exactly 64 lowercase hex digits. `rpc_id`
   is a unique `rpc_` plus 32 lowercase hex digits within this bound start.
   Neither value may be reused on retry, reconnection, or a rotated CLI.
   The challenge deadline is at most 10 seconds after acceptance.
2. H verifies that the request came on the active B-bound connection, matches
   its finalized start, member selector, runtime and A-signed assignment and
   child-observation envelope hashes, and has an unused RPC ID and nonce.
   The initial B proof key was consumed at bind; there is no per-call B MAC.
   H forwards the exact challenge bytes to paired A on the authenticated
   local H-to-A channel. H supplies its active A-signed ready envelope for A
   to recheck; B does not have to know that later ready digest at arm time.
3. A, in its secure administrative account, independently observes the live
   CLI PID/start, executable path and bytes, and direct ACP parent PID/start.
   A compares the executable to the adjacent CLI path and digest from the
   measured source declaration in the signed member assignment and the
   parent to the corresponding A-observed ACP child. A refuses missing,
   exited, changed, reused or sibling processes. `pid_version` is B's
   reported kernel token field; A echoes it without claiming to have
   independently obtained it from process inspection.
4. A signs `machine/v3/stage2a-relay-peer-attestation-payload` using Ed25519.
   The exact signature preimage is the ASCII bytes
   `agent-bot/stage2a-relay-peer-attestation/v1`, one NUL byte, and the exact
   RFC 8785 JCS UTF-8 payload bytes. The payload hashes the exact challenge
   JCS bytes and the signed assignment, child and ready **envelope** bytes.
   Its `expires_at` is no more than five seconds after `issued_at` and no
   later than the one-use reservation expiry. A/keyd does not use a nonsecure
   account or a direct network signer.
5. H verifies A's Ed25519 signature with its independently pinned paired A
   key, exact purpose and canonical bytes, all start/member/runtime and
   challenge fields, live issuance window, and active ready state. H sends
   `hq/v1/stage2a-relay-peer-verified` on the same bound B connection. The
   response includes the complete A envelope bytes as unpadded base64url
   and their SHA-256, plus the exact RPC ID, nonce, peer token and challenge
   digest. It has no separate H signature; its runtime authenticity is the
   existing bound broker connection.
6. B accepts only the response for its outstanding RPC and one-use nonce.
   B checks every echoed field and deadline, then rereads the same live
   kernel peer token and direct parent PID/start immediately before serving
   the held request. It refuses a changed PIDVersion, parent, process start,
   expired response, lost H/A connection, or timeout. A later accepted
   request and every rotated CLI require a fresh challenge. POST also remains
   subject to the existing per-member request digest, grant and spend rules.

## Offline verification and limits

An offline verifier checks the exact JCS challenge bytes, the full A-signed
envelope and payload, the independently pinned A public key, purpose-separated
signature, envelope digests, member and process joins, nonce/RPC correlation,
and timing limits. It never treats the unsigned H reply alone as proof of A
observation or a physical test. The H reply's channel binding and B's final
kernel recheck are runtime facts; a completed Machine-signed host report must
bind the recorded run and physical results before any Stage 2a acceptance.
Absent a complete matching A envelope, active finalization, measured inputs,
or T01/T02/T03/T21 physical result, protected launch and profile acceptance
remain fail closed.
