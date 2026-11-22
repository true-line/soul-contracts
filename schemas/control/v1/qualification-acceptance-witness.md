# Draft supplemental qualification policy acceptance witness

This [payload](qualification-acceptance-witness-payload.schema.json) and
[envelope](qualification-acceptance-witness.schema.json) define a proposed
Machine/keyd checkpoint for the greatest locally accepted owner policy. They
do not authorize protected launch. The owner-signed v1 or v2 policy, its
release-pinned Ed25519 public root, release and Souls build attestations,
designated-host report signatures, live pairing, exact local owner approval,
measured installed bytes and physical results remain independent requirements
under [PDR-0102](https://github.com/true-line/agent-bot-platform/blob/main/docs/04-decisions/PDR-0102-protected-adapter-qualification.md).
For a linked machine, the [Harbor control and owner device-presence
signatures](https://github.com/true-line/agent-bot-platform/blob/main/docs/04-decisions/PDR-0047-harbor-is-the-control-plane-of-a-linked-machine.md)
remain separate.

## Exact signed bytes and trust anchors

The fixed purpose is ASCII
`agent-bot/qualification-policy-acceptance-witness/v1`. The payload is UTF-8
RFC 8785 JCS JSON without a BOM or terminal newline. The first implementation
accepts only the ASCII subset. Parsing rejects duplicate keys, noncanonical
bytes, and any payload above 4,096 bytes. The ES256 preimage is
`ASCII(purpose) || 0x00 || payload_bytes`. The signer is a distinct P-256 Secure
Enclave key held by keyd in the secure administrative account. The envelope's
`signature_base64url` is its 64-byte `r || s` signature in strict, canonical,
unpadded base64url. The envelope is at most 8,192 bytes. Decode
`payload_base64url` strictly and verify `payload_sha256` over the **exact**
decoded bytes before parsing them. The envelope and payload witness key IDs
must match.

The witness public SPKI and key ID come from reviewed Machine release and
owner-present pairing state, never from the envelope, an HQ message, or an
ordinary device enrollment. They are distinct from the owner policy Ed25519
root, the pairing owner's P-256 key, and the owner-designated host-report key.
The owner private policy root stays off an ordinary designated host. keyd
cannot sign this witness through its ordinary HQ device-request allowlist.
Only Machine's authenticated secure-admin path may supply a fresh challenge.

The payload names the designated `host_id`, the exact live pairing tuple
`machine_pub`, `hq_pub`, `hq_uid`, `hq_epoch`, `pair_owner_pub`, the pinned
`witness_key_id`, a 32-byte Machine challenge, and the accepted owner policy's
version, revision, payload digest and owner root ID. The policy version is 1
or 2 and selects the corresponding fixed owner-policy purpose and envelope
schema. `policy_sha256` is the SHA-256 of the exact signed canonical policy
payload, not a digest of an unsigned reserialization or of the outer envelope.
The verifier strictly decodes and re-encodes the paired public keys and the
challenge before comparing them to protected state; regex shape alone cannot
prove the P-256 point is valid.
`issued_at` and `expires_at` are UTC RFC 3339 timestamps with whole seconds;
the interval must be positive and at most 60 seconds. This short validity
does not extend the owner's policy, qualification, or revocation-snapshot
expiry.

## Secure-admin acceptance and launch check

At first installation, an owner-present ceremony pins the exact host, pairing
and witness SPKI and initializes keyd's distinct accepted-policy ledger from
the authenticated initial owner-signed policy shipped with the reviewed
Machine release. A later missing ledger, witness key, pairing, or root-owned
checkpoint is a refusal, never an empty revision or automatic first install.
Repair after a crash requires the exact authenticated owner policy and the
same greatest `(policy_version, policy_revision, policy_sha256)` tuple. A v2
upgrade requires a greater revision than the accepted v1 policy. An equal
revision with changed digest or version and any lower revision fail closed.
Once v2 has been accepted, a v1 policy is a version regression and refuses
even if it claims a higher revision.

Under the secure-admin lock, keyd independently verifies the owner policy
signature against its release-pinned public root, fixed purpose, exact bytes,
expiry and current revocation snapshot, then advances its ledger durably by a
monotonic compare-and-swap **before** signing a challenge-bound witness. The
pairing tuple and witness key must still match. Machine generates and durably
records an outstanding 32-byte challenge, verifies the witness against the
pairing-pinned SPKI and consumes the challenge once before protected mutation.
A restart invalidates outstanding challenges; a lost or ambiguous consume
record refuses replay. An HQ epoch change invalidates the old witness.

At **every** protected admission, Machine rereads the greatest accepted
policy tuple and exact authenticated owner policy, checks current policy and
qualification expiry and revocations, and recomputes snapshot freshness.
The snapshot is current only when `0 <= now - updated_at <= 3600` seconds:
exactly 3,600 seconds passes; 3,601 seconds refuses even if a witness signed
one second earlier remains within its own 60-second interval. A newer
accepted policy makes an older witness unusable. The witness is supplemental
to release, installed-byte, designated-host signature and physical-result
verification. No schema-valid or synthetic fixture below supplies a trusted
signature or positive launch authority.

The freshness calculation assumes a trustworthy time source. A stored
last-seen wall-clock value can detect an observed rollback, but cannot prove
elapsed time across power-off or reboot if local time can be reset. Where
Machine cannot establish trustworthy elapsed time through that interval, it
must refuse protected admission until a new authenticated revocation snapshot
and time basis are available. A local clock reading alone must not be claimed
to enforce the 3,600-second bound against arbitrary clock rollback.
