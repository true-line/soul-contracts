# Draft v2 owner qualification policy

The [v2 policy payload](qualification-trust-policy.schema.json) extends the
owner trust boundary for a bridge-aware protected qualification. The current
v1 owner policy pins the adapter release workflow and designated host keys,
but has no authority for a Souls source/build receipt. A v1 policy cannot
authorize the v2 protected release or its Souls build provenance.

The [v2 envelope](qualification-policy-envelope.schema.json) carries the
exact canonical UTF-8 policy bytes, their SHA-256, owner key ID and Ed25519
signature. The signing preimage is
`ASCII("agent-bot/qualification-policy/v2") || 0x00 || policy_bytes`.
The reviewed owner public root remains outside the envelope; neither an
envelope nor a build receipt may supply its own root. Machine must reject a
v1 purpose, noncanonical bytes, a key ID mismatch and a policy revision below
the greatest accepted revision across **both** v1 and v2. At the same
revision, only the exact previously accepted policy digest may be reused;
different bytes or a missing accepted digest fail closed. Machine persists
the greatest accepted revision and digest atomically before admission. The
v2 payload keeps the exact 3,600-second revocation snapshot age limit;
expiry, future snapshots and rollback fail closed.

`souls_build_workflow` is a separate authority from `release_workflow`. It
pins the Souls repository, exact reviewed Git commit and tree, workflow path,
OIDC issuer, certificate identity, exact trusted-root JSON digest, builder and
toolchain digests, Sigstore bundle v0.3 media type, DSSE in-toto payload type
and `https://true-line.ai/soul-contracts/adapter/v2/souls-build` predicate.
The owner must review the actual source tree, builder, workflow identity and
trusted root before signing this policy. The fixture values are synthetic
and grant no authority. The signed build receipt's run ID and attempt remain
per-build values; Machine binds them to the exact v2 qualification and release
Statement. The policy revokes Souls build workflow IDs and individual signed
receipt bundle digests in addition to the existing release and host signers.

Machine must authenticate the Souls receipt bundle offline using only the
trusted-root bytes whose digest this owner policy pins. Apply the same
certificate chain, OIDC identity, transparency-log inclusion, signed
checkpoint and independent timestamp requirements as the adapter release
bundle. Compare the receipt subject to the independently measured installed
Souls archive or Machine-authenticated installation receipt, then compare
the exact source/build fields with the owner-approved values and the v2
qualification Statement. Missing, stale, revoked, mismatched or unreviewed
inputs refuse protected launch. A schema-valid payload or synthetic fixture
cannot establish a production trust root or a physical qualification.
