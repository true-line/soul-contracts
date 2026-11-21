# Draft qualification trust policy payload

This is the decoded payload of an owner-signed policy for protected adapter
qualification, under [platform PDR-0102](https://github.com/true-line/agent-bot-platform/blob/main/docs/04-decisions/PDR-0102-protected-adapter-qualification.md).
It is one slice of the future `control/v1` policy bundle, not the entire
[PDR-0047](https://github.com/true-line/agent-bot-platform/blob/main/docs/04-decisions/PDR-0047-harbor-is-the-control-plane-of-a-linked-machine.md)
control contract. A schema-valid JSON object has no authority by itself.

Before using it, Machine must verify the owner signature over the exact
policy payload with its pinned owner key, reject a policy revision older than
the highest accepted revision, verify policy time bounds, and retain the last
accepted revision across restart. It must verify release and host report
signatures against this policy and compare the signed reports with measured
installed inputs. HQ may carry a newer policy but cannot add a signer,
override a revocation or extend expiry on its own. Those signature and
measurement checks are not implemented by this schema or its synthetic
fixtures; protected qualification remains unavailable until product consumers
enforce them.

`revocation_snapshot.updated_at` is bound to the snapshot's complete sets by
the owner signature. At a protected launch, reject a missing or future-dated
snapshot and refuse when `now - updated_at > 3600` seconds. Exactly 3600
seconds is current. Policy `issued_at` and `expires_at` do not refresh this
clock. The snapshot may contain the same set as an older one only when the
owner freshly authenticated that snapshot; merely reissuing other policy
fields cannot reset its timestamp. Compare revocation IDs with the exact
attestation bytes, host evidence signer and release workflow being used.

The fixture and semantic checks exercise record shape and time boundaries,
not an owner signature or release trust chain. The unqualified adapter
manifest continues to require `profiles_qualified: []`.
