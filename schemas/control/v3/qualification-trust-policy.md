# Draft v3 owner qualification policy for frozen Soul bytes

The [v3 policy payload](qualification-trust-policy.schema.json) adds one
frozen installable `.soul` trust slot to the existing v2 adapter release,
Souls runtime `.tgz` build and designated-host authorities. The
[v3 envelope](qualification-policy-envelope.schema.json) has exactly the six
fields used by v2, with `schema_version: 3` and the separate purpose
`agent-bot/qualification-policy/v3`. Its Ed25519 signature covers
`ASCII(purpose) || 0x00 || exact RFC 8785 JCS policy bytes`. The envelope
contains neither the owner root nor any workflow trust-root bytes. Both must
come from a reviewed Machine release, and the local trusted-root file must
hash to the owner-signed `trust_root_sha256` before offline verification.

This is a **source-only candidate**, coordinated with the unsigned frozen
`.soul` Statement proposal in
[soul-package #5](https://github.com/true-line/soul-package/pull/5). The
synthetic fixture has dummy keys, digests and an all-zero signature. It is
never a production policy, receipt, owner approval or physical result.

## Separate frozen build authority

`frozen_soul_build_workflow` pins the `true-line/soul-package` repository,
the exact source commit/tree and workflow path, OIDC issuer, certificate
identity, exact trusted-root JSON digest, builder and toolchain digests, and
the controlled template repository/commit/tree/path/subtree. The candidate
workflow path is `.github/workflows/stage2a-frozen-soul-receipt.yml`; the
template path is `templates/hello.soul`. It pins the separate predicate
`https://true-line.ai/soul-contracts/package/v1/frozen-soul-build`,
`application/vnd.dev.sigstore.bundle.v0.3+json`,
`application/vnd.in-toto+json`, and
`stage2a-frozen-hello-ustar/v1`. The owner must select and sign the exact
Rekor log ID, entry kind/version and trusted root. `dsse/0.0.1` and
`hashedrekord/0.0.2` are the only candidate pairs; the former requires
authenticated signed-entry time and the latter an independently verified
RFC 3161 timestamp for this proposed keyless path. A syntactically valid
selection supplies no authority without the matching verified proofs.
`transparency_log_id` is the lowercase hex encoding of the 32-byte SHA-256
DER SubjectPublicKeyInfo log ID. The verifier must decode the bundle's
`logId.keyId` bytes, compare them to this value and the matching log in the
pinned trusted root, then verify the signed inclusion proof and checkpoint
with that root. A log ID claimed only by the bundle is untrusted.
This follows the [Sigstore trusted-root log ID definition](https://github.com/sigstore/protobuf-specs/blob/main/protos/sigstore_trustroot.proto).

The decoded DSSE Statement must have exactly one subject named
`sha256-<artifact_sha256>.soul`, with only a bare `sha256` digest equal to
the installed archive bytes. Its predicate must carry the exact
`artifact_format`, `builder`, `toolchain_sha256`, `template`, and
`definition_measurement` values. The verifier must match them to the owner
policy, the delivered archive, and the reviewed local build inputs. The
runtime `.tgz` keeps its distinct v2 `souls_build_workflow` authority; its
receipt cannot substitute for a frozen `.soul` receipt.

`frozen_soul_mapping` pins an exact bare archive SHA-256 to one Soul ID,
the claimed SoulLock definition digest and an independently measured frozen
definition digest. The last two are `sha256:`-prefixed. Machine must compare
all four values with the owner-approved plan, authenticated build receipt,
root-owned installed-byte measurement and both one-use physical runs.
The build Statement deliberately omits the Soul ID and owner approval, so
the owner-signed mapping is a separate required authority.

The v3 revocation snapshot adds frozen workflow IDs, signed receipt bundle
digests and bare artifact digests to the existing adapter, host and runtime
revocations. The owner signs its timestamp and exact sets. A missing or
future snapshot, an age greater than **3,600 seconds**, a revoked item,
policy expiry, or a missing exact trust-root file refuses. Exactly 3,600
seconds is current. Reissuing a policy with the old snapshot does not reset
its age.

## Version and implementation boundary

All policy versions share one monotonically increasing accepted revision
and exact policy digest. A lower revision fails; the same revision with
different bytes fails, even across v1, v2 and v3. Existing v1/v2 policies
remain readable for their own historical formats, but neither can authorize
a frozen `.soul` v3 qualification. A newer v2 policy after v3 is also
incapable of granting that qualification. The owner root does not rotate
through this candidate; changing roots requires a separate reviewed path.

Current Machine and keyd implementations accept only v1/v2 owner policy,
and the v3 report/release code presently requires a verified v2 policy for
its source-only fixture checks. A production change must add v3 owner
signature verification, keyd owner-present signing, shared revision
checkpoint, frozen bundle verification and exact installed mapping before
any positive result. Until those changes, an actual owner-signed v3 policy,
verified real receipt, measured installed archive and authenticated one-use
records exist together, protected launch and Stage 2a acceptance stay closed.
