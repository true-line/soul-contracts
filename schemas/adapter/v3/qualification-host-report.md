# Draft Stage 2a measured qualification bytes

These [v3 report](qualification-host-report.schema.json),
[signature envelope](qualification-host-signature.schema.json),
[qualification.json](qualification-evidence.schema.json) and
[release Statement](qualification-attestation.schema.json) contracts extend the
[PDR-0102](https://github.com/true-line/agent-bot-platform/blob/main/docs/04-decisions/PDR-0102-protected-adapter-qualification.md)
path with the [admin-owned controlled measurement binding](../../machine/v2/stage2a-measurement.md).
They are source-only. A schema-valid fixture is not a host run, signature,
release or permission to launch.

## Report and signing bytes

One protected report has `profile_in_force: managed-protected`, passing
T01/T02/T03 and the complete v2 `bridge` custody object. A separate cooperative
report has `profile_in_force: managed-cooperative`, passing T21 and no `bridge`
object. Both carry the complete `machine/v2` `measurement_binding` and
`run_evidence` with exact reservation and finalization `{uri,sha256}` refs and
a `challenge_sha256` value. Reservation and finalization must differ in both
URI and digest within each run. These are reported claims until Machine resolves
and authenticates the referenced bytes under its secure-admin custody. No
bearer challenge, bootstrap proof or credential appears in the report.
The binding's explicit bare `soul_artifact_sha256` names exact frozen `.soul`
transport bytes. It must agree across the protected and cooperative reports,
the qualification record and release Statement. The adapter package digest
and separately signed Souls runtime `.tgz` digest retain their own fields.
The legacy binding `package_sha256` remains a distinct claim; equal-looking
fixture digests must never substitute for a typed artifact or receipt.

The runner serializes the **entire** report as RFC 8785 JCS UTF-8, with no BOM
or trailing newline and duplicate object keys refused. The current Machine
implementation's ASCII-only JCS subset refuses non-ASCII report bytes. The
fixed signature purpose is `agent-bot/qualification-host-report/v3`. Keyd
signs SHA-256 of

```text
ASCII("agent-bot/qualification-host-report/v3") || 0x00 || report_bytes
```

using the owner-designated host's Secure Enclave P-256 key and raw 64-byte
`r || s` ES256 signature. The v3 envelope has exactly seven fields:
`schema_version: 3`, fixed `purpose`, `host_id`, `signer_id`,
`report_sha256`, unpadded canonical `report_base64url`, and unpadded canonical
`signature_base64url`. `report_sha256` is `sha256:` plus lowercase SHA-256 of
the exact report bytes. The envelope's host and signer must match the
owner-signed policy's active signer entry for that designated physical host;
ordinary device enrollment supplies no designation. v1/v2 purpose, schema or
envelope cannot substitute for v3.

## Acyclic completion and release binding

The signed report contains the per-start binding and pre-completion references.
It does **not** contain a digest of its completed-run record. Machine must first
spend the exact one-use reservation and authenticate post-Hello finalization,
then prepare the canonical report. Its immutable completed-run record commits
to the exact report digest after physical execution. The release
`qualification.json` and Statement each reference the report payload,
signature envelope and that separately authenticated completed-run record.
This ordering avoids a circular hash. A `started` or merely finalized attempt
is insufficient. The completed-run record's issuer, signature framing,
atomic challenge-consumption and crash-recovery rules are still being defined
in the Machine one-use contract; until they are released and implemented,
positive signing and release acceptance stay closed.

The v3 Statement predicate type is
`https://true-line.ai/soul-contracts/adapter/v3/macos-measured-qualification`.
Its sole subject is the digest of the **exact delivered** `qualification.json`
bytes. The Statement and qualification record carry identical protected and
cooperative report references, each fixed to v3 purpose and schema and each
with its own completed-run reference. The separate cooperative attempt must
use a distinct one-use reservation, finalization, challenge, start ID, launch ID, profile,
launch-input measurement and launch snapshot identity. It may share the
reviewed frozen definition measurement and approved SoulLock mapping.
The reservation and finalization references must each differ in both URI and
digest across the protected and cooperative reports; changing only the URI
does not make reused record bytes a distinct attempt.
The two release `completed_run` references must also differ in URI and digest.

## Offline verification order

The Machine and release verifier must, in order:

1. Authenticate the release-pinned owner Ed25519 root and exact owner-signed
   policy bytes, persist the greatest accepted policy revision across versions
   and reject rollback or equivocation. The current source-only report fixtures
   require the distinct owner-signed [v3 frozen Soul policy](../../control/v3/qualification-trust-policy.md)
   after it is approved and implemented. Independently check policy expiry and
   the signed revocation snapshot. A missing or future snapshot, or age greater
   than **3,600 seconds**, refuses; age exactly 3,600 seconds is current.
2. Authenticate the designated host signer and verify each v3 envelope,
   canonical report bytes, fixed purpose, exact digest and ES256 signature.
   Reject a revoked signer or release workflow.
3. Resolve the two reports' reservation and finalization refs and the release
   record's two completed-run refs. Verify their independent Machine issuer,
   exact bytes, one-use lifecycle and matching full `measurement_binding`.
   Compare host, HQ epoch, installation, Soul/start/launch IDs, plan and
   package digests, frozen definition, full launch-input measurement and both
   host-local snapshot identities with independently retained observations.
   For protected runs, the bridge assignment, B/HQ/Comms receipts and
   Machine-observed HQ-started Soul must also match.
   Independently authenticate the frozen `.soul` release receipt under an
   owner-pinned trust anchor, measure the installed `.soul` bytes, and compare
   the exact owner-approved Soul/definition mapping. No v3 positive path exists
   while that receipt, anchor and mapping remain unspecified or unavailable.
4. Authenticate the designated release workflow, source commit, trust chain
   and signing-time proof for the v3 Statement. Verify its exact subject,
   both report refs and the separately signed Souls build receipt against
   the owner policy. Compare the released adapter package/executable, ordered
   arguments, complete code inputs, native harness, independent runner, host,
   suite revision, evaluation cells, results and physical T01/T02/T03/T21
   evidence with the installed measured bytes.

The qualification record must be dated at or after both physical reports.
Reject a future-dated report, qualification record or authenticated Machine
lifecycle record. The v3 Statement `expires_at` must be strictly later than
every report and authenticated record date and than verification time; equality
at the expiry instant refuses. Its signing-time proof must place the signature
before expiry. A valid owner policy does not extend a stale Statement.

No network lookup is required for these checks, but missing locally
authenticated artifacts refuse. Report fields and URI/digest pairs alone do
not establish physical custody, completed execution or release authority.
Protected launch and Stage 2a acceptance remain closed until the released
producer, verifier, trust pins, measured installation and physical results
all pass.
