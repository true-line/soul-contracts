# Draft bridge-aware protected qualification release

The v2 `qualification.json` and release Statement are the only proposed
protected T01–T03 binding for the per-installation bridge UID B in
[PDR-0052](https://github.com/true-line/agent-bot-platform/blob/main/docs/04-decisions/PDR-0052-process-isolation-for-harness-egress.md).
An older v1 qualification, v1 Statement predicate, or v1 protected host report
cannot qualify this protected path. This draft does not enable production
qualification or launch.

The signed in-toto Statement/v1 payload has predicate type
`https://true-line.ai/soul-contracts/adapter/v2/macos-protected-qualification`.
Its sole subject is `qualification.json` with SHA-256 of the **exact delivered
file bytes**. The Statement predicate and v2 qualification record both name
`protected_report` and `cooperative_report`. Each is an object containing
`report_schema_version`, `signature_purpose`, and separate `{uri,sha256}`
references for `payload` and `signature`. Each Statement object must have
exactly the same field values as its qualification counterpart after strict
decoding. The protected report uses schema version 2 and
purpose `agent-bot/qualification-host-report/v2`; the cooperative T21 report
uses version 1 and purpose `agent-bot/qualification-host-report/v1`. The
release verifier must obtain the exact payload and signature-envelope bytes
and check both referenced digests, envelope embedded report bytes/digest,
designated host signer, signature preimage and owner policy. Repacking a
Statement or report changes the signed bytes and cannot preserve authority.

Both the v2 qualification record and the release Statement predicate also
carry an identical `souls_build` object. It binds the exact Souls Git commit
**and tree**, builder and toolchain SHA-256, build workflow, run ID and attempt,
**Souls archive** digest, and the exact byte digest of a separately signed build-receipt
bundle. The designated CI or owner-reviewed build signer must authenticate the
decoded [build receipt](qualification-build-receipt.schema.json) under the
`https://true-line.ai/soul-contracts/adapter/v2/souls-build` predicate. Its
subject digest must equal the independently measured installed Souls archive
or Machine-authenticated installation receipt digest; its source and
build fields must equal `souls_build`. Owner-signed qualification policy must
separately pin the Souls build trust root and signer identity, exact approved
Souls source commit and tree, builder digest, toolchain digest and build
workflow identity. The current v1 policy only designates the adapter release
signer and cannot authenticate this Souls receipt. Machine must fail closed
for production until that owner-policy extension or an equivalent separately
owner-pinned trust anchor is implemented and verified offline. A producer `source.json`
sidecar is useful diagnostics but has no authority unless these signed bytes
bind it. Identical package bytes from different Git trees remain distinct
release candidates and a receipt for one cannot qualify the other. The
release verifier must reject a missing, stale, untrusted or mismatched receipt
even if the package digest and all conformance reports are unchanged.
The Souls archive digest is distinct from `adapter.package_sha256`, which
identifies the adapter package. If the installation process discards the
archive, Machine must preserve an authenticated install receipt and compare
the extracted code-bearing files; a claimed hash in `qualification.json`
cannot stand in for the installed Souls bytes.

Before accepting a release, compare both reports with the qualification's
adapter package, executable path and digest, ordered arguments, complete code
inputs, selected harness and independent runner digests, suite revision and
host identity. The v2 protected report must be the primary run: its run ID,
profile, checks, evaluation cells, renders, cost classification and HQ-started
Soul/Machine observation **and recorded time** agree with `qualification.json`. Require passing
T01–T03 in v2 and passing T21 in v1, including independently observed B
custody and actual HQ broker HMAC bind described in the
[v2 host report](qualification-host-report.md). A report digest or a passing
field does not establish physical execution.

`conformance.runner_observations` binds exact bytes for six additional
observation sets. The authenticated verifier must inspect the captured data:

- `pinned_acp_and_cli`: exact adjacent ACP server and CLI binary digests, and
  the process actually invoked by the pinned runner;
- `private_state`: private HOME, XDG paths and the selected harness's
  temporary-state directory, with no shared writable state;
- `authenticated_session`: authenticated `session/new` when credentials are
  present, or independently observed credential absence and the expected
  refusal when they are not;
- `assigned_endpoints`: the assigned broker, member and relay endpoints and
  kernel peer identities match the Machine reservation and B's live bind;
- `direct_ipv4_ipv6_egress`: direct IPv4 and IPv6 destinations fail from R
  while approved B relay traffic reaches only the assigned path;
- `clean_shutdown`: R/B termination, token retirement, socket removal and
  refusal of stale or replayed bootstrap after stop or HQ restart.

These are evidence references, not self-proving flags. A schema-valid fixture
can only exercise shape and byte-binding refusal. Production must require
Machine's independently retained observation, authenticated host signatures,
the owner-signed trust and revocation policy, exact installed measurements,
passing hostile-member physical tests and a current release. Revocation
snapshot age may not exceed **3,600 seconds**. Missing or unverifiable data
refuses protected qualification.
