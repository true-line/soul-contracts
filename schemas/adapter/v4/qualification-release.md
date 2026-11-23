# Draft v4 qualification release binding

This successor to the v3 `qualification.json` and in-toto Statement is for the
authenticated host report chain in this directory. It changes neither the
owner-designated release workflow nor the signed owner policy. The distinct
Statement predicate type is
`https://true-line.ai/soul-contracts/adapter/v4/macos-measured-qualification`.
Its sole subject is the SHA-256 of the exact released `qualification.json`
bytes. Both `conformance` reports and both Statement `host_reports` entries
must name report schema version 4, purpose
`agent-bot/qualification-host-report/v4`, and the exact payload, host signature
envelope, and post-sign commitment byte digests. The protected and cooperative
reports, run IDs, challenge digests, and completed-run records must be distinct.

The release workflow must verify, in order:

1. The owner-signed policy against the reviewed release's owner root, its
   highest accepted revision, expiry, designated host/signer, release workflow
   source and signing-time trust root, revocations, and a snapshot no more than
   3,600 seconds old at the verification instant. Reissuing a policy does not
   renew the snapshot.
2. Exact raw v4 host report bytes and P-256 signature envelopes under the
   designated host keys; then the A-signed pre-sign completion and separately
   A-signed post-sign commitment under an independently enrolled Machine key.
3. Every report reference against independently captured raw Q wire, signed
   frame index and clean EOF; reservation, assignment or finalization, the
   brokered-B publication order and outcome, and the watched request.
   Direct-Comms T21 Q-only control cannot replace brokered-B qualification.
4. The owner-approved one-use attempt, A custody and observed HQ-started Soul,
   fixed runner/adapter/host identity, exact installed H/R and external input
   bytes, independent physical T01/T02/T03 protected and T21 cooperative
   results, and signed segment/capture records. A report's `pass` claim or
   presence of a URI supplies none of these checks.
5. The separate Souls build receipt and frozen artifact mapping; then the
   exact `qualification.json` subject digest, matching Statement report refs,
   authenticated release workflow signing-time proof, and released adapter
   manifest's reference to that signed Statement.

No schema-valid fixture here is a physical result or signing-time proof.
Protected launch and Stage 2a acceptance remain closed until the entire
sequence is implemented and independently verified offline.
