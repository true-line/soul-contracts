# Stage 2a c5 child path and order source contract

This draft `machine/local-test-v2` family adds a signed, per-start child path and
ancillary-order record. The checked-in vector is a deterministic vendor-neutral
synthetic twin of an externally reviewed signed source, pinned by SHA-256
`9ed32dfb54df653d2ec1d1a11f979275f90e0705736edaa8d8bfacc2e12de8d2`.
The original source bytes and stock-specific memory path stay outside Contracts.
The twin uses a test key and a neutral memory directory; its signature is not
installed authority.

The start slot is the first ten bytes of SHA-256 over the exact UTF-8 bytes
`agent-bot-soul-endpoint-start/v1`, NUL, installation ID, NUL, start ID. Work and
home live under the per-start `state/child-<slot>` directory in the assigned
runner account. The emitted paths include the platform's `/private` prefix.
The memory project slug maps every non-ASCII-alphanumeric byte in the emitted
work path to `-`, including `_`. Ancillary requests stay ordered first, second;
the target may follow the first or both. Target-first refuses. The signed
stale shared-work vector refuses even though its signature is valid.

Before any client selects this family, Machine must compare the exact
owner-approved private tuple and signed package manifest to the installed
client: selected package, executable digests, installation/start slot,
lexical and emitted work/home/memory paths, slug, fixed ancillary ordering,
and every signed hash. The earlier source capture used an ACP binary with a
different digest from the selected stock package; a recapture with the exact
selected ACP is required. The c4 stable shared-work path is not a c5 guest
path. An exact installed Contracts release and client selection pin, reviewed
Machine/HQ/R/B/Q source cohort and separate guest evidence are required before
physical T03 credit. This source-only schema and vector grant none of those.

The same successor PR carries the c4-derived neutral local-test and distinct
Machine prewrite proof source contracts. Their exact signed ingress/prewrite
joins and one-use receipt refusal remain required for any later c5 runtime
integration; this path/order record does not replace that proof.
