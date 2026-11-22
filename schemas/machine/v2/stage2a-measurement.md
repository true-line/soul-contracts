# Draft Machine v2 admin-custody reservation bytes

The [v2 binding](measurement-binding.schema.json), [snapshot identity](snapshot-identity.schema.json),
[reservation payload](stage2a-reservation-payload.schema.json) and
[signed envelope](stage2a-signed-reservation.schema.json) describe the secure
administrator's frozen Stage 2a start. The portable definition and launch
input record shapes and their domain-separated digest purposes remain in the
[v1 measurement byte contract](../v1/stage2a-measurement.md). Version 2 changes
the custody and signed wire identity; it does not reinterpret those digests.

Each snapshot root is a Machine-published `snap_` directory below
`/private/var/db/managed-machine/soul-snapshots/<installation slot>/`. The slot
is the first 20 lowercase hex digits of SHA-256 of ASCII
`agent-bot-soul-endpoint-installation/v1`, NUL, and the installation ID. The
snapshot root has mode `0555`, owner UID equal to the secure Machine admin UID
in the signed assignment, and owner GID equal to that runner's primary GID.
The two snapshot roots must be distinct. The signed `assignment.package_root`
names the approved installed source; the signed
`measurement_binding.snapshots.definition.root_path` names the frozen copy
executed by R as `--soul`. These paths have different roles and cannot be
substituted for one another. A schema-valid path claim alone does not prove
ownership, ACLs, descriptor identity, approved bytes, or immutability.

The six-field reservation envelope uses `schema_version: 2` and fixed purpose
`agent-bot/stage2a-reservation/v2`. Its Ed25519 signature covers ASCII purpose,
NUL, then exact RFC 8785 JCS payload bytes; SHA-256 digest fields name exact
bytes, with lowercase hex and the `sha256:` prefix. The payload uses
`contract: machine/v2`, `schema_version: 2`, and embeds the full v2 measurement
binding with the exact bare frozen `.soul` artifact digest. The envelope's
issuer key must match Machine's installed pin. The reservation expires no
later than 30 seconds after issue. It does not itself prove that HQ finalized
the start or that a physical host passed a qualification test.

The [synthetic signed vector](../../../fixtures/reservation/v2/machine-admin-synthetic.json)
and fixture assertions exercise the exact canonical bytes and refusals for
alteration, wrong signer, expiry, host mismatch and root-owned snapshots. The
test seed is public fixture material and grants no host authority. Production
acceptance requires independently authenticated installed policy, source
receipt, one-use lifecycle and physical evidence.
