# Controlled Stage 2a measurement bytes

These schemas encode the exact qualification-only byte rule in the
[Platform Stage 2a measurement interface](https://github.com/true-line/agent-bot-platform/blob/main/docs/03-architecture/interfaces/stage2a-measurement.md).
They do not approve a launch, validate a Soul package, authenticate a host,
or implement a one-use reservation. The positive fixtures are synthetic.

## Definition records and launch-input object

The [definition records](definition-records.schema.json) are one JSON array
ordered by each record's root-relative ASCII `path` as unsigned UTF-8 bytes.
The root is the approved Soul installation root. The array includes the
`Contents` directory itself, `Contents/SoulInfo.json`,
`Contents/SoulLock.json`, and every directory and regular file beneath
`Contents/primitives/` and `Contents/opt/`. No Life, Rebuilt, Recreated or
Dropped path can enter this frozen inventory. The owner-approved inventory
must match the array exactly; a wildcard is insufficient. The fixture shows
five files, including `Contents/opt/quickstart-check.mjs` moved into the
frozen closure.
The array schema alone cannot express this closed tree: the semantic verifier
requires the `Contents` directory record and the two top-level files, checks
parent directories and rejects any other top-level path.

The separate [launch-input records](launch-input-records.schema.json) form
one JSON **object**. Its `files` field is a sorted array of regular-file
records. Paths are relative to one explicit secure-admin-owned launch projection
root, recorded in the binding's `snapshots.launch_inputs`. For example,
`bin/node` and `host/adapters.json` refer to paths inside that projection,
not to the Soul's writable `Contents/host/`. The projection must include
every selected external executable, module, host configuration and
confinement-policy byte. Missing or late-loaded code fails independently of
the record schema.

The same launch-input object includes parsed exact `host_projection.adapters`
and `.installation` values, verified against the separately hashed raw
`host/adapters.json` and `host/installation.json` file bytes. It includes
`selected_command` as an absolute executable regular file inside either the
approved launch snapshot or frozen `Contents/opt/` definition snapshot, and
`argv` as the complete ordered `execve` vector, including argv[0]; for
this controlled run argv[0] equals `selected_command`. `environment` holds
the complete static nonsecret string map and `effective_config` the exact
parsed runtime configuration. B-only bootstrap or credential bytes cannot
enter R's environment or these portable records. `system_images` fixes the
macOS build and code-signing requirement, and `sandbox_policy_digest` names
the separately measured policy file. `component_digests` separately names
Machine, HQ, Souls, the per-installation B `bridge`, the HQ-hosted
`comms_broker`, adapter, native harness and test provider. Each named digest
must match a reviewed file record and the actual selected process or module
closure. The broker is hosted by HQ; the bridge is a distinct principal.

Each directory record has exactly `path`, `kind: "directory"`, and a
four-character octal `mode`. Each file has exactly `path`,
`kind: "regular"`, `mode`, unsigned integer `size`, and `sha256` as **bare**
64 lowercase hexadecimal characters for its descriptor-read bytes. A record
path is printable ASCII, has no leading or trailing slash, empty component,
`.` or `..` component; duplicate and case-folding aliases refuse. Every
literal backslash also refuses, including in host-local snapshot root paths.
Each non-root parent of a definition record must itself be a directory record.
Symlinks, hard links, devices, sockets, ACL allow entries, runner-writable
ancestry and changed opened bytes or mode refuse before digesting.

The system image claim contains the exact macOS ProductVersion, BuildVersion
and Darwin kernel, plus a sorted selected image/module array with absolute
path, per-image signing requirement and lowercase CDHash. Each raw projected
host JSON file and each parsed host JSON, environment, argv and effective
config value is limited to 64 KiB; system images to 512 KiB; the complete
JCS launch object to 1 MiB. Nested JSON is limited to depth 16 and 4,096
nodes. An image-only, argv-only or environment-only change changes the launch
digest; Machine still has to compare those claims with the running system.

Definition records have at most 512 entries; launch inputs have at most 64
regular files. Each regular file is at most 268,435,456 bytes; the definition
array and launch `files` array each allow at most 1,073,741,824 total file
bytes. Limit checks happen before hashing. Serialize the exact definition
array and full launch object as RFC 8785 JCS UTF-8, with duplicate keys
refused and no BOM or trailing newline. The output digests are

```text
definition_measurement = "sha256:" + lowercase_hex(SHA256(
  ASCII("agent-bot/stage2a-definition-opt-closure/v1") || 0x00 || JCS(definition_records)))
launch_input_measurement = "sha256:" + lowercase_hex(SHA256(
  ASCII("agent-bot/stage2a-launch-inputs/v1") || 0x00 || JCS(launch_input_records)))
```

Owner, group, device, inode, generation, birth time, ACL and ancestor state
are custody facts, not record or digest members. Machine must obtain
them from no-follow descriptors and compare the private staged snapshot again
immediately before exec; schema-valid bytes cannot prove these observations.

## Per-start binding

The nonauthorizing [measurement binding](measurement-binding.schema.json)
contains the two portable digests, a separate
[host-local identity](snapshot-identity.schema.json) for each read-only
secure-admin-owned snapshot, exact installed-plan digest, independently measured
candidate package digest, SoulLock's claimed
definition digest, installation/Soul/start/launch/host/HQ epoch, plan ID and
profile. Start IDs use `st_` plus 24 lowercase hex characters; launch IDs use
`ln_` plus 24 lowercase hex characters, matching Machine's prepared start
assignment.
The verifier compares `host_id` and `plan_id` with the independently approved
host and plan, not merely their presence in this object.
Its `installed_plan_digest` is bare 64 lowercase hex in the live Machine
assignment; a signed host report normalizes it to `sha256:` plus the same
characters. `package_sha256` is a separate bare 64-hex digest of the installed
candidate and cannot be inferred from the two closure measurements.
For v3 qualification, `soul_artifact_sha256` is an additional bare 64-hex
digest of the exact frozen installable `.soul` transport. It is not an alias
for this legacy package claim, the adapter release package, or the Souls
runtime `.tgz`. The v3 verifier measures the installed transport bytes and
compares the exact owner-approved Soul identity and definition mapping. It
also authenticates a separate `.soul` release receipt if the owner-signed
`frozen_soul_release_provenance_enabled` feature is true; the private pilot
keeps it false. Until installed measurement and mapping exist, the digest is
a claim only.
`claimed_definition_digest` is the exact `sha256:` value from
SoulLock, not a measurement of SoulLock's own containing file. The approved
one-use plan must map `(soul_id, claimed_definition_digest,
definition_measurement)` and match the separately measured launch inputs.

Both snapshot identities include an absolute root path, device, inode,
generation, birth time in nanoseconds, secure-admin UID/GID and mode. Large host-local
numbers are decimal strings to avoid JCS integer precision loss. The two
roots must be distinct and read-only. Machine's signer and HQ must compare
this same binding across the future pre-Hello reservation, post-Hello
finalization, immutable completed-run record and signed host report. A
protected start and a cooperative T21 replay can use the same frozen
measurement but must spend different one-use reservations and carry different
start and launch IDs and declared profiles. This shared object supplies neither a
signed reservation envelope nor completion evidence; those outer payloads
remain to be specified and implemented.

**Production hold:** the current adapter/v2 signed host report and Machine
verifier do not yet carry these two measurements and host-local snapshot
identities. No Stage 2a host-report signing or protected qualification can
claim this chain until a coordinated versioned report schema, signer and
verifier bind the values through completed physical evidence. This draft
does not weaken or make the existing v2 report optional.

The [byte vectors](../../../fixtures/measurement/v1/byte-vectors.json) and
negative vectors test domain separation, exact inventory, ordering, aliases,
limits, source scope, argv-only and environment-only changes, OS build and
signing constraints, host projection, custody claims, pre-exec identity and
per-start context.
They are fixture oracles only; Machine must verify the physical filesystem,
live process and signed lifecycle independently.
