# Draft Machine v3 installed H/R wire

Status: **draft interface, not an accepted protected launch or qualification**. This
version requires a Platform owner decision on the H/R limits and installation
semantics, released producer and consumer code, an authenticated installed
policy, and physical results. The prior `machine/v1` and `machine/v2` bytes
retain their own meanings; a v3 verifier must reject them as v3 input.

The [H and R inventory](domain-inventory.schema.json),
[compact reference](inventory-ref.schema.json),
[static H descriptor](h-service-descriptor-payload.schema.json),
[signed H envelope](h-service-descriptor-signed.schema.json),
[per-start binding](measurement-binding.schema.json), and
[reservation payload](stage2a-reservation-payload.schema.json) and
[envelope](stage2a-signed-reservation.schema.json) are separate types.

## Exact bytes and custody

An inventory is exact RFC 8785 JCS UTF-8 without BOM or trailing newline.
Reject duplicate keys, noncanonical bytes, extra fields, unsorted or duplicate
file and directory paths, and a directory set different from the exact parent
closure of its files. The only allowed rows are regular files and directories.
Each file row binds its relative installed path, mode, byte size, SHA-256,
component ID and path inside that component's authenticated release manifest.
Directory rows bind relative path and reviewed mode. The final sealed root has
mode `0555` below a distinct A-owned A:reader `0750` parent. It and its
out-of-tree sidecar are owned by A with the exact reader group; the sidecar is
`0440`. H and R have different parents and reader groups. A runtime verifier
must reopen by no-follow descriptors and reject any missing, extra, changed,
linked, writable, ACL-bearing or unlisted path, and recheck before every start.
JSON Schema cannot prove the filesystem observations.

The fixed inventory digest is SHA-256 of ASCII purpose, NUL, then exact JCS
inventory bytes, formatted `sha256:` plus lowercase hex. Purpose is
`agent-bot/stage2a-h-code-inventory/v3` for `H-code` and
`agent-bot/stage2a-r-runtime-inventory/v3` for `R-runtime`. The sidecar SHA-256
instead covers its exact JCS bytes without a prefix. The compact reference
binds domain, installation, A and reader identities, exact sealed root and
sidecar path/stat identity, sidecar byte size/hash, reviewed source digest,
counts, total size, inventory digest, and the separately approved owner plan
digest. The preinstall inventory has **no plan digest**: the owner plan may pin
that inventory, then A signs the installed result, without a hash cycle.
The H and R roots, sidecars, and reader groups must be distinct. The R
reference's `owner_plan_digest` must equal `sha256:` plus the binding's bare
`installed_plan_digest`; an R reference from another Soul plan refuses.

The **proposed** ceiling is 512 files, 384 MiB per file, and 1 GiB per H or R
domain, with at most 1,024 explicit child directories and a 2 MiB sidecar.
These are draft schema ceilings, not owner-approved installed policy. A positive
verifier also requires exact limits in the authenticated owner plan and checks
the installed count and bytes against that plan. The measured source lists
(H 480 regular files, R 428) are sizing inputs only; the final installed list
and all late loads still require measurement.

## Static H descriptor and release mapping

The existing paired HQ service install/upgrade plan may opt into an H seal.
That H service plan pins the reviewed H inventory and selected release/source,
host, A/H identities, paths, selected Node/preloader/entry/guard, and exact
argv. It cannot pin the postinstall descriptor digest that A has yet to sign.
After A seals and reopens the installed H tree, A signs the static descriptor.
The signed payload contains the designated `host_id`, HQ service installation,
H reference, H service plan digest, selected component release artifact,
release attestation and manifest digests, and exact selected Node, preloader,
entry paths and installed row hashes. It contains no Soul installation, Soul
set, start ID, or HQ epoch. Each component's independently authenticated
release manifest must map **all and only** its released files to installed H
rows by release path and byte hash. A matching archive digest alone is not
sufficient. The runtime argv begins with the selected H Node, `--no-addons`,
`--disallow-code-generation-from-strings`, `--import`, the selected H preloader,
the H entry, and `run`; the full ordered argv must match the approved plan.
The `guard_policy_sha256` is a claim to be checked against the approved
runtime guard, not evidence that Node's dynamic-code paths are closed.

The H envelope Ed25519 signature covers ASCII
`agent-bot/stage2a-h-service-descriptor/v3`, NUL, then exact JCS payload bytes.
Its `payload_sha256` covers only those JCS bytes. The digest carried into Soul
plans and reservations is SHA-256 of that **purpose plus NUL plus payload**,
not the envelope digest. Verifiers require the independently pinned paired A
public key, the authenticated H owner plan and release attestations, and the
designated host. An envelope's self-declared key grants no trust.

## One-use Soul start

The separately approved Soul plan pins the installed H descriptor digest and
its own reviewed R inventory. A's v3 per-start reservation binds that H digest,
R compact reference, installed Soul plan, HQ epoch, designated host, Soul,
installation, start and launch IDs, and the v2 frozen definition/launch-input
measurement fields. The inherited bare `measurement_binding.package_sha256`
names the Machine package. `adapter_release.package_sha256` is a distinct
qualified adapter release artifact. Its attested release manifest must map all
R component rows, and its executable path and hash plus the complete qualified
code-input list must map to exact R rows. The code-input digest is SHA-256 of
ASCII `agent-bot/stage2a-adapter-code-inputs/v3`, NUL, then JCS of the ordered
absolute path array. The array is resolved from the authenticated adapter
release record; it is not copied into the bounded reservation. The B native
executable and provider configuration remain separately selected and measured.

The reservation signature covers ASCII `agent-bot/stage2a-reservation/v3`, NUL,
then exact JCS payload bytes; its envelope key must match the installed A pin.
The reservation expires at most 30 seconds after issue. A positive verifier
also requires the one-use claim/finalization/completed-run lifecycle, no stale
or replayed reservation, identical H/R identities at pre-exec remeasurement,
and independent physical evidence. The synthetic vector and refusal cases in
`fixtures/reservation/v3/machine-hr-synthetic.json` demonstrate bytes and
cross-field checks only; its public seed has no authority.
