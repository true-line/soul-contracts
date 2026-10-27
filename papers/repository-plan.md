# Soul Agent Platform: Repository Implementation Plan

Oct 24, 2026 · Chris Kane

Companion to whitepaper draft 0.3 and the operator questions document. This plan says, for each repository, what exists, what must be built or moved, in what order, and which conformance tests prove it. Stage numbers and test IDs are the paper's (Sections 13 and 14). Repository names under `true-line/` exist as of today with scaffolds; the `qwts/` repositories are the existing code the paper migrates.

## 1 Repository map

Repositories follow trust-domain and contract boundaries, not features. Dependencies point only toward the contract repositories.

| Repository | Role | State today | Work package | Stage gates |
| --- | --- | --- | --- | --- |
| true-line/soul-contracts | Schemas, glossary, fixtures, error registry, traceability, papers | Scaffolded; hq/v1 Hello and admission result with fixtures and CI | WP1 | 0 |
| true-line/soul-package | .soul format: manifest, validation, soul build renderer, transfer | Scaffolded; layout and render-plugin spec stubs | WP5 | 1, 3, 4 |
| qwts/agent-comms | Wire, sealing, mailbox, dedup, outbox, task state machine, relay mode, A2A gateway | Exists: NDJSON wire v1, durable mailbox, tasks docs, federation policy accepted, no relay runtime | WP4 | 1, 2b, 4 |
| qwts/managed-machine | HQ: hq/v1 socket, owner auth, admission, grants, keys, task authority, action ledger, broker host, HQ CLI | Exists as a provisioner only; HQ half lives in the agent-bot daemon | WP2, WP6 | 1, 2a, 2b, 3 |
| qwts/agent-bot-identity | Soul runtime: entry point, ACP server and client, member supervision, recovery, notes, dream runs, identity CLI | Exists: daemon with census, lifecycle, wake, approvals; .soul format 1 and 2; dream scheduler and journal | WP3, WP5 | 1, 2b, 3 |
| true-line/soul-adapters | Per-harness ACP adapter, render plugin, signed qualification manifest | Scaffolded; three package stubs | WP3 | 1, 2a, 3 |
| true-line/agent-watcher | Operator observability over HQ: receipts timeline, lease ages, reconciliation queue, diagnostics bundle | Exists; directive and query model not yet reviewed against the paper | WP6 | 3 |
| GeniusBar | Owner front end over the HQ client | Exists; talks to the agent-bot daemon today | WP6 | 3 |
| true-line/soul-conformance | T01–T30, hostile-member suite, simulators, hello.soul, eval harness, release reports | Scaffolded; 30 suite stubs | WP7 | 0 through 4 |
| qwts/managed-machine-config | Host isolation profiles, qualified-adapter catalog, provisioning | Exists: provisioning, fleet, catalog | WP2 | 2a, 4 |

Dependency order: soul-contracts ← soul-package ← agent-comms ← managed-machine. agent-bot-identity depends on contracts, package, comms (client), adapters. soul-adapters depends on contracts and package only. GeniusBar and agent-watcher depend on the HQ client only. soul-conformance depends on contracts at build time and on binaries only at test time.

## 2 Cross-repository sequence

The paper's stages, expressed as what each repository must have landed before the stage can exit.

| Stage | Exit evidence (paper) | What lands, by repository |
| --- | --- | --- |
| 0 Contract baseline (weeks 1–2) | Shared positive and negative fixtures validate in both runtime and broker; T14 | soul-contracts: all Appendix A schemas, fixtures, error registry filled, traceability current. soul-conformance: fixture loader, T14 harness. agent-comms and agent-bot-identity: tests load soul-contracts fixtures instead of local copies. |
| 1 Local vertical slice (weeks 3–5) | One task completes with scoped proposals and one final commitment; T04, T05, T20 | soul-package: manifest, validation, soul build with one fake plugin. soul-adapters: fake adapter package. agent-comms: task state machine library, dedup in a pluggable store. managed-machine: hq/v1 socket, Hello/Admit/Equip/Ready/Lease, grant store, task authority, action ledger, owner session auth (local account). agent-bot-identity: entry point drives two fake adapters over ACP, handoff notes, recovery ladder rung 1. soul-conformance: simulators, hello.soul, Stage 1 demo script. |
| 2a Member isolation (weeks 6–7) | Hostile-member suite passes under the protected label; T01, T02, T03, T21 | managed-machine: HQ-controlled launch, per-member principals, protected connection binding, caller-bound handles, private member state. managed-machine-config: Linux namespace profile. soul-adapters: state redirection honored by the first real adapter. soul-conformance: hostile-member suite. |
| 2b Brokered adapters (weeks 8–9) | Unknown effects reconcile without blind replay; T05–T11, T17–T19, T23, T25, T26 | managed-machine: brokered inference, service adapter host, budgets with sub-allocations, reconciliation. agent-comms: outbox, send reservations, wake classes, poison quarantine, expiry. agent-bot-identity: recovery rungs 2–5, destination checks before failover. soul-adapters: claude-code and codex adapters qualified cooperative, one qualified protected. |
| 3 Operator pilot (weeks 10–12) | Pilot tasks meet functional and operational targets; T16, T22, T24, T27–T30 | managed-machine: HQ CLI complete, approvals, export and restore, accept-revision and rollback-revision. GeniusBar: enrollment, task view, approvals, receipts. agent-watcher: receipts timeline, diag bundle. agent-bot-identity: dream runs with candidate staging. soul-package: renderer with real plugins, candidate tree, transfer export. soul-conformance: eval harness, release report. |
| 4 Portability and relay (after pilot) | Fencing, transfer, partition, crypto conformance; T12, T13, T15 | agent-comms: relay mode, sealing profile, enrollment. managed-machine: coordinated move, installation authority client. soul-package: offline artifacts, target platforms. managed-machine-config: macOS per-member profile. soul-adapters: macOS protected qualification. |

Migration is strangler-style. Nothing new is created before soul-contracts ships its fixtures; the agent-bot daemon keeps working at every step; the daemon's HQ half is retired only when both implementations pass the same soul-conformance run.

## 3 Plan by repository

Each entry lists what to build or move, in order, the paper sections that specify it, and the tests that prove it.

### 3.1 true-line/soul-contracts (WP1)

Done: hq/v1 Hello and admission result, 12 fixtures, canonicalization vector, validator, CI.

1. wire/v1 outer frame and sealed envelope (§6, Appendix A): destination Soul, epoch hint, message ID, expiry, payload size, wake class, required capabilities, sealed block. Fixtures for oversized frame, duplicate key, unknown required capability, stale expiry.
2. task/v1 commitment request and task record (§7, Appendix A): the full state machine as an enum plus transition table fixture; revision conflict and repeated operation ID vectors.
3. Grant record, directive and query, lifecycle request, ready and lease renewal, approval record (§5, §8).
4. Action record, receipt (§7): action state enum, unknown outcome vector.
5. Typed note, dream grant, eval plan, candidate revision record (§10).
6. Transfer record (§11).
7. Error registry: description and retryable flag for all 24 codes; add codes only here, before any implementation emits them.
8. Glossary and traceability kept current with every schema change; a PR that adds a test updates Appendix D's matrix file in the same change.

Tests: T14 (version mismatch) is this repository's own gate at Stage 0. Every other test consumes its fixtures.

### 3.2 true-line/soul-package (WP5)

1. Manifest: SHA-256 per path, sizes, modes; definition-digest byte rules excluding the manifest's own digest field (§11); dependency graph and cycle refusal.
2. Import validation: path traversal, absolute paths, symlink escapes, expansion limits, platform match, host requirements declared in SoulInfo.json (§11, R12).
3. soul build: deterministic render through the plugin interface in `spec/RENDER-PLUGIN.md`; rendered-output digest per adapter into SoulLock.json; `render_failed` naming the class (§10).
4. Candidate tree staging support: a full tree under dreams/runs/<run-id>/candidate/ with its own manifest and digest; promotion to an immutable revision directory (§10).
5. Transfer and export: life selection by class, comms/ as mirror, template and fork derivation, transfer record with no secrets or reusable grants (§11).
6. Offline artifacts and target platforms (Stage 4).

Tests: T16 (package attack) at Stage 3; T15 (transfer) at Stage 4; render determinism is a unit gate for Stage 1.

### 3.3 qwts/agent-comms (WP4)

Exists: NDJSON wire v1 (`lib/wire.mjs`, `canonical-json.mjs`), durable mailbox (ADR-0004), tasks docs (offer, accept, update with revisions), federation policy (ADR-0028), A2A at the edge (ADR-0005), host apps embed agent-comms (ADR-0059).

1. Load soul-contracts fixtures in the existing wire tests; retire local copies (Stage 0).
2. Task state machine as a library: nine states, the Section 7 transition table, compare-and-swap on revision, write-scope exclusion. The library decides nothing about authority; it exposes checks HQ calls.
3. Deduplication and outbox behind a store interface that HQ implements in its protected database (§6, §11); the client keeps a mirror only.
4. Wake classes and the external-untrusted cold-start rule (§6); send reservations and retry reuse (§8); poison quarantine, expiry, mailbox backpressure (§6 defaults).
5. Remove the "comms enforces orchestration" code path; client checks become advisory with the broker repeating them (Appendix B).
6. Relay mode: the same binary with routing only, outer-frame inspection, no execution channel (Stage 4). Sealing profile and enrollment per the reviewed cryptographic contract.
7. A2A and MCP gateways preserving provenance and applying admission policy (§12).

Tests: T05, T08, T18, T23, T25 at Stage 2b; T12, T13 at Stage 4.

### 3.4 qwts/managed-machine (WP2, WP6 CLI)

Exists: provisioning, fleet, catalog. Becomes HQ.

1. hq/v1 control socket with owner session authentication: the installing host account over the access-controlled socket; every approval, grant, and lifecycle request records the owner session (§4).
2. Supervise the existing agent-bot daemon unchanged (migration step 1).
3. Move keyd, delegation-grants, census, lifecycle, wake dispatch, and approvals from the daemon behind hq/v1; Hello, Admit, Equip, Ready, Lease (§5).
4. Protected store: grants, spent nonces, keys, task revisions, deduplication, action ledger, budgets; transactional embedded database; crash persistence stated and tested (§12).
5. Task authority using the agent-comms state library: atomic dedup plus transition plus outbox (§6, §7).
6. Caller binding: HQ-controlled launch, per-member principals, protected connection binding, handles bound to the admitted caller, durable spent-nonce store (§4). Linux profile first.
7. Broker host: brokered inference with destination check against data restrictions, cost reservation and settlement; service adapter host with operation-type, scope, redirect, and payload validation; short-lived-token route labeled in receipts (§4, §8).
8. Budgets: one ceiling, working and maintenance sub-allocations, atomic reservations (§8).
9. Reconciliation: durable action intent before send, idempotency keys, unknown outcome and owner decision (§7).
10. Approval records bound to digest; accept-revision and rollback-revision; drain then re-admit at the new digest (§5, §8, §10).
11. HQ CLI: every approved operation, so headless hosts and tests need no screen (§3, §8); `hq-client` package for GeniusBar and agent-watcher.
12. Export of authority history for transfer; restore after new admission (§11). Coordinated move and installation-authority client (Stage 4).

Tests: T01, T02, T03, T21 at Stage 2a; T06, T07, T09, T10, T11, T17, T19, T26 at Stage 2b; T22, T24, T27, T28, T30 at Stage 3; T15 at Stage 4.

### 3.5 qwts/agent-bot-identity (WP3, WP5 dreams)

Exists: agent-bot daemon (census, lifecycle, wake dispatch, approvals), .soul format 1 and 2, dream scheduler, journal, checkpoints (owner-gated, coverage unverified), identity contract docs, delegation-grants, keyd.

1. Load soul-contracts fixtures; retire `docs/identity-contract.md` in favor of the contracts repository once the glossary matches (Stage 0).
2. Entry point (`agent-bot soul run`, `soul chat`): ACP server as the front door; ACP client driving members through soul-adapters; cooperative scheduling; owner turn preempts at a safe point (§3, §5).
3. Census v2: members and runtimes per Soul, not one harnessAuth (S1 step 3).
4. Typed notes in dreams/inputs/ with batched writes; handoff and open-task state flushed to comms/ immediately (§10); per-member homes with HOME, XDG, PATH, and temp redirected inside the Soul root (§4).
5. Recovery ladder: restart with backoff and quarantine, re-equip through HQ, destination-checked failover, unavailable with queued mail, resume with reconciliation first (§9).
6. Hand the HQ half to managed-machine (migration steps 3 and 6); keep the identity CLI as the Soul's toolset.
7. Dream runs: admitted as a dream-role member under a dream grant; discovery inputs; candidate tree staging through soul-package; evaluation plan and per-cell runs through the soul-conformance eval harness; candidate revision record; never writes primitives/ or SoulInfo.json (§10).
8. Memory consolidation under the dream grant with transactional watermark and deletion of consumed inputs (§10).

Tests: T04, T20 at Stage 1; T09 (entry-point half), T10 at Stage 2b; T22, T29 at Stage 3.

### 3.6 true-line/soul-adapters (WP3)

1. Fake adapter package for Stage 1 (lives in soul-conformance simulators; this repository hosts its manifest).
2. claude-code and codex packages: ACP adapter, render plugin for the classes each harness supports, state redirection into the member's private root, interruption and resume, cost-bound reporting or an explicit `none` (§4, §10, `docs/QUALIFICATION.md`).
3. local-model package: brokered inference to a local destination for budget and receipts; offline route (§4).
4. Qualification runs through soul-conformance per host profile; signed `qualification.json` per version; cooperative first, protected when T02 and T03 pass on the Linux profile.
5. macOS protected qualification after the per-member account profile lands (Stage 4).

Tests: T03 and T21 per adapter at Stage 2a or 2b; T09 at Stage 2b; T27 at Stage 3.

### 3.7 true-line/agent-watcher (WP6)

1. Review its directive and query model against Appendix A; move the vocabulary into soul-contracts or record it as superseded (§12).
2. Re-scope to observability over the HQ client: per-task timeline interleaving receipts (authoritative) and notes (self-reported), lease ages, queue depth, reconciliation queue, unknown outcomes.
3. `diag bundle`: admission result, profile, SoulLock digests, adapter manifests, render log, eval summaries, last receipts with content redacted, OTLP span export; never member homes.

Tests: none of its own; it must display T06 and T17 outcomes correctly during the Stage 3 pilot.

### 3.8 GeniusBar (WP6)

1. Switch its backend from the agent-bot daemon to the HQ client (migration step 6).
2. Enrollment with the prerequisite report; role assignment writing SoulInfo.json as a new revision; destination and grant approval with the exact-action record; profile in force shown on the main view (§8).
3. Task view with queued, delivered, accepted, running, paused, completed, outcome unknown; budget by sub-allocation; unresolved decisions.
4. Candidate review: change list, per-cell matrix, provenance warnings, cost; accept and rollback (§10).

Tests: T24 (approval binding) exercised through its approval path at Stage 3.

### 3.9 true-line/soul-conformance (WP7)

1. Fixture loader and T14 harness (Stage 0).
2. Simulators: fake adapter with kill-at-step; fake service with idempotency, no-idempotency, and accept-then-drop-response modes; fake provider with cost, latency, 5xx, and version string.
3. hello.soul template and the Stage 1 demo script: issue-like task, simulated remote write, kill the lead after acceptance, replacement reconciles, one final commitment with the same remote object (§13).
4. Hostile-member suite: copied handle, HQ file read, credential CLI call, direct provider egress, process-ID reuse, descriptor theft (§4, T01–T03).
5. Eval harness: baseline-in-run replay, train and held-out split, regression rule, ATIF output, per-cell summary (§10).
6. Release report generator naming revision, policy digest, dependency versions, profile, host, adapter versions (§14).
7. Latency measurement for the local authorization and durable-enqueue path, published with workload and storage configuration (§14).

Tests: owns all thirty. The reviewer merges; implementers propose.

### 3.10 qwts/managed-machine-config

1. Linux reference profile: one service identity per member, namespaces around the Soul root, host /usr and /opt read-only, broker socket and workspace mounts as the only exits (§4).
2. macOS profile: one account per member plus sandbox profile, carried from ENG-0339; HQ in its own account (Stage 4).
3. Qualified-adapter catalog consumed by HQ at Admit.

Tests: T01–T03 run against each profile it defines.

## 4 High-level test plan

| Gate | Tests | Run by | Against |
| --- | --- | --- | --- |
| Stage 0 | T14 | soul-conformance CI | soul-contracts fixtures loaded by agent-comms and agent-bot-identity |
| Stage 1 | T04, T05, T20 | soul-conformance, local | HQ, runtime, fake adapters, fake service |
| Stage 2a | T01, T02, T03, T21 | soul-conformance on the Linux reference host | HQ protected profile, one real adapter |
| Stage 2b | T06–T11, T17–T19, T23, T25, T26 | soul-conformance | HQ, broker, real adapters under cooperative or protected as qualified, fake service in all three modes |
| Stage 3 | T16, T22, T24, T27–T30 plus pilot metrics | soul-conformance and the pilot cohort | Full stack with one real service adapter |
| Stage 4 | T12, T13, T15 plus cryptographic conformance | soul-conformance across two hosts and a relay | Relay mode, transfer, installation authority |

Pilot measurements (§14): setup time, completion against a rubric, operator interventions, cost per accepted result, recovery time, unexplained side effects. Targets are hypotheses: first useful task within 30 minutes after account setup, at least 80 percent completion on 50 bounded tasks, zero unauthorized effects in the negative suite, complete receipts for every protected write, p95 under 50 ms for local authorization and durable enqueue.

## 5 Initial how-to

The first end-to-end run, using only the Stage 1 deliverables. Command names are the proposed HQ CLI surface; they are not implemented yet.

1. Install HQ on the Linux reference host under the account that will own it. HQ creates the control socket, key store, and authority database. That account is the owner.
2. `hq soul create hello --template soul-conformance/templates/hello.soul`. HQ validates the manifest and reports missing host requirements. The template produces a new Soul ID.
3. `hq soul roles hello --lead fake-adapter --specialist fake-adapter`. This writes SoulInfo.json as a new definition revision under an owner approval record.
4. `hq grant add hello --resource workspace:scratch --action edit --destination fake-provider --expiry 24h --ceiling 5.00`. Standing authority for the demo; nothing else is granted.
5. `hq soul start hello`. Watch Hello, Admit, Equip, Brief, Ready, Lease in the console; confirm the profile shown is the one you expect (managed cooperative until Stage 2a passes).
6. `agent-bot soul chat hello` and give it the hello task: investigate the seeded issue, change one file in the scratch workspace, run the approved checks, produce a reviewable change.
7. Open the task in the console: the specialist's result appears as a proposal; the lead's commitment finalizes it; the fake service's write has a receipt with an operation ID.
8. Repeat with the demo script: `soul-conformance/scripts/stage1-demo` kills the lead immediately after the fake service accepts the write. The replacement lead must reconcile the operation, complete the task, and show one final commitment with the same remote object. That run is T06 in miniature and is the Stage 1 exit.

## 6 Decisions that block specific repositories

From the paper's Section 16; each blocks the repository named until recorded.

| Decision | Blocks | Needed by |
| --- | --- | --- |
| Owner authentication model (host account over socket; tunnel for remote) | managed-machine step 1 | Stage 1 |
| Authoritative task state in HQ's store; comms/ as mirror | agent-comms step 3, managed-machine step 4 | Stage 1 |
| Member isolation: separate principals on Linux first | managed-machine step 6, managed-machine-config | Stage 2a |
| Epoch semantics: commit fence versus routing hint | agent-comms step 4, managed-machine step 5 | Stage 2b |
| Budget shape: one ceiling, two sub-allocations | managed-machine step 8 | Stage 2b |
| Primitive rendering: canonical plus per-adapter overrides | soul-package step 3, soul-adapters step 2 | Stage 3 |
| Candidate acceptance: whole-candidate, no partial accept | managed-machine step 10, agent-bot-identity step 7 | Stage 3 |
| Federation cryptographic profile | agent-comms step 6 | Stage 4 |
| Installation authority placement | managed-machine step 12 | Stage 4 |
