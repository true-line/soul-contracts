# Stage 2a Q pre-sign record bytes (draft)

This draft fixes the Q session record interface used before A may request a
host-report signature. It implements the Q portion of [Platform
PDR-0102](https://github.com/true-line/agent-bot-platform/blob/main/docs/04-decisions/PDR-0102-protected-adapter-qualification.md).
The exact host report and its trust policy live in
[`adapter/v3`](../../adapter/v3/qualification-host-report.md). The synthetic
vector here is a wire fixture, not an accepted physical qualification run.

## Raw records and signing

Q exchanges canonical UTF-8 JSON in four-byte unsigned big-endian
length-prefixed frames, at most 65,536 JSON bytes per frame. A preserves the
exact observed frame bytes in the `framed-wire` object, encoded as unpadded
base64url. Request and observation fields carry concatenated complete frames;
the ordered transcript is Begin, Ready, alternating request and observation
pairs, Finish request, and Finished response. A hashes raw frames, including
their prefixes, and hashes the canonical RFC 8785 JSON bytes of `framed-wire`.
The record may contain at most 128 observation pairs, and the wire object is
limited to 32 MiB.

A signs two separate canonical RFC 8785 UTF-8 JSON payloads with its enrolled
Ed25519 Machine key. The index purpose is
`agent-bot/stage2a-q-frame-index/v1`; the clean-EOF receipt purpose is
`agent-bot/stage2a-q-finished-eof/v1`. Each signature covers the ASCII purpose,
one zero byte, and the exact payload bytes. Each six-field envelope is itself
canonical JSON, carries unpadded base64url payload and signature, and binds
the SHA-256 of the payload bytes. The index binds the raw wire digest, the
ordered frame digest, each component frame digest, Q kernel and socket
identity, the reservation digest, and the separate launch and Q challenges.
The EOF receipt binds the **index envelope bytes**, wire and Finished frame,
observation count, and A's observed clean EOF with no trailing bytes. A emits
both signed records within 30 seconds after EOF and publishes the EOF receipt
last. Missing or inconsistent records refuse qualification.

Begin has exactly 19 fields, including `require_argv_proof: true`. Ready has
exactly 12 fields, including `exec_path` and the ordered `argv` array. The
offline reader compares Ready's `exec_path` and `argv` with the A-signed index
`q_executable` and `q_argv`; `argv[0]` equals the executable. Unknown or missing
fields, changed order, duplicate keys, noncanonical encodings, mismatched
challenges, and changed signed or framed bytes refuse qualification.

Ready reports Q's own argv. That claim alone does not prove the installed
launchd command or the kernel image that ran. A must independently compare
the installed launchd command and authenticated Q kernel peer before issuing
the index. A downstream offline verifier must also join the signed Q records
to the independently authenticated installed-input evidence and the exact
one-use reservation. These records carry no T01, T02, T03, or T21 verdict by
themselves. The physical driver control socket, ACP capture custody, and
report/completion successor are outside this interface until their bytes are
frozen separately.

The vector generator, validator, and positive/negative schema fixtures are
synthetic. They assert JCS, signature purposes, raw frame digests, EOF joins,
and refusal of coherently re-signed wrong Q executable or argv. They do not
install Q, read a kernel peer, or confer physical evidence credit.
