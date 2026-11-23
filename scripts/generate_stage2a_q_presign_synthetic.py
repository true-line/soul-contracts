#!/usr/bin/env python3
"""Generate deterministic, synthetic Q pre-sign contract vectors.

The fixed private key exists only for schema fixtures. It is not an enrolled
Machine key and the generated records never count as physical evidence.
"""

import base64
import hashlib
import json
import pathlib
import struct
import sys

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from jcs import canonicalize  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parents[1]
BASE = "machine/v3/stage2a-q-"
SESSION_SCHEMA = "soul-conformance/qualification-session/v1"
DIGEST = {"type": "string", "pattern": "^sha256:[0-9a-f]{64}$"}
TOKEN = {"type": "string", "minLength": 1, "maxLength": 128}
ID = {"type": "string", "pattern": "^[0-9a-f]{32}$"}
TIME = {"type": "string", "pattern": "^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(?:\\.\\d{3})?Z$"}
POS = {"type": "integer", "minimum": 1, "maximum": 2147483647}
NONNEG = {"type": "integer", "minimum": 0, "maximum": 2147483647}
PATH = {"type": "string", "pattern": "^/[^\\u0000\\r\\n]+$", "maxLength": 512}
B64 = {"type": "string", "pattern": "^[A-Za-z0-9_-]+$"}
ARGV = {"type": "array", "minItems": 3, "maxItems": 128,
        "items": {"type": "string", "minLength": 1, "maxLength": 4096}}


def sha(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def b64(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def frame(obj):
    raw = canonicalize(obj)
    return struct.pack(">I", len(raw)) + raw


def schema(name, title, props):
    relative = BASE + name + ".schema.json"
    obj = {"$schema": "https://json-schema.org/draft/2020-12/schema",
           "$id": "https://true-line.ai/soul-contracts/" + relative,
           "title": title, "type": "object", "required": list(props),
           "properties": props, "additionalProperties": False}
    path = ROOT / "schemas" / relative
    path.write_text(json.dumps(obj, indent=2) + "\n")
    return relative


def fixture(relative, obj, invalid_field, invalid_value):
    stem = pathlib.Path(relative).name.removesuffix(".schema.json")
    positive = {"schema": relative, "input": obj, "expect": {"schema": "valid"},
                "canonical_sha256": sha(canonicalize(obj))}
    positive_path = ROOT / "fixtures/positive" / (stem + ".synthetic.json")
    positive_path.write_text(json.dumps(positive, indent=2, sort_keys=True) + "\n")
    negative = dict(obj)
    negative[invalid_field] = invalid_value
    negative_record = {"schema": relative, "input": negative, "expect": {"schema": "invalid"},
                       "base": {"fixture": "positive/" + positive_path.name,
                                "sha256": sha(positive_path.read_bytes())}}
    (ROOT / "fixtures/negative" / (stem + ".synthetic.bad.json")).write_text(
        json.dumps(negative_record, indent=2, sort_keys=True) + "\n")


def signed(payload, purpose, private, public):
    raw = canonicalize(payload)
    return {"schema_version": 1, "purpose": purpose,
            "issuer_public_key_base64url": b64(public),
            "payload_sha256": sha(raw), "payload_base64url": b64(raw),
            "signature_base64url": b64(private.sign(purpose.encode() + b"\0" + raw))}


def main():
    session = "1234567890abcdef1234567890abcdef"
    soul = "agent_12345678-1234-1234-1234-1234567890ab"
    start = "st_1234567890abcdef12345678"
    challenge = b"B" * 32
    launch = sha(b"launch challenge")
    q_digest = sha(challenge)
    reservation = sha(b"synthetic signed reservation envelope")
    plan = sha(b"synthetic test plan")
    source = sha(b"synthetic Q source")
    executable = "/usr/local/bin/node"
    argv = [executable, "--", "/tmp/q.mjs"]
    begin = {"schema": SESSION_SCHEMA, "kind": "begin", "session_id": session,
             "challenge_base64url": b64(challenge), "cohort_id": "synthetic-cohort",
             "installation_id": "synthetic-install", "soul_id": soul, "start_id": start,
             "host_id": "synthetic-host", "profile": "managed-protected",
             "reservation_sha256": reservation, "test_plan_sha256": plan,
             "suite_revision": "1" * 40, "ps_sha256": sha(b"synthetic ps"),
             "path_roots": ["/tmp/q-root"], "q_uid": 501, "q_gid": 20,
             "deadline_at": "2026-11-22T12:05:00Z", "require_argv_proof": True}
    ready = {"schema": SESSION_SCHEMA, "kind": "ready", "session_id": session,
             "challenge_sha256": q_digest, "sequence": 0, "pid": 812, "uid": 501,
             "gid": 20, "source_sha256": source,
             "captured_at": "2026-11-22T12:00:00Z", "exec_path": executable, "argv": argv}
    request = {"schema": SESSION_SCHEMA, "kind": "observe", "session_id": session,
               "sequence": 1, "gate": "T01", "phase": "launch", "event_id": "first",
               "processes": [], "paths": []}
    req_frame = frame(request)
    observation = {"schema": SESSION_SCHEMA, "kind": "observation", "session_id": session,
                   "challenge_sha256": q_digest, "sequence": 1,
                   "request_sha256": sha(req_frame[4:]),
                   "captured_at": "2026-11-22T12:00:01Z", "gate": "T01",
                   "phase": "launch", "event_id": "first", "processes": [], "paths": []}
    framed = {"begin_frame": frame(begin), "ready_frame": frame(ready),
              "request_frames": req_frame, "observation_frames": frame(observation),
              "finish_request_frame": frame({"schema": SESSION_SCHEMA, "kind": "finish",
                                              "session_id": session, "sequence": 2})}
    framed["finished_frame"] = frame({
        "schema": SESSION_SCHEMA, "kind": "finished", "session_id": session,
        "challenge_sha256": q_digest, "sequence": 2, "observation_count": 1,
        "observations_sha256": sha(framed["observation_frames"]),
        "captured_at": "2026-11-22T12:00:02Z"})
    wire = {"schema": SESSION_SCHEMA, "kind": "framed-wire", "session_id": session,
            **{name + "_base64url": b64(raw) for name, raw in framed.items()}}
    wire_raw = canonicalize(wire)
    idx = {"schema": SESSION_SCHEMA, "kind": "pre-sign-index", "cohort_id": "synthetic-cohort",
           "installation_id": "synthetic-install", "soul_id": soul, "start_id": start,
           "host_id": "synthetic-host", "profile": "managed-protected",
           "reservation_sha256": reservation, "session_id": session,
           "q_challenge_sha256": q_digest, "launch_challenge_sha256": launch,
           "q_source_sha256": source, "test_plan_sha256": plan,
           "q_socket_path": "/tmp/q.sock", "q_socket_device": 1, "q_socket_inode": 2,
           "q_socket_birth_seconds": 1795348700, "q_socket_birth_nanos": 123,
           "q_pid": 812, "q_uid": 501, "q_gid": 20, "q_parent_pid": 811,
           "q_process_group_id": 811, "q_start_seconds": 1795348750,
           "q_start_micros": 123456, "q_executable": executable, "q_argv": argv,
           "wire_sha256": sha(wire_raw),
           "ordered_frames_sha256": sha(b"".join(framed.values())),
           **{name + "_sha256": sha(raw) for name, raw in framed.items()},
           "observation_count": 1, "issued_at": "2026-11-22T12:00:04Z"}
    private = Ed25519PrivateKey.from_private_bytes(b"\x13" * 32)
    public = private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
    index = signed(idx, "agent-bot/stage2a-q-frame-index/v1", private, public)
    index_raw = canonicalize(index)
    eof = {"schema": SESSION_SCHEMA, "kind": "finished-clean-eof", "session_id": session,
           "index_envelope_sha256": sha(index_raw), "wire_sha256": sha(wire_raw),
           "finished_frame_sha256": sha(framed["finished_frame"]),
           "observation_count": 1, "clean_eof_observed": True,
           "no_trailing_bytes": True, "eof_observed_at": "2026-11-22T12:00:03Z",
           "issued_at": "2026-11-22T12:00:04Z"}
    eof_envelope = signed(eof, "agent-bot/stage2a-q-finished-eof/v1", private, public)

    common = {"schema": {"const": SESSION_SCHEMA}}
    begin_props = {**common, "kind": {"const": "begin"}, "session_id": ID,
                   "challenge_base64url": {"type": "string", "pattern": "^[A-Za-z0-9_-]{43}$"},
                   "cohort_id": TOKEN, "installation_id": TOKEN,
                   "soul_id": {"type": "string", "pattern": "^agent_[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$"},
                   "start_id": {"type": "string", "pattern": "^st_[0-9a-f]{24}$"},
                   "host_id": TOKEN, "profile": {"enum": ["managed-protected", "managed-cooperative"]},
                   "reservation_sha256": DIGEST, "test_plan_sha256": DIGEST,
                   "suite_revision": {"type": "string", "pattern": "^[0-9a-f]{40}$"},
                   "ps_sha256": DIGEST,
                   "path_roots": {"type": "array", "minItems": 1, "maxItems": 16,
                                  "uniqueItems": True, "items": PATH},
                   "q_uid": {"type": "integer", "minimum": 400, "maximum": 2147483647},
                   "q_gid": POS, "deadline_at": TIME, "require_argv_proof": {"const": True}}
    ready_props = {**common, "kind": {"const": "ready"}, "session_id": ID,
                   "challenge_sha256": DIGEST, "sequence": {"const": 0},
                   "pid": POS, "uid": POS, "gid": POS, "source_sha256": DIGEST,
                   "captured_at": TIME, "exec_path": PATH, "argv": ARGV}
    wire_props = {**common, "kind": {"const": "framed-wire"}, "session_id": ID,
                  **{name + "_base64url": B64 for name in framed}}
    idx_props = {**common, "kind": {"const": "pre-sign-index"},
                 "cohort_id": TOKEN, "installation_id": TOKEN,
                 "soul_id": begin_props["soul_id"], "start_id": begin_props["start_id"],
                 "host_id": TOKEN, "profile": begin_props["profile"],
                 "reservation_sha256": DIGEST, "session_id": ID,
                 "q_challenge_sha256": DIGEST, "launch_challenge_sha256": DIGEST,
                 "q_source_sha256": DIGEST, "test_plan_sha256": DIGEST,
                 "q_socket_path": PATH, "q_socket_device": POS, "q_socket_inode": POS,
                 "q_socket_birth_seconds": POS,
                 "q_socket_birth_nanos": {"type": "integer", "minimum": 0, "maximum": 999999999},
                 "q_pid": POS, "q_uid": begin_props["q_uid"], "q_gid": POS,
                 "q_parent_pid": POS, "q_process_group_id": POS, "q_start_seconds": POS,
                 "q_start_micros": {"type": "integer", "minimum": 0, "maximum": 999999},
                 "q_executable": PATH, "q_argv": ARGV, "wire_sha256": DIGEST,
                 "ordered_frames_sha256": DIGEST,
                 **{name + "_sha256": DIGEST for name in framed},
                 "observation_count": {"type": "integer", "minimum": 1, "maximum": 128},
                 "issued_at": TIME}
    eof_props = {**common, "kind": {"const": "finished-clean-eof"}, "session_id": ID,
                 "index_envelope_sha256": DIGEST, "wire_sha256": DIGEST,
                 "finished_frame_sha256": DIGEST,
                 "observation_count": {"type": "integer", "minimum": 1, "maximum": 128},
                 "clean_eof_observed": {"const": True}, "no_trailing_bytes": {"const": True},
                 "eof_observed_at": TIME, "issued_at": TIME}
    envelope_props = {"schema_version": {"const": 1}, "purpose": None,
                      "issuer_public_key_base64url": {"type": "string", "pattern": "^[A-Za-z0-9_-]{43}$"},
                      "payload_sha256": DIGEST, "payload_base64url": B64,
                      "signature_base64url": {"type": "string", "pattern": "^[A-Za-z0-9_-]{86}$"}}
    records = [
        ("begin", "Q Begin frame with mandatory argv challenge", begin_props, begin, "require_argv_proof", False),
        ("ready", "Q Ready frame with challenged executable and argv", ready_props, ready, "argv", []),
        ("framed-wire", "Exact framed Q session bytes", wire_props, wire, "kind", "unframed"),
        ("pre-sign-index", "A observed Q session pre-sign index", idx_props, idx, "q_argv", []),
        ("clean-eof", "A observed clean EOF receipt", eof_props, eof, "clean_eof_observed", False),
        ("signed-index", "A signed Q frame index envelope",
         {**envelope_props, "purpose": {"const": "agent-bot/stage2a-q-frame-index/v1"}},
         index, "purpose", "agent-bot/stage2a-q-finished-eof/v1"),
        ("signed-eof", "A signed Q clean EOF envelope",
         {**envelope_props, "purpose": {"const": "agent-bot/stage2a-q-finished-eof/v1"}},
         eof_envelope, "purpose", "agent-bot/stage2a-q-frame-index/v1"),
    ]
    for name, title, props, obj, bad_field, bad_value in records:
        fixture(schema(name, title, props), obj, bad_field, bad_value)
    vector = {"issuer_public_key_base64url": b64(public), "wire_jcs": wire_raw.decode(),
              "index_envelope_jcs": index_raw.decode(),
              "eof_envelope_jcs": canonicalize(eof_envelope).decode()}
    path = ROOT / "fixtures/qualification/v3/q-presign-argv-synthetic.json"
    path.write_text(json.dumps(vector, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
