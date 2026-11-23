"""Synthetic Q pre-sign bytes and cross-record refusal oracles.

These vectors pin the wire and signatures. They are not physical T21 results.
"""

import base64
import hashlib
import json
from datetime import datetime, timedelta

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from jcs import canonicalize, parse_strict

SCHEMA = "soul-conformance/qualification-session/v1"
INDEX_PURPOSE = "agent-bot/stage2a-q-frame-index/v1"
EOF_PURPOSE = "agent-bot/stage2a-q-finished-eof/v1"
PREFIX = "machine/v3/stage2a-q-"


def digest(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def decode(value):
    raw = base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
    if base64.urlsafe_b64encode(raw).rstrip(b"=").decode() != value:
        raise ValueError("noncanonical base64url")
    return raw


def require(condition, message):
    if not condition:
        raise ValueError(message)


def signed_payload(raw, purpose, key, schema):
    require(canonicalize(parse_strict(raw)) == raw, "signed envelope JCS")
    envelope = parse_strict(raw)
    require(schema.is_valid(envelope), "signed envelope shape and purpose")
    require(decode(envelope["issuer_public_key_base64url"]) == key, "enrolled A key")
    payload_raw = decode(envelope["payload_base64url"])
    require(canonicalize(parse_strict(payload_raw)) == payload_raw, "signed payload JCS")
    require(digest(payload_raw) == envelope["payload_sha256"], "payload digest")
    Ed25519PublicKey.from_public_bytes(key).verify(
        decode(envelope["signature_base64url"]), purpose.encode() + b"\0" + payload_raw)
    return parse_strict(payload_raw)


def frame(raw):
    require(5 <= len(raw) <= 65540 and int.from_bytes(raw[:4], "big") == len(raw) - 4,
            "exact length-prefixed Q frame")
    payload = raw[4:]
    require(canonicalize(parse_strict(payload)) == payload, "raw frame JCS")
    return parse_strict(payload)


def verify(vector, schemas):
    key = decode(vector["issuer_public_key_base64url"])
    require(len(key) == 32, "Ed25519 public key")
    wire_raw = vector["wire_jcs"].encode()
    require(canonicalize(parse_strict(wire_raw)) == wire_raw, "wire JCS")
    wire = parse_strict(wire_raw)
    require(schemas[PREFIX + "framed-wire.schema.json"].is_valid(wire), "wire schema")
    index_raw = vector["index_envelope_jcs"].encode()
    idx = signed_payload(index_raw, INDEX_PURPOSE, key, schemas[PREFIX + "signed-index.schema.json"])
    require(schemas[PREFIX + "pre-sign-index.schema.json"].is_valid(idx), "index schema")
    eof_raw = vector["eof_envelope_jcs"].encode()
    eof = signed_payload(eof_raw, EOF_PURPOSE, key, schemas[PREFIX + "signed-eof.schema.json"])
    require(schemas[PREFIX + "clean-eof.schema.json"].is_valid(eof), "EOF schema")

    require(idx["wire_sha256"] == digest(wire_raw), "index binds raw wire")
    require(eof["index_envelope_sha256"] == digest(index_raw), "EOF binds signed index envelope")
    require(eof["wire_sha256"] == idx["wire_sha256"], "EOF binds same wire")
    require(eof["session_id"] == idx["session_id"] == wire["session_id"], "one session")
    require(eof["finished_frame_sha256"] == idx["finished_frame_sha256"], "same Finished frame")
    require(eof["observation_count"] == idx["observation_count"], "same observation count")
    require(eof["clean_eof_observed"] and eof["no_trailing_bytes"], "clean EOF and no trailing bytes")
    issued = datetime.fromisoformat(idx["issued_at"].replace("Z", "+00:00"))
    eof_at = datetime.fromisoformat(eof["eof_observed_at"].replace("Z", "+00:00"))
    eof_issued = datetime.fromisoformat(eof["issued_at"].replace("Z", "+00:00"))
    require(eof_at <= issued <= eof_at + timedelta(seconds=30) and eof_issued == issued,
            "A signed both records within 30 seconds of EOF")

    decoded = {name: decode(wire[name + "_base64url"]) for name in (
        "begin_frame", "ready_frame", "request_frames", "observation_frames",
        "finish_request_frame", "finished_frame")}
    for name in decoded:
        require(idx[name + "_sha256"] == digest(decoded[name]), "signed raw " + name)
    begin = frame(decoded["begin_frame"])
    ready = frame(decoded["ready_frame"])
    require(schemas[PREFIX + "begin.schema.json"].is_valid(begin), "Begin requires argv proof")
    require(schemas[PREFIX + "ready.schema.json"].is_valid(ready), "Ready requires exec and argv")
    require(begin["session_id"] == ready["session_id"] == idx["session_id"], "frame session")
    require(begin["reservation_sha256"] == idx["reservation_sha256"], "reservation join")
    require(begin["test_plan_sha256"] == idx["test_plan_sha256"], "test plan join")
    require(begin["q_uid"] == ready["uid"] == idx["q_uid"] and
            begin["q_gid"] == ready["gid"] == idx["q_gid"], "Q identity join")
    require(ready["pid"] == idx["q_pid"], "Q PID join")
    require(ready["challenge_sha256"] == idx["q_challenge_sha256"] ==
            digest(decode(begin["challenge_base64url"])), "Q challenge join")
    require(idx["q_challenge_sha256"] != idx["launch_challenge_sha256"], "distinct Q challenge")
    require(ready["source_sha256"] == idx["q_source_sha256"], "Q source join")
    require(ready["exec_path"] == idx["q_executable"] and ready["argv"] == idx["q_argv"],
            "ordered Q executable and argv join")
    require(ready["argv"][0] == ready["exec_path"], "argv[0] executable")
    require(idx["observation_count"] == 1, "vector has one observation")
    request = frame(decoded["request_frames"])
    observation = frame(decoded["observation_frames"])
    finish = frame(decoded["finish_request_frame"])
    finished = frame(decoded["finished_frame"])
    require(request["sequence"] == observation["sequence"] == 1 and
            finish["sequence"] == finished["sequence"] == 2 and
            finished["observation_count"] == 1, "ordered session sequence")
    require(observation["request_sha256"] == digest(decoded["request_frames"][4:]) and
            finished["observations_sha256"] == digest(decoded["observation_frames"]),
            "request and observation bytes")
    ordered = b"".join(decoded[name] for name in (
        "begin_frame", "ready_frame", "request_frames", "observation_frames",
        "finish_request_frame", "finished_frame"))
    require(idx["ordered_frames_sha256"] == digest(ordered), "ordered raw frames")
    require(all(x["session_id"] == idx["session_id"] for x in
                (request, observation, finish, finished)), "all frames share session")


def check_stage2a_q_presign_fixtures(root, schemas, report):
    path = root / "fixtures/qualification/v3/q-presign-argv-synthetic.json"
    vector = json.loads(path.read_text())
    try:
        verify(vector, schemas)
        report(True, "Q pre-sign synthetic wire/index/EOF joins")
    except (ValueError, KeyError, InvalidSignature) as exc:
        report(False, "Q pre-sign synthetic wire/index/EOF joins", str(exc))

    # Coherent shape is insufficient. The signed index, EOF receipt, and raw
    # frames must all agree, including the challenged executable and argv.
    for label, mutate in (
        ("wrong enrolled key", lambda v: v.update(issuer_public_key_base64url="A" * 43)),
        ("wire bytes altered", lambda v: v.update(wire_jcs=v["wire_jcs"] + " ")),
        ("missing EOF", lambda v: v.update(eof_envelope_jcs="")),
        ("wrong index envelope", lambda v: v.update(index_envelope_jcs=v["eof_envelope_jcs"])),
    ):
        bad = dict(vector)
        mutate(bad)
        try:
            verify(bad, schemas)
            report(False, "Q refuses " + label)
        except (ValueError, KeyError, InvalidSignature):
            report(True, "Q refuses " + label)

    def resign(payload, purpose, key):
        raw = canonicalize(payload)
        return canonicalize({
            "schema_version": 1, "purpose": purpose,
            "issuer_public_key_base64url": vector["issuer_public_key_base64url"],
            "payload_sha256": digest(raw),
            "payload_base64url": base64.urlsafe_b64encode(raw).rstrip(b"=").decode(),
            "signature_base64url": base64.urlsafe_b64encode(
                key.sign(purpose.encode() + b"\0" + raw)).rstrip(b"=").decode(),
        })

    # Mutate a signed claim and repair every dependent digest/signature. This
    # isolates the Ready-to-index equality rule from ordinary signature failure.
    key = Ed25519PrivateKey.from_private_bytes(b"\x13" * 32)
    for label, mutate in (
        ("coherently signed wrong Q argv", lambda i: i["q_argv"].__setitem__(1, "--different")),
        ("coherently signed wrong Q executable", lambda i: (i.__setitem__("q_executable", "/tmp/other-node"),
                                                      i["q_argv"].__setitem__(0, "/tmp/other-node"))),
    ):
        bad = dict(vector)
        idx = parse_strict(decode(parse_strict(bad["index_envelope_jcs"])["payload_base64url"]))
        mutate(idx)
        index_raw = resign(idx, INDEX_PURPOSE, key)
        eof = parse_strict(decode(parse_strict(bad["eof_envelope_jcs"])["payload_base64url"]))
        eof["index_envelope_sha256"] = digest(index_raw)
        bad["index_envelope_jcs"] = index_raw.decode()
        bad["eof_envelope_jcs"] = resign(eof, EOF_PURPOSE, key).decode()
        try:
            verify(bad, schemas)
            report(False, "Q refuses " + label)
        except (ValueError, KeyError, InvalidSignature):
            report(True, "Q refuses " + label)
