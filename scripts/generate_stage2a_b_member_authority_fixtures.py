#!/usr/bin/env python3
"""Regenerate synthetic A-signed two-member B FD3 contract vectors."""

import base64
import copy
import hashlib
import json
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from jcs import canonicalize

ROOT = Path(__file__).resolve().parents[1]
PURPOSE = "agent-bot/stage2a-b-member-authority/v1"
PIN = "/Library/Application Support/ai.true-line.agent-bot-hq/soul-authority.pub"
PREFIX = "stage2a-b-member-authority.two-member-synthetic"


def b64(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def sha(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def write(path, value):
    dst = ROOT / path
    dst.parent.mkdir(parents=True, exist_ok=True)
    dst.write_text(json.dumps(value, sort_keys=True, indent=2, ensure_ascii=False) + "\n")


def fixture(schema, value, positive, suffix):
    name = schema.rsplit("/", 1)[-1].removesuffix(".schema.json") + ".two-member-synthetic.json"
    path = "fixtures/" + ("positive/" if positive else "negative/") + name
    data = {"schema": schema, "input": value, "expect": {"schema": "valid" if positive else "invalid"}}
    if positive:
        data["canonical_sha256"] = sha(canonicalize(value))
    else:
        base = "fixtures/positive/" + name
        data["base"] = {"fixture": base.removeprefix("fixtures/"), "sha256": sha((ROOT / base).read_bytes())}
    write(path, data)


def main():
    source = json.loads((ROOT / "fixtures/reservation/v3/stage2a-member-set.synthetic.json").read_text())[
        "managed-protected"]
    assignment_raw = source["assignment_envelope_jcs"].encode()
    assignment = json.loads(source["assignment_payload_jcs"])
    shared_key = sha(b"fixture-local-relay-placeholder")
    rows = []
    for i, member in enumerate(assignment["members"]):
        rows.append({key: member[key] for key in
                     ("member_id", "launch_id", "member_selector", "adjacent_cli_path", "adjacent_cli_sha256")})
        rows[-1]["qualification"] = {
            "model": "fixture-model-" + str(i + 1),
            "request_sha256": sha(("fixture-request-" + str(i + 1)).encode()),
            "headers_sha256": sha(("fixture-headers-" + str(i + 1)).encode()),
            "client_key_sha256": shared_key,
            "http_host": "localhost",
            "messages_query": "fixture=" + str(i + 1),
            "response_text": "fixture response " + str(i + 1),
        }
    payload = {key: assignment[key] for key in (
        "profile_in_force", "host_id", "installation_id", "soul_id", "start_id", "hq_epoch",
        "plan_id", "plan_digest", "reservation_sha256", "owner_plan_member_set_sha256", "b_authority", "bridge")}
    payload.update({
        "contract": "machine/v3", "kind": "stage2a-b-member-authority", "schema_version": 1,
        "member_set_assignment_envelope_sha256": sha(assignment_raw),
        "hq_uid": assignment["bridge"]["endpoints"]["broker"]["owner_uid"],
        "runner_uid": assignment["runner_uid"],
        "members": rows, "issued_at": "2026-11-22T14:15:18Z", "expires_at": "2026-11-22T14:15:35Z",
    })
    key = Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33)))
    pub = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    payload_raw = canonicalize(payload)
    envelope = {
        "schema_version": 1, "purpose": PURPOSE, "issuer_public_key_base64url": b64(pub),
        "payload_sha256": sha(payload_raw), "payload_base64url": b64(payload_raw),
        "signature_base64url": b64(key.sign(PURPOSE.encode() + b"\0" + payload_raw)),
    }
    authority_raw = canonicalize(envelope)
    identity = {"uid": 333, "gid": 333, "device": 11, "inode": 12, "mode": 432}
    fd3 = {
        "version": "stage2a-b-assignment/v3", "machine_pin_path": PIN,
        "assignment_envelope_base64url": b64(assignment_raw),
        "authority_envelope_base64url": b64(authority_raw),
        "selectors": {
            "installation_id": assignment["installation_id"], "start_id": assignment["start_id"],
            "plan_id": assignment["plan_id"], "plan_digest": assignment["plan_digest"],
            "reservation_digest": assignment["reservation_sha256"],
            "assignment_envelope_sha256": sha(assignment_raw),
            "authority_envelope_sha256": sha(authority_raw),
            "member_selectors_sha256": sha(canonicalize([m["member_selector"] for m in rows])),
        },
        "hq_epoch": assignment["hq_epoch"], "bridge_uid": assignment["bridge"]["uid"],
        "hq_uid": payload["hq_uid"], "runner_uid": payload["runner_uid"],
        "expires_at": payload["expires_at"],
        "broker": {"path": assignment["bridge"]["endpoints"]["broker"]["socket_path"],
                   "parent": dict(identity, uid=309, inode=13), "socket": dict(identity, uid=309, inode=14)},
        "relay": {"path": assignment["bridge"]["endpoints"]["relay"]["socket_path"],
                  "parent": dict(identity, uid=333, inode=15), "socket": dict(identity, uid=333, inode=16)},
    }
    write("fixtures/reservation/v3/" + PREFIX + ".json", {
        "assignment_envelope_jcs": assignment_raw.decode(),
        "authority_payload_jcs": payload_raw.decode(),
        "authority_envelope_jcs": authority_raw.decode(), "fd3": fd3,
        "owner_plan_member_bridge_qualifications": [m["qualification"] for m in rows],
    })
    schemas = [
        ("machine/v3/stage2a-b-member-authority-payload.schema.json", payload, "payload"),
        ("machine/v3/stage2a-b-member-signed-authority.schema.json", envelope, "envelope"),
        ("machine/v3/stage2a-b-member-fd3.schema.json", fd3, "fd3"),
    ]
    for schema, value, suffix in schemas:
        fixture(schema, value, True, suffix)
        invalid = copy.deepcopy(value)
        invalid["unexpected"] = True
        fixture(schema, invalid, False, suffix)


if __name__ == "__main__":
    main()
