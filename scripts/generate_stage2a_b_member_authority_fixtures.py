#!/usr/bin/env python3
"""Regenerate synthetic A-signed two-member B FD3 contract vectors."""

import base64
import copy
import hashlib
import json
from pathlib import Path

from jcs import canonicalize

ROOT = Path(__file__).resolve().parents[1]
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
    payload_raw = source["member_b_authority_payload_jcs"].encode()
    payload = json.loads(payload_raw)
    rows = payload["members"]
    authority_raw = source["member_b_authority_envelope_jcs"].encode()
    envelope = json.loads(authority_raw)
    assert json.loads(source["ready_payload_jcs"])["member_b_authority_envelope_sha256"] == sha(authority_raw)
    broker_parent = {"uid": payload["hq_uid"], "gid": assignment["bridge"]["gid"],
                     "device": 11, "inode": 13, "mode": 1512}
    broker_socket = dict(broker_parent, inode=14, mode=432)
    relay_parent = {"uid": assignment["bridge"]["uid"], "gid": assignment["runner_gid"],
                    "device": 11, "inode": 15, "mode": 1512}
    relay_socket = dict(relay_parent, device=0, inode=0, mode=432)
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
                   "parent": broker_parent, "socket": broker_socket},
        "relay": {"path": assignment["bridge"]["endpoints"]["relay"]["socket_path"],
                  "parent": relay_parent, "socket": relay_socket},
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
