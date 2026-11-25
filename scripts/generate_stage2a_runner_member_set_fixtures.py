#!/usr/bin/env python3
"""Regenerate schema-only synthetic protected/cooperative two-member R FD3 vectors."""

import base64
import copy
import json
from pathlib import Path

from jcs import canonicalize

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = "machine/v3/stage2a-runner-member-set-fd3.schema.json"
PIN = "/Library/Application Support/ai.true-line.agent-bot-hq/soul-authority.pub"


def b64(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def sha(raw):
    import hashlib
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def write(path, value):
    target = ROOT / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8")


def build(profile):
    member_vector = json.loads((ROOT / "fixtures/reservation/v3/stage2a-member-set.synthetic.json").read_text())[profile]
    assignment_raw = member_vector["assignment_envelope_jcs"].encode("utf-8")
    assignment = json.loads(member_vector["assignment_payload_jcs"])
    reservation_raw = member_vector["primary_reservation_envelope_jcs"].encode("utf-8")
    if profile == "managed-protected":
        launch_fixture = "launch-input-records.stage2a-synthetic.json"
        frame = {"schema": "agent-bot-souls/protected-start/v2"}
    else:
        fixture = json.loads((ROOT / "fixtures/reservation/v3/soul-cooperative-signed-reservation.brokered-b.synthetic.json").read_text())
        launch_fixture = None
        frame = {"schema": "agent-bot-souls/cooperative-start/v3",
                 "admission_challenge_base64url": fixture["admission_challenge_base64url"],
                 "member_socket_path": assignment["bridge"]["endpoints"]["member"]["socket_path"],
                 "relay_socket_path": assignment["bridge"]["endpoints"]["relay"]["socket_path"],
                 "publish_outcome_envelope_base64url": b64(canonicalize({"synthetic_schema_shape_only": True})),
                 "request_identity": {"device": "11", "inode": "12", "birthtime_ns": "13",
                                      "owner_uid": assignment["runner_uid"], "group_gid": assignment["runner_gid"],
                                      "mode": 416}}
    if launch_fixture is None:
        launch = json.loads(json.loads((ROOT / "fixtures/reservation/v3/"
                                       "soul-cooperative-launch-inputs.brokered-b.synthetic.json").read_text())[
            "records_jcs"])
    else:
        launch = json.loads((ROOT / "fixtures/positive" / launch_fixture).read_text())["input"]
    launch["host_projection"] = json.loads(member_vector["host_projection_jcs"])
    launch["selected_command"] = assignment["members"][0]["command_path"]
    launch["argv"] = [assignment["members"][0]["command_path"]]
    launch["component_digests"]["adapter"] = assignment["members"][0]["command_sha256"]
    if profile == "managed-cooperative":
        primary = json.loads(base64.urlsafe_b64decode(
            json.loads(member_vector["primary_reservation_envelope_jcs"])["payload_base64url"] + "=="))
        launch["adapter_transport"] = "brokered-b"
        launch["bridge_launch_sha256"] = primary["bridge_launch_sha256"]
    frame.update({
        "reservation_envelope_base64url": b64(reservation_raw),
        "reservation_sha256": sha(reservation_raw),
        "machine_pin_path": PIN,
        "launch_input_records": launch,
        "state_root": "/fixture/r/state",
        "member_set_assignment_envelope_base64url": b64(assignment_raw),
    })
    return frame


def main():
    vectors = {p: build(p) for p in ("managed-protected", "managed-cooperative")}
    write("fixtures/reservation/v3/stage2a-runner-member-set-fd3.synthetic.json", vectors)
    positive = {"schema": SCHEMA, "input": vectors["managed-protected"],
                "expect": {"schema": "valid"},
                "canonical_sha256": sha(canonicalize(vectors["managed-protected"]))}
    path = "fixtures/positive/stage2a-runner-member-set-fd3.two-member-synthetic.json"
    write(path, positive)
    cooperative_path = "fixtures/positive/stage2a-runner-member-set-fd3.cooperative-two-member-synthetic.json"
    write(cooperative_path, {"schema": SCHEMA, "input": vectors["managed-cooperative"],
                             "expect": {"schema": "valid"},
                             "canonical_sha256": sha(canonicalize(vectors["managed-cooperative"]))})
    cooperative_negative = copy.deepcopy(vectors["managed-cooperative"])
    cooperative_negative["launch_input_records"].pop("bridge_launch_sha256")
    write("fixtures/negative/stage2a-runner-member-set-fd3.cooperative-two-member-synthetic.json", {
        "schema": SCHEMA, "input": cooperative_negative, "expect": {"schema": "invalid"},
        "base": {"fixture": cooperative_path.removeprefix("fixtures/"),
                 "sha256": sha((ROOT / cooperative_path).read_bytes())},
    })
    negative = copy.deepcopy(vectors["managed-protected"])
    negative["schema"] = "agent-bot-souls/protected-start/v1"
    write("fixtures/negative/stage2a-runner-member-set-fd3.two-member-synthetic-refusal.json", {
        "schema": SCHEMA, "input": negative, "expect": {"schema": "invalid"},
        "base": {"fixture": path.removeprefix("fixtures/"), "sha256": sha((ROOT / path).read_bytes())},
    })


if __name__ == "__main__":
    main()
