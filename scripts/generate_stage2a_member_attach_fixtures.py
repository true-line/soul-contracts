#!/usr/bin/env python3
"""Regenerate synthetic verified prestarted two-member H-to-R attach results."""

import base64
import copy
import json
from pathlib import Path

from jcs import canonicalize

from stage2a_member_set_fixtures import digest

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = "hq/v1/stage2a-member-attach.schema.json"
NAME = "stage2a-member-attach.two-member-synthetic.json"


def b64(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def write(path, value):
    target = ROOT / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n")


def main():
    source = json.loads((ROOT / "fixtures/reservation/v3/stage2a-member-set.synthetic.json").read_text())[
        "managed-protected"]
    assignment = json.loads(source["assignment_payload_jcs"])
    child = json.loads(source["child_observation_payload_jcs"])
    ready = json.loads(source["ready_payload_jcs"])
    child_raw = source["child_observation_envelope_jcs"].encode("utf-8")
    authority_raw = source["member_b_authority_envelope_jcs"].encode("utf-8")
    ready_raw = source["ready_envelope_jcs"].encode("utf-8")
    approved = assignment["bridge"]["endpoints"]["member"]
    endpoint = {key: approved[key] for key in
                ("directory", "owner_uid", "group_gid", "dir_mode", "socket_mode", "peer_uids")}
    results = []
    for i, member in enumerate(assignment["members"]):
        result = {
            "version": "stage2a-member-attach/v1", "installation_id": assignment["installation_id"],
            "start_id": assignment["start_id"], "member_id": member["member_id"],
            "member_selector": member["member_selector"], "runtime_id": child["members"][i]["runtime_id"],
            "launch_id": member["launch_id"], "attach": str(i + 1) * 64,
            "expires_at": assignment["expires_at"], "cwd": "/fixture/r",
            "member_socket": approved["socket_path"], "member_endpoint": endpoint,
            "member_bridge_token": str(i + 3) * 48,
            "bridge_ready_nonce": str(i + 5) * 64,
            "runner_endpoint": {"socketPath": "/fixture/r/admission.sock",
                                "peerUid": assignment["runner_uid"], "directory": "/fixture/r"},
            "child_observation_envelope_base64url": b64(child_raw),
            "child_observation_envelope_sha256": digest(child_raw),
            "member_b_authority_envelope_base64url": b64(authority_raw),
            "member_b_authority_envelope_sha256": digest(authority_raw),
            "ready_envelope_base64url": b64(ready_raw), "ready_envelope_sha256": digest(ready_raw),
        }
        results.append(result)
    write("fixtures/reservation/v3/" + NAME, {"results": results})
    positive = "fixtures/positive/" + NAME
    write(positive, {"schema": SCHEMA, "input": results[0], "expect": {"schema": "valid"},
                     "canonical_sha256": digest(canonicalize(results[0]))})
    changed = copy.deepcopy(results[0])
    changed["version"] = "stage2a-member-attach/v0"
    write("fixtures/negative/" + NAME, {"schema": SCHEMA, "input": changed,
                                       "expect": {"schema": "invalid"},
                                       "base": {"fixture": positive.removeprefix("fixtures/"),
                                                "sha256": digest((ROOT / positive).read_bytes())}})
    assert ready["member_b_authority_envelope_sha256"] == digest(authority_raw)


if __name__ == "__main__":
    main()
