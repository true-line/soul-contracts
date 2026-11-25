#!/usr/bin/env python3
"""Regenerate synthetic verified prestarted two-member H-to-R attach results."""

import base64
import copy
import json
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from jcs import canonicalize

from stage2a_member_set_fixtures import digest

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = "hq/v1/stage2a-member-attach.schema.json"
PROTECTED_NAME = "stage2a-member-attach.two-member-synthetic.json"
COOPERATIVE_NAME = "stage2a-member-attach.cooperative-two-member-synthetic.json"
OBSERVED_PURPOSE = "agent-bot/soul-cooperative-b-observed/v3"
READY_PURPOSE = "agent-bot/soul-cooperative-member-ready/v3"


def b64(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def write(path, value):
    target = ROOT / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n")


def sign(payload, purpose):
    key = Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33)))
    public = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    raw = canonicalize(payload)
    envelope = {"schema_version": 3, "purpose": purpose,
                "issuer_public_key_base64url": b64(public), "payload_sha256": digest(raw),
                "payload_base64url": b64(raw),
                "signature_base64url": b64(key.sign(purpose.encode() + b"\0" + raw))}
    return canonicalize(envelope)


def cooperative_evidence(source, assignment):
    """Synthetic exact-byte join vector; no installed, live or physical claim."""
    arm = json.loads((ROOT / "fixtures/reservation/v3/soul-cooperative-b-member-arm-exchange.two-member-synthetic.json").read_text())
    ready_source = json.loads((ROOT / "fixtures/reservation/v3/soul-cooperative-member-ready.two-member-synthetic.json").read_text())
    relay = assignment["bridge"]["endpoints"]["relay"]
    observed = {
        "contract": "machine/v3", "kind": "soul-cooperative-b-observed", "schema_version": 3,
        "reservation_sha256": assignment["reservation_sha256"],
        "bridge_assignment_sha256": digest(source["private_b_authority_envelope_jcs"].encode()),
        "bind_receipt_sha256": "sha256:" + "9" * 64,
        "installation_id": assignment["installation_id"], "start_id": assignment["start_id"],
        "launch_id": assignment["members"][0]["launch_id"], "plan_id": assignment["plan_id"],
        "plan_digest": assignment["plan_digest"], "hq_epoch": assignment["hq_epoch"],
        "grant_nonce": b64(bytes(range(32))),
        "launcher": {"pid": 3901, "uid": assignment["bridge"]["uid"],
                     "gid": assignment["bridge"]["gid"],
                     "start_seconds": 1795356917, "start_micros": 80},
        "bridge": {"pid": 3902, "uid": assignment["bridge"]["uid"],
                   "gid": assignment["bridge"]["gid"], "start_seconds": 1795356918,
                   "start_micros": 70},
        "relay_socket": {"path": relay["socket_path"],
                         "socket": {"uid": assignment["bridge"]["uid"],
                                    "gid": assignment["runner_gid"], "device": "1",
                                    "inode": "3001", "mode": relay["socket_mode"]}},
        "relay_socket_birthtime_ns": "1795356919000000000",
        "observed_at": "2026-11-22T14:15:20Z", "expires_at": assignment["expires_at"],
    }
    observed_raw = sign(observed, OBSERVED_PURPOSE)
    ready = json.loads(ready_source["payload_jcs"])
    ready["bridge_observed_sha256"] = digest(observed_raw)
    arm_rows = []
    for i, row in enumerate(arm["members"]):
        inner = canonicalize(row["arm_request"]["bridge_arm"])
        assert ready["members"][i]["member_id"] == row["arm_request"]["member_id"]
        assert ready["members"][i]["b_arm_receipt_sha256"] == digest(inner)
        arm_rows.append(inner)
    ready_raw = sign(ready, READY_PURPOSE)
    write("fixtures/reservation/v3/soul-cooperative-b-observed.attach-synthetic.json",
          {"payload_jcs": canonicalize(observed).decode(), "envelope_jcs": observed_raw.decode(),
           "ready_payload_jcs": canonicalize(ready).decode(), "ready_envelope_jcs": ready_raw.decode(),
           "bridge_arm_rows_jcs": [row.decode() for row in arm_rows],
           "evidence_status": "synthetic-only; bind receipt, H observation and grant are placeholders"})
    for schema, value in (("machine/v3/soul-cooperative-b-observed-payload.schema.json", observed),
                          ("machine/v3/soul-cooperative-b-signed-observed.schema.json", json.loads(observed_raw))):
        name = schema.rsplit("/", 1)[-1].removesuffix(".schema.json") + ".attach-synthetic.json"
        positive = "fixtures/positive/" + name
        write(positive, {"schema": schema, "input": value, "expect": {"schema": "valid"},
                         "canonical_sha256": digest(canonicalize(value))})
        changed = copy.deepcopy(value)
        changed["relay_socket_birthtime_ns" if schema.endswith("payload.schema.json") else "purpose"] = \
            "0" if schema.endswith("payload.schema.json") else "agent-bot/soul-cooperative-b-observed/v2"
        write("fixtures/negative/" + name,
              {"schema": schema, "input": changed, "expect": {"schema": "invalid"},
               "base": {"fixture": positive.removeprefix("fixtures/"),
                        "sha256": digest((ROOT / positive).read_bytes())}})
    return observed_raw, ready_raw, arm_rows


def generate(profile, name):
    source = json.loads((ROOT / "fixtures/reservation/v3/stage2a-member-set.synthetic.json").read_text())[
        profile]
    assignment = json.loads(source["assignment_payload_jcs"])
    child = json.loads(source["child_observation_payload_jcs"])
    ready = json.loads(source["ready_payload_jcs"])
    child_raw = source["child_observation_envelope_jcs"].encode("utf-8")
    authority_raw = source["member_b_authority_envelope_jcs"].encode("utf-8")
    ready_raw = source["ready_envelope_jcs"].encode("utf-8")
    observed_raw = None
    arm_rows = None
    if profile == "managed-cooperative":
        observed_raw, ready_raw, arm_rows = cooperative_evidence(source, assignment)
    approved = assignment["bridge"]["endpoints"]["member"]
    endpoint = ({key: approved[key] for key in
                 ("directory", "owner_uid", "group_gid", "dir_mode", "socket_mode", "peer_uids")}
                if profile == "managed-protected" else approved)
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
        if profile == "managed-cooperative":
            result["bridge_observed_envelope_base64url"] = b64(observed_raw)
            result["bridge_arm_rows_base64url"] = [b64(row) for row in arm_rows]
        results.append(result)
    write("fixtures/reservation/v3/" + name, {"results": results})
    positive = "fixtures/positive/" + name
    write(positive, {"schema": SCHEMA, "input": results[0], "expect": {"schema": "valid"},
                     "canonical_sha256": digest(canonicalize(results[0]))})
    changed = copy.deepcopy(results[0])
    changed["version"] = "stage2a-member-attach/v0"
    write("fixtures/negative/" + name, {"schema": SCHEMA, "input": changed,
                                       "expect": {"schema": "invalid"},
                                       "base": {"fixture": positive.removeprefix("fixtures/"),
                                                "sha256": digest((ROOT / positive).read_bytes())}})
    assert ready["member_b_authority_envelope_sha256"] == digest(authority_raw)


def main():
    generate("managed-protected", PROTECTED_NAME)
    generate("managed-cooperative", COOPERATIVE_NAME)


if __name__ == "__main__":
    main()
