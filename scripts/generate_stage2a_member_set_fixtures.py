#!/usr/bin/env python3
"""Regenerate synthetic three-phase member-set vectors and schema fixtures."""

import base64
import copy
import hashlib
import json
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from jcs import canonicalize

ROOT = Path(__file__).resolve().parents[1]
KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33)))  # public test seed
PUBLIC = KEY.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
PURPOSES = {
    "assignment": "agent-bot/stage2a-member-set-assignment/v1",
    "child_observation": "agent-bot/stage2a-member-set-child-observation/v1",
    "ready": "agent-bot/stage2a-member-set-ready/v1",
}
SCHEMAS = {
    "assignment": "machine/v3/stage2a-member-set-assignment-payload.schema.json",
    "signed_assignment": "machine/v3/stage2a-member-set-signed-assignment.schema.json",
    "mapping": "hq/v1/stage2a-provisional-member-map.schema.json",
    "child_observation": "machine/v3/stage2a-member-set-child-observation-payload.schema.json",
    "signed_child_observation": "machine/v3/stage2a-member-set-signed-child-observation.schema.json",
    "ready": "machine/v3/stage2a-member-set-ready-payload.schema.json",
    "signed_ready": "machine/v3/stage2a-member-set-signed-ready.schema.json",
}


def sha(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def b64(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def json_file(path):
    return json.loads((ROOT / path).read_text(encoding="utf-8"))


def write(path, value):
    target = ROOT / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8")


def sign(kind, payload):
    payload_raw = canonicalize(payload)
    purpose = PURPOSES[kind]
    envelope = {
        "schema_version": 1,
        "purpose": purpose,
        "issuer_public_key_base64url": b64(PUBLIC),
        "payload_sha256": sha(payload_raw),
        "payload_base64url": b64(payload_raw),
        "signature_base64url": b64(KEY.sign(purpose.encode("ascii") + b"\0" + payload_raw)),
    }
    return payload_raw.decode("utf-8"), envelope, canonicalize(envelope).decode("utf-8")


def selector(reservation_sha256, member_id, launch_id):
    raw = b"agent-bot/stage2a-member-selector/v1\0" + reservation_sha256.encode("ascii") + b"\0"
    raw += member_id.encode("utf-8") + b"\0" + launch_id.encode("ascii")
    return "mb_" + hashlib.sha256(raw).hexdigest()


def profile_inputs(profile):
    if profile == "managed-protected":
        payload = json_file("fixtures/positive/stage2a-reservation-payload.v3-synthetic.json")["input"]
        primary = canonicalize(json_file("fixtures/positive/stage2a-signed-reservation.v3-synthetic.json")["input"])
        a = payload["assignment"]
        bridge = {"account": a["bridge_account"], "uid": a["bridge_uid"], "gid": a["bridge_gid"],
                  "endpoints": {name: a[name] for name in ("broker", "member", "relay")}}
        authority = {"purpose": "agent-bot/stage2a-reservation/v3", "envelope_sha256": sha(primary)}
        bridge_executable = sha(b"synthetic-protected-bridge")
        source = "fixtures/positive/stage2a-signed-reservation.v3-synthetic.json"
    else:
        vector = json_file("fixtures/reservation/v3/soul-cooperative-signed-reservation.brokered-b.synthetic.json")
        payload = json.loads(vector["reservation_payload_jcs"])
        primary = vector["reservation_envelope_jcs"].encode("utf-8")
        private = vector["bridge_envelope_jcs"].encode("utf-8")
        envelope = json.loads(private)
        raw = base64.urlsafe_b64decode(envelope["payload_base64url"] + "=" * (-len(envelope["payload_base64url"]) % 4))
        b = json.loads(raw)
        bridge = {"account": b["bridge"]["account"], "uid": b["bridge"]["uid"],
                  "gid": b["bridge"]["gid"], "endpoints": b["endpoints"]}
        authority = {"purpose": "agent-bot/soul-cooperative-bridge-assignment/v3", "envelope_sha256": sha(private)}
        bridge_executable = b["bridge"]["executable_sha256"]
        source = "fixtures/reservation/v3/soul-cooperative-signed-reservation.brokered-b.synthetic.json"
    return payload, primary, bridge, authority, bridge_executable, source


def build(profile):
    primary, reservation_raw, bridge, authority, bridge_executable, source = profile_inputs(profile)
    a = primary["assignment"]
    commands = {"m_lead": b"synthetic-acp-command", "m_spec": b"synthetic-acp-command"}
    paths = {"m_lead": "/fixture/r/adapter/fixture-acp", "m_spec": "/fixture/r/adapter/fixture-acp"}
    cli_bytes = b"synthetic-adjacent-cli-command"
    cli_path = "/fixture/r/adapter/fixture-cli"
    manifest = {"adapter_id": "fixture-stock", "adapter_version": "1.0.0",
                "executable": "fixture-acp", "executable_sha256": sha(commands["m_lead"]),
                "adjacent_cli": "fixture-cli", "adjacent_cli_sha256": sha(cli_bytes)}
    manifest_raw = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("utf-8")
    soul_info = {"soul_id": a["soul_id"], "members": [
        {"member_id": "m_lead", "role": "lead", "adapter_id": "fixture-stock", "adapter_version": "1.0.0"},
        {"member_id": "m_spec", "role": "specialist", "adapter_id": "fixture-stock", "adapter_version": "1.0.0"},
    ]}
    soul_info_raw = (json.dumps(soul_info, indent=2, ensure_ascii=False) + "\n").encode("utf-8")
    host_projection = {"installation": {"installation_id": a["installation_id"]}, "adapters": {
        "fixture-stock": {"command": [paths["m_lead"]], "env": {}},
    }}
    stable = []
    members = []
    for index, info in enumerate(soul_info["members"]):
        member_id = info["member_id"]
        launch_id = a["launch_id"] if index == 0 else "ln_0123456789abcdef01234568"
        member = {**info, "command_path": paths[member_id], "command_sha256": sha(commands[member_id]),
                  "adjacent_cli_path": cli_path, "adjacent_cli_sha256": sha(cli_bytes),
                  "launch_id": launch_id, "member_selector": selector(sha(reservation_raw), member_id, launch_id)}
        members.append(member)
        stable.append({key: member[key] for key in
                       ("member_id", "role", "adapter_id", "adapter_version", "command_path", "command_sha256",
                        "adjacent_cli_path", "adjacent_cli_sha256")})
    assignment = {
        "contract": "machine/v3", "kind": "stage2a-member-set-assignment", "schema_version": 1,
        "profile_in_force": profile, "host_id": primary["host_id"], "installation_id": a["installation_id"],
        "soul_id": a["soul_id"], "start_id": a["start_id"], "hq_epoch": a["hq_epoch"],
        "plan_id": a["plan_id"], "plan_digest": a["plan_digest"],
        "owner_plan_member_set_sha256": sha(canonicalize(stable)), "reservation_sha256": sha(reservation_raw),
        "b_authority": authority, "soul_artifact_sha256": "sha256:" + a["soul_artifact_sha256"],
        "frozen_soul_info_sha256": sha(soul_info_raw),
        "adapter_manifest_relpath": "Contents/opt/fixture-stock.json",
        "frozen_adapter_manifest_sha256": sha(manifest_raw),
        "host_projection_sha256": sha(canonicalize(host_projection)),
        "definition_measurement": primary["measurement_binding"]["definition_measurement"],
        "runner_uid": a["runner_uid"], "runner_gid": a["runner_gid"], "bridge": bridge,
        "members": members, "issued_at": "2026-11-22T14:15:17Z", "expires_at": a["expires_at"],
    }
    assignment_jcs, assignment_envelope, assignment_envelope_jcs = sign("assignment", assignment)
    mapping = {
        "contract": "hq/v1", "kind": "stage2a-provisional-member-map", "schema_version": 1,
        "profile_in_force": profile, "host_id": primary["host_id"], "installation_id": a["installation_id"],
        "soul_id": a["soul_id"], "start_id": a["start_id"], "hq_epoch": a["hq_epoch"],
        "assignment_envelope_sha256": sha(assignment_envelope_jcs.encode("utf-8")),
        "runtime_state": "provisional", "acp_authority": "withheld",
        "members": [{"member_id": m["member_id"], "member_selector": m["member_selector"],
                     "runtime_id": "runtime_fixture_" + m["member_id"],
                     "channel_binding": b64(bytes([40 + i]) * 24)} for i, m in enumerate(members)],
        "issued_at": "2026-11-22T14:15:18Z", "expires_at": a["expires_at"],
    }
    child_members = []
    for i, m in enumerate(members):
        child_members.append({"member_id": m["member_id"], "launch_id": m["launch_id"],
                              "member_selector": m["member_selector"], "runtime_id": mapping["members"][i]["runtime_id"],
                              "child_process": {"pid": 4101 + i, "uid": a["runner_uid"], "gid": a["runner_gid"],
                                                "parent_pid": 4001, "process_group_id": 4001,
                                                "start_seconds": 1795356918, "start_micros": 100 + i,
                                                "executable_sha256": m["command_sha256"]}})
    child = {"contract": "machine/v3", "kind": "stage2a-member-set-child-observation", "schema_version": 1,
             "profile_in_force": profile, "host_id": primary["host_id"], "installation_id": a["installation_id"],
             "soul_id": a["soul_id"], "start_id": a["start_id"], "hq_epoch": a["hq_epoch"],
             "reservation_sha256": sha(reservation_raw),
             "assignment_envelope_sha256": sha(assignment_envelope_jcs.encode("utf-8")),
             "provisional_hq_mapping_sha256": sha(canonicalize(mapping)), "provisional_hq_mapping": mapping,
             "members": child_members, "observed_at": "2026-11-22T14:15:19Z",
             "issued_at": "2026-11-22T14:15:19Z", "expires_at": a["expires_at"]}
    child_jcs, child_envelope, child_envelope_jcs = sign("child_observation", child)
    ready_members = []
    for m in child_members:
        process = m["child_process"]
        arm = {"member_id": m["member_id"], "member_selector": m["member_selector"],
               "runtime_id": m["runtime_id"], "child_observation_envelope_sha256": sha(child_envelope_jcs.encode("utf-8")),
               "bridge_uid": bridge["uid"], "adapter_pid": process["pid"], "adapter_uid": process["uid"],
               "adapter_gid": process["gid"], "adapter_start_seconds": process["start_seconds"],
               "adapter_start_micros": process["start_micros"],
               "relay_peer_rule": "a-attested-live-direct-child-of-adapter-v1",
               "relay_peer_state": "unobserved",
               "provider_ingress": "withheld-pending-per-peer-attestation", "state": "armed",
               "armed_at": "2026-11-22T14:15:20Z"}
        ready_members.append({"member_id": m["member_id"], "launch_id": m["launch_id"],
                              "member_selector": m["member_selector"], "runtime_id": m["runtime_id"],
                              "bridge_arm": arm, "bridge_arm_receipt_sha256": sha(canonicalize(arm))})
    ready = {"contract": "machine/v3", "kind": "stage2a-member-set-ready", "schema_version": 1,
             "profile_in_force": profile, "host_id": primary["host_id"], "installation_id": a["installation_id"],
             "soul_id": a["soul_id"], "start_id": a["start_id"], "hq_epoch": a["hq_epoch"],
             "reservation_sha256": sha(reservation_raw),
             "assignment_envelope_sha256": sha(assignment_envelope_jcs.encode("utf-8")),
             "child_observation_envelope_sha256": sha(child_envelope_jcs.encode("utf-8")),
             "b_authority_sha256": authority["envelope_sha256"],
             "provisional_hq_mapping_sha256": sha(canonicalize(mapping)),
             "bridge_process": {"pid": 3901, "uid": bridge["uid"], "gid": bridge["gid"],
                                "start_seconds": 1795356917, "start_micros": 99,
                                "executable_sha256": bridge_executable},
             "members": ready_members, "observed_at": "2026-11-22T14:15:20Z",
             "issued_at": "2026-11-22T14:15:21Z", "expires_at": a["expires_at"]}
    ready_jcs, ready_envelope, ready_envelope_jcs = sign("ready", ready)
    return {
        "source_reservation_fixture": source, "source_reservation_sha256": sha(reservation_raw),
        "frozen_soul_info_raw_base64url": b64(soul_info_raw), "host_projection_jcs": canonicalize(host_projection).decode("utf-8"),
        "adapter_manifest_raw_base64url": b64(manifest_raw), "cli_bytes_base64url": b64(cli_bytes),
        "command_bytes_base64url": {member_id: b64(raw) for member_id, raw in commands.items()},
        "owner_plan_selection": {"plan_digest": a["plan_digest"],
                                 "owner_plan_member_set_sha256": assignment["owner_plan_member_set_sha256"]},
        "assignment_payload_jcs": assignment_jcs, "assignment_envelope_jcs": assignment_envelope_jcs,
        "provisional_hq_mapping_jcs": canonicalize(mapping).decode("utf-8"),
        "child_observation_payload_jcs": child_jcs, "child_observation_envelope_jcs": child_envelope_jcs,
        "ready_payload_jcs": ready_jcs, "ready_envelope_jcs": ready_envelope_jcs,
    }, {"assignment": assignment, "signed_assignment": assignment_envelope, "mapping": mapping,
        "child_observation": child, "signed_child_observation": child_envelope,
        "ready": ready, "signed_ready": ready_envelope}


def fixture(kind, value):
    return {"schema": SCHEMAS[kind], "input": value, "expect": {"schema": "valid"},
            "canonical_sha256": sha(canonicalize(value))}


def main():
    vectors = {}
    cooperative = None
    for profile in ("managed-protected", "managed-cooperative"):
        vector, values = build(profile)
        vectors[profile] = vector
        if profile == "managed-cooperative":
            cooperative = values
    write("fixtures/reservation/v3/stage2a-member-set.synthetic.json", vectors)
    for kind, value in cooperative.items():
        positive = fixture(kind, value)
        name = SCHEMAS[kind].split("/")[-1].replace(".schema.json", "")
        path = f"fixtures/positive/{name}.two-member-synthetic.json"
        write(path, positive)
        negative_input = copy.deepcopy(value)
        if kind.startswith("signed_"):
            negative_input["purpose"] = "agent-bot/wrong-purpose/v1"
        elif kind == "assignment":
            negative_input["members"] = negative_input["members"][:1]
        elif kind == "mapping":
            negative_input["acp_authority"] = "granted"
        elif kind == "child_observation":
            negative_input["members"] = negative_input["members"][:1]
        elif kind == "ready":
            negative_input["members"][1]["bridge_arm"]["state"] = "unarmed"
        base_raw = (ROOT / path).read_bytes()
        write(f"fixtures/negative/{name}.two-member-synthetic-refusal.json", {
            "schema": SCHEMAS[kind], "input": negative_input, "expect": {"schema": "invalid"},
            "base": {"fixture": path.removeprefix("fixtures/"), "sha256": sha(base_raw)},
        })


if __name__ == "__main__":
    main()
