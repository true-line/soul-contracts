#!/usr/bin/env python3
"""Regenerate synthetic A-signed protected post-Ready member lease chains."""

import base64
import copy
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from jcs import canonicalize

from stage2a_member_set_fixtures import digest

ROOT = Path(__file__).resolve().parents[1]
PURPOSE = "agent-bot/stage2a-member-runtime-lease/v1"
PAYLOAD = "machine/v3/stage2a-member-runtime-lease-payload.schema.json"
ENVELOPE = "machine/v3/stage2a-member-signed-runtime-lease.schema.json"


def b64(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def write(path, value):
    target = ROOT / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def fixture(schema, value, positive):
    name = schema.rsplit("/", 1)[-1].removesuffix(".schema.json") + ".protected-synthetic.json"
    path = "fixtures/" + ("positive/" if positive else "negative/") + name
    record = {"schema": schema, "input": value,
              "expect": {"schema": "valid" if positive else "invalid"}}
    if positive:
        record["canonical_sha256"] = digest(canonicalize(value))
    else:
        base = ROOT / "fixtures/positive" / name
        record["base"] = {"fixture": "positive/" + name, "sha256": digest(base.read_bytes())}
    write(path, record)


def sign(payload, key, public):
    raw = canonicalize(payload)
    envelope = {"schema_version": 1, "purpose": PURPOSE,
                "issuer_public_key_base64url": b64(public), "payload_sha256": digest(raw),
                "payload_base64url": b64(raw),
                "signature_base64url": b64(key.sign(PURPOSE.encode() + b"\0" + raw))}
    return {"payload_jcs": raw.decode(), "envelope_jcs": canonicalize(envelope).decode()}


def stamp(value):
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def main():
    source = json.loads((ROOT / "fixtures/reservation/v3/stage2a-member-set.synthetic.json").read_text())[
        "managed-protected"]
    assignment = json.loads(source["assignment_payload_jcs"])
    child = json.loads(source["child_observation_payload_jcs"])
    ready = json.loads(source["ready_payload_jcs"])
    key = Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33)))
    public = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    base = datetime.fromisoformat("2026-11-22T14:15:22+00:00")
    role = lambda pid, uid, gid: {"pid": pid, "uid": uid, "gid": gid,
                                  "start_seconds": 1795356917, "start_micros": 99}
    bridge = {k: v for k, v in ready["bridge_process"].items() if k != "executable_sha256"}
    vectors = []
    for member_index, observed in enumerate(child["members"]):
        prior = None
        for lease_index in range(6 if member_index == 0 else 1):
            issued = base + timedelta(seconds=3 * lease_index)
            ready_member = ready["members"][member_index]
            payload = {k: assignment[k] for k in
                       ("host_id", "installation_id", "soul_id", "start_id", "hq_epoch",
                        "reservation_sha256")}
            payload.update({
                "contract": "machine/v3", "kind": "stage2a-member-runtime-lease", "schema_version": 1,
                "profile_in_force": "managed-protected",
                "assignment_envelope_sha256": digest(source["assignment_envelope_jcs"].encode()),
                "child_observation_envelope_sha256": digest(source["child_observation_envelope_jcs"].encode()),
                "ready_envelope_sha256": digest(source["ready_envelope_jcs"].encode()),
                "member_b_authority_envelope_sha256": ready["member_b_authority_envelope_sha256"],
                "hq_finalization_sha256": "sha256:" + "f" * 64,
                "bind_receipt_sha256": "sha256:" + "b" * 64,
                "installed_authority_sha256": "sha256:" + "d" * 64,
                "member_id": observed["member_id"], "member_selector": observed["member_selector"],
                "member_launch_id": observed["launch_id"], "runtime_id": observed["runtime_id"],
                "grant_sha256": observed["grant_sha256"],
                "bridge_arm_receipt_sha256": ready_member["bridge_arm_receipt_sha256"],
                "runner_process": role(3801, 331, 331), "bridge_process": bridge,
                "q_process": role(3601, 351, 351), "owner_driver_process": role(3501, 501, 20),
                "launcher_process": observed["launcher_process"], "child_process": observed["child_process"],
                "challenge_nonce_base64url": b64(bytes([70 + member_index + lease_index]) * 32),
                "sequence": lease_index + 1,
                "previous_lease_envelope_sha256": digest(prior["envelope_jcs"].encode()) if prior else None,
                "approved_until": "2026-11-22T14:16:00Z",
                "issued_at": stamp(issued), "expires_at": stamp(issued + timedelta(seconds=4)),
            })
            vector = sign(payload, key, public)
            vectors.append(vector)
            prior = vector
            if member_index == 0 and lease_index == 0:
                fixture(PAYLOAD, payload, True)
                fixture(ENVELOPE, json.loads(vector["envelope_jcs"]), True)
                bad = copy.deepcopy(payload)
                bad["profile_in_force"] = "managed-cooperative"
                fixture(PAYLOAD, bad, False)
                bad = json.loads(vector["envelope_jcs"])
                bad["purpose"] = "agent-bot/stage2a-member-live-lease/v1"
                fixture(ENVELOPE, bad, False)
    write("fixtures/reservation/v3/stage2a-member-runtime-lease.protected-synthetic.json",
          {"members": vectors, "ready_expires_at": ready["expires_at"]})


if __name__ == "__main__":
    main()
