#!/usr/bin/env python3
"""Generate a synthetic distinct cooperative aggregate Ready signature vector."""

import base64
import copy
import json
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from jcs import canonicalize

from stage2a_member_set_fixtures import digest

ROOT = Path(__file__).resolve().parents[1]
PURPOSE = "agent-bot/soul-cooperative-member-ready/v3"
PAYLOAD = "machine/v3/soul-cooperative-member-ready-payload.schema.json"
ENVELOPE = "machine/v3/soul-cooperative-member-signed-ready.schema.json"


def b64(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def write(path, value):
    target = ROOT / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def fixture(schema, value, valid):
    name = schema.rsplit("/", 1)[-1].removesuffix(".schema.json") + ".two-member-synthetic.json"
    record = {"schema": schema, "input": value,
              "expect": {"schema": "valid" if valid else "invalid"}}
    if valid:
        record["canonical_sha256"] = digest(canonicalize(value))
    else:
        base = ROOT / "fixtures/positive" / name
        record["base"] = {"fixture": "positive/" + name,
                          "sha256": digest(base.read_bytes())}
    write("fixtures/" + ("positive/" if valid else "negative/") + name, record)


def main():
    source = json.loads((ROOT / "fixtures/reservation/v3/stage2a-member-set.synthetic.json").read_text())[
        "managed-cooperative"]
    assignment = json.loads(source["assignment_payload_jcs"])
    child = json.loads(source["child_observation_payload_jcs"])
    old_ready = json.loads(source["ready_payload_jcs"])
    key = Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33)))
    public = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    payload = {k: assignment[k] for k in
               ("host_id", "installation_id", "start_id", "hq_epoch", "reservation_sha256")}
    payload.update({
        "contract": "machine/v3", "kind": "soul-cooperative-member-ready", "schema_version": 3,
        "profile_in_force": "managed-cooperative",
        "assignment_envelope_sha256": digest(source["assignment_envelope_jcs"].encode()),
        "child_observation_envelope_sha256": digest(source["child_observation_envelope_jcs"].encode()),
        "provisional_hq_mapping_sha256": child["provisional_hq_mapping_sha256"],
        "member_b_authority_envelope_sha256": digest(source["member_b_authority_envelope_jcs"].encode()),
        "bridge_observed_sha256": "sha256:" + "8" * 64,
        "members": [], "issued_at": old_ready["issued_at"], "expires_at": old_ready["expires_at"],
    })
    for i, observed in enumerate(child["members"]):
        payload["members"].append({
            "member_id": observed["member_id"], "member_launch_id": observed["launch_id"],
            "member_selector": observed["member_selector"], "grant_sha256": observed["grant_sha256"],
            "launcher_process": observed["launcher_process"], "child_process": observed["child_process"],
            "h_observation_sha256": "sha256:" + str(i + 6) * 64,
            "b_arm_receipt_sha256": old_ready["members"][i]["bridge_arm_receipt_sha256"],
        })
    raw = canonicalize(payload)
    envelope = {"schema_version": 3, "purpose": PURPOSE,
                "issuer_public_key_base64url": b64(public), "payload_sha256": digest(raw),
                "payload_base64url": b64(raw),
                "signature_base64url": b64(key.sign(PURPOSE.encode() + b"\0" + raw))}
    fixture(PAYLOAD, payload, True)
    fixture(ENVELOPE, envelope, True)
    bad = copy.deepcopy(payload)
    bad["profile_in_force"] = "managed-protected"
    fixture(PAYLOAD, bad, False)
    bad = copy.deepcopy(envelope)
    bad["purpose"] = "agent-bot/stage2a-member-set-ready/v1"
    fixture(ENVELOPE, bad, False)
    write("fixtures/reservation/v3/soul-cooperative-member-ready.two-member-synthetic.json",
          {"payload_jcs": raw.decode(), "envelope_jcs": canonicalize(envelope).decode(),
           "observation_artifacts": "synthetic hashes only; real A/B/H bytes still required"})


if __name__ == "__main__":
    main()
