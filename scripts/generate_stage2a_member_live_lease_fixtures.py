#!/usr/bin/env python3
"""Regenerate fixture-only A-signed pre-finalization member live leases."""

import base64
import copy
import json
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from jcs import canonicalize

from stage2a_member_set_fixtures import digest

ROOT = Path(__file__).resolve().parents[1]
PURPOSE = "agent-bot/stage2a-member-live-lease/v1"
PREFIX = "stage2a-member-live-lease.two-member-synthetic"
PAYLOAD_SCHEMA = "machine/v3/stage2a-member-live-lease-payload.schema.json"
ENVELOPE_SCHEMA = "machine/v3/stage2a-member-signed-live-lease.schema.json"


def b64(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def write(path, value):
    target = ROOT / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n")


def fixture(schema, value, positive):
    name = schema.rsplit("/", 1)[-1].removesuffix(".schema.json") + ".two-member-synthetic.json"
    path = "fixtures/" + ("positive/" if positive else "negative/") + name
    record = {"schema": schema, "input": value, "expect": {"schema": "valid" if positive else "invalid"}}
    if positive:
        record["canonical_sha256"] = digest(canonicalize(value))
    else:
        base = "fixtures/positive/" + name
        record["base"] = {"fixture": base.removeprefix("fixtures/"),
                          "sha256": digest((ROOT / base).read_bytes())}
    write(path, record)


def main():
    source = json.loads((ROOT / "fixtures/reservation/v3/stage2a-member-set.synthetic.json").read_text())[
        "managed-protected"]
    assignment = json.loads(source["assignment_payload_jcs"])
    child = json.loads(source["child_observation_payload_jcs"])
    child_raw = source["child_observation_envelope_jcs"].encode()
    assignment_raw = source["assignment_envelope_jcs"].encode()
    key = Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33)))
    public = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    vectors = []
    for i, member in enumerate(child["members"]):
        payload = {k: assignment[k] for k in
                   ("host_id", "installation_id", "soul_id", "start_id", "hq_epoch", "reservation_sha256")}
        payload.update({
            "contract": "machine/v3", "kind": "stage2a-member-live-lease", "schema_version": 1,
            "profile_in_force": "managed-protected", "assignment_envelope_sha256": digest(assignment_raw),
            "child_observation_envelope_sha256": digest(child_raw),
            "member_id": member["member_id"], "member_selector": member["member_selector"],
            "member_launch_id": member["launch_id"], "grant_sha256": member["grant_sha256"],
            "launcher_process": member["launcher_process"], "child_process": member["child_process"],
            "challenge_nonce_base64url": b64(bytes([50 + i]) * 32), "sequence": 1,
            "issued_at": "2026-11-22T14:15:20Z", "expires_at": "2026-11-22T14:15:24Z",
        })
        raw = canonicalize(payload)
        envelope = {"schema_version": 1, "purpose": PURPOSE,
                    "issuer_public_key_base64url": b64(public),
                    "payload_sha256": digest(raw), "payload_base64url": b64(raw),
                    "signature_base64url": b64(key.sign(PURPOSE.encode() + b"\0" + raw))}
        vectors.append({"payload_jcs": raw.decode(), "envelope_jcs": canonicalize(envelope).decode()})
        if i == 0:
            fixture(PAYLOAD_SCHEMA, payload, True)
            fixture(ENVELOPE_SCHEMA, envelope, True)
            bad_payload = copy.deepcopy(payload)
            bad_payload["sequence"] = 0
            fixture(PAYLOAD_SCHEMA, bad_payload, False)
            bad_envelope = copy.deepcopy(envelope)
            bad_envelope["purpose"] = "agent-bot/stage2a-member-live-lease/v0"
            fixture(ENVELOPE_SCHEMA, bad_envelope, False)
    write("fixtures/reservation/v3/" + PREFIX + ".json", {"members": vectors})


if __name__ == "__main__":
    main()
