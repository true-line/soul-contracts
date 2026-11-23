#!/usr/bin/env python3
"""Generate synthetic durable H finalization and purpose-separated A acknowledgement."""

import base64
import copy
import json
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from jcs import canonicalize

from stage2a_member_set_fixtures import decode, digest

ROOT = Path(__file__).resolve().parents[1]
PURPOSE = "agent-bot/stage2a-member-finalization-ack/v1"
SCHEMAS = {
    "record": "hq/v1/stage2a-member-finalization.schema.json",
    "request": "machine/v3/stage2a-member-finalization-request.schema.json",
    "payload": "machine/v3/stage2a-member-finalization-ack-payload.schema.json",
    "envelope": "machine/v3/stage2a-member-finalization-signed-ack.schema.json",
    "runtime_request": "machine/v3/stage2a-member-runtime-request.schema.json",
}


def b64(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def write(path, value):
    target = ROOT / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def fixture(kind, value, changed):
    schema = SCHEMAS[kind]
    name = schema.rsplit("/", 1)[-1].removesuffix(".schema.json") + ".two-member-synthetic.json"
    positive = "fixtures/positive/" + name
    write(positive, {"schema": schema, "input": value, "expect": {"schema": "valid"},
                     "canonical_sha256": digest(canonicalize(value))})
    write("fixtures/negative/" + name,
          {"schema": schema, "input": changed, "expect": {"schema": "invalid"},
           "base": {"fixture": positive.removeprefix("fixtures/"),
                    "sha256": digest((ROOT / positive).read_bytes())}})


def main():
    source = json.loads((ROOT / "fixtures/reservation/v3/stage2a-member-set.synthetic.json").read_text())[
        "managed-protected"]
    assignment = json.loads(source["assignment_payload_jcs"])
    child = json.loads(source["child_observation_payload_jcs"])
    ready = json.loads(source["ready_payload_jcs"])
    reservation_envelope = json.loads(source["primary_reservation_envelope_jcs"])
    reservation = json.loads(decode(reservation_envelope["payload_base64url"]))
    rows = []
    for member, observed, armed in zip(assignment["members"], child["members"], ready["members"], strict=True):
        assert member["member_id"] == observed["member_id"] == armed["member_id"]
        rows.append({"member_id": member["member_id"], "member_selector": member["member_selector"],
                     "member_launch_id": member["launch_id"], "runtime_id": observed["runtime_id"],
                     "grant_sha256": observed["grant_sha256"],
                     "bridge_arm_receipt_sha256": armed["bridge_arm_receipt_sha256"],
                     "launcher_process": observed["launcher_process"],
                     "child_process": observed["child_process"]})
    record = {"schema": "agent-bot-hq/stage2a-member-finalization/v1",
              "profile_in_force": "managed-protected",
              **{k: assignment[k] for k in ("host_id", "installation_id", "soul_id", "start_id",
                                               "hq_epoch", "reservation_sha256", "plan_id", "plan_digest")},
              "launch_id": reservation["assignment"]["launch_id"],
              "assignment_envelope_sha256": digest(source["assignment_envelope_jcs"].encode()),
              "child_observation_envelope_sha256": digest(source["child_observation_envelope_jcs"].encode()),
              "ready_envelope_sha256": digest(source["ready_envelope_jcs"].encode()),
              "member_b_authority_envelope_sha256": digest(source["member_b_authority_envelope_jcs"].encode()),
              "provisional_hq_mapping_sha256": child["provisional_hq_mapping_sha256"],
              "bind_receipt_sha256": "sha256:" + "9" * 64,
              "members": rows, "committed_at": "2026-11-22T14:15:22.000Z"}
    record_raw = canonicalize(record)
    request = {k: record[k] for k in ("reservation_sha256", "installation_id", "start_id",
                                            "launch_id", "plan_id", "plan_digest", "hq_epoch")}
    request.update({"finalization_base64url": b64(record_raw),
                    "finalization_sha256": digest(record_raw)})
    ack = {"contract": "machine/v3", "kind": "stage2a-member-finalization-ack",
           "schema_version": 1, "profile_in_force": "managed-protected",
           **{k: record[k] for k in ("host_id", "installation_id", "soul_id", "start_id",
                                       "launch_id", "plan_id", "plan_digest", "hq_epoch",
                                       "reservation_sha256", "ready_envelope_sha256",
                                       "child_observation_envelope_sha256")},
           "hq_finalization_sha256": digest(record_raw),
           "issued_at": "2026-11-22T14:15:22.100Z"}
    ack_raw = canonicalize(ack)
    key = Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33)))
    public = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    envelope = {"schema_version": 1, "purpose": PURPOSE,
                "issuer_public_key_base64url": b64(public),
                "payload_sha256": digest(ack_raw), "payload_base64url": b64(ack_raw),
                "signature_base64url": b64(key.sign(PURPOSE.encode() + b"\0" + ack_raw))}
    bad_record = copy.deepcopy(record)
    bad_record["schema"] = "agent-bot-hq/stage2a-member-finalization/v0"
    fixture("record", record, bad_record)
    bad_request = copy.deepcopy(request)
    bad_request["finalization_sha256"] = "0" * 64
    fixture("request", request, bad_request)
    bad_ack = copy.deepcopy(ack)
    bad_ack["profile_in_force"] = "managed-cooperative"
    fixture("payload", ack, bad_ack)
    bad_envelope = copy.deepcopy(envelope)
    bad_envelope["purpose"] = "agent-bot/stage2a-member-runtime-lease/v1"
    fixture("envelope", envelope, bad_envelope)
    first = rows[0]
    runtime_request = {k: request[k] for k in ("reservation_sha256", "installation_id", "start_id",
                                                "launch_id", "plan_id", "plan_digest", "hq_epoch")}
    runtime_request.update({"member_id": first["member_id"],
                            "member_selector": first["member_selector"],
                            "member_launch_id": first["member_launch_id"],
                            "grant_sha256": first["grant_sha256"],
                            "child_observation_envelope_sha256": record["child_observation_envelope_sha256"],
                            "launcher_pid": first["launcher_process"]["pid"],
                            "child_pid": first["child_process"]["pid"],
                            "peer_uid": assignment["runner_uid"],
                            "peer_pid": first["launcher_process"]["pid"],
                            "challenge_nonce_base64url": b64(bytes(range(32))),
                            "after_sequence": 0, "prior_expires_at": "2026-11-22T14:15:23Z",
                            "ready_envelope_sha256": record["ready_envelope_sha256"],
                            "hq_finalization_sha256": digest(record_raw),
                            "hq_finalization_base64url": b64(record_raw),
                            "previous_lease_envelope_sha256": None})
    bad_runtime = copy.deepcopy(runtime_request)
    bad_runtime["previous_lease_envelope_sha256"] = "sha256:" + "0" * 64
    fixture("runtime_request", runtime_request, bad_runtime)
    write("fixtures/reservation/v3/stage2a-member-finalization.two-member-synthetic.json",
          {"record_jcs": record_raw.decode(), "request_jcs": canonicalize(request).decode(),
           "runtime_request_jcs": canonicalize(runtime_request).decode(),
           "ack_payload_jcs": ack_raw.decode(), "ack_envelope_jcs": canonicalize(envelope).decode(),
           "evidence_status": "synthetic only; H bind receipt is a placeholder, no durable or physical proof"})


if __name__ == "__main__":
    main()
