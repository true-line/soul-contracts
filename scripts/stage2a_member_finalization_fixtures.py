"""Independent exact-byte joins for synthetic H commit and A acknowledgement."""

import copy
from datetime import datetime

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from jcs import canonicalize, parse_strict

from stage2a_member_set_fixtures import (
    ASSIGNMENT, CHILD, READY, SIGNED_ASSIGNMENT, SIGNED_CHILD, SIGNED_READY,
    decode, digest, require, signed, verify_existing_envelope,
)

RECORD = "hq/v1/stage2a-member-finalization.schema.json"
REQUEST = "machine/v3/stage2a-member-finalization-request.schema.json"
ACK_PAYLOAD = "machine/v3/stage2a-member-finalization-ack-payload.schema.json"
ACK_ENVELOPE = "machine/v3/stage2a-member-finalization-signed-ack.schema.json"
ACK_PURPOSE = "agent-bot/stage2a-member-finalization-ack/v1"
RUNTIME_REQUEST = "machine/v3/stage2a-member-runtime-request.schema.json"


def when(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def check(source, vector, schemas, public):
    assignment, assignment_raw = signed(source, "assignment", SIGNED_ASSIGNMENT, ASSIGNMENT, schemas, public)
    child, child_raw = signed(source, "child_observation", SIGNED_CHILD, CHILD, schemas, public)
    ready, ready_raw = signed(source, "ready", SIGNED_READY, READY, schemas, public)
    primary_raw = source["primary_reservation_envelope_jcs"].encode()
    primary = verify_existing_envelope(primary_raw, "agent-bot/stage2a-reservation/v3",
        "machine/v3/stage2a-signed-reservation.schema.json",
        "machine/v3/stage2a-reservation-payload.schema.json", schemas, public)
    b_raw = source["member_b_authority_envelope_jcs"].encode()
    b_authority = verify_existing_envelope(b_raw, "agent-bot/stage2a-b-member-authority/v1",
        "machine/v3/stage2a-b-member-signed-authority.schema.json",
        "machine/v3/stage2a-b-member-authority-payload.schema.json", schemas, public)
    record_raw = vector["record_jcs"].encode()
    record = parse_strict(record_raw)
    request_raw = vector["request_jcs"].encode()
    request = parse_strict(request_raw)
    ack_raw = vector["ack_envelope_jcs"].encode()
    ack = verify_existing_envelope(ack_raw, ACK_PURPOSE, ACK_ENVELOPE, ACK_PAYLOAD, schemas, public)
    require(canonicalize(record) == record_raw and schemas[RECORD].is_valid(record) and
            len(record_raw) <= 8192 and canonicalize(request) == request_raw and
            schemas[REQUEST].is_valid(request) and len(request_raw) <= 16384,
            "exact H JCS record/request and paired wire caps")
    require(record["profile_in_force"] == "managed-protected" == assignment["profile_in_force"] and
            record["launch_id"] == primary["assignment"]["launch_id"] and
            all(record[k] == assignment[k] for k in
                ("host_id", "installation_id", "soul_id", "start_id", "hq_epoch",
                 "reservation_sha256", "plan_id", "plan_digest")) and
            record["assignment_envelope_sha256"] == digest(assignment_raw) and
            record["child_observation_envelope_sha256"] == digest(child_raw) and
            record["ready_envelope_sha256"] == digest(ready_raw) and
            record["member_b_authority_envelope_sha256"] == digest(b_raw) and
            b_authority["member_set_assignment_envelope_sha256"] == digest(assignment_raw) and
            record["provisional_hq_mapping_sha256"] == child["provisional_hq_mapping_sha256"] ==
                ready["provisional_hq_mapping_sha256"] and
            when(ready["issued_at"]) <= when(record["committed_at"]) < when(ready["expires_at"]),
            "H commit selects exact primary and four A-signed envelopes before Ready expiry")
    require(len(record["members"]) == 2 and
            [row["member_id"] for row in record["members"]] == sorted(row["member_id"] for row in record["members"]),
            "two distinct ordered member rows")
    for i, row in enumerate(record["members"]):
        member, observed, armed = assignment["members"][i], child["members"][i], ready["members"][i]
        require(row == {
            "member_id": member["member_id"], "member_selector": member["member_selector"],
            "member_launch_id": member["launch_id"], "runtime_id": observed["runtime_id"],
            "grant_sha256": observed["grant_sha256"],
            "bridge_arm_receipt_sha256": armed["bridge_arm_receipt_sha256"],
            "launcher_process": observed["launcher_process"], "child_process": observed["child_process"],
        } and armed["bridge_arm_receipt_sha256"] == digest(canonicalize(armed["bridge_arm"])) and
            armed["bridge_arm"]["adapter_pid"] == observed["child_process"]["pid"],
            "each durable H member row equals A child, Ready and exact B arm bytes")
    require(decode(request["finalization_base64url"]) == record_raw and
            request["finalization_sha256"] == digest(record_raw) and
            all(request[k] == record[k] for k in
                ("reservation_sha256", "installation_id", "start_id", "launch_id",
                 "plan_id", "plan_digest", "hq_epoch")),
            "paired H request carries exact reopened H bytes, digest and Stop selectors")
    require(vector["ack_payload_jcs"].encode() == canonicalize(ack) and
            ack["hq_finalization_sha256"] == digest(record_raw) and
            ack["ready_envelope_sha256"] == digest(ready_raw) and
            ack["child_observation_envelope_sha256"] == digest(child_raw) and
            all(ack[k] == record[k] for k in
                ("host_id", "installation_id", "soul_id", "start_id", "launch_id",
                 "plan_id", "plan_digest", "hq_epoch", "reservation_sha256")) and
            when(ack["issued_at"]) >= when(record["committed_at"]),
            "A-signed acknowledgement binds exact durable H bytes, Ready, child and selectors")
    runtime_raw = vector["runtime_request_jcs"].encode()
    runtime = parse_strict(runtime_raw)
    first = record["members"][0]
    require(canonicalize(runtime) == runtime_raw and schemas[RUNTIME_REQUEST].is_valid(runtime) and
            len(runtime_raw) <= 16384 and
            decode(runtime["hq_finalization_base64url"]) == record_raw and
            runtime["hq_finalization_sha256"] == ack["hq_finalization_sha256"] and
            runtime["ready_envelope_sha256"] == digest(ready_raw) and
            runtime["child_observation_envelope_sha256"] == digest(child_raw) and
            all(runtime[k] == request[k] for k in
                ("reservation_sha256", "installation_id", "start_id", "launch_id",
                 "plan_id", "plan_digest", "hq_epoch")) and
            all(runtime[k] == first[k] for k in
                ("member_id", "member_selector", "member_launch_id", "grant_sha256")) and
            runtime["launcher_pid"] == runtime["peer_pid"] == first["launcher_process"]["pid"] and
            runtime["child_pid"] == first["child_process"]["pid"] and
            runtime["peer_uid"] == assignment["runner_uid"] and
            runtime["after_sequence"] == 0 and runtime["previous_lease_envelope_sha256"] is None,
            "renewal carries exact reopened H bytes and peer-bound member selectors")


def check_stage2a_member_finalization_fixtures(root, schemas, report):
    public = Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33))).public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    source = parse_strict((root / "fixtures/reservation/v3/stage2a-member-set.synthetic.json").read_bytes())[
        "managed-protected"]
    vector = parse_strict((root / "fixtures/reservation/v3/stage2a-member-finalization.two-member-synthetic.json").read_bytes())
    try:
        check(source, vector, schemas, public)
        changed = copy.deepcopy(vector)
        record = parse_strict(changed["record_jcs"].encode())
        record["members"][0]["runtime_id"] = record["members"][1]["runtime_id"]
        changed["record_jcs"] = canonicalize(record).decode()
        try:
            check(source, changed, schemas, public)
        except ValueError:
            pass
        else:
            raise ValueError("cross-member durable H map accepted")
        changed = copy.deepcopy(vector)
        record = parse_strict(changed["record_jcs"].encode())
        record["launch_id"] = record["members"][1]["member_launch_id"]
        changed["record_jcs"] = canonicalize(record).decode()
        try:
            check(source, changed, schemas, public)
        except ValueError:
            pass
        else:
            raise ValueError("wrong primary reservation launch accepted")
        changed = copy.deepcopy(vector)
        record = parse_strict(changed["record_jcs"].encode())
        record["committed_at"] = "2026-11-22T14:15:37.000Z"
        changed["record_jcs"] = canonicalize(record).decode()
        try:
            check(source, changed, schemas, public)
        except ValueError:
            pass
        else:
            raise ValueError("H commit after Ready expiry accepted")
        changed = copy.deepcopy(vector)
        request = parse_strict(changed["request_jcs"].encode())
        request["finalization_sha256"] = "sha256:" + "0" * 64
        changed["request_jcs"] = canonicalize(request).decode()
        try:
            check(source, changed, schemas, public)
        except ValueError:
            pass
        else:
            raise ValueError("changed reopened H record digest accepted")
        changed = copy.deepcopy(vector)
        runtime = parse_strict(changed["runtime_request_jcs"].encode())
        raw_field = runtime["hq_finalization_base64url"]
        runtime["hq_finalization_base64url"] = raw_field[:-1] + ("B" if raw_field[-1] == "A" else "A")
        changed["runtime_request_jcs"] = canonicalize(runtime).decode()
        try:
            check(source, changed, schemas, public)
        except ValueError:
            pass
        else:
            raise ValueError("changed reopened H runtime bytes accepted")
        report(True, "protected H durable two-member commit and A-signed ack exact-byte joins")
    except Exception as error:
        report(False, "protected H durable two-member commit and A-signed ack exact-byte joins", str(error))
