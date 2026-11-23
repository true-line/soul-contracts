"""Independent cooperative B/H arm bytes and paired A Ready request oracle."""

import copy
from datetime import datetime

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from jcs import canonicalize, parse_strict

from stage2a_member_set_fixtures import (
    ASSIGNMENT, CHILD, SIGNED_ASSIGNMENT, SIGNED_CHILD, decode, digest, require,
    signed, verify_existing_envelope,
)

WIRE = "hq/v1/soul-cooperative-b-member-arm-exchange.schema.json"
READY_REQUEST = "machine/v3/soul-cooperative-member-ready-request.schema.json"


def when(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def check(vector, source, signed_ready, schemas, public):
    assignment, assignment_raw = signed(source, "assignment", SIGNED_ASSIGNMENT, ASSIGNMENT, schemas, public)
    child, child_raw = signed(source, "child_observation", SIGNED_CHILD, CHILD, schemas, public)
    authority_raw = source["member_b_authority_envelope_jcs"].encode()
    authority = verify_existing_envelope(
        authority_raw, "agent-bot/stage2a-b-member-authority/v1",
        "machine/v3/stage2a-b-member-signed-authority.schema.json",
        "machine/v3/stage2a-b-member-authority-payload.schema.json", schemas, public)
    ready = verify_existing_envelope(
        signed_ready["envelope_jcs"].encode(), "agent-bot/soul-cooperative-member-ready/v3",
        "machine/v3/soul-cooperative-member-signed-ready.schema.json",
        "machine/v3/soul-cooperative-member-ready-payload.schema.json", schemas, public)
    rows, request = vector["members"], vector["ready_request"]
    require(len(rows) == len(request["arms"]) == len(ready["members"]) == 2 and
            schemas[READY_REQUEST].is_valid(request) and
            ready["member_b_authority_envelope_sha256"] == digest(authority_raw) and
            authority["profile_in_force"] == "managed-cooperative" and
            request["bridge_observed_sha256"] == ready["bridge_observed_sha256"] and
            request["child_observation_envelope_sha256"] == digest(child_raw) and
            request["member_b_authority_envelope_sha256"] == digest(authority_raw),
            "paired A request names exact cooperative signed child/B/Ready sources")
    expected = {
        "installation_id": assignment["installation_id"], "start_id": assignment["start_id"],
        "plan_id": assignment["plan_id"], "plan_digest": assignment["plan_digest"],
        "reservation_digest": assignment["reservation_sha256"],
        "assignment_envelope_sha256": digest(assignment_raw),
        "authority_envelope_sha256": digest(authority_raw),
        "member_selectors_sha256": digest(canonicalize([m["member_selector"] for m in assignment["members"]])),
    }
    require(request["reservation_sha256"] == assignment["reservation_sha256"] and
            all(request[k] == assignment[k] for k in
                ("installation_id", "start_id", "plan_id", "plan_digest", "hq_epoch")) and
            len({row["observe_request"]["observe_nonce"] for row in rows}) == 2 and
            len({row["arm_request"]["arm_nonce"] for row in rows}) == 2,
            "same reservation/plan and distinct one-use B/H challenges")
    for i, row in enumerate(rows):
        observe, result, arm, ack = (row[k] for k in
                                     ("observe_request", "observe_result", "arm_request", "arm_result"))
        require(all(schemas[WIRE].is_valid(frame) for frame in row.values()) and
                request["arms"][i] == {"arm_request": arm, "arm_result": ack} and
                observe["selectors"] == arm["selectors"] == expected and
                all(frame["member_id"] == ready["members"][i]["member_id"] and
                    frame["member_selector"] == ready["members"][i]["member_selector"]
                    for frame in row.values()) and
                child["members"][i]["member_id"] == ready["members"][i]["member_id"],
                "distinct cooperative op kinds and same-bound exact A selectors/member")
        require(observe["observe_nonce"] == result["observe_nonce"] == arm["observe_nonce"] and
                arm["arm_nonce"] == ack["arm_nonce"] and
                decode(result["child_observation_envelope_base64url"]) == child_raw and
                result["child_observation_envelope_sha256"] ==
                    arm["child_observation_envelope_sha256"] == digest(child_raw) and
                result["expires_at"] == ack["expires_at"] == child["expires_at"],
                "full exact A-signed child envelope and fresh nonce echoes")
        arm_bytes = canonicalize(arm["bridge_arm"])
        require(arm["bridge_arm_receipt_sha256"] == digest(arm_bytes) ==
                ack["bridge_arm_receipt_sha256"] == ready["members"][i]["b_arm_receipt_sha256"] and
                arm["bridge_arm"]["child_observation_envelope_sha256"] == digest(child_raw) and
                arm["bridge_arm"]["member_id"] == ready["members"][i]["member_id"] and
                arm["bridge_arm"]["member_selector"] == ready["members"][i]["member_selector"] and
                ack["state"] == "recorded-pending-aggregate-ready" and
                when(arm["bridge_arm"]["armed_at"]) < when(ready["issued_at"]),
                "B-to-H bridge_arm JCS bytes, not H ACK, define Ready receipt hash")
    require(rows[0]["arm_request"]["bridge_arm_receipt_sha256"] !=
            rows[1]["arm_request"]["bridge_arm_receipt_sha256"],
            "two distinct arm receipts required before aggregate Ready")


def check_soul_cooperative_b_member_arm_fixtures(root, schemas, report):
    vector = parse_strict((root / "fixtures/reservation/v3/"
                           "soul-cooperative-b-member-arm-exchange.two-member-synthetic.json").read_bytes())
    source = parse_strict((root / "fixtures/reservation/v3/stage2a-member-set.synthetic.json").read_bytes())[
        "managed-cooperative"]
    signed_ready = parse_strict((root / "fixtures/reservation/v3/"
                                 "soul-cooperative-member-ready.two-member-synthetic.json").read_bytes())
    public = Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33))).public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    try:
        check(vector, source, signed_ready, schemas, public)
        bad = copy.deepcopy(vector)
        bad["ready_request"]["arms"][1]["arm_request"]["bridge_arm_receipt_sha256"] = \
            bad["ready_request"]["arms"][0]["arm_request"]["bridge_arm_receipt_sha256"]
        try:
            check(bad, source, signed_ready, schemas, public)
        except ValueError:
            pass
        else:
            raise ValueError("swapped cooperative B arm digest accepted")
        report(True, "distinct cooperative B/H observe/arm and exact B-row Ready request joins")
    except Exception as error:
        report(False, "distinct cooperative B/H observe/arm and exact B-row Ready request joins", str(error))
