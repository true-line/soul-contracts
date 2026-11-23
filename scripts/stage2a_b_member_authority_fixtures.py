"""Independent synthetic signature and cross-record oracle for B v3 authority."""

import copy
import json
from datetime import datetime

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from jcs import canonicalize, parse_strict

from stage2a_member_set_fixtures import (
    ASSIGNMENT, SIGNED_ASSIGNMENT, decode, digest, require, signed, verify_existing_envelope,
)

PURPOSE = "agent-bot/stage2a-b-member-authority/v1"
PAYLOAD = "machine/v3/stage2a-b-member-authority-payload.schema.json"
ENVELOPE = "machine/v3/stage2a-b-member-signed-authority.schema.json"
FD3 = "machine/v3/stage2a-b-member-fd3.schema.json"
PIN = "/Library/Application Support/ai.true-line.agent-bot-hq/soul-authority.pub"


def when(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def check(root, vector, assignment_vector, schemas, public):
    assignment, assignment_raw = signed(assignment_vector, "assignment", SIGNED_ASSIGNMENT,
                                        ASSIGNMENT, schemas, public)
    authority_raw = vector["authority_envelope_jcs"].encode("utf-8")
    authority = verify_existing_envelope(authority_raw, PURPOSE, ENVELOPE, PAYLOAD, schemas, public)
    require(canonicalize(authority) == vector["authority_payload_jcs"].encode("utf-8"),
            "exact A-signed B payload bytes")
    for field in ("profile_in_force", "host_id", "installation_id", "soul_id", "start_id",
                  "hq_epoch", "plan_id", "plan_digest", "reservation_sha256",
                  "owner_plan_member_set_sha256", "b_authority", "bridge"):
        require(authority[field] == assignment[field], "B authority " + field + " joins A assignment")
    require(authority["member_set_assignment_envelope_sha256"] == digest(assignment_raw) and
            authority["runner_uid"] == assignment["runner_uid"] and
            authority["hq_uid"] == assignment["bridge"]["endpoints"]["broker"]["owner_uid"] and
            when(assignment["issued_at"]) < when(authority["issued_at"]) <
            when(authority["expires_at"]) <= when(assignment["expires_at"]),
            "B authority exact assignment, accounts and bounded lifetime")
    rows = authority["members"]
    owner_rows = vector["owner_plan_member_bridge_qualifications"]
    require(len(rows) == len(owner_rows) == 2 and
            [m["member_id"] for m in rows] == sorted(m["member_id"] for m in rows) and
            len({m["member_selector"] for m in rows}) == 2 and
            len({m["launch_id"] for m in rows}) == 2,
            "strict sorted exact two member policies")
    for member, assigned, owner in zip(rows, assignment["members"], owner_rows):
        require(all(member[key] == assigned[key] for key in
                    ("member_id", "launch_id", "member_selector", "adjacent_cli_path", "adjacent_cli_sha256")) and
                member["qualification"] == owner, "explicit owner policy equals assigned member")
    require(rows[0]["qualification"]["client_key_sha256"] ==
            rows[1]["qualification"]["client_key_sha256"],
            "shared nonsecret fixture placeholder is permitted")
    frame = vector["fd3"]
    require(schemas[FD3].is_valid(frame) and len(canonicalize(frame)) <= 16384 and
            frame["machine_pin_path"] == PIN and frame["version"] == "stage2a-b-assignment/v3" and
            decode(frame["assignment_envelope_base64url"]) == assignment_raw and
            decode(frame["authority_envelope_base64url"]) == authority_raw,
            "B FD3 bounded exact signed envelope bytes and fixed A pin")
    selectors = frame["selectors"]
    for fd, field in (("installation_id", "installation_id"), ("start_id", "start_id"),
                      ("plan_id", "plan_id"), ("plan_digest", "plan_digest"),
                      ("reservation_digest", "reservation_sha256")):
        require(selectors[fd] == assignment[field], "B FD3 selector " + fd)
    require(selectors["assignment_envelope_sha256"] == digest(assignment_raw) and
            selectors["authority_envelope_sha256"] == digest(authority_raw) and
            selectors["member_selectors_sha256"] == digest(canonicalize(
                [m["member_selector"] for m in rows])) and
            frame["hq_epoch"] == assignment["hq_epoch"] and
            frame["bridge_uid"] == assignment["bridge"]["uid"] and
            frame["hq_uid"] == authority["hq_uid"] and
            frame["runner_uid"] == authority["runner_uid"] and
            when(frame["expires_at"]) == when(authority["expires_at"]),
            "B FD3 selector/account/expiry joins")
    for endpoint in ("broker", "relay"):
        require(frame[endpoint]["path"] == assignment["bridge"]["endpoints"][endpoint]["socket_path"],
                "B FD3 signed endpoint path " + endpoint)


def check_stage2a_b_member_authority_fixtures(root, schemas, report):
    vector = parse_strict((root / "fixtures/reservation/v3/"
                           "stage2a-b-member-authority.two-member-synthetic.json").read_bytes())
    assignment = parse_strict((root / "fixtures/reservation/v3/stage2a-member-set.synthetic.json").read_bytes())[
        "managed-protected"]
    public = Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33))).public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    try:
        check(root, vector, assignment, schemas, public)
        tampered = copy.deepcopy(vector)
        tampered["fd3"]["selectors"]["member_selectors_sha256"] = "sha256:" + "0" * 64
        try:
            check(root, tampered, assignment, schemas, public)
        except ValueError:
            pass
        else:
            raise ValueError("tampered member selectors accepted")
        report(True, "B v3 two-member A signature, reviewed policies, FD3 exact-byte joins")
    except Exception as error:
        report(False, "B v3 two-member A signature, reviewed policies, FD3 exact-byte joins", str(error))
