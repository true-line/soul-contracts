"""Independent fixture oracle for A-signed inert member wrapper live leases."""

import copy
from datetime import datetime

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from jcs import canonicalize, parse_strict

from stage2a_member_set_fixtures import (
    ASSIGNMENT, CHILD, SIGNED_ASSIGNMENT, SIGNED_CHILD, decode, digest, require,
    signed, verify_existing_envelope,
)

PURPOSE = "agent-bot/stage2a-member-live-lease/v1"
PAYLOAD = "machine/v3/stage2a-member-live-lease-payload.schema.json"
ENVELOPE = "machine/v3/stage2a-member-signed-live-lease.schema.json"


def when(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def check(vectors, source, schemas, public):
    assignment, assignment_raw = signed(source, "assignment", SIGNED_ASSIGNMENT, ASSIGNMENT, schemas, public)
    child, child_raw = signed(source, "child_observation", SIGNED_CHILD, CHILD, schemas, public)
    require(len(vectors) == len(child["members"]) == 2, "exact two separately leased wrappers")
    used = set()
    for i, vector in enumerate(vectors):
        raw = vector["envelope_jcs"].encode("utf-8")
        payload = verify_existing_envelope(raw, PURPOSE, ENVELOPE, PAYLOAD, schemas, public)
        observed = child["members"][i]
        assigned = assignment["members"][i]
        require(canonicalize(payload) == vector["payload_jcs"].encode("utf-8") and
                all(payload[k] == assignment[k] for k in
                    ("host_id", "installation_id", "soul_id", "start_id", "hq_epoch", "reservation_sha256")) and
                payload["assignment_envelope_sha256"] == digest(assignment_raw) and
                payload["child_observation_envelope_sha256"] == digest(child_raw),
                "exact A-signed grant/observation parent selectors")
        require(payload["member_id"] == observed["member_id"] == assigned["member_id"] and
                payload["member_selector"] == observed["member_selector"] == assigned["member_selector"] and
                payload["member_launch_id"] == observed["launch_id"] == assigned["launch_id"] and
                payload["grant_sha256"] == observed["grant_sha256"] and
                payload["launcher_process"] == observed["launcher_process"] and
                payload["child_process"] == observed["child_process"] and
                payload["child_process"]["parent_pid"] == payload["launcher_process"]["pid"],
                "member-specific grant, wrapper and inert ACP child kernel tuple")
        nonce = decode(payload["challenge_nonce_base64url"])
        key = (payload["member_selector"], payload["sequence"], nonce)
        require(len(nonce) == 32 and key not in used and payload["sequence"] == 1 and
                when(child["issued_at"]) <= when(payload["issued_at"]) < when(payload["expires_at"]) and
                (when(payload["expires_at"]) - when(payload["issued_at"])).total_seconds() <= 5 and
                when(payload["expires_at"]) <= when(child["expires_at"]),
                "fresh nonce, increasing per-member sequence and at-most-five-second lease")
        used.add(key)


def check_stage2a_member_live_lease_fixtures(root, schemas, report):
    vectors = parse_strict((root / "fixtures/reservation/v3/"
                            "stage2a-member-live-lease.two-member-synthetic.json").read_bytes())["members"]
    source = parse_strict((root / "fixtures/reservation/v3/stage2a-member-set.synthetic.json").read_bytes())[
        "managed-protected"]
    public = Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33))).public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    try:
        check(vectors, source, schemas, public)
        changed = copy.deepcopy(vectors)
        changed[1] = changed[0]
        try:
            check(changed, source, schemas, public)
        except ValueError:
            pass
        else:
            raise ValueError("wrong-member/replayed lease accepted")
        report(True, "pre-finalization member live lease A signature, grant/child and five-second joins")
    except Exception as error:
        report(False, "pre-finalization member live lease A signature, grant/child and five-second joins", str(error))
