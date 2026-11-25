"""Independent purpose-separated cooperative aggregate Ready signature oracle."""

import base64
import copy
from datetime import datetime

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from jcs import canonicalize, parse_strict

from stage2a_member_set_fixtures import (
    ASSIGNMENT, CHILD, SIGNED_ASSIGNMENT, SIGNED_CHILD, digest, require, signed,
    verify_existing_envelope,
)

PURPOSE = "agent-bot/soul-cooperative-member-ready/v3"
PAYLOAD = "machine/v3/soul-cooperative-member-ready-payload.schema.json"
ENVELOPE = "machine/v3/soul-cooperative-member-signed-ready.schema.json"


def when(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def check(vector, source, schemas, public):
    assignment, assignment_raw = signed(source, "assignment", SIGNED_ASSIGNMENT, ASSIGNMENT, schemas, public)
    child, child_raw = signed(source, "child_observation", SIGNED_CHILD, CHILD, schemas, public)
    raw = vector["envelope_jcs"].encode()
    ready = verify_existing_envelope(raw, PURPOSE, ENVELOPE, PAYLOAD, schemas, public)
    require(canonicalize(ready) == vector["payload_jcs"].encode() and
            ready["profile_in_force"] == assignment["profile_in_force"] ==
                child["profile_in_force"] == "managed-cooperative" and
            all(ready[k] == assignment[k] == child[k] for k in
                ("host_id", "installation_id", "start_id", "hq_epoch", "reservation_sha256")) and
            ready["assignment_envelope_sha256"] == digest(assignment_raw) and
            ready["child_observation_envelope_sha256"] == digest(child_raw) and
            ready["provisional_hq_mapping_sha256"] == child["provisional_hq_mapping_sha256"] and
            ready["member_b_authority_envelope_sha256"] ==
                digest(source["member_b_authority_envelope_jcs"].encode()),
            "distinct cooperative Ready exact A assignment, child, H map and B authority")
    require(when(child["issued_at"]) <= when(ready["issued_at"]) <
            when(ready["expires_at"]) <= when(child["expires_at"]) and
            len(ready["members"]) == len(child["members"]) == len(assignment["members"]) == 2,
            "short aggregate Ready after observation for exact two members")
    ids = []
    launches = []
    selectors = []
    for i, member in enumerate(ready["members"]):
        observed, assigned = child["members"][i], assignment["members"][i]
        require(member["member_id"] == observed["member_id"] == assigned["member_id"] and
                member["member_launch_id"] == observed["launch_id"] == assigned["launch_id"] and
                member["member_selector"] == observed["member_selector"] == assigned["member_selector"] and
                member["grant_sha256"] == observed["grant_sha256"] and
                member["launcher_process"] == observed["launcher_process"] and
                member["child_process"] == observed["child_process"] and
                member["child_process"]["parent_pid"] == member["launcher_process"]["pid"],
                "own A-observed child, grant, launcher and distinct assigned selector")
        ids.append(member["member_id"])
        launches.append(member["member_launch_id"])
        selectors.append(member["member_selector"])
    require(ids == sorted(ids) and len(set(ids)) == len(set(launches)) == len(set(selectors)) == 2 and
            ready["members"][0]["h_observation_sha256"] !=
                ready["members"][1]["h_observation_sha256"] and
            ready["members"][0]["b_arm_receipt_sha256"] !=
                ready["members"][1]["b_arm_receipt_sha256"],
            "sorted distinct H observations and B arms, no one-member replay")


def resign(vector, key):
    payload = parse_strict(vector["payload_jcs"].encode())
    raw = canonicalize(payload)
    envelope = parse_strict(vector["envelope_jcs"].encode())
    envelope["payload_base64url"] = base64.urlsafe_b64encode(raw).rstrip(b"=").decode()
    envelope["payload_sha256"] = digest(raw)
    envelope["signature_base64url"] = base64.urlsafe_b64encode(
        key.sign(PURPOSE.encode() + b"\0" + raw)).rstrip(b"=").decode()
    return {"payload_jcs": raw.decode(), "envelope_jcs": canonicalize(envelope).decode()}


def check_soul_cooperative_member_ready_fixtures(root, schemas, report):
    vector = parse_strict((root / "fixtures/reservation/v3/"
                           "soul-cooperative-member-ready.two-member-synthetic.json").read_bytes())
    source = parse_strict((root / "fixtures/reservation/v3/stage2a-member-set.synthetic.json").read_bytes())[
        "managed-cooperative"]
    key = Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33)))
    public = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    try:
        check(vector, source, schemas, public)
        changed = copy.deepcopy(vector)
        payload = parse_strict(changed["payload_jcs"].encode())
        payload["members"][1]["member_id"] = payload["members"][0]["member_id"]
        changed.update(resign({"payload_jcs": canonicalize(payload).decode(),
                               "envelope_jcs": changed["envelope_jcs"]}, key))
        try:
            check(changed, source, schemas, public)
        except ValueError:
            pass
        else:
            raise ValueError("signed one-member replay accepted as two-member Ready")
        changed = copy.deepcopy(vector)
        payload = parse_strict(changed["payload_jcs"].encode())
        payload["bridge_observed_sha256"] = "sha256:" + "0" * 64
        changed.update(resign({"payload_jcs": canonicalize(payload).decode(),
                               "envelope_jcs": changed["envelope_jcs"]}, key))
        # The bridge observation digest is synthetic and has no raw signed
        # source in this vector. The signer/consumer must resolve it before a
        # physical claim; shape-only validation cannot reject this mutation.
        require(changed["payload_jcs"] != vector["payload_jcs"], "synthetic bridge digest mutation")
        report(True, "cooperative v3 Ready A signature, two-member joins and replay refusal")
    except Exception as error:
        report(False, "cooperative v3 Ready A signature, two-member joins and replay refusal", str(error))
