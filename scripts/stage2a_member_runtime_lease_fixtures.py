"""Independent signed post-Ready protected member lease and renewal-chain oracle."""

import base64
import copy
from datetime import datetime

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from jcs import canonicalize, parse_strict

from stage2a_member_set_fixtures import (
    ASSIGNMENT, CHILD, READY, SIGNED_ASSIGNMENT, SIGNED_CHILD, SIGNED_READY,
    decode, digest, require, signed, verify_existing_envelope,
)

PURPOSE = "agent-bot/stage2a-member-runtime-lease/v1"
PAYLOAD = "machine/v3/stage2a-member-runtime-lease-payload.schema.json"
ENVELOPE = "machine/v3/stage2a-member-signed-runtime-lease.schema.json"


def when(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def check(vectors, source, ready_expires, schemas, public):
    assignment, assignment_raw = signed(source, "assignment", SIGNED_ASSIGNMENT, ASSIGNMENT, schemas, public)
    child, child_raw = signed(source, "child_observation", SIGNED_CHILD, CHILD, schemas, public)
    ready, ready_raw = signed(source, "ready", SIGNED_READY, READY, schemas, public)
    require(ready_expires == ready["expires_at"] and len(vectors) == 7,
            "synthetic signed Ready and two separately leased members")
    histories = {}
    used = set()
    for vector in vectors:
        raw = vector["envelope_jcs"].encode()
        payload = verify_existing_envelope(raw, PURPOSE, ENVELOPE, PAYLOAD, schemas, public)
        require(canonicalize(payload) == vector["payload_jcs"].encode() and
                all(payload[k] == assignment[k] for k in
                    ("host_id", "installation_id", "soul_id", "start_id", "hq_epoch", "reservation_sha256")) and
                payload["profile_in_force"] == ready["profile_in_force"] == "managed-protected" and
                payload["assignment_envelope_sha256"] == digest(assignment_raw) and
                payload["child_observation_envelope_sha256"] == digest(child_raw) and
                payload["ready_envelope_sha256"] == digest(ready_raw) and
                payload["member_b_authority_envelope_sha256"] ==
                    ready["member_b_authority_envelope_sha256"] and
                payload["hq_finalization_sha256"] == "sha256:" + "f" * 64,
                "exact signed A assignment, child, Ready and B-policy joins")
        matches = [i for i, m in enumerate(ready["members"]) if m["member_id"] == payload["member_id"]]
        require(len(matches) == 1, "exact one Ready member")
        i = matches[0]
        observed, admitted, assigned = child["members"][i], ready["members"][i], assignment["members"][i]
        require(payload["member_selector"] == observed["member_selector"] == admitted["member_selector"] == assigned["member_selector"] and
                payload["member_launch_id"] == observed["launch_id"] == admitted["launch_id"] == assigned["launch_id"] and
                payload["runtime_id"] == observed["runtime_id"] == admitted["runtime_id"] and
                payload["grant_sha256"] == observed["grant_sha256"] and
                payload["bridge_arm_receipt_sha256"] == admitted["bridge_arm_receipt_sha256"] and
                payload["launcher_process"] == observed["launcher_process"] and
                payload["child_process"] == observed["child_process"] and
                payload["child_process"]["parent_pid"] == payload["launcher_process"]["pid"] and
                all(payload["bridge_process"][k] == ready["bridge_process"][k] for k in
                    ("pid", "uid", "gid", "start_seconds", "start_micros")),
                "own member grant, arm, wrapper/child and B kernel identity")
        nonce = decode(payload["challenge_nonce_base64url"])
        key = (payload["member_id"], payload["sequence"], nonce)
        require(len(nonce) == 32 and key not in used, "fresh 32-byte one-use member challenge")
        used.add(key)
        issued, expires, approved = (when(payload[k]) for k in ("issued_at", "expires_at", "approved_until"))
        require(when(ready["issued_at"]) <= issued < expires <= approved and
                (expires - issued).total_seconds() <= 5 and
                payload["installed_authority_sha256"] == "sha256:" + "d" * 64 and
                payload["bind_receipt_sha256"] == "sha256:" + "b" * 64,
                "bounded five-second lease and pinned synthetic installed authority/bind")
        history = histories.setdefault(payload["member_id"], [])
        if not history:
            require(payload["sequence"] == 1 and payload["previous_lease_envelope_sha256"] is None and
                    issued < when(ready["expires_at"]), "first lease before short Ready expires")
        else:
            previous = history[-1]
            prior_payload = previous["payload"]
            require(payload["sequence"] == prior_payload["sequence"] + 1 and
                    payload["previous_lease_envelope_sha256"] == digest(previous["raw"]) and
                    issued < when(prior_payload["expires_at"]) and
                    payload["approved_until"] == prior_payload["approved_until"] and
                    payload["runner_process"] == prior_payload["runner_process"] and
                    payload["q_process"] == prior_payload["q_process"] and
                    payload["owner_driver_process"] == prior_payload["owner_driver_process"],
                    "unbroken previous exact signed envelope, process and approval chain")
        history.append({"payload": payload, "raw": raw})
    require(len(histories) == 2 and sorted(len(v) for v in histories.values()) == [1, 6] and
            any(when(v["payload"]["issued_at"]) > when(ready["expires_at"])
                for v in max(histories.values(), key=len)),
            "one chain renews past admission Ready only through uninterrupted live leases")


def resign(vector, key):
    payload = parse_strict(vector["payload_jcs"].encode())
    raw = canonicalize(payload)
    envelope = parse_strict(vector["envelope_jcs"].encode())
    envelope["payload_base64url"] = base64.urlsafe_b64encode(raw).rstrip(b"=").decode()
    envelope["payload_sha256"] = digest(raw)
    envelope["signature_base64url"] = base64.urlsafe_b64encode(
        key.sign(PURPOSE.encode() + b"\0" + raw)).rstrip(b"=").decode()
    return {"payload_jcs": raw.decode(), "envelope_jcs": canonicalize(envelope).decode()}


def check_stage2a_member_runtime_lease_fixtures(root, schemas, report):
    vector = parse_strict((root / "fixtures/reservation/v3/"
                           "stage2a-member-runtime-lease.protected-synthetic.json").read_bytes())
    source = parse_strict((root / "fixtures/reservation/v3/stage2a-member-set.synthetic.json").read_bytes())[
        "managed-protected"]
    key = Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33)))
    public = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    try:
        check(vector["members"], source, vector["ready_expires_at"], schemas, public)
        for label, patch in (
            ("wrong prior digest", {"previous_lease_envelope_sha256": "sha256:" + "0" * 64}),
            ("missed renewal", {"issued_at": "2026-11-22T14:15:27Z", "expires_at": "2026-11-22T14:15:31Z"}),
        ):
            bad = copy.deepcopy(vector["members"])
            payload = parse_strict(bad[1]["payload_jcs"].encode())
            payload.update(patch)
            bad[1] = resign({"payload_jcs": canonicalize(payload).decode(),
                             "envelope_jcs": bad[1]["envelope_jcs"]}, key)
            try:
                check(bad, source, vector["ready_expires_at"], schemas, public)
            except ValueError:
                pass
            else:
                raise ValueError(label + " accepted")
        report(True, "protected post-Ready A member runtime signature and unbroken five-second chain")
    except Exception as error:
        report(False, "protected post-Ready A member runtime signature and unbroken five-second chain", str(error))
