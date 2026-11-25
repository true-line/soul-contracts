"""Independent A-envelope joins for synthetic prestarted H-to-R attach results."""

import copy
from datetime import datetime

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from jcs import canonicalize, parse_strict

from stage2a_member_set_fixtures import (
    ASSIGNMENT, CHILD, READY, SIGNED_ASSIGNMENT, SIGNED_CHILD, SIGNED_READY,
    decode, digest, require, signed, verify_existing_envelope,
)

SCHEMA = "hq/v1/stage2a-member-attach.schema.json"
PURPOSE = "agent-bot/stage2a-b-member-authority/v1"
ENVELOPE = "machine/v3/stage2a-b-member-signed-authority.schema.json"
PAYLOAD = "machine/v3/stage2a-b-member-authority-payload.schema.json"


def when(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def check(results, source, schemas, public):
    assignment, assignment_raw = signed(source, "assignment", SIGNED_ASSIGNMENT, ASSIGNMENT, schemas, public)
    child, child_raw = signed(source, "child_observation", SIGNED_CHILD, CHILD, schemas, public)
    ready, ready_raw = signed(source, "ready", SIGNED_READY, READY, schemas, public)
    authority_raw = source["member_b_authority_envelope_jcs"].encode("utf-8")
    authority = verify_existing_envelope(authority_raw, PURPOSE, ENVELOPE, PAYLOAD, schemas, public)
    require(assignment["profile_in_force"] == child["profile_in_force"] ==
            authority["profile_in_force"] == ready["profile_in_force"],
            "A-signed assignment, child, B authority and Ready have one profile")
    require(len(results) == 2 and child["assignment_envelope_sha256"] ==
            ready["assignment_envelope_sha256"] == digest(assignment_raw) and
            ready["child_observation_envelope_sha256"] == digest(child_raw) and
            ready["member_b_authority_envelope_sha256"] == digest(authority_raw) and
            authority["member_set_assignment_envelope_sha256"] == digest(assignment_raw),
            "three exact A envelopes and distinct B policy close the assignment chain")
    seen = set()
    for i, result in enumerate(results):
        require(schemas[SCHEMA].is_valid(result) and len(canonicalize(result)) <= 131072,
                "versioned H-to-R result shape and 128 KiB JCS cap")
        member = assignment["members"][i]
        observed = child["members"][i]
        armed = ready["members"][i]
        require(all(result[k] == assignment[k] for k in ("installation_id", "start_id")) and
                result["member_id"] == member["member_id"] == observed["member_id"] == armed["member_id"] and
                result["member_selector"] == member["member_selector"] == observed["member_selector"] ==
                    armed["member_selector"] == authority["members"][i]["member_selector"] and
                result["launch_id"] == member["launch_id"] == observed["launch_id"] == armed["launch_id"] and
                result["runtime_id"] == observed["runtime_id"] == armed["runtime_id"] ==
                    child["provisional_hq_mapping"]["members"][i]["runtime_id"] and
                result["member_selector"] not in seen,
                "exact signed per-member selector/launch/runtime and distinctness")
        seen.add(result["member_selector"])
        require(decode(result["child_observation_envelope_base64url"]) == child_raw and
                decode(result["member_b_authority_envelope_base64url"]) == authority_raw and
                decode(result["ready_envelope_base64url"]) == ready_raw and
                result["child_observation_envelope_sha256"] == digest(child_raw) and
                result["member_b_authority_envelope_sha256"] == digest(authority_raw) and
                result["ready_envelope_sha256"] == digest(ready_raw) and
                when(result["expires_at"]) <= when(ready["expires_at"]),
                "full exact A-signed child/B-policy/Ready envelopes and bounded expiry")
        require(result["runner_endpoint"]["peerUid"] == assignment["runner_uid"],
                "H admission endpoint expects the A-assigned connecting R UID")
        approved = assignment["bridge"]["endpoints"]["member"]
        endpoint = ({key: approved[key] for key in
                    ("directory", "owner_uid", "group_gid", "dir_mode", "socket_mode", "peer_uids")}
                    if assignment["profile_in_force"] == "managed-protected" else approved)
        require(result["member_socket"] == approved["socket_path"] and
                result["member_endpoint"] == endpoint and
                armed["bridge_arm"]["adapter_pid"] == observed["child_process"]["pid"] and
                armed["bridge_arm_receipt_sha256"] == digest(canonicalize(armed["bridge_arm"])),
                "signed member socket and A-observed ACP child equal B arm receipt")


def check_stage2a_member_attach_fixtures(root, schemas, report):
    public = Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33))).public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    sources = parse_strict((root / "fixtures/reservation/v3/stage2a-member-set.synthetic.json").read_bytes())
    for profile, name in (("managed-protected", "stage2a-member-attach.two-member-synthetic.json"),
                          ("managed-cooperative", "stage2a-member-attach.cooperative-two-member-synthetic.json")):
        results = parse_strict((root / "fixtures/reservation/v3" / name).read_bytes())["results"]
        source = sources[profile]
        try:
            check(results, source, schemas, public)
            changed = copy.deepcopy(results)
            changed[0]["member_selector"] = changed[1]["member_selector"]
            try:
                check(changed, source, schemas, public)
            except ValueError:
                pass
            else:
                raise ValueError("cross-member selector accepted")
            changed = copy.deepcopy(results)
            changed[0]["runner_endpoint"]["peerUid"] += 1
            try:
                check(changed, source, schemas, public)
            except ValueError:
                pass
            else:
                raise ValueError("wrong H admission peer UID accepted")
            changed = copy.deepcopy(results)
            if profile == "managed-cooperative":
                changed[0]["member_endpoint"]["parent_inode"] = "9009"
            else:
                changed[0]["member_endpoint"]["peer_uids"] = changed[0]["member_endpoint"]["peer_uids"][:1]
            try:
                check(changed, source, schemas, public)
            except ValueError:
                pass
            else:
                raise ValueError("wrong profile-specific signed member endpoint accepted")
            changed_source = copy.deepcopy(source)
            other = "managed-cooperative" if profile == "managed-protected" else "managed-protected"
            changed_source["ready_envelope_jcs"] = sources[other]["ready_envelope_jcs"]
            try:
                check(results, changed_source, schemas, public)
            except ValueError:
                pass
            else:
                raise ValueError("cross-profile A-signed Ready accepted")
            report(True, f"{profile} H-to-R prestarted attach exact A child/B-policy/Ready joins")
        except Exception as error:
            report(False, f"{profile} H-to-R prestarted attach exact A child/B-policy/Ready joins", str(error))
