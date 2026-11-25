"""Independent A-envelope joins for synthetic prestarted H-to-R attach results."""

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

SCHEMA = "hq/v1/stage2a-member-attach.schema.json"
PURPOSE = "agent-bot/stage2a-b-member-authority/v1"
ENVELOPE = "machine/v3/stage2a-b-member-signed-authority.schema.json"
PAYLOAD = "machine/v3/stage2a-b-member-authority-payload.schema.json"


def when(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def cooperative_lead_launch(assignment, detached, observed):
    leads = [member for member in assignment["members"] if member["role"] == "lead"]
    require(len(leads) == 1 and observed["launch_id"] == detached["launch_id"] == leads[0]["launch_id"],
            "cooperative B observation names the unique signed lead launch")


def check(results, source, schemas, public, cooperative=None):
    assignment, assignment_raw = signed(source, "assignment", SIGNED_ASSIGNMENT, ASSIGNMENT, schemas, public)
    child, child_raw = signed(source, "child_observation", SIGNED_CHILD, CHILD, schemas, public)
    if cooperative is None:
        ready, ready_raw = signed(source, "ready", SIGNED_READY, READY, schemas, public)
    else:
        ready_raw = cooperative["ready_envelope_jcs"].encode()
        ready = verify_existing_envelope(ready_raw, "agent-bot/soul-cooperative-member-ready/v3",
            "machine/v3/soul-cooperative-member-signed-ready.schema.json",
            "machine/v3/soul-cooperative-member-ready-payload.schema.json", schemas, public)
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
    if cooperative is not None:
        detached_raw = source["private_b_authority_envelope_jcs"].encode()
        detached = verify_existing_envelope(detached_raw, "agent-bot/soul-cooperative-bridge-assignment/v3",
            "machine/v3/soul-cooperative-bridge-signed-assignment.schema.json",
            "machine/v3/soul-cooperative-bridge-assignment-payload.schema.json", schemas, public)
        observed_raw = cooperative["envelope_jcs"].encode()
        observed = verify_existing_envelope(observed_raw, "agent-bot/soul-cooperative-b-observed/v3",
            "machine/v3/soul-cooperative-b-signed-observed.schema.json",
            "machine/v3/soul-cooperative-b-observed-payload.schema.json", schemas, public)
        require(ready["bridge_observed_sha256"] == digest(observed_raw) and
                observed["bridge_assignment_sha256"] == digest(detached_raw) ==
                    assignment["b_authority"]["envelope_sha256"] and
                observed["reservation_sha256"] == assignment["reservation_sha256"] and
                observed["installation_id"] == assignment["installation_id"] and
                observed["start_id"] == assignment["start_id"] and
                all(observed[key] == detached[key] == assignment[key] for key in
                    ("plan_id", "plan_digest", "hq_epoch", "installation_id", "start_id")) and
                observed["bridge"]["uid"] == detached["bridge"]["uid"] and
                observed["bridge"]["gid"] == detached["bridge"]["gid"] and
                observed["relay_socket_birthtime_ns"].isdigit() and
                observed["relay_socket"]["path"] == assignment["bridge"]["endpoints"]["relay"]["socket_path"],
                "exact A-observed B and relay identity join cooperative Ready")
        cooperative_lead_launch(assignment, detached, observed)
        require(when(assignment["issued_at"]) <= when(observed["observed_at"]) <=
                when(ready["issued_at"]) <= min(when(observed["expires_at"]),
                    when(detached["expires_at"]), when(assignment["expires_at"])) and
                when(ready["expires_at"]) <= min(when(observed["expires_at"]),
                    when(detached["expires_at"]), when(assignment["expires_at"])),
                "cooperative B observation precedes Ready and bounds its expiry")
    seen = set()
    for i, result in enumerate(results):
        cap = 32768 if cooperative is not None else 131072
        require(schemas[SCHEMA].is_valid(result) and len(canonicalize(result)) <= cap,
                "versioned H-to-R result shape and profile JCS cap")
        member = assignment["members"][i]
        observed = child["members"][i]
        armed = ready["members"][i]
        require(all(result[k] == assignment[k] for k in ("installation_id", "start_id")) and
                result["member_id"] == member["member_id"] == observed["member_id"] == armed["member_id"] and
                result["member_selector"] == member["member_selector"] == observed["member_selector"] ==
                    armed["member_selector"] == authority["members"][i]["member_selector"] and
                result["launch_id"] == member["launch_id"] == observed["launch_id"] ==
                    armed["launch_id" if cooperative is None else "member_launch_id"] and
                result["runtime_id"] == observed["runtime_id"] ==
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
        if cooperative is not None:
            rows = [decode(row) for row in result["bridge_arm_rows_base64url"]]
            arm_schema = schemas["machine/v3/stage2a-member-set-ready-payload.schema.json"].evolve(
                schema={"$ref": "https://true-line.ai/soul-contracts/machine/v3/"
                        "stage2a-member-set-ready-payload.schema.json#/$defs/readyMember/properties/bridge_arm"})
            require(decode(result["bridge_observed_envelope_base64url"]) == observed_raw and
                    rows == [row.encode() for row in cooperative["bridge_arm_rows_jcs"]] and
                    len({row for row in rows}) == 2 and
                    all(canonicalize(parse_strict(row)) == row and arm_schema.is_valid(parse_strict(row)) and
                        parse_strict(row)["member_id"] == ready["members"][j]["member_id"] and
                        parse_strict(row)["member_selector"] == ready["members"][j]["member_selector"] ==
                            assignment["members"][j]["member_selector"] and
                        parse_strict(row)["runtime_id"] == child["members"][j]["runtime_id"] and
                        parse_strict(row)["child_observation_envelope_sha256"] == digest(child_raw) and
                        parse_strict(row)["bridge_uid"] == detached["bridge"]["uid"] and
                        all(parse_strict(row)[arm_key] == child["members"][j]["child_process"][child_key]
                            for arm_key, child_key in (("adapter_pid", "pid"), ("adapter_uid", "uid"),
                                ("adapter_gid", "gid"), ("adapter_start_seconds", "start_seconds"),
                                ("adapter_start_micros", "start_micros"))) and
                        when(child["observed_at"]) <= when(parse_strict(row)["armed_at"]) <=
                            when(ready["issued_at"]) and
                        digest(row) == ready["members"][j]["b_arm_receipt_sha256"]
                        for j, row in enumerate(rows)),
                    "separate exact B arm JCS rows join A-signed Ready per member")
        require(result["runner_endpoint"]["peerUid"] == assignment["runner_uid"],
                "H admission endpoint expects the A-assigned connecting R UID")
        approved = assignment["bridge"]["endpoints"]["member"]
        endpoint = ({key: approved[key] for key in
                    ("directory", "owner_uid", "group_gid", "dir_mode", "socket_mode", "peer_uids")}
                    if assignment["profile_in_force"] == "managed-protected" else approved)
        require(result["member_socket"] == approved["socket_path"] and
                result["member_endpoint"] == endpoint,
                "signed member socket")
        if cooperative is None:
            require(armed["runtime_id"] == result["runtime_id"],
                    "protected Ready runtime equals the attached A-observed runtime")
            require(armed["bridge_arm"]["adapter_pid"] == observed["child_process"]["pid"] and
                    armed["bridge_arm_receipt_sha256"] == digest(canonicalize(armed["bridge_arm"])),
                    "A-observed ACP child equals B arm receipt")
        else:
            require(armed["child_process"] == observed["child_process"] and
                    armed["launcher_process"] == observed["launcher_process"] and
                    armed["member_launch_id"] == observed["launch_id"] and
                    digest(decode(result["bridge_arm_rows_base64url"][i])) == armed["b_arm_receipt_sha256"],
                    "A-observed child and exact B arm row join cooperative Ready")


def resign_payload_envelope(raw, payload):
    signer = Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33)))
    envelope = parse_strict(raw.encode())
    payload_raw = canonicalize(payload)
    envelope["payload_base64url"] = base64.urlsafe_b64encode(payload_raw).rstrip(b"=").decode()
    envelope["payload_sha256"] = digest(payload_raw)
    envelope["signature_base64url"] = base64.urlsafe_b64encode(
        signer.sign(envelope["purpose"].encode() + b"\0" + payload_raw)).rstrip(b"=").decode()
    return canonicalize(envelope)


def resign_cooperative_mutant(evidence, results, observed_field=None, observed_value=None,
                              arm_field=None, arm_value=None):
    changed_evidence = copy.deepcopy(evidence)
    changed_results = copy.deepcopy(results)

    observed = parse_strict(changed_evidence["payload_jcs"].encode())
    if observed_field is not None:
        observed[observed_field] = observed_value
    observed_raw = resign_payload_envelope(changed_evidence["envelope_jcs"], observed)
    changed_evidence["payload_jcs"] = canonicalize(observed).decode()
    changed_evidence["envelope_jcs"] = observed_raw.decode()

    ready = parse_strict(changed_evidence["ready_payload_jcs"].encode())
    ready["bridge_observed_sha256"] = digest(observed_raw)
    if arm_field is not None:
        arm = parse_strict(changed_evidence["bridge_arm_rows_jcs"][0].encode())
        arm[arm_field] = arm_value
        arm_raw = canonicalize(arm)
        changed_evidence["bridge_arm_rows_jcs"][0] = arm_raw.decode()
        ready["members"][0]["b_arm_receipt_sha256"] = digest(arm_raw)
    ready_raw = resign_payload_envelope(changed_evidence["ready_envelope_jcs"], ready)
    changed_evidence["ready_payload_jcs"] = canonicalize(ready).decode()
    changed_evidence["ready_envelope_jcs"] = ready_raw.decode()
    for result in changed_results:
        result["bridge_observed_envelope_base64url"] = base64.urlsafe_b64encode(observed_raw).rstrip(b"=").decode()
        result["ready_envelope_base64url"] = base64.urlsafe_b64encode(ready_raw).rstrip(b"=").decode()
        result["ready_envelope_sha256"] = digest(ready_raw)
        if arm_field is not None:
            result["bridge_arm_rows_base64url"][0] = base64.urlsafe_b64encode(arm_raw).rstrip(b"=").decode()
    return changed_evidence, changed_results


def check_stage2a_member_attach_fixtures(root, schemas, report):
    public = Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33))).public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    sources = parse_strict((root / "fixtures/reservation/v3/stage2a-member-set.synthetic.json").read_bytes())
    cooperative = parse_strict((root / "fixtures/reservation/v3/soul-cooperative-b-observed.attach-synthetic.json").read_bytes())
    for profile, name in (("managed-protected", "stage2a-member-attach.two-member-synthetic.json"),
                          ("managed-cooperative", "stage2a-member-attach.cooperative-two-member-synthetic.json")):
        results = parse_strict((root / "fixtures/reservation/v3" / name).read_bytes())["results"]
        source = sources[profile]
        try:
            evidence = cooperative if profile == "managed-cooperative" else None
            check(results, source, schemas, public, evidence)
            changed = copy.deepcopy(results)
            changed[0]["member_selector"] = changed[1]["member_selector"]
            try:
                check(changed, source, schemas, public, evidence)
            except ValueError:
                pass
            else:
                raise ValueError("cross-member selector accepted")
            changed = copy.deepcopy(results)
            changed[0]["runner_endpoint"]["peerUid"] += 1
            try:
                check(changed, source, schemas, public, evidence)
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
                check(changed, source, schemas, public, evidence)
            except ValueError:
                pass
            else:
                raise ValueError("wrong profile-specific signed member endpoint accepted")
            changed_source = copy.deepcopy(source)
            changed_evidence = copy.deepcopy(evidence)
            other = "managed-cooperative" if profile == "managed-protected" else "managed-protected"
            if profile == "managed-cooperative":
                changed_evidence["ready_envelope_jcs"] = sources[other]["ready_envelope_jcs"]
            else:
                changed_source["ready_envelope_jcs"] = sources[other]["ready_envelope_jcs"]
            try:
                check(results, changed_source, schemas, public, changed_evidence)
            except ValueError:
                pass
            else:
                raise ValueError("cross-profile A-signed Ready accepted")
            if profile == "managed-cooperative":
                second_lead_source = copy.deepcopy(source)
                second_lead_assignment = parse_strict(source["assignment_payload_jcs"].encode())
                second_lead_assignment["members"].reverse()
                second_lead_source["assignment_payload_jcs"] = canonicalize(second_lead_assignment).decode()
                second_lead_source["assignment_envelope_jcs"] = resign_payload_envelope(
                    source["assignment_envelope_jcs"], second_lead_assignment).decode()
                signed_second_lead, _ = signed(second_lead_source, "assignment", SIGNED_ASSIGNMENT,
                    ASSIGNMENT, schemas, public)
                require(signed_second_lead["members"][1]["role"] == "lead",
                        "A-signed non-first cooperative lead fixture")
                detached = verify_existing_envelope(
                    source["private_b_authority_envelope_jcs"].encode(),
                    "agent-bot/soul-cooperative-bridge-assignment/v3",
                    "machine/v3/soul-cooperative-bridge-signed-assignment.schema.json",
                    "machine/v3/soul-cooperative-bridge-assignment-payload.schema.json", schemas, public)
                signed_observed = verify_existing_envelope(
                    evidence["envelope_jcs"].encode(), "agent-bot/soul-cooperative-b-observed/v3",
                    "machine/v3/soul-cooperative-b-signed-observed.schema.json",
                    "machine/v3/soul-cooperative-b-observed-payload.schema.json", schemas, public)
                cooperative_lead_launch(signed_second_lead, detached, signed_observed)
                wrong_launch = copy.deepcopy(signed_observed)
                wrong_launch["launch_id"] = signed_second_lead["members"][0]["launch_id"]
                wrong_raw = resign_payload_envelope(evidence["envelope_jcs"], wrong_launch)
                signed_wrong_launch = verify_existing_envelope(
                    wrong_raw, "agent-bot/soul-cooperative-b-observed/v3",
                    "machine/v3/soul-cooperative-b-signed-observed.schema.json",
                    "machine/v3/soul-cooperative-b-observed-payload.schema.json", schemas, public)
                try:
                    cooperative_lead_launch(signed_second_lead, detached, signed_wrong_launch)
                except ValueError as error:
                    require(str(error) == "cooperative B observation names the unique signed lead launch",
                            "re-signed non-first-lead wrong launch refused at the intended join")
                else:
                    raise ValueError("re-signed non-first-lead wrong launch accepted")
                signed_mutants = (
                    ("wrong detached B assignment", "bridge_assignment_sha256", "sha256:" + "0" * 64,
                     None, None, "exact A-observed B and relay identity join cooperative Ready"),
                    ("wrong plan", "plan_id", "plan_wrong", None, None,
                     "exact A-observed B and relay identity join cooperative Ready"),
                    ("wrong launch", "launch_id", "ln_ffffffffffffffffffffffff", None, None,
                     "cooperative B observation names the unique signed lead launch"),
                    ("wrong epoch", "hq_epoch", "f" * 64, None, None,
                     "exact A-observed B and relay identity join cooperative Ready"),
                    ("stale observation", "observed_at", "2026-11-22T14:15:22Z", None, None,
                     "cooperative B observation precedes Ready and bounds its expiry"),
                    ("early observation expiry", "expires_at", "2026-11-22T14:15:20Z", None, None,
                     "cooperative B observation precedes Ready and bounds its expiry"),
                    ("wrong B arm selector", None, None, "member_selector", "mb_" + "f" * 64,
                     "separate exact B arm JCS rows join A-signed Ready per member"),
                )
                for label, observed_field, observed_value, arm_field, arm_value, reason in signed_mutants:
                    changed_evidence, changed = resign_cooperative_mutant(
                        evidence, results, observed_field, observed_value, arm_field, arm_value)
                    try:
                        check(changed, source, schemas, public, changed_evidence)
                    except ValueError as error:
                        require(str(error) == reason, label + " refused for the intended signed join")
                    else:
                        raise ValueError("re-signed cooperative " + label + " accepted")
                changed = copy.deepcopy(results)
                changed[0]["bridge_arm_rows_base64url"][0] = changed[0]["bridge_arm_rows_base64url"][1]
                try:
                    check(changed, source, schemas, public, evidence)
                except ValueError:
                    pass
                else:
                    raise ValueError("cross-member B arm row accepted")
                changed = copy.deepcopy(results)
                del changed[0]["bridge_observed_envelope_base64url"]
                try:
                    check(changed, source, schemas, public, evidence)
                except ValueError:
                    pass
                else:
                    raise ValueError("missing A-signed B observation accepted")
                boundary = copy.deepcopy(results)
                paths = ((boundary[0], "cwd"),
                         (boundary[0]["runner_endpoint"], "directory"),
                         (boundary[0]["runner_endpoint"], "socketPath"))
                for parent, key in paths:
                    need = 32768 - len(canonicalize(boundary[0]))
                    parent[key] += "x" * min(need, 4096 - len(parent[key]))
                require(len(canonicalize(boundary[0])) == 32768 and
                        schemas[SCHEMA].is_valid(boundary[0]),
                        "schema-valid cooperative attach result exactly 32768 JCS bytes")
                check(boundary, source, schemas, public, evidence)
                for parent, key in paths:
                    if len(parent[key]) < 4096:
                        parent[key] += "x"
                        break
                require(len(canonicalize(boundary[0])) == 32769 and
                        schemas[SCHEMA].is_valid(boundary[0]),
                        "schema-valid cooperative attach result exactly 32769 JCS bytes")
                try:
                    check(boundary, source, schemas, public, evidence)
                except ValueError:
                    pass
                else:
                    raise ValueError("32769-byte cooperative result accepted")
            else:
                changed_source = copy.deepcopy(source)
                changed = copy.deepcopy(results)
                ready_payload = parse_strict(changed_source["ready_payload_jcs"].encode())
                ready_payload["members"][0]["runtime_id"] = "runtime_wrong"
                payload_raw = canonicalize(ready_payload)
                envelope = parse_strict(changed_source["ready_envelope_jcs"].encode())
                envelope["payload_base64url"] = base64.urlsafe_b64encode(payload_raw).rstrip(b"=").decode()
                envelope["payload_sha256"] = digest(payload_raw)
                signer = Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33)))
                envelope["signature_base64url"] = base64.urlsafe_b64encode(
                    signer.sign(envelope["purpose"].encode() + b"\0" + payload_raw)).rstrip(b"=").decode()
                envelope_raw = canonicalize(envelope)
                changed_source["ready_payload_jcs"] = payload_raw.decode()
                changed_source["ready_envelope_jcs"] = envelope_raw.decode()
                for result in changed:
                    result["ready_envelope_base64url"] = base64.urlsafe_b64encode(envelope_raw).rstrip(b"=").decode()
                    result["ready_envelope_sha256"] = digest(envelope_raw)
                try:
                    check(changed, changed_source, schemas, public)
                except ValueError as error:
                    if "protected Ready runtime" not in str(error):
                        raise ValueError("Ready/runtime mismatch refused for a different reason") from error
                else:
                    raise ValueError("A-signed protected Ready/runtime mismatch accepted")
            report(True, f"{profile} H-to-R prestarted attach exact A child/B-policy/Ready joins")
        except Exception as error:
            report(False, f"{profile} H-to-R prestarted attach exact A child/B-policy/Ready joins", str(error))
