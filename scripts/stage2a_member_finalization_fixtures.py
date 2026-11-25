"""Independent exact-byte joins for synthetic H commit and A acknowledgement."""

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

RECORD = "hq/v1/stage2a-member-finalization.schema.json"
REQUEST = "machine/v3/stage2a-member-finalization-request.schema.json"
ACK_PAYLOAD = "machine/v3/stage2a-member-finalization-ack-payload.schema.json"
ACK_ENVELOPE = "machine/v3/stage2a-member-finalization-signed-ack.schema.json"
ACK_PURPOSE = "agent-bot/stage2a-member-finalization-ack/v1"
RUNTIME_REQUEST = "machine/v3/stage2a-member-runtime-request.schema.json"
LEASE_PURPOSE = "agent-bot/stage2a-member-runtime-lease/v1"
LEASE_ENVELOPE = "machine/v3/stage2a-member-signed-runtime-lease.schema.json"
LEASE_PAYLOAD = "machine/v3/stage2a-member-runtime-lease-payload.schema.json"
INERT_PURPOSE = "agent-bot/stage2a-member-live-lease/v1"
INERT_ENVELOPE = "machine/v3/stage2a-member-signed-live-lease.schema.json"
INERT_PAYLOAD = "machine/v3/stage2a-member-live-lease-payload.schema.json"


def when(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def check(source, vector, schemas, public, prior_lease_raw=None, used_nonces=(), inert_lease_raw=None):
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
    matching = [row for row in record["members"] if row["member_id"] == runtime["member_id"]]
    require(len(matching) == 1, "renewal names exactly one signed H member row")
    member = matching[0]
    require(canonicalize(runtime) == runtime_raw and schemas[RUNTIME_REQUEST].is_valid(runtime) and
            len(runtime_raw) <= 16384 and
            decode(runtime["hq_finalization_base64url"]) == record_raw and
            runtime["hq_finalization_sha256"] == ack["hq_finalization_sha256"] and
            runtime["ready_envelope_sha256"] == digest(ready_raw) and
            runtime["child_observation_envelope_sha256"] == digest(child_raw) and
            all(runtime[k] == request[k] for k in
                ("reservation_sha256", "installation_id", "start_id", "launch_id",
                 "plan_id", "plan_digest", "hq_epoch")) and
            all(runtime[k] == member[k] for k in
                ("member_id", "member_selector", "member_launch_id", "grant_sha256")) and
            runtime["launcher_pid"] == runtime["peer_pid"] == member["launcher_process"]["pid"] and
            runtime["child_pid"] == member["child_process"]["pid"] and
            runtime["peer_uid"] == assignment["runner_uid"],
            "renewal carries exact reopened H bytes and peer-bound member selectors")
    nonce = decode(runtime["challenge_nonce_base64url"])
    require(len(nonce) == 32 and nonce not in used_nonces,
            "runtime request has a fresh canonical 32-byte challenge")
    if prior_lease_raw is None:
        require(inert_lease_raw is not None, "first request requires A's signed inert member lease")
        inert = verify_existing_envelope(inert_lease_raw, INERT_PURPOSE,
            INERT_ENVELOPE, INERT_PAYLOAD, schemas, public)
        require(runtime["after_sequence"] == 0 and
                runtime["previous_lease_envelope_sha256"] is None and
                inert["member_id"] == runtime["member_id"] and
                all(inert[key] == runtime[key] for key in
                    ("member_selector", "member_launch_id", "grant_sha256",
                     "child_observation_envelope_sha256", "installation_id", "start_id",
                     "hq_epoch", "reservation_sha256")) and
                inert["assignment_envelope_sha256"] == digest(assignment_raw) and
                inert["launcher_process"] == member["launcher_process"] and
                inert["child_process"] == member["child_process"] and
                inert["launcher_process"]["pid"] == runtime["launcher_pid"] == runtime["peer_pid"] and
                inert["child_process"]["pid"] == runtime["child_pid"] and
                inert["launcher_process"]["uid"] == runtime["peer_uid"] and
                when(inert["issued_at"]) <= when(record["committed_at"]) <=
                    when(ack["issued_at"]) < when(inert["expires_at"]) <= when(ready["expires_at"]) and
                when(runtime["prior_expires_at"]) == when(inert["expires_at"]),
                "first request uses A-signed live inert lease; H expiry cannot extend it")
    else:
        prior = verify_existing_envelope(prior_lease_raw, LEASE_PURPOSE,
            LEASE_ENVELOPE, LEASE_PAYLOAD, schemas, public)
        require(prior["member_id"] == runtime["member_id"] and
                all(prior[key] == runtime[key] for key in
                    ("member_selector", "member_launch_id", "grant_sha256",
                     "ready_envelope_sha256", "child_observation_envelope_sha256",
                     "installation_id", "start_id", "hq_epoch", "reservation_sha256")) and
                prior["hq_finalization_sha256"] == runtime["hq_finalization_sha256"] and
                prior["launcher_process"]["pid"] == runtime["launcher_pid"] == runtime["peer_pid"] and
                prior["child_process"]["pid"] == runtime["child_pid"],
                "renewal follows the same signed member lease and H finalization")
        require(runtime["after_sequence"] == prior["sequence"] and
                runtime["previous_lease_envelope_sha256"] == digest(prior_lease_raw) and
                when(runtime["prior_expires_at"]) == when(prior["expires_at"]) and
                when(ack["issued_at"]) <= when(prior["issued_at"]) < when(prior["expires_at"]) and
                (prior["sequence"] != 1 or when(prior["issued_at"]) < when(ready["expires_at"])),
                "renewal names exact prior signed sequence, digest and expiry")
        require(nonce != decode(prior["challenge_nonce_base64url"]),
                "renewal challenge does not replay the prior signed lease nonce")


def resign_payload_envelope(raw, payload):
    envelope = parse_strict(raw.encode())
    payload_raw = canonicalize(payload)
    envelope["payload_base64url"] = base64.urlsafe_b64encode(payload_raw).rstrip(b"=").decode()
    envelope["payload_sha256"] = digest(payload_raw)
    key = Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33)))
    envelope["signature_base64url"] = base64.urlsafe_b64encode(
        key.sign(envelope["purpose"].encode() + b"\0" + payload_raw)).rstrip(b"=").decode()
    return canonicalize(envelope)


def check_stage2a_member_finalization_fixtures(root, schemas, report):
    public = Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33))).public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    source = parse_strict((root / "fixtures/reservation/v3/stage2a-member-set.synthetic.json").read_bytes())[
        "managed-protected"]
    vector = parse_strict((root / "fixtures/reservation/v3/stage2a-member-finalization.two-member-synthetic.json").read_bytes())
    inert_vectors = parse_strict((root / "fixtures/reservation/v3/"
        "stage2a-member-live-lease.two-member-synthetic.json").read_bytes())["members"]
    inert_by_member = {parse_strict(item["payload_jcs"].encode())["member_id"]:
                       item["envelope_jcs"].encode() for item in inert_vectors}

    def verify(candidate, prior_lease_raw=None, used_nonces=(), inert_override=None):
        requested = parse_strict(candidate["runtime_request_jcs"].encode())
        inert = (inert_by_member[requested["member_id"]] if inert_override is None
                 else inert_override)
        check(source, candidate, schemas, public, prior_lease_raw, used_nonces, inert)

    try:
        verify(vector)
        second = copy.deepcopy(vector)
        record = parse_strict(second["record_jcs"].encode())
        selected = record["members"][1]
        runtime = parse_strict(second["runtime_request_jcs"].encode())
        for key in ("member_id", "member_selector", "member_launch_id", "grant_sha256"):
            runtime[key] = selected[key]
        runtime["launcher_pid"] = runtime["peer_pid"] = selected["launcher_process"]["pid"]
        runtime["child_pid"] = selected["child_process"]["pid"]
        second["runtime_request_jcs"] = canonicalize(runtime).decode()
        verify(second)
        for label, claimed_expiry in (("shortened inert expiry", "2026-11-22T14:15:23Z"),
                                      ("extended inert expiry", "2026-11-22T14:15:25Z")):
            wrong = copy.deepcopy(vector)
            claimed = parse_strict(wrong["runtime_request_jcs"].encode())
            claimed["prior_expires_at"] = claimed_expiry
            wrong["runtime_request_jcs"] = canonicalize(claimed).decode()
            try:
                verify(wrong)
            except ValueError as error:
                require(str(error) == "first request uses A-signed live inert lease; H expiry cannot extend it",
                        label + " refused at exact A-derived expiry")
            else:
                raise ValueError(label + " accepted")
        try:
            verify(vector, inert_override=inert_by_member[record["members"][1]["member_id"]])
        except ValueError as error:
            require(str(error) == "first request uses A-signed live inert lease; H expiry cannot extend it",
                    "cross-member signed inert lease refused at first-request join")
        else:
            raise ValueError("cross-member signed inert lease accepted")
        stale_inert = parse_strict(inert_vectors[0]["payload_jcs"].encode())
        stale_inert["expires_at"] = "2026-11-22T14:15:22.050Z"
        stale_raw = resign_payload_envelope(inert_vectors[0]["envelope_jcs"], stale_inert)
        try:
            verify(vector, inert_override=stale_raw)
        except ValueError as error:
            require(str(error) == "first request uses A-signed live inert lease; H expiry cannot extend it",
                    "stale A-signed inert lease refused before first runtime request")
        else:
            raise ValueError("stale A-signed inert lease accepted")
        for label, process, field, value in (
                ("same-PID different-start launcher", "launcher_process", "start_seconds", 1795356919),
                ("different launcher UID", "launcher_process", "uid", 332),
                ("different child GID", "child_process", "gid", 332)):
            wrong_inert = parse_strict(inert_vectors[0]["payload_jcs"].encode())
            wrong_inert[process][field] = value
            wrong_raw = resign_payload_envelope(inert_vectors[0]["envelope_jcs"], wrong_inert)
            try:
                verify(vector, inert_override=wrong_raw)
            except ValueError as error:
                require(str(error) == "first request uses A-signed live inert lease; H expiry cannot extend it",
                        label + " refused at full signed process tuple")
            else:
                raise ValueError("re-signed " + label + " inert lease accepted")
        for label, field, value in (
                ("selector", "member_selector", record["members"][0]["member_selector"]),
                ("launcher PID", "launcher_pid", record["members"][0]["launcher_process"]["pid"]),
                ("peer PID", "peer_pid", record["members"][0]["launcher_process"]["pid"]),
                ("child PID", "child_pid", record["members"][0]["child_process"]["pid"])):
            wrong = copy.deepcopy(second)
            mutated = parse_strict(wrong["runtime_request_jcs"].encode())
            mutated[field] = value
            wrong["runtime_request_jcs"] = canonicalize(mutated).decode()
            try:
                verify(wrong)
            except ValueError as error:
                require(str(error) == "renewal carries exact reopened H bytes and peer-bound member selectors",
                        "cross-member " + label + " refused for intended signed row join")
            else:
                raise ValueError("cross-member " + label + " accepted for second member")
        lease_fixture = parse_strict((root / "fixtures/reservation/v3/"
            "stage2a-member-runtime-lease.protected-synthetic.json").read_bytes())
        first_lease = lease_fixture["members"][0]
        prior_payload = parse_strict(first_lease["payload_jcs"].encode())
        prior_payload["hq_finalization_sha256"] = digest(vector["record_jcs"].encode())
        prior_payload["issued_at"] = "2026-11-22T14:15:22.200Z"
        prior_raw = resign_payload_envelope(first_lease["envelope_jcs"], prior_payload)
        verify_existing_envelope(prior_raw, LEASE_PURPOSE, LEASE_ENVELOPE, LEASE_PAYLOAD,
                                 schemas, public)
        renewed = copy.deepcopy(vector)
        request = parse_strict(renewed["runtime_request_jcs"].encode())
        request["after_sequence"] = prior_payload["sequence"]
        request["previous_lease_envelope_sha256"] = digest(prior_raw)
        request["prior_expires_at"] = prior_payload["expires_at"]
        request["challenge_nonce_base64url"] = base64.urlsafe_b64encode(
            bytes(range(32, 64))).rstrip(b"=").decode()
        renewed["runtime_request_jcs"] = canonicalize(request).decode()
        verify(renewed, prior_raw)
        for label, field, value, expected in (
                ("replayed sequence", "after_sequence", 2,
                 "renewal names exact prior signed sequence, digest and expiry"),
                ("wrong prior digest", "previous_lease_envelope_sha256", "sha256:" + "0" * 64,
                 "renewal names exact prior signed sequence, digest and expiry"),
                ("wrong prior expiry", "prior_expires_at", "2026-11-22T14:15:25Z",
                 "renewal names exact prior signed sequence, digest and expiry"),
                ("replayed prior nonce", "challenge_nonce_base64url",
                 prior_payload["challenge_nonce_base64url"],
                 "renewal challenge does not replay the prior signed lease nonce")):
            wrong = copy.deepcopy(renewed)
            mutated = parse_strict(wrong["runtime_request_jcs"].encode())
            mutated[field] = value
            wrong["runtime_request_jcs"] = canonicalize(mutated).decode()
            try:
                verify(wrong, prior_raw)
            except ValueError as error:
                require(str(error) == expected, label + " refused at intended prior-lease join")
            else:
                raise ValueError(label + " accepted")
        try:
            verify(renewed, prior_raw,
                  {decode(request["challenge_nonce_base64url"])})
        except ValueError as error:
            require(str(error) == "runtime request has a fresh canonical 32-byte challenge",
                    "replayed request nonce refused at freshness join")
        else:
            raise ValueError("replayed request nonce accepted")
        other = parse_strict(lease_fixture["members"][-1]["payload_jcs"].encode())
        other["hq_finalization_sha256"] = digest(vector["record_jcs"].encode())
        other["issued_at"] = "2026-11-22T14:15:22.200Z"
        other_raw = resign_payload_envelope(lease_fixture["members"][-1]["envelope_jcs"], other)
        try:
            verify(renewed, other_raw)
        except ValueError as error:
            require(str(error) == "renewal follows the same signed member lease and H finalization",
                    "cross-member prior lease refused at member join")
        else:
            raise ValueError("cross-member prior lease accepted")
        late = copy.deepcopy(vector)
        late_ack = parse_strict(late["ack_payload_jcs"].encode())
        late_ack["issued_at"] = "2026-11-22T14:15:37Z"
        late["ack_payload_jcs"] = canonicalize(late_ack).decode()
        late["ack_envelope_jcs"] = resign_payload_envelope(late["ack_envelope_jcs"], late_ack).decode()
        try:
            verify(late)
        except ValueError as error:
            require(str(error) == "first request uses A-signed live inert lease; H expiry cannot extend it",
                    "late A acknowledgement cannot feed first lease")
        else:
            raise ValueError("late A acknowledgement accepted for first lease")
        changed = copy.deepcopy(vector)
        record = parse_strict(changed["record_jcs"].encode())
        record["members"][0]["runtime_id"] = record["members"][1]["runtime_id"]
        changed["record_jcs"] = canonicalize(record).decode()
        try:
            verify(changed)
        except ValueError:
            pass
        else:
            raise ValueError("cross-member durable H map accepted")
        changed = copy.deepcopy(vector)
        record = parse_strict(changed["record_jcs"].encode())
        record["launch_id"] = record["members"][1]["member_launch_id"]
        changed["record_jcs"] = canonicalize(record).decode()
        try:
            verify(changed)
        except ValueError:
            pass
        else:
            raise ValueError("wrong primary reservation launch accepted")
        changed = copy.deepcopy(vector)
        record = parse_strict(changed["record_jcs"].encode())
        record["committed_at"] = "2026-11-22T14:15:37.000Z"
        changed["record_jcs"] = canonicalize(record).decode()
        try:
            verify(changed)
        except ValueError:
            pass
        else:
            raise ValueError("H commit after Ready expiry accepted")
        changed = copy.deepcopy(vector)
        request = parse_strict(changed["request_jcs"].encode())
        request["finalization_sha256"] = "sha256:" + "0" * 64
        changed["request_jcs"] = canonicalize(request).decode()
        try:
            verify(changed)
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
            verify(changed)
        except ValueError:
            pass
        else:
            raise ValueError("changed reopened H runtime bytes accepted")
        report(True, "protected H durable two-member commit and A-signed ack exact-byte joins")
    except Exception as error:
        report(False, "protected H durable two-member commit and A-signed ack exact-byte joins", str(error))
