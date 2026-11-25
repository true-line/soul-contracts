"""Independent exact-byte oracle for same-bound-broker B observe/arm frames."""

import copy
from datetime import datetime

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from jcs import canonicalize, parse_strict

from stage2a_member_set_fixtures import (
    CHILD, READY, SIGNED_CHILD, SIGNED_READY, decode, digest, require, signed,
)

SCHEMA = "hq/v1/stage2a-b-member-arm-exchange.schema.json"


def when(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def check(vector, source, b, schemas, public):
    child, child_raw = signed(source, "child_observation", SIGNED_CHILD, CHILD, schemas, public)
    ready, ready_raw = signed(source, "ready", SIGNED_READY, READY, schemas, public)
    authority_raw = b["authority_envelope_jcs"].encode("utf-8")
    selectors = b["fd3"]["selectors"]
    require(ready["member_b_authority_envelope_sha256"] == digest(authority_raw) and
            ready["child_observation_envelope_sha256"] == digest(child_raw) and
            when(child["issued_at"]) < when(ready["issued_at"]),
            "aggregate Ready binds distinct B policy and follows A child observation")
    rows = vector["members"]
    require(schemas["common/v1/error-response.schema.json"].is_valid(vector["refusal"]) and
            vector["refusal"]["error"] == "control_binding_mismatch",
            "same-RPC typed refusal carries no authority")
    require(len(rows) == 2 and len({r["observe_request"]["observe_nonce"] for r in rows}) == 2 and
            len({r["arm_request"]["arm_nonce"] for r in rows}) == 2,
            "exact two distinct one-use member exchanges")
    for i, row in enumerate(rows):
        observe = row["observe_request"]
        result = row["observe_result"]
        arm = row["arm_request"]
        ack = row["arm_result"]
        require(all(schemas[SCHEMA].is_valid(frame) for frame in row.values()),
                "each four-phase broker payload matches exact schema")
        member = ready["members"][i]
        observed = child["members"][i]
        require(observe["selectors"] == arm["selectors"] == selectors and
                all(frame["member_id"] == member["member_id"] and
                    frame["member_selector"] == member["member_selector"] for frame in row.values()) and
                observed["member_id"] == member["member_id"] and
                observed["member_selector"] == member["member_selector"],
                "same bound B v3 selectors, assigned member and A-observed child")
        require(observe["observe_nonce"] == result["observe_nonce"] == arm["observe_nonce"] and
                arm["arm_nonce"] == ack["arm_nonce"] and
                decode(result["child_observation_envelope_base64url"]) == child_raw and
                result["child_observation_envelope_sha256"] ==
                arm["child_observation_envelope_sha256"] == digest(child_raw) and
                result["expires_at"] == ack["expires_at"] == child["expires_at"],
                "fresh challenge echo and exact A-signed two-child envelope")
        require(arm["bridge_arm"] == member["bridge_arm"] and
                arm["bridge_arm_receipt_sha256"] == ack["bridge_arm_receipt_sha256"] ==
                member["bridge_arm_receipt_sha256"] == digest(canonicalize(arm["bridge_arm"])) and
                ack["state"] == "recorded-pending-aggregate-ready" and
                arm["bridge_arm"]["child_observation_envelope_sha256"] == digest(child_raw) and
                when(arm["bridge_arm"]["armed_at"]) < when(ready["issued_at"]),
                "B per-member receipt precedes aggregate Ready and never itself permits ingress")
    require(parse_strict(vector["aggregate_ready_envelope_jcs_after_both_arms"].encode("utf-8")) ==
            parse_strict(ready_raw), "only later A-signed aggregate Ready may finalize")


def check_stage2a_b_member_arm_fixtures(root, schemas, report):
    vector = parse_strict((root / "fixtures/reservation/v3/"
                           "stage2a-b-member-arm-exchange.two-member-synthetic.json").read_bytes())
    source = parse_strict((root / "fixtures/reservation/v3/stage2a-member-set.synthetic.json").read_bytes())[
        "managed-protected"]
    b = parse_strict((root / "fixtures/reservation/v3/"
                      "stage2a-b-member-authority.two-member-synthetic.json").read_bytes())
    public = Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33))).public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    try:
        check(vector, source, b, schemas, public)
        changed = copy.deepcopy(vector)
        changed["members"][0]["arm_request"]["bridge_arm_receipt_sha256"] = "sha256:" + "0" * 64
        try:
            check(changed, source, b, schemas, public)
        except ValueError:
            pass
        else:
            raise ValueError("tampered B arm receipt accepted")
        report(True, "B v3 same-bound observe/arm exchange and later aggregate Ready joins")
    except Exception as error:
        report(False, "B v3 same-bound observe/arm exchange and later aggregate Ready joins", str(error))
