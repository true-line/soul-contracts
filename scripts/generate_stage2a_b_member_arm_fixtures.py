#!/usr/bin/env python3
"""Regenerate synthetic same-bound-broker B observe/arm frames."""

import copy
import hashlib
import json
from pathlib import Path

from jcs import canonicalize

from stage2a_member_set_fixtures import digest

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = "hq/v1/stage2a-b-member-arm-exchange.schema.json"
PREFIX = "stage2a-b-member-arm-exchange.two-member-synthetic"


def b64(raw):
    import base64
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def write(path, value):
    target = ROOT / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n")


def main():
    source = json.loads((ROOT / "fixtures/reservation/v3/stage2a-member-set.synthetic.json").read_text())[
        "managed-protected"]
    b = json.loads((ROOT / "fixtures/reservation/v3/stage2a-b-member-authority.two-member-synthetic.json").read_text())
    child_raw = source["child_observation_envelope_jcs"].encode("utf-8")
    child = json.loads(source["child_observation_payload_jcs"])
    ready = json.loads(source["ready_payload_jcs"])
    selectors = b["fd3"]["selectors"]
    rows = []
    for i, member in enumerate(ready["members"]):
        observe_nonce = hashlib.sha256(("fixture-observe-" + str(i)).encode()).hexdigest()
        arm_nonce = hashlib.sha256(("fixture-arm-" + str(i)).encode()).hexdigest()
        base = {"member_id": member["member_id"], "member_selector": member["member_selector"]}
        observe_request = dict(base, kind="bridge.member.observe.v3.request",
                               selectors=selectors, observe_nonce=observe_nonce)
        observe_result = dict(base, kind="bridge.member.observe.v3.result",
                              observe_nonce=observe_nonce,
                              child_observation_envelope_base64url=b64(child_raw),
                              child_observation_envelope_sha256=digest(child_raw),
                              expires_at=child["expires_at"])
        arm_request = dict(base, kind="bridge.member.arm.v3.request", selectors=selectors,
                           observe_nonce=observe_nonce, arm_nonce=arm_nonce,
                           child_observation_envelope_sha256=digest(child_raw),
                           bridge_arm=member["bridge_arm"],
                           bridge_arm_receipt_sha256=digest(canonicalize(member["bridge_arm"])))
        arm_result = dict(base, kind="bridge.member.arm.v3.result", arm_nonce=arm_nonce,
                          bridge_arm_receipt_sha256=arm_request["bridge_arm_receipt_sha256"],
                          state="recorded-pending-aggregate-ready", expires_at=child["expires_at"])
        rows.append({"observe_request": observe_request, "observe_result": observe_result,
                     "arm_request": arm_request, "arm_result": arm_result})
    vector_path = "fixtures/reservation/v3/" + PREFIX + ".json"
    write(vector_path, {"members": rows, "aggregate_ready_envelope_jcs_after_both_arms":
                        source["ready_envelope_jcs"],
                        "refusal": {"error": "control_binding_mismatch",
                                    "explanation": "member arm binding refused",
                                    "correlation_id": "fixture-arm-1"}})
    positive_path = "fixtures/positive/" + PREFIX + ".json"
    write(positive_path, {"schema": SCHEMA, "input": rows[0]["observe_request"],
                          "expect": {"schema": "valid"},
                          "canonical_sha256": digest(canonicalize(rows[0]["observe_request"]))})
    bad = copy.deepcopy(rows[0]["arm_request"])
    bad["kind"] = "bridge.member.arm.v2.request"
    write("fixtures/negative/" + PREFIX + ".json", {
        "schema": SCHEMA, "input": bad, "expect": {"schema": "invalid"},
        "base": {"fixture": positive_path.removeprefix("fixtures/"),
                 "sha256": digest((ROOT / positive_path).read_bytes())}})


if __name__ == "__main__":
    main()
