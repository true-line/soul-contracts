#!/usr/bin/env python3
"""Generate distinct cooperative same-bound B observe/arm and A Ready request vectors."""

import base64
import copy
import hashlib
import json
from pathlib import Path

from jcs import canonicalize
from stage2a_member_set_fixtures import digest

ROOT = Path(__file__).resolve().parents[1]
WIRE = "hq/v1/soul-cooperative-b-member-arm-exchange.schema.json"
READY_REQUEST = "machine/v3/soul-cooperative-member-ready-request.schema.json"


def b64(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def decode(value):
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def write(path, value):
    target = ROOT / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def fixture(schema, value, valid):
    name = schema.rsplit("/", 1)[-1].removesuffix(".schema.json") + ".two-member-synthetic.json"
    path = "fixtures/" + ("positive/" if valid else "negative/") + name
    record = {"schema": schema, "input": value,
              "expect": {"schema": "valid" if valid else "invalid"}}
    if valid:
        record["canonical_sha256"] = digest(canonicalize(value))
    else:
        base = ROOT / "fixtures/positive" / name
        record["base"] = {"fixture": "positive/" + name, "sha256": digest(base.read_bytes())}
    write(path, record)


def main():
    source = json.loads((ROOT / "fixtures/reservation/v3/stage2a-member-set.synthetic.json").read_text())[
        "managed-cooperative"]
    assignment = json.loads(source["assignment_payload_jcs"])
    primary = json.loads(decode(json.loads(source["primary_reservation_envelope_jcs"])["payload_base64url"]))
    child = json.loads(source["child_observation_payload_jcs"])
    old_ready = json.loads(source["ready_payload_jcs"])
    ready = json.loads(json.loads((ROOT / "fixtures/reservation/v3/"
                                  "soul-cooperative-member-ready.two-member-synthetic.json").read_text())["payload_jcs"])
    child_raw = source["child_observation_envelope_jcs"].encode()
    selectors = {
        "installation_id": assignment["installation_id"], "start_id": assignment["start_id"],
        "plan_id": assignment["plan_id"], "plan_digest": assignment["plan_digest"],
        "reservation_digest": assignment["reservation_sha256"],
        "assignment_envelope_sha256": digest(source["assignment_envelope_jcs"].encode()),
        "authority_envelope_sha256": digest(source["member_b_authority_envelope_jcs"].encode()),
        "member_selectors_sha256": digest(canonicalize([m["member_selector"] for m in assignment["members"]])),
    }
    rows = []
    for i, member in enumerate(old_ready["members"]):
        observe_nonce = hashlib.sha256(("cooperative-observe-" + str(i)).encode()).hexdigest()
        arm_nonce = hashlib.sha256(("cooperative-arm-" + str(i)).encode()).hexdigest()
        base = {"member_id": member["member_id"], "member_selector": member["member_selector"]}
        observe_request = dict(base, kind="bridge.member.observe.cooperative.v3.request",
                               selectors=selectors, observe_nonce=observe_nonce)
        observe_result = dict(base, kind="bridge.member.observe.cooperative.v3.result",
                              observe_nonce=observe_nonce,
                              child_observation_envelope_base64url=b64(child_raw),
                              child_observation_envelope_sha256=digest(child_raw),
                              expires_at=child["expires_at"])
        arm_request = dict(base, kind="bridge.member.arm.cooperative.v3.request",
                           selectors=selectors, observe_nonce=observe_nonce, arm_nonce=arm_nonce,
                           child_observation_envelope_sha256=digest(child_raw),
                           bridge_arm=member["bridge_arm"],
                           bridge_arm_receipt_sha256=digest(canonicalize(member["bridge_arm"])))
        arm_result = dict(base, kind="bridge.member.arm.cooperative.v3.result",
                          arm_nonce=arm_nonce,
                          bridge_arm_receipt_sha256=arm_request["bridge_arm_receipt_sha256"],
                          state="recorded-pending-aggregate-ready", expires_at=child["expires_at"])
        rows.append({"observe_request": observe_request, "observe_result": observe_result,
                     "arm_request": arm_request, "arm_result": arm_result})
    request = {k: primary["assignment"][k] for k in
               ("installation_id", "start_id", "launch_id", "plan_id", "plan_digest", "hq_epoch")}
    request.update({"reservation_sha256": digest(source["primary_reservation_envelope_jcs"].encode()),
                    "child_observation_envelope_sha256": digest(child_raw),
                    "member_b_authority_envelope_sha256": selectors["authority_envelope_sha256"],
                    "bridge_observed_sha256": ready["bridge_observed_sha256"],
                    "arms": [{"arm_request": row["arm_request"], "arm_result": row["arm_result"]}
                             for row in rows]})
    write("fixtures/reservation/v3/soul-cooperative-b-member-arm-exchange.two-member-synthetic.json",
          {"members": rows, "ready_request": request})
    fixture(WIRE, rows[0]["observe_request"], True)
    bad = copy.deepcopy(rows[0]["arm_request"])
    bad["kind"] = "bridge.member.arm.v3.request"
    fixture(WIRE, bad, False)
    fixture(READY_REQUEST, request, True)
    bad = copy.deepcopy(request)
    bad["arms"] = bad["arms"][:1]
    fixture(READY_REQUEST, bad, False)


if __name__ == "__main__":
    main()
