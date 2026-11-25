#!/usr/bin/env python3
"""Generate deterministic cooperative B/H bind and same-stream policy vectors."""

import base64
import copy
import hashlib
import hmac
import json
from pathlib import Path

from jcs import canonicalize

ROOT = Path(__file__).resolve().parents[1]
CONTEXT = "agent-bot-stage2a-cooperative-bridge-bind-v3"
BIND_SCHEMA = "hq/v1/stage2a-cooperative-bridge-bind-exchange.schema.json"
POLICY_SCHEMA = "hq/v1/stage2a-cooperative-member-policy-exchange.schema.json"


def b64(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def decode(value):
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def sha(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def write(path, value):
    target = ROOT / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def fixture(name, schema, value, valid=True):
    positive = ROOT / "fixtures/positive" / name
    record = {"schema": schema, "input": value,
              "expect": {"schema": "valid" if valid else "invalid"}}
    if valid:
        record["canonical_sha256"] = sha(canonicalize(value))
    else:
        record["base"] = {"fixture": "positive/" + name, "sha256": sha(positive.read_bytes())}
    write("fixtures/" + ("positive/" if valid else "negative/") + name, record)


def main():
    source = json.loads((ROOT / "fixtures/reservation/v3/stage2a-member-set.synthetic.json").read_text())[
        "managed-cooperative"]
    primary_raw = source["primary_reservation_envelope_jcs"].encode()
    detached_raw = source["private_b_authority_envelope_jcs"].encode()
    primary = json.loads(decode(json.loads(primary_raw)["payload_base64url"]))
    detached = json.loads(decode(json.loads(detached_raw)["payload_base64url"]))
    assigned = primary["assignment"]
    challenge = {"nonce": "a" * 64, "algorithm": "hmac-sha256", "context": CONTEXT,
                 "hq_epoch": assigned["hq_epoch"], "expires_at": primary["expires_at"]}
    request = {"nonce": challenge["nonce"], "hq_epoch": assigned["hq_epoch"],
               "installation_id": assigned["installation_id"], "start_id": assigned["start_id"],
               "launch_id": assigned["launch_id"], "plan_id": assigned["plan_id"],
               "plan_digest": assigned["plan_digest"], "reservation_sha256": sha(primary_raw),
               "bridge_assignment_envelope_sha256": sha(detached_raw),
               "bridge_uid": detached["bridge"]["uid"],
               "broker_socket_path": detached["endpoints"]["broker"]["socket_path"]}
    fields = [CONTEXT, request["nonce"], request["hq_epoch"], request["installation_id"],
              request["start_id"], request["launch_id"], request["plan_id"], request["plan_digest"],
              request["reservation_sha256"], request["bridge_assignment_envelope_sha256"],
              str(request["bridge_uid"]), request["broker_socket_path"]]
    preimage = "\0".join(fields).encode("utf-8")
    key = bytes(range(32))
    request["proof_hex"] = hmac.new(key, preimage, hashlib.sha256).hexdigest()
    policy_request = {"reservation_sha256": sha(primary_raw),
                      "bridge_assignment_envelope_sha256": sha(detached_raw)}
    assignment_raw = source["assignment_envelope_jcs"].encode()
    authority_raw = source["member_b_authority_envelope_jcs"].encode()
    policy_result = {
        "member_set_assignment_envelope_base64url": b64(assignment_raw),
        "member_set_assignment_envelope_sha256": sha(assignment_raw),
        "member_b_authority_envelope_base64url": b64(authority_raw),
        "member_b_authority_envelope_sha256": sha(authority_raw),
    }
    write("fixtures/reservation/v3/stage2a-cooperative-bridge-bind.synthetic.json",
          {"key_base64url": b64(key), "preimage_base64url": b64(preimage),
           "challenge_result": challenge, "proof_request": request,
           "policy_request": policy_request, "policy_result": policy_result})
    bind_name = "stage2a-cooperative-bridge-bind-exchange.two-member-synthetic.json"
    fixture(bind_name, BIND_SCHEMA, request)
    bad = copy.deepcopy(request)
    bad["proof_hex"] = bad["proof_hex"].upper()
    fixture(bind_name, BIND_SCHEMA, bad, False)
    policy_name = "stage2a-cooperative-member-policy-exchange.two-member-synthetic.json"
    fixture(policy_name, POLICY_SCHEMA, policy_result)
    bad = copy.deepcopy(policy_result)
    bad["policy_rows"] = []
    fixture(policy_name, POLICY_SCHEMA, bad, False)


if __name__ == "__main__":
    main()
