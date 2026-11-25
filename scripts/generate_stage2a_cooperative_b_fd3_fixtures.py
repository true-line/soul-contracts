#!/usr/bin/env python3
"""Generate the exact cooperative B pre-bind FD3 fixture pair."""

import base64
import copy
import hashlib
import json
from pathlib import Path

from jcs import canonicalize

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = "machine/v3/stage2a-cooperative-b-fd3.schema.json"
NAME = "stage2a-cooperative-b-fd3.two-member-synthetic.json"


def digest(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def b64(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def write(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def main():
    source = json.loads((ROOT / "fixtures/reservation/v3/stage2a-member-set.synthetic.json").read_text())[
        "managed-cooperative"]
    frame = {
        "version": "agent-bot-comms/cooperative-b-start/v3",
        "machine_pin_path": "/Library/Application Support/ai.true-line.agent-bot-hq/soul-authority.pub",
        "reservation_envelope_base64url": b64(source["primary_reservation_envelope_jcs"].encode()),
        "bridge_assignment_envelope_base64url": b64(source["private_b_authority_envelope_jcs"].encode()),
    }
    positive = ROOT / "fixtures/positive" / NAME
    write(positive, {"schema": SCHEMA, "input": frame, "expect": {"schema": "valid"},
                     "canonical_sha256": digest(canonicalize(frame))})
    invalid = copy.deepcopy(frame)
    invalid["member_b_authority_envelope_base64url"] = b64(
        source["member_b_authority_envelope_jcs"].encode())
    write(ROOT / "fixtures/negative" / NAME,
          {"schema": SCHEMA, "input": invalid, "expect": {"schema": "invalid"},
           "base": {"fixture": "positive/" + NAME, "sha256": digest(positive.read_bytes())}})
    (ROOT / "fixtures/reservation/v3/stage2a-cooperative-b-fd3.synthetic.json").write_text(
        json.dumps({"fd3": frame, "fd3_jcs_sha256": digest(canonicalize(frame))}, indent=2,
                   sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
