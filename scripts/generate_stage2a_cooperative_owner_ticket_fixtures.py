#!/usr/bin/env python3
"""Generate closed synthetic H/R cooperative first reply and delayed ticket shapes."""

import base64
import copy
import json
from pathlib import Path

from jcs import canonicalize
from stage2a_member_set_fixtures import digest

ROOT = Path(__file__).resolve().parents[1]


def write(name, schema, value, valid=True):
    path = ROOT / "fixtures" / ("positive" if valid else "negative") / name
    positive = ROOT / "fixtures/positive" / name
    path.write_text(json.dumps({"schema": schema, "input": value,
                                "expect": {"schema": "valid" if valid else "invalid"},
                                **({"canonical_sha256": digest(canonicalize(value))} if valid else
                                   {"base": {"fixture": "positive/" + name,
                                             "sha256": digest(positive.read_bytes())}})},
                               indent=2, sort_keys=True) + "\n")


def main():
    source = json.loads((ROOT / "fixtures/reservation/v3/stage2a-member-set.synthetic.json").read_text())[
        "managed-cooperative"]
    assignment = json.loads(source["assignment_payload_jcs"])
    primary = json.loads(base64.urlsafe_b64decode(
        json.loads(source["primary_reservation_envelope_jcs"])["payload_base64url"] + "=="))
    first = {
        "schema": "hq/cooperative-member-set-attach/v3",
        "reservation_sha256": digest(source["primary_reservation_envelope_jcs"].encode()),
        "start_id": assignment["start_id"], "launch_id": primary["assignment"]["launch_id"],
        "broker_socket_path": assignment["bridge"]["endpoints"]["broker"]["socket_path"],
        "member_set_assignment_envelope_sha256": digest(source["assignment_envelope_jcs"].encode()),
        "member_b_authority_envelope_sha256": digest(source["member_b_authority_envelope_jcs"].encode()),
    }
    first_schema = "hq/v1/cooperative-member-set-attach.schema.json"
    write("cooperative-member-set-attach.two-member-synthetic.json", first_schema, first)
    bad = copy.deepcopy(first)
    bad["acp_ticket_base64url"] = base64.urlsafe_b64encode(bytes(32)).rstrip(b"=").decode()
    write("cooperative-member-set-attach.two-member-synthetic.json", first_schema, bad, False)

    ticket = {
        "schema": "hq/cooperative-owner-acp-ticket/v3",
        "reservation_sha256": first["reservation_sha256"],
        "start_id": first["start_id"], "launch_id": first["launch_id"],
        "ready_envelope_sha256": digest(source["ready_envelope_jcs"].encode()),
        "acp_ticket_base64url": base64.urlsafe_b64encode(bytes(range(32))).rstrip(b"=").decode(),
    }
    ticket_schema = "hq/v1/cooperative-owner-acp-ticket.schema.json"
    write("cooperative-owner-acp-ticket.two-member-synthetic.json", ticket_schema, ticket)
    bad = copy.deepcopy(ticket)
    bad["acp_ticket_base64url"] = bad["acp_ticket_base64url"] + "="
    write("cooperative-owner-acp-ticket.two-member-synthetic.json", ticket_schema, bad, False)


if __name__ == "__main__":
    main()
