"""Independent signed-envelope and exact-byte oracle for cooperative B FD3."""

import base64
import copy

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from jcs import canonicalize, parse_strict

from stage2a_member_set_fixtures import decode, digest, require, verify_existing_envelope

SCHEMA = "machine/v3/stage2a-cooperative-b-fd3.schema.json"
PIN = "/Library/Application Support/ai.true-line.agent-bot-hq/soul-authority.pub"


def check(frame, source, schemas, public):
    require(schemas[SCHEMA].is_valid(frame) and len(canonicalize(frame)) <= 32768,
            "closed cooperative B FD3 shape and 32 KiB JCS frame cap")
    require(frame["version"] == "agent-bot-comms/cooperative-b-start/v3" and
            frame["machine_pin_path"] == PIN, "fixed cooperative B FD3 version and A pin")
    primary_raw = decode(frame["reservation_envelope_base64url"])
    detached_raw = decode(frame["bridge_assignment_envelope_base64url"])
    require(primary_raw == source["primary_reservation_envelope_jcs"].encode() and
            detached_raw == source["private_b_authority_envelope_jcs"].encode(),
            "FD3 retains the exact signed primary and detached B assignment bytes")
    primary = verify_existing_envelope(
        primary_raw, "agent-bot/soul-cooperative-reservation/v3",
        "machine/v3/soul-cooperative-signed-reservation.schema.json",
        "machine/v3/soul-cooperative-reservation-payload.schema.json", schemas, public)
    detached = verify_existing_envelope(
        detached_raw, "agent-bot/soul-cooperative-bridge-assignment/v3",
        "machine/v3/soul-cooperative-bridge-signed-assignment.schema.json",
        "machine/v3/soul-cooperative-bridge-assignment-payload.schema.json", schemas, public)
    assigned = primary["assignment"]
    require(detached["reservation_sha256"] == digest(primary_raw) and
            all(detached[key] == assigned[key] for key in
                ("installation_id", "start_id", "launch_id", "plan_id", "plan_digest")) and
            detached["expires_at"] <= primary["expires_at"],
            "detached B assignment joins the exact primary and admission selectors")


def check_stage2a_cooperative_b_fd3_fixtures(root, schemas, report):
    vector = parse_strict((root / "fixtures/reservation/v3/stage2a-cooperative-b-fd3.synthetic.json").read_bytes())
    source = parse_strict((root / "fixtures/reservation/v3/stage2a-member-set.synthetic.json").read_bytes())[
        "managed-cooperative"]
    public = Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33))).public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    try:
        frame = vector["fd3"]
        require(digest(canonicalize(frame)) == vector["fd3_jcs_sha256"], "exact JCS frame hash")
        check(frame, source, schemas, public)
        altered = copy.deepcopy(frame)
        altered["bridge_assignment_envelope_base64url"] = base64.urlsafe_b64encode(
            source["member_b_authority_envelope_jcs"].encode()).rstrip(b"=").decode()
        try:
            check(altered, source, schemas, public)
        except ValueError:
            pass
        else:
            raise ValueError("later two-member B authority accepted in pre-bind FD3")
        altered = copy.deepcopy(frame)
        altered["reservation_envelope_base64url"] += "="
        try:
            check(altered, source, schemas, public)
        except ValueError:
            pass
        else:
            raise ValueError("noncanonical base64url accepted in FD3")
        report(True, "cooperative B FD3 exact A envelopes, digest join, frame cap and refusal")
    except Exception as error:
        report(False, "cooperative B FD3 exact A envelopes, digest join, frame cap and refusal", str(error))
