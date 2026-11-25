"""Independent signed-envelope and exact-byte oracle for cooperative B FD3."""

import base64
import copy

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from jcs import canonicalize, parse_strict

from stage2a_member_set_fixtures import decode, digest, require, verify_existing_envelope, when

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
                ("installation_id", "start_id", "launch_id", "plan_id", "plan_digest")),
            "detached B assignment joins the exact primary and admission selectors")
    require(when(detached["expires_at"]) <= when(primary["expires_at"]),
            "detached B assignment expires no later than the primary reservation")


def signed_detached_with_expiry(source, expires_at):
    altered = copy.deepcopy(source)
    envelope = parse_strict(source["private_b_authority_envelope_jcs"].encode())
    payload = parse_strict(decode(envelope["payload_base64url"]))
    payload["expires_at"] = expires_at
    payload_raw = canonicalize(payload)
    envelope["payload_base64url"] = base64.urlsafe_b64encode(payload_raw).rstrip(b"=").decode()
    envelope["payload_sha256"] = digest(payload_raw)
    key = Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33)))
    envelope["signature_base64url"] = base64.urlsafe_b64encode(key.sign(
        envelope["purpose"].encode() + b"\0" + payload_raw)).rstrip(b"=").decode()
    altered["private_b_authority_envelope_jcs"] = canonicalize(envelope).decode()
    return altered


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
        later = signed_detached_with_expiry(source, "2026-11-22T09:15:37-05:00")
        altered = copy.deepcopy(frame)
        altered["bridge_assignment_envelope_base64url"] = base64.urlsafe_b64encode(
            later["private_b_authority_envelope_jcs"].encode()).rstrip(b"=").decode()
        try:
            check(altered, later, schemas, public)
        except ValueError as error:
            require(str(error) == "detached B assignment expires no later than the primary reservation",
                    "signed offset expiry refused for the intended reason")
        else:
            raise ValueError("later signed detached B expiry accepted through offset ordering")
        report(True, "cooperative B FD3 exact A envelopes, digest join, frame cap and refusal")
    except Exception as error:
        report(False, "cooperative B FD3 exact A envelopes, digest join, frame cap and refusal", str(error))
