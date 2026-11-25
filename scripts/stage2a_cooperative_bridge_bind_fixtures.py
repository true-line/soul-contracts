"""Independent cooperative B/H HMAC preimage and signed policy joins."""

import base64
import copy
import hashlib
import hmac

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from jcs import parse_strict
from stage2a_cooperative_b_fd3_fixtures import signed_detached_with_expiry
from stage2a_member_set_fixtures import digest, require, verify_existing_envelope, when

BIND = "hq/v1/stage2a-cooperative-bridge-bind-exchange.schema.json"
POLICY = "hq/v1/stage2a-cooperative-member-policy-exchange.schema.json"
CONTEXT = "agent-bot-stage2a-cooperative-bridge-bind-v3"


def decode(value):
    raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    require(base64.urlsafe_b64encode(raw).rstrip(b"=").decode() == value, "canonical base64url")
    return raw


def check(root, vector, source, schemas):
    challenge, request = vector["challenge_result"], vector["proof_request"]
    policy_request, policy_result = vector["policy_request"], vector["policy_result"]
    require(all(schemas[BIND].is_valid(x) for x in (challenge, request)) and
            all(schemas[POLICY].is_valid(x) for x in (policy_request, policy_result)),
            "closed challenge/proof and same-bound policy shapes")
    primary_raw = source["primary_reservation_envelope_jcs"].encode()
    detached_raw = source["private_b_authority_envelope_jcs"].encode()
    public = Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33))).public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    primary = verify_existing_envelope(
        primary_raw, "agent-bot/soul-cooperative-reservation/v3",
        "machine/v3/soul-cooperative-signed-reservation.schema.json",
        "machine/v3/soul-cooperative-reservation-payload.schema.json", schemas, public)
    detached = verify_existing_envelope(
        detached_raw, "agent-bot/soul-cooperative-bridge-assignment/v3",
        "machine/v3/soul-cooperative-bridge-signed-assignment.schema.json",
        "machine/v3/soul-cooperative-bridge-assignment-payload.schema.json", schemas, public)
    assigned = primary["assignment"]
    require(when(detached["expires_at"]) <= when(primary["expires_at"]),
            "detached B assignment expires no later than the primary reservation")
    require(when(challenge["expires_at"]) <= min(
        when(primary["expires_at"]), when(detached["expires_at"])),
        "bind challenge expires no later than both signed authorities")
    require(challenge["context"] == CONTEXT and request["nonce"] == challenge["nonce"] and
            request["hq_epoch"] == challenge["hq_epoch"] == assigned["hq_epoch"] and
            all(request[key] == assigned[key] for key in
                ("installation_id", "start_id", "launch_id", "plan_id", "plan_digest")) and
            request["reservation_sha256"] == policy_request["reservation_sha256"] == digest(primary_raw) and
            request["bridge_assignment_envelope_sha256"] ==
                policy_request["bridge_assignment_envelope_sha256"] == digest(detached_raw) and
            request["bridge_uid"] == detached["bridge"]["uid"] and
            request["broker_socket_path"] == detached["endpoints"]["broker"]["socket_path"],
            "bind selectors name exact signed FD3 primary and detached B assignment")
    fields = [CONTEXT, request["nonce"], request["hq_epoch"], request["installation_id"],
              request["start_id"], request["launch_id"], request["plan_id"], request["plan_digest"],
              request["reservation_sha256"], request["bridge_assignment_envelope_sha256"],
              str(request["bridge_uid"]), request["broker_socket_path"]]
    preimage = "\0".join(fields).encode("utf-8")
    require(decode(vector["preimage_base64url"]) == preimage and
            hmac.compare_digest(hmac.new(decode(vector["key_base64url"]), preimage,
                                         hashlib.sha256).hexdigest(), request["proof_hex"]),
            "12-field no-trailing-NUL HMAC preimage and A-private 32-byte proof")
    assignment_raw = source["assignment_envelope_jcs"].encode()
    authority_raw = source["member_b_authority_envelope_jcs"].encode()
    authority = parse_strict(decode(parse_strict(authority_raw)["payload_base64url"]))
    require(decode(policy_result["member_set_assignment_envelope_base64url"]) == assignment_raw and
            policy_result["member_set_assignment_envelope_sha256"] == digest(assignment_raw) and
            decode(policy_result["member_b_authority_envelope_base64url"]) == authority_raw and
            policy_result["member_b_authority_envelope_sha256"] == digest(authority_raw) and
            authority["reservation_sha256"] == digest(primary_raw) and
            authority["member_set_assignment_envelope_sha256"] == digest(assignment_raw) and
            digest(detached_raw) != digest(authority_raw),
            "post-bind policy has both exact A envelopes and never swaps detached B authority")


def check_stage2a_cooperative_bridge_bind_fixtures(root, schemas, report):
    vector = parse_strict((root / "fixtures/reservation/v3/stage2a-cooperative-bridge-bind.synthetic.json").read_bytes())
    source = parse_strict((root / "fixtures/reservation/v3/stage2a-member-set.synthetic.json").read_bytes())[
        "managed-cooperative"]
    try:
        check(root, vector, source, schemas)
        bad = parse_strict((root / "fixtures/reservation/v3/stage2a-cooperative-bridge-bind.synthetic.json").read_bytes())
        bad["proof_request"]["bridge_assignment_envelope_sha256"] = bad["policy_result"][
            "member_b_authority_envelope_sha256"]
        try:
            check(root, bad, source, schemas)
        except ValueError:
            pass
        else:
            raise ValueError("later member authority digest accepted in pre-bind FD3 slot")
        offset = copy.deepcopy(vector)
        offset["challenge_result"]["expires_at"] = "2026-11-22T09:15:37-05:00"
        try:
            check(root, offset, source, schemas)
        except ValueError as error:
            require(str(error) == "bind challenge expires no later than both signed authorities",
                    "offset challenge refused for the intended expiry reason")
        else:
            raise ValueError("later offset challenge expiry accepted")
        earlier = signed_detached_with_expiry(source, "2026-11-22T14:15:35Z")
        try:
            check(root, vector, earlier, schemas)
        except ValueError as error:
            require(str(error) == "bind challenge expires no later than both signed authorities",
                    "signed earlier detached expiry refused for the intended reason")
        else:
            raise ValueError("challenge accepted after earlier signed detached expiry")
        report(True, "cooperative B/H exact HMAC preimage and post-bind A-policy joins")
    except Exception as error:
        report(False, "cooperative B/H exact HMAC preimage and post-bind A-policy joins", str(error))
