"""Independent byte and authority joins for synthetic Machine-to-R FD3 frames."""

import json

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from jcs import canonicalize, parse_strict

from stage2a_member_set_fixtures import (
    ASSIGNMENT, SIGNED_ASSIGNMENT, decode, digest, primary_bytes, require, signed,
)

FRAME = "machine/v3/stage2a-runner-member-set-fd3.schema.json"
PIN = "/Library/Application Support/ai.true-line.agent-bot-hq/soul-authority.pub"


def check_frame(root, profile, frame, vector, schemas, public):
    require(schemas[FRAME].is_valid(frame), "FD3 frame shape")
    assignment, assignment_raw = signed(vector, "assignment", SIGNED_ASSIGNMENT,
                                        ASSIGNMENT, schemas, public)
    reservation, reservation_raw, _, _, _ = primary_bytes(root, profile, vector, schemas, public)
    require(decode(frame["member_set_assignment_envelope_base64url"]) == assignment_raw and
            decode(frame["reservation_envelope_base64url"]) == reservation_raw and
            frame["reservation_sha256"] == digest(reservation_raw) == assignment["reservation_sha256"],
            "exact signed A assignment and primary reservation bytes")
    require(frame["machine_pin_path"] == PIN and
            assignment["profile_in_force"] == profile and
            frame["launch_input_records"]["host_projection"] == parse_strict(
                vector["host_projection_jcs"].encode("utf-8")) and
            digest(canonicalize(frame["launch_input_records"]["host_projection"])) ==
                assignment["host_projection_sha256"],
            "fixed pin, profile, and measured host projection")
    lead = assignment["members"][0]
    require(frame["launch_input_records"]["selected_command"] == lead["command_path"] and
            frame["launch_input_records"]["component_digests"]["adapter"] == lead["command_sha256"] and
            reservation["assignment"]["plan_digest"] == assignment["plan_digest"],
            "runner command bytes and owner-reviewed plan")
    if profile == "managed-protected":
        require(frame["schema"] == "agent-bot-souls/protected-start/v2", "protected FD3 literal")
    else:
        require(frame["schema"] == "agent-bot-souls/cooperative-start/v3" and
                frame["launch_input_records"]["adapter_transport"] == "brokered-b" and
                frame["launch_input_records"]["bridge_launch_sha256"] == reservation["bridge_launch_sha256"] and
                len(decode(frame["admission_challenge_base64url"])) == 32 and
                frame["member_socket_path"] == assignment["bridge"]["endpoints"]["member"]["socket_path"] and
                frame["relay_socket_path"] == assignment["bridge"]["endpoints"]["relay"]["socket_path"],
                "cooperative FD3 literal, challenge, and two fixed B endpoints")


def check_stage2a_runner_member_set_fixtures(root, schemas, report):
    vectors = json.loads((root / "fixtures/reservation/v3/stage2a-member-set.synthetic.json").read_text())
    frames = json.loads((root / "fixtures/reservation/v3/stage2a-runner-member-set-fd3.synthetic.json").read_text())
    public = Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33))).public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    for profile in ("managed-protected", "managed-cooperative"):
        try:
            check_frame(root, profile, frames[profile], vectors[profile], schemas, public)
            tampered = dict(frames[profile])
            tampered["reservation_sha256"] = "sha256:" + "0" * 64
            try:
                check_frame(root, profile, tampered, vectors[profile], schemas, public)
            except ValueError:
                pass
            else:
                raise ValueError("tampered reservation digest accepted")
            report(True, "runner FD3 " + profile + " signed assignment/reservation/measured-input joins")
        except Exception as error:
            report(False, "runner FD3 " + profile + " signed assignment/reservation/measured-input joins", str(error))
