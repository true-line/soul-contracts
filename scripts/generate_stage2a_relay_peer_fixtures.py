#!/usr/bin/env python3
"""Regenerate signed synthetic live-CLI challenge vectors for both Stage 2a profiles."""

import copy

from generate_stage2a_member_set_fixtures import KEY, PUBLIC, b64, build, sha, write
from jcs import canonicalize

PURPOSE = "agent-bot/stage2a-relay-peer-attestation/v1"
SCHEMAS = {
    "challenge": "hq/v1/stage2a-relay-peer-challenge.schema.json",
    "attestation": "machine/v3/stage2a-relay-peer-attestation-payload.schema.json",
    "signed": "machine/v3/stage2a-relay-peer-signed-attestation.schema.json",
    "verified": "hq/v1/stage2a-relay-peer-verified.schema.json",
}


def signed(payload):
    raw = canonicalize(payload)
    envelope = {
        "schema_version": 1, "purpose": PURPOSE,
        "issuer_public_key_base64url": b64(PUBLIC),
        "payload_sha256": sha(raw), "payload_base64url": b64(raw),
        "signature_base64url": b64(KEY.sign(PURPOSE.encode("ascii") + b"\0" + raw)),
    }
    return envelope, canonicalize(envelope)


def build_peer(profile):
    member_vector, records = build(profile)
    assignment = records["assignment"]
    child = records["child_observation"]
    member = assignment["members"][0]
    child_process = child["members"][0]["child_process"]
    ids = {key: assignment[key] for key in
           ("profile_in_force", "host_id", "installation_id", "soul_id", "start_id", "hq_epoch",
            "reservation_sha256")}
    token = {"uid": assignment["runner_uid"], "pid": 4201, "pid_version": 77}
    challenge = {
        "contract": "hq/v1", "kind": "stage2a-relay-peer-challenge", "schema_version": 1,
        **ids,
        "assignment_envelope_sha256": sha(member_vector["assignment_envelope_jcs"].encode("utf-8")),
        "child_observation_envelope_sha256": sha(member_vector["child_observation_envelope_jcs"].encode("utf-8")),
        "member_id": member["member_id"], "member_selector": member["member_selector"],
        "runtime_id": child["members"][0]["runtime_id"],
        "rpc_id": "rpc_" + "a" * 32, "nonce_hex": "b" * 64,
        "peer_token": token,
        "accepted_at": "2026-11-22T14:15:22Z", "deadline_at": "2026-11-22T14:15:32Z",
    }
    challenge_raw = canonicalize(challenge)
    parent = {key: child_process[key] for key in
              ("pid", "uid", "start_seconds", "start_micros", "executable_sha256")}
    cli = {"pid": token["pid"], "uid": token["uid"], "gid": assignment["runner_gid"],
           "start_seconds": 1795356922, "start_micros": 250,
           "executable_path": member["adjacent_cli_path"],
           "executable_sha256": member["adjacent_cli_sha256"],
           "parent_pid": child_process["pid"]}
    attestation = {
        "contract": "machine/v3", "kind": "stage2a-relay-peer-attestation", "schema_version": 1,
        **ids,
        "assignment_envelope_sha256": challenge["assignment_envelope_sha256"],
        "child_observation_envelope_sha256": challenge["child_observation_envelope_sha256"],
        "ready_envelope_sha256": sha(member_vector["ready_envelope_jcs"].encode("utf-8")),
        "challenge_sha256": sha(challenge_raw),
        "member_id": member["member_id"], "member_selector": member["member_selector"],
        "runtime_id": challenge["runtime_id"], "rpc_id": challenge["rpc_id"],
        "nonce_hex": challenge["nonce_hex"], "reported_peer_token": token,
        "observed_cli": cli, "observed_adapter_parent": parent,
        "observed_at": "2026-11-22T14:15:23Z", "issued_at": "2026-11-22T14:15:23Z",
        "expires_at": "2026-11-22T14:15:28Z",
    }
    envelope, envelope_raw = signed(attestation)
    verified = {
        "contract": "hq/v1", "kind": "stage2a-relay-peer-verified", "schema_version": 1,
        "profile_in_force": profile, "start_id": assignment["start_id"],
        "rpc_id": challenge["rpc_id"], "nonce_hex": challenge["nonce_hex"],
        "member_id": member["member_id"], "member_selector": member["member_selector"],
        "runtime_id": challenge["runtime_id"], "peer_token": token,
        "challenge_sha256": sha(challenge_raw), "attestation_envelope_sha256": sha(envelope_raw),
        "attestation_envelope_base64url": b64(envelope_raw),
        "verdict": "verified", "verified_at": "2026-11-22T14:15:24Z",
        "expires_at": attestation["expires_at"],
    }
    vector = {"challenge_jcs": challenge_raw.decode("utf-8"),
              "attestation_payload_jcs": canonicalize(attestation).decode("utf-8"),
              "attestation_envelope_jcs": envelope_raw.decode("utf-8"),
              "verified_jcs": canonicalize(verified).decode("utf-8")}
    return vector, {"challenge": challenge, "attestation": attestation,
                    "signed": envelope, "verified": verified}


def fixture(kind, value):
    return {"schema": SCHEMAS[kind], "input": value, "expect": {"schema": "valid"},
            "canonical_sha256": sha(canonicalize(value))}


def main():
    vectors = {}
    cooperative = None
    for profile in ("managed-protected", "managed-cooperative"):
        vector, values = build_peer(profile)
        vectors[profile] = vector
        if profile == "managed-cooperative":
            cooperative = values
    write("fixtures/reservation/v3/stage2a-relay-peer.synthetic.json", vectors)
    for kind, value in cooperative.items():
        name = SCHEMAS[kind].split("/")[-1].removesuffix(".schema.json")
        positive = f"fixtures/positive/{name}.live-peer-synthetic.json"
        write(positive, fixture(kind, value))
        negative = copy.deepcopy(value)
        if kind == "challenge":
            negative["nonce_hex"] = "short"
        elif kind == "attestation":
            negative["observed_cli"]["pid"] = 1
        elif kind == "signed":
            negative["purpose"] = "agent-bot/wrong-purpose/v1"
        else:
            negative["verdict"] = "unverified"
        from pathlib import Path
        base_sha = sha((Path(__file__).resolve().parents[1] / positive).read_bytes())
        write(f"fixtures/negative/{name}.live-peer-synthetic-refusal.json", {
            "schema": SCHEMAS[kind], "input": negative, "expect": {"schema": "invalid"},
            "base": {"fixture": positive.removeprefix("fixtures/"), "sha256": base_sha},
        })


if __name__ == "__main__":
    main()
