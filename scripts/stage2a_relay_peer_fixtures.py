"""Independent exact-byte and cross-record oracle for live relay-peer vectors."""

import copy
import json
from datetime import timedelta

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from jcs import canonicalize, parse_strict
from stage2a_member_set_fixtures import decode, digest, require, when

CHALLENGE = "hq/v1/stage2a-relay-peer-challenge.schema.json"
ATTESTATION = "machine/v3/stage2a-relay-peer-attestation-payload.schema.json"
SIGNED = "machine/v3/stage2a-relay-peer-signed-attestation.schema.json"
VERIFIED = "hq/v1/stage2a-relay-peer-verified.schema.json"
PURPOSE = b"agent-bot/stage2a-relay-peer-attestation/v1"
TEST_KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33)))
TEST_PUBLIC = TEST_KEY.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def canonical_record(vector, key, schema, schemas):
    raw = vector[key].encode("utf-8")
    value = parse_strict(raw)
    require(canonicalize(value) == raw and schemas[schema].is_valid(value), key + " JCS and shape")
    return value, raw


def verify_vector(root, profile, vector, schemas, used):
    source = json.loads((root / "fixtures/reservation/v3/stage2a-member-set.synthetic.json").read_text())[profile]
    assignment = parse_strict(source["assignment_payload_jcs"].encode("utf-8"))
    child = parse_strict(source["child_observation_payload_jcs"].encode("utf-8"))
    ready = parse_strict(source["ready_payload_jcs"].encode("utf-8"))
    challenge, challenge_raw = canonical_record(vector, "challenge_jcs", CHALLENGE, schemas)
    envelope, envelope_raw = canonical_record(vector, "attestation_envelope_jcs", SIGNED, schemas)
    require(decode(envelope["issuer_public_key_base64url"]) == TEST_PUBLIC and
            envelope["purpose"].encode("ascii") == PURPOSE, "independently pinned A test issuer and purpose")
    payload_raw = decode(envelope["payload_base64url"])
    require(payload_raw == vector["attestation_payload_jcs"].encode("utf-8") and
            digest(payload_raw) == envelope["payload_sha256"], "exact A payload bytes/hash")
    attestation = parse_strict(payload_raw)
    require(canonicalize(attestation) == payload_raw and schemas[ATTESTATION].is_valid(attestation),
            "A payload JCS and shape")
    Ed25519PublicKey.from_public_bytes(TEST_PUBLIC).verify(
        decode(envelope["signature_base64url"]), PURPOSE + b"\0" + payload_raw)
    verified, _ = canonical_record(vector, "verified_jcs", VERIFIED, schemas)

    ids = ("profile_in_force", "host_id", "installation_id", "soul_id", "start_id", "hq_epoch",
           "reservation_sha256")
    require(all(challenge[k] == attestation[k] == assignment[k] for k in ids) and
            challenge["profile_in_force"] == profile, "shared active start/profile/reservation")
    require(challenge["assignment_envelope_sha256"] == attestation["assignment_envelope_sha256"] ==
            digest(source["assignment_envelope_jcs"].encode("utf-8")) and
            challenge["child_observation_envelope_sha256"] == attestation["child_observation_envelope_sha256"] ==
            digest(source["child_observation_envelope_jcs"].encode("utf-8")) and
            attestation["ready_envelope_sha256"] == digest(source["ready_envelope_jcs"].encode("utf-8")),
            "exact A assignment/child/ready envelope joins")
    require(ready["assignment_envelope_sha256"] == challenge["assignment_envelope_sha256"] and
            ready["child_observation_envelope_sha256"] == challenge["child_observation_envelope_sha256"],
            "ready joins the same frozen set")
    member = assignment["members"][0]
    observed_child = child["members"][0]
    require(challenge["member_id"] == attestation["member_id"] == member["member_id"] and
            challenge["member_selector"] == attestation["member_selector"] == member["member_selector"] and
            challenge["runtime_id"] == attestation["runtime_id"] == observed_child["runtime_id"],
            "one exact assigned member/runtime, not a same-UID sibling")
    require(challenge["rpc_id"] == attestation["rpc_id"] and
            challenge["nonce_hex"] == attestation["nonce_hex"] and
            attestation["challenge_sha256"] == digest(challenge_raw) and
            attestation["reported_peer_token"] == challenge["peer_token"],
            "A signs exact one-use B challenge and reported kernel token")
    start_history = used.get(assignment["start_id"], {"rpc_ids": set(), "nonces": set()})
    require(challenge["rpc_id"] not in start_history["rpc_ids"] and
            challenge["nonce_hex"] not in start_history["nonces"],
            "RPC ID and nonce must each be unused for this start")
    cli, parent, token, pinned_child = (attestation["observed_cli"], attestation["observed_adapter_parent"],
                                         challenge["peer_token"], observed_child["child_process"])
    require(cli["pid"] == token["pid"] and cli["uid"] == token["uid"] == assignment["runner_uid"] and
            cli["gid"] == assignment["runner_gid"] and
            cli["executable_path"] == member["adjacent_cli_path"] and
            cli["executable_sha256"] == member["adjacent_cli_sha256"],
            "live CLI peer equals pinned adjacent executable and B token")
    require(cli["parent_pid"] == parent["pid"] == pinned_child["pid"] and
            all(parent[k] == pinned_child[k] for k in
                ("uid", "start_seconds", "start_micros", "executable_sha256")),
            "live direct ACP parent equals A-signed child PID/start/executable")
    require(when(challenge["accepted_at"]) <= when(attestation["observed_at"]) <=
            when(attestation["issued_at"]) <= when(verified["verified_at"]) <=
            when(attestation["expires_at"]) <= when(challenge["deadline_at"]) and
            when(challenge["deadline_at"]) - when(challenge["accepted_at"]) <= timedelta(seconds=10) and
            when(attestation["expires_at"]) - when(attestation["issued_at"]) <= timedelta(seconds=5) and
            when(attestation["expires_at"]) <= when(assignment["expires_at"]),
            "10-second transport and 5-second A attestation limits")
    require(verified["verdict"] == "verified" and
            verified["attestation_envelope_sha256"] == digest(envelope_raw) and
            decode(verified["attestation_envelope_base64url"]) == envelope_raw and
            verified["challenge_sha256"] == digest(challenge_raw) and
            verified["expires_at"] == attestation["expires_at"] and
            all(verified[k] == challenge[k] for k in
                ("profile_in_force", "start_id", "rpc_id", "nonce_hex", "member_id", "member_selector",
                 "runtime_id", "peer_token")),
            "H bound-channel reply echoes exact verified A envelope/challenge/token")
    start_history = used.setdefault(assignment["start_id"], {"rpc_ids": set(), "nonces": set()})
    start_history["rpc_ids"].add(challenge["rpc_id"])
    start_history["nonces"].add(challenge["nonce_hex"])


def resign_mutation(vector, change):
    mutant = copy.deepcopy(vector)
    payload = parse_strict(mutant["attestation_payload_jcs"].encode("utf-8"))
    change(payload)
    payload_raw = canonicalize(payload)
    envelope = parse_strict(mutant["attestation_envelope_jcs"].encode("utf-8"))
    envelope["payload_sha256"] = digest(payload_raw)
    import base64
    envelope["payload_base64url"] = base64.urlsafe_b64encode(payload_raw).rstrip(b"=").decode("ascii")
    envelope["signature_base64url"] = base64.urlsafe_b64encode(TEST_KEY.sign(PURPOSE + b"\0" + payload_raw)).rstrip(b"=").decode("ascii")
    envelope_raw = canonicalize(envelope)
    reply = parse_strict(mutant["verified_jcs"].encode("utf-8"))
    reply["attestation_envelope_sha256"] = digest(envelope_raw)
    reply["attestation_envelope_base64url"] = base64.urlsafe_b64encode(envelope_raw).rstrip(b"=").decode("ascii")
    mutant["attestation_payload_jcs"] = payload_raw.decode("utf-8")
    mutant["attestation_envelope_jcs"] = envelope_raw.decode("utf-8")
    mutant["verified_jcs"] = canonicalize(reply).decode("utf-8")
    return mutant


def resign_challenge_mutation(vector, change):
    """Re-sign a valid A proof for a changed B challenge and H reply."""
    mutant = copy.deepcopy(vector)
    challenge = parse_strict(mutant["challenge_jcs"].encode("utf-8"))
    change(challenge)
    challenge_raw = canonicalize(challenge)
    mutant["challenge_jcs"] = challenge_raw.decode("utf-8")
    mutant = resign_mutation(mutant, lambda payload: payload.update(
        rpc_id=challenge["rpc_id"], nonce_hex=challenge["nonce_hex"],
        challenge_sha256=digest(challenge_raw)))
    verified = parse_strict(mutant["verified_jcs"].encode("utf-8"))
    verified.update(rpc_id=challenge["rpc_id"], nonce_hex=challenge["nonce_hex"],
                    challenge_sha256=digest(challenge_raw))
    mutant["verified_jcs"] = canonicalize(verified).decode("utf-8")
    return mutant


def check_stage2a_relay_peer_fixtures(root, schemas, report):
    vectors = parse_strict((root / "fixtures/reservation/v3/stage2a-relay-peer.synthetic.json").read_bytes())
    for profile in ("managed-protected", "managed-cooperative"):
        vector = vectors[profile]
        try:
            used = {}
            verify_vector(root, profile, vector, schemas, used)
            report(True, "relay-peer " + profile + " exact challenge/A signature/H reply joins")
            try:
                verify_vector(root, profile, vector, schemas, used)
                report(False, "relay-peer " + profile + " refuses nonce/RPC replay")
            except ValueError:
                report(True, "relay-peer " + profile + " refuses nonce/RPC replay")
            for label, change in (
                ("reused nonce with fresh RPC ID", lambda c: c.update(rpc_id="rpc_" + "c" * 32)),
                ("reused RPC ID with fresh nonce", lambda c: c.update(nonce_hex="c" * 64)),
            ):
                mutant = resign_challenge_mutation(vector, change)
                verify_vector(root, profile, mutant, schemas, {})
                try:
                    verify_vector(root, profile, mutant, schemas, used)
                    report(False, "relay-peer " + profile + " refuses " + label)
                except ValueError:
                    report(True, "relay-peer " + profile + " refuses " + label)
            for label, change in (
                ("wrong direct parent", lambda p: p["observed_cli"].update(parent_pid=9999)),
                ("wrong CLI bytes", lambda p: p["observed_cli"].update(executable_sha256="sha256:" + "0" * 64)),
                ("stale A proof", lambda p: p.update(expires_at="2026-11-22T14:15:34Z")),
            ):
                mutant = resign_mutation(vector, change)
                try:
                    verify_vector(root, profile, mutant, schemas, {})
                    report(False, "relay-peer " + profile + " refuses " + label)
                except ValueError:
                    report(True, "relay-peer " + profile + " refuses " + label)
        except Exception as error:
            report(False, "relay-peer " + profile + " exact challenge/A signature/H reply joins", str(error))
