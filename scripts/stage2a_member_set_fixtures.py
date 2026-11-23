"""Independent synthetic oracle for the three A-signed two-member records."""

import base64
import hashlib
import json
import posixpath
from datetime import datetime

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from jcs import canonicalize, parse_strict

ASSIGNMENT = "machine/v3/stage2a-member-set-assignment-payload.schema.json"
SIGNED_ASSIGNMENT = "machine/v3/stage2a-member-set-signed-assignment.schema.json"
H_MAP = "hq/v1/stage2a-provisional-member-map.schema.json"
CHILD = "machine/v3/stage2a-member-set-child-observation-payload.schema.json"
SIGNED_CHILD = "machine/v3/stage2a-member-set-signed-child-observation.schema.json"
READY = "machine/v3/stage2a-member-set-ready-payload.schema.json"
SIGNED_READY = "machine/v3/stage2a-member-set-signed-ready.schema.json"
PURPOSES = {
    "assignment": b"agent-bot/stage2a-member-set-assignment/v1",
    "child_observation": b"agent-bot/stage2a-member-set-child-observation/v1",
    "ready": b"agent-bot/stage2a-member-set-ready/v1",
}


def digest(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def decode(value):
    raw = base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
    if base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii") != value:
        raise ValueError("noncanonical base64url")
    return raw


def require(ok, message):
    if not ok:
        raise ValueError(message)


def when(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def signed(vector, kind, envelope_schema, payload_schema, schemas, public):
    envelope_raw = vector[f"{kind}_envelope_jcs"].encode("utf-8")
    envelope = parse_strict(envelope_raw)
    require(canonicalize(envelope) == envelope_raw and schemas[envelope_schema].is_valid(envelope),
            kind + " exact JCS envelope and shape")
    require(envelope["purpose"].encode("ascii") == PURPOSES[kind], kind + " purpose")
    require(decode(envelope["issuer_public_key_base64url"]) == public, kind + " pinned test key")
    payload_raw = decode(envelope["payload_base64url"])
    require(payload_raw == vector[f"{kind}_payload_jcs"].encode("utf-8") and
            digest(payload_raw) == envelope["payload_sha256"], kind + " exact payload digest")
    payload = parse_strict(payload_raw)
    require(canonicalize(payload) == payload_raw and schemas[payload_schema].is_valid(payload),
            kind + " exact JCS payload and shape")
    Ed25519PublicKey.from_public_bytes(public).verify(
        decode(envelope["signature_base64url"]), PURPOSES[kind] + b"\0" + payload_raw)
    return payload, envelope_raw


def verify_existing_envelope(raw, purpose, envelope_schema, payload_schema, schemas, public):
    envelope = parse_strict(raw)
    require(canonicalize(envelope) == raw and schemas[envelope_schema].is_valid(envelope) and
            envelope["purpose"] == purpose and decode(envelope["issuer_public_key_base64url"]) == public,
            "existing authority shares pinned A key, purpose and JCS")
    payload_raw = decode(envelope["payload_base64url"])
    payload = parse_strict(payload_raw)
    require(canonicalize(payload) == payload_raw and digest(payload_raw) == envelope["payload_sha256"] and
            schemas[payload_schema].is_valid(payload), "existing authority exact payload/JCS/digest")
    Ed25519PublicKey.from_public_bytes(public).verify(
        decode(envelope["signature_base64url"]), purpose.encode("ascii") + b"\0" + payload_raw)
    return payload


def primary_bytes(root, profile, vector, schemas, public):
    raw = vector["primary_reservation_envelope_jcs"].encode("utf-8")
    if profile == "managed-protected":
        payload = verify_existing_envelope(raw, "agent-bot/stage2a-reservation/v3",
            "machine/v3/stage2a-signed-reservation.schema.json",
            "machine/v3/stage2a-reservation-payload.schema.json", schemas, public)
        source_payload = json.loads((root / "fixtures/positive/stage2a-reservation-payload.v3-synthetic.json").read_text())["input"]
        require(payload == source_payload and vector["private_b_authority_envelope_jcs"] is None,
                "synthetic primary uses exact reviewed protected payload")
        a = payload["assignment"]
        b = {"account": a["bridge_account"], "uid": a["bridge_uid"], "gid": a["bridge_gid"],
             "endpoints": {name: a[name] for name in ("broker", "member", "relay")}}
        purpose = "agent-bot/stage2a-reservation/v3"
        authority_sha = digest(raw)
    else:
        fx = json.loads((root / "fixtures/reservation/v3/soul-cooperative-signed-reservation.brokered-b.synthetic.json").read_text())
        payload = verify_existing_envelope(raw, "agent-bot/soul-cooperative-reservation/v3",
            "machine/v3/soul-cooperative-signed-reservation.schema.json",
            "machine/v3/soul-cooperative-reservation-payload.schema.json", schemas, public)
        require(payload == parse_strict(fx["reservation_payload_jcs"].encode("utf-8")),
                "synthetic primary uses exact reviewed cooperative payload")
        private_raw = vector["private_b_authority_envelope_jcs"].encode("utf-8")
        private = verify_existing_envelope(private_raw, "agent-bot/soul-cooperative-bridge-assignment/v3",
            "machine/v3/soul-cooperative-bridge-signed-assignment.schema.json",
            "machine/v3/soul-cooperative-bridge-assignment-payload.schema.json", schemas, public)
        source_private = parse_strict(decode(parse_strict(fx["bridge_envelope_jcs"].encode("utf-8"))["payload_base64url"]))
        require(private == source_private, "synthetic private B authority uses exact reviewed payload")
        b = {"account": private["bridge"]["account"], "uid": private["bridge"]["uid"],
             "gid": private["bridge"]["gid"], "endpoints": private["endpoints"]}
        purpose = "agent-bot/soul-cooperative-bridge-assignment/v3"
        authority_sha = digest(private_raw)
    return payload, raw, b, purpose, authority_sha


def check_vector(root, profile, vector, schemas, public):
    assignment, assignment_envelope = signed(vector, "assignment", SIGNED_ASSIGNMENT, ASSIGNMENT, schemas, public)
    child, child_envelope = signed(vector, "child_observation", SIGNED_CHILD, CHILD, schemas, public)
    ready, ready_envelope = signed(vector, "ready", SIGNED_READY, READY, schemas, public)
    primary, reservation_raw, bridge, authority_purpose, authority_sha = primary_bytes(
        root, profile, vector, schemas, public)
    a = primary["assignment"]
    require(vector["source_reservation_sha256"] == digest(reservation_raw) == assignment["reservation_sha256"],
            "exact existing A reservation")
    require(assignment["profile_in_force"] == child["profile_in_force"] == ready["profile_in_force"] == profile,
            "profile-separated member set")
    for name in ("host_id", "installation_id", "soul_id", "start_id", "hq_epoch"):
        want = primary["host_id"] if name == "host_id" else a[name]
        require(assignment[name] == child[name] == ready[name] == want, name + " join")
    require(assignment["plan_id"] == a["plan_id"] and assignment["plan_digest"] == a["plan_digest"],
            "reviewed plan identity")
    require(assignment["soul_artifact_sha256"] == "sha256:" + a["soul_artifact_sha256"] and
            assignment["definition_measurement"] == primary["measurement_binding"]["definition_measurement"],
            "frozen package and definition")
    require(assignment["runner_uid"] == a["runner_uid"] and assignment["runner_gid"] == a["runner_gid"],
            "runner account")
    require(assignment["bridge"] == bridge and assignment["b_authority"] ==
            {"purpose": authority_purpose, "envelope_sha256": authority_sha},
            "one existing B account and approved endpoint authority")
    require(len({e["socket_path"] for e in bridge["endpoints"].values()}) == 3,
            "exactly three distinct approved endpoints")

    soul_raw = decode(vector["frozen_soul_info_raw_base64url"])
    soul_info = parse_strict(soul_raw)
    manifest_raw = decode(vector["adapter_manifest_raw_base64url"])
    manifest = parse_strict(manifest_raw)
    host_raw = vector["host_projection_jcs"].encode("utf-8")
    host = parse_strict(host_raw)
    require(canonicalize(host) == host_raw and assignment["frozen_soul_info_sha256"] == digest(soul_raw) and
            assignment["frozen_adapter_manifest_sha256"] == digest(manifest_raw) and
            assignment["host_projection_sha256"] == digest(host_raw),
            "exact frozen SoulInfo, adapter manifest and host projection bytes")
    require(assignment["adapter_manifest_relpath"] == "Contents/opt/fixture-stock.json" and
            manifest["adapter_id"] == "fixture-stock" and manifest["adapter_version"] == "1.0.0" and
            all("/" not in manifest[key] and manifest[key] not in (".", "..") for key in
                ("executable", "adjacent_cli")), "frozen adapter source declaration")
    require(soul_info["soul_id"] == assignment["soul_id"] and
            host["installation"]["installation_id"] == assignment["installation_id"], "frozen selectors")
    members = assignment["members"]
    ids = [m["member_id"] for m in members]
    selectors = [m["member_selector"] for m in members]
    launches = [m["launch_id"] for m in members]
    require(len(members) == 2 and ids == sorted(ids) and len(set(ids)) == len(set(selectors)) == len(set(launches)) == 2,
            "strict sorted exact two-member set")
    require(len([m for m in members if m["role"] == "lead"]) == 1,
            "exactly one frozen lead")
    stable = []
    for actual, frozen in zip(members, sorted(soul_info["members"], key=lambda m: m["member_id"])):
        require(all(actual[k] == frozen[k] for k in ("member_id", "role", "adapter_id", "adapter_version")),
                "member equals frozen SoulInfo")
        command = host["adapters"][actual["adapter_id"]]["command"]
        require(len(command) == 1 and command[0] == actual["command_path"] and
                digest(decode(vector["command_bytes_base64url"][actual["member_id"]])) ==
                actual["command_sha256"] == manifest["executable_sha256"] and
                posixpath.basename(actual["command_path"]) == manifest["executable"] and
                actual["adjacent_cli_path"] == posixpath.join(
                    posixpath.dirname(actual["command_path"]), manifest["adjacent_cli"]) and
                actual["adjacent_cli_sha256"] == digest(decode(vector["cli_bytes_base64url"])) ==
                manifest["adjacent_cli_sha256"],
                "member ACP command and adjacent CLI equal measured host/source bytes")
        preimage = b"agent-bot/stage2a-member-selector/v1\0" + assignment["reservation_sha256"].encode() + b"\0"
        preimage += actual["member_id"].encode() + b"\0" + actual["launch_id"].encode()
        require(actual["member_selector"] == "mb_" + hashlib.sha256(preimage).hexdigest(),
                "non-bearer member selector derivation")
        stable.append({k: actual[k] for k in
                       ("member_id", "role", "adapter_id", "adapter_version", "command_path", "command_sha256",
                        "adjacent_cli_path", "adjacent_cli_sha256")})
    plan = vector["owner_plan_selection"]
    selected_digest = digest(canonicalize(stable))
    require(plan.get("owner_plan_member_set_sha256") == selected_digest == assignment["owner_plan_member_set_sha256"] and
            plan["plan_digest"] == assignment["plan_digest"], "explicit owner-reviewed two-member plan selector")
    require({"plan_digest": plan["plan_digest"]}.get("owner_plan_member_set_sha256") != selected_digest and
            digest(canonicalize(stable[:1])) != selected_digest, "missing or one-member plan selection refuses")

    map_raw = vector["provisional_hq_mapping_jcs"].encode("utf-8")
    mapping = parse_strict(map_raw)
    require(canonicalize(mapping) == map_raw and schemas[H_MAP].is_valid(mapping) and
            child["provisional_hq_mapping"] == mapping and
            child["provisional_hq_mapping_sha256"] == ready["provisional_hq_mapping_sha256"] == digest(map_raw),
            "exact paired H provisional mapping bytes")
    require(mapping["profile_in_force"] == profile and mapping["runtime_state"] == "provisional" and
            mapping["acp_authority"] == "withheld" and
            mapping["assignment_envelope_sha256"] == digest(assignment_envelope), "H keeps ACP withheld")
    require([m["member_id"] for m in mapping["members"]] == ids and
            [m["member_selector"] for m in mapping["members"]] == selectors and
            len({m["runtime_id"] for m in mapping["members"]}) == 2 and
            len({m["channel_binding"] for m in mapping["members"]}) == 2, "H per-member runtime map")

    require(child["reservation_sha256"] == ready["reservation_sha256"] == digest(reservation_raw) and
            child["assignment_envelope_sha256"] == ready["assignment_envelope_sha256"] == digest(assignment_envelope) and
            ready["child_observation_envelope_sha256"] == digest(child_envelope) and
            ready["b_authority_sha256"] == authority_sha, "three-phase exact envelope joins")
    children = child["members"]
    require([m["member_id"] for m in children] == ids and
            [m["member_selector"] for m in children] == selectors and
            [m["launch_id"] for m in children] == launches and
            [m["runtime_id"] for m in children] == [m["runtime_id"] for m in mapping["members"]],
            "A-observed children equal assigned/H provisional members")
    require(len({(m["child_process"]["pid"], m["child_process"]["start_seconds"],
                  m["child_process"]["start_micros"]) for m in children}) == 2,
            "distinct kernel child identities")
    require(all(m["child_process"]["executable_sha256"] == assignment["members"][i]["command_sha256"]
                for i, m in enumerate(children)), "A-observed ACP executable equals pinned member command")
    require(ready["bridge_process"]["uid"] == bridge["uid"] and
            ready["bridge_process"]["gid"] == bridge["gid"], "one A-observed B process")
    require([m["member_id"] for m in ready["members"]] == ids, "ready exact member order")
    arm_hashes = set()
    for member, observed, mapped in zip(ready["members"], children, mapping["members"]):
        p, arm = observed["child_process"], member["bridge_arm"]
        require(all(member[k] == observed[k] for k in ("member_id", "member_selector", "launch_id", "runtime_id")) and
                arm["member_id"] == member["member_id"] and arm["member_selector"] == member["member_selector"] and
                arm["runtime_id"] == mapped["runtime_id"], "B arm selector/runtime join")
        require(arm["child_observation_envelope_sha256"] == digest(child_envelope) and
                arm["bridge_uid"] == bridge["uid"] and arm["state"] == "armed" and
                all(arm["adapter_" + key] == p[key] for key in ("pid", "uid", "gid", "start_seconds", "start_micros")) and
                arm["relay_peer_rule"] == "a-attested-live-direct-child-of-adapter-v1" and
                arm["relay_peer_state"] == "unobserved" and
                arm["provider_ingress"] == "withheld-pending-per-peer-attestation",
                "B arms deferred CLI-peer gate anchored to A-observed ACP child before ACP")
        require(member["bridge_arm_receipt_sha256"] == digest(canonicalize(arm)), "exact B arm JCS receipt")
        arm_hashes.add(member["bridge_arm_receipt_sha256"])
        require(when(child["observed_at"]) <= when(arm["armed_at"]) <= when(ready["issued_at"]),
                "B arms after A observation and before A ready signature")
    require(len(arm_hashes) == 2, "independent per-member B arm receipts")
    require(when(assignment["issued_at"]) < when(mapping["issued_at"]) <= when(child["issued_at"]) <
            when(ready["issued_at"]) < when(ready["expires_at"]) <= when(primary["expires_at"]),
            "one-use three-phase time order")
    require(len(ready_envelope) > 0, "signed ready envelope bytes present")


def check_stage2a_member_set_fixtures(root, schemas, report):
    vectors = parse_strict((root / "fixtures/reservation/v3/stage2a-member-set.synthetic.json").read_bytes())
    public_raw = Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33))).public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    for profile in ("managed-protected", "managed-cooperative"):
        try:
            check_vector(root, profile, vectors[profile], schemas, public_raw)
            report(True, "member-set " + profile + " exact signed assignment/child/B-ready joins")
        except Exception as error:
            report(False, "member-set " + profile + " exact signed assignment/child/B-ready joins", str(error))
