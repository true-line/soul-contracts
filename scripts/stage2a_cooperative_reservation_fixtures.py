"""Bridge-free cooperative reservation vectors and cross-field checks."""

import base64
import copy
import hashlib
from datetime import datetime, timedelta

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from jcs import canonicalize, parse_strict

PURPOSE = b"agent-bot/soul-cooperative-reservation/v3"
PAYLOAD = "machine/v3/soul-cooperative-reservation-payload.schema.json"
ENVELOPE = "machine/v3/soul-cooperative-signed-reservation.schema.json"


def decode(value):
    raw = base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
    if base64.urlsafe_b64encode(raw).rstrip(b"=").decode() != value:
        raise ValueError("noncanonical base64url")
    return raw


def digest(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def require(condition, message):
    if not condition:
        raise ValueError(message)


def peers_match(payload):
    assignment = payload["assignment"]
    return all(endpoint["expected_peer_uid"] == assignment["runner_uid"]
               for endpoint in payload["endpoints"].values())


def check_stage2a_cooperative_reservation_fixtures(root, schemas, report):
    path = root / "fixtures/reservation/v3/soul-cooperative-signed-reservation.synthetic.json"
    try:
        vector = parse_strict(path.read_bytes())
        envelope_raw = vector["reservation_envelope_jcs"].encode()
        envelope = parse_strict(envelope_raw)
        require(canonicalize(envelope) == envelope_raw, "envelope must be exact JCS bytes")
        require(schemas[ENVELOPE].is_valid(envelope), "purpose-separated envelope shape")
        payload_raw = decode(envelope["payload_base64url"])
        require(payload_raw == vector["reservation_payload_jcs"].encode(), "exact payload bytes")
        require(digest(payload_raw) == envelope["payload_sha256"], "payload digest")
        payload = parse_strict(payload_raw)
        require(canonicalize(payload) == payload_raw, "payload must be exact JCS bytes")
        require(schemas[PAYLOAD].is_valid(payload), "cooperative payload schema")
        public_key = decode(envelope["issuer_public_key_base64url"])
        require(public_key == decode(vector["issuer_public_key_base64url"]), "pinned synthetic issuer key")
        Ed25519PublicKey.from_public_bytes(public_key).verify(
            decode(envelope["signature_base64url"]), PURPOSE + b"\0" + payload_raw)

        assignment, binding, endpoints = payload["assignment"], payload["measurement_binding"], payload["endpoints"]
        require(binding["profile_in_force"] == "managed-cooperative", "cooperative-only measurement profile")
        require(payload["host_id"] == binding["host_id"], "host binding")
        require(assignment["expires_at"] == payload["expires_at"], "assignment lease expiry binding")
        require(datetime.fromisoformat(payload["issued_at"].replace("Z", "+00:00")) <
                datetime.fromisoformat(payload["expires_at"].replace("Z", "+00:00")) <=
                datetime.fromisoformat(payload["issued_at"].replace("Z", "+00:00")) + timedelta(seconds=30),
                "one-use lease is positive and at most 30 seconds")
        for field in ("installation_id", "soul_id", "start_id", "launch_id", "plan_id", "hq_epoch"):
            require(assignment[field] == binding[field], field + " binding")
        require(assignment["plan_digest"] == binding["installed_plan_digest"], "installed plan digest binding")
        require(assignment["package_sha256"] == binding["package_sha256"] and
                assignment["soul_artifact_sha256"] == binding["soul_artifact_sha256"], "artifact binding")
        require(assignment["package_root"] == binding["snapshots"]["definition"]["root_path"],
                "package root binds frozen definition snapshot")
        require(assignment["launch_inputs_root"] == binding["snapshots"]["launch_inputs"]["root_path"],
                "launch inputs root binds frozen launch-input snapshot")
        inventory = binding["r_inventory"]
        require(inventory["domain"] == "R-runtime", "R installed inventory reference")
        require(inventory["installation_id"] == assignment["installation_id"], "R installation binding")
        require(inventory["owner_plan_digest"] == "sha256:" + assignment["plan_digest"], "R plan binding")
        require(inventory["reader_uid"] == assignment["runner_uid"] and
                inventory["reader_gid"] == assignment["runner_gid"], "runner and R inventory binding")
        require(assignment["runtime_root"] == inventory["snapshot"]["path"],
                "runtime root binds sealed R inventory snapshot")
        require(assignment["node_path"] == assignment["runtime_root"].rstrip("/") + "/bin/node" and
                assignment["entry_path"] == assignment["runtime_root"].rstrip("/") + "/bin/agent-bot-souls.mjs",
                "fixed Node and entry paths inside R runtime")
        require(assignment["state_root"] == f"/var/agent-bot-soul-runner-{assignment['runner_account']}/state" and
                assignment["state_root_mode"] == "0700", "dedicated external runner state path and mode")
        require(binding["h_service_descriptor_digest"], "H descriptor digest is bound")
        require(set(endpoints) == {"admission", "broker"}, "exact admission and broker endpoints")
        require(peers_match(payload), "both endpoints expect the assigned R peer")
        paths = set()
        for name, endpoint in endpoints.items():
            require(endpoint["owner_uid"] == assignment["hq_uid"], name + " is H-owned")
            require(endpoint["group_gid"] == assignment["runner_gid"], name + " grants runner group access")
            require(endpoint["expected_peer_uid"] == assignment["runner_uid"], name + " expects assigned R peer")
            require(endpoint["dir_mode"] == 0o2750 and endpoint["socket_mode"] == 0o660,
                    name + " has only H-owner and assigned R-group access")
            require(endpoint["socket_path"].startswith(endpoint["directory"].rstrip("/") + "/"), name + " socket is inside directory")
            paths.add(endpoint["socket_path"])
        require(len(paths) == 2, "admission and broker sockets are distinct")

        protected_payload = copy.deepcopy(payload)
        protected_envelope = copy.deepcopy(envelope)
        protected_envelope["purpose"] = "agent-bot/stage2a-reservation/v3"
        require(not schemas[ENVELOPE].is_valid(protected_envelope), "protected purpose cannot authorize cooperative payload")
        try:
            Ed25519PublicKey.from_public_bytes(public_key).verify(
                decode(envelope["signature_base64url"]), b"agent-bot/stage2a-reservation/v3\0" + payload_raw)
        except InvalidSignature:
            pass
        else:
            raise ValueError("protected purpose must not verify the cooperative signature")
        require(not schemas["machine/v3/stage2a-reservation-payload.schema.json"].is_valid(protected_payload),
                "protected reservation schema refuses cooperative payload")
        wrong_peer = copy.deepcopy(payload)
        wrong_peer["endpoints"]["broker"]["expected_peer_uid"] += 1
        require(schemas[PAYLOAD].is_valid(wrong_peer), "wrong peer fixture reaches semantic binding check")
        require(not peers_match(wrong_peer), "wrong broker peer is rejected by runner binding")
        bridged = copy.deepcopy(payload)
        bridged["assignment"]["bridge_uid"] = 333
        require(not schemas[PAYLOAD].is_valid(bridged), "cooperative schema refuses bridge claims")
        report(True, str(path.relative_to(root)))
    except (KeyError, OSError, ValueError, InvalidSignature) as exc:
        report(False, str(path.relative_to(root)), str(exc))
