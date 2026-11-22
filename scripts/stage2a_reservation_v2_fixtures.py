"""Deterministic Machine v2 reservation bytes; no physical custody claim."""
import base64
import copy
import hashlib
import json
from datetime import datetime

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from jcs import canonicalize, parse_strict

PURPOSE = b"agent-bot/stage2a-reservation/v2"


def digest(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def decode(value):
    raw = base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
    if base64.urlsafe_b64encode(raw).rstrip(b"=").decode() != value:
        raise ValueError("noncanonical base64url")
    return raw


def verify(envelope, schemas, pinned, now):
    if not schemas["machine/v2/stage2a-signed-reservation.schema.json"].is_valid(envelope):
        raise ValueError("envelope shape")
    if decode(envelope["issuer_public_key_base64url"]) != pinned:
        raise ValueError("installed signer pin")
    raw = decode(envelope["payload_base64url"])
    if envelope["payload_sha256"] != digest(raw):
        raise ValueError("payload digest")
    payload = parse_strict(raw)
    if canonicalize(payload) != raw or not schemas["machine/v2/stage2a-reservation-payload.schema.json"].is_valid(payload):
        raise ValueError("payload shape or canonicalization")
    try:
        Ed25519PublicKey.from_public_bytes(pinned).verify(decode(envelope["signature_base64url"]), PURPOSE + b"\0" + raw)
    except InvalidSignature as exc:
        raise ValueError("reservation signature") from exc
    assignment, binding = payload["assignment"], payload["measurement_binding"]
    for field, bound in (("installation_id", "installation_id"), ("soul_id", "soul_id"),
                         ("start_id", "start_id"), ("launch_id", "launch_id"),
                         ("plan_id", "plan_id"), ("plan_digest", "installed_plan_digest"),
                         ("hq_epoch", "hq_epoch"), ("package_sha256", "package_sha256"),
                         ("soul_artifact_sha256", "soul_artifact_sha256")):
        if assignment[field] != binding[bound]:
            raise ValueError("assignment binding")
    if payload["host_id"] != binding["host_id"] or payload["expires_at"] != assignment["expires_at"]:
        raise ValueError("host or expiry binding")
    issued = datetime.fromisoformat(payload["issued_at"].replace("Z", "+00:00"))
    expires = datetime.fromisoformat(payload["expires_at"].replace("Z", "+00:00"))
    if not issued <= now < expires or not 0 < (expires - issued).total_seconds() <= 30:
        raise ValueError("stale reservation")
    slot = hashlib.sha256(b"agent-bot-soul-endpoint-installation/v1\0" + binding["installation_id"].encode()).hexdigest()[:20]
    namespace = "/private/var/db/managed-machine/soul-snapshots/" + slot + "/snap_"
    roots = []
    for snapshot in binding["snapshots"].values():
        if (snapshot["owner_uid"] != assignment["machine_uid"] or
                snapshot["owner_gid"] != assignment["runner_gid"] or
                not snapshot["root_path"].startswith(namespace) or
                len(snapshot["root_path"]) != len(namespace) + 24):
            raise ValueError("admin snapshot identity")
        roots.append(snapshot["root_path"])
    if len(set(roots)) != 2 or assignment["package_root"] in roots:
        raise ValueError("approved source and frozen snapshot differ")
    member = assignment["member"]
    if payload["member_endpoint"] != {"member_socket": member["socket_path"],
                                       "member_endpoint": {k: v for k, v in member.items() if k != "socket_path"}}:
        raise ValueError("member endpoint binding")
    return raw


def check_stage2a_reservation_v2_fixtures(root, schemas, report):
    vector = json.loads((root / "fixtures/reservation/v2/machine-admin-synthetic.json").read_text())
    key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(vector["seed_hex"]))
    pinned = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    now = datetime.fromisoformat(vector["verification_at"].replace("Z", "+00:00"))
    envelope_raw, payload_raw = vector["envelope_jcs"].encode(), vector["payload_jcs"].encode()
    envelope = parse_strict(envelope_raw)
    try:
        assert canonicalize(envelope) == envelope_raw
        assert verify(envelope, schemas, pinned, now) == payload_raw
        assert vector["purpose"].encode() == PURPOSE
        assert vector["issuer_public_key_base64url"] == envelope["issuer_public_key_base64url"]
        assert vector["payload_sha256"] == digest(payload_raw) == envelope["payload_sha256"]
        assert vector["reservation_sha256"] == digest(envelope_raw)
        assert decode(vector["signing_preimage_base64url"]) == PURPOSE + b"\0" + payload_raw
        assert vector["signature_base64url"] == envelope["signature_base64url"]
        for name, value in (("stage2a-reservation-payload", parse_strict(payload_raw)),
                            ("stage2a-signed-reservation", envelope)):
            fixture = json.loads((root / "fixtures/positive" / (name + ".machine-admin-synthetic.json")).read_text())
            assert fixture["input"] == value
        report(True, "Machine v2 admin reservation exact signed vector")
    except Exception as exc:
        report(False, "Machine v2 admin reservation exact signed vector", str(exc))

    def resigned(payload):
        raw = canonicalize(payload)
        out = dict(envelope, payload_base64url=base64.urlsafe_b64encode(raw).rstrip(b"=").decode(),
                   payload_sha256=digest(raw))
        out["signature_base64url"] = base64.urlsafe_b64encode(key.sign(PURPOSE + b"\0" + raw)).rstrip(b"=").decode()
        return out

    payload = parse_strict(payload_raw)
    changed_host = copy.deepcopy(payload)
    changed_host["measurement_binding"]["host_id"] = "different-host"
    expired = copy.deepcopy(payload)
    expired["expires_at"] = expired["assignment"]["expires_at"] = "2026-11-22T14:15:19Z"
    wrong_owner = copy.deepcopy(payload)
    wrong_owner["measurement_binding"]["snapshots"]["definition"]["owner_uid"] = 0
    cases = {
        "altered payload without resigning": dict(envelope, payload_base64url=resigned(changed_host)["payload_base64url"],
                                                  payload_sha256=resigned(changed_host)["payload_sha256"]),
        "wrong pinned signer": envelope,
        "expired signed reservation": resigned(expired),
        "wrong signed host": resigned(changed_host),
        "root-owned snapshot under v2": resigned(wrong_owner),
    }
    for name, candidate in cases.items():
        try:
            verify(candidate, schemas, bytes(32) if name == "wrong pinned signer" else pinned, now)
        except (ValueError, KeyError, TypeError):
            report(True, "Machine v2 refuses " + name)
        else:
            report(False, "Machine v2 refuses " + name)
