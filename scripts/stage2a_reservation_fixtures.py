"""Synthetic reservation wire vectors; not an authority or custody verifier."""
import base64
import hashlib
import json

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from jcs import canonicalize, parse_strict

PURPOSE = b"agent-bot/stage2a-reservation/v1"
MACHINE_ENVELOPE_DIGEST = "sha256:b9c7405e480fc31a8e48369fb4a413d152713a614c064cfc1dd17bc190a21dd4"


def digest(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def decode(s):
    raw = base64.b64decode(s + "=" * (-len(s) % 4), altchars=b"-_", validate=True)
    if base64.urlsafe_b64encode(raw).rstrip(b"=").decode() != s:
        raise ValueError("noncanonical base64url")
    return raw


def verify(e, schemas):
    if not schemas["machine/v1/stage2a-signed-reservation.schema.json"].is_valid(e):
        raise ValueError("envelope shape")
    raw = decode(e["payload_base64url"])
    if e["payload_sha256"] != digest(raw):
        raise ValueError("payload digest")
    p = parse_strict(raw)
    if canonicalize(p) != raw or not schemas["machine/v1/stage2a-reservation-payload.schema.json"].is_valid(p):
        raise ValueError("payload shape or canonicalization")
    try:
        Ed25519PublicKey.from_public_bytes(decode(e["issuer_public_key_base64url"])).verify(
            decode(e["signature_base64url"]), PURPOSE + b"\0" + raw)
    except InvalidSignature as exc:
        raise ValueError("signature") from exc
    a, m, member = p["assignment"], p["measurement_binding"], p["member_endpoint"]
    for ak, mk in [("installation_id", "installation_id"), ("soul_id", "soul_id"),
                   ("start_id", "start_id"), ("launch_id", "launch_id"), ("plan_id", "plan_id"),
                   ("plan_digest", "installed_plan_digest"), ("hq_epoch", "hq_epoch"),
                   ("package_sha256", "package_sha256"), ("soul_artifact_sha256", "soul_artifact_sha256")]:
        if a[ak] != m[mk]:
            raise ValueError("assignment binding")
    if p["host_id"] != m["host_id"] or p["expires_at"] != a["expires_at"]:
        raise ValueError("host or expiry binding")
    if any(snapshot["owner_gid"] != a["runner_gid"] for snapshot in m["snapshots"].values()):
        raise ValueError("snapshot owner group binding")
    ep = a["member"]
    if member["member_socket"] != ep["socket_path"] or member["member_endpoint"] != {k: v for k, v in ep.items() if k != "socket_path"}:
        raise ValueError("member endpoint binding")
    return raw


def check_stage2a_reservation_fixtures(root, schemas, report):
    folder = root / "fixtures/reservation/v1"
    try:
        v = json.loads((folder / "machine-658-synthetic.json").read_text())
        envelope_bytes, payload_bytes = v["envelope_jcs"].encode(), v["payload_jcs"].encode()
        e = parse_strict(envelope_bytes)
        assert canonicalize(e) == envelope_bytes and verify(e, schemas) == payload_bytes
        assert digest(envelope_bytes) == v["reservation_sha256"] == MACHINE_ENVELOPE_DIGEST
        assert digest(payload_bytes) == v["payload_sha256"] == e["payload_sha256"]
        assert v["purpose"].encode() == PURPOSE and v["signature_base64url"] == e["signature_base64url"]
        assert decode(v["signing_preimage_base64url"]) == PURPOSE + b"\0" + payload_bytes
        public = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(v["seed_hex"])).public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        assert decode(v["issuer_public_key_base64url"]) == public == decode(e["issuer_public_key_base64url"])
        for kind, key in [("payload", "payload_jcs"), ("signed-reservation", "envelope_jcs")]:
            name = "stage2a-reservation-payload" if kind == "payload" else "stage2a-signed-reservation"
            fixture = json.loads((root / "fixtures/positive" / (name + ".machine-658-synthetic.json")).read_text())
            assert canonicalize(fixture["input"]) == v[key].encode()
        report(True, "Stage 2a Machine synthetic reservation signature and bindings")
    except Exception as exc:
        report(False, "Stage 2a Machine synthetic reservation signature and bindings", str(exc))
    for name, e in json.loads((folder / "negative-vectors.json").read_text()).items():
        try:
            verify(e, schemas)
        except (ValueError, KeyError, TypeError):
            report(True, "Stage 2a reservation rejects " + name)
        else:
            report(False, "Stage 2a reservation rejects " + name)
