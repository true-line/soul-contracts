"""Check the source-only T01 signed-byte vector and its cross-record joins."""

import base64
import hashlib
import json

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from jcs import canonicalize, parse_strict


def sha(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def decode(value):
    raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    if base64.urlsafe_b64encode(raw).rstrip(b"=").decode() != value:
        raise ValueError("noncanonical base64url")
    return raw


def check_stage2a_t01_grant_fixtures(root, schemas, report):
    vector = json.loads((root / "fixtures/qualification/t01/t01-grant-wire-synthetic.json").read_text())
    parsed = {}
    for name, schema in [
        ("request", "hq/v1/stage2a-protected-grant-invoke.schema.json"),
        ("assertion", "hq/v1/stage2a-protected-grant-refusal-assertion.schema.json"),
        ("a_payload", "machine/v1/stage2a-protected-grant-refusal-payload.schema.json"),
        ("a_envelope", "machine/v1/stage2a-protected-grant-signed-refusal.schema.json"),
    ]:
        raw = vector[name + "_jcs"].encode()
        obj = parse_strict(raw.decode())
        parsed[name] = (raw, obj)
        report(raw == canonicalize(obj) and schemas[schema].is_valid(obj),
               f"T01 {name} exact JCS and schema")

    request_raw, request = parsed["request"]
    assertion_raw, assertion = parsed["assertion"]
    payload_raw, payload = parsed["a_payload"]
    envelope_raw, envelope = parsed["a_envelope"]
    purpose = "agent-bot/stage2a-protected-grant-refusal/v1"
    public = decode(vector["fixture_a_public_key_base64url"])
    try:
        Ed25519PublicKey.from_public_bytes(public).verify(
            decode(envelope["signature_base64url"]), purpose.encode() + b"\0" + payload_raw)
        signed = True
    except Exception:  # noqa: BLE001 - a fixture failure must be reported
        signed = False
    report(signed and envelope["purpose"] == purpose and
           envelope["issuer_public_key_base64url"] == vector["fixture_a_public_key_base64url"] and
           envelope["payload_sha256"] == sha(payload_raw) and
           decode(envelope["payload_base64url"]) == payload_raw,
           "T01 purpose-separated A signature and exact payload")

    def joined(req, claim, signed_payload):
        return (claim["request_sha256"] == sha(canonicalize(req)) and
                claim["grant_handle_sha256"] == sha(req["grant_handle"].encode("ascii")) and
                all(claim[field] == req[field] for field in
                    ("installation_id", "start_id", "launch_id", "runtime_id", "operation",
                     "resource_selector", "prompt_sha256", "request_nonce_base64url")) and
                claim["code"] == "caller_mismatch" and claim["decision_stage"] == "before_effect" and
                claim["effect_invoked"] is False and
                signed_payload["hq_assertion_sha256"] == sha(canonicalize(claim)) and
                decode(signed_payload["hq_assertion_base64url"]) == canonicalize(claim) and
                all(signed_payload[field] == claim[field] for field in
                    ("host_id", "installation_id", "start_id", "launch_id", "hq_epoch")) and
                signed_payload["evidence_class"] == "authenticated-hq-assertion-only")

    report(joined(request, assertion, payload), "T01 request, handle, broker assertion and A exact-byte join")
    wrong_handle = dict(request, grant_handle="gh_" + "e" * 32)
    report(not joined(wrong_handle, assertion, payload), "T01 copied handle substitution refused")
    wrong_start = dict(assertion, start_id="st_" + "f" * 24)
    report(not joined(request, wrong_start, payload), "T01 restart/start substitution refused")
    changed_claim = dict(assertion, effect_invoked=True)
    report(not joined(request, changed_claim, payload), "T01 effect claim refuses")
    report(len(envelope_raw) > 0 and len(request_raw) > 0 and len(assertion_raw) > 0,
           "T01 vector byte strings present")
