"""Synthetic witness byte and state comparisons; never signature verification."""

import base64
import hashlib
import json
from datetime import datetime

from jcs import canonicalize, parse_strict


PURPOSE = "agent-bot/qualification-policy-acceptance-witness/v1"
PAIR_FIELDS = ("machine_pub", "hq_pub", "hq_uid", "hq_epoch", "pair_owner_pub")


def digest(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def decode_payload(envelope):
    """Check only exact-byte binding, not the synthetic ES256 signature."""
    if envelope.get("purpose") != PURPOSE:
        return None, "purpose"
    encoded = envelope.get("payload_base64url", "")
    try:
        raw = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
    except (ValueError, UnicodeError):
        return None, "payload-encoding"
    if base64.urlsafe_b64encode(raw).rstrip(b"=").decode() != encoded:
        return None, "payload-encoding"
    if not raw or len(raw) > 4096 or not raw.isascii() or digest(raw) != envelope.get("payload_sha256"):
        return None, "payload-bytes"
    try:
        payload = parse_strict(raw.decode("ascii"))
    except (UnicodeError, ValueError):
        return None, "payload-canonical"
    if not isinstance(payload, dict) or canonicalize(payload) != raw:
        return None, "payload-canonical"
    if payload.get("witness_key_id") != envelope.get("witness_key_id"):
        return None, "witness-key-mismatch"
    return payload, None


def at(value):
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.utcoffset().total_seconds() != 0 or parsed.microsecond or not value.endswith("Z"):
        raise ValueError("not whole-second UTC")
    return parsed


def acceptance_refusal(payload, context):
    """Compare a hypothetically verified witness to current protected state.

    The runtime must separately verify the ES256 signature, owner policy,
    release, physical reports and challenge persistence. Context booleans in
    these synthetic fixtures are not substitutes for those verifications.
    """
    if not all(context[name] for name in ("ledger_present", "witness_key_present", "pairing_present", "checkpoint_present")):
        return "state-missing"
    if not context["trusted_elapsed_time"]:
        return "time-untrusted"
    if payload["host_id"] != context["host_id"]:
        return "host-mismatch"
    if any(payload[name] != context[name] for name in PAIR_FIELDS):
        return "pairing-mismatch"
    if context["witness_key_revoked"] or payload["witness_key_id"] != context["witness_key_id"]:
        return "witness-key-mismatch"
    if not context["challenge_outstanding"] or payload["challenge_base64url"] != context["challenge_base64url"]:
        return "challenge-mismatch"
    now = at(context["now"])
    issued = at(payload["issued_at"])
    expiry = at(payload["expires_at"])
    if issued > now or expiry <= now or not 0 < (expiry - issued).total_seconds() <= 60:
        return "witness-time"
    if (payload["policy_version"], payload["policy_revision"], payload["policy_sha256"]) != (
            context["accepted_policy_version"], context["accepted_policy_revision"], context["accepted_policy_sha256"]):
        return "accepted-tuple-mismatch"
    if payload["owner_key_id"] != context["accepted_owner_key_id"]:
        return "owner-key-mismatch"
    if at(context["policy_expires_at"]) <= now:
        return "policy-expired"
    snapshot_age = (now - at(context["revocation_updated_at"])).total_seconds()
    if not 0 <= snapshot_age <= 3600:
        return "revocation-stale"
    return None


def ledger_transition_refusal(previous, proposed):
    """Synthetic monotonic tuple comparison after owner-signature verification."""
    if proposed[0] < previous[0]:
        return "policy-version-regression"
    if proposed[1] < previous[1]:
        return "policy-rollback"
    if proposed[1] == previous[1] and proposed != previous:
        return "policy-equivocation"
    return None


def check_qualification_acceptance_witness_fixtures(root, schemas, report):
    fixture = root / "fixtures/positive/qualification-acceptance-witness-payload.synthetic.json"
    enrolled = json.loads(fixture.read_text())["input"]
    envelope = json.loads((root / "fixtures/positive/qualification-acceptance-witness.synthetic.json").read_text())["input"]
    payload, error = decode_payload(envelope)
    report(error is None and payload == enrolled and schemas["control/v1/qualification-acceptance-witness-payload.schema.json"].is_valid(payload),
           "witness synthetic exact canonical payload binding")
    altered = {**envelope, "payload_sha256": "sha256:" + "f" * 64}
    report(decode_payload(altered)[1] == "payload-bytes", "witness altered payload digest refused")
    altered = {**envelope, "payload_base64url": envelope["payload_base64url"] + "="}
    report(decode_payload(altered)[1] == "payload-encoding", "witness padded base64url refused")
    altered = {**envelope, "witness_key_id": "other-key"}
    report(decode_payload(altered)[1] == "witness-key-mismatch", "witness envelope key mismatch refused")
    raw = b'{"a":1,"a":2}'
    altered = {**envelope, "payload_base64url": base64.urlsafe_b64encode(raw).rstrip(b"=").decode(), "payload_sha256": digest(raw)}
    report(decode_payload(altered)[1] == "payload-canonical", "witness duplicate JSON keys refused")
    raw = b" " * 4097
    altered = {**envelope, "payload_base64url": base64.urlsafe_b64encode(raw).rstrip(b"=").decode(), "payload_sha256": digest(raw)}
    report(decode_payload(altered)[1] == "payload-bytes", "witness overbound payload refused")

    cases_path = root / "fixtures/qualification/witness-v1/admission-cases.json"
    cases = json.loads(cases_path.read_text())
    report(cases["base"]["fixture"] == "positive/" + fixture.name and cases["base"]["sha256"] == digest(fixture.read_bytes()),
           "witness comparison cases pin their source fixture")
    names = [case["name"] for case in cases["cases"]]
    report(len(names) == len(set(names)) and len(names) >= 20, "witness comparison case names unique")
    for case in cases["cases"]:
        candidate = {**enrolled, **case["payload_overrides"]}
        context = {**cases["context"], **case["context_overrides"]}
        actual = acceptance_refusal(candidate, context)
        report(actual == case["expect_refusal"], "witness " + case["name"],
               f"expected {case['expect_refusal']}, got {actual}")
    transitions = cases["ledger_transitions"]
    report(len(transitions) >= 7 and len({case["name"] for case in transitions}) == len(transitions),
           "witness ledger transition cases unique")
    for case in transitions:
        actual = ledger_transition_refusal(tuple(case["previous"]), tuple(case["proposed"]))
        report(actual == case["expect_refusal"], "witness ledger " + case["name"],
               f"expected {case['expect_refusal']}, got {actual}")
