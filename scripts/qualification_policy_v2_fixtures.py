"""Synthetic v2 owner-policy byte and policy checks; never signature verification."""
import base64
import copy
import hashlib
import json
from datetime import datetime, timezone

from jcs import canonicalize, parse_strict


def _digest(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _time(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def v2_policy_refusal(schemas, policy_bytes, envelope, *, now, highest_revision,
                      accepted_digest, approved_build_workflow, receipt_digest):
    if not schemas["control/v2/qualification-policy-envelope.schema.json"].is_valid(envelope):
        return "envelope-shape"
    if envelope["policy_sha256"] != _digest(policy_bytes) or envelope["policy_base64url"] != base64.urlsafe_b64encode(policy_bytes).rstrip(b"=").decode():
        return "policy-bytes"
    try:
        policy = parse_strict(policy_bytes.decode())
    except (UnicodeError, ValueError):
        return "policy-shape"
    if not schemas["control/v2/qualification-trust-policy.schema.json"].is_valid(policy):
        return "policy-shape"
    if policy["owner_key_id"] != envelope["owner_key_id"]:
        return "owner-key-binding"
    if policy["policy_revision"] < highest_revision:
        return "revision-rollback"
    if policy["policy_revision"] == highest_revision and _digest(policy_bytes) != accepted_digest:
        return "revision-equivocation"
    issued = _time(policy["issued_at"])
    expiry = _time(policy["expires_at"])
    revoked_at = _time(policy["revocation_snapshot"]["updated_at"])
    if not issued <= now < expiry or revoked_at > now or (now - revoked_at).total_seconds() > 3600:
        return "policy-time-or-revocation-age"
    if policy["souls_build_workflow"] != approved_build_workflow:
        return "unapproved-souls-build-workflow"
    revocations = policy["revocation_snapshot"]
    if policy["souls_build_workflow"]["id"] in revocations["revoked_souls_build_workflow_ids"] or receipt_digest in revocations["revoked_souls_build_receipt_sha256"]:
        return "souls-build-revoked"
    return None


def check_qualification_policy_v2_fixtures(root, schemas, report):
    policy = json.loads((root / "fixtures/positive/qualification-trust-policy.bridge-v2-synthetic.json").read_text())["input"]
    envelope = json.loads((root / "fixtures/positive/qualification-policy-envelope.bridge-v2-synthetic.json").read_text())["input"]
    raw = canonicalize(policy)
    now = _time("2026-11-21T18:45:00Z")
    receipt = "sha256:" + "a" * 64
    approved = policy["souls_build_workflow"]

    def check(label, expected, *, p=raw, e=envelope, t=now, highest=1,
              accepted_digest=None, workflow=approved, r=receipt):
        actual = v2_policy_refusal(schemas, p, e, now=t, highest_revision=highest,
                                   accepted_digest=accepted_digest,
                                   approved_build_workflow=workflow, receipt_digest=r)
        report(actual == expected, "v2 owner policy " + label, f"expected {expected}, got {actual}")

    def repack(changed):
        b = canonicalize(changed)
        e = copy.deepcopy(envelope)
        e["policy_sha256"] = _digest(b)
        e["policy_base64url"] = base64.urlsafe_b64encode(b).rstrip(b"=").decode()
        return b, e

    check("shape, bytes and 45-minute revocation snapshot", None)
    check("refuses v1 signature purpose", "envelope-shape", e={**envelope, "purpose": "agent-bot/qualification-policy/v1"})
    check("refuses altered policy bytes", "policy-bytes", p=raw + b"\n")
    check("refuses revision rollback across v1/v2", "revision-rollback", highest=3)
    check("accepts same revision with exact accepted digest", None,
          highest=2, accepted_digest=_digest(raw))
    check("refuses same revision with different accepted digest", "revision-equivocation",
          highest=2, accepted_digest="sha256:" + "f" * 64)
    check("refuses same revision without accepted digest", "revision-equivocation", highest=2)
    changed = copy.deepcopy(policy)
    changed["issued_at"] = "2026-11-21T18:00:01Z"
    b, e = repack(changed)
    check("refuses changed policy bytes at accepted revision", "revision-equivocation",
          p=b, e=e, highest=2, accepted_digest=_digest(raw))
    check("refuses revocation snapshot after one hour", "policy-time-or-revocation-age", t=_time("2026-11-21T19:00:01Z"))
    check("accepts snapshot exactly one hour old", None, t=_time("2026-11-21T19:00:00Z"))
    changed = copy.deepcopy(policy)
    changed["souls_build_workflow"]["source_tree"] = "f" * 40
    b, e = repack(changed)
    check("refuses unapproved source tree with same release bytes", "unapproved-souls-build-workflow", p=b, e=e)
    changed = copy.deepcopy(policy)
    changed["revocation_snapshot"]["revoked_souls_build_workflow_ids"] = [approved["id"]]
    b, e = repack(changed)
    check("refuses revoked Souls workflow", "souls-build-revoked", p=b, e=e)
    changed = copy.deepcopy(policy)
    changed["revocation_snapshot"]["revoked_souls_build_receipt_sha256"] = [receipt]
    b, e = repack(changed)
    check("refuses revoked Souls receipt", "souls-build-revoked", p=b, e=e)
