"""Semantic fixture oracles for a decoded policy. This does not verify signatures."""
from copy import deepcopy
from datetime import datetime


def instant(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def policy_refusal(policy, *, now, highest_revision=0, attestation=None,
                   evidence_signer=None, release_workflow=None):
    """Check time, rollback and revocation after an external signature check.

    A caller must verify the owner signature and validate schema before calling.
    Returning None never grants launch authority on its own.
    """
    issued = instant(policy["issued_at"])
    expiry = instant(policy["expires_at"])
    snapshot = instant(policy["revocation_snapshot"]["updated_at"])
    if policy["policy_revision"] < highest_revision:
        return "rollback"
    if issued > now or expiry <= issued or expiry <= now:
        return "policy-time"
    if snapshot > now or snapshot > issued:
        return "revocation-future"
    if (now - snapshot).total_seconds() > policy["max_revocation_age_seconds"]:
        return "revocation-stale"
    revoked = policy["revocation_snapshot"]
    if attestation in revoked["revoked_attestation_sha256"]:
        return "attestation-revoked"
    if evidence_signer in revoked["revoked_evidence_signer_ids"]:
        return "evidence-signer-revoked"
    if release_workflow in revoked["revoked_release_workflow_ids"]:
        return "release-workflow-revoked"
    return None


def check_qualification_policy_fixtures(root, schemas, report):
    import json

    source = json.loads((root / "fixtures/positive/qualification-trust-policy.synthetic.json").read_text())
    policy = source["input"]
    schema = schemas["control/v1/qualification-trust-policy.schema.json"]
    report(schema.is_valid(policy), "qualification policy synthetic payload shape")
    attestation = "sha256:" + "a" * 64
    args = dict(attestation=attestation, evidence_signer="fixture-signer",
                release_workflow="fixture-workflow")

    def check(label, expected, current=policy, now="2026-11-21T19:00:00Z", **extra):
        actual = policy_refusal(current, now=instant(now), **{**args, **extra})
        report(actual == expected, "qualification policy " + label,
               f"expected {expected}, got {actual}")

    check("accepts exactly 3600 seconds", None)
    check("refuses 3600 seconds plus a microsecond", "revocation-stale",
          now="2026-11-21T19:00:00.000001Z")
    changed = deepcopy(policy)
    changed["issued_at"] = "2026-11-21T18:59:00Z"
    changed["revocation_snapshot"]["updated_at"] = "2026-11-21T17:00:00Z"
    check("fresh policy cannot revive stale revocations", "revocation-stale", changed)
    changed = deepcopy(policy)
    changed["revocation_snapshot"]["updated_at"] = "2026-11-21T19:00:00.000001Z"
    check("refuses future revocation snapshot", "revocation-future", changed)
    changed = deepcopy(policy)
    changed["expires_at"] = "2026-11-21T19:00:00Z"
    check("refuses at policy expiry", "policy-time", changed)
    check("refuses older revision", "rollback", highest_revision=policy["policy_revision"] + 1)
    for field, value, expected in (
        ("revoked_attestation_sha256", attestation, "attestation-revoked"),
        ("revoked_evidence_signer_ids", "fixture-signer", "evidence-signer-revoked"),
        ("revoked_release_workflow_ids", "fixture-workflow", "release-workflow-revoked"),
    ):
        changed = deepcopy(policy)
        changed["revocation_snapshot"][field].append(value)
        check("refuses " + field, expected, changed)

