"""Source-only v3 owner-policy fixture oracle; never verifies a signature."""

import base64
import copy
import hashlib
import json
import re
from datetime import datetime

from jcs import canonicalize, parse_strict


SYNTHETIC_ROOT = b"synthetic frozen root bytes; not a Sigstore trusted root"


def _digest(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _time(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _valid_digest(value):
    return isinstance(value, str) and re.fullmatch(r"sha256:[0-9a-f]{64}", value) is not None


def v3_policy_refusal(schemas, policy_bytes, envelope, *, now,
                      highest_revision, accepted_digest, reviewed_workflow,
                      reviewed_mapping, trusted_root_bytes, receipt_digest,
                      subject_name, subject_digest, statement_predicate):
    if type(highest_revision) is not int or highest_revision < 0 or \
            (highest_revision == 0 and accepted_digest != "") or \
            (highest_revision > 0 and not _valid_digest(accepted_digest)):
        return "checkpoint-state"
    if not schemas["control/v3/qualification-policy-envelope.schema.json"].is_valid(envelope):
        return "envelope-shape"
    if envelope["policy_sha256"] != _digest(policy_bytes) or \
            envelope["policy_base64url"] != base64.urlsafe_b64encode(policy_bytes).rstrip(b"=").decode():
        return "policy-bytes"
    try:
        policy = parse_strict(policy_bytes.decode("ascii"))
        if canonicalize(policy) != policy_bytes:
            return "policy-bytes"
    except (UnicodeError, ValueError):
        return "policy-shape"
    if not schemas["control/v3/qualification-trust-policy.schema.json"].is_valid(policy):
        return "policy-shape"
    if policy["owner_key_id"] != envelope["owner_key_id"]:
        return "owner-key-binding"
    if policy["policy_revision"] < highest_revision:
        return "revision-rollback"
    if policy["policy_revision"] == highest_revision and _digest(policy_bytes) != accepted_digest:
        return "revision-equivocation"
    issued = _time(policy["issued_at"])
    expiry = _time(policy["expires_at"])
    updated = _time(policy["revocation_snapshot"]["updated_at"])
    if not issued <= updated <= now < expiry or (now - updated).total_seconds() > 3600:
        return "policy-time-or-revocation-age"
    workflow = policy["frozen_soul_build_workflow"]
    mapping = policy["frozen_soul_mapping"]
    if workflow != reviewed_workflow:
        return "unapproved-frozen-workflow"
    if _digest(trusted_root_bytes) != workflow["trust_root_sha256"]:
        return "frozen-root-mismatch"
    if mapping != reviewed_mapping:
        return "unapproved-frozen-mapping"
    if subject_name != f"sha256-{mapping['artifact_sha256']}.soul" or \
            subject_digest != mapping["artifact_sha256"]:
        return "frozen-subject-mismatch"
    if set(statement_predicate) != {"artifact_format", "builder", "toolchain_sha256",
                                    "template", "definition_measurement"}:
        return "frozen-predicate-mismatch"
    builder = statement_predicate["builder"]
    if not isinstance(builder, dict) or set(builder) != {"repository", "source_commit", "source_tree",
                                                         "workflow", "run_id", "run_attempt",
                                                         "builder_sha256"} or \
            not isinstance(builder["run_id"], str) or not re.fullmatch(r"[1-9][0-9]*", builder["run_id"]) or \
            type(builder["run_attempt"]) is not int or builder["run_attempt"] < 1 or \
            any(builder[name] != workflow[other] for name, other in (
                ("repository", "repository"), ("source_commit", "source_commit"),
                ("source_tree", "source_tree"), ("workflow", "workflow_path"),
                ("builder_sha256", "builder_sha256"))) or \
            statement_predicate["artifact_format"] != workflow["artifact_format"] or \
            statement_predicate["toolchain_sha256"] != workflow["toolchain_sha256"] or \
            statement_predicate["template"] != workflow["template"] or \
            statement_predicate["definition_measurement"] != mapping["definition_measurement"]:
        return "frozen-predicate-mismatch"
    revoked = policy["revocation_snapshot"]
    if workflow["id"] in revoked["revoked_frozen_soul_build_workflow_ids"] or \
            receipt_digest in revoked["revoked_frozen_soul_receipt_sha256"] or \
            mapping["artifact_sha256"] in revoked["revoked_frozen_soul_artifact_sha256"]:
        return "frozen-authority-revoked"
    return None


def check_qualification_policy_v3_fixtures(root, schemas, report):
    policy = json.loads((root / "fixtures/positive/qualification-trust-policy.frozen-v3-synthetic.json").read_text())["input"]
    envelope = json.loads((root / "fixtures/positive/qualification-policy-envelope.frozen-v3-synthetic.json").read_text())["input"]
    raw = canonicalize(policy)
    now = _time("2026-11-21T18:45:00Z")
    workflow = policy["frozen_soul_build_workflow"]
    mapping = policy["frozen_soul_mapping"]
    receipt = "sha256:" + "e" * 64
    subject_name = f"sha256-{mapping['artifact_sha256']}.soul"
    predicate = {
        "artifact_format": workflow["artifact_format"],
        "builder": {
            "repository": workflow["repository"],
            "source_commit": workflow["source_commit"],
            "source_tree": workflow["source_tree"],
            "workflow": workflow["workflow_path"],
            "run_id": "12345",
            "run_attempt": 1,
            "builder_sha256": workflow["builder_sha256"],
        },
        "toolchain_sha256": workflow["toolchain_sha256"],
        "template": workflow["template"],
        "definition_measurement": mapping["definition_measurement"],
    }

    def check(label, expected, *, p=raw, e=envelope, t=now, highest=2,
              accepted_digest="sha256:" + "d" * 64, w=workflow, m=mapping,
              root_bytes=SYNTHETIC_ROOT, r=receipt, name=subject_name,
              subject_digest=mapping["artifact_sha256"], statement=predicate):
        got = v3_policy_refusal(
            schemas, p, e, now=t, highest_revision=highest,
            accepted_digest=accepted_digest, reviewed_workflow=w,
            reviewed_mapping=m, trusted_root_bytes=root_bytes,
            receipt_digest=r, subject_name=name, subject_digest=subject_digest,
            statement_predicate=statement,
        )
        report(got == expected, "v3 owner policy " + label, f"expected {expected}, got {got}")

    def repack(changed):
        value = canonicalize(changed)
        e = copy.deepcopy(envelope)
        e["policy_sha256"] = _digest(value)
        e["policy_base64url"] = base64.urlsafe_b64encode(value).rstrip(b"=").decode()
        return value, e

    check("synthetic shape, bytes and 45-minute snapshot", None)
    check("initial shared revision state", None, highest=0, accepted_digest="")
    check("v2 purpose cannot substitute", "envelope-shape", e={**envelope, "purpose": "agent-bot/qualification-policy/v2"})
    check("v2 payload cannot substitute", "policy-shape", p=canonicalize({**policy, "contract": "control/v2"}),
          e=repack({**policy, "contract": "control/v2"})[1])
    check("rejects noncanonical policy bytes", "policy-bytes", p=raw + b"\n",
          e={**envelope, "policy_sha256": _digest(raw + b"\n"),
             "policy_base64url": base64.urlsafe_b64encode(raw + b"\n").rstrip(b"=").decode()})
    for label, malformed in (
        ("invalid UTF-8", raw.replace(b"fixture-owner-key", b"fixture-owner-\xff")),
        ("lone escaped surrogate", raw.replace(b"fixture-owner-key", b"fixture-owner-\\ud800")),
    ):
        bad_envelope = {**envelope, "policy_sha256": _digest(malformed),
                        "policy_base64url": base64.urlsafe_b64encode(malformed).rstrip(b"=").decode()}
        check("rejects " + label, "policy-shape", p=malformed, e=bad_envelope)
    check("rollback across policy versions", "revision-rollback", highest=4)
    check("same revision exact bytes", None, highest=3, accepted_digest=_digest(raw))
    check("same revision changed bytes", "revision-equivocation", highest=3,
          accepted_digest="sha256:" + "f" * 64)
    check("orphan digest at zero revision", "checkpoint-state", highest=0,
          accepted_digest="sha256:" + "d" * 64)
    check("missing digest at persisted revision", "checkpoint-state", accepted_digest="")
    check("snapshot exactly 3600 seconds old", None, t=_time("2026-11-21T19:00:00Z"))
    check("snapshot 3601 seconds old", "policy-time-or-revocation-age", t=_time("2026-11-21T19:00:01Z"))
    changed = copy.deepcopy(policy)
    changed["issued_at"] = "2026-11-21T18:00:01Z"
    b, e = repack(changed)
    check("snapshot before issuance", "policy-time-or-revocation-age", p=b, e=e)
    changed = copy.deepcopy(policy)
    changed["frozen_soul_build_workflow"]["builder_sha256"] = "sha256:" + "f" * 64
    b, e = repack(changed)
    check("changed frozen builder", "unapproved-frozen-workflow", p=b, e=e)
    check("different trusted root bytes", "frozen-root-mismatch", root_bytes=b"other synthetic root")
    changed = copy.deepcopy(policy)
    changed["frozen_soul_mapping"]["definition_measurement"] = "sha256:" + "f" * 64
    b, e = repack(changed)
    check("changed definition mapping", "unapproved-frozen-mapping", p=b, e=e)
    check("runtime archive subject substitution", "frozen-subject-mismatch", name="souls-package.tgz")
    check("changed frozen subject digest", "frozen-subject-mismatch", subject_digest="f" * 64)
    changed_predicate = copy.deepcopy(predicate)
    changed_predicate["builder"]["source_commit"] = "f" * 40
    check("changed Statement builder commit", "frozen-predicate-mismatch", statement=changed_predicate)
    changed_predicate = copy.deepcopy(predicate)
    changed_predicate["template"]["source_tree"] = "f" * 40
    check("changed Statement template tree", "frozen-predicate-mismatch", statement=changed_predicate)
    changed_predicate = copy.deepcopy(predicate)
    changed_predicate["definition_measurement"] = "sha256:" + "f" * 64
    check("changed Statement definition", "frozen-predicate-mismatch", statement=changed_predicate)
    for field, value in (
        ("revoked_frozen_soul_build_workflow_ids", workflow["id"]),
        ("revoked_frozen_soul_receipt_sha256", receipt),
        ("revoked_frozen_soul_artifact_sha256", mapping["artifact_sha256"]),
    ):
        changed = copy.deepcopy(policy)
        changed["revocation_snapshot"][field] = [value]
        b, e = repack(changed)
        check("revoked " + field, "frozen-authority-revoked", p=b, e=e)
